"""Service alert engine + optional Home Assistant notify."""
from __future__ import annotations

import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from hub.config import cfg
from hub.paths import DATA_DIR
from hub.status import full_status

ALERTS_FILE = DATA_DIR / "alerts.jsonl"
STATE_FILE = DATA_DIR / "alert_state.json"
MAX_ALERTS = 500
_lock = threading.Lock()
_thread: threading.Thread | None = None
_stop = threading.Event()


def _load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {}


def _save_state(st: dict):
    STATE_FILE.parent.mkdir(exist_ok=True)
    STATE_FILE.write_text(json.dumps(st, ensure_ascii=False, indent=2))


def _append_alert(alert: dict):
    ALERTS_FILE.parent.mkdir(exist_ok=True)
    with _lock:
        with open(ALERTS_FILE, "a") as f:
            f.write(json.dumps(alert, ensure_ascii=False) + "\n")
        try:
            lines = ALERTS_FILE.read_text().splitlines()
            if len(lines) > MAX_ALERTS:
                ALERTS_FILE.write_text("\n".join(lines[-MAX_ALERTS:]) + "\n")
        except OSError:
            pass


def list_alerts(limit: int = 50) -> list:
    if not ALERTS_FILE.exists():
        return []
    try:
        lines = [ln for ln in ALERTS_FILE.read_text().splitlines() if ln.strip()]
    except OSError:
        return []
    out = []
    for ln in lines[-limit:]:
        try:
            out.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
    out.reverse()
    return out


def notify_settings() -> dict:
    return ((cfg().get("settings") or {}).get("notify") or {})


def _http_url_ok(url: str) -> bool:
    """Only http(s) outbound.  The notify URL is admin-set, but without a scheme
    check the server would happily POST to file://, gopher://, ftp:// etc. —
    turning a self-config field into a broader SSRF primitive than intended."""
    try:
        scheme = urllib.parse.urlsplit(url).scheme.lower()
    except ValueError:
        return False
    return scheme in ("http", "https")


def send_ha_notify(title: str, message: str) -> dict:
    n = notify_settings()
    if not n.get("enabled"):
        return {"ok": False, "message": "notify disabled"}
    url = n.get("ha_webhook_url") or n.get("webhook_url")
    if url and not _http_url_ok(url):
        return {"ok": False, "message": "webhook URL must be http(s)"}
    if not url:
        base = (n.get("ha_url") or "http://localhost:8123").rstrip("/")
        token = n.get("ha_token")
        service = n.get("ha_service") or "notify.notify"
        if not token:
            return {"ok": False, "message": "no webhook or token configured"}
        parts = service.split(".", 1)
        domain = parts[0] if len(parts) == 2 else "notify"
        svc = parts[1] if len(parts) == 2 else parts[0]
        url = f"{base}/api/services/{domain}/{svc}"
        body = json.dumps({"title": title, "message": message}).encode()
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
    else:
        body = json.dumps({
            "title": title,
            "message": message,
            "text": f"{title}: {message}",
        }).encode()
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return {
                "ok": True,
                "status": r.status,
                "body": r.read()[:200].decode(errors="replace"),
            }
    except urllib.error.HTTPError as e:
        detail = e.read()[:200].decode(errors="replace")
        return {"ok": False, "message": f"HTTP {e.code}: {detail}"}
    except Exception as e:
        return {"ok": False, "message": str(e)}


def _resource_thresholds() -> dict:
    from hub.system_settings_svc import get_thresholds
    return get_thresholds()


def _check_resource_thresholds(prev: dict, new_state: dict, now: int) -> list:
    """OMV/TrueNAS-style CPU/mem/disk threshold alerts with cooldown."""
    th = _resource_thresholds()
    if not th.get("enabled", True):
        return []
    emitted = []
    try:
        from hub import metrics
        # Prefer in-memory last sample — never re-read metrics.jsonl every alert tick
        latest = metrics.latest_sample()
        if latest is None:
            hist = metrics.history(5)
            latest = hist[-1] if hist else None
    except Exception:
        latest = None
    if not latest:
        return []
    cpu_val = latest.get("cpu_used_pct")
    if cpu_val is None:
        cpu_val = latest.get("load_pct")
    checks = [
        ("cpu", cpu_val, th.get("cpu_pct", 90), "CPU"),
        ("mem", latest.get("mem_used_pct"), th.get("mem_pct", 90), "Memory"),
        ("disk", latest.get("disk_pct"), th.get("disk_pct", 90), "Disk"),
    ]
    cooldown = int(th.get("cooldown_sec") or 1800)
    last_fire = prev.get("_resource_last") or {}
    if not isinstance(last_fire, dict):
        last_fire = {}
    new_last = dict(last_fire)
    n = notify_settings()
    for rid, val, limit, label in checks:
        if val is None or limit is None:
            continue
        try:
            val_f = float(val)
            limit_f = float(limit)
        except (TypeError, ValueError):
            continue
        key = f"resource:{rid}"
        over = val_f >= limit_f
        new_state[key] = "warn" if over else "ok"
        old = prev.get(key)
        last_t = int(last_fire.get(rid) or 0)
        if over and (old != "warn" or (now - last_t) >= cooldown):
            alert = {
                "t": now,
                "id": key,
                "name": f"Resource · {label}",
                "kind": "resource",
                "group": "system",
                "level": "warn",
                "event": "problem",
                "detail": f"{val_f:.0f}% ≥ {limit_f:.0f}%",
                "message": f"{label} usage {val_f:.0f}% (threshold {limit_f:.0f}%)",
            }
            _append_alert(alert)
            emitted.append(alert)
            new_last[rid] = now
            if n.get("enabled") and n.get("include_warn", True):
                send_ha_notify("ServerHub resource alert", alert["message"])
        elif old == "warn" and not over:
            alert = {
                "t": now,
                "id": key,
                "name": f"Resource · {label}",
                "kind": "resource",
                "group": "system",
                "level": "ok",
                "event": "resolved",
                "detail": f"{val_f:.0f}%",
                "message": f"{label} usage back down to {val_f:.0f}%",
            }
            _append_alert(alert)
            emitted.append(alert)
            if n.get("enabled") and n.get("notify_resolve", True):
                send_ha_notify("ServerHub resource recovered", alert["message"])
    new_state["_resource_last"] = new_last
    return emitted


# --- SMART disk health -------------------------------------------------------

#: First number in a smartctl field.  Kept module level so the parse below is not
#: recompiling it once per attribute per disk per sweep.
_NUM_RE = re.compile(r"-?\d+(?:\.\d+)?")

#: Everything a state-file key and an alert id may contain.  Serial numbers and
#: model strings carry spaces, slashes and colons ("APPLE SSD AP1024R"), and those
#: end up in a JSON key, in the alert `id` and in a URL the UI builds from it.
_KEY_UNSAFE_RE = re.compile(r"[^0-9A-Za-z._-]+")

#: Alert copy for the SMART checks: check -> (terse `detail` form, prose clause).
#: ``v`` is the tripped value, ``lim`` the configured threshold.
#:
#: Collected in one table rather than written inline at each check for two reasons.
#: The two renderings of a check cannot drift apart when they sit on one line -- the
#: alert list showing one number and the notification another is a bug an operator
#: cannot diagnose.  And keeping this copy at one site makes any future move behind
#: i18n a single edit instead of twenty scattered f-strings.
_SMART_REASON_TEXT = {
    "health": ("health={v}", "overall health verdict is {v} (a healthy disk reports PASSED)"),
    "media_errors": ("media errors={v:.0f}", "{v:.0f} media and data integrity errors (threshold 0)"),
    "pending": ("pending sectors={v:.0f}", "{v:.0f} sectors pending reallocation (threshold 0)"),
    "prefail": ("{name} below vendor threshold ({v:.0f}≤{lim:.0f})", "attribute {name} has fallen below the vendor threshold (now {v:.0f}, threshold {lim:.0f})"),
    # Deliberately states only the count.  An earlier wording added "the drive still
    # considers this within tolerance", which is true when this is the only thing
    # tripped -- but the same clause gets appended to a `down` alert whose pre-fail
    # attribute *has* crossed the vendor threshold, where it flatly contradicts the
    # headline.  A reason string is reused across levels, so it must read correctly
    # at every level it can appear in.
    "reallocated": ("reallocated sectors={v:.0f}", "{v:.0f} sectors reallocated; watch for growth"),
    "critical_warning": ("critical warning={v}", "NVMe critical warning bits {v} (a healthy disk reports 0x00)"),
    "temp": ("temp={v:.0f}C≥{lim:.0f}C", "temperature {v:.0f}°C (threshold {lim:.0f}°C)"),
    "wear": ("wear={v:.0f}%≥{lim:.0f}%", "wear {v:.0f}% (threshold {lim:.0f}%)"),
    "spare": ("spare={v:.0f}%≤{lim:.0f}%", "only {v:.0f}% of spare blocks remain (threshold {lim:.0f}%; lower is worse)"),
}

#: level -> (notification title, message template), plus the two fixed strings.
#: Same reasoning as above; ``ok`` needs no body because there is nothing to list.
_SMART_ALERT_TEXT = {
    "name": "Disk · {model}",
    "ok_detail": "SMART metrics normal",
    "down": ("ServerHub disk alert", "Disk {label} reports SMART failures and may be about to fail: {body}"),
    "warn": ("ServerHub disk alert", "Disk {label} has SMART metrics out of bounds: {body}"),
    "ok": ("ServerHub disk recovered", "Disk {label} SMART metrics are back to normal"),
}


def _smart_reason(kind: str, **kw) -> tuple[str, str]:
    """One tripped check, rendered both ways from the same values."""
    detail, sentence = _SMART_REASON_TEXT[kind]
    return detail.format(**kw), sentence.format(**kw)


def _smart_num(raw) -> float | None:
    """The number inside a smartctl field, or None when there isn't one.

    Nothing in ``storage_svc``'s smart dict is a number: temperature arrives as
    ``"37 Celsius"``, wear and spare as ``"0%"`` / ``"100%"``, counters as ``"0"``
    and the NVMe critical-warning bitmap as ``"0x00"``.  Comparing those to an int
    threshold raises, so the digits have to come out first.

    Returns None rather than 0.0 when nothing parses, because here "unreadable" and
    "zero" mean opposite things: 0 media errors is a healthy disk, an unparseable
    media-error field is a disk we know nothing about.  Callers skip that check
    instead of reporting a fault they cannot actually see.
    """
    if raw is None:
        return None
    if isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        return float(raw)
    s = str(raw).strip()
    if not s:
        return None
    low = s.lower()
    # The NVMe critical-warning bitmap is printed in hex.  A decimal-digit scan
    # would read "0x02" (spare below threshold) as 0 and silently drop the warning.
    if low.startswith("0x"):
        try:
            return float(int(low, 16))
        except ValueError:
            return None
    # A few smartctl counters are printed with thousands separators ("1,234").
    m = _NUM_RE.search(s.replace(",", ""))
    if not m:
        return None
    try:
        return float(m.group(0))
    except ValueError:
        return None


def _smart_key(dev: dict) -> str:
    """Stable per-disk identity for the state machine.

    Deliberately not ``diskN``: macOS assigns those in enumeration order, so a
    reboot or a re-plug can turn disk4 into disk5.  The state machine would then see
    one key vanish (its alert never resolving) and a brand-new key appear (the same
    fault announced again), which is exactly the repeat-alert noise the debounce is
    supposed to prevent.  A serial number is the disk's own identity and survives
    both.  Model+capacity is the fallback for disks whose serial smartctl did not
    print, and the enumeration id is the last resort so a key always exists.
    """
    smart = dev.get("smart") or {}
    serial = str(smart.get("serial") or "").strip()
    model = str(smart.get("model") or dev.get("name") or "").strip()
    size_bytes = dev.get("size_bytes")
    disk_id = str(dev.get("id") or "disk").strip() or "disk"
    if serial:
        raw = serial
    elif model and size_bytes:
        raw = f"{model}-{size_bytes}"
    else:
        raw = disk_id
    key = _KEY_UNSAFE_RE.sub("-", raw).strip("-")
    # Bounded: the key lands in a JSON object key and in an alert id, and some USB
    # bridges report absurdly long "serials".
    return key[:64] or disk_id


def _smart_reasons(smart: dict, th: dict) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Split the tripped SMART checks into (fatal, worth-watching).

    Each reason is a ``(detail, sentence)`` pair: `detail` is the terse
    machine-ish form the alert list shows, `sentence` is the prose clause the
    notification body is built from.  Both are produced here so a check can never
    appear in one and be missing from the other.
    """
    down: list[tuple[str, str]] = []
    warn: list[tuple[str, str]] = []

    # The drive's own overall verdict, and the most authoritative signal available:
    # the firmware has already weighed its internal attributes against the vendor's
    # failure thresholds.  Anything that is not PASSED/OK is fatal, including
    # "WARNING" -- smartctl uses that word for a drive that has crossed a vendor
    # threshold, which is a different thing from our own soft warn level below.
    health = str(smart.get("health") or "").strip()
    if health and health.upper().rstrip("!") not in ("PASSED", "OK"):
        down.append(_smart_reason("health", v=health))

    # NVMe media and data integrity errors: the controller could not deliver data it
    # was asked for.  Any non-zero value is already data loss, hence the implicit >0.
    #
    # `pending` is the ATA equivalent that genuinely is urgent at 1: a pending sector
    # is one the drive tried to read, could not, and has not remapped yet -- the data
    # in it is unreadable *now*.
    for field in ("media_errors", "pending"):
        val = _smart_num(smart.get(field))
        if val is not None and val > 0:
            down.append(_smart_reason(field, v=val))

    # The drive's own pre-fail verdict, read from the attribute table.  Every ATA
    # attribute carries a normalised value and the vendor's failure threshold, and
    # the vendor is the only party who knows how much margin a given model has.
    #
    # This exists because the raw counters alone are a bad severity signal, and the
    # host this was built on proves it: its external SATA SSD reports 55 reallocated
    # sectors, which sounds alarming, while the same attribute's normalised value is
    # 100 against a threshold of 10 and the drive answers PASSED.  Alerting "this
    # disk is about to fail" there would be a false positive on day one, and an
    # operator who is shown one of those stops reading disk alerts -- which is worse
    # than having none.  So "raw count is non-zero" is a warn below, and *crossing
    # the vendor's own threshold* is what counts as fatal.
    for attr in smart.get("attrs") or []:
        if not isinstance(attr, dict) or str(attr.get("type") or "") != "Pre-fail":
            continue
        value = _smart_num(attr.get("value"))
        thresh = _smart_num(attr.get("thresh"))
        # A threshold of 0 means the vendor declared no failure point for this
        # attribute, so there is nothing to be below.
        if value is None or thresh is None or thresh <= 0:
            continue
        if value <= thresh:
            down.append(_smart_reason(
                "prefail", name=str(attr.get("name") or attr.get("id") or "?"),
                v=value, lim=thresh,
            ))

    # Reallocated sectors: real information, but not an emergency by itself.  The
    # drive has already moved the data and, on an SSD with a large over-provisioning
    # pool, a few dozen is unremarkable.  What matters is growth, and the pre-fail
    # check above is what fires when the vendor decides the margin is gone.
    realloc = _smart_num(smart.get("reallocated"))
    if realloc is not None and realloc > 0:
        warn.append(_smart_reason("reallocated", v=realloc))

    # NVMe critical warning bitmap: any bit set means the controller is reporting a
    # fault (spare exhausted, degraded reliability, read-only mode, over temperature).
    crit_raw = str(smart.get("critical_warning") or "").strip()
    crit = _smart_num(crit_raw)
    if crit is not None and crit > 0:
        down.append(_smart_reason("critical_warning", v=crit_raw))

    # The soft checks, all read from the thresholds so an operator can retune them.
    # `spare` is the odd one out and gets `<=`: "Available Spare" is the share of the
    # NVMe over-provisioning pool still unused, so it counts *down* from 100%, and
    # comparing it the same way as everything else would make a disk with 2% spare
    # left look healthier than a brand-new one.
    for field, source, limit_key, hotter_is_worse in (
        ("temp", "temp", "smart_temp_c", True),
        ("wear", "wear", "smart_wear_pct", True),
        ("spare", "available_spare", "smart_spare_pct", False),
    ):
        val = _smart_num(smart.get(source))
        lim = _smart_num(th.get(limit_key))
        if val is None or lim is None:
            continue
        if (val >= lim) if hotter_is_worse else (val <= lim):
            warn.append(_smart_reason(field, v=val, lim=lim))
    return down, warn


def _check_smart_health(prev: dict, new_state: dict, now: int) -> list:
    """Unraid/OMV-style SMART health alerts, from the shared SMART snapshot.

    Reads ``storage_svc.smart_devices()`` rather than running smartctl itself.  That
    is not only about duplication: ``POST /api/alerts/check`` calls
    :func:`check_once` synchronously, and a direct probe is a ``diskutil info`` plus
    a ``smartctl -a`` per disk -- each with a 10s timeout, plus a conditional sudo
    retry -- so that endpoint would block for tens of seconds on a machine with a
    few disks attached.  ``smart_devices()`` is memoised for 10 minutes and shared
    with the storage page and the dashboard tile, so at the configured 300s alert
    interval most sweeps read it for free and none of them spawn a process of
    their own.
    """
    th = _resource_thresholds()
    # Not gated on `thresholds.enabled`: see the comment beside `smart_enabled` in
    # system_settings_svc.DEFAULT_THRESHOLDS.  The usage alerts and the
    # disk-is-dying alerts have very different signal-to-noise, so they get
    # separate switches.
    if not th.get("smart_enabled", True):
        return []
    try:
        from hub import storage_svc
        devices = storage_svc.smart_devices()
    except Exception:
        return []

    cooldown = int(th.get("cooldown_sec") or 1800)
    last_fire = prev.get("_smart_last")
    if not isinstance(last_fire, dict):
        last_fire = {}
    new_last = dict(last_fire)
    n = notify_settings()
    emitted: list = []

    for dev in devices or []:
        if not isinstance(dev, dict):
            continue
        smart = dev.get("smart")
        if not smart or not isinstance(smart, dict) or dev.get("error"):
            # Unknown, not broken.  macOS gives userspace no ATA/SCSI passthrough
            # over USB or Thunderbolt bridges, so smartctl answers "not supported by
            # device" for a perfectly healthy external disk.  Skip it entirely and
            # write no state: treating an unreadable disk as a failing one would
            # mean every Mac with a backup drive plugged in alerts on every sweep,
            # forever, and the operator learns to ignore disk alerts.
            continue

        down, warn = _smart_reasons(smart, th)
        # One alert per disk, at the worst level it earned.  A disk that is failing
        # usually trips several checks at once (health + media errors + temperature),
        # and five separate alerts for one disk would bury the other disks.
        if down:
            level, reasons = "down", down + warn
        elif warn:
            level, reasons = "warn", warn
        else:
            level, reasons = "ok", []

        key = _smart_key(dev)
        sid = f"smart:{key}"
        new_state[sid] = level
        old = prev.get(sid)
        last_t = int(last_fire.get(key) or 0)
        model = str(smart.get("model") or dev.get("name") or dev.get("id") or key).strip()
        device = str(dev.get("device") or "").strip()
        # /dev/diskN is useless as an identity (see _smart_key) but is exactly what
        # an operator needs to find the disk right now, so it belongs in the prose.
        label = f"{model} {device}".strip()
        name = _SMART_ALERT_TEXT["name"].format(model=model)

        if level != "ok":
            # Edge-triggered plus a cooldown re-announce, same semantics as
            # _check_resource_thresholds: fire when the level changes, and again
            # while still bad once the cooldown has elapsed.
            #
            # Unlike the service loop above, there is no `if old is None: continue`
            # here.  A service with no history is skipped because a fresh state file
            # would otherwise re-announce every already-down service on startup, and
            # a service can be restarted.  A disk cannot: if the very first SMART
            # read we ever take says FAILED, the disk is losing data now, and the
            # state file happening to be new -- fresh install, wiped data/, first
            # boot after the disk was added -- is not a reason to stay silent until
            # something else changes.
            if old != level or (now - last_t) >= cooldown:
                title, template = _SMART_ALERT_TEXT[level]
                message = template.format(
                    label=label, body="; ".join(s for _, s in reasons)
                )
                alert = {
                    "t": now,
                    "id": sid,
                    "name": name,
                    "kind": "smart",
                    "group": "storage",
                    "level": level,
                    "event": "problem",
                    "detail": " · ".join(d for d, _ in reasons),
                    "message": message,
                }
                _append_alert(alert)
                emitted.append(alert)
                new_last[key] = now
                # Gate by level, not by include_warn alone.  include_warn means
                # "also push the warn-level chatter" and ships false on real
                # installs; a disk that is failing is not chatter, so `down` follows
                # `enabled` only, exactly like the service down alerts above.
                if n.get("enabled") and (level == "down" or n.get("include_warn")):
                    send_ha_notify(title, message)
        elif old in ("down", "warn"):
            title, template = _SMART_ALERT_TEXT["ok"]
            alert = {
                "t": now,
                "id": sid,
                "name": name,
                "kind": "smart",
                "group": "storage",
                "level": "ok",
                "event": "resolved",
                "detail": _SMART_ALERT_TEXT["ok_detail"],
                "message": template.format(label=label),
            }
            _append_alert(alert)
            emitted.append(alert)
            # Drop the cooldown stamp with the alert it belonged to, so the map does
            # not accumulate an entry per disk ever seen.
            new_last.pop(key, None)
            if n.get("enabled") and n.get("notify_resolve", True):
                send_ha_notify(title, alert["message"])

    new_state["_smart_last"] = new_last
    return emitted


def check_once(force_status: bool = False) -> list:
    """Emit alerts on transition to down/warn and recovery.

    SSD-friendly: reuses status cache; only rewrites alert_state.json when changed.
    """
    st = full_status(force=force_status)
    prev = _load_state()
    services = {}
    for g in st.get("groups") or []:
        for s in g.get("services") or []:
            services[s["id"]] = s
    now = int(time.time())
    emitted = []
    new_state = {}
    # `new_state` is rebuilt from scratch every sweep, so any bookkeeping sub-dict
    # that is not copied across here is silently lost.  That is not a hypothetical:
    # a cooldown map dropped each round resets its own debounce, so a still-bad
    # resource or disk gets re-announced on every single sweep (every 300s on a real
    # install) instead of once per cooldown.  Both maps are carried before the checks
    # run, so they also survive a check raising halfway through.
    if isinstance(prev.get("_resource_last"), dict):
        new_state["_resource_last"] = prev["_resource_last"]
    if isinstance(prev.get("_smart_last"), dict):
        new_state["_smart_last"] = prev["_smart_last"]
    for sid, s in services.items():
        state = s.get("state", "unknown")
        new_state[sid] = state
        old = prev.get(sid)
        if old is None:
            continue
        if state != old and state in ("down", "warn"):
            alert = {
                "t": now,
                "id": sid,
                "name": s.get("name", sid),
                "kind": s.get("kind"),
                "group": s.get("group"),
                "level": state,
                "event": "problem",
                "detail": s.get("detail", ""),
                "message": f"{s.get('name', sid)} changed to {state}: {s.get('detail', '')}",
            }
            _append_alert(alert)
            emitted.append(alert)
            n = notify_settings()
            if n.get("enabled") and (state == "down" or n.get("include_warn")):
                send_ha_notify("ServerHub alert", alert["message"])
        elif old in ("down", "warn") and state == "ok":
            alert = {
                "t": now,
                "id": sid,
                "name": s.get("name", sid),
                "kind": s.get("kind"),
                "group": s.get("group"),
                "level": "ok",
                "event": "resolved",
                "detail": s.get("detail", ""),
                "message": f"{s.get('name', sid)} has recovered",
            }
            _append_alert(alert)
            emitted.append(alert)
            n = notify_settings()
            if n.get("enabled") and n.get("notify_resolve", True):
                send_ha_notify("ServerHub recovered", alert["message"])
    try:
        emitted.extend(_check_resource_thresholds(prev, new_state, now))
    except Exception:
        pass
    # Same containment as the resource check: this runs on the single alerter
    # thread, and one disk with a smartctl field we did not anticipate must not take
    # the whole engine down with it -- a dead alert thread is silent, which is the
    # worst possible failure mode for an alerting system.
    try:
        emitted.extend(_check_smart_health(prev, new_state, now))
    except Exception:
        pass
    # Only rewrite state file when map actually changed (huge SSD win)
    if new_state != prev:
        _save_state(new_state)
    return emitted


def _loop(interval: int = 90):
    try:
        st = full_status(force=False)
        baseline = {}
        for g in st.get("groups") or []:
            for s in g.get("services") or []:
                baseline[s["id"]] = s.get("state")
        # Seed a baseline only on a genuinely fresh install.  Keyed on the state
        # actually loading rather than on STATE_FILE.exists(): a false negative
        # there would replace the operator's saved state with a fresh baseline,
        # discarding the per-service history that suppresses repeat alerts, so the
        # next sweep would re-announce everything as if it had just changed.
        if not _load_state():
            _save_state(baseline)
    except Exception:
        pass
    while not _stop.is_set():
        try:
            # Prefer cache; force at most occasionally via TTL
            check_once(force_status=False)
        except Exception:
            pass
        _stop.wait(max(30, int(interval)))


def start_alerter(interval: int = 90):
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(
        target=_loop, args=(max(30, int(interval)),), daemon=True, name="alert-engine"
    )
    _thread.start()


def stop_alerter(timeout: float = 3.0) -> None:
    """Stop the alert worker cleanly during app shutdown/reload."""
    global _thread
    _stop.set()
    thread = _thread
    if thread and thread.is_alive() and thread is not threading.current_thread():
        thread.join(timeout=timeout)
    _thread = None


def test_notify() -> dict:
    return send_ha_notify("ServerHub test", f"Notification channel test {time.strftime('%H:%M:%S')}")
