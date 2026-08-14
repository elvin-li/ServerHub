"""Service alert engine + optional Home Assistant notify."""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request

from hub import secure_io
from hub.config import cfg
from hub.paths import DATA_DIR
from hub.status import full_status
from hub.url_safety import SafeOutboundRedirects, outbound_url_allowed

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
    secure_io.replace_secret_text(
        STATE_FILE, json.dumps(st, ensure_ascii=False, indent=2)
    )


def _append_jsonl(path, line: str) -> None:
    """Append one line at mode 0600 without following a planted leaf symlink."""
    path.parent.mkdir(exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        try:
            os.fchmod(fd, 0o600)
        except OSError:
            pass
        os.write(fd, line.encode("utf-8"))
    finally:
        os.close(fd)


def _append_alert(alert: dict):
    with _lock:
        _append_jsonl(ALERTS_FILE, json.dumps(alert, ensure_ascii=False) + "\n")
        try:
            lines = ALERTS_FILE.read_text().splitlines()
            if len(lines) > MAX_ALERTS:
                trimmed = "\n".join(lines[-MAX_ALERTS:]) + "\n"
                tmp = ALERTS_FILE.with_suffix(".jsonl.tmp")
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(trimmed)
                os.replace(tmp, ALERTS_FILE)
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


def send_ha_notify(title: str, message: str) -> dict:
    n = notify_settings()
    if not n.get("enabled"):
        return {"ok": False, "message": "notify disabled"}
    url = n.get("ha_webhook_url") or n.get("webhook_url")
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
    allowed, reason = outbound_url_allowed(url, allow_loopback=True)
    if not allowed:
        return {"ok": False, "message": f"blocked notify url: {reason}"}
    try:
        opener = urllib.request.build_opener(
            SafeOutboundRedirects(allow_loopback=True)
        )
        with opener.open(req, timeout=10) as r:
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
                "message": f"{label} usage recovered to {val_f:.0f}%",
            }
            _append_alert(alert)
            emitted.append(alert)
            if n.get("enabled") and n.get("notify_resolve", True):
                send_ha_notify("ServerHub resource recovered", alert["message"])
    new_state["_resource_last"] = new_last
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
    # preserve resource cooldown map
    if isinstance(prev.get("_resource_last"), dict):
        new_state["_resource_last"] = prev["_resource_last"]
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
                "message": f"{s.get('name', sid)} became {state}: {s.get('detail', '')}",
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
                "message": f"{s.get('name', sid)} recovered",
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
    return send_ha_notify(
        "ServerHub notify test",
        f"Notification channel test {time.strftime('%H:%M:%S')}",
    )
