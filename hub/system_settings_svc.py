"""Unraid-style system settings aggregates for macOS (read + safe writes).

Inspired by:
  Unraid Settings (Identification, DateTime, Disk, Network, Docker, Notify,
  Management Access, Scheduler, Diagnostics, Other)
  OpenMediaVault (SMART, notifications thresholds, services)
  Cockpit (system overview, logs, power)
  CasaOS / TrueNAS (simple panels, resource alerts)
"""
from __future__ import annotations

import json
import platform
import re
import time
from hub import __version__, power_svc
from hub.config import cfg, settings_section
from hub.host_address import configured_host, host_ip
from hub.paths import BASE, CONFIG_FILE, DATA_DIR
from hub.errors import api_error, soft_fail
from hub.secure_io import replace_bytes
from hub.util import LazyPool, cached_snapshot, fan_out, sh, strftime_now, ttl_memo

_pool = LazyPool(12, "hub-syssettings")


def shutdown_executor() -> None:
    _pool.shutdown()


def _isa(value, kinds) -> bool:
    """``isinstance`` that a leftover ``__class__``-property bomb cannot 500.

    ``isinstance`` consults ``value.__class__`` when the exact-type check
    misses, so a leftover whose ``__class__`` is a *raising property*
    detonated the sanitizer gates themselves — one step ahead of every
    scrub in this module (the dash9 host_address / nas8 rule).  A real
    subclass still matches through the C-level type check; only a value
    that cannot answer what it is takes the non-matching branch.
    """
    try:
        return isinstance(value, kinds)
    except Exception:
        return False


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
    # _isa, not a bare isinstance: a ``__class__``-property bomb riding a
    # timer row used to detonate this gate itself and 500 the scheduler trio.
    if _isa(value, (bytes, bytearray)):
        try:
            # Unbound base decode (the tools_svc._as_text rule): the old
            # ``bytes(value)`` copy dispatched into a subclass's own
            # ``__bytes__``, so a leftover ``__bytes__`` bomb raised out of
            # the sanitizer just like the decode() bomb it was guarding
            # against.  The base read survives both and salvages the real
            # bytes.  The try is for a *lying* ``__class__`` (claims bytes,
            # is not): the unbound call TypeErrors and the impostor renders
            # like any other junk object below instead of 500ing.
            base = bytes if isinstance(value, bytes) else bytearray
            return base.decode(value, "utf-8", "replace")
        except Exception:
            pass
    try:
        text = str(value)
    except RecursionError:
        try:
            return type(value).__name__
        except Exception:
            return ""
    except Exception:
        return ""
    # Unbound str.encode, not text.encode: ``str(x)`` of a str *subclass*
    # whose ``__str__`` returns itself keeps the subclass, so the bound
    # ``.encode`` dispatched into a leftover override — a bomb there raised
    # out of the sanitizer and 500'd GET /api/settings/other, /thresholds
    # and /disk (the jobs6 class, sealed elsewhere).
    return str.encode(text, "utf-8", "replace").decode("utf-8")


def _as_text(value) -> str:
    # _isa on every rank gate: a ``__class__``-property bomb used to
    # detonate the first bare isinstance and raise out of the scrub itself.
    if _isa(value, str):
        return _utf8_text(value)
    if _isa(value, (bytes, bytearray)):
        try:
            # Unbound base decode: ``bytes(value)`` ran a subclass ``__bytes__``
            # bomb (and the bound ``.decode`` was the subclass's own) — either
            # one raised out of the sanitizer.  The try is for a lying
            # ``__class__`` impostor, which renders as junk text below.
            base = bytes if isinstance(value, bytes) else bytearray
            return base.decode(value, "utf-8", "replace")
        except Exception:
            pass
    if _isa(value, float):
        try:
            # Base coercion to an exact float: a subclass ``__eq__``/``__ne__``
            # bomb used to blow the NaN/inf probes below.
            value = float.__float__(value)
        except Exception:
            return ""
        if value != value or value in (float("inf"), float("-inf")):
            return ""
        return _utf8_text(value)
    if value is None or _isa(value, (dict, list, tuple, set, bool)):
        return ""
    try:
        return _utf8_text(value)
    except Exception:
        return ""


def _mapping_get(mapping, key, default=None):
    """Field read that neither a dict-subclass ``.get`` bomb nor a leftover
    *hash-shadowing* key can detonate.

    ``dict.get`` (unbound) bypasses a subclass's own ``.get`` override, but
    the C-level lookup still calls the *stored* key's ``__eq__`` when the
    probe's hash lands on its slot — so a leftover key carrying
    ``hash("label")`` / ``hash("server_comment")`` with a raising ``__eq__``
    used to 500 GET /api/settings/scheduler, /disk, /other and
    /api/identity straight out of the compare (the alerts/notify_channels
    ``_mapping_get`` rule, which these host surfaces never got).
    """
    if not _isa(mapping, dict):
        return default
    try:
        return dict.get(mapping, key, default)
    except Exception:
        return default


def _finite_number(value, default=None):
    """YAML leftover ``.inf`` / a date used to 500 GET /api/settings/other."""
    # type-is for the bool gate and _isa for the ranks: a ``__class__``-
    # property bomb used to detonate the first bare isinstance itself and
    # 500 GET /api/settings/other on the metrics_interval read.
    if type(value) is bool or value is None:
        return default
    if _isa(value, int):
        try:
            # Base coercion to an exact int first: an int *subclass* whose
            # ``__index__``/``__str__`` bombs (the modules5 class) used to
            # raise past the ValueError-only digit-cap catch and 500
            # GET /api/settings/thresholds and /other.
            value = int.__index__(value)
            str(value)
        except Exception:
            # A >4300-digit leftover int is unrenderable by json.dumps
            # (CPython's int->str digit cap) — fall back like inf.
            return default
        return value
    if _isa(value, float):
        try:
            # Base coercion to an exact float: a subclass ``__eq__``/``__ne__``
            # bomb used to blow the NaN/inf probes below.
            value = float.__float__(value)
        except Exception:
            return default
        if value != value or value in (float("inf"), float("-inf")):
            return default
        return value
    return default


def _truthy(value) -> bool:
    """Guarded ``bool(...)``: a leftover ``__bool__``/``__len__`` bomb in a
    stored flag must degrade to False, never raise out of a settings read."""
    # ``type(value) is bool``, not isinstance: a *bool-liar* (lying
    # ``__class__`` claims bool, is not) passed isinstance and was returned
    # raw into the payload, where the C encoder's exact-type check refused
    # it — a raw 500 on GET /api/settings/system.  bool() below coerces the
    # liar to an honest True/False without ever consulting ``__class__``.
    if type(value) is bool:
        return value
    try:
        return bool(value)
    except Exception:
        return False


def _as_map(value) -> dict:
    """A plain-dict copy of *value*, or ``{}``.

    ``dict(subclass)`` copies through CPython's C-level storage, bypassing
    a leftover's overridden ``.get``/``.items``/``keys`` (the bomb class
    usage5/json5 sealed elsewhere), so every read on the returned map is on
    a plain dict.
    """
    # _isa: a ``__class__``-property bomb handed in as a row used to
    # detonate the gate itself instead of degrading to {}.
    if not _isa(value, dict):
        return {}
    try:
        return dict(value)
    except Exception:
        return {}


def _settings_map() -> dict:
    """Laundered ``settings`` mapping off ``cfg()`` for the readers here.

    ``cfg().get("settings") or {}`` reflected into the leftover itself
    twice: a config root that is a dict *subclass* with a bombing ``.get``
    raised on the read, and a ``settings`` value whose ``__bool__`` bombs
    raised on the ``or`` — each a raw 500 on GET /api/settings/other (the
    same reads inside get_management_access degraded that section of the
    Settings bundle to an error row).
    """
    try:
        data = cfg()
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    # _mapping_get, not a bare ``dict.get``: the unbound read dodges a
    # subclass ``.get`` bomb but a hash-shadowing "settings" key still
    # raised inside the C lookup and 500'd GET /api/settings/other.
    return _as_map(_mapping_get(data, "settings"))


def _json_bool(value, default: bool = True) -> bool:
    # ``type(value) is bool``: a bool-liar (lying ``__class__``) passed
    # isinstance and rode raw into the payload — the C encoder's exact-type
    # check refused it and 500'd GET /api/settings/other.  A class-bomb
    # (raising ``__class__``) detonated the isinstance itself.  type() never
    # dispatches into the leftover.
    return value if type(value) is bool else default


def _json_atom(value):
    """Drop leftover inf/bytes/dates/sets/``\\ud800`` so Starlette cannot 500."""
    # _isa on every rank gate (the dash9 rule): a ``__class__``-property
    # bomb used to detonate the first bare isinstance and 500 every rider.
    if _isa(value, (bytes, bytearray)):
        try:
            # Unbound base decode: ``bytes(value)`` ran a subclass ``__bytes__``
            # bomb (and the bound ``.decode`` was the subclass's own) — either
            # one raised out of the sanitizer.
            base = bytes if isinstance(value, bytes) else bytearray
            return base.decode(value, "utf-8", "replace")
        except Exception:
            # A lying ``__class__`` (claims bytes, is not) TypeErrors the
            # unbound decode: junk drops like any other unrenderable.
            return None
    if _isa(value, str):
        return _utf8_text(value)
    if _isa(value, float):
        try:
            # Base coercion to an exact float: a subclass ``__eq__``/``__ne__``
            # bomb used to blow the NaN/inf probes below.
            value = float.__float__(value)
        except Exception:
            return None
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if _isa(value, (dict, list, tuple, set, frozenset)):
        return None
    try:
        iso = getattr(value, "isoformat", None)
    except Exception:
        # A raising ``isoformat`` property used to blow the probe itself
        # (the _plist_jsonable rule from host7): getattr's default only
        # swallows AttributeError, so the bomb 500'd every _json_atom rider.
        iso = None
    if callable(iso):
        try:
            stamped = iso()
        except Exception:
            return None
        if stamped is value:
            return None
        return _json_atom(stamped)
    if _isa(value, int) and type(value) is not bool:
        try:
            # Base coercion first: an int subclass ``__index__``/``__str__``
            # bomb used to raise past the ValueError-only digit-cap catch.
            # A *bool-liar* (lying ``__class__`` claims bool) lands here too
            # — bool subclasses int — and the coercion TypeErrors it into
            # the same drop instead of returning it raw.
            value = int.__index__(value)
            str(value)
        except Exception:
            # Past CPython's int->str digit cap the encoder cannot render
            # the number at all — same drop as its inf float sibling.
            return None
        return value
    if value is None or type(value) is bool:
        # ``type(value) is bool``, not ``_isa``: a bool-liar passed the
        # lying-``__class__`` check and was returned raw, and Starlette's
        # C encoder — which checks the exact type — refused it with a
        # TypeError: a raw 500 on every _json_atom rider.
        return value
    try:
        return _utf8_text(value)
    except Exception:
        return None


def _json_tree(value, depth: int = 0):
    """Drop leftover inf/bytes/``\\ud800`` so diagnostics cannot 500 UTF-8.

    ``isoformat()`` returning inf used to skip the float sanitizer.
    Unknown leftovers (Path, complex) used to TypeError Starlette.
    A >4300-digit leftover int still passed through untouched: CPython's
    int->str digit limit then ValueError'd ``json.dumps`` itself.
    """
    if depth > 32:
        return None
    if value is None or type(value) is bool:
        # ``type(value) is bool``, not ``_isa``: a *bool-liar* (lying
        # ``__class__`` claims bool, is not) passed this gate and was
        # returned raw — Starlette's C encoder checks the exact type and
        # TypeError'd it, a raw 500 on GET /api/scheduler and
        # /api/system/scheduler.  The liar now falls through to the int
        # gate (bool subclasses int), where ``int.__index__`` refuses it
        # and it drops to null like any other unrenderable.
        return value
    if _isa(value, int):
        try:
            # Base coercion first: an int subclass ``__index__``/``__str__``
            # bomb used to raise past the ValueError-only digit-cap catch.
            value = int.__index__(value)
            str(value)
        except Exception:
            # Past CPython's int->str digit cap the encoder cannot render
            # the number at all — same drop as its inf float sibling.
            return None
        return value
    if _isa(value, float):
        try:
            # Base coercion to an exact float: a subclass ``__eq__``/``__ne__``
            # bomb used to blow the NaN/inf probes below.
            value = float.__float__(value)
        except Exception:
            return None
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if _isa(value, (bytes, bytearray)):
        try:
            # Unbound base decode: ``bytes(value)`` ran a subclass ``__bytes__``
            # bomb (and the bound ``.decode`` was the subclass's own) — either
            # one raised out of the sanitizer.
            base = bytes if isinstance(value, bytes) else bytearray
            return base.decode(value, "utf-8", "replace")
        except Exception:
            # A lying ``__class__`` (claims bytes, is not) TypeErrors the
            # unbound decode: junk drops like any other unrenderable.
            return None
    if _isa(value, str):
        return _utf8_text(value)
    if _isa(value, dict):
        out = {}
        try:
            items = list(value.items())
        except Exception:
            # A dict *subclass* whose items() raises must not 500 the
            # settings bundle — drop the node like an unrenderable scalar;
            # healthy siblings around it are untouched.
            return None
        for pair in items:
            try:
                k, v = pair
            except Exception:
                # A subclass items() answering torn pairs (three-tuples, a
                # bombing pair iterator) used to ValueError out of the walk
                # itself; the torn entry drops and its siblings survive.
                continue
            # _isa on the key rank too: a ``__class__``-property bomb as a
            # mapping key used to detonate this gate and 500 the walk.
            if _isa(k, (bytes, bytearray)):
                try:
                    # Unbound base decode, matching the value arm: a key-rank
                    # ``__bytes__`` bomb used to raise out of the walk.
                    kbase = bytes if isinstance(k, bytes) else bytearray
                    k = kbase.decode(k, "utf-8", "replace")
                except Exception:
                    # A lying-``__class__`` key cannot be rendered: the
                    # entry drops, its siblings stay.
                    continue
            else:
                try:
                    k = str(k)
                except Exception:
                    continue
            out[_utf8_text(k)] = _json_tree(v, depth + 1)
        return out
    if _isa(value, (list, tuple, set, frozenset)):
        try:
            seq = list(value)
        except Exception:
            # A list/set subclass whose __iter__ raises drops to null rather
            # than raising out of the encode; the structure survives.
            return None
        return [_json_tree(v, depth + 1) for v in seq]
    try:
        iso = getattr(value, "isoformat", None)
    except Exception:
        # A raising ``isoformat`` property used to blow the probe itself
        # (the _plist_jsonable rule from host7): getattr's default only
        # swallows AttributeError, so the bomb 500'd GET /api/scheduler,
        # GET /api/system/scheduler and every other _json_tree rider.
        iso = None
    if callable(iso):
        try:
            return _json_tree(iso(), depth + 1)
        except Exception:
            return None
    try:
        return _utf8_text(value)
    except Exception:
        return None


DEFAULT_THRESHOLDS = {
    "enabled": True,
    "cpu_pct": 90,
    "mem_pct": 90,
    "disk_pct": 90,
    "cooldown_sec": 1800,
    # SMART disk health gets its own switch instead of riding on `enabled` above.
    # `enabled` is the mute button for the CPU/mem/disk-usage alerts, which trip on
    # ordinary load spikes and are the ones an operator switches off during a big
    # build or a backup run.  A disk reporting FAILED, or growing reallocated
    # sectors, is not that kind of noise -- it is data being lost right now -- and
    # must not disappear with the same click.
    "smart_enabled": True,
    # Consumer NVMe/SATA drives are rated to roughly 70C and throttle before it, so
    # 60C reads as "this enclosure has no airflow", not "this disk is busy".
    "smart_temp_c": 60,
    # NVMe "Percentage Used": 100% means the rated write endurance is spent, so 90%
    # is the last comfortable moment to plan a replacement rather than react to one.
    "smart_wear_pct": 90,
    # NVMe "Available Spare" counts *down* from 100% as the over-provisioning pool
    # is consumed, so this threshold trips when the value falls to or below it --
    # the opposite direction from every other number in this dict.
    "smart_spare_pct": 10,
}
_BUNDLE_TTL = 25.0  # settings page is interactive but not real-time


def _clock_now() -> str:
    rc, now, _ = sh(["/bin/date", "+%Y-%m-%d %H:%M:%S %Z"], timeout=3)
    text = _as_text(now)
    return text if rc == 0 else strftime_now("%Y-%m-%d %H:%M:%S")


def _ntp_enabled() -> bool | None:
    """None when systemsetup would not say, which the page renders as unknown."""
    rc, out, _ = sh(["/usr/sbin/systemsetup", "-getusingnetworktime"], timeout=4)
    text = _as_text(out)
    return "on" in text.lower() if rc == 0 and text else None


def _ntp_server() -> str | None:
    rc, out, _ = sh(["/usr/sbin/systemsetup", "-getnetworktimeserver"], timeout=4)
    text = _as_text(out)
    return text.split(":", 1)[-1].strip() if rc == 0 and text and ":" in text else None


def get_datetime_info() -> dict:
    """Date / timezone / NTP-ish info (macOS).

    The two `systemsetup` reads are the slow ones -- it is a notoriously unhurried
    binary and each carries its own 4s timeout -- and neither depends on the other
    or on the clock and timezone reads beside them.
    """
    from hub.identity_svc import time_zone

    def _safe(item):
        probe, fallback = item
        try:
            return probe()
        except Exception:
            return fallback

    now, tz, ntp_on, ntp_server = fan_out(
        _safe,
        [
            (_clock_now, strftime_now("%Y-%m-%d %H:%M:%S")),
            (time_zone, ""),
            (_ntp_enabled, None),
            (_ntp_server, None),
        ],
        max_workers=4,
    )
    try:
        unix = int(time.time())
    except (TypeError, ValueError, OverflowError):
        # Leftover ``time.time() = inf`` OverflowError'd GET /api/settings datetime.
        unix = 0
    return _json_tree({
        "now": _as_text(now),
        "timezone": _as_text(tz or ""),
        "ntp_enabled": ntp_on,
        "ntp_server": _as_text(ntp_server) if ntp_server is not None else None,
        "unix": unix,
        "hint": "Changing the system time zone / NTP usually requires administrator rights (System Settings → General → Date & Time)",
    })


def get_ups_info() -> dict:
    """Power source / battery (Unraid UPS-ish; Mac uses AC + internal battery)."""
    rc, out, _ = sh(["/usr/bin/pmset", "-g", "batt"], timeout=5)
    lines = _as_text(out).strip().splitlines() if rc == 0 else []
    source = "unknown"
    percent = None
    charging = None
    present = None
    raw = "\n".join(lines[:8])
    for line in lines:
        low = line.lower()
        if "ac power" in low:
            source = "ac"
        elif "battery power" in low:
            source = "battery"
        if "internalbattery" in low.replace(" ", "") or "internalbattery" in low:
            m = re.search(r"(\d+)%", line)
            if m:
                try:
                    # Clamped like ups_svc: ``(\d+)`` bounds the charset, not
                    # the length, and ``int()`` of a >4300-digit pmset percent
                    # is ValueError (CPython's str->int cap).  It used to null
                    # the whole UPS leg of GET /api/settings/power through
                    # get_power_info's fan-out.
                    percent = max(0, min(100, int(m.group(1))))
                except ValueError:
                    percent = None
            charging = "charging" in low and "not charging" not in low
            present = "present: true" in low
    return {
        "source": source,
        "on_ac": source == "ac",
        "battery_percent": percent,
        "charging": charging,
        "battery_present": present,
        "raw": raw,
        "hint": "Without an external UPS a Mac reports its internal battery / AC power; with an APC UPS you can install apcupsd.",
    }


def _pmset_settings() -> dict:
    rc, out, _ = sh(["/usr/bin/pmset", "-g"], timeout=5)
    settings: dict = {}
    if rc == 0:
        for line in _as_text(out).splitlines():
            line = line.strip()
            if not line or line.startswith("System-wide") or line.startswith("Currently"):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0].isalpha():
                key = parts[0]
                val = parts[1]
                try:
                    if val.isdigit():
                        settings[key] = int(val)
                    else:
                        settings[key] = val
                except Exception:
                    settings[key] = val
    return settings


#: Assertion lines handed to the page.  This was 12, which a plain desktop
#: already reaches -- a remote screen-sharing session plus one `caffeinate`
#: accounts for 9 -- and the truncation was silent, so the assertion an operator
#: is hunting ("what is keeping this NAS awake?") could be the one dropped.  The
#: panel renders these in a scrolling block, so a low cap bought nothing; keep a
#: bound against a pathological `pmset` and report the real count beside it.
MAX_ASSERTIONS = 40


def _pmset_assertions() -> list[str]:
    sleep_prevented_by: list[str] = []
    rc, out, _ = sh(["/usr/bin/pmset", "-g", "assertions"], timeout=5)
    if rc == 0:
        for line in _as_text(out).splitlines():
            if "pid " in line and "named:" in line:
                sleep_prevented_by.append(line.strip()[:160])
            if "sleep prevented by" in line.lower():
                sleep_prevented_by.append(line.strip())
    return sleep_prevented_by


@ttl_memo(5.0)
def get_power_info() -> dict:
    """Power management snapshot (pmset).

    Two `pmset` reads and the UPS probe answer unrelated questions; the settings
    dump says nothing about what is currently holding the machine awake.

    Memoised briefly because the Settings bundle wants it twice -- once directly and
    once through :func:`get_disk_settings` for the disk-sleep value -- so one
    ``/api/settings/system`` read ran all three ``pmset`` commands twice. The TTL is
    short rather than matching the bundle's 25s: this is also the whole payload of
    ``/api/settings/power``, and an operator who has just changed a setting should not
    wait out a long cache. :func:`set_power_pref` drops it explicitly, because after
    changing pmset the re-read must see the new value and not the memo.
    """
    def _safe(item):
        probe, fallback = item
        try:
            return probe()
        except Exception:
            return fallback

    settings, sleep_prevented_by, ups = fan_out(
        _safe,
        [
            (_pmset_settings, {}),
            (_pmset_assertions, []),
            (get_ups_info, {"source": "unknown", "on_ac": False}),
        ],
        max_workers=3,
    )
    cleaned = _json_tree({
        "settings": settings,
        "displaysleep": settings.get("displaysleep"),
        "disksleep": settings.get("disksleep"),
        "sleep": settings.get("sleep"),
        "womp": settings.get("womp"),
        "lowpowermode": settings.get("lowpowermode"),
        "assertions": sleep_prevented_by[:MAX_ASSERTIONS],
        "assertion_count": len(sleep_prevented_by),
        "ups": ups,
        "hint": "disksleep=0 means disks never sleep (common for a home NAS). Changing pmset may require sudo.",
    })
    return cleaned if isinstance(cleaned, dict) else {}


def set_power_pref(key: str, value: int) -> dict:
    """Best-effort pmset -a KEY VALUE (may need sudo)."""
    key = (key or "").strip()
    allowed = {
        "disksleep", "displaysleep", "sleep", "womp", "powernap",
        "networkoversleep", "ttyskeepawake", "lowpowermode",
    }
    if key not in allowed:
        return soft_fail("power.bad_key", key=key)
    try:
        value = int(value)
    except (TypeError, ValueError, OverflowError):
        return soft_fail("power.bad_value")
    if value < 0 or value > 180:
        return soft_fail("power.value_range")
    rc, out, err = sh([power_svc.PMSET, "-a", key, str(value)], timeout=8)
    if rc != 0:
        if power_svc._pmset_missing(rc, err):
            # A vanished pmset used to answer ok:false with a message telling
            # the operator to run ``sudo pmset -a`` by hand — blaming
            # privileges for a binary the disk confirm just proved is gone
            # (the sudo fallback below cannot spawn it either).  Coded 503
            # like set_wol; the sentinel alone never classifies, and the disk
            # probe runs on this failure path only.
            raise api_error("power.pmset_missing")
        rc, out, err = sh(["/usr/bin/sudo", "-n", power_svc.PMSET, "-a", key, str(value)], timeout=8)
    msg = _as_text(out) or _as_text(err)
    if rc != 0:
        msg = (msg or "failed") + f" · run manually: sudo pmset -a {key} {value}"
    # Bust the caches so the UI sees the new pmset values. Order matters: the return
    # value below re-reads get_power_info(), and without dropping its memo first that
    # read would report the setting as it was before this call changed it.
    get_power_info.invalidate()
    unraid_settings_bundle.invalidate()
    return {"ok": rc == 0, "key": key, "value": value, "message": msg or "applied", "power": get_power_info()}


def _storage_snapshot() -> tuple[dict, list]:
    try:
        from hub import storage_svc
        st = storage_svc.collect_storage(force=False)
        smart = (st.get("system") or {}).get("smart") or st.get("smart") or {}
        return smart, st.get("disks") or []
    except Exception:
        return {}, []


def _power_disks() -> list:
    try:
        from hub import disk_power_svc
        return disk_power_svc.list_power_disks()
    except Exception:
        return []


def get_disk_settings() -> dict:
    """Disk-related settings summary for Settings page.

    Three independent reads, each of which is a page payload in its own right:
    the pmset snapshot, the storage inventory and the per-disk power states. Each
    absorbs its own failure, as it did serially -- a missing storage module left
    the disk list empty rather than failing the settings page.
    """
    try:
        power, storage, power_disks = fan_out(
            lambda probe: probe(),
            [get_power_info, _storage_snapshot, _power_disks],
            max_workers=3,
        )
    except Exception:
        power, storage, power_disks = {}, ({}, []), []
    # _as_map, not the bare isinstance gate: a leftover dict-*subclass*
    # power snapshot with a bombing ``.get`` passed the gate and raised on
    # the disksleep read — a raw 500 on GET /api/settings/disk.
    power = _as_map(power)
    if isinstance(storage, (tuple, list)) and len(storage) >= 2:
        smart, disks = storage[0], storage[1]
    else:
        smart, disks = {}, []
    if not isinstance(disks, list):
        disks = []
    if not isinstance(power_disks, list):
        power_disks = []
    rows = []
    for d in power_disks[:20]:
        # _isa: a class-bomb row used to blow the gate itself and 500
        # GET /api/settings/disk before the laundering ever ran.
        if not _isa(d, dict):
            continue
        # Launder each row: a power-disk row that is a dict subclass with a
        # bombing ``.get`` (the jobs/metrics row-bomb class) used to raise
        # out of the field reads below and 500 GET /api/settings/disk.
        # _mapping_get on the field reads: a hash-shadowing "id"/"name" key
        # survives the plain-dict copy and used to detonate the C-level
        # compare under the laundered ``.get`` — the same 500.
        d = _as_map(d)
        rows.append({
            "id": _json_atom(_mapping_get(d, "id")),
            "name": _json_atom(_mapping_get(d, "name")) or _json_atom(_mapping_get(d, "id")),
            "power_state": _json_atom(_mapping_get(d, "power_state")),
            "size_gb": _finite_number(_mapping_get(d, "size_gb")),
        })
    cleaned = _json_tree({
        # ``smart`` used to pass through raw — the one section of this
        # payload the sanitizer never touched.  A leftover ``\ud800`` /
        # over-cap int / non-UTF-8 bytes / items()-bomb subclass inside the
        # SMART snapshot 500'd GET /api/settings/disk while the same data
        # rendered fine inside the bundle (which _json_tree's everything).
        "disksleep_minutes": _finite_number(_mapping_get(power, "disksleep")),
        "smart": smart,
        "disk_count": len(disks) or len(power_disks),
        "power_disks": rows,
        "hint": "Sleep / wake HDDs from the Storage Array page; this adjusts the system disksleep policy.",
    })
    return cleaned if isinstance(cleaned, dict) else {}


def _panel_update_snapshot() -> dict:
    """Cached GitHub panel version.  Never fetches; never raises."""
    try:
        from hub.tools_svc import github_update_status
        snap = github_update_status(fetch=False, checkout=False)
    except Exception:
        return {}
    return snap if isinstance(snap, dict) else {}


def get_management_access() -> dict:
    """Unraid Management Access style summary."""
    # The old ``cfg().get("settings") or {}`` read was dead (nothing below
    # consumed it) and reflected into a leftover dict-subclass ``.get`` /
    # ``__bool__`` bomb — degrading this whole section of the Settings
    # bundle to an error row.
    auth = settings_section("auth")
    # _mapping_get: a hash-shadowing key in the stored auth section used to
    # detonate the bare ``.get`` reads and degrade this whole section.
    username = _json_atom(_mapping_get(auth, "username"))
    if not isinstance(username, str) or not username:
        username = "admin"
    # leftover ``\ud800`` in host_ip() / configured_host() used to 500
    # GET /api/settings/system and the Management Access tile.
    cleaned = _json_tree({
        "panel_port": 8086,
        "auth_enabled": _truthy(_mapping_get(auth, "enabled")),
        "allow_localhost": _json_bool(_mapping_get(auth, "allow_localhost", True), True),
        "username": username,
        "host_ip": host_ip(),
        "host_ip_config": configured_host(),
        "ssl_via_nginx": True,
        "nginx_https": f"https://{host_ip()}:8281",
        "export_yaml": "/api/export/services-yaml",
        "version": __version__,
        "panel_update": _panel_update_snapshot(),
        "paths": {
            "base": str(BASE),
            "services_yaml": str(CONFIG_FILE),
            "data": str(DATA_DIR),
        },
    })
    return cleaned if isinstance(cleaned, dict) else {}


def get_share_globals() -> dict:
    """SMB/share-ish globals (macOS file sharing status)."""
    rc, out, _ = sh(["/usr/sbin/sharing", "-l"], timeout=8)
    share_count = 0
    if rc == 0:
        share_count = len(re.findall(r"name:\s+", _as_text(out), re.I))
    rc2, out2, _ = sh(["/bin/launchctl", "print", "system/com.apple.smbd"], timeout=4)
    smb_running = rc2 == 0 and "state = running" in _as_text(out2)
    return {
        "smb_running": smb_running,
        "share_count": share_count,
        "hint": "Manage shares on the Shares page; macOS File Sharing lives in System Settings → General → Sharing.",
    }


def get_thresholds() -> dict:
    s = settings_section("thresholds")
    out = dict(DEFAULT_THRESHOLDS)
    for k, v in s.items():
        # Scrub mapping keys before they become response keys: a leftover
        # ``\ud800`` YAML key blew up Starlette's UTF-8 encode, and a
        # >4300-digit int key ValueError'd the encoder's key stringify —
        # both 500'd GET /api/settings/thresholds.
        # _isa on the key gates (the _json_tree key-arm rule): a
        # ``__class__``-property bomb as a key detonated the first bare
        # isinstance itself and 500'd the route one step ahead of the scrub.
        if _isa(k, (bytes, bytearray)):
            try:
                # Unbound base decode: the old ``bytes(k)`` copy ran a
                # subclass ``__bytes__`` bomb and 500'd GET
                # /api/settings/thresholds and /other.  The try is for a
                # lying ``__class__`` (claims bytes, is not): the entry
                # drops, its siblings stay.
                k = (bytes if isinstance(k, bytes) else bytearray).decode(
                    k, "utf-8", "replace",
                )
            except Exception:
                continue
        elif not _isa(k, str):
            try:
                k = str(k)
            except Exception:
                continue
        k = _utf8_text(k)
        if not k or v is None:
            continue
        if k in ("enabled", "smart_enabled"):
            # type-is, not isinstance: a class-bomb value detonated the
            # gate and a bool-liar rode raw into the payload.
            if type(v) is bool:
                out[k] = v
            continue
        n = _finite_number(v)
        if n is not None:
            out[k] = n
    return out


def get_other_settings() -> dict:
    """Unraid Other Settings + OMV-style toggles."""
    # _settings_map, not ``cfg().get("settings") or {}``: a leftover config
    # root / settings map that is a dict subclass with a bombing ``.get`` /
    # ``__bool__`` used to 500 GET /api/settings/other on the very first
    # read (the json5 bomb class, already laundered in settings_api).
    s = _settings_map()
    alias = settings_section("ip_aliases")
    # _mapping_get on every stored read: the section maps are plain-dict
    # copies but a leftover *hash-shadowing* key inside them (same hash as
    # "ips"/"adaptive"/…, raising ``__eq__``) survived the laundering copy
    # and detonated the C-level compare under a bare ``.get`` — a raw 500
    # on GET /api/settings/other.
    ips = _mapping_get(alias, "ips")
    clean_ips = []
    # _isa: a class-bomb ips value used to blow the gate itself.
    if _isa(ips, list):
        try:
            items = list(ips)
        except Exception:
            # A list *subclass* whose __iter__ raises passes the isinstance
            # gate; iterating it 500'd GET /api/settings/other.
            items = []
        for item in items:
            text = _json_atom(item)
            if isinstance(text, str) and text:
                clean_ips.append(text)
    netmask = _json_atom(_mapping_get(alias, "netmask")) or "255.255.255.255"
    if not isinstance(netmask, str):
        netmask = "255.255.255.255"
    # _as_text first, then membership: the raw tuple compare gave a
    # str-subclass ``__eq__`` bomb (and any non-str leftover's reflected
    # ``__eq__``) priority — a raw 500 where every sibling degraded fine.
    resource_mode = _as_text(_mapping_get(s, "resource_mode"))
    return {
        "adaptive": _json_bool(_mapping_get(s, "adaptive", True), True),
        "metrics_interval": _finite_number(_mapping_get(s, "metrics_interval"), 90),
        "alert_interval": _finite_number(_mapping_get(s, "alert_interval"), 90),
        "resource_mode": resource_mode if resource_mode in ("low", "high") else "low",
        "ip_aliases": {
            "auto_bind": _json_bool(_mapping_get(alias, "auto_bind", True), True),
            "prefer_wired": _json_bool(_mapping_get(alias, "prefer_wired", True), True),
            "interval": _finite_number(_mapping_get(alias, "interval"), 60),
            "ips": clean_ips,
            "netmask": netmask,
        },
        "thresholds": get_thresholds(),
        "ssd_friendly": {
            "metrics_batch": True,
            "alert_write_if_changed": True,
            "yaml_bak_keep": 5,
            "hint": "Metrics are flushed in batches and alert state is written only on change, reducing SSD wear",
        },
        "hint": "Advanced toggles: adaptive discovery, IP aliases, resource thresholds, sampling intervals",
    }


def _first_truthy(mapping: dict, *keys):
    """First truthy ``mapping[key]``, with a leftover ``__bool__`` bomb in a
    value degrading to "not it" instead of raising out of the ``or`` chain.

    _mapping_get, not a bare ``.get``: the rows are laundered plain dicts
    but a hash-shadowing key (same hash as "label"/"interval"/…, raising
    ``__eq__``) survives the copy and used to detonate the C-level compare
    — a raw 500 on GET /api/settings/scheduler.
    """
    for key in keys:
        value = _mapping_get(mapping, key)
        if _truthy(value):
            return value
    return None


def get_scheduler_summary() -> dict:
    try:
        # ``list(...)`` inside the same try: a timers value that is a list
        # *subclass* whose ``__iter__``/``__getitem__``/``__len__`` bombs
        # passed the old ``or []`` and blew the slice / len below.
        from hub.tools_svc import launchd_timers
        timers = list(launchd_timers() or [])
    except Exception as e:
        # leftover ``str(e)`` RecursionError / ``\\ud800`` used to 500 GET /api/settings.
        return {"timers": [], "count": 0, "error": _as_text(e)}
    slim = []
    for t in timers[:40]:
        # _isa: a class-bomb row used to blow this gate itself and 500
        # GET /api/settings/scheduler ahead of the laundering.
        if not _isa(t, dict):
            continue
        # Launder the row: a timer row that is a dict subclass with a bombing
        # ``.get`` passed the isinstance gate and raised out of the field
        # reads — a raw 500 on GET /api/settings/scheduler.  The bare ``or``
        # chains reflected into a leftover value's own ``__bool__`` the same
        # way; _first_truthy keeps the fallback order without the dispatch.
        t = _as_map(t)
        slim.append({
            "label": _json_atom(_first_truthy(t, "label", "id", "name")),
            "interval": _finite_number(_first_truthy(t, "interval", "StartInterval")),
            "calendar": _json_tree(_first_truthy(t, "calendar", "StartCalendarInterval")),
            "path": _json_atom(_first_truthy(t, "path", "plist")),
        })
    return {
        "timers": slim,
        "count": len(timers),
        "hint": "LaunchAgents scheduled tasks",
    }


def get_vm_settings() -> dict:
    """Unraid VM Manager settings-style summary."""
    try:
        from hub import vms_svc
        data = vms_svc.list_all_vms()
        if not isinstance(data, dict):
            data = {}
        utm = data.get("utm") or data.get("utm_vms") or []
        orb = data.get("orb") or data.get("orb_machines") or []
        if not isinstance(utm, list):
            utm = []
        if not isinstance(orb, list):
            orb = []
        if isinstance(data.get("vms"), list):
            # fallback if different shape
            items = []
            for v in data["vms"]:
                if not isinstance(v, dict):
                    continue
                items.append({
                    "id": _json_atom(v.get("id")),
                    "name": _json_atom(v.get("name")),
                    "state": _json_atom(v.get("state")),
                    "backend": _json_atom(v.get("backend")),
                })
            running = sum(
                1 for v in items
                if str(v.get("state") or "").lower() in ("ok", "running", "started")
            )
            return {
                "utm_available": vms_svc._utm_available(),
                "orb_available": vms_svc._orb_available(),
                "total": len(items),
                "running": running,
                "items": items[:20],
                "hint": "Manage VMs on the Virtual Machines page",
            }
        items = []
        for v in utm:
            if not isinstance(v, dict):
                continue
            items.append({
                "id": _json_atom(v.get("id") or v.get("uuid") or v.get("name")),
                "name": _json_atom(v.get("display_name") or v.get("name")),
                "state": _json_atom(v.get("state") or v.get("status")),
                "backend": "utm",
            })
        for v in orb:
            if not isinstance(v, dict):
                continue
            items.append({
                "id": _json_atom(v.get("id") or v.get("name")),
                "name": _json_atom(v.get("display_name") or v.get("name")),
                "state": _json_atom(v.get("state") or v.get("status")),
                "backend": "orb",
            })
        running = sum(
            1 for v in items
            if str(v.get("state") or "").lower() in ("ok", "running", "started", "active")
        )
        return {
            "utm_available": vms_svc._utm_available(),
            "orb_available": vms_svc._orb_available(),
            "total": len(items),
            "running": running,
            "items": items[:20],
            "hint": "UTM + OrbStack virtual machines",
        }
    except Exception as e:
        return {"error": _as_text(e), "total": 0, "running": 0, "items": []}


def _diag_host() -> dict:
    """Interpreter and OS identity.

    Goes through ``identity_svc.platform_string`` rather than ``platform.platform()``
    so that this and the ``identity`` section beside it -- which also wants it -- share
    one answer instead of racing to shell out twice.

    Absorbs its own failure like every ``_diag_*`` sibling: this header rides
    the same fan-out as the sections, whose ``ex.map`` re-raises on iteration,
    so a raise here used to 500 the whole GET /api/diagnostics — the one
    collector in the wave without the try the module docstring promises.
    """
    try:
        from hub.identity_svc import platform_string

        return {
            "platform": _as_text(platform_string()),
            "python": _as_text(platform.python_version()),
            "hostname": _as_text(platform.node()),
        }
    except Exception as e:
        return {"platform": "", "python": "", "hostname": "", "host_error": _as_text(e)}


def _diag_identity() -> dict:
    try:
        from hub import identity_svc
        return {"identity": identity_svc.get_identity()}
    except Exception as e:
        return {"identity": {"error": _as_text(e)}}


def _diag_datetime() -> dict:
    try:
        return {"datetime": get_datetime_info()}
    except Exception as e:
        return {"datetime": {"error": _as_text(e)}}


def _diag_power() -> dict:
    """The power section, from one reading.

    ``get_power_info()`` was called twice here -- once for the body and once for the
    assertion count -- which ran ``pmset`` twice to answer one question.
    """
    try:
        info = get_power_info()
    except Exception as e:
        return {"power": {"error": _as_text(e)}}
    return {"power": {
        **{k: v for k, v in info.items() if k != "assertions"},
        "assertions_count": len(info.get("assertions") or []),
    }}


def _diag_management() -> dict:
    try:
        return {"management": get_management_access()}
    except Exception as e:
        return {"management": {"error": _as_text(e)}}


def _diag_other() -> dict:
    try:
        return {"other": get_other_settings()}
    except Exception as e:
        return {"other": {"error": _as_text(e)}}


def _diag_docker() -> dict:
    try:
        from hub import docker_info_svc
        di = docker_info_svc.engine_info()
        return {"docker": {
            "engine_up": di.get("engine_up"),
            "version": (di.get("info") or {}).get("ServerVersion"),
            "containers_running": (di.get("info") or {}).get("ContainersRunning"),
            "orb_version": di.get("orb_version"),
        }}
    except Exception as e:
        return {"docker": {"error": _as_text(e)}}


def _diag_alias_auto() -> dict:
    try:
        from hub import network_svc
        return {"alias_auto": network_svc.alias_auto_status()}
    except Exception as e:
        return {"alias_auto": {"error": _as_text(e)}}


def _diag_alerts() -> dict:
    try:
        from hub import alerts
        return {"recent_alerts": alerts.list_alerts(20)}
    except Exception:
        return {"recent_alerts": []}


def _diag_health() -> dict:
    try:
        from hub import health_svc
        return {"health": health_svc.run_checks()}
    except Exception as e:
        return {"health": {"error": _as_text(e)}}


def _diag_metrics() -> dict:
    try:
        from hub import metrics
        hist = metrics.history(30)
        latest = hist[-1] if hist else None
        return {"metrics_latest": _json_tree(latest) if isinstance(latest, dict) else None}
    except Exception:
        return {"metrics_latest": None}


def _diag_vms() -> dict:
    """Empty on failure, not ``{"vms": None}``.

    The serial version used a bare ``except: pass`` after assigning nothing, so a
    failure left the key out of the bundle entirely.  Returning ``{}`` reproduces
    that rather than inventing a null the download schema never contained.
    """
    try:
        vm = get_vm_settings()
        return {"vms": {"total": vm.get("total"), "running": vm.get("running")}}
    except Exception:
        return {}


#: The diagnostics sections, in the order they appear in the saved JSON.
_DIAG_SECTIONS = (
    _diag_identity,
    _diag_datetime,
    _diag_power,
    _diag_management,
    _diag_other,
    _diag_docker,
    _diag_alias_auto,
    _diag_alerts,
    _diag_health,
    _diag_metrics,
    _diag_vms,
)


def collect_diagnostics() -> dict:
    """Unraid Diagnostics-style snapshot (JSON, not full syslog dump).

    Eleven sections, each interrogating a different subsystem and none reading
    another's output.  Collected in turn this was the deepest serial path in the
    API -- 23 subprocesses back to back, several of them whole page payloads in
    their own right (``health_svc.run_checks``, ``docker_info_svc.engine_info``),
    so the bundle cost roughly the sum of every page it summarises.

    Every section absorbs its own failure and reports it as ``{"error": ...}`` in
    its own slot.  Four of them -- ``datetime``, ``power``, ``management``,
    ``other`` -- used not to, so a raise from any one of them failed the whole
    request.  That is the opposite of what this endpoint is for: the page offers it
    as a "download diagnostics" button, which is pressed exactly when a subsystem is
    broken, and the section that fails is usually the one the operator needs to see.
    The seven that already worked this way set the shape.

    ``fan_out`` returns results in submission order, so the saved JSON keeps its
    section order.
    """
    bundle: dict = {"generated_at": strftime_now("%Y-%m-%dT%H:%M:%S%z")}
    # `platform.platform()` is not the pure string-formatting call it looks like: on
    # macOS it shells out to `uname -p` and then `file -b` on the Python binary, and
    # both ran before the wave started, adding two serial spawns to the front of the
    # bundle. It joins the wave instead. Python memoises the result internally, so on
    # every later request this costs nothing at all.
    for section in fan_out(
        lambda probe: probe(),
        (_diag_host, *_DIAG_SECTIONS),
        max_workers=len(_DIAG_SECTIONS) + 1,
    ):
        bundle.update(section)
    cleaned = _json_tree(bundle)
    if not isinstance(cleaned, dict):
        cleaned = {}
    # Persist last diagnostics for download convenience.  Generation and
    # persistence are separate outcomes: callers can still render the in-memory
    # snapshot when the state directory is full or read-only, but must not claim
    # that a downloadable file was saved.
    saved_path, save_error = _persist_diagnostics(cleaned)
    cleaned["saved_path"] = saved_path
    cleaned["save_error"] = save_error
    return cleaned


def _persist_diagnostics(bundle: dict) -> tuple[str | None, str | None]:
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        path = DATA_DIR / "diagnostics-latest.json"
        payload = _json_tree(bundle)
        replace_bytes(
            path,
            json.dumps(
                payload, ensure_ascii=False, indent=2, default=str, allow_nan=False,
            ).encode("utf-8"),
        )
        return str(path), None
    except Exception as e:
        # Assigned onto the JSON body after ``_json_tree``; leftover ``\\ud800``
        # / RecursionError on ``str(e)`` used to 500 GET /api/diagnostics.
        return None, _as_text(e) or "save failed"


@cached_snapshot(_BUNDLE_TTL)
def unraid_settings_bundle(force: bool = False) -> dict:
    """Aggregate for Settings page (Unraid parity). Cached ~25s to avoid shell storms."""

    from hub import identity_svc, network_svc

    # Twelve independent collectors, each shelling out one to three times
    # (systemsetup, pmset, sharing, launchctl, diskutil, scutil …). They were run
    # one after another — several of them inline in the dict literal below — so
    # the Settings page paid for the whole chain in sequence on every cache miss.
    # Nothing here reads another's output, so the sequence bought nothing.
    #
    # Every collector is absorbed: `.result()` re-raises, and one wedged
    # ``pmset`` / ``systemsetup`` used to 500 the whole Settings page.
    f_identity = _pool.submit(identity_svc.get_identity)
    f_alias = _pool.submit(network_svc.alias_auto_status)
    f_shares = _pool.submit(get_share_globals)
    f_sched = _pool.submit(get_scheduler_summary)
    f_vms = _pool.submit(get_vm_settings)
    f_datetime = _pool.submit(get_datetime_info)
    f_power = _pool.submit(get_power_info)
    f_disk = _pool.submit(get_disk_settings)
    f_mgmt = _pool.submit(get_management_access)
    f_other = _pool.submit(get_other_settings)
    f_thresholds = _pool.submit(get_thresholds)

    try:
        identity = f_identity.result()
    except Exception as e:
        identity = {"error": _as_text(e)}
    try:
        alias = f_alias.result()
    except Exception:
        alias = None
    try:
        shares = f_shares.result()
    except Exception as e:
        shares = {"error": _as_text(e), "smb_running": False, "share_count": 0}
    try:
        sched = f_sched.result()
    except Exception as e:
        sched = {"timers": [], "count": 0, "error": _as_text(e)}
    try:
        vms = f_vms.result()
    except Exception as e:
        vms = {"total": 0, "running": 0, "items": [], "error": _as_text(e)}
    try:
        datetime_info = f_datetime.result()
    except Exception as e:
        datetime_info = {"error": _as_text(e)}
    try:
        power = f_power.result()
    except Exception as e:
        power = {"error": _as_text(e)}
    try:
        disk = f_disk.result()
    except Exception as e:
        disk = {"error": _as_text(e)}
    try:
        mgmt = f_mgmt.result()
    except Exception as e:
        mgmt = {"error": _as_text(e)}
    try:
        other = f_other.result()
    except Exception as e:
        other = {"error": _as_text(e)}
    try:
        thresholds = f_thresholds.result()
    except Exception as e:
        thresholds = {**DEFAULT_THRESHOLDS, "error": _as_text(e)}

    v = {
        "ts": strftime_now("%H:%M:%S"),
        "identity": identity,
        "datetime": datetime_info,
        "power": power,
        "disk": disk,
        "management": mgmt,
        "shares": shares,
        "alias_auto": alias,
        "other": other,
        "scheduler": sched,
        "vms": vms,
        "thresholds": thresholds,
        "sections": [
            {"id": "appearance", "label": "Display", "unraid": "Display Settings"},
            {"id": "identity", "label": "Identification", "unraid": "Identification"},
            {"id": "datetime", "label": "Date & Time", "unraid": "Date & Time"},
            {"id": "network", "label": "Network / Aliases", "unraid": "Network Settings"},
            {"id": "disk", "label": "Disks", "unraid": "Disk Settings"},
            {"id": "power", "label": "Power / UPS", "unraid": "UPS / Power"},
            {"id": "docker", "label": "Docker", "unraid": "Docker"},
            {"id": "vms", "label": "Virtual Machines", "unraid": "VM Manager"},
            {"id": "notify", "label": "Notifications", "unraid": "Notifications"},
            {"id": "shares", "label": "Shares", "unraid": "SMB / Shares"},
            {"id": "scheduler", "label": "Scheduler", "unraid": "Scheduler"},
            {"id": "access", "label": "Management Access", "unraid": "Management Access"},
            {"id": "advanced", "label": "Advanced", "unraid": "Other Settings"},
            {"id": "diagnostics", "label": "Diagnostics", "unraid": "Diagnostics"},
            {"id": "panel", "label": "Panel", "unraid": "User Preferences"},
        ],
        "cached_ttl": _BUNDLE_TTL,
    }
    # identity / alias_auto / exception strings used to skip the sanitizer
    # that collect_diagnostics already applies; leftover inf / ``\ud800``
    # 500'd GET /api/settings/system.
    cleaned = _json_tree(v)
    return cleaned if isinstance(cleaned, dict) else v
