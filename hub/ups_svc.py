"""UPS / battery power monitoring via pmset (macOS).

macOS recognises USB UPS units natively: ``pmset -g batt`` reports the active
power source and the UPS (or internal battery) charge state, and
``pmset -g ups`` reports the system's own emergency-shutdown thresholds.
Both are cheap reads, cached 30s and shared between the dashboard tile, the
/api/ups endpoint and the alert sweep, so none of them spawns its own
process storm.

No UPS is not an error: a Mac mini on wall power answers
``{"present": false}`` and every consumer renders "not detected".
"""
from __future__ import annotations

import re

from hub.config import cfg, update_settings
from hub.util import cached_snapshot, sh

#: Panel-level alert policy (settings.ups).  Distinct from the pmset halt
#: thresholds, which are the *system's* hard shutdown policy: the panel warns
#: first so the operator can act before macOS pulls the plug.
#: Safe-shutdown (soft landing) policy defaults — settings.ups.shutdown.
#: ``None`` for a trigger means "this condition is off"; with both off the
#: policy can never fire, which the settings API refuses to save while
#: ``enabled`` is true.  ``stacks`` is either the literal "all" or an ordered
#: list of stack ids — order is the stop order.  See hub/ups_policy.py for
#: the state machine that consumes this.
SHUTDOWN_DEFAULTS = {
    "enabled": False,
    "trigger_pct": 25,
    "trigger_remaining_min": None,
    "require_both": False,
    "stacks": "all",
    "stop_scripts": [],
}

UPS_DEFAULTS = {
    "alerts_enabled": True,
    "low_battery_pct": 20,
    "shutdown": SHUTDOWN_DEFAULTS,
}

_PCT_RE = re.compile(r"(\d{1,3})%")
#: "3:12 remaining" — pmset prints h:mm.  "(no estimate)" simply won't match.
_REMAIN_RE = re.compile(r"(\d+):(\d{2})\s+remaining")
_SOURCE_RE = re.compile(r"now drawing from\s+'([^']+)'", re.I)


def _as_text(value) -> str:
    """pmset stdout as text.  Leftover ``str()`` RecursionError used to 500 GET /api/ups."""
    if isinstance(value, str):
        text = value
    elif isinstance(value, (bytes, bytearray)):
        text = value.decode("utf-8", "replace")
    elif value is None:
        return ""
    else:
        try:
            text = str(value)
        except RecursionError:
            try:
                return type(value).__name__
            except Exception:
                return ""
        except Exception:
            return ""
    return text.encode("utf-8", "replace").decode("utf-8")


def _jsonable(value, depth: int = 0):
    """Drop leftovers so Starlette's allow_nan=False encoder cannot 500.

    YAML ``low_battery_pct: .inf`` / ``trigger_pct: .nan`` used to 500 GET /api/ups.
    A leftover ``name: 2026-08-19`` / ``!!binary`` / ``!!set`` still leaked
    ``datetime.date`` / bytes / set into the GET /api/ups body.
    A >4300-digit leftover int still passed through untouched: CPython's
    int->str digit limit then ValueError'd ``json.dumps`` itself.
    """
    if depth > 32:
        return None
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        try:
            str(value)
        except ValueError:
            # Past CPython's int->str digit cap the encoder cannot render
            # the number at all — same drop as its inf float sibling.
            return None
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if isinstance(value, str):
        return value.encode("utf-8", "replace").decode("utf-8")
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    if isinstance(value, dict):
        try:
            items = list(value.items())
        except Exception:
            # A mapping that refuses iteration (odd dict subclass): there is
            # nothing to salvage from it, but its *siblings* must survive —
            # pre-fix this raised out of ups_status()'s scrub and 500'd
            # GET /api/ups (the nginx_svc._jsonable rule).
            return None
        out = {}
        for k, v in items:
            if not isinstance(k, str):
                try:
                    k = str(k)
                except Exception:
                    continue
            # A str *key* skipped the string sanitizer: a leftover lone
            # surrogate in a settings key used to 500 Starlette's UTF-8
            # encode of GET /api/ups (the hub.errors._jsonable_param rule).
            k = k.encode("utf-8", "replace").decode("utf-8")
            out[k] = _jsonable(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        try:
            return [_jsonable(v, depth + 1) for v in value]
        except Exception:
            # Same class as the mapping above, at sequence rank: only this
            # field drops, never the row or the route.
            return None
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/ups.
            return _jsonable(iso(), depth + 1)
        except Exception:
            pass
    try:
        return str(value).encode("utf-8", "replace").decode("utf-8")
    except Exception:
        return None


def _mapping_get(mapping, key):
    """Field read that a dict-subclass ``.get`` bomb cannot 500.

    ``isinstance(x, dict)`` passes an odd subclass whose ``get`` raises (the
    disk_power_svc pool5 class): one such settings block used to raise out of
    ``ups_settings()`` and 500 GET /api/ups, GET /api/ups/shutdown/plan,
    POST /api/ups/shutdown/drill and PUT /api/ups/settings all at once, while
    the sibling ``items()`` call right next to it was already guarded.
    ``dict.get`` reads the real storage underneath the override, so a subclass
    that only poisoned its method keeps its sane data.
    """
    if not isinstance(mapping, dict):
        return None
    try:
        return mapping.get(key)
    except Exception:
        try:
            return dict.get(mapping, key)
        except Exception:
            return None


def _finite_int(raw, default: int | None):
    """``int(inf)`` OverflowError is not ValueError; leftover ``.inf`` must fall back.

    A 400-digit leftover integer is a valid ``int`` but ``float()`` OverflowError's
    it — the shutdown trigger comparison used to 500 GET /api/ups/shutdown/plan.
    """
    if isinstance(raw, bool) or raw is None:
        return default
    if isinstance(raw, float) and (raw != raw or raw in (float("inf"), float("-inf"))):
        return default
    try:
        n = int(raw)
        float(n)
        return n
    except (TypeError, ValueError, OverflowError):
        return default


def _parse_batt(text: str) -> dict:
    """One pmset -g batt dump -> power-source + device fields.

    Handles the three shapes this command takes: a desktop with no battery
    (one "Now drawing from" line), a MacBook (``-InternalBattery-0 …``) and
    an external UPS (``-APC Back-UPS ES 750 …`` with source ``'UPS Power'``).
    """
    text = _as_text(text)
    source = "unknown"
    device_name = None
    kind = None
    percent = None
    charging = None
    remaining_min = None

    for line in (text or "").splitlines():
        s = line.strip()
        if not s:
            continue
        m = _SOURCE_RE.search(s)
        if m:
            label = m.group(1).lower()
            if "ac" in label:
                source = "ac"
            elif "ups" in label:
                source = "ups"
            elif "battery" in label:
                source = "battery"
            continue
        if not s.startswith("-"):
            continue
        # Device line: "-<name> (id=…)\t85%; discharging; 3:12 remaining present: true"
        body = s[1:]
        low = body.lower()
        if "present: false" in low:
            continue
        name = body.split("(id=")[0].split("\t")[0].strip()
        # The charge details follow the first TAB (or the id parenthesis).
        m = _PCT_RE.search(body)
        if m:
            try:
                percent = max(0, min(100, int(m.group(1))))
            except ValueError:
                percent = None
        device_name = name or device_name
        kind = "internal_battery" if name.lower().startswith("internalbattery") else "ups"
        charging = ("charging" in low) and ("discharging" not in low) and ("not charging" not in low)
        m = _REMAIN_RE.search(low)
        if m:
            try:
                remaining_min = int(m.group(1)) * 60 + int(m.group(2))
                float(remaining_min)
            except (TypeError, ValueError, OverflowError):
                remaining_min = None

    # A UPS device implies UPS wall-power semantics even when pmset words the
    # source line as generic "Battery Power".
    on_battery = source in ("battery", "ups")
    return {
        "present": device_name is not None,
        "kind": kind,
        "name": device_name,
        "source": source,
        "on_ac": source == "ac",
        "on_battery": on_battery,
        "battery_percent": percent,
        "charging": charging if device_name else None,
        "time_remaining_min": remaining_min,
    }


def _parse_ups_thresholds(text: str) -> dict | None:
    """pmset -g ups -> the system's shutdown thresholds, or None when unset.

    Values of -1 mean "not configured" and are omitted, so the UI can render
    only the thresholds that actually exist.
    """
    out: dict = {}
    for line in _as_text(text).splitlines():
        parts = line.strip().split()
        if len(parts) == 2 and parts[0] in ("haltlevel", "haltafter", "haltremain"):
            try:
                value = int(parts[1])
            except ValueError:
                continue
            if value >= 0:
                out[parts[0]] = value
    return out or None


@cached_snapshot(30.0)
def ups_snapshot() -> dict:
    """Hardware state only; policy settings are merged in ups_status()."""
    rc, out, _ = sh(["/usr/bin/pmset", "-g", "batt"], timeout=5)
    snapshot = _parse_batt(out if rc == 0 else "")
    if snapshot["present"]:
        rc2, out2, _ = sh(["/usr/bin/pmset", "-g", "ups"], timeout=5)
        snapshot["halt_levels"] = _parse_ups_thresholds(out2 if rc2 == 0 else "")
    else:
        snapshot["halt_levels"] = None
    return snapshot


def _normalized_shutdown(raw: dict | None) -> dict:
    """Stored shutdown policy -> complete dict, unknown keys dropped.

    Unlike the flat keys above, ``None`` is a *meaningful* stored value here
    (a trigger condition switched off), so only unknown keys are filtered —
    explicit nulls pass through instead of being replaced by the default.
    """
    out = dict(SHUTDOWN_DEFAULTS)
    if isinstance(raw, dict):
        try:
            items = list(raw.items())
        except Exception:
            # A shutdown block that refuses iteration (odd dict subclass
            # passing the isinstance gate) used to raise out of this merge
            # and 500 GET /api/ups; the defaults are the honest degrade.
            items = []
        for pair in items:
            # Per-pair guard: ``k in SHUTDOWN_DEFAULTS`` hashes the key, so
            # one unhashable leftover key — or a torn non-pair row from a
            # subclass ``items()`` — used to raise out of the old
            # comprehension *after* the guarded materialize above and 500
            # GET /api/ups along with every sane sibling key.
            try:
                k, v = pair
                if k in SHUTDOWN_DEFAULTS:
                    out[k] = v
            except Exception:
                continue
    # Explicit null still means "condition off"; leftover inf must not leak
    # into GET /api/ups (Starlette allow_nan=False) or fire the policy.
    if out.get("trigger_pct") is not None:
        out["trigger_pct"] = _finite_int(out["trigger_pct"], None)
    if out.get("trigger_remaining_min") is not None:
        out["trigger_remaining_min"] = _finite_int(out["trigger_remaining_min"], None)
    return out


def ups_settings() -> dict:
    # _mapping_get at every rank: the ``.get`` bombs pass the isinstance
    # gates below, and this function backs four routes at once.
    settings = _mapping_get(cfg(), "settings")
    raw = _mapping_get(settings, "ups")
    if not isinstance(raw, dict):
        raw = {}
    try:
        raw_items = list(raw.items())
    except Exception:
        # settings.ups that refuses iteration: same class as the shutdown
        # block below — pre-fix the comprehension raised and 500'd
        # GET /api/ups instead of falling back to the defaults.
        raw_items = []
    out = dict(UPS_DEFAULTS)
    for pair in raw_items:
        # Per-pair guard, matching _normalized_shutdown: ``k in
        # UPS_DEFAULTS`` hashes the key, so one unhashable leftover key —
        # or a torn non-pair row from a subclass ``items()`` — used to
        # raise here and 500 GET /api/ups with every sane sibling key.
        try:
            k, v = pair
            if k in UPS_DEFAULTS and k != "shutdown" and v is not None:
                out[k] = v
        except Exception:
            continue
    if "alerts_enabled" in out:
        try:
            out["alerts_enabled"] = bool(out["alerts_enabled"])
        except Exception:
            # A __bool__ bomb value is unreadable either way; the default
            # is the honest degrade, never a 500.
            out["alerts_enabled"] = UPS_DEFAULTS["alerts_enabled"]
    if "low_battery_pct" in out:
        pct = _finite_int(out["low_battery_pct"], UPS_DEFAULTS["low_battery_pct"])
        out["low_battery_pct"] = UPS_DEFAULTS["low_battery_pct"] if pct is None else pct
    out["shutdown"] = _normalized_shutdown(_mapping_get(raw, "shutdown"))
    return _jsonable(out)


def save_ups_settings(patch: dict) -> dict:
    clean = {k: v for k, v in patch.items() if k in UPS_DEFAULTS and k != "shutdown"}
    shutdown = patch.get("shutdown")
    if isinstance(shutdown, dict):
        # Partial patch: update_settings deep-merges dicts, so only the keys
        # provided here move; lists (stacks order) are replaced wholesale.
        clean["shutdown"] = {k: v for k, v in shutdown.items() if k in SHUTDOWN_DEFAULTS}
    update_settings({"ups": clean})
    return ups_settings()


def ups_status(force: bool = False) -> dict:
    """Snapshot + policy, the shape /api/ups serves and the alert sweep reads."""
    return _jsonable({**ups_snapshot(force=force), "settings": ups_settings()})
