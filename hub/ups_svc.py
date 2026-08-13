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


def _parse_batt(text: str) -> dict:
    """One pmset -g batt dump -> power-source + device fields.

    Handles the three shapes this command takes: a desktop with no battery
    (one "Now drawing from" line), a MacBook (``-InternalBattery-0 …``) and
    an external UPS (``-APC Back-UPS ES 750 …`` with source ``'UPS Power'``).
    """
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
            remaining_min = int(m.group(1)) * 60 + int(m.group(2))

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
    for line in (text or "").splitlines():
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
        out.update({k: v for k, v in raw.items() if k in SHUTDOWN_DEFAULTS})
    return out


def ups_settings() -> dict:
    raw = (cfg().get("settings") or {}).get("ups") or {}
    out = dict(UPS_DEFAULTS)
    out.update({
        k: v for k, v in raw.items()
        if k in UPS_DEFAULTS and k != "shutdown" and v is not None
    })
    out["shutdown"] = _normalized_shutdown(raw.get("shutdown"))
    return out


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
    return {**ups_snapshot(force=force), "settings": ups_settings()}
