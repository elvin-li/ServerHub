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

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")

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


def _isa(value, kinds) -> bool:
    """``isinstance`` that a leftover ``__class__``-property bomb cannot 500.

    ``isinstance`` consults ``value.__class__`` when the exact-type check
    misses, so a leftover whose ``__class__`` is a *raising property* —
    planted in settings.ups or a snapshot field — detonated the sanitizer
    gates themselves, one step ahead of every scrub in this module (the
    host9 identity_svc rule).  A real subclass still matches through the
    C-level type check; only a value that cannot answer what it is takes
    the non-matching branch.
    """
    try:
        return isinstance(value, kinds)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _rc_int(rc) -> int:
    """Exact exit status for the ``==`` probes; a bomb reads as failure.

    This module does not own ``sh`` (tests and tooling patch it), and an
    rc-*subclass* whose ``__eq__`` raises used to detonate the bare
    ``rc == 0`` probes in :func:`ups_snapshot` — a raw 500 on GET /api/ups
    (the host9 identity_svc rule).  ``-255`` is no honest exit status, so a
    bomb keeps the failure branch and pmset output reads as empty.
    """
    try:
        if type(rc) is bool:
            return int(rc)
        if _isa(rc, int):
            return int.__index__(rc)
        return int(rc)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return -255


def _decode_bytes(value) -> str:
    """Unbound base decode: a leftover subclass ``.decode`` bomb cannot 500."""
    for base in (bytes, bytearray):
        try:
            return base.decode(value, "utf-8", "replace")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
    try:
        return str.encode(str.__str__(value), "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""


def _sh_triple(argv, timeout: int) -> tuple:
    """The ``sh`` seam laundered to an exact ``(rc, out, err)`` shape.

    ``rc, out, _ = sh(...)`` iterates whatever the seam handed back, so a
    leftover sequence subclass whose ``__iter__`` raises, a torn two-field
    result, or a patched ``sh`` that raises outright each used to blow the
    unpack inside :func:`ups_snapshot` — a raw 500 on GET /api/ups?force=true
    one step ahead of the ``_rc_int`` guards on the fields themselves.  An
    unreadable result reads as pmset failure (no UPS is not an error), so
    the route answers ``present: false`` instead.
    """
    try:
        rc, out, err = sh(argv, timeout=timeout)
        return rc, out, err
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return -255, "", ""


def _as_text(value) -> str:
    """pmset stdout as text.  Leftover ``str()`` RecursionError used to 500 GET /api/ups."""
    # _isa, not bare isinstance: a ``__class__``-property bomb handed
    # through the sh seam used to detonate this gate itself.
    if _isa(value, str):
        try:
            # Unbound base encode: a str-subclass ``.encode`` bomb used to
            # raise out of the laundering pass itself.  The try is for a
            # *lying* ``__class__`` (claims str, is not): the unbound call
            # TypeErrors and the impostor renders like junk below.
            return str.encode(value, "utf-8", "replace").decode("utf-8")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            pass
    elif _isa(value, (bytes, bytearray)):
        try:
            # Same impostor guard: a lying ``__class__`` that claims bytes
            # TypeErrors the unbound base decode and renders as junk below.
            return _decode_bytes(value)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            pass
    elif value is None:
        return ""
    try:
        text = str(value)
    except RecursionError:
        try:
            return type(value).__name__
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return ""
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    try:
        cls = type(value)
        if cls.__str__ is object.__str__ and cls.__repr__ is object.__repr__:
            return ""
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    try:
        text = str.encode(text, "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    return "" if _ADDR_REPR_RE.search(text) else text


def _jsonable(value, depth: int = 0):
    """Drop leftovers so Starlette's allow_nan=False encoder cannot 500.

    YAML ``low_battery_pct: .inf`` / ``trigger_pct: .nan`` used to 500 GET /api/ups.
    A leftover ``name: 2026-08-19`` / ``!!binary`` / ``!!set`` still leaked
    ``datetime.date`` / bytes / set into the GET /api/ups body.
    A >4300-digit leftover int still passed through untouched: CPython's
    int->str digit limit then ValueError'd ``json.dumps`` itself.
    A *subclass* scalar still ran its own dunders through the probes: an int
    ``__str__`` bomb, a float ``__eq__`` bomb, a bytes ``decode`` bomb and a
    str ``encode`` bomb (value or key) each used to raise out of this scrub
    and 500 GET /api/ups — the hub.modules unbound-base rule.
    A leftover whose ``__class__`` is a *raising property* detonated the
    bare isinstance rank gates themselves, and a *lying* ``__class__``
    (claims bytes, is not) TypeError'd the unguarded unbound decode — each
    still a raw 500 on GET /api/ups after all of the above (the host9
    _json_tree rule), hence ``_isa`` on every gate and the guarded decode.
    """
    if depth > 32:
        return None
    # Identity, not ``_isa(value, bool)``: bool cannot be subclassed, so a
    # real flag is one of the two singletons — but a *bool-liar* (a
    # ``__class__`` property that *returns* bool on a plain object) passed
    # the old gate and rode out of this scrub as itself, straight into
    # Starlette's ``json.dumps`` for a 500 on GET /api/ups.  The liar now
    # falls to the int rank below, where the unbound base coercion refuses
    # it and it drops like any other unrenderable.
    if value is None or type(value) is bool:
        return value
    if _isa(value, int):
        if type(value) is not int:
            try:
                # Base coercion to an exact int: a subclass ``__str__``
                # bomb used to blow the digit-cap probe below.
                value = int.__index__(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return None
        try:
            str(value)
        except ValueError:
            # Past CPython's int->str digit cap the encoder cannot render
            # the number at all — same drop as its inf float sibling.
            return None
        return value
    if _isa(value, float):
        if type(value) is not float:
            try:
                # Base coercion to an exact float: a subclass ``__eq__``
                # bomb used to blow the NaN/inf probes below.
                value = float.__float__(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return None
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if _isa(value, str):
        # str() then unbound base encode: a str-subclass ``encode`` bomb
        # used to raise out of the surrogate laundering itself.
        try:
            value = str(value)
            return str.encode(value, "utf-8", "replace").decode("utf-8")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
    if _isa(value, (bytes, bytearray)):
        try:
            return _decode_bytes(value)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # A lying ``__class__`` (claims bytes, is not) TypeErrors the
            # unbound decode: junk drops like any other unrenderable.
            return None
    if _isa(value, dict):
        try:
            items = list(value.items())
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # A mapping that refuses iteration (odd dict subclass): there is
            # nothing to salvage from it, but its *siblings* must survive —
            # pre-fix this raised out of ups_status()'s scrub and 500'd
            # GET /api/ups (the nginx_svc._jsonable rule).
            return None
        out = {}
        for pair in items:
            # Per-pair unpack guard: a torn non-pair row from a subclass
            # ``items()`` used to ValueError out of the loop head and 500
            # GET /api/ups with every sane sibling pair.
            try:
                k, v = pair
            except _CONTROL_FLOW:
                raise
            except BaseException:
                continue
            if _isa(k, (bytes, bytearray)):
                try:
                    k = _decode_bytes(k)
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    # A lying ``__class__`` key TypeErrors the unbound
                    # decode; it renders through str() below instead.
                    pass
            elif not _isa(k, str):
                try:
                    k = str(k)
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    continue
            # A str *key* skipped the string sanitizer: a leftover lone
            # surrogate in a settings key used to 500 Starlette's UTF-8
            # encode of GET /api/ups — and a str-subclass key whose
            # ``encode`` raises blew the laundering itself, so both go
            # through str() + the unbound base encode.
            try:
                k = str(k)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                continue
            try:
                k = str.encode(k, "utf-8", "replace").decode("utf-8")
            except _CONTROL_FLOW:
                raise
            except BaseException:
                continue
            out[k] = _jsonable(v, depth + 1)
        return out
    if _isa(value, (list, tuple, set, frozenset)):
        try:
            return [_jsonable(v, depth + 1) for v in value]
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # Same class as the mapping above, at sequence rank: only this
            # field drops, never the row or the route.
            return None
    try:
        iso = getattr(value, "isoformat", None)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # getattr's default only swallows AttributeError; a property or
        # ``__getattr__`` bomb still raised out of the probe itself.
        iso = None
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/ups.
            return _jsonable(iso(), depth + 1)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            pass
    try:
        return _as_text(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
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
    _isa, not bare isinstance: a ``__class__``-property bomb planted as the
    settings block (or as the whole config root) used to detonate this gate
    itself and 500 the same four routes at once.
    """
    if not _isa(mapping, dict):
        return None
    try:
        return mapping.get(key)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        try:
            return dict.get(mapping, key)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None


def _finite_int(raw, default: int | None):
    """``int(inf)`` OverflowError is not ValueError; leftover ``.inf`` must fall back.

    A 400-digit leftover integer is a valid ``int`` but ``float()`` OverflowError's
    it — the shutdown trigger comparison used to 500 GET /api/ups/shutdown/plan.
    A float-*subclass* ``__eq__`` bomb blew the NaN/inf probe outside the
    ``try``, and an object whose ``__int__`` raises something other than
    Type/Value/OverflowError escaped it — both used to 500 GET /api/ups
    through ``low_battery_pct`` / ``trigger_pct``.
    _isa on the rank gates: a ``__class__``-property bomb stored as the
    threshold used to detonate the first bare isinstance the same way.
    """
    if _isa(raw, bool) or raw is None:
        return default
    if _isa(raw, float):
        try:
            # Base coercion to an exact float, so the NaN/inf probe below
            # never runs a subclass ``__eq__``.
            raw = float.__float__(raw)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return default
        if raw != raw or raw in (float("inf"), float("-inf")):
            return default
    if _isa(raw, int) and type(raw) is not int:
        try:
            # Base coercion: an int subclass whose ``__int__``/``__str__``
            # raises must fall back, not 500.
            raw = int.__index__(raw)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return default
    try:
        n = int(raw)
        float(n)
        return n
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # int() runs the value's own __int__/__index__/__trunc__: a leftover
        # conversion bomb raising outside Type/Value/OverflowError is the
        # same unreadable value, never a 500.
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
    # _rc_int on both probes: an rc-subclass ``__eq__`` bomb from a patched
    # or odd ``sh`` used to detonate the bare ``rc == 0`` reads here and 500
    # GET /api/ups (the host9 identity_svc rule).  _sh_triple on both calls:
    # a torn or iteration-refusing seam result used to blow the unpack
    # itself, one step ahead of those field guards.
    rc, out, _ = _sh_triple(["/usr/bin/pmset", "-g", "batt"], timeout=5)
    snapshot = _parse_batt(out if _rc_int(rc) == 0 else "")
    if snapshot["present"]:
        rc2, out2, _ = _sh_triple(["/usr/bin/pmset", "-g", "ups"], timeout=5)
        snapshot["halt_levels"] = _parse_ups_thresholds(out2 if _rc_int(rc2) == 0 else "")
    else:
        snapshot["halt_levels"] = None
    return snapshot


def _normalized_shutdown(raw: dict | None) -> dict:
    """Stored shutdown policy -> complete dict, unknown keys dropped.

    Unlike the flat keys above, ``None`` is a *meaningful* stored value here
    (a trigger condition switched off), so only unknown keys are filtered —
    explicit nulls pass through instead of being replaced by the default.
    _isa: a ``__class__``-property bomb stored as the shutdown block used to
    detonate this gate itself instead of falling back to the defaults.
    """
    out = dict(SHUTDOWN_DEFAULTS)
    if _isa(raw, dict):
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
    # Guarded cfg(): a config root that raises on read (a dying seam or a
    # patched loader) used to escape every _mapping_get below — the call
    # itself sat outside any try — and 500 GET /api/ups, the plan/drill
    # routes and PUT /api/ups/settings all at once.  No config reads as the
    # defaults, the same degrade every other unreadable block gets.
    try:
        root = cfg()
    except Exception:
        root = None
    # _mapping_get at every rank: the ``.get`` bombs pass the isinstance
    # gates below, and this function backs four routes at once.
    settings = _mapping_get(root, "settings")
    raw = _mapping_get(settings, "ups")
    # _isa: a ``__class__``-property bomb stored as settings.ups used to
    # detonate this gate ahead of the guarded items() read below.
    if not _isa(raw, dict):
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
    snap = ups_snapshot(force=force)
    try:
        # ``{**snap}`` TypeErrors on a non-mapping (a lying ``__class__``
        # impostor from a patched seam passes no isinstance gate honestly);
        # the settings half of the payload must survive it.
        merged = {**snap} if _isa(snap, dict) else {}
    except Exception:
        merged = {}
    # Launder *before* the "settings" insert, not after: writing a str key
    # into the raw copy probes every stored key that shares its hash, so a
    # leftover hash-shadowing snapshot key (hashes like "settings", raising
    # ``__eq__``) used to detonate the bare ``merged["settings"] = ...``
    # itself and 500 GET /api/ups.  _jsonable rebuilds the mapping with
    # exact-str keys first, so the insert only ever compares honest strings.
    merged = _jsonable(merged)
    if not _isa(merged, dict):
        merged = {}
    merged["settings"] = ups_settings()
    return merged
