"""Service alert engine + optional Home Assistant notify."""
from __future__ import annotations

import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from hub import secure_io
from hub.paths import DATA_DIR
from hub.status import full_status
from hub.util import read_text_capped, safe_json_loads, strftime_now, tail_file_lines

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")

ALERTS_FILE = DATA_DIR / "alerts.jsonl"
STATE_FILE = DATA_DIR / "alert_state.json"
#: Leftover multi-MB alert_state.json used to OOM GET /api/alerts.
_STATE_CAP = 256 * 1024
MAX_ALERTS = 500
_lock = threading.Lock()
_thread: threading.Thread | None = None
_stop = threading.Event()
_appends_since_trim = 0
#: Trim gate: full read-and-rewrite at most every N appends.  Deliberately a
#: count gate rather than the time gate metrics.py/scheduler_svc.py use: this
#: journal appends 10-170 lines per *day* (measured 2026-08, quiet days vs the
#: worst alert-storm day), so 50 appends is hours-to-days between trims and the
#: file is ~130KB — the rewrite costs less than the bookkeeping to avoid it.
#: The count gate also bounds the file at MAX_ALERTS+_TRIM_EVERY lines, which
#: a pure time gate does not.  Revisit only if the append rate grows by orders
#: of magnitude.
_TRIM_EVERY = 50


def _capped_json_int(text):
    """``json.loads`` parse_int hook: an over-cap digit run drops to None.

    ``int()`` of a >4300-digit number is the digit-cap *ValueError* (not
    JSONDecodeError) for the whole document: one poisoned cooldown stamp used
    to make :func:`_load_state` return ``{}``, so every sweep saw
    ``prev={}`` — per-service history, cooldown maps and the pending set all
    gone at once — and re-announced every still-bad service, disk and
    resource condition on every pass until the file was hand-fixed.
    """
    try:
        return int(text)
    except ValueError:
        return None


def _load_state() -> dict:
    try:
        # Path.exists() only swallows ENOENT/ELOOP.  EIO/ESTALE on a dying
        # mount used to raise out of GET /api/alerts and POST /api/alerts/check.
        if not STATE_FILE.exists():
            return {}
        data = safe_json_loads(
            read_text_capped(STATE_FILE, _STATE_CAP), parse_int=_capped_json_int
        )
    except (OSError, ValueError, RecursionError):
        # RecursionError: leftover deeply-nested alert_state.json is not ValueError.
        return {}
    # A list/string leftover from a torn write used to raise
    # ``prev.get(...)`` on every sweep and silence the alerter,
    # UPS policy, and stale-runtime kickstarts for good.
    if not isinstance(data, dict):
        return {}
    # Scrub keys on load, before they become the sweep's lookup keys.
    # ``json.loads`` produces lone-surrogate keys from escaped ``"\ud800…"``
    # text; _save_state scrubs at write time, so a raw-loaded key never
    # matched what the next save wrote — the state "changed" on every sweep
    # (an SSD rewrite each pass) while the surrogate sat on disk.
    cleaned = _jsonable_alert(data)
    return cleaned if isinstance(cleaned, dict) else {}


def _save_state(st: dict):
    """Atomically publish alert state.

    A crash mid-``write_text`` used to leave an empty/partial file. The next
    sweep then saw ``prev={}``, lost cooldown maps, and re-announced every
    still-bad SMART/resource condition — exactly the SSD thrash + alert spam
    the write-if-changed path exists to prevent.
    """
    STATE_FILE.parent.mkdir(exist_ok=True)
    try:
        payload = json.dumps(
            _jsonable_alert(st) if isinstance(st, dict) else {},
            ensure_ascii=False, indent=2, allow_nan=False,
        )
    except (TypeError, ValueError, OverflowError, RecursionError):
        # RecursionError: leftover circular state after _jsonable_alert is not
        # ValueError; POST /api/alerts/check used to 500 before the OSError guard.
        return
    # replace_bytes: O_EXCL|O_NOFOLLOW tmp so a planted `{name}.{pid}.tmp`
    # symlink cannot redirect the write, then atomic replace onto the live file.
    secure_io.drop_leftover_nonfile(STATE_FILE)
    try:
        secure_io.replace_bytes(STATE_FILE, payload.encode("utf-8"))
    except FileExistsError:
        # Planted tmp symlink must surface — swallowing it used to look like a
        # quiet no-op while alert state never landed on disk.
        raise
    except OSError:
        # Leftover directory occupying alert_state.json must not 500
        # POST /api/alerts/check.
        pass


def _append_alert(alert: dict):
    global _appends_since_trim
    if not isinstance(alert, dict):
        return
    alert = _jsonable_alert(alert)
    if not isinstance(alert, dict):
        return
    alert["t"] = _alert_ts(alert.get("t"))
    ALERTS_FILE.parent.mkdir(exist_ok=True)
    try:
        line = json.dumps(alert, ensure_ascii=False, allow_nan=False) + "\n"
    except (TypeError, ValueError, OverflowError, RecursionError):
        return
    # file_lock as well as _lock: two panel processes sharing data/ (packaged
    # .app + LaunchAgent) both run this sweep, and a trim in one used to swap
    # away an alert row the other had just appended to the pre-replace inode.
    with _lock, secure_io.file_lock(ALERTS_FILE):
        # A leftover directory occupying alerts.jsonl IsADirectoryError'd
        # this append out of emit_alert (500ing the scheduler/UPS caller),
        # and a leftover FIFO parked it forever.  Drop the node so the
        # journal self-heals; a disk that still refuses loses this row,
        # never the request.
        secure_io.drop_leftover_nonfile(ALERTS_FILE)
        try:
            secure_io.append_text(
                ALERTS_FILE,
                line,
            )
        except OSError:
            return
        _appends_since_trim += 1
        if _appends_since_trim < _TRIM_EVERY:
            return
        _appends_since_trim = 0
        try:
            # errors="replace": one torn/binary write must not raise
            # UnicodeDecodeError past the OSError guard and disable trimming
            # forever; the per-line json parse skips mangled lines instead.
            lines = tail_file_lines(ALERTS_FILE, MAX_ALERTS, max_bytes=1024 * 1024)
            if len(lines) >= MAX_ALERTS:
                # Atomic trim: a crash mid-write_text used to empty the trail.
                payload = "\n".join(lines[-MAX_ALERTS:]) + "\n"
                secure_io.replace_bytes(ALERTS_FILE, payload.encode("utf-8"))
        except OSError:
            pass


def _alert_ts(raw) -> int | None:
    """Epoch for the Alerts page.  Leftover ``t: 2026-08-19`` / ``.inf``
    used to stringify and render as Invalid Date; ``t: null`` is dropped.
    """
    if isinstance(raw, bool) or raw is None:
        return None
    if isinstance(raw, int):
        if type(raw) is not int:
            try:
                # Base coercion to an exact int: an int-subclass leftover with
                # a ``__str__``/``__eq__`` bomb must not ride into the payload.
                raw = int.__index__(raw)
            except Exception:
                return None
        return raw
    if isinstance(raw, float):
        if type(raw) is not float:
            try:
                # Base coercion to an exact float: a subclass ``__eq__`` bomb
                # used to blow the NaN/inf probes below.
                raw = float.__float__(raw)
            except Exception:
                return None
        if raw != raw or raw in (float("inf"), float("-inf")):
            return None
        try:
            return int(raw)
        except OverflowError:
            return None
    if isinstance(raw, str):
        if type(raw) is not str:
            try:
                # Exact-str copy so a subclass ``strip``/``__eq__`` bomb
                # never runs on the probes below.
                raw = str.__str__(raw)
            except Exception:
                return None
        text = raw.strip()
        if text.isdigit() or (text.startswith("-") and text[1:].isdigit()):
            try:
                return int(text)
            except (ValueError, OverflowError):
                # ValueError: a >4300-digit leftover ``t`` (CPython's str->int
                # cap) — and non-ASCII digits that pass isdigit() — used to
                # 500 GET /api/alerts through list_alerts.
                return None
        return None
    return None


def _isa(value, kinds) -> bool:
    try:
        return isinstance(value, kinds)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


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


def _mapping_get(mapping, key, default=None):
    """Field read that a dict-subclass ``.get`` bomb cannot detonate.

    The ``hub.notify_channels._mapping_get`` rule, which the check feeders'
    seams never got: ``ups_svc.ups_status()``, ``metrics.latest_sample()``,
    ``system_settings_svc.get_thresholds()`` and
    ``storage_svc.smart_devices()`` hand back whatever an in-process caller
    last cached, and ``isinstance(x, dict)`` passes a subclass whose bound
    ``get`` raises.  One such wrapper used to raise out of its whole check —
    check_once's containment turned that into a *silently dead pass* (every
    disk unwatched, the UPS countdown unannounced) rather than a 500, which
    is the worst failure mode an alerting system has.  ``dict.get`` reads
    the real C-level storage underneath the override, so the sane data a
    poisoned wrapper carries still feeds the sweep.
    """
    if not _isa(mapping, dict):
        return default
    try:
        return dict.get(mapping, key, default)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        try:
            return dict.get(mapping, key, default)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return default


def _truthy(value) -> bool:
    """``bool(value)`` that survives a leftover ``__bool__`` bomb.

    The ``hub.jobs``/``hub.notify_channels`` rule: the truth tests hidden in
    ``bool(n.get("enabled"))`` / ``th.get("enabled", True)`` /
    ``st.get("settings") or {}`` used to detonate a junk stored value whose
    ``__bool__`` raises — out of :func:`emit_alert` into its callers (the
    UPS shutdown policy had already latched ENGAGED and never reached its
    stop sequence; the scheduler's guard swallowed the alert its failure
    streak had earned), and out of every ``_check_*`` pass into check_once's
    containment.  Fails closed to False — a bomb flag is junk, not consent
    to notify (or to sweep with it).
    """
    if type(value) is bool:
        return value
    try:
        return bool(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _pick(value, fallback):
    """``value or fallback`` that a leftover ``__bool__`` bomb cannot blow."""
    return value if _truthy(value) else fallback


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
    if isinstance(value, (bytes, bytearray)):
        # Unbound base decode: a bytes-subclass ``.decode`` bomb riding a
        # poisoned check row used to raise straight out of the sanitizer
        # and 500 POST /api/alerts/check.
        return _decode_bytes(value)
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


def _jsonable_alert(value, depth: int = 0):
    """Coerce leftovers so Starlette's allow_nan=False encoder cannot 500.

    Leftover YAML ``name: 2026-08-19`` / ``kind: .inf`` used to land in the
    ``check_once`` payload and 500 POST /api/alerts/check at encode time.
    A leftover ``\\ud800`` in alerts.jsonl still 500'd GET /api/alerts.

    Probes run on the *base* types (the modules5 unbound convention): a
    subclass ``items()`` / ``__iter__`` / ``__str__`` / ``__eq__`` /
    ``decode`` bomb, or a raising ``isoformat`` property, riding a row one
    of the check feeders (ups_policy.sweep, freshness_svc.check_freshness,
    stale_runtime.remediate) handed back used to raise out of this very
    sanitizer in ``check_once``'s final sweep — the one spot no try/except
    covers — and 500 POST /api/alerts/check.
    """
    if depth > 32:
        return None
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, float):
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
    if isinstance(value, dict):
        out = {}
        # Unbound base view: a dict-subclass ``items()`` bomb cannot 500,
        # and the real entries in its C-level storage still walk.
        for k, v in dict.items(value):
            if not isinstance(k, str):
                # str() probe, not an isinstance gate: the gate silently
                # dropped every numeric YAML/plist key (``123: …``) from the
                # journal and the saved state.  An over-cap hex/octal int key
                # loads uncapped and its str() *is* the digit-cap ValueError —
                # drop just that entry, never the dict (or the route).
                try:
                    k = str(k)
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    continue
            out[_utf8_text(k)] = _jsonable_alert(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        for base in (list, tuple, set, frozenset):
            if isinstance(value, base):
                # Unbound base iteration: a subclass ``__iter__`` bomb
                # cannot 500 and the real elements still survive.
                return [_jsonable_alert(v, depth + 1) for v in base.__iter__(value)]
    if isinstance(value, str):
        return _utf8_text(value)
    if isinstance(value, int):
        if type(value) is not int:
            try:
                # Base coercion to an exact int: a subclass ``__str__`` bomb
                # raising anything but ValueError escaped the digit-cap
                # probe below and 500'd the route.
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
    if isinstance(value, (bytes, bytearray)):
        return _decode_bytes(value)
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
            # used to skip the float sanitizer and 500 GET /api/alerts.
            return _jsonable_alert(iso(), depth + 1)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
    try:
        return _utf8_text(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None


def _service_id(raw) -> str:
    """Service id for the sweep, via the str() probe.

    services.yaml is hand-editable, so ``id: 123`` arrives as an *int*.  The
    strict ``isinstance(id, str)`` gate this replaces silently dropped the
    row from the sweep: the service could go down without ever alerting, and
    its saved per-service history vanished from alert_state.json.  YAML hex
    (``id: 0xFF…``) loads uncapped (``int(x, 16)`` is exempt from CPython's
    4300-digit conversion limit), so a bare ``str()`` on it *is* the
    digit-cap ValueError — such a row has no renderable id and is dropped,
    not the sweep.  Lists/None/bool stay dropped: an unhashable leftover
    ``id: [foo]`` used to TypeError ``services[sid]``.
    """
    if isinstance(raw, str):
        if type(raw) is str:
            return raw
        try:
            # Exact-str copy: a str-subclass id whose ``__hash__``/``__eq__``
            # raises used to detonate the ``services[sid]`` dict insert.
            return str.__str__(raw)
        except Exception:
            return ""
    if isinstance(raw, bool) or not isinstance(raw, int):
        return ""
    if type(raw) is not int:
        try:
            # Base coercion first: an int-subclass ``__str__`` bomb raising
            # anything but ValueError escaped the digit-cap catch below.
            raw = int.__index__(raw)
        except Exception:
            return ""
    try:
        return str(raw)
    except ValueError:
        return ""


def list_alerts(limit: int = 50) -> list:
    try:
        n = max(1, min(int(limit), MAX_ALERTS))
    except (TypeError, ValueError, OverflowError):
        n = 50
    try:
        if not ALERTS_FILE.exists():
            return []
        # Tail rather than slurp: ``lines[-limit:]`` after a full read loaded
        # the whole journal, and ``limit=0`` is ``[-0:]`` — the entire file.
        lines = [ln for ln in tail_file_lines(ALERTS_FILE, n) if ln.strip()]
    except OSError:
        return []
    out = []
    for ln in lines:
        try:
            parsed = safe_json_loads(ln)
        except (ValueError, RecursionError):
            # ValueError, not just JSONDecodeError: a leftover >4300-digit
            # number raises CPython's str->int digit-cap ValueError out of
            # json.loads, which used to 500 GET /api/alerts on that line.
            continue
        if isinstance(parsed, dict):
            row = _jsonable_alert(parsed)
            if isinstance(row, dict):
                row["t"] = _alert_ts(row.get("t"))
                out.append(row)
    out.reverse()
    return out


def notify_settings() -> dict:
    """Effective notify settings for the alert call sites below.

    The raw ``settings.notify`` dict, with the global enabled/include_warn/
    notify_resolve flags widened when explicit notify channels exist — those
    gates now mean "does any channel want this"; the per-channel routing
    happens inside notify_channels.dispatch().  Pure-legacy configs pass
    through unchanged.
    """
    from hub.config import settings_section
    # Try-wrapped: settings_section's own ``isinstance`` gate runs a leftover
    # section's ``__class__`` property, so a bomb planted as the whole
    # ``settings.notify`` value used to raise out of this read into every
    # caller — emit_alert (the UPS shutdown policy and scheduler entry) and
    # each per-check sweep's ``n = notify_settings()`` line.  A section that
    # cannot answer what it is reads as unconfigured; when it returns at all
    # it is already a plain dict copy.
    try:
        raw = settings_section("notify")
    except Exception:
        raw = {}
    if not isinstance(raw, dict):
        raw = {}
    try:
        from hub import notify_channels
        return notify_channels.effective_settings(raw)
    except Exception:
        return raw


def _http_url_ok(url: str) -> bool:
    """Only http(s) outbound.  The notify URL is admin-set, but without a scheme
    check the server would happily POST to file://, gopher://, ftp:// etc. —
    turning a self-config field into a broader SSRF primitive than intended."""
    try:
        scheme = urllib.parse.urlsplit(url).scheme.lower()
    except ValueError:
        return False
    return scheme in ("http", "https")


def send_ha_notify(title: str, message: str, *, level: str | None = None,
                   event: str | None = None) -> dict:
    """Send a notification through every configured channel.

    Historically this spoke only to Home Assistant; it now delegates to
    hub.notify_channels, which treats the legacy ``settings.notify`` HA
    config as an implicit channel — old installs keep working unchanged —
    and additionally routes to the explicit multi-channel list by level.
    Name and (title, message) signature are kept so the call sites in this
    module and existing tests stay untouched; ``level``/``event`` are
    optional routing hints the channels use for min_level filtering.
    """
    from hub import notify_channels
    return notify_channels.dispatch(title, message, level=level, event=event)


def emit_alert(*, kind: str, level: str, alert_id: str, message: str,
               title: str = "ServerHub scheduled task",
               event: str = "problem") -> dict:
    """Record one alert and notify through the configured channels.

    Public entry for modules outside the sweep loop (the scheduler engine's
    consecutive-failure alerts, the UPS shutdown policy's trigger/reset
    events).  Mirrors what the checks above do per event: append to
    alerts.jsonl, then hand the text to send_ha_notify, whose per-channel
    min_level routing decides who actually hears about it.  The global
    enabled/include_warn/notify_resolve gates are honoured the same way the
    sweep-loop alerts honour them: ``down`` always notifies, a resolved
    ``ok`` follows notify_resolve, everything else follows include_warn.
    """
    alert = {
        "t": _as_epoch(time.time()),
        "level": level,
        "kind": kind,
        "id": alert_id,
        # Same shape as the sweep-loop alerts above: the Alerts page renders
        # a.name and a.event, and records missing them drew blank cells.
        # _pick, not ``or``: a leftover title wearing a ``__bool__`` bomb
        # used to raise before the alert was even recorded.
        "name": _pick(title, alert_id),
        "event": event,
        "message": message,
    }
    _append_alert(alert)
    n = notify_settings()
    # _truthy/_mapping_get, not bool()/bare ``.get``: a ``__bool__`` bomb
    # flag (or a dict-subclass ``.get`` bomb section) used to raise out of
    # this public entry into its callers — the UPS shutdown policy had
    # already latched ENGAGED and never reached its stop sequence, and the
    # scheduler's containment swallowed the alert its failure streak had
    # earned.  The journal row above always lands; junk flags fail closed.
    if level == "down":
        wanted = _truthy(_mapping_get(n, "enabled"))
    elif event == "resolved":
        wanted = _truthy(_mapping_get(n, "enabled")) and _truthy(
            _mapping_get(n, "notify_resolve", True))
    else:
        wanted = _truthy(_mapping_get(n, "enabled")) and _truthy(
            _mapping_get(n, "include_warn", True))
    if wanted:
        try:
            send_ha_notify(title, message, level=level, event=event if event != "problem" else None)
        except Exception:
            # Notification failure must not propagate into the caller's thread.
            pass
    return alert


def _resource_thresholds() -> dict:
    from hub.system_settings_svc import get_thresholds
    return get_thresholds()


def _check_resource_thresholds(prev: dict, new_state: dict, now: int) -> list:
    """OMV/TrueNAS-style CPU/mem/disk threshold alerts with cooldown."""
    th = _resource_thresholds()
    # _truthy/_mapping_get, not bare ``.get``/truth tests: a leftover
    # thresholds wrapper that is a dict subclass with a bombing ``get`` —
    # or an ``enabled`` flag whose ``__bool__`` raises — used to raise out
    # of this pass into check_once's containment, silently losing every
    # resource alert for the sweep.
    if not _truthy(_mapping_get(th, "enabled", True)):
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
    if not isinstance(latest, dict):
        return []
    # _mapping_get: the cached sample is whatever the metrics thread last
    # stored, and a dict-subclass ``.get`` bomb wrapper used to kill the
    # pass while its real readings sat intact in the C-level storage.
    cpu_val = _mapping_get(latest, "cpu_used_pct")
    if cpu_val is None:
        cpu_val = _mapping_get(latest, "load_pct")
    checks = [
        ("cpu", cpu_val, _mapping_get(th, "cpu_pct", 90), "CPU"),
        ("mem", _mapping_get(latest, "mem_used_pct"), _mapping_get(th, "mem_pct", 90), "Memory"),
        ("disk", _mapping_get(latest, "disk_pct"), _mapping_get(th, "disk_pct", 90), "Disk"),
    ]
    # _as_epoch/_pick, not ``int(... or 1800)``: an int-subclass cooldown
    # whose ``__str__``/``__index__`` raises a non-ValueError — or a
    # ``__bool__`` bomb under the ``or`` — escaped the old enumerated net.
    cooldown = _as_epoch(_pick(_mapping_get(th, "cooldown_sec"), 1800), 1800)
    last_fire = prev.get("_resource_last") or {}
    if not isinstance(last_fire, dict):
        last_fire = {}
    new_last = dict(last_fire)
    n = notify_settings()
    #: CPU on this host hovers 88–100% during agent / brew work.  Without a
    #: gap, 90% trips and 89.6% (rendered "90%") resolves every few minutes,
    #: and a resolve resets the cooldown so the next spike re-alerts.
    hysteresis = 5.0
    for rid, val, limit, label in checks:
        if val is None or limit is None:
            continue
        try:
            val_f = float(val)
            limit_f = float(limit)
        except Exception:
            # Leftover ``cpu_used_pct: 10**10000`` OverflowError'd the sweep
            # (``int too large to convert to float`` is not ValueError).
            # Exception, not the enumerated trio: ``float()`` dispatches into
            # a subclass value's own ``__float__``, and a bomb there raised
            # RuntimeError past the old net — dropping every check after the
            # poisoned one from the pass.
            continue
        if (
            val_f != val_f or limit_f != limit_f
            or val_f in (float("inf"), float("-inf"))
            or limit_f in (float("inf"), float("-inf"))
        ):
            # ``float(inf)`` succeeds and used to emit "CPU usage inf%".
            continue
        key = f"resource:{rid}"
        over = val_f >= limit_f
        recovered = val_f <= (limit_f - hysteresis)
        old = prev.get(key)
        last_t = _as_epoch(last_fire.get(rid))
        if over and old != "warn" and (now - last_t) < cooldown:
            # Still inside the last alert's quiet window: a 100→70→100
            # flap must not reprint.  Keep the recovered state.
            new_state[key] = old or "ok"
            continue
        if over:
            new_state[key] = "warn"
        elif old == "warn" and not recovered:
            new_state[key] = "warn"
        else:
            new_state[key] = "ok"
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
            # _truthy: a ``__bool__`` bomb notify flag must read as junk
            # (no send), never abort the rest of the resource pass.
            if _truthy(_mapping_get(n, "enabled")) and _truthy(
                    _mapping_get(n, "include_warn", True)):
                send_ha_notify("ServerHub resource alert", alert["message"], level="warn")
        elif old == "warn" and recovered:
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
            if _truthy(_mapping_get(n, "enabled")) and _truthy(
                    _mapping_get(n, "notify_resolve", True)):
                send_ha_notify("ServerHub resource recovered", alert["message"],
                               level="ok", event="resolved")
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


def _format_alert(template: str, **kw) -> str:
    """Fill an alert template without letting leftover values 500 the sweep.

    ``str.format`` parses only the template, so a model named ``SSD {990}`` is
    fine as a *value*.  A numeric spec (``{v:.0f}``) applied to a non-number
    leftover — or a template field the caller forgot — used to raise and abort
    the whole SMART pass (the sweep catches it, so the disk just goes silent).
    """
    try:
        return _utf8_text(template.format(**kw))
    except Exception:
        # Exception, not an enumerated tuple: ``str.format`` dispatches into
        # each value's own ``__format__``/``__str__``, and a subclass bomb
        # there raises whatever it likes (a RuntimeError escaped the old
        # KeyError/IndexError/ValueError/TypeError/RecursionError/
        # OverflowError list and aborted the SMART pass).
        out = template
        for key, val in kw.items():
            try:
                token = "{" + _utf8_text(key)
            except Exception:
                continue
            start = 0
            pieces: list[str] = []
            while True:
                idx = out.find(token, start)
                if idx < 0:
                    pieces.append(out[start:])
                    break
                end = out.find("}", idx)
                if end < 0:
                    pieces.append(out[start:])
                    break
                pieces.append(out[start:idx])
                pieces.append(_utf8_text(val))
                start = end + 1
            out = "".join(pieces)
        return _utf8_text(out)


def _smart_reason(kind: str, **kw) -> tuple[str, str]:
    """One tripped check, rendered both ways from the same values."""
    detail, sentence = _SMART_REASON_TEXT[kind]
    return _format_alert(detail, **kw), _format_alert(sentence, **kw)


def _as_epoch(raw, default: int = 0) -> int:
    """Cooldown stamps from alert_state.json; garbage must not raise."""
    if isinstance(raw, bool) or raw is None:
        return default
    if isinstance(raw, int):
        if type(raw) is not int:
            try:
                # Base coercion to an exact int: a subclass arithmetic/compare
                # bomb must not ride into the cooldown math.
                raw = int.__index__(raw)
            except Exception:
                return default
        return raw
    if isinstance(raw, float):
        if type(raw) is not float:
            try:
                # Base coercion to an exact float: a subclass ``__eq__`` bomb
                # (a leftover patched ``time.time`` included) used to blow the
                # NaN/inf probes below.
                raw = float.__float__(raw)
            except Exception:
                return default
        if raw != raw or raw in (float("inf"), float("-inf")):
            return default
        try:
            return int(raw)
        except (OverflowError, ValueError):
            return default
    if isinstance(raw, str):
        if type(raw) is not str:
            try:
                raw = str.__str__(raw)
            except Exception:
                return default
        text = raw.strip()
        if not text:
            return default
        try:
            return int(text)
        except ValueError:
            try:
                return _as_epoch(float(text), default)
            except ValueError:
                return default
    return default


_SMART_TEMP_READING = re.compile(r"^temp=\d+C")


def _stable_smart_token(token: str) -> str:
    """The dedup form of one reason token: strip readings that wobble.

    The temperature clause embeds the live reading (``temp=69C≥60C``), and a
    disk hovering at its threshold re-renders it 69→70→69 on every 10-minute
    SMART refresh.  Comparing the rendered string treated each degree as
    "growth", so the repeat suppression re-fired on every refresh — the
    2026-08-13 22:26–23:26 alert storm in alerts.jsonl is seven copies of the
    same warn differing only in that number.  Counters (reallocated / pending /
    media errors / wear / spare) keep their value: growth there *is* the news.
    """
    return _SMART_TEMP_READING.sub("temp", token)


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
        if isinstance(raw, int) and type(raw) is not int:
            try:
                # Base coercion first: an int-subclass ``__float__``/``__index__``
                # bomb riding a cached smart row used to raise out of float()
                # and silently abort the whole SMART pass.
                raw = int.__index__(raw)
            except Exception:
                return None
        elif isinstance(raw, float) and type(raw) is not float:
            try:
                raw = float.__float__(raw)
            except Exception:
                return None
        try:
            val = float(raw)
        except OverflowError:
            # Leftover ``10**400`` OverflowError'd the SMART pass (``int`` too
            # large to convert to float is not ValueError).  Inf/NaN used to
            # render as "media errors=inf" after ``float(inf)`` succeeded.
            return None
        if val != val or val in (float("inf"), float("-inf")):
            return None
        return val
    # _utf8_text, not bare str(): a subclass ``__str__`` bomb (or an over-cap
    # int hiding behind one) used to raise here and kill the SMART pass.
    s = _utf8_text(raw).strip()
    if not s:
        return None
    low = s.lower()
    # The NVMe critical-warning bitmap is printed in hex.  A decimal-digit scan
    # would read "0x02" (spare below threshold) as 0 and silently drop the warning.
    if low.startswith("0x"):
        try:
            return float(int(low, 16))
        except (ValueError, OverflowError):
            return None
    # A few smartctl counters are printed with thousands separators ("1,234").
    m = _NUM_RE.search(s.replace(",", ""))
    if not m:
        return None
    try:
        val = float(m.group(0))
    except (ValueError, OverflowError):
        return None
    if val != val or val in (float("inf"), float("-inf")):
        return None
    return val


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
    # _mapping_get/_pick, not bare ``.get``/``or``: a dev row (or its smart
    # dict) that is a dict subclass with a bombing ``get`` — or a field whose
    # ``__bool__`` raises under the ``or`` — used to abort the SMART pass.
    smart = _pick(_mapping_get(dev, "smart"), {})
    if not isinstance(smart, dict):
        smart = {}
    # _utf8_text, not bare str(): a leftover over-cap plist/YAML-hex int
    # serial/model/size (uncapped ``int(x, 16)`` load) made str() raise the
    # digit-cap ValueError and silently aborted the whole SMART pass — every
    # disk went unwatched.  Unrenderable fields coerce to "" and the next
    # fallback identity is used instead.
    serial = _utf8_text(_pick(_mapping_get(smart, "serial"), "")).strip()
    model = _utf8_text(
        _pick(_mapping_get(smart, "model"), _pick(_mapping_get(dev, "name"), ""))
    ).strip()
    size_text = _utf8_text(_pick(_mapping_get(dev, "size_bytes"), "")).strip()
    disk_id = _utf8_text(_pick(_mapping_get(dev, "id"), "disk")).strip() or "disk"
    if serial:
        raw = serial
    elif model and size_text:
        raw = f"{model}-{size_text}"
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
    # _utf8_text: a leftover over-cap int verdict must not raise str()'s
    # digit-cap ValueError out of the pass (it coerces to "" — unknown).
    # _mapping_get/_pick: a smart dict wearing a ``.get`` bomb, or a verdict
    # wearing a ``__bool__`` bomb, used to abort the pass the same way.
    health = _utf8_text(_pick(_mapping_get(smart, "health"), "")).strip()
    if health and health.upper().rstrip("!") not in ("PASSED", "OK"):
        down.append(_smart_reason("health", v=health))

    # NVMe media and data integrity errors: the controller could not deliver data it
    # was asked for.  Any non-zero value is already data loss, hence the implicit >0.
    #
    # `pending` is the ATA equivalent that genuinely is urgent at 1: a pending sector
    # is one the drive tried to read, could not, and has not remapped yet -- the data
    # in it is unreadable *now*.
    for field in ("media_errors", "pending"):
        val = _smart_num(_mapping_get(smart, field))
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
    attrs = _mapping_get(smart, "attrs")
    if not isinstance(attrs, list):
        attrs = []
    # Unbound base iteration: a list-subclass ``__iter__`` bomb attrs table
    # cannot abort the pass, and its real rows still walk.
    for attr in list.__iter__(attrs):
        # _utf8_text, not bare str(): a subclass ``__str__`` bomb type — and
        # the exact-str copy keeps a subclass ``__eq__`` bomb off the compare.
        if not isinstance(attr, dict) or _utf8_text(
                _pick(_mapping_get(attr, "type"), "")) != "Pre-fail":
            continue
        value = _smart_num(_mapping_get(attr, "value"))
        thresh = _smart_num(_mapping_get(attr, "thresh"))
        # A threshold of 0 means the vendor declared no failure point for this
        # attribute, so there is nothing to be below.
        if value is None or thresh is None or thresh <= 0:
            continue
        if value <= thresh:
            # _utf8_text: an over-cap int attribute name used to raise the
            # digit-cap ValueError out of str() and abort the SMART pass.
            down.append(_smart_reason(
                "prefail",
                name=_utf8_text(
                    _pick(_mapping_get(attr, "name"),
                          _pick(_mapping_get(attr, "id"), "?"))
                ) or "?",
                v=value, lim=thresh,
            ))

    # Reallocated sectors: real information, but not an emergency by itself.  The
    # drive has already moved the data and, on an SSD with a large over-provisioning
    # pool, a few dozen is unremarkable.  What matters is growth, and the pre-fail
    # check above is what fires when the vendor decides the margin is gone.
    realloc = _smart_num(_mapping_get(smart, "reallocated"))
    if realloc is not None and realloc > 0:
        warn.append(_smart_reason("reallocated", v=realloc))

    # NVMe critical warning bitmap: any bit set means the controller is reporting a
    # fault (spare exhausted, degraded reliability, read-only mode, over temperature).
    crit_raw = _utf8_text(_pick(_mapping_get(smart, "critical_warning"), "")).strip()
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
        val = _smart_num(_mapping_get(smart, source))
        lim = _smart_num(_mapping_get(th, limit_key))
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
    # _truthy/_mapping_get: a thresholds wrapper wearing a ``.get`` bomb, or
    # a flag wearing a ``__bool__`` bomb, used to kill the whole SMART pass.
    if not _truthy(_mapping_get(th, "smart_enabled", True)):
        return []
    try:
        from hub import storage_svc
        devices = storage_svc.smart_devices()
    except Exception:
        return []
    if not isinstance(devices, list):
        devices = []

    cooldown = _as_epoch(_pick(_mapping_get(th, "cooldown_sec"), 1800), 1800)
    last_fire = prev.get("_smart_last")
    if not isinstance(last_fire, dict):
        last_fire = {}
    new_last = dict(last_fire)
    last_details = prev.get("_smart_detail")
    if not isinstance(last_details, dict):
        last_details = {}
    new_details = dict(last_details)
    n = notify_settings()
    emitted: list = []

    # Unbound base iteration: a list-subclass ``__iter__``/``__bool__`` bomb
    # snapshot cannot kill the pass, and its real rows still walk.
    for dev in list.__iter__(devices):
        if not isinstance(dev, dict):
            continue
        smart = _mapping_get(dev, "smart")
        # dict.__len__ / _truthy: a smart dict whose ``__bool__`` raises, or
        # an ``error`` flag wearing one, used to abort the pass mid-loop.
        if (not isinstance(smart, dict) or not dict.__len__(smart)
                or _truthy(_mapping_get(dev, "error"))):
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
        last_t = _as_epoch(last_fire.get(key))
        # _utf8_text with the key as last resort: a leftover over-cap int
        # model/device made bare str() raise the digit-cap ValueError and
        # silently killed the whole SMART pass (see _smart_key).
        model = _utf8_text(
            _pick(_mapping_get(smart, "model"),
                  _pick(_mapping_get(dev, "name"),
                        _pick(_mapping_get(dev, "id"), key)))
        ).strip() or key
        device = _utf8_text(_pick(_mapping_get(dev, "device"), "")).strip()
        # /dev/diskN is useless as an identity (see _smart_key) but is exactly what
        # an operator needs to find the disk right now, so it belongs in the prose.
        label = f"{model} {device}".strip()
        name = _format_alert(_SMART_ALERT_TEXT["name"], model=model)

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
            #
            # Warn-level counters (reallocated=55 on a PASSED drive) are
            # informational.  Re-announcing the same number every cooldown
            # writes alerts.jsonl + state and trains the operator to ignore
            # disk alerts.  Re-fire warn only when the detail changes
            # (growth).  ``down`` still uses the cooldown so a dying disk
            # does not go quiet after the first ping.
            detail = " · ".join(d for d, _ in reasons)
            # Compared in stable form: the operator sees the live temperature,
            # the dedup must not (see _stable_smart_token).  And "grew" means a
            # token appeared or changed — a reason *disappearing* (temperature
            # dropping back under its threshold) is an improvement and must not
            # re-fire either.
            stable_tokens = [_stable_smart_token(d) for d, _ in reasons]
            new_details[key] = " · ".join(stable_tokens)
            prev_tokens = set(str(last_details.get(key) or "").split(" · "))
            # Missing stamp is not growth: first-seen fires via `old != level`,
            # and a freshly upgraded state file must not re-siren a known warn.
            grew = key in last_details and any(
                t not in prev_tokens for t in stable_tokens
            )
            fatal = level == "down"
            if old != level or grew or (fatal and (now - last_t) >= cooldown):
                title, template = _SMART_ALERT_TEXT[level]
                message = _format_alert(
                    template, label=label, body="; ".join(s for _, s in reasons)
                )
                alert = {
                    "t": now,
                    "id": sid,
                    "name": name,
                    "kind": "smart",
                    "group": "storage",
                    "level": level,
                    "event": "problem",
                    "detail": detail,
                    "message": message,
                }
                _append_alert(alert)
                emitted.append(alert)
                new_last[key] = now
                # Gate by level, not by include_warn alone.  include_warn means
                # "also push the warn-level chatter" and ships false on real
                # installs; a disk that is failing is not chatter, so `down` follows
                # `enabled` only, exactly like the service down alerts above.
                if _truthy(_mapping_get(n, "enabled")) and (
                        level == "down"
                        or _truthy(_mapping_get(n, "include_warn"))):
                    send_ha_notify(title, message, level=level)
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
                "message": _format_alert(template, label=label),
            }
            _append_alert(alert)
            emitted.append(alert)
            # Drop the cooldown stamp with the alert it belonged to, so the map does
            # not accumulate an entry per disk ever seen.
            new_last.pop(key, None)
            new_details.pop(key, None)
            if _truthy(_mapping_get(n, "enabled")) and _truthy(
                    _mapping_get(n, "notify_resolve", True)):
                send_ha_notify(title, alert["message"], level="ok", event="resolved")

    new_state["_smart_last"] = new_last
    new_state["_smart_detail"] = new_details
    return emitted


# --- UPS / battery power -------------------------------------------------------

def _check_ups(prev: dict, new_state: dict, now: int) -> list:
    """Power-loss / low-battery / power-restored alerts, pmset-backed.

    Same state-machine shape as _check_smart_health: edge-triggered on the
    stored state, resolve clears it.  Two independent keys — ``ups:power``
    (on battery at all, always ``down``: a NAS on battery is on a countdown)
    and ``ups:battery`` (charge at or below the configured floor while on
    battery).  Low battery clears silently when power returns; the restored
    alert already tells that story, and a second "resolved" ping for the
    same recovery would be noise.

    First sight counts: like a failing disk and unlike a service, a machine
    that boots on battery must alert even with a fresh state file.
    Reads the 30s-cached snapshot, so most sweeps cost nothing; no UPS (or
    a probe failure) tracks nothing rather than alerting on the unknown.
    """
    try:
        from hub import ups_svc
        st = ups_svc.ups_status()
    except Exception:
        return []
    # _mapping_get/_truthy/_pick, not bare ``.get``/``or``/bool(): the 30s
    # snapshot is whatever an in-process caller last cached, and a
    # dict-subclass ``.get`` bomb wrapper — or a ``present``/``on_battery``
    # flag wearing a ``__bool__`` bomb — used to raise out of this pass into
    # check_once's containment: the power-loss countdown went unannounced
    # while the real readings sat intact in the C-level storage.
    if not isinstance(st, dict) or not _truthy(_mapping_get(st, "present")):
        return []
    settings = _pick(_mapping_get(st, "settings"), {})
    if not isinstance(settings, dict):
        settings = {}
    if not _truthy(_mapping_get(settings, "alerts_enabled", True)):
        return []

    emitted: list = []
    n = notify_settings()
    # _utf8_text: a leftover over-cap int name made bare str() raise the
    # digit-cap ValueError and silently disabled every UPS alert.
    name = _utf8_text(_pick(_mapping_get(st, "name"), "UPS")) or "UPS"
    pct = _mapping_get(st, "battery_percent")
    try:
        pct_f = None if pct is None or isinstance(pct, bool) else float(pct)
    except Exception:
        # Exception, not the enumerated trio: ``float()`` dispatches into a
        # subclass value's own ``__float__``, and a bomb there escaped the
        # old net and killed the pass.
        pct_f = None
    if pct_f is not None:
        # _utf8_text, not a bare f-string: a pct wearing a ``__str__`` bomb
        # used to blow the detail render after float() had already succeeded.
        pct_text = (_utf8_text(pct).strip() or f"{pct_f:g}") + "%"
    else:
        pct_text = "unknown charge"
    on_battery = _truthy(_mapping_get(st, "on_battery"))

    key = "ups:power"
    level = "down" if on_battery else "ok"
    new_state[key] = level
    old = prev.get(key)
    if level == "down" and old != "down":
        alert = {
            "t": now,
            "id": key,
            "name": f"UPS · {name}",
            "kind": "ups",
            "group": "power",
            "level": "down",
            "event": "problem",
            "detail": f"on battery · {pct_text}",
            "message": f"Power lost: {name} is running on battery ({pct_text})",
        }
        _append_alert(alert)
        emitted.append(alert)
        if _truthy(_mapping_get(n, "enabled")):
            send_ha_notify("ServerHub UPS alert", alert["message"], level="down")
    elif level == "ok" and old == "down":
        alert = {
            "t": now,
            "id": key,
            "name": f"UPS · {name}",
            "kind": "ups",
            "group": "power",
            "level": "ok",
            "event": "resolved",
            "detail": f"on AC · {pct_text}",
            "message": f"Power restored: {name} is back on AC ({pct_text})",
        }
        _append_alert(alert)
        emitted.append(alert)
        if _truthy(_mapping_get(n, "enabled")) and _truthy(
                _mapping_get(n, "notify_resolve", True)):
            send_ha_notify("ServerHub UPS recovered", alert["message"],
                           level="ok", event="resolved")

    try:
        floor = float(_pick(_mapping_get(settings, "low_battery_pct"), 20))
    except Exception:
        # Exception, not the enumerated trio: a subclass ``__float__`` bomb
        # floor escaped the old net and killed the pass.
        floor = 20.0
    low = on_battery and pct_f is not None and pct_f <= floor
    key2 = "ups:battery"
    new_state[key2] = "down" if low else "ok"
    if low and prev.get(key2) != "down":
        alert = {
            "t": now,
            "id": key2,
            "name": f"UPS · {name}",
            "kind": "ups",
            "group": "power",
            "level": "down",
            "event": "problem",
            "detail": f"battery {pct_text} ≤ {floor:.0f}%",
            "message": (
                f"UPS battery low: {name} at {pct_text} "
                f"(threshold {floor:.0f}%) — shut down or restore power soon"
            ),
        }
        _append_alert(alert)
        emitted.append(alert)
        if _truthy(_mapping_get(n, "enabled")):
            send_ha_notify("ServerHub UPS alert", alert["message"], level="down")
    return emitted


def _service_transition_alerts(
    prev: dict, new_state: dict, services: dict, now: int,
) -> list:
    """Page on a confirmed down/warn, not on a one-sweep flicker.

    KeepAlive launchd jobs (OneDrive Share) vanish from ``launchctl list``
    for one alert tick after a panel kickstart or their own bounce, then
    come back ``ok`` before the next 90s sweep.  Firing on the first
    ``ok → down`` trained the operator to ignore the journal.

    First bad sweep is held in ``_service_pending``.  Still bad on the
    next sweep → problem.  Back to ok before that → silent on both sides,
    because we never announced the fault.
    """
    pending = new_state.get("_service_pending")
    if not isinstance(pending, dict):
        pending = {}
        new_state["_service_pending"] = pending
    emitted: list = []

    def _fire(alert: dict, *, notify_title: str, notify_ok: bool) -> None:
        _append_alert(alert)
        emitted.append(alert)
        n = notify_settings()
        # _truthy/_mapping_get: a ``__bool__`` bomb enabled flag used to
        # raise here and drop every service transition after this one.
        if _truthy(_mapping_get(n, "enabled")) and notify_ok:
            extra = {"event": "resolved"} if alert["event"] == "resolved" else {}
            send_ha_notify(
                notify_title, alert["message"], level=alert["level"], **extra,
            )

    if not isinstance(services, dict):
        return emitted
    for sid, s in services.items():
        if not isinstance(s, dict):
            continue
        state = s.get("state", "unknown")
        new_state[sid] = state
        old = prev.get(sid)
        if old is None:
            pending.pop(sid, None)
            continue
        # The f-strings below run str() on these fields.  A leftover YAML-hex
        # over-cap int ``name``/``detail`` (uncapped ``int(x, 16)`` load) made
        # that str() raise the digit-cap ValueError mid-loop, silently
        # aborting the rest of the service sweep — every service after the
        # poisoned one lost its alert and its saved state for that pass.
        name_text = _utf8_text(s.get("name") or sid) or sid
        detail_text = _utf8_text(s.get("detail") or "")
        if state in ("down", "warn"):
            if old not in ("down", "warn") and sid not in pending:
                pending[sid] = 1
                continue
            if sid in pending:
                pending.pop(sid, None)
            elif state == old:
                continue
            alert = {
                "t": now,
                "id": sid,
                "name": s.get("name", sid),
                "kind": s.get("kind"),
                "group": s.get("group"),
                "level": state,
                "event": "problem",
                "detail": s.get("detail", ""),
                "message": f"{name_text} changed to {state}: {detail_text}",
            }
            _fire(
                alert,
                notify_title="ServerHub alert",
                # _truthy/_mapping_get: a bomb include_warn value used to
                # detonate the ``or`` / the ``and`` truth test in _fire.
                notify_ok=(state == "down" or _truthy(
                    _mapping_get(notify_settings(), "include_warn"))),
            )
        elif old in ("down", "warn") and state == "ok":
            if pending.pop(sid, None):
                continue
            alert = {
                "t": now,
                "id": sid,
                "name": s.get("name", sid),
                "kind": s.get("kind"),
                "group": s.get("group"),
                "level": "ok",
                "event": "resolved",
                "detail": s.get("detail", ""),
                "message": f"{name_text} has recovered",
            }
            _fire(
                alert,
                notify_title="ServerHub recovered",
                notify_ok=_truthy(
                    _mapping_get(notify_settings(), "notify_resolve", True)),
            )
        else:
            pending.pop(sid, None)
    return emitted


def check_once(force_status: bool = False) -> list:
    """Emit alerts on transition to down/warn and recovery.

    SSD-friendly: reuses status cache; only rewrites alert_state.json when changed.
    """
    st = full_status(force=force_status)
    prev = _load_state()
    services = {}
    groups = st.get("groups") if isinstance(st, dict) else None
    if not isinstance(groups, list):
        groups = []
    for g in groups:
        if not isinstance(g, dict):
            continue
        rows = g.get("services")
        if not isinstance(rows, list):
            continue
        for s in rows:
            # Status still groups a leftover ``id: [foo]`` / ``id: .inf``.
            # Using that as a dict key TypeError'd POST /api/alerts/check,
            # and an inf id leaked into the emitted JSON (allow_nan=False).
            # _service_id, not an ``isinstance(sid, str)`` gate: a numeric
            # YAML ``id: 123`` was silently dropped from the sweep — the
            # service could go down without ever alerting.
            if not isinstance(s, dict):
                continue
            sid = _service_id(s.get("id"))
            if sid:
                services[sid] = s
    # ``int(time.time())`` OverflowError on leftover inf used to 500
    # POST /api/alerts/check before any check's try/except ran.
    now = _as_epoch(time.time())
    emitted = []
    new_state = {}
    # `new_state` is rebuilt from scratch every sweep, so any bookkeeping sub-dict
    # that is not copied across here is silently lost.  That is not a hypothetical:
    # a cooldown map dropped each round resets its own debounce, so a still-bad
    # resource or disk gets re-announced on every single sweep (every 300s on a real
    # install) instead of once per cooldown.  The cooldown maps and the
    # service-pending set are carried before the checks run, so they also
    # survive a check raising halfway through.
    if isinstance(prev.get("_resource_last"), dict):
        new_state["_resource_last"] = prev["_resource_last"]
    if isinstance(prev.get("_smart_last"), dict):
        new_state["_smart_last"] = prev["_smart_last"]
    if isinstance(prev.get("_smart_detail"), dict):
        new_state["_smart_detail"] = prev["_smart_detail"]
    if isinstance(prev.get("_freshness_last"), dict):
        new_state["_freshness_last"] = prev["_freshness_last"]
    if isinstance(prev.get("_service_pending"), dict):
        new_state["_service_pending"] = dict(prev["_service_pending"])
    try:
        emitted.extend(_service_transition_alerts(prev, new_state, services, now))
    except Exception:
        pass
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
    try:
        emitted.extend(_check_ups(prev, new_state, now))
    except Exception:
        pass
    # UPS safe-shutdown policy (hub/ups_policy.py): decides on the same
    # 30s-cached snapshot _check_ups just read, keeps its latch in its own
    # persisted file (not alert_state.json — it must survive independently of
    # this sweep's state), and runs every slow action on a worker thread, so
    # this tick costs the sweep nothing.  Same containment rule as the other
    # checks: a policy bug must not kill the alerter thread.
    try:
        from hub import ups_policy
        emitted.extend(ups_policy.sweep(now))
    except Exception:
        pass
    # Artifact freshness for daily launchd jobs — catches "loaded but never
    # firing", the failure class the service sweep above is blind to (see
    # hub/freshness_svc.py for the 2026-08-10 incident this guards against).
    try:
        from hub import freshness_svc
        emitted.extend(freshness_svc.check_freshness(prev, new_state, now))
    except Exception:
        pass
    # Homebrew python upgrades leave KeepAlive PIDs running on a deleted
    # Cellar path; TCP still answers so the service sweep above stays green.
    # Health checks are side-effect free — kickstart lives here, like
    # ups_policy, and a bug must not kill the alerter thread.
    try:
        from hub import stale_runtime
        emitted.extend(stale_runtime.remediate(now))
    except Exception:
        pass
    # Only rewrite state file when map actually changed (huge SSD win)
    if new_state != prev:
        try:
            _save_state(new_state)
        except (OSError, TypeError, ValueError):
            pass
    # Non-dict leftovers (inf / a YAML date / !!binary / !!set) used to
    # skip sanitization and 500 POST /api/alerts/check at encode time.
    return [_jsonable_alert(a) for a in emitted]


def _loop(interval: int = 90):
    from hub import worker_health
    worker_health.register("alert-engine", interval)
    try:
        st = full_status(force=False)
        baseline = {}
        for g in st.get("groups") or []:
            if not isinstance(g, dict):
                continue
            for s in g.get("services") or []:
                if not isinstance(s, dict):
                    continue
                # Same str() probe as check_once: a numeric YAML ``id: 123``
                # must seed the baseline under the key the sweep will use.
                sid = _service_id(s.get("id"))
                if sid:
                    baseline[sid] = s.get("state")
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
            worker_health.beat("alert-engine")
            # Prefer cache; force at most occasionally via TTL
            check_once(force_status=False)
        except Exception:
            pass
        _stop.wait(interval)


def start_alerter(interval: int = 90):
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop.clear()
    from hub.worker_health import loop_interval
    _thread = threading.Thread(
        target=_loop, args=(loop_interval(interval),), daemon=True, name="alert-engine"
    )
    _thread.start()


def stop_alerter(timeout: float = 3.0) -> None:
    """Stop the alert worker cleanly during app shutdown/reload."""
    global _thread
    _stop.set()
    # A deliberately stopped worker must not be reported as a dead one.
    from hub import worker_health
    worker_health.unregister("alert-engine")
    thread = _thread
    if thread and thread.is_alive() and thread is not threading.current_thread():
        thread.join(timeout=timeout)
    _thread = None


def test_notify() -> dict:
    return send_ha_notify(
        "ServerHub test",
        f"Notification channel test {strftime_now('%H:%M:%S')}",
        event="test",
    )
