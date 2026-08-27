"""Liveness registry for the panel's long-lived worker threads.

Every core background subsystem here is a daemon thread running a loop —
metrics sampler, alert engine, cron scheduler, SMART test scheduler.  A
daemon thread that dies is the worst failure mode this process has: nothing
restarts it, nothing logs it after the fact, and the panel keeps answering
requests while alerts silently stop firing or metrics silently stop
recording.  The loops themselves guard their bodies, but "the loop is
guarded" is an invariant only tests enforce; this registry makes the runtime
state observable so the health page can report a dead or wedged worker.

Usage, from inside the worker thread:

    worker_health.register("alert-engine", interval)   # loop start
    worker_health.beat("alert-engine")                 # once per iteration

and from the matching ``stop_*`` function:

    worker_health.unregister("alert-engine")           # a stopped worker is
                                                       # not a dead worker

The health check (hub/health_svc.py) calls :func:`problems`, which reports a
worker whose thread is no longer alive, or whose last beat is older than
``interval * STALE_AFTER`` — a loop that is alive but wedged (e.g. blocked
forever on something that escaped every timeout) stops beating and turns
stale.  Deliberately dependency-free: dict + monotonic-ish wall clock, no
subprocesses, no locks held while doing anything slow, so a health probe can
never be the thing that hurts the workers it watches.
"""
from __future__ import annotations

import threading
import time

#: A worker is reported stale when its last beat is older than this many
#: multiples of its own loop interval.  3x tolerates one slow tick and one
#: missed tick before alarming, which keeps the check quiet on a loaded host.
STALE_AFTER = 3.0

_lock = threading.Lock()
_workers: dict[str, dict] = {}


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
    if isinstance(value, (bytes, bytearray)):
        # Unbound base decode: a subclass ``.decode`` bomb registered as a
        # worker name used to raise out of snapshot() and silently wipe the
        # workers row from the health page.
        base = bytes if isinstance(value, bytes) else bytearray
        return base.decode(value, "utf-8", "replace")
    try:
        text = str(value)
    except RecursionError:
        try:
            return type(value).__name__
        except Exception:
            return ""
    except Exception:
        return ""
    # Unbound ``str.encode`` (the modules6 rule): ``str(x)`` of a subclass
    # whose ``__str__`` answers *self* skips CPython's exact-str copy, so a
    # bound ``encode`` bomb rode this scrub out of snapshot()/problems().
    return str.encode(text, "utf-8", "replace").decode("utf-8")


def _coerce_interval(interval) -> float:
    """A positive finite loop interval, even when a hand-edit passed ``90s``.

    Leftover YAML ``true`` is a bool subclass of int; ``float(True)`` is 1.0
    and used to mark the worker stale after three seconds.
    """
    if isinstance(interval, bool) or interval is None:
        return 60.0
    try:
        # Base coercions before ``float()`` (the smart_test_svc._schedule_epoch
        # rule): a numeric-subclass ``__float__``/``__index__`` bomb raised
        # RuntimeError past the old arithmetic trio — out of register() on the
        # worker's own thread, and out of snapshot() where it silently wiped
        # the workers row from GET /api/health/checks.
        if isinstance(interval, int):
            interval = int.__index__(interval)
        elif isinstance(interval, float):
            interval = float.__float__(interval)
        n = float(interval)
    except Exception:
        n = 60.0
    if n != n or n in (float("inf"), float("-inf")) or n <= 0:
        n = 60.0
    n = max(1.0, n)
    prod = n * STALE_AFTER
    if prod != prod or prod in (float("inf"), float("-inf")):
        n = 60.0
    return n


def loop_interval(raw, default: int = 90, *, minimum: int = 30, maximum: int = 86400) -> int:
    """Positive seconds for ``Event.wait`` / ``int(interval)`` on the start path.

    YAML leftover ``.inf`` / ``1e308`` / ``true`` / ``!!binary`` used to
    OverflowError ``int(inf)`` on the LaunchAgent thread (sampler / alerter)
    or kill the SMART scheduler on ``stop.wait(check_interval)``.
    """
    if isinstance(raw, bool) or raw is None:
        return default
    try:
        # Base coercions first (the _coerce_interval rule): a float-subclass
        # ``__eq__`` bomb used to blow the NaN probe below, and an
        # int-subclass ``__int__`` bomb blew ``int(raw)`` — both raised on
        # the sampler/alerter/scheduler start path instead of answering the
        # default interval.
        if isinstance(raw, int):
            raw = int.__index__(raw)
        elif isinstance(raw, float):
            raw = float.__float__(raw)
        if isinstance(raw, float) and (raw != raw or raw in (float("inf"), float("-inf"))):
            return default
        n = int(raw)
    except Exception:
        return default
    if n <= 0 or n > maximum:
        return default
    return n if n >= minimum else minimum


def _wall_now() -> float:
    """Finite wall clock. Leftover ``time.time() = inf`` used to poison health age math."""
    try:
        n = float(time.time())
    except (TypeError, ValueError, OverflowError):
        return 0.0
    if n != n or n in (float("inf"), float("-inf")) or abs(n) > 1e18:
        return 0.0
    return n


def _finite_beat(raw) -> float:
    """Finite beat timestamp from an entry this walk may not own.

    beat() only ever writes ``_wall_now()``, but tests and tooling plant
    entries directly, and a numeric-subclass ``__bool__``/``__float__`` bomb
    used to blow the old ``raw or 0.0`` / ``float(raw)`` past the arithmetic
    trio — snapshot() raised and the workers row silently vanished from
    GET /api/health/checks (the health7 wipe class, one field over).
    """
    if isinstance(raw, bool) or raw is None:
        return 0.0
    try:
        if isinstance(raw, int):
            raw = int.__index__(raw)
        elif isinstance(raw, float):
            raw = float.__float__(raw)
        beat = float(raw)
    except Exception:
        return 0.0
    if beat != beat or beat in (float("inf"), float("-inf")):
        return 0.0
    return beat


def _coerce_now(now) -> float:
    """Wall clock for age math; garbage / overflow must not 500 the health page."""
    if now is None:
        return _wall_now()
    try:
        n = float(now)
    except (TypeError, ValueError, OverflowError):
        return _wall_now()
    if n != n or n in (float("inf"), float("-inf")) or abs(n) > 1e18:
        return _wall_now()
    return n


def _name_key(name) -> str:
    """The registry key for *name*; a ``__str__`` bomb keys by its type.

    register(), beat() and unregister() must agree on the key, so the
    fallback is deterministic rather than "".  A bare ``str(name)`` used to
    re-raise a subclass ``__str__`` bomb out of register() on the worker's
    own thread — killing the loop this registry exists to watch.
    """
    try:
        return str(name)
    except Exception:
        try:
            return type(name).__name__
        except Exception:
            return "?"


def register(name: str, interval: float, thread: threading.Thread | None = None) -> None:
    """(Re-)register a worker; records an initial beat.

    *thread* defaults to the calling thread, which is the normal case: the
    worker loop registers itself as its first act.  Passing an explicit
    thread exists for tests, which register fakes.
    """
    entry = {
        "thread": thread if thread is not None else threading.current_thread(),
        "interval": _coerce_interval(interval),
        "beat": _wall_now(),
    }
    with _lock:
        _workers[_name_key(name)] = entry


def beat(name: str) -> None:
    """Record one loop iteration.  A beat for an unregistered name is a no-op
    (the worker may have been unregistered by a concurrent ``stop_*``)."""
    with _lock:
        entry = _workers.get(_name_key(name))
        if isinstance(entry, dict):
            entry["beat"] = _wall_now()


def unregister(name: str) -> None:
    with _lock:
        _workers.pop(_name_key(name), None)


def snapshot(now: float | None = None) -> list[dict]:
    """State of every registered worker, sorted by name."""
    now_f = _coerce_now(now)
    with _lock:
        items = []
        for name, entry in _workers.items():
            if isinstance(entry, dict):
                items.append((name, dict(entry)))
    out = []
    for name, entry in sorted(items, key=lambda kv: str(kv[0])):
        thread = entry.get("thread")
        try:
            alive = bool(thread is not None and thread.is_alive())
        except Exception:
            alive = False
        beat = _finite_beat(entry.get("beat"))
        interval = _coerce_interval(entry.get("interval"))
        age = max(0.0, now_f - beat)
        if age != age or age in (float("inf"), float("-inf")):
            age = 0.0
        age_sec = round(age, 1)
        if age_sec != age_sec or age_sec in (float("inf"), float("-inf")):
            age_sec = 0.0
        try:
            stale = age > interval * STALE_AFTER
        except (OverflowError, TypeError, ValueError):
            stale = True
        out.append({
            "name": _utf8_text(name),
            "alive": alive,
            "interval": interval,
            "age_sec": age_sec,
            "stale": stale,
        })
    return out


def problems(now: float | None = None, rows: list[dict] | None = None) -> list[str]:
    """Human-readable descriptions of dead or stale workers (empty = healthy).

    *rows* reuses a :func:`snapshot` already taken by the caller so health
    cannot report ``N worker threads ticking`` from one read and a dead-thread
    line from a second read that raced with unregister.
    """
    if rows is None:
        rows = snapshot(now)
    elif isinstance(rows, list):
        # Unbound base walk (the health_svc._as_checks rule): this function
        # does not own *rows*, and a list-subclass ``__iter__`` bomb used to
        # raise here and silently wipe the workers row from the health page.
        rows = list.__iter__(rows)
    else:
        try:
            rows = iter(rows)
        except Exception:
            return []
    out = []
    for w in rows:
        if not isinstance(w, dict):
            continue
        try:
            # Unbound ``dict.get`` and one Exception net per row: a
            # dict-subclass row (or a ``__bool__``-bomb field) drops alone
            # rather than costing every sibling's dead/stale report.
            name = _utf8_text(dict.get(w, "name") or "?")
            if not dict.get(w, "alive"):
                out.append(f"{name}: thread died")
            elif dict.get(w, "stale"):
                age = int(_finite_beat(dict.get(w, "age_sec")))
                interval = int(_finite_beat(dict.get(w, "interval")))
                out.append(f"{name}: last tick {age}s ago (interval {interval}s)")
        except Exception:
            continue
    return out
