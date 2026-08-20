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
        return value.decode("utf-8", "replace")
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


def _coerce_interval(interval) -> float:
    """A positive finite loop interval, even when a hand-edit passed ``90s``.

    Leftover YAML ``true`` is a bool subclass of int; ``float(True)`` is 1.0
    and used to mark the worker stale after three seconds.
    """
    if isinstance(interval, bool) or interval is None:
        return 60.0
    try:
        n = float(interval)
    except (TypeError, ValueError, OverflowError):
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
    if isinstance(raw, float) and (raw != raw or raw in (float("inf"), float("-inf"))):
        return default
    try:
        n = int(raw)
    except (TypeError, ValueError, OverflowError):
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
        _workers[str(name)] = entry


def beat(name: str) -> None:
    """Record one loop iteration.  A beat for an unregistered name is a no-op
    (the worker may have been unregistered by a concurrent ``stop_*``)."""
    with _lock:
        entry = _workers.get(str(name))
        if isinstance(entry, dict):
            entry["beat"] = _wall_now()


def unregister(name: str) -> None:
    with _lock:
        _workers.pop(str(name), None)


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
        try:
            beat = float(entry.get("beat") or 0.0)
        except (TypeError, ValueError, OverflowError):
            beat = 0.0
        if beat != beat or beat in (float("inf"), float("-inf")):
            beat = 0.0
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
    out = []
    for w in rows if rows is not None else snapshot(now):
        if not isinstance(w, dict):
            continue
        name = _utf8_text(w.get("name") or "?")
        if not w.get("alive"):
            out.append(f"{name}: thread died")
        elif w.get("stale"):
            try:
                age = int(float(w.get("age_sec") or 0))
            except (TypeError, ValueError, OverflowError):
                age = 0
            try:
                interval = int(float(w.get("interval") or 0))
            except (TypeError, ValueError, OverflowError):
                interval = 0
            out.append(f"{name}: last tick {age}s ago (interval {interval}s)")
    return out
