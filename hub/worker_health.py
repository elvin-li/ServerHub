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


def register(name: str, interval: float, thread: threading.Thread | None = None) -> None:
    """(Re-)register a worker; records an initial beat.

    *thread* defaults to the calling thread, which is the normal case: the
    worker loop registers itself as its first act.  Passing an explicit
    thread exists for tests, which register fakes.
    """
    entry = {
        "thread": thread if thread is not None else threading.current_thread(),
        "interval": max(1.0, float(interval)),
        "beat": time.time(),
    }
    with _lock:
        _workers[name] = entry


def beat(name: str) -> None:
    """Record one loop iteration.  A beat for an unregistered name is a no-op
    (the worker may have been unregistered by a concurrent ``stop_*``)."""
    with _lock:
        entry = _workers.get(name)
        if entry is not None:
            entry["beat"] = time.time()


def unregister(name: str) -> None:
    with _lock:
        _workers.pop(name, None)


def snapshot(now: float | None = None) -> list[dict]:
    """State of every registered worker, sorted by name."""
    now = time.time() if now is None else now
    with _lock:
        items = [(name, dict(entry)) for name, entry in _workers.items()]
    out = []
    for name, entry in sorted(items):
        thread = entry["thread"]
        age = max(0.0, now - entry["beat"])
        out.append({
            "name": name,
            "alive": bool(thread is not None and thread.is_alive()),
            "interval": entry["interval"],
            "age_sec": round(age, 1),
            "stale": age > entry["interval"] * STALE_AFTER,
        })
    return out


def problems(now: float | None = None) -> list[str]:
    """Human-readable descriptions of dead or stale workers (empty = healthy)."""
    out = []
    for w in snapshot(now):
        if not w["alive"]:
            out.append(f"{w['name']}: thread died")
        elif w["stale"]:
            out.append(
                f"{w['name']}: last tick {int(w['age_sec'])}s ago"
                f" (interval {int(w['interval'])}s)"
            )
    return out
