"""Shared subprocess / network helpers."""
from __future__ import annotations

import functools
import socket
import subprocess
import threading
import time
from typing import Any, Callable, TypeVar

T = TypeVar("T")


def ttl_memo(ttl: float) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Cache a read for *ttl* seconds, and let only one caller compute it.

    The TTL half of this is obvious.  The single-flight half is the part that keeps
    getting written wrong: a plain "check the cache, else compute, else store" is
    correct only while callers arrive one at a time.  Once several branches of a
    fan-out reach the same read simultaneously they all miss the cold cache, all
    run the command, and the cache never gets a chance to help — one request ran
    `networksetup -listallhardwareports` five times that way, and a per-device
    smartctl transport probe twice per disk.

    This has now been hand-written five times across hub/ (correctly in
    brew_cache.py, incorrectly in three other places), which is reason enough for
    it to exist once.

    The wrapper exposes:
        fn.invalidate()   drop the cache, for use after an action changes the state
                          the read reports
        fn.cache_clear()  alias, matching functools.lru_cache's name

    Arguments are part of the cache key, so a per-device or per-service read works
    without a separate memo per caller.  Keys must be hashable.
    """
    def decorate(fn: Callable[..., T]) -> Callable[..., T]:
        cache: dict[Any, tuple[float, T]] = {}
        guard = threading.Lock()
        refresh_locks: dict[Any, threading.Lock] = {}

        def key_for(args: tuple, kwargs: dict) -> Any:
            return (args, tuple(sorted(kwargs.items()))) if kwargs else args

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            key = key_for(args, kwargs)
            now = time.time()
            with guard:
                hit = cache.get(key)
                if hit is not None and now - hit[0] < ttl:
                    return hit[1]
                # Per key, not global: two different devices must still be read
                # concurrently — serialising them would defeat the fan-out that
                # made this helper necessary.
                lock = refresh_locks.setdefault(key, threading.Lock())

            with lock:
                with guard:
                    hit = cache.get(key)
                    if hit is not None and time.time() - hit[0] < ttl:
                        return hit[1]
                value = fn(*args, **kwargs)
                with guard:
                    cache[key] = (time.time(), value)
                return value

        def invalidate() -> None:
            with guard:
                cache.clear()

        wrapper.invalidate = invalidate       # type: ignore[attr-defined]
        wrapper.cache_clear = invalidate      # type: ignore[attr-defined]
        return wrapper

    return decorate
from concurrent.futures import ThreadPoolExecutor

#: Ceiling on probe concurrency.  These pools exist to hide latency, not to use
#: the CPU: every task in them is blocked on a subprocess or a socket, so the
#: useful width is bounded by how many of those the machine will service at once
#: rather than by core count.
MAX_PROBE_WORKERS = 8


def fan_out(probe, items, *, max_workers=MAX_PROBE_WORKERS):
    """Map *probe* over *items* concurrently, preserving input order.

    One definition for a pattern that otherwise gets rewritten per module, with
    the three details that are easy to get wrong each time:

    * ``ex.map``, not ``as_completed``.  Callers render these lists in
      enumeration order -- configured order, or the order a CLI reported -- and
      completion order would reshuffle a table between refreshes.
    * an empty ``items`` returns immediately, because ``max_workers=0`` is a
      ValueError rather than an empty pool.
    * a single item runs inline, since a pool cannot overlap one task and only
      adds a thread handoff.

    *probe* must not raise -- ``ex.map`` re-raises on iteration, which would cost
    the whole batch rather than one entry -- and must not depend on the
    request-scoped administrator password, which does not cross into a worker.
    See tests/test_privileged_calls_stay_on_the_request_thread.py.
    """
    items = list(items)
    if not items:
        return []
    if len(items) == 1:
        return [probe(items[0])]
    with ThreadPoolExecutor(max_workers=min(max_workers, len(items))) as ex:
        return list(ex.map(probe, items))


def sh(cmd, timeout=10, shell=False):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=shell)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return -1, "", "not found"


def port_open(port, host="localhost", timeout=0.6):
    if not port:
        return None
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False
