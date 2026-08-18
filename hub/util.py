"""Shared subprocess / network helpers."""
from __future__ import annotations

import functools
import inspect
import logging
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, TypeVar

log = logging.getLogger("serverhub.util")

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


#: Ceiling on probe concurrency.  These pools exist to hide latency, not to use
#: the CPU: every task in them is blocked on a subprocess or a socket, so the
#: useful width is bounded by how many of those the machine will service at once
#: rather than by core count.
MAX_PROBE_WORKERS = 8


class LazyPool:
    """Process-lifetime ThreadPoolExecutor, created on first use.

    Dashboard polls used to construct and join a pool on every tick.  The
    probes still dominate latency, but the thread churn was paid on every
    ``/api/status`` and ``/api/sensors`` request — the same tax, five modules.
    ``shutdown`` drops the executor so a reload or test can start a fresh one.
    """

    def __init__(self, max_workers: int, name: str):
        if max_workers < 1:
            raise ValueError("max_workers must be >= 1")
        self.max_workers = max_workers
        self.name = name
        self._ex: ThreadPoolExecutor | None = None
        self._guard = threading.Lock()

    def _executor(self) -> ThreadPoolExecutor:
        with self._guard:
            if self._ex is None:
                self._ex = ThreadPoolExecutor(
                    max_workers=self.max_workers,
                    thread_name_prefix=self.name,
                )
            return self._ex

    def submit(self, fn, /, *args, **kwargs):
        return self._executor().submit(fn, *args, **kwargs)

    def map(self, fn, items):
        return self._executor().map(fn, items)

    def shutdown(self, wait: bool = False) -> None:
        with self._guard:
            ex = self._ex
            self._ex = None
        if ex is not None:
            ex.shutdown(wait=wait)


_FANOUT_POOL = LazyPool(MAX_PROBE_WORKERS, "hub-fanout")
#: Nested ``fan_out`` (hardware profile → four system_profiler reports;
#: health → port sweep) must not ``map`` on :data:`_FANOUT_POOL`: the
#: caller occupies a worker of that pool while waiting for more work on
#: it, which deadlocks once the outer batch is wide enough.  A second
#: pool keeps the inner batch overlapping.  A third level runs inline.
_FANOUT_NESTED_POOL = LazyPool(MAX_PROBE_WORKERS, "hub-fanout-nested")
_FANOUT_DEPTH = threading.local()


def shutdown_pools() -> None:
    """Drop the shared fan-out pools (app lifespan / tests)."""
    _FANOUT_POOL.shutdown()
    _FANOUT_NESTED_POOL.shutdown()


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
    * a nested call from a worker uses a second pool so the inner batch still
      overlaps, without scheduling onto the caller's executor.  A third level
      runs inline.  Callers that need two overlapping widths on the *same*
      pool (overview + per-disk SMART) keep a dedicated :class:`LazyPool`
      for the outer composer.

    *probe* must not raise -- ``ex.map`` re-raises on iteration, which would cost
    the whole batch rather than one entry -- and must not depend on the
    request-scoped administrator password, which does not cross into a worker.
    See tests/test_privileged_calls_stay_on_the_request_thread.py.

    *max_workers* is kept for call-site compatibility.  The shared process
    pool is sized to :data:`MAX_PROBE_WORKERS`; a smaller request still
    shares that pool rather than constructing a throwaway executor.
    """
    items = list(items)
    if not items:
        return []
    if len(items) == 1:
        return [probe(items[0])]
    depth = getattr(_FANOUT_DEPTH, "n", 0)
    if depth >= 2:
        return [probe(item) for item in items]
    pool = _FANOUT_NESTED_POOL if depth else _FANOUT_POOL

    def _run(item):
        _FANOUT_DEPTH.n = depth + 1
        try:
            return probe(item)
        finally:
            _FANOUT_DEPTH.n = depth

    return list(pool.map(_run, items))


def cached_snapshot(ttl: float) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """A whole-payload read: TTL cache, single-flight refresh, ``force`` bypass.

    :func:`ttl_memo` covers per-key sub-reads.  This covers the other cache in every
    service module -- the one holding an endpoint's entire payload behind a ``force``
    flag -- which had been hand-written eight times, and every copy had the same two
    defects:

    * **No lock at all.**  ``_cache.update(t=..., v=...)`` is two key writes, not one
      atomic publish, so a concurrent reader could observe the new timestamp beside
      the previous payload and serve a stale answer as fresh for a whole TTL.
    * **No single-flight.**  The TTL was tested and the build then ran outside any
      lock, so overlapping callers all missed and all rebuilt.  That is worst exactly
      where it matters: when a rebuild takes longer than the poll interval, every
      poll arriving during a rebuild starts another one.

    The builder may take a ``force`` parameter if it means something to it beyond the
    cache -- ``apps_manage_svc.inventory`` re-probes brew for just-installed natives
    -- and is called with no arguments otherwise.  Arity is resolved once, at
    decoration time.

    The cached object is returned as-is rather than copied, matching what every
    hand-written version did; callers must not mutate it.

    Exposes ``invalidate()`` / ``cache_clear()``, like :func:`ttl_memo`.
    """
    def decorate(build: Callable[..., T]) -> Callable[..., T]:
        takes_force = bool(inspect.signature(build).parameters)
        cache: dict[str, Any] = {"t": 0.0, "v": None}
        access = threading.Lock()
        refresh = threading.Lock()

        def fresh() -> Any:
            with access:
                value = cache["v"]
                if value is not None and time.time() - cache["t"] < ttl:
                    return value
            return None

        @functools.wraps(build)
        def wrapper(force: bool = False) -> T:
            if not force:
                hit = fresh()
                if hit is not None:
                    return hit
            with refresh:
                # Re-check: the caller holding the lock published while this one
                # queued behind it, and rebuilding would defeat the point of waiting.
                if not force:
                    hit = fresh()
                    if hit is not None:
                        return hit
                value = build(force) if takes_force else build()
                with access:
                    cache.update(t=time.time(), v=value)
                return value

        def invalidate() -> None:
            with access:
                cache.update(t=0.0, v=None)

        wrapper.invalidate = invalidate  # type: ignore[attr-defined]
        wrapper.cache_clear = invalidate  # type: ignore[attr-defined]
        return wrapper

    return decorate


def iter_capped_lines(stream, cap):
    """Yield lines from a text stream, each capped at *cap* characters.

    ``for line in stream`` buffers a whole line before the caller can trim it,
    so one line with no newline in it — a dumped blob, a progress bar written
    with ``\\r`` — balloons memory no matter how the caller caps its log.
    ``readline(cap)`` bounds every read; the remainder of an over-long line is
    read and *discarded* in cap-sized chunks, and the kept prefix is marked.
    Trailing whitespace is stripped, matching what the log loops did inline.

    Iterators without ``readline`` (test fakes, already-split lists) still
    get a per-line cap so callers can share one helper.
    """
    readline = getattr(stream, "readline", None)
    if readline is None:
        for line in stream:
            text = line.rstrip() if isinstance(line, str) else str(line).rstrip()
            if len(text) >= cap:
                yield text[:cap] + " …[line truncated]"
            elif text:
                yield text
        return
    while True:
        line = readline(cap)
        if line == "":
            return
        if len(line) >= cap and not line.endswith("\n"):
            while True:
                rest = readline(cap)
                if rest == "" or rest.endswith("\n"):
                    break
            yield line.rstrip() + " …[line truncated]"
            continue
        yield line.rstrip()


def tail_file_lines(path, n: int, *, max_bytes: int = 256 * 1024) -> list[str]:
    """Last *n* lines of *path*, reading at most *max_bytes* from the end.

    Callers that used ``Path.read_text().splitlines()[-n:]`` loaded the whole
    file — a PhotosHub backup log or a LaunchAgent stdout that grew for months
    — just to show a 40-line tail.  A prefix byte is dropped so a mid-line
    seek does not return a torn first row.
    """
    n = max(1, int(n))
    cap = max(1, int(max_bytes))
    with open(path, "rb") as fh:
        fh.seek(0, 2)
        size = fh.tell()
        take = min(size, cap)
        if take <= 0:
            return []
        fh.seek(size - take)
        data = fh.read(take)
    text = data.decode("utf-8", errors="replace")
    if take < size:
        nl = text.find("\n")
        if nl != -1:
            text = text[nl + 1 :]
    return text.splitlines()[-n:]


#: Same argv timing out on every dashboard tick used to reprint the warning
#: into ~/Library/Logs/serverhub.err.log.  `brew outdated` and
#: `brew services list --json` each hung past their timeout for hours on this
#: host; the panel already returns a fallback, so one line per gap is enough
#: to see that brew is stuck without growing the launchd log.
_TIMEOUT_LOG_GAP = 300.0
_noisy_log_lock = threading.Lock()
_noisy_log_at: dict[tuple[str, tuple[str, ...]], float] = {}


def _cmd_key(cmd) -> tuple[str, ...]:
    if isinstance(cmd, (list, tuple)):
        return tuple(str(part) for part in cmd)
    return (str(cmd),)


def _log_once(kind: str, cmd, message: str) -> None:
    key = (kind, _cmd_key(cmd))
    now = time.time()
    with _noisy_log_lock:
        last = _noisy_log_at.get(key, 0.0)
        if now - last < _TIMEOUT_LOG_GAP:
            return
        _noisy_log_at[key] = now
    log.warning(message, cmd)


def sh(cmd, timeout=10, shell=False, env=None):
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, shell=shell, env=env,
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        _log_once("timeout", cmd, "command timed out: %s")
        return -1, "", "timeout"
    except FileNotFoundError:
        _log_once("missing", cmd, "command not found: %s")
        return -1, "", "not found"


def port_open(port, host="localhost", timeout=0.6):
    if not port:
        return None
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False
