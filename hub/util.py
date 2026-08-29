"""Shared subprocess / network helpers."""
from __future__ import annotations

import errno
import functools
import inspect
import json
import logging
import os
import re
import socket
import stat
import subprocess
import tempfile
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, TypeVar

from hub.cli_args import as_argv

log = logging.getLogger("serverhub.util")

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")

T = TypeVar("T")


#: Below this a sweep would walk more entries than it could ever free, and the
#: memos that take no arguments -- most of them -- never reach it at all.
_MEMO_SWEEP_AT = 32


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
    without a separate memo per caller.  Keys must be hashable.  Entries past
    their TTL are swept on a miss, so keying on something that varies is safe:
    the memo holds roughly the keys seen within one TTL rather than every key
    seen since the process started.
    """
    def decorate(fn: Callable[..., T]) -> Callable[..., T]:
        cache: dict[Any, tuple[float, T]] = {}
        guard = threading.Lock()
        #: key -> [lock, waiters].  Ref-counted rather than kept forever: the
        #: lock for a key nobody is refreshing has no reader to protect, and
        #: leaving it behind grows this dict for the life of the process
        #: alongside the cache it guards.
        refresh_locks: dict[Any, list] = {}
        #: Bumped by invalidate().  A refresh already running at that moment has
        #: read the pre-action state, so publishing its result afterwards would
        #: quietly undo the invalidate and pin the stale answer for a full TTL.
        #: The dashboard polls while the operator acts, so the losing refresh is
        #: the common case, not the rare one: stop a container and the list keeps
        #: it running until the TTL lapses, which for smart_devices is ten
        #: minutes.  A refresh that started in an older epoch is dropped instead.
        epoch = 0

        def key_for(args: tuple, kwargs: dict) -> Any:
            return (args, tuple(sorted(kwargs.items()))) if kwargs else args

        def drop_expired(now: float) -> None:
            """Forget entries past their TTL.  Call with `guard` held.

            An expired entry can never be served, so dropping it is invisible
            to callers -- but without this the cache only ever shrank on
            invalidate(), and a memo keyed on something that keeps changing
            grew one dead entry per distinct key for the life of the process.
            Callers had to work around that by not keying on anything varied,
            which is a constraint the helper should not impose.  Swept on a
            miss and only past the threshold, so the single-key memos that
            make up most callers never walk anything.
            """
            for key, (stamp, _) in list(cache.items()):
                if now - stamp >= ttl:
                    del cache[key]

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            key = key_for(args, kwargs)
            now = time.time()
            with guard:
                hit = cache.get(key)
                if hit is not None and now - hit[0] < ttl:
                    return hit[1]
                if len(cache) > _MEMO_SWEEP_AT:
                    drop_expired(now)
                # Per key, not global: two different devices must still be read
                # concurrently — serialising them would defeat the fan-out that
                # made this helper necessary.
                entry = refresh_locks.get(key)
                if entry is None:
                    entry = refresh_locks[key] = [threading.Lock(), 0]
                entry[1] += 1
                lock = entry[0]

            try:
                with lock:
                    with guard:
                        hit = cache.get(key)
                        if hit is not None and time.time() - hit[0] < ttl:
                            return hit[1]
                        began = epoch
                    value = fn(*args, **kwargs)
                    with guard:
                        if epoch == began:
                            cache[key] = (time.time(), value)
                    # Returned either way: this caller asked before the
                    # invalidate, and re-running the probe on its behalf buys
                    # nothing.
                    return value
            finally:
                with guard:
                    entry[1] -= 1
                    # Nobody else holds or waits on it, so this key is not
                    # being refreshed and the lock has nothing left to guard.
                    if entry[1] <= 0:
                        refresh_locks.pop(key, None)

        def invalidate() -> None:
            nonlocal epoch
            with guard:
                epoch += 1
                cache.clear()

        wrapper.invalidate = invalidate       # type: ignore[attr-defined]
        wrapper._cache = cache                # type: ignore[attr-defined]
        wrapper._refresh_locks = refresh_locks  # type: ignore[attr-defined]
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
        try:
            return self._executor().submit(fn, *args, **kwargs)
        except RuntimeError:
            # Executor shut down between lookup and submit (reload / lifespan).
            # Inline so GET /api/status cannot 500 while workers drain.
            fut = Future()
            try:
                fut.set_result(fn(*args, **kwargs))
            except _CONTROL_FLOW:
                raise
            except BaseException as exc:
                fut.set_exception(exc)
            return fut

    def map(self, fn, items):
        try:
            return self._executor().map(fn, items)
        except RuntimeError:
            return [fn(item) for item in items]

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
        #: See ttl_memo: an invalidate that lands mid-build must win over the
        #: build, or the payload the action was supposed to refresh comes back.
        epoch = 0

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
                with access:
                    began = epoch
                value = build(force) if takes_force else build()
                with access:
                    if epoch == began:
                        cache.update(t=time.time(), v=value)
                return value

        def invalidate() -> None:
            nonlocal epoch
            with access:
                epoch += 1
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

    ``open(path, "rb")`` followed a last-component symlink, so a log path
    swapped between the denylist check and the read would leak whatever it
    pointed at.  Resolve first (so a legitimate rotation link still works),
    then ``O_NOFOLLOW`` so a swap of the resolved name cannot be followed.

    ``O_NONBLOCK`` + the regular-file check: a leftover FIFO occupying a
    journal (data/metrics.jsonl was the found case) used to park ``os.open``
    until a writer appeared — hanging GET /api/metrics forever instead of
    raising the OSError every caller already handles.
    """
    n = max(1, int(n))
    cap = max(1, int(max_bytes))
    try:
        target = os.path.realpath(path)
    except OSError:
        target = path
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(target, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file", str(target))
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            fh.seek(0, 2)
            size = fh.tell()
            take = min(size, cap)
            if take <= 0:
                return []
            fh.seek(size - take)
            data = fh.read(take)
    finally:
        if fd >= 0:
            os.close(fd)
    text = data.decode("utf-8", errors="replace")
    if take < size:
        nl = text.find("\n")
        if nl != -1:
            text = text[nl + 1 :]
    return text.splitlines()[-n:]


def read_text_capped(
    path, max_bytes: int, *, encoding: str = "utf-8", errors: str = "strict"
) -> str:
    """Read *path*, refusing leftover multi-MB junk that used to OOM handlers.

    ``Path.read_text()`` loads the whole file.  A leftover pidfile, key, conf,
    or JSON store that grew to megabytes used to OOM the request that opened
    it.  Raises ``OSError`` (including ``FileNotFoundError``) like
    ``Path.read_text``, plus ``OSError(EFBIG)`` when the file exceeds
    *max_bytes* so callers reuse their existing OSError fallback, plus
    ``OSError(EINVAL)`` for a leftover FIFO/device occupying the path —
    ``open()`` of a FIFO used to park the caller until a writer appeared
    (a FIFO at data/metrics-rollup-state.json wedged the metrics sampler).
    """
    cap = max(1, int(max_bytes))
    try:
        p = path if isinstance(path, Path) else Path(path)
        fd = os.open(p, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except UnicodeEncodeError as exc:
        # Leftover ``\\ud800`` in the name is not OSError; open() used to
        # 500 callers that only catch OSError.
        raise OSError(errno.EINVAL, str(exc), str(path)) from exc
    except ValueError as exc:
        if isinstance(exc, UnicodeError):
            raise
        # Leftover NUL in the name.
        raise OSError(errno.EINVAL, str(exc), str(path)) from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file", str(p))
        with os.fdopen(fd, encoding=encoding, errors=errors) as fh:
            fd = -1
            data = fh.read(cap + 1)
    finally:
        if fd >= 0:
            os.close(fd)
    if len(data) > cap:
        raise OSError(errno.EFBIG, "file exceeds read cap", str(p))
    return data


#: Depth at which leftover JSON is treated as corrupt.  Python 3.14's
#: ``json.loads`` is iterative and will build a 12k-deep tree; 3.12
#: RecursionError'd around the C recursion limit (~1000).  256 is below
#: that and far above any store this panel writes.
JSON_MAX_DEPTH = 256

_STR_QUOTE = '"'
_STR_SLASH = "\\"
_STR_OPEN = frozenset("{[")
_STR_CLOSE = frozenset("}]")
_BYTE_QUOTE = 0x22
_BYTE_SLASH = 0x5C
_BYTE_OPEN = frozenset((0x7B, 0x5B))
_BYTE_CLOSE = frozenset((0x7D, 0x5D))


def json_nesting_exceeds(raw, max_depth: int = JSON_MAX_DEPTH) -> bool:
    """True when *raw* has more unquoted ``{`` / ``[`` than *max_depth*."""
    try:
        limit = int(max_depth)
    except (TypeError, ValueError, OverflowError):
        limit = JSON_MAX_DEPTH
    if limit < 1:
        return True
    if isinstance(raw, (bytes, bytearray, memoryview)):
        data = raw if not isinstance(raw, memoryview) else raw.tobytes()
        quote, slash, openers, closers = (
            _BYTE_QUOTE, _BYTE_SLASH, _BYTE_OPEN, _BYTE_CLOSE,
        )
    elif isinstance(raw, str):
        data = raw
        quote, slash, openers, closers = (
            _STR_QUOTE, _STR_SLASH, _STR_OPEN, _STR_CLOSE,
        )
    else:
        return False
    depth = 0
    in_str = False
    escape = False
    for ch in data:
        if in_str:
            if escape:
                escape = False
            elif ch == slash:
                escape = True
            elif ch == quote:
                in_str = False
            continue
        if ch == quote:
            in_str = True
        elif ch in openers:
            depth += 1
            if depth > limit:
                return True
        elif ch in closers and depth:
            depth -= 1
    return False


def safe_json_loads(s, *, loads=None, max_depth: int = JSON_MAX_DEPTH, **kwargs):
    """``json.loads`` that RecursionError's leftover deeply-nested documents.

    Python 3.12's decoder RecursionError's around the C recursion limit.
    Python 3.14's is iterative and returns the nest, so call sites that
    catch RecursionError and return ``{}`` / skip would accept a huge
    nested object.  Scan first; RecursionError stays the corrupt-document
    signal on both versions.

    *loads* is the decoder (default ``json.loads``) so tests that patch
    ``module.json.loads`` still apply when the caller passes that name.
    """
    if json_nesting_exceeds(s, max_depth):
        raise RecursionError("JSON nesting exceeds limit")
    decoder = json.loads if loads is None else loads
    return decoder(s, **kwargs)


def read_bytes_capped(path, max_bytes: int) -> bytes:
    """Read *path* as bytes, refusing leftover multi-MB junk that used to OOM.

    ``Path.read_bytes()`` / ``open(..., "rb").read()`` loads the whole file.
    A leftover LaunchAgent plist that grew to megabytes used to OOM the
    request that parsed it.  Raises ``OSError`` (including
    ``FileNotFoundError``) like ``Path.read_bytes``, plus ``OSError(EFBIG)``
    when the file exceeds *max_bytes* so callers reuse their existing
    OSError fallback, plus ``OSError(EINVAL)`` for a leftover FIFO/device
    occupying the path (a plain open of a FIFO parks until a writer appears).
    """
    cap = max(1, int(max_bytes))
    try:
        p = path if isinstance(path, Path) else Path(path)
        fd = os.open(p, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except UnicodeEncodeError as exc:
        raise OSError(errno.EINVAL, str(exc), str(path)) from exc
    except ValueError as exc:
        if isinstance(exc, UnicodeError):
            raise
        raise OSError(errno.EINVAL, str(exc), str(path)) from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file", str(p))
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            data = fh.read(cap + 1)
    finally:
        if fd >= 0:
            os.close(fd)
    if len(data) > cap:
        raise OSError(errno.EFBIG, "file exceeds read cap", str(p))
    return data


#: Same argv timing out on every dashboard tick used to reprint the warning
#: into ~/Library/Logs/serverhub.err.log.  `brew outdated` and
#: `brew services list --json` each hung past their timeout for hours on this
#: host; the panel already returns a fallback, so one line per gap is enough
#: to see that brew is stuck without growing the launchd log.
_TIMEOUT_LOG_GAP = 300.0
_noisy_log_lock = threading.Lock()
_noisy_log_at: dict[tuple[str, tuple[str, ...]], float] = {}
#: Sweep the gap table once it holds more argvs than this.  A healthy host
#: keeps a handful of entries -- one per command that is actually broken --
#: so passing this means argv is carrying identifiers rather than repeating.
_NOISY_SWEEP_AT = 256


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
        # The whole argv is the key, and argv carries identifiers: container
        # IDs, device paths, tunnel names.  Every one that ever failed used
        # to stay here for the life of the process.  An entry past the gap
        # is already spent -- the next failure logs regardless -- so
        # forgetting it costs nothing and bounds the table.
        if len(_noisy_log_at) > _NOISY_SWEEP_AT:
            for spent, at in list(_noisy_log_at.items()):
                if now - at >= _TIMEOUT_LOG_GAP:
                    del _noisy_log_at[spent]
        _noisy_log_at[key] = now
    log.warning(message, cmd)


def _exc_text(exc, cap: int = 200) -> str:
    """Exception text that cannot RecursionError leftover ``str(e)`` or UTF-8 500."""
    if exc is None:
        text = "error"
    else:
        for base in (bytes, bytearray):
            try:
                text = base.decode(exc, "utf-8", "replace")
                break
            except _CONTROL_FLOW:
                raise
            except BaseException:
                continue
        else:
            try:
                text = str.encode(str.__str__(exc), "utf-8", "replace").decode("utf-8")
            except _CONTROL_FLOW:
                raise
            except BaseException:
                text = None
            if text is None:
                try:
                    cls = type(exc)
                    if cls.__str__ is object.__str__ and cls.__repr__ is object.__repr__:
                        text = "error"
                    else:
                        text = None
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    text = "error"
            if text is None:
                try:
                    text = str(exc)
                except RecursionError:
                    try:
                        text = type(exc).__name__
                    except _CONTROL_FLOW:
                        raise
                    except BaseException:
                        text = "error"
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    text = "error"
    if not isinstance(text, str):
        text = "error"
    try:
        text = str.encode(text, "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        text = "error"
    if _ADDR_REPR_RE.search(text):
        text = "error"
    try:
        cap_n = int(cap)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        cap_n = 200
    return text[: max(0, cap_n)]


def strftime_now(fmt: str, default: str = "") -> str:
    """``time.strftime`` of the current clock.

    Leftover ``time.time() = inf`` OverflowError'd ``localtime`` and 500'd
    GET /api/status, /api/sensors, /api/health, and Settings.
    """
    try:
        return time.strftime(fmt)
    except (OverflowError, OSError, ValueError, TypeError):
        return default


def utf8_env(env=None) -> dict[str, str]:
    """Env mapping ``subprocess`` can encode.

    Leftover ``\\ud800`` / NUL in a key or value UnicodeEncodeError'd
    ``subprocess.run`` / ``Popen`` (not OSError) and 500'd compose
    validate, brew, catalog install, and any other request that passed
    ``os.environ``.
    """
    source = os.environ if env is None else env
    try:
        items = source.items()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return {}
    out: dict[str, str] = {}
    for key, value in items:
        if isinstance(key, (bytes, bytearray)):
            try:
                key = key.decode("utf-8")
            except UnicodeDecodeError:
                continue
        if isinstance(value, (bytes, bytearray)):
            try:
                value = value.decode("utf-8")
            except UnicodeDecodeError:
                continue
        if not isinstance(key, str) or not isinstance(value, str):
            continue
        if "\x00" in key or "\x00" in value:
            continue
        try:
            key.encode("utf-8")
            value.encode("utf-8")
        except UnicodeEncodeError:
            continue
        out[key] = value
    return out


#: Tumbling window for :class:`SpawnCounts`.  Peek and record both reset when
#: the window elapses so a sitting dashboard does not accumulate forever.
_SPAWN_WINDOW_S = 60
_SPAWN_KEY_CAP = 64
_SPAWN_SUBCOMMAND = frozenset({"docker", "brew", "launchctl"})
_SPAWN_TOKEN_MAX = 64


def _spawn_tokens(cmd, *, shell: bool = False) -> list[str]:
    """Executable + args as str tokens.  Never returns leftover non-str argv."""
    if shell and isinstance(cmd, str):
        parts = cmd.split()
        return parts[:2] if parts else []
    if not isinstance(cmd, (list, tuple)):
        return []
    out: list[str] = []
    for part in cmd:
        if not isinstance(part, str):
            return []
        out.append(part)
        if len(out) >= 8:
            break
    return out


def spawn_key(cmd, *, shell: bool = False) -> str:
    """Counter key: basename, or '{basename} {first_subcommand}' for a few CLIs.

    First subcommand only for docker/brew/launchctl — never the rest of argv
    (tokens, paths).  Unknown / empty subcommand → basename only.
    """
    tokens = _spawn_tokens(cmd, shell=shell)
    if not tokens:
        return ""
    base = os.path.basename(tokens[0])
    if not base or len(base) > _SPAWN_TOKEN_MAX:
        return ""
    if base not in _SPAWN_SUBCOMMAND:
        return base
    for tok in tokens[1:]:
        if not tok or tok.startswith("-"):
            continue
        if len(tok) > _SPAWN_TOKEN_MAX:
            return base
        return f"{base} {tok}"
    return base


class SpawnCounts:
    """Process-local subprocess spawn counters (``sh`` / ``run_capped``)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._started = 0.0
        self._total = 0
        self._overflow = 0
        self._by_key: dict[str, int] = {}
        self.reset()

    def reset(self) -> None:
        """Drop the window.  Tests call this in setUp/tearDown."""
        with self._lock:
            self._reset_unlocked()

    def _reset_unlocked(self) -> None:
        self._started = time.monotonic()
        self._total = 0
        self._overflow = 0
        self._by_key = {}

    def _tumble_unlocked(self) -> None:
        try:
            age = time.monotonic() - self._started
        except (TypeError, OverflowError):
            self._reset_unlocked()
            return
        if age != age or age in (float("inf"), float("-inf")) or age >= _SPAWN_WINDOW_S:
            self._reset_unlocked()

    def record(self, cmd, *, shell: bool = False) -> None:
        try:
            key = spawn_key(cmd, shell=shell)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return
        if not key:
            return
        with self._lock:
            self._tumble_unlocked()
            self._total += 1
            n = self._by_key.get(key)
            if n is not None:
                self._by_key[key] = n + 1
            elif len(self._by_key) < _SPAWN_KEY_CAP:
                self._by_key[key] = 1
            else:
                self._overflow += 1

    def snapshot(self) -> dict:
        with self._lock:
            self._tumble_unlocked()
            try:
                age = time.monotonic() - self._started
            except (TypeError, OverflowError):
                age = 0.0
            if age != age or age in (float("inf"), float("-inf")) or age < 0:
                age = 0.0
            try:
                age_s = round(age, 3)
            except (TypeError, OverflowError):
                age_s = 0.0
            return {
                "window_s": _SPAWN_WINDOW_S,
                "age_s": age_s,
                "total": self._total,
                "overflow": self._overflow,
                "by_key": dict(self._by_key),
            }


spawn_counts = SpawnCounts()


def run_capped(cmd, timeout=10, env=None, cwd=None, cap=2048):
    """Run *cmd* and keep at most *cap* trailing bytes of combined output.

    ``subprocess.run(capture_output=True)`` buffers the whole pipe until
    exit.  A chatty ``docker compose up`` or ``pg_dump`` on a request
    thread can RSS-bomb the panel for the length of *timeout*.
    """
    cap = max(1, int(cap))
    argv = as_argv(cmd)
    if argv is None:
        return -1, "invalid argv"
    try:
        spawn_counts.record(argv)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        pass
    with tempfile.TemporaryFile() as out:
        try:
            p = subprocess.run(
                argv, stdout=out, stderr=subprocess.STDOUT,
                timeout=timeout, env=utf8_env(env), cwd=cwd, check=False,
            )
            rc = p.returncode
        except subprocess.TimeoutExpired:
            rc = -1
        except FileNotFoundError:
            return -1, "not found"
        except (OSError, ValueError, TypeError, RecursionError) as exc:
            # ValueError: leftover ``\\ud800`` cwd (UnicodeEncodeError).
            # RecursionError: leftover ``str(e)`` on a nested exception is not ValueError.
            return -1, _exc_text(exc, cap)
        try:
            size = out.seek(0, 2)
            out.seek(max(0, size - cap))
            text = out.read().decode("utf-8", "replace")
        except OSError:
            text = ""
    return rc, text


#: Per-stream ceiling for :func:`run_bytes`.  Binary plists (``diskutil
#: -plist``) must stay intact; a torn prefix is never a valid plist.  The
#: cap still bounds a runaway child so a request thread cannot RSS-bomb
#: the panel.
_BYTES_CAP = 4 * 1024 * 1024


def run_bytes(cmd, timeout=10, cap=_BYTES_CAP, runner=None):
    """Run *cmd* and keep at most *cap* leading bytes of stdout (binary).

    ``capture_output=True`` buffers the whole pipe in RAM.  Callers that
    parse ``diskutil -plist`` need raw bytes (UTF-8 :func:`sh` would
    corrupt a binary plist), but they do not need an unbounded buffer.

    *runner* defaults to :func:`subprocess.run`.  Disk modules pass their
    own ``subprocess.run`` so existing tests can stub it.
    """
    cap = max(1, int(cap))
    argv = as_argv(cmd)
    if argv is None:
        return -1, b"", b"invalid argv"
    run = runner or subprocess.run
    try:
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            try:
                r = run(
                    argv, stdout=out, stderr=err, timeout=timeout, check=False,
                    env=utf8_env(),
                )
                rc = r.returncode if getattr(r, "returncode", None) is not None else 0
            except subprocess.TimeoutExpired:
                _log_once("timeout", cmd, "command timed out: %s")
                return -1, b"", b"timeout"
            except FileNotFoundError:
                _log_once("missing", cmd, "command not found: %s")
                return -1, b"", b"not found"
            except (OSError, ValueError, TypeError, RecursionError) as exc:
                # Leftover ``\\ud800`` env UnicodeEncodeError is ValueError.
                # RecursionError: leftover ``str(e)`` on a nested exception is not ValueError.
                _log_once("error", cmd, "command failed: %s")
                return -1, b"", _exc_text(exc).encode("utf-8", "replace")[:200]

            # Tests (and any caller that stubs ``subprocess.run``) return a
            # CompletedProcess with captured bytes.  A real run redirected
            # the pipes into *out*/*err*, so ``r.stdout`` is None.
            captured = getattr(r, "stdout", None)
            if captured is not None:
                if isinstance(captured, str):
                    captured = captured.encode("utf-8", "replace")
                elif not isinstance(captured, (bytes, bytearray)):
                    captured = bytes(captured)
                return rc, bytes(captured)[:cap], b""

            try:
                size = out.seek(0, 2)
                if size > cap:
                    return -1, b"", b"truncated"
                out.seek(0)
                stdout = out.read(cap)
            except OSError:
                stdout = b""
            return rc, stdout, b""
    except (OSError, RecursionError) as exc:
        return -1, b"", _exc_text(exc).encode("utf-8", "replace")[:200]


#: Per-stream ceiling for :func:`sh`.  ``capture_output=True`` used to keep
#: the whole pipe in RAM until exit; a chatty ``docker inspect`` / ``find``
#: on a request thread could RSS-bomb the panel for the length of *timeout*.
_SH_CAP = 1024 * 1024


def sh(cmd, timeout=10, shell=False, env=None):
    """Run *cmd* and keep at most :data:`_SH_CAP` leading bytes of each stream.

    Head, not tail: callers parse JSON / plists from stdout.  A torn prefix
    still fails those parsers (they already treat garbage as empty), but a
    tail of a huge object is never valid JSON either and wastes the cap.
    """
    if not shell:
        argv = as_argv(cmd)
        if argv is None:
            return -1, "", "invalid argv"
        cmd = argv
    try:
        spawn_counts.record(cmd, shell=shell)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        pass
    try:
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            try:
                r = subprocess.run(
                    cmd, stdout=out, stderr=err,
                    timeout=timeout, shell=shell, env=utf8_env(env),
                )
                rc = r.returncode
            except subprocess.TimeoutExpired:
                _log_once("timeout", cmd, "command timed out: %s")
                return -1, "", "timeout"
            except FileNotFoundError:
                _log_once("missing", cmd, "command not found: %s")
                return -1, "", "not found"
            except (OSError, ValueError, TypeError, RecursionError) as exc:
                # RecursionError: leftover ``str(e)`` on a nested exception is not ValueError.
                _log_once("error", cmd, "command failed: %s")
                return -1, "", _exc_text(exc)

            def _head(fh) -> str:
                try:
                    fh.seek(0)
                    return fh.read(_SH_CAP).decode("utf-8", "replace").strip()
                except OSError:
                    return ""

            return rc, _head(out), _head(err)
    except (OSError, RecursionError) as exc:
        return -1, "", _exc_text(exc)


def port_open(port, host="localhost", timeout=0.6):
    if not port:
        return None
    # YAML leftover ``port: .inf`` / ``.nan`` used to OverflowError /
    # ValueError past the OSError guard.  ``fan_out`` re-raises, so one
    # leftover took the whole /api/status batch with it.
    try:
        port_n = int(port)
    except (TypeError, ValueError, OverflowError):
        return False
    if not 0 < port_n <= 65535:
        # ``int()`` does not catch an *already-int* over-cap value: a YAML
        # hex/octal leftover (``port: 0xfff…`` dodges the int(str) digit cap)
        # reached ``create_connection``, whose digit-capped str conversion
        # raised ValueError past the OSError guard below.  Out of range is
        # simply "not open".
        return False
    try:
        with socket.create_connection((host, port_n), timeout=timeout):
            return True
    except OSError:
        return False
