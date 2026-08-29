"""Host metrics history (ring buffer on disk) — SSD-friendly batched writes."""
from __future__ import annotations

import json
import os
import re
import shutil
import threading
import time

from hub import secure_io
from hub.paths import DATA_DIR
from hub.util import safe_json_loads, sh, tail_file_lines

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")

METRICS_FILE = DATA_DIR / "metrics.jsonl"
# ~48h at 90s interval ≈ 1920 points; keep headroom
MAX_POINTS = 2880
# Rewrite only once we have grown this far past the cap. At the 90s sample
# interval a 10% slack is ~7h between full rewrites instead of every hour
# at a file that sits permanently at the cap.
_TRIM_SLACK = 288
_lock = threading.Lock()
_thread: threading.Thread | None = None
_stop = threading.Event()
_last_trim = 0.0
_TRIM_INTERVAL = 3600.0  # full rewrite at most hourly — SSD-friendly
_ncpu_cache: dict = {"t": 0.0, "n": None}
_NCPU_TTL = 600.0
# In-memory batch: fewer fsync/small-write cycles on SSD
_write_buf: list[str] = []
_last_flush = 0.0
_FLUSH_EVERY_N = 4          # flush every N samples (~6 min at 90s)
_FLUSH_MAX_AGE = 300.0      # or at least every 5 min


def _ncpu() -> int:
    now = time.time()
    cached = _ncpu_cache["n"]
    if cached is not None and now - _ncpu_cache["t"] < _NCPU_TTL:
        try:
            n = int(cached)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # Leftover planted ``n: .inf`` OverflowError'd ``int(inf)``;
            # BaseException because ``int()`` of a leftover subclass dispatches
            # into its own ``__int__``/``__index__`` bomb.
            n = 0
        if n > 0:
            return n
    from hub import macos_sysctl

    n = macos_sysctl.sysctl_int("hw.ncpu", timeout=2, sh=sh)
    try:
        n = int(n) if n is not None else 1
    except _CONTROL_FLOW:
        raise
    except BaseException:
        n = 1
    if n <= 0:
        n = 1
    _ncpu_cache.update(t=now, n=n)
    return n


def _plain_dict(value) -> dict | None:
    """*value* as a plain ``dict``, or None.

    A leftover dict-*subclass* snapshot (usage5's row-bomb class: passes the
    isinstance gate, then ``.get()`` / ``__bool__`` raises) used to kill the
    sampler tick past metrics4's shape guards — the jsonl row was silently
    lost and maybe_rollup() skipped with it.  ``dict()`` copies through the
    C-level storage, so an overridden method cannot fire.
    """
    if type(value) is dict:
        return value
    if isinstance(value, dict):
        try:
            return dict(value)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
    return None


def _sensors_snapshot() -> dict | None:
    """Reuse a warm full sample, otherwise a light one — never spawn ``top``.

    ``collect_sensors()`` on a cold cache measured 0.85–1.6s here, almost all
    of it ``top -l 1``.  The sampler runs with nobody looking; a jsonl point
    only needs load, pressure, and Mach CPU ticks.
    """
    try:
        from hub import sensors_svc
        # _plain_dict, not a bare isinstance: a leftover dict-subclass hit
        # whose .get()/__bool__ raised used to pass the gate and kill the
        # tick in _sample() one call later.
        hit = _plain_dict(sensors_svc.peek_sensors())
        if hit is not None:
            return hit
        from hub.resource_mode import is_high
        if is_high():
            snap = sensors_svc.collect_sensors()
        else:
            snap = sensors_svc.collect_light()
        # A leftover non-dict planted in the sensors cache used to come back
        # verbatim, and _sample()'s snapshot.get() AttributeError killed the
        # tick — no jsonl row and no maybe_rollup() pass until the cache
        # expired.
        return _plain_dict(snap)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None


def _cpu_used_quick(sensors: dict | None = None) -> float | None:
    """Lightweight CPU used % without full top if sensors cache warm."""
    # _plain_dict on a caller-provided snapshot: a leftover dict-subclass
    # whose .get() raised escaped the numeric-only except below.
    s = _plain_dict(sensors) if sensors is not None else _sensors_snapshot()
    try:
        # isinstance, not truthiness: a leftover non-dict snapshot used to
        # AttributeError .get() past the numeric-only except below.
        # Exception, not the three usual conversion errors: ``float()`` of a
        # leftover float-subclass field dispatches into its own ``__float__``,
        # whose modules5 bomb killed the sampler tick past metrics5's guards.
        if isinstance(s, dict) and s.get("cpu_used_pct") is not None:
            return float(s["cpu_used_pct"])
    except _CONTROL_FLOW:
        raise
    except BaseException:
        pass
    try:
        load1 = os.getloadavg()[0]
        n = _ncpu()
        return round(min(100.0, load1 / n * 100), 1)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None


def _sample() -> dict:
    load1, load5, load15 = os.getloadavg()
    du = shutil.disk_usage("/")
    mem_free = None
    ncpu = _ncpu()
    s = _sensors_snapshot()
    cpu_used = _cpu_used_quick(s)
    mem_used_pct = None
    gpu_util_pct = None
    load_pct = round(min(200.0, load1 / ncpu * 100), 1) if ncpu else None

    net_rx = net_tx = None
    sensors_hit = isinstance(s, dict) and bool(s)
    if sensors_hit:
        # isinstance, not ``or {}``: a leftover truthy non-dict ``network`` /
        # ``memory`` in the snapshot ("down", a list) used to AttributeError
        # .get() here, killing the sampler tick — the jsonl row was silently
        # lost and maybe_rollup() was skipped with it.
        net = s.get("network")
        if not isinstance(net, dict):
            net = {}
        net_rx = net.get("rx_bps")
        net_tx = net.get("tx_bps")
        m = s.get("memory")
        if not isinstance(m, dict):
            m = {}
        if m.get("pressure_used_pct") is not None:
            mem_used_pct = m["pressure_used_pct"]
            mem_free = m.get("pressure_free_pct", mem_free)
        elif m.get("used_pct") is not None:
            mem_used_pct = m["used_pct"]
            mem_free = m.get("free_pct", mem_free)
        if s.get("cpu_used_pct") is not None:
            try:
                cpu_used = min(100.0, max(0.0, float(s["cpu_used_pct"])))
            except _CONTROL_FLOW:
                raise
            except BaseException:
                # Exception: a leftover float-subclass ``__float__`` bomb in
                # the snapshot is not one of the three conversion errors.
                pass
        gpu = s.get("gpu")
        if isinstance(gpu, dict):
            raw = gpu.get("util_pct")
            # Bool is an int; float(True) would store a fake 1.0% reading.
            if not isinstance(raw, bool) and raw is not None:
                try:
                    v = float(raw)
                    if v == v and v not in (float("inf"), float("-inf")):
                        gpu_util_pct = round(min(100.0, max(0.0, v)), 1)
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    # Exception: a leftover float-subclass ``__float__`` bomb
                    # is not one of the three conversion errors.
                    pass

    if not sensors_hit or mem_free is None:
        rc, out, _ = sh(["/usr/bin/memory_pressure", "-Q"], timeout=4)
        if rc == 0:
            for line in out.splitlines():
                if "free percentage" in line:
                    try:
                        mem_free = int(
                            line.rstrip("%").split(":")[-1].strip().rstrip("%")
                        )
                    except ValueError:
                        pass
        if mem_used_pct is None and mem_free is not None:
            mem_used_pct = 100 - mem_free

    return {
        "t": sample_ts(time.time()) or 0,
        "load1": round(load1, 2),
        "load5": round(load5, 2),
        "load15": round(load15, 2),
        "load_pct": load_pct,
        "ncpu": ncpu,
        "cpu_used_pct": cpu_used,
        "mem_free_pct": mem_free,
        "mem_used_pct": mem_used_pct,
        "disk_pct": round(du.used / du.total * 100, 1) if du.total else None,
        "disk_used_gb": round(du.used / 2**30, 1),
        "net_rx_bps": net_rx,
        "net_tx_bps": net_tx,
        "gpu_util_pct": gpu_util_pct,
    }


def _flush_buf_locked(force_trim: bool = False) -> None:
    """Caller must hold _lock."""
    global _last_flush, _last_trim, _write_buf
    if not _write_buf:
        return
    METRICS_FILE.parent.mkdir(exist_ok=True)
    chunk = "".join(_write_buf)
    _write_buf = []
    # file_lock as well as _lock: both panel processes sharing data/ run a
    # sampler, and a ring-buffer rewrite in one used to swap away samples the
    # other had just appended to the pre-replace inode.
    with secure_io.file_lock(METRICS_FILE):
        # A leftover FIFO occupying metrics.jsonl used to park this append
        # forever — while holding _lock, so GET /api/metrics wedged behind
        # it.  Drop the non-regular node (dir/FIFO/socket) so the append
        # recreates a real journal; a disk that still refuses loses this
        # chunk, not the sampler thread.
        secure_io.drop_leftover_nonfile(METRICS_FILE)
        try:
            secure_io.append_text(METRICS_FILE, chunk)
        except OSError:
            return
        _last_flush = time.time()
        now = time.time()
        if force_trim or now - _last_trim >= _TRIM_INTERVAL:
            _last_trim = now
            try:
                # errors="replace": a torn/binary write raised UnicodeDecodeError
                # past the OSError guard below, which disabled the ring-buffer
                # trim forever and let the file grow without bound.
                lines = tail_file_lines(
                    METRICS_FILE, MAX_POINTS + _TRIM_SLACK + 1, max_bytes=4 * 1024 * 1024
                )
                if len(lines) > MAX_POINTS + _TRIM_SLACK:
                    # Atomic ring-buffer rewrite: partial write_text left a short
                    # or empty history and the next sampler grew a second full copy.
                    payload = "\n".join(lines[-MAX_POINTS:]) + "\n"
                    secure_io.replace_bytes(METRICS_FILE, payload.encode("utf-8"))
            except OSError:
                pass


def flush_metrics() -> None:
    with _lock:
        _flush_buf_locked(force_trim=True)


def flush_pending() -> None:
    """Flush buffered samples to disk without forcing a trim pass.

    Used by the rollup (hub/metrics_rollup.py) right before it reads the file
    tail, so a just-completed 5-minute window is fully on disk.  Deliberately
    not flush_metrics(): forcing the trim would re-read the whole file every
    5 minutes, defeating the hourly _TRIM_INTERVAL gate above.
    """
    with _lock:
        _flush_buf_locked()


def _decode_bytes(value) -> str:
    """Unbound base decode: a leftover subclass ``.decode`` bomb cannot 500."""
    for base in (bytes, bytearray):
        try:
            return base.decode(value, "utf-8", "replace")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
    return ""


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
    if value is None:
        return ""
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
        pass
    try:
        cls = type(value)
        if cls.__str__ is object.__str__ and cls.__repr__ is object.__repr__:
            return ""
    except _CONTROL_FLOW:
        raise
    except BaseException:
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
    if not isinstance(text, str):
        return ""
    try:
        text = str.encode(text, "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    return "" if _ADDR_REPR_RE.search(text) else text


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's allow_nan=False encoder cannot 500.

    JSON ``Infinity`` / ``NaN`` in a leftover metrics.jsonl row used to take
    down ``GET /api/metrics`` at encode time.  A leftover ``\\ud800`` string
    or key still 500'd the same encoder (``ensure_ascii=False`` then UTF-8).
    ``t`` is handled separately by :func:`sample_ts`.

    The remaining bound probes still blew on the modules5 subclass-bomb
    classes (already neutralized in sensors_svc._jsonable, never ported
    here): an int subclass whose ``__str__`` raises (only ValueError was
    caught around the digit-cap probe), a float subclass whose
    ``__eq__``/``__float__`` raises (the NaN probe and the inf
    tuple-membership probe both call it), and a bytes/bytearray subclass
    whose ``decode`` raises — as a value and as a mapping key.  Each used
    to raise straight out of this sanitizer, killing the sampler tick in
    record_sample() and escaping latest_sample()'s alert path.  Hence the
    unbound base-type coercions below, the modules5 convention.
    """
    if depth > 32:
        return None
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
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
    if isinstance(value, str):
        return _utf8_text(value)
    if isinstance(value, (bytes, bytearray)):
        return _decode_bytes(value)
    if isinstance(value, dict):
        if type(value) is not dict:
            # dict() copies through the C-level storage, ignoring overridden
            # items()/keys()/__iter__ — a leftover subclass method bomb
            # cannot fire (same guard as sensors_svc._jsonable).
            try:
                value = dict(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return None
        out = {}
        for k, v in value.items():
            if not isinstance(k, (str, bytes, bytearray)):
                try:
                    k = str(k)
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    continue
            out[_utf8_text(k)] = _jsonable(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        for base in (list, tuple, set, frozenset):
            if isinstance(value, base):
                # Unbound base iteration: a subclass ``__iter__`` bomb
                # cannot drop the real elements (``list(value)`` dispatched
                # into the override and threw the payload away with it).
                return [_jsonable(v, depth + 1) for v in base.__iter__(value)]
    try:
        iso = getattr(value, "isoformat", None)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # Property bomb / __getattr__ raising something that is not
        # AttributeError escapes getattr's default.
        iso = None
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/metrics.
            return _jsonable(iso(), depth + 1)
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


def sample_ts(raw) -> int | None:
    """Finite epoch seconds from a sample's ``t``, or None.

    JSON allows ``Infinity`` / ``NaN``, and a leftover string timestamp used
    to be skipped (or, on the rollup path, ``int(inf)`` OverflowError 500'd
    ``GET /api/metrics?range=``).  Bool is rejected: ``True`` is an ``int``.
    """
    if isinstance(raw, bool) or raw is None:
        return None
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return None
        try:
            raw = int(text)
        except ValueError:
            try:
                raw = float(text)
            except ValueError:
                return None
    if not isinstance(raw, (int, float)):
        return None
    # Base coercion first: ``float(raw)`` / ``int(raw)`` dispatch into a
    # subclass ``__float__`` / ``__int__`` / ``__trunc__``, whose modules5
    # bomb is none of the errors caught below and used to escape.
    if type(raw) not in (int, float):
        try:
            raw = int.__index__(raw) if isinstance(raw, int) else float.__float__(raw)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
    # A leftover 400-digit ``t`` (or ``?since=`` of the same) used to
    # OverflowError ``float(raw)`` / ``time.time() - since`` on the range path.
    try:
        as_float = float(raw)
    except OverflowError:
        return None
    if as_float != as_float or as_float in (float("inf"), float("-inf")):
        return None
    try:
        return int(raw)
    except (OverflowError, ValueError):
        return None


def record_sample(sample: dict | None = None, *, immediate: bool = False) -> dict:
    """Record one sample. Batched to disk unless immediate=True."""
    global _last_sample
    if sample is not None:
        # _plain_dict: a caller-provided dict-subclass whose __bool__ raised
        # used to blow up the ``sample or`` truthiness below and lose the row.
        sample = _plain_dict(sample)
    s = _jsonable(sample or _sample())
    if not isinstance(s, dict):
        s = {"t": sample_ts(time.time()) or 0}
    _last_sample = s
    try:
        line = json.dumps(s, ensure_ascii=False, allow_nan=False) + "\n"
    except (TypeError, ValueError, OverflowError, RecursionError):
        # RecursionError: leftover nested sample after _jsonable is not
        # ValueError; the sampler thread used to die before the flush.
        line = '{"t":0}\n'
    with _lock:
        _write_buf.append(line)
        now = time.time()
        should = (
            immediate
            or len(_write_buf) >= _FLUSH_EVERY_N
            or (now - _last_flush) >= _FLUSH_MAX_AGE
        )
        if should:
            _flush_buf_locked()
    return s


_last_sample: dict | None = None


def latest_sample() -> dict | None:
    """O(1) last sample for alert thresholds (no full file read)."""
    global _last_sample
    if _last_sample is not None:
        return _last_sample
    # cold start: tail last line only
    try:
        if METRICS_FILE.exists():
            # tail_file_lines, not a bare open(): a leftover FIFO occupying
            # metrics.jsonl used to park the open forever (alert thresholds
            # call this on the request path).  It raises OSError instead,
            # which the guard below already absorbs.
            lines = [
                ln for ln in tail_file_lines(METRICS_FILE, 64, max_bytes=4096)
                if ln.strip()
            ]
            if lines:
                parsed = safe_json_loads(lines[-1], loads=json.loads)
                if isinstance(parsed, dict):
                    _last_sample = _jsonable(parsed)
                    return _last_sample
    except (OSError, ValueError, RecursionError):
        # RecursionError: leftover deeply-nested metrics.jsonl is not ValueError.
        pass
    return None


def history(minutes: int = 60) -> list:
    # include buffered points not yet on disk
    now = sample_ts(time.time()) or 0
    try:
        span = int(minutes) * 60
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # Leftover ``minutes: .inf`` / ``int(time.time())`` on inf used to
        # OverflowError GET /api/metrics.  Exception, not the three usual
        # conversion errors: ``int()`` of a leftover subclass dispatches
        # into its own ``__int__``/``__index__``, whose bomb is neither.
        span = 3600
    if span < 0:
        span = 3600
    cutoff = now - span
    out = []
    try:
        if METRICS_FILE.exists():
            # errors="replace", matching the trim: mangled lines fail the
            # per-line json parse below and are skipped, not raised.
            for line in tail_file_lines(
                METRICS_FILE, MAX_POINTS, max_bytes=4 * 1024 * 1024
            ):
                if not line.strip():
                    continue
                try:
                    o = safe_json_loads(line)
                except (ValueError, RecursionError):
                    # ValueError, not just JSONDecodeError: a leftover
                    # >4300-digit number raises CPython's str->int digit-cap
                    # ValueError out of json.loads, which used to 500
                    # GET /api/metrics on that line.
                    continue
                t = sample_ts(o.get("t") if isinstance(o, dict) else None)
                if t is not None and t >= cutoff:
                    o = _jsonable(o) if isinstance(o, dict) else None
                    if not isinstance(o, dict):
                        continue
                    o["t"] = t
                    out.append(o)
    except OSError:
        pass
    with _lock:
        for line in _write_buf:
            try:
                o = safe_json_loads(line)
            except (ValueError, RecursionError):
                continue
            t = sample_ts(o.get("t") if isinstance(o, dict) else None)
            if t is not None and t >= cutoff:
                o = _jsonable(o) if isinstance(o, dict) else None
                if not isinstance(o, dict):
                    continue
                o["t"] = t
                out.append(o)
    return out


def _loop(interval: int = 90):
    from hub import worker_health
    worker_health.register("metrics-sampler", interval)
    tick = 0
    while not _stop.is_set():
        try:
            worker_health.beat("metrics-sampler")
            tick += 1
            # The first pass flushes rather than buffering, which is what
            # start_sampler used to do on the caller's thread.  Taking it here
            # keeps a data point on disk promptly without the startup path
            # waiting for it.
            record_sample(immediate=(tick == 1))
            # Long-term history rides on this thread rather than owning one:
            # maybe_rollup() is an integer comparison per tick and only does
            # file IO when a wall-clock 5-minute/1-hour window has completed
            # since its persisted watermark (see hub/metrics_rollup.py).
            try:
                from hub import metrics_rollup
                metrics_rollup.maybe_rollup()
            except _CONTROL_FLOW:
                raise
            except BaseException:
                pass
        except _CONTROL_FLOW:
            raise
        except BaseException:
            pass
        _stop.wait(interval)
    # flush remaining on stop
    try:
        flush_metrics()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        pass


def start_sampler(interval: int = 90):
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop.clear()
    # Deliberately not sampling here.  This runs inside the FastAPI lifespan, so
    # anything it waits for delays the moment uvicorn starts serving -- and a cold
    # _sample() measured 1257ms on this host, which is most of the window where a
    # restarted panel looks hung.  The sampler thread takes the first sample as
    # its own first iteration instead, so nothing is lost: _loop samples before
    # its first wait, and latest_sample() already falls back to tailing the
    # metrics file while _last_sample is still unset.
    from hub.worker_health import loop_interval
    _thread = threading.Thread(
        target=_loop, args=(loop_interval(interval),), daemon=True, name="metrics-sampler"
    )
    _thread.start()


def stop_sampler(timeout: float = 3.0) -> None:
    """Stop the sampler and flush buffered metrics during app shutdown."""
    global _thread
    _stop.set()
    # A deliberately stopped worker must not be reported as a dead one.
    from hub import worker_health
    worker_health.unregister("metrics-sampler")
    thread = _thread
    if thread and thread.is_alive() and thread is not threading.current_thread():
        thread.join(timeout=timeout)
    _thread = None
    try:
        flush_metrics()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        pass
