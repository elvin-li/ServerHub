"""Host metrics history (ring buffer on disk) — SSD-friendly batched writes."""
from __future__ import annotations

import json
import os
import shutil
import threading
import time

from hub import secure_io
from hub.paths import DATA_DIR
from hub.util import safe_json_loads, sh, tail_file_lines

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
        except (TypeError, ValueError, OverflowError):
            # Leftover planted ``n: .inf`` OverflowError'd ``int(inf)``.
            n = 0
        if n > 0:
            return n
    from hub import macos_sysctl

    n = macos_sysctl.sysctl_int("hw.ncpu", timeout=2, sh=sh)
    try:
        n = int(n) if n is not None else 1
    except (TypeError, ValueError, OverflowError):
        n = 1
    if n <= 0:
        n = 1
    _ncpu_cache.update(t=now, n=n)
    return n


def _sensors_snapshot() -> dict | None:
    """Reuse a warm full sample, otherwise a light one — never spawn ``top``.

    ``collect_sensors()`` on a cold cache measured 0.85–1.6s here, almost all
    of it ``top -l 1``.  The sampler runs with nobody looking; a jsonl point
    only needs load, pressure, and Mach CPU ticks.
    """
    try:
        from hub import sensors_svc
        hit = sensors_svc.peek_sensors()
        if hit is not None:
            return hit
        from hub.resource_mode import is_high
        if is_high():
            return sensors_svc.collect_sensors()
        return sensors_svc.collect_light()
    except Exception:
        return None


def _cpu_used_quick(sensors: dict | None = None) -> float | None:
    """Lightweight CPU used % without full top if sensors cache warm."""
    s = sensors if sensors is not None else _sensors_snapshot()
    try:
        if s and s.get("cpu_used_pct") is not None:
            return float(s["cpu_used_pct"])
    except (TypeError, ValueError, OverflowError):
        pass
    try:
        load1 = os.getloadavg()[0]
        n = _ncpu()
        return round(min(100.0, load1 / n * 100), 1)
    except Exception:
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
    sensors_hit = bool(s)
    if s:
        net = s.get("network") or {}
        net_rx = net.get("rx_bps")
        net_tx = net.get("tx_bps")
        m = s.get("memory") or {}
        if m.get("pressure_used_pct") is not None:
            mem_used_pct = m["pressure_used_pct"]
            mem_free = m.get("pressure_free_pct", mem_free)
        elif m.get("used_pct") is not None:
            mem_used_pct = m["used_pct"]
            mem_free = m.get("free_pct", mem_free)
        if s.get("cpu_used_pct") is not None:
            try:
                cpu_used = min(100.0, max(0.0, float(s["cpu_used_pct"])))
            except (TypeError, ValueError, OverflowError):
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
                except (TypeError, ValueError, OverflowError):
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
    secure_io.append_text(METRICS_FILE, chunk)
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


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's allow_nan=False encoder cannot 500.

    JSON ``Infinity`` / ``NaN`` in a leftover metrics.jsonl row used to take
    down ``GET /api/metrics`` at encode time.  A leftover ``\\ud800`` string
    or key still 500'd the same encoder (``ensure_ascii=False`` then UTF-8).
    ``t`` is handled separately by :func:`sample_ts`.
    """
    if depth > 32:
        return None
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if isinstance(value, str):
        return _utf8_text(value)
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if not isinstance(k, (str, bytes, bytearray)):
                try:
                    k = str(k)
                except Exception:
                    continue
            out[_utf8_text(k)] = _jsonable(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v, depth + 1) for v in value]
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/metrics.
            return _jsonable(iso(), depth + 1)
        except Exception:
            return None
    try:
        return _utf8_text(value)
    except Exception:
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
    if sample is not None and not isinstance(sample, dict):
        sample = None
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
            # read last ~4KB
            with open(METRICS_FILE, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - 4096))
                chunk = f.read().decode(errors="replace")
            lines = [ln for ln in chunk.splitlines() if ln.strip()]
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
    except (TypeError, ValueError, OverflowError):
        # Leftover ``minutes: .inf`` / ``int(time.time())`` on inf used to
        # OverflowError GET /api/metrics.
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
                except (json.JSONDecodeError, RecursionError):
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
            except (json.JSONDecodeError, RecursionError):
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
            except Exception:
                pass
        except Exception:
            pass
        _stop.wait(interval)
    # flush remaining on stop
    try:
        flush_metrics()
    except Exception:
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
    except Exception:
        pass
