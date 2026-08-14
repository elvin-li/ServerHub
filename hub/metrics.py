"""Host metrics history (ring buffer on disk) — SSD-friendly batched writes."""
from __future__ import annotations

import json
import os
import shutil
import threading
import time

from hub.paths import DATA_DIR
from hub.util import sh

METRICS_FILE = DATA_DIR / "metrics.jsonl"
# ~48h at 90s interval ≈ 1920 points; keep headroom
MAX_POINTS = 2880
_lock = threading.Lock()
_thread: threading.Thread | None = None
_stop = threading.Event()
_last_trim = 0.0
_TRIM_INTERVAL = 900.0  # full rewrite at most every 15 min
_ncpu_cache: dict = {"t": 0.0, "n": None}
_NCPU_TTL = 600.0
# In-memory batch: fewer fsync/small-write cycles on SSD
_write_buf: list[str] = []
_last_flush = 0.0
_FLUSH_EVERY_N = 2          # flush every N samples
_FLUSH_MAX_AGE = 180.0      # or at least every 3 min


def _ncpu() -> int:
    now = time.time()
    if _ncpu_cache["n"] is not None and now - _ncpu_cache["t"] < _NCPU_TTL:
        return int(_ncpu_cache["n"])
    rc, ncpu_s, _ = sh(["/usr/sbin/sysctl", "-n", "hw.ncpu"], timeout=2)
    n = int(ncpu_s) if rc == 0 and ncpu_s.isdigit() else 1
    _ncpu_cache.update(t=now, n=n)
    return n


def _cpu_used_quick() -> float | None:
    """Lightweight CPU used % without full top if sensors cache warm."""
    try:
        from hub import sensors_svc
        s = sensors_svc.collect_sensors(force=False)
        if s.get("cpu_used_pct") is not None:
            return float(s["cpu_used_pct"])
    except Exception:
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
    cpu_used = _cpu_used_quick()
    mem_used_pct = None
    load_pct = round(min(200.0, load1 / ncpu * 100), 1) if ncpu else None

    net_rx = net_tx = None
    sensors_hit = False
    try:
        from hub import sensors_svc
        s = sensors_svc.collect_sensors(force=False)
        sensors_hit = bool(s)
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
            cpu_used = s["cpu_used_pct"]
    except Exception:
        pass

    if not sensors_hit or mem_free is None:
        rc, out, _ = sh(["memory_pressure", "-Q"], timeout=4)
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
        "t": int(time.time()),
        "load1": round(load1, 2),
        "load5": round(load5, 2),
        "load15": round(load15, 2),
        "load_pct": load_pct,
        "ncpu": ncpu,
        "cpu_used_pct": cpu_used,
        "mem_free_pct": mem_free,
        "mem_used_pct": mem_used_pct,
        "disk_pct": round(du.used / du.total * 100, 1),
        "disk_used_gb": round(du.used / 2**30, 1),
        "net_rx_bps": net_rx,
        "net_tx_bps": net_tx,
    }


def _flush_buf_locked(force_trim: bool = False) -> None:
    """Caller must hold _lock."""
    global _last_flush, _last_trim, _write_buf
    if not _write_buf:
        return
    METRICS_FILE.parent.mkdir(exist_ok=True)
    chunk = "".join(_write_buf)
    _write_buf = []
    with open(METRICS_FILE, "a") as f:
        f.write(chunk)
    _last_flush = time.time()
    now = time.time()
    if force_trim or now - _last_trim >= _TRIM_INTERVAL:
        _last_trim = now
        try:
            lines = METRICS_FILE.read_text().splitlines()
            if len(lines) > MAX_POINTS:
                trimmed = "\n".join(lines[-MAX_POINTS:]) + "\n"
                tmp = METRICS_FILE.with_suffix(".jsonl.tmp")
                tmp.write_text(trimmed)
                os.replace(tmp, METRICS_FILE)
        except OSError:
            pass


def flush_metrics() -> None:
    with _lock:
        _flush_buf_locked(force_trim=True)


def record_sample(sample: dict | None = None, *, immediate: bool = False) -> dict:
    """Record one sample. Batched to disk unless immediate=True."""
    global _last_sample
    s = sample or _sample()
    _last_sample = s
    line = json.dumps(s, ensure_ascii=False) + "\n"
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
                _last_sample = json.loads(lines[-1])
                return _last_sample
    except Exception:
        pass
    return None


def history(minutes: int = 60) -> list:
    # include buffered points not yet on disk
    cutoff = int(time.time()) - minutes * 60
    out = []
    try:
        if METRICS_FILE.exists():
            for line in METRICS_FILE.read_text().splitlines():
                if not line.strip():
                    continue
                try:
                    o = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if o.get("t", 0) >= cutoff:
                    out.append(o)
    except OSError:
        pass
    with _lock:
        for line in _write_buf:
            try:
                o = json.loads(line)
            except json.JSONDecodeError:
                continue
            if o.get("t", 0) >= cutoff:
                out.append(o)
    return out


def _loop(interval: int = 90):
    tick = 0
    while not _stop.is_set():
        try:
            tick += 1
            try:
                from hub import sensors_svc
                # Force sensors less often: every 3rd sample (~4.5 min at 90s)
                sensors_svc.collect_sensors(force=(tick % 3 == 1))
            except Exception:
                pass
            # The first pass flushes rather than buffering, which is what
            # start_sampler used to do on the caller's thread.  Taking it here
            # keeps a data point on disk promptly without the startup path
            # waiting for it.
            record_sample(immediate=(tick == 1))
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
    _thread = threading.Thread(
        target=_loop, args=(max(30, int(interval)),), daemon=True, name="metrics-sampler"
    )
    _thread.start()


def stop_sampler(timeout: float = 3.0) -> None:
    """Stop the sampler and flush buffered metrics during app shutdown."""
    global _thread
    _stop.set()
    thread = _thread
    if thread and thread.is_alive() and thread is not threading.current_thread():
        thread.join(timeout=timeout)
    _thread = None
    try:
        flush_metrics()
    except Exception:
        pass
