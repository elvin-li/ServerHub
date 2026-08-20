"""Host system metrics."""
from __future__ import annotations

import os
import re
import shutil
import time
from hub.paths import SMARTCTL
from hub.util import LazyPool, sh

_pool = LazyPool(4, "hub-system")


def shutdown_executor() -> None:
    _pool.shutdown()

_smart_cache = {"t": 0.0, "v": None}


def _as_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    elif value is None:
        return ""
    else:
        try:
            value = str(value)
        except RecursionError:
            try:
                return type(value).__name__
            except Exception:
                return ""
        except Exception:
            return ""
    return value.encode("utf-8", "replace").decode("utf-8")


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's allow_nan=False encoder cannot 500.

    OverflowError on huge memsize / disk / boottime was already isolated;
    leftover ``\\ud800`` / inf in the SMART cache still leaked into
    GET /api/status's ``system`` object when the status sanitizer was
    bypassed (and into any direct collect_system caller).
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
        return _as_text(value)
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
            out[_as_text(k)] = _jsonable(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v, depth + 1) for v in value]
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/status system.
            return _jsonable(iso(), depth + 1)
        except Exception:
            return None
    try:
        return _as_text(value)
    except Exception:
        return None


def _sysctl_int(value) -> int | None:
    """int from a sysctl `-n` payload that may be str, bytes, or already int."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    text = _as_text(value).strip()
    return int(text) if text.isdigit() else None


def _after_colon(line: str) -> str | None:
    if ":" not in line:
        return None
    return line.split(":", 1)[1].strip() or None


def _finite_float(value) -> float | None:
    """float from a memory_pressure token, or None for inf/NaN/overflow."""
    try:
        n = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if n != n or n in (float("inf"), float("-inf")):
        return None
    return n


def _safe_div(num, den) -> float | None:
    """num/den as a finite float. Huge ints OverflowError'd collect_system."""
    try:
        return _finite_float(num / den)
    except (TypeError, ZeroDivisionError, OverflowError):
        return None


def _bytes_to_gb(n, digits: int | None = 1):
    ratio = _safe_div(n, 2**30)
    if ratio is None:
        return None
    return round(ratio) if digits is None else round(ratio, digits)


def _mem_free_pct(out) -> int | None:
    """Free-memory percent from ``memory_pressure -Q``, or None if unreadable.

    ``int(float(raw))`` used to OverflowError on ``inf%`` / huge digit strings
    and 500 ``/api/status``.  A matching line that does not parse is skipped
    rather than poisoning the whole snapshot.
    """
    mem_free = None
    for line in _as_text(out).splitlines():
        if "free percentage" not in line:
            continue
        m = re.search(r"(\d+(?:\.\d+)?)\s*%", line)
        raw = m.group(1) if m else line.split(":")[-1].strip().rstrip("%")
        n = _finite_float(raw)
        if n is None:
            continue
        try:
            mem_free = int(n)
        except (TypeError, ValueError, OverflowError):
            continue
    return mem_free


def collect_system():
    try:
        raw_load = os.getloadavg()
    except OSError:
        load1 = load5 = load15 = None
    else:
        load1 = _finite_float(raw_load[0]) if len(raw_load) > 0 else None
        load5 = _finite_float(raw_load[1]) if len(raw_load) > 1 else None
        load15 = _finite_float(raw_load[2]) if len(raw_load) > 2 else None

    try:
        du = shutil.disk_usage("/")
        used = getattr(du, "used", 0) or 0
        total = getattr(du, "total", 0) or 0
        free = getattr(du, "free", 0) or 0
    except Exception:
        # A dying root mount used to OSError/RuntimeError collect_system
        # and empty the ``system`` object on GET /api/status.
        used = total = free = None

    # This is one leg of the /api/status fan-out, which the dashboard polls every
    # 12s, so its own internals sit on that endpoint's critical path. The four
    # reads below are independent, and two of them are the slow ones:
    # `memory_pressure -Q` and — once every 10 minutes — a `sudo -n smartctl`.
    # Running them in sequence made the whole status refresh wait for their sum.
    smart_due = time.time() - _smart_cache["t"] > 600
    def _ncpu_and_memsize():
        # One worker, two cheap sysctls: the pool is already full with boot /
        # memory_pressure / (sometimes) smartctl, and hw.memsize is what lets
        # the dashboard print RAM total from /api/status before sensors land.
        rc_n, ncpu, _ = sh(["/usr/sbin/sysctl", "-n", "hw.ncpu"], timeout=2)
        rc_m, memsize, _ = sh(["/usr/sbin/sysctl", "-n", "hw.memsize"], timeout=2)
        return rc_n, ncpu, rc_m, memsize

    f_boot = _pool.submit(sh, ["/usr/sbin/sysctl", "-n", "kern.boottime"], timeout=3)
    f_mem = _pool.submit(sh, ["/usr/bin/memory_pressure", "-Q"], timeout=4)
    f_hw = _pool.submit(_ncpu_and_memsize)
    f_smart = (
        _pool.submit(sh, ["/usr/bin/sudo", "-n", SMARTCTL, "-a", "/dev/disk0"], timeout=10)
        if smart_due
        else None
    )

    def _result(fut, fallback):
        try:
            return fut.result()
        except Exception:
            return fallback

    # `.result()` re-raises; memory_pressure must not drop load/disk from /api/status.
    rc, out, _ = _result(f_boot, (1, "", ""))
    out = _as_text(out)
    uptime_h = 0.0
    if rc == 0 and "sec =" in out:
        try:
            boot = int(out.split("sec =")[1].split(",")[0].strip())
        except (IndexError, TypeError, ValueError, OverflowError):
            boot = 0
        if boot:
            try:
                uptime_h = (time.time() - boot) / 3600
            except (TypeError, OverflowError):
                uptime_h = 0.0
            else:
                n = _finite_float(uptime_h)
                uptime_h = n if n is not None else 0.0

    rc, out, _ = _result(f_mem, (1, "", ""))
    mem_free = _mem_free_pct(out)

    rc_n, ncpu, rc_m, memsize = _result(f_hw, (1, "", 1, ""))
    ncpu_i = _sysctl_int(ncpu) if rc_n == 0 else None
    mem_n = _sysctl_int(memsize) if rc_m == 0 else None
    mem_total_gb = _bytes_to_gb(mem_n, 1) if mem_n is not None else None

    smart = _smart_cache["v"]
    if f_smart is not None:
        rc, out, _ = _result(f_smart, (1, "", ""))
        if rc in (0, 4):
            smart = {}
            for line in _as_text(out).splitlines():
                if "Data Units Written" in line and "[" in line:
                    smart["written"] = line.split("[")[1].rstrip("]")
                elif "Percentage Used" in line:
                    wear = _after_colon(line)
                    if wear:
                        smart["wear"] = wear
                elif line.strip().startswith("Temperature:"):
                    temp = _after_colon(line)
                    if temp:
                        smart.setdefault("temp", temp)
                elif "Temperature_Celsius" in line:
                    parts = line.split()
                    if len(parts) >= 10:
                        smart.setdefault("temp", f"{parts[9]} Celsius")
                elif "Airflow_Temperature" in line:
                    parts = line.split()
                    if len(parts) >= 10:
                        smart.setdefault("temp", f"{parts[9]} Celsius")
            _smart_cache.update(t=time.time(), v=smart)
    n = ncpu_i or 1
    load_pct = None
    if load1 is not None:
        ratio = _safe_div(load1 * 100, n)
        if ratio is not None:
            load_pct = round(min(200.0, ratio), 1)
    disk_ratio = _safe_div(used, total) if total else None
    disk_pct = round(disk_ratio * 100) if disk_ratio is not None else 0
    try:
        days = int(uptime_h // 24)
        hours = int(uptime_h % 24)
    except (TypeError, ValueError, OverflowError):
        days, hours = 0, 0
        uptime_h = 0.0
    if load1 is None or load5 is None or load15 is None:
        load_s = ""
    else:
        load_s = f"{round(load1, 2):.2f} / {round(load5, 2):.2f} / {round(load15, 2):.2f}"
    cleaned = _jsonable({
        "load": load_s,
        "load1": None if load1 is None else round(load1, 2),
        "load5": None if load5 is None else round(load5, 2),
        "load15": None if load15 is None else round(load15, 2),
        "load_pct": load_pct,
        "ncpu": ncpu_i,
        "mem_total_gb": mem_total_gb,
        "mem_free_pct": mem_free,
        "mem_used_pct": (100 - mem_free) if mem_free is not None else None,
        "disk_used_gb": _bytes_to_gb(used, None),
        "disk_total_gb": _bytes_to_gb(total, None),
        "disk_free_gb": _bytes_to_gb(free, None),
        "disk_pct": disk_pct,
        "uptime": (
            f"{days} days {hours} hours"
            if uptime_h >= 24
            else f"{uptime_h:.1f} hours"
        ),
        "uptime_hours": round(uptime_h, 2),
        "smart": smart,
    })
    return cleaned if isinstance(cleaned, dict) else {}
