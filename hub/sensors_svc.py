"""Rich host sensors — Glances / Unraid Dashboard style (macOS)."""
from __future__ import annotations

import ctypes
import os
import plistlib
import re
import shutil
import threading
import time
from pathlib import Path

from hub.proc_cache import ps_lines
from hub.util import LazyPool, sh, strftime_now


def _as_text(value) -> str:
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    if value is None:
        return ""
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

    Inf CPU / huge RSS were already dropped at parse; leftover ``\\ud800``
    in a process name, leftover bytes, or a leftover inf planted in the
    peek cache still 500'd GET /api/system/sensors?light=1.
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
            # used to skip the float sanitizer and 500 GET /api/system/sensors.
            return _jsonable(iso(), depth + 1)
        except Exception:
            return None
    try:
        return _utf8_text(value)
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


def _finite_float(value) -> float | None:
    """float from a sensor token, or None for inf/NaN/overflow."""
    try:
        n = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if n != n or n in (float("inf"), float("-inf")):
        return None
    return n


def _safe_div(num, den) -> float | None:
    """num/den as a finite float. Huge ints used to OverflowError the dashboard."""
    try:
        return _finite_float(num / den)
    except (TypeError, ZeroDivisionError, OverflowError):
        return None


def _bytes_to_gb(n, digits: int = 1) -> float | None:
    ratio = _safe_div(n, 2**30)
    return None if ratio is None else round(ratio, digits)

# ── Mach host CPU ticks — accurate, non-blocking CPU% via cumulative deltas ──
# host_statistics(HOST_CPU_LOAD_INFO) returns lifetime ticks in
# [user, system, idle, nice]. Diffing two reads gives true busy% over the
# interval — matching Activity Monitor without top's 1s sampling block.
_HOST_CPU_LOAD_INFO = 3
_CPU_STATE_MAX = 4


class _HostCpuLoadInfo(ctypes.Structure):
    _fields_ = [("ticks", ctypes.c_uint * _CPU_STATE_MAX)]


try:
    _libc = ctypes.CDLL("/usr/lib/libSystem.dylib")
    _libc.mach_host_self.restype = ctypes.c_uint
except Exception:  # pragma: no cover — non-macOS / sandbox
    _libc = None

_cpu_ticks_prev: list[int] | None = None
_cpu_ticks_lock = threading.Lock()


def _read_cpu_ticks() -> list[int] | None:
    if _libc is None:
        return None
    try:
        host = _libc.mach_host_self()
        info = _HostCpuLoadInfo()
        count = ctypes.c_uint(_CPU_STATE_MAX)
        rc = _libc.host_statistics(
            host, _HOST_CPU_LOAD_INFO, ctypes.byref(info), ctypes.byref(count)
        )
        if rc != 0:
            return None
        return list(info.ticks)  # [user, system, idle, nice]
    except Exception:
        return None


def _cpu_from_ticks() -> dict | None:
    """Busy%/user/sys/idle from the delta since the previous read.

    First call seeds the baseline with a tiny 0.15s sample (once per process);
    every later call is an instant diff against the prior collection.
    """
    global _cpu_ticks_prev
    with _cpu_ticks_lock:
        cur = _read_cpu_ticks()
        if cur is None:
            return None
        prev = _cpu_ticks_prev
        if prev is None:
            # One-time bootstrap so the very first sample is meaningful.
            time.sleep(0.15)
            nxt = _read_cpu_ticks()
            if nxt is None:
                _cpu_ticks_prev = cur
                return None
            prev, cur = cur, nxt
        # c_uint wrap or a short noisy window can make a field go backwards;
        # re-seed instead of publishing used_pct > 100 (measured 149% once).
        if any(c < p for c, p in zip(cur, prev)):
            _cpu_ticks_prev = cur
            return None
        _cpu_ticks_prev = cur
    du = cur[0] - prev[0]
    ds = cur[1] - prev[1]
    di = cur[2] - prev[2]
    dn = cur[3] - prev[3]
    busy = du + ds + dn
    total = busy + di
    if total <= 0:
        return None
    used = round(busy / total * 100, 1)
    if used > 100.0:
        return None
    return {
        "user": round((du + dn) / total * 100, 1),
        "sys": round(ds / total * 100, 1),
        "idle": round(di / total * 100, 1),
        "used_pct": used,
    }


_cache = {"t": 0.0, "v": None}
# Above the Dashboard's 20s light poll: a shorter TTL expired every tick and
# re-ran top (measured 1.6s here).  30s lets two UI polls share one sample.
_TTL = 30.0
_TTL_HIGH = 15.0
#: `top -l 1` is the expensive half of a sensors collect.  PhysMem breakdown
#: changes slowly; reuse it across a couple of UI polls.
_TOP_TTL = 60.0
_TOP_TTL_HIGH = 20.0


def _sensors_ttl() -> float:
    from hub.resource_mode import is_high
    return _TTL_HIGH if is_high() else _TTL


def _top_ttl() -> float:
    from hub.resource_mode import is_high
    return _TOP_TTL_HIGH if is_high() else _TOP_TTL
_top_cache = {"t": 0.0, "v": None}
_refresh_lock = threading.Lock()
_net_prev = {"t": 0.0, "rx": 0, "tx": 0}
# hw.ncpu / memsize / pagesize almost never change at runtime
_static = {"t": 0.0, "ncpu": None, "mem_gb": None, "page_size": 16384}
_STATIC_TTL = 300.0
_pool = LazyPool(9, "hub-sensors")


def shutdown_executor() -> None:
    _pool.shutdown()


def _parse_size_to_gb(token: str) -> float | None:
    """Parse 30G / 2548M / 975M / 1.2T into GB."""
    token = _as_text(token).strip().replace(",", "")
    m = re.match(r"^([\d.]+)\s*([KMGTP]?)B?$", token, re.I)
    if not m:
        return None
    n = _finite_float(m.group(1))
    if n is None:
        return None
    u = (m.group(2) or "G").upper()
    mul = {"": 1 / 1024**3, "K": 1 / 1024**2, "M": 1 / 1024, "G": 1, "T": 1024, "P": 1024**2}
    out = n * mul.get(u, 1)
    if out != out or out in (float("inf"), float("-inf")):
        return None
    return round(out, 2)


def _cpu_and_mem_from_top_cached() -> dict:
    now = time.time()
    if _top_cache["v"] is not None and now - _top_cache["t"] < _top_ttl():
        return _top_cache["v"]
    value = _cpu_and_mem_from_top() or {}
    _top_cache.update(t=now, v=value)
    return value


def _cpu_and_mem_from_top() -> dict:
    """Single fast top sample for PhysMem + load snapshots (point-in-time).

    CPU% is NOT taken from here — top's single-frame CPU line over-reports on
    macOS. Accurate CPU busy% comes from _cpu_from_ticks() (Mach deltas). The
    CPU line is still parsed as a last-resort fallback only.
    """
    rc, out, _ = sh(["/usr/bin/top", "-l", "1", "-n", "0", "-s", "0"], timeout=10)
    if rc != 0:
        return {}
    data: dict = {}
    for line in _as_text(out).splitlines():
        if "CPU usage" in line:
            for part in line.split(":")[-1].split(","):
                part = part.strip()
                if "% user" in part:
                    n = _finite_float(part.replace("% user", "").strip())
                    if n is not None:
                        data["user"] = n
                elif "% sys" in part:
                    n = _finite_float(part.replace("% sys", "").strip())
                    if n is not None:
                        data["sys"] = n
                elif "% idle" in part:
                    n = _finite_float(part.replace("% idle", "").strip())
                    if n is not None:
                        data["idle"] = n
        if line.startswith("Load Avg:"):
            nums = line.split(":")[-1].replace(" ", "").split(",")
            n1 = _finite_float(nums[0]) if nums else None
            n5 = _finite_float(nums[1]) if len(nums) > 1 else None
            n15 = _finite_float(nums[2]) if len(nums) > 2 else None
            if n1 is not None:
                data["load1"] = n1
            if n5 is not None:
                data["load5"] = n5
            if n15 is not None:
                data["load15"] = n15
        if line.startswith("PhysMem:"):
            raw = line.split(":", 1)[1].strip()
            data["physmem_raw"] = raw
            # 30G used (2548M wired, 1309M compressor), 975M unused.
            m_used = re.search(r"([\d.]+[KMGTP]?)\s+used", raw, re.I)
            m_unused = re.search(r"([\d.]+[KMGTP]?)\s+unused", raw, re.I)
            m_wired = re.search(r"([\d.]+[KMGTP]?)\s+wired", raw, re.I)
            m_comp = re.search(r"([\d.]+[KMGTP]?)\s+compressor", raw, re.I)
            if m_used:
                data["mem_used_gb"] = _parse_size_to_gb(m_used.group(1))
            if m_unused:
                data["mem_unused_gb"] = _parse_size_to_gb(m_unused.group(1))
            if m_wired:
                data["mem_wired_gb"] = _parse_size_to_gb(m_wired.group(1))
            if m_comp:
                data["mem_compressor_gb"] = _parse_size_to_gb(m_comp.group(1))
        if line.startswith("Networks:"):
            # Networks: packets: 123/456 in, 78/90 out.
            data["networks_raw"] = line.split(":", 1)[1].strip()
        if line.startswith("Disks:"):
            data["disks_raw"] = line.split(":", 1)[1].strip()
        if "processes:" in line.lower() and "total" in line.lower():
            # Processes: 512 total, 8 running, 504 sleeping...
            data["processes_raw"] = line.strip()
            m = re.search(r"(\d+)\s+total", line)
            if m:
                data["proc_total"] = int(m.group(1))
            m = re.search(r"(\d+)\s+running", line)
            if m:
                data["proc_running"] = int(m.group(1))
    return data


def _static_hw() -> dict:
    """ncpu / total RAM / page size — stable, cached 5 min."""
    now = time.time()
    if _static["ncpu"] is not None and now - _static["t"] < _STATIC_TTL:
        return {
            "ncpu": _static["ncpu"],
            "mem_total_gb": _static["mem_gb"],
            "page_size": _static["page_size"],
        }
    from hub import macos_sysctl

    ncpu_i = macos_sysctl.sysctl_int("hw.ncpu", timeout=2, sh=sh)
    mem_n = macos_sysctl.sysctl_int("hw.memsize", timeout=2, sh=sh)
    pgsz = macos_sysctl.sysctl_int("hw.pagesize", timeout=2, sh=sh)
    mem_gb = _bytes_to_gb(mem_n) if mem_n is not None else None
    page_n = pgsz
    page_size = page_n if page_n else 16384
    _static.update(t=now, ncpu=ncpu_i, mem_gb=mem_gb, page_size=page_size)
    return {"ncpu": ncpu_i, "mem_total_gb": mem_gb, "page_size": page_size}


def _memory_base() -> dict:
    try:
        raw_load = os.getloadavg()
    except OSError:
        load1 = load5 = load15 = None
    else:
        load1 = _finite_float(raw_load[0])
        load5 = _finite_float(raw_load[1])
        load15 = _finite_float(raw_load[2])
    rc, out, _ = sh(["/usr/bin/memory_pressure", "-Q"], timeout=4)
    free_pct = None
    pages_free = pages_spec = pages_inactive = pages_wired = None
    for line in _as_text(out).splitlines():
        low = line.lower()
        if "free percentage" in low:
            # ``int(float('inf'))`` OverflowError'd collect_light / the
            # dashboard light poll; skip a matching line that is not finite.
            m = re.search(r"(\d+(?:\.\d+)?)\s*%", line)
            raw = m.group(1) if m else line.split(":")[-1].strip().rstrip("%")
            n = _finite_float(raw)
            if n is not None:
                try:
                    free_pct = int(n)
                except (TypeError, ValueError, OverflowError):
                    pass
        elif "pages free" in low:
            try:
                pages_free = int(re.findall(r"\d+", line)[-1])
            except (IndexError, TypeError, ValueError):
                pass
        elif "pages speculative" in low:
            try:
                pages_spec = int(re.findall(r"\d+", line)[-1])
            except (IndexError, TypeError, ValueError):
                pass
        elif "pages inactive" in low:
            try:
                pages_inactive = int(re.findall(r"\d+", line)[-1])
            except (IndexError, TypeError, ValueError):
                pass
        elif "pages wired down" in low:
            try:
                pages_wired = int(re.findall(r"\d+", line)[-1])
            except (IndexError, TypeError, ValueError):
                pass
    hw = _static_hw()
    return {
        "load1": None if load1 is None else round(load1, 2),
        "load5": None if load5 is None else round(load5, 2),
        "load15": None if load15 is None else round(load15, 2),
        "mem_free_pct": free_pct,
        "mem_used_pct": (100 - free_pct) if free_pct is not None else None,
        "ncpu": hw["ncpu"],
        "mem_total_gb": hw["mem_total_gb"],
        "page_size": hw["page_size"],
        "pages_free": pages_free,
        "pages_speculative": pages_spec,
        "pages_inactive": pages_inactive,
        "pages_wired": pages_wired,
    }


def _disk() -> dict:
    try:
        du = shutil.disk_usage("/")
    except OSError:
        # A dying root mount used to OSError collect_light / the dashboard.
        return {
            "root_pct": 0,
            "root_used_gb": None,
            "root_total_gb": None,
            "root_free_gb": None,
        }
    total = du.total or 0
    used = du.used or 0
    free = du.free or 0
    pct = 0
    if total:
        ratio = _safe_div(used, total)
        if ratio is not None:
            pct = round(min(100.0, max(0.0, ratio * 100)), 1)
    return {
        "root_pct": pct,
        "root_used_gb": _bytes_to_gb(used),
        "root_total_gb": _bytes_to_gb(total),
        "root_free_gb": _bytes_to_gb(free),
    }


def _top_processes(limit: int = 8) -> list:
    """Top CPU rows from the shared ``ps aux`` table.

    A dedicated ``ps -A -o … -r`` used to run on every full sensors sample
    and timed out on this host while ``proc_cache`` already held the same
    table for the request.  ``aux`` is not CPU-sorted, so we sort here.
    """
    lines = ps_lines()
    if len(lines) < 2:
        return []
    rows = []
    for line in lines[1:]:
        parts = line.split(None, 10)
        if len(parts) < 11:
            continue
        try:
            pid = int(parts[1])
        except (TypeError, ValueError, OverflowError):
            continue
        # inf/nan %CPU in `ps aux` used to leak into GET /api/system/sensors
        # (Starlette allow_nan=False). A 400-digit RSS OverflowError'd / 1024.
        cpu = _finite_float(parts[2])
        mem = _finite_float(parts[3])
        if cpu is None or mem is None:
            continue
        try:
            rss_kb = int(parts[5])
        except (TypeError, ValueError, OverflowError):
            rss_mb = None
        else:
            rss = _safe_div(rss_kb, 1024)
            rss_mb = None if rss is None else round(rss, 1)
        name = parts[10].strip()
        if "/" in name:
            name = name.split(None, 1)[0].rsplit("/", 1)[-1]
        rows.append({
            "pid": pid,
            "cpu": round(cpu, 1),
            "mem": round(mem, 1),
            "rss_mb": rss_mb,
            "name": name[:40],
        })
    rows.sort(key=lambda r: (r["cpu"], r["mem"]), reverse=True)
    try:
        cap = max(1, int(limit))
    except (TypeError, ValueError, OverflowError):
        cap = 8
    return rows[:cap]


def _network_rates() -> dict:
    """Aggregate interface bytes and compute RX/TX B/s since last sample."""
    global _net_prev
    rc, out, _ = sh(["/usr/sbin/netstat", "-ibn"], timeout=5)
    if rc != 0:
        return {}
    # netstat -ibn: multiple rows per iface. Prefer Link# rows (have MAC) and real NICs.
    by_name: dict[str, dict] = {}
    for line in _as_text(out).splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        name = parts[0].rstrip("*")
        # only physical / useful interfaces
        if not (name.startswith("en") or name.startswith("bridge") or name.startswith("ap")):
            continue
        if "Link#" not in line and not any(c.isdigit() and "." in p for p in parts[2:4] for c in "1"):
            # still accept; prefer highest byte counts below
            pass
        try:
            # Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
            # When Network is <Link#N>, Address is MAC → same column indices still hold on macOS
            ibytes = int(parts[6])
            obytes = int(parts[9])
        except (ValueError, TypeError, IndexError):
            continue
        prev = by_name.get(name)
        if not prev or ibytes + obytes > prev["rx_bytes"] + prev["tx_bytes"]:
            by_name[name] = {"iface": name, "rx_bytes": ibytes, "tx_bytes": obytes}
    ifaces = sorted(by_name.values(), key=lambda x: -(x["rx_bytes"] + x["tx_bytes"]))[:6]
    total_rx = sum(i["rx_bytes"] for i in ifaces)
    total_tx = sum(i["tx_bytes"] for i in ifaces)
    now = time.time()
    rx_bps = tx_bps = None
    if _net_prev["t"] and now > _net_prev["t"]:
        dt = now - _net_prev["t"]
        if dt > 0.5:
            # A leftover 400-digit Ibytes counter used to OverflowError
            # `int((total - prev) / dt)` on the second sample.
            try:
                rx_bps = max(0, int((total_rx - _net_prev["rx"]) / dt))
                tx_bps = max(0, int((total_tx - _net_prev["tx"]) / dt))
            except (OverflowError, ValueError, TypeError):
                rx_bps = tx_bps = None
    _net_prev = {"t": now, "rx": total_rx, "tx": total_tx}
    return {
        "rx_bytes": total_rx,
        "tx_bytes": total_tx,
        "rx_bps": rx_bps,
        "tx_bps": tx_bps,
        "ifaces": ifaces[:8],
    }


def _thermal() -> dict | None:
    """Best-effort CPU temperature plus Apple's thermal-pressure status.

    Apple Silicon does not expose a stable, unprivileged absolute-temperature
    API.  Use an installed temperature helper when available and always report
    the OS thermal-pressure state instead of inventing a Celsius value.
    """
    temp_c = None
    source = None
    helpers = [
        (shutil.which("osx-cpu-temp"), []),
        (shutil.which("istats"), ["cpu", "temp", "--value-only"]),
    ]
    for binary, args in helpers:
        if not binary:
            continue
        rc, out, _ = sh([binary, *args], timeout=4)
        if rc == 0:
            m = re.search(r"(-?\d+(?:\.\d+)?)\s*(?:°?C)?", _as_text(out), re.I)
            if m:
                value = float(m.group(1))
                if 0 < value < 130:
                    temp_c = round(value, 1)
                    source = Path(binary).name
                    break

    rc, out, _ = sh(["/usr/sbin/sysctl", "-n", "machdep.xcpm.cpu_thermal_level"], timeout=2)
    level_n = _sysctl_int(out) if rc == 0 else None
    if level_n is not None:
        level = level_n
        return {
            "cpu_temp_c": temp_c,
            "temp_source": source,
            "pressure": "normal" if level == 0 else "warning",
            "cpu_thermal_level": level,
            "available": temp_c is not None,
        }

    rc, out, _ = sh(["/usr/bin/pmset", "-g", "therm"], timeout=3)
    text = _as_text(out).lower()
    if rc != 0 or "error:" in text or "failed to get" in text:
        pressure = "unknown"
    elif "no thermal warning" in text:
        pressure = "normal"
    else:
        level = re.search(r"thermal warning level\D+(\d+)", text)
        pressure = "warning" if level and int(level.group(1)) > 0 else "normal"
    return {
        "cpu_temp_c": temp_c,
        "temp_source": source,
        "pressure": pressure,
        "available": temp_c is not None,
        "reason": None if temp_c is not None else "absolute_temperature_unavailable",
    }


def _nonneg_bytes(value) -> int | None:
    """Non-negative byte count, or None for leftovers that would 500 JSON."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value if 0 <= value <= 2**62 else None
    n = _finite_float(value)
    if n is None:
        return None
    try:
        i = int(n)
    except (OverflowError, ValueError):
        return None
    return i if 0 <= i <= 2**62 else None


def _gpu_model(entry: dict) -> str | None:
    for key in ("model", "Model", "IORegistryEntryName", "IONameMatched"):
        raw = entry.get(key)
        if raw is None:
            continue
        text = _utf8_text(raw).strip()
        if text and text != "IOAccelerator":
            return text[:80]
    return None


def _iter_ioreg_dicts(value, depth: int = 0):
    if depth > 6 or value is None:
        return
    if isinstance(value, dict):
        yield value
        for v in value.values():
            yield from _iter_ioreg_dicts(v, depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _iter_ioreg_dicts(item, depth + 1)


def _gpu() -> dict | None:
    """Best-effort GPU util / memory from IOAccelerator (macOS IORegistry).

    ``ioreg -a`` is an XML plist. Failures return None so GET /api/system/sensors
    never 500s when the accelerator is missing or the plist is leftover junk.
    """
    try:
        rc, out, _ = sh(
            ["/usr/sbin/ioreg", "-a", "-r", "-d", "1", "-c", "IOAccelerator"],
            timeout=4,
        )
        if rc != 0 or not out:
            return None
        raw = out.encode("utf-8", "replace") if isinstance(out, str) else out
        parsed = plistlib.loads(raw)

        best = None
        best_score = -1.0
        for entry in _iter_ioreg_dicts(parsed):
            if not isinstance(entry, dict):
                continue
            stats = entry.get("PerformanceStatistics")
            if not isinstance(stats, dict):
                stats = {}
            util_raw = stats.get("Device Utilization %")
            util = None if isinstance(util_raw, bool) else _finite_float(util_raw)
            used = _nonneg_bytes(stats.get("In use system memory"))
            alloc = _nonneg_bytes(stats.get("Alloc system memory"))
            model = _gpu_model(entry)
            if util is None and used is None and alloc is None and not model:
                continue
            score = 0.0
            if util is not None:
                score += 1000.0
            if alloc is not None:
                score += min(alloc, 10**15) / 10**9
            if used is not None:
                score += 1.0
            if model:
                score += 0.1
            if score > best_score:
                best_score = score
                best = {
                    "util_pct": None if util is None else round(util, 1),
                    "mem_used_bytes": used,
                    "mem_alloc_bytes": alloc,
                    "model": model,
                }
        return best
    except Exception:
        return None


def _uptime() -> dict:
    rc, out, _ = sh(["/usr/sbin/sysctl", "-n", "kern.boottime"], timeout=3)
    hours = 0.0
    text = _as_text(out)
    if rc == 0 and "sec =" in text:
        try:
            boot = int(text.split("sec =")[1].split(",")[0].strip())
            hours = (time.time() - boot) / 3600 if boot else 0.0
        except (IndexError, TypeError, ValueError, OverflowError):
            hours = 0.0
    hours = _finite_float(hours) or 0.0
    try:
        days = int(hours // 24)
        h = int(hours % 24)
        m = int((hours * 60) % 60)
    except (TypeError, ValueError, OverflowError):
        days, h, m = 0, 0, 0
        hours = 0.0
    if days:
        text = f"{days}d {h}h"
    elif h:
        text = f"{h}h {m}m"
    else:
        text = f"{m}m"
    return {"uptime_hours": round(hours, 2), "uptime_text": text}


def peek_sensors() -> dict | None:
    """Return the last full sample if it is still within the TTL, else None.

    The metrics sampler uses this so a 5-minute idle tick does not spawn
    ``top`` (1.6s on this host) just to write one jsonl point.
    Re-sanitizes: leftover inf / bytes / ``\\ud800`` in the peek cache
    used to 500 GET /api/system/sensors?light=1 at encode time.
    """
    v = _cache["v"]
    if v is not None and time.time() - _cache["t"] < _sensors_ttl():
        return _jsonable(v)
    return None


def collect_light() -> dict:
    """CPU / memory / load without top, ps, or netstat.

    Mach ticks + memory_pressure + hw.memsize.  First ticks call sleeps
    0.15s to seed a baseline; later calls are microseconds.  Does not
    overwrite the full sensors cache, so a dashboard poll still gets
    process rows and PhysMem the next time it asks for a full sample.
    """
    mem = _memory_base()
    cpu_ticks = _cpu_from_ticks() or {}
    disk = _disk()
    ncpu = mem.get("ncpu") or 1
    load1 = mem.get("load1")
    load5 = mem.get("load5")
    load15 = mem.get("load15")
    ratio = _safe_div(load1 or 0, ncpu) if ncpu else None
    load_pct = None if ratio is None else round(min(200.0, ratio * 100), 1)
    cpu_used = _finite_float(cpu_ticks.get("used_pct"))
    if cpu_used is None:
        cpu_used = load_pct
    if cpu_used is not None:
        cpu_used = min(100.0, max(0.0, cpu_used))
    pressure_free = mem.get("mem_free_pct")
    pressure_used = (100 - pressure_free) if pressure_free is not None else None
    mem_total = mem.get("mem_total_gb")
    available_gb = None
    if mem_total is not None and pressure_free is not None:
        try:
            held = _finite_float(mem_total * pressure_free / 100)
        except (TypeError, OverflowError):
            held = None
        available_gb = None if held is None else round(held, 1)
    used_gb = None
    if mem_total is not None and available_gb is not None:
        try:
            used_gb = round(max(0.0, mem_total - available_gb), 1)
        except (TypeError, OverflowError):
            used_gb = None
    return _jsonable({
        "ts": strftime_now("%H:%M:%S"),
        "cpu": {
            "user": cpu_ticks.get("user"),
            "sys": cpu_ticks.get("sys"),
            "idle": cpu_ticks.get("idle"),
            "used_pct": cpu_used,
            "load1": load1,
            "load5": load5,
            "load15": load15,
            "load_pct": load_pct,
            "ncpu": ncpu,
        },
        "memory": {
            "total_gb": mem_total,
            "used_pct": pressure_used,
            "free_pct": pressure_free,
            "used_gb": used_gb,
            "free_gb": available_gb,
            "available_gb": available_gb,
            "pressure_free_pct": pressure_free,
            "pressure_used_pct": pressure_used,
        },
        "disk": disk,
        "network": {},
        "top_processes": [],
        # ioreg GPU is cheap vs top; light ticks still need util for the CPU card.
        "gpu": _gpu(),
        "cpu_used_pct": cpu_used,
        "load1": load1,
        "load5": load5,
        "load15": load15,
        "light": True,
    })


def collect_sensors(force: bool = False) -> dict:
    if not force and _cache["v"] and time.time() - _cache["t"] < _sensors_ttl():
        # Re-sanitize: leftover inf / ``\ud800`` planted in the cache used
        # to 500 GET /api/system/sensors (the light peek already re-sanitized).
        cleaned = _jsonable(_cache["v"])
        return cleaned if isinstance(cleaned, dict) else {}

    with _refresh_lock:
        # Single-flight: concurrent dashboard/metrics callers share one sample.
        # Coalesce back-to-back force=True (metrics + UI) within 1s.
        age = time.time() - _cache["t"] if _cache["v"] else 1e9
        if _cache["v"] is not None and ((not force and age < _sensors_ttl()) or age < 1.0):
            cleaned = _jsonable(_cache["v"])
            return cleaned if isinstance(cleaned, dict) else {}
        return _collect_sensors_uncached()


def _collect_sensors_uncached() -> dict:
    # Parallel shell collection — top is the slowest (~0.5–1s); overlap the rest.
    f_mem = _pool.submit(_memory_base)
    f_disk = _pool.submit(_disk)
    f_top = _pool.submit(_cpu_and_mem_from_top_cached)
    f_cpu = _pool.submit(_cpu_from_ticks)
    f_thermal = _pool.submit(_thermal)
    f_gpu = _pool.submit(_gpu)
    f_net = _pool.submit(_network_rates)
    f_procs = _pool.submit(_top_processes, 8)
    f_up = _pool.submit(_uptime)

    def _result(fut, fallback):
        try:
            return fut.result()
        except Exception:
            return fallback

    # `.result()` re-raises; one wedged `top`/`pmset` must not 500 the dashboard.
    mem = _result(f_mem, {}) or {}
    disk = _result(f_disk, {}) or {}
    top = _result(f_top, {}) or {}
    cpu_ticks = _result(f_cpu, {}) or {}
    thermal = _result(f_thermal, None)
    gpu = _result(f_gpu, None)
    net = _result(f_net, {}) or {}
    procs = _result(f_procs, []) or []
    up = _result(f_up, {}) or {}

    ncpu = mem.get("ncpu") or 1
    load1 = top.get("load1", mem.get("load1"))
    load5 = top.get("load5", mem.get("load5"))
    load15 = top.get("load15", mem.get("load15"))

    # load as % of core capacity (Unraid / Glances style)
    ratio = _safe_div(load1 or 0, ncpu) if ncpu else None
    load_pct = None if ratio is None else round(min(200.0, ratio * 100), 1)

    # Prefer Mach-tick deltas (accurate, matches Activity Monitor); fall back
    # to top's single-frame CPU line, then to load-based estimate.
    cpu_user = cpu_ticks.get("user", top.get("user"))
    cpu_sys = cpu_ticks.get("sys", top.get("sys"))
    cpu_idle = cpu_ticks.get("idle", top.get("idle"))
    if cpu_ticks.get("used_pct") is not None:
        cpu_used_pct = _finite_float(cpu_ticks["used_pct"])
    elif cpu_idle is not None:
        cpu_used_pct = _finite_float(100 - cpu_idle)
        cpu_used_pct = None if cpu_used_pct is None else round(cpu_used_pct, 1)
    elif cpu_user is not None and cpu_sys is not None:
        cpu_used_pct = _finite_float(cpu_user + cpu_sys)
        cpu_used_pct = None if cpu_used_pct is None else round(cpu_used_pct, 1)
    else:
        cpu_used_pct = load_pct

    # --- Memory (macOS-aware) ---
    # PhysMem "used" includes file cache and is almost always near-full; NOT stress.
    # memory_pressure free% is the right "is the machine tight?" metric.
    mem_total = mem.get("mem_total_gb")
    phys_used_gb = top.get("mem_used_gb")  # includes cache
    phys_unused_gb = top.get("mem_unused_gb")
    wired_gb = top.get("mem_wired_gb")
    compressor_gb = top.get("mem_compressor_gb")
    pressure_free_pct = mem.get("mem_free_pct")  # memory_pressure -Q

    # Primary stress metric from Apple memory_pressure
    if pressure_free_pct is not None:
        used = _finite_float(100 - pressure_free_pct)
        pressure_used_pct = None if used is None else round(used, 1)
        free_pct = pressure_free_pct
        used_pct = pressure_used_pct
    else:
        free_pct = None
        used_pct = None
        pressure_used_pct = None

    # Approx non-cache footprint (wired + compressor); cache ≈ phys_used - that
    app_gb = None
    cache_gb = None
    if wired_gb is not None or compressor_gb is not None:
        try:
            app_gb = round((wired_gb or 0) + (compressor_gb or 0), 2)
        except (TypeError, OverflowError):
            app_gb = None
        if phys_used_gb is not None and app_gb is not None:
            try:
                cache_gb = round(max(0.0, phys_used_gb - app_gb), 2)
            except (TypeError, OverflowError):
                cache_gb = None

    # Available ≈ total * free_pct / 100 (pressure free), fallback unused
    available_gb = None
    if mem_total is not None and free_pct is not None:
        try:
            held = _finite_float(mem_total * free_pct / 100)
        except (TypeError, OverflowError):
            held = None
        available_gb = None if held is None else round(held, 1)
    elif phys_unused_gb is not None:
        available_gb = phys_unused_gb

    # "In use" under pressure ≈ total - available
    pressure_used_gb = None
    if mem_total is not None and available_gb is not None:
        try:
            pressure_used_gb = round(max(0.0, mem_total - available_gb), 1)
        except (TypeError, OverflowError):
            pressure_used_gb = None

    v = {
        "ts": strftime_now("%H:%M:%S"),
        "uptime": up,
        "cpu": {
            "user": cpu_user,
            "sys": cpu_sys,
            "idle": cpu_idle,
            "used_pct": cpu_used_pct,
            "load1": load1,
            "load5": load5,
            "load15": load15,
            "load_pct": load_pct,
            "ncpu": ncpu,
            "thermal": thermal,
            "proc_total": top.get("proc_total"),
            "proc_running": top.get("proc_running"),
        },
        "memory": {
            "total_gb": mem_total,
            # primary UI fields = pressure-based (not PhysMem cache-inflated)
            "used_pct": used_pct,
            "free_pct": free_pct,
            "used_gb": pressure_used_gb,
            "free_gb": available_gb,
            "available_gb": available_gb,
            # breakdown
            "wired_gb": wired_gb,
            "compressor_gb": compressor_gb,
            "app_gb": app_gb,
            "cache_gb": cache_gb,
            "phys_used_gb": phys_used_gb,
            "phys_unused_gb": phys_unused_gb,
            "pressure_free_pct": pressure_free_pct,
            "pressure_used_pct": pressure_used_pct,
            "physmem_raw": top.get("physmem_raw"),
            "hint": "Usage follows memory_pressure and excludes file cache; PhysMem 'used' includes cache and reads high",
        },
        "disk": disk,
        "network": net,
        "top_processes": procs,
        "thermal": thermal,
        "gpu": gpu,
        # backward-compat flat fields used by existing UI
        "cpu_used_pct": cpu_used_pct,
        "load1": load1,
        "load5": load5,
        "load15": load15,
    }
    v = _jsonable(v)
    _cache.update(t=time.time(), v=v)
    return v
