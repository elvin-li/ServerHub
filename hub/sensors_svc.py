"""Rich host sensors — Glances / Unraid Dashboard style (macOS)."""
from __future__ import annotations

import ctypes
import os
import re
import shutil
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from hub.util import sh

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
        _cpu_ticks_prev = cur
    du = cur[0] - prev[0]
    ds = cur[1] - prev[1]
    di = cur[2] - prev[2]
    dn = cur[3] - prev[3]
    busy = du + ds + dn
    total = busy + di
    if total <= 0:
        return None
    return {
        "user": round((du + dn) / total * 100, 1),
        "sys": round(ds / total * 100, 1),
        "idle": round(di / total * 100, 1),
        "used_pct": round(busy / total * 100, 1),
    }


_cache = {"t": 0.0, "v": None}
# Above the Dashboard's 12s light poll on purpose: at 8s the cache had always
# expired by the next tick, so every poll re-ran the full 7-subprocess
# collection (top, memory_pressure, netstat, ps, sysctl, pmset) and the cache
# absorbed nothing.  At 15s alternate ticks are served from memory.
_TTL = 15.0
_refresh_lock = threading.Lock()
_net_prev = {"t": 0.0, "rx": 0, "tx": 0}
# hw.ncpu / memsize / pagesize almost never change at runtime
_static = {"t": 0.0, "ncpu": None, "mem_gb": None, "page_size": 16384}
_STATIC_TTL = 300.0


def _parse_size_to_gb(token: str) -> float | None:
    """Parse 30G / 2548M / 975M / 1.2T into GB."""
    token = token.strip().replace(",", "")
    m = re.match(r"^([\d.]+)\s*([KMGTP]?)B?$", token, re.I)
    if not m:
        return None
    n = float(m.group(1))
    u = (m.group(2) or "G").upper()
    mul = {"": 1 / 1024**3, "K": 1 / 1024**2, "M": 1 / 1024, "G": 1, "T": 1024, "P": 1024**2}
    return round(n * mul.get(u, 1), 2)


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
    for line in out.splitlines():
        if "CPU usage" in line:
            for part in line.split(":")[-1].split(","):
                part = part.strip()
                if "% user" in part:
                    try:
                        data["user"] = float(part.replace("% user", "").strip())
                    except ValueError:
                        pass
                elif "% sys" in part:
                    try:
                        data["sys"] = float(part.replace("% sys", "").strip())
                    except ValueError:
                        pass
                elif "% idle" in part:
                    try:
                        data["idle"] = float(part.replace("% idle", "").strip())
                    except ValueError:
                        pass
        if line.startswith("Load Avg:"):
            nums = line.split(":")[-1].replace(" ", "").split(",")
            try:
                data["load1"] = float(nums[0])
                data["load5"] = float(nums[1])
                data["load15"] = float(nums[2])
            except (IndexError, ValueError):
                pass
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
    rc, ncpu, _ = sh(["/usr/sbin/sysctl", "-n", "hw.ncpu"], timeout=2)
    rc2, memsize, _ = sh(["/usr/sbin/sysctl", "-n", "hw.memsize"], timeout=2)
    rc3, pgsz, _ = sh(["/usr/sbin/sysctl", "-n", "hw.pagesize"], timeout=2)
    ncpu_i = int(ncpu) if rc == 0 and ncpu.isdigit() else None
    mem_gb = round(int(memsize) / 2**30, 1) if rc2 == 0 and memsize.isdigit() else None
    page_size = int(pgsz) if rc3 == 0 and pgsz.isdigit() else 16384
    _static.update(t=now, ncpu=ncpu_i, mem_gb=mem_gb, page_size=page_size)
    return {"ncpu": ncpu_i, "mem_total_gb": mem_gb, "page_size": page_size}


def _memory_base() -> dict:
    load1, load5, load15 = os.getloadavg()
    rc, out, _ = sh(["/usr/bin/memory_pressure", "-Q"], timeout=4)
    free_pct = None
    pages_free = pages_spec = pages_inactive = pages_wired = None
    for line in out.splitlines():
        low = line.lower()
        if "free percentage" in low:
            try:
                free_pct = int(line.rstrip("%").split(":")[-1].strip().rstrip("%"))
            except ValueError:
                pass
        elif "pages free" in low:
            try:
                pages_free = int(re.findall(r"\d+", line)[-1])
            except (IndexError, ValueError):
                pass
        elif "pages speculative" in low:
            try:
                pages_spec = int(re.findall(r"\d+", line)[-1])
            except (IndexError, ValueError):
                pass
        elif "pages inactive" in low:
            try:
                pages_inactive = int(re.findall(r"\d+", line)[-1])
            except (IndexError, ValueError):
                pass
        elif "pages wired down" in low:
            try:
                pages_wired = int(re.findall(r"\d+", line)[-1])
            except (IndexError, ValueError):
                pass
    hw = _static_hw()
    return {
        "load1": round(load1, 2),
        "load5": round(load5, 2),
        "load15": round(load15, 2),
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
    du = shutil.disk_usage("/")
    return {
        "root_pct": round(du.used / du.total * 100, 1),
        "root_used_gb": round(du.used / 2**30, 1),
        "root_total_gb": round(du.total / 2**30, 1),
        "root_free_gb": round(du.free / 2**30, 1),
    }


def _top_processes(limit: int = 8) -> list:
    rc, out, _ = sh(
        ["/bin/ps", "-A", "-o", "pid,%cpu,%mem,rss,comm", "-r"],
        timeout=5,
    )
    if rc != 0:
        return []
    rows = []
    for line in out.splitlines()[1:]:
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue
        try:
            pid = int(parts[0])
            cpu = float(parts[1])
            mem = float(parts[2])
            rss_kb = int(parts[3])
        except ValueError:
            continue
        name = parts[4].strip()
        # shorten path
        if "/" in name:
            name = name.rsplit("/", 1)[-1]
        rows.append({
            "pid": pid,
            "cpu": round(cpu, 1),
            "mem": round(mem, 1),
            "rss_mb": round(rss_kb / 1024, 1),
            "name": name[:40],
        })
        if len(rows) >= limit:
            break
    return rows


def _network_rates() -> dict:
    """Aggregate interface bytes and compute RX/TX B/s since last sample."""
    global _net_prev
    rc, out, _ = sh(["/usr/sbin/netstat", "-ibn"], timeout=5)
    if rc != 0:
        return {}
    # netstat -ibn: multiple rows per iface. Prefer Link# rows (have MAC) and real NICs.
    by_name: dict[str, dict] = {}
    for line in out.splitlines()[1:]:
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
        except (ValueError, IndexError):
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
            rx_bps = max(0, int((total_rx - _net_prev["rx"]) / dt))
            tx_bps = max(0, int((total_tx - _net_prev["tx"]) / dt))
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
            m = re.search(r"(-?\d+(?:\.\d+)?)\s*(?:°?C)?", out or "", re.I)
            if m:
                value = float(m.group(1))
                if 0 < value < 130:
                    temp_c = round(value, 1)
                    source = Path(binary).name
                    break

    rc, out, _ = sh(["/usr/sbin/sysctl", "-n", "machdep.xcpm.cpu_thermal_level"], timeout=2)
    if rc == 0 and out.strip().isdigit():
        level = int(out.strip())
        return {
            "cpu_temp_c": temp_c,
            "temp_source": source,
            "pressure": "normal" if level == 0 else "warning",
            "cpu_thermal_level": level,
            "available": temp_c is not None,
        }

    rc, out, _ = sh(["/usr/bin/pmset", "-g", "therm"], timeout=3)
    text = (out or "").lower()
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


def _uptime() -> dict:
    rc, out, _ = sh(["/usr/sbin/sysctl", "-n", "kern.boottime"], timeout=3)
    hours = 0.0
    if rc == 0 and "sec =" in out:
        boot = int(out.split("sec =")[1].split(",")[0].strip())
        hours = (time.time() - boot) / 3600
    days = int(hours // 24)
    h = int(hours % 24)
    m = int((hours * 60) % 60)
    if days:
        text = f"{days}d {h}h"
    elif h:
        text = f"{h}h {m}m"
    else:
        text = f"{m}m"
    return {"uptime_hours": round(hours, 2), "uptime_text": text}


def collect_sensors(force: bool = False) -> dict:
    if not force and _cache["v"] and time.time() - _cache["t"] < _TTL:
        return _cache["v"]

    with _refresh_lock:
        # Single-flight: concurrent dashboard/metrics callers share one sample.
        # Coalesce back-to-back force=True (metrics + UI) within 1s.
        age = time.time() - _cache["t"] if _cache["v"] else 1e9
        if _cache["v"] is not None and ((not force and age < _TTL) or age < 1.0):
            return _cache["v"]
        return _collect_sensors_uncached()


def _collect_sensors_uncached() -> dict:
    # Parallel shell collection — top is the slowest (~0.5–1s); overlap the rest.
    with ThreadPoolExecutor(max_workers=6) as ex:
        f_mem = ex.submit(_memory_base)
        f_disk = ex.submit(_disk)
        f_top = ex.submit(_cpu_and_mem_from_top)
        f_cpu = ex.submit(_cpu_from_ticks)
        f_thermal = ex.submit(_thermal)
        f_net = ex.submit(_network_rates)
        f_procs = ex.submit(_top_processes, 8)
        f_up = ex.submit(_uptime)
        mem = f_mem.result()
        disk = f_disk.result()
        top = f_top.result() or {}
        cpu_ticks = f_cpu.result() or {}
        thermal = f_thermal.result()
        net = f_net.result() or {}
        procs = f_procs.result() or []
        up = f_up.result()

    ncpu = mem.get("ncpu") or 1
    load1 = top.get("load1", mem.get("load1"))
    load5 = top.get("load5", mem.get("load5"))
    load15 = top.get("load15", mem.get("load15"))

    # load as % of core capacity (Unraid / Glances style)
    load_pct = round(min(200, (load1 or 0) / ncpu * 100), 1) if ncpu else None

    # Prefer Mach-tick deltas (accurate, matches Activity Monitor); fall back
    # to top's single-frame CPU line, then to load-based estimate.
    cpu_user = cpu_ticks.get("user", top.get("user"))
    cpu_sys = cpu_ticks.get("sys", top.get("sys"))
    cpu_idle = cpu_ticks.get("idle", top.get("idle"))
    if cpu_ticks.get("used_pct") is not None:
        cpu_used_pct = cpu_ticks["used_pct"]
    elif cpu_idle is not None:
        cpu_used_pct = round(100 - cpu_idle, 1)
    elif cpu_user is not None and cpu_sys is not None:
        cpu_used_pct = round(cpu_user + cpu_sys, 1)
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
        pressure_used_pct = round(100 - pressure_free_pct, 1)
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
        app_gb = round((wired_gb or 0) + (compressor_gb or 0), 2)
        if phys_used_gb is not None and app_gb is not None:
            cache_gb = round(max(0.0, phys_used_gb - app_gb), 2)

    # Available ≈ total * free_pct / 100 (pressure free), fallback unused
    available_gb = None
    if mem_total is not None and free_pct is not None:
        available_gb = round(mem_total * free_pct / 100, 1)
    elif phys_unused_gb is not None:
        available_gb = phys_unused_gb

    # "In use" under pressure ≈ total - available
    pressure_used_gb = None
    if mem_total is not None and available_gb is not None:
        pressure_used_gb = round(max(0.0, mem_total - available_gb), 1)

    v = {
        "ts": time.strftime("%H:%M:%S"),
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
        # backward-compat flat fields used by existing UI
        "cpu_used_pct": cpu_used_pct,
        "load1": load1,
        "load5": load5,
        "load15": load15,
    }
    _cache.update(t=time.time(), v=v)
    return v
