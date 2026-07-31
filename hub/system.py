"""Host system metrics."""
from __future__ import annotations

import os
import shutil
import time

from hub.paths import SMARTCTL
from hub.util import sh

_smart_cache = {"t": 0.0, "v": None}


def collect_system():
    load1, load5, load15 = os.getloadavg()
    du = shutil.disk_usage("/")
    rc, out, _ = sh(["/usr/sbin/sysctl", "-n", "kern.boottime"], timeout=3)
    uptime_h = 0.0
    if rc == 0 and "sec =" in out:
        boot = int(out.split("sec =")[1].split(",")[0].strip())
        uptime_h = (time.time() - boot) / 3600
    rc, out, _ = sh(["/usr/bin/memory_pressure", "-Q"], timeout=4)
    mem_free = None
    for line in out.splitlines():
        if "free percentage" in line:
            try:
                mem_free = int(line.rstrip("%").split(":")[-1].strip().rstrip("%"))
            except ValueError:
                mem_free = None
    rc, ncpu, _ = sh(["/usr/sbin/sysctl", "-n", "hw.ncpu"], timeout=2)
    ncpu_i = int(ncpu) if rc == 0 and ncpu.isdigit() else None
    smart = _smart_cache["v"]
    if time.time() - _smart_cache["t"] > 600:
        rc, out, _ = sh(["sudo", "-n", SMARTCTL, "-a", "/dev/disk0"], timeout=10)
        if rc in (0, 4):
            smart = {}
            for line in out.splitlines():
                if "Data Units Written" in line and "[" in line:
                    smart["written"] = line.split("[")[1].rstrip("]")
                elif "Percentage Used" in line:
                    smart["wear"] = line.split(":")[1].strip()
                elif line.strip().startswith("Temperature:"):
                    smart.setdefault("temp", line.split(":")[1].strip())
            _smart_cache.update(t=time.time(), v=smart)
    n = ncpu_i or 1
    load_pct = round(min(200.0, load1 / n * 100), 1)
    return {
        "load": f"{load1:.2f} / {load5:.2f} / {load15:.2f}",
        "load1": round(load1, 2),
        "load5": round(load5, 2),
        "load15": round(load15, 2),
        "load_pct": load_pct,
        "ncpu": ncpu_i,
        "mem_free_pct": mem_free,
        "mem_used_pct": (100 - mem_free) if mem_free is not None else None,
        "disk_used_gb": round(du.used / 2**30),
        "disk_total_gb": round(du.total / 2**30),
        "disk_free_gb": round(du.free / 2**30),
        "disk_pct": round(du.used / du.total * 100),
        "uptime": (
            f"{int(uptime_h//24)} 天 {int(uptime_h%24)} 小时"
            if uptime_h >= 24
            else f"{uptime_h:.1f} 小时"
        ),
        "uptime_hours": round(uptime_h, 2),
        "smart": smart,
    }
