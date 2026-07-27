"""Disk / volume / SMART for macOS — capacity deduped by physical/container."""
from __future__ import annotations

import re
import shutil
import time
from pathlib import Path

from hub.paths import SMARTCTL
from hub.util import sh

_smart_multi = {"t": 0.0, "v": None}

# skip noisy synthetic mounts
SKIP_PREFIXES = (
    "/dev", "/System/Volumes/VM", "/System/Volumes/Preboot",
    "/System/Volumes/Update", "/System/Volumes/xarts",
    "/System/Volumes/iSCPreboot", "/System/Volumes/Hardware",
    "/private/var/vm",
)
SKIP_FS = {"devfs", "autofs", "map"}


def _parent_disk_id(filesystem: str) -> str | None:
    """/dev/disk3s1s1 → disk3 ; OrbStack → None."""
    if not filesystem:
        return None
    m = re.search(r"(disk\d+)", filesystem)
    return m.group(1) if m else None


def list_volumes() -> list:
    items = []
    rc, out, _ = sh(["df", "-P", "-k"], timeout=8)
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        fs, blocks, used, avail, pct = parts[0], parts[1], parts[2], parts[3], parts[4]
        mount = " ".join(parts[5:])
        if any(mount == p or mount.startswith(p + "/") for p in SKIP_PREFIXES if p != "/"):
            if mount not in ("/", "/System/Volumes/Data"):
                if not mount.startswith("/Volumes/") and mount not in ("/", "/System/Volumes/Data") \
                        and "OrbStack" not in mount and not mount.startswith(str(Path.home() / "OrbStack")):
                    if mount.startswith("/System/") or mount.startswith("/dev"):
                        continue
        if fs in SKIP_FS or mount.startswith("/dev"):
            continue
        if mount.startswith("/System/Volumes/") and mount not in ("/System/Volumes/Data",):
            continue
        try:
            total_kb = int(blocks)
            used_kb = int(used)
            avail_kb = int(avail)
        except ValueError:
            continue
        if total_kb <= 0:
            continue
        if total_kb < 100 * 1024:  # < 100MB
            continue
        parent = _parent_disk_id(fs)
        items.append({
            "filesystem": fs,
            "device": fs,
            "disk_id": parent,  # whole-disk id when known
            "mount": mount,
            "total_gb": round(total_kb / 1024 / 1024, 1),
            "used_gb": round(used_kb / 1024 / 1024, 1),
            "avail_gb": round(avail_kb / 1024 / 1024, 1),
            "pct": int(pct.rstrip("%")) if pct.endswith("%") else round(used_kb / total_kb * 100),
            "kind": _classify(mount, fs),
        })
    mounts = {i["mount"] for i in items}
    if "/" not in mounts:
        du = shutil.disk_usage("/")
        items.insert(0, {
            "filesystem": "/",
            "device": "/",
            "disk_id": None,
            "mount": "/",
            "total_gb": round(du.total / 2**30, 1),
            "used_gb": round(du.used / 2**30, 1),
            "avail_gb": round(du.free / 2**30, 1),
            "pct": round(du.used / du.total * 100),
            "kind": "system",
        })
    return items


def _classify(mount: str, fs: str) -> str:
    if mount == "/" or mount == "/System/Volumes/Data":
        return "system"
    if mount.startswith("/Volumes/"):
        return "external"
    if "OrbStack" in mount or mount.endswith("/OrbStack"):
        return "orbstack"
    if fs.startswith("OrbStack") or "orbstack" in fs.lower():
        return "orbstack"
    return "other"


def _shared_pool(group: list) -> bool:
    """APFS (and similar) volumes on same container report the same total capacity."""
    if len(group) <= 1:
        return False
    max_t = max(v["total_gb"] for v in group)
    if max_t <= 0:
        return False
    # all totals within 3% of the max → shared free space pool
    return all(abs(v["total_gb"] - max_t) / max_t < 0.03 for v in group)


def aggregate_capacity(vols: list, kinds: set | None = None) -> dict:
    """Sum capacity without double-counting shared APFS containers.

    Group by disk_id (physical/synthetic whole disk). Within a group:
    - shared pool (same total): count total once, used = max, free = max
    - independent partitions: sum totals/used/free
    """
    selected = [v for v in vols if kinds is None or v.get("kind") in kinds]
    groups: dict[str, list] = {}
    for v in selected:
        key = v.get("disk_id") or f"fs:{v.get('filesystem')}:{v.get('mount')}"
        groups.setdefault(key, []).append(v)

    total = used = free = 0.0
    counted_mounts = []
    for key, group in groups.items():
        if _shared_pool(group):
            t = max(x["total_gb"] for x in group)
            u = max(x["used_gb"] for x in group)
            a = max(x["avail_gb"] for x in group)
            # prefer Data volume as representative for used (more accurate app data)
            data_vol = next((x for x in group if x["mount"] == "/System/Volumes/Data"), None)
            if data_vol:
                u = data_vol["used_gb"]
                a = data_vol["avail_gb"]
            total += t
            used += u
            free += a
            counted_mounts.append({
                "disk_id": key if not key.startswith("fs:") else group[0].get("disk_id"),
                "mode": "shared_pool",
                "mounts": [x["mount"] for x in group],
                "total_gb": t,
                "used_gb": u,
                "avail_gb": a,
            })
        else:
            t = sum(x["total_gb"] for x in group)
            u = sum(x["used_gb"] for x in group)
            a = sum(x["avail_gb"] for x in group)
            total += t
            used += u
            free += a
            counted_mounts.append({
                "disk_id": key if not key.startswith("fs:") else group[0].get("disk_id"),
                "mode": "sum_partitions",
                "mounts": [x["mount"] for x in group],
                "total_gb": round(t, 1),
                "used_gb": round(u, 1),
                "avail_gb": round(a, 1),
            })
    return {
        "total_gb": round(total, 1),
        "used_gb": round(used, 1),
        "free_gb": round(free, 1),
        "total_tb": round(total / 1024, 2),
        "used_tb": round(used / 1024, 2),
        "free_tb": round(free / 1024, 2),
        "groups": counted_mounts,
    }


def smart_devices() -> list:
    """Enumerate disks and pull SMART summary (cached 10 min)."""
    global _smart_multi
    if time.time() - _smart_multi["t"] < 600 and _smart_multi["v"] is not None:
        return _smart_multi["v"]

    devices = []
    rc, out, _ = sh(["diskutil", "list", "physical"], timeout=10)
    disk_ids = []
    if rc == 0:
        for m in re.finditer(r"/dev/(disk\d+)\s", out):
            d = m.group(1)
            if d not in disk_ids:
                disk_ids.append(d)
    if not disk_ids:
        disk_ids = ["disk0"]

    for d in disk_ids:
        dev = f"/dev/{d}"
        info = {
            "device": dev, "id": d, "name": d,
            "size": None, "size_bytes": None, "size_gb": None,
            "smart": None, "error": None,
        }
        rc, iout, _ = sh(["diskutil", "info", dev], timeout=8)
        if rc == 0:
            for line in iout.splitlines():
                if "Device / Media Name:" in line or "Media Name:" in line:
                    info["name"] = line.split(":", 1)[1].strip()
                elif "Disk Size:" in line:
                    raw_size = line.split(":", 1)[1].strip()
                    info["size"] = raw_size.split("(")[0].strip()
                    byte_match = re.search(r"\(([\d,]+)\s+Bytes\)", raw_size, re.IGNORECASE)
                    if byte_match:
                        size_bytes = int(byte_match.group(1).replace(",", ""))
                        info["size_bytes"] = size_bytes
                        info["size_gb"] = round(size_bytes / 2**30, 1)
                elif "Solid State:" in line:
                    info["ssd"] = "Yes" in line
                elif "Protocol:" in line:
                    info["protocol"] = line.split(":", 1)[1].strip()
        # Most macOS NVMe devices are readable as the login user.  Avoid a
        # failing sudo process on every disk; retry with passwordless sudo only
        # when the direct read clearly failed for permissions.
        rc, sout, serr = sh([SMARTCTL, "-a", dev], timeout=10)
        msg_lower = f"{sout}\n{serr}".lower()
        if rc not in (0, 4) and any(x in msg_lower for x in ("permission", "operation not permitted", "access denied")):
            rc, sout, serr = sh(["sudo", "-n", SMARTCTL, "-a", dev], timeout=10)
        if rc in (0, 4) and sout:
            sm = {}
            for line in sout.splitlines():
                if "Data Units Written" in line and "[" in line:
                    sm["written"] = line.split("[")[1].rstrip("]")
                elif "Percentage Used" in line:
                    sm["wear"] = line.split(":")[1].strip()
                elif line.strip().startswith("Temperature:"):
                    sm["temp"] = line.split(":")[1].strip()
                elif "Power On Hours" in line or "Power_On_Hours" in line:
                    if ":" in line:
                        sm["power_on"] = line.split(":")[-1].strip()
                elif "Serial Number:" in line:
                    sm["serial"] = line.split(":")[1].strip()
                elif "Model Number:" in line or "Device Model:" in line:
                    sm["model"] = line.split(":")[1].strip()
                elif "SMART overall-health" in line:
                    sm["health"] = line.split(":")[-1].strip()
                elif line.strip().startswith("Critical Warning:"):
                    raw = line.split(":", 1)[1].strip()
                    sm["critical_warning"] = raw
                elif line.strip().startswith("Available Spare:"):
                    sm["available_spare"] = line.split(":", 1)[1].strip()
                elif line.strip().startswith("Unsafe Shutdowns:"):
                    sm["unsafe_shutdowns"] = line.split(":", 1)[1].strip()
                elif line.strip().startswith("Media and Data Integrity Errors:"):
                    sm["media_errors"] = line.split(":", 1)[1].strip()
                elif "Reallocated_Sector_Ct" in line:
                    sm["reallocated"] = line.split()[-1]
                elif "Current_Pending_Sector" in line:
                    sm["pending"] = line.split()[-1]
                elif "Offline_Uncorrectable" in line:
                    sm["uncorrectable"] = line.split()[-1]
            if "health" not in sm:
                critical = str(sm.get("critical_warning") or "0").lower()
                sm["health"] = "PASSED" if critical in ("0", "0x00") else "WARNING"
            info["smart"] = sm
        else:
            info["error"] = (serr or sout or "smartctl 不可用或需 sudo")[:120]
        devices.append(info)

    _smart_multi = {"t": time.time(), "v": devices}
    return devices


def storage_overview() -> dict:
    vols = list_volumes()
    disks = smart_devices()
    system_vols = [v for v in vols if v["kind"] == "system"]
    external_vols = [v for v in vols if v["kind"] == "external"]
    other_vols = [v for v in vols if v["kind"] not in ("system", "external")]

    # Physical-ish capacity: system + external (exclude virtual OrbStack from array totals)
    cap_array = aggregate_capacity(vols, kinds={"system", "external"})
    cap_all = aggregate_capacity(vols, kinds=None)

    array_devices = []
    for v in system_vols + external_vols:
        array_devices.append({
            "role": "cache" if v["kind"] == "system" else "data",
            "mount": v["mount"],
            "kind": v["kind"],
            "disk_id": v.get("disk_id"),
            "device": v.get("device") or v.get("filesystem"),
            "total_gb": v["total_gb"],
            "used_gb": v["used_gb"],
            "avail_gb": v["avail_gb"],
            "pct": v["pct"],
            "filesystem": v["filesystem"],
            "shared_pool": False,  # filled below
        })

    # Mark shared-pool siblings so UI can show a hint
    shared_keys = {
        g["disk_id"] for g in cap_array.get("groups") or []
        if g.get("mode") == "shared_pool" and g.get("disk_id")
    }
    for d in array_devices:
        if d.get("disk_id") in shared_keys:
            d["shared_pool"] = True

    return {
        "volumes": vols,
        "disks": disks,
        "array": {
            "devices": array_devices,
            "system_count": len(system_vols),
            "data_count": len(external_vols),
            "other_count": len(other_vols),
            "disk_count": len(disks),
            "total_tb": cap_array["total_tb"],
            "used_tb": cap_array["used_tb"],
            "free_tb": cap_array["free_tb"],
            "total_gb": cap_array["total_gb"],
            "used_gb": cap_array["used_gb"],
            "free_gb": cap_array["free_gb"],
            "capacity_groups": cap_array["groups"],
            "status": "started",
            "note": "同磁盘/APFS 容器多挂载点只计一次容量",
        },
        "totals": {
            "volume_count": len(vols),
            "used_gb": cap_array["used_gb"],
            "total_gb": cap_array["total_gb"],
            "free_gb": cap_array["free_gb"],
            "all_including_virtual_gb": cap_all["total_gb"],
        },
    }
