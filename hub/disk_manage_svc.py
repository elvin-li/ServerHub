"""Disk management via diskutil (mount / unmount / rename / format).

Destructive ops (format / erase) require confirm flags and never target system disk.
"""
from __future__ import annotations

import plistlib
import re
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from fastapi import HTTPException

from hub.errors import api_error
from hub.util import sh

DISK_RE = re.compile(r"^disk\d+(s\d+)*$")
WHOLE_RE = re.compile(r"^disk\d+$")

# Formats we allow for eraseVolume / eraseDisk
FS_TYPES = {
    "APFS": "APFS",
    "JHFS+": "JHFS+",
    "HFS+": "JHFS+",
    "ExFAT": "ExFAT",
    "MS-DOS": "MS-DOS",
    "FAT32": "MS-DOS",
    "Free Space": "Free Space",
}


def _plist(cmd: list[str], timeout: int = 30) -> dict | list | None:
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        if p.returncode != 0 or not p.stdout:
            return None
        return plistlib.loads(p.stdout)
    except Exception:
        return None


#: `diskutil info` costs ~130ms per device.  Listing volumes needs one call per
#: partition, so a 25-volume host spent ~3.7s in serial subprocesses on every
#: /api/storage request.  A short TTL keeps the page responsive while still
#: reflecting a mount/unmount the user just performed.
_INFO_TTL = 8.0
_INFO_CACHE: dict[str, tuple[float, dict]] = {}
_INFO_LOCK = threading.Lock()

#: Bounded: diskutil is a system service, and a wide fan-out on a host with many
#: volumes would trade one slow request for a thundering herd of processes.
_INFO_WORKERS = 8


def invalidate_disk_info() -> None:
    """Drop cached `diskutil info` output after an operation changes state."""
    with _INFO_LOCK:
        _INFO_CACHE.clear()


def _diskutil_info_uncached(node: str) -> dict:
    pl = _plist(["/usr/sbin/diskutil", "info", "-plist", node], timeout=15)
    return pl if isinstance(pl, dict) else {}


def _diskutil_info(node: str) -> dict:
    now = time.time()
    with _INFO_LOCK:
        hit = _INFO_CACHE.get(node)
        if hit and now - hit[0] < _INFO_TTL:
            return hit[1]
    data = _diskutil_info_uncached(node)
    with _INFO_LOCK:
        _INFO_CACHE[node] = (time.time(), data)
    return data


def _prefetch_disk_info(nodes: list[str]) -> None:
    """Warm the cache for *nodes* concurrently.

    The callers below walk a device tree and ask for each node in turn.  Doing
    that serially is what made the request slow; fetching them together turns
    ~30 sequential waits into a handful of parallel ones.
    """
    now = time.time()
    with _INFO_LOCK:
        pending = [
            n for n in dict.fromkeys(nodes)
            if n and not (
                (hit := _INFO_CACHE.get(n)) and now - hit[0] < _INFO_TTL
            )
        ]
    if not pending:
        return
    with ThreadPoolExecutor(max_workers=min(_INFO_WORKERS, len(pending))) as ex:
        for node, data in zip(pending, ex.map(_diskutil_info_uncached, pending)):
            with _INFO_LOCK:
                _INFO_CACHE[node] = (time.time(), data)


def _normalize_id(device: str) -> str:
    d = (device or "").strip().replace("/dev/", "")
    if not DISK_RE.match(d):
        raise HTTPException(400, f"invalid device id: {device}")
    return d


def _is_system_related(info: dict, device_id: str) -> bool:
    """Block ops on boot/system volumes and their parent whole disk."""
    # Mounted at system paths
    mp = info.get("MountPoint") or ""
    if mp in ("/", "/System/Volumes/Data", "/System/Volumes/Preboot", "/System/Volumes/VM"):
        return True
    if mp.startswith("/System/Volumes/"):
        return True
    # Whole disk of root
    if WHOLE_RE.match(device_id):
        # check if any volume on this disk is system
        vols = list_managed_volumes()
        for v in vols:
            if v.get("whole_disk") == device_id and v.get("system"):
                return True
        # disk0 typically system on Mac
        if device_id == "disk0":
            return True
    # Parent whole of a system volume
    whole = info.get("ParentWholeDisk") or ""
    if whole == "disk0":
        # only if this is internal system — still be careful for partitions of disk0
        if info.get("Internal") and info.get("SolidState"):
            # APFS system container
            fs = (info.get("FilesystemType") or info.get("FilesystemName") or "").lower()
            if "apfs" in fs or info.get("APFSContainerReference"):
                # any volume on system APFS container
                if not (info.get("MountPoint") or "").startswith("/Volumes/"):
                    # not user external mount
                    # If not mounted under /Volumes, treat APFS on disk0 parent as system-ish
                    parent = info.get("ParentWholeDisk") or device_id
                    if parent == "disk0" or device_id.startswith("disk0"):
                        # allow only if explicitly external volume name on /Volumes - handled above
                        if not mp.startswith("/Volumes/"):
                            return True
    # Root device chain
    rc, out, _ = sh(["/bin/df", "-P", "/"], timeout=5)
    if rc == 0:
        for line in out.splitlines()[1:]:
            fs = line.split()[0]
            m = re.search(r"/dev/(disk\d+)", fs)
            if m and (device_id == m.group(1) or device_id.startswith(m.group(1) + "s")):
                return True
    return False


def list_managed_volumes() -> list[dict]:
    """All diskutil volumes with mount/format metadata for management UI."""
    pl = _plist(["/usr/sbin/diskutil", "list", "-plist"], timeout=20)
    if not isinstance(pl, dict):
        return []

    # Real physical whole disks (disk0, external HDDs) vs synthetic APFS containers (disk1/2/3…)
    physical_wholes: set[str] = set()
    pphys = _plist(["/usr/sbin/diskutil", "list", "-plist", "physical"], timeout=15)
    if isinstance(pphys, dict):
        for x in pphys.get("WholeDisks") or []:
            physical_wholes.add(str(x))

    # Build set of system whole disks from root
    system_wholes = set(physical_wholes)  # start empty of external later
    system_wholes = set()
    rc, dfout, _ = sh(["/bin/df", "-P", "/"], timeout=5)
    if rc == 0:
        for line in dfout.splitlines()[1:]:
            fs = line.split()[0]
            m = re.search(r"/dev/(disk\d+)", fs)
            if m:
                system_wholes.add(m.group(1))
    # also from diskutil info /
    root_info = _diskutil_info("/")
    if root_info.get("ParentWholeDisk"):
        system_wholes.add(root_info["ParentWholeDisk"])
    # Physical store of APFS container
    stores = root_info.get("APFSPhysicalStores") or []
    if isinstance(stores, list):
        for s in stores:
            if isinstance(s, dict) and s.get("APFSPhysicalStore"):
                m = re.search(r"(disk\d+)", s["APFSPhysicalStore"])
                if m:
                    system_wholes.add(m.group(1))
    # boot physical disk always system
    system_wholes.add("disk0")

    all_disks = list(pl.get("AllDisksAndPartitions") or [])
    out = []

    def walk(node: dict, whole: str | None = None):
        ident = node.get("DeviceIdentifier") or ""
        if not ident:
            return
        is_whole = WHOLE_RE.match(ident) is not None
        w = ident if is_whole else (whole or ident)
        # partitions list
        parts = node.get("Partitions") or []
        apfs_vols = node.get("APFSVolumes") or []
        children = parts + apfs_vols
        if children:
            for ch in children:
                walk(ch, w if is_whole else whole or w)
            # still record whole disk summary
            if is_whole:
                info = _diskutil_info(ident)
                size = node.get("Size") or info.get("TotalSize") or 0
                content = str(node.get("Content") or info.get("Content") or "")
                # Synthetic APFS containers (not in physical list) are system-side
                synth = bool(physical_wholes) and ident not in physical_wholes
                is_sys = (
                    ident in system_wholes
                    or ident == "disk0"
                    or synth
                    or "Recovery" in content
                    or "APFS_ISC" in content
                )
                out.append({
                    "id": ident,
                    "device": f"/dev/{ident}",
                    "name": info.get("MediaName") or info.get("IORegistryEntryName") or ident,
                    "volume_name": info.get("VolumeName") or "",
                    "whole_disk": ident,
                    "is_whole": True,
                    "size_bytes": size,
                    "size_gb": round(size / 2**30, 1) if size else None,
                    "fs": info.get("FilesystemType") or content,
                    "content": content,
                    "mount": info.get("MountPoint") or "",
                    "mounted": bool(info.get("MountPoint")),
                    "writable": info.get("Writable") if "Writable" in info else None,
                    "internal": bool(info.get("Internal")),
                    "ejectable": bool(info.get("Ejectable")),
                    "removable": bool(info.get("Removable") or info.get("RemovableMedia")),
                    "system": is_sys,
                    "actions": _actions_for(info, ident, is_whole=True, system=is_sys),
                })
            return

        # leaf volume / partition
        info = _diskutil_info(ident)
        size = node.get("Size") or info.get("TotalSize") or 0
        mount = info.get("MountPoint") or node.get("MountPoint") or ""
        content = str(node.get("Content") or info.get("Content") or "")
        fs_type = (
            info.get("FilesystemType")
            or info.get("FilesystemName")
            or content
            or ""
        )
        # system / recovery / preboot — never manage
        synth_parent = bool(physical_wholes) and w and w not in physical_wholes
        system = (
            (w in system_wholes and not str(mount).startswith("/Volumes/"))
            or mount in ("/", "/System/Volumes/Data")
            or str(mount).startswith("/System/")
            or w == "disk0"
            or synth_parent  # recovery/ISC/system APFS containers
            or "Recovery" in content
            or "APFS_ISC" in content
            or "Apple_APFS_ISC" in content
            or "Apple_APFS_Recovery" in content
            or "Preboot" in str(mount)
        )
        name = (
            info.get("VolumeName")
            or node.get("VolumeName")
            or info.get("MediaName")
            or ident
        )
        item = {
            "id": ident,
            "device": f"/dev/{ident}",
            "name": name,
            "volume_name": info.get("VolumeName") or node.get("VolumeName") or "",
            "whole_disk": w,
            "is_whole": False,
            "size_bytes": size,
            "size_gb": round(size / 2**30, 1) if size else None,
            "fs": fs_type,
            "content": content,
            "mount": mount or "",
            "mounted": bool(mount),
            "writable": info.get("WritableVolume", info.get("Writable")),
            "internal": bool(info.get("Internal")),
            "ejectable": bool(info.get("Ejectable")),
            "removable": bool(info.get("Removable") or info.get("RemovableMedia")),
            "system": system,
            "actions": _actions_for(info, ident, is_whole=False, system=system),
        }
        out.append(item)

    for d in all_disks:
        walk(d)

    # de-dupe by id
    seen = set()
    uniq = []
    for i in out:
        if i["id"] in seen:
            continue
        seen.add(i["id"])
        uniq.append(i)
    # sort: non-system first for management focus, then by id
    uniq.sort(key=lambda x: (x["system"], x["is_whole"], x["id"]))
    return uniq


def _actions_for(info: dict, device_id: str, is_whole: bool, system: bool) -> list[str]:
    if system:
        return []  # no management actions on system volumes
    actions = []
    mounted = bool(info.get("MountPoint"))
    if is_whole:
        actions.append("mountDisk")
        actions.append("unmountDisk")
        if info.get("Ejectable") or info.get("Removable") or info.get("RemovableMedia"):
            actions.append("eject")
        # erase whole disk — very destructive
        actions.append("eraseDisk")
    else:
        if mounted:
            actions.append("unmount")
        else:
            actions.append("mount")
        actions.append("rename")
        actions.append("eraseVolume")
        if info.get("Ejectable"):
            actions.append("eject")
    return actions


def disk_action(
    device: str,
    action: str,
    *,
    name: str | None = None,
    fs: str | None = None,
    confirm: bool = False,
    confirm_name: str | None = None,
) -> dict[str, Any]:
    """Execute mount/unmount/rename/format via diskutil."""
    did = _normalize_id(device)
    info = _diskutil_info(did)
    if not info and action not in ("mount", "mountDisk"):
        # may still exist
        pass

    system = _is_system_related(info, did) if info else (did == "disk0" or did.startswith("disk0s"))
    if system:
        raise api_error("disk.system_protected")

    action = (action or "").strip()
    log: list[str] = []

    def run(args: list[str], timeout: int = 120) -> tuple[int, str, str]:
        rc, out, err = sh(args, timeout=timeout)
        log.append(f"$ {' '.join(args)}\n{(out or '')}\n{(err or '')}".strip())
        return rc, out or "", err or ""

    # ---- non-destructive ----
    if action == "mount":
        rc, out, err = run(["/usr/sbin/diskutil", "mount", did])
        return {"ok": rc == 0, "action": action, "device": did, "message": out or err, "log": log}
    if action == "mountDisk":
        rc, out, err = run(["/usr/sbin/diskutil", "mountDisk", did])
        return {"ok": rc == 0, "action": action, "device": did, "message": out or err, "log": log}
    if action == "unmount":
        rc, out, err = run(["/usr/sbin/diskutil", "unmount", did])
        if rc != 0:
            rc, out, err = run(["/usr/sbin/diskutil", "unmount", "force", did])
        return {"ok": rc == 0, "action": action, "device": did, "message": out or err, "log": log}
    if action == "unmountDisk":
        rc, out, err = run(["/usr/sbin/diskutil", "unmountDisk", did])
        if rc != 0:
            rc, out, err = run(["/usr/sbin/diskutil", "unmountDisk", "force", did])
        return {"ok": rc == 0, "action": action, "device": did, "message": out or err, "log": log}
    if action == "eject":
        rc, out, err = run(["/usr/sbin/diskutil", "eject", did])
        return {"ok": rc == 0, "action": action, "device": did, "message": out or err, "log": log}
    if action == "rename":
        new_name = (name or "").strip()
        if not new_name or len(new_name) > 64:
            raise api_error("disk.name_required")
        # diskutil rename /Volumes/Old New  OR  diskutil rename diskXsY New
        rc, out, err = run(["/usr/sbin/diskutil", "rename", did, new_name])
        return {"ok": rc == 0, "action": action, "device": did, "message": out or err, "log": log}

    # ---- destructive ----
    if action in ("eraseVolume", "format", "eraseDisk"):
        if not confirm:
            raise api_error("disk.confirm_required")
        vol_name = (info.get("VolumeName") or info.get("MediaName") or did).strip()
        if confirm_name is not None and confirm_name.strip() != vol_name and confirm_name.strip() != did:
            raise api_error("disk.confirm_name_mismatch", name=vol_name, id=did)
        fs_key = (fs or "ExFAT").strip()
        fs_type = FS_TYPES.get(fs_key) or FS_TYPES.get(fs_key.upper())
        if not fs_type:
            raise api_error(
            "disk.unsupported_fs", fs=fs, choices=", ".join(sorted(set(FS_TYPES)))
        )
        new_label = (name or vol_name or "UNTITLED").strip()[:32] or "UNTITLED"

        if action == "eraseDisk":
            if not WHOLE_RE.match(did):
                raise api_error("disk.whole_disk_only")
            # diskutil eraseDisk APFS Name disk4
            rc, out, err = run(
                ["/usr/sbin/diskutil", "eraseDisk", fs_type, new_label, did],
                timeout=600,
            )
        else:
            # eraseVolume
            rc, out, err = run(
                ["/usr/sbin/diskutil", "eraseVolume", fs_type, new_label, did],
                timeout=600,
            )
        return {
            "ok": rc == 0,
            "action": action,
            "device": did,
            "fs": fs_type,
            "name": new_label,
            "message": out or err,
            "log": log,
        }

    raise api_error("disk.unknown_action", action=action)


def overview() -> dict:
    vols = list_managed_volumes()
    return {
        "volumes": vols,
        "count": len(vols),
        "fs_types": sorted(set(FS_TYPES.keys())),
        "hint": "格式化/抹掉会清空数据；系统盘已锁定。操作调用 /usr/sbin/diskutil。",
    }
