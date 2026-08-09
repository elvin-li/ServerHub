"""Disk sleep / wake for HDDs and removable volumes (macOS).

Goal: let users park mechanical disks (or eject SD/USB media) instead of
keeping them spinning. System boot disk is never put to sleep.

Strategies:
  - ATA/SATA/USB HDD: unmount → smartctl standby,now (if supported)
  - Removable / SD / USB: unmountDisk → eject; wake via mountDisk
  - Wake: mountDisk, or a tiny read to spin up then remount
"""
from __future__ import annotations

import plistlib
import re
import subprocess
import threading
import time
from pathlib import Path

from fastapi import HTTPException

from hub.disk_manage_svc import invalidate_disk_info
from hub.paths import SMARTCTL
from hub.util import fan_out, sh, ttl_memo

# Whole-disk identifiers only
DISK_RE = re.compile(r"^disk\d+$")


#: A wedged diskutil (typically an external HDD asleep) used to pin this whole
#: listing at its subprocess timeout -- 12-15s per call.  Five seconds is far
#: beyond a healthy answer and bounds the worst case instead.
_DISKUTIL_TIMEOUT = 5


def _diskutil_info(node: str) -> dict:
    # -plist outputs binary plist — must use raw bytes (not text mode)
    try:
        p = subprocess.run(
            ["/usr/sbin/diskutil", "info", "-plist", node],
            capture_output=True, timeout=_DISKUTIL_TIMEOUT,
        )
        if p.returncode == 0 and p.stdout:
            return plistlib.loads(p.stdout)
    except Exception:
        pass
    return {}


def _list_whole_disks() -> list[str]:
    p = subprocess.run(
        ["/usr/sbin/diskutil", "list", "-plist", "physical"],
        capture_output=True, timeout=_DISKUTIL_TIMEOUT,
    )
    if p.returncode != 0:
        # fallback text
        rc, out, _ = sh(["/usr/sbin/diskutil", "list", "physical"], timeout=_DISKUTIL_TIMEOUT)
        ids = []
        for m in re.finditer(r"/dev/(disk\d+)\s", out or ""):
            if m.group(1) not in ids:
                ids.append(m.group(1))
        return ids
    try:
        pl = plistlib.loads(p.stdout)
        return list(pl.get("WholeDisks") or [])
    except Exception:
        return []


#: The mount table, shared across one listing.  `df` reports every volume on the
#: machine in a single call, but the per-disk helper below asked for the whole table
#: and then threw away every row belonging to another disk -- so a listing ran one
#: full `df` per disk to read one table.  Locked for the same reason as the root-disk
#: memo: the per-disk work is concurrent now.
_df_cache: list[str] | None = None
_df_lock = threading.Lock()


def _df_lines() -> list[str]:
    """`df -P -k` output lines, read once per listing."""
    global _df_cache
    with _df_lock:
        if _df_cache is None:
            rc, out, _ = sh(["/bin/df", "-P", "-k"], timeout=8)
            _df_cache = (out or "").splitlines() if rc == 0 else []
        return _df_cache


def _invalidate_df() -> None:
    global _df_cache
    with _df_lock:
        _df_cache = None


def _volumes_on_disk(disk_id: str) -> list[dict]:
    """Mounted volumes belonging to this whole disk."""
    vols = []
    for line in _df_lines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        fs, mount = parts[0], " ".join(parts[5:])
        # /dev/disk4s1 or /dev/disk3s1s1
        m = re.search(r"/dev/(disk\d+)", fs)
        if not m:
            continue
        if m.group(1) != disk_id:
            continue
        try:
            total_kb = int(parts[1])
            used_kb = int(parts[2])
        except ValueError:
            total_kb = used_kb = 0
        vols.append({
            "device": fs,
            "mount": mount,
            "total_gb": round(total_kb / 1024 / 1024, 1) if total_kb else None,
            "used_gb": round(used_kb / 1024 / 1024, 1) if used_kb else None,
        })
    return vols


#: Whole disks that carry the running system, and the lock guarding the memo.
#:
#: Everything behind this asks about ``/``, not about a particular disk, but it used
#: to be re-read inside the per-disk loop: three subprocesses (`diskutil info /`,
#: `df -P /`, `diskutil info -plist /`) times the number of disks, to answer a
#: question with one answer.  Resolved once per listing instead.
_root_disks: set[str] | None = None
_root_disks_lock = threading.Lock()


def _root_whole_disks() -> set[str]:
    """Every whole-disk id that ``/`` resolves to, read once and cached.

    The lock is not decoration: the per-disk loop is now concurrent, and an
    unguarded memo let every thread that found it empty start its own copy of all
    three reads -- turning one `df` into one per worker.
    """
    global _root_disks
    with _root_disks_lock:
        if _root_disks is not None:
            return _root_disks

        found: set[str] = set()

        # The device `/` sits on, as diskutil spells it.
        rc, out, _ = sh(["/usr/sbin/diskutil", "info", "/"], timeout=_DISKUTIL_TIMEOUT)
        if rc == 0:
            found.update(re.findall(r"/dev/(disk\d+)", out or ""))

        # The same question through df, which reports the mounted device directly.
        rc, root_dev, _ = sh(["/bin/df", "-P", "/"], timeout=5)
        if rc == 0:
            for line in (root_dev or "").splitlines()[1:]:
                parts = line.split()
                if not parts:
                    continue
                m = re.search(r"/dev/(disk\d+)", parts[0])
                if m:
                    found.add(m.group(1))

        # APFS: root lives on a synthesised disk whose physical store is elsewhere,
        # so neither read above names the disk an operator could spin down.
        try:
            p = subprocess.run(
                ["/usr/sbin/diskutil", "info", "-plist", "/"],
                capture_output=True, timeout=_DISKUTIL_TIMEOUT,
            )
            if p.returncode == 0:
                rpl = plistlib.loads(p.stdout)
                parent = rpl.get("ParentWholeDisk") or ""
                if parent:
                    found.add(str(parent))
                for store in rpl.get("APFSPhysicalStores") or []:
                    dev = store.get("APFSPhysicalStore") if isinstance(store, dict) else store
                    if isinstance(dev, str):
                        m = re.match(r"(disk\d+)", dev)
                        if m:
                            found.add(m.group(1))
        except Exception:
            pass

        _root_disks = found
        return _root_disks


def _invalidate_root_disks() -> None:
    global _root_disks
    with _root_disks_lock:
        _root_disks = None


def _is_system_disk(info: dict, disk_id: str, volumes: list) -> bool:
    """Never allow sleep/eject of the boot / system APFS container parent."""
    # Root is usually on APFS container under disk0
    for v in volumes:
        if v.get("mount") in ("/", "/System/Volumes/Data", "/System/Volumes/Preboot"):
            return True
    # Internal Apple SSD
    name = (info.get("MediaName") or info.get("IORegistryEntryName") or "").upper()
    protocol = (info.get("BusProtocol") or "").lower()
    if info.get("SolidState") and info.get("Internal") and protocol in ("apple fabric", "pci-express", "nvme", ""):
        if "APPLE SSD" in name or info.get("DeviceLocation") == "Internal":
            # disk0 is typically the real whole disk
            if disk_id == "disk0":
                return True
    # Whatever `/` sits on, resolved once for the whole listing.
    return disk_id in _root_whole_disks()


def _power_state(disk_id: str, volumes: list, info: dict, probe: bool = True) -> str:
    """active | idle | spun_down | offline

    *probe* controls the ``smartctl -n standby`` power check.  Internal disks
    and SSDs never spin down, so probing them only pays for a subprocess
    (which on a wedged bus can even hang); callers skip it for those.
    """
    if volumes:
        return "active"
    # exists?
    node = f"/dev/{disk_id}"
    if not Path(node).exists() and not info:
        return "offline"
    if not probe:
        # Unmounted but present, no spin state to discover.
        return "idle"
    # smartctl check power mode
    rc, out, err = sh(["sudo", "-n", SMARTCTL, "-n", "standby", node], timeout=_DISKUTIL_TIMEOUT)
    text = (out or "") + (err or "")
    if "STANDBY" in text.upper() or "Device is in STANDBY" in text:
        return "spun_down"
    if "SLEEP" in text.upper():
        return "spun_down"
    if rc == 2 or "STANDBY" in text:
        return "spun_down"
    if rc == -1:
        # The probe timed out: the device is present but refuses to answer,
        # which is exactly what a spun-down disk behind a USB bridge does.
        # Report it as parked rather than holding the whole listing hostage.
        return "spun_down"
    # unmounted but present
    if info.get("Ejectable") or info.get("Removable") or info.get("RemovableMedia"):
        # after eject, disk may disappear
        if not Path(node).exists():
            return "offline"
        return "idle"
    return "idle"


#: The storage page polls every 45s and the menu bar client polls too, and a
#: cold listing costs one `diskutil info` per disk plus a smartctl probe per
#: sleeping candidate -- 0.3-0.8s healthy, and wedged up to the subprocess
#: timeouts when an external disk is asleep.  Mount/eject state changes rarely,
#: and every path that does change it calls invalidate_power_disks(), so a
#: 15s window trades imperceptible staleness for skipping the re-probe on
#: nearly every read.
_POWER_DISKS_TTL = 15.0


#: Concurrent per-disk probes.  Each one is a `diskutil info` plus, for a sleeping
#: candidate, a `smartctl` power query -- so this is bounded rather than one thread
#: per disk: a dozen enclosure disks would otherwise put a dozen smartctl processes
#: on a single controller at once.
_DISK_PROBE_WORKERS = 6


@ttl_memo(_POWER_DISKS_TTL)
def list_power_disks() -> list:
    ids = [d for d in _list_whole_disks() if DISK_RE.match(d)]
    if not ids:
        return []

    # Both shared reads are resolved before fanning out, so the workers find the
    # memos populated rather than racing to fill them.  A listing reflects the state
    # at its own start, so they are dropped first.
    _invalidate_df()
    _invalidate_root_disks()
    _df_lines()
    _root_whole_disks()

    # One `diskutil info` per disk, plus a smartctl probe per sleeping candidate --
    # and a probe against an external disk that is asleep costs the whole subprocess
    # timeout.  In series the page waited for the sum of those; the disks are
    # independent, so they overlap.  `fan_out` keeps `diskutil list` order, which is
    # what the storage table renders.
    return [d for d in fan_out(_describe_disk, ids, max_workers=_DISK_PROBE_WORKERS) if d]


def _describe_disk(disk_id: str) -> dict | None:
    """One row of the power listing.  Must not raise: `fan_out` re-raises on
    iteration, which would cost the whole listing instead of one disk."""
    try:
        node = f"/dev/{disk_id}"
        info = _diskutil_info(node)
        if not info:
            # try without path
            info = _diskutil_info(disk_id)
        volumes = _volumes_on_disk(disk_id)
        ssd = info.get("SolidState")
        # SolidState can be missing
        if ssd is None:
            media = (info.get("MediaName") or "") + " " + (info.get("IORegistryEntryName") or "")
            ssd = "SSD" in media.upper() or "NVME" in media.upper()
        protocol = info.get("BusProtocol") or info.get("Protocol") or ""
        name = (
            info.get("IORegistryEntryName")
            or info.get("MediaName")
            or info.get("VolumeName")
            or disk_id
        )
        size = info.get("TotalSize") or info.get("Size") or 0
        size_gb = round(size / 1e9, 1) if size else None
        system = _is_system_disk(info, disk_id, volumes)
        ejectable = bool(info.get("Ejectable"))
        removable = bool(info.get("Removable") or info.get("RemovableMedia"))
        internal = bool(info.get("Internal"))
        rotational = (ssd is False) or (
            not ssd and protocol.lower() in ("sata", "usb", "sas", "scsi", "secure digital")
            and not system
        )
        # SD card / USB external: treat as sleepable via eject/mount
        can_sleep = (not system) and (rotational or ejectable or removable or not internal)
        # pure internal SSD: cannot sleep
        if ssd and internal and system:
            can_sleep = False
        if ssd and internal and disk_id == "disk0":
            can_sleep = False
            system = True

        state = _power_state(
            disk_id,
            volumes,
            info,
            # Only an explicit fact skips the probe: `Internal` or `SolidState`
            # must be reported as true by diskutil.  A missing field keeps the
            # probe, because an SSD behind some USB bridges reports neither.
            probe=not (info.get("Internal") is True or info.get("SolidState") is True),
        )
        if system:
            state = "active"  # boot disk is always considered running
        actions = []
        if can_sleep:
            if state in ("active", "idle"):
                actions.append("sleep")  # 休眠/停转
                if ejectable or removable:
                    actions.append("eject")
            if state in ("spun_down", "idle", "offline"):
                actions.append("wake")  # 唤醒/挂载
            if state != "active" and (ejectable or removable or not volumes):
                if "wake" not in actions:
                    actions.append("wake")
            if volumes and can_sleep:
                if "sleep" not in actions:
                    actions.append("sleep")
        kind = "system"
        if system:
            kind = "system"
        elif ssd:
            kind = "ssd"
        elif removable or "SD" in protocol or "Secure Digital" in protocol:
            kind = "removable"
        elif not internal or ejectable:
            kind = "external_hdd" if not ssd else "external"
        else:
            kind = "hdd" if not ssd else "disk"

        return {
            "id": disk_id,
            "device": node,
            "name": name,
            "size_gb": size_gb,
            "size_human": info.get("TotalSize") and f"{size_gb} GB",
            "protocol": protocol,
            "ssd": bool(ssd),
            "rotational": bool(rotational) and not bool(ssd),
            "internal": internal,
            "ejectable": ejectable,
            "removable": removable,
            "system": system,
            "can_sleep": can_sleep,
            "power_state": state,
            "volumes": volumes,
            "kind": kind,
            "actions": actions,
            "hint": _hint(system, ssd, can_sleep, state),
        }
    except Exception:
        # One unreadable disk drops its own row rather than emptying the table.
        return None


def invalidate_power_disks() -> None:
    """Drop the cached power listing after an operation changed disk state.

    Kept beside the cross-module disk-info invalidation call sites below:
    both caches describe the same physical state (what is mounted, what is
    present), so they must be dropped together.  The manage side of the house
    reaches this through routers/storage.py, which can import both services
    without an import cycle.
    """
    list_power_disks.invalidate()
    # Both derived reads describe the same physical state, so they go too --
    # otherwise a disk that became the boot disk, or a volume that was just
    # unmounted, would keep its old classification for the life of the process.
    _invalidate_root_disks()
    _invalidate_df()


def _hint(system, ssd, can_sleep, state) -> str:
    if system:
        return "系统盘，禁止休眠"
    if ssd and not can_sleep:
        return "内置 SSD，无需/不可休眠"
    if state == "spun_down":
        return "已休眠，需要时点「唤醒」"
    if state == "offline":
        return "已推出或不在线，插入后点「唤醒/挂载」"
    if can_sleep:
        return "可休眠：停转后再访问前请先唤醒（减少机械盘频繁启停）"
    return ""


def sleep_disk(disk_id: str, mode: str = "sleep") -> dict:
    """Sleep or eject a disk. mode: sleep | eject"""
    if not DISK_RE.match(disk_id):
        raise HTTPException(400, "invalid disk id")
    disks = {d["id"]: d for d in list_power_disks()}
    d = disks.get(disk_id)
    if not d:
        raise HTTPException(404, f"disk not found: {disk_id}")
    if d["system"] or not d["can_sleep"]:
        raise HTTPException(403, "系统盘或不可休眠磁盘")
    node = d["device"]
    log = []

    # 1) Always unmount first (safe, keeps device node for wake)
    rc, out, err = sh(["/usr/sbin/diskutil", "unmountDisk", "force", node], timeout=60)
    log.append(f"unmountDisk: rc={rc} {(out or err)[:200]}")
    # This module mutates the very mount state disk_manage_svc caches, so its
    # short-TTL `diskutil info` entries are stale the moment the command runs.
    # Drop them here too: the storage page renders both modules side by side, and
    # without this a disk parked from the power panel still shows as mounted in
    # the managed-volumes list for up to the cache TTL.  Invalidate even on
    # failure -- a partial unmount still moved state.
    invalidate_disk_info()
    invalidate_power_disks()
    if rc != 0:
        return {
            "ok": False,
            "action": mode,
            "disk": disk_id,
            "message": err or out or "卸载失败（可能有进程占用）",
            "log": log,
        }

    # 2) Explicit eject only when requested (USB 机械盘彻底停转/安全移除)
    #    注意：内置 SD 读卡器 eject 后设备节点会消失，无法软件唤醒，故 sleep 不做 eject
    if mode == "eject":
        rc2, out2, err2 = sh(["/usr/sbin/diskutil", "eject", node], timeout=60)
        log.append(f"eject: rc={rc2} {(out2 or err2)[:200]}")
        # Eject removes the device node entirely, which is a second state change
        # after the unmount above -- the earlier invalidation predates it.
        invalidate_disk_info()
        invalidate_power_disks()
        ok = rc2 == 0
        return {
            "ok": ok,
            "action": "eject",
            "disk": disk_id,
            "message": (
                "已推出。USB 机械盘一般会停转；再次使用请重新插入或点唤醒。"
                if ok else (err2 or out2 or "推出失败")
            ),
            "log": log,
        }

    # 3) ATA/SATA/USB HDD: try SMART standby (spin down, keep device)
    rc3, out3, err3 = sh(
        ["sudo", "-n", SMARTCTL, "-s", "standby,now", node],
        timeout=20,
    )
    log.append(f"smartctl standby: rc={rc3} {(out3 or err3)[:200]}")
    if rc3 == 0:
        return {
            "ok": True,
            "action": "sleep",
            "disk": disk_id,
            "message": "已卸载并发送 standby，机械盘应已停转。需要时点「唤醒」。",
            "log": log,
        }

    # 4) Unmount-only success (SD 卡 / 不支持 SMART 的设备)
    return {
        "ok": True,
        "action": "sleep",
        "disk": disk_id,
        "message": (
            "已卸载卷（设备仍保留，可点唤醒重新挂载）。"
            "该设备不支持 smartctl standby；"
            "外接 USB 机械盘若要彻底停转请用「推出」。"
        ),
        "log": log,
    }


def wake_disk(disk_id: str) -> dict:
    if not DISK_RE.match(disk_id):
        raise HTTPException(400, "invalid disk id")
    node = f"/dev/{disk_id}"
    log = []

    # If disk node gone after eject, user must re-plug
    if not Path(node).exists():
        # try diskutil list to refresh
        sh(["/usr/sbin/diskutil", "list"], timeout=10)
        if not Path(node).exists():
            return {
                "ok": False,
                "action": "wake",
                "disk": disk_id,
                "message": f"{node} 不存在。若已推出 USB/SD，请重新插入后再唤醒。",
                "log": log,
            }

    # gentle spin-up: read first sector (may need raw device)
    rdev = node.replace("/dev/disk", "/dev/rdisk")
    rc0, out0, err0 = sh(
        ["/bin/dd", f"if={rdev}", "of=/dev/null", "bs=512", "count=1"],
        timeout=30,
    )
    log.append(f"dd spin-up: rc={rc0} {(err0 or out0)[:120]}")

    # exit standby via smartctl if possible
    rc1, out1, err1 = sh(
        ["sudo", "-n", SMARTCTL, "-s", "standby,off", node],
        timeout=15,
    )
    log.append(f"smartctl standby off: rc={rc1} {(out1 or err1)[:120]}")

    time.sleep(0.5)
    rc2, out2, err2 = sh(["/usr/sbin/diskutil", "mountDisk", node], timeout=90)
    log.append(f"mountDisk: rc={rc2} {(out2 or err2)[:200]}")
    # Waking remounts the volumes, so every cached `diskutil info` entry for this
    # disk and its children now reports the wrong mount point.
    invalidate_disk_info()
    invalidate_power_disks()
    ok = rc2 == 0
    return {
        "ok": ok,
        "action": "wake",
        "disk": disk_id,
        "message": (out2 or "已挂载/唤醒") if ok else (err2 or out2 or "挂载失败"),
        "log": log,
    }


def disk_power_action(disk_id: str, action: str) -> dict:
    action = (action or "").lower()
    if action in ("sleep", "standby", "spindown"):
        return sleep_disk(disk_id, mode="sleep")
    if action in ("eject",):
        return sleep_disk(disk_id, mode="eject")
    if action in ("wake", "spinup", "mount"):
        return wake_disk(disk_id)
    raise HTTPException(400, f"unknown action: {action}")
