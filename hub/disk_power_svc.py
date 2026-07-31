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
import time
from pathlib import Path

from fastapi import HTTPException

from hub.paths import SMARTCTL
from hub.util import sh

# Whole-disk identifiers only
DISK_RE = re.compile(r"^disk\d+$")


def _diskutil_info(node: str) -> dict:
    # -plist outputs binary plist — must use raw bytes (not text mode)
    try:
        p = subprocess.run(
            ["/usr/sbin/diskutil", "info", "-plist", node],
            capture_output=True, timeout=12,
        )
        if p.returncode == 0 and p.stdout:
            return plistlib.loads(p.stdout)
    except Exception:
        pass
    return {}


def _list_whole_disks() -> list[str]:
    p = subprocess.run(
        ["/usr/sbin/diskutil", "list", "-plist", "physical"],
        capture_output=True, timeout=15,
    )
    if p.returncode != 0:
        # fallback text
        rc, out, _ = sh(["/usr/sbin/diskutil", "list", "physical"], timeout=12)
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


def _volumes_on_disk(disk_id: str) -> list[dict]:
    """Mounted volumes belonging to this whole disk."""
    vols = []
    rc, out, _ = sh(["/bin/df", "-P", "-k"], timeout=8)
    for line in (out or "").splitlines()[1:]:
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
    # Mount point of boot
    rc, out, _ = sh(["/usr/sbin/diskutil", "info", "/"], timeout=8)
    if rc == 0 and f"/dev/{disk_id}" in out:
        return True
    # Parent of root device
    rc, root_dev, _ = sh(["/bin/df", "-P", "/"], timeout=5)
    if rc == 0:
        for line in root_dev.splitlines()[1:]:
            fs = line.split()[0]
            m = re.search(r"/dev/(disk\d+)", fs)
            if m and m.group(1) == disk_id:
                return True
            # APFS: root on disk3sX but whole physical is disk0 — check Physical Store
    # walk APFS physical stores
    p = subprocess.run(
        ["/usr/sbin/diskutil", "info", "-plist", "/"],
        capture_output=True, timeout=12,
    )
    if p.returncode == 0:
        try:
            rpl = plistlib.loads(p.stdout)
            parent = rpl.get("ParentWholeDisk") or ""
            if parent == disk_id:
                return True
            # APFS container parent
            for key in ("APFSPhysicalStores",):
                stores = rpl.get(key) or []
                for s in stores:
                    dev = s.get("APFSPhysicalStore") if isinstance(s, dict) else s
                    if isinstance(dev, str) and dev.startswith(disk_id):
                        return True
        except Exception:
            pass
    return False


def _power_state(disk_id: str, volumes: list, info: dict) -> str:
    """active | idle | spun_down | offline"""
    if volumes:
        return "active"
    # exists?
    node = f"/dev/{disk_id}"
    if not Path(node).exists() and not info:
        return "offline"
    # smartctl check power mode
    rc, out, err = sh(["sudo", "-n", SMARTCTL, "-n", "standby", node], timeout=10)
    text = (out or "") + (err or "")
    if "STANDBY" in text.upper() or "Device is in STANDBY" in text:
        return "spun_down"
    if "SLEEP" in text.upper():
        return "spun_down"
    if rc == 2 or "STANDBY" in text:
        return "spun_down"
    # unmounted but present
    if info.get("Ejectable") or info.get("Removable") or info.get("RemovableMedia"):
        # after eject, disk may disappear
        if not Path(node).exists():
            return "offline"
        return "idle"
    return "idle"


def list_power_disks() -> list:
    disks = []
    for disk_id in _list_whole_disks():
        if not DISK_RE.match(disk_id):
            continue
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

        state = _power_state(disk_id, volumes, info)
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

        disks.append({
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
        })
    return disks


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
