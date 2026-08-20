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

from hub.disk_manage_svc import invalidate_disk_info
from hub.errors import api_error
from hub.disk_snapshot import (
    df_lines,
    invalidate_disks,
    physical_whole_disks,
    root_whole_disks,
)
from hub.paths import SMARTCTL
from hub.util import fan_out, run_bytes, sh, ttl_memo

# Whole-disk identifiers only
DISK_RE = re.compile(r"^disk\d+$")


def _text(value) -> str:
    """Plist display field as a JSON-safe string.

    ``MediaName`` / ``BusProtocol`` are strings in a healthy diskutil plist.
    ``inf`` used to fail Starlette's ``allow_nan=False`` encoder on the
    power listing (size inf was already dropped; the name/protocol fields
    were not).  Leftover ``sh`` int/None used to TypeError slicing the
    sleep/wake log.  A leftover ``\\ud800`` name still 500'd the UTF-8
    encode of GET /api/storage/disks.
    """
    if isinstance(value, (list, tuple)):
        value = value[0] if value else ""
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", "replace")
    elif isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
        return ""
    elif value in (None, False, ""):
        return ""
    elif isinstance(value, (dict, set, frozenset)):
        return ""
    elif not isinstance(value, str):
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


def _dev_exists(node: str) -> bool:
    """``Path.exists()`` raises EIO/ESTALE on a dying mount; pathlib only
    swallows ENOENT/ELOOP.  Wake used to 500 POST /api/storage/disks."""
    try:
        return Path(node).exists()
    except (OSError, ValueError):
        return False


#: A wedged diskutil (typically an external HDD asleep) used to pin this whole
#: listing at its subprocess timeout -- 12-15s per call.  Five seconds is far
#: beyond a healthy answer and bounds the worst case instead.
_DISKUTIL_TIMEOUT = 5


def _diskutil_info(node: str) -> dict:
    # -plist outputs binary plist — must use raw bytes (not text mode)
    try:
        rc, stdout, _ = run_bytes(
            ["/usr/sbin/diskutil", "info", "-plist", node],
            timeout=_DISKUTIL_TIMEOUT,
            runner=subprocess.run,
        )
        if rc == 0 and stdout:
            parsed = plistlib.loads(stdout)
            return parsed if isinstance(parsed, dict) else {}
    except Exception:
        pass
    return {}


def _list_whole_disks() -> list[str]:
    """Physical whole disks, from the snapshot shared with disk_manage_svc.

    `/api/storage` fans this module out alongside that one, so both reached the same
    cold `diskutil list -plist physical` in the same millisecond.
    """
    return list(physical_whole_disks())


#: The mount table.  `df` reports every volume on the machine in a single call, but
#: the per-disk helper below asked for the whole table and then threw away every row
#: belonging to another disk -- so a listing ran one full `df` per disk to read one
#: table.  That much was fixed by a per-listing memo; the table now lives in
#: hub.disk_snapshot, which widens the sharing to `storage_svc`, the other module on
#: this endpoint that reads it -- and which spelled the command `df` where this one
#: spelled it `/bin/df`, so the duplicate did not show up when grouping spawns by
#: argv.
def _df_lines() -> tuple[str, ...]:
    """`df -P -k` output lines, read once per request."""
    return df_lines()


def _invalidate_df() -> None:
    invalidate_disks()


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
        except (TypeError, ValueError, OverflowError):
            total_kb = used_kb = 0
        try:
            total_gb = round(total_kb / 1024 / 1024, 1) if total_kb else None
            used_gb = round(used_kb / 1024 / 1024, 1) if used_kb else None
        except OverflowError:
            total_gb = used_gb = None
        if total_gb is not None and (
            total_gb != total_gb or total_gb in (float("inf"), float("-inf"))
        ):
            total_gb = None
        if used_gb is not None and (
            used_gb != used_gb or used_gb in (float("inf"), float("-inf"))
        ):
            used_gb = None
        vols.append({
            "device": _text(fs),
            "mount": _text(mount),
            "total_gb": total_gb,
            "used_gb": used_gb,
        })
    return vols


#: Whole disks that carry the running system, and the lock guarding the memo.
#:
#: Everything behind this asks about ``/``, not about a particular disk, but it used
#: to be re-read inside the per-disk loop: three subprocesses (`diskutil info /`,
#: `df -P /`, `diskutil info -plist /`) times the number of disks, to answer a
#: question with one answer.  Resolved once per listing instead.
def _root_whole_disks() -> frozenset[str]:
    """Every whole-disk id that ``/`` resolves to.

    One definition, in hub.disk_snapshot, because all three reads behind it are
    whole-machine questions that the volume list and the manage listing ask too.  It
    is a union of three independent probes and they run concurrently there; here they
    ran one after another, which was three of the seven waves on /api/storage/disks.
    """
    return root_whole_disks()


def _invalidate_root_disks() -> None:
    invalidate_disks()


def _is_system_disk(info: dict, disk_id: str, volumes: list) -> bool:
    """Never allow sleep/eject of the boot / system APFS container parent."""
    # Root is usually on APFS container under disk0
    for v in volumes:
        if v.get("mount") in ("/", "/System/Volumes/Data", "/System/Volumes/Preboot"):
            return True
    # Internal Apple SSD
    name = _text(info.get("MediaName") or info.get("IORegistryEntryName")).upper()
    protocol = _text(info.get("BusProtocol")).lower()
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
    if not _dev_exists(node) and not info:
        return "offline"
    if not probe:
        # Unmounted but present, no spin state to discover.
        return "idle"
    # smartctl check power mode
    rc, out, err = sh(["/usr/bin/sudo", "-n", SMARTCTL, "-n", "standby", node], timeout=_DISKUTIL_TIMEOUT)
    text = _text(out) + _text(err)
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
        if not _dev_exists(node):
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

    # Both shared reads are resolved before fanning out, so the workers find them
    # populated rather than racing to fill them -- and they are resolved *together*,
    # because neither reads the other and in series they were two more levels on the
    # critical path of every page that lists disks.
    #
    # `_root_whole_disks` reaches the mount table itself, through one of its three
    # union members.  That is not a double read: both go through the same
    # single-flight cache, so whichever arrives second waits for the first rather
    # than spawning again.  Keeping the explicit `_df_lines` here anyway, because the
    # per-disk workers below need the table and depending on another function's
    # internals to warm it would be a trap for the next edit.
    #
    # The whole-disk list stays ahead of them: its result decides whether there is
    # any work at all, and the early return above is worth more than one level.
    #
    # These are no longer dropped first.  That was right while they were local to
    # this module, but they now live in hub.disk_snapshot and are shared with the two
    # other sections of /api/storage, which run concurrently with this one -- so
    # clearing them here discarded a read one of those had already paid for and put a
    # second `df -P -k` and a second `diskutil list -plist physical` back into the
    # request.  Both carry their own TTL, well inside this listing's own, and every
    # path that changes disk presence calls invalidate_power_disks().
    fan_out(lambda probe: probe(), [_df_lines, _root_whole_disks], max_workers=2)

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
        protocol = _text(info.get("BusProtocol") or info.get("Protocol"))
        name = (
            _text(info.get("IORegistryEntryName"))
            or _text(info.get("MediaName"))
            or _text(info.get("VolumeName"))
            or disk_id
        )
        size = info.get("TotalSize") or info.get("Size") or 0
        try:
            size_n = int(size)
        except (TypeError, ValueError, OverflowError):
            size_n = 0
        try:
            size_gb = round(size_n / 1e9, 1) if size_n else None
        except OverflowError:
            size_gb = None
        if size_gb is not None and (
            size_gb != size_gb or size_gb in (float("inf"), float("-inf"))
        ):
            size_gb = None
        system = _is_system_disk(info, disk_id, volumes)
        ejectable = bool(info.get("Ejectable"))
        removable = bool(info.get("Removable") or info.get("RemovableMedia"))
        internal = bool(info.get("Internal"))
        ssd = info.get("SolidState")
        # SolidState can be missing (USB bridges, sleeping disks, diskutil timeout).
        # Cascade of fallbacks: each only upgrades None → True, never downgrades
        # to False, so the next fallback in the chain still fires.
        if ssd is None:
            media = _text(info.get("MediaName")) + " " + _text(info.get("IORegistryEntryName"))
            media_upper = media.upper()
            if "SSD" in media_upper or "NVME" in media_upper:
                ssd = True
        if ssd is None:
            proto_lower = protocol.lower()
            if "fabric" in proto_lower or "nvme" in proto_lower or "pci" in proto_lower:
                ssd = True
        # Last-resort: ask smartctl (only for external non-system disks, avoids
        # the cost for internal disks where diskutil always answers).
        if ssd is None and not system and not internal:
            rc_s, out_s, _ = sh([SMARTCTL, "-a", node], timeout=8)
            out_s = _text(out_s)
            if rc_s in (0, 4) and out_s:
                for sline in out_s.splitlines():
                    if "Rotation Rate" in sline and "Solid State" in sline:
                        ssd = True
                        break
                    if sline.strip().startswith("Namespace 1") or "NVMe" in sline:
                        ssd = True
                        break
        # Default to False only after all fallbacks exhausted
        if ssd is None:
            ssd = False
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
                actions.append("sleep")  # spin down / standby
                if ejectable or removable:
                    actions.append("eject")
            if state in ("spun_down", "idle", "offline"):
                actions.append("wake")  # wake / mount
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
            "size_human": f"{size_gb} GB" if size_gb else None,
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
        return "System disk; sleep is not allowed"
    if ssd and not can_sleep:
        return "Internal SSD; sleep is unnecessary/unsupported"
    if state == "spun_down":
        return "Asleep; click Wake when you need it"
    if state == "offline":
        return "Ejected or offline; plug it in and click Wake/Mount"
    if can_sleep:
        if ssd:
            return "Can sleep: wake it before accessing again"
        return "Can sleep: wake it before accessing again (avoids frequent HDD spin-up/down cycles)"
    return ""


def sleep_disk(disk_id: str, mode: str = "sleep") -> dict:
    """Sleep or eject a disk. mode: sleep | eject"""
    if not DISK_RE.match(disk_id):
        raise api_error("disk_power.invalid_id")
    disks = {d["id"]: d for d in list_power_disks()}
    d = disks.get(disk_id)
    if not d:
        raise api_error("disk_power.not_found", disk=disk_id)
    if d["system"] or not d["can_sleep"]:
        raise api_error("disk_power.protected")
    node = d["device"]
    log = []

    # 1) Always unmount first (safe, keeps device node for wake)
    rc, out, err = sh(["/usr/sbin/diskutil", "unmountDisk", "force", node], timeout=60)
    out, err = _text(out), _text(err)
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
            "message": err or out or "unmount failed (a process may be using the volume)",
            "log": log,
        }

    # 2) Explicit eject only when requested (USB 机械盘彻底停转/安全移除)
    #    注意：内置 SD 读卡器 eject 后设备节点会消失，无法软件唤醒，故 sleep 不做 eject
    if mode == "eject":
        rc2, out2, err2 = sh(["/usr/sbin/diskutil", "eject", node], timeout=60)
        out2, err2 = _text(out2), _text(err2)
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
                "Ejected. USB HDDs usually spin down; re-plug the disk or click Wake to use it again."
                if ok else (err2 or out2 or "eject failed")
            ),
            "log": log,
        }

    # 3) ATA/SATA/USB HDD: try SMART standby (spin down, keep device)
    rc3, out3, err3 = sh(
        ["/usr/bin/sudo", "-n", SMARTCTL, "-s", "standby,now", node],
        timeout=20,
    )
    out3, err3 = _text(out3), _text(err3)
    log.append(f"smartctl standby: rc={rc3} {(out3 or err3)[:200]}")
    if rc3 == 0:
        return {
            "ok": True,
            "action": "sleep",
            "disk": disk_id,
            "message": "Unmounted and standby sent; the HDD should have spun down. Click Wake when you need it.",
            "log": log,
        }

    # 4) Unmount-only success (SD 卡 / 不支持 SMART 的设备)
    return {
        "ok": True,
        "action": "sleep",
        "disk": disk_id,
        "message": (
            "Volumes unmounted (the device node remains; click Wake to remount). "
            "This device does not support smartctl standby; "
            "to fully spin down an external USB HDD, use Eject."
        ),
        "log": log,
    }


def wake_disk(disk_id: str) -> dict:
    if not DISK_RE.match(disk_id):
        raise api_error("disk_power.invalid_id")
    node = f"/dev/{disk_id}"
    log = []

    # If disk node gone after eject, user must re-plug
    if not _dev_exists(node):
        # try diskutil list to refresh
        sh(["/usr/sbin/diskutil", "list"], timeout=10)
        if not _dev_exists(node):
            return {
                "ok": False,
                "action": "wake",
                "disk": disk_id,
                "message": f"{node} does not exist. If the USB/SD device was ejected, re-plug it before waking.",
                "log": log,
            }

    # gentle spin-up: read first sector (may need raw device)
    rdev = node.replace("/dev/disk", "/dev/rdisk")
    rc0, out0, err0 = sh(
        ["/bin/dd", f"if={rdev}", "of=/dev/null", "bs=512", "count=1"],
        timeout=30,
    )
    log.append(f"dd spin-up: rc={rc0} {(_text(err0) or _text(out0))[:120]}")

    # exit standby via smartctl if possible
    rc1, out1, err1 = sh(
        ["/usr/bin/sudo", "-n", SMARTCTL, "-s", "standby,off", node],
        timeout=15,
    )
    log.append(f"smartctl standby off: rc={rc1} {(_text(out1) or _text(err1))[:120]}")

    time.sleep(0.5)
    rc2, out2, err2 = sh(["/usr/sbin/diskutil", "mountDisk", node], timeout=90)
    out2, err2 = _text(out2), _text(err2)
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
        "message": (out2 or "mounted/awake") if ok else (err2 or out2 or "mount failed"),
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
    raise api_error("disk_power.unknown_action", action=action)
