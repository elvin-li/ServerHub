"""AppleRAID sets — the mirror/stripe/concat layer Unraid and OMV expose as RAID.

macOS has a software RAID implementation built into ``diskutil`` that most panels
ignore: mirrors (RAID 1), stripes (RAID 0) and concatenated sets (JBOD span).
This module reports set health, degraded members and rebuild progress, and drives
creation, member replacement and teardown.

Boundaries worth stating plainly, because they differ from Unraid:

* There is no parity-with-one-disk-failure mode like Unraid's array.  A mirror is
  the only redundant level macOS offers, so the UI must not imply otherwise.
* Every mutation here destroys or rewrites data on the selected devices.  Each one
  demands an explicit confirmation token and refuses any device that carries a
  mounted system volume, and the argv handed to the authorization sheet is rebuilt
  from device identifiers this process re-enumerated rather than from request data.
"""
from __future__ import annotations

import plistlib
import re
import time

from hub.macos_admin import run_admin
from hub.util import fan_out, sh

DISKUTIL = "/usr/sbin/diskutil"

#: ``disk4`` / ``disk4s2`` — the only device shape any argv here accepts.
_DEV_RE = re.compile(r"^disk\d{1,3}(?:s\d{1,3})*$")

#: Set names: keep to what diskutil and the Finder both handle predictably.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}$")

LEVELS = ("mirror", "stripe", "concat")
FILESYSTEMS = ("APFS", "JHFS+", "ExFAT")

_cache: dict = {"t": 0.0, "v": None}
_CACHE_TTL = 15.0

#: Concurrent ``diskutil info`` reads.  Measured knee: throughput stops improving at
#: 8 and degrades past it (16 and above ran slower than 8) because the requests
#: contend inside diskutil rather than on the bus.  Same value and same reason as the
#: constant in disk_manage_svc; kept local so neither module reaches into the other.
_INFO_WORKERS = 8


class RaidError(ValueError):
    """Carries a stable ``code`` for the router to translate."""

    def __init__(self, code: str, **params):
        super().__init__(code)
        self.code = code
        self.params = params


def _plist(argv: list[str], *, timeout: int = 15) -> dict:
    rc, out, _ = sh(argv, timeout=timeout)
    if rc != 0 or not out:
        return {}
    start = out.find("<?xml")
    if start < 0:
        return {}
    try:
        parsed = plistlib.loads(out[start:].encode())
    except (plistlib.InvalidFileException, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _disk_info(device: str) -> dict:
    """``diskutil info -plist`` for one device, as a plain dict."""
    if not _DEV_RE.match(device or ""):
        return {}
    return _plist([DISKUTIL, "info", "-plist", device], timeout=10)


def _whole_disk(device: str) -> str:
    """``disk0s2`` → ``disk0``; a whole-disk id passes through unchanged."""
    m = re.match(r"^(disk\d{1,3})", str(device or ""))
    return m.group(1) if m else ""


def disk_topology() -> dict[str, dict]:
    """Map every physical whole disk to the volumes it actually carries.

    This indirection is the whole reason the naive version of this check was
    wrong.  On an Apple-silicon Mac the boot volume is *not* a partition of the
    boot disk: ``/`` is a sealed snapshot on ``disk3s1``, ``disk3`` is a
    synthesized APFS container, and only that container's
    ``APFSPhysicalStores`` entry (``disk0s2``) ties it back to ``disk0``.  Walking
    partitions alone therefore reports ``disk0`` as carrying no mounted volume,
    which would have offered the boot disk as a RAID member.
    """
    data = _plist([DISKUTIL, "list", "-plist"], timeout=12)
    topology: dict[str, dict] = {}

    def slot(whole: str) -> dict:
        return topology.setdefault(whole, {"volumes": [], "system": False, "containers": []})

    entries = [d for d in (data.get("AllDisksAndPartitions") or []) if isinstance(d, dict)]

    # Pass 1: plain partition tables — a mount here belongs to this disk directly.
    for disk in entries:
        whole = str(disk.get("DeviceIdentifier") or "")
        if not whole:
            continue
        record = slot(whole)
        for part in disk.get("Partitions") or []:
            if not isinstance(part, dict):
                continue
            mount = str(part.get("MountPoint") or "")
            if mount:
                record["volumes"].append({
                    "device": str(part.get("DeviceIdentifier") or ""),
                    "mount": mount,
                    "name": str(part.get("VolumeName") or ""),
                })

    # Pass 2: APFS containers — attribute their volumes to the physical stores.
    for disk in entries:
        stores = disk.get("APFSPhysicalStores") or []
        volumes = disk.get("APFSVolumes") or []
        if not stores:
            continue
        backing = {
            _whole_disk(str(s.get("DeviceIdentifier") or ""))
            for s in stores if isinstance(s, dict)
        }
        backing.discard("")
        container = str(disk.get("DeviceIdentifier") or "")
        container_internal = bool(disk.get("OSInternal"))
        for whole in backing:
            record = slot(whole)
            record["containers"].append(container)
            if container_internal:
                record["system"] = True
            for vol in volumes:
                if not isinstance(vol, dict):
                    continue
                mounts = [str(vol.get("MountPoint") or "")]
                # A sealed system volume is mounted as a snapshot, so its own
                # MountPoint is empty and `/` only appears under MountedSnapshots.
                for snap in vol.get("MountedSnapshots") or []:
                    if isinstance(snap, dict):
                        mounts.append(str(snap.get("SnapshotMountPoint") or ""))
                for mount in [m for m in mounts if m]:
                    record["volumes"].append({
                        "device": str(vol.get("DeviceIdentifier") or ""),
                        "mount": mount,
                        "name": str(vol.get("VolumeName") or ""),
                    })
                if bool(vol.get("OSInternal")):
                    record["system"] = True

    # Pass 3: classify by mount point, which is the authoritative signal.
    for record in topology.values():
        for vol in record["volumes"]:
            mount = vol["mount"]
            if mount in ("/", "/System/Volumes/Data") or mount.startswith("/System/"):
                record["system"] = True
    return topology


def _parse_members(raw: list) -> list[dict]:
    members = []
    for entry in raw or []:
        if not isinstance(entry, dict):
            continue
        status = str(entry.get("MemberStatus") or entry.get("AppleRAIDMemberStatus") or "")
        members.append({
            "device": str(entry.get("AppleRAIDMemberDeviceNode") or entry.get("DeviceIdentifier") or "").replace("/dev/", ""),
            "uuid": str(entry.get("AppleRAIDMemberUUID") or ""),
            "status": status,
            "healthy": status.lower() in ("online", "ok"),
            "rebuild_percent": entry.get("AppleRAIDMemberRebuildPercent"),
            "size_bytes": entry.get("Size"),
            "size_gb": round(int(entry["Size"]) / 2**30, 1) if str(entry.get("Size") or "").isdigit() else None,
        })
    return members


def list_sets() -> list[dict]:
    data = _plist([DISKUTIL, "appleRAID", "list", "-plist"], timeout=15)
    sets = []
    for entry in data.get("AppleRAIDSets") or []:
        if not isinstance(entry, dict):
            continue
        members = _parse_members(entry.get("AppleRAIDMembers") or entry.get("Members") or [])
        status = str(entry.get("Status") or entry.get("AppleRAIDSetStatus") or "")
        level = str(entry.get("Level") or entry.get("AppleRAIDSetLevel") or "").lower()
        size = entry.get("Size")
        degraded = status.lower() in ("degraded", "failed") or any(not m["healthy"] for m in members)
        sets.append({
            "uuid": str(entry.get("AppleRAIDSetUUID") or entry.get("SetUUID") or ""),
            "name": str(entry.get("Name") or entry.get("AppleRAIDSetName") or ""),
            "level": level,
            "status": status,
            "degraded": degraded,
            # Only a mirror survives losing a member; say so rather than letting
            # the UI imply that any RAID level is protection.
            "redundant": level == "mirror",
            "device": str(entry.get("AppleRAIDSetDeviceNode") or "").replace("/dev/", ""),
            "size_bytes": size,
            "size_gb": round(int(size) / 2**30, 1) if str(size or "").isdigit() else None,
            "members": members,
            "member_count": len(members),
            "rebuilding": any(
                m.get("rebuild_percent") not in (None, "", 100) for m in members
            ),
        })
    return sets


def candidate_devices() -> list[dict]:
    """Whole disks that could join a new set, and why the rest cannot.

    ``diskutil list physical`` is the source, so disk-image and synthesized
    container devices are excluded before this even runs.  A disk that merely
    holds data is still offered, but with its mounted volumes attached so the UI
    can spell out exactly what an erase would destroy — silently hiding it would
    be worse, because the operator would not learn why their disk is missing.
    """
    topology = disk_topology()
    data = _plist([DISKUTIL, "list", "-plist", "physical"], timeout=12)

    disks = [
        (str(disk.get("DeviceIdentifier") or ""), disk)
        for disk in data.get("AllDisksAndPartitions") or []
        if isinstance(disk, dict)
    ]
    disks = [(device, disk) for device, disk in disks if _DEV_RE.fullmatch(device)]

    # One `diskutil info` per disk, and none of them depends on another.  In series
    # this grew with the number of physical disks -- and the machines this page
    # exists for are the ones with the most of them.  `_disk_info` cannot raise (its
    # `_plist` answers {} on every failure), which is what `fan_out` requires, and
    # `fan_out` keeps `diskutil list` order so the picker does not reorder between
    # refreshes.  Bounded width: concurrent `diskutil info` calls contend inside
    # diskutil, and past 8 the batch measured slower rather than faster.
    infos = fan_out(lambda item: _disk_info(item[0]), disks, max_workers=_INFO_WORKERS)

    out = []
    for (device, disk), info in zip(disks, infos):
        size = info.get("TotalSize") or disk.get("Size")
        record = topology.get(device) or {"volumes": [], "system": False}
        mounted = [
            {"mount": v["mount"], "name": v["name"], "device": v["device"]}
            for v in record["volumes"]
        ]
        blocked = "system" if record["system"] else ""
        out.append({
            "device": device,
            "name": str(info.get("MediaName") or info.get("IORegistryEntryName") or device),
            "size_bytes": size,
            "size_gb": round(int(size) / 2**30, 1) if str(size or "").isdigit() else None,
            "internal": bool(info.get("Internal")),
            "solid_state": bool(info.get("SolidState")),
            "protocol": str(info.get("BusProtocol") or ""),
            "mounted_volumes": mounted,
            "has_data": bool(mounted),
            "eligible": not blocked,
            "blocked_reason": blocked,
        })
    return out


def overview(force: bool = False) -> dict:
    now = time.time()
    if not force and _cache["v"] is not None and now - _cache["t"] < _CACHE_TTL:
        return _cache["v"]
    sets = list_sets()
    data = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "sets": sets,
        "count": len(sets),
        "degraded": sum(1 for s in sets if s["degraded"]),
        "rebuilding": sum(1 for s in sets if s["rebuilding"]),
        "candidates": candidate_devices(),
        "levels": list(LEVELS),
        "filesystems": list(FILESYSTEMS),
    }
    _cache.update(t=now, v=data)
    return data


def invalidate() -> None:
    _cache.update(t=0.0, v=None)


# ── mutations ────────────────────────────────────────────────────────────────

def _check_devices(devices: list[str], *, minimum: int) -> list[str]:
    """Validate and re-verify member devices against a fresh enumeration."""
    cleaned: list[str] = []
    for device in devices or []:
        value = str(device or "").strip().replace("/dev/", "")
        if not _DEV_RE.match(value):
            raise RaidError("raid.bad_device", device=value[:40])
        if value in cleaned:
            raise RaidError("raid.duplicate_device", device=value)
        cleaned.append(value)
    if len(cleaned) < minimum:
        raise RaidError("raid.too_few_members", minimum=minimum)

    eligible = {c["device"] for c in candidate_devices() if c["eligible"]}
    for device in cleaned:
        if device not in eligible:
            raise RaidError("raid.device_not_eligible", device=device)
    return cleaned


def create_set(
    *,
    level: str,
    name: str,
    filesystem: str,
    devices: list[str],
    confirm: bool,
    confirm_phrase: str,
) -> dict:
    """Build a new AppleRAID set.  Erases every selected device."""
    level = (level or "").strip().lower()
    if level not in LEVELS:
        raise RaidError("raid.bad_level", level=level[:20], choices=", ".join(LEVELS))
    filesystem = (filesystem or "").strip()
    if filesystem not in FILESYSTEMS:
        raise RaidError("raid.bad_filesystem", fs=filesystem[:20], choices=", ".join(FILESYSTEMS))
    name = (name or "").strip()
    if not _NAME_RE.match(name):
        raise RaidError("raid.bad_name")
    if not confirm:
        raise RaidError("raid.confirm_required")
    if (confirm_phrase or "").strip() != "ERASE":
        raise RaidError("raid.confirm_phrase_mismatch")

    # A mirror needs two members; a stripe needs two to be a stripe at all; a
    # concat set is meaningful from two upward.
    members = _check_devices(devices, minimum=2)

    result = run_admin(
        [DISKUTIL, "appleRAID", "create", level, name, filesystem, *members],
        timeout=900,
    )
    invalidate()
    if result.get("ok"):
        result.update(level=level, name=name, members=members)
    return result


def delete_set(*, set_uuid: str, confirm: bool, confirm_phrase: str) -> dict:
    """Tear a set down.  Every member is erased."""
    target = _resolve_set(set_uuid)
    if not confirm:
        raise RaidError("raid.confirm_required")
    if (confirm_phrase or "").strip() != target["name"]:
        raise RaidError("raid.confirm_name_mismatch", name=target["name"])
    result = run_admin([DISKUTIL, "appleRAID", "delete", target["uuid"]], timeout=600)
    invalidate()
    return result


def _resolve_set(set_uuid: str) -> dict:
    """Look a set up by UUID from a fresh enumeration."""
    value = str(set_uuid or "").strip()
    if not re.fullmatch(r"[0-9A-Fa-f-]{8,64}", value):
        raise RaidError("raid.bad_set")
    for entry in list_sets():
        if entry["uuid"].lower() == value.lower():
            return entry
    raise RaidError("raid.set_not_found", uuid=value[:40])


def repair_mirror(*, set_uuid: str, device: str, confirm: bool) -> dict:
    """Replace a failed mirror member.  Erases the incoming device."""
    target = _resolve_set(set_uuid)
    if target["level"] != "mirror":
        raise RaidError("raid.not_a_mirror")
    if not confirm:
        raise RaidError("raid.confirm_required")
    members = _check_devices([device], minimum=1)
    result = run_admin(
        [DISKUTIL, "appleRAID", "repairMirror", target["uuid"], members[0]],
        timeout=900,
    )
    invalidate()
    return result


def add_member(*, set_uuid: str, device: str, confirm: bool) -> dict:
    """Grow a mirror or concat set by one member.  Erases the incoming device."""
    target = _resolve_set(set_uuid)
    if target["level"] == "stripe":
        raise RaidError("raid.stripe_not_growable")
    if not confirm:
        raise RaidError("raid.confirm_required")
    members = _check_devices([device], minimum=1)
    result = run_admin(
        [DISKUTIL, "appleRAID", "add", "member", members[0], target["uuid"]],
        timeout=900,
    )
    invalidate()
    return result


def remove_member(*, set_uuid: str, member_uuid: str, confirm: bool) -> dict:
    """Detach one member from a set, leaving the set with fewer copies."""
    target = _resolve_set(set_uuid)
    value = str(member_uuid or "").strip()
    known = {m["uuid"].lower() for m in target["members"] if m["uuid"]}
    if value.lower() not in known:
        raise RaidError("raid.member_not_found", uuid=value[:40])
    if not confirm:
        raise RaidError("raid.confirm_required")
    if target["level"] == "mirror" and target["member_count"] <= 2:
        raise RaidError("raid.last_redundant_member")
    result = run_admin(
        [DISKUTIL, "appleRAID", "remove", value, target["uuid"]],
        timeout=600,
    )
    invalidate()
    return result
