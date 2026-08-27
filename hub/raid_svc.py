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

from pathlib import Path

from hub.macos_admin import run_admin
from hub.util import cached_snapshot, fan_out, sh, strftime_now

DISKUTIL = "/usr/sbin/diskutil"

#: ``disk4`` / ``disk4s2`` — the only device shape any argv here accepts.
_DEV_RE = re.compile(r"^disk\d{1,3}(?:s\d{1,3})*$")

#: Set names: keep to what diskutil and the Finder both handle predictably.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}$")

LEVELS = ("mirror", "stripe", "concat")
FILESYSTEMS = ("APFS", "JHFS+", "ExFAT")

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
    if isinstance(out, (bytes, bytearray)):
        out = bytes(out).decode("utf-8", "replace")
    elif not isinstance(out, str):
        try:
            out = str(out)
        except RecursionError:
            return {}
        except Exception:
            return {}
    start = out.find("<?xml")
    if start < 0:
        return {}
    try:
        parsed = plistlib.loads(out[start:].encode())
    except Exception:
        # Torn XML (``sh`` cap, diagnostics ahead of a truncated plist)
        # raises xml.parsers.expat.ExpatError, which is not ValueError —
        # that used to 500 /api/raid.
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _disk_info(device: str) -> dict:
    """``diskutil info -plist`` for one device, as a plain dict."""
    if not _DEV_RE.match(device or ""):
        return {}
    return _plist([DISKUTIL, "info", "-plist", device], timeout=10)


def _ident(value) -> str:
    """Plist device / mount field as text.

    ``DeviceIdentifier`` / ``APFSPhysicalStore`` / ``SnapshotMountPoint`` are
    strings in a healthy diskutil plist.  Leftover ``bytes`` used to stringify
    as ``b'disk0s2'`` and drop the APFS physical store from the boot-disk
    union; array-shaped leftovers used to skip the store the same way.
    """
    if isinstance(value, (list, tuple)):
        value = value[0] if value else ""
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", "replace")
    if not isinstance(value, str):
        return ""
    # Leftover ``\\ud800`` in a plist Name used to 500 GET /api/raid.
    return value.encode("utf-8", "replace").decode("utf-8")


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's ``allow_nan=False`` encoder cannot 500.

    Plist names were already scrubbed; leftover ``\\ud800`` / ``Infinity`` in
    a ``run_admin`` message still 500'd POST /api/raid.
    """
    if depth > 16:
        return None
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        try:
            str(value)
        except ValueError:
            # Past CPython's int->str digit cap the encoder cannot render
            # the number at all — same drop as its inf float sibling.
            return None
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if isinstance(value, str):
        return _ident(value)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    if isinstance(value, dict):
        try:
            items = list(value.items())
        except Exception:
            # A mapping that refuses iteration (odd dict subclass in a
            # run_admin result): nothing to salvage, but its *siblings* must
            # survive — pre-fix this raised out of _admin_result and 500'd
            # POST /api/raid/* (the ups_svc/nginx_svc._jsonable rule).
            return None
        out = {}
        for k, v in items:
            if not isinstance(k, (str, bytes, bytearray)):
                try:
                    k = str(k)
                except Exception:
                    continue
            out[_ident(k)] = _jsonable(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        try:
            return [_jsonable(v, depth + 1) for v in value]
        except Exception:
            # Same class as the mapping above, at sequence rank: only this
            # field drops, never the payload or the route.
            return None
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/raid.
            return _jsonable(iso(), depth + 1)
        except Exception:
            return None
    try:
        return _ident(value) or str(value).encode("utf-8", "replace").decode("utf-8")
    except RecursionError:
        try:
            return type(value).__name__
        except Exception:
            return None
    except Exception:
        return None


def _req_text(raw) -> str:
    """Mutation argument as text via the str() probe (never the digit-cap raise).

    Arguments arrive as str through Pydantic, but the service is also called
    in-process, and a leftover YAML/plist hex int is *already-int* —
    ``int(x, 16)`` is exempt from CPython's 4300-digit parse cap — so the bare
    ``str()`` these call sites used raised the int->str digit-cap ValueError
    (a 500 on POST /api/raid/sets, /delete, /repair and /members/*) where
    every other junk value gets the coded refusal.  A str() probe, not an
    ``isinstance(str)`` gate: a finite numeric leftover must keep behaving as
    its string form and earn the same coded refusal path.  Lone surrogates
    are scrubbed so a refusal's own params cannot 500 the error body.
    """
    if raw is None or isinstance(raw, bool):
        return ""
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw).decode("utf-8", "replace")
    if not isinstance(raw, str):
        try:
            raw = str(raw)
        except Exception:
            # The digit-cap ValueError, or a leftover whose __str__ raises.
            return ""
    return raw.encode("utf-8", "replace").decode("utf-8")


def _diskutil_on_disk() -> bool:
    """Fresh disk probe for the mutation-failure path only (vms/brew/rsync rule).

    ``Path.is_file()`` can itself raise on a dying volume (EIO/ESTALE); a disk
    that cannot even answer for /usr/sbin is not confirmably carrying it.
    """
    try:
        return Path(DISKUTIL).is_file()
    except (OSError, ValueError):
        return False


#: What a spawn of a gone binary reads like through run_admin: the shell's own
#: refusal (``sh: /usr/sbin/diskutil: command not found`` / ``No such file or
#: directory``) or sh()'s FileNotFoundError sentinel (``not found``).  Purely a
#: message-pattern gate: classification additionally requires the fresh
#: :func:`_diskutil_on_disk` probe to confirm the binary is really gone.
_VANISH_MARKERS = ("command not found", "no such file or directory", "not found")


def _admin_result(result) -> dict:
    cleaned = _jsonable(result) if isinstance(result, dict) else {}
    if not isinstance(cleaned, dict):
        return {"ok": False, "error": "failed"}
    # A diskutil that vanished between the eligibility check and the spawn
    # (an OS update mid-flight, a dying system volume) used to surface as the
    # generic 500 ``admin.failed`` — "the privileged macOS operation failed"
    # sends the operator to re-enter a password that can never help.  The
    # coded 503 fires only after a fresh disk probe confirms diskutil is gone
    # (the vms/brew/rsync rule); with the binary still on disk the raw
    # failure is the truth and keeps its own message.  The probe runs only on
    # this failure path, never on a successful mutation.
    if not cleaned.get("ok") and cleaned.get("error") == "failed":
        message = _ident(cleaned.get("message") or "").lower()
        if any(marker in message for marker in _VANISH_MARKERS) and not _diskutil_on_disk():
            return {"ok": False, "error": "diskutil_missing"}
    return cleaned


def _whole_disk(device: str) -> str:
    """``disk0s2`` → ``disk0``; a whole-disk id passes through unchanged."""
    m = re.match(r"^(disk\d{1,3})", _ident(device))
    return m.group(1) if m else ""


def _size_fields(raw) -> tuple:
    """JSON-safe ``(size_bytes, size_gb)``.

    ``Size: inf`` used to 500 GET /api/raid under Starlette's ``allow_nan=False``
    encoder (disk_manage already dropped inf sizes; this module still emitted
    the raw plist number).  A huge finite integer OverflowError'd the GB
    conversion the same way a 400-digit ``df`` block count did.
    """
    if isinstance(raw, bool) or raw is None:
        return None, None
    if isinstance(raw, float) and (raw != raw or raw in (float("inf"), float("-inf"))):
        return None, None
    try:
        n = int(raw)
    except (TypeError, ValueError, OverflowError):
        return None, None
    try:
        str(n)
    except ValueError:
        # A leftover plist Size already past CPython's int->str digit cap
        # survives ``int()`` unchanged and ValueError'd json.dumps itself
        # on GET /api/raid (the 400-digit class only lost its GB figure).
        return None, None
    try:
        gb = round(n / 2**30, 1)
    except OverflowError:
        return n, None
    if gb != gb or gb in (float("inf"), float("-inf")):
        gb = None
    return n, gb


def _finite_float(raw):
    if isinstance(raw, bool) or raw in (None, ""):
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError, OverflowError):
        return None
    if value != value or value in (float("inf"), float("-inf")):
        return None
    return value


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

    raw_disks = data.get("AllDisksAndPartitions")
    entries = [d for d in raw_disks if isinstance(d, dict)] if isinstance(raw_disks, list) else []

    # Pass 1: plain partition tables — a mount here belongs to this disk directly.
    for disk in entries:
        whole = _ident(disk.get("DeviceIdentifier"))
        if not whole:
            continue
        record = slot(whole)
        for part in disk.get("Partitions") if isinstance(disk.get("Partitions"), list) else []:
            if not isinstance(part, dict):
                continue
            mount = _ident(part.get("MountPoint"))
            if mount:
                record["volumes"].append({
                    "device": _ident(part.get("DeviceIdentifier")),
                    "mount": mount,
                    "name": _ident(part.get("VolumeName")),
                })

    # Pass 2: APFS containers — attribute their volumes to the physical stores.
    for disk in entries:
        stores = disk.get("APFSPhysicalStores") if isinstance(disk.get("APFSPhysicalStores"), list) else []
        volumes = disk.get("APFSVolumes") if isinstance(disk.get("APFSVolumes"), list) else []
        if not stores:
            continue
        backing: set[str] = set()
        for store in stores:
            if isinstance(store, dict):
                raw = store.get("DeviceIdentifier") or store.get("APFSPhysicalStore")
            else:
                raw = store
            whole = _whole_disk(raw)
            if whole:
                backing.add(whole)
        container = _ident(disk.get("DeviceIdentifier"))
        container_internal = bool(disk.get("OSInternal"))
        for whole in backing:
            record = slot(whole)
            record["containers"].append(container)
            if container_internal:
                record["system"] = True
            for vol in volumes:
                if not isinstance(vol, dict):
                    continue
                mounts = [_ident(vol.get("MountPoint"))]
                # A sealed system volume is mounted as a snapshot, so its own
                # MountPoint is empty and `/` only appears under MountedSnapshots.
                for snap in vol.get("MountedSnapshots") if isinstance(vol.get("MountedSnapshots"), list) else []:
                    if isinstance(snap, dict):
                        mounts.append(_ident(snap.get("SnapshotMountPoint")))
                for mount in [m for m in mounts if m]:
                    record["volumes"].append({
                        "device": _ident(vol.get("DeviceIdentifier")),
                        "mount": mount,
                        "name": _ident(vol.get("VolumeName")),
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


def _parse_members(raw) -> list[dict]:
    members = []
    if not isinstance(raw, list):
        return members
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        status = _ident(entry.get("MemberStatus") or entry.get("AppleRAIDMemberStatus") or "")
        size_bytes, size_gb = _size_fields(entry.get("Size"))
        members.append({
            "device": _ident(entry.get("AppleRAIDMemberDeviceNode") or entry.get("DeviceIdentifier") or "").replace("/dev/", ""),
            "uuid": _ident(entry.get("AppleRAIDMemberUUID") or ""),
            "status": status,
            "healthy": status.lower() in ("online", "ok"),
            "rebuild_percent": _finite_float(entry.get("AppleRAIDMemberRebuildPercent")),
            "size_bytes": size_bytes,
            "size_gb": size_gb,
        })
    return members


def list_sets() -> list[dict]:
    data = _plist([DISKUTIL, "appleRAID", "list", "-plist"], timeout=15)
    sets = []
    raw_sets = data.get("AppleRAIDSets")
    if not isinstance(raw_sets, list):
        raw_sets = []
    for entry in raw_sets:
        if not isinstance(entry, dict):
            continue
        members = _parse_members(entry.get("AppleRAIDMembers") or entry.get("Members") or [])
        status = _ident(entry.get("Status") or entry.get("AppleRAIDSetStatus") or "")
        level = _ident(entry.get("Level") or entry.get("AppleRAIDSetLevel") or "").lower()
        size_bytes, size_gb = _size_fields(entry.get("Size"))
        degraded = status.lower() in ("degraded", "failed") or any(not m["healthy"] for m in members)
        sets.append({
            "uuid": _ident(entry.get("AppleRAIDSetUUID") or entry.get("SetUUID") or ""),
            "name": _ident(entry.get("Name") or entry.get("AppleRAIDSetName") or ""),
            "level": level,
            "status": status,
            "degraded": degraded,
            # Only a mirror survives losing a member; say so rather than letting
            # the UI imply that any RAID level is protection.
            "redundant": level == "mirror",
            "device": _ident(entry.get("AppleRAIDSetDeviceNode") or "").replace("/dev/", ""),
            "size_bytes": size_bytes,
            "size_gb": size_gb,
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

    raw_disks = data.get("AllDisksAndPartitions")
    disks = [
        (_ident(disk.get("DeviceIdentifier")), disk)
        for disk in (raw_disks if isinstance(raw_disks, list) else [])
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
        size_bytes, size_gb = _size_fields(info.get("TotalSize") or disk.get("Size"))
        record = topology.get(device) or {"volumes": [], "system": False}
        mounted = [
            {"mount": v["mount"], "name": v["name"], "device": v["device"]}
            for v in record["volumes"]
        ]
        blocked = "system" if record["system"] else ""
        out.append({
            "device": device,
            "name": _ident(info.get("MediaName")) or _ident(info.get("IORegistryEntryName")) or device,
            "size_bytes": size_bytes,
            "size_gb": size_gb,
            "internal": bool(info.get("Internal")),
            "solid_state": bool(info.get("SolidState")),
            "protocol": _ident(info.get("BusProtocol")),
            "mounted_volumes": mounted,
            "has_data": bool(mounted),
            "eligible": not blocked,
            "blocked_reason": blocked,
        })
    return out


def _listing(provider) -> list:
    """A listing provider's answer materialized under its own guard.

    ``list_sets`` / ``candidate_devices`` build plain rows, but this module
    does not own them (tests and tooling patch both), and a leftover listing
    that passes ``isinstance`` yet refuses iteration — or a row missing its
    own keys — used to blow ``overview()``'s counts *before* the route's
    sanitizer could drop the unusable field, 500ing GET /api/raid (the
    usage_svc.scan_roots / storage_pool_svc._candidates rule).
    """
    try:
        rows = provider()
    except Exception:
        return []
    if not isinstance(rows, list):
        return []
    try:
        return [r for r in list.__iter__(rows) if isinstance(r, dict)]
    except Exception:
        return []


def _flagged(rows: list, key: str) -> int:
    """How many rows carry a truthy *key*; a hostile row counts as false."""
    total = 0
    for row in rows:
        try:
            if bool(dict.get(row, key)):
                total += 1
        except Exception:
            continue
    return total


@cached_snapshot(_CACHE_TTL)
def overview(force: bool = False) -> dict:
    sets = _listing(list_sets)
    data = {
        "ts": strftime_now("%Y-%m-%d %H:%M:%S"),
        "sets": sets,
        "count": len(sets),
        # dict.get + a guarded bool, not ``s["degraded"]``: a row that lost
        # its own flag KeyError'd the count, and a leftover ``__bool__`` bomb
        # detonated the truth test itself.
        "degraded": _flagged(sets, "degraded"),
        "rebuilding": _flagged(sets, "rebuilding"),
        "candidates": _listing(candidate_devices),
        "levels": list(LEVELS),
        "filesystems": list(FILESYSTEMS),
    }
    return data


def invalidate() -> None:
    overview.invalidate()


# ── mutations ────────────────────────────────────────────────────────────────

def _check_devices(devices: list[str], *, minimum: int) -> list[str]:
    """Validate and re-verify member devices against a fresh enumeration."""
    cleaned: list[str] = []
    # Guarded unbound walk (the smart_test_svc.set_schedule rule): the routes
    # hand over Pydantic-exact lists, but the service is also called
    # in-process, and a leftover list-subclass ``__bool__``/``__iter__`` bomb
    # used to blow the old ``(devices or [])`` raw — past the router's
    # RaidError catch — where every junk device already earns the coded
    # ``raid.bad_device`` refusal.
    if isinstance(devices, list):
        rows = list.__iter__(devices)
    elif isinstance(devices, tuple):
        rows = tuple.__iter__(devices)
    else:
        rows = iter(())
    for device in rows:
        # _req_text, not str(): a leftover int already past CPython's
        # int->str digit cap made ``str(device)`` itself ValueError out of
        # the endpoint instead of the coded refusal every other junk
        # device gets (the storage_pool_svc._validate convention).
        value = _req_text(device).strip().replace("/dev/", "")
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
    # _req_text throughout: ``(level or "").strip()`` AttributeError'd (a
    # 500) on any in-process non-str leftover where the coded refusal below
    # is the contract.
    level = _req_text(level).strip().lower()
    if level not in LEVELS:
        raise RaidError("raid.bad_level", level=level[:20], choices=", ".join(LEVELS))
    filesystem = _req_text(filesystem).strip()
    if filesystem not in FILESYSTEMS:
        raise RaidError("raid.bad_filesystem", fs=filesystem[:20], choices=", ".join(FILESYSTEMS))
    name = _req_text(name).strip()
    if not _NAME_RE.match(name):
        raise RaidError("raid.bad_name")
    if not confirm:
        raise RaidError("raid.confirm_required")
    if _req_text(confirm_phrase).strip() != "ERASE":
        raise RaidError("raid.confirm_phrase_mismatch")

    # A mirror needs two members; a stripe needs two to be a stripe at all; a
    # concat set is meaningful from two upward.
    members = _check_devices(devices, minimum=2)

    result = run_admin(
        [DISKUTIL, "appleRAID", "create", level, name, filesystem, *members],
        timeout=900,
    )
    invalidate()
    if isinstance(result, dict) and result.get("ok"):
        result = dict(result)
        result.update(level=level, name=name, members=members)
    return _admin_result(result)


def delete_set(*, set_uuid: str, confirm: bool, confirm_phrase: str) -> dict:
    """Tear a set down.  Every member is erased."""
    target = _resolve_set(set_uuid)
    if not confirm:
        raise RaidError("raid.confirm_required")
    if _req_text(confirm_phrase).strip() != target["name"]:
        raise RaidError("raid.confirm_name_mismatch", name=target["name"])
    result = run_admin([DISKUTIL, "appleRAID", "delete", target["uuid"]], timeout=600)
    invalidate()
    return _admin_result(result)


def _resolve_set(set_uuid: str) -> dict:
    """Look a set up by UUID from a fresh enumeration."""
    # _req_text, not str(): an already-int over-cap uuid ValueError'd here
    # instead of the coded ``raid.bad_set`` refusal.
    value = _req_text(set_uuid).strip()
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
    return _admin_result(result)


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
    return _admin_result(result)


def remove_member(*, set_uuid: str, member_uuid: str, confirm: bool) -> dict:
    """Detach one member from a set, leaving the set with fewer copies."""
    target = _resolve_set(set_uuid)
    # Same probe as _resolve_set: str() of an over-cap member uuid was the
    # digit-cap ValueError, not the coded ``raid.member_not_found``.
    value = _req_text(member_uuid).strip()
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
    return _admin_result(result)
