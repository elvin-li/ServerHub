"""Disk management via diskutil (mount / unmount / rename / format).

Destructive ops (format / erase) require confirm flags and never target system disk.
"""
from __future__ import annotations

import plistlib
import re
import subprocess
import threading
import time
from concurrent.futures import Future
from pathlib import Path
from typing import Any

from hub.disk_snapshot import (
    invalidate_disks,
    physical_whole_disks,
    root_devices,
    root_info,
)
from hub.errors import api_error
from hub.util import fan_out, run_bytes, sh

DISK_RE = re.compile(r"^disk\d+(s\d+)*$")
WHOLE_RE = re.compile(r"^disk\d+$")

#: Every mutation below shells out to this one binary.
DISKUTIL = "/usr/sbin/diskutil"

#: What a spawn of a gone binary reads like: sh()'s FileNotFoundError
#: sentinel (``not found``) or a wrapper shell's own refusal.  Purely a
#: message-pattern gate — diskutil's genuine failures can contain "not
#: found" too ("Volume … was not found"), so classification additionally
#: requires the fresh :func:`_diskutil_on_disk` probe (the raid_svc rule).
_VANISH_MARKERS = ("command not found", "no such file or directory", "not found")


def _diskutil_on_disk() -> bool:
    """Fresh disk probe for the mutation-failure path only (raid_svc rule).

    ``Path.is_file()`` can itself raise on a dying volume (EIO/ESTALE); a
    disk that cannot even answer for /usr/sbin is not confirmably carrying
    the binary.
    """
    try:
        return Path(DISKUTIL).is_file()
    except (OSError, ValueError):
        return False


def _vanished_spawn(rc: int, out: str, err: str) -> bool:
    """True when a diskutil failure reads like the binary itself is gone.

    Callers must still confirm with :func:`_diskutil_on_disk`: with the
    binary on disk the raw failure is the truth and keeps its own message.
    """
    if rc == 0:
        return False
    blob = f"{out}\n{err}".lower()
    return any(marker in blob for marker in _VANISH_MARKERS)

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
        # Binary plist: UTF-8 ``sh()`` would corrupt it.  ``run_bytes``
        # streams to a tempfile and refuses a payload past the cap.
        rc, stdout, _ = run_bytes(cmd, timeout=timeout, runner=subprocess.run)
        if rc != 0 or not stdout:
            return None
        return plistlib.loads(stdout)
    except Exception:
        return None


#: `diskutil info` costs ~130ms per device.  Listing volumes needs one call per
#: partition, so a 25-volume host spent ~3.7s in serial subprocesses on every
#: /api/storage request.  A short TTL keeps the page responsive while still
#: reflecting a mount/unmount the user just performed.
#:
#: Raised from 8s to 30s: the storage page polls every 45s, so at 8s every poll
#: expired the cache and re-ran the whole fan-out (~2s on a 25-node tree) for
#: data nothing could have changed in between.  Freshness after a real
#: mount/unmount/eject/rename/format is still guaranteed because every one of
#: those paths calls invalidate_disk_info() unconditionally.
_INFO_TTL = 30.0
_INFO_CACHE: dict[str, tuple[float, dict]] = {}
_INFO_LOCK = threading.Lock()

#: Bounded: diskutil is a system service, and a wide fan-out on a host with many
#: volumes would trade one slow request for a thundering herd of processes.
#:
#: Raising this was tried and measured to do nothing: a 39-node tree took a
#: median 2068ms at eight workers, 2121ms at sixteen and 2061ms at twenty-four,
#: all within run-to-run noise.  `diskutil` serialises internally, so the wall
#: time is set by the service and not by how many clients queue against it.
#: Leave it at eight; the concurrency win comes from _INFO_INFLIGHT below.
_INFO_WORKERS = 8

#: In-flight fetches, keyed by node.
#:
#: The cache alone only helps *after* a fetch completes, so simultaneous readers
#: each started their own fan-out for the same nodes.  Measured: one request
#: spawned 38 `diskutil info` processes in 2.1s, two spawned 76 in 4.4s, four
#: spawned 152 in 9.5s -- latency scaling linearly with readers because they
#: competed for one system service while fetching identical data.  The panel
#: polls, the menu-bar client polls, and a browser refresh adds another reader,
#: which is how /api/storage reached ~20s.  Joining an in-flight fetch instead of
#: duplicating it keeps the spawn count flat at 38 regardless of reader count.
_INFO_INFLIGHT: dict[str, "Future[dict]"] = {}

#: Bumped by invalidate_disk_info().  A fetch that started before an
#: invalidation must not write its now-stale result into the cache afterwards,
#: which is the one race single-flighting introduces.
_INFO_GENERATION = 0


def invalidate_disk_info() -> None:
    """Drop cached `diskutil info` output after an operation changes state."""
    global _INFO_GENERATION
    with _INFO_LOCK:
        _INFO_CACHE.clear()
        _INFO_GENERATION += 1


def _diskutil_info_uncached(node: str) -> dict:
    # Five seconds caps a wedged diskutil (typically a sleeping external disk);
    # on timeout _plist() returns None and this yields {}, so the walk below
    # keeps the tree structure and simply renders that node without details
    # instead of holding the whole overview until the disk answers.
    pl = _plist(["/usr/sbin/diskutil", "info", "-plist", node], timeout=5)
    return pl if isinstance(pl, dict) else {}


def _fetch_shared(node: str) -> dict:
    """Fetch *node* info, joining a concurrent fetch for the same node.

    The first caller owns the fetch and publishes the result; everyone else waits
    on its future.  Only the owner runs a subprocess, so N readers cost one
    ``diskutil info`` per node rather than N.
    """
    now = time.time()
    with _INFO_LOCK:
        hit = _INFO_CACHE.get(node)
        if hit and now - hit[0] < _INFO_TTL:
            return hit[1]
        pending = _INFO_INFLIGHT.get(node)
        if pending is not None:
            owner = False
            future: "Future[dict]" = pending
        else:
            owner = True
            future = Future()
            _INFO_INFLIGHT[node] = future
        generation = _INFO_GENERATION

    if not owner:
        try:
            # Bounded so a wedged diskutil cannot pin an unrelated request
            # forever; the fetch itself is capped at five seconds, so a joiner
            # waiting much longer than that is already an anomaly.  Falling
            # back to an empty dict matches _plist()'s own behaviour on failure.
            return future.result(timeout=15)
        except Exception:
            return {}

    try:
        data = _diskutil_info_uncached(node)
    except BaseException as exc:
        with _INFO_LOCK:
            _INFO_INFLIGHT.pop(node, None)
        future.set_exception(exc)
        raise
    with _INFO_LOCK:
        _INFO_INFLIGHT.pop(node, None)
        # A mutation landed while this was in flight: the result describes the
        # pre-mutation state, so serve it to the current waiters but keep it out
        # of the cache.
        if generation == _INFO_GENERATION:
            _INFO_CACHE[node] = (time.time(), data)
    future.set_result(data)
    return data


def _diskutil_info(node: str) -> dict:
    return _fetch_shared(node)


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
    # _fetch_shared publishes into the cache itself and de-duplicates against any
    # other request already fetching the same node, so the results are simply
    # discarded here rather than written a second time.
    fan_out(_fetch_shared, pending, max_workers=min(_INFO_WORKERS, len(pending)))


def _ident(value) -> str:
    """Plist device identifier as a string.

    ``DeviceIdentifier`` / ``ParentWholeDisk`` are strings in a healthy
    diskutil plist.  An array-shaped or non-string value used to TypeError
    ``re.match`` / ``set.add`` and 500 the manage listing.  Leftover
    ``bytes`` used to stringify as ``b'disk4'`` and drop the node.  A
    leftover ``\\ud800`` identifier used to 500 the same JSON encoder.
    """
    if isinstance(value, (list, tuple)):
        value = value[0] if value else ""
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", "replace")
    if not isinstance(value, str):
        return ""
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return ""
    return value


def _text(value) -> str:
    """Plist display field as a JSON-safe string.

    ``VolumeName`` / ``MountPoint`` / ``MediaName`` are strings in a healthy
    diskutil plist.  ``inf`` used to fail Starlette's ``allow_nan=False``
    encoder and ``bytes`` used to TypeError ``json.dumps``.  A leftover
    ``\\ud800`` name still 500'd the UTF-8 encode of GET /api/storage.
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


def _req_text(raw) -> str:
    """Mutation argument as text via the str() probe (never the digit-cap raise).

    Arguments arrive as str through Pydantic, but the service is also called
    in-process, and a leftover YAML/plist hex int is *already-int* —
    ``int(x, 16)`` is exempt from CPython's 4300-digit parse cap — so a bare
    ``str()`` raises the int->str digit-cap ValueError where every other junk
    value gets the coded refusal.  A str() probe, not an ``isinstance(str)``
    gate: a finite numeric leftover keeps behaving as its string form (the
    raid_svc._req_text convention).  Two deliberate differences from the plist
    display sanitizer ``_text`` above: a container coerces to "" rather than
    unwrapping — ``["Backups"]`` must never read as a plausible rename label —
    and lone surrogates are kept, so the strict validators downstream
    (``_label_ok``, the anchored ``DISK_RE``, the FS_TYPES lookup) refuse them
    with the same coded error junk text earns; ``errors.error_payload`` scrubs
    the refusal's own message and params before Starlette's UTF-8 encode.
    """
    if raw is None or isinstance(raw, bool):
        return ""
    if isinstance(raw, (list, tuple, dict, set, frozenset)):
        return ""
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw).decode("utf-8", "replace")
    if not isinstance(raw, str):
        try:
            raw = str(raw)
        except Exception:
            # The digit-cap ValueError, or a leftover whose __str__ raises.
            return ""
    return raw


def _opt_bool(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
        return None
    return bool(value)


def _size_bytes(raw) -> int:
    try:
        size = int(raw or 0)
    except (TypeError, ValueError, OverflowError):
        return 0
    try:
        str(size)
    except ValueError:
        # A leftover plist Size already past CPython's int->str digit cap
        # survives ``int()`` unchanged; the 400-digit class only overflowed
        # the GB conversion, this one ValueError'd json.dumps itself on
        # GET /api/storage/manage.
        return 0
    return size


def _size_gb(size: int):
    """``round(10**400 / 2**30)`` OverflowError'd the manage listing.

    ``int(inf)`` is already caught by ``_size_bytes``; a huge *finite* plist
    integer is a valid Python int and used to escape on the GB conversion.
    """
    if not size:
        return None
    try:
        gb = round(size / 2**30, 1)
    except OverflowError:
        return None
    if gb != gb or gb in (float("inf"), float("-inf")):
        return None
    return gb


def _label_ok(value: str) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        # Leftover ``\\ud800`` used to UnicodeEncodeError ``subprocess`` argv
        # on POST /api/storage/manage rename/erase.
        return False
    return not any(ord(c) < 0x20 or ord(c) == 0x7F for c in value)


def _normalize_id(device: str) -> str:
    # _req_text, not an isinstance gate: the route hands the id over as str,
    # but the service is also called in-process, and a finite numeric leftover
    # must keep behaving as its string form.  An over-cap already-int
    # (YAML/plist hex loads uncapped) coerces to "" instead of leaving the
    # error body's ``{device}`` placeholder unfilled after
    # errors._jsonable_param drops the raw int.
    d = _req_text(device).strip().replace("/dev/", "")
    if not DISK_RE.match(d):
        raise api_error("disk.invalid_device", device=d[:40])
    return d


def _is_system_related(info: dict, device_id: str) -> bool:
    """Block ops on boot/system volumes and their parent whole disk."""
    # Mounted at system paths.  Leftover plist ``bytes`` used to stringify as
    # ``b'/'`` and skip the boot-volume guard on POST /api/storage/manage.
    mp = _text(info.get("MountPoint"))
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
    whole = _ident(info.get("ParentWholeDisk"))
    if whole == "disk0":
        # only if this is internal system — still be careful for partitions of disk0
        if info.get("Internal") and info.get("SolidState"):
            # APFS system container
            fs = _text(info.get("FilesystemType") or info.get("FilesystemName")).lower()
            if "apfs" in fs or info.get("APFSContainerReference"):
                # any volume on system APFS container
                if not mp.startswith("/Volumes/"):
                    # not user external mount
                    # If not mounted under /Volumes, treat APFS on disk0 parent as system-ish
                    parent = whole or device_id
                    if parent == "disk0" or device_id.startswith("disk0"):
                        # allow only if explicitly external volume name on /Volumes - handled above
                        if not mp.startswith("/Volumes/"):
                            return True
    # Root device chain.  From the shared mount table rather than this function's own
    # `df -P /`: it is called once per node in the listing walk below, so it was one
    # extra subprocess per volume to re-read a row the table already had.
    for whole in root_devices():
        if device_id == whole or device_id.startswith(whole + "s"):
            return True
    return False


def list_managed_volumes() -> list[dict]:
    """All diskutil volumes with mount/format metadata for management UI."""
    # Four reads open this listing and none consumes another's output: the device
    # tree, the physical whole-disk list, the root device per `df`, and `diskutil
    # info /`.  Taken in turn they were four subprocesses of pure prologue before any
    # per-node work could start, on the branch that dominates /api/storage.
    #
    # Each probe returns the empty value the serial version would have produced
    # rather than raising, which is what `fan_out` requires.
    def probe_tree() -> dict:
        found = _plist(["/usr/sbin/diskutil", "list", "-plist"], timeout=5)
        return found if isinstance(found, dict) else {}

    # Three of the four now come from hub.disk_snapshot, shared with the power
    # listing (that module name is deliberately not written here: an import guard in
    # tests/test_disk_info_cache_invalidation.py greps this file for it, because the
    # reverse import edge would be a cycle):
    # /api/storage runs both modules concurrently, so each of these was reached cold
    # by two callers in the same millisecond.
    def probe_physical() -> set[str]:
        # Real physical whole disks (disk0, external HDDs) vs synthetic APFS
        # containers (disk1/2/3…).
        return set(physical_whole_disks())

    def probe_root_df() -> set[str]:
        return set(root_devices())

    def probe_root_info() -> dict:
        try:
            return dict(root_info())
        except Exception:
            return {}

    # `root_details`, not `root_info`: that name now belongs to the shared read this
    # probe calls, and shadowing it here made the module look like it had two.
    pl, physical_wholes, system_wholes, root_details = fan_out(
        lambda probe: probe(),
        [probe_tree, probe_physical, probe_root_df, probe_root_info],
        max_workers=4,
    )
    if not pl:
        return []

    parent_whole = _ident(root_details.get("ParentWholeDisk"))
    if parent_whole:
        system_wholes.add(parent_whole)
    # Physical store of APFS container
    stores = root_details.get("APFSPhysicalStores") or []
    if isinstance(stores, list):
        for s in stores:
            if not isinstance(s, dict):
                continue
            store = _ident(s.get("APFSPhysicalStore"))
            if not store:
                continue
            m = re.search(r"(disk\d+)", store)
            if m:
                system_wholes.add(m.group(1))
    # boot physical disk always system
    system_wholes.add("disk0")

    raw_disks = pl.get("AllDisksAndPartitions")
    all_disks = [n for n in raw_disks if isinstance(n, dict)] if isinstance(raw_disks, list) else []
    out = []

    def walk(node: dict, whole: str | None = None):
        if not isinstance(node, dict):
            return
        ident = _ident(node.get("DeviceIdentifier"))
        if not ident:
            return
        is_whole = WHOLE_RE.match(ident) is not None
        w = ident if is_whole else (whole or ident)
        # partitions list
        parts = node.get("Partitions") if isinstance(node.get("Partitions"), list) else []
        apfs_vols = node.get("APFSVolumes") if isinstance(node.get("APFSVolumes"), list) else []
        children = [c for c in (parts + apfs_vols) if isinstance(c, dict)]
        if children:
            for ch in children:
                walk(ch, w if is_whole else whole or w)
            # still record whole disk summary
            if is_whole:
                info = _diskutil_info(ident)
                size = _size_bytes(node.get("Size") or info.get("TotalSize"))
                content = _text(node.get("Content") or info.get("Content"))
                # Synthetic APFS containers (not in physical list) are system-side
                synth = bool(physical_wholes) and ident not in physical_wholes
                is_sys = (
                    ident in system_wholes
                    or ident == "disk0"
                    or synth
                    or "Recovery" in content
                    or "APFS_ISC" in content
                )
                mount = _text(info.get("MountPoint"))
                out.append({
                    "id": ident,
                    "device": f"/dev/{ident}",
                    "name": _text(info.get("MediaName") or info.get("IORegistryEntryName")) or ident,
                    "volume_name": _text(info.get("VolumeName")),
                    "whole_disk": ident,
                    "is_whole": True,
                    "size_bytes": size,
                    "size_gb": _size_gb(size),
                    "fs": _text(info.get("FilesystemType")) or content,
                    "content": content,
                    "mount": mount,
                    "mounted": bool(mount),
                    "writable": _opt_bool(info.get("Writable")) if "Writable" in info else None,
                    "internal": bool(info.get("Internal")),
                    "ejectable": bool(info.get("Ejectable")),
                    "removable": bool(info.get("Removable") or info.get("RemovableMedia")),
                    "system": is_sys,
                    "actions": _actions_for(info, ident, is_whole=True, system=is_sys),
                })
            return

        # leaf volume / partition
        info = _diskutil_info(ident)
        size = _size_bytes(node.get("Size") or info.get("TotalSize"))
        mount = _text(info.get("MountPoint") or node.get("MountPoint"))
        content = _text(node.get("Content") or info.get("Content"))
        fs_type = (
            _text(info.get("FilesystemType"))
            or _text(info.get("FilesystemName"))
            or content
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
            _text(info.get("VolumeName"))
            or _text(node.get("VolumeName"))
            or _text(info.get("MediaName"))
            or ident
        )
        item = {
            "id": ident,
            "device": f"/dev/{ident}",
            "name": name,
            "volume_name": _text(info.get("VolumeName") or node.get("VolumeName")),
            "whole_disk": w,
            "is_whole": False,
            "size_bytes": size,
            "size_gb": _size_gb(size),
            "fs": fs_type,
            "content": content,
            "mount": mount,
            "mounted": bool(mount),
            "writable": _opt_bool(info.get("WritableVolume", info.get("Writable"))),
            "internal": bool(info.get("Internal")),
            "ejectable": bool(info.get("Ejectable")),
            "removable": bool(info.get("Removable") or info.get("RemovableMedia")),
            "system": system,
            "actions": _actions_for(info, ident, is_whole=False, system=system),
        }
        out.append(item)

    # Warm every node the walk is about to ask for, in one parallel batch.  The
    # walk itself calls _diskutil_info() one identifier at a time, and each miss
    # is a ~130ms subprocess, so a host with many volumes spent seconds in
    # serial waits before this.  Collect the identifiers from the same tree the
    # walk descends so the two cannot disagree about which nodes are visited.
    def _identifiers(node: dict) -> list[str]:
        if not isinstance(node, dict):
            return []
        ident = _ident(node.get("DeviceIdentifier"))
        if not ident:
            return []
        found = [ident]
        parts = node.get("Partitions") if isinstance(node.get("Partitions"), list) else []
        apfs = node.get("APFSVolumes") if isinstance(node.get("APFSVolumes"), list) else []
        for ch in parts + apfs:
            if isinstance(ch, dict):
                found.extend(_identifiers(ch))
        return found

    _prefetch_disk_info([n for d in all_disks for n in _identifiers(d)])

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

    # _req_text: a leftover non-str action AttributeError'd ``.strip()`` (a
    # 500 for in-process callers) where ``disk.unknown_action`` is the
    # contract.
    action = _req_text(action).strip()
    log: list[str] = []

    def run(args: list[str], timeout: int = 120) -> tuple[int, str, str]:
        rc, out, err = sh(args, timeout=timeout)
        out, err = _text(out), _text(err)
        log.append(f"$ {' '.join(args)}\n{out}\n{err}".strip())
        # Every branch below reaches diskutil through here, and every one of them
        # changes what `diskutil info` would report -- mount point, volume name,
        # filesystem.  Without this the panel could serve the pre-operation view
        # for up to _INFO_TTL seconds, so a user who just unmounted a disk still
        # sees it mounted.  Invalidate unconditionally: a failed command can
        # still have moved state (`unmount` failing after `unmount force`
        # succeeded), and a whole-disk operation changes every child node, so
        # dropping the whole cache is the only correct scope.
        invalidate_disk_info()
        # The whole-machine reads move for the same reasons and in the same cases: a
        # mount or an erase changes the `df` table, and `mountDisk`/`eraseDisk` change
        # what `/` resolves to on a machine booting from the affected disk.  Dropped
        # here rather than only in the router so the service is correct when called
        # directly.
        invalidate_disks()
        # A diskutil that vanished between the eligibility checks and the
        # spawn (an OS update mid-flight, a dying system volume) used to
        # surface as HTTP 200 ``{"ok": false, "message": "not found"}`` —
        # a body that reads like a missing *disk* and misdirects the
        # operator.  The coded 503 fires only after a fresh disk probe
        # confirms the binary is really gone (the raid_svc rule); with
        # diskutil still on disk the raw failure keeps its own message.
        # The probe runs only on this failure path, never on success.
        if rc != 0 and _vanished_spawn(rc, out, err) and not _diskutil_on_disk():
            raise api_error("disk.diskutil_missing")
        return rc, out, err

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
        # _req_text probe: a finite numeric name keeps its string form; an
        # over-cap already-int or a container coerces to "" and a surrogate
        # name fails _label_ok — the coded refusal every unusable name gets.
        new_name = _req_text(name).strip()
        if not new_name or len(new_name) > 64 or not _label_ok(new_name):
            raise api_error("disk.name_required")
        # diskutil rename /Volumes/Old New  OR  diskutil rename diskXsY New
        rc, out, err = run(["/usr/sbin/diskutil", "rename", did, new_name])
        return {"ok": rc == 0, "action": action, "device": did, "message": out or err, "log": log}

    # ---- destructive ----
    if action in ("eraseVolume", "format", "eraseDisk"):
        if not confirm:
            raise api_error("disk.confirm_required")
        vol_name = _text(info.get("VolumeName") or info.get("MediaName") or did).strip()
        if confirm_name is not None:
            # _req_text probe, not an isinstance gate: a finite numeric
            # confirm_name compares as its string form; an over-cap
            # already-int coerces to "" and mismatches like any other junk.
            given = _req_text(confirm_name).strip()
            if given != vol_name and given != did:
                raise api_error("disk.confirm_name_mismatch", name=vol_name, id=did)
        # Same probe for fs: the old isinstance gate passed the raw non-str
        # into the error params, where errors._jsonable_param drops an
        # over-cap int and the message's ``{fs}`` placeholder stayed
        # unfilled.  None/"" keeps the ExFAT default; every other shape
        # coerces and is judged by its string form.
        fs_key = "ExFAT" if fs in (None, "") else _req_text(fs).strip()
        fs_type = FS_TYPES.get(fs_key) or FS_TYPES.get(fs_key.upper())
        if not fs_type:
            raise api_error(
                "disk.unsupported_fs", fs=fs_key[:20],
                choices=", ".join(sorted(set(FS_TYPES))),
            )
        # ``subprocess.run`` ValueError's a NUL in argv.  Rename already
        # rejected control characters; erase used to 500 POST /api/storage/manage.
        # _req_text probe: a numeric label keeps its string form, an over-cap
        # already-int coerces to "" and falls back to the volume's own name.
        new_label = ((_req_text(name) or vol_name or "UNTITLED").strip()[:32] or "UNTITLED")
        if not _label_ok(new_label):
            raise api_error("disk.name_required")

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
        "hint": "Format/erase destroys all data; system disks are locked. Operations use /usr/sbin/diskutil.",
    }
