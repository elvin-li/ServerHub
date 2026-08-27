"""Single source for the three disk reads that answer whole-machine questions.

``storage_svc``, ``disk_power_svc`` and ``disk_manage_svc`` each asked the same
three questions of the same host, and each shelled out for them:

    `df -P -k`                        the mount table      storage_svc, disk_power_svc
    `diskutil list -plist physical`   physical whole disks disk_power_svc, disk_manage_svc
    `diskutil info -plist /`          what `/` sits on     disk_power_svc, disk_manage_svc

plus `df -P /`, which is the mount table again filtered to one row -- and which
``disk_manage_svc`` ran once per node inside its listing walk.

``/api/storage`` fans all three modules out concurrently, so the duplication was
not sequential waste that a cache upstream would have absorbed; it was three
modules reaching the same cold read in the same millisecond.  Two of the
duplicates were also invisible to any measurement grouping spawns by argv, because
``storage_svc`` spelled the command ``df`` and ``disk_power_svc`` ``/bin/df``.

Same shape as :mod:`hub.brew_cache`, :mod:`hub.launchd_cache` and
:mod:`hub.proc_cache`: a short TTL, a single-flight refresh, and an explicit
invalidation that every path changing mount or presence state already reaches
through ``disk_power_svc.invalidate_power_disks()``.

The root-disk set deserves a note, because it is load-bearing for safety rather
than for latency: ``disk_power_svc`` refuses to sleep or eject a disk that carries
``/``, and it decides that from the union of three independent reads.  Only the two
that were duplicated are shared here.  The third -- scraping ``diskutil info /`` in
its text form -- stays where it is, because narrowing that union is how a panel ends
up offering to eject the boot disk.
"""
from __future__ import annotations

import plistlib
import re
import subprocess
from types import MappingProxyType
from typing import Any, Mapping

from hub.util import cached_snapshot, fan_out, run_bytes, sh

#: Short, and for the usual reason: these are dependency reads whose consumers
#: already sit behind their own caches (the power-disk listing, the SMART snapshot).
#: The window that matters is one request's worth of overlapping readers.
_TTL = 5.0

#: A wedged diskutil -- typically an external HDD that has spun down -- used to pin
#: a whole listing at 12-15s per call.  Matches disk_power_svc._DISKUTIL_TIMEOUT.
_DISKUTIL_TIMEOUT = 5

_DISK_RE = re.compile(r"/dev/(disk\d+)")
_WHOLE_RE = re.compile(r"(disk\d+)")


def _isa(value, kinds) -> bool:
    """``isinstance`` that survives a leftover ``__class__``-property bomb.

    ``isinstance`` consults ``value.__class__`` when the exact-type check
    misses, so a leftover token whose ``__class__`` is a *raising property*
    detonated the sequence gate at the head of both scrubs below — and a
    raise out of ``_disk_token`` does not drop one identifier, it collapses
    the whole plist arm of ``root_whole_disks`` (the set the panel refuses
    to spin down or eject), the exact narrowing storage8 sealed for the
    ``__bool__``/``__getitem__`` bomb class.  A real subclass still matches
    through the C-level type check (the storage_svc rule).
    """
    try:
        return isinstance(value, kinds)
    except Exception:
        return False


def _rc_int(rc) -> int:
    """Exact exit status for the ``==`` probes; a bomb reads as failure.

    This module does not own ``sh`` / ``run_bytes`` (tests and tooling patch
    them), and an rc-subclass whose ``__eq__`` raises used to detonate the
    bare ``rc == 0`` probes — one bombed rc raised out of ``df_lines`` into
    all three consumer modules at once and emptied the volume table where a
    failed read is the honest degrade (the system/health9 rule).
    """
    try:
        if isinstance(rc, bool):
            return int(rc)
        if isinstance(rc, int):
            return int.__index__(rc)
        return int(rc)
    except Exception:
        return -255


def _as_text(value) -> str:
    """diskutil / df leftovers arrive as bytes / int / inf, not str.

    A leftover ``\\ud800`` in a FUSE volume name used to 500 GET /api/storage
    under Starlette's UTF-8 encode of ``df`` mount fields.
    """
    if _isa(value, (list, tuple)):
        # Guarded unwrap, matching disk_manage_svc._text / disk_power_svc._text:
        # a sequence *subclass* whose ``__bool__`` / ``__getitem__`` raises (the
        # storage4/pool4 iteration-bomb class) used to raise straight out of this
        # scrub — the one surface in the disk-read family whose list-unwrap was
        # still bare after storage7 sealed its encode tail.
        try:
            value = value[0] if value else ""
        except Exception:
            return ""
    if _isa(value, (bytes, bytearray)):
        try:
            value = bytes(value).decode("utf-8", "replace")
        except Exception:
            # A lying ``__class__`` property claiming bytes TypeErrors the
            # base copy itself; the token degrades like any unreadable one.
            return ""
    elif _isa(value, float) and (value != value or value in (float("inf"), float("-inf"))):
        return ""
    elif value is None or value is False or value is True \
            or _isa(value, (dict, set, frozenset)):
        # Identity tests, not ``value in (None, False, True, "")``: the old
        # containment probe reflected into a leftover's own ``__eq__`` and
        # raised out of the scrub.  An empty string needs no special case —
        # the unbound encode below answers "" for it anyway.
        return ""
    elif type(value) is not str:
        # Exact-type gate, not ``not _isa(value, str)``: a *lying*
        # ``__class__`` claiming str passed the isinstance probe untouched
        # and the unbound ``str.encode`` below TypeError'd on the foreign
        # layout — a raise out of the shared df/diskutil scrub itself.  A
        # real str subclass base-copies through str() and keeps its text.
        try:
            value = str(value)
        except RecursionError:
            try:
                return type(value).__name__
            except Exception:
                return ""
        except Exception:
            return ""
    # Unbound base encode: a str subclass whose ``__str__`` returns *self*
    # keeps its bound ``encode`` bomb through the coercion above and used to
    # raise out of the shared df/diskutil reads.
    return str.encode(value, "utf-8", "replace").decode("utf-8")


def _disk_token(value) -> str:
    """Plist disk identifier as text.

    ``WholeDisks`` / ``ParentWholeDisk`` / ``APFSPhysicalStore`` are strings in
    a healthy diskutil plist.  Leftover ``bytes`` used to stringify as
    ``b'disk0'`` (so the boot disk dropped out of the safety union);
    array-shaped leftovers used to ``re.match`` / ``set.add`` 500.

    The token must scrub, never raise: it feeds ``root_whole_disks`` — the set
    the panel refuses to spin down or eject — so a raise here does not merely
    drop one identifier, it collapses the whole plist arm of that safety union
    (``from_plist`` returns an empty set), silently narrowing boot-disk
    protection.  A sequence *subclass* whose ``__bool__`` / ``__getitem__``
    raises now degrades to "" like every other unreadable token, so the
    surviving ``APFSPhysicalStores`` disks still contribute.
    """
    if _isa(value, (list, tuple)):
        try:
            value = value[0] if value else ""
        except Exception:
            return ""
    if _isa(value, (bytes, bytearray)):
        try:
            value = bytes(value).decode("utf-8", "replace")
        except Exception:
            return ""
    if not _isa(value, str):
        return ""
    # Unbound base encode: same self-``__str__`` encode-bomb class as
    # ``_as_text`` above — the token must scrub, never raise.
    return str.encode(value, "utf-8", "replace").decode("utf-8")


def _whole_id(value) -> str:
    match = _WHOLE_RE.match(_disk_token(value))
    return match.group(1) if match else ""


#: Why every read here is wrapped: ``cached_snapshot`` keeps any value that is not
#: ``None``, and an empty tuple or empty mapping is not ``None``.  So a `df` that
#: timed out would be *remembered as truth* for the whole TTL -- and remembered for
#: three modules at once, where each used to fail independently and retry on its own
#: next call.
#:
#: That is not a latency question.  ``root_devices()`` is one of three sources for the
#: set of disks the panel refuses to spin down or eject, so caching a failed read as
#: "no disk carries /" narrows a safety union for five seconds.  A failed read is
#: returned to the caller -- degrading exactly as the code it replaced did -- but it
#: is dropped from the cache so the next reader tries again.
def _forget_if_empty(cached, value):
    if not value:
        cached.invalidate()
    return value


@cached_snapshot(_TTL)
def _df_table() -> tuple[str, ...]:
    rc, out, _ = sh(["/bin/df", "-P", "-k"], timeout=8)
    return tuple(_as_text(out).splitlines()) if _rc_int(rc) == 0 else ()


def df_lines(force: bool = False) -> tuple[str, ...]:
    """`df -P -k` output lines including the header.

    A tuple so the cached table can be handed to concurrent callers without copying
    it per caller, and so none of them can mutate the shared copy.

    `df` prints a header on success, so an empty table means the read failed.
    """
    return _forget_if_empty(_df_table, _df_table(force=force))


def root_devices() -> frozenset[str]:
    """Whole-disk ids carrying ``/``, read out of the shared mount table.

    This replaces a separate ``df -P /`` in two modules.  ``df -P /`` prints the
    filesystem holding ``/``; the full table contains that same row, so filtering it
    in memory asks nothing new of the host -- and ``disk_manage_svc`` was running
    that extra ``df`` once per node it examined.
    """
    found: set[str] = set()
    for line in df_lines()[1:]:
        if type(line) is not str:
            # Exact-type gate (the storage_svc.list_volumes rule): a
            # *lying* ``__class__`` claiming str passes any isinstance
            # probe and then AttributeErrors ``line.split()`` — one junk
            # table line used to collapse this whole arm of the boot-disk
            # safety union while the healthy ``/`` row sat readable.
            line = _as_text(line)
            if not line:
                continue
        parts = line.split()
        if len(parts) < 6:
            continue
        if " ".join(parts[5:]) != "/":
            continue
        match = _DISK_RE.search(parts[0])
        if match:
            found.add(match.group(1))
    return frozenset(found)


@cached_snapshot(_TTL)
def _physical_whole_disks() -> tuple[str, ...]:
    try:
        rc, stdout, _ = run_bytes(
            ["/usr/sbin/diskutil", "list", "-plist", "physical"],
            timeout=_DISKUTIL_TIMEOUT,
            runner=subprocess.run,
        )
    except Exception:
        rc, stdout = -1, b""
    if _rc_int(rc) == 0:
        # Truthiness and parse inside the guard: a poisoned runner's stdout
        # ``__bool__`` bomb sat outside the old try and raised out of the
        # shared read into all three consumer modules at once.
        try:
            parsed = plistlib.loads(stdout) if stdout else None
            if _isa(parsed, dict):
                wholes = dict.get(parsed, "WholeDisks")
                if not _isa(wholes, list):
                    wholes = []
                return tuple(t for x in wholes if (t := _disk_token(x)))
        except Exception:
            pass
    rc, out, _ = sh(["/usr/sbin/diskutil", "list", "physical"], timeout=_DISKUTIL_TIMEOUT)
    if _rc_int(rc) != 0:
        return ()
    ids: list[str] = []
    for match in re.finditer(r"/dev/(disk\d+)\s", _as_text(out)):
        if match.group(1) not in ids:
            ids.append(match.group(1))
    return tuple(ids)


@cached_snapshot(_TTL)
def _root_info() -> Mapping[str, Any]:
    try:
        rc, stdout, _ = run_bytes(
            ["/usr/sbin/diskutil", "info", "-plist", "/"],
            timeout=_DISKUTIL_TIMEOUT,
            runner=subprocess.run,
        )
        # _rc_int (the _physical_whole_disks rule this sibling missed): an
        # honest rc-bomb zero from a poisoned runner used to raise into the
        # except arm and read as "no root info" — silently narrowing the
        # plist arm of the boot-disk safety union.
        if _rc_int(rc) == 0 and stdout:
            parsed = plistlib.loads(stdout)
            if _isa(parsed, dict):
                return MappingProxyType(parsed)
    except Exception:
        pass
    return MappingProxyType({})


def physical_whole_disks(force: bool = False) -> tuple[str, ...]:
    """Real physical whole disks, as opposed to synthesised APFS containers.

    Keeps the plaintext fallback: ``diskutil list -plist physical`` is the reliable
    form, but when it fails the text listing still names the disks, and returning
    nothing here means the storage page shows no disks at all.
    """
    return _forget_if_empty(
        _physical_whole_disks, _physical_whole_disks(force=force)
    )


def root_info(force: bool = False) -> Mapping[str, Any]:
    """`diskutil info -plist /`, or an empty mapping.

    Read-only view: this is the shared copy, and one caller annotating it would
    become every later caller's answer.
    """
    return _forget_if_empty(_root_info, _root_info(force=force))


@cached_snapshot(_TTL)
def root_whole_disks() -> frozenset[str]:
    """Every whole-disk id that ``/`` resolves to, from three reads at once.

    This is the set the panel refuses to spin down or eject, and it is a *union* --
    three reads that answer the same question in different ways, none of which reads
    another's output:

    * ``diskutil info /`` in its text form, scraped for any ``/dev/diskN``.
    * the mount table's ``/`` row, which names the mounted device directly.
    * ``diskutil info -plist /``, the only one that reaches through a synthesised
      APFS container to the physical store underneath -- on this machine ``/`` is on
      disk3 and the disk an operator could actually spin down is disk0, so dropping
      this read would remove the boot disk's protection entirely.

    Being a union is exactly what makes the three safe to overlap: the result does
    not depend on the order they answer in, and each contributes independently.  They
    used to run one after another, which showed up as three of the seven waves on
    /api/storage/disks and three of the eight on /api/tools/hardware.

    Each probe returns the empty set the serial version would have produced rather
    than raising, which is what ``fan_out`` requires -- and here it is also what keeps
    one failed read from emptying the whole union.
    """
    def from_text() -> set[str]:
        try:
            rc, out, _ = sh(["/usr/sbin/diskutil", "info", "/"], timeout=_DISKUTIL_TIMEOUT)
            return set(_DISK_RE.findall(_as_text(out))) if rc == 0 else set()
        except Exception:
            return set()

    def from_mount_table() -> set[str]:
        try:
            return set(root_devices())
        except Exception:
            return set()

    def from_plist() -> set[str]:
        found: set[str] = set()
        try:
            info = root_info()
            parent = _whole_id(info.get("ParentWholeDisk"))
            if parent:
                found.add(parent)
            stores = info.get("APFSPhysicalStores") or []
            if not isinstance(stores, list):
                stores = []
            for store in stores:
                if isinstance(store, dict):
                    device = store.get("APFSPhysicalStore") or store.get("DeviceIdentifier")
                else:
                    device = store
                whole = _whole_id(device)
                if whole:
                    found.add(whole)
        except Exception:
            return set()
        return found

    found: set[str] = set()
    for part in fan_out(
        lambda probe: probe(), [from_text, from_mount_table, from_plist], max_workers=3
    ):
        found |= part
    return frozenset(found)


def invalidate_disks() -> None:
    """Forget all three reads after something changed mount or presence state.

    Reached from ``disk_power_svc.invalidate_power_disks()`` and from
    ``disk_manage_svc.disk_action``, so a mount, unmount, eject or erase is visible
    to the next read rather than a TTL later.  Sleeping or ejecting a disk changes
    whether it is present at all, which is exactly the state these describe.
    """
    _df_table.invalidate()             # type: ignore[attr-defined]
    _physical_whole_disks.invalidate()  # type: ignore[attr-defined]
    _root_info.invalidate()            # type: ignore[attr-defined]
    root_whole_disks.invalidate()      # type: ignore[attr-defined]
