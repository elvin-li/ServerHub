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


def _rc_int(rc) -> int:
    """Exact exit status for the ``!=`` probe; junk reads as failure.

    This module does not own ``sh`` (tests and tooling patch it — the
    health9 / shares_svc ``_rc_int`` rule), and ``_plist`` compared the
    *rc* slot raw: an rc-subclass whose ``__ne__`` raises detonated
    ``rc != 0`` — a raw 500 on every POST /api/raid/* mutation through
    ``list_sets`` / ``disk_topology`` / ``candidate_devices`` (the read
    page catches it in ``_listing``, the mutation resolvers do not).
    ``int.__index__`` reads the real value underneath a subclass override;
    a *lying* ``__class__`` impostor TypeErrors on the unbound read and
    drops with the junk.  ``-255`` is no honest exit status, so a bomb
    keeps the empty-plist branch.
    """
    try:
        if isinstance(rc, bool):
            return int(rc)
        value = int.__index__(rc) if isinstance(rc, int) else int(rc)
        str(value)
        return value
    except Exception:
        return -255


def _sh_triple(argv, *, timeout: int) -> tuple:
    """The ``sh`` seam laundered to an exact ``(rc, out, err)`` shape.

    nas11's ``_rc_int`` laundered the rc *value*, but the answer's *shape*
    stayed bare: ``rc, out, _ = sh(...)`` iterates whatever the seam handed
    back, and this module does not own ``sh`` (tests and tooling patch it).
    A leftover sequence subclass whose ``__iter__`` raises, a torn
    two-field answer, or a patched ``sh`` that raises outright each used to
    blow the unpack inside ``_plist`` — the read page catches it in
    ``_listing``, but ``list_sets`` / ``disk_topology`` /
    ``candidate_devices`` on the mutation path (``_resolve_set`` /
    ``_check_devices``) do not, a raw 500 on every POST /api/raid/* — one
    step ahead of the ``_rc_int`` guard on the field itself (the
    ups/vms/storage ``_sh3`` rule).  An unreadable answer reads as spawn
    failure: ``-255`` is nonzero and never ``sh``'s ``-1`` sentinel.
    """
    try:
        rc, out, err = sh(argv, timeout=timeout)
        return rc, out, err
    except Exception:
        return -255, "", ""


def _plist(argv: list[str], *, timeout: int = 15) -> dict:
    rc, out, _ = _sh_triple(argv, timeout=timeout)
    if _rc_int(rc) != 0:
        return {}
    if _isa(out, (bytes, bytearray)):
        # Unbound base decode in a try (the modules9 / snapshots rule): the
        # old bound ``bytes(out)`` copy consulted a subclass ``__bytes__``,
        # and a *lying* ``__class__`` claiming bytes rejects either call
        # with a TypeError — outside any try, a raw 500 on every
        # POST /api/raid/* through the mutation walks (the read page hides
        # behind ``_listing``).  Output that cannot decode is no plist.
        base = bytes if _isa(out, bytes) else bytearray
        try:
            out = base.decode(out, "utf-8", "replace")
        except Exception:
            return {}
    elif not _isa(out, str):
        try:
            out = str(out)
        except RecursionError:
            return {}
        except Exception:
            return {}
    # Exact-str copy before any probe: the old bare ``not out`` asked a
    # leftover str-subclass ``__bool__`` bomb for truth, and the bound
    # ``out.find`` ran a subclass override — each a raw raise on the same
    # mutation paths.  The unbound base pair answers an exact str (and
    # scrubs lone surrogates); a str-liar impostor TypeErrors here and
    # reads as the empty document.
    try:
        out = bytes.decode(str.encode(out, "utf-8", "replace"), "utf-8")
    except Exception:
        return {}
    if not out:
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


def _isa(value, kinds) -> bool:
    """``isinstance`` that survives a leftover ``__class__``-property bomb.

    ``isinstance`` consults ``value.__class__`` when the exact-type check
    misses, so a leftover whose ``__class__`` is a *raising property*
    detonated the gate itself: ``_admin_result``'s dict gate — and
    ``_jsonable``'s rank gates under it — 500'd every POST /api/raid/*
    mutation one line ahead of the laundering built to absorb junk shapes,
    and ``_listing``'s list gate blew GET /api/raid outside its own try.
    A real subclass still matches through the C-level type check; only a
    value that cannot answer what it is takes the non-matching branch.
    """
    try:
        return isinstance(value, kinds)
    except Exception:
        return False


def _ident(value) -> str:
    """Plist device / mount field as text.

    ``DeviceIdentifier`` / ``APFSPhysicalStore`` / ``SnapshotMountPoint`` are
    strings in a healthy diskutil plist.  Leftover ``bytes`` used to stringify
    as ``b'disk0s2'`` and drop the APFS physical store from the boot-disk
    union; array-shaped leftovers used to skip the store the same way.
    """
    if _isa(value, (list, tuple)):
        try:
            # A leftover subclass ``__bool__``/``__getitem__`` bomb must
            # cost this field, never the page.
            value = value[0] if value else ""
        except Exception:
            return ""
    if _isa(value, (bytes, bytearray)):
        # Unbound base decode in a try (the modules9 rule): the old bound
        # ``bytes(value)`` copy consulted a subclass ``__bytes__``, and a
        # *lying* ``__class__`` claiming bytes rejects either call with a
        # TypeError outside any try — a raw 500 on the raid mutations
        # through _jsonable/_req_text.  An impostor that cannot decode
        # reads as an empty field like any other junk ident.
        base = bytes if _isa(value, bytes) else bytearray
        try:
            value = base.decode(value, "utf-8", "replace")
        except Exception:
            return ""
    if not _isa(value, str):
        return ""
    # Leftover ``\\ud800`` in a plist Name used to 500 GET /api/raid.
    # Unbound ``str.encode`` in a try: a str-liar impostor passes the gate
    # above with no ``.encode`` at all, and a subclass whose ``__str__``
    # answers *self* carries a bound encode bomb — either raise used to
    # escape this line raw.
    try:
        return bytes.decode(str.encode(value, "utf-8", "replace"), "utf-8")
    except Exception:
        return ""


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's ``allow_nan=False`` encoder cannot 500.

    Plist names were already scrubbed; leftover ``\\ud800`` / ``Infinity`` in
    a ``run_admin`` message still 500'd POST /api/raid.
    """
    if depth > 16:
        return None
    # _isa at every rank (the nas_common rule): a ``__class__``-property
    # bomb nested in a run_admin payload used to detonate the first gate it
    # failed and 500 every POST /api/raid/* mutation; it now falls through
    # to the final text probe like any other unrecognized leftover.
    if value is None:
        return value
    if _isa(value, bool):
        # ``bool`` is final, so a value that answers the bool gate while
        # its real type is not bool is a *lying* ``__class__`` impostor
        # (the modules9 rule).  The old arm returned it raw and Starlette's
        # ``allow_nan=False`` encoder 500'd the mutation; only a real bool
        # renders, the impostor drops like a lying int.
        if type(value) is bool:
            return value
        return None
    if _isa(value, int):
        try:
            # Base coercion first (the snapshots/smart rule): an int
            # subclass ``__str__`` bomb raised a non-ValueError past the
            # digit-cap probe below.
            if type(value) is not int:
                value = int.__index__(value)
            str(value)
        except Exception:
            # Past CPython's int->str digit cap the encoder cannot render
            # the number at all — same drop as its inf float sibling.
            return None
        return value
    if _isa(value, float):
        if type(value) is not float:
            try:
                # Base coercion to an exact float: a subclass ``__eq__``
                # bomb used to blow the NaN/inf probes below.
                value = float.__float__(value)
            except Exception:
                return None
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if _isa(value, str):
        return _ident(value)
    if _isa(value, (bytes, bytearray)):
        # Unbound base decode in a try (the modules9 rule): a bytes-liar
        # impostor rejects both the old ``bytes(value)`` copy and the
        # descriptor — it drops instead of 500ing the mutation.
        base = bytes if _isa(value, bytes) else bytearray
        try:
            return base.decode(value, "utf-8", "replace")
        except Exception:
            return None
    if _isa(value, dict):
        # Unbound base view (the nas_common rule): the old bound
        # ``value.items()`` guarded its own raise but unpacked *outside*
        # the try, so a dict subclass whose ``items()`` answers non-pair
        # rows blew ``for k, v in items`` raw — a 500 on POST /api/raid/*
        # where every sibling module already reads the C-level storage.
        # ``dict.items`` in a try: a *lying* ``__class__`` claiming dict
        # makes the descriptor reject the operand — the impostor drops
        # like a lying int (the modules9 rule).
        try:
            items = dict.items(value)
        except Exception:
            return None
        out = {}
        for k, v in items:
            try:
                # Per-pair guard: a ``__class__``-bomb key drops alone;
                # its sibling keys survive.
                if not _isa(k, (str, bytes, bytearray)):
                    k = str(k)
                out[_ident(k)] = _jsonable(v, depth + 1)
            except Exception:
                continue
        return out
    if _isa(value, (list, tuple, set, frozenset)):
        try:
            return [_jsonable(v, depth + 1) for v in value]
        except Exception:
            # Same class as the mapping above, at sequence rank: only this
            # field drops, never the payload or the route.
            return None
    try:
        iso = getattr(value, "isoformat", None)
    except Exception:
        # getattr's default only swallows AttributeError; a leftover whose
        # ``isoformat`` is a *raising property* (or a ``__getattr__`` bomb)
        # still raised out of the probe itself and 500'd POST /api/raid/*
        # — the guard nas_common._jsonable already carries.
        iso = None
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
    if raw is None or _isa(raw, bool):
        return ""
    if _isa(raw, (bytes, bytearray)):
        # Unbound base decode in a try (the modules9 rule): a bytes-liar
        # argument rejects both the old ``bytes(raw)`` copy and the
        # descriptor with a raise outside any try — a raw 500 on the raid
        # mutations where every junk argument earns its coded refusal.  An
        # impostor that cannot decode falls through to the str() probe.
        base = bytes if _isa(raw, bytes) else bytearray
        try:
            return base.decode(raw, "utf-8", "replace")
        except Exception:
            pass
    if type(raw) is not str:
        try:
            raw = str(raw)
        except Exception:
            # The digit-cap ValueError, or a leftover whose __str__ raises.
            return ""
    # Unbound ``str.encode`` in a try: a subclass whose ``__str__`` answers
    # *self* keeps its bound encode bomb past the str() above, and the
    # descriptor rejects nothing real — junk coerces to "" for the coded
    # refusal path instead of raising.
    try:
        return bytes.decode(str.encode(raw, "utf-8", "replace"), "utf-8")
    except Exception:
        return ""


def _plain_map(value) -> dict | None:
    """*value* as a plain dict, or None for junk (the _plain_result rule).

    The plist walks below gate rows with ``_isa(row, dict)`` and then read
    them with bound ``.get`` — but ``isinstance`` honours a *lying*
    ``__class__``, so an impostor claiming dict passed the gate with no
    ``.get`` at all, and the AttributeError raised raw out of ``list_sets``
    / ``disk_topology`` / ``candidate_devices`` on the mutation path
    (``_resolve_set`` / ``_check_devices`` walk them outside ``_listing``'s
    guard) — a raw 500 on every POST /api/raid/* where every other junk row
    already drops.  ``dict()`` copies through the C-level storage, so a
    genuine subclass keeps its salvageable rows and no override can fire.
    """
    if type(value) is dict:
        return value
    if not _isa(value, dict):
        return None
    try:
        return dict(value)
    except Exception:
        return None


def _row_list(value) -> list:
    """A plist row table materialized under its own guard.

    The unbound ``__iter__`` in a try (the modules9 rule): a *lying*
    ``__class__`` claiming list passed the old ``_isa(value, list)`` gates
    and the loop header's TypeError raised raw out of the same mutation
    walks ``_plain_map`` covers.  A genuine list passes through untouched.
    """
    if type(value) is list:
        return value
    if not _isa(value, list):
        return []
    try:
        return list(list.__iter__(value))
    except Exception:
        return []


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
    # _isa: a ``__class__``-property bomb result detonated the bare gate
    # itself — a raw 500 on every raid mutation one line ahead of the
    # laundering built to absorb junk shapes.
    cleaned = _jsonable(result) if _isa(result, dict) else {}
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
    if _isa(raw, bool) or raw is None:
        return None, None
    try:
        # One guard around the probes and the coercion: a float-subclass
        # ``__eq__``/``__ne__`` bomb Size used to detonate the NaN/inf
        # probes themselves (not the numeric trio the old except named).
        if _isa(raw, float) and (raw != raw or raw in (float("inf"), float("-inf"))):
            return None, None
        n = int(raw)
    except Exception:
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
    try:
        # One guard around the gate and the coercion: an ``__eq__``-bomb
        # rebuild percent used to detonate the ``in (None, "")`` membership
        # probe itself (not the numeric trio the old except named).
        if _isa(raw, bool) or raw in (None, ""):
            return None
        value = float(raw)
    except Exception:
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
    # _plain_map / _row_list at every rank: this module does not own the
    # plist provider (tests and tooling patch it), and a lying-``__class__``
    # impostor at any rank — the document, the disk table, a disk row, a
    # partition/store/volume row — passed the old ``_isa`` gates and blew
    # the bound read behind them, a raw 500 on every POST /api/raid/*
    # through _check_devices' fresh enumeration.
    data = _plain_map(_plist([DISKUTIL, "list", "-plist"], timeout=12)) or {}
    topology: dict[str, dict] = {}

    def slot(whole: str) -> dict:
        return topology.setdefault(whole, {"volumes": [], "system": False, "containers": []})

    entries = [
        plain
        for plain in (_plain_map(d) for d in _row_list(data.get("AllDisksAndPartitions")))
        if plain is not None
    ]

    # Pass 1: plain partition tables — a mount here belongs to this disk directly.
    for disk in entries:
        whole = _ident(disk.get("DeviceIdentifier"))
        if not whole:
            continue
        record = slot(whole)
        for part in _row_list(disk.get("Partitions")):
            part = _plain_map(part)
            if part is None:
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
        stores = _row_list(disk.get("APFSPhysicalStores"))
        volumes = _row_list(disk.get("APFSVolumes"))
        if not stores:
            continue
        backing: set[str] = set()
        for store in stores:
            plain_store = _plain_map(store)
            if plain_store is not None:
                raw = plain_store.get("DeviceIdentifier") or plain_store.get("APFSPhysicalStore")
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
                vol = _plain_map(vol)
                if vol is None:
                    continue
                mounts = [_ident(vol.get("MountPoint"))]
                # A sealed system volume is mounted as a snapshot, so its own
                # MountPoint is empty and `/` only appears under MountedSnapshots.
                for snap in _row_list(vol.get("MountedSnapshots")):
                    snap = _plain_map(snap)
                    if snap is not None:
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
    # _row_list + _plain_map (the disk_topology rule): a lying-``__class__``
    # member table or row passed the old gates and blew the walk or the
    # bound ``.get`` behind them — raw on the mutation path via _resolve_set.
    for entry in _row_list(raw):
        entry = _plain_map(entry)
        if entry is None:
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
    # _plain_map / _row_list (the disk_topology rule): a lying-``__class__``
    # impostor as the plist document, the set table or a set row passed the
    # old ``_isa`` gates and blew the bound reads behind them — a raw 500 on
    # POST /api/raid/* through _resolve_set, outside the _listing guard.
    data = _plain_map(_plist([DISKUTIL, "appleRAID", "list", "-plist"], timeout=15)) or {}
    sets = []
    for entry in _row_list(data.get("AppleRAIDSets")):
        # _plain_map: a ``__class__``-bomb (or dict-liar) set row used to
        # detonate this gate — or the ``.get`` reads below it — on the
        # mutation path and 500 POST /api/raid/* raw.
        entry = _plain_map(entry)
        if entry is None:
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
    # Same _plain_map / _row_list laundering as disk_topology: this listing
    # also feeds the mutation path (_check_devices re-verifies members here),
    # where a lying-``__class__`` impostor used to raise raw.
    data = _plain_map(_plist([DISKUTIL, "list", "-plist", "physical"], timeout=12)) or {}

    disks = [
        (_ident(plain.get("DeviceIdentifier")), plain)
        for plain in (_plain_map(d) for d in _row_list(data.get("AllDisksAndPartitions")))
        if plain is not None
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
        # _plain_map: a dict-liar ``diskutil info`` answer from a patched
        # provider passed the shape check inside _plist's replacement and
        # blew the bound ``.get`` reads below.
        info = _plain_map(info) or {}
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
    # _isa: a ``__class__``-bomb listing detonated this gate *outside* the
    # trys on either side of it and 500'd GET /api/raid.
    if not _isa(rows, list):
        return []
    try:
        return [r for r in list.__iter__(rows) if _isa(r, dict)]
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
    # The unbound ``__iter__`` in a try (the modules9 rule nfs_svc's
    # save_exports already carries): a *lying* ``__class__`` claiming
    # list/tuple passed the ``_isa`` gate with no real sequence storage,
    # and the descriptor's TypeError raised raw past the router's
    # RaidError catch — a raw 500 where an empty table earns the coded
    # ``raid.too_few_members`` refusal.
    try:
        if _isa(devices, list):
            rows = list.__iter__(devices)
        elif _isa(devices, tuple):
            rows = tuple.__iter__(devices)
        else:
            rows = iter(())
    except Exception:
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
    # _isa + guarded reads: a ``__class__``-bomb result — or a subclass
    # whose ``.get``/copy raises — must reach _admin_result's laundering,
    # never 500 POST /api/raid/sets at this enrichment step.
    if _isa(result, dict):
        try:
            enriched = dict(result)
            if enriched.get("ok"):
                enriched.update(level=level, name=name, members=members)
                result = enriched
        except Exception:
            pass
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
