"""APFS local snapshots + Time Machine — macOS-native point-in-time recovery.

Unraid grows this capability from btrfs/ZFS and OMV from rsync snapshots.  macOS
ships it natively: every APFS volume can carry local snapshots, and Time Machine
drives them on a schedule towards an external or network destination.  This
module surfaces both as first-class panel features so a rollback target exists
before a bad container update or a mistaken bulk delete, not after.

Read paths are unprivileged on purpose so the page renders for any signed-in
operator.  Mutations that macOS reserves for root (deleting snapshots, toggling
Time Machine, changing its destination) go through :mod:`hub.macos_admin`, which
asks macOS to present its own authorization sheet — ServerHub never sees the
administrator password.
"""
from __future__ import annotations

import plistlib
import re
from pathlib import Path

from hub.macos_admin import run_admin, run_admin_sequence
from hub.util import cached_snapshot, fan_out, sh, strftime_now

TMUTIL = "/usr/bin/tmutil"
DISKUTIL = "/usr/sbin/diskutil"

#: ``com.apple.TimeMachine.2026-08-03-160000.local`` → ``2026-08-03-160000``.
#: Also matches the bare ``2026-08-03-160000`` that ``tmutil`` prints on some
#: releases, which is the token ``deletelocalsnapshots`` expects back.
_SNAP_DATE = re.compile(r"(\d{4}-\d{2}-\d{2}-\d{6})")

#: Snapshot names macOS creates for its own purposes.  They are surfaced but
#: flagged, because deleting an in-progress OS update snapshot is a bad idea and
#: the UI should say so rather than offering an undifferentiated delete button.
_SYSTEM_SNAPSHOT_PREFIXES = ("com.apple.os.update-", "com.apple.installer")

_CACHE_TTL = 20.0

#: Real control flow must keep propagating even through the bomb guards
#: (the modules12/logs12/json13 convention): swallowing a Ctrl-C or an
#: interpreter shutdown to save one snapshot row would turn the sanitizer
#: into a hang.  Everything else BaseException-shaped that a leftover
#: raises out of its own hooks is a bomb like any other — the nas12
#: guards all stopped at ``except Exception``, so one such leftover
#: sailed past every catch in the module at once.
_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)


def _isa(value, kinds) -> bool:
    """``isinstance`` that survives a leftover ``__class__``-property bomb.

    ``isinstance`` consults ``value.__class__`` when the exact-type check
    misses, so a leftover whose ``__class__`` is a *raising property*
    detonated the gate itself: ``_admin_result``'s dict gate 500'd
    POST /api/snapshots/* and /api/timemachine/action ahead of the
    laundering built to absorb junk shapes, ``_jsonable``'s rank gates blew
    the same routes on a bomb nested in a run_admin payload, and
    ``list_snapshots``' entry gate 500'd GET /api/snapshots out of a
    poisoned plist row.  A real subclass still matches through the C-level
    type check; only a value that cannot answer what it is takes the
    non-matching branch.

    ``except BaseException``: the nas9 guard stopped at ``Exception``, so a
    leftover whose ``__class__`` property raises a *BaseException* subclass
    (the watchdog/timeout shape the modules12/logs12/json13 sweeps sealed
    on their own surfaces) sailed past this catch — and past every sibling
    guard in this module, because each one stopped at ``Exception`` too —
    a raw 500 on GET /api/snapshots and the mutation routes.  Only genuine
    control flow keeps propagating.
    """
    try:
        return isinstance(value, kinds)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _as_text(value) -> str:
    """``sh`` leftovers arrive as int/None/bytes; leftover ``\\ud800`` used to 500 GET /api/snapshots."""
    if _isa(value, (bytes, bytearray)):
        # Unbound base decode (the modules5 / nas_common rule): the old
        # ``bytes(value)`` copy consulted a subclass ``__bytes__``, so a
        # leftover bytes-subclass bomb in sh() output raised out of _plist
        # and 500'd GET /api/snapshots.  The base method reads the real
        # buffer and no override can fire.  In a try (the modules9 rule): a
        # *lying* ``__class__`` claiming bytes passes the gate but is no
        # bytes underneath, and the descriptor's TypeError used to 500 the
        # same routes — it falls through to the str() probe so a legible
        # impostor still renders.
        # Both bases are tried, real layout first-come (the modules12 /
        # logs12 ``_decode_bytes`` rule): the old arm picked the base off
        # the *claimed* ``__class__``, so a genuine ``bytearray`` whose
        # ``__class__`` lied ``bytes`` was handed to ``bytes.decode``,
        # rejected by the descriptor, and its perfectly decodable content
        # fell to the str() probe — which rendered the ``bytearray(b'…')``
        # repr into the page instead of the text.
        for base in (bytes, bytearray):
            try:
                value = base.decode(value, "utf-8", "replace")
                break
            except _CONTROL_FLOW:
                raise
            except BaseException:
                continue
    if value is None:
        return ""
    if type(value) is not str:
        try:
            value = str(value)
        except RecursionError:
            try:
                return type(value).__name__
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return ""
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return ""
    # Unbound base encode (the nas_common._utf8_text / modules6 rule):
    # ``str()`` of a subclass whose ``__str__`` answers *self* skips
    # CPython's exact-str copy, so the old bound ``value.encode(...)`` ran
    # the subclass override — a leftover encode bomb in sh() output raised
    # out of _plist and 500'd GET /api/snapshots, out of create_snapshot's
    # message join and 500'd POST /api/snapshots/create, and out of
    # _jsonable's nested key/value coercion and 500'd
    # POST /api/timemachine/action.  The base pair answers an exact str.
    return bytes.decode(str.encode(value, "utf-8", "replace"), "utf-8")


def _truthy(value) -> bool:
    """``bool(value)`` that survives a leftover ``__bool__`` bomb (fails False)."""
    try:
        return bool(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _rc_int(rc) -> int:
    """Exact exit status for the ``==`` / ``!=`` probes; junk reads as failure.

    This module does not own ``sh`` (tests and tooling patch it — the
    health9 / shares_svc ``_rc_int`` rule), and both ``_plist`` and
    ``_tm_latest_backup`` compared the *rc* slot raw.  An rc-subclass whose
    ``__ne__`` raises detonated ``_plist``'s ``rc != 0`` — and ``__eq__``
    detonated ``_tm_latest_backup``'s ``rc == 0`` — a raw 500 on
    GET /api/snapshots: ``list_snapshots`` calls ``_plist`` outside any try
    under ``overview``'s fan-out, and ``_tm_latest_backup`` runs directly in
    ``time_machine_overview``'s fan-out, which re-raises a probe's error.
    ``int.__index__`` reads the real value underneath a subclass override;
    a *lying* ``__class__`` impostor TypeErrors on the unbound read and
    drops with the junk.  ``-255`` is no honest exit status, so a bomb keeps
    the failure branch.
    """
    try:
        if isinstance(rc, bool):
            return int(rc)
        value = int.__index__(rc) if isinstance(rc, int) else int(rc)
        str(value)
        return value
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return -255


def _sh_triple(argv, *, timeout: int) -> tuple:
    """The ``sh`` seam laundered to an exact ``(rc, out, err)`` shape.

    nas11's ``_rc_int`` laundered the rc *value*, but the answer's *shape*
    stayed bare: ``rc, out, err = sh(...)`` iterates whatever the seam
    handed back, and this module does not own ``sh`` (tests and tooling
    patch it).  A leftover sequence subclass whose ``__iter__`` raises, a
    torn two-field answer, or a patched ``sh`` that raises outright each
    used to blow the unpack itself — inside ``_plist`` /
    ``_tm_latest_backup`` (a raw 500 on GET /api/snapshots through
    ``overview``'s fan-out, which re-raises a probe's error) and
    ``create_snapshot`` (a raw 500 on POST /api/snapshots/create) — one
    step ahead of the ``_rc_int`` / ``_as_text`` guards on the fields
    themselves (the ups/vms/storage ``_sh3`` rule).  An unreadable answer
    reads as spawn failure: ``-255`` is nonzero and never ``sh``'s ``-1``
    sentinel.
    """
    try:
        rc, out, err = sh(argv, timeout=timeout)
        return rc, out, err
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return -255, "", ""


def _opt_text(value) -> str:
    """``_as_text(value or "")`` without asking the raw value for truth.

    ``time_machine_overview`` read its plist fields through the bare
    ``entry.get(...) or ""`` — but this module does not own the plist
    providers (tests and tooling patch them), and a leftover ``__bool__``
    bomb detonated the ``or`` itself, one step ahead of ``_as_text``'s
    laundering.  The old MountPoint probe was worse: ``str(...)`` caught
    only the digit-cap ValueError, so a ``__str__`` bomb raising anything
    else escaped raw.  Each was a raw 500 on GET /api/snapshots through
    fan_out; a field that cannot even answer for its truth reads as empty.
    """
    return _as_text(value) if _truthy(value) else ""


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's ``allow_nan=False`` encoder cannot 500.

    ``tmutil`` / ``run_admin`` leftover ``\\ud800`` / ``Infinity`` still 500'd
    POST /api/snapshots/delete after the plist walk already scrubbed SnapshotName.
    """
    if depth > 16:
        return None
    # _isa at every rank (the nas_common rule): a ``__class__``-property
    # bomb nested in a run_admin payload used to detonate the first gate it
    # failed and 500 the mutation routes; it now falls through to the final
    # text probe like any other unrecognized leftover.
    if value is None:
        return value
    if _isa(value, bool):
        # ``bool`` is final, so a value that answers the bool gate while
        # its real type is not bool is a *lying* ``__class__`` impostor
        # (the modules9 rule).  The old arm returned it raw and Starlette's
        # ``allow_nan=False`` encoder 500'd the mutation routes; only a
        # real bool renders, the impostor drops like a lying int.
        if type(value) is bool:
            return value
        return None
    if _isa(value, int):
        if type(value) is not int:
            try:
                # Base coercion to an exact int (the modules5 / nas_common
                # rule): an int-subclass ``__str__`` bomb in a run_admin
                # result raised a non-ValueError past the digit-cap probe
                # below and 500'd POST /api/snapshots/* and
                # /api/timemachine/action.
                value = int.__index__(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return None
        try:
            str(value)
        except ValueError:
            # Past CPython's int->str digit cap the encoder cannot render
            # the number at all — same drop as its inf float sibling.
            return None
        return value
    if _isa(value, float):
        if type(value) is not float:
            try:
                # Base coercion to an exact float: a float-subclass
                # ``__eq__``/``__ne__`` bomb used to blow the NaN/inf probes
                # below and 500 the same mutation routes.
                value = float.__float__(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return None
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if _isa(value, str):
        return _as_text(value)
    if _isa(value, (bytes, bytearray)):
        # Unbound base decode: a bytes-subclass whose bound ``.decode``
        # raises used to 500 the mutation routes out of _admin_result.
        # In a try (the modules9 rule): a *lying* ``__class__`` claiming
        # bytes made the descriptor raise outside any try — the impostor
        # drops like a lying int instead of 500ing the mutation.
        # Both bases, real layout first-come (the modules12/logs12 rule):
        # a genuine bytearray lying ``bytes`` used to fail the claimed
        # base's descriptor and drop its decodable message to null.
        for base in (bytes, bytearray):
            try:
                return base.decode(value, "utf-8", "replace")
            except _CONTROL_FLOW:
                raise
            except BaseException:
                continue
        return None
    if _isa(value, dict):
        try:
            items = list(value.items())
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # A mapping that refuses iteration (odd dict subclass in a
            # run_admin result): nothing to salvage, but its *siblings* must
            # survive — pre-fix this raised out of _admin_result and 500'd
            # POST /api/snapshots/* (the ups_svc/nginx_svc._jsonable rule).
            return None
        out = {}
        for pair in items:
            try:
                k, v = pair
            except _CONTROL_FLOW:
                raise
            except BaseException:
                # An items() that yields non-pairs: the two-target unpack
                # used to happen outside the guard above and 500 the same
                # routes — the torn row drops, its sibling pairs survive.
                continue
            try:
                # Per-pair guard: a ``__class__``-bomb key used to detonate
                # its own gate and cost the whole mapping — the torn pair
                # drops alone, its sibling keys survive.
                if not _isa(k, (str, bytes, bytearray)):
                    k = str(k)
                out[_as_text(k)] = _jsonable(v, depth + 1)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                continue
        return out
    if _isa(value, (list, tuple, set, frozenset)):
        try:
            return [_jsonable(v, depth + 1) for v in value]
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # Same class as the mapping above, at sequence rank: only this
            # field drops, never the payload or the route.
            return None
    try:
        iso = getattr(value, "isoformat", None)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # getattr's default only swallows AttributeError; a leftover whose
        # ``isoformat`` is a *raising property* (or a ``__getattr__`` bomb)
        # still raised out of the probe itself and 500'd
        # POST /api/snapshots/* and /api/timemachine/action — the guard
        # nas_common._jsonable already carries.
        iso = None
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/snapshots.
            return _jsonable(iso(), depth + 1)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
    try:
        return _as_text(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None


def _tmutil_on_disk() -> bool:
    """Fresh disk probe for the mutation-failure path only (raid/nfs/vms rule).

    ``Path.is_file()`` can itself raise on a dying volume (EIO/ESTALE); a disk
    that cannot even answer for /usr/bin is not confirmably carrying tmutil.
    """
    try:
        return Path(TMUTIL).is_file()
    except (OSError, ValueError):
        return False


#: What a spawn of a gone binary reads like through run_admin / sh: the
#: shell's own refusal (``sh: /usr/bin/tmutil: command not found`` / ``No
#: such file or directory``) or sh()'s FileNotFoundError sentinel (``not
#: found``).  Purely a message-pattern gate: classification additionally
#: requires the fresh :func:`_tmutil_on_disk` probe, and only the generic
#: ``failed`` shape is eligible — timeouts, cancelled sheets and password
#: failures keep their original shape.
_VANISH_MARKERS = ("command not found", "no such file or directory", "not found")


def _admin_result(result) -> dict:
    # _isa: a ``__class__``-property bomb result detonated the bare gate
    # itself — a raw 500 on every snapshots/timemachine mutation one line
    # ahead of the laundering built to absorb junk shapes.
    cleaned = _jsonable(result) if _isa(result, dict) else {}
    if not isinstance(cleaned, dict):
        return {"ok": False, "error": "failed"}
    # A tmutil that vanished between boot and the mutation (an OS update
    # mid-flight, a dying system volume) used to surface as the generic 500
    # ``admin.failed`` — "the privileged macOS operation failed" sends the
    # operator back to a password dialog that cannot help.  Every sibling
    # NAS CLI (nfsd, diskutil, smartctl, mdutil) already answers its coded
    # 503; the probe runs only on this failure path, never on a success.
    if not cleaned.get("ok") and cleaned.get("error") == "failed":
        message = _as_text(cleaned.get("message") or "").lower()
        if any(marker in message for marker in _VANISH_MARKERS) and not _tmutil_on_disk():
            return {"ok": False, "error": "tmutil_missing"}
    return cleaned


def _run_admin(argv, *, timeout) -> dict:
    """The privileged-runner *call* itself guarded (the users12 rule).

    ``_admin_result`` launders ``run_admin``'s junk *answers*, but every
    mutation seam ran the call bare — and this module does not own the
    runner (tests and tooling patch it; the share_acl_svc ``_sh_call`` /
    ``_admin_sequence`` guarded-call rule).  A leftover stub that *raises*
    instead of answering blew POST /api/snapshots/delete, /thin and
    /api/timemachine/action one seam ahead of the launder built for its
    answers.  A raising runner reads as the generic coded failure — with
    no message text it can never mint the disk-confirmed vanished-CLI 503
    — while an honest answer keeps riding ``_admin_result`` untouched,
    cancelled / password_required shapes included.
    """
    try:
        return run_admin(argv, timeout=timeout)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return {"ok": False, "error": "failed"}


def _admin_sequence(commands, *, timeout) -> dict:
    """The privileged-helper sequence call guarded the same way.

    ``delete_all_snapshots`` ran ``run_admin_sequence`` bare; a leftover
    stub that raises instead of answering 500'd POST /api/snapshots/delete
    one seam ahead of ``_admin_result``.
    """
    try:
        answer = run_admin_sequence(commands, timeout=timeout)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return {"ok": False, "error": "failed"}
    return _admin_result(answer)


def _plist(argv: list[str], *, timeout: int = 15) -> dict | None:
    """Run *argv* and parse its stdout as a plist, or None when unusable.

    ``tmutil`` writes diagnostics to stdout ahead of the XML on some failures,
    so the payload is located by its declaration rather than assumed to start at
    byte zero.
    """
    rc, out, _ = _sh_triple(argv, timeout=timeout)
    out = _as_text(out)
    if _rc_int(rc) != 0 or not out:
        return None
    start = out.find("<?xml")
    if start < 0:
        return None
    try:
        parsed = plistlib.loads(out[start:].encode())
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # Same ExpatError leftover as raid_svc._plist: a torn tmutil plist
        # used to 500 /api/snapshots instead of rendering an empty page.
        return None
    return parsed if isinstance(parsed, dict) else None


def _snapshot_date(name: str) -> str:
    m = _SNAP_DATE.search(_as_text(name))
    return m.group(1) if m else ""


def _xid(raw):
    """JSON-safe SnapshotXID.

    ``inf`` / ``nan`` used to 500 GET /api/snapshots under Starlette's
    ``allow_nan=False`` encoder; ``bytes`` used to TypeError ``json.dumps``.
    """
    if _isa(raw, bool) or raw is None:
        return None
    if _isa(raw, (bytes, bytearray, list, dict, tuple, set)):
        return None
    if _isa(raw, float):
        try:
            # Base coercion before the NaN/inf probes (the _jsonable rule):
            # a float-subclass ``__eq__``/``__ne__`` bomb XID used to
            # detonate the probes themselves and 500 GET /api/snapshots.
            raw = float.__float__(raw)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
        if raw != raw or raw in (float("inf"), float("-inf")):
            return None
    if _isa(raw, int):
        try:
            # Base coercion first: an int-subclass ``__str__`` bomb raised
            # a non-ValueError past the digit-cap probe below.
            raw = int.__index__(raw)
            str(raw)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # A >4300-digit leftover XID is past CPython's int->str digit
            # cap and ValueError'd json.dumps on GET /api/snapshots.
            return None
        return raw
    if _isa(raw, str):
        # A leftover ``\ud800`` XID string used to 500 the UTF-8 encode the
        # same way an unscrubbed SnapshotName did.
        return _as_text(raw)
    try:
        return int(raw)
    except (TypeError, ValueError, OverflowError):
        return None


def _human_date(token: str) -> str:
    """``2026-08-03-160000`` → ``2026-08-03 16:00:00`` (empty when unparseable)."""
    if not token or len(token) != 17:
        return ""
    return f"{token[:10]} {token[11:13]}:{token[13:15]}:{token[15:17]}"


def snapshot_mounts() -> list[str]:
    """Mounted APFS volumes that can hold snapshots.

    ``/`` is reported by ``tmutil`` as the disk covering the whole boot volume
    group, so it is always included; everything else comes from ``/Volumes``.
    Read-only mounts are skipped because a snapshot cannot be created there.
    """
    mounts = ["/"]
    rc, out, _ = _sh_triple([DISKUTIL, "list", "-plist"], timeout=10)
    seen = set(mounts)
    try:
        volumes = Path("/Volumes")
        entries = sorted(volumes.iterdir()) if volumes.is_dir() else []
    except OSError:
        entries = []
    for entry in entries:
        try:
            if not entry.is_dir() or entry.is_symlink():
                continue
        except OSError:
            continue
        path = _as_text(entry)
        if not path or path in seen:
            continue
        seen.add(path)
        mounts.append(path)
    del rc, out  # diskutil is probed only to keep the call shape stable
    return mounts


def list_snapshots(mount: str = "/") -> list[dict]:
    """Snapshots on *mount*, newest first.

    ``diskutil apfs listSnapshots -plist`` is the detailed source (UUID, XID,
    purgeable flag).  Its output is unprivileged, unlike much of ``tmutil``.
    """
    data = _plist([DISKUTIL, "apfs", "listSnapshots", "-plist", mount])
    # Every read below in a try (the modules9 rule): ``_plist`` builds plain
    # shapes, but this module does not own the provider (tests and tooling
    # patch it), and a *lying* ``__class__`` impostor passes each ``_isa``
    # gate and then blows the read behind it — a dict-liar plist blew the
    # bound ``.get``, a list-liar Snapshots table blew the loop header, and
    # a dict-liar row blew its own field reads, each a raw 500 on
    # GET /api/snapshots through fan_out where every other junk shape
    # already drops silently.
    raw = None
    if _isa(data, dict):
        try:
            raw = dict.get(data, "Snapshots")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            raw = None
    if not _isa(raw, list):
        raw = []
    try:
        rows = list(list.__iter__(raw))
    except _CONTROL_FLOW:
        raise
    except BaseException:
        rows = []
    items: list[dict] = []
    for entry in rows:
        # _isa: a ``__class__``-property bomb row in a poisoned plist used
        # to detonate this gate and 500 GET /api/snapshots through fan_out,
        # where every other junk row already drops silently.
        if not _isa(entry, dict):
            continue
        try:
            name = _as_text(dict.get(entry, "SnapshotName") or "")
            token = _snapshot_date(name)
            system = name.startswith(_SYSTEM_SNAPSHOT_PREFIXES)
            items.append({
                "mount": _as_text(mount),
                "name": name,
                "uuid": _as_text(dict.get(entry, "SnapshotUUID") or ""),
                "xid": _xid(dict.get(entry, "SnapshotXID")),
                "date_token": token,
                "date": _human_date(token),
                "purgeable": _truthy(dict.get(entry, "Purgeable")),
                "limits_shrink": _truthy(dict.get(entry, "LimitingContainerShrink")),
                "kind": "system" if system else ("timemachine" if token else "other"),
                # An OS-update snapshot is macOS rollback state, not operator
                # backup state.  Deleting one is legal but rarely intended.
                "deletable": bool(token) and not system,
            })
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # A dict-liar row rejects the unbound read; it drops alone and
            # its sibling rows survive.
            continue
    items.sort(key=lambda x: x["date_token"], reverse=True)
    return items


def _tm_destinations() -> dict | None:
    return _plist([TMUTIL, "destinationinfo", "-X"])


def _tm_status() -> dict | None:
    return _plist([TMUTIL, "status", "-X"])


def _tm_latest_backup() -> str:
    rc, latest, _ = _sh_triple([TMUTIL, "latestbackup"], timeout=12)
    return _as_text(latest).strip() if _rc_int(rc) == 0 else ""


def time_machine_overview() -> dict:
    """Destinations, schedule and current run state for Time Machine.

    The three `tmutil` reads answer unrelated questions and none consumes another's
    output, but `latestbackup` alone can block for its full 12s timeout when a
    network destination is unreachable -- which used to delay the destination list
    and the progress percentage behind it. `_plist` returns None and
    `_tm_latest_backup` returns "" on every failure, so nothing here raises into
    fan_out.
    """
    dest, status, latest_path = fan_out(
        lambda probe: probe(),
        [_tm_destinations, _tm_status, _tm_latest_backup],
        max_workers=3,
    )
    # A plain-dict copy of both plist answers (the nas_common._plain_result
    # rule): ``_plist`` builds plain shapes, but this module does not own
    # the providers (tests and tooling patch them), and a *lying*
    # ``__class__`` impostor claiming dict passed the old bare gates and
    # blew the bound ``.get`` reads below — a raw 500 on GET /api/snapshots
    # through fan_out.  ``dict()`` copies through the C-level storage; a
    # shape whose copy itself raises is junk and reads as "no answer".
    def _plain(mapping):
        if type(mapping) is dict:
            return mapping
        if not _isa(mapping, dict):
            return None
        try:
            return dict(mapping)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None

    dest = _plain(dest) or {}
    status = _plain(status) or {}
    destinations = []
    raw_dest = dest.get("Destinations")
    if not _isa(raw_dest, list):
        raw_dest = []
    try:
        # Unbound base walk in a try (the modules9 rule): a list-liar
        # destination table passed the gate and the loop header 500'd
        # GET /api/snapshots; the real rows of a genuine subclass still walk.
        dest_rows = list(list.__iter__(raw_dest))
    except _CONTROL_FLOW:
        raise
    except BaseException:
        dest_rows = []
    for entry in dest_rows:
        # _isa, same as the list_snapshots walk: a ``__class__``-bomb
        # destination row must drop alone, never 500 GET /api/snapshots.
        # The plain-dict copy also strips a dict-liar row whose bound
        # reads would otherwise raise.
        entry = _plain(entry)
        if entry is None:
            continue
        # _opt_text, not ``str(entry.get(...) or "")``: the bare ``or``
        # asked a leftover ``__bool__``-bomb field for truth and the old
        # str() caught only the digit-cap ValueError, so a ``__str__``
        # bomb raising anything else escaped raw — each a raw 500 on
        # GET /api/snapshots through fan_out.  An over-cap plist-hex
        # MountPoint (plistlib parses ``<integer>0xF…</integer>`` through
        # ``int(x, 16)``, exempt from CPython's 4300-digit parse cap)
        # still scrubs to "" inside _as_text: an unrenderable mount can
        # never name a directory, so it reads as unmounted.
        mount_point = _opt_text(entry.get("MountPoint"))
        mounted = False
        if mount_point and "\x00" not in mount_point:
            try:
                mounted = Path(mount_point).is_dir()
            except (OSError, ValueError):
                mounted = False
        destinations.append({
            "id": _opt_text(entry.get("ID")),
            "name": _opt_text(entry.get("Name")),
            "kind": _opt_text(entry.get("Kind")),
            "mount": mount_point,
            "url": _opt_text(entry.get("URL")),
            # _truthy: a leftover ``__bool__``-bomb flag detonated the bare
            # bool() itself — a raw 500 on GET /api/snapshots.
            "last_used": _truthy(entry.get("LastDestination")),
            "mounted": mounted,
        })

    # _truthy, not bool(): a ``__bool__``-bomb Running value in a poisoned
    # status plist used to detonate the truth test raw under fan_out.
    running = _truthy(status.get("Running"))
    progress = _plain(status.get("Progress")) or {}
    percent = progress.get("Percent")
    percent_val = None
    if percent is not None:
        try:
            raw_pct = float(percent)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # The old catch named only the arithmetic trio (TypeError,
            # ValueError, OverflowError), so a leftover ``__float__`` bomb
            # raising anything else — RuntimeError or a BaseException
            # subclass alike — rode out of the probe raw and 500'd
            # GET /api/snapshots through fan_out, which re-raises a
            # probe's error.  An unreadable percent reads as no percent.
            raw_pct = None
        if raw_pct is not None and raw_pct == raw_pct and raw_pct not in (
            float("inf"), float("-inf"),
        ):
            # Leftover finite ``1e308`` is not inf, then ``* 100`` overflows
            # to inf and 500'd GET /api/snapshots under allow_nan=False.
            try:
                scaled = round(raw_pct * 100, 1)
            except OverflowError:
                scaled = None
            if scaled is not None and scaled == scaled and scaled not in (
                float("inf"), float("-inf"),
            ):
                percent_val = scaled

    return {
        "configured": bool(destinations),
        "destinations": destinations,
        "running": running,
        # _opt_text: the bare ``or ""`` ran a leftover ``__bool__`` bomb.
        "phase": _opt_text(status.get("BackupPhase")),
        "percent": percent_val,
        "latest_backup": latest_path,
        "latest_backup_date": _human_date(_snapshot_date(latest_path)),
    }


@cached_snapshot(_CACHE_TTL)
def overview(force: bool = False) -> dict:
    """Snapshot inventory across volumes plus Time Machine state.

    Cached briefly: ``diskutil apfs listSnapshots`` is one process per volume and
    the page polls, so an uncached read multiplies process spawns by the number
    of attached disks.
    """

    # Materialized under its own guard, like the router's ``_known_mount``
    # gate (nas6): this module does not own the provider (tests and tooling
    # patch it), and a leftover listing that passes ``isinstance`` yet
    # refuses iteration used to blow this walk *before* the route's
    # sanitizer could help — a raw 500 on GET /api/snapshots.  "/" is pinned
    # because snapshot_mounts always reports the boot volume first, so the
    # page still renders while a hostile listing drops.
    try:
        mounts = [m for m in list(snapshot_mounts()) if isinstance(m, str)]
    except _CONTROL_FLOW:
        raise
    except BaseException:
        mounts = []
    if "/" not in mounts:
        mounts.insert(0, "/")
    # One `diskutil apfs listSnapshots` per volume, plus the Time Machine read that
    # used to sit as a serial tail after the whole loop. None of them depends on
    # another, so they all go in one wave: an uncached read now costs one probe
    # instead of one-per-attached-disk-plus-three. `list_snapshots` swallows its own
    # failures via `_plist`, and `fan_out` keeps `snapshot_mounts()` order so the
    # volume table does not reshuffle between refreshes.
    probes = [(lambda m=mount: list_snapshots(m)) for mount in mounts]
    results = fan_out(
        lambda probe: probe(),
        probes + [time_machine_overview],
        max_workers=min(len(probes) + 1, 8),
    )
    per_mount, time_machine = results[:-1], results[-1]

    volumes = []
    total = 0
    for mount, snaps in zip(mounts, per_mount):
        # Per-volume guard, same class as the mount listing above: a hostile
        # per-mount result (one that refuses ``len()`` or iteration, or a row
        # missing its own keys) must cost its own volume row, never the page.
        try:
            rows = list(snaps) if isinstance(snaps, list) else []
            if not rows and mount != "/":
                # A non-APFS or snapshot-less external volume adds no signal.
                continue
            total += len(rows)
            newest = rows[0] if rows else None
            volumes.append({
                "mount": mount,
                "count": len(rows),
                "snapshots": rows,
                "newest": (
                    _as_text(dict.get(newest, "date"))
                    if isinstance(newest, dict) else ""
                ),
                "deletable": sum(
                    1 for s in rows
                    if isinstance(s, dict) and _truthy(dict.get(s, "deletable"))
                ),
            })
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue

    data = {
        "ts": strftime_now("%Y-%m-%d %H:%M:%S"),
        "volumes": volumes,
        "total": total,
        "time_machine": time_machine,
    }
    return data


def invalidate() -> None:
    overview.invalidate()


# ── mutations ────────────────────────────────────────────────────────────────

def create_snapshot() -> dict:
    """Take a local snapshot of every eligible volume.

    ``tmutil localsnapshot`` needs no elevation and covers all snapshot-capable
    mounted volumes in one pass, which is also how macOS itself does it before
    a system update.
    """
    rc, out, err = _sh_triple([TMUTIL, "localsnapshot"], timeout=120)
    invalidate()
    message = (_as_text(out) or _as_text(err)).strip()
    if _rc_int(rc) != 0:
        return _admin_result({"ok": False, "error": "failed", "message": message[-400:]})
    return _admin_result({
        "ok": True,
        "message": message[-400:],
        "date_token": _snapshot_date(message),
    })


def delete_snapshot(mount: str, date_token: str) -> dict:
    """Delete one dated local snapshot from *mount* (requires authorization)."""
    # _as_text is a str() probe, not an isinstance gate: the route hands the
    # token over as str through Pydantic, but the service is also called
    # in-process, and a non-str leftover TypeError'd fullmatch (a 500) where
    # the coded ``bad_token`` refusal is the contract.  An over-cap
    # already-int (YAML/plist hex loads uncapped through ``int(x, 16)``)
    # scrubs to "" and earns the same refusal.
    token = _as_text(date_token)
    if not _SNAP_DATE.fullmatch(token):
        return {"ok": False, "error": "bad_token"}
    result = _run_admin(
        [TMUTIL, "deletelocalsnapshots", token],
        timeout=180,
    )
    invalidate()
    return _admin_result(result)


def delete_all_snapshots(mount: str) -> dict:
    """Delete every dated local snapshot on *mount* (requires authorization).

    Snapshot names are re-read here rather than accepted from the caller: the
    argv handed to the authorization sheet must be built from values this
    process validated, never from request data.
    """
    # Guarded unbound walk with per-row reads, like ``overview()``'s mount
    # gate: this module does not own the listing provider (tests and tooling
    # patch it), and the old bare subscripts raised past the router — a
    # listing that passes ``isinstance`` yet refuses iteration, or a row that
    # lost its own ``date_token`` / ``deletable`` key, 500'd
    # POST /api/snapshots/delete where "nothing deletable" is the honest
    # answer.  A hostile row drops alone; its siblings still get deleted.
    tokens = []
    try:
        listed = list_snapshots(mount)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        listed = []
    try:
        rows = list.__iter__(listed) if isinstance(listed, list) else iter(())
    except _CONTROL_FLOW:
        raise
    except BaseException:
        rows = iter(())
    try:
        for s in rows:
            if not isinstance(s, dict) or not _truthy(dict.get(s, "deletable")):
                continue
            token = _as_text(dict.get(s, "date_token"))
            if _SNAP_DATE.fullmatch(token):
                tokens.append(token)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # A walk dying mid-iteration keeps the tokens already collected.
        pass
    if not tokens:
        return {"ok": True, "deleted": 0, "message": "no deletable snapshots"}
    commands = [[TMUTIL, "deletelocalsnapshots", token] for token in tokens]
    # Launder *before* the ok read: ``result.get("ok")`` on the raw
    # run_admin_sequence payload used to fire a dict-subclass ``.get`` bomb
    # (and the ``if`` a ``__bool__``-bomb ok) and 500 POST /api/snapshots/delete
    # ahead of the scrub — _admin_sequence guards the call itself and
    # _admin_result inside it always answers a plain dict.
    result = _admin_sequence(commands, timeout=600)
    invalidate()
    if result.get("ok"):
        result["deleted"] = len(tokens)
    return result


def thin_snapshots(mount: str, urgency: int = 1) -> dict:
    """Ask macOS to reclaim snapshot space on *mount*.

    ``thinlocalsnapshots`` deletes purgeable snapshots until the requested space
    is free.  Urgency 1-4 selects how aggressively macOS is willing to drop
    them; 4 means "free the space even if all snapshots go".
    """
    # Base coercion + a guarded membership probe: the route hands over a
    # Pydantic-exact int, but the service is also called in-process, and an
    # int-subclass ``__eq__`` bomb used to detonate the bare
    # ``urgency not in (1, 2, 3, 4)`` — a raw raise where every other junk
    # urgency earns the coded ``bad_urgency`` refusal (the raid_svc._req_text
    # convention at membership rank).
    if _isa(urgency, int) and not _isa(urgency, bool):
        try:
            urgency = int.__index__(urgency)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return {"ok": False, "error": "bad_urgency"}
    try:
        valid = urgency in (1, 2, 3, 4)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        valid = False
    if not valid:
        return {"ok": False, "error": "bad_urgency"}
    target = str(10 * 1024 * 1024 * 1024)  # 10 GiB request; macOS frees what it can
    result = _run_admin(
        [TMUTIL, "thinlocalsnapshots", mount, target, str(urgency)],
        timeout=300,
    )
    invalidate()
    return _admin_result(result)


_TM_ACTIONS = {
    "start": [TMUTIL, "startbackup"],
    "stop": [TMUTIL, "stopbackup"],
    "enable": [TMUTIL, "enable"],
    "disable": [TMUTIL, "disable"],
}


def time_machine_action(action: str) -> dict:
    """Run a Time Machine control verb through the authorization sheet."""
    # _as_text is a str() probe, not an isinstance gate: the route hands the
    # verb over as str through Pydantic, but the service is also called
    # in-process, and a leftover non-str action AttributeError'd ``.strip()``
    # (a 500) where the coded ``bad_action`` refusal is the contract — the
    # raid_svc._req_text / smart_test_svc._schedule_text convention this
    # module already applies to delete_snapshot's token.  An over-cap
    # already-int (YAML/plist hex loads uncapped through ``int(x, 16)``)
    # coerces to "" and earns the same refusal.
    argv = _TM_ACTIONS.get(_as_text(action).strip().lower())
    if not argv:
        return {"ok": False, "error": "bad_action"}
    result = _run_admin(argv, timeout=180)
    invalidate()
    return _admin_result(result)
