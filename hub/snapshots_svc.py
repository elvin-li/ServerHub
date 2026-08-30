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


def _real(value, types) -> bool:
    """True when the *real* storage layout is one of *types*.

    ``type(value)`` reads the C-level type slot, which a lying ``__class__``
    property cannot swap, so this is the probe for the recover-the-real-
    storage fall-throughs (the maint14/nas14 rule): ``isinstance`` consults
    ``value.__class__`` only after the real-MRO check misses, so a lying
    claim steered a leftover into the arm of its *claim*, the unbound
    descriptor there refused the real layout, and the old early return
    threw honest renderable storage away at the wrong rank.  Fail-closed
    like ``_isa``.
    """
    try:
        return issubclass(type(value), types)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _str_text(value):
    """Exact text of *really-str* storage, or ``None`` for an impostor.

    ``str.__str__`` is a descriptor bound to the real str layout: any real
    str (or subclass) answers its character data without dispatching an
    override, while a *lying* ``__class__`` that only claims str rejects
    the operand — ``None`` lets the caller fall through to the arm the
    real storage matches instead of wiping honest non-str storage at the
    wrong rank (the maint14/nas14 rule).
    """
    try:
        return str.encode(str.__str__(value), "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None


#: CPython's angle-repr shape (``<X object at 0x7f...>``) — a raw heap
#: address, never snapshot or Time Machine data.  Applied to the *coercion*
#: arms only: real str storage is data (a tmutil stderr tail quoting a repr
#: serves verbatim).
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")


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
    coerced = False
    if type(value) is not str:
        if not _real(value, str):
            # Slot probe (the maint14/nas14 rule): for a type that never
            # overrode ``__str__``/``__repr__`` the str() below answers the
            # default ``object.__repr__`` — ``<X object at 0x7f...>``, a
            # raw heap address — which a junk plist Name / MountPoint /
            # message cell used to carry verbatim onto GET /api/snapshots
            # and the mutation bodies.  ``type(value)`` reads the C-level
            # slot a flickering ``__class__`` property cannot swap.
            try:
                cls = type(value)
                if cls.__str__ is object.__str__ and cls.__repr__ is object.__repr__:
                    return ""
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return ""
            coerced = True
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
    text = bytes.decode(str.encode(value, "utf-8", "replace"), "utf-8")
    # The address belt, on the coercion arm only (real str storage is
    # data): a custom ``__repr__`` embedding a heap address the slot probe
    # cannot see must not render either (the maint14/nas14 rule).
    return "" if coerced and _ADDR_REPR_RE.search(text) else text


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
        if type(rc) is bool:
            return int(rc)
        value = int.__index__(rc) if _isa(rc, int) else int(rc)
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


def _key_text(k):
    """One mapping key as text, or ``None`` to drop just its entry.

    The old key path ran bare ``str(k)`` on any non-str/bytes key, and for
    a type that never overrode ``__str__``/``__repr__`` the answer is the
    default ``object.__repr__`` — ``<X object at 0x7f...>``, a raw heap
    address — which a junk key nested in a run_admin payload carried
    verbatim as a JSON *key* on POST /api/snapshots/* and
    /api/timemachine/action (the maint14/nas14 ``_key_text`` rule).  Real
    str/bytes key storage — behind a lying ``__class__`` too — keeps its
    scrubbed text.
    """
    if _isa(k, (bytes, bytearray)):
        for base in (bytes, bytearray):
            try:
                return base.decode(k, "utf-8", "replace")
            except _CONTROL_FLOW:
                raise
            except BaseException:
                continue
        # A lying-bytes claim: real str storage recovers just below.
    if _isa(k, str) or _real(k, str):
        text = _str_text(k)
        if text is not None:
            return text
        # A lying-str claim: coerce off whatever the real storage renders.
    try:
        cls = type(k)
        if cls.__str__ is object.__str__ and cls.__repr__ is object.__repr__:
            return None
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None
    try:
        text = str(k)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # A raising ``__str__`` key keeps dropping its entry, like before.
        return None
    try:
        text = str.encode(text, "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None
    return None if _ADDR_REPR_RE.search(text) else text


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's ``allow_nan=False`` encoder cannot 500.

    ``tmutil`` / ``run_admin`` leftover ``\\ud800`` / ``Infinity`` still 500'd
    POST /api/snapshots/delete after the plist walk already scrubbed SnapshotName.

    nas14 (the maint14/jobs14 shape): a *lying* ``__class__`` steered a
    leftover into the arm of its claim, the unbound descriptor there
    rejected the real layout, and an early return threw honest renderable
    storage away at the wrong rank — a genuine str message claiming int
    wiped to None, a genuine tuple claiming list vanished whole.  The
    rejected arms now fall through to the arm the *real* storage matches
    (``_real``); a total impostor keeps its established None drop (the
    nas9 pins).  The mapping walk reads the *unbound* ``dict.items`` view
    (the nested-unbound rule this module's siblings already carry): the
    old bound ``value.items()`` dispatched a subclass override, so an
    items-bomb whose C-level storage was perfectly walkable vaporised the
    whole mapping to None even though the raise was absorbed — same for
    the sequence arm's bound comprehension and an ``__iter__`` bomb.  Keys
    go through ``_key_text`` (a plain-object key used to serve its default
    ``object.__repr__`` — a raw heap address — as a JSON key).
    """
    if depth > 16:
        return None
    # ``type(value) is bool``, not the old _isa arm: bool is final, so the
    # exact check is complete and never reads a bombing ``__class__``; a
    # bool-liar impostor falls to the int arm's unbound coercion and from
    # there to its real rank — or the established None drop.
    if value is None or type(value) is bool:
        return value
    if _isa(value, int):
        num = value if type(value) is int else None
        if num is None:
            try:
                # Base coercion to an exact int (the modules5 / nas_common
                # rule): an int-subclass ``__str__`` bomb in a run_admin
                # result raised a non-ValueError past the digit-cap probe
                # below and 500'd POST /api/snapshots/* and
                # /api/timemachine/action.
                num = int.__index__(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                num = None
        if num is not None:
            try:
                str(num)
            except ValueError:
                # Past CPython's int->str digit cap the encoder cannot
                # render the number at all — same drop as its inf float
                # sibling.
                return None
            return num
        if not _real(value, (float, str, bytes, bytearray, dict,
                             list, tuple, set, frozenset)):
            # A total impostor claiming int/bool keeps the old None drop.
            return None
        # A lying-int claim over honest storage falls through to its rank.
    if _isa(value, float):
        num = value if type(value) is float else None
        if num is None:
            try:
                # Base coercion to an exact float: a float-subclass
                # ``__eq__``/``__ne__`` bomb used to blow the NaN/inf probes
                # below and 500 the same mutation routes.
                num = float.__float__(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                num = None
        if num is not None:
            if num != num or num in (float("inf"), float("-inf")):
                return None
            return num
        if not _real(value, (str, bytes, bytearray, dict,
                             list, tuple, set, frozenset)):
            return None
        # Genuine text / container behind a lying-float claim falls through.
    if _isa(value, str):
        # Real str storage (any subclass) keeps its scrubbed text; a
        # lying-str claim over genuine bytes / container storage falls
        # through instead of wiping at the wrong rank.
        text = _str_text(value)
        if text is not None:
            return text
        if not _real(value, (bytes, bytearray, dict,
                             list, tuple, set, frozenset)):
            # A total impostor claiming str: the coercion arm's slot probe
            # + address belt answer (a legible ``__str__`` still renders,
            # the default-repr heap address never does).
            return _as_text(value)
    if _isa(value, (bytes, bytearray)):
        # Unbound base decode: a bytes-subclass whose bound ``.decode``
        # raises used to 500 the mutation routes out of _admin_result.
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
        if not _real(value, (dict, list, tuple, set, frozenset)):
            # A total impostor claiming bytes keeps the old None drop.
            return None
        # Genuine container storage behind a lying-bytes claim falls
        # through to the arm that reads its real layout.
    if _isa(value, dict):
        # Unbound base view, materialized (the nas_common/raid rule):
        # ``dict.items`` reads the real C-level storage, so a subclass
        # ``items()`` bomb cannot vaporise perfectly walkable rows the way
        # the old bound ``value.items()`` did — and the ``list(...)``
        # snapshot keeps a mid-walk mutation from ever touching a live
        # view.  Non-pair rows cannot happen off the real storage.
        try:
            items = list(dict.items(value))
        except _CONTROL_FLOW:
            raise
        except BaseException:
            if not _real(value, (list, tuple, set, frozenset)):
                # A total impostor claiming dict keeps the old None drop.
                return None
            items = None
        if items is not None:
            out = {}
            for k, v in items:
                try:
                    # Per-pair guard: a bomb key/value drops alone; its
                    # sibling keys survive.
                    key = _key_text(k)
                    if key is None:
                        continue
                    out[key] = _jsonable(v, depth + 1)
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    continue
            return out
        # Genuine sequence storage behind a lying-dict claim falls through.
    if _isa(value, (list, tuple, set, frozenset)):
        # Unbound base iteration, real layout first-come (the nas13 decode
        # rule at sequence rank): the old bound comprehension dispatched a
        # real subclass's overridden ``__iter__``, so an iter-bomb whose
        # C-level storage was perfectly walkable vaporised to None even
        # though the raise was absorbed — and a total list-liar impostor
        # keeps that None drop.
        for base in (list, tuple, set, frozenset):
            try:
                rows = list(base.__iter__(value))
            except _CONTROL_FLOW:
                raise
            except BaseException:
                continue
            return [_jsonable(v, depth + 1) for v in rows]
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
    if not _isa(cleaned, dict):
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
    return parsed if _isa(parsed, dict) else None


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
        mounts = [m for m in list(snapshot_mounts()) if _isa(m, str)]
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
            rows = list(snaps) if _isa(snaps, list) else []
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
                    if _isa(newest, dict) else ""
                ),
                "deletable": sum(
                    1 for s in rows
                    if _isa(s, dict) and _truthy(dict.get(s, "deletable"))
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
        rows = list.__iter__(listed) if _isa(listed, list) else iter(())
    except _CONTROL_FLOW:
        raise
    except BaseException:
        rows = iter(())
    try:
        for s in rows:
            if not _isa(s, dict) or not _truthy(dict.get(s, "deletable")):
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
