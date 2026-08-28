"""Per-user access to SMB share folders via filesystem ACLs.

Research result (macOS 26, this machine): the native ``sharing`` tool and the
``dscl /SharePoints`` records carry only share-wide flags — guest access,
read-only, sealed — with **no per-user field at all**.  What actually decides
which authenticated user may enter an SMB share on macOS is the filesystem:
``smbd`` acts as the connected user, so POSIX bits plus NFSv4-style ACLs
(``chmod +a`` / ``ls -le``) are the real per-user access control.  That is the
same mechanism OMV reaches with ``setfacl`` — macOS just spells it differently.

This module therefore reads and edits ACL entries on the *share directory*:

* ``read_acl``    — parse ``ls -lde`` into structured entries,
* ``local_users`` — the pickable macOS accounts (uid ≥ 500, not ``_service``),
* ``set_user_access`` — replace one user's entries with a canonical grant.

Verified live: the owner of a directory may edit its ACL without privileges;
anything else needs root, which goes through the same web password path as the
other privileged share operations (:func:`hub.macos_admin.run_admin_sequence`).
macOS normalises permission tokens on directories (``read``→``list``,
``execute``→``search``, ``write``→``add_file``, ``append``→``add_subdirectory``),
so verification after a write classifies tokens semantically instead of
comparing strings.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from hub import macos_admin
from hub.util import sh

CHMOD = "/bin/chmod"
LS = "/bin/ls"
DSCL = "/usr/bin/dscl"

#: Real control flow must keep propagating even through the bomb guards
#: (the modules12/jobs13/apps13 convention): swallowing a Ctrl-C or an
#: interpreter shutdown to save one JSON field would turn the sanitizer
#: into a hang.  Everything else BaseException-shaped that a leftover
#: raises out of its own hooks is a bomb like any other — the users12
#: sweep sealed the raising-runner/admin seams, but every guard in this
#: module stopped at ``except Exception``, so a leftover whose hooks raise
#: a *BaseException* subclass (the watchdog/timeout shape the sibling
#: sweeps sealed on their own surfaces) sailed past every catch at once
#: and 500'd GET and PUT /api/shares/acl raw.
_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)

#: Canonical grants written by set_user_access.  Inheritance flags are included
#: so files created later inside the share inherit the same access.
_READ_PERMS = (
    "read,execute,readattr,readextattr,readsecurity,file_inherit,directory_inherit"
)
_RW_PERMS = (
    "read,write,execute,delete,append,readattr,writeattr,readextattr,"
    "writeextattr,readsecurity,delete_child,file_inherit,directory_inherit"
)
LEVELS = ("none", "read", "readwrite")

#: Tokens that mean "can change content" once macOS has normalised the entry.
_WRITE_TOKENS = {
    "write", "add_file", "append", "add_subdirectory", "delete",
    "delete_child", "writeattr", "writeextattr", "writesecurity", "chown",
}

#: ``ls -le`` ACL line:  `` 0: user:alice allow read,write`` — the qualifier
#: may itself contain spaces (display-name groups), so the kind:name pair is
#: matched non-greedily up to the allow/deny verb.
_ACL_LINE = re.compile(
    r"^\s*(?P<index>\d+):\s+"
    r"(?P<kind>user|group):(?P<name>.+?)\s+"
    r"(?P<inherited>inherited\s+)?"
    r"(?P<effect>allow|deny)\s+"
    r"(?P<perms>\S+)\s*$"
)

#: Same shape the panel accounts use — and, not coincidentally, what macOS
#: accepts as a record name.  Rejects anything that could smuggle an option
#: or a second field into the chmod ACL spec.
_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,63}$")


def _isa(value, kinds) -> bool:
    """``isinstance`` that survives a leftover ``__class__``-property bomb.

    ``isinstance`` consults ``value.__class__`` when the exact-type check
    misses, so a leftover whose ``__class__`` is a *raising property*
    detonated the gate itself: ``_plain_result``'s dict gate 500'd
    PUT /api/shares/acl one line ahead of the laundering built to absorb
    junk shapes.  A real subclass still matches through the C-level type
    check; only a value that cannot answer what it is takes the
    non-matching branch.

    ``except BaseException``: the users9 guard stopped at ``Exception``,
    so a leftover whose ``__class__`` property raises a *BaseException*
    subclass sailed past this catch — the gate every sanitizer arm in
    this module stands on — and past every sibling ``except Exception``
    up the stack, a raw 500 on GET and PUT /api/shares/acl.  Only genuine
    control flow keeps propagating.
    """
    try:
        return isinstance(value, kinds)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


#: CPython's angle-repr shape (``<X object at 0x7f...>`` and the function /
#: bound-method variants) — a raw heap address, never share/ACL data (the
#: bookmarks/assistant/files13 rule).  Only the free-text *coercion* arm of
#: ``_as_text`` is scrubbed with it; real str/bytes storage is data — an ls
#: line may legitimately contain the pattern — and stays verbatim.
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")


def _as_text(value) -> str:
    """``sh`` leftovers arrive as int/None/bytes; leftover ``\\ud800`` used to 500 GET /api/shares/acl.

    The type gates match through a *lying* ``__class__`` too (isinstance
    consults it once the real-MRO check misses), so each arm can be handed a
    value whose real storage belongs to a different arm — and the old flow
    degraded honest data at the wrong rank (the files13/notify13/logs13
    recover-the-real-storage rule): a genuine str whose ``__class__`` lied
    ``bytes`` failed both base decodes, then fell to the *dispatching*
    ``str(value)``, so a bombed ``__str__`` vanished the perfectly readable
    ls/dscl text to ``""`` — GET /api/shares/acl answered the coded read
    failure where the honest listing should have parsed, and a legible
    coded ``error`` ("cancelled") on PUT degraded to the generic
    authorization failure in place of its own refusal.  Real str storage now
    reads through the unbound ``str.encode`` no matter what the claim says.

    The free-text coercion arm ran ``str()`` on any leftover shape, and for
    a type that never overrode ``__str__``/``__repr__`` the answer is the
    default ``object.__repr__`` — ``<X object at 0x7f...>``, a raw heap
    address — which a junk ls answer carried verbatim into the GET
    /api/shares/acl body (the ``group`` column of the parsed header) and a
    junk RealName read into every picker row (the bookmarks/assistant
    address-leak rule).  A slot probe on the real ``type(value)`` refuses
    the shape, and the regex belt catches what the probe cannot see
    (C-level ``__repr__`` overrides and container renders embedding a
    default repr).  Only the coercion arm is scrubbed — real str/bytes
    storage is data and stays verbatim.
    """
    if _isa(value, (bytes, bytearray)):
        # Unbound base decode (the brew6 rule): a leftover bytes-subclass
        # whose bound ``.decode`` raises used to escape read_acl untyped and
        # 500 GET /api/shares/acl past the share gate.  Both bases are
        # tried, real layout first-come (the jobs13/modules12/apps13 decode
        # rule): the users9 arm picked the base off the *claimed*
        # ``__class__`` (``bytes if _isa(value, bytes)``), so a genuine
        # ``bytearray`` whose ``__class__`` lied ``bytes`` was handed to
        # ``bytes.decode``, rejected by the descriptor, and its perfectly
        # decodable ls/dscl text fell through to the str() rank — a
        # ``bytearray(b'…')`` repr where the honest listing should have
        # parsed.  A total impostor (real type is neither base) still falls
        # through so a legible impostor renders instead of costing the
        # route; honest str storage behind a lying-bytes ``__class__``
        # recovers through the unbound str read below.
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
    if _isa(value, str):
        # Unbound base read, not the dispatching ``str()``: real str storage
        # keeps its text even when the subclass ``__str__`` raises (and a
        # ``__str__`` answering *self* can no longer ride its bound
        # ``encode`` bomb out of this line — the modules6 rule).  Exact strs
        # take this arm untouched: real storage is data, never belt-scrubbed.
        try:
            return str.encode(value, "utf-8", "replace").decode("utf-8")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # Claims str, carries no character storage: a lying impostor —
            # fall to the coercion arm so a legible one still renders.
            pass
    # Free-text coercion arm: only a type that renders *itself* may coerce.
    # For a type that never overrode ``__str__``/``__repr__`` the coercion
    # answers the default ``object.__repr__`` — a raw heap address — which
    # used to ride into the GET body verbatim.
    try:
        cls = type(value)
        if cls.__str__ is object.__str__ and cls.__repr__ is object.__repr__:
            return ""
    except _CONTROL_FLOW:
        raise
    except BaseException:
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
            # A ``__str__`` bomb raising a *BaseException* subclass used to
            # sail past the ``except Exception`` here and 500 GET and PUT
            # /api/shares/acl at value, field and message rank.
            return ""
    if not _isa(value, str):
        return ""
    try:
        text = str.encode(value, "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    # Belt for what the slot probe cannot see: a function / bound-method
    # leftover (C-level ``__repr__`` override) and a rendering that embeds a
    # default repr (``{'x': <_Junk object at 0x...>}``) still answered an
    # address.  Only this coercion arm is scrubbed.
    return "" if _ADDR_REPR_RE.search(text) else text


def _truthy(value) -> bool:
    """``bool(value)`` that survives a leftover ``__bool__`` bomb (fails False).

    ``except BaseException``: a ``__bool__`` bomb raising a *BaseException*
    subclass (a stderr slot riding ``_pick``'s truth test, a privileged
    result's ``ok`` / ``message``) sailed past the old catch — a raw 500
    on GET and PUT /api/shares/acl out of the very probes built to absorb
    the Exception-shaped twin.
    """
    try:
        return bool(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _pick(value, fallback):
    """``value or fallback`` that a leftover ``__bool__`` bomb cannot 500."""
    return value if _truthy(value) else fallback


def _rc_int(rc) -> int:
    """Exact exit status for the ``==`` / ``!=`` probes; junk reads as failure.

    This module does not own ``sh`` (tests and tooling patch it — the
    health9 / host_address / docker10 ``_rc_int`` rule), and every probe
    compared the *rc* slot raw: an rc-subclass whose ``__eq__``/``__ne__``
    raises detonated ``rc != 0`` in ``read_acl`` and ``local_users`` — raw
    500s on GET and PUT /api/shares/acl past every coded refusal — and the
    same bomb in ``_run_unprivileged`` blew the PUT one line ahead of its
    failure funnel.  ``-255`` is no honest exit status and is distinct from
    the ``-1`` spawn-failure sentinel, so junk can never be misread as
    success or as a vanished CLI.
    """
    # Identity, not ``isinstance(rc, bool)``, for the real singletons:
    # ``bool`` is final, so a value that answers the bool gate without
    # *being* True or False is a lying-``__class__`` impostor, and the old
    # ``int(rc)`` arm dispatched into its own ``__int__`` — a bool-liar
    # answering ``0`` forged a *success* exit status for a spawn that never
    # succeeded (the vms10 bool-liar rule: junk is never consent to claim
    # success).
    if rc is True:
        return 1
    if rc is False:
        return 0
    try:
        if isinstance(rc, bool):
            # Passed the final-type gate without being either singleton:
            # a lying impostor, junk by definition.
            return -255
        # Unbound base coercion: a subclass ``__index__``/``__int__`` bomb
        # cannot fire, and a lying-``__class__`` impostor TypeErrors here
        # instead of passing the gate (the modules5 unbound convention).
        # ``int(rc)`` for everything else keeps the shares10 contract: a
        # stringy "0" from an odd stub parses (the str->int path is
        # parse-capped, so a 4300+-digit string is ValueError -> junk).
        value = int.__index__(rc) if isinstance(rc, int) else int(rc)
        if type(value) is not int:
            return -255
        # Digit-cap probe: past CPython's int->str cap the status cannot be
        # rendered by any log line or JSON encoder — junk, reads as failure.
        str(value)
        return value
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # The bare ``isinstance`` gates inside the try read a raising
        # ``__class__`` property, and an rc whose property — or whose
        # ``__int__`` coercion — raises a *BaseException* subclass sailed
        # past the users11 catch: raw 500s out of every ``!=`` / ``==``
        # probe on GET and PUT /api/shares/acl.
        return -255


def _sh3(value) -> tuple:
    """Exact ``(rc, out, err)`` storage from a possibly-poisoned ``sh`` answer.

    A real spawn always answers an exact 3-tuple, but this module does not
    own ``sh`` (tests and tooling patch it), and every call site unpacked the
    answer raw: ``rc, output, error = sh(...)`` dispatched into the answer's
    own iteration, so a tuple-subclass whose bound ``__iter__`` bombs — or a
    lying ``__class__`` impostor claiming tuple/list over no real sequence
    storage, a wrong-arity tuple, a bare ``None`` — raised straight out of
    ``read_acl``, ``local_users`` (both dscl reads) and
    ``_run_unprivileged``: raw 500s on GET and PUT /api/shares/acl past
    every coded refusal (the vms10/network10 sequence-unwrap class).  The
    unbound base reads see the real C-level storage, so an honest answer in
    a subclass wrapper survives untouched — the ``-1`` vanished-spawn
    sentinel included — while junk degrades to ``(-255, "", "")``: nonzero
    (a poisoned answer is not consent to claim success) and never the
    ``-1`` sentinel (an unusable answer cannot forge the vanished-CLI 503).
    BaseException-shaped failure reads take the same junk branch as their
    Exception twins; only genuine control flow keeps propagating.
    """
    # ``except BaseException`` on both storage reads: a lying-``__class__``
    # impostor whose failure shape is a *BaseException* subclass sailed
    # past the users11 catches and blew the unwrap it was built for.
    if type(value) is tuple:
        items = value
    elif _isa(value, tuple):
        try:
            items = tuple(tuple.__iter__(value))
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return (-255, "", "")
    elif _isa(value, list):
        try:
            items = tuple(list.__getitem__(value, slice(None)))
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return (-255, "", "")
    else:
        return (-255, "", "")
    if len(items) != 3:
        return (-255, "", "")
    return items


def _sh_call(argv, *, timeout) -> tuple:
    """One guarded spawn: the *call* itself can no longer cost the route.

    ``_sh3`` launders the answer's shape, but every seam still ran the call
    bare — and this module does not own ``sh`` (tests and tooling patch it;
    the wireguard ``_sh_answer`` guarded-call rule).  A leftover stub that
    *raises* instead of answering blew ``read_acl`` (a raw 500 on GET and
    PUT /api/shares/acl before any gate ran), both dscl reads in
    ``local_users`` (a raw 500 through the picker half of the GET, or one
    poisoned per-user RealName read costing the whole picker) and
    ``_run_unprivileged`` (a raw 500 on the PUT's owner-run path one line
    ahead of its failure funnel).  A raising runner reads as
    ``(-255, "", "")``: nonzero (a runner that cannot answer is never
    consent to claim success) and never the ``-1`` spawn sentinel, and with
    no marker text it can never mint the disk-confirmed vanished-CLI 503
    either.  An honest answer — the ``-1`` sentinel included — keeps riding
    ``_sh3`` untouched.

    ``except BaseException``: the users12 guard stopped at ``Exception``,
    so a leftover runner raising a *BaseException* subclass (the
    watchdog/timeout shape) sailed past the guard built for it — the same
    raw 500s on GET and PUT /api/shares/acl the guard exists to absorb,
    one exception rank over.  Only genuine control flow keeps propagating:
    a Ctrl-C mid-spawn must still stop the process, not read as one more
    failed ls.
    """
    try:
        answer = sh(argv, timeout=timeout)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return (-255, "", "")
    return _sh3(answer)


def _str_keyed(plain: dict) -> dict:
    """*plain* (an exact dict) with every key an exact ``str``.

    One hash-shadowing key — same hash as the literal a reader fetches,
    raising ``__eq__`` — detonates the *probe itself*: ``dict.get`` on a
    laundered copy is still a hash-table probe, one seam earlier than any
    value gate (the compose10 / files13 shadow-key class).  A shadow over
    ``ok`` / ``error`` / ``message`` in a privileged result blew
    ``_plain_result`` and ``set_user_access``'s failure funnel — raw 500s
    on PUT /api/shares/acl in place of the coded refusals.  ``str.__str__``
    copies through the C storage, so laundering cannot itself detonate;
    non-str keys drop — no reader ever looks a field up by one.
    """
    # Iterating a plain dict's keys never dispatches into a subclass, so
    # this probe cannot raise; the common all-exact-str map returns as-is.
    if all(type(k) is str for k in plain):
        return plain
    out = {}
    for k, v in plain.items():
        if type(k) is str:
            out[k] = v
        elif _isa(k, str):
            # _isa: a ``__class__``-property-bomb KEY blew a bare gate.
            # str.__str__ TypeErrors on a lying-``__class__`` impostor and
            # the junk key drops like any other non-str — BaseException
            # rank included, so a bombed key can never cost the copy.
            try:
                out[str.__str__(k)] = v
            except _CONTROL_FLOW:
                raise
            except BaseException:
                continue
    return out


def _plain_result(result) -> dict:
    """A privileged-helper result as a plain dict with a real bool ``ok``.

    A leftover dict-*subclass* result from ``run_admin_sequence`` (the
    jobs/metrics row-bomb class: passes an isinstance gate, then ``.get()``
    raises) used to 500 PUT /api/shares/acl right out of
    ``if not result.get("ok")`` — and again out of the ``{**result, ...}``
    merge below it.  ``dict()`` copies through the C-level storage, so an
    overridden method cannot fire; junk shapes degrade to the coded failure.
    _isa, not a bare isinstance: a ``__class__``-property bomb detonated
    the gate itself before the non-dict branch could answer.
    """
    if _isa(result, dict):
        try:
            # _str_keyed after the copy: a hash-shadowing ``ok`` key kept
            # its raising ``__eq__`` through ``dict()`` and detonated the
            # very next ``plain.get("ok")`` probe — and the ``{**result,
            # "error": ...}`` merge in set_user_access after it — raw 500s
            # on PUT /api/shares/acl out of the laundering itself.
            # ``except BaseException``: a subclass whose ``keys()`` /
            # ``__iter__`` raises a *BaseException* subclass took
            # ``dict()``'s slow path past the users10 catch — the same
            # detonation one rank over.
            plain = _str_keyed(dict(result))
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return {"ok": False, "error": "failed"}
    else:
        return {"ok": False, "error": "failed"}
    plain["ok"] = _truthy(plain.get("ok"))
    return plain


def _admin_sequence(commands) -> dict:
    """A plain admin result even when the privileged helper itself raises.

    ``_plain_result`` launders ``run_admin_sequence``'s junk *answers*, but
    both escalation seams in ``set_user_access`` ran the call bare — and
    this module does not own the helper (tests and tooling patch it; the
    usage/smart/wireguard guarded-call rule).  A leftover stub that raises
    instead of answering 500'd PUT /api/shares/acl one seam ahead of the
    launder built for its answers, in place of the coded authorization
    failure.  A raising helper reads as the generic coded failure — with no
    ``-1``-shaped message text it can never mint the disk-confirmed
    vanished-CLI answer — while an honest answer keeps riding
    ``_plain_result`` untouched, ``cancelled`` / ``password_required``
    shapes included.

    ``except BaseException``: the users12 guard stopped at ``Exception``,
    so a leftover helper raising a *BaseException* subclass blew both
    escalation seams past the guard built for it — a raw 500 on PUT
    /api/shares/acl in place of the coded authorization failure.  Only
    genuine control flow keeps propagating: an interpreter shutdown
    mid-escalation must never be reported as one more failed grant.
    """
    try:
        answer = macos_admin.run_admin_sequence(commands)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return {"ok": False, "error": "failed"}
    return _plain_result(answer)


class ShareAclError(Exception):
    """Validation failure with a stable API error code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _tool_on_disk(path: str) -> bool:
    """Fresh disk probe for the failure paths only (raid/vms rule).

    ``Path.is_file()`` can itself raise on a dying volume (EIO/ESTALE); a disk
    that cannot even answer for /bin is not confirmably carrying the tool.
    """
    try:
        return Path(path).is_file()
    except (OSError, ValueError):
        return False


#: What a spawn of a gone binary reads like through run_admin / sh: the
#: shell's own refusal (``sh: /bin/chmod: command not found`` / ``No such
#: file or directory``) or sh()'s FileNotFoundError sentinel (``not found``).
#: Purely a message-pattern gate: classification additionally requires the
#: fresh :func:`_tool_on_disk` probe, and only the generic failure shape is
#: eligible — timeouts and authorization outcomes keep their original shape.
_VANISH_MARKERS = ("command not found", "no such file or directory", "not found")


def parse_acl_listing(output: str) -> dict:
    """Structured view of one ``ls -lde <dir>`` listing.

    Returns ``{"mode", "owner", "group", "entries": [...]}`` where each entry
    is ``{"index", "kind", "name", "effect", "perms", "inherited", "level"}``.
    ``level`` classifies an *allow* entry as read / readwrite from its tokens.
    """
    lines = [line for line in _as_text(output).splitlines() if line.strip()]
    if not lines:
        raise ShareAclError("shares.acl_read_failed")
    head = lines[0].split()
    if len(head) < 4:
        raise ShareAclError("shares.acl_read_failed")
    mode, owner, group = head[0], head[2], head[3]
    entries: list[dict] = []
    for line in lines[1:]:
        match = _ACL_LINE.match(line)
        if not match:
            continue
        try:
            index = int(match.group("index"))
        except ValueError:
            # ``(\d+)`` bounds the charset but not the length: ``int()`` of a
            # >4300-digit index is ValueError (CPython's str->int cap), not
            # ShareAclError, so it used to raise past the routers' handler and
            # 500 GET and PUT /api/shares/acl through read_acl.  The index is
            # load-bearing — removals run ``chmod -a# <index>`` — so a row
            # whose number is unusable is skipped like any other unparsable
            # line rather than given a guessed position.
            continue
        perms = [p for p in match.group("perms").split(",") if p]
        level = None
        if match.group("effect") == "allow":
            level = "readwrite" if any(p in _WRITE_TOKENS for p in perms) else "read"
        entries.append({
            "index": index,
            "kind": _as_text(match.group("kind")),
            "name": _as_text(match.group("name")),
            "effect": _as_text(match.group("effect")),
            "perms": [_as_text(p) for p in perms],
            "inherited": bool(match.group("inherited")),
            "level": level,
        })
    return {
        "mode": _as_text(mode),
        "owner": _as_text(owner),
        "group": _as_text(group),
        "entries": entries,
    }


def _validated_dir(path: str) -> Path:
    try:
        raw = Path(str(path or ""))
    except ValueError as error:
        raise ShareAclError("shares.bad_path") from error
    if not raw.is_absolute():
        raise ShareAclError("shares.bad_path")
    try:
        resolved = raw.resolve(strict=True)
        is_dir = resolved.is_dir()
    except (OSError, ValueError, RuntimeError) as error:
        # Path.resolve() raises RuntimeError on a symlink loop.
        # is_dir() still raises EIO/ESTALE on a dying mount after resolve().
        raise ShareAclError("shares.bad_path") from error
    if not is_dir or resolved == Path("/"):
        raise ShareAclError("shares.bad_path")
    return resolved


def read_acl(path: str) -> dict:
    """ACL and ownership of *path* (validated absolute directory)."""
    resolved = _validated_dir(path)
    # _sh_call (_sh3 inside): a leftover subclass/impostor answer used to
    # blow this unpack itself — and a patched sh that *raises* blew the call
    # one token earlier — a raw 500 on GET and PUT /api/shares/acl before
    # any gate ran.
    rc, output, error = _sh_call([LS, "-lde", str(resolved)], timeout=8)
    # _rc_int: an rc-subclass ``__ne__`` bomb from a patched/odd ``sh`` used
    # to detonate this gate — a raw 500 on GET and PUT /api/shares/acl in
    # place of the coded read failure.  Junk rc reads as failure, and the
    # vanish classification below still needs the message marker plus the
    # fresh disk probe, so junk can never fake a vanished CLI.
    if _rc_int(rc) != 0:
        # An ls confirmed vanished by a fresh disk probe answers the coded
        # 503, not the 500 "the ACL could not be read" that blames the
        # directory.  Probe on this failure path only.
        # _pick, not ``or``: a leftover ``__bool__``-bomb stderr used to
        # detonate the truth test itself and 500 GET and PUT /api/shares/acl
        # past every coded refusal.
        lowered = _as_text(_pick(error, output)).lower()
        if any(marker in lowered for marker in _VANISH_MARKERS) and not _tool_on_disk(LS):
            raise ShareAclError("shares.acl_tool_missing")
        raise ShareAclError("shares.acl_read_failed")
    parsed = parse_acl_listing(output)
    try:
        stat = resolved.stat()
        owned = stat.st_uid == os.getuid()
    except OSError:
        owned = False
    return {
        "path": _as_text(resolved),
        **parsed,
        # Whether the panel process can edit without the admin password.
        "owned_by_panel": owned,
    }


def local_users() -> list[dict]:
    """macOS accounts that make sense in a share-access picker.

    ``dscl . -list /Users UniqueID`` names every record; service accounts
    (``_spotlight`` …) start with an underscore and real people start at
    uid 500 on macOS, so both filters together keep exactly the human set.
    """
    # _sh_call (_sh3 inside): a poisoned dscl answer used to raise out of
    # this unpack — and a raising patched sh out of the call itself — and
    # 500 GET /api/shares/acl through the picker half.
    rc, output, _ = _sh_call([DSCL, ".", "-list", "/Users", "UniqueID"], timeout=8)
    # _rc_int: an rc-``__ne__`` bomb used to raise out of this gate and 500
    # GET /api/shares/acl — the route reads the picker outside any try.
    if _rc_int(rc) != 0:
        return []
    users: list[dict] = []
    for line in _as_text(output).splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[0].startswith("_"):
            continue
        try:
            uid = int(parts[1])
        except (TypeError, ValueError, OverflowError):
            # Leftover UniqueID ``inf`` OverflowError'd GET /api/shares/acl.
            continue
        if uid < 500:
            continue
        username = parts[0]
        real_name = ""
        # _sh_call (_sh3 inside): one poisoned per-user RealName answer used
        # to blow the unpack — and one raising read the call itself — and
        # cost the whole picker as a raw 500.
        rc_name, name_out, _ = _sh_call(
            [DSCL, ".", "-read", f"/Users/{username}", "RealName"], timeout=5
        )
        # _rc_int: the same rc-``__eq__`` bomb class, per picked user — one
        # poisoned RealName read used to cost the whole picker as a raw 500.
        if _rc_int(rc_name) == 0:
            # Two shapes: "RealName: Alice" on one line, or the value alone on
            # the following line when it contains spaces.
            lines = [l.strip() for l in _as_text(name_out).splitlines() if l.strip()]
            if lines:
                first = lines[0]
                real_name = (
                    first.partition(":")[2].strip()
                    if first.lower().startswith("realname")
                    else first
                )
                if not real_name and len(lines) > 1:
                    real_name = lines[1]
        users.append({
            "username": _as_text(username),
            "uid": uid,
            "real_name": _as_text(real_name),
        })
    return sorted(users, key=lambda u: u["uid"])


def _validate_username(username: str) -> str:
    try:
        # A str() probe, not an isinstance gate: a numeric leftover keeps
        # behaving as its string form, while a >4300-digit *already-int*
        # (YAML/plist hex loads with int(x, 16), exempt from the int(str)
        # parse cap) earns the coded refusal instead of the digit-cap
        # ValueError a bare str() raises past the router.
        name = str(username or "").strip()
    except ValueError as error:
        raise ShareAclError("shares.acl_bad_user") from error
    if not _USERNAME_RE.match(name):
        raise ShareAclError("shares.acl_bad_user")
    known = {user["username"] for user in local_users()}
    if name not in known:
        # With dscl gone from disk, local_users() degrades to [] (the GET
        # keeps its ACL data and just shows an empty picker), so a
        # well-formed grant used to answer the 400 "unknown local macOS
        # user" — blaming the operator's pick for a vanished CLI.  Same
        # bar as routers/shares._share_directory's sharing_missing: the
        # fresh disk probe runs on this empty-listing failure path only,
        # and an honestly empty picker with dscl on disk keeps the
        # honest refusal.
        if not known and not _tool_on_disk(DSCL):
            raise ShareAclError("shares.acl_tool_missing")
        raise ShareAclError("shares.acl_bad_user")
    return name


def _removal_then_grant(entries: list[dict], username: str, level: str) -> list[list[str]]:
    """The chmod argv sequence replacing *username*'s direct entries.

    Removals go by index, highest first — each ``chmod -a#`` renumbers the
    entries below it, so ascending order would remove the wrong lines.
    Inherited entries are left alone: they belong to a parent directory.
    """
    commands: list[list[str]] = []
    indices = [
        entry["index"]
        for entry in entries
        if entry["kind"] == "user" and entry["name"] == username and not entry["inherited"]
    ]
    for index in sorted(indices, reverse=True):
        commands.append([CHMOD, "-a#", str(index), "__PATH__"])
    if level != "none":
        perms = _RW_PERMS if level == "readwrite" else _READ_PERMS
        commands.append([CHMOD, "+a", f"user:{username} allow {perms}", "__PATH__"])
    return commands


def _run_unprivileged(commands: list[list[str]]) -> dict:
    for command in commands:
        # ``capture_output=True`` used to keep chmod chatter in RAM for the
        # full timeout.  ``sh`` streams to a tempfile and already maps
        # timeout/OSError to rc=-1 instead of raising into the Shares page.
        # _sh_call (_sh3 inside): a poisoned chmod answer used to blow this
        # unpack itself — and a raising patched sh the call one token
        # earlier — a raw 500 on PUT /api/shares/acl on the owner-run path,
        # one line ahead of the failure funnel.
        rc, out, err = _sh_call(command, timeout=15)
        # _rc_int: an rc-``__ne__`` bomb used to blow this probe one line
        # ahead of the funnel that classifies the failure — a raw 500 on
        # PUT /api/shares/acl on the owner-run path.
        if _rc_int(rc) != 0:
            # int/bytes/date leftovers used to AttributeError ``.strip`` /
            # TypeError ``"denied" in bytes`` on PUT /api/shares/acl.
            # _pick, not ``or``: a ``__bool__``-bomb stderr used to raise out
            # of the fallback chain itself before _as_text could scrub it.
            message = _as_text(_pick(err, _pick(out, "failed"))).strip()[:200]
            lowered = message.lower()
            if "operation not permitted" in lowered or "permission denied" in lowered:
                return {"ok": False, "error": "needs_root", "message": message}
            return {"ok": False, "error": "failed", "message": message or "failed"}
    return {"ok": True}


def set_user_access(path: str, username: str, level: str) -> dict:
    """Replace *username*'s ACL entries on *path* with one canonical grant.

    Owner-run when the panel user owns the directory; otherwise through the
    web-password sudo path shared by every privileged share operation.  The
    result is read back and verified — the caller gets the state that is
    actually on disk, not an assumption.
    """
    if level not in LEVELS:
        raise ShareAclError("shares.acl_bad_level")
    resolved = _validated_dir(path)
    username = _validate_username(username)

    before = read_acl(str(resolved))
    template = _removal_then_grant(before["entries"], username, level)
    if not template:
        # Nothing to remove and nothing to add: "none" on a user with no entry.
        return {"ok": True, **read_acl(str(resolved))}
    commands = [
        [part if part != "__PATH__" else str(resolved) for part in command]
        for command in template
    ]

    # _admin_sequence (_plain_result inside): a raising leftover stub for
    # run_admin_sequence used to blow either escalation seam as a raw 500
    # on PUT /api/shares/acl, one token ahead of the answer launder.
    if before["owned_by_panel"]:
        result = _run_unprivileged(commands)
        if not result.get("ok") and result.get("error") == "needs_root":
            result = _admin_sequence(commands)
    else:
        result = _admin_sequence(commands)
    if not result.get("ok"):
        # _isa + _as_text, not a bare ``raw_error and``: the truth test
        # detonated a str-subclass ``__bool__`` bomb, and keeping the subclass
        # instance let an ``__eq__`` bomb blow the ``== "failed"`` probe below
        # (and the router's mapping lookup after it).  The unbound scrub reads
        # the real text underneath the override, so a bombed-but-legible
        # "cancelled" still earns its coded refusal instead of the generic one.
        # _isa, not isinstance: an error value whose ``__class__`` is a
        # raising property blew the gate itself and 500'd PUT /api/shares/acl
        # one line ahead of the scrub.
        raw_error = result.get("error")
        error = (_as_text(raw_error) if _isa(raw_error, str) else "") or "failed"
        # A chmod confirmed vanished by a fresh disk probe answers the coded
        # 503, not the generic 500 sharing failure.  Only the generic failure
        # shape is eligible — timeouts and authorization outcomes (cancelled,
        # password_required, …) keep their original shape.
        if error == "failed":
            raw_message = result.get("message")
            message = (_as_text(raw_message) if _truthy(raw_message) else "").lower()
            if any(marker in message for marker in _VANISH_MARKERS) and not _tool_on_disk(CHMOD):
                return {"ok": False, "error": "acl_tool_missing"}
        return {**result, "error": error}

    after = read_acl(str(resolved))
    granted = [
        entry
        for entry in after["entries"]
        if entry["kind"] == "user" and entry["name"] == username and not entry["inherited"]
    ]
    if level == "none":
        verified = not granted
    else:
        verified = any(
            entry["effect"] == "allow" and entry["level"] == level for entry in granted
        )
    if not verified:
        return {"ok": False, "error": "verification_failed"}
    return {"ok": True, **after}
