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
    """
    try:
        return isinstance(value, kinds)
    except Exception:
        return False


def _as_text(value) -> str:
    """``sh`` leftovers arrive as int/None/bytes; leftover ``\\ud800`` used to 500 GET /api/shares/acl."""
    if _isa(value, (bytes, bytearray)):
        # Unbound base decode (the brew6 rule): a leftover bytes-subclass
        # whose bound ``.decode`` raises used to escape read_acl untyped and
        # 500 GET /api/shares/acl past the share gate.  _isa + try-wrap: a
        # *lying* ``__class__`` impostor passes the bytes gate but is no
        # bytes underneath, and the unbound call's TypeError used to 500
        # GET /api/shares/acl (parse_acl_listing / local_users) and PUT's
        # failure funnel — fall through to the str() rank so a legible
        # impostor still renders instead of costing the route.
        base = bytes if _isa(value, bytes) else bytearray
        try:
            value = base.decode(value, "utf-8", "replace")
        except Exception:
            pass
    if value is None:
        return ""
    if type(value) is not str:
        try:
            value = str(value)
        except RecursionError:
            try:
                return type(value).__name__
            except Exception:
                return ""
        except Exception:
            return ""
    # Unbound base encode (the modules6 rule): ``str()`` of a subclass whose
    # ``__str__`` answers *self* skips CPython's exact-str copy, so a leftover
    # bound ``encode`` bomb in sh output rode this line to a raw 500 on GET
    # and PUT /api/shares/acl (read_acl, local_users and the failure funnels).
    return str.encode(value, "utf-8", "replace").decode("utf-8")


def _truthy(value) -> bool:
    """``bool(value)`` that survives a leftover ``__bool__`` bomb (fails False)."""
    try:
        return bool(value)
    except Exception:
        return False


def _pick(value, fallback):
    """``value or fallback`` that a leftover ``__bool__`` bomb cannot 500."""
    return value if _truthy(value) else fallback


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
            plain = dict(result)
        except Exception:
            return {"ok": False, "error": "failed"}
    else:
        return {"ok": False, "error": "failed"}
    plain["ok"] = _truthy(plain.get("ok"))
    return plain


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
    rc, output, error = sh([LS, "-lde", str(resolved)], timeout=8)
    if rc != 0:
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
    rc, output, _ = sh([DSCL, ".", "-list", "/Users", "UniqueID"], timeout=8)
    if rc != 0:
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
        rc_name, name_out, _ = sh(
            [DSCL, ".", "-read", f"/Users/{username}", "RealName"], timeout=5
        )
        if rc_name == 0:
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
        rc, out, err = sh(command, timeout=15)
        if rc != 0:
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

    if before["owned_by_panel"]:
        result = _run_unprivileged(commands)
        if not result.get("ok") and result.get("error") == "needs_root":
            result = _plain_result(macos_admin.run_admin_sequence(commands))
    else:
        result = _plain_result(macos_admin.run_admin_sequence(commands))
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
