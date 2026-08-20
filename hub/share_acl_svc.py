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


def _as_text(value) -> str:
    """``sh`` leftovers arrive as int/None/bytes; leftover ``\\ud800`` used to 500 GET /api/shares/acl."""
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    elif value is None:
        return ""
    else:
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


class ShareAclError(Exception):
    """Validation failure with a stable API error code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


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
        perms = [p for p in match.group("perms").split(",") if p]
        level = None
        if match.group("effect") == "allow":
            level = "readwrite" if any(p in _WRITE_TOKENS for p in perms) else "read"
        entries.append({
            "index": int(match.group("index")),
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
    name = str(username or "").strip()
    if not _USERNAME_RE.match(name):
        raise ShareAclError("shares.acl_bad_user")
    known = {user["username"] for user in local_users()}
    if name not in known:
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
            message = _as_text(err or out or "failed").strip()[:200]
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
            result = macos_admin.run_admin_sequence(commands)
    else:
        result = macos_admin.run_admin_sequence(commands)
    if not result.get("ok"):
        return {**result, "error": result.get("error") or "failed"}

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
