"""macOS users listing (Unraid Users page equivalent — read-oriented)."""
from __future__ import annotations

import os
import pwd
import grp
import re

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")


def _isa(value, kinds) -> bool:
    """``isinstance`` that a leftover ``__class__``-property bomb cannot blow.

    ``isinstance`` consults ``value.__class__`` when the exact-type check
    misses, so a leftover Open Directory field whose ``__class__`` is a
    *raising property* detonated ``_pwd_text``'s bytes gate itself — planted
    as ``pw_name`` / ``pw_shell`` / ``pw_dir`` / ``pw_gecos``, the raise rode
    into the walk's outer catch and silently wiped every healthy pwd row
    after the poisoned one (the logs9 / share_acl rule, at row rank).  A
    real subclass still matches through the C-level type check; only a
    value that cannot answer what it is takes the non-matching branch.
    """
    try:
        return isinstance(value, kinds)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _pwd_text(value) -> str:
    """JSON-encodable pwd/grp field.  Leftover bytes / ``\\ud800`` used to 500 GET /api/users."""
    if value is None:
        return ""
    for base in (bytes, bytearray):
        try:
            return base.decode(value, "utf-8", "replace")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
    try:
        return str.encode(str.__str__(value), "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        pass
    try:
        cls = type(value)
        if cls.__str__ is object.__str__ and cls.__repr__ is object.__repr__:
            return ""
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    try:
        text = str(value)
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
    try:
        text = str.encode(text, "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    return "" if _ADDR_REPR_RE.search(text) else text


def _user_row(u, seen: set):
    """One pwd record as its JSON row, or ``None`` for a filtered row.

    Split out of the walk so the caller can give each record its own catch:
    any raise here costs the poisoned row only, never the healthy rows after
    it (the users5/users7 "a poisoned Open Directory value costs itself
    only" rule, at row rank).
    """
    try:
        uid = int(u.pw_uid)
        gid = int(u.pw_gid)
        # An *already-int* id past CPython's int->str digit cap
        # sails through int() (no string conversion happens) and
        # only exploded later, at Starlette's json.dumps — one
        # poisoned Open Directory record 500'd GET /api/users for
        # every healthy row.  The str() probe reuses this except.
        str(uid)
        str(gid)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # Broad, not (TypeError, ValueError, OverflowError,
        # AttributeError): a leftover int-subclass id whose
        # ``__int__``/``__index__`` raises something else used to
        # escape into the walk's mid-iteration catch and silently
        # wipe every healthy row after (and including) the poisoned
        # one.  A row whose ids are unanswerable costs itself only.
        return None
    name = _pwd_text(getattr(u, "pw_name", ""))
    if not name:
        return None
    if uid < 500 and name not in ("root",):
        return None
    if name in ("nobody", "daemon", "null"):
        return None
    key = (name, uid)
    if key in seen:
        return None
    seen.add(key)
    shell = _pwd_text(getattr(u, "pw_shell", ""))
    if shell in ("/usr/bin/false", "/bin/false", "/usr/sbin/nologin") and uid != 0:
        if uid < 500:
            return None
    groups = []
    is_admin = uid == 0
    try:
        gids = os.getgrouplist(name, gid)
        for g in gids:
            try:
                gn = _pwd_text(grp.getgrgid(g).gr_name)
                groups.append(gn)
                if gn in ("admin", "wheel"):
                    is_admin = True
            except _CONTROL_FLOW:
                raise
            except BaseException:
                # Broad, not (KeyError, OSError, TypeError,
                # OverflowError): a leftover Open Directory gid whose
                # getgrgid lookup raises something else — a RuntimeError
                # from an int-subclass ``__index__`` / ``__hash__``, an
                # AttributeError on a struct missing ``gr_name`` —
                # escaped into the outer catch and aborted the *whole*
                # membership walk.  Every group after the poisoned gid
                # was dropped and the ``admin``/``wheel`` classification
                # silently flipped off (the users7 "a poisoned id costs
                # itself only" rule at group rank).  One unanswerable
                # gid now costs only its own entry.
                pass
    except _CONTROL_FLOW:
        raise
    except BaseException:
        pass
    return {
        "name": name,
        "uid": uid,
        "gid": gid,
        "home": _pwd_text(getattr(u, "pw_dir", "")),
        "shell": shell,
        "gecos": _pwd_text(getattr(u, "pw_gecos", "")).split(",")[0],
        "admin": is_admin,
        "groups": groups[:12],
    }


def list_users() -> list:
    """Local users with login shells / admin group membership."""
    admin_gids = set()
    try:
        admin_gids.add(grp.getgrnam("admin").gr_gid)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # Broad, not (KeyError, OSError, TypeError): a leftover int-subclass
        # gr_gid whose ``__hash__`` raises detonated ``set.add`` itself and
        # 500'd GET /api/users before the first pwd row was even read.
        pass
    try:
        admin_gids.add(grp.getgrnam("staff").gr_gid)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        pass
    # dscl for UniqueID >= 500 typically; macOS can emit duplicate root via OD
    users = []
    seen = set()
    try:
        entries = pwd.getpwall()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # Open Directory leftover KeyError / TypeError / EIO used to 500
        # GET /api/users.  Same bar as getgrouplist below.
        return []
    try:
        iterator = iter(entries)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # Not just TypeError: a directory-service handle that dies *at* the
        # start of the walk raises OSError(EIO) from __iter__ — one step
        # earlier than the mid-iteration death below — and used to 500
        # GET /api/users instead of answering the empty page.
        return []
    try:
        for u in iterator:
            try:
                row = _user_row(u, seen)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                # Per-row catch, one rank inside the mid-iteration one below:
                # a poisoned Open Directory *field* — a getattr property
                # raising EIO, anything ``_user_row``'s own nets miss — used
                # to escape into the walk-level catch and silently wipe every
                # healthy row after the poisoned one.  A hostile row costs
                # itself only.
                continue
            if row is not None:
                users.append(row)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # Directory Service dying mid-iteration used to 500 the page
        # instead of returning the rows already collected.
        pass
    users.sort(key=lambda x: (0 if x["name"] == "root" else 1, x["uid"]))
    return users


def overview() -> dict:
    try:
        users = list_users()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        users = []
    if not _isa(users, list):
        users = []
    count = 0
    admins = 0
    kept = []
    for row in users:
        try:
            if not _isa(row, dict):
                continue
            kept.append(row)
            count += 1
            if row.get("admin"):
                admins += 1
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
    return {
        "users": kept,
        "count": count,
        "admins": admins,
        "hint": "Read-only list of macOS users; add or remove them in System Settings → Users & Groups",
    }
