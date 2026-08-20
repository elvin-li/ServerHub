"""macOS users listing (Unraid Users page equivalent — read-oriented)."""
from __future__ import annotations

import os
import pwd
import grp


def _pwd_text(value) -> str:
    """JSON-encodable pwd/grp field.  Leftover bytes / ``\\ud800`` used to 500 GET /api/users."""
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    elif value is None:
        value = ""
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


def list_users() -> list:
    """Local users with login shells / admin group membership."""
    admin_gids = set()
    try:
        admin_gids.add(grp.getgrnam("admin").gr_gid)
    except (KeyError, OSError, TypeError):
        pass
    try:
        admin_gids.add(grp.getgrnam("staff").gr_gid)
    except (KeyError, OSError, TypeError):
        pass
    # dscl for UniqueID >= 500 typically; macOS can emit duplicate root via OD
    users = []
    seen = set()
    try:
        entries = pwd.getpwall()
    except Exception:
        # Open Directory leftover KeyError / TypeError / EIO used to 500
        # GET /api/users.  Same bar as getgrouplist below.
        return []
    try:
        iterator = iter(entries)
    except TypeError:
        return []
    try:
        for u in iterator:
            try:
                uid = int(u.pw_uid)
                gid = int(u.pw_gid)
            except (TypeError, ValueError, OverflowError, AttributeError):
                continue
            name = _pwd_text(getattr(u, "pw_name", ""))
            if not name:
                continue
            if uid < 500 and name not in ("root",):
                continue
            if name in ("nobody", "daemon", "null"):
                continue
            key = (name, uid)
            if key in seen:
                continue
            seen.add(key)
            shell = _pwd_text(getattr(u, "pw_shell", ""))
            if shell in ("/usr/bin/false", "/bin/false", "/usr/sbin/nologin") and uid != 0:
                if uid < 500:
                    continue
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
                    except (KeyError, OSError, TypeError, OverflowError):
                        pass
            except Exception:
                pass
            users.append({
                "name": name,
                "uid": uid,
                "gid": gid,
                "home": _pwd_text(getattr(u, "pw_dir", "")),
                "shell": shell,
                "gecos": _pwd_text(getattr(u, "pw_gecos", "")).split(",")[0],
                "admin": is_admin,
                "groups": groups[:12],
            })
    except Exception:
        # Directory Service dying mid-iteration used to 500 the page
        # instead of returning the rows already collected.
        pass
    users.sort(key=lambda x: (0 if x["name"] == "root" else 1, x["uid"]))
    return users


def overview() -> dict:
    users = list_users()
    return {
        "users": users,
        "count": len(users),
        "admins": sum(1 for u in users if u["admin"]),
        "hint": "Read-only list of macOS users; add or remove them in System Settings → Users & Groups",
    }
