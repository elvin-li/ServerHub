"""macOS users listing (Unraid Users page equivalent — read-oriented)."""
from __future__ import annotations

import os
import pwd
import grp



def list_users() -> list:
    """Local users with login shells / admin group membership."""
    admin_gids = set()
    try:
        admin_gids.add(grp.getgrnam("admin").gr_gid)
    except KeyError:
        pass
    try:
        admin_gids.add(grp.getgrnam("staff").gr_gid)
    except KeyError:
        pass
    # dscl for UniqueID >= 500 typically; macOS can emit duplicate root via OD
    users = []
    seen = set()
    for u in pwd.getpwall():
        if u.pw_uid < 500 and u.pw_name not in ("root",):
            continue
        if u.pw_name in ("nobody", "daemon", "null"):
            continue
        key = (u.pw_name, u.pw_uid)
        if key in seen:
            continue
        seen.add(key)
        shell = u.pw_shell or ""
        if shell in ("/usr/bin/false", "/bin/false", "/usr/sbin/nologin") and u.pw_uid != 0:
            if u.pw_uid < 500:
                continue
        groups = []
        is_admin = u.pw_uid == 0
        try:
            gids = os.getgrouplist(u.pw_name, u.pw_gid)
            for g in gids:
                try:
                    gn = grp.getgrgid(g).gr_name
                    groups.append(gn)
                    if gn in ("admin", "wheel"):
                        is_admin = True
                except KeyError:
                    pass
        except Exception:
            pass
        users.append({
            "name": u.pw_name,
            "uid": u.pw_uid,
            "gid": u.pw_gid,
            "home": u.pw_dir,
            "shell": shell,
            "gecos": (u.pw_gecos or "").split(",")[0],
            "admin": is_admin,
            "groups": groups[:12],
        })
    users.sort(key=lambda x: (0 if x["name"] == "root" else 1, x["uid"]))
    return users


def overview() -> dict:
    users = list_users()
    return {
        "users": users,
        "count": len(users),
        "admins": sum(1 for u in users if u["admin"]),
        "hint": "macOS 用户只读列表；增删请用「系统设置 → 用户与群组」",
    }
