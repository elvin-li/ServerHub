"""macOS file shares (SMB via sharing -l) + configured file services."""
from __future__ import annotations


from hub.config import cfg
from hub.host_address import host_ip, resolve_value
from hub.util import port_open, sh


def _field_value(line: str, key: str) -> str | None:
    """Parse 'key: value' lines; macOS sharing -l uses tabs and curly quotes."""
    s = line.strip()
    prefix = key + ":"
    if not s.startswith(prefix):
        return None
    val = s[len(prefix):].strip().lstrip("\t ")
    # strip wrapping quotes (straight or curly)
    if len(val) >= 2 and val[0] in "\"“'" and val[-1] in "\"”'":
        val = val[1:-1]
    return val


def list_smb_shares() -> list:
    rc, out, err = sh(["sharing", "-l"], timeout=8)
    if rc != 0:
        return []
    shares = []
    current = None
    in_smb = False
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("name:") and not in_smb:
            name = _field_value(line, "name")
            # macOS may emit name:“user”的公共文件夹 (quotes only around user)
            raw = line.split(":", 1)[1].strip().lstrip("\t ") if ":" in line else name
            if current:
                shares.append(current)
            current = {"name": raw or name, "path": None, "smb_name": None,
                       "shared": None, "guest": None, "readonly": None}
            in_smb = False
            continue
        if not current:
            continue
        if s.startswith("path:"):
            current["path"] = _field_value(line, "path")
        elif s.startswith("smb:"):
            in_smb = True
        elif in_smb and s.startswith("}"):
            in_smb = False
        elif in_smb:
            if s.startswith("name:"):
                raw = line.split(":", 1)[1].strip().lstrip("\t ") if ":" in line else ""
                current["smb_name"] = raw
            elif s.startswith("shared:"):
                current["shared"] = s.split(":", 1)[1].strip() in ("1", "true", "yes")
            elif s.startswith("guest access:"):
                current["guest"] = s.split(":", 1)[1].strip() in ("1", "true", "yes")
            elif s.startswith("read-only:"):
                current["readonly"] = s.split(":", 1)[1].strip() in ("1", "true", "yes")
    if current:
        shares.append(current)
    return shares


def file_services() -> list:
    """Configured file-related services from status-like config."""
    services = []
    # from quick_links + known ports
    known = [
        {"id": "filebrowser", "name": "FileBrowser", "port": 8125, "url": None},
        {"id": "onedrive-share", "name": "OneDrive Share", "port": 8281, "url": None},
    ]
    host = host_ip()
    links = {
        link["name"]: link["url"]
        for link in resolve_value(cfg().get("quick_links") or [])
    }
    for k in known:
        if k["name"] in links:
            k["url"] = links[k["name"]]
        else:
            k["url"] = f"http://{host}:{k['port']}"
        up = port_open(k["port"])
        k["state"] = "ok" if up else "down"
        k["detail"] = f"端口 :{k['port']} " + ("可达" if up else "不可达")
        services.append(k)
    return services


def _dir_size_mb(path: str) -> float | None:
    """Shallow size estimate for a path (du -sm)."""
    import os
    p = os.path.expanduser(path)
    if not os.path.isdir(p):
        return None
    rc, out, _ = sh(["/usr/bin/du", "-sm", p], timeout=15)
    if rc != 0 or not out:
        return None
    try:
        return float(out.split()[0])
    except (ValueError, IndexError):
        return None


def shares_overview() -> dict:
    smb = list_smb_shares()
    for s in smb:
        if s.get("path"):
            s["size_mb"] = _dir_size_mb(s["path"])
    return {
        "smb": smb,
        "services": file_services(),
        "hint": "完整 SMB 增删请使用「系统设置 → 通用 → 共享」",
    }
