"""Central log tail from configured sources."""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import HTTPException

from hub.config import cfg
from hub import files_svc


def _log_path_allowed(path: Path) -> bool:
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path
    return not files_svc.is_protected(path) and not files_svc.is_protected(resolved)


def _open_log_readonly(path: Path):
    """Open a log file without following a planted leaf symlink."""
    if path.is_symlink():
        raise HTTPException(403, "symlink log path refused")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as e:
        raise HTTPException(403, f"cannot open log: {e.strerror}") from e
    return os.fdopen(fd, "rb")


def log_sources() -> list:
    sources = cfg().get("log_sources") or []
    if not sources:
        # defaults
        home = Path.home()
        sources = [
            {"id": "autostart", "name": "开机自启", "path": str(home / "Library/Logs/server-autostart.log")},
            {"id": "serverhub", "name": "ServerHub", "path": str(home / "Library/Logs/serverhub.err.log")},
            {"id": "ha", "name": "Home Assistant", "path": str(home / "Services/homeassistant/config/home-assistant.log")},
        ]
    out = []
    for s in sources:
        p = Path(os.path.expanduser(s["path"]))
        if not _log_path_allowed(p):
            continue
        if p.is_symlink():
            continue
        exists = p.is_file()
        size = 0
        if exists:
            try:
                size = p.stat().st_size
            except OSError:
                exists = False
        out.append({
            "id": s["id"],
            "name": s.get("name", s["id"]),
            "path": str(p),
            "exists": exists,
            "size": size,
        })
    return out


def tail_log(source_id: str, lines: int = 200) -> dict:
    sources = {s["id"]: s for s in log_sources()}
    if source_id not in sources:
        raise HTTPException(404, "unknown log source")
    meta = sources[source_id]
    p = Path(meta["path"])
    if not _log_path_allowed(p):
        raise HTTPException(403, "protected log path")
    if p.is_symlink() or not p.is_file():
        return {"id": source_id, "name": meta["name"], "path": meta["path"],
                "exists": False, "log": "（文件不存在）", "lines": 0}
    lines = max(10, min(int(lines), 2000))
    # efficient tail
    try:
        with _open_log_readonly(p) as f:
            f.seek(0, 2)
            size = f.tell()
            block = 4096
            data = b""
            while size > 0 and data.count(b"\n") <= lines:
                step = min(block, size)
                size -= step
                f.seek(size)
                data = f.read(step) + data
            text = data.decode("utf-8", errors="replace")
            parts = text.splitlines()[-lines:]
            return {"id": source_id, "name": meta["name"], "path": meta["path"],
                    "exists": True, "log": "\n".join(parts), "lines": len(parts)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))
