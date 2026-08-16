"""Central log tail from configured sources."""
from __future__ import annotations

import os
from pathlib import Path

from hub import cli_args, files_svc
from hub.config import cfg
from hub.errors import api_error


def _log_path_allowed(path: Path) -> bool:
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path
    return not files_svc.is_protected(path) and not files_svc.is_protected(resolved)


def log_sources() -> list:
    sources = cfg().get("log_sources") or []
    if not sources:
        # defaults
        home = Path.home()
        sources = [
            {"id": "autostart", "name": "Autostart", "path": str(home / "Library/Logs/server-autostart.log")},
            {"id": "serverhub", "name": "ServerHub", "path": str(home / "Library/Logs/serverhub.err.log")},
            {"id": "ha", "name": "Home Assistant", "path": str(home / "Services/homeassistant/config/home-assistant.log")},
        ]
    out = []
    for s in sources:
        p = Path(os.path.expanduser(s["path"]))
        if not _log_path_allowed(p):
            continue
        out.append({
            "id": s["id"],
            "name": s.get("name", s["id"]),
            "path": str(p),
            "exists": p.is_file(),
            "size": p.stat().st_size if p.is_file() else 0,
        })
    return out


def tail_log(source_id: str, lines: int = 200) -> dict:
    source_id = cli_args.require_positional(source_id, label="log source")
    sources = {s["id"]: s for s in log_sources()}
    if source_id not in sources:
        raise api_error("logs.unknown_source")
    meta = sources[source_id]
    p = Path(meta["path"])
    if not _log_path_allowed(p):
        raise api_error("logs.protected")
    if not p.is_file():
        return {"id": source_id, "name": meta["name"], "path": meta["path"],
                "exists": False, "size": 0, "log": "(file does not exist)", "lines": 0}
    lines = max(10, min(int(lines), 2000))
    # efficient tail
    try:
        with open(p, "rb") as f:
            f.seek(0, 2)
            file_size = f.tell()
            size = file_size
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
                    "exists": True, "size": file_size, "log": "\n".join(parts),
                    "lines": len(parts)}
    except Exception:
        raise api_error("logs.read_failed")
