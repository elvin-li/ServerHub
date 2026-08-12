"""Central log tail from configured sources."""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import HTTPException

from hub.config import cfg


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
        out.append({
            "id": s["id"],
            "name": s.get("name", s["id"]),
            "path": str(p),
            "exists": p.is_file(),
            "size": p.stat().st_size if p.is_file() else 0,
        })
    return out


def tail_log(source_id: str, lines: int = 200) -> dict:
    sources = {s["id"]: s for s in log_sources()}
    if source_id not in sources:
        raise HTTPException(404, "unknown log source")
    meta = sources[source_id]
    p = Path(meta["path"])
    if not p.is_file():
        return {"id": source_id, "name": meta["name"], "path": meta["path"],
                "exists": False, "log": "(file does not exist)", "lines": 0}
    lines = max(10, min(int(lines), 2000))
    # efficient tail
    try:
        with open(p, "rb") as f:
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
    except Exception as e:
        raise HTTPException(500, str(e))
