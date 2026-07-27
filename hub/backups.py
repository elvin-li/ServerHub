"""Backup helpers: list artifacts + run common backup jobs."""
from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

from hub.config import cfg
from hub.paths import BASE

BACKUP_ROOT = Path.home() / "Services" / "backups"
BACKUP_ROOT.mkdir(parents=True, exist_ok=True)


def list_backups(limit: int = 40) -> list:
    items = []
    roots = [
        BACKUP_ROOT,
        Path.home() / "Services" / "teslamate" / "backups",
        BASE / "data",
    ]
    for root in roots:
        if not root.is_dir():
            continue
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            name = p.name
            if not (
                p.suffix in (".bak", ".sql", ".gz", ".tgz", ".zip")
                or ".bak." in name
                or name.endswith(".sql.bak")
            ):
                continue
            try:
                st = p.stat()
                items.append({
                    "path": str(p),
                    "name": name,
                    "dir": str(p.parent),
                    "size_mb": round(st.st_size / 1024 / 1024, 2),
                    "mtime": int(st.st_mtime),
                })
            except OSError:
                pass
    items.sort(key=lambda x: x["mtime"], reverse=True)
    return items[:limit]


def backup_postgres() -> dict:
    """Dump TeslaMate DB (native PG17)."""
    stamp = time.strftime("%Y%m%d_%H%M%S")
    dest = BACKUP_ROOT / f"teslamate_{stamp}.sql.bak"
    dest.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env.update({
        k: str(v)
        for k, v in ((cfg().get("settings") or {}).get("maintenance_env") or {}).items()
    })
    env.setdefault("PGPASSWORD", os.environ.get("PGPASSWORD", "teslamate_secret"))
    cmd = [
        "pg_dump", "-h", "localhost", "-U", "teslamate", "-d", "teslamate",
        "-F", "c", "-b", "-f", str(dest),
    ]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=600, env=env)
        ok = p.returncode == 0 and dest.exists()
        return {
            "ok": ok,
            "path": str(dest) if ok else None,
            "message": (p.stdout or p.stderr or f"exit {p.returncode}")[:500],
            "size_mb": round(dest.stat().st_size / 1024 / 1024, 2) if ok else 0,
        }
    except Exception as e:
        return {"ok": False, "message": str(e)}


def backup_configs() -> dict:
    """Tar key configs into Services/backups."""
    stamp = time.strftime("%Y%m%d_%H%M%S")
    dest = BACKUP_ROOT / f"configs_{stamp}.tgz"
    paths = [
        BASE / "services.yaml",
        Path.home() / "Services" / "teslamate" / "docker-compose.yml",
        Path.home() / "Services" / "music-assistant" / "docker-compose.yml",
    ]
    # include launchagents selectively
    agents = Path.home() / "Library" / "LaunchAgents"
    if agents.is_dir():
        for pl in agents.glob("*.plist"):
            if any(x in pl.name for x in ("elvin", "homeassistant", "kidsmusic", "filebrowser", "onedrive", "gravity", "cloudflare")):
                paths.append(pl)
    existing = [str(p) for p in paths if p.exists()]
    if not existing:
        return {"ok": False, "message": "no files to backup"}
    try:
        p = subprocess.run(
            ["tar", "czf", str(dest)] + existing,
            capture_output=True,
            text=True,
            timeout=120,
        )
        ok = p.returncode == 0 and dest.exists()
        return {
            "ok": ok,
            "path": str(dest) if ok else None,
            "message": (p.stderr or p.stdout or "")[:500] or ("ok" if ok else "fail"),
            "size_mb": round(dest.stat().st_size / 1024 / 1024, 2) if ok else 0,
        }
    except Exception as e:
        return {"ok": False, "message": str(e)}
