"""Backup helpers: list artifacts + run common backup jobs."""
from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

from hub import secure_io
from hub.config import cfg
from hub.paths import CONFIG_FILE, DATA_DIR

BACKUP_ROOT = Path.home() / "Services" / "backups"
# 0700, not the umask default: a config backup contains services.yaml verbatim,
# which holds the admin password hash and any tunnel/API tokens, and a database
# dump contains whatever the database holds.  The originals are 0600, so leaving
# the copies at 0644 in a traversable directory handed every other local account
# the exact secrets the originals protect.
secure_io.make_secret_dir(BACKUP_ROOT)


def _private_dest(dest: Path) -> Path:
    """Pre-create ``dest`` as an owner-only file before a tool writes into it.

    ``tar`` and ``pg_dump`` open the output with O_CREAT|O_TRUNC, which keeps the
    mode of a file that already exists.  Creating it 0600 up front therefore
    means the archive is never readable by anyone else, not even briefly --
    chmod'ing after the command finishes would leave the whole dump window open.

    Callers must judge success by :func:`_written_bytes` rather than by the file
    existing, because after this the file always exists.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.close(os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600))
        os.chmod(dest, 0o600)
    except OSError:
        pass
    return dest


def _written_bytes(dest: Path) -> int:
    """Size of a produced archive, or 0 when it is missing or still empty."""
    try:
        return dest.stat().st_size
    except OSError:
        return 0


def _discard(dest: Path) -> None:
    """Remove the pre-created placeholder after a failed run."""
    try:
        dest.unlink()
    except OSError:
        pass


def list_backups(limit: int = 40) -> list:
    items = []
    roots = [
        BACKUP_ROOT,
        Path.home() / "Services" / "teslamate" / "backups",
        DATA_DIR,
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
    dest = _private_dest(BACKUP_ROOT / f"teslamate_{stamp}.sql.bak")
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
        # Size, not existence: the destination was pre-created 0600 so pg_dump
        # could not publish it, which means it exists even when the dump failed.
        size = _written_bytes(dest)
        ok = p.returncode == 0 and size > 0
        if not ok:
            _discard(dest)
        return {
            "ok": ok,
            "path": str(dest) if ok else None,
            "message": (p.stdout or p.stderr or f"exit {p.returncode}")[:500],
            "size_mb": round(size / 1024 / 1024, 2) if ok else 0,
        }
    except Exception as e:
        _discard(dest)
        return {"ok": False, "message": str(e)}


def backup_configs() -> dict:
    """Tar key configs into Services/backups."""
    stamp = time.strftime("%Y%m%d_%H%M%S")
    dest = BACKUP_ROOT / f"configs_{stamp}.tgz"
    paths = [
        CONFIG_FILE,
        Path.home() / "Services" / "teslamate" / "docker-compose.yml",
        Path.home() / "Services" / "music-assistant" / "docker-compose.yml",
    ]
    # include launchagents selectively
    agents = Path.home() / "Library" / "LaunchAgents"
    if agents.is_dir():
        for pl in agents.glob("*.plist"):
            if any(x in pl.name for x in ("serverhub", "homeassistant", "filebrowser", "onedrive", "cloudflare")):
                paths.append(pl)
    existing = [str(p) for p in paths if p.exists()]
    if not existing:
        return {"ok": False, "message": "no files to backup"}
    # Only now that there is something to archive, so a no-op call does not leave
    # an empty placeholder behind in the backup listing.
    _private_dest(dest)
    try:
        p = subprocess.run(
            ["tar", "czf", str(dest)] + existing,
            capture_output=True,
            text=True,
            timeout=120,
        )
        # This archive contains services.yaml, so judge success by size: the
        # placeholder always exists after _private_dest.
        size = _written_bytes(dest)
        ok = p.returncode == 0 and size > 0
        if not ok:
            _discard(dest)
        return {
            "ok": ok,
            "path": str(dest) if ok else None,
            "message": (p.stderr or p.stdout or "")[:500] or ("ok" if ok else "fail"),
            "size_mb": round(size / 1024 / 1024, 2) if ok else 0,
        }
    except Exception as e:
        _discard(dest)
        return {"ok": False, "message": str(e)}
