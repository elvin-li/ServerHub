"""PhotosHub integration — status + actions for the family photo pipeline.

Reads state produced by ~/PhotosHub scripts; never writes into the Apple
Photos library package. Mutations only invoke existing photoctl/scripts.
"""
from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HUB = Path.home() / "PhotosHub"
CFG_PATH = HUB / "config" / "config.json"
STATE = HUB / "state"
BIN_PHOTOCTL = HUB / "bin" / "photoctl"
SCRIPTS = HUB / "scripts"

ALLOWED_ACTIONS = {
    "status": ["status"],
    "originals": ["originals"],
    "sync": ["sync"],
    "doctor": ["doctor"],
    "panel": ["panel"],
    "inbox": ["inbox"],
    "delete-review": ["delete-review"],
    "cleanup": ["cleanup"],
    "external-backup": ["external-backup", "--once"],
    "backup": ["backup"],
    "enable-delete": ["enable-delete"],
    "enable-cleanup": ["enable-cleanup"],
    "configure-people": None,  # special: python script
}


def _load_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _cfg() -> dict:
    return _load_json(CFG_PATH, {}) or {}


def _immich_key() -> str:
    p = HUB / "config" / "immich_api_key"
    if p.exists():
        return p.read_text(encoding="utf-8").strip()
    return ""


def _immich_api(method: str, path: str, body: Any = None) -> Any:
    cfg = _cfg()
    base = (cfg.get("immich") or {}).get("base_url") or "http://127.0.0.1:2283"
    key = _immich_key()
    if not key:
        raise RuntimeError("immich_api_key missing")
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        base.rstrip("/") + path,
        data=data,
        method=method,
        headers={
            "x-api-key": key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read()
        return json.loads(raw) if raw else None


def status() -> dict:
    cfg = _cfg()
    originals = _load_json(STATE / "originals_status.json", {}) or {}
    bridge = _load_json(STATE / "bridge_status.json", {}) or {}
    delete = _load_json(STATE / "delete_review_status.json", {}) or {}
    cleanup = _load_json(STATE / "cleanup_status.json", {}) or {}
    backup = _load_json(STATE / "backup_status.json", {}) or {}
    external = _load_json(STATE / "external_backup_status.json", {}) or {}
    inventory = _load_json(STATE / "inventory_report.json", {}) or {}
    gates = cfg.get("gates") or {}
    gate_ready = bool(originals.get("gate_ready"))
    return {
        "ts": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "photoshub_ok": HUB.is_dir() and BIN_PHOTOCTL.is_file(),
        "originals": originals,
        "bridge": bridge,
        "delete_review": delete,
        "cleanup": cleanup,
        "backup": backup,
        "external_backup": external,
        "inventory": inventory,
        "gates": {
            "originals_ready": gate_ready,
            "allow_delete_channel": bool(gates.get("allow_delete_channel")) and gate_ready,
            "allow_cleanup": bool(gates.get("allow_cleanup")) and gate_ready,
            "force_fallback": bool((cfg.get("bridge") or {}).get("force_fallback", True)),
        },
        "links": {
            "immich": (cfg.get("immich") or {}).get("public_url") or "http://192.168.1.206:8282",
            "panel": "http://192.168.1.206:8283/",
            "handbook": str(HUB / "手册.md"),
        },
        "albums": {
            "pending_delete": (cfg.get("immich") or {}).get("album_pending_delete", "待删除"),
            "yuanbao": (cfg.get("immich") or {}).get("album_yuanbao", "元宝成长"),
            "erbao": (cfg.get("immich") or {}).get("album_erbao", "二宝成长"),
        },
    }


def pending_delete_assets(limit: int = 60) -> dict:
    """List assets currently in Immich album「待删除」."""
    cfg = _cfg()
    name = (cfg.get("immich") or {}).get("album_pending_delete", "待删除")
    albums = _immich_api("GET", "/api/albums") or []
    album = next((a for a in albums if a.get("albumName") == name), None)
    if not album:
        return {"album": name, "album_id": None, "assets": [], "count": 0}
    detail = _immich_api("GET", f"/api/albums/{album['id']}") or {}
    assets = detail.get("assets") or []
    out = []
    for a in assets[:limit]:
        out.append(
            {
                "id": a.get("id"),
                "originalFileName": a.get("originalFileName") or a.get("fileName"),
                "localDateTime": a.get("localDateTime") or a.get("fileCreatedAt"),
                "isArchived": a.get("isArchived"),
                "type": a.get("type"),
                "thumbHash": a.get("thumbhash") or a.get("thumbHash"),
            }
        )
    return {
        "album": name,
        "album_id": album["id"],
        "count": len(assets),
        "assets": out,
        "gated": not status()["gates"]["allow_delete_channel"],
    }


def remove_from_pending(ids: list[str]) -> dict:
    """Remove assets from Immich「待删除」without deleting files."""
    if not ids:
        return {"removed": 0}
    info = pending_delete_assets(limit=1)
    album_id = info.get("album_id")
    if not album_id:
        raise RuntimeError("pending album not found")
    _immich_api("DELETE", f"/api/albums/{album_id}/assets", {"ids": ids})
    return {"removed": len(ids), "album_id": album_id}


def run_action(action: str, timeout: int = 600) -> dict:
    if action not in ALLOWED_ACTIONS:
        raise ValueError(f"unknown action: {action}")
    env = os.environ.copy()
    env["PATH"] = f"{HUB / 'bin'}:{Path.home() / '.local/bin'}:/opt/homebrew/bin:" + env.get("PATH", "")

    if action == "configure-people":
        script = SCRIPTS / "configure_person_albums.py"
        cmd = ["/usr/bin/python3", str(script)]
    else:
        args = ALLOWED_ACTIONS[action]
        cmd = [str(BIN_PHOTOCTL), *args]

    started = datetime.now().astimezone().isoformat(timespec="seconds")
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            cwd=str(HUB),
        )
        return {
            "ok": r.returncode == 0,
            "action": action,
            "exit_code": r.returncode,
            "started": started,
            "stdout": (r.stdout or "")[-4000:],
            "stderr": (r.stderr or "")[-2000:],
            "status_after": status(),
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "action": action,
            "exit_code": -1,
            "started": started,
            "stdout": "",
            "stderr": f"timeout after {timeout}s",
            "status_after": status(),
        }


def recent_logs(name: str = "bridge", lines: int = 40) -> dict:
    log_dir = HUB / "logs"
    mapping = {
        "bridge": sorted(log_dir.glob("bridge-*.log")),
        "delete": [log_dir / "delete_review.log"],
        "cleanup": [log_dir / "cleanup.log"],
        "external": sorted(log_dir.glob("external-backup-*.log")),
        "errors": [log_dir / "errors.log"],
    }
    files = mapping.get(name) or []
    path = None
    for p in reversed(files):
        if p.exists():
            path = p
            break
    if not path:
        return {"name": name, "path": None, "lines": []}
    try:
        content = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception as e:
        return {"name": name, "path": str(path), "lines": [str(e)]}
    return {"name": name, "path": str(path), "lines": content[-lines:]}
