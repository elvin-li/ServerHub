"""PhotosHub integration — status + actions for the family photo pipeline.

Reads state produced by ~/PhotosHub scripts; never writes into the Apple
Photos library package. Mutations only invoke existing photoctl/scripts.
"""
from __future__ import annotations

import json
import os
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from hub.errors import api_error
from hub.http_guard import (
    RedirectRefused as _ImmichRedirect,
    local_http_origin,
    no_redirect_opener,
)
from hub.jobs import run_watchdog

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

#: Immich asset / album ids are UUIDs.  Anything else in a URL path is SSRF
#: or path injection, so the charset is hex + hyphen only.
_IMMICH_ID = re.compile(r"\A[0-9a-fA-F-]{8,64}\Z")
_IMMICH_OPENER = no_redirect_opener()


def installed() -> bool:
    """True when the operator's PhotosHub tree is actually on this Mac."""
    return HUB.is_dir() and BIN_PHOTOCTL.is_file()


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


def _public_href(raw: Any) -> str:
    """Operator-facing link: http(s) only, never javascript: or file:."""
    text = str(raw or "").strip()
    parts = urlsplit(text)
    if parts.scheme in ("http", "https") and parts.hostname:
        return text
    return ""


def _immich_base() -> str:
    """Immich API origin the panel is allowed to contact.

    The URL comes from the operator's PhotosHub config, so it is not a
    browser-supplied SSRF primitive — but a compromised or copy-pasted
    config must still not make the panel fetch the public internet or
    cloud metadata.  Decision is from the literal hostname, never DNS.
    """
    raw = str(((_cfg().get("immich") or {}).get("base_url") or "http://127.0.0.1:2283")).strip()
    origin = local_http_origin(raw)
    if not origin:
        raise api_error("photoshub.bad_immich_url")
    return origin


def _safe_id(value: Any) -> str:
    text = str(value or "").strip()
    if not _IMMICH_ID.fullmatch(text):
        raise api_error("photoshub.bad_ids")
    return text


def _immich_api(method: str, path: str, body: Any = None) -> Any:
    key = _immich_key()
    if not key:
        raise api_error("photoshub.key_missing")
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        _immich_base() + path,
        data=data,
        method=method,
        headers={
            "x-api-key": key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with _IMMICH_OPENER.open(req, timeout=30) as resp:
            raw = resp.read()
    except _ImmichRedirect:
        raise api_error("photoshub.bad_immich_url")
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
    immich = cfg.get("immich") or {}
    snap = {
        "ts": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "photoshub_ok": installed(),
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
            "immich": _public_href(immich.get("public_url")),
            "panel": _public_href((cfg.get("panel") or {}).get("url")),
            "handbook": "handbook.md" if (HUB / "handbook.md").is_file() else "",
        },
        "albums": {
            "pending_delete": immich.get("album_pending_delete") or "Pending Delete",
            "yuanbao": immich.get("album_yuanbao") or "",
            "erbao": immich.get("album_erbao") or "",
        },
    }
    return snap


def _delete_gated() -> bool:
    """True when the pending-delete channel is frozen (or originals are not ready)."""
    cfg = _cfg()
    originals = _load_json(STATE / "originals_status.json", {}) or {}
    gates = cfg.get("gates") or {}
    ready = bool(originals.get("gate_ready"))
    return not (bool(gates.get("allow_delete_channel")) and ready)


def _pending_album_name() -> str:
    return (_cfg().get("immich") or {}).get("album_pending_delete") or "Pending Delete"


def _pending_album_id(name: str) -> str | None:
    albums = _immich_api("GET", "/api/albums") or []
    album = next((a for a in albums if a.get("albumName") == name), None)
    if not album:
        return None
    return _safe_id(album.get("id"))


def pending_delete_assets(limit: int = 60) -> dict:
    """List assets currently in the Immich pending-delete album."""
    if not installed():
        raise api_error("photoshub.not_installed")
    name = _pending_album_name()
    album_id = _pending_album_id(name)
    if not album_id:
        return {"album": name, "album_id": None, "assets": [], "count": 0}
    detail = _immich_api("GET", f"/api/albums/{album_id}") or {}
    assets = detail.get("assets") or []
    out = []
    for a in assets[:limit]:
        asset_id = a.get("id")
        if not _IMMICH_ID.fullmatch(str(asset_id or "")):
            continue
        out.append(
            {
                "id": asset_id,
                "originalFileName": a.get("originalFileName") or a.get("fileName"),
                "localDateTime": a.get("localDateTime") or a.get("fileCreatedAt"),
                "isArchived": a.get("isArchived"),
                "type": a.get("type"),
                "thumbHash": a.get("thumbhash") or a.get("thumbHash"),
            }
        )
    return {
        "album": name,
        "album_id": album_id,
        "count": len(assets),
        "assets": out,
        "gated": _delete_gated(),
    }


def remove_from_pending(ids: list[str]) -> dict:
    """Remove assets from the Immich pending-delete album without deleting files."""
    if not installed():
        raise api_error("photoshub.not_installed")
    clean = [_safe_id(i) for i in ids if i]
    if not clean:
        raise api_error("photoshub.bad_ids")
    album_id = _pending_album_id(_pending_album_name())
    if not album_id:
        raise api_error("photoshub.album_missing")
    _immich_api("DELETE", f"/api/albums/{album_id}/assets", {"ids": clean})
    return {"removed": len(clean), "album_id": album_id}


def run_action(action: str, timeout: int = 600) -> dict:
    if action not in ALLOWED_ACTIONS:
        raise api_error("photoshub.bad_action", action=action)
    if not installed():
        raise api_error("photoshub.not_installed")

    env = os.environ.copy()
    env["PATH"] = f"{HUB / 'bin'}:{Path.home() / '.local/bin'}:/opt/homebrew/bin:" + env.get("PATH", "")

    if action == "configure-people":
        script = SCRIPTS / "configure_person_albums.py"
        if not script.is_file():
            raise api_error("photoshub.script_missing")
        cmd = ["/usr/bin/python3", str(script)]
    else:
        args = ALLOWED_ACTIONS[action]
        cmd = [str(BIN_PHOTOCTL), *args]

    started = datetime.now().astimezone().isoformat(timespec="seconds")
    log: list[str] = []
    rc = run_watchdog(cmd, timeout=timeout, log=log, env=env, cwd=str(HUB))
    output = "\n".join(log)
    return {
        "ok": rc == 0,
        "action": action,
        "exit_code": rc,
        "started": started,
        "stdout": output[-4000:],
        "stderr": "" if rc == 0 else output[-2000:],
        "status_after": status(),
    }


def recent_logs(name: str = "bridge", lines: int = 40) -> dict:
    if not installed():
        return {"name": name, "path": None, "lines": []}
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
