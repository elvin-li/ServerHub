"""PhotosHub integration — status + actions for the family photo pipeline.

Reads state produced by ~/PhotosHub scripts; never writes into the Apple
Photos library package. Mutations invoke existing photoctl/scripts, or
patch operator-facing fields in config.json (names, album titles, URLs).
"""
from __future__ import annotations

import json
import os
import re
import threading
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from hub import secure_io
from hub.errors import api_error
from hub.http_guard import (
    RedirectRefused as _ImmichRedirect,
    local_http_origin,
    no_redirect_opener,
)
from hub.jobs import run_watchdog
from hub.util import tail_file_lines

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
_NAME = re.compile(r"\A[^\x00-\x1f\x7f]{1,40}\Z")
_ALBUM = re.compile(r"\A[^\x00-\x1f\x7f/\\]{0,80}\Z")
_BIRTHDAY = re.compile(r"\A\d{4}-(0[1-9]|1[0-2])(-([0-2]\d|3[01]))?\Z")
_PERSON_KEYS = ("yuanbao", "erbao")
_ALBUM_KEYS = {
    "pending_delete": "album_pending_delete",
    "yuanbao": "album_yuanbao",
    "erbao": "album_erbao",
}
ALLOWED_LOGS = frozenset({"bridge", "delete", "cleanup", "external", "backup", "errors"})
_THUMB_MAX = 512 * 1024
#: Album JSON can be large; unbounded ``resp.read()`` would OOM the panel.
_API_MAX = 4 * 1024 * 1024
#: Raster types only.  ``image/*`` would also admit ``image/svg+xml``, and an
#: SVG is a script document: harmless in an ``<img>``, not harmless in the tab
#: an operator opens when a thumbnail looks wrong.  Immich serves JPEG or WebP.
_THUMB_TYPES = frozenset({"image/jpeg", "image/webp", "image/png", "image/avif"})
_IMMICH_OPENER = no_redirect_opener()
_CFG_LOCK = threading.Lock()


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


def _load_json_obj(path: Path) -> dict:
    """Status JSON the UI indexes with ``.get``; a list/string must not 500."""
    data = _load_json(path, {}) or {}
    return data if isinstance(data, dict) else {}


def _cfg() -> dict:
    data = _load_json(CFG_PATH, {}) or {}
    return data if isinstance(data, dict) else {}


def _cfg_strict() -> dict:
    """Parse config.json for a write.  A broken file must not be overwritten."""
    if not CFG_PATH.exists():
        return {}
    try:
        data = json.loads(CFG_PATH.read_text(encoding="utf-8"))
    except Exception:
        raise api_error("photoshub.bad_config")
    if not isinstance(data, dict):
        raise api_error("photoshub.bad_config")
    return data


def _write_cfg(cfg: dict) -> None:
    secure_io.replace_secret_text(
        CFG_PATH,
        json.dumps(cfg, ensure_ascii=False, indent=2) + "\n",
    )


def _safe_name(raw: Any) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    if not _NAME.fullmatch(text):
        raise api_error("photoshub.bad_name")
    return text


def _safe_birthday(raw: Any) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    if not _BIRTHDAY.fullmatch(text):
        raise api_error("photoshub.bad_birthday")
    return text


def _safe_album(raw: Any, *, required: bool = False) -> str:
    text = str(raw or "").strip()
    if required and not text:
        raise api_error("photoshub.bad_album")
    if not _ALBUM.fullmatch(text):
        raise api_error("photoshub.bad_album")
    return text


def _safe_link(raw: Any) -> str:
    """Operator-facing http(s) link; empty clears the stored value."""
    text = str(raw or "").strip()
    if not text:
        return ""
    href = _public_href(text)
    if not href:
        raise api_error("photoshub.bad_link_url")
    return href


def _abs_path(raw: Any) -> str:
    text = str(raw or "").strip()
    return text if text.startswith("/") else ""


def _people_public(cfg: dict) -> dict:
    people = cfg.get("people") or {}
    out = {}
    for key in _PERSON_KEYS:
        item = people.get(key) if isinstance(people, dict) else None
        if not isinstance(item, dict):
            item = {}
        out[key] = {
            "name": str(item.get("name") or "").strip()[:40],
            "birthday": str(item.get("birthday") or "").strip()[:10],
        }
    return out


def _inventory_public(raw: Any) -> dict:
    """Count of photos that exist elsewhere, never the filename sample list."""
    if not isinstance(raw, dict):
        return {"missing_elsewhere": 0}
    missing = raw.get("missing_elsewhere", raw.get("missing", raw.get("服务器图库没有")))  # cjk-input: key written by the operator's inventory script
    try:
        n = int(missing or 0)
    except (TypeError, ValueError):
        n = 0
    return {"missing_elsewhere": max(0, n)}


def _albums_public(cfg: dict) -> dict:
    immich = cfg.get("immich") or {}
    return {
        "pending_delete": immich.get("album_pending_delete") or "Pending Delete",
        "yuanbao": str(immich.get("album_yuanbao") or ""),
        "erbao": str(immich.get("album_erbao") or ""),
    }


def _handbook_name() -> str:
    for name in ("handbook.md", "手册.md"):  # cjk-input: the handbook's real filename on disk
        if (HUB / name).is_file():
            return name
    return ""


def _log_relpath(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(HUB.resolve()))
    except Exception:
        return path.name


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
            raw = resp.read(_API_MAX + 1)
    except _ImmichRedirect:
        raise api_error("photoshub.bad_immich_url")
    if not raw:
        return None
    if len(raw) > _API_MAX:
        raise api_error("photoshub.immich_response", detail="payload too large")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        raise api_error("photoshub.immich_response", detail="not JSON")
    return parsed


def asset_thumbnail(asset_id: str) -> tuple[bytes, str]:
    """Small Immich preview for the pending-delete review grid.

    The browser never sees the API key.  The asset id is a UUID, and the
    Immich origin is the same private-only check used for album calls.
    """
    if not installed():
        raise api_error("photoshub.not_installed")
    aid = _safe_id(asset_id)
    key = _immich_key()
    if not key:
        raise api_error("photoshub.key_missing")
    req = urllib.request.Request(
        f"{_immich_base()}/api/assets/{aid}/thumbnail?size=thumbnail",
        method="GET",
        headers={"x-api-key": key, "Accept": "image/*"},
    )
    try:
        with _IMMICH_OPENER.open(req, timeout=15) as resp:
            ctype = str(resp.headers.get("Content-Type") or "image/jpeg").split(";", 1)[0].strip()
            raw = resp.read(_THUMB_MAX + 1)
    except _ImmichRedirect:
        raise api_error("photoshub.bad_immich_url")
    except Exception as e:
        raise api_error("photoshub.thumb_failed", detail=str(e)[:160])
    if len(raw) > _THUMB_MAX or not raw:
        raise api_error("photoshub.thumb_failed", detail="empty or too large")
    if ctype.lower() not in _THUMB_TYPES:
        raise api_error("photoshub.thumb_failed", detail=f"unsupported type {ctype}")
    return raw, ctype


def status() -> dict:
    cfg = _cfg()
    originals = _load_json_obj(STATE / "originals_status.json")
    bridge = _load_json_obj(STATE / "bridge_status.json")
    delete = _load_json_obj(STATE / "delete_review_status.json")
    cleanup = _load_json_obj(STATE / "cleanup_status.json")
    backup = _load_json_obj(STATE / "backup_status.json")
    external = _load_json_obj(STATE / "external_backup_status.json")
    inventory = _load_json_obj(STATE / "inventory_report.json")
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
        "inventory": _inventory_public(inventory),
        "gates": {
            "originals_ready": gate_ready,
            "allow_delete_channel": bool(gates.get("allow_delete_channel")) and gate_ready,
            "allow_cleanup": bool(gates.get("allow_cleanup")) and gate_ready,
            "force_fallback": bool((cfg.get("bridge") or {}).get("force_fallback", True)),
        },
        "links": {
            "immich": _public_href(immich.get("public_url")),
            "panel": _public_href((cfg.get("panel") or {}).get("url")),
            "handbook": _handbook_name(),
        },
        "albums": _albums_public(cfg),
        "people": _people_public(cfg),
    }
    return snap


def public_config() -> dict:
    """Operator-facing settings.  Never includes the Immich API key."""
    cfg = _cfg()
    immich = cfg.get("immich") if isinstance(cfg.get("immich"), dict) else {}
    gates = cfg.get("gates") if isinstance(cfg.get("gates"), dict) else {}
    bridge = cfg.get("bridge") if isinstance(cfg.get("bridge"), dict) else {}
    panel = cfg.get("panel") if isinstance(cfg.get("panel"), dict) else {}
    try:
        min_pct = float(gates.get("min_local_original_pct") or 99)
    except (TypeError, ValueError):
        min_pct = 99.0
    return {
        "photoshub_ok": installed(),
        "people": _people_public(cfg),
        "albums": _albums_public(cfg),
        "immich": {
            "base_url": str(immich.get("base_url") or "").strip(),
            "public_url": _public_href(immich.get("public_url")),
            "has_api_key": bool(_immich_key()),
        },
        "panel": {"url": _public_href(panel.get("url"))},
        "gates": {
            "allow_delete_channel": bool(gates.get("allow_delete_channel")),
            "allow_cleanup": bool(gates.get("allow_cleanup")),
            "min_local_original_pct": min_pct,
        },
        "bridge": {
            "force_fallback": bool(bridge.get("force_fallback", True)),
            "note": str(bridge.get("note") or "")[:240],
        },
        "paths": {
            "photos_library": _abs_path(cfg.get("photos_library")),
            "bridge_dir": _abs_path(cfg.get("bridge_dir")),
            "inbox_dir": _abs_path(cfg.get("inbox_dir")),
            "backup_dir": _abs_path(cfg.get("backup_dir")),
            "media_location": _abs_path(immich.get("media_location")),
        },
    }


def _apply_config_patch(cfg: dict, patch: dict) -> None:
    people_patch = patch.get("people")
    if people_patch:
        if not isinstance(people_patch, dict):
            raise api_error("photoshub.bad_person")
        unknown = set(people_patch) - set(_PERSON_KEYS)
        if unknown:
            raise api_error("photoshub.bad_person")
        people = cfg.setdefault("people", {})
        if not isinstance(people, dict):
            people = {}
            cfg["people"] = people
        for key in _PERSON_KEYS:
            item = people_patch.get(key)
            if item is None:
                continue
            if not isinstance(item, dict):
                raise api_error("photoshub.bad_person")
            person = people.get(key)
            if not isinstance(person, dict):
                person = {}
                people[key] = person
            if "name" in item and item["name"] is not None:
                person["name"] = _safe_name(item["name"])
            if "birthday" in item and item["birthday"] is not None:
                person["birthday"] = _safe_birthday(item["birthday"])

    albums_patch = patch.get("albums")
    if albums_patch:
        if not isinstance(albums_patch, dict):
            raise api_error("photoshub.bad_album")
        unknown = set(albums_patch) - set(_ALBUM_KEYS)
        if unknown:
            raise api_error("photoshub.bad_album")
        immich = cfg.setdefault("immich", {})
        if not isinstance(immich, dict):
            immich = {}
            cfg["immich"] = immich
        for key, dest in _ALBUM_KEYS.items():
            if key not in albums_patch or albums_patch[key] is None:
                continue
            immich[dest] = _safe_album(albums_patch[key], required=(key == "pending_delete"))

    immich_patch = patch.get("immich")
    if immich_patch:
        if not isinstance(immich_patch, dict):
            raise api_error("photoshub.bad_immich_url")
        immich = cfg.setdefault("immich", {})
        if not isinstance(immich, dict):
            immich = {}
            cfg["immich"] = immich
        if "base_url" in immich_patch and immich_patch["base_url"] is not None:
            origin = local_http_origin(str(immich_patch["base_url"]).strip())
            if not origin:
                raise api_error("photoshub.bad_immich_url")
            immich["base_url"] = origin
        if "public_url" in immich_patch and immich_patch["public_url"] is not None:
            immich["public_url"] = _safe_link(immich_patch["public_url"])

    panel_patch = patch.get("panel")
    if panel_patch:
        if not isinstance(panel_patch, dict):
            raise api_error("photoshub.bad_link_url")
        panel = cfg.setdefault("panel", {})
        if not isinstance(panel, dict):
            panel = {}
            cfg["panel"] = panel
        if "url" in panel_patch and panel_patch["url"] is not None:
            panel["url"] = _safe_link(panel_patch["url"])


def update_config(patch: dict) -> dict:
    """Merge safe operator fields into config.json.  Never writes Photos.sqlite."""
    if not installed():
        raise api_error("photoshub.not_installed")
    if not isinstance(patch, dict):
        raise api_error("photoshub.bad_config")
    with _CFG_LOCK:
        cfg = _cfg_strict()
        _apply_config_patch(cfg, patch)
        _write_cfg(cfg)
    return public_config()


def _delete_gated() -> bool:
    """True when the pending-delete channel is frozen (or originals are not ready)."""
    cfg = _cfg()
    originals = _load_json_obj(STATE / "originals_status.json")
    gates = cfg.get("gates") or {}
    ready = bool(originals.get("gate_ready"))
    return not (bool(gates.get("allow_delete_channel")) and ready)


def _pending_album_name() -> str:
    return (_cfg().get("immich") or {}).get("album_pending_delete") or "Pending Delete"


def _pending_album_id(name: str) -> str | None:
    albums = _immich_api("GET", "/api/albums") or []
    if not isinstance(albums, list):
        albums = []
    album = next(
        (a for a in albums if isinstance(a, dict) and a.get("albumName") == name),
        None,
    )
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
        return {
            "album": name,
            "album_id": None,
            "assets": [],
            "count": 0,
            "gated": _delete_gated(),
        }
    detail = _immich_api("GET", f"/api/albums/{album_id}") or {}
    if not isinstance(detail, dict):
        detail = {}
    assets = detail.get("assets") or []
    if not isinstance(assets, list):
        assets = []
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
    if name not in ALLOWED_LOGS:
        raise api_error("photoshub.bad_log")
    if not installed():
        return {"name": name, "path": None, "lines": []}
    log_dir = HUB / "logs"
    mapping = {
        "bridge": sorted(log_dir.glob("bridge-*.log")),
        "delete": [log_dir / "delete_review.log"],
        "cleanup": [log_dir / "cleanup.log"],
        "external": sorted(log_dir.glob("external-backup-*.log")),
        "backup": sorted(log_dir.glob("backup-*.log")),
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
    rel = _log_relpath(path)
    try:
        content = tail_file_lines(path, lines)
    except Exception as e:
        return {"name": name, "path": rel, "lines": [str(e)]}
    return {"name": name, "path": rel, "lines": content}
