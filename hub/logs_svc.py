"""Central log tail from configured sources."""
from __future__ import annotations

import os
from pathlib import Path

from hub import cli_args, files_svc
from hub.config import cfg
from hub.errors import api_error
from hub.paths import user_home
from hub.util import tail_file_lines


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    try:
        text = str(value)
    except RecursionError:
        try:
            return type(value).__name__
        except Exception:
            return ""
    except Exception:
        return ""
    return text.encode("utf-8", "replace").decode("utf-8")


def _stat_size(path: Path) -> int:
    """``st_size`` can be inf/nan from a FUSE stub; Starlette rejects those."""
    try:
        size = int(path.stat().st_size)
    except (OSError, TypeError, ValueError, OverflowError):
        return 0
    return size if size >= 0 else 0


def _log_path_allowed(path: Path) -> bool:
    try:
        resolved = path.resolve()
    except (OSError, RuntimeError, ValueError):
        resolved = path
    return not files_svc.is_protected(path) and not files_svc.is_protected(resolved)


def log_sources() -> list:
    sources = cfg().get("log_sources")
    if not isinstance(sources, list) or not sources:
        home = user_home()
        if home is None:
            return []
        sources = [
            {"id": "autostart", "name": "Autostart", "path": str(home / "Library/Logs/server-autostart.log")},
            {"id": "serverhub", "name": "ServerHub", "path": str(home / "Library/Logs/serverhub.err.log")},
            {"id": "ha", "name": "Home Assistant", "path": str(home / "Services/homeassistant/config/home-assistant.log")},
        ]
    out = []
    for s in sources:
        if not isinstance(s, dict) or not isinstance(s.get("id"), str) or not s.get("id") or not s.get("path"):
            continue
        try:
            p = Path(os.path.expanduser(str(s["path"])))
        except (OSError, ValueError, TypeError, RuntimeError):
            # RuntimeError: leftover HOME unset on a ``~/…`` log path.
            continue
        if not _log_path_allowed(p):
            continue
        try:
            exists = p.is_file()
            size = _stat_size(p) if exists else 0
        except OSError:
            exists, size = False, 0
        sid = _utf8_text(s["id"])
        name = s.get("name", sid)
        if not isinstance(name, str) or not name:
            name = sid
        else:
            name = _utf8_text(name)
        out.append({
            "id": sid,
            "name": name,
            "path": _utf8_text(p),
            "exists": exists,
            "size": size,
        })
    return out


def _clamp_lines(raw, default: int = 200) -> int:
    if isinstance(raw, bool) or raw is None:
        value = default
    else:
        try:
            value = int(raw)
        except (TypeError, ValueError, OverflowError):
            value = default
    return max(10, min(value, 2000))


def tail_log(source_id: str, lines: int = 200) -> dict:
    source_id = cli_args.require_positional(source_id, label="log source")
    sources = {s["id"]: s for s in log_sources()}
    if source_id not in sources:
        raise api_error("logs.unknown_source")
    meta = sources[source_id]
    try:
        p = Path(str(meta.get("path") or ""))
    except (OSError, ValueError, TypeError):
        raise api_error("logs.read_failed")
    if not _log_path_allowed(p):
        raise api_error("logs.protected")
    try:
        p = p.resolve()
    except (OSError, RuntimeError, ValueError):
        raise api_error("logs.read_failed")
    if not _log_path_allowed(p):
        raise api_error("logs.protected")
    try:
        is_file = p.is_file()
    except (OSError, ValueError):
        # Dying FUSE mounts raise EIO; a NUL leftover raises ValueError.
        raise api_error("logs.read_failed")
    name = meta.get("name") if isinstance(meta.get("name"), str) else source_id
    name = _utf8_text(name)
    path_s = _utf8_text(p)
    if not is_file:
        return {"id": _utf8_text(source_id), "name": name, "path": path_s,
                "exists": False, "size": 0, "log": "(file does not exist)", "lines": 0}
    lines = _clamp_lines(lines)
    try:
        file_size = _stat_size(p)
        parts = tail_file_lines(p, lines)
        return {"id": _utf8_text(source_id), "name": name, "path": path_s,
                "exists": True, "size": file_size,
                "log": _utf8_text("\n".join(parts)),
                "lines": len(parts)}
    except Exception:
        raise api_error("logs.read_failed")
