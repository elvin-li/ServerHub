"""Central log tail from configured sources."""
from __future__ import annotations

import os
from pathlib import Path

from hub import files_svc
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
    """``st_size`` can be inf/nan from a FUSE stub; Starlette rejects those.

    ``int(...)`` with a try only guards *conversions*: a leftover ``st_size``
    that is already a >4300-digit int passes through untouched, and CPython's
    int->str digit limit then ValueError'd Starlette's ``json.dumps`` —
    500ing GET /api/logs and GET /api/logs/{id} after the tail had already
    been read.  ``float()`` rejects anything beyond float range, the same
    junk test hub/files_svc.py's ``_finite_int`` applies to its stat numbers.
    """
    try:
        size = int(path.stat().st_size)
        float(size)
    except (OSError, TypeError, ValueError, OverflowError):
        return 0
    return size if size >= 0 else 0


def _config_text(value) -> str | None:
    """A configured id/name as text, or None when the entry must skip it.

    YAML hex/octal (``id: 0x2A``) loads *already-int* — uncapped, because
    ``int(x, 16)`` is exempt from CPython's 4300-digit conversion limit.
    The original panel accepted numeric ids verbatim, so the strict
    ``isinstance(str)`` gate a later sweep added silently hid the whole
    configured source from GET /api/logs (and 404'd its tail).  A
    renderable int coerces through the ``str()`` probe; an unrenderable
    >4300-digit leftover — whose ``str()`` is the same digit-cap
    ValueError ``json.dumps`` would raise — returns None so only its
    field/entry drops.  bool passes ``isinstance(int)`` and must not
    become ``"True"``.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    try:
        return str(value)
    except ValueError:
        return None


def _lookup_id(value) -> str | None:
    """The tail lookup key, or None when nothing listed could match it.

    A source id is only ever a dict key here — the tail is a plain file
    read, so nothing about it lands in a subprocess argv.  The
    ``require_positional`` argv gate a security sweep bolted onto
    ``tail_log`` therefore refused values that are perfectly legal ids:
    a configured ``id: 日志`` (the panel defaults to zh-CN) or ``id: my
    log`` was listed by GET /api/logs yet 400'd its own tail — on the
    Logs page and in the Services script-log fallback that feeds
    ``log_sources`` ids straight back into ``tail_log``.

    The listing scrubbed its keys through :func:`_utf8_text`, so the raw
    value is scrubbed the same way *before* the dict lookup — a leftover
    lone surrogate must compare against the replace-encoded key it was
    listed under.  Non-str callers follow the ``_config_text`` rule: a
    renderable int coerces (matching the ``"42"`` the listing publishes
    for ``id: 0x2A``), bool and over-cap ints match nothing.
    """
    if not isinstance(value, str):
        value = _config_text(value)
        if value is None:
            return None
    return _utf8_text(value)


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
        if not isinstance(s, dict) or not s.get("path"):
            continue
        raw_id = _config_text(s.get("id"))
        if not raw_id:
            continue
        try:
            p = Path(os.path.expanduser(str(s["path"])))
        except (OSError, ValueError, TypeError, RuntimeError):
            # RuntimeError: leftover HOME unset on a ``~/…`` log path.
            # ValueError: an over-cap int path is the digit-cap ``str()``.
            continue
        if not _log_path_allowed(p):
            continue
        try:
            exists = p.is_file()
            size = _stat_size(p) if exists else 0
        except OSError:
            exists, size = False, 0
        sid = _utf8_text(raw_id)
        name = _config_text(s.get("name"))
        if not name:
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
    source_id = _lookup_id(source_id)
    if source_id is None:
        raise api_error("logs.unknown_source")
    sources = {s["id"]: s for s in log_sources()}
    if source_id not in sources:
        raise api_error("logs.unknown_source")
    meta = sources[source_id]
    name = meta.get("name") if isinstance(meta.get("name"), str) else source_id
    name = _utf8_text(name)

    def _missing(path: Path) -> dict:
        return {"id": _utf8_text(source_id), "name": name, "path": _utf8_text(path),
                "exists": False, "size": 0, "log": "(file does not exist)", "lines": 0}

    try:
        p = Path(str(meta.get("path") or ""))
    except (OSError, ValueError, TypeError):
        raise api_error("logs.read_failed")
    if not _log_path_allowed(p):
        raise api_error("logs.protected")
    try:
        p = p.resolve()
    except ValueError:
        # Embedded NUL: such a path can never name an on-disk file.  The
        # listing already reports it as ``exists: false``, but the tail
        # used to answer the same source with a coded 500 (logs.read_failed)
        # although no read was ever attempted.  Give the same answer the
        # listing gives.
        return _missing(p)
    except (OSError, RuntimeError):
        raise api_error("logs.read_failed")
    if not _log_path_allowed(p):
        raise api_error("logs.protected")
    try:
        is_file = p.is_file()
    except ValueError:
        # A NUL that survived resolve() is still "no such file", not a
        # failed read.
        return _missing(p)
    except OSError:
        # Dying FUSE mounts raise EIO.
        raise api_error("logs.read_failed")
    path_s = _utf8_text(p)
    if not is_file:
        return _missing(p)
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
