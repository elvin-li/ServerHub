"""Central log tail from configured sources."""
from __future__ import annotations

import datetime
import os
import sys
from pathlib import Path

from hub import files_svc
from hub.config import cfg
from hub.errors import api_error
from hub.paths import user_home
from hub.util import tail_file_lines


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500.

    Unbound base methods throughout (the json6 convention): ``str(x)`` of a
    subclass whose ``__str__`` returns *itself* keeps the subclass, so the
    bound ``.encode`` used to dispatch into a leftover override and 500 both
    logs routes; the same held for a bytes/bytearray-subclass ``.decode``.
    """
    if isinstance(value, (bytes, bytearray)):
        base = bytes if isinstance(value, bytes) else bytearray
        try:
            return base.decode(value, "utf-8", "replace")
        except Exception:
            return ""
    try:
        text = str(value)
    except RecursionError:
        try:
            return type(value).__name__
        except Exception:
            return ""
    except Exception:
        return ""
    try:
        return str.encode(text, "utf-8", "replace").decode("utf-8")
    except Exception:
        return ""


def _mapping_get(mapping, key):
    """Field read that a dict-subclass ``.get`` bomb cannot 500.

    ``isinstance(x, dict)`` passes an odd subclass whose ``get`` (or
    ``__getitem__``) raises — the ups_svc/backups convention.  One such
    leftover as the cfg() root or as a ``log_sources`` entry used to raise
    out of :func:`_entries` and 500 GET /api/logs and GET /api/logs/{id}
    at once.  ``dict.get`` reads the real storage underneath the override,
    so a subclass that only poisoned its method keeps its sane fields.
    """
    if not isinstance(mapping, dict):
        return None
    try:
        return mapping.get(key)
    except Exception:
        try:
            return dict.get(mapping, key)
        except Exception:
            return None


def _truthy(value) -> bool:
    """``bool(value)`` that survives a leftover ``__bool__`` bomb.

    Fails closed to False: a bomb as a ``path`` value is junk, not a
    configured source, so the entry drops instead of 500ing the listing.
    """
    try:
        return bool(value)
    except Exception:
        return False


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
        raw = path.stat().st_size
    except OSError:
        return 0
    try:
        # Unbound base reads (the settings8 convention): ``int(x)`` /
        # ``float(x)`` of a leftover int/float *subclass* dispatch into its
        # ``__int__``/``__index__``/``__float__`` override, and one such bomb
        # riding a poisoned stat used to raise past the conversion catch and
        # 500 GET /api/logs and GET /api/logs/{id} together.  The unbound
        # slots read the real number stored underneath the override.
        if isinstance(raw, int):
            size = int.__index__(raw)
        elif isinstance(raw, float):
            value = float.__float__(raw)
            if value != value or value in (float("inf"), float("-inf")):
                return 0
            size = int(value)
        else:
            size = int(raw)
        float(size)
    except Exception:
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

    bytes and date/datetime follow the same accepted-verbatim history:
    the original panel published them through FastAPI's encoder (bytes
    strict-decoded — 500ing the listing on invalid UTF-8 — and dates as
    isoformat), so the strict gate silently hid sources that used to
    list.  bytes replace-decode (never 500), dates keep the isoformat
    text the encoder used to publish.
    """
    if isinstance(value, str):
        # Exact-str launder (the json6 ``str.__str__`` convention): a
        # subclass returned verbatim kept its poisoned ``encode``/``__len__``
        # in play for every later bound read, and one self-``__str__``
        # encode bomb as an id/name used to 500 both logs routes.  The
        # unbound base ``__str__`` copies the carried text to an exact str.
        try:
            return str.__str__(value)
        except Exception:
            return None
    if isinstance(value, (bytes, bytearray)):
        # Unbound decode: ``bytes(value)`` dispatches into a subclass
        # ``__bytes__`` override, and one such bomb as an id used to 500
        # both logs routes before anything was listed.
        base = bytes if isinstance(value, bytes) else bytearray
        try:
            return base.decode(value, "utf-8", "replace")
        except Exception:
            return None
    if isinstance(value, (datetime.date, datetime.datetime)):
        try:
            return str(value.isoformat())
        except Exception:
            return None
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    try:
        return str(value)
    except Exception:
        # ValueError is the >4300-digit cap; anything else is an
        # int-subclass ``__str__`` bomb, which used to raise past the
        # narrow catch and 500 both logs routes.  Either way the field
        # cannot be rendered — drop it, not the page.
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


def _entries() -> list[tuple[Path, dict]]:
    """(raw path, published row) per usable configured source.

    The published row scrubs lone surrogates out of every field (they
    would 500 Starlette's UTF-8 encode), so the row's ``path`` text
    cannot be trusted to re-open the file: a surrogateescape name — one
    weird byte in an on-disk filename — listed as ``exists: true`` yet
    its scrubbed U+FFFD text names nothing, and the tail answered
    "(file does not exist)" for a file the listing had just stat'ed.
    The tail therefore reads through the raw ``Path`` kept here.
    """
    # _mapping_get / unbound list reads throughout: cfg() normally hands out
    # plain parsed YAML, but a leftover cache poisoned with dict/list
    # *subclasses* passes every isinstance gate here while its ``.get`` /
    # ``__bool__`` / ``__iter__`` / ``__getitem__`` overrides raise — one
    # such bomb used to 500 GET /api/logs and GET /api/logs/{id} together.
    # The unbound reads keep the sane data stored underneath the override.
    sources = _mapping_get(cfg(), "log_sources")
    if not isinstance(sources, list) or not list.__len__(sources):
        home = user_home()
        if home is None:
            return []
        sources = [
            {"id": "autostart", "name": "Autostart", "path": str(home / "Library/Logs/server-autostart.log")},
            {"id": "serverhub", "name": "ServerHub", "path": str(home / "Library/Logs/serverhub.err.log")},
            {"id": "ha", "name": "Home Assistant", "path": str(home / "Services/homeassistant/config/home-assistant.log")},
        ]
    out = []
    for s in list.__iter__(sources):
        raw_path = _mapping_get(s, "path")
        if not _truthy(raw_path):
            continue
        raw_id = _config_text(_mapping_get(s, "id"))
        if not raw_id:
            continue
        if isinstance(raw_path, (bytes, bytearray)):
            # A bytes path (os.listdir(b"...") leftover) used to stringify
            # to the garbage relative name ``b'/…'``; the fs-encoding decode
            # keeps the surrogateescape text that names the real on-disk
            # file.  Unbound, because ``os.fsdecode(bytes(raw_path))``
            # dispatched into a subclass ``__bytes__`` override — one such
            # bomb as a path used to 500 both logs routes.
            base = bytes if isinstance(raw_path, bytes) else bytearray
            try:
                raw_path = base.decode(
                    raw_path,
                    sys.getfilesystemencoding(),
                    sys.getfilesystemencodeerrors(),
                )
            except Exception:
                continue
        if isinstance(raw_path, str):
            # Exact-str launder (the json6 ``str.__str__`` convention, the
            # same one ``_config_text`` gives the id/name fields): a str
            # *subclass* left the poisoned ``__str__`` in play for the bound
            # ``str(raw_path)`` below, and one whose ``__str__`` *raised*
            # anything outside the narrow catch (a plain ``KeyError`` /
            # ``LookupError`` / ``StopIteration`` leftover, not the
            # OSError/ValueError/TypeError/RuntimeError it listed) used to
            # 500 GET /api/logs and GET /api/logs/{id} together.  The unbound
            # base ``__str__`` reads the carried path text underneath the
            # override, so the source keeps listing and tailing its real file.
            try:
                raw_path = str.__str__(raw_path)
            except Exception:
                continue
        try:
            p = Path(os.path.expanduser(str(raw_path)))
        except Exception:
            # RuntimeError: leftover HOME unset on a ``~/…`` log path.
            # ValueError: an over-cap int path is the digit-cap ``str()``.
            # Broad, like ``_stat_size`` / ``_config_text``: a non-str
            # ``path`` leftover whose own ``str()`` bombs (a poisoned
            # ``__str__`` on an arbitrary object) drops the one entry rather
            # than the whole page.
            continue
        if not _log_path_allowed(p):
            continue
        try:
            exists = p.is_file()
            size = _stat_size(p) if exists else 0
        except OSError:
            exists, size = False, 0
        sid = _utf8_text(raw_id)
        name = _config_text(_mapping_get(s, "name"))
        if not name:
            name = sid
        else:
            name = _utf8_text(name)
        out.append((p, {
            "id": sid,
            "name": name,
            "path": _utf8_text(p),
            "exists": exists,
            "size": size,
        }))
    return out


def log_sources() -> list:
    return [row for _, row in _entries()]


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

    # Read through the raw Path the listing stat'ed, not the published text:
    # the row's ``path`` is scrubbed for Starlette's UTF-8 encode, so a
    # surrogateescape name (one non-UTF-8 byte in the filename) listed as
    # ``exists: true`` yet its U+FFFD text named nothing — the tail answered
    # "(file does not exist)" for a file the listing had just stat'ed.  The
    # raw Path is taken only when its published row matches the looked-up
    # one (same id, same path text); a caller that stubbed ``log_sources``
    # keeps the historical text-derived behavior.  Last match wins, like
    # the dict comprehension above.
    p = None
    meta_path = meta.get("path")
    for raw, row in _entries():
        if row["id"] == source_id and row["path"] == meta_path:
            p = raw
    if p is None:
        try:
            p = Path(str(meta_path or ""))
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
    except RuntimeError:
        # Symlink loop: ``resolve()`` signals it as RuntimeError, not
        # OSError.  The listing reports the same source ``exists: false``
        # (``is_file`` ignores ELOOP), and a loop can never name a readable
        # file — like the NUL path, the tail used to answer it with a coded
        # 500 although no read was ever attempted.  Same answer as the
        # listing.
        return _missing(p)
    except OSError:
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
    except OSError:
        # Race between the is_file gate above and the open: the file was
        # rotated/unlinked (FileNotFoundError), or a non-regular node — a
        # FIFO, device, socket, directory, even a symlink loop — was
        # swapped onto the name (EINVAL/ENXIO/EISDIR/ELOOP out of
        # ``tail_file_lines``, which refuses to read anything that is not
        # a regular file).  A fresh disk probe on the failure path (the
        # vanished-CLI rule) decides the answer: a name that no longer
        # holds a regular file gets the same missing-200 the listing
        # gives, not a 500 blaming the server for logrotate (or a leftover
        # FIFO) doing its thing.  While the probe still sees a real file —
        # ghost ENOENT, EACCES, or O_NOFOLLOW refusing a symlink swapped
        # over the resolved name — read_failed stands.
        try:
            still_there = p.is_file()
        except (OSError, ValueError):
            still_there = False
        if not still_there:
            return _missing(p)
        raise api_error("logs.read_failed")
    except Exception:
        raise api_error("logs.read_failed")
