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

# Real control flow must keep propagating even through the bomb guards
# (the modules12 convention): swallowing a Ctrl-C or an interpreter
# shutdown to save one log row would turn the sanitizer into a hang.
# Everything else BaseException-shaped that a leftover raises out of its
# own hooks is a bomb like any other.
_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)


def _isa(value, kinds) -> bool:
    """``isinstance`` that a leftover ``__class__``-property bomb cannot 500.

    ``isinstance`` consults ``value.__class__`` when the exact-type check
    misses, so a leftover whose ``__class__`` is a *raising property*
    detonated the bare type gates themselves — planted as the cfg() root
    (``_mapping_get``'s dict gate), the ``log_sources`` value (``_entries``'
    list gate), an entry, or an entry's id/name/path field
    (``_config_text``'s rank gates, ``_entries``' bytes/str gates) — and
    500'd GET /api/logs and GET /api/logs/{id} together, one line ahead of
    the laundering built to absorb junk shapes (the ups_svc / vms_svc /
    smart_test_svc rule).  A real subclass still matches through the
    C-level type check; only a value that cannot answer what it is takes
    the non-matching branch.

    ``except BaseException``: the logs9 guard stopped at ``Exception``, so
    a leftover whose ``__class__`` property raises a *BaseException*
    subclass (a watchdog/timeout-style leftover, the shape modules12 just
    sealed) sailed past this catch — and past every sibling guard below —
    straight out of GET /api/logs and GET /api/logs/{id} raw.  Only
    genuine control flow keeps propagating.
    """
    try:
        return isinstance(value, kinds)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500.

    Unbound base methods throughout (the json6 convention): ``str(x)`` of a
    subclass whose ``__str__`` returns *itself* keeps the subclass, so the
    bound ``.encode`` used to dispatch into a leftover override and 500 both
    logs routes; the same held for a bytes/bytearray-subclass ``.decode``.

    Both decode bases are tried, real layout first-come (the modules12
    ``_decode_bytes`` rule): the old arm picked the base off the *claimed*
    ``__class__``, so a genuine ``bytearray`` whose ``__class__`` lied
    ``bytes`` was handed to ``bytes.decode``, rejected by the descriptor,
    and its perfectly decodable content vanished to ``""`` — degrade at
    the wrong rank.  The descriptor that matches the real storage wins; a
    total impostor still fails both and falls to the ``str()`` probe.
    """
    if _isa(value, (bytes, bytearray)):
        for base in (bytes, bytearray):
            try:
                return base.decode(value, "utf-8", "replace")
            except _CONTROL_FLOW:
                raise
            except BaseException:
                continue
        # Honest str storage behind a lying-bytes ``__class__`` (the
        # audit13 recover-the-real-storage rule): the gate above matches
        # through the *lie*, both base decodes reject the str layout, and
        # the old unconditional ``return ""`` vanished text that the str
        # probe below renders verbatim.  Only a real str falls through; a
        # total impostor (neither layout) still degrades to ``""``.
        if not _isa(value, str):
            return ""
    try:
        text = str(value)
    except RecursionError:
        try:
            return type(value).__name__
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return ""
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # A ``__str__`` bomb raising a *BaseException* subclass used to
        # sail past the ``except Exception`` here.
        return ""
    try:
        return str.encode(text, "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""


def _exact_str(text) -> str | None:
    """*text* as an exact ``str``, or None when it cannot be copied.

    ``str(x)`` hands back its operand's ``tp_str`` result *verbatim* when
    that result is a str subclass: an int-subclass id whose ``__str__``
    returns a poisoned subclass, and a date-subclass id whose
    ``isoformat()`` returns a self-``__str__`` subclass (the json6
    convention), both sailed through ``_config_text`` still carrying their
    ``__len__``/``__bool__`` bombs — and the bare ``if not raw_id:``
    truthiness probe in :func:`_entries` detonated them, 500ing
    GET /api/logs and GET /api/logs/{id} together.  The unbound
    ``str.__str__`` copies a subclass to an exact str (CPython returns a
    plain-str copy for non-exact operands), so nothing poisoned survives.
    """
    if type(text) is str:
        return text
    if not _isa(text, str):
        return None
    try:
        return str.__str__(text)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None


def _mapping_get(mapping, key):
    """Field read that a dict-subclass ``.get`` bomb cannot 500.

    ``isinstance(x, dict)`` passes an odd subclass whose ``get`` (or
    ``__getitem__``) raises — the ups_svc/backups convention.  One such
    leftover as the cfg() root or as a ``log_sources`` entry used to raise
    out of :func:`_entries` and 500 GET /api/logs and GET /api/logs/{id}
    at once.  ``dict.get`` reads the real storage underneath the override,
    so a subclass that only poisoned its method keeps its sane fields.
    The gate itself goes through :func:`_isa`: a ``__class__``-property
    bomb as the cfg root or an entry used to detonate the bare isinstance
    one line ahead of everything this helper absorbs.
    """
    if not _isa(mapping, dict):
        return None
    try:
        return mapping.get(key)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # A ``.get`` bomb raising a *BaseException* subclass used to sail
        # past the ``except Exception`` here — one such leftover as a
        # ``log_sources`` entry 500'd both logs routes raw, one line ahead
        # of the dict.get salvage below.
        try:
            return dict.get(mapping, key)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None


def _truthy(value) -> bool:
    """``bool(value)`` that survives a leftover ``__bool__`` bomb.

    Fails closed to False: a bomb as a ``path`` value is junk, not a
    configured source, so the entry drops instead of 500ing the listing.
    """
    try:
        return bool(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
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
        size = None
        if _isa(raw, int):
            try:
                size = int.__index__(raw)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                # The int gate matches through a lying ``__class__`` too
                # (the audit13 recover-the-real-storage rule): a genuine
                # float ``st_size`` claiming int reached ``int.__index__``,
                # was rejected for its real layout, and the honest number a
                # FUSE stub reported degraded to 0 one arm too early.  A
                # real float falls to the float arm below; anything else
                # is the same junk as before and takes the 0.
                if not _isa(raw, float):
                    raise
        if size is None:
            if _isa(raw, float):
                value = float.__float__(raw)
                if value != value or value in (float("inf"), float("-inf")):
                    return 0
                size = int(value)
            else:
                size = int(raw)
        float(size)
    except _CONTROL_FLOW:
        raise
    except BaseException:
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
    if _isa(value, str):
        # Exact-str launder (the json6 ``str.__str__`` convention): a
        # subclass returned verbatim kept its poisoned ``encode``/``__len__``
        # in play for every later bound read, and one self-``__str__``
        # encode bomb as an id/name used to 500 both logs routes.  The
        # unbound base ``__str__`` copies the carried text to an exact str.
        #
        # No ``return None`` on failure (the audit13 recover-the-real-
        # storage rule): this gate matches through a *lying* ``__class__``
        # too, so a genuine bytes/bytearray (or date, or int) id/name
        # claiming ``str`` reached the descriptor, was rejected for its
        # real layout, and the old unconditional None silently unlisted a
        # source whose ``b"logid"`` decodes perfectly — degrade at the
        # wrong rank, the same shape logs12 sealed in the decode arms.
        # Falling through lets each later arm real-type-check the honest
        # storage; a total impostor (claims str, carries no renderable
        # layout) matches none of them and still drops at the tail gate.
        try:
            return str.__str__(value)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            pass
    if _isa(value, (bytes, bytearray)):
        # Unbound decode: ``bytes(value)`` dispatches into a subclass
        # ``__bytes__`` override, and one such bomb as an id used to 500
        # both logs routes before anything was listed.  Both bases are
        # tried, real layout first-come (the modules12 rule): picking the
        # base off the *claimed* ``__class__`` handed a genuine bytearray
        # lying ``bytes`` to ``bytes.decode``, and its perfectly decodable
        # id/name vanished to None — the source silently unlisted.
        for base in (bytes, bytearray):
            try:
                return base.decode(value, "utf-8", "replace")
            except _CONTROL_FLOW:
                raise
            except BaseException:
                continue
        return None
    if _isa(value, (datetime.date, datetime.datetime)):
        # _exact_str: ``str(...)`` keeps a str-*subclass* isoformat result
        # verbatim when its ``__str__`` returns itself (the json6 self-str
        # convention), so a subclass ``__len__``/``__bool__`` bomb riding a
        # leftover date's isoformat used to detonate the ``if not raw_id:``
        # truthiness probe in _entries — 500ing both logs routes.
        try:
            return _exact_str(str(value.isoformat()))
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
    if _isa(value, bool) or not _isa(value, int):
        # ``_isa`` for the bool head too, not ``type(x) is bool``: a
        # ``__class__`` liar claiming bool would otherwise slip past the
        # exact-type check, match the int gate through the same lie, and
        # publish its object repr as a configured id/name.  A value that
        # claims to be bool renders like one — dropped, never "True".
        return None
    try:
        # _exact_str: ``str(x)`` returns the ``tp_str`` result *verbatim*
        # when an int-subclass ``__str__`` override hands back a str
        # subclass, so a poisoned ``__len__``/``__bool__`` riding that
        # result used to detonate the ``if not raw_id:`` truthiness probe
        # in _entries — 500ing both logs routes after this catch had
        # already passed.
        return _exact_str(str(value))
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # ValueError is the >4300-digit cap; anything else is an
        # int-subclass ``__str__`` bomb — including one raising a
        # *BaseException* subclass, which used to sail past the old
        # ``except Exception`` and 500 both logs routes.  Either way the
        # field cannot be rendered — drop it, not the page.
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
    if not _isa(value, str):
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
    # Guarded cfg() (the try/except-around-cfg() union rule ups_svc /
    # status / scheduler_svc / smart_test_svc already follow): the call
    # itself sat outside any try, so a config snapshot provider that
    # *raises* on read (a dying seam or a patched loader) escaped every
    # _mapping_get below and 500'd GET /api/logs and GET /api/logs/{id}
    # at once.  No config degrades to the unconfigured defaults, the same
    # answer an empty services.yaml gets.
    # ``except BaseException``: a provider raising a *BaseException*
    # subclass (the watchdog/timeout shape) used to sail past the logs11
    # ``except Exception`` and 500 both routes raw all over again.
    try:
        root = cfg()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        root = None
    # _mapping_get / unbound list reads throughout: cfg() normally hands out
    # plain parsed YAML, but a leftover cache poisoned with dict/list
    # *subclasses* passes every isinstance gate here while its ``.get`` /
    # ``__bool__`` / ``__iter__`` / ``__getitem__`` overrides raise — one
    # such bomb used to 500 GET /api/logs and GET /api/logs/{id} together.
    # The unbound reads keep the sane data stored underneath the override.
    sources = _mapping_get(root, "log_sources")
    rows = None
    if _isa(sources, list):
        try:
            # Unbound ``list.__iter__`` doubles as the impostor gate: a
            # lying ``__class__`` property that *returns* list passes
            # ``_isa`` yet is no list at all, and the bare
            # ``list.__len__(sources)`` used to raise the descriptor
            # TypeError out of :func:`_entries` — 500ing GET /api/logs and
            # GET /api/logs/{id} together.  Only a real list (or subclass,
            # its poisoned ``__iter__``/``__len__`` bypassed) snapshots.
            rows = list(list.__iter__(sources))
        except _CONTROL_FLOW:
            raise
        except BaseException:
            rows = None
    if not rows:
        home = user_home()
        if home is None:
            return []
        rows = [
            {"id": "autostart", "name": "Autostart", "path": str(home / "Library/Logs/server-autostart.log")},
            {"id": "serverhub", "name": "ServerHub", "path": str(home / "Library/Logs/serverhub.err.log")},
            {"id": "ha", "name": "Home Assistant", "path": str(home / "Services/homeassistant/config/home-assistant.log")},
        ]
    out = []
    for s in rows:
        raw_path = _mapping_get(s, "path")
        if not _truthy(raw_path):
            continue
        raw_id = _config_text(_mapping_get(s, "id"))
        if not raw_id:
            continue
        if _isa(raw_path, (bytes, bytearray)):
            # A bytes path (os.listdir(b"...") leftover) used to stringify
            # to the garbage relative name ``b'/…'``; the fs-encoding decode
            # keeps the surrogateescape text that names the real on-disk
            # file.  Unbound, because ``os.fsdecode(bytes(raw_path))``
            # dispatched into a subclass ``__bytes__`` override — one such
            # bomb as a path used to 500 both logs routes.  Both bases are
            # tried, real layout first-come (the modules12 rule): picking
            # the base off the *claimed* ``__class__`` handed a genuine
            # bytearray lying ``bytes`` to ``bytes.decode``, and a source
            # whose on-disk path was perfectly decodable silently vanished
            # from the listing — degrade at the wrong rank.
            decoded = None
            for base in (bytes, bytearray):
                try:
                    decoded = base.decode(
                        raw_path,
                        sys.getfilesystemencoding(),
                        sys.getfilesystemencodeerrors(),
                    )
                    break
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    continue
            if decoded is not None:
                raw_path = decoded
            elif not _isa(raw_path, str):
                # Claimed-bytes junk with no readable layout drops, as
                # before.  But honest str storage behind a lying-bytes
                # ``__class__`` (the audit13 recover-the-real-storage
                # rule) used to drop here too: the gate above matches
                # through the *lie*, both base decodes reject the str
                # layout, and a source whose real path text was perfectly
                # usable silently vanished from the listing — degrade at
                # the wrong rank.  A real str falls through to the str
                # arm below, which reads the carried text unbound.
                continue
        if _isa(raw_path, str):
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
            except _CONTROL_FLOW:
                raise
            except BaseException:
                continue
        try:
            # _exact_str before Path(): ``str(raw_path)`` of a non-str
            # leftover returns its ``__str__`` result *verbatim* when that
            # result is a str subclass, and ``Path`` stores the raw text and
            # parses it *lazily* — so a poisoned ``__getitem__``/``replace``
            # riding the subclass detonated later, inside
            # ``_log_path_allowed`` / ``is_file``, outside this guard, and
            # 500'd both logs routes.  The exact-str copy leaves nothing
            # poisoned for pathlib to trip on.
            path_text = _exact_str(str(raw_path))
            if path_text is None:
                continue
            p = Path(os.path.expanduser(path_text))
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # RuntimeError: leftover HOME unset on a ``~/…`` log path.
            # ValueError: an over-cap int path is the digit-cap ``str()``.
            # Broad, like ``_stat_size`` / ``_config_text``: a non-str
            # ``path`` leftover whose own ``str()`` bombs (a poisoned
            # ``__str__`` on an arbitrary object — including one raising a
            # *BaseException* subclass past the old ``except Exception``)
            # drops the one entry rather than the whole page.
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
    if _isa(raw, bool) or raw is None:
        value = default
    else:
        try:
            # Unbound base read for int subclasses (the _stat_size rule):
            # ``int(raw)`` dispatches into a subclass ``__int__``/
            # ``__index__`` override, and one raising anything outside the
            # old narrow (TypeError, ValueError, OverflowError) catch —
            # the Services script-log fallback hands ``tail_log`` its
            # caller's raw ``lines`` — used to 500 the tail instead of
            # falling back to the default.
            value = int.__index__(raw) if _isa(raw, int) else int(raw)
        except _CONTROL_FLOW:
            raise
        except BaseException:
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
    name = meta.get("name") if _isa(meta.get("name"), str) else source_id
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
            # _exact_str, same as _entries: a stubbed log_sources() can hand
            # back a path whose ``str()`` is a poisoned str subclass, and
            # Path parses its stored text lazily — outside this guard.
            p = Path(_exact_str(str(meta_path or "")) or "")
        except _CONTROL_FLOW:
            raise
        except BaseException:
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
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # A read-path bomb raising a *BaseException* subclass used to sail
        # past the ``except Exception`` here and escape the route raw
        # instead of taking the coded read_failed answer.
        raise api_error("logs.read_failed")
