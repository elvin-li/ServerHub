"""On-demand file manager — no long-lived worker; only runs while handling requests.

Optional FileBrowser (port 8125) can be started/stopped for the full UI, but the
built-in browser works without it and uses no extra process memory when idle.
"""
from __future__ import annotations

import asyncio
import errno
import mimetypes
import os
import stat
import subprocess
import time
from pathlib import Path
from urllib.parse import quote

from fastapi import UploadFile
from fastapi.responses import StreamingResponse

from hub.config import settings_section
from hub.errors import api_error, exc_detail
from hub.host_address import host_ip
from hub.paths import AGENTS_DIR, BASE, STATE_ROOT, UID, user_home
from hub.util import read_bytes_capped, sh, utf8_env


def _default_home() -> Path:
    """User home.  ``Path.home()`` leftover must not 500 import."""
    return user_home() or Path("/var/empty/serverhub-files")


HOME = _default_home()
SERVICES_ROOT = HOME / "Services"
#: Leftover multi-MB FileBrowser LaunchAgent plist used to OOM GET /api/files.
_PLIST_CAP = 256 * 1024

# ─── Protected paths ──────────────────────────────────────────────────────────
# The default roots include ~/Services (which contains this install) and ~, so
# without an explicit deny-list the browser would hand out ServerHub's own
# session-signing key, its credential store and the admin password hash — and
# accept delete/rename on them.  Enforced in _resolve_safe() so a directly
# supplied path is refused too, not just filtered out of a listing.

#: Directory subtrees that are never browsable, downloadable or writable.
PROTECTED_DIRS: tuple[Path, ...] = (
    BASE,                       # immutable ServerHub runtime
    STATE_ROOT,                 # mutable config, tokens, audits, and metrics
    HOME / ".ssh",
    HOME / ".aws",
    HOME / ".gnupg",
    HOME / ".kube",
    HOME / "Library" / "Keychains",
    # A local private-integration directory may contain account credentials,
    # long-lived API tokens, session cookies, and browser profiles. File modes
    # are no defence here because the panel runs as the file owner.
    SERVICES_ROOT / "private_integration",
)

#: Basenames that are never exposed, wherever they appear.
PROTECTED_NAMES: frozenset[str] = frozenset({
    ".session-secret",
    "service-credentials.json",
    "backup-credentials.json",
    "twofa.json",
    "api-keys.json",
    "notify-credentials.json",
    "wireguard-peers.json",
    ".local-client-token",
    ".setup-token",
    "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
})

#: Filename prefixes that are never exposed (covers services.yaml.bak.<ts>
#: and private-integration credential/session artefacts copied elsewhere).
PROTECTED_PREFIXES: tuple[str, ...] = ("services.yaml", ".env", ".private_")
#: ``db.env`` does not start with ``.env``; Immich stores the Postgres
#: password there under the default ~/Services root.
PROTECTED_SUFFIXES: tuple[str, ...] = (".env",)


def _fold(value: str) -> str:
    """Case-fold a path string so the deny-list matches what the FS opens.

    macOS (APFS) is case-insensitive by default, so a deny-list that compares
    raw strings is trivially bypassed: `Services.YAML` does not equal
    `services.yaml`, and `.../ServerHub/...` is not `relative_to`
    `.../serverhub`, yet all of them open the very same bytes.  Confirmed on
    this host — requesting the install directory with a different capitalisation
    returned the session-signing key and the admin password hash.

    NOTE: os.path.normcase is *not* the primitive to use here.  It only folds
    case on Windows; on darwin it is the identity function (verified on this
    host), so it silently leaves the bypass wide open.  Fold explicitly.

    Folding unconditionally is the safe direction: on a case-sensitive volume
    it can only ever over-match (deny a name that differs just by case), never
    under-match.  A denied file is a visible annoyance; a leaked signing key is
    not.
    """
    try:
        text = str(value)
    except RecursionError:
        return ""
    except Exception:
        return ""
    return text.lower()


def is_protected(p: Path) -> bool:
    """True when *p* is inside a protected subtree or is a protected file."""
    folded = _fold(p)
    for d in PROTECTED_DIRS:
        try:
            resolved_dir = d.resolve()
        except (OSError, RuntimeError, ValueError):
            continue
        folded_dir = _fold(resolved_dir)
        if folded == folded_dir:
            return True
        # Compare on the folded strings rather than Path.relative_to(): the
        # trailing separator keeps `/a/bcd` from matching the parent `/a/bc`.
        if folded.startswith(folded_dir.rstrip(os.sep) + os.sep):
            return True
    name = _fold(p.name)
    if name in {_fold(n) for n in PROTECTED_NAMES}:
        return True
    if any(name.startswith(_fold(pre)) for pre in PROTECTED_PREFIXES):
        return True
    return any(name.endswith(_fold(suf)) for suf in PROTECTED_SUFFIXES)


FB_LABEL = "local.filebrowser"
FB_PLIST = Path(AGENTS_DIR) / f"{FB_LABEL}.plist"
FB_BIN = SERVICES_ROOT / "filebrowser" / "filebrowser-bin"
FB_DB = SERVICES_ROOT / "filebrowser" / "filebrowser.db"
FB_PORT = 8125
FB_ROOT_DEFAULT = SERVICES_ROOT / "media"
# Not /tmp: that directory is world-writable and sticky, so any other local
# account could pre-create this name as a symlink and have ServerHub append the
# child's output into a file of the attacker's choosing, running as the panel
# user.  ~/Library/Logs is the macOS convention, is inside the 0700 home, and is
# already where the LaunchAgent variant of this service writes.
FB_LOG = HOME / "Library" / "Logs" / "filebrowser-hub.log"

# Session note: whether this hub session started FB (so stop can free memory)
_started_by_hub = False


def _settings() -> dict:
    return settings_section("files")


def _setting(key: str, default=None):
    """One files-settings value, or *default* when the section cannot answer.

    ``settings_section`` launders the section *mapping* with ``dict(...)``,
    but a plain-dict copy keeps hostile **keys** as-is — and a ``.get`` on
    the copy is still a hash-table probe.  A leftover key whose ``__hash__``
    collides with the literal being fetched runs its ``__eq__`` during that
    probe (CPython demotes the table to the general lookup once a non-exact
    -str key is inserted), so a raising ``__eq__`` blew
    ``_settings().get("roots")`` at the head of :func:`default_roots` —
    500ing GET /api/files, /api/files/list, download and every Files write
    at once, because ``_resolve_safe`` starts there — and
    ``.get("max_upload_mb")`` in :func:`_max_upload_mb`, which 500'd POST
    /api/files/upload after the multipart body was already accepted.  The
    sibling ``show_hidden`` read only survived because its ``bool(...)``
    try happened to wrap the get too.

    A section that cannot even answer a key lookup degrades to the absent
    -key default (the files12 ``_isinst`` fail-closed direction): ``roots``
    falls back to the default candidates, the upload cap to 512 MB.  The
    ``_settings()`` call sits inside the try so a raising section provider
    degrades the same way instead of 500ing.
    """
    try:
        return dict.get(_settings(), key, default)
    except Exception:
        return default


def _rc_int(rc) -> int:
    """Exact int from an ``sh()`` return code; junk reads as ``-255``.

    ``rc == 0`` in :func:`filebrowser_status` ran a leftover int-subclass's
    own ``__eq__``/``__ne__`` — a bomb there raised straight out of the
    status read and 500'd GET /api/files (the Files page's first request:
    ``overview()`` embeds the FileBrowser status next to the roots), GET
    /api/files/filebrowser and both sidecar mutations.  ``int.__index__``
    reads the real value underneath a subclass override, so an honest exit
    in a bombed wrapper survives, while a *lying* ``__class__`` impostor
    (claims int/bool over no real int storage) TypeErrors on the unbound
    read and drops with the junk (the nginx/docker_cli/host_address
    ``_rc_int`` rule).  ``-255`` is no honest exit status, so junk always
    keeps the not-running/failure branch — it can never read as success.
    """
    if type(rc) is int:
        pass
    elif rc is True:
        return 1
    elif rc is False:
        return 0
    elif _isinst(rc, int):
        try:
            rc = int.__index__(rc)
        except Exception:
            return -255
    else:
        try:
            rc = int(rc)
        except Exception:
            return -255
    try:
        # An over-cap exact int (>4300 digits — YAML/plist hex loads dodge
        # the parse-time cap) is unrenderable anywhere downstream; junk.
        str(rc)
    except Exception:
        return -255
    return rc


def _sh3(value) -> tuple:
    """Exact ``(rc, out, err)`` storage from a possibly-poisoned ``sh`` answer.

    A real spawn always answers an exact 3-tuple, but this module does not
    own ``sh`` (tests and tooling patch it — the gateway5/brew rule): a
    tuple/list *subclass* whose bound ``__iter__`` bombs — or a lying
    ``__class__`` impostor claiming tuple/list over no real sequence
    storage — raised straight out of ``rc, out, _ = sh(...)`` in
    :func:`filebrowser_status`, and a wrong-arity answer (bare ``None``, a
    2-tuple) was a TypeError/ValueError the same way — each a raw 500 on
    GET /api/files.  The unbound base reads see the real C-level storage,
    so an honest answer in a subclass wrapper survives untouched, while
    junk degrades to ``(-255, "", "")``.
    """
    if type(value) is tuple:
        items = value
    elif _isinst(value, tuple):
        try:
            items = tuple(tuple.__iter__(value))
        except Exception:
            return (-255, "", "")
    elif _isinst(value, list):
        try:
            items = tuple(list.__getitem__(value, slice(None)))
        except Exception:
            return (-255, "", "")
    else:
        return (-255, "", "")
    if len(items) != 3:
        return (-255, "", "")
    return items


def _sh_triple(cmd, timeout: int) -> tuple:
    """Spawn with the unpack inside the guard (the brew/nginx ``_sh_triple`` rule).

    The production ``sh`` never raises and always answers ``(rc, out,
    err)``, but a patched or odd one can raise outright (RecursionError
    from a leftover ``str(e)`` on a nested exception is not ValueError;
    FileNotFoundError from a stub) or answer a wrong-arity tuple / bare
    ``None`` — every one of those used to ride to Starlette uncaught and
    500 GET /api/files, GET /api/files/filebrowser, POST
    /api/files/filebrowser/ensure and /stop.  A raising or unusable runner
    degrades to the ``-255`` failure triple: no files caller classifies
    rc values beyond zero/nonzero, so the sidecar simply reads as
    not-running and the roots/listing payload beside it keeps serving.
    """
    try:
        answer = sh(cmd, timeout=timeout)
    except Exception as exc:
        return -255, "", _as_text(exc)
    rc, out, err = _sh3(answer)
    return _rc_int(rc), out, err


def _host_text() -> str:
    """The advertised host as exact text; a raising/odd provider reads as localhost.

    This module does not own ``host_ip`` (tests and tooling patch it — the
    same rule the runner seam earned in :func:`_sh_triple`), and
    :func:`filebrowser_status` interpolated its answer into an f-string
    *before* the ``_as_text`` scrub could run: ``f"http://{host}:…"`` calls
    the answer's own ``__format__``, so a provider raising outright — or
    answering a str subclass whose ``__format__`` bombs — detonated one seam
    ahead of the launderer.  Confirmed live before the fix: each shape was a
    raw HTTP 500 on GET /api/files (the Files page's first request:
    ``overview()`` embeds this status beside the roots), GET
    /api/files/filebrowser, POST /api/files/filebrowser/ensure and /stop.
    ``_as_text`` reduces every honest answer (bytes, surrogates, subclass
    wrappers) to an exact str the f-string cannot detonate on; junk and a
    raising provider degrade to ``localhost`` — the sidecar URL is a hint,
    not a gate, so a wrong-but-renderable host is strictly better than
    taking down the roots payload beside it.
    """
    try:
        host = host_ip()
    except Exception:
        return "localhost"
    return _as_text(host).strip() or "localhost"


def _spawn_env() -> dict:
    """A real dict for ``subprocess.Popen(env=…)``; junk degrades to ``{}``.

    This module does not own ``utf8_env`` either, and the direct-spawn
    branch of :func:`ensure_filebrowser` evaluated it *inside* a try whose
    except arm is typed ``(OSError, ValueError, TypeError)`` — a patched or
    odd provider raising anything else (RuntimeError from a leftover
    ``str(e)`` chain, RecursionError) escaped the arm and 500'd POST
    /api/files/filebrowser/ensure raw, after the log/media directories were
    already created.  A dict *subclass* answer is materialised through the
    unbound ``dict.items`` so a hostile bound ``items``/``keys`` cannot
    raise later inside ``Popen``'s own env walk, past the typed arm the
    same way.  ``{}`` is the safe floor: FileBrowser needs no inherited
    variables to start, and a spawn with an empty env still serves.
    """
    try:
        env = utf8_env()
    except Exception:
        return {}
    if type(env) is dict:
        return env
    if _isinst(env, dict):
        try:
            return dict(dict.items(env))
        except Exception:
            return {}
    return {}


def _isinst(value, types) -> bool:
    """``isinstance`` that a leftover ``__class__`` bomb cannot 500 through.

    CPython's ``isinstance`` reads the operand's ``__class__`` whenever the
    real-type fast check misses, so a leftover whose ``__class__`` is a
    raising property blew straight through a bare type gate before any
    launderer could run.  Two such gates sat outside a try and 500'd raw:
    ``isinstance(_settings().get("roots"), list)`` in :func:`default_roots`
    (every Files route starts there) and ``isinstance(raw, bool)`` on a
    ``max_upload_mb`` leftover in :func:`_max_upload_mb` (POST
    /api/files/upload).  A raising ``__class__`` is treated as "none of
    these types" — fail closed to the default/scrub branch (the
    modules8/catalog10/tools ``_isinst`` rule).
    """
    try:
        return isinstance(value, types)
    except Exception:
        return False


def _as_text(value) -> str:
    """JSON-safe text. Leftover ``\\ud800`` in a filename used to 500 Files JSON.

    Unbound base-type calls only (the config._env_text / audit._utf8_text
    convention): ``str(value)`` answers *self* for a str subclass whose
    ``__str__`` returns self, so the final scrub used to run the subclass's
    own bound ``encode`` — and a leftover encode bomb riding a configured
    root's ``id``/``name`` raised out of this launderer and dropped the whole
    root row instead of degrading the one value.  Same for a bytes subclass
    overriding ``decode``.  ``str.encode(value, ...)`` reads the C-level
    storage, bypassing the override at no copy cost.
    """
    if _isinst(value, (bytes, bytearray)):
        base = bytes if _isinst(value, bytes) else bytearray
        try:
            value = base.decode(value, "utf-8", "replace")
        except Exception:
            return ""
    elif value is None:
        return ""
    else:
        try:
            value = str(value)
        except RecursionError:
            try:
                return type(value).__name__
            except Exception:
                return ""
        except Exception:
            return ""
    if not _isinst(value, str):
        return ""
    try:
        return str.encode(value, "utf-8", "replace").decode("utf-8")
    except Exception:
        return ""


def _finite_int(value, default: int = 0) -> int:
    """A stat number JSON and headers can carry, or *default*.

    ``int(...)`` with a try only guards *conversions*: a leftover FUSE/SMB
    ``st_size`` that is already a >4300-digit int passes through untouched,
    and CPython's int->str digit limit then ValueError'd Starlette's
    ``json.dumps`` — 500ing GET /api/files/list after the listing had
    already been built — and the ``str(length)`` Content-Length header on
    GET /api/files/download.  ``float()`` rejects anything beyond float
    range, the same junk test hub/backups.py applies to its stat numbers.
    """
    try:
        value = int(value)
        float(value)
    except Exception:
        # (TypeError, ValueError, OverflowError, OSError) are the ordinary
        # conversion failures.  The broad arm also eats a leftover int
        # *subclass* whose ``__int__``/``__index__`` raises (the modules5
        # bomb class): planted as ``max_upload_mb``, its RuntimeError used
        # to escape the named tuple and 500 POST /api/files/upload raw.
        return default
    return value


def _max_upload_mb() -> int:
    """The configured upload cap in MB, or 512 on junk.

    ``int(raw)`` with a try only guards *conversions*: YAML parses hex and
    octal integer text uncapped (``int(x, 16)`` is a power-of-two base, so
    CPython's 4300-digit parse limit does not apply), and a leftover
    ``max_upload_mb: 0xFFF…`` was therefore already an over-cap int that
    passed straight through — silently disabling the upload size cap, and
    handing ``files.upload_too_large`` an over-cap ``max_mb`` param that
    ``json.dumps`` cannot render.  :func:`_finite_int`'s float() probe
    rejects anything beyond float range, the same junk test the stat
    numbers get.
    """
    # ``_setting``, not ``_settings().get``: a leftover section key whose
    # ``__hash__`` collides with this literal ran its raising ``__eq__``
    # inside the hash-table probe and 500'd POST /api/files/upload.
    raw = _setting("max_upload_mb")
    # ``_isinst``, not bare ``isinstance``: a leftover ``max_upload_mb`` whose
    # ``__class__`` is a raising property read the operand's ``__class__`` on
    # the real-type miss and 500'd POST /api/files/upload before the
    # ``_finite_int`` scrub could reject it (the modules8/_isinst rule).
    if raw is None or _isinst(raw, bool):
        return 512
    max_mb = _finite_int(raw, 512)
    if max_mb <= 0:
        return 512
    return max_mb


def _root_label(value) -> str:
    """Configured root id/name as text, via a ``str()`` probe.

    YAML parses ``id: 2`` / ``name: 2024`` as ints, and the previous
    ``isinstance(value, str)`` gate silently replaced them with the directory
    basename.  Two configured roots whose directories share a basename then
    collapsed onto one id: the SPA's picker showed two identical entries and
    ``root_id=2`` — the id the YAML author wrote — answered
    ``files.unknown_root`` (400) with the directory sitting right there.
    Probe with ``str()`` instead (``_as_text`` already eats the ValueError a
    leftover over-cap hex int raises past CPython's digit limit, and scrubs
    lone surrogates before Starlette's UTF-8 encode); only ``None``/bool —
    YAML's ``id: yes`` footgun, junk everywhere else in this file — fall back
    to the basename.
    """
    if value is None or _isinst(value, bool):
        return ""
    return _as_text(value).strip()


def _try_resolve(value) -> Path | None:
    """Resolve *value*, or None on a leftover path the kernel will not follow.

    Python 3.12 ``Path.resolve()`` raises RuntimeError on a symlink loop.
    Python 3.14's non-strict resolve returns the looping path instead, and
    later ``relative_to`` / ``exists`` checks used to surface
    ``files.path_outside_root`` or succeed.  ``stat`` still ELOOP's.
    """
    try:
        p = Path(os.path.expanduser(str(value))).resolve()
    except (OSError, ValueError, TypeError, RuntimeError):
        return None
    try:
        os.stat(p)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return None
    except (ValueError, TypeError, RuntimeError):
        return None
    return p


def _is_dir(p: Path) -> bool:
    try:
        return p.is_dir()
    except OSError:
        return False


def _exists(p: Path) -> bool:
    try:
        return p.exists()
    except OSError:
        return False


def default_roots() -> list[dict]:
    """Allowlisted roots. Configurable via settings.files.roots."""
    # ``_setting``, not ``_settings().get``: a leftover section key whose
    # ``__hash__`` collides with ``"roots"`` ran its raising ``__eq__``
    # inside the hash-table probe — before any value gate could help — and
    # 500'd every Files route, because ``_resolve_safe`` starts here.
    custom = _setting("roots")
    # ``_isinst``, not bare ``isinstance``: this gate is the first thing every
    # Files route runs (``_resolve_safe`` → ``default_roots``), and a leftover
    # ``roots`` value whose ``__class__`` is a raising property made
    # ``isinstance`` consult that property on the real-type miss and 500'd GET
    # /api/files, /api/files/list and every sibling raw.  A raising
    # ``__class__`` fails closed here to "not a list", so the section degrades
    # to the default candidates like an absent key (the modules8/_isinst rule).
    if _isinst(custom, list):
        # Materialised once, guarded: settings_section() launders the section
        # mapping but not the values inside it, so a leftover list *subclass*
        # whose ``__iter__`` (or ``__len__``, via the old truthiness test)
        # raises used to 500 GET /api/files and /api/files/list — and with
        # them every route, because _resolve_safe() starts here.  The bomb
        # cannot yield its rows, so it degrades to the default candidates
        # like an absent key.
        try:
            custom = list(custom)
        except Exception:
            custom = []
    else:
        custom = []
    if custom:
        out = []
        for r in custom:
            try:
                if _isinst(r, str):
                    p = _try_resolve(r)
                    if p is None:
                        continue
                    out.append({
                        "id": _as_text(p.name or "root") or "root",
                        "name": _as_text(p.name or str(p)) or "root",
                        "path": _as_text(p),
                    })
                elif _isinst(r, dict):
                    # Unbound ``dict.get`` (the settings_section convention):
                    # a leftover dict *subclass* row whose bound ``.get`` /
                    # ``__getitem__`` raises used to blow up here — and when
                    # the bomb raised anything outside the old (OSError,
                    # ValueError, TypeError, RuntimeError) arm (a KeyError
                    # get-bomb, say) it escaped the per-row guard entirely
                    # and 500'd every Files route, because _resolve_safe()
                    # starts at default_roots().  The unbound builtin reads
                    # the C-level storage, so the row now *serves* instead
                    # of dropping — its keys are real; only the override is
                    # hostile.
                    raw_path = dict.get(r, "path")
                    if not raw_path:
                        continue
                    p = _try_resolve(raw_path)
                    if p is None:
                        continue
                    rid = _root_label(dict.get(r, "id")) or _as_text(p.name) or "root"
                    rname = (
                        _root_label(dict.get(r, "name"))
                        or _as_text(p.name or str(p))
                        or "root"
                    )
                    out.append({
                        "id": rid,
                        "name": rname,
                        "path": _as_text(p),
                    })
            except Exception:
                # Broad like the list() guard above: whatever a bombing row
                # value raises (a ``__bool__`` bomb on the path value is not
                # bound to any exception type), the cost is that one row,
                # never the whole Files page.
                continue
        return [x for x in out if _is_dir(Path(x["path"]))]
    candidates = [
        {"id": "services", "name": "Services", "path": str(SERVICES_ROOT)},
        {"id": "media", "name": "Media", "path": str(SERVICES_ROOT / "media")},
        # NOTE: the whole home directory is deliberately NOT a default root — it
        # exposed ~/.ssh and every dotfile credential store.  Users who want it
        # can opt in explicitly via settings.files.roots.
        {"id": "downloads", "name": "Downloads", "path": str(HOME / "Downloads")},
        {"id": "documents", "name": "Documents", "path": str(HOME / "Documents")},
    ]
    out = []
    for c in candidates:
        p = Path(c["path"])
        if not _exists(p):
            continue
        resolved = _try_resolve(p)
        if resolved is not None:
            out.append({
                **c,
                "id": _as_text(c["id"]),
                "name": _as_text(c["name"]),
                "path": _as_text(resolved),
            })
    return out


def _resolve_safe(path: str | None, root_id: str | None = None) -> Path:
    """Resolve path, ensure it stays under an allowed root and is not protected."""
    roots = default_roots()
    if not roots:
        raise api_error("files.no_roots")

    root_path: Path | None = None
    if root_id:
        matched = False
        for r in roots:
            if r["id"] == root_id:
                matched = True
                root_path = _try_resolve(r["path"])
                break
        if not matched or root_path is None:
            raise api_error("files.unknown_root", root_id=root_id)

    if not path or path in (".", "/"):
        if root_path:
            return root_path
        first = _try_resolve(roots[0]["path"])
        if first is None:
            raise api_error("files.no_roots")
        return first

    p = _try_resolve(path)
    if p is None:
        raise api_error("files.not_found", path=str(path)[:200])

    # must be under some allowed root
    if root_path:
        allowed = [root_path]
    else:
        allowed = []
        for r in roots:
            resolved = _try_resolve(r["path"])
            if resolved is not None:
                allowed.append(resolved)
        if not allowed:
            raise api_error("files.no_roots")
    ok = False
    for a in allowed:
        try:
            p.relative_to(a)
            ok = True
            break
        except ValueError:
            continue
    if not ok:
        raise api_error("files.path_outside_root")
    # Protected paths are rejected here, at the single choke point every
    # list/download/upload/rename/delete call passes through, so supplying an
    # exact path cannot bypass the check the way listing filters can.
    if is_protected(p):
        raise api_error("files.path_protected")
    return p


def _entry(p: Path, root: Path) -> dict:
    try:
        st = p.lstat()
    except (OSError, ValueError, TypeError) as e:
        # ValueError: leftover ``\\ud800`` in a FUSE/SMB name. pathlib
        # exists/is_dir swallow that; lstat/open do not.
        return {"name": _as_text(p.name), "error": _as_text(e)}
    try:
        is_link = p.is_symlink()
        is_dir = p.is_dir() and not is_link
        # follow only for size of regular files
        size = 0
        if p.is_file():
            size = _finite_int(st.st_size)
            if size < 0:
                size = 0
        try:
            rel = str(p.relative_to(root)) if p != root else ""
        except ValueError:
            rel = p.name
        mtime = _finite_int(st.st_mtime)
        try:
            mode = stat.filemode(int(st.st_mode))
        except (TypeError, ValueError, OverflowError):
            mode = ""
        return {
            "name": _as_text(p.name or str(p)),
            "path": _as_text(p),
            "rel": _as_text(rel),
            "is_dir": bool(is_dir or (is_link and p.is_dir())),
            "is_file": p.is_file(),
            "is_link": is_link,
            "size": size,
            "mtime": mtime,
            "mode": mode,
            "ext": _as_text(p.suffix.lower()) if p.is_file() else "",
        }
    except (OSError, TypeError, ValueError) as e:
        return {"name": _as_text(p.name), "error": _as_text(e)}


def list_dir(path: str | None = None, root_id: str | None = None) -> dict:
    p = _resolve_safe(path, root_id)
    try:
        exists = p.exists()
        is_dir = p.is_dir() if exists else False
    except OSError:
        # exists/is_dir on a dying FUSE mount raise EIO before iterdir.
        raise api_error("files.permission_denied", path=str(p))
    if not exists:
        raise api_error("files.not_found", path=str(p))
    if not is_dir:
        raise api_error("files.not_a_dir")

    # pick root for relative paths
    roots = default_roots()
    if not roots:
        raise api_error("files.no_roots")
    root = _try_resolve(roots[0]["path"])
    if root is None:
        raise api_error("files.no_roots")
    if root_id:
        for r in roots:
            if r["id"] == root_id:
                resolved = _try_resolve(r["path"])
                if resolved is not None:
                    root = resolved
                break
    else:
        for r in roots:
            rp = _try_resolve(r["path"])
            if rp is None:
                continue
            try:
                p.relative_to(rp)
                root = rp
                root_id = r["id"]
                break
            except ValueError:
                continue

    items = []
    try:
        # exists/is_dir above can lose a race: the directory is unmounted or
        # replaced before iterdir, and FileNotFoundError / NotADirectoryError
        # used to 500 the Files page.
        children = list(p.iterdir())
    except FileNotFoundError:
        raise api_error("files.not_found", path=str(p))
    except NotADirectoryError:
        raise api_error("files.not_a_dir")
    except PermissionError:
        raise api_error("files.permission_denied", path=str(p))
    except OSError:
        # Dying FUSE/SMB mounts raise EIO / EINVAL rather than PermissionError.
        raise api_error("files.permission_denied", path=str(p))
    try:
        # bool(), guarded: a leftover ``show_hidden`` whose ``__bool__``
        # raises (the bookmarks5 BoolBomb class) used to escape here and
        # 500 GET /api/files/list after the directory was already read.
        # ``_setting`` for the read itself: a hash-colliding eq-bomb key
        # answers the default instead of relying on this try alone.
        show_hidden = bool(_setting("show_hidden"))
    except Exception:
        show_hidden = False
    for c in children:
        if c.name.startswith(".") and not show_hidden:
            continue
        # Also omit protected entries so they do not show up as rows that
        # error on every click.  _resolve_safe() is the actual gate.
        if is_protected(c):
            continue
        items.append(_entry(c, root))
    items.sort(key=lambda x: (not x.get("is_dir"), (x.get("name") or "").lower()))

    # breadcrumb
    crumbs = []
    cur = p
    while True:
        try:
            cur.relative_to(root)
        except ValueError:
            break
        crumbs.append({"name": _as_text(cur.name or root.name), "path": _as_text(cur)})
        if cur == root:
            break
        cur = cur.parent
    crumbs.reverse()

    return {
        "path": _as_text(p),
        "root_id": _as_text(root_id) if root_id else root_id,
        "root": _as_text(root),
        "crumbs": crumbs,
        "items": items,
        "count": len(items),
    }


def _clean_component(value: str | None) -> str:
    """A single path component: no separators and no control characters.

    Stripping only ``/`` and ``\\`` left tabs, newlines and other control bytes
    in the name.  That is not just cosmetic: a directory created here can later
    be handed to ``POST /api/nfs/exports``, and exports(5) is whitespace
    delimited, so a name containing a tab split one validated path into several
    fields in the root-owned /etc/exports.  Names like this are never
    intentional, so refuse them at the point of creation too.
    """
    if value is None:
        text = ""
    elif not isinstance(value, str):
        raise api_error("files.bad_name")
    else:
        text = value.strip().replace("/", "").replace("\\", "")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in text):
        raise api_error("files.bad_name")
    # Leftover ``\\ud800`` is not a control byte; Path.lstat/mkdir still
    # UnicodeEncodeError, and the JSON encoder then 500s the Files page.
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        raise api_error("files.bad_name")
    return text


def mkdir(path: str, name: str, root_id: str | None = None) -> dict:
    parent = _resolve_safe(path, root_id)
    try:
        is_dir = parent.is_dir()
    except OSError:
        raise api_error("files.permission_denied", path=str(parent))
    if not is_dir:
        raise api_error("files.parent_not_a_dir")
    name = _clean_component(name)
    if not name or name in (".", ".."):
        raise api_error("files.bad_name")
    try:
        dest = (parent / name).resolve()
    except (OSError, ValueError, RuntimeError):
        raise api_error("files.bad_name")
    _resolve_safe(str(dest), root_id)  # re-check under root
    try:
        # O_EXCL equivalent: exists-then-mkdir raced and FileExistsError 500'd
        # the Files page.  Let the kernel decide.
        dest.mkdir(parents=False)
    except FileExistsError:
        raise api_error("files.exists")
    except FileNotFoundError:
        # Parent vanished between is_dir and mkdir.
        raise api_error("files.parent_not_a_dir")
    except NotADirectoryError:
        raise api_error("files.parent_not_a_dir")
    except OSError:
        raise api_error("files.permission_denied", path=str(dest))
    return {"ok": True, "path": _as_text(dest)}


def _rmtree_iterative(top: Path) -> None:
    """Remove directory *top* and its subtree without Python-level recursion.

    CPython 3.12 ``shutil.rmtree`` descends one Python frame per directory
    level, so a leftover ~1000-deep tree — buildable one level at a time
    through POST /api/files/mkdir, or dropped by a runaway script or a tar
    bomb of relative paths — raised RecursionError mid-walk.  That is not
    OSError, so it escaped :func:`delete_path`'s except arms and answered a
    raw HTTP 500 after part of the tree was already gone, and every retry
    500'd the same way.

    Same walk shape as shutil's safe-fd path — ``O_NOFOLLOW`` descent via
    ``dir_fd`` so a symlink swapped in mid-delete is unlinked, never
    followed, and parent fds stay open so a moved ancestor cannot redirect
    the deletion — but with an explicit frame stack.  The depth bound
    becomes the process fd limit; running into it is OSError (EMFILE),
    which callers already map to the coded error.  Raises OSError exactly
    like ``shutil.rmtree(ignore_errors=False)``; entries that vanish
    mid-walk are treated as already deleted rather than raised, because a
    concurrent deletion is this operation's goal, not its failure.
    """
    o_dir = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW
    top_fd = os.open(top, o_dir)
    # One frame per open directory: (fd, scandir iterator, name in parent,
    # parent fd).  The top frame has no parent; it is rmdir'd by path.
    frames: list[tuple[int, object, str | None, int | None]] = []

    def _push(fd: int, name: str | None, parent_fd: int | None) -> None:
        try:
            it = os.scandir(fd)
        except BaseException:
            os.close(fd)
            raise
        frames.append((fd, it, name, parent_fd))

    try:
        _push(top_fd, None, None)
        while frames:
            fd, it, name, parent_fd = frames[-1]
            entry = next(it, None)
            if entry is None:
                frames.pop()
                it.close()
                os.close(fd)
                try:
                    if parent_fd is None:
                        os.rmdir(top)
                    else:
                        os.rmdir(name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
                continue
            try:
                st = os.lstat(entry.name, dir_fd=fd)
            except FileNotFoundError:
                continue
            if stat.S_ISDIR(st.st_mode):
                try:
                    child = os.open(entry.name, o_dir, dir_fd=fd)
                except FileNotFoundError:
                    continue
                _push(child, entry.name, fd)
            else:
                try:
                    os.unlink(entry.name, dir_fd=fd)
                except FileNotFoundError:
                    pass
    finally:
        # Only reached with frames left when an OSError is propagating;
        # release the walk's fds so the coded-error path does not leak them.
        for fd, it, _name, _parent in frames:
            try:
                it.close()
            except Exception:
                pass
            try:
                os.close(fd)
            except OSError:
                pass


def delete_path(path: str, root_id: str | None = None) -> dict:
    p = _resolve_safe(path, root_id)
    # never delete roots themselves
    for r in default_roots():
        resolved = _try_resolve(r["path"])
        if resolved is not None and p == resolved:
            raise api_error("files.cannot_delete_root")
    try:
        # exists-then-unlink raced: a file removed between the check and the
        # syscall raised FileNotFoundError and 500'd the Files page.
        if p.is_dir() and not p.is_symlink():
            _rmtree_iterative(p)
        else:
            p.unlink()
    except FileNotFoundError:
        raise api_error("files.not_found", path=str(p)[:200])
    except NotADirectoryError:
        # is_dir() then rmtree: the path became a file in the gap.
        try:
            p.unlink()
        except FileNotFoundError:
            raise api_error("files.not_found", path=str(p)[:200])
        except OSError:
            raise api_error("files.permission_denied", path=str(p))
    except OSError:
        raise api_error("files.permission_denied", path=str(p))
    return {"ok": True, "path": _as_text(p)}


#: Darwin ``renameatx_np`` / ``AT_FDCWD`` / ``RENAME_EXCL``.
_AT_FDCWD = -2
_RENAME_EXCL = 0x0004
_renameatx_np = None


def _dir_rename_no_clobber(src: Path, dest: Path) -> None:
    """Rename a directory without replacing dest.

    POSIX ``rename`` of a directory onto an empty dest directory succeeds and
    deletes dest.  ``dest.exists()`` then ``os.rename`` is therefore still a
    TOCTOU for directories.  ``renameatx_np(RENAME_EXCL)`` is one syscall.
    When libSystem is absent, refuse dest via lstat before rename — never
    ``os.rename`` onto an existing empty directory.
    """
    global _renameatx_np
    import ctypes

    if _renameatx_np is None:
        try:
            libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
            fn = libc.renameatx_np
            fn.argtypes = [
                ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint,
            ]
            fn.restype = ctypes.c_int
            _renameatx_np = fn
        except OSError:
            _renameatx_np = False
    if _renameatx_np:
        rc = _renameatx_np(
            _AT_FDCWD, os.fsencode(src), _AT_FDCWD, os.fsencode(dest), _RENAME_EXCL,
        )
        if rc == 0:
            return
        err = ctypes.get_errno() or errno.EIO
        raise OSError(err, os.strerror(err), str(src), None, str(dest))
    try:
        os.lstat(dest)
    except FileNotFoundError:
        os.rename(src, dest)
        return
    raise OSError(errno.EEXIST, os.strerror(errno.EEXIST), str(src), None, str(dest))


def _rename_no_clobber(src: Path, dest: Path) -> None:
    """Rename *src* to *dest* without replacing an existing dest.

    POSIX ``rename`` replaces a dest file (and an empty dest directory).
    ``dest.exists()`` then ``Path.rename`` is a TOCTOU: a name planted in the
    gap is overwritten and ``FileExistsError`` is never raised.  ``link`` +
    ``unlink`` is exclusive for files; directories use ``RENAME_EXCL``.
    """
    try:
        directory = src.is_dir() and not src.is_symlink()
    except OSError:
        directory = False
    if directory:
        _dir_rename_no_clobber(src, dest)
        return
    os.link(src, dest)
    try:
        src.unlink()
    except FileNotFoundError:
        # Dest holds the remaining link; the rename completed.
        pass


def rename_path(path: str, new_name: str, root_id: str | None = None) -> dict:
    p = _resolve_safe(path, root_id)
    new_name = _clean_component(new_name)
    if not new_name or new_name in (".", ".."):
        raise api_error("files.bad_name")
    try:
        dest = (p.parent / new_name).resolve()
    except (OSError, ValueError, RuntimeError):
        raise api_error("files.bad_name")
    try:
        os.stat(dest)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise api_error("files.bad_name")
    _resolve_safe(str(dest), root_id)
    try:
        taken = dest.exists()
    except OSError:
        raise api_error("files.permission_denied", path=str(dest))
    if taken:
        raise api_error("files.dest_exists")
    try:
        _rename_no_clobber(p, dest)
    except FileExistsError:
        raise api_error("files.dest_exists")
    except FileNotFoundError:
        # Source vanished between resolve and rename.  Pass the path: the
        # ``files.not_found`` template interpolates ``{path}``, and raising
        # bare left the literal placeholder in the message the SPA shows
        # (there is no err.files.not_found locale key, so the English
        # fallback is exactly what the operator reads).
        raise api_error("files.not_found", path=str(p)[:200])
    except OSError as exc:
        if exc.errno == errno.EEXIST:
            raise api_error("files.dest_exists")
        if exc.errno in {errno.ENOTEMPTY, errno.EISDIR}:
            raise api_error("files.dest_exists")
        if exc.errno == errno.ENOENT:
            raise api_error("files.not_found", path=str(p)[:200])
        raise api_error("files.permission_denied", path=str(p))
    return {"ok": True, "path": _as_text(dest), "from": _as_text(p)}


def _path_of_fd(fd: int) -> str | None:
    """The path Darwin actually opened, or None when the kernel will not say.

    ``O_NOFOLLOW`` only refuses a symlink at the last component.  An ancestor
    swapped for a symlink after :func:`_resolve_safe` still leads ``open()``
    into STATE_ROOT.  ``F_GETPATH`` is the path of the fd, so the denylist
    can run against what was opened rather than what was asked for.
    """
    try:
        import fcntl

        raw = fcntl.fcntl(fd, fcntl.F_GETPATH, bytes(4096))
    except (OSError, AttributeError, TypeError, ValueError):
        return None
    if not isinstance(raw, (bytes, bytearray)):
        return None
    text = bytes(raw).split(b"\x00", 1)[0].decode("utf-8", "surrogateescape")
    return text or None


def _reject_opened_outside(fd: int, root_id: str | None) -> None:
    opened = _path_of_fd(fd)
    if not opened:
        return
    _resolve_safe(opened, root_id)


def download(path: str, root_id: str | None = None) -> StreamingResponse:
    p = _resolve_safe(path, root_id)
    # Open the last component ourselves. FileResponse would re-open the
    # path after this check, and a symlink planted in that window would
    # be followed into STATE_ROOT secrets. O_NOFOLLOW is one syscall.
    # O_NONBLOCK: a leftover FIFO at this path parked the plain open until a
    # writer appeared — never, for a leftover — so GET /api/files/download
    # held its worker thread forever instead of answering.  With O_NONBLOCK
    # the FIFO opens immediately and the S_ISREG check below refuses it as
    # the coded 400; regular-file reads are unaffected (the same guard as
    # hub.util.read_bytes_capped).
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOENT, errno.EISDIR}:
            raise api_error("files.file_only")
        raise api_error("files.permission_denied", path=str(p))
    except ValueError:
        # Leftover ``\\ud800`` in the last component: os.open encodes
        # strictly, unlike Path.exists.
        raise api_error("files.file_only")
    try:
        try:
            st = os.fstat(fd)
        except OSError:
            # Dying FUSE/SMB after open: EIO used to 500 GET /api/files/download.
            raise api_error("files.permission_denied", path=str(p))
        if not stat.S_ISREG(st.st_mode):
            raise api_error("files.file_only")
        _reject_opened_outside(fd, root_id)
        media = mimetypes.guess_type(str(p))[0] or "application/octet-stream"
        length = _finite_int(st.st_size)
        if length < 0:
            length = 0
        headers = {
            "Content-Length": str(length),
            "Content-Disposition": "attachment; filename*=UTF-8''" + quote(_as_text(p.name)),
        }

        def chunks():
            try:
                while True:
                    buf = os.read(fd, 65536)
                    if not buf:
                        break
                    yield buf
            finally:
                os.close(fd)

        return StreamingResponse(chunks(), media_type=media, headers=headers)
    except Exception:
        os.close(fd)
        raise


async def upload(path: str, file: UploadFile, root_id: str | None = None) -> dict:
    # Every filesystem touch below runs in a worker thread.  This is the only
    # async route that hits the disk, and upload targets include external
    # drives under power management: a stat() or open() against a spun-down
    # HDD blocks for the whole spin-up, and inline on the event loop that
    # freezes every other request in the process for 5-15 seconds.
    def _prepare() -> tuple[Path, str, int]:
        parent = _resolve_safe(path, root_id)
        try:
            is_dir = parent.is_dir()
        except OSError:
            raise api_error("files.permission_denied", path=str(parent))
        if not is_dir:
            raise api_error("files.dest_not_a_dir")
        try:
            raw_name = Path(str(file.filename or "upload.bin")).name
        except (OSError, ValueError, TypeError):
            raise api_error("files.bad_filename")
        name = _clean_component(raw_name)
        if not name or name in (".", ".."):
            raise api_error("files.bad_filename")
        dest = parent / name
        _resolve_safe(str(dest), root_id)
        # Create the last component ourselves.  exists()+open("wb") followed
        # a symlink planted in the gap; O_EXCL|O_NOFOLLOW is one syscall.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        try:
            fd = os.open(dest, flags, 0o644)
        except FileExistsError:
            raise api_error("files.upload_would_overwrite", name=name)
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.EEXIST}:
                raise api_error("files.upload_would_overwrite", name=name)
            if exc.errno in {errno.ENOENT, errno.ENOTDIR}:
                # Parent vanished or became a file between is_dir and open.
                raise api_error("files.dest_not_a_dir")
            raise api_error("files.permission_denied", path=str(dest))
        opened = _path_of_fd(fd)
        if opened:
            try:
                _resolve_safe(opened, root_id)
            except Exception:
                os.close(fd)
                for victim in (opened, dest):
                    try:
                        Path(victim).unlink()
                    except OSError:
                        pass
                raise
        return dest, name, fd

    dest, name, fd = await asyncio.to_thread(_prepare)
    max_mb = _max_upload_mb()
    max_bytes = max_mb * 1024 * 1024
    written = 0
    try:
        f = os.fdopen(fd, "wb")
        fd = -1
        try:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    raise api_error("files.upload_too_large", max_mb=max_mb)
                await asyncio.to_thread(f.write, chunk)
            # The close sits INSIDE the guarded region: it flushes the
            # buffered tail, so ENOSPC/EIO surfaces here as readily as in
            # write() — and used to escape this function raw (see below)
            # with the torn file left on disk.
            await asyncio.to_thread(f.close)
        except BaseException:
            try:
                # No-op when the failure came from f.close() itself:
                # BufferedWriter closes the raw fd even when its flush
                # raises, and a second close() on a closed file returns.
                await asyncio.to_thread(f.close)
            except OSError:
                pass
            try:
                await asyncio.to_thread(dest.unlink)
            except OSError:
                pass
            raise
    except OSError as exc:
        # A failing disk write (ENOSPC on a full volume, EIO on a dying
        # FUSE/SMB mount) is OSError out of write()/close() — none of the
        # except arms mapped it, so POST /api/files/upload answered a raw
        # uncoded 500 after validation had already passed.  503 like
        # compose.save_failed / settings.save_failed: a disk that cannot
        # be written is a dependency state, not a defect in the upload.
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            await asyncio.to_thread(dest.unlink)
        except OSError:
            pass
        raise api_error("files.upload_write_failed", error=exc_detail(exc))
    except BaseException:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        raise
    finally:
        await file.close()
    return {"ok": True, "path": _as_text(dest), "size": written, "name": _as_text(name)}


# ─── Optional FileBrowser process (full UI) ───────────────────────────────────

def filebrowser_status() -> dict:
    running = False
    pid = None
    # _sh_triple, not a bare unpack + ``rc == 0``: this module does not own
    # ``sh``, and a raising runner / wrong-arity answer / rc-``__eq__`` bomb
    # each used to raise out of this status read and 500 GET /api/files
    # (overview embeds this status beside the roots), GET
    # /api/files/filebrowser and both sidecar mutations.
    rc, out, _ = _sh_triple(["/bin/launchctl", "print", f"gui/{UID}/{FB_LABEL}"], timeout=5)
    out = _as_text(out)
    if rc == 0 and "state = running" in out:
        running = True
        for line in out.splitlines():
            if "pid =" in line:
                try:
                    pid = int(line.split("=")[-1].strip())
                except (TypeError, ValueError, OverflowError):
                    pass
    if not running:
        rc2, out2, _ = _sh_triple(["/usr/bin/pgrep", "-x", "filebrowser-bin"], timeout=5)
        out2 = _as_text(out2)
        if rc2 == 0 and out2.strip():
            running = True
            try:
                pid = int(out2.splitlines()[0].strip())
            except (TypeError, ValueError, OverflowError):
                pass
    # _host_text, not a bare host_ip(): this module does not own the host
    # provider, and a raising one — or a str-subclass answer whose
    # ``__format__`` bombs — used to detonate the f-string below one seam
    # ahead of _as_text and 500 GET /api/files, GET /api/files/filebrowser,
    # POST ensure and POST stop.
    host = _host_text()
    # _as_text, not str: these paths derive from the home directory, and a
    # home whose on-disk name holds undecodable bytes reaches here as lone
    # surrogates (os surrogateescape).  The listing fields are sanitized in
    # _entry(); these were returned raw, so GET /api/files used to 500 at
    # Starlette's UTF-8 encode while the listing itself was clean.
    return {
        "installed": _exists(FB_BIN) or _exists(FB_PLIST),
        "running": running,
        "pid": pid,
        "port": FB_PORT,
        "url": _as_text(f"http://{host}:{FB_PORT}"),
        "plist": _as_text(FB_PLIST) if _exists(FB_PLIST) else None,
        "bin": _as_text(FB_BIN) if _exists(FB_BIN) else None,
        "root": _as_text(FB_ROOT_DEFAULT),
        "started_by_hub": _started_by_hub,
        "keepalive": _plist_keepalive(),
    }


def _plist_keepalive() -> bool | None:
    if not _exists(FB_PLIST):
        return None
    try:
        import plistlib
        pl = plistlib.loads(read_bytes_capped(FB_PLIST, _PLIST_CAP))
        return bool(isinstance(pl, dict) and pl.get("KeepAlive"))
    except Exception:
        return None


def _fb_on_disk() -> bool:
    """True when the FileBrowser binary is still present on disk.

    Every failed direct spawn collapses into the same except arm below, so
    mapping it to the coded 503 must first confirm the binary actually left
    the disk (the docker ``cli_on_disk`` / vms ``_cli_missing`` /
    photoshub ``_ctl_on_disk`` rule) — with the binary still present, the
    raw start failure is the truth.  A stat that raises (EIO under a dying
    volume holding ~/Services) counts as gone: the tool is unreachable
    either way.
    """
    try:
        return FB_BIN.is_file()
    except (OSError, ValueError):
        return False


def ensure_filebrowser() -> dict:
    """Start FileBrowser only if needed (on-demand)."""
    global _started_by_hub
    st = filebrowser_status()
    if st["running"]:
        return {"ok": True, "message": "FileBrowser is already running", **st, "started": False}
    if not _exists(FB_BIN) and not _exists(FB_PLIST):
        raise api_error("files.fb_not_installed")

    dom = f"gui/{UID}"
    if _exists(FB_PLIST):
        # _sh_triple: the results are ignored, but a *raising* patched/odd
        # runner used to escape these fire-and-forget spawns and 500 POST
        # /api/files/filebrowser/ensure raw.
        _sh_triple(["/bin/launchctl", "bootstrap", dom, str(FB_PLIST)], timeout=10)
        _sh_triple(["/bin/launchctl", "kickstart", "-k", f"{dom}/{FB_LABEL}"], timeout=10)
    elif _exists(FB_BIN):
        # Direct start without KeepAlive. Pass an argv vector so spaces or shell
        # metacharacters in the user's home path can never change the command.
        try:
            FB_ROOT_DEFAULT.mkdir(parents=True, exist_ok=True)
            SERVICES_ROOT.joinpath("filebrowser").mkdir(parents=True, exist_ok=True)
            FB_LOG.parent.mkdir(parents=True, exist_ok=True)
            # O_NOFOLLOW refuses to follow a symlink planted at this exact path,
            # so a pre-existing link fails the start instead of redirecting the
            # child's stdout into whatever it points at.
            # O_NONBLOCK: a leftover FIFO at the log path parked the plain
            # write-open until a reader appeared, holding POST
            # /api/files/filebrowser/ensure forever; with it the open fails
            # ENXIO instead, which the except arm below maps to the coded
            # start failure.  Writes to a regular log file never block, so
            # the flag is inert on the happy path.
            log_fd = os.open(
                FB_LOG,
                os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW
                | getattr(os, "O_NONBLOCK", 0),
                0o600,
            )
            with os.fdopen(log_fd, "ab") as log:
                subprocess.Popen(
                    [
                        str(FB_BIN), "-d", str(FB_DB), "-r", str(FB_ROOT_DEFAULT),
                        "-a", "127.0.0.1", "-p", str(FB_PORT),
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                    close_fds=True,
                    # _spawn_env, not a bare utf8_env(): a patched/odd env
                    # provider raising outside the typed arm below used to
                    # 500 POST /api/files/filebrowser/ensure raw.
                    env=_spawn_env(),
                )
        except (OSError, ValueError, TypeError):
            # Leftover ``\\ud800`` env/path UnicodeEncodeError is ValueError, not OSError.
            if not _fb_on_disk():
                # The _exists gate blessed this binary moments ago; vanished
                # between the check and the spawn (an uninstall or an
                # unmounted ~/Services volume), the answer used to be the
                # uncoded 500 fb_start_failed instead of a 503 like the
                # other tool-absent states.
                raise api_error("files.fb_missing")
            raise api_error("files.fb_start_failed")
    else:
        raise api_error("files.fb_start_failed")

    # wait up to ~3s for port
    for _ in range(15):
        time.sleep(0.2)
        st2 = filebrowser_status()
        if st2["running"]:
            _started_by_hub = True
            return {"ok": True, "message": "FileBrowser started on demand", **st2, "started": True}
    st3 = filebrowser_status()
    return {
        "ok": st3["running"],
        "message": "Start command sent" if st3["running"] else "Start timed out; check the logs",
        **st3,
        "started": st3["running"],
    }


def stop_filebrowser() -> dict:
    """Stop FileBrowser to free memory. Disables KeepAlive temporarily via bootout."""
    global _started_by_hub
    dom = f"gui/{UID}"
    if _exists(FB_PLIST):
        # _sh_triple: a raising patched/odd runner used to escape these
        # fire-and-forget spawns and 500 POST /api/files/filebrowser/stop.
        _sh_triple(["/bin/launchctl", "bootout", f"{dom}/{FB_LABEL}"], timeout=10)
    # Exact comm, not ``-f``: an editor or ``tail`` whose argv mentions the
    # binary must not be SIGTERM'd.
    _sh_triple(["/usr/bin/pkill", "-x", "filebrowser-bin"], timeout=5)
    _started_by_hub = False
    time.sleep(0.3)
    st = filebrowser_status()
    return {
        "ok": not st["running"],
        "message": "FileBrowser stopped, memory released" if not st["running"] else "A process is still running",
        **st,
    }


def set_filebrowser_ondemand(enabled: bool = True) -> dict:
    """Write LaunchAgent RunAtLoad/KeepAlive off for true on-demand (no boot RAM)."""
    if not _exists(FB_PLIST):
        raise api_error("files.fb_no_plist")
    import plistlib
    from hub import secure_io
    try:
        pl = plistlib.loads(read_bytes_capped(FB_PLIST, _PLIST_CAP))
    except Exception:
        # An enumerated tuple is a losing game against plistlib's XML path:
        # a torn or invalid-UTF-8 plist raises xml.parsers.expat.ExpatError,
        # a junk <date> raises AttributeError, and a stray <key> outside any
        # <dict> raises IndexError — none of them ValueError, so every one
        # escaped the previous (OSError, ValueError, OverflowError,
        # RecursionError) arm and 500'd POST /api/files/filebrowser/ondemand
        # raw.  The try wraps only the capped read + parse (the coded raise
        # sits outside it), and any parse failure means the same one thing —
        # not a usable LaunchAgent — so swallow broadly like the sibling
        # reader _plist_keepalive() and the repo's other plist readers.
        raise api_error("files.fb_bad_plist")
    if not isinstance(pl, dict):
        raise api_error("files.fb_bad_plist")
    if enabled:
        pl["RunAtLoad"] = False
        pl["KeepAlive"] = False
    else:
        pl["RunAtLoad"] = True
        pl["KeepAlive"] = True
    try:
        payload = plistlib.dumps(pl)
    except (OverflowError, ValueError, TypeError, RecursionError):
        # The XML parser reads ``<integer>0x…</integer>`` uncapped (a
        # power-of-two base dodges CPython's 4300-digit parse limit), so a
        # leftover hex integer loads fine and then OverflowErrors the
        # writer's 64-bit range check — which used to 500 POST
        # /api/files/filebrowser/ondemand after loads() had already been
        # guarded.  TypeError: a loaded value dumps cannot represent.
        raise api_error("files.fb_bad_plist")
    try:
        secure_io.replace_bytes(FB_PLIST, payload)
    except OSError:
        raise api_error("files.permission_denied", path=str(FB_PLIST))
    # reload definition if loaded.  _sh_triple: a raising patched/odd runner
    # used to escape these fire-and-forget spawns and 500 POST
    # /api/files/filebrowser/ondemand *after* the plist was already written.
    dom = f"gui/{UID}"
    _sh_triple(["/bin/launchctl", "bootout", f"{dom}/{FB_LABEL}"], timeout=8)
    if not enabled:
        # re-enable resident mode
        _sh_triple(["/bin/launchctl", "bootstrap", dom, str(FB_PLIST)], timeout=8)
        _sh_triple(["/bin/launchctl", "kickstart", f"{dom}/{FB_LABEL}"], timeout=8)
    return {
        "ok": True,
        "ondemand": enabled,
        "message": "Set to on-demand (not resident at boot)" if enabled else "Set to resident (starts at boot)",
        "plist": _as_text(FB_PLIST),
    }


def overview() -> dict:
    return {
        "roots": default_roots(),
        "filebrowser": filebrowser_status(),
        "builtin": True,
        "hint": "The built-in file manager only uses resources while this page is open; the full FileBrowser can be started and stopped on demand.",
    }
