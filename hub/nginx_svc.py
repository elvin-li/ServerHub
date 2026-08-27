"""System nginx reverse proxy management."""
from __future__ import annotations

import os
from pathlib import Path

from hub.adaptive import nginx_sites
from hub.errors import api_error
from hub.launchd_cache import invalidate_launchd, listing as launchd_listing
from hub.paths import NGINX as NGINX_BIN
from hub.paths import user_home
from hub.status import invalidate_status
from hub.util import sh


def _default_root() -> Path:
    """Nginx tree under ``~/Services/nginx``.  ``Path.home()`` leftover must not 500 import."""
    home = user_home()
    return (home / "Services" / "nginx") if home is not None else Path("/var/empty/serverhub-nginx")


NGINX_ROOT = _default_root()
NGINX_CONF = NGINX_ROOT / "nginx.conf"
CONF_D = NGINX_ROOT / "conf.d"
LABEL = "local.system-nginx"


def _isinst(value, types) -> bool:
    """``isinstance`` that a leftover ``__class__`` bomb cannot 500 through.

    CPython's ``isinstance`` reads the operand's ``__class__`` whenever the
    real-type fast check misses, so a leftover whose ``__class__`` is a
    raising property blew every unguarded ``isinstance`` gate below — at
    site-row rank, nested value and mapping-key rank inside ``_jsonable``,
    at the whole-``sites``-return rank in ``overview()``, and through
    ``_as_text`` on the ``sh`` out/err seam — and 500'd GET /api/nginx and
    POST /api/nginx/test|reload.  A lying ``__class__`` (answers ``int``)
    is *not* an error and still reports its claim here; the numeric arms'
    unbound base coercion then drops it, exactly as before.
    """
    try:
        return isinstance(value, types)
    except Exception:
        return False


def _decode_bytes(value) -> str:
    """Unbound base decode: a leftover subclass ``.decode`` bomb cannot 500."""
    base = bytes if _isinst(value, bytes) else bytearray
    return base.decode(value, "utf-8", "replace")


def _as_text(value) -> str:
    """Leftover ``\\ud800`` in ``nginx -t`` used to 500 Settings → Test/Reload.

    Reads through unbound base-type calls (the modules5 convention this
    module never got): a bytes-subclass ``.decode`` bomb arriving as an odd
    ``sh`` answer or a site-row key used to 500 POST /api/nginx/test and
    GET /api/nginx, and a str subclass whose ``__str__`` returns *itself*
    kept the bound ``encode`` bomb live through the final scrub line.
    """
    if _isinst(value, (bytes, bytearray)):
        value = _decode_bytes(value)
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
    # ``str(x)`` on a subclass whose ``__str__`` answers self is still the
    # subclass: the unbound base encode dodges its ``encode`` override.
    return str.encode(value, "utf-8", "replace").decode("utf-8")


def _sh_message(err, out, fallback: str = "") -> str:
    return (_as_text(err) or _as_text(out) or fallback).strip()


def _sh_triple(cmd, timeout: int) -> tuple:
    """Spawn with the unpack inside the guard (the brew_svc.service_action rule).

    ``test_config``/``reload_nginx`` do not own the runner: the production
    ``sh`` never raises and always answers ``(rc, out, err)``, but a patched
    or odd one (the same class ``_sh_message`` guards at value rank) can
    raise outright or answer a wrong-arity tuple / bare None — both used to
    ride to Starlette uncaught and 500 POST /api/nginx/test and /reload.
    Degrade to the failure triple instead; the vanished-CLI classification
    stays with the callers, disk-confirmed, so a raise whose text merely
    reads "not found" is never misclassified while nginx is still on disk.
    """
    try:
        rc, out, err = sh(cmd, timeout=timeout)
    except Exception as exc:
        return -1, "", _as_text(exc)
    # Exact-int rc, the same base coercion _jsonable applies: the callers
    # compare ``rc == 0`` / ``rc == -1`` / ``rc != 0``, and an rc whose
    # ``__eq__`` raises (an int-subclass bomb, or a non-int shape) used to
    # ride those comparisons to Starlette and 500 POST /api/nginx/test and
    # both spawn ranks of POST /api/nginx/reload.  A junk rc degrades to the
    # same failure code as a raising runner; the vanished-CLI classification
    # stays disk-confirmed either way.
    try:
        rc = int.__index__(rc) if isinstance(rc, int) else -1
    except Exception:
        rc = -1
    return rc, out, err


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's ``allow_nan=False`` encoder cannot 500.

    ``overview()`` does not own the sites parser: the real
    ``adaptive.nginx_sites`` scrubs its output, but a patched or odd one (the
    same class ``_sh_message`` guards for ``sh`` and ``_pid_text`` for the
    listing) can answer rows the production parser never does.  Every other
    field of the payload was scrubbed; a lone surrogate in a site key or
    value rode raw to Starlette's UTF-8 encode, and an already-int over-cap
    number (YAML/plist hex loads uncapped — ``int(x, 16)`` is exempt from
    CPython's 4300-digit cap) ValueError'd Starlette's own ``json.dumps`` at
    int->str time — both used to 500 GET /api/nginx.
    """
    if depth > 32:
        return None
    if value is None or _isinst(value, bool):
        return value
    if _isinst(value, int):
        if type(value) is not int:
            try:
                # Base coercion to an exact int (the modules5 unbound
                # convention): an int subclass whose ``__str__`` raises used
                # to blow the digit-cap probe below out of overview() and
                # 500 GET /api/nginx.
                value = int.__index__(value)
            except Exception:
                return None
        try:
            # A str() probe, never an isinstance(x, str) gate: the finite
            # numeric listen ports the Gateway table renders must pass
            # through as ints, only the unrenderable over-cap ones drop.
            str(value)
        except ValueError:
            return None
        return value
    if _isinst(value, float):
        if type(value) is not float:
            try:
                # Base coercion to an exact float: a float subclass whose
                # ``__eq__``/``__ne__`` raises used to blow the NaN/inf
                # probes below the same way.
                value = float.__float__(value)
            except Exception:
                return None
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if _isinst(value, str):
        return _as_text(value)
    if _isinst(value, (bytes, bytearray)):
        # Unbound base decode: ``bytes(value)`` re-enters a subclass
        # ``__bytes__`` bomb before the copy, and a bound ``.decode`` bomb
        # was live for bytearray shapes — both used to 500 GET /api/nginx.
        return _decode_bytes(value)
    if _isinst(value, dict):
        out = {}
        # Unbound base view: a dict subclass whose ``items()`` raises used
        # to wipe its whole row (pre-fix the raise escaped overview()'s
        # comprehension and 500'd the route, taking every sane sibling site
        # down with it); the base view cannot raise and the real entries
        # survive.
        for k, v in dict.items(value):
            if _isinst(k, (bytes, bytearray)):
                k = _decode_bytes(k)
            elif not _isinst(k, str):
                try:
                    k = str(k)
                except Exception:
                    # The over-cap int key: the entry drops, not the row.
                    continue
            out[_as_text(k)] = _jsonable(v, depth + 1)
        return out
    if _isinst(value, (list, tuple, set, frozenset)):
        for base in (list, tuple, set, frozenset):
            if _isinst(value, base):
                # Unbound base iteration: a subclass ``__iter__`` bomb used
                # to drop the whole field — the real elements survive now.
                return [_jsonable(v, depth + 1) for v in base.__iter__(value)]
    return _as_text(value)


def _pid_text(value) -> str | None:
    """Pid shapes that dodge ``Listing``'s coercion must not poison the payload.

    ``overview()`` does not own the listing object, so a patched or odd one
    (the same class ``_sh_message`` guards for ``sh``) can answer shapes the
    production ``Listing`` never does:

    * an *already-int* over-cap pid — YAML/plist hex loads uncapped, and
      ``str()`` of it is CPython's 4300-digit ValueError, which used to ride
      to Starlette's own ``json.dumps`` and 500 GET /api/nginx.  A str()
      probe, not a strict ``isinstance(pid, str)`` gate: a finite numeric
      pid must keep reporting running;
    * ``True`` — bool is int's subclass, and ``true`` in JSON made the
      SPA's ``Number(true)`` render the lie "pid 1";
    * digit runs past pid_t (signed 32-bit) are no real process — the same
      bound cloudflared_svc applies before ``os.kill``.
    """
    if value is None or _isinst(value, bool):
        return None
    if _isinst(value, int):
        if type(value) is not int:
            try:
                # Base coercion first (the modules5 unbound convention): an
                # int subclass whose ``__str__`` raises non-ValueError used
                # to escape into overview()'s guard and flip ``running`` to
                # a false "stopped" while nginx held a real pid.
                value = int.__index__(value)
            except Exception:
                return None
        try:
            value = str(value)
        except ValueError:
            return None
    text = _as_text(value).strip()
    if not text.isascii() or not text.isdigit():
        return None
    try:
        n = int(text)
    except ValueError:
        return None
    if n < 1 or n > 2**31 - 1:
        return None
    return text


def _nginx_present() -> bool:
    """``os.path.isfile`` re-raises EIO/ESTALE; that must not 500 Test/Reload."""
    try:
        return os.path.isfile(NGINX_BIN)
    except OSError:
        return False


def _raise_if_cli_vanished(rc: int, message: str) -> None:
    """Classify the ``sh`` spawn sentinel as the coded 503, disk-confirmed.

    ``sh`` reports a FileNotFoundError spawn as ``(-1, "", "not found")`` —
    a sentinel, never a real nginx exit.  That used to leak to the Gateway
    card as an uncoded ``{ok: false, message: "not found"}`` (and Reload
    mislabelled it "Invalid configuration; not reloaded").  Answer with a
    coded 503 like ``brew.not_found`` instead — but only after confirming
    against the filesystem, on the failure path only: a signal-killed or
    vanished-cwd spawn is also rc -1, so an nginx that is still on disk
    keeps its raw result, and a genuine nginx exit whose stderr merely
    reads "not found" is never reclassified.
    """
    if rc == -1 and message == "not found" and not _nginx_present():
        raise api_error("nginx.not_found")


def overview() -> dict:
    # GET /api/nginx used to 500 when one unreadable ``*.conf`` raised inside
    # ``nginx_sites`` (MemoryError / ValueError are not OSError).
    try:
        sites = nginx_sites()
    except Exception:
        sites = []
    # _isinst, not a bare isinstance: a sites *return* whose ``__class__``
    # is a raising property blew this gate outside the try above and 500'd
    # GET /api/nginx before a single row was read.
    if not _isinst(sites, list):
        sites = []
    # Field-level scrub of rows overview() does not own (see _jsonable):
    # surrogate keys/values and already-int over-cap numbers used to 500 the
    # encode.  Non-dict rows are dropped before site_count counts them — the
    # SPA keys the table on ``s.file``.
    #
    # Materialize before scrubbing: ``isinstance(sites, list)`` passes for a
    # list *subclass*, and one whose ``__iter__`` raises used to blow up the
    # comprehension outside the try above and 500 GET /api/nginx.  Row-level
    # isolation after that: a row whose scrub collapses (a mapping that
    # refuses ``items()``) drops alone — pre-fix it took every sane sibling
    # site down with the 500.
    try:
        rows = list(sites)
    except Exception:
        rows = []
    sites = []
    for row in rows:
        # _isinst at row rank: a leftover row whose ``__class__`` is a
        # raising property used to blow this gate out of the loop and 500
        # the route, taking every sane sibling site down with it.
        if not _isinst(row, dict):
            continue
        scrubbed = _jsonable(row)
        if _isinst(scrubbed, dict):
            sites.append(scrubbed)
    # The shared listing (hub/launchd_cache.py) rather than this module's own
    # `launchctl list`: the health page calls this *and* two other readers of the
    # same listing, so the bundle used to spawn three of them.
    #
    # Exact label match now, where this scanned for `LABEL in line` -- a substring
    # test that would have matched a different job whose label merely contains
    # `local.system-nginx`.
    try:
        pid = _pid_text(launchd_listing().pid_for(LABEL))
    except Exception:
        pid = None
    running = pid is not None
    # ``str(path)`` verbatim used to 500 the encode: these two derive from
    # ``Path.home()``, and a HOME whose on-disk name is undecodable arrives
    # through os.environ's surrogateescape as a str carrying a lone
    # ``\udcff`` — every sibling field here is scrubbed, the conf paths were not.
    return {
        "label": LABEL,
        "conf": _as_text(NGINX_CONF),
        "conf_d": _as_text(CONF_D),
        "running": running,
        "pid": pid,
        "sites": sites,
        "site_count": len(sites),
        "hint": "New site: drop a *.conf into conf.d/ and click \"Reload\"",
    }


def test_config() -> dict:
    try:
        present = NGINX_CONF.is_file()
    except (OSError, ValueError):
        # Dying mount EIO / a NUL leftover used to 500 Settings → Test/Reload.
        present = False
    if not present:
        raise api_error("nginx.conf_missing")
    # ``sh`` swallows FileNotFoundError / TimeoutExpired; a missing binary
    # used to 500 Settings → Reload instead of returning a coded failure.
    rc, out, err = _sh_triple([NGINX_BIN, "-t", "-c", str(NGINX_CONF)], timeout=15)
    # bytes/None from a patched or odd `sh` used to TypeError when Reload
    # concatenated the probe text onto a str prefix.
    message = _sh_message(err, out)
    _raise_if_cli_vanished(rc, message)
    return {"ok": rc == 0, "message": message}


def reload_nginx() -> dict:
    t = test_config()
    if not t["ok"]:
        return {
            "ok": False,
            "message": "Invalid configuration; not reloaded\n" + _as_text(t.get("message")),
        }
    rc, out, err = _sh_triple(
        [NGINX_BIN, "-c", str(NGINX_CONF), "-s", "reload"], timeout=15,
    )
    if rc != 0:
        # nginx vanished between ``-t`` and ``-s reload``: a coded 503,
        # not a launchd kickstart aimed at a binary that is gone.
        _raise_if_cli_vanished(rc, _sh_message(err, out))
        uid = os.getuid()
        rc2, out2, err2 = _sh_triple(
            ["/bin/launchctl", "kickstart", "-k", f"gui/{uid}/{LABEL}"],
            timeout=30,
        )
        invalidate_launchd()
        invalidate_status()
        return {
            "ok": rc2 == 0,
            "message": _sh_message(err2, out2, _as_text(t.get("message")) or "kickstart"),
        }
    invalidate_status()
    return {"ok": True, "message": "Reloaded\n" + _as_text(t.get("message"))}
