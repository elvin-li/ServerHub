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


def _as_text(value) -> str:
    """Leftover ``\\ud800`` in ``nginx -t`` used to 500 Settings → Test/Reload."""
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
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
    return value.encode("utf-8", "replace").decode("utf-8")


def _sh_message(err, out, fallback: str = "") -> str:
    return (_as_text(err) or _as_text(out) or fallback).strip()


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
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        try:
            # A str() probe, never an isinstance(x, str) gate: the finite
            # numeric listen ports the Gateway table renders must pass
            # through as ints, only the unrenderable over-cap ones drop.
            str(value)
        except ValueError:
            return None
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if isinstance(value, str):
        return _as_text(value)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    if isinstance(value, dict):
        try:
            items = list(value.items())
        except Exception:
            # A mapping that refuses iteration (odd dict subclass): there is
            # nothing to salvage from it, but its *siblings* must survive —
            # pre-fix this raised out of the comprehension in overview() and
            # 500'd GET /api/nginx, wiping the sane rows beside it.
            return None
        out = {}
        for k, v in items:
            if not isinstance(k, (str, bytes, bytearray)):
                try:
                    k = str(k)
                except Exception:
                    # The over-cap int key: the entry drops, not the row.
                    continue
            out[_as_text(k)] = _jsonable(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        try:
            return [_jsonable(v, depth + 1) for v in value]
        except Exception:
            # Same class as the mapping above, at sequence rank: only this
            # field drops, never the row or the route.
            return None
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
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
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
    if not isinstance(sites, list):
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
        if not isinstance(row, dict):
            continue
        scrubbed = _jsonable(row)
        if isinstance(scrubbed, dict):
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
    rc, out, err = sh([NGINX_BIN, "-t", "-c", str(NGINX_CONF)], timeout=15)
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
    rc, out, err = sh(
        [NGINX_BIN, "-c", str(NGINX_CONF), "-s", "reload"], timeout=15,
    )
    if rc != 0:
        # nginx vanished between ``-t`` and ``-s reload``: a coded 503,
        # not a launchd kickstart aimed at a binary that is gone.
        _raise_if_cli_vanished(rc, _sh_message(err, out))
        uid = os.getuid()
        rc2, out2, err2 = sh(
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
