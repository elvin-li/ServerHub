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
    # The shared listing (hub/launchd_cache.py) rather than this module's own
    # `launchctl list`: the health page calls this *and* two other readers of the
    # same listing, so the bundle used to spawn three of them.
    #
    # Exact label match now, where this scanned for `LABEL in line` -- a substring
    # test that would have matched a different job whose label merely contains
    # `local.system-nginx`.
    try:
        pid = launchd_listing().pid_for(LABEL)
    except Exception:
        pid = None
    running = pid is not None
    return {
        "label": LABEL,
        "conf": str(NGINX_CONF),
        "conf_d": str(CONF_D),
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
