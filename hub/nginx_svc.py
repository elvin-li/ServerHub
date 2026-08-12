"""System nginx reverse proxy management."""
from __future__ import annotations

import subprocess
from pathlib import Path

from fastapi import HTTPException

from hub.adaptive import nginx_sites
from hub.launchd_cache import invalidate_launchd, listing as launchd_listing
from hub.status import invalidate_status

NGINX_BIN = "/opt/homebrew/bin/nginx"
NGINX_ROOT = Path.home() / "Services" / "nginx"
NGINX_CONF = NGINX_ROOT / "nginx.conf"
CONF_D = NGINX_ROOT / "conf.d"
LABEL = "local.system-nginx"


def overview() -> dict:
    sites = nginx_sites()
    # The shared listing (hub/launchd_cache.py) rather than this module's own
    # `launchctl list`: the health page calls this *and* two other readers of the
    # same listing, so the bundle used to spawn three of them.
    #
    # Exact label match now, where this scanned for `LABEL in line` -- a substring
    # test that would have matched a different job whose label merely contains
    # `local.system-nginx`.
    pid = launchd_listing().pid_for(LABEL)
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
    if not NGINX_CONF.is_file():
        raise HTTPException(404, "nginx.conf missing")
    p = subprocess.run(
        [NGINX_BIN, "-t", "-c", str(NGINX_CONF)],
        capture_output=True, text=True, timeout=15,
    )
    msg = (p.stderr or p.stdout or "").strip()
    return {"ok": p.returncode == 0, "message": msg}


def reload_nginx() -> dict:
    t = test_config()
    if not t["ok"]:
        return {"ok": False, "message": "Invalid configuration; not reloaded\n" + t["message"]}
    # Prefer signal via nginx -s reload with same conf
    p = subprocess.run(
        [NGINX_BIN, "-c", str(NGINX_CONF), "-s", "reload"],
        capture_output=True, text=True, timeout=15,
    )
    if p.returncode != 0:
        # kickstart launchd
        import os as _os
        uid = _os.getuid()
        p2 = subprocess.run(
            ["/bin/launchctl", "kickstart", "-k", f"gui/{uid}/{LABEL}"],
            capture_output=True, text=True, timeout=30,
        )
        # A kickstart replaces the process, so the pid in the shared listing is now
        # the previous one.
        invalidate_launchd()
        invalidate_status()
        return {
            "ok": p2.returncode == 0,
            "message": (p2.stderr or p2.stdout or t["message"] or "kickstart").strip(),
        }
    invalidate_status()
    return {"ok": True, "message": "Reloaded\n" + t["message"]}
