"""System nginx reverse proxy management."""
from __future__ import annotations

import subprocess
from pathlib import Path

from fastapi import HTTPException

from hub.adaptive import nginx_sites
from hub.status import invalidate_status
from hub.util import sh

NGINX_BIN = "/opt/homebrew/bin/nginx"
NGINX_ROOT = Path.home() / "Services" / "nginx"
NGINX_CONF = NGINX_ROOT / "nginx.conf"
CONF_D = NGINX_ROOT / "conf.d"
LABEL = "local.system-nginx"


def overview() -> dict:
    sites = nginx_sites()
    running = False
    pid = None
    rc, out, _ = sh(["/bin/launchctl", "list"], timeout=5)
    for line in out.splitlines():
        if LABEL in line:
            parts = line.split("\t")
            if parts and parts[0] not in ("-", ""):
                running = True
                pid = parts[0]
            break
    return {
        "label": LABEL,
        "conf": str(NGINX_CONF),
        "conf_d": str(CONF_D),
        "running": running,
        "pid": pid,
        "sites": sites,
        "site_count": len(sites),
        "hint": "新站点：把 *.conf 放进 conf.d/ 后点「重载」",
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
        return {"ok": False, "message": "配置无效，未重载\n" + t["message"]}
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
        invalidate_status()
        return {
            "ok": p2.returncode == 0,
            "message": (p2.stderr or p2.stdout or t["message"] or "kickstart").strip(),
        }
    invalidate_status()
    return {"ok": True, "message": "已重载\n" + t["message"]}
