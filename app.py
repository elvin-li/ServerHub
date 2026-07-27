#!/usr/bin/env python3
"""ServerHub entrypoint — LaunchAgent compatible.

Host and port come from the environment so the LaunchAgent written by
install.sh can pin them without editing code:

    SERVERHUB_HOST   bind address (default 0.0.0.0 — reachable on the LAN)
    SERVERHUB_PORT   TCP port     (default 8086)
"""
import os

from hub.app_factory import create_app

app = create_app()


def _port() -> int:
    raw = os.environ.get("SERVERHUB_PORT", "").strip()
    if not raw:
        return 8086
    try:
        port = int(raw)
    except ValueError:
        return 8086
    return port if 1 <= port <= 65535 else 8086


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        # Reachable on the LAN by default so browsers and phones on the home
        # network can open the panel directly. This is only safe because
        # authentication is mandatory once setup completes (hub/auth.py:
        # auth_enabled) — a LAN client gets the login page, not an anonymous
        # admin API. Set SERVERHUB_HOST=127.0.0.1 to restrict to loopback and
        # reach the panel exclusively through the Cloudflare tunnel.
        host=os.environ.get("SERVERHUB_HOST") or "0.0.0.0",  # noqa: S104
        port=_port(),
        access_log=False,
    )
