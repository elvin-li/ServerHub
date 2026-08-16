#!/usr/bin/env python3
"""ServerHub entrypoint — LaunchAgent compatible.

Host and port come from the environment so the LaunchAgent written by
install.sh can pin them without editing code:

    SERVERHUB_HOST   bind address (default 127.0.0.1 — this Mac only)
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

    # Loopback by default. The panel is reached from this Mac, or through a
    # tunnel / reverse proxy that hops to 127.0.0.1. Binding 0.0.0.0 puts
    # every privileged API on the LAN; that is opt-in via SERVERHUB_HOST.
    uvicorn.run(
        app,
        host=os.environ.get("SERVERHUB_HOST") or "127.0.0.1",
        port=_port(),
        access_log=False,
        # launchd captures stderr into serverhub.err.log.  INFO is just
        # "Started server process" on every kickstart; warnings and our
        # own serverhub.* handler still land.
        log_level="warning",
    )
