#!/usr/bin/env python3
"""ServerHub entrypoint — LaunchAgent compatible.

Host and port come from the environment so the LaunchAgent written by
install.sh can pin them without editing code:

    SERVERHUB_HOST   bind address (default 0.0.0.0 — reachable on the LAN)
    SERVERHUB_PORT   TCP port     (default 8086)
"""
import os
import sys
import time


def _port() -> int:
    raw = os.environ.get("SERVERHUB_PORT", "").strip()
    if not raw:
        return 8086
    try:
        port = int(raw)
    except ValueError:
        return 8086
    return port if 1 <= port <= 65535 else 8086


def _log(msg: str) -> None:
    """Write to stderr (launchd captures this to the log file)."""
    print(f"serverhub: {msg}", file=sys.stderr, flush=True)


# Module-level ``app`` is kept for test clients and WSGI intros that do
# ``from app import app``.  At launchd boot time the import chain can fail
# transiently (filesystem still warming up, .pyc regeneration mid-write),
# so a bare except keeps the module importable even when the factory blows
# up — the __main__ retry below will re-attempt with back-off.
try:
    from hub.app_factory import create_app
    app = create_app()
except Exception as exc:
    _log(f"create_app failed at import: {exc}")
    app = None


if __name__ == "__main__":
    import uvicorn

    # Reachable on the LAN by default so browsers and phones on the home
    # network can open the panel directly. This is only safe because
    # authentication is mandatory once setup completes (hub/auth.py:
    # auth_enabled) — a LAN client gets the login page, not an anonymous
    # admin API. Set SERVERHUB_HOST=127.0.0.1 to restrict to loopback and
    # reach the panel exclusively through the Cloudflare tunnel.
    host = os.environ.get("SERVERHUB_HOST") or "0.0.0.0"  # noqa: S104
    port = _port()
    max_retries = 5

    for attempt in range(1, max_retries + 1):
        # Re-create on every attempt: a failed create_app() may have left
        # half-initialised singletons that a fresh call will rebuild.
        if app is None or attempt > 1:
            try:
                from hub.app_factory import create_app as _create
                app = _create()
            except Exception as exc:
                wait = min(10 * attempt, 30)
                _log(f"create_app failed (attempt {attempt}/{max_retries}): "
                     f"{exc}; retrying in {wait}s")
                time.sleep(wait)
                continue

        try:
            uvicorn.run(app, host=host, port=port, access_log=False)
            break  # clean exit (SIGTERM / Ctrl-C) — do not restart
        except OSError as exc:
            # Port still held by the previous process, or network not ready.
            if attempt >= max_retries:
                raise
            wait = min(5 * attempt, 20)
            _log(f"bind failed (attempt {attempt}/{max_retries}): "
                 f"{exc}; retrying in {wait}s")
            time.sleep(wait)
