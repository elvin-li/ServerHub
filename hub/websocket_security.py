"""Shared browser-session and same-origin checks for privileged WebSockets."""
from __future__ import annotations

from urllib.parse import urlsplit

from fastapi import WebSocket

from hub.auth import COOKIE_NAME, is_admin, session_username, setup_required, verify_session


def origin_allowed(origin: str | None, host: str | None) -> bool:
    """Return whether an HTTP(S) Origin exactly matches the request Host.

    WebSocket routes cannot rely on ordinary CSRF middleware.  Requiring both
    headers and an exact authority match prevents a third-party page from using
    a logged-in browser to open a privileged socket.
    """
    if not origin or not host:
        return False
    try:
        parsed = urlsplit(origin)
    except ValueError:
        return False
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return False
    if parsed.username is not None or parsed.password is not None:
        return False
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        return False
    return parsed.netloc.lower() == host.strip().lower()


async def reject_websocket(websocket: WebSocket, close_code: int, error: str) -> None:
    """Accept briefly so the first-party client receives a stable error code."""
    try:
        await websocket.accept()
        await websocket.send_json({"type": "error", "code": error})
    finally:
        try:
            await websocket.close(code=close_code)
        except Exception:
            pass


async def authenticate_websocket(websocket: WebSocket) -> tuple[str, str] | None:
    """Authenticate a browser WebSocket and return ``(cookie, username)``.

    Privileged sockets deliberately do not accept HTTP Basic or the loopback
    native-client token: the exact browser session cookie is also used to bind
    short-lived capabilities such as VM console tickets.
    """
    token = websocket.cookies.get(COOKIE_NAME)
    if setup_required() or not verify_session(token):
        await reject_websocket(websocket, 4401, "auth.login_required")
        return None
    if not origin_allowed(websocket.headers.get("origin"), websocket.headers.get("host")):
        await reject_websocket(websocket, 4403, "auth.cross_site_denied")
        return None
    user = session_username(token)
    if not user:
        await reject_websocket(websocket, 4401, "auth.login_required")
        return None
    if not is_admin(user):
        await reject_websocket(websocket, 4403, "auth.admin_required")
        return None
    return str(token), user
