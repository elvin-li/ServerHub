"""Shared guards for the NAS feature routers.

Every endpoint that runs a privileged macOS command needs the same three things:
a real browser session belonging to an administrator, a translation from
:mod:`hub.macos_admin`'s result dict to an API error, and the caller's address for
the audit trail.  ``hub/routers/shares.py`` grew its own copies first; these are
the shared versions so the newer feature routers do not each reinvent them and
drift apart on, say, whether a dismissed authorization sheet is a 409 or a 500.

Why a browser session specifically: a privileged action needs the operator's
macOS administrator password, which the SPA collects in its own dialog and
hands to the backend per request.  A token-authenticated script or the menu-bar
client cannot present that dialog, so allowing them to trigger a privileged
operation just strands a request that can never be authorized.
"""
from __future__ import annotations

from fastapi import Request

from hub import auth
from hub.errors import api_error

#: run_admin() error string → API error code.
_ADMIN_ERRORS = {
    "cancelled": "admin.cancelled",
    "unavailable": "admin.unavailable",
    "invalid_command": "admin.failed",
    "failed": "admin.failed",
    #: The SPA answers these two with its in-browser password dialog and a retry.
    "password_required": "admin.password_required",
    "password_incorrect": "admin.password_incorrect",
}


def require_admin_browser(request: Request) -> str:
    """Return the signed-in administrator's username, or raise."""
    if not auth.browser_authenticated(request):
        raise api_error("admin.browser_session_required")
    username = auth.request_username(request)
    if not auth.is_admin(username):
        raise api_error("admin.admin_required")
    return username


def client_host(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def raise_for_admin_result(result: dict) -> dict:
    """Pass a successful privileged result through; convert a failure to an error.

    The service layer returns ``{"ok": False, "error": ...}`` rather than raising,
    because the same helpers are called from background threads where an
    HTTPException would be meaningless.  Translation happens here instead.
    """
    if result.get("ok"):
        return result
    code = _ADMIN_ERRORS.get(str(result.get("error") or "failed"), "admin.failed")
    # The command's stderr tail (e.g. wg-quick's own failure line) rides along as
    # ``detail``: the SPA appends it to the translated message, and the generic
    # "operation failed" text stops hiding the actual cause.
    detail = str(result.get("message") or "").strip()[:300]
    if detail:
        raise api_error(code, detail=detail)
    raise api_error(code)


def raise_service_error(result: dict, mapping: dict[str, str]) -> dict:
    """Like :func:`raise_for_admin_result` but with feature-specific codes first.

    *mapping* covers validation failures the service reports as ``error`` strings
    (``bad_action``, ``bad_device``, …).  Anything not listed falls back to the
    shared authorization codes.
    """
    if result.get("ok"):
        return result
    error = str(result.get("error") or "failed")
    code = mapping.get(error)
    if code:
        params = {k: v for k, v in result.items() if k not in ("ok", "error")}
        raise api_error(code, **{k: v for k, v in params.items() if isinstance(v, (str, int, float))})
    return raise_for_admin_result(result)
