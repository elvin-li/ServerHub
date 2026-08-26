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


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    try:
        text = str(value)
    except RecursionError:
        try:
            return type(value).__name__
        except Exception:
            return ""
    except Exception:
        return ""
    try:
        return text.encode("utf-8", "replace").decode("utf-8")
    except Exception:
        return ""


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so a privileged ok payload cannot 500 the encoder."""
    if depth > 32:
        return None
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        try:
            str(value)
        except ValueError:
            # Past CPython's int->str digit cap the encoder cannot render the
            # number at all (YAML/plist hex loads uncapped through
            # ``int(x, 16)``, so an over-cap leftover arrives already-int) —
            # json.dumps raises this same ValueError inside Starlette and
            # 500'd the privileged ok payload.  Same drop as its inf float
            # sibling, matching power_svc / system_settings_svc / status.
            return None
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if isinstance(value, str):
        return _utf8_text(value)
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    if isinstance(value, dict):
        try:
            items = list(value.items())
        except Exception:
            # A mapping that refuses iteration (odd dict subclass in a
            # privileged result): there is nothing to salvage from it, but
            # its *siblings* must survive — pre-fix this raised out of
            # raise_for_admin_result and 500'd the POST NAS routes (the
            # ups_svc/nginx_svc._jsonable rule).
            return None
        out = {}
        for k, v in items:
            if not isinstance(k, str):
                try:
                    k = str(k)
                except Exception:
                    continue
            out[_utf8_text(k)] = _jsonable(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        try:
            return [_jsonable(v, depth + 1) for v in value]
        except Exception:
            # Same class as the mapping above, at sequence rank: only this
            # field drops, never the payload or the route.
            return None
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 a privileged NAS body.
            return _jsonable(iso(), depth + 1)
        except Exception:
            return None
    try:
        return _utf8_text(value)
    except Exception:
        return None

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
    return auth.request_client_id(request)


def raise_for_admin_result(result: dict) -> dict:
    """Pass a successful privileged result through; convert a failure to an error.

    The service layer returns ``{"ok": False, "error": ...}`` rather than raising,
    because the same helpers are called from background threads where an
    HTTPException would be meaningless.  Translation happens here instead.
    """
    # Leftover None / inf from a privileged helper AttributeError'd GET/POST
    # NAS routes; leftover inf / ``\\ud800`` in an ok payload 500'd the encoder.
    if not isinstance(result, dict):
        raise api_error("admin.failed")
    if result.get("ok"):
        cleaned = _jsonable(result)
        return cleaned if isinstance(cleaned, dict) else {"ok": True}
    # _utf8_text, not str(): a leftover *already-int* error field past
    # CPython's int->str digit cap (YAML/plist hex loads uncapped through
    # ``int(x, 16)``) made the bare str() raise the digit-cap ValueError out
    # of the route — an unhandled 500 in place of the coded admin.failed.
    code = _ADMIN_ERRORS.get(_utf8_text(result.get("error") or "failed") or "failed", "admin.failed")
    # The command's stderr tail (e.g. wg-quick's own failure line) rides along as
    # ``detail``: the SPA appends it to the translated message, and the generic
    # "operation failed" text stops hiding the actual cause.
    detail = _utf8_text(result.get("message") or "").strip()[:300]
    if detail:
        raise api_error(code, detail=detail)
    raise api_error(code)


def raise_service_error(result: dict, mapping: dict[str, str]) -> dict:
    """Like :func:`raise_for_admin_result` but with feature-specific codes first.

    *mapping* covers validation failures the service reports as ``error`` strings
    (``bad_action``, ``bad_device``, …).  Anything not listed falls back to the
    shared authorization codes.
    """
    if not isinstance(result, dict):
        raise api_error("admin.failed")
    if result.get("ok"):
        cleaned = _jsonable(result)
        return cleaned if isinstance(cleaned, dict) else {"ok": True}
    # Same str() probe as raise_for_admin_result: an over-cap already-int
    # error field must earn the coded fallback, not the digit-cap ValueError.
    error = _utf8_text(result.get("error") or "failed") or "failed"
    code = mapping.get(error)
    if code:
        try:
            extras = list(result.items())
        except Exception:
            # A dict subclass whose items() raises still answered .get()
            # above; the coded refusal must not lose to its hostile extras.
            extras = []
        raise api_error(code, **{
            k: v for k, v in extras
            if k not in ("ok", "error")
            and isinstance(k, str)
            and isinstance(v, (str, int, float))
        })
    return raise_for_admin_result(result)
