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


def _decode_bytes(value) -> str:
    """Unbound base decode: a leftover subclass ``.decode`` bomb cannot 500."""
    base = bytes if isinstance(value, bytes) else bytearray
    return base.decode(value, "utf-8", "replace")


def _truthy(value) -> bool:
    """``bool(value)`` that survives a leftover ``__bool__`` bomb (fails False)."""
    try:
        return bool(value)
    except Exception:
        return False


def _plain_result(result) -> dict | None:
    """*result* as a plain ``dict``, or None.

    A leftover dict-*subclass* result from a privileged helper (the
    jobs/metrics row-bomb class: passes the ``isinstance`` gate, then
    ``.get()`` raises) used to 500 the NAS routes right out of
    ``result.get("ok")``.  ``dict()`` copies through the C-level storage, so
    an overridden method cannot fire; a subclass whose copy itself raises is
    junk and drops.
    """
    if type(result) is dict:
        return result
    if isinstance(result, dict):
        try:
            return dict(result)
        except Exception:
            return None
    return None


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
    if isinstance(value, (bytes, bytearray)):
        # Unbound base decode: a leftover bytes-subclass whose bound
        # ``.decode`` raises used to 500 the shares/NAS failure funnels.
        return _decode_bytes(value)
    if value is None:
        return ""
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
        # Unbound base encode (the modules6 rule share_acl_svc already
        # follows): ``str()`` of a subclass whose ``__str__`` answers *self*
        # skips CPython's exact-str copy, so a leftover bound ``encode`` bomb
        # dropped the real text to "" — and with it a coded error string
        # ("cancelled", "exists", …) degraded to the generic admin.failed /
        # shares.operation_failed 500 in place of its mapped refusal.
        return str.encode(text, "utf-8", "replace").decode("utf-8")
    except Exception:
        return ""


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so a privileged ok payload cannot 500 the encoder."""
    if depth > 32:
        return None
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if type(value) is not int:
            try:
                # Base coercion to an exact int (the modules5 rule): a
                # subclass ``__str__`` bomb used to raise a non-ValueError
                # past the digit-cap probe below and 500 the privileged
                # ok payload.
                value = int.__index__(value)
            except Exception:
                return None
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
        if type(value) is not float:
            try:
                # Base coercion to an exact float: a subclass ``__eq__``
                # bomb used to blow the NaN/inf probes below.
                value = float.__float__(value)
            except Exception:
                return None
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if isinstance(value, str):
        return _utf8_text(value)
    if isinstance(value, (bytes, bytearray)):
        return _decode_bytes(value)
    if isinstance(value, dict):
        out = {}
        # Unbound base view (the modules5 rule): a dict subclass whose
        # ``items()`` raises *or yields non-pairs* used to 500 the routes —
        # the raise inside the old ``list(value.items())`` was caught, but
        # the two-target unpack of a non-pair row happened outside the try.
        # ``dict.items`` reads the real C-level storage, so the salvageable
        # keys still survive.
        for k, v in dict.items(value):
            if isinstance(k, (bytes, bytearray)):
                k = _decode_bytes(k)
            elif not isinstance(k, str):
                try:
                    k = str(k)
                except Exception:
                    continue
            out[_utf8_text(k)] = _jsonable(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        # Unbound base ``__iter__`` (the modules5 rule at sequence rank): a
        # subclass whose bound ``__iter__`` raises — or answers an iterator
        # that bombs mid-walk — used to drop the whole field to None even
        # though the real C-level storage still held every element.
        base = (
            list if isinstance(value, list)
            else tuple if isinstance(value, tuple)
            else set if isinstance(value, set)
            else frozenset
        )
        try:
            rows = base.__iter__(value)
        except Exception:
            return None
        out = []
        try:
            for v in rows:
                out.append(_jsonable(v, depth + 1))
        except Exception:
            # A walk dying mid-iteration keeps the elements already coerced.
            pass
        return out
    try:
        iso = getattr(value, "isoformat", None)
    except Exception:
        # getattr's default only swallows AttributeError; a property or
        # ``__getattr__`` bomb still raised out of the probe itself and
        # 500'd the privileged ok payload.
        iso = None
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

def result_ok(result) -> bool:
    """Safe ``bool(result.get("ok"))`` for the routes' audit fields.

    Every nas_storage mutation recorded ``ok=bool(result.get("ok"))`` on the
    *raw* service result before :func:`raise_service_error` laundered it, so
    a leftover ``None`` (AttributeError), a dict-*subclass* result whose
    bound ``.get`` raises, or a ``__bool__``-bomb ``ok`` value 500'd the
    route at the audit line — one line ahead of the funnel that already
    knows how to answer coded.  Same laundering, fails False.
    """
    plain = _plain_result(result)
    if plain is None:
        return False
    return _truthy(plain.get("ok"))


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
    # _plain_result, not a bare isinstance: a dict-*subclass* result whose
    # ``.get`` raised used to 500 the funnel one line later, and a
    # ``__bool__``-bomb ``ok`` value blew the truthiness read itself.
    result = _plain_result(result)
    if result is None:
        raise api_error("admin.failed")
    if _truthy(result.get("ok")):
        cleaned = _jsonable(result)
        return cleaned if isinstance(cleaned, dict) else {"ok": True}
    # _utf8_text, not str(): a leftover *already-int* error field past
    # CPython's int->str digit cap (YAML/plist hex loads uncapped through
    # ``int(x, 16)``) made the bare str() raise the digit-cap ValueError out
    # of the route — an unhandled 500 in place of the coded admin.failed.
    # _truthy before the ``or``: a ``__bool__``-bomb error value used to
    # raise out of the fallback chain itself.
    raw_error = result.get("error")
    error = _utf8_text(raw_error) if _truthy(raw_error) else ""
    code = _ADMIN_ERRORS.get(error or "failed", "admin.failed")
    # The command's stderr tail (e.g. wg-quick's own failure line) rides along as
    # ``detail``: the SPA appends it to the translated message, and the generic
    # "operation failed" text stops hiding the actual cause.
    raw_message = result.get("message")
    detail = (_utf8_text(raw_message) if _truthy(raw_message) else "").strip()[:300]
    if detail:
        raise api_error(code, detail=detail)
    raise api_error(code)


def raise_service_error(result: dict, mapping: dict[str, str]) -> dict:
    """Like :func:`raise_for_admin_result` but with feature-specific codes first.

    *mapping* covers validation failures the service reports as ``error`` strings
    (``bad_action``, ``bad_device``, …).  Anything not listed falls back to the
    shared authorization codes.
    """
    # Same laundering as raise_for_admin_result: a dict-subclass result whose
    # ``.get`` / ``items()`` raised — or a ``__bool__``-bomb ``ok`` value —
    # used to 500 the funnel in place of the coded refusal.
    result = _plain_result(result)
    if result is None:
        raise api_error("admin.failed")
    if _truthy(result.get("ok")):
        cleaned = _jsonable(result)
        return cleaned if isinstance(cleaned, dict) else {"ok": True}
    # Same str() probe as raise_for_admin_result: an over-cap already-int
    # error field must earn the coded fallback, not the digit-cap ValueError.
    raw_error = result.get("error")
    error = (_utf8_text(raw_error) if _truthy(raw_error) else "") or "failed"
    code = mapping.get(error)
    if code:
        # Per-field laundering before api_error: the old comprehension probed
        # ``k not in ("ok", "error")`` *first*, so a leftover subclass key
        # whose ``__eq__`` raises blew the coded refusal while it was being
        # built — and a str-subclass value whose bound ``encode`` raises (or
        # an int subclass whose ``__str__`` raises a non-ValueError) rode the
        # isinstance gate into errors._jsonable_param's bound calls and 500'd
        # the same coded body one layer down.  _utf8_text / _jsonable answer
        # exact types, so the encoder walk downstream cannot detonate.
        params = {}
        for k, v in dict.items(result):
            if not isinstance(k, str) or not isinstance(v, (str, int, float)):
                continue
            key = _utf8_text(k)
            if key in ("ok", "error"):
                continue
            cleaned = _jsonable(v)
            if isinstance(cleaned, (str, int, float)):
                params[key] = cleaned
        raise api_error(code, **params)
    return raise_for_admin_result(result)
