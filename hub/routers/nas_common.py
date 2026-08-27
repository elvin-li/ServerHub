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


def _isa(value, kinds) -> bool:
    """``isinstance`` that survives a leftover ``__class__``-property bomb.

    When the exact-type check misses, ``isinstance`` consults
    ``value.__class__`` — so a leftover whose ``__class__`` is a *raising
    property* detonated the gate itself, one step ahead of every guard
    built on top of it: ``_plain_result`` blew ``result_ok`` at the routes'
    audit line and both error funnels, and ``_jsonable`` blew ``_rendered``
    on GET /api/nfs, /api/raid, /api/snapshots, /api/smart and
    /api/storage/usage.  A real subclass still matches through the C-level
    type check without touching ``__class__``; only a value that cannot
    even answer what it is takes the non-matching branch.
    """
    try:
        return isinstance(value, kinds)
    except Exception:
        return False


def _decode_bytes(value):
    """Unbound base decode: a leftover subclass ``.decode`` bomb cannot 500.

    Returns ``None`` for a *lying* ``__class__`` that answers ``bytes`` /
    ``bytearray`` while the real type is neither (the modules9 rule):
    ``isinstance`` honours the lie, so such an impostor passed every ``_isa``
    bytes gate and then blew the unbound base decode — a descriptor bound to
    the real ``bytes``/``bytearray`` layout rejects the foreign operand with
    a TypeError outside any try, 500ing the NAS read routes out of
    ``_jsonable`` and the mutation funnels out of ``_utf8_text``.  A raise
    means "not really this type"; callers drop or re-probe the impostor.
    """
    base = bytes if _isa(value, bytes) else bytearray
    try:
        return base.decode(value, "utf-8", "replace")
    except Exception:
        return None


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
    # _isa, not a bare isinstance: a leftover whose ``__class__`` is a
    # raising property detonated the gate itself and 500'd the audit line
    # (result_ok) and both funnels ahead of the coded admin.failed.
    if _isa(result, dict):
        try:
            return dict(result)
        except Exception:
            return None
    return None


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
    if _isa(value, (bytes, bytearray)):
        # Unbound base decode: a leftover bytes-subclass whose bound
        # ``.decode`` raises used to 500 the shares/NAS failure funnels.
        # A lying ``__class__`` claiming bytes decodes to None and falls
        # through to the str() probe below, so a legible impostor error
        # field still renders instead of 500ing the funnel it rode in on.
        decoded = _decode_bytes(value)
        if decoded is not None:
            return decoded
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
    # _isa at every rank: a leftover whose ``__class__`` is a raising
    # property detonates the first bare gate it fails, so a bomb nested as
    # a dict *value* in any NAS payload used to 500 the read routes out of
    # ``_rendered`` and the mutation ok bodies out of the funnels.  It now
    # falls through every gate to the final text probe like any other
    # unrecognized leftover.
    if value is None:
        return value
    if _isa(value, bool):
        # ``bool`` is final, so a value that answers the bool gate while its
        # real type is not bool is a *lying* ``__class__`` impostor, not a
        # genuine bool (the modules9 rule).  The old arm returned it raw,
        # handing Starlette's ``allow_nan=False`` encoder a non-serializable
        # object — a raw 500 on every NAS read route through ``_rendered``
        # and on every mutation ok body through the funnels.  Only a real
        # bool renders; the impostor drops like its lying numeric siblings.
        if type(value) is bool:
            return value
        return None
    if _isa(value, int):
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
    if _isa(value, float):
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
    if _isa(value, str):
        return _utf8_text(value)
    if _isa(value, (bytes, bytearray)):
        return _decode_bytes(value)
    if _isa(value, dict):
        # Unbound base view (the modules5 rule): a dict subclass whose
        # ``items()`` raises *or yields non-pairs* used to 500 the routes —
        # the raise inside the old ``list(value.items())`` was caught, but
        # the two-target unpack of a non-pair row happened outside the try.
        # ``dict.items`` reads the real C-level storage, so the salvageable
        # keys still survive.  ``dict.items`` is itself a descriptor bound
        # to the real dict layout, so a *lying* ``__class__`` claiming dict
        # (real type is neither) blew the call outside any try — a raw 500
        # on every NAS read route and mutation funnel; the impostor drops
        # like a lying int (the modules9 rule).
        try:
            items = dict.items(value)
        except Exception:
            return None
        out = {}
        for k, v in items:
            # Per-pair guard: a ``__class__``-bomb *key* used to detonate
            # its own gates below and cost the whole mapping — the torn
            # pair drops alone, its sibling keys survive.
            try:
                if _isa(k, (bytes, bytearray)):
                    k = _decode_bytes(k)
                    if k is None:
                        # A lying ``__class__`` key claiming bytes — drop
                        # just this entry, keep the rest of the mapping.
                        continue
                elif not _isa(k, str):
                    k = str(k)
                out[_utf8_text(k)] = _jsonable(v, depth + 1)
            except Exception:
                continue
        return out
    if _isa(value, (list, tuple, set, frozenset)):
        # Unbound base ``__iter__`` (the modules5 rule at sequence rank): a
        # subclass whose bound ``__iter__`` raises — or answers an iterator
        # that bombs mid-walk — used to drop the whole field to None even
        # though the real C-level storage still held every element.
        base = (
            list if _isa(value, list)
            else tuple if _isa(value, tuple)
            else set if _isa(value, set)
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
            # _isa on both reads: a leftover ``__class__``-bomb key or value
            # riding a coded failure used to detonate the gate itself and
            # 500 the refusal while it was being built.
            if not _isa(k, str) or not _isa(v, (str, int, float)):
                continue
            key = _utf8_text(k)
            if key in ("ok", "error"):
                continue
            cleaned = _jsonable(v)
            if isinstance(cleaned, (str, int, float)):
                params[key] = cleaned
        raise api_error(code, **params)
    return raise_for_admin_result(result)
