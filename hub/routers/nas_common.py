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

import re

from fastapi import Request

from hub import auth
from hub.errors import api_error

#: Real control flow must keep propagating even through the bomb guards
#: (the nas13 / maint14 convention the three NAS services already carry):
#: swallowing a Ctrl-C or an interpreter shutdown to save one payload field
#: would turn the sanitizer into a hang.  Everything else BaseException-shaped
#: that a leftover raises out of its own hooks is a bomb like any other —
#: nas13 sealed the svc modules but this router file's guards all stopped at
#: ``except Exception``, so one such leftover nested in any payload sailed
#: past every catch here at once and 500'd the funnels and ``_rendered``.
_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)


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

    ``except BaseException`` with the control-flow re-raise (the nas13 rule
    the three NAS services already carry): a ``__class__`` property raising
    a *BaseException* subclass sailed past the old ``except Exception`` —
    and past every sibling guard in this file, because each one stopped at
    ``Exception`` too — a raw 500 through the mutation funnels and every
    read route behind ``_rendered``.
    """
    try:
        return isinstance(value, kinds)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _real(value, types) -> bool:
    """True when the *real* storage layout is one of *types*.

    ``type(value)`` reads the C-level type slot, which a lying ``__class__``
    property cannot swap, so this is the probe for the recover-the-real-
    storage fall-throughs below (the maint14/jobs14 rule): ``isinstance``
    consults ``value.__class__`` only after the real-MRO check misses, so a
    lying claim steered a leftover into the arm of its *claim*, the unbound
    descriptor there refused the real layout, and the old early return
    threw honest renderable storage away at the wrong rank.  After a
    claimed arm rejects the operand, only the arm the real layout matches
    may pick the value up — the lie must not steer the walk twice.
    Fail-closed like ``_isa``.
    """
    try:
        return issubclass(type(value), types)
    except _CONTROL_FLOW:
        raise
    except BaseException:
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

    Both bases are tried, real layout first-come (the modules12 / nas13
    ``_decode_bytes`` rule the three NAS services already carry): the old
    pick chose the base off the *claimed* ``__class__``, so a genuine
    ``bytearray`` whose ``__class__`` lied ``bytes`` was handed to
    ``bytes.decode``, refused by the descriptor, and its perfectly
    decodable content dropped to None in ``_jsonable``'s bytes arm — and
    rendered as the ``bytearray(b'…')`` repr through ``_utf8_text``'s
    str() probe — degrade at the wrong rank.
    """
    for base in (bytes, bytearray):
        try:
            return base.decode(value, "utf-8", "replace")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
    return None


def _str_text(value):
    """Exact text of *really-str* storage, or ``None`` for an impostor.

    ``str.__str__`` is a descriptor bound to the real str layout: any real
    str (or subclass) answers its character data without dispatching an
    override, while a *lying* ``__class__`` that only claims str rejects
    the operand.  ``None`` lets the caller fall through to the arm the real
    storage matches instead of wiping honest non-str storage to ``""`` at
    the wrong rank (the maint14/jobs14 rule).  The encode-replace pass
    scrubs lone surrogates exactly like the old path.
    """
    try:
        return str.encode(str.__str__(value), "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None


def _truthy(value) -> bool:
    """``bool(value)`` that survives a leftover ``__bool__`` bomb (fails False)."""
    try:
        return bool(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
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
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
    return None


#: CPython's angle-repr shape (``<X object at 0x7f...>`` and the function /
#: bound-method variants) — a raw heap address, never NAS data.  Applied to
#: the *coercion* arms only: real str storage is data (an /etc/exports line
#: or a stderr tail quoting a Python repr serves verbatim).
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500.

    nas14: a *lying* ``__class__`` claim no longer wipes honest storage at
    the wrong rank — a rejected bytes claim falls through so genuine str
    storage keeps its text (the maint14 rule).  And the free-text arm no
    longer runs the dispatching ``str()`` on a type that never overrode
    ``__str__``/``__repr__``: the answer there is the default
    ``object.__repr__`` — ``<X object at 0x7f...>``, a raw heap address —
    which a junk detail / message / name cell used to carry verbatim into
    the JSON body of every NAS read route and mutation funnel.  The slot
    probe reads the real ``type(value)`` (a flickering ``__class__``
    property cannot swap it) and the address belt drops a rendered heap
    address the probe cannot see (a custom ``__repr__`` embedding one).
    """
    if _isa(value, (bytes, bytearray)):
        # Unbound base decode: a leftover bytes-subclass whose bound
        # ``.decode`` raises used to 500 the shares/NAS failure funnels.
        # A lying ``__class__`` claiming bytes decodes to None and falls
        # through, so genuine str storage behind the lie — and a legible
        # impostor with its own ``__str__`` — still renders instead of
        # 500ing the funnel it rode in on.
        decoded = _decode_bytes(value)
        if decoded is not None:
            return decoded
    if _isa(value, str) or _real(value, str):
        text = _str_text(value)
        if text is not None:
            return text
        # A lying-str claim refused the unbound read: coerce off whatever
        # the real storage renders instead of the old "" wipe.
    if value is None:
        return ""
    try:
        cls = type(value)
        if cls.__str__ is object.__str__ and cls.__repr__ is object.__repr__:
            # The dispatching str() below could only answer the default
            # object repr — a raw heap address; never render it.
            return ""
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    try:
        text = str(value)
    except RecursionError:
        try:
            return type(value).__name__
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return ""
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    try:
        # Unbound base encode (the modules6 rule share_acl_svc already
        # follows): ``str()`` of a subclass whose ``__str__`` answers *self*
        # skips CPython's exact-str copy, so a leftover bound ``encode`` bomb
        # dropped the real text to "" — and with it a coded error string
        # ("cancelled", "exists", …) degraded to the generic admin.failed /
        # shares.operation_failed 500 in place of its mapped refusal.
        text = str.encode(text, "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    return "" if _ADDR_REPR_RE.search(text) else text


def _key_text(k):
    """One mapping key as text, or ``None`` to drop just its entry.

    ``_jsonable``'s old key path ran bare ``str(k)`` on any non-str/bytes
    key, and for a type that never overrode ``__str__``/``__repr__`` the
    answer is the default ``object.__repr__`` — ``<X object at 0x7f...>``,
    a raw heap address — which a junk key nested in any NAS payload carried
    verbatim as a JSON *key* on the read routes and the mutation ok bodies
    (the maint14 ``_key_text`` rule).  Same slot probe + address belt as
    ``_utf8_text``'s coercion arm; real str/bytes key storage — behind a
    lying ``__class__`` too — keeps its text verbatim, and a lying-str
    claim with no text storage no longer files its value under a
    fabricated ``""`` key.
    """
    if _isa(k, (bytes, bytearray)):
        decoded = _decode_bytes(k)
        if decoded is not None:
            return decoded
        # A lying-bytes claim: real str storage recovers just below.
    if _isa(k, str) or _real(k, str):
        text = _str_text(k)
        if text is not None:
            return text
        # A lying-str claim: coerce off whatever the real storage renders.
    try:
        cls = type(k)
        if cls.__str__ is object.__str__ and cls.__repr__ is object.__repr__:
            return None
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None
    try:
        text = str(k)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # A raising ``__str__`` key keeps dropping its entry, like before.
        return None
    try:
        text = str.encode(text, "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None
    return None if _ADDR_REPR_RE.search(text) else text


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so a privileged ok payload cannot 500 the encoder.

    nas14 (the maint14/jobs14 shape): ``isinstance`` consults
    ``value.__class__`` only after the real-MRO check misses, so a lying
    ``__class__`` steered a leftover into the arm of its *claim*, the
    unbound descriptor there rejected the real layout, and an early return
    threw honest renderable storage away at the wrong rank — a genuine str
    detail claiming int wiped to ``None``, a genuine bytearray claiming
    bytes dropped its decodable message, a genuine tuple claiming list
    vanished whole.  The rejected arms now fall through to the arm the
    *real* storage matches, probed via ``_real`` so the lie cannot steer
    the walk twice; a total impostor — a claim with no usable layout
    underneath — keeps its established ``None`` drop (the nas9 pins).

    The dict walk also snapshots its items first: a nested cell whose
    guarded hook mutates the mapping mid-walk used to RuntimeError the
    live-view iteration at the loop header — outside every net — a raw
    500 on every NAS read route through ``_rendered``.  Keys go through
    ``_key_text`` (a plain-object key used to serve its default
    ``object.__repr__`` — a raw heap address — as a JSON key), and the
    sequence arm iterates the unbound bases real-layout first-come so a
    real subclass's ``__iter__`` bomb cannot vaporise its perfectly
    walkable storage.
    """
    if depth > 32:
        return None
    # ``type(value) is bool``, not isinstance: bool is final and cannot be
    # subclassed, so the exact check is complete, never reads a bombing
    # ``__class__``, and a bool-liar impostor falls to the int arm's
    # unbound coercion (and from there to its real rank, or the None drop).
    if value is None or type(value) is bool:
        return value
    if _isa(value, int):
        num = value if type(value) is int else None
        if num is None:
            try:
                # Base coercion to an exact int (the modules5 rule): a
                # subclass ``__str__`` bomb used to raise a non-ValueError
                # past the digit-cap probe below and 500 the privileged
                # ok payload.
                num = int.__index__(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                num = None
        if num is not None:
            try:
                str(num)
            except ValueError:
                # Past CPython's int->str digit cap the encoder cannot
                # render the number at all (YAML/plist hex loads uncapped
                # through ``int(x, 16)``, so an over-cap leftover arrives
                # already-int) — json.dumps raises this same ValueError
                # inside Starlette and 500'd the privileged ok payload.
                return None
            return num
        if not _real(value, (float, str, bytes, bytearray, dict,
                             list, tuple, set, frozenset)):
            # A total impostor claiming int/bool keeps the old None drop.
            return None
        # The descriptor refused the operand, so the claimed ``int`` was a
        # lie — but the real storage matches a later arm: fall through.
    if _isa(value, float):
        num = value if type(value) is float else None
        if num is None:
            try:
                # Base coercion to an exact float: a subclass ``__eq__``
                # bomb used to blow the NaN/inf probes below.
                num = float.__float__(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                num = None
        if num is not None:
            if num != num or num in (float("inf"), float("-inf")):
                return None
            return num
        if not _real(value, (str, bytes, bytearray, dict,
                             list, tuple, set, frozenset)):
            # A total impostor claiming float keeps the old None drop.
            return None
        # Genuine text / container behind a lying-float claim falls through.
    if _isa(value, str):
        # ``_str_text``, not the dispatching path: real str storage (any
        # subclass) keeps its scrubbed text; a lying-str claim over genuine
        # bytes / container storage falls through to the arm one rank below
        # instead of the old "" wipe.
        text = _str_text(value)
        if text is not None:
            return text
        if not _real(value, (bytes, bytearray, dict,
                             list, tuple, set, frozenset)):
            # A total impostor claiming str: the coercion arm's slot probe
            # + address belt answer (its default repr — a heap address —
            # must never render; a legible ``__str__`` still does).
            return _utf8_text(value)
    if _isa(value, (bytes, bytearray)):
        decoded = _decode_bytes(value)
        if decoded is not None:
            return decoded
        if not _real(value, (dict, list, tuple, set, frozenset)):
            # A total impostor claiming bytes keeps the old None drop
            # (the nas9 top-rank pin).
            return None
        # Genuine mapping / sequence behind a lying-bytes claim falls
        # through to the arm that reads its real storage.
    if _isa(value, dict):
        # Unbound base view (the modules5 rule): ``dict.items`` reads the
        # real C-level storage, so a subclass ``items()`` bomb cannot fire
        # and the salvageable keys survive.  Materialized (``list(...)``),
        # not the live view: a nested cell whose guarded hook mutates this
        # mapping mid-walk used to RuntimeError the ``for`` header itself —
        # outside every net — and 500 every NAS read route and mutation
        # funnel.  Only genuine control flow keeps propagating.
        try:
            items = list(dict.items(value))
        except _CONTROL_FLOW:
            raise
        except BaseException:
            if not _real(value, (list, tuple, set, frozenset)):
                # A total impostor claiming dict keeps the old None drop.
                return None
            items = None
        if items is not None:
            out = {}
            for k, v in items:
                # Per-pair guard: a bomb *value* drops alone, its sibling
                # keys survive; an unrenderable key (raising ``__str__``, a
                # total lying impostor, a default-repr heap address) drops
                # just its entry through ``_key_text``.
                try:
                    key = _key_text(k)
                    if key is None:
                        continue
                    out[key] = _jsonable(v, depth + 1)
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    continue
            return out
        # Genuine sequence storage behind a lying-dict ``__class__`` falls
        # through: its elements render below instead of vanishing whole.
    if _isa(value, (list, tuple, set, frozenset)):
        # Unbound base iteration, real layout first-come (the nas13 decode
        # rule at sequence rank): the old pick chose the base off the
        # *claimed* ``__class__``, so a genuine tuple lying ``list`` was
        # handed to ``list.__iter__``, refused by the descriptor, and its
        # perfectly walkable rows vanished to None at the wrong rank.
        for base in (list, tuple, set, frozenset):
            try:
                rows = list(base.__iter__(value))
            except _CONTROL_FLOW:
                raise
            except BaseException:
                continue
            out = []
            try:
                for v in rows:
                    out.append(_jsonable(v, depth + 1))
            except _CONTROL_FLOW:
                raise
            except BaseException:
                # A walk dying mid-coercion keeps the elements already done.
                pass
            return out
        return None
    try:
        iso = getattr(value, "isoformat", None)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # getattr's default only swallows AttributeError; a property or
        # ``__getattr__`` bomb still raised out of the probe itself and
        # 500'd the privileged ok payload.
        iso = None
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 a privileged NAS body.
            return _jsonable(iso(), depth + 1)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
    try:
        return _utf8_text(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
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
        return cleaned if _isa(cleaned, dict) else {"ok": True}
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
        return cleaned if _isa(cleaned, dict) else {"ok": True}
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
            if _isa(cleaned, (str, int, float)):
                params[key] = cleaned
        raise api_error(code, **params)
    return raise_for_admin_result(result)
