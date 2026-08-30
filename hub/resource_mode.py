"""Panel resource profile: low (quiet idle) vs high (fresher UI)."""
from __future__ import annotations

from hub.config import cfg

ALLOWED = ("low", "high")
DEFAULT = "low"

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)


def _isinst(value, types) -> bool:
    """``isinstance`` that a leftover ``__class__`` bomb cannot 500 through.

    CPython's ``isinstance`` reads the operand's ``__class__`` whenever the
    real-type fast check misses, so a leftover whose ``__class__`` is a
    raising property blew the settings-map gate and the ``resource_mode``
    value gate — GET /api/status (``_status_ttl`` → ``is_high``) and
    GET /api/system/sensors?light=1 answered HTTP 500 instead of DEFAULT
    ``low``.  Fail-closed.  Exact-str copies still use ``type(v) is not str``.
    """
    try:
        return isinstance(value, types)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def resource_mode() -> str:
    # ``settings: []`` / a scalar used to AttributeError ``.get`` and 500
    # GET /api/status on a cache hit (``_status_ttl`` → ``is_high``) plus
    # GET /api/system/sensors?light=1.  ``_as_config`` sanitizes disk reads;
    # this still has to tolerate a leftover in-memory mapping.
    try:
        settings = cfg().get("settings")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        settings = {}
    if not _isinst(settings, dict):
        settings = {}
    # ``dict.get`` under a guard, not the bound ``.get``: a leftover settings
    # map that is a dict *subclass* with a bombing ``.get`` passes the
    # isinstance gate above, and this helper runs on *every* ``full_status``
    # call (``_status_ttl`` → ``is_high``, cache hit included) — one bomb
    # used to 500 GET /api/status and POST /api/alerts/check unconditionally.
    try:
        v = settings.get("resource_mode")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        try:
            v = dict.get(settings, "resource_mode")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            v = None
    if _isinst(v, str) and type(v) is not str:
        # Exact-str copy: a str-subclass value whose ``__eq__`` raises used
        # to detonate the ``v in ALLOWED`` membership below.
        try:
            v = str.__str__(v)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            v = None
    if not _isinst(v, str) or not v:
        return DEFAULT
    return v if v in ALLOWED else DEFAULT


def is_high() -> bool:
    return resource_mode() == "high"
