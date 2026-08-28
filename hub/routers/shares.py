from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, StrictBool, StrictInt

from hub import audit, auth, shares_svc
from hub.errors import api_error, api_error_from
from hub.routers.nas_common import _isa, _jsonable, _plain_result, _truthy, _utf8_text

router = APIRouter(tags=["shares"])


def _str_keyed(plain: dict) -> dict:
    """*plain* (an exact dict) with every key an exact ``str``.

    One hash-shadowing key — same hash as the literal a reader fetches,
    raising ``__eq__`` — detonates the *probe itself*: ``.get`` on a
    laundered copy is still a hash-table probe, one seam earlier than any
    value gate (the compose10 / files13 shadow-key class).  A shadow over
    ``ok`` in a service result blew ``_service_result``'s very next read,
    a shadow over ``error`` blew ``_raise_service_error``, and a shadow
    over ``users`` in an ACL state blew the GET route's ``{**plain, ...}``
    merge — raw 500s in place of the coded refusals.  ``str.__str__``
    copies through the C storage, so laundering cannot itself detonate;
    non-str keys drop — no reader ever looks a field up by one.
    """
    # Iterating a plain dict's keys never dispatches into a subclass, so
    # this probe cannot raise; the common all-exact-str map returns as-is.
    if all(type(k) is str for k in plain):
        return plain
    out = {}
    for k, v in plain.items():
        if type(k) is str:
            out[k] = v
        elif _isa(k, str):
            # _isa: a ``__class__``-property-bomb KEY blew a bare gate.
            # str.__str__ TypeErrors on a lying-``__class__`` impostor and
            # the junk key drops like any other non-str.
            try:
                out[str.__str__(k)] = v
            except Exception:
                continue
    return out


def _service_result(result) -> dict:
    """Coerce a leftover non-dict service result into the coded failure.

    Every route below reads ``result.get("ok")`` and hands the payload to
    Starlette verbatim, so a leftover ``None`` from a privileged helper
    AttributeError'd the route as a raw 500 — the exact class
    ``nas_common.raise_for_admin_result`` already guards for the newer NAS
    routers.  The coded ``shares.operation_failed`` is the honest answer.

    ``_plain_result`` + ``_truthy``, not the bare isinstance the first fix
    used: a leftover dict-*subclass* result whose ``.get`` raised passed the
    gate and 500'd the very next line, and a ``__bool__``-bomb ``ok`` value
    blew the routes' own ``if not result.get("ok")`` reads.  The laundered
    copy carries a real bool ``ok`` so every downstream read is safe.
    """
    plain = _plain_result(result)
    if plain is None:
        return {"ok": False, "error": "failed"}
    # _str_keyed before any probe: a hash-shadowing ``ok`` / ``error`` key
    # survived ``_plain_result``'s type laundering and detonated the
    # ``plain.get("ok")`` read below (and ``_raise_service_error``'s
    # ``result.get("error")`` after it) — raw 500s on every share mutation.
    plain = _str_keyed(plain)
    plain["ok"] = _truthy(plain.get("ok"))
    return plain


def _ok_payload(result: dict) -> dict:
    """A successful result through the shared sanitizer before Starlette.

    The share routes pasted the service result into the response body
    verbatim, so a leftover the encoder cannot take — a lone ``\\ud800`` in a
    key or value, an over-cap already-int (YAML/plist hex loads uncapped
    through ``int(x, 16)``), or a collection that passes ``isinstance`` but
    refuses iteration — 500'd the whole route where every NAS sibling answers
    with the field dropped or the text scrubbed (the ``nas_common._jsonable``
    rule this router missed).
    """
    cleaned = _jsonable(result)
    return cleaned if isinstance(cleaned, dict) else {"ok": True}


class SMBCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    name: str
    smb_name: str
    guest: StrictBool = False
    readonly: StrictBool = False
    encrypted: StrictBool = False
    time_machine: StrictBool = False
    # Range and the "quota needs the TM flag" rule are enforced in shares_svc,
    # where violations surface as machine-readable codes instead of a 422.
    tm_quota_gb: StrictInt | None = None


class SMBUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    smb_name: str
    guest: StrictBool = False
    readonly: StrictBool = False
    encrypted: StrictBool = False
    time_machine: StrictBool = False
    tm_quota_gb: StrictInt | None = None


class SystemServicePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: StrictBool


def _require_admin_browser(request: Request) -> str:
    if not auth.browser_authenticated(request):
        raise api_error("shares.browser_session_required")
    username = auth.request_username(request)
    if not auth.is_admin(username):
        raise api_error("shares.admin_required")
    return username


def _client(request: Request) -> str:
    return auth.request_client_id(request)


def _raise_service_error(result: dict, *, service: str = "") -> None:
    # _utf8_text, not str(): a leftover *already-int* error field past
    # CPython's int->str digit cap (YAML/plist hex loads uncapped through
    # ``int(x, 16)``) made the bare str() raise the digit-cap ValueError out
    # of the route — an unhandled 500 in place of the coded refusal (the
    # nas_common.raise_for_admin_result rule this copy predates).  _truthy
    # before the ``or``: a ``__bool__``-bomb error value used to raise out
    # of the fallback chain itself.
    raw_error = result.get("error")
    error = (_utf8_text(raw_error) if _truthy(raw_error) else "") or "failed"
    code = {
        "cancelled": "shares.authorization_cancelled",
        "unavailable": "shares.authorization_unavailable",
        "failed": "shares.authorization_failed",
        "verification_failed": "shares.verification_failed",
        "unknown_service": "shares.unknown_service",
        "exists": "shares.exists",
        "not_found": "shares.not_found",
        # Confirmed-vanished CLIs (fresh disk probe on the failure path only):
        # a coded 503, not the generic 500 that sends the operator back to a
        # password dialog that cannot help.
        "sharing_missing": "shares.sharing_missing",
        "acl_tool_missing": "shares.acl_tool_missing",
        "system_tool_missing": "shares.system_tool_missing",
        # Shared admin codes so the SPA's password dialog handles every feature
        # the same way.
        "password_required": "admin.password_required",
        "password_incorrect": "admin.password_incorrect",
    }.get(error, "shares.operation_failed")
    if code == "shares.unknown_service":
        raise api_error(code, service=service)
    raise api_error(code)


def _path_label(path: str) -> str:
    # Audits identify the affected folder without recording its full hierarchy.
    return Path(path).name[:64]


def _audit_change(
    event: str,
    request: Request,
    username: str,
    *,
    action: str,
    outcome: str,
    **fields,
) -> None:
    audit.record(
        event,
        username=username,
        client=_client(request),
        action=action,
        outcome=outcome,
        **fields,
    )


@router.get("/api/shares")
def shares():
    # The mutations below all clean their body through ``_ok_payload``; this
    # read pasted the whole page payload in verbatim.  A leftover the encoder
    # cannot take — a lone ``\ud800`` in a share or service name, an over-cap
    # already-int quota (plist hex loads uncapped through ``int(x, 16)``), an
    # ``inf`` ``size_mb`` from a garbled ``du``, or a listing that passes
    # ``isinstance`` but refuses iteration — 500'd the entire shares page
    # where every sibling answers with the field dropped or the text
    # scrubbed (the nas_storage / storage ``_rendered`` rule).
    cleaned = _jsonable(shares_svc.shares_overview())
    return cleaned if isinstance(cleaned, dict) else {}


@router.post("/api/shares/smb")
def create_share(body: SMBCreate, request: Request):
    username = _require_admin_browser(request)
    try:
        result = _service_result(shares_svc.create_smb_share(**body.model_dump()))
    except shares_svc.ShareValidationError as error:
        # api_error_from, not bare ``api_error(error.code)``: a leftover
        # subclass whose ``code`` is a *raising property* used to detonate
        # the attribute read inside this except clause — a raw HTTP 500 in
        # place of the coded validation refusal (same guarded unwrap on
        # every ShareValidationError / ShareAclError site in this router).
        raise api_error_from(error)
    outcome = "success" if result.get("ok") else "failure"
    _audit_change(
        audit.SHARE_CHANGED,
        request,
        username,
        action="create",
        outcome=outcome,
        record=body.name[:64],
        folder=_path_label(body.path),
        time_machine=body.time_machine,
        # The quota is part of the TM contract (it caps how much a client may
        # write), so a change to it must be answerable from the trail too.
        tm_quota_gb=body.tm_quota_gb,
    )
    if not result.get("ok"):
        _raise_service_error(result)
    return _ok_payload(result)


@router.put("/api/shares/smb/{record_name}")
def update_share(record_name: str, body: SMBUpdate, request: Request):
    username = _require_admin_browser(request)
    try:
        result = _service_result(
            shares_svc.update_smb_share(record_name, **body.model_dump())
        )
    except shares_svc.ShareValidationError as error:
        raise api_error_from(error)
    _audit_change(
        audit.SHARE_CHANGED,
        request,
        username,
        action="update",
        outcome="success" if result.get("ok") else "failure",
        record=record_name[:64],
        time_machine=body.time_machine,
        tm_quota_gb=body.tm_quota_gb,
    )
    if not result.get("ok"):
        _raise_service_error(result)
    return _ok_payload(result)


@router.delete("/api/shares/smb/{record_name}")
def delete_share(record_name: str, request: Request, confirm: bool = False):
    username = _require_admin_browser(request)
    if confirm is not True:
        raise api_error("shares.confirm_required")
    try:
        result = _service_result(shares_svc.remove_smb_share(record_name))
    except shares_svc.ShareValidationError as error:
        raise api_error_from(error)
    _audit_change(
        audit.SHARE_CHANGED,
        request,
        username,
        action="remove",
        outcome="success" if result.get("ok") else "failure",
        record=record_name[:64],
    )
    if not result.get("ok"):
        _raise_service_error(result)
    return _ok_payload(result)


@router.put("/api/shares/system/{service_id}")
def set_system_service(
    service_id: str,
    body: SystemServicePatch,
    request: Request,
):
    username = _require_admin_browser(request)
    result = _service_result(shares_svc.set_system_service(service_id, body.enabled))
    _audit_change(
        audit.SYSTEM_SHARING_CHANGED,
        request,
        username,
        action="enable" if body.enabled else "disable",
        outcome="success" if result.get("ok") else "failure",
        service=service_id[:64],
    )
    if not result.get("ok"):
        _raise_service_error(result, service=service_id)
    return _ok_payload(result)


@router.post("/api/shares/open-system-settings")
def open_system_settings(request: Request):
    _require_admin_browser(request)
    result = _service_result(shares_svc.open_system_settings())
    if not result.get("ok"):
        # A confirmed-vanished ``open`` is the coded 503, not the 500 that
        # blames System Settings itself.  _utf8_text before the ``==``: a
        # leftover subclass error value whose ``__eq__`` raises used to
        # detonate this very probe into a raw 500.
        if _utf8_text(result.get("error")) == "system_tool_missing":
            raise api_error("shares.system_tool_missing")
        raise api_error("shares.settings_open_failed")
    return _ok_payload(result)


# ── per-user share access (filesystem ACLs) ──────────────────────────────────
# macOS has no per-user field on the share record itself (verified: sharing -l
# and the dscl SharePoints attributes are share-wide flags only), so per-user
# access is the share directory's ACL.  See hub/share_acl_svc.py.


class ShareAclPut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    username: str
    level: str  # none | read | readwrite


def _share_directory(path: str) -> str:
    """Resolve *path* against the current share points, fail closed.

    Restricting the ACL surface to directories that are actually shared keeps
    this endpoint from becoming a generic chmod-as-root oracle: everything
    else in the filesystem stays out of reach no matter what is posted.
    """
    try:
        resolved = str(Path(str(path or "")).resolve(strict=True))
    except (OSError, ValueError, TypeError, RuntimeError):
        raise api_error("shares.bad_path")
    shared = set()
    try:
        listing = shares_svc.list_smb_shares(include_sizes=False)
    except Exception:
        listing = []
    try:
        # Guarded iter() (the users_svc rule): a leftover list-subclass
        # listing whose ``__iter__`` bomb fired *at* the walk used to raise
        # out of the gate itself and 500 GET and PUT /api/shares/acl.
        rows = iter(listing)
    except Exception:
        rows = iter(())
    try:
        for share in rows:
            # dict.get, not share.get: a leftover dict-subclass row whose bound
            # ``.get`` raised used to 500 GET and PUT /api/shares/acl out of the
            # gate itself (the jobs/metrics row-bomb class).  _isa, not a bare
            # isinstance: a row whose ``__class__`` is a raising property blew
            # the gate into the walk-level catch, so every share point after
            # the hostile row was lost and a legitimately shared directory
            # answered the acl_not_share lie.  Try-wrapped unbound get: a
            # *lying* ``__class__`` impostor passes the dict gate but is no
            # dict underneath, and the unbound TypeError rode the same path.
            try:
                raw = dict.get(share, "path") if _isa(share, dict) else None
            except Exception:
                raw = None
            if not _truthy(raw):
                continue
            try:
                shared.add(str(Path(str(raw)).resolve()))
            except Exception:
                # Any exception, not just the four Path shapes: a leftover
                # ``__str__`` bomb raising something else used to escape into
                # the outer catch and abort the walk, so every share point
                # *after* the hostile row was lost and a legitimate directory
                # answered the acl_not_share / sharing_missing lie.
                continue
    except Exception:
        # A walk dying mid-iteration keeps the share points already
        # collected; the resolve below then answers from what is known.
        pass
    if resolved not in shared:
        # With the sharing CLI gone the listing cannot answer at all, so
        # "not a share point" would be a 400 lie — the same family as the
        # update/remove 404 lie.  Fresh disk probe on this failure path
        # only: an honestly empty share set with the CLI on disk keeps the
        # honest refusal.
        if not shared and not shares_svc._sharing_on_disk():
            raise api_error("shares.sharing_missing")
        raise api_error("shares.acl_not_share")
    return resolved


@router.get("/api/shares/acl")
def share_acl(path: str, request: Request):
    """Current ACL of one shared directory plus the pickable local users."""
    from hub import share_acl_svc

    _require_admin_browser(request)
    resolved = _share_directory(path)
    try:
        state = share_acl_svc.read_acl(resolved)
    except share_acl_svc.ShareAclError as error:
        raise api_error_from(error)
    # _plain_result before the ``{**state}`` merge: a leftover dict-subclass
    # state whose ``keys()``/``__iter__`` raises takes dict-unpacking's slow
    # path and used to 500 the route out of the merge itself; junk shapes
    # earn the coded read failure.  _jsonable before Starlette: a lone
    # ``\\ud800`` or over-cap already-int leftover in the state or the user
    # rows used to 500 the encoder where every sibling route answers with
    # the field dropped or the text scrubbed (the _ok_payload rule this GET
    # missed).
    plain = _plain_result(state)
    if plain is None:
        raise api_error("shares.acl_read_failed")
    # _str_keyed before the merge: inserting ``users`` is a hash-table
    # probe, so a hash-shadowing ``users`` key in a leftover state raised
    # its ``__eq__`` bomb out of the merge itself — a raw 500 on
    # GET /api/shares/acl one line past the type laundering.
    return _jsonable({**_str_keyed(plain), "users": share_acl_svc.local_users()})


@router.put("/api/shares/acl")
def share_acl_put(body: ShareAclPut, request: Request):
    """Grant / revoke one user's access to one shared directory.

    Writes are verified by reading the ACL back; the response carries the
    on-disk state.  Runs under the same web-password escalation as every
    other privileged share mutation when the panel does not own the folder.
    """
    from hub import share_acl_svc

    username = _require_admin_browser(request)
    resolved = _share_directory(body.path)
    try:
        result = _service_result(
            share_acl_svc.set_user_access(resolved, body.username, body.level)
        )
    except share_acl_svc.ShareAclError as error:
        raise api_error_from(error)
    _audit_change(
        audit.SHARE_CHANGED,
        request,
        username,
        action="acl_set",
        outcome="success" if result.get("ok") else "failure",
        folder=_path_label(resolved),
        target=body.username[:64],
        level=body.level[:16],
    )
    if not result.get("ok"):
        _raise_service_error(result)
    return _ok_payload(result)
