from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, StrictBool, StrictInt

from hub import audit, auth, shares_svc
from hub.errors import api_error

router = APIRouter(tags=["shares"])


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
    error = str(result.get("error") or "failed")
    code = {
        "cancelled": "shares.authorization_cancelled",
        "unavailable": "shares.authorization_unavailable",
        "failed": "shares.authorization_failed",
        "verification_failed": "shares.verification_failed",
        "unknown_service": "shares.unknown_service",
        "exists": "shares.exists",
        "not_found": "shares.not_found",
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
    return shares_svc.shares_overview()


@router.post("/api/shares/smb")
def create_share(body: SMBCreate, request: Request):
    username = _require_admin_browser(request)
    try:
        result = shares_svc.create_smb_share(**body.model_dump())
    except shares_svc.ShareValidationError as error:
        raise api_error(error.code)
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
    return result


@router.put("/api/shares/smb/{record_name}")
def update_share(record_name: str, body: SMBUpdate, request: Request):
    username = _require_admin_browser(request)
    try:
        result = shares_svc.update_smb_share(record_name, **body.model_dump())
    except shares_svc.ShareValidationError as error:
        raise api_error(error.code)
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
    return result


@router.delete("/api/shares/smb/{record_name}")
def delete_share(record_name: str, request: Request, confirm: bool = False):
    username = _require_admin_browser(request)
    if confirm is not True:
        raise api_error("shares.confirm_required")
    try:
        result = shares_svc.remove_smb_share(record_name)
    except shares_svc.ShareValidationError as error:
        raise api_error(error.code)
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
    return result


@router.put("/api/shares/system/{service_id}")
def set_system_service(
    service_id: str,
    body: SystemServicePatch,
    request: Request,
):
    username = _require_admin_browser(request)
    result = shares_svc.set_system_service(service_id, body.enabled)
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
    return result


@router.post("/api/shares/open-system-settings")
def open_system_settings(request: Request):
    _require_admin_browser(request)
    result = shares_svc.open_system_settings()
    if not result.get("ok"):
        raise api_error("shares.settings_open_failed")
    return result


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
    except OSError:
        raise api_error("shares.bad_path")
    shared = {
        str(Path(str(share.get("path"))).resolve())
        for share in shares_svc.list_smb_shares(include_sizes=False)
        if share.get("path")
    }
    if resolved not in shared:
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
        raise api_error(error.code)
    return {**state, "users": share_acl_svc.local_users()}


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
        result = share_acl_svc.set_user_access(resolved, body.username, body.level)
    except share_acl_svc.ShareAclError as error:
        raise api_error(error.code)
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
    return result
