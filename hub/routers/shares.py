from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, StrictBool

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


class SMBUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    smb_name: str
    guest: StrictBool = False
    readonly: StrictBool = False
    encrypted: StrictBool = False


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
    return request.client.host if request.client else "unknown"


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
