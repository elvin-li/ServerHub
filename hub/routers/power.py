"""Power control + remote desktop (Screen Sharing / VNC) API."""
from __future__ import annotations

from fastapi import APIRouter, Request
from pydantic import BaseModel

from hub import auth, power_svc, shares_svc
from hub.errors import api_error

router = APIRouter(tags=["power"])


class PowerBody(BaseModel):
    action: str            # shutdown | restart | sleep
    confirm: bool = False


class WolBody(BaseModel):
    enabled: bool = True


@router.get("/api/system/power")
def power_overview():
    return power_svc.power_overview()


@router.post("/api/system/power/action")
def power_action(body: PowerBody):
    return power_svc.power_action(body.action, confirm=body.confirm)


@router.put("/api/system/power/wol")
def set_wol(body: WolBody):
    return power_svc.set_wol(body.enabled)


@router.get("/api/system/screensharing")
def screensharing_status():
    return power_svc.screensharing_status()


def _require_admin_browser(request: Request) -> None:
    if not auth.browser_authenticated(request):
        raise api_error("shares.browser_session_required")
    if not auth.is_admin(auth.request_username(request)):
        raise api_error("shares.admin_required")


def _set_screen_sharing(request: Request, enabled: bool) -> dict:
    _require_admin_browser(request)
    result = shares_svc.set_system_service("screen_sharing", enabled)
    if result.get("ok"):
        return result
    error = str(result.get("error") or "failed")
    code = {
        "cancelled": "shares.authorization_cancelled",
        "unavailable": "shares.authorization_unavailable",
        "verification_failed": "shares.verification_failed",
        "password_required": "admin.password_required",
        "password_incorrect": "admin.password_incorrect",
    }.get(error, "shares.operation_failed")
    raise api_error(code)


@router.post("/api/system/screensharing/enable")
def screensharing_enable(request: Request):
    return _set_screen_sharing(request, True)


@router.post("/api/system/screensharing/disable")
def screensharing_disable(request: Request):
    return _set_screen_sharing(request, False)
