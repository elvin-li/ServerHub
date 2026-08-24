"""Power control + remote desktop (Screen Sharing / VNC) API."""
from __future__ import annotations

from fastapi import APIRouter, Request
from pydantic import BaseModel

from hub import audit, auth, power_svc, shares_svc
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
def power_action(body: PowerBody, request: Request):
    # power_svc raises before scheduling on an unknown action or a missing
    # confirm, so reaching record() means the countdown really started —
    # this is the last moment the trail can be written before shutdown.
    result = power_svc.power_action(body.action, confirm=body.confirm)
    audit.record(
        audit.POWER_ACTION,
        username=auth.request_username(request),
        client=auth.request_client_id(request),
        action=body.action,
    )
    return result


@router.put("/api/system/power/wol")
def set_wol(body: WolBody, request: Request):
    result = power_svc.set_wol(body.enabled)
    audit.record(
        audit.POWER_WOL_CHANGED,
        username=auth.request_username(request),
        client=auth.request_client_id(request),
        action="enable" if body.enabled else "disable",
        outcome="success" if result.get("ok") else "failure",
    )
    return result


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
    # Same event and shape as the shares router's system-service toggle:
    # Screen Sharing is remote-desktop access to the whole machine, and this
    # endpoint used to flip it without a trace while /api/system/services/…
    # recorded the equivalent change.
    audit.record(
        audit.SYSTEM_SHARING_CHANGED,
        username=auth.request_username(request),
        client=auth.request_client_id(request),
        action="enable" if enabled else "disable",
        outcome="success" if isinstance(result, dict) and result.get("ok") else "failure",
        service="screen_sharing",
    )
    # Leftover None AttributeError'd enable/disable; leftover inf / ``\\ud800``
    # in an ok payload 500'd Starlette's allow_nan=False encoder.
    if not isinstance(result, dict):
        raise api_error("shares.operation_failed")
    if result.get("ok"):
        cleaned = power_svc._jsonable(result)
        return cleaned if isinstance(cleaned, dict) else {"ok": True}
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
