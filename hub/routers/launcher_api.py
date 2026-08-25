from __future__ import annotations

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, StrictBool

from hub import audit, auth, launcher_svc
from hub.errors import api_error

router = APIRouter(prefix="/api/launcher", tags=["launcher"])


class LoginItemPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: StrictBool


def _require_admin_browser(request: Request) -> str:
    if not auth.browser_authenticated(request):
        raise api_error("launcher.browser_session_required")
    username = auth.request_username(request)
    if not auth.is_admin(username):
        raise api_error("launcher.admin_required")
    return username


@router.get("")
def launcher_status():
    return launcher_svc.status()


@router.post("/open")
def launcher_open(request: Request):
    username = _require_admin_browser(request)
    result = launcher_svc.open_app()
    audit.record(
        audit.LAUNCHER_CHANGED,
        username=username,
        client=auth.request_client_id(request),
        action="open",
    )
    return result


@router.put("/login")
def launcher_login(body: LoginItemPatch, request: Request):
    username = _require_admin_browser(request)
    result = launcher_svc.set_login_enabled(body.enabled)
    audit.record(
        audit.LAUNCHER_CHANGED,
        username=username,
        client=auth.request_client_id(request),
        action="login_item",
        enabled=bool(body.enabled),
    )
    return result


@router.post("/panel/{action}")
def launcher_panel(action: str, request: Request):
    username = _require_admin_browser(request)
    if action not in {"restart", "stop"}:
        raise api_error("launcher.bad_action", action=action)
    result = launcher_svc.schedule_panel_action(action)
    # Stopping the panel is the last moment this trail can be written.
    audit.record(
        audit.LAUNCHER_CHANGED,
        username=username,
        client=auth.request_client_id(request),
        action=action,
    )
    return result
