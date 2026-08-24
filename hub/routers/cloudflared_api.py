"""Cloudflare Tunnel management API (web panel, no RDP)."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from hub import audit, auth, cloudflared_svc

router = APIRouter(tags=["cloudflared"])


def _audit_change(request: Request | None, action: str, **fields) -> None:
    """One line per tunnel mutation — a tunnel exposes this panel to the
    public internet, and route-dns points a public hostname at it.

    Called after the service call returned, so a failed cloudflared
    invocation that raised leaves no record.  FastAPI always injects
    `request`; the None guard only keeps direct in-process calls (tests,
    tooling) working.
    """
    audit.record(
        audit.TUNNEL_CHANGED,
        username=auth.request_username(request) if request is not None else "",
        client=auth.request_client_id(request),
        action=action,
        **fields,
    )


@router.get("/api/cloudflared/status")
def cf_status():
    return cloudflared_svc.status()


@router.post("/api/cloudflared/login")
def cf_login(request: Request = None):
    result = cloudflared_svc.login_start()
    _audit_change(request, "login_started")
    return result


@router.get("/api/cloudflared/login/poll")
def cf_login_poll():
    return cloudflared_svc.login_poll()


class CreateBody(BaseModel):
    name: str = Field(min_length=1, max_length=64)


@router.post("/api/cloudflared/create")
def cf_create(body: CreateBody, request: Request = None):
    result = cloudflared_svc.create_tunnel(body.name)
    _audit_change(request, "create", tunnel=body.name)
    return result


class StartTunnelBody(BaseModel):
    tunnel: str = Field(min_length=1, max_length=80)


@router.post("/api/cloudflared/start")
def cf_start_tunnel(body: StartTunnelBody, request: Request = None):
    result = cloudflared_svc.start_with_tunnel(body.tunnel)
    _audit_change(request, "start", tunnel=body.tunnel)
    return result


class StartTokenBody(BaseModel):
    token: str = Field(min_length=40, max_length=4000)
    label: Optional[str] = None


@router.post("/api/cloudflared/start-token")
def cf_start_token(body: StartTokenBody, request: Request = None):
    result = cloudflared_svc.start_with_token(body.token, label=body.label)
    # The connector token is a credential and is never passed to record().
    _audit_change(request, "start_token", label=body.label or "")
    return result


@router.post("/api/cloudflared/stop")
def cf_stop(request: Request = None):
    result = cloudflared_svc.stop()
    _audit_change(request, "stop")
    return result


@router.post("/api/cloudflared/restart")
def cf_restart(request: Request = None):
    result = cloudflared_svc.restart()
    _audit_change(request, "restart")
    return result


class RouteBody(BaseModel):
    tunnel: str = Field(min_length=1, max_length=80)
    hostname: str = Field(min_length=3, max_length=253)


@router.post("/api/cloudflared/route-dns")
def cf_route(body: RouteBody, request: Request = None):
    result = cloudflared_svc.route_dns(body.tunnel, body.hostname)
    _audit_change(request, "route_dns", tunnel=body.tunnel, hostname=body.hostname)
    return result


@router.get("/api/cloudflared/logs")
def cf_logs(lines: int = 120):
    return cloudflared_svc.logs(lines=lines)


@router.post("/api/cloudflared/uninstall-service")
def cf_uninstall_service(request: Request = None):
    result = cloudflared_svc.uninstall_service()
    _audit_change(request, "uninstall_service")
    return result
