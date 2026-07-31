"""Cloudflare Tunnel management API (web panel, no RDP)."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from hub import cloudflared_svc

router = APIRouter(tags=["cloudflared"])


@router.get("/api/cloudflared/status")
def cf_status():
    return cloudflared_svc.status()


@router.post("/api/cloudflared/login")
def cf_login():
    return cloudflared_svc.login_start()


@router.get("/api/cloudflared/login/poll")
def cf_login_poll():
    return cloudflared_svc.login_poll()


class CreateBody(BaseModel):
    name: str = Field(min_length=1, max_length=64)


@router.post("/api/cloudflared/create")
def cf_create(body: CreateBody):
    return cloudflared_svc.create_tunnel(body.name)


class StartTunnelBody(BaseModel):
    tunnel: str = Field(min_length=1, max_length=80)


@router.post("/api/cloudflared/start")
def cf_start_tunnel(body: StartTunnelBody):
    return cloudflared_svc.start_with_tunnel(body.tunnel)


class StartTokenBody(BaseModel):
    token: str = Field(min_length=40, max_length=4000)
    label: Optional[str] = None


@router.post("/api/cloudflared/start-token")
def cf_start_token(body: StartTokenBody):
    return cloudflared_svc.start_with_token(body.token, label=body.label)


@router.post("/api/cloudflared/stop")
def cf_stop():
    return cloudflared_svc.stop()


@router.post("/api/cloudflared/restart")
def cf_restart():
    return cloudflared_svc.restart()


class RouteBody(BaseModel):
    tunnel: str = Field(min_length=1, max_length=80)
    hostname: str = Field(min_length=3, max_length=253)


@router.post("/api/cloudflared/route-dns")
def cf_route(body: RouteBody):
    return cloudflared_svc.route_dns(body.tunnel, body.hostname)


@router.get("/api/cloudflared/logs")
def cf_logs(lines: int = 120):
    return cloudflared_svc.logs(lines=lines)


@router.post("/api/cloudflared/uninstall-service")
def cf_uninstall_service():
    return cloudflared_svc.uninstall_service()
