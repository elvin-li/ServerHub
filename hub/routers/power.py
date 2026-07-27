"""Power control + remote desktop (Screen Sharing / VNC) API."""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from hub import power_svc

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


@router.post("/api/system/screensharing/enable")
def screensharing_enable():
    return power_svc.enable_screensharing()


@router.post("/api/system/screensharing/disable")
def screensharing_disable():
    return power_svc.disable_screensharing()
