"""APIs for Unraid-parity features: users, health, identity, docker settings, scheduler."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from hub import docker_info_svc, health_svc, identity_svc, system_settings_svc, users_svc
from hub.tools_svc import launchd_timers

router = APIRouter(tags=["unraid-parity"])


@router.get("/api/users")
def api_users():
    return users_svc.overview()


@router.get("/api/health/checks")
def api_health_checks():
    return health_svc.run_checks()


@router.get("/api/identity")
def api_identity():
    return identity_svc.get_identity()


class IdentityBody(BaseModel):
    computer_name: Optional[str] = None
    comment: Optional[str] = None
    host_ip: Optional[str] = None


@router.put("/api/identity")
def api_identity_put(body: IdentityBody):
    return identity_svc.set_identity(
        computer_name=body.computer_name,
        comment=body.comment,
        host_ip=body.host_ip,
    )


@router.get("/api/docker/info")
def api_docker_info():
    return docker_info_svc.engine_info()


@router.get("/api/scheduler")
def api_scheduler():
    """Dedicated scheduler endpoint (alias of system/scheduler with Unraid naming)."""
    timers = launchd_timers()
    return {
        "timers": timers,
        "count": len(timers),
        "hint": "From StartInterval / Calendar entries in LaunchAgents",
    }


@router.get("/api/settings/system")
def api_settings_system():
    """Unraid Settings bundle: datetime / power / disk / management / shares / alias."""
    return system_settings_svc.unraid_settings_bundle()


@router.get("/api/settings/datetime")
def api_settings_datetime():
    return system_settings_svc.get_datetime_info()


@router.get("/api/settings/power")
def api_settings_power():
    return system_settings_svc.get_power_info()


class PowerPrefBody(BaseModel):
    key: str
    value: int


@router.post("/api/settings/power")
def api_settings_power_set(body: PowerPrefBody):
    return system_settings_svc.set_power_pref(body.key, body.value)


@router.get("/api/settings/disk")
def api_settings_disk():
    return system_settings_svc.get_disk_settings()


@router.get("/api/settings/other")
def api_settings_other():
    return system_settings_svc.get_other_settings()


@router.get("/api/settings/thresholds")
def api_settings_thresholds():
    return system_settings_svc.get_thresholds()


@router.get("/api/settings/vms")
def api_settings_vms():
    return system_settings_svc.get_vm_settings()


@router.get("/api/settings/scheduler")
def api_settings_scheduler():
    return system_settings_svc.get_scheduler_summary()


@router.get("/api/diagnostics")
def api_diagnostics():
    """Unraid Diagnostics-style JSON snapshot."""
    return system_settings_svc.collect_diagnostics()


@router.get("/api/diagnostics/download")
def api_diagnostics_download():
    import json
    import time

    data = system_settings_svc.collect_diagnostics()
    body = json.dumps(data, ensure_ascii=False, indent=2, default=str)
    name = f"serverhub-diagnostics-{time.strftime('%Y%m%d-%H%M%S')}.json"
    return PlainTextResponse(
        body,
        media_type="application/json; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )
