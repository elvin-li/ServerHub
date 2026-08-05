from fastapi import APIRouter

from hub.routers import (
    api,
    audit_api,
    catalog,
    cloudflared_api,
    containers,
    files_api,
    logs,
    launcher_api,
    modules_api,
    nas_storage,
    power,
    services_api,
    settings_api,
    shares,
    storage,
    system_extra,
    terminal_api,
    unraid_parity,
    wireguard_api,
)

router = APIRouter()
router.include_router(api.router)
router.include_router(containers.router)
router.include_router(storage.router)
router.include_router(shares.router)
router.include_router(logs.router)
router.include_router(settings_api.router)
router.include_router(system_extra.router)
router.include_router(catalog.router)
router.include_router(modules_api.router)
router.include_router(unraid_parity.router)
router.include_router(services_api.router)
router.include_router(files_api.router)
router.include_router(power.router)
router.include_router(cloudflared_api.router)
router.include_router(terminal_api.router)
router.include_router(audit_api.router)
router.include_router(launcher_api.router)
router.include_router(nas_storage.router)
router.include_router(wireguard_api.router)

__all__ = ["router"]
