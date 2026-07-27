from __future__ import annotations

from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from hub import disk_manage_svc, disk_power_svc, storage_pool_svc, storage_svc

router = APIRouter(tags=["storage"])


@router.get("/api/storage")
def storage(light: bool = False):
    data = storage_svc.storage_overview()
    if light:
        return data
    # attach power-manageable disks (HDD sleep/wake)
    try:
        data["power_disks"] = disk_power_svc.list_power_disks()
    except Exception as e:
        data["power_disks"] = []
        data["power_error"] = str(e)
    try:
        data["managed"] = disk_manage_svc.overview()
    except Exception as e:
        data["managed"] = {"volumes": [], "error": str(e)}
    return data


@router.get("/api/storage/disks")
def storage_disks():
    return {"disks": disk_power_svc.list_power_disks()}


@router.get("/api/storage/manage")
def storage_manage():
    """List volumes/partitions for mount/format management."""
    return disk_manage_svc.overview()


class DiskPowerBody(BaseModel):
    action: str  # sleep | wake | eject


@router.post("/api/storage/disks/{disk_id}/power")
def storage_disk_power(disk_id: str, body: DiskPowerBody):
    return disk_power_svc.disk_power_action(disk_id, body.action)


class DiskManageBody(BaseModel):
    action: str = Field(..., description="mount|unmount|mountDisk|unmountDisk|eject|rename|eraseVolume|eraseDisk")
    name: Optional[str] = None  # rename target / format volume name
    fs: Optional[str] = None  # APFS | ExFAT | JHFS+ | MS-DOS
    confirm: bool = False
    confirm_name: Optional[str] = None  # must match current volume name for format


@router.post("/api/storage/manage/{device_id}")
def storage_manage_action(device_id: str, body: DiskManageBody):
    return disk_manage_svc.disk_action(
        device_id,
        body.action,
        name=body.name,
        fs=body.fs,
        confirm=body.confirm,
        confirm_name=body.confirm_name,
    )


class PoolPlanBody(BaseModel):
    #: Mount points, matching what /api/storage/pool reports as candidates.
    #: The service keys members by mount path because that is what a union
    #: layer would be given, and it survives a device-id renumber on reboot.
    mounts: list[str] = Field(default_factory=list)
    policy: str = "most-free"


@router.get("/api/storage/pool")
def storage_pool(force: bool = False):
    """Volumes that could join a pool, and why the others cannot.

    Read-only: this endpoint never mounts or modifies anything.
    """
    return storage_pool_svc.pool_overview(force=force)


@router.post("/api/storage/pool/plan")
def storage_pool_plan(body: PoolPlanBody):
    """Combined capacity and failure semantics for a hypothetical pool.

    Read-only.  A real union mount needs a FUSE layer that is deliberately not
    installed here; the response states that explicitly.
    """
    return storage_pool_svc.plan_pool(body.mounts, policy=body.policy)


class PoolSaveBody(PoolPlanBody):
    #: Display label only; the pool is keyed by its member mounts.
    name: str = "pool"
    #: Reserve headroom on each member so a full disk cannot be handed the next
    #: write.  0 means no reservation.
    min_free_gb: float = 0


@router.post("/api/storage/pool/save")
def storage_pool_save(body: PoolSaveBody):
    """Persist which mounts form the pool, and the placement policy.

    Writes panel configuration only.  No partition table, filesystem, mount or
    file is touched, and dropping a member never removes data from that disk.
    """
    return storage_pool_svc.save_pool(
        body.mounts,
        policy=body.policy,
        name=body.name,
        min_free_gb=body.min_free_gb,
    )


@router.post("/api/storage/pool/clear")
def storage_pool_clear():
    """Forget the pool definition.  Member disks keep every file and stay mounted."""
    return storage_pool_svc.clear_pool()
