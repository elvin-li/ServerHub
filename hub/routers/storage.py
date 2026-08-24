from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from hub import audit, auth, disk_manage_svc, disk_power_svc, storage_pool_svc, storage_svc
from hub.util import LazyPool


def _audit_disk_change(event: str, request: Request | None, **fields) -> None:
    """One audit line for a disk or pool mutation — eraseDisk is the most
    destructive action in the panel.  Called after the service call returned,
    so a rejected action that raised leaves no record.  FastAPI always injects
    `request`; the None guard only keeps direct in-process calls working."""
    audit.record(
        event,
        username=auth.request_username(request) if request is not None else "",
        client=auth.request_client_id(request),
        **fields,
    )


def _as_text(value) -> str:
    """Drop leftover ``\\ud800`` in ``str(e)`` so GET /api/storage cannot UTF-8 500."""
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    elif value is None:
        return ""
    else:
        try:
            value = str(value)
        except RecursionError:
            try:
                return type(value).__name__
            except Exception:
                return ""
        except Exception:
            return ""
    return value.encode("utf-8", "replace").decode("utf-8")


router = APIRouter(tags=["storage"])

#: Page composer only.  Overview fans out SMART on the shared probe pool.
_PAGE_POOL = LazyPool(3, "storage-page")


def shutdown_executor() -> None:
    _PAGE_POOL.shutdown()


@router.get("/api/storage")
def storage(light: bool = False):
    if light:
        return storage_svc.storage_overview()
    # The three sections read independent state, so run them concurrently and
    # pay for the slowest one instead of their sum.  Error semantics are
    # unchanged from the serial version: an overview failure propagates (the
    # response is the overview itself, so there is nothing to fall back to),
    # while a power or managed failure degrades just its own key.
    f_overview = _PAGE_POOL.submit(storage_svc.storage_overview)
    f_power = _PAGE_POOL.submit(disk_power_svc.list_power_disks)
    f_managed = _PAGE_POOL.submit(disk_manage_svc.overview)
    try:
        data = f_overview.result()
    except Exception as e:
        data = {"volumes": [], "disks": [], "error": _as_text(e)}
    if not isinstance(data, dict):
        data = {"volumes": [], "disks": [], "error": _as_text(data)}
    try:
        data["power_disks"] = f_power.result()
    except Exception as e:
        data["power_disks"] = []
        data["power_error"] = _as_text(e)
    try:
        data["managed"] = f_managed.result()
    except Exception as e:
        data["managed"] = {"volumes": [], "error": _as_text(e)}
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
def storage_disk_power(disk_id: str, body: DiskPowerBody, request: Request = None):
    try:
        result = disk_power_svc.disk_power_action(disk_id, body.action)
        _audit_disk_change(audit.DISK_CHANGED, request,
                           action=body.action, disk=disk_id)
        return result
    finally:
        # Sleeping, ejecting or waking a disk changes whether it answers SMART at
        # all.  The service already drops its own caches; the SMART snapshot lives
        # in a third module, so it is dropped here for the same reason the manage
        # route below does it.  Fired even on failure: a partial eject still moved
        # state, and dropping a cache can never lie.
        storage_svc.invalidate_smart()


class DiskManageBody(BaseModel):
    action: str = Field(..., description="mount|unmount|mountDisk|unmountDisk|eject|rename|eraseVolume|eraseDisk")
    name: Optional[str] = None  # rename target / format volume name
    fs: Optional[str] = None  # APFS | ExFAT | JHFS+ | MS-DOS
    confirm: bool = False
    confirm_name: Optional[str] = None  # must match current volume name for format


@router.post("/api/storage/manage/{device_id}")
def storage_manage_action(device_id: str, body: DiskManageBody, request: Request = None):
    try:
        result = disk_manage_svc.disk_action(
            device_id,
            body.action,
            name=body.name,
            fs=body.fs,
            confirm=body.confirm,
            confirm_name=body.confirm_name,
        )
        _audit_disk_change(audit.DISK_CHANGED, request,
                           action=body.action, disk=device_id,
                           fs=body.fs or "")
        return result
    finally:
        # Manage actions mutate the same mount/presence state the power panel
        # renders.  This module may import both services without the cycle a
        # direct disk_manage_svc -> disk_power_svc edge would create, so the
        # cross-module invalidation lives here.  Fired even on a rejected
        # action: dropping the cache costs one refetch and can never lie.
        disk_power_svc.invalidate_power_disks()
        # The SMART snapshot describes which disks are present, so an eject or an
        # erase invalidates it too -- and its TTL is ten minutes, long enough for a
        # removed disk to keep showing a health row for the rest of the session.
        storage_svc.invalidate_smart()


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
def storage_pool_save(body: PoolSaveBody, request: Request = None):
    """Persist which mounts form the pool, and the placement policy.

    Writes panel configuration only.  No partition table, filesystem, mount or
    file is touched, and dropping a member never removes data from that disk.
    """
    result = storage_pool_svc.save_pool(
        body.mounts,
        policy=body.policy,
        name=body.name,
        min_free_gb=body.min_free_gb,
    )
    _audit_disk_change(audit.POOL_CHANGED, request,
                       action="save", mounts=",".join(body.mounts or []),
                       policy=body.policy)
    return result


@router.post("/api/storage/pool/clear")
def storage_pool_clear(request: Request = None):
    """Forget the pool definition.  Member disks keep every file and stay mounted."""
    result = storage_pool_svc.clear_pool()
    _audit_disk_change(audit.POOL_CHANGED, request, action="clear")
    return result
