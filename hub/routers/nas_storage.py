"""Storage and data-protection APIs: NFS exports, AppleRAID, snapshots, SMART, usage.

These are the features an operator coming from Unraid or OMV looks for first and
that this panel previously had no answer for.  Read endpoints are open to any
signed-in session; anything that exports data to the network, erases a disk or
deletes a restore point additionally requires an administrator *browser* session,
because it drives a native macOS authorization sheet.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field, StrictBool

from hub import audit, nfs_svc, raid_svc, smart_test_svc, snapshots_svc, usage_svc
from hub.errors import api_error
from hub.routers.nas_common import (
    _utf8_text,
    client_host,
    raise_for_admin_result,
    raise_service_error,
    require_admin_browser,
)

router = APIRouter(tags=["nas-storage"])


# ── NFS exports ──────────────────────────────────────────────────────────────

class NfsExportEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    #: Host list.  Accepts IPv4, IPv4/prefix or hostname; the literal "everyone"
    #: opts into an unrestricted export and is reported as such in the UI.
    clients: list[str] = Field(default_factory=list)
    readonly: StrictBool = False
    alldirs: StrictBool = True
    maproot: str = ""
    mapall: str = ""


class NfsSaveBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: The complete export table.  Saving replaces /etc/exports wholesale, so an
    #: omitted entry is a deletion — the SPA always sends the full list.
    entries: list[NfsExportEntry] = Field(default_factory=list)


class NfsServerActionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str = Field(..., description="enable|disable|start|stop|restart|update")


@router.get("/api/nfs")
def api_nfs(force: bool = False):
    return nfs_svc.overview(force=force)


@router.get("/api/nfs/stats")
def api_nfs_stats():
    return nfs_svc.statistics()


@router.post("/api/nfs/exports")
def api_nfs_save(body: NfsSaveBody, request: Request):
    username = require_admin_browser(request)
    try:
        result = nfs_svc.save_exports([e.model_dump() for e in body.entries])
    except nfs_svc.NfsConfigError as exc:
        raise api_error(exc.code, **exc.params)
    audit.record(
        audit.NFS_CHANGED,
        username=username,
        client=client_host(request),
        action="save",
        count=len(body.entries),
        ok=bool(result.get("ok")),
    )
    return raise_for_admin_result(result)


@router.post("/api/nfs/server")
def api_nfs_server(body: NfsServerActionBody, request: Request):
    username = require_admin_browser(request)
    result = nfs_svc.server_action(body.action)
    audit.record(
        audit.NFS_CHANGED,
        username=username,
        client=client_host(request),
        action=body.action,
        ok=bool(result.get("ok")),
    )
    return raise_service_error(result, {"bad_action": "nfs.bad_action"})


# ── AppleRAID ────────────────────────────────────────────────────────────────

class RaidCreateBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    level: str = Field(..., description="mirror|stripe|concat")
    name: str
    filesystem: str = "APFS"
    devices: list[str] = Field(default_factory=list)
    confirm: StrictBool = False
    #: Must be the literal "ERASE".  A second, differently-shaped confirmation
    #: keeps an accidental replay of a create request from wiping disks.
    confirm_phrase: str = ""


class RaidDeleteBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    set_uuid: str
    confirm: StrictBool = False
    #: Must equal the set's own name, so the operator names what they destroy.
    confirm_phrase: str = ""


class RaidMemberBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    set_uuid: str
    device: str
    confirm: StrictBool = False


class RaidRemoveMemberBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    set_uuid: str
    member_uuid: str
    confirm: StrictBool = False


@router.get("/api/raid")
def api_raid(force: bool = False):
    return raid_svc.overview(force=force)


def _raid_call(fn, request: Request, action: str, **kwargs):
    username = require_admin_browser(request)
    try:
        result = fn(**kwargs)
    except raid_svc.RaidError as exc:
        raise api_error(exc.code, **exc.params)
    audit.record(
        audit.RAID_CHANGED,
        username=username,
        client=client_host(request),
        action=action,
        ok=bool(result.get("ok")),
        **{k: v for k, v in kwargs.items() if k != "confirm_phrase"},
    )
    return raise_for_admin_result(result)


@router.post("/api/raid/sets")
def api_raid_create(body: RaidCreateBody, request: Request):
    return _raid_call(
        raid_svc.create_set,
        request,
        "create",
        level=body.level,
        name=body.name,
        filesystem=body.filesystem,
        devices=body.devices,
        confirm=body.confirm,
        confirm_phrase=body.confirm_phrase,
    )


@router.post("/api/raid/delete")
def api_raid_delete(body: RaidDeleteBody, request: Request):
    return _raid_call(
        raid_svc.delete_set,
        request,
        "delete",
        set_uuid=body.set_uuid,
        confirm=body.confirm,
        confirm_phrase=body.confirm_phrase,
    )


@router.post("/api/raid/repair")
def api_raid_repair(body: RaidMemberBody, request: Request):
    return _raid_call(
        raid_svc.repair_mirror,
        request,
        "repair",
        set_uuid=body.set_uuid,
        device=body.device,
        confirm=body.confirm,
    )


@router.post("/api/raid/members/add")
def api_raid_add_member(body: RaidMemberBody, request: Request):
    return _raid_call(
        raid_svc.add_member,
        request,
        "add_member",
        set_uuid=body.set_uuid,
        device=body.device,
        confirm=body.confirm,
    )


@router.post("/api/raid/members/remove")
def api_raid_remove_member(body: RaidRemoveMemberBody, request: Request):
    return _raid_call(
        raid_svc.remove_member,
        request,
        "remove_member",
        set_uuid=body.set_uuid,
        member_uuid=body.member_uuid,
        confirm=body.confirm,
    )


# ── APFS snapshots + Time Machine ────────────────────────────────────────────

class SnapshotDeleteBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mount: str = "/"
    #: Omit to delete every dated snapshot on the volume.
    date_token: Optional[str] = None
    confirm: StrictBool = False


class SnapshotThinBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mount: str = "/"
    urgency: int = 1


class TimeMachineActionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str = Field(..., description="start|stop|enable|disable")


@router.get("/api/snapshots")
def api_snapshots(force: bool = False):
    return snapshots_svc.overview(force=force)


@router.post("/api/snapshots/create")
def api_snapshot_create(request: Request):
    username = require_admin_browser(request)
    result = snapshots_svc.create_snapshot()
    audit.record(
        audit.SNAPSHOT_CHANGED,
        username=username,
        client=client_host(request),
        action="create",
        ok=bool(result.get("ok")),
    )
    return raise_for_admin_result(result)


def _known_mount(mount: str) -> str:
    """Reject a volume the snapshot service does not report."""
    value = str(mount or "/").strip() or "/"
    if value not in set(snapshots_svc.snapshot_mounts()):
        raise api_error("snapshot.bad_mount", mount=value[:80])
    return value


@router.post("/api/snapshots/delete")
def api_snapshot_delete(body: SnapshotDeleteBody, request: Request):
    username = require_admin_browser(request)
    if not body.confirm:
        raise api_error("snapshot.confirm_required")
    mount = _known_mount(body.mount)
    if body.date_token:
        result = snapshots_svc.delete_snapshot(mount, body.date_token)
        action = "delete"
    else:
        result = snapshots_svc.delete_all_snapshots(mount)
        action = "delete_all"
    audit.record(
        audit.SNAPSHOT_CHANGED,
        username=username,
        client=client_host(request),
        action=action,
        mount=mount,
        ok=bool(result.get("ok")),
    )
    return raise_service_error(result, {"bad_token": "snapshot.bad_token"})


@router.post("/api/snapshots/thin")
def api_snapshot_thin(body: SnapshotThinBody, request: Request):
    username = require_admin_browser(request)
    mount = _known_mount(body.mount)
    result = snapshots_svc.thin_snapshots(mount, body.urgency)
    audit.record(
        audit.SNAPSHOT_CHANGED,
        username=username,
        client=client_host(request),
        action="thin",
        mount=mount,
        urgency=body.urgency,
        ok=bool(result.get("ok")),
    )
    return raise_service_error(result, {"bad_urgency": "snapshot.bad_urgency"})


@router.post("/api/timemachine/action")
def api_time_machine_action(body: TimeMachineActionBody, request: Request):
    username = require_admin_browser(request)
    result = snapshots_svc.time_machine_action(body.action)
    audit.record(
        audit.SNAPSHOT_CHANGED,
        username=username,
        client=client_host(request),
        action=f"tm_{body.action}",
        ok=bool(result.get("ok")),
    )
    return raise_service_error(result, {"bad_action": "snapshot.bad_action"})


# ── SMART self-tests ─────────────────────────────────────────────────────────

class SmartTestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device: str
    kind: str = "short"


class SmartAbortBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device: str


class SmartScheduleBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    interval: str = "off"
    kind: str = "short"
    devices: list[str] = Field(default_factory=list)


@router.get("/api/smart")
def api_smart(force: bool = False):
    return smart_test_svc.overview(force=force)


@router.get("/api/smart/history")
def api_smart_history(limit: int = 100):
    return {"history": smart_test_svc.history(limit)}


_SMART_ERRORS = {
    "bad_device": "smart.bad_device",
    "bad_kind": "smart.bad_kind",
    "unsupported": "smart.unsupported",
    "kind_unsupported": "smart.kind_unsupported",
}


@router.post("/api/smart/test")
def api_smart_test(body: SmartTestBody, request: Request):
    username = require_admin_browser(request)
    result = smart_test_svc.start_test(body.device, body.kind)
    audit.record(
        audit.SMART_TEST_STARTED,
        username=username,
        client=client_host(request),
        device=body.device,
        kind=body.kind,
        ok=bool(result.get("ok")),
    )
    return raise_service_error(result, _SMART_ERRORS)


@router.post("/api/smart/abort")
def api_smart_abort(body: SmartAbortBody, request: Request):
    require_admin_browser(request)
    return raise_service_error(smart_test_svc.abort_test(body.device), _SMART_ERRORS)


@router.put("/api/smart/schedule")
def api_smart_schedule(body: SmartScheduleBody, request: Request):
    require_admin_browser(request)
    result = smart_test_svc.set_schedule(
        interval=body.interval, kind=body.kind, devices=body.devices
    )
    return raise_service_error(
        result, {"bad_interval": "smart.bad_interval", "bad_kind": "smart.bad_kind"}
    )


# ── usage explorer ───────────────────────────────────────────────────────────

class SpotlightBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    volume: str
    enabled: StrictBool


@router.get("/api/storage/usage")
def api_storage_usage():
    return usage_svc.overview()


@router.get("/api/storage/usage/tree")
def api_storage_usage_tree(path: str = "", root_id: str = ""):
    return usage_svc.tree(path or None, root_id or None)


@router.get("/api/storage/usage/largest")
def api_storage_usage_largest(path: str = "", root_id: str = "", limit: int = 50):
    return usage_svc.largest_files(path or None, root_id or None, limit)


@router.get("/api/storage/usage/duplicates")
def api_storage_usage_duplicates(path: str = "", root_id: str = "", min_mb: float = 1.0):
    return usage_svc.duplicates(path or None, root_id or None, min_mb)


@router.post("/api/storage/spotlight")
def api_storage_spotlight(body: SpotlightBody, request: Request):
    username = require_admin_browser(request)
    result = usage_svc.set_spotlight(body.volume, body.enabled)
    audit.record(
        audit.SPOTLIGHT_CHANGED,
        username=username,
        client=client_host(request),
        volume=body.volume,
        enabled=body.enabled,
        ok=bool(result.get("ok")),
    )
    return raise_service_error(result, {"bad_volume": "usage.bad_volume"})


@router.get("/api/nfs/exports/preview", response_class=PlainTextResponse)
def api_nfs_preview():
    """The exact ``/etc/exports`` body a save would install, for review first."""
    entries = nfs_svc.read_exports()
    lines = []
    if isinstance(entries, list):
        for e in entries:
            if not isinstance(e, dict):
                continue
            raw = _utf8_text(e.get("raw"))
            if raw:
                lines.append(raw)
    return PlainTextResponse("\n".join(lines) + ("\n" if lines else ""))
