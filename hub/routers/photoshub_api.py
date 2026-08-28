"""PhotosHub API — family photo pipeline management (admin-only via whitelist)."""
from __future__ import annotations

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)

from typing import Optional

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from hub import audit, photoshub_svc
from hub.auth import request_client_id, request_username
from hub.errors import api_error, exc_detail

router = APIRouter(tags=["photoshub"])


class ActionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: str = Field(..., max_length=40)


class IdsBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ids: list[str] = Field(default_factory=list, max_length=200)


class PersonPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Optional[str] = Field(None, max_length=40)
    birthday: Optional[str] = Field(None, max_length=10)


class PeoplePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    yuanbao: Optional[PersonPatch] = None
    erbao: Optional[PersonPatch] = None


class AlbumsPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pending_delete: Optional[str] = Field(None, max_length=80)
    yuanbao: Optional[str] = Field(None, max_length=80)
    erbao: Optional[str] = Field(None, max_length=80)


class ImmichPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    base_url: Optional[str] = Field(None, max_length=200)
    public_url: Optional[str] = Field(None, max_length=200)


class PanelPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: Optional[str] = Field(None, max_length=200)


class ConfigPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    people: Optional[PeoplePatch] = None
    albums: Optional[AlbumsPatch] = None
    immich: Optional[ImmichPatch] = None
    panel: Optional[PanelPatch] = None


@router.get("/api/photoshub/status")
def get_status():
    try:
        return photoshub_svc.status()
    except HTTPException:
        raise
    except _CONTROL_FLOW:
        raise
    except BaseException as e:
        raise api_error("photoshub.status_failed", detail=exc_detail(e))


@router.get("/api/photoshub/pending-delete")
def pending_delete(limit: int = 60):
    try:
        cap = max(1, min(int(limit), 200))
    except (TypeError, ValueError, OverflowError):
        cap = 60
    try:
        return photoshub_svc.pending_delete_assets(limit=cap)
    except HTTPException:
        raise
    except _CONTROL_FLOW:
        raise
    except BaseException as e:
        raise api_error("photoshub.pending_failed", detail=exc_detail(e))


@router.get("/api/photoshub/pending-delete/thumb/{asset_id}")
def pending_delete_thumb(asset_id: str):
    """One Immich preview, proxied so the browser never holds the API key.

    Deciding which photos to delete from filenames alone is guesswork, so the
    review grid needs the picture — but Immich wants ``x-api-key`` on every
    request, and handing that to the SPA would give any open tab the whole
    library.  The panel session authorises the request and this fetches it.
    """
    try:
        raw, ctype = photoshub_svc.asset_thumbnail(asset_id)
    except HTTPException:
        raise
    except _CONTROL_FLOW:
        raise
    except BaseException as e:
        raise api_error("photoshub.thumb_failed", detail=exc_detail(e, 160))
    return Response(
        content=raw,
        media_type=ctype,
        headers={
            # A preview for a given asset id does not change, and the grid
            # re-renders on every status poll; without this each poll refetches
            # every tile through this process.
            "Cache-Control": "private, max-age=300",
            # These bytes come from another service.  The content type is on an
            # allow-list already; this is the second lock, for the case where an
            # operator opens the URL directly instead of viewing it in an <img>.
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.post("/api/photoshub/pending-delete/remove")
def pending_remove(body: IdsBody, request: Request):
    ids = [i for i in body.ids if i]
    if not ids:
        raise api_error("photoshub.bad_ids")
    try:
        result = photoshub_svc.remove_from_pending(ids)
    except HTTPException:
        raise
    except _CONTROL_FLOW:
        raise
    except BaseException as e:
        raise api_error("photoshub.remove_failed", detail=exc_detail(e))
    audit.record(
        "photoshub.pending_remove",
        username=request_username(request) or "unknown",
        client=request_client_id(request),
        detail=f"removed={result.get('removed')}",
    )
    return result


@router.post("/api/photoshub/action")
def run_action(body: ActionBody, request: Request):
    action = body.action.strip()
    if action not in photoshub_svc.ALLOWED_ACTIONS:
        raise api_error("photoshub.bad_action", action=action)
    # Dangerous unlocks stay explicit
    try:
        result = photoshub_svc.run_action(action)
    except HTTPException:
        raise
    except _CONTROL_FLOW:
        raise
    except BaseException as e:
        raise api_error("photoshub.action_failed", detail=exc_detail(e))
    audit.record(
        "photoshub.action",
        username=request_username(request) or "unknown",
        client=request_client_id(request),
        detail=f"action={action} ok={result.get('ok')}",
    )
    return result


@router.get("/api/photoshub/config")
def get_config():
    try:
        return photoshub_svc.public_config()
    except HTTPException:
        raise
    except _CONTROL_FLOW:
        raise
    except BaseException as e:
        raise api_error("photoshub.config_failed", detail=exc_detail(e))


@router.patch("/api/photoshub/config")
def patch_config(body: ConfigPatch, request: Request):
    patch = body.model_dump(exclude_unset=True)
    try:
        result = photoshub_svc.update_config(patch)
    except HTTPException:
        raise
    except _CONTROL_FLOW:
        raise
    except BaseException as e:
        raise api_error("photoshub.config_failed", detail=exc_detail(e))
    audit.record(
        "photoshub.config",
        username=request_username(request) or "unknown",
        client=request_client_id(request),
        detail="updated=" + ",".join(sorted(patch)) if patch else "noop",
    )
    return result


@router.get("/api/photoshub/logs/{name}")
def logs(name: str, lines: int = 40):
    if name not in photoshub_svc.ALLOWED_LOGS:
        raise api_error("photoshub.bad_log")
    return photoshub_svc.recent_logs(name, lines=max(10, min(lines, 200)))
