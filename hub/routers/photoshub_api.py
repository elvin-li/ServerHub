"""PhotosHub API — family photo pipeline management (admin-only via whitelist)."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from hub import audit, photoshub_svc
from hub.auth import request_username
from hub.errors import api_error

router = APIRouter(tags=["photoshub"])


class ActionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: str = Field(..., max_length=40)


class IdsBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ids: list[str] = Field(default_factory=list, max_length=200)


@router.get("/api/photoshub/status")
def get_status():
    try:
        return photoshub_svc.status()
    except HTTPException:
        raise
    except Exception as e:
        raise api_error("photoshub.status_failed", detail=str(e)[:200])


@router.get("/api/photoshub/pending-delete")
def pending_delete(limit: int = 60):
    try:
        return photoshub_svc.pending_delete_assets(limit=max(1, min(limit, 200)))
    except HTTPException:
        raise
    except Exception as e:
        raise api_error("photoshub.pending_failed", detail=str(e)[:200])


@router.post("/api/photoshub/pending-delete/remove")
def pending_remove(body: IdsBody, request: Request):
    ids = [i for i in body.ids if i]
    if not ids:
        raise api_error("photoshub.bad_ids")
    try:
        result = photoshub_svc.remove_from_pending(ids)
    except HTTPException:
        raise
    except Exception as e:
        raise api_error("photoshub.remove_failed", detail=str(e)[:200])
    audit.record(
        "photoshub.pending_remove",
        user=request_username(request) or "unknown",
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
    except Exception as e:
        raise api_error("photoshub.action_failed", detail=str(e)[:200])
    audit.record(
        "photoshub.action",
        user=request_username(request) or "unknown",
        detail=f"action={action} ok={result.get('ok')}",
    )
    return result


@router.get("/api/photoshub/logs/{name}")
def logs(name: str, lines: int = 40):
    if name not in {"bridge", "delete", "cleanup", "external", "errors"}:
        raise api_error("photoshub.bad_log")
    return photoshub_svc.recent_logs(name, lines=max(10, min(lines, 200)))
