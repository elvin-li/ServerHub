"""Services page management APIs."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from hub import actions, auth, services_manage_svc, services_uninstall_svc
from hub.errors import api_error
from hub.status import invalidate_status

router = APIRouter(tags=["services"])


class OverrideBody(BaseModel):
    name: Optional[str] = None
    group: Optional[str] = None
    url: Optional[str] = None
    port: Optional[int] = None
    hide: Optional[bool] = None


class HideBody(BaseModel):
    hide: bool = True


class BulkActionBody(BaseModel):
    ids: list[str] = Field(default_factory=list)
    action: str


@router.get("/api/services")
def services_list(force: bool = False):
    """Status with enriched management actions."""
    return services_manage_svc.list_manageable(force=force)


@router.get("/api/services/{sid}/detail")
def services_detail(sid: str):
    return services_manage_svc.service_detail(sid)


@router.get("/api/services/{sid}/logs")
def services_logs(sid: str, lines: int = 150):
    return services_manage_svc.service_logs(sid, lines=lines)


@router.put("/api/services/{sid}/override")
def services_override(sid: str, body: OverrideBody):
    patch = body.model_dump(exclude_unset=True)
    return services_manage_svc.update_override(sid, patch)


@router.post("/api/services/{sid}/hide")
def services_hide(sid: str, body: HideBody = HideBody()):
    return services_manage_svc.hide_service(sid, hide=body.hide)


@router.get("/api/services/{sid}/uninstall/preview")
def services_uninstall_preview(sid: str):
    """What an uninstall would remove and keep, without changing anything.

    The UI calls this before showing the confirmation dialog so the wording
    states the actual blast radius instead of a generic warning.
    """
    return services_uninstall_svc.preview(sid)


@router.post("/api/services/{sid}/uninstall")
def services_uninstall(sid: str, request: Request):
    """Unregister a launch agent and archive its plist.

    Stricter than ordinary service actions: this changes what starts at login,
    so the loopback menu-bar token is not accepted and the caller must hold a
    real browser session.
    """
    if not auth.browser_authenticated(request):
        raise api_error("services.uninstall_browser_session_required", id=sid)
    return services_uninstall_svc.uninstall(sid)


@router.post("/api/services/bulk-action")
def services_bulk(body: BulkActionBody):
    if body.action not in ("start", "stop", "restart", "run"):
        raise HTTPException(400, "action must be start|stop|restart|run")
    results = []
    for sid in body.ids or []:
        try:
            rc, out, err = actions.run_action(sid, body.action)
            results.append({
                "id": sid,
                "ok": rc == 0,
                "message": (out if rc == 0 else (err or out or f"exit {rc}"))[:300],
            })
        except Exception as e:
            results.append({"id": sid, "ok": False, "message": str(e)[:300]})
    invalidate_status()
    ok_n = sum(1 for r in results if r["ok"])
    return {
        "ok": ok_n == len(results) and bool(results),
        "ok_count": ok_n,
        "fail_count": len(results) - ok_n,
        "results": results,
    }
