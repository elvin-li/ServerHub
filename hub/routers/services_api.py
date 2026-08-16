"""Services page management APIs."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from hub import actions, auth, services_manage_svc, services_uninstall_svc
from hub.errors import api_error
from hub.status import invalidate_status, member_service_summary

router = APIRouter(tags=["services"])


class OverrideBody(BaseModel):
    name: Optional[str] = None
    group: Optional[str] = None
    url: Optional[str] = None
    port: Optional[int] = None
    hide: Optional[bool] = None


class HideBody(BaseModel):
    hide: bool = True


class AdoptBody(BaseModel):
    id: Optional[str] = None
    name: Optional[str] = None
    group: Optional[str] = None
    url: Optional[str] = None
    ports: Optional[list[int]] = None
    start: Optional[str] = None
    stop: Optional[str] = None
    remember: Optional[bool] = None


class ScriptBody(BaseModel):
    name: Optional[str] = None
    group: Optional[str] = None
    url: Optional[str] = None
    ports: Optional[list[int]] = None
    start: Optional[str] = None
    stop: Optional[str] = None


class SignatureBody(BaseModel):
    slug: str
    name: Optional[str] = None
    category: Optional[str] = None
    procs: Optional[list[str]] = None
    ports: Optional[list[int]] = None
    http: Optional[bool] = None
    brew: Optional[str] = None


class BulkActionBody(BaseModel):
    ids: list[str] = Field(default_factory=list)
    action: str


def _member_username(request: Request) -> str:
    username = auth.request_username(request)
    return "" if auth.is_admin(username) else username


def _require_resource(request: Request, sid: str) -> None:
    username = _member_username(request)
    if username and not auth.may_use_resource(username, sid):
        raise api_error("auth.admin_required")


@router.get("/api/services/signatures")
def services_list_signatures(request: Request):
    """Operator recognition rules written by Adopt → Remember or by hand."""
    if _member_username(request):
        raise api_error("auth.admin_required")
    return services_manage_svc.list_signatures()


@router.put("/api/services/signatures")
def services_upsert_signature(request: Request, body: SignatureBody):
    if _member_username(request):
        raise api_error("auth.admin_required")
    return services_manage_svc.upsert_signature(body.model_dump())


@router.delete("/api/services/signatures/{slug}")
def services_forget_signature(request: Request, slug: str):
    if _member_username(request):
        raise api_error("auth.admin_required")
    return services_manage_svc.forget_signature(slug)


@router.get("/api/services")
def services_list(request: Request, force: bool = False):
    """Status with enriched management actions, filtered for member accounts."""
    member = _member_username(request)
    # A member gets the cached snapshot regardless of ?force=; only an admin
    # may force the expensive docker/launchctl rebuild (see _visible_status).
    result = services_manage_svc.list_manageable(force=force and not member)
    if member:
        from hub.status import filter_status_for_resources

        result = filter_status_for_resources(result, auth.allowed_resources(member))
    return result


@router.get("/api/services/{sid}/detail")
def services_detail(sid: str, request: Request):
    _require_resource(request, sid)
    result = services_manage_svc.service_detail(sid)
    if _member_username(request):
        result = {
            **member_service_summary(result),
            "can_logs": False,
            "can_hide": False,
            "can_edit": False,
        }
    return result


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


@router.post("/api/services/{sid}/adopt")
def services_adopt(sid: str, request: Request, body: AdoptBody = AdoptBody()):
    """Promote an auto-discovered listener into a managed services.yaml entry.

    Writes configuration, so member accounts are refused outright rather than
    resource-checked: adoption changes what everyone's Services page shows.
    """
    if _member_username(request):
        raise api_error("auth.admin_required")
    return services_manage_svc.adopt_service(sid, body.model_dump(exclude_unset=True))


@router.put("/api/services/{sid}/script")
def services_update_script(sid: str, request: Request, body: ScriptBody):
    """Rewrite a managed scripts[] entry (adopted or hand-written)."""
    if _member_username(request):
        raise api_error("auth.admin_required")
    return services_manage_svc.update_script(sid, body.model_dump(exclude_unset=True))


@router.delete("/api/services/{sid}/script")
def services_forget_script(sid: str, request: Request):
    """Drop a managed scripts[] entry so a live listener can be rediscovered."""
    if _member_username(request):
        raise api_error("auth.admin_required")
    return services_manage_svc.forget_script(sid)


@router.get("/api/services/{sid}/uninstall/preview")
def services_uninstall_preview(sid: str):
    """What an uninstall would remove and keep, without changing anything.

    The UI calls this before showing the confirmation dialog so the wording
    states the actual blast radius instead of a generic warning.
    """
    return services_uninstall_svc.preview(sid)


class UninstallBody(BaseModel):
    remove_data: bool = False


@router.post("/api/services/{sid}/uninstall")
def services_uninstall(sid: str, request: Request, body: Optional[UninstallBody] = None):
    """Unregister a launch agent and archive its plist.

    Stricter than ordinary service actions: this changes what starts at login,
    so the loopback menu-bar token is not accepted and the caller must hold a
    real browser session.  ``remove_data`` deletes the program tree only when
    it sits strictly inside ~/Services.
    """
    if not auth.browser_authenticated(request):
        raise api_error("services.uninstall_browser_session_required", id=sid)
    return services_uninstall_svc.uninstall(
        sid, remove_data=bool(body and body.remove_data),
    )


@router.post("/api/services/bulk-action")
def services_bulk(body: BulkActionBody):
    if body.action not in ("start", "stop", "restart", "run"):
        raise api_error("services.bad_action")
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
