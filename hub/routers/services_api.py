"""Services page management APIs."""
from __future__ import annotations

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)

from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from hub import actions, audit, auth, services_manage_svc, services_uninstall_svc
from hub.errors import api_error
from hub.status import invalidate_status, member_service_summary


def _isinst(value, types) -> bool:
    """isinstance that a leftover raising ``__class__`` cannot 500 through."""
    try:
        return isinstance(value, types)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _as_text(value) -> str:
    """``sh`` leftovers arrive as int/None/bytes; leftover ``\\ud800`` used
    to 500 POST /api/services/bulk-action under Starlette's UTF-8 encode.
    """
    if _isinst(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    elif value is None:
        return ""
    else:
        try:
            value = str(value)
        except RecursionError:
            try:
                return type(value).__name__
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return ""
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return ""
    return value.encode("utf-8", "replace").decode("utf-8")


router = APIRouter(tags=["services"])


def _audit_config(request: Request | None, action: str, **fields) -> None:
    """One audit line for a services.yaml configuration change.

    The script entries matter most: a saved start/stop script is arbitrary
    code the next lifecycle action runs.  Called after the service call
    returned, so a rejected change leaves no record.  FastAPI always injects
    `request`; the None guard only keeps direct in-process calls working."""
    audit.record(
        audit.SERVICE_CONFIG_CHANGED,
        username=auth.request_username(request) if request is not None else "",
        client=auth.request_client_id(request),
        action=action,
        **fields,
    )


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
    result = services_manage_svc.upsert_signature(body.model_dump())
    _audit_config(request, "signature_saved")
    return result


@router.delete("/api/services/signatures/{slug}")
def services_forget_signature(request: Request, slug: str):
    if _member_username(request):
        raise api_error("auth.admin_required")
    result = services_manage_svc.forget_signature(slug)
    _audit_config(request, "signature_deleted", target=slug)
    return result


@router.get("/api/services/group-rules")
def services_list_group_rules(request: Request):
    """Services-page grouping rules (yaml list, or code seeds if unset)."""
    if _member_username(request):
        raise api_error("auth.admin_required")
    return services_manage_svc.list_group_rules()


@router.put("/api/services/group-rules")
def services_save_group_rules(request: Request, body: dict[str, Any] | None = None):
    """Upsert one rule, or replace the list when ``rules`` is present."""
    if _member_username(request):
        raise api_error("auth.admin_required")
    result = services_manage_svc.save_group_rules(body if _isinst(body, dict) else {})
    _audit_config(request, "group_rules_saved")
    return result


@router.delete("/api/services/group-rules/{rule_id}")
def services_delete_group_rule(request: Request, rule_id: str):
    if _member_username(request):
        raise api_error("auth.admin_required")
    result = services_manage_svc.delete_group_rule(rule_id)
    _audit_config(request, "group_rule_deleted", target=rule_id)
    return result


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
def services_override(sid: str, body: OverrideBody, request: Request = None):
    patch = body.model_dump(exclude_unset=True)
    result = services_manage_svc.update_override(sid, patch)
    _audit_config(request, "override_saved", target=sid,
                  fields=",".join(sorted(patch.keys())))
    return result


@router.post("/api/services/{sid}/hide")
def services_hide(sid: str, body: HideBody = HideBody(), request: Request = None):
    result = services_manage_svc.hide_service(sid, hide=body.hide)
    _audit_config(request, "hide" if body.hide else "unhide", target=sid)
    return result


@router.post("/api/services/{sid}/adopt")
def services_adopt(sid: str, request: Request, body: AdoptBody = AdoptBody()):
    """Promote an auto-discovered listener into a managed services.yaml entry.

    Writes configuration, so member accounts are refused outright rather than
    resource-checked: adoption changes what everyone's Services page shows.
    """
    if _member_username(request):
        raise api_error("auth.admin_required")
    result = services_manage_svc.adopt_service(sid, body.model_dump(exclude_unset=True))
    _audit_config(request, "adopt", target=sid)
    return result


@router.put("/api/services/{sid}/script")
def services_update_script(sid: str, request: Request, body: ScriptBody):
    """Rewrite a managed scripts[] entry (adopted or hand-written)."""
    if _member_username(request):
        raise api_error("auth.admin_required")
    patch = body.model_dump(exclude_unset=True)
    result = services_manage_svc.update_script(sid, patch)
    # The script text itself is not recorded — it can embed credentials —
    # but a saved script is arbitrary code the next lifecycle action runs,
    # so who changed which fields is.
    _audit_config(request, "script_saved", target=sid,
                  fields=",".join(sorted(patch.keys())))
    return result


@router.delete("/api/services/{sid}/script")
def services_forget_script(sid: str, request: Request):
    """Drop a managed scripts[] entry so a live listener can be rediscovered."""
    if _member_username(request):
        raise api_error("auth.admin_required")
    result = services_manage_svc.forget_script(sid)
    _audit_config(request, "script_deleted", target=sid)
    return result


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
    result = services_uninstall_svc.uninstall(
        sid, remove_data=bool(body and body.remove_data),
    )
    # uninstall() raises on an unknown or protected service, so a record here
    # means the launch agent really was unregistered.
    audit.record(
        audit.SERVICE_UNINSTALLED,
        username=auth.request_username(request),
        client=auth.request_client_id(request),
        target=sid,
        remove_data=bool(body and body.remove_data),
    )
    return result


@router.post("/api/services/bulk-action")
def services_bulk(body: BulkActionBody, request: Request = None):
    if body.action not in ("start", "stop", "restart", "run"):
        raise api_error("services.bad_action")
    results = []
    for sid in body.ids or []:
        try:
            rc, out, err = actions.run_action(sid, body.action)
            if rc == 0:
                msg = out
            else:
                msg = err or out or f"exit {rc}"
            results.append({
                "id": _as_text(sid),
                "ok": rc == 0,
                "message": _as_text(msg)[:300],
            })
        except HTTPException as e:
            detail = e.detail if _isinst(e.detail, dict) else {}
            msg = detail.get("message") if _isinst(detail, dict) else e.detail
            results.append({
                "id": _as_text(sid),
                "ok": False,
                "message": _as_text(msg)[:300],
                "code": detail.get("code") if _isinst(detail, dict) else None,
            })
        except _CONTROL_FLOW:
            raise
        except BaseException as e:
            results.append({
                "id": _as_text(sid),
                "ok": False,
                "message": _as_text(e)[:300],
            })
    invalidate_status()
    ok_n = sum(1 for r in results if r["ok"])
    # One record per request, not per id: the trail is capped and evicts
    # oldest-first, so a stop of forty services must not push forty real
    # security events out.  The ids ride along for "what exactly was hit".
    audit.record(
        audit.SERVICE_BULK_ACTION,
        # FastAPI always injects `request`; the None default only keeps
        # direct in-process calls (tests, tooling) working.
        username=auth.request_username(request) if request is not None else "",
        client=auth.request_client_id(request),
        action=body.action,
        targets=",".join(_as_text(sid) for sid in (body.ids or [])),
        ok_count=ok_n,
        fail_count=len(results) - ok_n,
    )
    return {
        "ok": ok_n == len(results) and bool(results),
        "ok_count": ok_n,
        "fail_count": len(results) - ok_n,
        "results": results,
    }
