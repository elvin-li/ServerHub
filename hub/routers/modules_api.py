from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Request
from pydantic import BaseModel

from hub import audit, auth, bookmarks_svc, brew_svc, compose_svc, modules, nginx_svc, sensors_svc
from hub.adaptive import scan_new_compose_projects

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)

def _isinst(value, types) -> bool:
    """``isinstance`` that a leftover ``__class__`` bomb cannot 500 through.

    Fail-closed: a raising ``__class__`` property cannot 500 a JSON route.
    """
    try:
        return isinstance(value, types)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


router = APIRouter(tags=["modules"])


def _operator(request: Request | None) -> dict:
    """Operator fields for an audit line.  FastAPI always injects `request`;
    the None guard only keeps direct in-process calls (tests, tooling) working."""
    return {
        "username": auth.request_username(request) if request is not None else "",
        "client": auth.request_client_id(request),
    }


@router.get("/api/modules")
def list_modules():
    return {
        "modules": modules.list_modules(),
        "by_category": modules.modules_by_category(),
    }


# ---- brew ----
class BrewAction(BaseModel):
    action: str


@router.get("/api/brew/services")
def brew_services():
    return {"services": brew_svc.list_services()}


@router.post("/api/brew/services/{name}/action")
def brew_action(name: str, body: BrewAction, request: Request = None):
    result = brew_svc.service_action(name, body.action)
    # Same event as the Services page's lifecycle actions: a brew service is
    # a workload on this host like any other.
    audit.record(
        audit.SERVICE_ACTION,
        **_operator(request),
        target=f"brew:{name}",
        action=body.action,
    )
    return result


# ---- compose editor ----
class ComposeSave(BaseModel):
    model_config = {"extra": "allow"}
    content: str
    # Do not name field `validate` — shadows BaseModel.validate (Pydantic warning)
    check: bool = True


class ComposeValidate(BaseModel):
    content: str
    cwd: Optional[str] = None


class ComposeCreate(BaseModel):
    id: str
    name: Optional[str] = None
    content: str


@router.get("/api/compose/{stack_id}")
def compose_get(stack_id: str):
    return compose_svc.get_compose(stack_id)


@router.put("/api/compose/{stack_id}")
def compose_put(stack_id: str, body: ComposeSave, request: Request = None):
    # accept legacy {validate: true} via model_extra if clients still send it
    do_check = body.check
    extra = getattr(body, "model_extra", None)
    if not _isinst(extra, dict):
        extra = {}
    if "validate" in extra:
        do_check = bool(extra.get("validate"))
    result = compose_svc.save_compose(stack_id, body.content, validate=do_check)
    # The YAML itself is not recorded — it can embed credentials — but a
    # compose save is arbitrary container config awaiting the next stack run,
    # so who wrote it and how much is.
    audit.record(
        audit.COMPOSE_CHANGED,
        **_operator(request),
        action="save",
        stack=stack_id,
        bytes=len(body.content or ""),
    )
    return result


@router.post("/api/compose/{stack_id}/validate")
def compose_validate_stack(stack_id: str):
    return compose_svc.validate_stack(stack_id)


@router.post("/api/compose/validate")
def compose_validate_text(body: ComposeValidate):
    return compose_svc.validate_compose_text(body.content, cwd=body.cwd)


@router.post("/api/compose")
def compose_create(body: ComposeCreate, request: Request = None):
    result = compose_svc.create_stack(body.id, body.name, body.content)
    audit.record(
        audit.COMPOSE_CHANGED,
        **_operator(request),
        action="create",
        stack=body.id,
        bytes=len(body.content or ""),
    )
    return result


# ---- bookmarks ----
@router.get("/api/bookmarks")
def bookmarks(force: bool = False):
    return bookmarks_svc.list_bookmarks(force=force)


# ---- sensors ----
@router.get("/api/system/sensors")
def sensors(force: bool = False, light: bool = False):
    # Dashboard's 20s light tick only needs CPU/mem/load.  The 90s heavy
    # tick and Refresh request full collect (``top`` / ps / netstat) so
    # RX/TX and Top CPU stay populated in low mode.
    from hub.resource_mode import is_high
    if light and not force and not is_high():
        hit = sensors_svc.peek_sensors()
        if hit is not None:
            return hit
        return sensors_svc.collect_light()
    return sensors_svc.collect_sensors(force=force)


# ---- system nginx ----
@router.get("/api/nginx")
def nginx_overview():
    return nginx_svc.overview()


@router.post("/api/nginx/test")
def nginx_test():
    return nginx_svc.test_config()


@router.post("/api/nginx/reload")
def nginx_reload(request: Request = None):
    result = nginx_svc.reload_nginx()
    audit.record(audit.NGINX_RELOADED, **_operator(request))
    return result


@router.get("/api/adaptive/compose-scan")
def adaptive_compose_scan():
    return {"projects": scan_new_compose_projects()}
