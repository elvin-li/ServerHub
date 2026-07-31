from __future__ import annotations

from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel

from hub import bookmarks_svc, brew_svc, compose_svc, modules, nginx_svc, sensors_svc
from hub.adaptive import scan_new_compose_projects

router = APIRouter(tags=["modules"])


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
def brew_action(name: str, body: BrewAction):
    return brew_svc.service_action(name, body.action)


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
def compose_put(stack_id: str, body: ComposeSave):
    # accept legacy {validate: true} via model_extra if clients still send it
    do_check = body.check
    extra = getattr(body, "model_extra", None) or {}
    if "validate" in extra:
        do_check = bool(extra["validate"])
    return compose_svc.save_compose(stack_id, body.content, validate=do_check)


@router.post("/api/compose/{stack_id}/validate")
def compose_validate_stack(stack_id: str):
    return compose_svc.validate_stack(stack_id)


@router.post("/api/compose/validate")
def compose_validate_text(body: ComposeValidate):
    return compose_svc.validate_compose_text(body.content, cwd=body.cwd)


@router.post("/api/compose")
def compose_create(body: ComposeCreate):
    return compose_svc.create_stack(body.id, body.name, body.content)


# ---- bookmarks ----
@router.get("/api/bookmarks")
def bookmarks(force: bool = False):
    return bookmarks_svc.list_bookmarks(force=force)


# ---- sensors ----
@router.get("/api/system/sensors")
def sensors(force: bool = False):
    return sensors_svc.collect_sensors(force=force)


# ---- system nginx ----
@router.get("/api/nginx")
def nginx_overview():
    return nginx_svc.overview()


@router.post("/api/nginx/test")
def nginx_test():
    return nginx_svc.test_config()


@router.post("/api/nginx/reload")
def nginx_reload():
    return nginx_svc.reload_nginx()


@router.get("/api/adaptive/compose-scan")
def adaptive_compose_scan():
    return {"projects": scan_new_compose_projects()}
