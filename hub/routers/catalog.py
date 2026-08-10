from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from hub import apps_manage_svc, auth, autostart_svc, catalog, service_credentials

router = APIRouter(tags=["catalog"])


def _require_browser_session(request: Request) -> None:
    # Credential APIs are intentionally stricter than the local menu-bar
    # exemption used by the rest of the protected API.
    if not auth.browser_authenticated(request):
        raise HTTPException(401, "请先在浏览器登录后管理服务凭据")


@router.get("/api/catalog")
def list_catalog():
    """App store overview: templates + categories."""
    return catalog.catalog_overview()


@router.get("/api/catalog/templates")
def list_templates_only():
    return {"templates": catalog.list_templates()}


class InstallBody(BaseModel):
    confirm: bool = True
    variables: Optional[dict[str, Any]] = None


class UninstallBody(BaseModel):
    confirm: bool = False
    remove_data: bool = True  # docker: rmtree + volumes; native brew: optional --zap


@router.post("/api/catalog/{template_id}/install")
def install(template_id: str, body: InstallBody):
    return catalog.install_template(template_id, body.variables or {})


@router.post("/api/catalog/{template_id}/uninstall")
def uninstall(template_id: str, body: UninstallBody):
    return catalog.uninstall_template(
        template_id,
        remove_data=body.remove_data,
        confirm=body.confirm,
    )


# ─── Unified managed apps (Docker / native / VM)
# Use query `id=` — path params break on "docker:name" / "native:…" ids.

@router.get("/api/apps/managed")
def apps_managed(force: bool = False):
    return apps_manage_svc.inventory(force=force)


@router.get("/api/apps/managed/detail")
def apps_managed_detail(id: str):
    return apps_manage_svc.detail(id)


class CredentialSaveBody(BaseModel):
    service_id: str = Field(min_length=1, max_length=160)
    display_name: str = Field(default="", max_length=120)
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=8, max_length=512)
    url: str = Field(default="", max_length=500)
    notes: str = Field(default="", max_length=1000)
    apply_to_service: bool = False


@router.get("/api/apps/credentials")
def app_credential(request: Request, id: str):
    _require_browser_session(request)
    return service_credentials.get(id)


@router.post("/api/apps/credentials")
def save_app_credential(body: CredentialSaveBody, request: Request):
    _require_browser_session(request)
    adapter = service_credentials.adapter_for(body.service_id)
    applied = False
    message = "凭据已安全保存到 macOS 钥匙串"
    if body.apply_to_service:
        result = service_credentials.apply(body.service_id, body.username, body.password)
        applied = bool(result.get("ok"))
        message = result.get("message") or message
    item = service_credentials.store(
        body.service_id,
        display_name=body.display_name,
        username=body.username,
        password=body.password,
        url=body.url,
        notes=body.notes,
        adapter=adapter,
        applied=applied,
    )
    return {"ok": True, "message": message, "credential": item}


@router.delete("/api/apps/credentials")
def delete_app_credential(request: Request, id: str):
    _require_browser_session(request)
    return service_credentials.delete(id)


@router.get("/api/apps/managed/logs")
def apps_managed_logs(id: str, lines: int = 120):
    return apps_manage_svc.logs(id, lines=lines)


class ManagedActionBody(BaseModel):
    id: str
    action: str
    remove_data: bool = False


@router.post("/api/apps/managed/action")
def apps_managed_action(body: ManagedActionBody):
    return apps_manage_svc.action(
        body.id,
        body.action,
        remove_data=body.remove_data,
    )


# ─── Boot / login autostart console ──────────────────────────────────────────

@router.get("/api/apps/autostart")
def apps_autostart_list(force: bool = False):
    return autostart_svc.overview(force=force)


class AutostartBody(BaseModel):
    id: str
    enabled: bool
    policy: Optional[str] = None  # docker: unless-stopped|always|on-failure|no


@router.post("/api/apps/autostart")
def apps_autostart_set(body: AutostartBody):
    return autostart_svc.set_autostart(body.id, body.enabled, policy=body.policy)


class DockerPolicyBody(BaseModel):
    name: str
    policy: str  # no|always|unless-stopped|on-failure


@router.post("/api/apps/autostart/docker-policy")
def apps_autostart_docker_policy(body: DockerPolicyBody):
    return autostart_svc.set_docker_policy(body.name, body.policy)


@router.post("/api/apps/autostart/run-now")
def apps_autostart_run_now():
    return autostart_svc.run_autostart_now()
