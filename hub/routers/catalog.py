from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from hub import apps_manage_svc, auth, autostart_svc, catalog, catalog_remote, service_credentials

from ..errors import api_error

router = APIRouter(tags=["catalog"])


def _require_browser_session(request: Request) -> None:
    # Credential APIs are intentionally stricter than the local menu-bar
    # exemption used by the rest of the protected API.
    if not auth.browser_authenticated(request):
        raise api_error("catalog.browser_session_required")


def _require_admin_browser(request: Request) -> str:
    """Changing the catalog source decides what software the panel offers to
    install, so it is admin + browser-session only (same bar as shares)."""
    if not auth.browser_authenticated(request):
        raise api_error("catalog_remote.browser_session_required")
    username = auth.request_username(request)
    if not auth.is_admin(username):
        raise api_error("catalog_remote.admin_required")
    return username


@router.get("/api/catalog")
def list_catalog():
    """App store overview: templates + categories."""
    return catalog.catalog_overview()


@router.get("/api/catalog/templates")
def list_templates_only():
    return {"templates": catalog.list_templates()}


# ── remote catalog source (fixed paths registered before /{template_id}/…) ───

class RemoteSourceBody(BaseModel):
    url: str = Field(default="", max_length=500)


class RemoteRestoreBody(BaseModel):
    id: str = Field(min_length=1, max_length=64)


@router.get("/api/catalog/remote")
def catalog_remote_status():
    return catalog_remote.status()


@router.put("/api/catalog/remote")
def catalog_remote_configure(body: RemoteSourceBody, request: Request):
    username = _require_admin_browser(request)
    return catalog_remote.set_source_url(body.url, operator=username)


@router.post("/api/catalog/remote/check")
def catalog_remote_check(request: Request):
    username = _require_admin_browser(request)
    return catalog_remote.check_updates(operator=username)


@router.post("/api/catalog/remote/restore")
def catalog_remote_restore(body: RemoteRestoreBody, request: Request):
    username = _require_admin_browser(request)
    return catalog_remote.restore_builtin(body.id, operator=username)


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
    message = "Credential saved securely to the macOS Keychain"
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
def apps_managed_action(body: ManagedActionBody, request: Request):
    """Dispatch one Apps-page action.

    ``uninstall`` on a launch agent lands in the same
    ``services_uninstall_svc.uninstall()`` as ``POST /api/services/{sid}/
    uninstall``, which refuses anything but a real browser session -- it
    changes what starts at login and can delete a program tree.  Reaching it
    through this route must not be the cheaper way in: an API key is
    deliberately not allowed on that surface, whatever its role.
    """
    if body.action.strip().lower() == "uninstall":
        sid = body.id.partition(":")[2] or body.id
        if not auth.browser_authenticated(request):
            raise api_error("services.uninstall_browser_session_required", id=sid)
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
