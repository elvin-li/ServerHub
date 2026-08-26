from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from hub import apps_manage_svc, audit, auth, autostart_svc, catalog, catalog_remote, service_credentials

from ..errors import api_error


def _as_text(value) -> str:
    """Drop leftover inf / ``\\ud800`` so POST /api/apps/credentials cannot 500."""
    if isinstance(value, (bytes, bytearray)):
        # Unbound base decode: a leftover subclass ``.decode`` bomb cannot fire.
        base = bytes if isinstance(value, bytes) else bytearray
        value = base.decode(value, "utf-8", "replace")
    elif value is None:
        return ""
    elif isinstance(value, float):
        if type(value) is not float:
            try:
                # Base coercion to an exact float: a subclass ``__eq__``
                # bomb used to blow the NaN/inf probes below.
                value = float.__float__(value)
            except Exception:
                return ""
        if value != value or value in (float("inf"), float("-inf")):
            return ""
        value = str(value)
    else:
        try:
            value = str(value)
        except RecursionError:
            try:
                return type(value).__name__
            except Exception:
                return ""
        except Exception:
            return ""
    # Unbound base encode: ``str()`` of a str subclass whose ``__str__``
    # returns self keeps the subclass, so a bound ``.encode`` bomb could
    # still fire (the modules5 unbound convention).
    return str.encode(value, "utf-8", "replace").decode("utf-8")


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
    return catalog_remote.set_source_url(
        body.url, operator=username, client=auth.request_client_id(request))


@router.post("/api/catalog/remote/check")
def catalog_remote_check(request: Request):
    username = _require_admin_browser(request)
    return catalog_remote.check_updates(
        operator=username, client=auth.request_client_id(request))


@router.post("/api/catalog/remote/restore")
def catalog_remote_restore(body: RemoteRestoreBody, request: Request):
    username = _require_admin_browser(request)
    return catalog_remote.restore_builtin(
        body.id, operator=username, client=auth.request_client_id(request))


class InstallBody(BaseModel):
    confirm: bool = True
    variables: Optional[dict[str, Any]] = None


class UninstallBody(BaseModel):
    confirm: bool = False
    remove_data: bool = True  # docker: rmtree + volumes; native brew: optional --zap


@router.post("/api/catalog/{template_id}/install")
def install(template_id: str, body: InstallBody, request: Request = None):
    result = catalog.install_template(template_id, body.variables or {})
    # Template variables are deliberately not recorded: they carry the
    # passwords and API keys the template prompts for.
    audit.record(
        audit.APP_INSTALLED,
        # FastAPI always injects `request`; the None default only keeps
        # direct in-process calls (tests, tooling) working.
        username=auth.request_username(request) if request is not None else "",
        client=auth.request_client_id(request),
        template=template_id,
    )
    return result


@router.post("/api/catalog/{template_id}/uninstall")
def uninstall(template_id: str, body: UninstallBody, request: Request = None):
    result = catalog.uninstall_template(
        template_id,
        remove_data=body.remove_data,
        confirm=body.confirm,
    )
    audit.record(
        audit.APP_UNINSTALLED,
        username=auth.request_username(request) if request is not None else "",
        client=auth.request_client_id(request),
        template=template_id,
        remove_data=bool(body.remove_data),
    )
    return result


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
        if not isinstance(result, dict):
            result = {}
        applied = bool(result.get("ok"))
        text = _as_text(result.get("message"))
        if text:
            message = text
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
    # The stored account name is an audit fact; the password never reaches
    # record() (and its redaction would blank it anyway).
    audit.record(
        audit.APP_CREDENTIAL_SAVED,
        username=auth.request_username(request),
        client=auth.request_client_id(request),
        service=body.service_id,
        account=body.username,
        applied=applied,
    )
    return {"ok": True, "message": message, "credential": item}


@router.delete("/api/apps/credentials")
def delete_app_credential(request: Request, id: str):
    _require_browser_session(request)
    result = service_credentials.delete(id)
    audit.record(
        audit.APP_CREDENTIAL_DELETED,
        username=auth.request_username(request),
        client=auth.request_client_id(request),
        service=id,
    )
    return result


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
    result = apps_manage_svc.action(
        body.id,
        body.action,
        remove_data=body.remove_data,
    )
    audit.record(
        audit.APP_ACTION,
        username=auth.request_username(request),
        client=auth.request_client_id(request),
        target=body.id,
        action=body.action,
        remove_data=bool(body.remove_data),
    )
    return result


# ─── Boot / login autostart console ──────────────────────────────────────────

@router.get("/api/apps/autostart")
def apps_autostart_list(force: bool = False):
    return autostart_svc.overview(force=force)


class AutostartBody(BaseModel):
    id: str
    enabled: bool
    policy: Optional[str] = None  # docker: unless-stopped|always|on-failure|no


@router.post("/api/apps/autostart")
def apps_autostart_set(body: AutostartBody, request: Request = None):
    result = autostart_svc.set_autostart(body.id, body.enabled, policy=body.policy)
    audit.record(
        audit.APP_AUTOSTART_CHANGED,
        username=auth.request_username(request) if request is not None else "",
        client=auth.request_client_id(request),
        target=body.id,
        enabled=bool(body.enabled),
        policy=body.policy or "",
    )
    return result


class DockerPolicyBody(BaseModel):
    name: str
    policy: str  # no|always|unless-stopped|on-failure


@router.post("/api/apps/autostart/docker-policy")
def apps_autostart_docker_policy(body: DockerPolicyBody, request: Request = None):
    result = autostart_svc.set_docker_policy(body.name, body.policy)
    audit.record(
        audit.APP_AUTOSTART_CHANGED,
        username=auth.request_username(request) if request is not None else "",
        client=auth.request_client_id(request),
        target=body.name,
        policy=body.policy,
    )
    return result


@router.post("/api/apps/autostart/run-now")
def apps_autostart_run_now(request: Request = None):
    result = autostart_svc.run_autostart_now()
    audit.record(
        audit.APP_AUTOSTART_CHANGED,
        username=auth.request_username(request) if request is not None else "",
        client=auth.request_client_id(request),
        target="all",
        action="run_now",
    )
    return result
