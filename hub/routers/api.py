"""REST API — menubar-compatible + panel."""
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from hub import __version__, actions, auth, jobs
from hub.config import cfg
from hub.errors import api_error
from hub.status import cached_status, filter_status_for_resources, full_status, invalidate_status

router = APIRouter()


class Action(BaseModel):
    target: str
    action: str


def _visible_status(request: Request, *, force: bool = False) -> dict:
    status = full_status(force=force)
    username = auth.request_username(request)
    if username and not auth.is_admin(username):
        return filter_status_for_resources(status, auth.allowed_resources(username))
    return status


@router.get("/api/health")
def api_health(request: Request):
    """Liveness for install.sh, the menu-bar client, and monitors.

    Must not run discovery. ``full_status()`` fans out launchd / docker / VMs /
    system probes; install.sh used to trigger that on every 1s poll during
    first boot. Cached counts are included when a snapshot already exists so
    existing clients that read ``ok`` / ``counts`` / ``engine_up`` keep working
    without a forced refresh. Use ``/api/status`` for a current inventory.
    """
    import time

    body = {
        "ok": True,
        "version": __version__,
        "ts": int(time.time()),
    }
    st = cached_status()
    if st is not None:
        username = auth.request_username(request)
        if username and not auth.is_admin(username):
            st = filter_status_for_resources(st, auth.allowed_resources(username))
        body["counts"] = st.get("counts")
        body["engine_up"] = st.get("engine_up")
    return body


@router.get("/api/status")
def api_status(request: Request, force: bool = False):
    return _visible_status(request, force=force)


_LOCAL_CLIENT_ACTIONS = {
    "start", "stop", "restart", "run", "pause", "unpause", "resume", "suspend",
}


def _local_client_action_allowed(target: str, action: str) -> bool:
    """Only execute actions the native menu received for this service."""
    if action not in _LOCAL_CLIENT_ACTIONS:
        return False
    for group in full_status().get("groups") or []:
        for service in group.get("services") or []:
            if service.get("id") == target:
                return action in set(service.get("actions") or [])
    return False


@router.post("/api/action")
def api_action(a: Action, request: Request):
    if getattr(request.state, "serverhub_auth_kind", "") == "local-client":
        if not _local_client_action_allowed(a.target, a.action):
            raise api_error("auth.admin_required")
    rc, out, err = actions.run_action(a.target, a.action)
    invalidate_status()
    ok = rc == 0
    return JSONResponse(
        {"ok": ok, "message": out if ok else (err or out or f"exit {rc}")},
        status_code=200 if ok else 500,
    )


@router.get("/api/maintenance")
def api_maintenance():
    return [
        {
            "id": t["id"],
            "name": t["name"],
            "desc": t.get("desc", ""),
            "confirm": bool(t.get("confirm")),
            **jobs.job_state(t["id"]),
        }
        for t in (cfg().get("maintenance") or [])
    ]


@router.post("/api/maintenance/{tid}/run")
def api_maintenance_run(tid: str):
    task = jobs.maintenance_tasks().get(tid)
    if not task:
        raise api_error("maintenance.unknown_task")
    jobs.start_job(task)
    return {"ok": True}


@router.get("/api/maintenance/{tid}/log")
def api_maintenance_log(tid: str):
    j = jobs.get_job(tid)
    if not j:
        return {"running": False, "rc": None, "log": "（尚未运行）"}
    return {
        "running": j["running"],
        "rc": j["rc"],
        "started": j["started"],
        "finished": j["finished"],
        "log": "\n".join(j["log"]) or "（等待输出…）",
    }
