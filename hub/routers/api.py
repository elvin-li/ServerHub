"""REST API — menubar-compatible + panel."""
from __future__ import annotations

import time

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
    username = auth.request_username(request)
    is_admin = bool(username and auth.is_admin(username))
    # A forced rebuild bypasses the 20s status cache (docker + launchctl +
    # lsof).  Only an admin may pay that cost on demand; a member is served the
    # cached snapshot regardless of ?force= so they cannot spin the host.
    status = full_status(force=force and is_admin)
    if username and not is_admin:
        return filter_status_for_resources(status, auth.allowed_resources(username))
    return status


@router.get("/api/health")
def api_health(request: Request):
    """Liveness for install.sh, the menu-bar client, and monitors.

    Must not run discovery. The app-factory public ``/api/health`` remains the
    unauthenticated watchdog probe (``{ok, ts}`` only). This authenticated
    handler may attach cached counts when a snapshot already exists.
    """
    try:
        ts = int(time.time())
    except (TypeError, ValueError, OverflowError):
        # Leftover ``time.time() = inf`` OverflowError'd GET /api/health.
        ts = 0
    body = {
        "ok": True,
        "version": __version__,
        "ts": ts,
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
    groups = full_status().get("groups")
    for group in groups if isinstance(groups, list) else []:
        if not isinstance(group, dict):
            continue
        rows = group.get("services")
        for service in rows if isinstance(rows, list) else []:
            if not isinstance(service, dict):
                continue
            if service.get("id") == target:
                acts = service.get("actions")
                return action in set(acts if isinstance(acts, list) else [])
    return False


@router.post("/api/action")
def api_action(a: Action, request: Request):
    if getattr(request.state, "serverhub_auth_kind", "") == "local-client":
        if not _local_client_action_allowed(a.target, a.action):
            raise api_error("auth.admin_required")
    rc, out, err = actions.run_action(a.target, a.action)
    invalidate_status()
    ok = rc == 0
    raw = out if ok else (err or out or f"exit {rc}")
    if isinstance(raw, (bytes, bytearray)):
        message = raw.decode("utf-8", "replace")
    elif isinstance(raw, float) and (raw != raw or raw in (float("inf"), float("-inf"))):
        message = ""
    else:
        message = "" if raw is None else str(raw)
    # Leftover ``\\ud800`` / bytes / inf from a VM/action helper used to
    # 500 the menubar's POST /api/action under Starlette's UTF-8 encoder.
    message = message.encode("utf-8", "replace").decode("utf-8")
    return JSONResponse(
        {"ok": bool(ok), "message": message},
        status_code=200 if ok else 500,
    )


@router.get("/api/maintenance")
def api_maintenance():
    return [
        {
            "id": t["id"],
            "name": t.get("name") or t["id"],
            "desc": t.get("desc", ""),
            "confirm": bool(t.get("confirm")),
            **jobs.job_state(t["id"]),
        }
        for t in jobs.maintenance_tasks().values()
    ]


@router.post("/api/maintenance/{tid}/run")
def api_maintenance_run(tid: str):
    task = jobs.maintenance_tasks().get(tid)
    if not task:
        raise api_error("maintenance.unknown_task")
    jobs.start_job(task)
    return {"ok": True, "message": "Task started"}


@router.get("/api/maintenance/{tid}/log")
def api_maintenance_log(tid: str):
    return jobs.job_log(tid)
