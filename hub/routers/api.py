"""REST API — menubar-compatible + panel."""
from __future__ import annotations

import time

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from hub import __version__, actions, audit, auth, jobs
from hub.errors import api_error
from hub.status import cached_status, filter_status_for_resources, full_status, invalidate_status

router = APIRouter()


class Action(BaseModel):
    target: str
    action: str


def _message_text(value) -> str:
    """One renderable message part from a run_action result.

    Leftover bytes / non-finite floats / ``\\ud800`` were already absorbed;
    a ``str()`` RecursionError still re-raised out of the shaping and 500'd
    POST /api/action — the bulk route's ``_as_text`` contract.
    """
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", "replace")
    elif value is None:
        return ""
    elif isinstance(value, float):
        try:
            finite = float.__float__(value)
        except Exception:
            return ""
        if finite != finite or finite in (float("inf"), float("-inf")):
            return ""
        value = str(finite)
    else:
        try:
            value = str(value)
        except RecursionError:
            try:
                value = type(value).__name__
            except Exception:
                return ""
        except Exception:
            return ""
    return value.encode("utf-8", "replace").decode("utf-8")


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


@router.get("/api/debug/spawns")
def debug_spawns(request: Request):
    """Admin peek at process-local ``sh`` / ``run_capped`` spawn counters.

    Public ``GET /api/health`` stays ``{ok, ts}``.  Keys are executable
    basename, or basename + first subcommand for docker/brew/launchctl —
    never argv.
    """
    if not auth.is_admin(auth.request_username(request)):
        raise api_error("auth.admin_required")
    from hub.util import spawn_counts
    return spawn_counts.snapshot()


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
    try:
        ok = rc == 0
    except Exception:
        # An int-subclass ``__eq__`` bomb rc from an action seam reads as
        # failure — the bulk route's per-id contract — never a 500.
        ok = False
    # run_action raises before touching anything on an unknown target or a
    # disallowed action, so reaching record() means the command really ran;
    # the outcome rides along rather than gating the record — a failed stop
    # is still an operator acting on the host.
    audit.record(
        audit.SERVICE_ACTION,
        username=auth.request_username(request),
        client=auth.request_client_id(request),
        target=a.target,
        action=a.action,
        ok=bool(ok),
    )
    # Leftover ``\\ud800`` / bytes / inf from a VM/action helper used to
    # 500 the menubar's POST /api/action under Starlette's UTF-8 encoder.
    # Shaped through _message_text rather than raw truth tests: a
    # ``__bool__`` bomb in ``err or out`` and the ``f"exit {rc}"`` int->str
    # digit-cap ValueError on an over-cap rc both 500'd this echo while the
    # bulk route rode the very same shapes as per-id failures.
    if ok:
        message = _message_text(out)
    else:
        message = _message_text(err) or _message_text(out)
        if not message:
            try:
                message = f"exit {rc}"
            except Exception:
                message = "exit (unrenderable code)"
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


# ``{tid:path}``, not ``{tid}``: task ids come straight from services.yaml and
# may contain ``/`` (``id: brew/upgrade``).  The SPA percent-encodes the id,
# but ASGI servers decode ``%2F`` back to ``/`` before routing, so a
# single-segment matcher can never see such an id — the list offered a Run
# button for a task whose run route answered the SPA fallback's 405, and
# whose log poll answered its HTML 404 (the "listed id the run route can
# never match" class the surrogate-id scrub already fixed).  tid is only ever
# a mapping key here (never a filesystem path or argv), so the greedy match
# is safe.
@router.post("/api/maintenance/{tid:path}/run")
def api_maintenance_run(tid: str, request: Request = None):
    task = jobs.maintenance_tasks().get(tid)
    if not task:
        raise api_error("maintenance.unknown_task")
    jobs.start_job(task)
    audit.record(
        audit.MAINTENANCE_RUN,
        # FastAPI always injects `request`; the None default only keeps
        # direct in-process calls (tests, tooling) working.
        username=auth.request_username(request) if request is not None else "",
        client=auth.request_client_id(request),
        task=tid,
    )
    return {"ok": True, "message": "Task started"}


@router.get("/api/maintenance/{tid:path}/log")
def api_maintenance_log(tid: str):
    return jobs.job_log(tid)
