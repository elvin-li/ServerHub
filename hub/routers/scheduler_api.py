"""Panel scheduler API: CRUD, enable/disable, run-now, run history.

Complements the existing read-only launchd view (``GET /api/scheduler`` in
unraid_parity/system_extra): those list what *macOS* schedules; these manage
what *the panel* schedules (hub/scheduler_svc.py).

Everything here is admin-only by construction: hub/auth.py routes member
sessions through a small read-only whitelist that does not include any
``/api/scheduler/jobs`` or ``/api/backups/rsync`` path, so a non-admin session
gets ``auth.admin_required`` before any handler below runs.  Every mutation is
audited with the operator's name; for shell jobs the command text itself is
part of the audit record.
"""
from __future__ import annotations

import re
from typing import Any, Optional

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field

from hub import audit, rsync_svc, scheduler_svc
from hub.auth import request_username
from hub.errors import api_error

router = APIRouter(tags=["scheduler"])

_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_STACK_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_-]{0,40}\Z")

_MAX_COMMAND_LEN = 4000


class JobBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: Optional[str] = None
    name: str = Field(..., max_length=80)
    type: str
    cron: str
    enabled: bool = True
    timeout: Optional[int] = None
    params: dict[str, Any] = Field(default_factory=dict)


class EnableBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool


def _validated_params(job_type: str, params: dict) -> dict:
    """Per-type parameter validation; returns exactly what will be stored."""
    params = params or {}
    if job_type == "command":
        command = str(params.get("command") or "").strip()
        if not command or len(command) > _MAX_COMMAND_LEN:
            raise api_error("scheduler.bad_params", field="command")
        return {"command": command}
    if job_type == "rsync":
        # rsync_svc owns the grammar (paths, remotes, excludes) and raises its
        # own rsync.* codes; storing its normalised output means the runner
        # executes exactly what was validated.
        return rsync_svc.validated(params)
    if job_type == "stack_backup":
        stack_id = str(params.get("stack_id") or "").strip()
        if not _STACK_ID_RE.match(stack_id):
            raise api_error("scheduler.bad_params", field="stack_id")
        out: dict[str, Any] = {"stack_id": stack_id}
        retain = params.get("retain")
        if retain not in (None, ""):
            try:
                retain = int(retain)
            except (TypeError, ValueError):
                raise api_error("scheduler.bad_params", field="retain")
            if not 1 <= retain <= 365:
                raise api_error("scheduler.bad_params", field="retain")
            out["retain"] = retain
        return out
    if job_type == "snapshot":
        return {}
    raise api_error("scheduler.bad_type", type=job_type)


def _validated_record(body: JobBody, jid: str) -> dict:
    name = body.name.strip()
    if not name:
        raise api_error("scheduler.bad_name")
    if body.type not in scheduler_svc.JOB_TYPES:
        raise api_error("scheduler.bad_type", type=body.type)
    cron = body.cron.strip()
    if not scheduler_svc.valid_cron(cron):
        raise api_error("scheduler.bad_cron", cron=cron[:80])
    record: dict[str, Any] = {
        "id": jid,
        "name": name,
        "type": body.type,
        "cron": cron,
        "enabled": bool(body.enabled),
        "params": _validated_params(body.type, body.params),
    }
    if body.timeout is not None:
        if not 1 <= int(body.timeout) <= scheduler_svc.MAX_TIMEOUT:
            raise api_error("scheduler.bad_params", field="timeout")
        record["timeout"] = int(body.timeout)
    return record


#: Distinguishes "caller did not preload the last run" from "job never ran".
_LAST_UNSET = object()


def _public_job(job: dict, last=_LAST_UNSET) -> dict:
    """One job as the UI sees it: definition plus live scheduling state.

    *last* lets the list endpoint pass a preloaded record (one journal read
    for all jobs) instead of re-reading the whole run journal per row.
    """
    out = dict(job)
    cron = str(job.get("cron") or "")
    out["next_run"] = scheduler_svc.next_run_ts(cron) if job.get("enabled") else None
    out["running"] = scheduler_svc.is_running(str(job.get("id")))
    if last is _LAST_UNSET:
        last = scheduler_svc.last_run(str(job.get("id")))
    out["last"] = (
        {k: last.get(k) for k in ("ts", "end", "status", "rc", "duration", "trigger")}
        if last else None
    )
    return out


def _audit_fields(record: dict) -> dict:
    """What a job mutation writes to the audit trail.

    The shell command is deliberately included: an audit line that says "a job
    changed" without saying what it now executes answers nothing.
    """
    fields = {
        "job_id": record.get("id"),
        "job_name": record.get("name"),
        "job_type": record.get("type"),
        "cron": record.get("cron"),
        "enabled": record.get("enabled"),
    }
    if record.get("type") == "command":
        fields["command"] = (record.get("params") or {}).get("command")
    return fields


def _bridged_smart_schedule() -> dict | None:
    """The SMART self-test schedule, shown read-only among panel jobs.

    Deliberately *not* absorbed into the cron engine: smart_test_svc's own
    scheduler is interval-based and intentionally catches up after sleep (a
    Mac that slept through the deadline still gets its weekly disk test on
    wake), whereas this engine's cron semantics drop missed triggers.
    Converting it would silently change disk-test cadence on sleep-prone
    machines, so the existing thread keeps running unchanged and this entry
    only *shows* it, pointing at the SMART page for edits.
    """
    try:
        from hub import smart_test_svc
        schedule = smart_test_svc.get_schedule()
    except Exception:
        return None
    interval = schedule.get("interval") or "off"
    period = smart_test_svc.SCHEDULE_INTERVALS.get(interval, 0)
    last = float(schedule.get("last_run") or 0)
    return {
        "id": "smart-selftest",
        "name": "SMART self-test",
        "type": "smart_test",
        "readonly": True,
        "enabled": interval != "off" and bool(schedule.get("devices")),
        "interval": interval,
        "kind": schedule.get("kind"),
        "devices": schedule.get("devices") or [],
        "last_run": int(last),
        "next_run": int(last + period) if period else None,
    }


@router.get("/api/scheduler/jobs")
def list_jobs():
    last_by_job = scheduler_svc.last_runs_by_job()
    return {
        "jobs": [
            _public_job(j, last=last_by_job.get(str(j.get("id"))))
            for j in scheduler_svc.list_jobs()
        ],
        "system": [b for b in (_bridged_smart_schedule(),) if b],
        "types": list(scheduler_svc.JOB_TYPES),
    }


@router.post("/api/scheduler/jobs")
def create_job(body: JobBody, request: Request):
    jid = (body.id or scheduler_svc.new_job_id()).strip()
    if not _ID_RE.match(jid):
        raise api_error("scheduler.bad_id")
    if scheduler_svc.get_job(jid) is not None:
        raise api_error("scheduler.exists", id=jid)
    record = _validated_record(body, jid)
    scheduler_svc.save_job(record)
    audit.record(audit.SCHEDULE_JOB_CREATED,
                 user=request_username(request), **_audit_fields(record))
    return {"ok": True, "job": _public_job(record)}


@router.put("/api/scheduler/jobs/{jid}")
def update_job(jid: str, body: JobBody, request: Request):
    if not _ID_RE.match(jid):
        raise api_error("scheduler.bad_id")
    if scheduler_svc.get_job(jid) is None:
        raise api_error("scheduler.not_found", id=jid)
    record = _validated_record(body, jid)
    scheduler_svc.save_job(record)
    audit.record(audit.SCHEDULE_JOB_UPDATED,
                 user=request_username(request), **_audit_fields(record))
    return {"ok": True, "job": _public_job(record)}


@router.delete("/api/scheduler/jobs/{jid}")
def delete_job(jid: str, request: Request):
    if not _ID_RE.match(jid):
        raise api_error("scheduler.bad_id")
    job = scheduler_svc.get_job(jid)
    if job is None or not scheduler_svc.delete_job(jid):
        raise api_error("scheduler.not_found", id=jid)
    audit.record(audit.SCHEDULE_JOB_DELETED,
                 user=request_username(request), **_audit_fields(job))
    return {"ok": True}


@router.post("/api/scheduler/jobs/{jid}/enable")
def enable_job(jid: str, body: EnableBody, request: Request):
    if not _ID_RE.match(jid):
        raise api_error("scheduler.bad_id")
    job = scheduler_svc.set_enabled(jid, body.enabled)
    if job is None:
        raise api_error("scheduler.not_found", id=jid)
    audit.record(audit.SCHEDULE_JOB_UPDATED,
                 user=request_username(request), **_audit_fields(job))
    return {"ok": True, "job": _public_job(job)}


@router.post("/api/scheduler/jobs/{jid}/run-now")
def run_job_now(jid: str, request: Request):
    if not _ID_RE.match(jid):
        raise api_error("scheduler.bad_id")
    job = scheduler_svc.get_job(jid)
    if job is None:
        raise api_error("scheduler.not_found", id=jid)
    if scheduler_svc.is_running(jid):
        raise api_error("scheduler.running")
    audit.record(audit.SCHEDULE_JOB_RUN,
                 user=request_username(request), **_audit_fields(job))
    return scheduler_svc.run_job_now(jid)


@router.get("/api/scheduler/jobs/{jid}/runs")
def job_runs(jid: str, limit: int = 20):
    if not _ID_RE.match(jid):
        raise api_error("scheduler.bad_id")
    return {"runs": scheduler_svc.runs(jid, limit=max(1, min(int(limit), 200)))}


@router.get("/api/scheduler/runs")
def all_runs(limit: int = 50):
    return {"runs": scheduler_svc.runs(limit=max(1, min(int(limit), 200)))}


# ── rsync helpers for the Backups page ───────────────────────────────────────

@router.get("/api/backups/rsync/binary")
def rsync_binary():
    return rsync_svc.binary_info()


@router.post("/api/backups/rsync/preview")
def rsync_preview(body: dict):
    """Dry-run: what a real run would create/change/delete.  Nothing is copied."""
    return rsync_svc.preview(body or {})
