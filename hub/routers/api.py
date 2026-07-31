"""REST API — menubar-compatible + panel."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from hub import actions, jobs
from hub.config import cfg
from hub.status import full_status, invalidate_status

router = APIRouter()


class Action(BaseModel):
    target: str
    action: str


@router.get("/api/health")
def api_health():
    """Lightweight health for menubar / monitoring."""
    try:
        st = full_status()
        return {
            "ok": True,
            "counts": st.get("counts"),
            "engine_up": st.get("engine_up"),
            "ts": st.get("ts"),
        }
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@router.get("/api/status")
def api_status(force: bool = False):
    return full_status(force=force)


@router.post("/api/action")
def api_action(a: Action):
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
        raise HTTPException(404, "unknown task")
    jobs.start_job(task)
    return {"ok": True, "message": "任务已开始"}


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
