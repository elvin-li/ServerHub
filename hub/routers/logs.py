from __future__ import annotations

from fastapi import APIRouter, Query

from hub import logs_svc

router = APIRouter(tags=["logs"])


@router.get("/api/logs")
def sources():
    return {"sources": logs_svc.log_sources()}


@router.get("/api/logs/{source_id}")
def tail(source_id: str, lines: int = Query(200, ge=10, le=2000)):
    return logs_svc.tail_log(source_id, lines)
