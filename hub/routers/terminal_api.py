"""Terminal APIs — container exec, and a host shell behind an explicit opt-in.

Mounted under the same ``require_auth`` dependency as the rest of ``router``, so
every endpoint here already requires an authenticated panel session (and, before
setup completes, refuses outright with ``auth.setup_required``).
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, Field

from hub import terminal_svc

router = APIRouter(tags=["terminal"])


class RunBody(BaseModel):
    command: str
    target: str = "host"
    container: str = ""
    shell: str = ""
    #: Working directory to start in, echoed back by the previous response so a
    #: console tab keeps its place across commands (`cd` appears to persist).
    #: Advisory only: the host side ignores anything that is not a real
    #: directory, and it grants no access the shell did not already have.
    cwd: str = ""
    #: Clamped server-side to terminal_svc.MAX_TIMEOUT regardless of what is sent.
    timeout: Optional[int] = Field(None, ge=1, le=terminal_svc.MAX_TIMEOUT)


def _who(request: Request) -> str:
    """Best-effort identity for the audit log.

    The session cookie carries a signed username; when the caller authenticated
    some other way (HTTP basic, or the localhost menu-bar bypass) there is no
    verified name, so fall back to the peer address rather than inventing one.
    """
    from hub import auth

    name = auth.request_username(request)
    peer = request.client.host if request.client else "?"
    return f"{name}@{peer}" if name else peer


@router.get("/api/terminal")
def terminal_status():
    return terminal_svc.status()


@router.post("/api/terminal/run")
def terminal_run(body: RunBody, request: Request):
    return terminal_svc.execute(
        body.target,
        body.command,
        container=body.container,
        shell=body.shell,
        timeout=body.timeout,
        cwd=body.cwd,
        who=_who(request),
    )


@router.get("/api/terminal/history")
def terminal_history(limit: int = Query(50, ge=1, le=500)):
    return {"entries": terminal_svc.recent_audit(limit)}
