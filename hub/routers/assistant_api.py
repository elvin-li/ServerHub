"""In-panel assistant — find a page or brief the host via the local LLM.

Admin-only by construction: every route here is a POST or a catalog GET on a
path the member whitelist does not include.  The member UI never mounts the
drawer (``can_manage``), and the backend still refuses the call.
"""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field

from hub import assistant_svc

router = APIRouter(tags=["assistant"])


class HistoryTurn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: str = Field(..., max_length=16)
    content: str = Field(default="", max_length=2000)


class AskBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(default="", max_length=2000)
    locale: str = Field(default="zh-CN", max_length=16)
    action: str = Field(default="auto", max_length=16)
    path: str = Field(default="", max_length=80)
    history: list[HistoryTurn] = Field(default_factory=list, max_length=8)


@router.get("/api/assistant/catalog")
def get_catalog(locale: str = "zh-CN"):
    return {"ok": True, "locale": assistant_svc.normalize_locale(locale), "panels": assistant_svc.catalog(locale)}


@router.post("/api/assistant/ask")
def ask(body: AskBody):
    # Sync on purpose: FastAPI runs it in the threadpool.  A brief can wait on
    # the resident model for tens of seconds the same way /api/ollama/chat does.
    history = [turn.model_dump() for turn in body.history]
    return assistant_svc.ask(
        body.query,
        locale=body.locale,
        action=body.action,
        history=history,
        path=body.path,
    )
