"""Ollama API — local LLM daemon status, model management, chat, quick tests.

Mutations (pull / delete / unload / test / chat) are admin-only by construction:
the member whitelist in hub/auth.py only passes GETs on a fixed path set, so
every POST here requires an administrator session.  Service start/stop/restart
is deliberately NOT here — the page drives the existing ``/api/action`` channel
with the launchd label that ``/api/ollama/status`` reports.
"""
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import iterate_in_threadpool

from hub import audit, ollama_svc
from hub.auth import request_username
from hub.errors import api_error, exc_detail

router = APIRouter(tags=["ollama"])


class ModelBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model: str = Field(..., max_length=200)


class DeleteBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model: str = Field(..., max_length=200)
    confirm: bool = False


class TestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model: str = Field(..., max_length=200)
    # Length is enforced in the service (ollama.prompt_too_long) so the SPA
    # gets a translatable code; the pydantic cap is just a transport bound.
    prompt: str = Field(..., max_length=8000)
    num_predict: int = Field(default=128, ge=1, le=ollama_svc.MAX_NUM_PREDICT)


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: str = Field(..., max_length=16)
    content: str = Field(default="", max_length=8000)


class ChatBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model: str = Field(..., max_length=200)
    messages: list[ChatMessage] = Field(..., min_length=1, max_length=40)
    num_predict: int = Field(default=128, ge=1, le=ollama_svc.MAX_NUM_PREDICT)


@router.get("/api/ollama/status")
def get_status(force: bool = False):
    try:
        return ollama_svc.status(force=force)
    except Exception as e:
        raise api_error("ollama.status_failed", detail=exc_detail(e))


@router.post("/api/ollama/pull")
def start_pull(body: ModelBody, request: Request):
    state = ollama_svc.start_pull(body.model)
    audit.record(
        "ollama.model.pull",
        username=request_username(request) or "unknown",
        model=state.get("model"),
    )
    return state


@router.get("/api/ollama/pull/log")
def pull_log():
    return ollama_svc.pull_log()


@router.post("/api/ollama/models/delete")
def delete_model(body: DeleteBody, request: Request):
    if not body.confirm:
        raise api_error("ollama.confirm_required")
    result = ollama_svc.delete_model(body.model)
    audit.record(
        "ollama.model.deleted",
        username=request_username(request) or "unknown",
        model=result.get("model"),
    )
    return result


@router.post("/api/ollama/models/unload")
def unload_model(body: ModelBody, request: Request):
    result = ollama_svc.unload_model(body.model)
    audit.record(
        "ollama.model.unloaded",
        username=request_username(request) or "unknown",
        model=result.get("model"),
    )
    return result


@router.post("/api/ollama/test")
def quick_test(body: TestBody):
    # Sync route on purpose: FastAPI runs it in the threadpool, and the
    # generation can legitimately take tens of seconds on a cold model.
    return ollama_svc.quick_test(body.model, body.prompt, body.num_predict)


@router.post("/api/ollama/chat")
def chat(body: ChatBody):
    """Stream one chat turn as Ollama NDJSON (application/x-ndjson).

    Validation and the daemon connect happen before the response starts, so
    a bad model name or an unreachable API is still a coded JSON error.
    Each readline runs in the threadpool so a slow token does not stall
    the rest of the panel.
    """
    messages = [m.model_dump() for m in body.messages]
    lines = ollama_svc.start_chat_stream(body.model, messages, body.num_predict)
    return StreamingResponse(
        iterate_in_threadpool(lines),
        media_type="application/x-ndjson",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            # Skip GZipMiddleware buffering so the first token is not held
            # until the 1 KiB minimum.
            "Content-Encoding": "identity",
        },
    )
