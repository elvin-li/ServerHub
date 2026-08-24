"""Notification channel management (multi-channel alert outlets).

CRUD over ``settings.notify.channels`` plus a per-channel test send.  Secret
fields ride in on writes only and are stored through hub.notify_channels'
0600 credentials file; responses carry ``has.<field>`` booleans instead of
values, matching the redaction pattern the settings API uses for the legacy
Home Assistant token.
"""
from __future__ import annotations

import re
import uuid
from typing import Any, Optional

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field

from hub import audit, notify_channels
from hub.auth import request_client_id, request_username
from hub.errors import api_error
from hub.util import strftime_now

router = APIRouter(tags=["notify"])

_LEVELS = ("info", "warn", "down")
_SLUG_RE = re.compile(r"[^a-z0-9._-]+")


class ChannelBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: Optional[str] = None
    type: str
    name: Optional[str] = Field(None, max_length=80)
    enabled: bool = True
    min_level: str = "warn"
    notify_resolve: bool = True
    #: Non-secret parameters, filtered against the type's field list.
    config: dict[str, Any] = Field(default_factory=dict)
    #: Write-only secrets.  Omitted/None = keep stored value, "" = clear.
    secrets: dict[str, Optional[str]] = Field(default_factory=dict)


def _spec_for(channel_type: str) -> dict:
    spec = notify_channels.CHANNEL_TYPES.get(channel_type)
    if spec is None:
        raise api_error("notify.bad_type", type=channel_type)
    return spec


def _generate_id(name: str | None) -> str:
    slug = _SLUG_RE.sub("-", (name or "").strip().lower()).strip("-.")[:40]
    suffix = uuid.uuid4().hex[:6]
    cid = f"{slug}-{suffix}" if slug else f"channel-{suffix}"
    return cid if notify_channels.valid_channel_id(cid) else f"channel-{suffix}"


def _validated_record(body: ChannelBody, cid: str) -> tuple[dict, dict]:
    """(channel record for services.yaml, secrets patch) — or raise."""
    spec = _spec_for(body.type)
    if body.min_level not in _LEVELS:
        raise api_error("notify.bad_level")

    record: dict[str, Any] = {
        "id": cid,
        "type": body.type,
        "name": (body.name or "").strip() or cid,
        "enabled": bool(body.enabled),
        "min_level": body.min_level,
        "notify_resolve": bool(body.notify_resolve),
    }
    for field in spec["fields"]:
        value = body.config.get(field)
        if value is None or value == "":
            continue
        record[field] = value if isinstance(value, (int, bool, list)) else str(value).strip()

    secrets_patch = {
        k: v for k, v in body.secrets.items() if k in spec["secrets"] and v is not None
    }

    # SSRF guard: every URL an operator can point the panel at must be http(s).
    for field in spec["urls"]:
        for source in (record, secrets_patch):
            value = source.get(field)
            if value and not notify_channels._http_url_ok(str(value)):
                raise api_error("notify.bad_url", field=field)

    for field in spec["required"]:
        if not record.get(field):
            raise api_error("notify.missing_field", field=field)
    return record, secrets_patch


def _require_secrets(cid: str, channel_type: str) -> None:
    """After a write, a channel must still hold its mandatory secrets."""
    spec = _spec_for(channel_type)
    stored = notify_channels.channel_secrets(cid)
    for field in spec["secret_required"]:
        if not stored.get(field):
            raise api_error("notify.missing_field", field=field)


def _audit_fields(record: dict) -> dict:
    """What a channel mutation writes to the audit trail — config only.

    Secret values never ride through here: the callers pass the channel
    *record* (services.yaml side), and audit.record() would drop token-shaped
    keys anyway.  A notification channel is an outbound data path, so who
    created/retargeted/deleted one must be answerable from the trail.
    """
    return {
        "channel_id": record.get("id"),
        "channel_type": record.get("type"),
        "channel_name": record.get("name"),
        "enabled": record.get("enabled"),
        "min_level": record.get("min_level"),
    }


@router.get("/api/alerts/channels")
def list_channels():
    return {
        "channels": [notify_channels.public_channel(c) for c in notify_channels.channels()],
        "types": {
            t: {"fields": list(s["fields"]), "secrets": list(s["secrets"]),
                "required": list(s["required"]), "secret_required": list(s["secret_required"])}
            for t, s in notify_channels.CHANNEL_TYPES.items()
        },
    }


@router.post("/api/alerts/channels")
def create_channel(body: ChannelBody, request: Request):
    cid = body.id or _generate_id(body.name)
    if not notify_channels.valid_channel_id(cid):
        raise api_error("notify.bad_id")
    if notify_channels.get_channel(cid) is not None:
        raise api_error("notify.exists", id=cid)
    record, secrets_patch = _validated_record(body, cid)
    # A half-completed delete (config gone, credentials write failed) can
    # leave orphaned secrets under this id; a new channel must never silently
    # inherit them, so the slate is wiped before the new values land.
    notify_channels.drop_channel_secrets(cid)
    notify_channels.set_channel_secrets(cid, secrets_patch)
    try:
        _require_secrets(cid, body.type)
    except Exception:
        # Don't leave orphaned secrets for a channel that was never created.
        notify_channels.drop_channel_secrets(cid)
        raise
    notify_channels.save_channel(record)
    audit.record(audit.NOTIFY_CHANNEL_CREATED,
                 username=request_username(request),
                 client=request_client_id(request), **_audit_fields(record))
    return {"ok": True, "channel": notify_channels.public_channel(record)}


@router.put("/api/alerts/channels/{cid}")
def update_channel(cid: str, body: ChannelBody, request: Request):
    if not notify_channels.valid_channel_id(cid):
        raise api_error("notify.bad_id")
    existing = notify_channels.get_channel(cid)
    if existing is None:
        raise api_error("notify.not_found", id=cid)
    # The type is immutable (the SPA never offered changing it).  Allowing it
    # would leave the old type's secrets orphaned in the credentials file —
    # and silently re-adopted if the channel ever switched back.
    if str(existing.get("type")) != body.type:
        raise api_error("notify.type_immutable", id=cid)
    record, secrets_patch = _validated_record(body, cid)
    notify_channels.set_channel_secrets(cid, secrets_patch)
    _require_secrets(cid, body.type)
    notify_channels.save_channel(record)
    audit.record(audit.NOTIFY_CHANNEL_UPDATED,
                 username=request_username(request),
                 client=request_client_id(request), **_audit_fields(record))
    return {"ok": True, "channel": notify_channels.public_channel(record)}


@router.delete("/api/alerts/channels/{cid}")
def remove_channel(cid: str, request: Request):
    if not notify_channels.valid_channel_id(cid):
        raise api_error("notify.bad_id")
    channel = notify_channels.get_channel(cid) or {"id": cid}
    if not notify_channels.delete_channel(cid):
        raise api_error("notify.not_found", id=cid)
    audit.record(audit.NOTIFY_CHANNEL_DELETED,
                 username=request_username(request),
                 client=request_client_id(request), **_audit_fields(channel))
    return {"ok": True}


@router.post("/api/alerts/channels/{cid}/test")
def test_channel(cid: str, request: Request):
    if not notify_channels.valid_channel_id(cid):
        raise api_error("notify.bad_id")
    channel = notify_channels.get_channel(cid)
    if channel is None:
        raise api_error("notify.not_found", id=cid)
    result = notify_channels.dispatch(
        "ServerHub test",
        f"Notification channel test {strftime_now('%H:%M:%S')}",
        event="test",
        channel_id=cid,
    )
    audit.record(audit.NOTIFY_CHANNEL_TESTED,
                 username=request_username(request),
                 client=request_client_id(request), ok=bool(result.get("ok")),
                 **_audit_fields(channel))
    return result
