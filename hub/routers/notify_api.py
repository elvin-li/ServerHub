"""Notification channel management (multi-channel alert outlets).

CRUD over ``settings.notify.channels`` plus a per-channel test send.  Secret
fields ride in on writes only and are stored through hub.notify_channels'
0600 credentials file; responses carry ``has.<field>`` booleans instead of
values, matching the redaction pattern the settings API uses for the legacy
Home Assistant token.
"""
from __future__ import annotations

import json
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

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)

def _isinst(value, types) -> bool:
    """``isinstance`` that a leftover ``__class__`` bomb cannot 500 through.

    Fail-closed: a raising ``__class__`` property cannot 500 a JSON route.
    """
    try:
        return isinstance(value, types)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


_LEVELS = ("info", "warn", "down")
_SLUG_RE = re.compile(r"[^a-z0-9._-]+")

#: Longest single config value (and list element, by its str() form).
#: Channel records land in services.yaml, whose reader caps at 1MB: one
#: unbounded value used to write a config every later cfg() answered {}
#: for — the admin account and every sibling setting vanished from the
#: panel's view, and the next mutate() persisted the wipe from that empty
#: snapshot.  Same class (and same 400 shape) as vms.name_too_long.
_VALUE_MAX = 1000
#: Most entries in a list-valued config field (the email ``to`` list).
_LIST_MAX = 100
#: Backstop on one whole record, so many at-cap fields still stay small.
_RECORD_MAX = 8 * 1024
#: Ceiling on stored channels: unbounded rows are the same services.yaml
#: growth path as unbounded values (see accounts.too_many).
_MAX_CHANNELS = 100


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


def _capped_value(field: str, value):
    """One config value, refused (coded 400) before it can outgrow the store."""
    if _isinst(value, (bool, int)):
        # JSON-body ints are parse-capped well below the int->str digit
        # limit, so they are always renderable and always small.
        return value
    if _isinst(value, list):
        if len(value) > _LIST_MAX:
            raise api_error("notify.list_too_long", field=field, max=_LIST_MAX)
        for item in value:
            if item is None or _isinst(item, (bool, int, float)):
                continue
            text = item if _isinst(item, str) else str(item)
            if len(text) > _VALUE_MAX:
                raise api_error("notify.value_too_long", field=field, max=_VALUE_MAX)
        return value
    text = str(value).strip()
    if len(text) > _VALUE_MAX:
        raise api_error("notify.value_too_long", field=field, max=_VALUE_MAX)
    return text


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
        record[field] = _capped_value(field, value)

    # Backstop on the whole record: per-field caps still allow a list of
    # at-cap entries to add up, and services.yaml must stay far below its
    # 1MB read cap even with _MAX_CHANNELS records in it.
    try:
        serialized = json.dumps(
            notify_channels._json_safe(record),
            ensure_ascii=False,
            default=str,
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError):
        serialized = ""
    if len(serialized) > _RECORD_MAX:
        raise api_error("notify.value_too_long", field="config", max=_RECORD_MAX)

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
    if len(notify_channels.channels()) >= _MAX_CHANNELS:
        raise api_error("notify.too_many")
    record, secrets_patch = _validated_record(body, cid)
    # A half-completed delete (config gone, credentials write failed) can
    # leave orphaned secrets under this id; a new channel must never silently
    # inherit them, so the slate is wiped before the new values land.
    notify_channels.drop_channel_secrets(cid)
    # require= rejects a missing mandatory secret before the write; the
    # after-write check below stays as the backstop for a write the disk
    # swallowed (EIO), where "created" would otherwise mean "secretless".
    notify_channels.set_channel_secrets(
        cid, secrets_patch, require=_spec_for(body.type)["secret_required"]
    )
    try:
        _require_secrets(cid, body.type)
        # save_channel sits inside the same cleanup net: a services.yaml
        # that turned unreadable refuses this write with the coded 503
        # (config.mutate -> _read_disk_for_mutate), and the mandatory
        # secret just written for the never-created channel used to stay
        # behind in notify-credentials.json — an orphaned live credential
        # no channel row references, invisible to the list and unreachable
        # by DELETE.  The half-completed *delete* mirror of this is exactly
        # what the pre-write wipe above exists for.
        notify_channels.save_channel(record)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # Don't leave orphaned secrets for a channel that was never created.
        # The drop itself is best-effort: masking the coded 503 with a raise
        # out of the cleanup would trade an orphan for a 500.
        try:
            notify_channels.drop_channel_secrets(cid)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            pass
        raise
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
    # require= refuses inside the secrets lock, before the write: clearing a
    # mandatory secret (``secrets: {"url": ""}``) used to persist the wipe
    # and *then* 400 on the after-write check — the "rejected" edit left the
    # channel secretless, and every later alert dispatch on it failed
    # silently.  The after-write check stays as the dying-disk backstop.
    notify_channels.set_channel_secrets(
        cid, secrets_patch, require=_spec_for(body.type)["secret_required"]
    )
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
