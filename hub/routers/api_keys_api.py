"""API key management endpoints — administrator *browser* sessions only.

Deliberately not mounted behind ``require_auth``: an admin API key passes
that dependency, and a credential that can mint further credentials would
make revocation meaningless.  The guard here demands the signed session
cookie (same semantics as every ``require_admin_browser`` route), which no
``Authorization`` header can produce — so keys manage nothing, including
themselves.  The keys' own authentication lives in
:func:`hub.auth.require_auth`; storage and hashing in :mod:`hub.api_keys`.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from hub import api_keys, audit
from hub.errors import api_error, exc_detail
from hub.routers.nas_common import client_host, require_admin_browser

router = APIRouter(tags=["api-keys"])

#: hub.api_keys.create ValueError reasons → stable API error codes.
_CREATE_ERRORS = {
    "bad_name": "apikeys.name_required",
    "bad_role": "apikeys.bad_role",
    "bad_expiry": "apikeys.bad_expiry",
    "too_many": "apikeys.too_many",
}


class ApiKeyCreateBody(BaseModel):
    name: str = Field(min_length=1, max_length=api_keys.MAX_NAME_LENGTH)
    role: str = Field(default="member")
    expires_days: Optional[int] = Field(default=None, ge=1, le=3650)


@router.get("/api/api-keys")
def api_keys_list(request: Request):
    require_admin_browser(request)
    return {"keys": api_keys.list_public()}


@router.post("/api/api-keys")
def api_keys_create(body: ApiKeyCreateBody, request: Request):
    username = require_admin_browser(request)
    try:
        record, plaintext = api_keys.create(
            body.name, body.role, expires_days=body.expires_days
        )
    except ValueError as exc:
        raise api_error(_CREATE_ERRORS.get(exc_detail(exc, cap=64), "apikeys.name_required"))
    # Field names chosen to survive audit redaction ("key" is a secret hint,
    # "kid" is not); the plaintext key is never passed to record() at all.
    audit.record(
        audit.APIKEY_CREATED,
        username=username,
        client=client_host(request),
        kid=record["id"],
        name=record["name"],
        role=record["role"],
        expires=record["expires"],
        outcome="success",
    )
    # ``key`` is the only copy of the plaintext that will ever exist; the SPA
    # shows it once with a copy button and the store keeps only its digest.
    return {"ok": True, "key": plaintext, "record": record}


@router.delete("/api/api-keys/{key_id}")
def api_keys_revoke(key_id: str, request: Request):
    username = require_admin_browser(request)
    record = api_keys.revoke(key_id)
    if record is None:
        raise api_error("apikeys.not_found")
    audit.record(
        audit.APIKEY_REVOKED,
        username=username,
        client=client_host(request),
        kid=record["id"],
        name=record["name"],
        role=record["role"],
        outcome="success",
    )
    return {"ok": True}
