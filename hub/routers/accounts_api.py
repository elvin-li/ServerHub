"""Panel account management — administrator *browser* sessions only.

Same mounting posture as :mod:`hub.routers.api_keys_api` and for the same
reason: these endpoints mint and revoke credentials (member accounts), so an
admin API key must not reach them.  The guard demands the signed session
cookie, which no ``Authorization`` header can produce.

Only *member* accounts are managed here.  The administrator credential has its
own lifecycle (setup, change-password) and deleting or demoting it through a
list endpoint would be an excellent way to lock the whole panel out.
"""
from __future__ import annotations

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from hub import audit, auth, twofa_svc
from hub.errors import api_error, exc_detail
from hub.routers.nas_common import client_host, require_admin_browser

router = APIRouter(tags=["accounts"])

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)

#: hub.auth account-writer ValueError reasons → stable API error codes.
_ACCOUNT_ERRORS = {
    "bad_username": "accounts.bad_username",
    "bad_role": "accounts.bad_username",
    "password_too_short": "auth.password_too_short",
    "exists": "accounts.exists",
    "too_many": "accounts.too_many",
    "not_found": "accounts.not_found",
    "not_member": "accounts.not_member",
}


def _account_error(exc: ValueError):
    code = _ACCOUNT_ERRORS.get(exc_detail(exc, cap=64), "accounts.bad_username")
    if code == "auth.password_too_short":
        return api_error(code, min=auth.MIN_PASSWORD_LENGTH)
    return api_error(code)


class AccountCreateBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    resources: list[str] = Field(default_factory=list, max_length=200)


class AccountResourcesBody(BaseModel):
    resources: list[str] = Field(default_factory=list, max_length=200)


class AccountPasswordBody(BaseModel):
    new_password: str = Field(min_length=1, max_length=256)


def _text(value) -> str:
    if value is None:
        return ""
    try:
        return str(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""


def _resource_ids(raw) -> list:
    """JSON list of grant ids.  A leftover mapping/int used to 500 GET accounts."""
    try:
        items = list(list.__iter__(raw))
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return []
    out = []
    for item in items:
        try:
            text = _text(item).strip()
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
        if text:
            out.append(text)
    return out


def _public_view(acct) -> dict | None:
    """Account record without its hash, plus 2FA state for the admin table.

    One leftover row (hostile grants list, raising field) costs itself only
    — never GET /api/auth/accounts for every sibling.
    """
    try:
        if not isinstance(acct, dict):
            return None
        username = _text(acct.get("username"))
        role = _text(acct.get("role")) or auth.ROLE_MEMBER
        try:
            flag = bool(twofa_svc.enabled(username))
        except _CONTROL_FLOW:
            raise
        except BaseException:
            flag = False
        return {
            "username": username,
            "role": role,
            "resources": _resource_ids(acct.get("resources")),
            "twofa_enabled": flag,
        }
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None


@router.get("/api/auth/accounts")
def accounts_list(request: Request):
    require_admin_browser(request)
    try:
        records = list(auth.accounts().values())
    except _CONTROL_FLOW:
        raise
    except BaseException:
        records = []
    views = []
    for raw in records:
        try:
            view = _public_view(raw)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
        if view is not None:
            views.append(view)
    try:
        views.sort(
            # Admins first, then alphabetically — the shape the Users table shows.
            key=lambda a: (str(a.get("role")) != auth.ROLE_ADMIN, str(a.get("username"))),
        )
    except _CONTROL_FLOW:
        raise
    except BaseException:
        pass
    return {"accounts": views}


@router.post("/api/auth/accounts")
def accounts_create(body: AccountCreateBody, request: Request):
    operator = require_admin_browser(request)
    try:
        created = auth.create_account(
            body.username,
            body.password,
            role=auth.ROLE_MEMBER,
            resources=body.resources,
        )
    except ValueError as exc:
        raise _account_error(exc)
    audit.record(
        audit.ACCOUNT_CREATED,
        username=operator,
        target=created["username"],
        role=created["role"],
        resources=created["resources"],
        client=client_host(request),
        outcome="success",
    )
    return {"ok": True, "account": {**created, "twofa_enabled": False}}


@router.put("/api/auth/accounts/{username}/resources")
def accounts_set_resources(username: str, body: AccountResourcesBody, request: Request):
    operator = require_admin_browser(request)
    try:
        granted = auth.set_account_resources(username, body.resources)
    except ValueError as exc:
        raise _account_error(exc)
    audit.record(
        audit.ACCOUNT_RESOURCES_CHANGED,
        username=operator,
        target=username,
        resources=granted,
        client=client_host(request),
        outcome="success",
    )
    return {"ok": True, "resources": granted}


@router.post("/api/auth/accounts/{username}/password")
def accounts_reset_password(username: str, body: AccountPasswordBody, request: Request):
    """Administrator reset of a member's password (forgotten, not rotated).

    No current password is demanded — the member cannot produce one, that is
    the point.  The hash change flips the account's session version, so every
    outstanding session of the target dies with the old password.
    """
    operator = require_admin_browser(request)
    target = auth.account(username)
    if not target:
        raise api_error("accounts.not_found")
    if str(target.get("role")) == auth.ROLE_ADMIN:
        # The admin rotates their own credential through change-password,
        # which demands the current one.  A no-questions-asked reset endpoint
        # must not exist for administrator accounts.
        raise api_error("accounts.not_member")
    try:
        auth.set_account_password(str(target["username"]), body.new_password)
    except ValueError as exc:
        raise _account_error(exc)
    audit.record(
        audit.ACCOUNT_PASSWORD_RESET,
        username=operator,
        target=str(target["username"]),
        client=client_host(request),
        outcome="success",
    )
    return {"ok": True}


@router.delete("/api/auth/accounts/{username}")
def accounts_delete(username: str, request: Request):
    operator = require_admin_browser(request)
    try:
        auth.delete_account(username)
    except ValueError as exc:
        raise _account_error(exc)
    # The account is gone; its 2FA enrollment must not outlive it, or a
    # recreated namesake would inherit someone else's authenticator.
    twofa_svc.disable(username)
    audit.record(
        audit.ACCOUNT_DELETED,
        username=operator,
        target=username,
        client=client_host(request),
        outcome="success",
    )
    return {"ok": True}
