"""Public authentication endpoints (not behind the protected API router)."""
from __future__ import annotations

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, Field

from hub import audit, auth
from hub.errors import api_error

router = APIRouter(tags=["auth"])


def _client(request: Request) -> str:
    return request.client.host if request.client else "unknown"


class LoginBody(BaseModel):
    username: str = "admin"
    password: str = Field(min_length=1, max_length=256)


class SetupBody(BaseModel):
    username: str = Field(default="admin", min_length=1, max_length=64)
    password: str = Field(min_length=10, max_length=256)
    setup_token: str = Field(min_length=32, max_length=128)


class ChangePasswordBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=10, max_length=256)


def _set_session(response: Response, request: Request, username: str) -> None:
    response.set_cookie(
        auth.COOKIE_NAME,
        auth.create_session(username),
        max_age=auth.SESSION_TTL,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="strict",
        path="/",
    )


@router.get("/api/auth/status")
def auth_status(request: Request):
    authenticated = auth.browser_authenticated(request)
    username = auth.request_username(request) if authenticated else ""
    # Keep the legacy administrator name as a login-form convenience only. Once a
    # session exists, every identity/capability field is derived from that signed
    # session instead of from the global administrator config.
    suggested_username = str(auth._auth_cfg().get("username") or "admin")
    return {
        "setup_required": auth.setup_required(),
        "auth_required": auth.auth_enabled() or auth.setup_required(),
        "authenticated": authenticated,
        "username": username or suggested_username,
        "role": auth.role_of(username) if authenticated else None,
        "resources": auth.allowed_resources(username) if authenticated else [],
        "can_manage": bool(authenticated and auth.is_admin(username)),
    }


@router.post("/api/auth/setup")
def auth_setup(body: SetupBody, request: Request, response: Response):
    if not auth.setup_required():
        raise api_error("auth.already_setup")
    try:
        completed = auth.complete_setup(
            body.setup_token, body.password, body.username.strip() or "admin"
        )
    except ValueError:
        raise api_error("auth.password_too_short", min=auth.MIN_PASSWORD_LENGTH)
    if not completed:
        # Re-check after the atomic claim: a competing valid request may have won.
        if not auth.setup_required():
            raise api_error("auth.already_setup")
        # A bad setup token is an attempt to claim an unclaimed install -- the
        # single most sensitive moment in the lifecycle.  The token itself is
        # never passed to record(); redaction would drop it anyway.
        audit.record(
            audit.SETUP_REJECTED,
            username=body.username.strip() or "admin",
            client=_client(request),
            reason="bad_setup_token",
            outcome="failure",
        )
        raise api_error("auth.bad_setup_token")
    claimed = body.username.strip() or "admin"
    _set_session(response, request, claimed)
    audit.record(
        audit.SETUP_CLAIMED,
        username=claimed,
        client=_client(request),
        outcome="success",
    )
    # No ``message``: the SPA owns the success wording so it stays localized.
    return {"ok": True}


@router.post("/api/auth/login")
def auth_login(body: LoginBody, request: Request, response: Response):
    if auth.setup_required():
        raise api_error("auth.setup_required")
    client = _client(request)
    allowed, retry = auth.login_allowed(client)
    if not allowed:
        # Recorded before raising: a burst of these is what a brute-force
        # attempt looks like from the outside.
        audit.record(
            audit.LOGIN_RATE_LIMITED,
            username=body.username,
            client=client,
            outcome="failure",
            retry_after=retry,
        )
        raise api_error("auth.rate_limited", retry=retry)
    username = str(auth._auth_cfg().get("username") or "admin")
    if not secrets_compare(body.username, username) or not auth.verify_password(body.password):
        auth.record_login_failure(client)
        # The attempted name is kept (it is not a secret and is the only clue
        # to *which* account is under attack); audit.record drops the password.
        audit.record(
            audit.LOGIN_FAILED,
            username=username,
            client=client,
            outcome="failure",
        )
        raise api_error("auth.bad_credentials")
    auth.clear_login_failures(client)
    _set_session(response, request, username)
    audit.record(
        audit.LOGIN_OK, username=username, client=client, outcome="success"
    )
    return {
        "ok": True,
        "username": username,
        "role": auth.role_of(username),
        "resources": auth.allowed_resources(username),
        "can_manage": auth.is_admin(username),
    }


@router.post("/api/auth/change-password")
def auth_change_password(body: ChangePasswordBody, request: Request, response: Response):
    """Change panel credentials after re-authentication.

    This deliberately requires a browser session instead of the localhost
    exemption used by the menu-bar client. Rotating the password changes the
    session version, invalidating every other existing browser session.
    """
    if auth.setup_required():
        raise api_error("auth.setup_required")
    if not auth.browser_authenticated(request):
        raise api_error("auth.login_required")
    current_username = auth.request_username(request)
    if not auth.is_admin(current_username):
        # Member password rotation needs a dedicated per-account writer. The
        # legacy setter below rewrites the primary administrator credential, so
        # allowing a member through here would be a privilege escalation.
        raise api_error("auth.admin_required")

    client = request.client.host if request.client else "unknown"
    allowed, retry = auth.login_allowed(client)
    if not allowed:
        raise api_error("auth.rate_limited", retry=retry)
    if not auth.verify_password(body.current_password):
        auth.record_login_failure(client)
        audit.record(
            audit.PASSWORD_CHANGE_DENIED,
            username=auth.request_username(request) or body.username.strip(),
            client=client,
            reason="bad_current_password",
            outcome="failure",
        )
        raise api_error("auth.bad_credentials")
    if auth.verify_password(body.new_password):
        audit.record(
            audit.PASSWORD_CHANGE_DENIED,
            username=auth.request_username(request) or body.username.strip(),
            client=client,
            reason="password_reused",
            outcome="failure",
        )
        raise api_error("auth.password_reused")

    username = body.username.strip()
    if not username:
        raise api_error("auth.username_required")
    try:
        auth.set_password(body.new_password, username, enable=True)
    except ValueError:
        raise api_error("auth.password_too_short", min=auth.MIN_PASSWORD_LENGTH)
    auth.clear_login_failures(client)
    _set_session(response, request, username)
    # Records the rotation, not either password: both field names contain
    # "password" and are dropped by redaction before anything reaches disk.
    audit.record(
        audit.PASSWORD_CHANGED,
        username=username,
        client=client,
        outcome="success",
    )
    # No ``message``: Settings.vue falls back to its own localized string.
    return {"ok": True, "username": username}


def secrets_compare(a: str, b: str) -> bool:
    import secrets
    return secrets.compare_digest(a, b)


@router.post("/api/auth/logout")
def auth_logout(request: Request, response: Response):
    # Name the session being ended, when there is a valid one.  request_username
    # verifies the cookie first, so an unauthenticated caller cannot write an
    # arbitrary name into the trail.
    audit.record(
        audit.LOGOUT,
        username=auth.request_username(request) or None,
        client=_client(request),
        outcome="success",
    )
    response.delete_cookie(auth.COOKIE_NAME, path="/", samesite="strict")
    return {"ok": True}
