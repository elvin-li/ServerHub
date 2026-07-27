"""Public authentication endpoints (not behind the protected API router)."""
from __future__ import annotations

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, Field

from hub import auth
from hub.errors import api_error

router = APIRouter(tags=["auth"])


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
    return {
        "setup_required": auth.setup_required(),
        "auth_required": auth.auth_enabled() or auth.setup_required(),
        "authenticated": auth.browser_authenticated(request),
        "username": (auth._auth_cfg().get("username") or "admin"),
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
        raise api_error("auth.bad_setup_token")
    _set_session(response, request, body.username.strip() or "admin")
    # No ``message``: the SPA owns the success wording so it stays localized.
    return {"ok": True}


@router.post("/api/auth/login")
def auth_login(body: LoginBody, request: Request, response: Response):
    if auth.setup_required():
        raise api_error("auth.setup_required")
    client = request.client.host if request.client else "unknown"
    allowed, retry = auth.login_allowed(client)
    if not allowed:
        raise api_error("auth.rate_limited", retry=retry)
    username = str(auth._auth_cfg().get("username") or "admin")
    if not secrets_compare(body.username, username) or not auth.verify_password(body.password):
        auth.record_login_failure(client)
        raise api_error("auth.bad_credentials")
    auth.clear_login_failures(client)
    _set_session(response, request, username)
    return {"ok": True, "username": username}


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

    client = request.client.host if request.client else "unknown"
    allowed, retry = auth.login_allowed(client)
    if not allowed:
        raise api_error("auth.rate_limited", retry=retry)
    if not auth.verify_password(body.current_password):
        auth.record_login_failure(client)
        raise api_error("auth.bad_credentials")
    if auth.verify_password(body.new_password):
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
    # No ``message``: Settings.vue falls back to its own localized string.
    return {"ok": True, "username": username}


def secrets_compare(a: str, b: str) -> bool:
    import secrets
    return secrets.compare_digest(a, b)


@router.post("/api/auth/logout")
def auth_logout(response: Response):
    response.delete_cookie(auth.COOKIE_NAME, path="/", samesite="strict")
    return {"ok": True}
