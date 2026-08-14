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
    #: Optional at the schema level because a loopback claim does not need one.
    #: Whether it is actually demanded is decided by auth.setup_token_required(),
    #: which sees the request; the length bound stays so an over-long value is
    #: rejected before it reaches a comparison.
    setup_token: str = Field(default="", max_length=128)


class ChangePasswordBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=10, max_length=256)


def _https_request(request: Request) -> bool:
    """Whether the browser reached us over TLS, including via a proxy.

    ServerHub is meant to be published through cloudflared or nginx, and both
    terminate TLS and then speak plain HTTP to this origin.  Reading only
    ``request.url.scheme`` therefore saw "http" on exactly the deployment that
    is exposed to the internet, and the session cookie went out without
    ``Secure`` -- so any later plain-HTTP request to the same host would leak it.

    Trusting the forwarded headers is safe *for this decision* because the only
    thing they can do is add ``Secure``, which is strictly more restrictive.
    """
    if request.url.scheme == "https":
        return True
    forwarded_proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip().lower()
    if forwarded_proto == "https":
        return True
    # RFC 7239: Forwarded: for=...;proto=https;by=...
    for element in (request.headers.get("forwarded") or "").split(","):
        for param in element.split(";"):
            key, _, value = param.partition("=")
            if key.strip().lower() == "proto" and value.strip().strip('"').lower() == "https":
                return True
    return False


def _set_session(response: Response, request: Request, username: str) -> None:
    response.set_cookie(
        auth.COOKIE_NAME,
        auth.create_session(username),
        max_age=auth.SESSION_TTL,
        httponly=True,
        secure=_https_request(request),
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
        # Lets the setup form omit the token field entirely when this claim does
        # not need one, instead of showing a box the operator must go and fill
        # from a file for no security gain.
        "setup_token_required": auth.setup_token_required(request),
        "setup_token_mode": auth.setup_token_mode(),
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
            body.setup_token,
            body.password,
            body.username.strip() or "admin",
            require_token=auth.setup_token_required(request),
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
    username = (body.username or "").strip()
    if not auth.verify_account_password(username, body.password):
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
    """Constant-time comparison that tolerates non-ASCII submitted usernames.

    A login body is attacker-controlled, and secrets.compare_digest rejects
    non-ASCII str with TypeError -- so a username like "admın" answered 500
    instead of "bad credentials".
    """
    return auth.constant_time_equals(a, b)


@router.get("/api/auth/setup-token")
def auth_setup_token(request: Request):
    """Return the one-time setup token — only when unclaimed and from localhost.

    This lets the first person to open the panel in a browser complete setup
    without ever touching the terminal or asking an AI for help.  The token is
    only disclosed to loopback clients (127.0.0.1 / ::1) and only while the
    installation is still unclaimed.
    """
    if not auth.setup_required():
        raise api_error("auth.already_setup")
    # TCP-peer loopback is not enough: a Cloudflare tunnel hop is also
    # 127.0.0.1. Only a browser that is actually on this Mac may read the token.
    if not auth.is_direct_loopback(request):
        raise api_error("auth.setup_token_localhost_only")
    return {"setup_token": auth.setup_token()}


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
    # Must match the flags used at login. Omitting ``secure`` leaves a Secure
    # cookie in place on HTTPS / tunneled deployments, so logout appeared to
    # succeed while the session stayed valid.
    response.delete_cookie(
        auth.COOKIE_NAME,
        path="/",
        samesite="strict",
        secure=_https_request(request),
    )
    return {"ok": True}
