"""Two-factor (TOTP) endpoints: the second sign-in step and self-service management.

Mounted beside the public auth router, *not* behind ``require_auth``, because

* the second sign-in step runs before any session exists, and
* management is per-account self-service — a member must be able to enroll
  and remove their own second factor, and the protected router refuses
  member mutations wholesale.

Every management endpoint therefore performs its own browser-session check.
A bearer API key never satisfies these routes: they demand the session
cookie, which a header cannot produce (see the boundary note in
:func:`hub.auth.require_auth`).

Brute-force posture: both the sign-in verifier and the management endpoints
that accept a code share the per-client failure budget of the password login
(:func:`hub.auth.login_allowed`).  Crucially, entering the TOTP step does
**not** clear the client's failure counter — only a fully completed sign-in
does — so "correct password, guessing the code" burns the same budget as
guessing passwords.  Replay of an already-spent code is refused inside
:mod:`hub.twofa_svc` via the persisted last-accepted counter.
"""
from __future__ import annotations

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, Field

from hub import audit, auth, twofa_svc
from hub.errors import api_error
from hub.routers.auth_api import _set_session

router = APIRouter(tags=["auth-totp"])


def _client(request: Request) -> str:
    # Same loopback-aware identity as the password login (auth.request_client),
    # so both sign-in steps share one per-visitor failure budget behind the
    # local reverse proxy instead of one global 127.0.0.1 bucket.
    return auth.request_client(request)


def _require_session_user(request: Request) -> str:
    """The signed-in account (any role) behind a browser session, or raise."""
    if auth.setup_required():
        raise api_error("auth.setup_required")
    if not auth.browser_authenticated(request):
        raise api_error("auth.login_required")
    return auth.request_username(request)


def _check_rate(client: str) -> None:
    allowed, retry = auth.login_allowed(client)
    if not allowed:
        audit.record(
            audit.LOGIN_RATE_LIMITED,
            client=client,
            outcome="failure",
            retry_after=retry,
            method="totp",
        )
        raise api_error("auth.rate_limited", retry=retry)


class TotpVerifyBody(BaseModel):
    #: The pending token handed out by /api/auth/login; opaque to the client.
    pending: str = Field(min_length=1, max_length=1024)
    #: A 6-digit TOTP code or one recovery code (one field serves both).
    code: str = Field(min_length=1, max_length=64)


class TotpCodeBody(BaseModel):
    code: str = Field(min_length=1, max_length=64)


class TotpAdminDisableBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)


@router.post("/api/auth/totp/verify")
def totp_verify(body: TotpVerifyBody, request: Request, response: Response):
    """Second sign-in step: trade pending token + valid code for a session."""
    if auth.setup_required():
        raise api_error("auth.setup_required")
    client = _client(request)
    _check_rate(client)
    username = auth.pending_totp_username(body.pending)
    if not username:
        # Expired, tampered with, or invalidated by a password rotation.  The
        # form has to restart from the password step, and the error says so.
        raise api_error("auth.totp_pending_invalid")
    method = twofa_svc.verify_second_factor(username, body.code)
    if method is None:
        auth.record_login_failure(client)
        audit.record(
            audit.LOGIN_FAILED,
            username=username,
            client=client,
            outcome="failure",
            method="totp",
        )
        raise api_error("auth.bad_totp")
    auth.clear_login_failures(client)
    _set_session(response, request, username)
    if method == "recovery":
        # A spent recovery code is worth its own trail line: it usually means
        # the authenticator is gone, and "how many are left" is the operator's
        # cue to regenerate before running out.
        audit.record(
            audit.TWOFA_RECOVERY_USED,
            username=username,
            client=client,
            outcome="success",
            remaining=twofa_svc.status(username)["recovery_remaining"],
        )
    audit.record(
        audit.LOGIN_OK, username=username, client=client, outcome="success", method=method
    )
    return {
        "ok": True,
        "username": username,
        "role": auth.role_of(username),
        "resources": auth.allowed_resources(username),
        "can_manage": auth.is_admin(username),
    }


@router.get("/api/auth/totp")
def totp_status(request: Request):
    """2FA state of the signed-in account.  Never includes secret material."""
    username = _require_session_user(request)
    return {"username": username, **twofa_svc.status(username)}


@router.post("/api/auth/totp/enroll")
def totp_enroll(request: Request):
    """Start (or restart) enrollment: mint a pending secret and pairing URI.

    Nothing is enforced yet — sign-in keeps working with the password alone
    until /confirm proves the authenticator actually has the secret.  The
    response is the one place the secret travels to the browser; it is shown,
    scanned and never echoed back by any other endpoint.
    """
    username = _require_session_user(request)
    try:
        enrollment = twofa_svc.begin_enrollment(username)
    except twofa_svc.AlreadyEnabled:
        raise api_error("auth.totp_already_enabled")
    return {"ok": True, **enrollment}


@router.post("/api/auth/totp/confirm")
def totp_confirm(body: TotpCodeBody, request: Request, response: Response):
    """Prove the pairing with one valid code, then actually enable 2FA."""
    username = _require_session_user(request)
    client = _client(request)
    _check_rate(client)
    try:
        codes = twofa_svc.confirm_enrollment(username, body.code)
    except twofa_svc.NotPending:
        raise api_error("auth.totp_not_pending")
    if codes is None:
        auth.record_login_failure(client)
        raise api_error("auth.bad_totp")
    auth.clear_login_failures(client)
    # Every outstanding session was issued under "password only"; enabling a
    # second factor is exactly the moment to revoke them.  The bump changes the
    # signed session version, so this browser gets a fresh cookie in the same
    # response and stays signed in.
    auth.bump_session_epoch(username)
    _set_session(response, request, username)
    audit.record(
        audit.TWOFA_ENABLED, username=username, client=client, outcome="success"
    )
    # The recovery codes exist in plaintext only in this response; storage
    # keeps digests.  The SPA renders them once with a copy button.
    return {"ok": True, "recovery_codes": codes}


@router.post("/api/auth/totp/disable")
def totp_disable(body: TotpCodeBody, request: Request, response: Response):
    """Self-service removal: requires a currently valid TOTP or recovery code.

    The session alone is deliberately not enough — a walked-away-from browser
    must not be able to strip the account back down to password-only.
    """
    username = _require_session_user(request)
    client = _client(request)
    _check_rate(client)
    if not twofa_svc.enabled(username):
        raise api_error("auth.totp_not_enabled")
    method = twofa_svc.verify_second_factor(username, body.code)
    if method is None:
        auth.record_login_failure(client)
        audit.record(
            audit.TWOFA_DISABLED,
            username=username,
            client=client,
            outcome="failure",
            reason="bad_code",
        )
        raise api_error("auth.bad_totp")
    twofa_svc.disable(username)
    # Same revocation logic as enabling: the credential requirements changed,
    # so no session issued under the old ones survives.
    auth.bump_session_epoch(username)
    _set_session(response, request, username)
    audit.record(
        audit.TWOFA_DISABLED,
        username=username,
        client=client,
        outcome="success",
        method=method,
    )
    return {"ok": True}


@router.post("/api/auth/totp/recovery")
def totp_regenerate_recovery(body: TotpCodeBody, request: Request):
    """Replace all outstanding recovery codes (needs a valid code first)."""
    username = _require_session_user(request)
    client = _client(request)
    _check_rate(client)
    if not twofa_svc.enabled(username):
        raise api_error("auth.totp_not_enabled")
    method = twofa_svc.verify_second_factor(username, body.code)
    if method is None:
        auth.record_login_failure(client)
        raise api_error("auth.bad_totp")
    codes = twofa_svc.regenerate_recovery(username)
    audit.record(
        audit.TWOFA_RECOVERY_REGENERATED,
        username=username,
        client=client,
        outcome="success",
        method=method,
    )
    return {"ok": True, "recovery_codes": codes}


@router.post("/api/auth/totp/admin-disable")
def totp_admin_disable(body: TotpAdminDisableBody, request: Request, response: Response):
    """Administrator rescue: strip 2FA off *another* account (lost phone).

    No code is demanded — the target cannot produce one, that is the point —
    so the authority here is the administrator's own signed-in browser
    session, and the action always lands in the audit trail naming both
    sides.  The target's sessions are revoked in the same breath.
    """
    operator = _require_session_user(request)
    if not auth.is_admin(operator):
        raise api_error("auth.admin_required")
    target = body.username.strip()
    if not twofa_svc.disable(target):
        raise api_error("auth.totp_not_enabled")
    auth.bump_session_epoch(target)
    if target == operator:
        # Rescuing one's own account through the admin path still has to keep
        # this browser signed in after its epoch bump.
        _set_session(response, request, operator)
    audit.record(
        audit.TWOFA_FORCE_DISABLED,
        username=operator,
        target=target,
        client=_client(request),
        outcome="success",
    )
    return {"ok": True}
