"""Form login, password hashing and signed session cookies."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Optional

from fastapi import Depends, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from hub.config import cfg, save_full
from hub.errors import api_error
from hub.paths import DATA_DIR

security = HTTPBasic(auto_error=False)

COOKIE_NAME = "serverhub_session"
MIN_PASSWORD_LENGTH = 10
SESSION_TTL = 7 * 24 * 3600
SECRET_FILE = DATA_DIR / ".session-secret"
SETUP_TOKEN_FILE = DATA_DIR / ".setup-token"
LOCAL_TOKEN_FILE = DATA_DIR / ".local-client-token"
LOCAL_TOKEN_HEADER = "x-serverhub-local-token"
_login_lock = threading.Lock()
_setup_lock = threading.Lock()
_login_attempts: dict[str, list[float]] = {}


def _auth_cfg() -> dict:
    return (cfg().get("settings") or {}).get("auth") or {}


#: Role names.  ``admin`` is unrestricted; ``member`` is the family role, which
#: only reaches the resources listed on its account.
ROLE_ADMIN = "admin"
ROLE_MEMBER = "member"
ROLES = (ROLE_ADMIN, ROLE_MEMBER)


def accounts() -> dict[str, dict]:
    """Every configured account, keyed by username.

    The legacy shape stored one ``username``/``password_hash`` pair directly on
    ``settings.auth``.  That pair is still read here and presented as the admin
    account, so an installation that has never seen a second account keeps
    working untouched -- and existing session cookies keep verifying, because the
    admin's per-account version is computed from the same hash as before.
    """
    a = _auth_cfg()
    out: dict[str, dict] = {}

    legacy_name = str(a.get("username") or "admin").strip() or "admin"
    legacy_hash = str(a.get("password_hash") or a.get("password") or "")
    if legacy_hash:
        out[legacy_name] = {
            "username": legacy_name,
            "password_hash": legacy_hash,
            "role": ROLE_ADMIN,
            "resources": [],
        }

    for raw in a.get("accounts") or []:
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("username") or "").strip()
        if not name:
            continue
        role = str(raw.get("role") or ROLE_MEMBER)
        if role not in ROLES:
            role = ROLE_MEMBER
        resources = [str(r) for r in (raw.get("resources") or []) if str(r).strip()]
        # An explicit entry wins over the legacy pair for the same name, so
        # promoting the admin into the accounts list is a safe migration.
        out[name] = {
            "username": name,
            "password_hash": str(raw.get("password_hash") or ""),
            "role": role,
            "resources": resources,
        }

    return out


def account(username: str | None) -> dict | None:
    """The account record for *username*, or None when no such account exists."""
    if not username:
        return None
    return accounts().get(str(username))


def role_of(username: str | None) -> str:
    """Role for *username*; ``member`` for anything unrecognised.

    Defaulting to the least-privileged role means a lookup miss cannot hand out
    administrative access.
    """
    acct = account(username)
    if not acct:
        return ROLE_MEMBER
    return str(acct.get("role") or ROLE_MEMBER)


def is_admin(username: str | None) -> bool:
    return role_of(username) == ROLE_ADMIN


def allowed_resources(username: str | None) -> list[str]:
    """Resource ids a member account may act on (empty for none).

    Admins are unrestricted, so callers should check :func:`is_admin` first
    rather than reading this as an allowlist for them.
    """
    acct = account(username)
    if not acct:
        return []
    return list(acct.get("resources") or [])


def may_use_resource(username: str | None, resource: str | None) -> bool:
    """True when *username* may act on *resource*.

    Admins reach everything.  A member reaches only the ids on their account,
    and an empty list means no resources at all -- never "all", so a
    half-configured account fails closed.
    """
    if is_admin(username):
        return True
    if not resource:
        return False
    return str(resource) in set(allowed_resources(username))


def setup_required() -> bool:
    a = _auth_cfg()
    legacy = str(a.get("password") or "")
    return not a.get("password_hash") and legacy in ("", "change-me")


def auth_enabled() -> bool:
    """Authentication is mandatory after setup.

    ServerHub exposes host/container administration and may be routed through a
    public tunnel.  Treating a config toggle as anonymous trust turns one
    settings change into remote code execution, so established installations
    can no longer disable authentication.
    """
    return not setup_required()


def _persistent_token(path: Path) -> str:
    """Read or atomically create a mode-0600 random bearer token."""
    try:
        value = path.read_text(encoding="utf-8").strip()
        if value:
            path.chmod(0o600)
            return value
    except FileNotFoundError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    value = secrets.token_urlsafe(32)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(value + "\n")
        return value
    except FileExistsError:
        return path.read_text(encoding="utf-8").strip()


def setup_token() -> str:
    """One-time token required to claim a fresh installation."""
    return _persistent_token(SETUP_TOKEN_FILE)


def consume_setup_token() -> None:
    """Remove the bootstrap secret after credentials are established."""
    try:
        SETUP_TOKEN_FILE.unlink()
    except FileNotFoundError:
        pass


def complete_setup(value: str | None, password: str, username: str) -> bool:
    """Atomically claim a fresh installation with its one-time token.

    Token verification, password persistence, and token consumption share one
    lock so two simultaneous setup requests cannot both become administrators.
    """
    if not value:
        return False
    with _setup_lock:
        if not setup_required():
            return False
        expected = setup_token()
        if not secrets.compare_digest(str(value), expected):
            return False
        set_password(password, username, enable=True)
        consume_setup_token()
        return True


def local_client_token() -> str:
    """Bearer token used only by the loopback menu-bar client."""
    return _persistent_token(LOCAL_TOKEN_FILE)


def local_client_authenticated(request: Request) -> bool:
    client = request.client.host if request.client else ""
    supplied = request.headers.get(LOCAL_TOKEN_HEADER, "")
    return (
        client in ("127.0.0.1", "::1")
        and bool(supplied)
        and secrets.compare_digest(supplied, local_client_token())
    )


def local_client_authorized(request: Request) -> bool:
    """Whether the native menu-bar token may call this exact endpoint.

    The token is deliberately narrower than an administrator session. It only
    covers the status and action calls made by the native and legacy menu-bar
    clients; possession must never unlock files, settings, credentials, shells,
    or arbitrary container APIs.
    """
    method = request.method.upper()
    path = request.url.path.rstrip("/") or "/"
    if (method, path) in {
        ("GET", "/api/health"),
        ("GET", "/api/status"),
        ("GET", "/api/maintenance"),
        ("GET", "/api/launcher"),
        ("POST", "/api/action"),
        ("POST", "/api/containers/all"),
    }:
        return True
    parts = path.strip("/").split("/")
    return (
        len(parts) == 4
        and parts[:2] == ["api", "maintenance"]
        and bool(parts[2])
        and (
            (method == "POST" and parts[3] == "run")
            or (method == "GET" and parts[3] == "log")
        )
    )


def member_request_authorized(request: Request, username: str) -> bool:
    """Allow a family member to read only their explicitly assigned services."""
    if request.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
        return False
    path = request.url.path.rstrip("/") or "/"
    if path in {"/api/health", "/api/status", "/api/services", "/api/launcher"}:
        return True
    parts = path.strip("/").split("/")
    return (
        len(parts) == 4
        and parts[:2] == ["api", "services"]
        and parts[3] == "detail"
        and may_use_resource(username, parts[2])
    )


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    n, r, p = 2**14, 8, 1
    derived = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32)
    return "scrypt${}${}${}${}${}".format(
        n, r, p,
        base64.urlsafe_b64encode(salt).decode().rstrip("="),
        base64.urlsafe_b64encode(derived).decode().rstrip("="),
    )


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def verify_password(password: str) -> bool:
    a = _auth_cfg()
    encoded = str(a.get("password_hash") or "")
    if encoded.startswith("scrypt$"):
        try:
            _, ns, rs, ps, salt_s, expected_s = encoded.split("$", 5)
            actual = hashlib.scrypt(
                password.encode("utf-8"), salt=_b64decode(salt_s),
                n=int(ns), r=int(rs), p=int(ps), dklen=32,
            )
            return hmac.compare_digest(actual, _b64decode(expected_s))
        except (ValueError, TypeError):
            return False
    legacy = str(a.get("password") or "")
    return bool(legacy and legacy != "change-me" and secrets.compare_digest(password, legacy))


def set_password(password: str, username: str = "admin", *, enable: bool = True) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        # Stays a ValueError so non-HTTP callers (menu bar, CLI setup) keep
        # working; the API layer catches it and re-raises auth.password_too_short.
        raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    import copy

    data = copy.deepcopy(cfg())
    settings = data.setdefault("settings", {})
    auth = dict(settings.get("auth") or {})
    auth.update({
        "enabled": bool(enable),
        "username": (username or "admin").strip() or "admin",
        "password_hash": hash_password(password),
    })
    auth.pop("password", None)
    settings["auth"] = auth
    save_full(data)


def _secret() -> bytes:
    try:
        return SECRET_FILE.read_bytes()
    except FileNotFoundError:
        SECRET_FILE.parent.mkdir(exist_ok=True)
        value = secrets.token_bytes(32)
        try:
            fd = os.open(SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(value)
            return value
        except FileExistsError:
            return SECRET_FILE.read_bytes()


def account_session_version(username: str) -> str:
    """Version stamp tying a session to one account's current credential.

    Per account, not global: with a single shared stamp, rotating the admin
    password would sign every family member out, and a member's own rotation
    could not invalidate their sessions.  For the admin this is still derived
    from ``password_hash``, so cookies issued before multi-account support keep
    verifying and nobody is logged out by the upgrade.
    """
    acct = accounts().get(username) or {}
    basis = str(acct.get("password_hash") or "legacy")
    return hashlib.sha256(basis.encode()).hexdigest()[:16]


def _session_payload(username: str, exp: int, version: str) -> bytes:
    return f"{username}|{exp}|{version}".encode()


def _parse_session_payload(payload: str) -> tuple[str, str, str]:
    """Split ``username|exp|version`` from the right.

    ``split("|", 2)`` read the fields left-to-right, so a username containing
    "|" shifted the boundaries and the parsed expiry came from attacker-chosen
    text -- an expired token could present itself as valid for a decade.  exp and
    version never contain "|", so taking the last two fields is unambiguous no
    matter what the username holds.
    """
    username, exp_s, version = payload.rsplit("|", 2)
    return username, exp_s, version


#: A sha256 HMAC is always 32 bytes.  Splitting the token on its "." separator
#: is unsound because the signature is raw bytes: about 12% of digests contain
#: 0x2e ('.'), and ``rsplit(b".", 1)`` then cuts *inside* the signature, so the
#: session fails to verify at random.  The length is fixed, so slice by it.
_SIG_LEN = hashlib.sha256().digest_size


def _split_signed(raw: bytes) -> tuple[bytes, bytes] | None:
    """Separate payload from its trailing ``. + signature`` by fixed length."""
    if len(raw) < _SIG_LEN + 1 or raw[-(_SIG_LEN + 1)] != 0x2E:
        return None
    return raw[: -(_SIG_LEN + 1)], raw[-_SIG_LEN:]


def create_session(username: str) -> str:
    exp = int(time.time()) + SESSION_TTL
    payload = _session_payload(username, exp, account_session_version(username))
    sig = hmac.new(_secret(), payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(payload + b"." + sig).decode().rstrip("=")


def verify_session(token: str | None) -> bool:
    if not token:
        return False
    try:
        split = _split_signed(_b64decode(token))
        if split is None:
            return False
        payload, sig = split
        if not hmac.compare_digest(sig, hmac.new(_secret(), payload, hashlib.sha256).digest()):
            return False
        username, exp_s, version = _parse_session_payload(payload.decode())
        # Membership in the account registry, not equality with one name: that
        # comparison is what made a second account impossible.  An unknown name
        # still has no account and so still has no version to match.
        if username not in accounts():
            return False
        return int(exp_s) > time.time() and hmac.compare_digest(
            version, account_session_version(username)
        )
    except (ValueError, UnicodeDecodeError):
        return False


def browser_authenticated(request: Request) -> bool:
    return verify_session(request.cookies.get(COOKIE_NAME))


def session_username(token: str | None) -> str:
    """Username carried by *token*, or "" when it is not a valid session.

    Verifies first: an unauthenticated caller must never be able to put an
    arbitrary name into an audit record just by crafting a cookie.
    """
    if not verify_session(token):
        return ""
    try:
        split = _split_signed(_b64decode(token))
        if split is None:
            return ""
        # Right-split, matching verify_session: an earlier ``split("|", 1)[0]``
        # reported only the text before the first separator, so an account whose
        # name contained "|" was named incorrectly in audit records.
        return _parse_session_payload(split[0].decode())[0]
    except (ValueError, UnicodeDecodeError):
        return ""


def request_username(request: Request) -> str:
    """Best-effort identity of the caller, for audit logs."""
    return session_username(request.cookies.get(COOKIE_NAME))


def login_allowed(client: str) -> tuple[bool, int]:
    now = time.time()
    with _login_lock:
        attempts = [t for t in _login_attempts.get(client, []) if now - t < 300]
        _login_attempts[client] = attempts
        if len(attempts) >= 5:
            return False, max(1, int(300 - (now - attempts[0])))
        return True, 0


def record_login_failure(client: str) -> None:
    with _login_lock:
        _login_attempts.setdefault(client, []).append(time.time())


def clear_login_failures(client: str) -> None:
    with _login_lock:
        _login_attempts.pop(client, None)


def _route_has_own_admin_guard(request: Request) -> bool:
    """Let routes with a stricter browser-only guard keep stable API errors."""
    if request.method.upper() in {"GET", "HEAD", "OPTIONS"}:
        return False
    path = request.url.path.rstrip("/") or "/"
    return path.startswith("/api/shares/") or path.startswith("/api/launcher/")


def require_auth(
    request: Request,
    credentials: Optional[HTTPBasicCredentials] = Depends(security),
):
    # Until setup completes, every privileged API stays closed.
    if setup_required():
        raise api_error("auth.setup_required")
    if browser_authenticated(request):
        username = request_username(request)
        if is_admin(username):
            request.state.serverhub_auth_kind = "browser-admin"
            return True
        # Shares and launcher mutations perform a stricter browser-admin check in
        # the route itself. Let that check return its established namespaced code.
        if _route_has_own_admin_guard(request):
            return True
        # Members fail closed: only a small read-only surface is reachable, and
        # service-bearing responses filter again by the account resource list.
        if member_request_authorized(request, username):
            return True
        raise api_error("auth.admin_required")
    # Loopback is transport, not identity. The native menu-bar client must prove
    # possession of a separate mode-0600 bearer token, and that token is scoped to
    # the handful of fixed endpoints those clients actually use.
    local_client = local_client_authenticated(request)
    if local_client and local_client_authorized(request):
        request.state.serverhub_auth_kind = "local-client"
        return True
    # A valid local token may reach browser-only mutation routes solely so their
    # own guard can reject it with the stable route-specific error. No operation
    # runs before that guard.
    if local_client and _route_has_own_admin_guard(request):
        request.state.serverhub_auth_kind = "local-client"
        return True
    if isinstance(credentials, HTTPBasicCredentials):
        user = str(_auth_cfg().get("username") or "admin")
        if secrets.compare_digest(credentials.username, user) and verify_password(credentials.password):
            request.state.serverhub_auth_kind = "basic-admin"
            return True
    if local_client:
        raise api_error("auth.admin_required")
    raise api_error("auth.login_required")
