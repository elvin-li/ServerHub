"""Form login, password hashing and signed session cookies."""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Optional

from fastapi import Depends, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from hub.config import cfg
from hub.config import mutate as config_mutate
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


def constant_time_equals(supplied: str | None, expected: str | None) -> bool:
    """Constant-time equality for text that may contain any Unicode.

    ``secrets.compare_digest`` raises TypeError on a str holding any non-ASCII
    character.  Every value compared here arrives from the network: Starlette
    decodes request headers as latin-1, so a single 0xFF byte in the local-token
    header became U+00FF and turned the comparison inside ``require_auth`` into
    an unhandled 500 on *every* protected endpoint -- reachable without any
    credential.  Comparing the UTF-8 encodings keeps the timing property and
    accepts arbitrary input, so a malformed value is a plain auth failure.
    """
    if supplied is None or expected is None:
        return False
    return hmac.compare_digest(str(supplied).encode("utf-8"), str(expected).encode("utf-8"))


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


#: Loopback source addresses. A request from here originates on the machine
#: itself *or* from a reverse proxy bound to loopback. IP alone is not identity.
LOOPBACK_HOSTS = ("127.0.0.1", "::1")

#: Host header values that mean the browser addressed this process as localhost.
#: Port is stripped before comparison (``localhost:8086`` → ``localhost``).
LOOPBACK_HOST_NAMES = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})

#: Headers injected by Cloudflare Tunnel, nginx, and Caddy. A browser on this
#: Mac does not send them; a proxied remote client almost always does.
_PROXY_HINT_HEADERS = (
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-real-ip",
    "cf-connecting-ip",
    "forwarded",
)

#: TCP peers we treat as reverse proxies when reading forwarded client headers.
#: Override with ``SERVERHUB_TRUSTED_PROXIES`` (comma-separated CIDRs). Default
#: is loopback only — the usual cloudflared / nginx hop on this Mac.
_DEFAULT_TRUSTED_PROXIES = "127.0.0.1/32,::1/128"

#: How strictly the first-run token is enforced.
#:
#: ``auto``   - required unless the claim is a *direct* loopback browser
#: ``always`` - required even on the machine itself
#: ``never``  - not required at all
SETUP_TOKEN_MODES = ("auto", "always", "never")


def setup_token() -> str:
    """One-time token required to claim a fresh installation."""
    return _persistent_token(SETUP_TOKEN_FILE)


def setup_token_mode() -> str:
    mode = str((_auth_cfg() or {}).get("setup_token_mode") or "auto").strip().lower()
    return mode if mode in SETUP_TOKEN_MODES else "auto"


def is_loopback(request: Request | None) -> bool:
    host = (request.client.host if request and request.client else "") or ""
    return host in LOOPBACK_HOSTS


def request_host_name(request: Request | None) -> str:
    """Hostname from the Host header, with the port stripped.

    ``localhost:8086`` and ``[::1]:8086`` are how a browser on this Mac
    addresses the panel. A tunnel publishes a public name in the same header.
    """
    if request is None:
        return ""
    raw = (request.headers.get("host") or "").strip().lower()
    if not raw:
        return ""
    if raw.startswith("["):
        end = raw.find("]")
        return raw[: end + 1] if end != -1 else raw
    if raw.count(":") == 1:
        return raw.rsplit(":", 1)[0]
    return raw


def is_direct_loopback(request: Request | None) -> bool:
    """True only when the browser is on this Mac, not a reverse-proxy hop.

    Cloudflare Tunnel and nginx terminate on 127.0.0.1, so ``request.client.host``
    is loopback for every remote visitor of a typical install. Those proxies
    inject Forwarded / X-Forwarded-* / CF-Connecting-IP, and they send a public
    Host. A browser opened on the machine itself does neither.

    Treating TCP-peer loopback as "on the machine" was how an unclaimed panel
    published through cloudflared could be claimed by the first remote visitor
    with no setup token.
    """
    if not is_loopback(request) or request is None:
        return False
    for name in _PROXY_HINT_HEADERS:
        if request.headers.get(name):
            return False
    host = request_host_name(request)
    if host and host not in LOOPBACK_HOST_NAMES:
        return False
    return True


def trusted_proxy_networks() -> tuple[ipaddress._BaseNetwork, ...]:
    """CIDRs whose TCP peers may supply a forwarded client address."""
    raw = os.environ.get("SERVERHUB_TRUSTED_PROXIES") or _DEFAULT_TRUSTED_PROXIES
    nets: list[ipaddress._BaseNetwork] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            continue
    return tuple(nets)


def _peer_in_trusted_proxy(peer: str) -> bool:
    try:
        addr = ipaddress.ip_address(peer)
    except ValueError:
        return False
    return any(addr in net for net in trusted_proxy_networks())


def _as_ip(value: str) -> str:
    """Return a canonical IP from a forwarded-header token, or ``""``."""
    raw = (value or "").strip().strip('"')
    if raw.startswith("[") and "]" in raw:
        raw = raw[1:raw.index("]")]
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        pass
    # IPv4 host:port — not IPv6, which has more than one colon.
    if raw.count(":") == 1:
        host, _, _port = raw.rpartition(":")
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            return ""
    return ""


def _parse_forwarded_client(request: Request) -> str:
    """Original client from proxy headers. Empty when none are a valid IP."""
    cf = (request.headers.get("cf-connecting-ip") or "").strip()
    parsed = _as_ip(cf)
    if parsed:
        return parsed
    xff = (request.headers.get("x-forwarded-for") or "").strip()
    if xff:
        parsed = _as_ip(xff.split(",")[0].strip())
        if parsed:
            return parsed
    for element in (request.headers.get("forwarded") or "").split(","):
        for param in element.split(";"):
            key, _, value = param.partition("=")
            if key.strip().lower() == "for":
                parsed = _as_ip(value)
                if parsed:
                    return parsed
    return _as_ip(request.headers.get("x-real-ip") or "")


def request_client_id(request: Request | None) -> str:
    """Identity used for login rate-limits and the audit trail.

    ``request.client.host`` is the TCP peer. Cloudflare Tunnel and nginx
    terminate on 127.0.0.1, so every remote visitor would share one bucket
    (and one audit name) if we keyed on that alone. Forwarded headers are
    only trusted when the peer is in ``SERVERHUB_TRUSTED_PROXIES``; a
    spoofed ``X-Forwarded-For`` from a LAN client is ignored.
    """
    peer = (request.client.host if request and request.client else "") or "unknown"
    if request is None or not _peer_in_trusted_proxy(peer):
        return peer
    return _parse_forwarded_client(request) or peer


def setup_token_required(request: Request | None = None) -> bool:
    """Whether this particular claim has to present the first-run token.

    Default is to require it only for a claim that is not a *direct* loopback
    browser. Requiring it on the machine itself achieves nothing:
    ``/api/auth/setup-token`` already hands the token to a direct loopback
    client, so a browser on this Mac can always obtain it. Demanding it there
    is pure friction -- copy a 64-character secret from one field into another
    -- with no attacker it excludes.

    Off the machine it is doing real work. It is the only thing standing between
    an unclaimed panel and whoever reaches it first, and this host publishes the
    panel over a Cloudflare tunnel and a VPN, so "first" is not necessarily
    someone in the house. A tunneled request looks like loopback at the TCP
    layer; :func:`is_direct_loopback` is what distinguishes the two.
    """
    mode = setup_token_mode()
    if mode == "never":
        return False
    if mode == "always":
        return True
    return not is_direct_loopback(request)


def consume_setup_token() -> None:
    """Remove the bootstrap secret after credentials are established."""
    try:
        SETUP_TOKEN_FILE.unlink()
    except FileNotFoundError:
        pass


def complete_setup(
    value: str | None,
    password: str,
    username: str,
    *,
    require_token: bool = True,
) -> bool:
    """Atomically claim a fresh installation.

    Token verification, password persistence, and token consumption share one
    lock so two simultaneous setup requests cannot both become administrators.

    *require_token* comes from :func:`setup_token_required`; when it is False the
    token is not demanded, but a token that *is* supplied must still be correct so
    a stale or mistyped value fails loudly instead of being silently ignored.
    """
    if require_token and not value:
        return False
    with _setup_lock:
        if not setup_required():
            return False
        if require_token or value:
            expected = setup_token()
            if not constant_time_equals(value or "", expected):
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
        and constant_time_equals(supplied, local_client_token())
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
    # GET /api/maintenance/{id}/log is what the menu bar tails. POST .../run
    # executes operator-configured shell from services.yaml — browser-admin only.
    return (
        method == "GET"
        and len(parts) == 4
        and parts[:2] == ["api", "maintenance"]
        and bool(parts[2])
        and parts[3] == "log"
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


def _verify_scrypt(password: str, encoded: str) -> bool:
    try:
        _, ns, rs, ps, salt_s, expected_s = encoded.split("$", 5)
        actual = hashlib.scrypt(
            password.encode("utf-8"), salt=_b64decode(salt_s),
            n=int(ns), r=int(rs), p=int(ps), dklen=32,
        )
        return hmac.compare_digest(actual, _b64decode(expected_s))
    except (ValueError, TypeError):
        return False


def verify_password(password: str) -> bool:
    a = _auth_cfg()
    encoded = str(a.get("password_hash") or "")
    if encoded.startswith("scrypt$"):
        return _verify_scrypt(password, encoded)
    legacy = str(a.get("password") or "")
    return bool(legacy and legacy != "change-me" and constant_time_equals(password, legacy))


def verify_account_password(username: str, password: str) -> bool:
    """Verify *password* for the named account.

    The legacy administrator still goes through :func:`verify_password` so
    existing tests and the single-hash settings shape keep working. Additional
    accounts in ``settings.auth.accounts`` use their own ``password_hash``.
    """
    name = (username or "").strip()
    if not name:
        return False
    a = _auth_cfg()
    legacy_name = str(a.get("username") or "admin").strip() or "admin"
    if constant_time_equals(name, legacy_name):
        return verify_password(password)
    acct = account(name)
    if not acct:
        return False
    encoded = str(acct.get("password_hash") or "")
    if encoded.startswith("scrypt$"):
        return _verify_scrypt(password, encoded)
    return bool(encoded and encoded != "change-me" and constant_time_equals(password, encoded))


def set_password(password: str, username: str = "admin", *, enable: bool = True) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        # Stays a ValueError so non-HTTP callers (menu bar, CLI setup) keep
        # working; the API layer catches it and re-raises auth.password_too_short.
        raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    # Written through config.mutate, not save_full(deepcopy(cfg())): the latter
    # rewrites the whole file from this process's cached snapshot, and with a
    # second ServerHub sharing services.yaml (the packaged .app alongside the
    # panel) whichever instance saved last reverted the other. That is how the
    # stored username and password_hash went missing and dropped the panel back
    # into "setup required". mutate() re-reads inside the write lock, so this
    # only ever adds the credential to the current on-disk config.
    digest = hash_password(password)
    resolved = (username or "admin").strip() or "admin"

    def apply(data: dict) -> None:
        settings = data.setdefault("settings", {})
        auth = dict(settings.get("auth") or {})
        auth.update({
            "enabled": bool(enable),
            "username": resolved,
            "password_hash": digest,
        })
        auth.pop("password", None)
        settings["auth"] = auth

    config_mutate(apply)


def set_account_password(username: str, password: str) -> None:
    """Rotate the password for one named account.

    Updates the matching ``settings.auth.accounts[]`` entry when one exists,
    and the legacy administrator pair when *username* is that account. A
    member can therefore change their own password without rewriting the
    administrator hash.
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    resolved = (username or "").strip()
    if not resolved:
        raise ValueError("username is required")
    digest = hash_password(password)

    def apply(data: dict) -> None:
        settings = data.setdefault("settings", {})
        auth_cfg = dict(settings.get("auth") or {})
        legacy_name = str(auth_cfg.get("username") or "admin").strip() or "admin"
        updated = False
        if constant_time_equals(resolved, legacy_name):
            auth_cfg["password_hash"] = digest
            auth_cfg.pop("password", None)
            updated = True
        accounts = list(auth_cfg.get("accounts") or [])
        new_accounts = []
        for raw in accounts:
            if not isinstance(raw, dict):
                new_accounts.append(raw)
                continue
            name = str(raw.get("username") or "").strip()
            if name and constant_time_equals(name, resolved):
                entry = dict(raw)
                entry["password_hash"] = digest
                new_accounts.append(entry)
                updated = True
            else:
                new_accounts.append(raw)
        if not updated:
            raise ValueError("unknown account")
        if accounts:
            auth_cfg["accounts"] = new_accounts
        settings["auth"] = auth_cfg

    config_mutate(apply)


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
        # Basic auth is an administrator transport, not a family-account one.
        # A member hash that verified here would unlock every mutating route.
        # The configured legacy username is admin even when accounts() has not
        # yet materialised a hash (setup-adjacent tests and a half-written
        # config); is_admin() alone would fail closed in that window.
        legacy_name = str(_auth_cfg().get("username") or "admin").strip() or "admin"
        if verify_account_password(credentials.username, credentials.password) and (
            is_admin(credentials.username)
            or constant_time_equals(credentials.username, legacy_name)
        ):
            request.state.serverhub_auth_kind = "basic-admin"
            return True
    if local_client:
        raise api_error("auth.admin_required")
    raise api_error("auth.login_required")
