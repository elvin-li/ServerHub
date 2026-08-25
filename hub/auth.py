"""Form login, password hashing and signed session cookies."""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import stat
import threading
import time
from pathlib import Path
from typing import Optional

from fastapi import Depends, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from hub import api_keys
from hub.config import cfg
from hub.config import mutate as config_mutate
from hub.errors import api_error
from hub.paths import DATA_DIR
from hub.util import read_text_capped

security = HTTPBasic(auto_error=False)

COOKIE_NAME = "serverhub_session"
MIN_PASSWORD_LENGTH = 10
SESSION_TTL = 7 * 24 * 3600
SECRET_FILE = DATA_DIR / ".session-secret"
SETUP_TOKEN_FILE = DATA_DIR / ".setup-token"
LOCAL_TOKEN_FILE = DATA_DIR / ".local-client-token"
#: Leftover multi-MB junk occupying these 32-byte tokens used to OOM login.
_SECRET_CAP = 64
_TOKEN_CAP = 128
LOCAL_TOKEN_HEADER = "x-serverhub-local-token"
_login_lock = threading.Lock()
_setup_lock = threading.Lock()
_login_attempts: dict[str, list[float]] = {}
#: How long a failed attempt counts against its bucket.
_LOGIN_WINDOW = 300.0
#: Sweep the attempt table once it holds more clients than this.  Well above
#: any household's device count, so the sweep is only ever paid for by a
#: caller minting buckets rather than by one using the panel.
_LOGIN_SWEEP_AT = 512


def _auth_cfg() -> dict:
    settings = cfg().get("settings")
    if not isinstance(settings, dict):
        return {}
    auth = settings.get("auth")
    return auth if isinstance(auth, dict) else {}


def _epoch_key(key) -> str:
    """A ``session_epochs`` mapping key as the account name it stands for.

    YAML round-trips an all-digit account name (``2024:``) as an *int* key
    and true/false-ish names as bools, so the strict string ``.get()``
    missed the row entirely: ``_session_epoch`` read 0 for that account and
    every pre-logout token kept verifying, ``bump_session_epoch`` wrote a
    second (string) spelling *below* the real counter, and
    ``delete_account`` left the stale row behind.  The same ``str()`` probe
    as :func:`accounts` usernames (``_cfg_text``): an over-cap hex int key
    reads as "" and is dropped, and a lone-surrogate key is dropped rather
    than carried into a lookup key nothing can ever match.
    """
    text = _cfg_text(key).strip()
    return text if _utf8_ok(text) else ""


def _epoch_count(raw) -> int:
    """One ``session_epochs`` value as a usable logout counter.

    Bool/None/inf/garbage read as 0.  An int past CPython's int->str digit
    cap reads as 1, not 0: the account has logged out at least once, so
    pre-logout tokens (whose version omits the epoch) must stay revoked.
    """
    if raw is None or isinstance(raw, bool):
        return 0
    try:
        value = int(raw)
    except (TypeError, ValueError, OverflowError):
        return 0
    try:
        str(value)
    except ValueError:
        return 1
    return value


def _clean_epochs(raw) -> dict:
    """``session_epochs`` rows that YAML can re-dump, keyed by account name.

    A leftover unrenderable-int epoch (or key) rode along untouched in every
    auth write and ValueError'd ``yaml.safe_dump`` inside ``config.mutate`` --
    setup, password changes and the TOTP epoch bump all 500'd on it.

    Keys are normalised through :func:`_epoch_key`, so an int-keyed leftover
    for a numeric account name folds onto its string spelling; when both
    spellings exist the *larger* counter wins, so neither copy can quietly
    un-revoke sessions the other had already revoked.
    """
    if not isinstance(raw, dict):
        return {}
    out: dict[str, int] = {}
    for k, v in raw.items():
        key = _epoch_key(k)
        if not key:
            continue
        count = _epoch_count(v)
        if key in out:
            count = max(count, out[key])
        out[key] = count
    return out


def _auth_block(data: dict) -> tuple[dict, dict]:
    """Ensure ``data['settings']['auth']`` are mappings before a mutate.

    ``setdefault("settings", {})`` returns a pre-existing list, and
    ``dict(settings.get("auth") or {})`` raises on ``auth: []``.  Password
    setup and account writes used to 500 in both cases.
    """
    settings = data.get("settings")
    if not isinstance(settings, dict):
        settings = {}
        data["settings"] = settings
    auth = settings.get("auth")
    auth = dict(auth) if isinstance(auth, dict) else {}
    if "session_epochs" in auth:
        auth["session_epochs"] = _clean_epochs(auth.get("session_epochs"))
    return settings, auth


def _account_rows(auth_cfg: dict) -> list[dict]:
    rows = auth_cfg.get("accounts") if isinstance(auth_cfg, dict) else None
    return [dict(e) for e in rows if isinstance(e, dict)] if isinstance(rows, list) else []


def _utf8(text: str) -> bytes:
    """UTF-8 bytes of *text*.  Lone surrogates must not 500 login or setup."""
    return str(text).encode("utf-8", "surrogatepass")


def _cfg_text(raw) -> str:
    """``str()`` of a config value that cannot 500 login / status / setup.

    YAML hex (``0x…``) parses through ``int(x, 16)``, which CPython's
    str↔int digit cap does not bound, so a leftover >4300-digit integer in
    ``settings.auth`` loads fine and then ValueError'd ``str()`` — every
    login attempt (``accounts()``), the unclaimed GET /api/auth/status
    (``suggested_setup_username``) and ``setup_token_mode`` returned 500.
    """
    try:
        return str(raw)
    except ValueError:
        return ""


def _utf8_ok(text: str) -> bool:
    """False for leftover YAML ``\\ud800`` — Starlette's JSON encoder rejects it."""
    try:
        text.encode("utf-8")
        return True
    except UnicodeEncodeError:
        return False


def constant_time_equals(supplied: str | None, expected: str | None) -> bool:
    """Constant-time equality for text that may contain any Unicode.

    ``secrets.compare_digest`` raises TypeError on a str holding any non-ASCII
    character.  Every value compared here arrives from the network: Starlette
    decodes request headers as latin-1, so a single 0xFF byte in the local-token
    header became U+00FF and turned the comparison inside ``require_auth`` into
    an unhandled 500 on *every* protected endpoint -- reachable without any
    credential.  Comparing the UTF-8 encodings keeps the timing property and
    accepts arbitrary input, so a malformed value is a plain auth failure.

    JSON bodies can also carry an unpaired surrogate (``\\ud800``).  Strict
    UTF-8 encoding of that raises UnicodeEncodeError, which is a ValueError
    and used to 500 ``/api/auth/setup`` instead of rejecting the token.
    """
    if supplied is None or expected is None:
        return False
    return hmac.compare_digest(_utf8(supplied), _utf8(expected))


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

    Names containing ``:`` are dropped at this single entrance.  API keys with
    the member role act under the synthetic identity ``key:<name>``
    (:func:`request_username`), and every authorisation lookup on that identity
    must fail closed to "member with no resources".  ``create_account`` already
    refuses ``:`` via USERNAME_RE, but services.yaml is hand-editable: an
    account literally named ``key:mon`` would otherwise hand its resource list
    to whoever holds the API key named ``mon``.  Filtering here covers every
    consumer (account/role_of/allowed_resources/verify_session) at once; the
    hand-written entry simply stops resolving, which is fail-closed.
    """
    a = _auth_cfg()
    out: dict[str, dict] = {}

    legacy_name = _cfg_text(a.get("username") or "admin").strip() or "admin"
    if not _utf8_ok(legacy_name):
        # Lone-surrogate leftover: keep the hash under the default name so
        # setup/status can still JSON-encode a suggested username.
        legacy_name = "admin"
    legacy_hash = _cfg_text(a.get("password_hash") or a.get("password") or "")
    if legacy_hash and ":" not in legacy_name:
        out[legacy_name] = {
            "username": legacy_name,
            "password_hash": legacy_hash,
            "role": ROLE_ADMIN,
            "resources": [],
        }

    rows = a.get("accounts")
    if not isinstance(rows, list):
        rows = []
    for raw in rows:
        if not isinstance(raw, dict):
            continue
        name = _cfg_text(raw.get("username") or "").strip()
        if not name or ":" in name or not _utf8_ok(name):
            continue
        role = _cfg_text(raw.get("role") or ROLE_MEMBER)
        if role not in ROLES:
            role = ROLE_MEMBER
        raw_res = raw.get("resources")
        resources = [
            _cfg_text(r) for r in raw_res
            if _cfg_text(r).strip() and _utf8_ok(_cfg_text(r))
        ] if isinstance(raw_res, list) else []
        # An explicit entry wins over the legacy pair for the same name, so
        # promoting the admin into the accounts list is a safe migration.
        out[name] = {
            "username": name,
            "password_hash": _cfg_text(raw.get("password_hash") or ""),
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
    raw = acct.get("resources")
    return [str(x) for x in raw] if isinstance(raw, list) else []


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


def _auth_is_claimed(auth_cfg: dict) -> bool:
    """Whether this auth mapping already has a usable credential."""
    if not isinstance(auth_cfg, dict):
        return False
    if auth_cfg.get("password_hash"):
        return True
    return _cfg_text(auth_cfg.get("password") or "") not in ("", "change-me")


def setup_required() -> bool:
    return not _auth_is_claimed(_auth_cfg())


def suggested_setup_username() -> str:
    """First-run username for GET /api/auth/status.  Must be JSON-encodable."""
    raw = _cfg_text(_auth_cfg().get("username") or "admin").strip() or "admin"
    return raw if _utf8_ok(raw) else "admin"


def auth_enabled() -> bool:
    """Authentication is mandatory after setup.

    ServerHub exposes host/container administration and may be routed through a
    public tunnel.  Treating a config toggle as anonymous trust turns one
    settings change into remote code execution, so established installations
    can no longer disable authentication.
    """
    return not setup_required()


def _drop_leftover_nonfile(path: Path) -> None:
    """Unlink a leftover directory/socket occupying a token path."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError:
        return
    if stat.S_ISREG(st.st_mode):
        return
    try:
        if stat.S_ISDIR(st.st_mode):
            os.rmdir(path)
        else:
            os.unlink(path)
    except OSError:
        pass


def _read_capped_bytes(path: Path, cap: int) -> bytes:
    """Read at most *cap* bytes.  Leftover multi-MB secrets used to OOM login."""
    with path.open("rb") as fh:
        data = fh.read(cap + 1)
    if not data or len(data) > cap:
        return b""
    return data


def _persistent_token(path: Path) -> str:
    """Read or atomically create a mode-0600 random bearer token."""
    try:
        value = read_text_capped(path, _TOKEN_CAP, encoding="utf-8").strip()
        if value:
            path.chmod(0o600)
            return value
    except FileNotFoundError:
        pass
    except (OSError, UnicodeDecodeError):
        try:
            path.unlink()
        except OSError:
            _drop_leftover_nonfile(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    value = secrets.token_urlsafe(32)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(value + "\n")
        return value
    except FileExistsError:
        try:
            return read_text_capped(path, _TOKEN_CAP, encoding="utf-8").strip()
        except (OSError, UnicodeDecodeError):
            return value


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
    mode = _cfg_text((_auth_cfg() or {}).get("setup_token_mode") or "auto").strip().lower()
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


def _addr_in_trusted_proxy(addr) -> bool:
    return any(addr in net for net in trusted_proxy_networks())


def _peer_in_trusted_proxy(peer: str) -> bool:
    try:
        addr = ipaddress.ip_address(peer)
    except ValueError:
        return False
    return _addr_in_trusted_proxy(addr)


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


def _forwarded_hops(request: Request) -> list[str]:
    hops: list[str] = []
    xff = (request.headers.get("x-forwarded-for") or "").strip()
    if xff:
        hops.extend(part.strip() for part in xff.split(",") if part.strip())
    for element in (request.headers.get("forwarded") or "").split(","):
        for param in element.split(";"):
            key, _, value = param.partition("=")
            if key.strip().lower() == "for" and value.strip():
                hops.append(value.strip())
    return hops


def _rightmost_untrusted_ip(hops: list[str]) -> str:
    """The hop the trusted proxy actually accepted.

    ``203.0.113.9, 127.0.0.1`` is nginx appending itself — skip the
    trusted tail.  ``6.6.6.6, 198.51.100.7`` is a spoofed prefix plus
    the address the proxy saw; the first hop is attacker-controlled.
    """
    for hop in reversed(hops):
        parsed = _as_ip(hop)
        if not parsed:
            continue
        try:
            addr = ipaddress.ip_address(parsed)
        except ValueError:
            continue
        # Classify hops against the configured CIDRs, not the TCP-peer
        # helper: tests (and callers) mock ``_peer_in_trusted_proxy`` to
        # stand in for a non-IP transport peer such as TestClient.
        if _addr_in_trusted_proxy(addr):
            continue
        return parsed
    return ""


def _parse_forwarded_client(request: Request) -> str:
    """Original client from proxy headers. Empty when none are a valid IP.

    ``X-Forwarded-For`` is consulted first: nginx appends the real hop and
    does not overwrite a client-supplied ``CF-Connecting-IP``. Preferring
    Cloudflare's header let anyone behind a trusted reverse proxy mint a
    fresh login-rate-limit bucket per request. Cloudflared still works —
    it usually sends the same address on both headers, and when XFF is
    absent the Cloudflare header is still used.
    """
    parsed = _rightmost_untrusted_ip(_forwarded_hops(request))
    if parsed:
        return parsed
    parsed = _as_ip((request.headers.get("cf-connecting-ip") or "").strip())
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
        # Re-check the on-disk snapshot inside set_password's mutate: the
        # in-process lock above cannot see a sibling ServerHub that just
        # claimed.  Without only_if_unclaimed, both processes hashed, both
        # wrote, and both returned True — last writer won the password,
        # both browsers got admin sessions.
        if not set_password(password, username, enable=True, only_if_unclaimed=True):
            return False
        consume_setup_token()
        return True


def local_client_token() -> str:
    """Bearer token used only by the loopback menu-bar client."""
    return _persistent_token(LOCAL_TOKEN_FILE)


def local_client_authenticated(request: Request) -> bool:
    """Menu-bar token is only valid from a direct loopback hop.

    Cloudflare Tunnel and nginx terminate on 127.0.0.1, so TCP-peer
    loopback plus a copied ``.local-client-token`` used to unlock
    ``POST /api/action`` for a tunneled visitor.  Same bar as the
    setup-token path: proxy-hint headers or a public Host fail closed.
    """
    supplied = request.headers.get(LOCAL_TOKEN_HEADER, "")
    return (
        is_direct_loopback(request)
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
    # A member sees a trimmed dashboard, their assigned services, and their own
    # account page — nothing else.  /api/launcher is admin-only (install paths,
    # LaunchAgent registration state, and four subprocesses per call); the
    # member UI never requests it, so it stays off the whitelist.
    if path in {"/api/health", "/api/status", "/api/services"}:
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
    derived = hashlib.scrypt(_utf8(password), salt=salt, n=n, r=r, p=p, dklen=32)
    return "scrypt${}${}${}${}${}".format(
        n, r, p,
        base64.urlsafe_b64encode(salt).decode().rstrip("="),
        base64.urlsafe_b64encode(derived).decode().rstrip("="),
    )


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _verify_scrypt(encoded: str, password: str) -> bool:
    """Whether *password* matches one ``scrypt$…`` digest string."""
    try:
        _, ns, rs, ps, salt_s, expected_s = encoded.split("$", 5)
        actual = hashlib.scrypt(
            _utf8(password), salt=_b64decode(salt_s),
            n=int(ns), r=int(rs), p=int(ps), dklen=32,
        )
        return hmac.compare_digest(actual, _b64decode(expected_s))
    except (ValueError, TypeError, OverflowError):
        return False


def verify_password(password: str) -> bool:
    a = _auth_cfg()
    encoded = _cfg_text(a.get("password_hash") or "")
    if encoded.startswith("scrypt$"):
        return _verify_scrypt(encoded, password)
    legacy = _cfg_text(a.get("password") or "")
    return bool(legacy and legacy != "change-me" and constant_time_equals(password, legacy))


#: Burned when a login names an unknown account, so "no such user" costs the
#: same scrypt evaluation as "wrong password" and response timing does not
#: enumerate usernames.  Random per process: it can never match anything.
_DUMMY_HASH: str | None = None


def _dummy_hash() -> str:
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password(secrets.token_urlsafe(24))
    return _DUMMY_HASH


def verify_account_password(username: str | None, password: str) -> bool:
    """Whether *password* is *username*'s own panel password.

    Unlike :func:`verify_password` (which only ever checks the legacy
    administrator credential) this verifies against the account's individual
    hash, so member sign-ins do not share the administrator's secret.  An
    unknown username still performs one scrypt evaluation against a dummy
    digest, keeping its timing indistinguishable from a wrong password.
    """
    acct = account(username)
    if not acct:
        _verify_scrypt(_dummy_hash(), password)
        return False
    encoded = _cfg_text(acct.get("password_hash") or "")
    if encoded.startswith("scrypt$"):
        return _verify_scrypt(encoded, password)
    # Only the legacy admin pair may carry a plaintext password from very old
    # configs; accounts-list entries are always created hashed.
    if str(acct.get("role")) == ROLE_ADMIN:
        legacy = _cfg_text(_auth_cfg().get("password") or "")
        return bool(
            legacy and legacy != "change-me" and constant_time_equals(password, legacy)
        )
    return False


def set_password(
    password: str,
    username: str = "admin",
    *,
    enable: bool = True,
    only_if_unclaimed: bool = False,
) -> bool:
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
    if ":" in resolved or not _valid_username(resolved):
        raise ValueError("bad_username")
    wrote = True

    def apply(data: dict) -> None:
        nonlocal wrote
        settings, auth = _auth_block(data)
        if only_if_unclaimed and _auth_is_claimed(auth):
            wrote = False
            return
        auth.update({
            "enabled": bool(enable),
            "username": resolved,
            "password_hash": digest,
        })
        auth.pop("password", None)
        settings["auth"] = auth

    config_mutate(apply)
    return wrote


# ── panel accounts (multi-user) ──────────────────────────────────────────────
# CRUD over the ``settings.auth.accounts`` list.  The legacy admin pair
# (``settings.auth.username``/``password_hash``) is left where it is: it keeps
# old sessions verifying, and accounts() already presents it as the admin.
# Every writer below raises ValueError with a stable reason string; the router
# maps those to namespaced API error codes.

#: Same shape the credentials store enforces: human-typable, shell-safe, and
#: unambiguous in audit lines.  ``|`` is excluded by construction, so session
#: payload parsing never meets its separator inside a new account name.
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,63}$")
#: A family panel with dozens of accounts is misconfiguration, not scale.
MAX_ACCOUNTS = 32


def _valid_username(name: str) -> bool:
    return bool(USERNAME_RE.match(name))


def _clean_resources(resources) -> list[str]:
    """Resource ids that Starlette can JSON-encode.  Leftover inf / ``\\ud800`` 500'd create."""
    if not isinstance(resources, list):
        return []
    out = []
    for raw in resources:
        text = str(raw).strip()
        if text and _utf8_ok(text):
            out.append(text)
    return out


def create_account(
    username: str,
    password: str,
    *,
    role: str = ROLE_MEMBER,
    resources: list[str] | None = None,
) -> dict:
    """Add one account to ``settings.auth.accounts`` and return its public view."""
    name = str(username or "").strip()
    if not _valid_username(name):
        raise ValueError("bad_username")
    if role not in ROLES:
        raise ValueError("bad_role")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError("password_too_short")
    digest = hash_password(password)
    clean_resources = _clean_resources(resources)

    def apply(data: dict) -> None:
        settings, auth_cfg = _auth_block(data)
        entries = _account_rows(auth_cfg)
        taken = {_cfg_text(e.get("username") or "").strip().lower() for e in entries}
        legacy = _cfg_text(auth_cfg.get("username") or "").strip().lower()
        if name.lower() in taken or (legacy and name.lower() == legacy):
            raise ValueError("exists")
        if len(entries) >= MAX_ACCOUNTS:
            raise ValueError("too_many")
        entries.append({
            "username": name,
            "password_hash": digest,
            "role": role,
            "resources": clean_resources,
        })
        auth_cfg["accounts"] = entries
        settings["auth"] = auth_cfg

    config_mutate(apply)
    return {"username": name, "role": role, "resources": clean_resources}


def set_account_resources(username: str, resources: list[str]) -> list[str]:
    """Replace a member account's resource grants (admins are unrestricted)."""
    name = str(username or "").strip()
    acct = account(name)
    if not acct:
        raise ValueError("not_found")
    if str(acct.get("role")) == ROLE_ADMIN:
        raise ValueError("not_member")
    clean = _clean_resources(resources)

    def apply(data: dict) -> None:
        settings, auth_cfg = _auth_block(data)
        entries = _account_rows(auth_cfg)
        for entry in entries:
            if _cfg_text(entry.get("username") or "") == name:
                entry["resources"] = clean
        auth_cfg["accounts"] = entries
        settings["auth"] = auth_cfg

    config_mutate(apply)
    return clean


def set_account_password(username: str, password: str) -> None:
    """Rotate one account's own password hash.

    The legacy admin pair is written through :func:`set_password` (same
    fields it has always lived in); an accounts-list entry is rewritten in
    place.  Either way the account's session version changes with the hash,
    so every outstanding session for that account stops verifying.
    """
    name = str(username or "").strip()
    acct = account(name)
    if not acct:
        raise ValueError("not_found")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError("password_too_short")
    in_accounts_list = any(
        _cfg_text(raw.get("username") or "").strip() == name
        for raw in _account_rows(_auth_cfg())
    )
    if not in_accounts_list:
        # Only the legacy admin exists outside the accounts list.
        set_password(password, name, enable=True)
        return
    digest = hash_password(password)

    def apply(data: dict) -> None:
        settings, auth_cfg = _auth_block(data)
        entries = _account_rows(auth_cfg)
        for entry in entries:
            if _cfg_text(entry.get("username") or "").strip() == name:
                entry["password_hash"] = digest
        auth_cfg["accounts"] = entries
        settings["auth"] = auth_cfg

    config_mutate(apply)


def delete_account(username: str) -> None:
    """Remove one member account.  Admins cannot be deleted through here.

    Existing sessions die on their own: verify_session requires membership in
    accounts(), and the deleted name no longer resolves.
    """
    name = str(username or "").strip()
    acct = account(name)
    if not acct:
        raise ValueError("not_found")
    if str(acct.get("role")) == ROLE_ADMIN:
        raise ValueError("not_member")

    def apply(data: dict) -> None:
        settings, auth_cfg = _auth_block(data)
        entries = [
            e for e in _account_rows(auth_cfg)
            if _cfg_text(e.get("username") or "").strip() != name
        ]
        auth_cfg["accounts"] = entries
        # Drop the logout counter too: a recreated account with the same name
        # must not inherit a stale epoch that predates it.
        epochs = _clean_epochs(auth_cfg.get("session_epochs"))
        epochs.pop(name, None)
        auth_cfg["session_epochs"] = epochs
        settings["auth"] = auth_cfg

    config_mutate(apply)


#: (path, mtime_ns, value) — verify_session runs 2-3 times per request, and each
#: run open()+read() the same 32 bytes from disk.  The stat-validated cache cuts
#: that to one stat per call while still noticing a replaced file (tests point
#: SECRET_FILE at throwaway dirs; nothing in production ever rewrites it).
_secret_cache: tuple[str, int, bytes] | None = None


def _secret() -> bytes:
    """32-byte HMAC key.  A leftover directory or unreadable file must not 500."""
    global _secret_cache
    path = SECRET_FILE
    try:
        st = os.stat(path)
        cached = _secret_cache
        if cached and cached[0] == str(path) and cached[1] == st.st_mtime_ns:
            return cached[2]
        if stat.S_ISREG(st.st_mode):
            try:
                value = _read_capped_bytes(path, _SECRET_CAP)
            except OSError:
                value = b""
            if value:
                _secret_cache = (str(path), st.st_mtime_ns, value)
                return value
        try:
            path.unlink()
        except OSError:
            pass
    except FileNotFoundError:
        pass
    except OSError:
        try:
            path.unlink()
        except OSError:
            pass

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    # Reuse a process-local fallback for this path: leftover huge/unreadable
    # files take FileExistsError after unlink, and minting a new key here
    # used to make create_session then verify_session disagree.
    cached = _secret_cache
    if cached and cached[0] == str(path):
        return cached[2]
    value = secrets.token_bytes(32)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(value)
        _secret_cache = (str(path), os.stat(path).st_mtime_ns, value)
        return value
    except FileExistsError:
        try:
            existing = _read_capped_bytes(path, _SECRET_CAP)
            if existing:
                _secret_cache = (str(path), os.stat(path).st_mtime_ns, existing)
                return existing
        except OSError:
            pass
    except OSError:
        pass
    # Leftover directory / no permission: process-local key so login/status
    # stay up; cookies issued this way last until restart.  Cache against the
    # leftover node's mtime so create_session then verify_session agree.
    try:
        mtime = os.stat(path).st_mtime_ns
    except OSError:
        mtime = 0
    _secret_cache = (str(path), mtime, value)
    return value


def _session_epoch(username: str) -> int:
    """Per-account logout counter.  Bumping it invalidates that account's
    outstanding tokens without a server-side session store.

    Matches on the *normalised* key, not ``epochs.get(username)``: a YAML
    round-trip stores a numeric account name as an int key (``2024: 5``) and
    the strict string lookup read 0 for it, so logout-everywhere silently
    stopped revoking that account's tokens.  When both spellings exist the
    larger counter wins, same rule as :func:`_clean_epochs`.  A leftover
    hex int past the digit cap reads as 1 via :func:`_epoch_count` — it
    used to 500 the f-string in ``account_session_version`` on every login
    and pending-TOTP token.
    """
    epochs = _auth_cfg().get("session_epochs")
    if not isinstance(epochs, dict):
        return 0
    target = str(username)
    matches = [
        _epoch_count(v) for k, v in epochs.items() if _epoch_key(k) == target
    ]
    return max(matches) if matches else 0


def bump_session_epoch(username: str) -> None:
    """Revoke every existing session for *username* (logout-everywhere).

    A stateless HMAC token cannot be individually revoked, so "logout" used to
    only drop the cookie — a captured token stayed valid for its full 7-day
    TTL.  Folding this counter into the signed version means one increment
    invalidates all of the account's tokens at once, which is what logout now
    does.
    """
    def apply(data: dict) -> None:
        settings = data.get("settings")
        if not isinstance(settings, dict):
            settings = {}
            data["settings"] = settings
        auth = settings.get("auth")
        auth = dict(auth) if isinstance(auth, dict) else {}
        raw_epochs = auth.get("session_epochs")
        epochs = _clean_epochs(raw_epochs)
        # The normalised (str-probed) counter, not raw_epochs.get(username):
        # an int-keyed leftover for a numeric account name was invisible to
        # the strict lookup, so the bump wrote a *lower* string-keyed copy
        # beside it and the revocation the counter recorded was lost.  An
        # unrenderable leftover reads back as 1 (_epoch_count), so the bump
        # lands past it — yaml.safe_dump of the huge int used to 500 TOTP
        # confirm before _clean_epochs pinned it.
        nxt = epochs.get(str(username), 0) + 1
        try:
            str(nxt)
        except ValueError:
            nxt = 2
        epochs[username] = nxt
        auth["session_epochs"] = epochs
        settings["auth"] = auth

    config_mutate(apply)


def account_session_version(username: str) -> str:
    """Version stamp tying a session to one account's current credential.

    Per account, not global: with a single shared stamp, rotating the admin
    password would sign every family member out, and a member's own rotation
    could not invalidate their sessions.  For the admin this is still derived
    from ``password_hash``, so cookies issued before multi-account support keep
    verifying and nobody is logged out by the upgrade.

    The logout epoch is appended only once it is non-zero, so cookies issued
    before the first logout on an upgraded install keep verifying unchanged.
    """
    acct = accounts().get(username) or {}
    basis = str(acct.get("password_hash") or "legacy")
    epoch = _session_epoch(username)
    if epoch:
        basis = f"{basis}|{epoch}"
    return hashlib.sha256(_utf8(basis)).hexdigest()[:16]


def _session_payload(username: str, exp: int, version: str) -> bytes:
    return f"{username}|{exp}|{version}".encode("utf-8", "surrogatepass")


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


def _now() -> int:
    """Finite unix timestamp. Leftover ``time.time() = inf`` OverflowError'd login."""
    try:
        return int(time.time())
    except (TypeError, ValueError, OverflowError):
        return 0


def create_session(username: str) -> str:
    exp = _now() + SESSION_TTL
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
        username, exp_s, version = _parse_session_payload(
            payload.decode("utf-8", "surrogatepass")
        )
        # Membership in the account registry, not equality with one name: that
        # comparison is what made a second account impossible.  An unknown name
        # still has no account and so still has no version to match.
        if username not in accounts():
            return False
        # constant_time_equals: hmac.compare_digest on str TypeErrors a
        # leftover non-ASCII version field and 500'd every cookie check.
        return int(exp_s) > time.time() and constant_time_equals(
            version, account_session_version(username)
        )
    except (ValueError, UnicodeDecodeError, TypeError, OSError, OverflowError):
        return False


def browser_authenticated(request: Request) -> bool:
    return verify_session(request.cookies.get(COOKIE_NAME))


#: Lifetime of the half-signed-in state between "password accepted" and "TOTP
#: code accepted".  Short on purpose: it exists only to bridge the two form
#: steps, and everything it can do is present one more code attempt.
PENDING_TOTP_TTL = 300
#: Marker keeping pending tokens and session tokens in disjoint namespaces.
#: A session payload starts with an account name, and account names are the
#: config operator's choice — the fixed prefix (with its separator) is what a
#: name would have to *contain* to collide, so the two verifiers can never
#: accept each other's tokens by accident.
_PENDING_TOTP_MARK = "totp-pending"


def create_pending_totp_token(username: str) -> str:
    """Signed proof that *username* just passed the password check.

    Handed to the browser instead of a session cookie when the account has
    TOTP enabled.  It is not a session: no route accepts it except the
    second-step verifier.  The account's session version is baked in, so a
    password rotation or logout-everywhere invalidates outstanding pending
    tokens exactly like it invalidates sessions.
    """
    exp = _now() + PENDING_TOTP_TTL
    payload = "|".join(
        (_PENDING_TOTP_MARK, username, str(exp), account_session_version(username))
    ).encode("utf-8", "surrogatepass")
    sig = hmac.new(_secret(), payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(payload + b"." + sig).decode().rstrip("=")


def pending_totp_username(token: str | None) -> str:
    """Account named by a valid, unexpired pending-TOTP token, or ""."""
    if not token:
        return ""
    try:
        split = _split_signed(_b64decode(token))
        if split is None:
            return ""
        payload, sig = split
        if not hmac.compare_digest(sig, hmac.new(_secret(), payload, hashlib.sha256).digest()):
            return ""
        text = payload.decode("utf-8", "surrogatepass")
        mark, _, rest = text.partition("|")
        if mark != _PENDING_TOTP_MARK or not rest:
            return ""
        # Right-split, same reasoning as _parse_session_payload: exp and
        # version never contain "|", a username theoretically may.
        username, exp_s, version = rest.rsplit("|", 2)
        if username not in accounts():
            return ""
        if int(exp_s) <= time.time():
            return ""
        if not constant_time_equals(version, account_session_version(username)):
            return ""
        return username
    except (ValueError, UnicodeDecodeError, TypeError, OSError, OverflowError):
        return ""


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
        return _parse_session_payload(split[0].decode("utf-8", "surrogatepass"))[0]
    except (ValueError, UnicodeDecodeError, TypeError, OSError, OverflowError):
        return ""


def request_username(request: Request) -> str:
    """Best-effort identity of the caller, for audit logs and member filtering.

    Browser sessions carry the account name.  A request authenticated by a
    *member* API key reports the synthetic identity ``key:<name>``: it is not
    an account, so every account lookup on it fails closed to "member with no
    resources" — which is exactly the key's authority — and the routes that
    filter listings for member sessions therefore filter member keys the same
    way instead of mistaking the empty username for an administrator.

    An *admin* API key deliberately stays "", mirroring how basic-auth admin
    requests have always looked to this function: unrestricted role, no
    per-account state.
    """
    username = session_username(request.cookies.get(COOKIE_NAME))
    if username:
        return username
    record = getattr(request.state, "serverhub_api_key", None)
    if isinstance(record, dict) and record.get("role") != ROLE_ADMIN:
        # The ":" makes this synthetic identity unrepresentable as an account:
        # USERNAME_RE refuses colons at creation and accounts() drops any
        # hand-written name containing one, so ``key:<x>`` can never resolve
        # to an account record and inherit its resources.
        return f"key:{record.get('name') or record.get('id') or 'unknown'}"
    return ""


def request_client(request: Request | None) -> str:
    """Peer address used for the login rate-limit bucket and audit lines.

    Trust model, from the outside in:

    * A *non-loopback* direct peer is its own answer.  Whatever
      ``X-Forwarded-For`` it sends is attacker-controlled text and is ignored
      — honouring it would let one remote client mint a fresh bucket per
      request and sidestep :func:`login_allowed` entirely.
    * A *loopback* direct peer is, in this deployment, a local reverse proxy
      (cloudflared or nginx terminate TLS on this machine and speak plain
      HTTP to the panel).  Without the forwarded header every proxied visitor
      collapses into one shared 127.0.0.1 bucket, so a single flaky client
      locks the whole family out for five minutes.  Only then is the *last*
      hop of ``X-Forwarded-For`` believed: that element was appended by the
      trusted local proxy and names the peer it actually accepted, while any
      earlier elements remain client-supplied noise.

    This is deliberately only a reporting/bucketing identity.  Authorisation
    decisions that key on loopback (setup-token disclosure, the menu-bar
    token) keep reading ``request.client.host`` directly — a forwarded header
    must never make a remote caller *more* trusted.
    """
    host = (request.client.host if request and request.client else "") or "unknown"
    if host not in LOOPBACK_HOSTS:
        return host
    forwarded = request.headers.get("x-forwarded-for") or ""
    last_hop = forwarded.rsplit(",", 1)[-1].strip()
    # Bounded so a local caller cannot bloat the attempt table or the audit
    # trail with an arbitrarily long fabricated value.
    return last_hop[:64] or host


def _sweep_login_attempts(now: float) -> None:
    """Forget buckets whose whole window has passed.  Caller holds the lock.

    :func:`login_allowed` prunes only the bucket it was asked about, so a
    client that never comes back leaves its entry behind for good.  That is
    harmless for a household, but the key is the peer address a trusted local
    proxy reports, and a caller on an IPv6 /64 can spend a fresh address per
    request: without this the table is a write-only record of every address
    that ever reached the login form.

    A bucket is dropped only when even its newest attempt has aged out, which
    is exactly when ``login_allowed`` would have emptied it on the next visit.
    A clock that stepped backwards makes the age negative, so the sweep keeps
    the bucket rather than handing back attempts someone is still spending.
    """
    if len(_login_attempts) <= _LOGIN_SWEEP_AT:
        return
    for client, attempts in list(_login_attempts.items()):
        if not attempts or now - attempts[-1] >= _LOGIN_WINDOW:
            del _login_attempts[client]


def login_allowed(client: str, *, consume: bool = True) -> tuple[bool, int]:
    """Return whether *client* may try another login.

    The slot is reserved under the same lock as the check (``consume=True``,
    the login/TOTP route).  Checking then incrementing on failure let N
    concurrent attempts all see ``< 5`` and all proceed; the 5/300s cap
    only applied after they finished.  A successful sign-in still clears
    the bucket via :func:`clear_login_failures`.
    """
    now = time.time()
    with _login_lock:
        _sweep_login_attempts(now)
        attempts = [t for t in _login_attempts.get(client, []) if now - t < _LOGIN_WINDOW]
        if attempts:
            _login_attempts[client] = attempts
        else:
            _login_attempts.pop(client, None)
        if len(attempts) >= 5:
            return False, max(1, int(_LOGIN_WINDOW - (now - attempts[0])))
        if consume:
            _login_attempts.setdefault(client, []).append(now)
        return True, 0


def release_login_reservation(client: str) -> None:
    """Drop the slot reserved by this request, keep earlier failures.

    Used when the password was accepted but the sign-in is not finished
    (TOTP still required).  Clearing the whole bucket here would reset the
    code-guessing budget; leaving the reservation would spend one of the
    five slots on a successful password.
    """
    with _login_lock:
        attempts = _login_attempts.get(client)
        if not attempts:
            return
        attempts.pop()
        if not attempts:
            _login_attempts.pop(client, None)


def record_login_failure(client: str) -> None:
    """Keep a failure that was not reserved by :func:`login_allowed`.

    Login routes reserve the slot on the way in, so they must not call
    this or a single miss would count twice.  Tests and any caller that
    only saw the failure after the fact still use this.
    """
    with _login_lock:
        _login_attempts.setdefault(client, []).append(time.time())


def clear_login_failures(client: str) -> None:
    with _login_lock:
        _login_attempts.pop(client, None)


def _bearer_token(request: Request) -> str:
    """The value of an ``Authorization: Bearer …`` header, or ""."""
    header = request.headers.get("authorization") or ""
    scheme, _, value = header.partition(" ")
    if scheme.strip().lower() != "bearer":
        return ""
    return value.strip()


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
    # API keys (Authorization: Bearer shk_..., see hub/api_keys.py) for scripts
    # and monitoring.  Handled entirely here and *only* here: routes that demand
    # a browser session — require_admin_browser and the per-router
    # _require_admin_browser guards, plus the terminal/VM-console WebSockets —
    # verify the session cookie itself, and a bearer header can never produce
    # one.  That boundary is deliberate and load-bearing: an API key must not
    # reach the browser-only high-risk surfaces (interactive terminals, shares/
    # launcher mutations, key management), no matter its role.  The local-client
    # and setup tokens above/below are separate mechanisms and stay untouched.
    supplied_bearer = _bearer_token(request)
    if api_keys.looks_like_key(supplied_bearer):
        record = api_keys.verify(supplied_bearer)
        if record is None:
            # Shaped like one of our keys but unknown, revoked or expired: say
            # so instead of the generic login_required, which reads like "add a
            # cookie" to the script author debugging it.
            raise api_error("auth.bad_api_key")
        request.state.serverhub_api_key = record
        if str(record.get("role")) == ROLE_ADMIN:
            request.state.serverhub_auth_kind = "api-key-admin"
            return True
        # Member keys reuse the member-session authorisation verbatim.  The
        # synthetic identity has no account record, so the resource list is
        # empty and every resource-gated route fails closed, exactly like a
        # member account that has been granted nothing.
        if member_request_authorized(request, request_username(request)):
            request.state.serverhub_auth_kind = "api-key-member"
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
        legacy_name = _cfg_text(_auth_cfg().get("username") or "admin").strip() or "admin"
        if verify_account_password(credentials.username, credentials.password) and (
            is_admin(credentials.username)
            or constant_time_equals(credentials.username, legacy_name)
        ):
            request.state.serverhub_auth_kind = "basic-admin"
            return True
    if local_client:
        raise api_error("auth.admin_required")
    raise api_error("auth.login_required")
