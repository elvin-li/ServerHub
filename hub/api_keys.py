"""Bearer API keys for scripts and monitoring — hashed at rest, role-scoped.

Key string: ``shk_`` + 32 random bytes (urlsafe base64), shown exactly once in
the create response.  At rest only the SHA-256 digest is kept: the plaintext is
43 chars of CSPRNG output, so a plain digest already puts recovery beyond
reach and — unlike a password — needs no KDF stretching.  The store is
``data/api-keys.json``, written 0600-at-creation through :mod:`hub.secure_io`
(same arrangement as notify-credentials.json).

Every key carries one of the two existing roles (``admin`` / ``member``) and
authorisation reuses the exact same code paths as the matching session role in
:func:`hub.auth.require_auth`; this module never grows its own permission
model.  Keys deliberately do **not** satisfy the stricter browser-session
guards (``require_admin_browser`` and friends) or the WebSocket endpoints —
those verify the session cookie itself, which a bearer header cannot produce.

``last_used`` is tracked but persisted at most once per
:data:`LAST_USED_PERSIST_SECONDS` per key, so a monitoring loop polling every
few seconds does not turn each request into a disk write; the in-memory value
stays fresh for the management listing either way.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time

from hub import secure_io
from hub.paths import DATA_DIR

#: Module-level so tests can point it at a scratch directory.
STORE_FILE = DATA_DIR / "api-keys.json"
_lock = threading.Lock()

PREFIX = "shk_"
#: Roles a key may carry; values must stay equal to hub.auth.ROLES.  A literal
#: tuple rather than an import: hub.auth imports this module for require_auth,
#: so importing hub.auth back at module level would be circular.
VALID_ROLES = ("admin", "member")
#: Hard cap on stored keys.  There is no legitimate reason for hundreds; a
#: bound keeps the file (read on the request path) small.
MAX_KEYS = 50
MAX_NAME_LENGTH = 64
#: Floor between two persisted ``last_used`` stamps for one key.
LAST_USED_PERSIST_SECONDS = 3600

#: Process-local freshness for the management listing between throttled disk
#: writes.  {key id: epoch seconds}.
_last_seen: dict[str, int] = {}


def _digest(token: str) -> str:
    return hashlib.sha256(str(token).encode("utf-8")).hexdigest()


def _load() -> list[dict]:
    try:
        raw = json.loads(STORE_FILE.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []
    keys = raw.get("keys") if isinstance(raw, dict) else None
    return [k for k in (keys or []) if isinstance(k, dict)]


def _save(keys: list[dict]) -> None:
    secure_io.replace_secret_text(
        STORE_FILE, json.dumps({"keys": keys}, ensure_ascii=False, indent=2) + "\n"
    )


def looks_like_key(token: str | None) -> bool:
    """Cheap shape test so require_auth only pays for real candidates."""
    return bool(token) and str(token).startswith(PREFIX)


def public_view(record: dict) -> dict:
    """Listing entry: everything except the digest."""
    kid = str(record.get("id") or "")
    stored = record.get("last_used")
    seen = _last_seen.get(kid)
    last_used = max(int(stored or 0), int(seen or 0)) or None
    return {
        "id": kid,
        "name": str(record.get("name") or ""),
        "role": str(record.get("role") or "member"),
        "created": record.get("created"),
        "expires": record.get("expires"),
        "last_used": last_used,
    }


def list_public() -> list[dict]:
    with _lock:
        return [public_view(k) for k in _load()]


def create(name: str, role: str, *, expires_days: int | None = None) -> tuple[dict, str]:
    """Mint a key.  Returns (public record, plaintext) — the only plaintext ever.

    Raises ValueError with a short reason code; the router maps those onto
    the stable API error codes.
    """
    cleaned = str(name or "").strip()
    if not cleaned or len(cleaned) > MAX_NAME_LENGTH:
        raise ValueError("bad_name")
    if role not in VALID_ROLES:
        raise ValueError("bad_role")
    expires: int | None = None
    if expires_days is not None:
        try:
            days = int(expires_days)
        except (TypeError, ValueError):
            raise ValueError("bad_expiry")
        if not 1 <= days <= 3650:
            raise ValueError("bad_expiry")
        expires = int(time.time()) + days * 86400
    token = PREFIX + secrets.token_urlsafe(32)
    record = {
        "id": "ak_" + secrets.token_hex(6),
        "name": cleaned,
        "role": role,
        "digest": _digest(token),
        "created": int(time.time()),
        "expires": expires,
        "last_used": None,
    }
    with _lock:
        keys = _load()
        if len(keys) >= MAX_KEYS:
            raise ValueError("too_many")
        keys.append(record)
        _save(keys)
    return public_view(record), token


def revoke(key_id: str) -> dict | None:
    """Remove one key; returns its public view, or None when unknown."""
    with _lock:
        keys = _load()
        for index, record in enumerate(keys):
            if str(record.get("id")) == str(key_id):
                del keys[index]
                _save(keys)
                _last_seen.pop(str(key_id), None)
                return public_view(record)
    return None


def verify(token: str | None) -> dict | None:
    """Resolve a presented bearer token to its key record, or None.

    Constant-time digest comparison against *every* stored key (no early
    exit), expiry enforced here so callers cannot forget it.  A hit updates
    ``last_used`` in memory always, on disk at most once per
    :data:`LAST_USED_PERSIST_SECONDS`.
    """
    if not looks_like_key(token):
        return None
    supplied = _digest(str(token))
    now = int(time.time())
    with _lock:
        keys = _load()
        hit: dict | None = None
        for record in keys:
            if hmac.compare_digest(str(record.get("digest") or ""), supplied):
                hit = record
        if hit is None:
            return None
        expires = hit.get("expires")
        if expires and now >= int(expires):
            return None
        kid = str(hit.get("id") or "")
        _last_seen[kid] = now
        stored = int(hit.get("last_used") or 0)
        if now - stored >= LAST_USED_PERSIST_SECONDS:
            hit["last_used"] = now
            try:
                _save(keys)
            except OSError:
                # A full disk must not fail authentication that already passed.
                pass
        return public_view(hit)
