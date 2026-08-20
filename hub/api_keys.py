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

import fcntl
import hashlib
import hmac
import json
import os
import secrets
import stat
import threading
import time
from contextlib import contextmanager

from hub import secure_io
from hub.paths import DATA_DIR
from hub.util import read_text_capped

#: Module-level so tests can point it at a scratch directory.
STORE_FILE = DATA_DIR / "api-keys.json"
#: Leftover multi-MB store used to OOM every Bearer-authenticated request.
_STORE_CAP = 256 * 1024
_lock = threading.Lock()


def _drop_leftover_nonfile(path) -> None:
    """Unlink a leftover directory/socket occupying the store path."""
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


def _lock_fd(lock_path) -> int | None:
    """flock fd, or None when a leftover node / EIO blocks creating it."""
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            st = os.lstat(lock_path)
        except FileNotFoundError:
            st = None
        if st is not None and not stat.S_ISREG(st.st_mode):
            try:
                if stat.S_ISDIR(st.st_mode):
                    os.rmdir(lock_path)
                else:
                    os.unlink(lock_path)
            except OSError:
                return None
        return os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError:
        return None


@contextmanager
def _file_lock():
    """Exclusive cross-process lock around every read-modify-write of the store.

    ``_lock`` only serialises writers inside one interpreter, and this file can
    be shared by two ServerHub processes (packaged .app + LaunchAgent panel,
    the deployment hub/config.py documents).  Without a kernel-arbitrated lock,
    ``verify``'s throttled last_used write-back can race a concurrent
    ``revoke``/``create`` in the other process and rewrite the store from its
    stale snapshot — silently resurrecting a key that was just revoked.  Same
    pattern as ``config._file_lock``: a separate ``.lock`` file, because the
    atomic replace in secure_io swaps the store's inode.

    A leftover directory named ``api-keys.json.lock``, or EIO creating it,
    must not 500 Bearer auth / key management — fall back to the in-process
    lock for that call.
    """
    lock_path = STORE_FILE.with_name(STORE_FILE.name + ".lock")
    fd = _lock_fd(lock_path)
    if fd is None:
        yield
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)

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
    return hashlib.sha256(str(token).encode("utf-8", "surrogatepass")).hexdigest()


def _utf8_text(value) -> str:
    """JSON-encodable text.  Leftover bytes / ``\\ud800`` must not 500 dumps."""
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    try:
        text = str(value)
    except RecursionError:
        try:
            return type(value).__name__
        except Exception:
            return ""
    except Exception:
        return ""
    return text.encode("utf-8", "replace").decode("utf-8")


def _json_safe(value, depth: int = 0):
    """Re-serializable leftover api-keys.json row (allow_nan=False, UTF-8).

    Extra ``1e309`` / NaN / bytes / lone-surrogate fields used to ValueError
    ``json.dumps`` on create, revoke, and the throttled last_used write —
    every Bearer request after a poisoned store.
    """
    if depth > 32:
        return None
    if isinstance(value, dict):
        return {_utf8_text(k): _json_safe(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(v, depth + 1) for v in value]
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if isinstance(value, str):
        return _utf8_text(value)
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 create / revoke / Bearer.
            return _json_safe(iso(), depth + 1)
        except Exception:
            return None
    return _utf8_text(value)


def _persistable_record(record: dict) -> dict:
    """Finite stamps only — ``Infinity`` in JSON is not JSON, and a later
    ``_load`` of it used to drop the whole store (every key 401)."""
    row = dict(record)
    for field in ("created", "last_used"):
        if field in row and row[field] is not None:
            row[field] = _as_epoch(row[field], default=None)
    if row.get("expires") is not None:
        # Junk / inf must persist as expired, never as "no expiry".
        exp = _as_epoch(row["expires"], default=None)
        row["expires"] = 0 if exp is None else exp
    cleaned = _json_safe(row)
    return cleaned if isinstance(cleaned, dict) else {}


def _store_rows(raw) -> list:
    """Accept leftover list-or-dict shapes; a non-iterable ``keys`` used to 500."""
    if isinstance(raw, list):
        return raw
    if not isinstance(raw, dict):
        return []
    keys = raw.get("keys")
    if isinstance(keys, list):
        return keys
    if isinstance(keys, dict):
        return [v for v in keys.values() if isinstance(v, dict)]
    return []


def _load() -> list[dict]:
    try:
        raw = json.loads(read_text_capped(STORE_FILE, _STORE_CAP, encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        # ValueError covers json.JSONDecodeError *and* UnicodeDecodeError: a
        # torn write leaving non-UTF-8 bytes used to raise past this guard,
        # and this loader runs on every Bearer-authenticated request.
        # RecursionError: a leftover deeply-nested document is not ValueError.
        return []
    return [_persistable_record(k) for k in _store_rows(raw) if isinstance(k, dict)]


def _save(keys: list[dict]) -> None:
    cleaned = [_persistable_record(k) for k in keys if isinstance(k, dict)]
    try:
        payload = json.dumps({"keys": cleaned}, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    except (TypeError, ValueError, OverflowError, RecursionError):
        # RecursionError: leftover nested api-keys.json after _persistable_record
        # is not ValueError; create / revoke / Bearer used to 500.
        return
    _drop_leftover_nonfile(STORE_FILE)
    try:
        secure_io.replace_secret_text(STORE_FILE, payload)
    except OSError:
        # Leftover directory / EIO must not 500 create, revoke, or Bearer auth.
        pass


def looks_like_key(token: str | None) -> bool:
    """Cheap shape test so require_auth only pays for real candidates."""
    return bool(token) and str(token).startswith(PREFIX)


def _as_epoch(raw, default: int | None = 0) -> int | None:
    """Parse a last_used/created/expires stamp.  Bool, inf, and junk must not 500."""
    if raw is None or raw is False:
        return default
    if isinstance(raw, bool):
        return default
    if isinstance(raw, int):
        return raw
    if isinstance(raw, float):
        if raw != raw or raw in (float("inf"), float("-inf")):
            return default
        try:
            return int(raw)
        except (OverflowError, ValueError):
            return default
    if isinstance(raw, (bytes, bytearray)):
        try:
            return _as_epoch(raw.decode("utf-8", "replace"), default)
        except Exception:
            return default
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return default
        try:
            return int(text)
        except ValueError:
            try:
                return _as_epoch(float(text), default)
            except ValueError:
                return default
    return default


def _digest_eq(stored, supplied: str) -> bool:
    """compare_digest raises on length mismatch — one bad row 500s every Bearer."""
    text = stored if isinstance(stored, str) else ""
    if not text or not text.isascii() or len(text) != len(supplied):
        return False
    return hmac.compare_digest(text, supplied)


def public_view(record: dict) -> dict:
    """Listing entry: everything except the digest."""
    kid = _utf8_text(record.get("id") or "")
    stored = record.get("last_used")
    seen = _last_seen.get(kid)
    last_used = max(_as_epoch(stored) or 0, _as_epoch(seen) or 0) or None
    created = record.get("created")
    expires = record.get("expires")
    return {
        "id": kid,
        "name": _utf8_text(record.get("name") or ""),
        "role": _utf8_text(record.get("role") or "member"),
        # Starlette encodes with allow_nan=False; JSON 1e309 becomes inf and
        # used to 500 GET /api/api-keys.  last_used already went through this.
        "created": None if created is None else _as_epoch(created, default=None),
        "expires": None if expires is None else _as_epoch(expires, default=None),
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
    cleaned = _utf8_text(name or "").strip()
    if not cleaned or len(cleaned) > MAX_NAME_LENGTH:
        raise ValueError("bad_name")
    if role not in VALID_ROLES:
        raise ValueError("bad_role")
    expires: int | None = None
    if expires_days is not None:
        try:
            days = int(expires_days)
        except (TypeError, ValueError, OverflowError):
            raise ValueError("bad_expiry")
        if not 1 <= days <= 3650:
            raise ValueError("bad_expiry")
        now = _as_epoch(time.time(), default=0) or 0
        expires = now + days * 86400
    token = PREFIX + secrets.token_urlsafe(32)
    record = {
        "id": "ak_" + secrets.token_hex(6),
        "name": cleaned,
        "role": role,
        "digest": _digest(token),
        "created": _as_epoch(time.time(), default=0) or 0,
        "expires": expires,
        "last_used": None,
    }
    with _lock, _file_lock():
        keys = _load()
        if len(keys) >= MAX_KEYS:
            raise ValueError("too_many")
        keys.append(record)
        _save(keys)
    return public_view(record), token


def revoke(key_id: str) -> dict | None:
    """Remove one key; returns its public view, or None when unknown."""
    with _lock, _file_lock():
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
    now = _as_epoch(time.time(), default=0) or 0
    # The file lock covers the read too, not just the throttled write: a
    # verify() that reads before a concurrent revoke in another process and
    # writes after it would resurrect the revoked key.
    with _lock, _file_lock():
        keys = _load()
        hit: dict | None = None
        for record in keys:
            if _digest_eq(record.get("digest"), supplied):
                hit = record
        if hit is None:
            return None
        expires = hit.get("expires")
        if expires is not None:
            # ``if expires:`` skipped 0 (fail-open forever) and ``int(inf)``
            # OverflowError'd every Bearer request after a JSON ``1e309``.
            if isinstance(expires, bool):
                return None
            exp = _as_epoch(expires, default=None)
            if exp is None or now >= exp:
                return None
        kid = str(hit.get("id") or "")
        _last_seen[kid] = now
        stored = _as_epoch(hit.get("last_used"))
        if now - stored >= LAST_USED_PERSIST_SECONDS:
            hit["last_used"] = now
            try:
                _save(keys)
            except OSError:
                # A full disk must not fail authentication that already passed.
                pass
        return public_view(hit)
