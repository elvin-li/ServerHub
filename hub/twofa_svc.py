"""Per-account TOTP two-factor state: enrollment, verification, recovery codes.

Storage model (mirrors hub/notify_channels.py):

* nothing 2FA-related goes into services.yaml — the shared TOTP secret must be
  readable back (it is the input of every future code), so it lives with the
  other reversible secrets in a mode-0600 file under ``data/``:
  ``data/twofa.json``, written through :mod:`hub.secure_io`.
* recovery codes are random and high-entropy, so they are stored as plain
  SHA-256 digests (a KDF hardens low-entropy human passwords; 50-bit random
  material gains nothing from scrypt) and removed on first use.

Replay defence: the last accepted TOTP counter is persisted per account and a
code only verifies when its counter is *strictly greater*.  Reusing the same
code inside its 30s window therefore fails, as does any code from an earlier
window once a newer one has been accepted.

Nothing in this module reads the request or decides authorisation; the routers
own "who may call this", the audit trail lives with the callers.
"""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from contextlib import contextmanager

from hub import secure_io, totp
from hub.paths import DATA_DIR

#: Module-level so tests can point it at a scratch directory, same pattern as
#: notify_channels.SECRETS_FILE.
STORE_FILE = DATA_DIR / "twofa.json"
_lock = threading.Lock()


@contextmanager
def _file_lock():
    """Exclusive cross-process lock around every read-modify-write of the store.

    The in-process ``_lock`` is not sufficient on its own: a packaged
    ServerHub.app and the LaunchAgent panel can share one ``data/`` directory
    (the same deployment hub/config.py grew its services.yaml flock for), and
    two interpreters that each read the store, verify the same TOTP or
    recovery code and write back independently would *both* accept it — the
    single-use guarantee (last_counter / consumed recovery digests) only holds
    if read→compare→write is atomic across processes.  Same pattern as
    ``config._file_lock``: a separate ``.lock`` file rather than the store
    itself, because ``secure_io.replace_secret_text`` swaps in a new inode and
    a lock on the old one would silently stop excluding anybody.
    """
    lock_path = STORE_FILE.with_name(STORE_FILE.name + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)

#: Recovery code shape: two groups of five from an alphabet without the
#: look-alikes (0/O, 1/I/L), ~50 bits — plenty for a code that is single-use,
#: rate-limited and revoked wholesale on regeneration.
RECOVERY_CODES = 10
_RECOVERY_ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ23456789"
_RECOVERY_GROUP = 5


def _load() -> dict[str, dict]:
    try:
        raw = json.loads(STORE_FILE.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def _save(data: dict[str, dict]) -> None:
    secure_io.replace_secret_text(
        STORE_FILE, json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    )


def _hash_recovery(code: str) -> str:
    normalized = str(code or "").replace("-", "").replace(" ", "").upper()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _new_recovery_codes() -> list[str]:
    out = []
    for _ in range(RECOVERY_CODES):
        chars = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(_RECOVERY_GROUP * 2))
        out.append(f"{chars[:_RECOVERY_GROUP]}-{chars[_RECOVERY_GROUP:]}")
    return out


def status(username: str) -> dict:
    """API-safe view: never contains the secret or any code material."""
    with _lock:
        entry = _load().get(str(username)) or {}
    return {
        "enabled": bool(entry.get("enabled")),
        "pending": bool(entry.get("pending_secret")) and not entry.get("enabled"),
        "recovery_remaining": len(entry.get("recovery") or []),
        "confirmed_at": entry.get("confirmed_at"),
    }


def enabled(username: str) -> bool:
    with _lock:
        entry = _load().get(str(username)) or {}
    return bool(entry.get("enabled"))


def begin_enrollment(username: str) -> dict:
    """Generate (or replace) a pending secret; nothing is enforced yet.

    The account keeps signing in with just the password until a valid code
    confirms the pairing — that ordering is what keeps an operator from
    locking themselves out with a mistyped import.
    """
    username = str(username)
    secret = totp.generate_secret()
    with _lock, _file_lock():
        data = _load()
        entry = dict(data.get(username) or {})
        if entry.get("enabled"):
            raise AlreadyEnabled(username)
        entry["pending_secret"] = secret
        data[username] = entry
        _save(data)
    return {
        "secret": secret,
        "otpauth_uri": totp.otpauth_uri(secret, username),
        "manual_entry": totp.manual_entry_groups(secret),
    }


def confirm_enrollment(username: str, code: str, *, timestamp: float | None = None) -> list[str] | None:
    """Turn the pending secret into the active one once *code* proves pairing.

    Returns the freshly generated recovery codes (the only time their
    plaintext exists) or None when the code does not verify.
    """
    username = str(username)
    with _lock, _file_lock():
        data = _load()
        entry = dict(data.get(username) or {})
        pending = str(entry.get("pending_secret") or "")
        if entry.get("enabled") or not pending:
            raise NotPending(username)
        matched = totp.verify(pending, code, timestamp=timestamp)
        if matched is None:
            return None
        codes = _new_recovery_codes()
        data[username] = {
            "secret": pending,
            "enabled": True,
            "confirmed_at": int(time.time()),
            "recovery": [_hash_recovery(c) for c in codes],
            "last_counter": matched,
        }
        _save(data)
    return codes


def verify_totp_code(username: str, code: str, *, timestamp: float | None = None) -> bool:
    """One TOTP verification with drift tolerance and replay rejection."""
    username = str(username)
    with _lock, _file_lock():
        data = _load()
        entry = dict(data.get(username) or {})
        if not entry.get("enabled") or not entry.get("secret"):
            return False
        matched = totp.verify(str(entry["secret"]), code, timestamp=timestamp)
        if matched is None:
            return False
        try:
            last = int(entry.get("last_counter") or 0)
        except (TypeError, ValueError):
            last = 0
        # Strictly greater: the same window (= the same code) can be spent once.
        if matched <= last:
            return False
        entry["last_counter"] = matched
        data[username] = entry
        _save(data)
    return True


def use_recovery_code(username: str, code: str) -> bool:
    """Spend one recovery code.  Consumed immediately on success."""
    username = str(username)
    supplied = _hash_recovery(code)
    with _lock, _file_lock():
        data = _load()
        entry = dict(data.get(username) or {})
        if not entry.get("enabled"):
            return False
        stored = [str(h) for h in (entry.get("recovery") or [])]
        # Compare against every stored digest so the duration does not say
        # which position (if any) matched.
        matched_index = -1
        for index, digest in enumerate(stored):
            if hmac.compare_digest(digest, supplied):
                matched_index = index
        if matched_index < 0:
            return False
        del stored[matched_index]
        entry["recovery"] = stored
        data[username] = entry
        _save(data)
    return True


def verify_second_factor(username: str, code: str, *, timestamp: float | None = None) -> str | None:
    """Accept either factor: returns "totp", "recovery", or None.

    TOTP is tried first (the common case); anything that fails as a TOTP code
    is then tried as a recovery code, so the login form needs only one field.
    """
    if verify_totp_code(username, code, timestamp=timestamp):
        return "totp"
    if use_recovery_code(username, code):
        return "recovery"
    return None


def regenerate_recovery(username: str) -> list[str]:
    """Replace every outstanding recovery code.  Caller must re-verify first."""
    username = str(username)
    codes = _new_recovery_codes()
    with _lock, _file_lock():
        data = _load()
        entry = dict(data.get(username) or {})
        if not entry.get("enabled"):
            raise NotEnabled(username)
        entry["recovery"] = [_hash_recovery(c) for c in codes]
        data[username] = entry
        _save(data)
    return codes


def disable(username: str) -> bool:
    """Drop the account's 2FA state entirely (secret, recovery, counters).

    Returns whether anything was actually enabled.  Verification of "may this
    caller disable it" (own valid code, or an administrator rescuing a locked
    -out family member) belongs to the route, not here.
    """
    username = str(username)
    with _lock, _file_lock():
        data = _load()
        entry = data.get(username) or {}
        was_enabled = bool(entry.get("enabled"))
        if username in data:
            del data[username]
            _save(data)
    return was_enabled


class AlreadyEnabled(Exception):
    """Enrollment attempted while 2FA is already active for the account."""


class NotPending(Exception):
    """Confirmation attempted with no enrollment in progress."""


class NotEnabled(Exception):
    """Operation requires active 2FA on the account."""
