"""Append-only audit trail for security-relevant events.

``terminal_svc`` already audits command execution, but authentication itself was
invisible: a successful sign-in, a failed one, a logout, a first-run setup claim
and a password rotation all left no record at all.  With family accounts on the
way, "who did this and when" stops being answerable from memory, so those events
need a durable trail.

Two properties matter more than the schema:

* **Secrets never land in the log.**  The events recorded here are exactly the
  ones whose request bodies carry passwords and setup tokens, so redaction is
  not a nicety -- writing a plaintext password into a file that is later read
  back by an API endpoint would be worse than having no audit log.  Redaction is
  therefore applied by key name inside :func:`record`, not left to each caller
  to remember.

* **Logging never breaks the request.**  A full disk or an unwritable directory
  must not turn a valid sign-in into a 500.  Every failure path here is
  swallowed, matching ``terminal_svc._audit``.

This module deliberately does not decide *authorisation*.  It observes and
records; it never grants or refuses anything.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from hub import secure_io
from hub.paths import DATA_DIR
from hub.util import safe_json_loads, strftime_now, tail_file_lines

AUDIT_PATH = DATA_DIR / "auth-audit.jsonl"

#: Keep the trail bounded so it cannot fill the disk unattended.  Old lines are
#: dropped from the front, because the newest events are the ones being
#: investigated.
MAX_LINES = 5000
# Skip the full-file read while the log is still well under the cap.  A
# typical line is ~150 B; 192 B/line starts checking before a fat-line
# trail can run far past MAX_LINES.
_TRIM_SOFT_BYTES = MAX_LINES * 192

#: Event names.  Kept as constants so a typo in a caller is an AttributeError
#: rather than a silently unqueryable log line.
LOGIN_OK = "auth.login.ok"
LOGIN_FAILED = "auth.login.failed"
LOGIN_RATE_LIMITED = "auth.login.rate_limited"
LOGOUT = "auth.logout"
SETUP_CLAIMED = "auth.setup.claimed"
SETUP_REJECTED = "auth.setup.rejected"
PASSWORD_CHANGED = "auth.password.changed"
PASSWORD_CHANGE_DENIED = "auth.password.change_denied"
#: Two-factor lifecycle.  Enabling, disabling and recovery-code churn change
#: what signing in takes, and a forced removal is an administrator acting on
#: someone else's credential — all of it leaves a trail.  The shared secret,
#: TOTP codes and recovery codes themselves are never passed to record().
TWOFA_ENABLED = "auth.2fa.enabled"
TWOFA_DISABLED = "auth.2fa.disabled"
TWOFA_FORCE_DISABLED = "auth.2fa.force_disabled"
TWOFA_RECOVERY_REGENERATED = "auth.2fa.recovery_regenerated"
TWOFA_RECOVERY_USED = "auth.2fa.recovery_used"
#: Panel accounts (multi-user).  Creating, re-scoping, resetting or deleting a
#: member account changes who can sign in and what they reach, so each names
#: both the administrator acting (``username``) and the account acted on
#: (``target``).  Passwords never reach record(); resource ids are public.
ACCOUNT_CREATED = "auth.account.created"
ACCOUNT_RESOURCES_CHANGED = "auth.account.resources_changed"
ACCOUNT_PASSWORD_RESET = "auth.account.password_reset"
ACCOUNT_DELETED = "auth.account.deleted"
#: API keys are standing credentials, so minting and revoking one names the
#: operator.  Records carry the key's id/name/role — never the key itself,
#: which exists in plaintext only inside the create response.
APIKEY_CREATED = "apikey.created"
APIKEY_REVOKED = "apikey.revoked"
SHARE_CHANGED = "shares.changed"
SYSTEM_SHARING_CHANGED = "shares.system.changed"
#: Storage and data-protection operations.  Every one of these either exposes
#: data to the network or destroys it, so each leaves a trail naming the operator.
NFS_CHANGED = "nfs.changed"
RAID_CHANGED = "raid.changed"
SNAPSHOT_CHANGED = "snapshots.changed"
SMART_TEST_STARTED = "smart.test.started"
SPOTLIGHT_CHANGED = "spotlight.changed"
#: Scheduled jobs run arbitrary shell commands and move data around, so every
#: definition change and manual trigger names the operator.  The command text
#: of a shell job is part of the record: "what exactly did the panel run at
#: 03:30" must be answerable from this trail alone.
SCHEDULE_JOB_CREATED = "scheduler.job.created"
SCHEDULE_JOB_UPDATED = "scheduler.job.updated"
SCHEDULE_JOB_DELETED = "scheduler.job.deleted"
SCHEDULE_JOB_RUN = "scheduler.job.run_now"
#: A notification channel is an outbound data path carrying alert content and
#: credentials, so its lifecycle names the operator.  Secret values never
#: enter these records (redaction drops token-shaped fields regardless).
NOTIFY_CHANNEL_CREATED = "notify.channel.created"
NOTIFY_CHANNEL_UPDATED = "notify.channel.updated"
NOTIFY_CHANNEL_DELETED = "notify.channel.deleted"
NOTIFY_CHANNEL_TESTED = "notify.channel.tested"
#: A WireGuard peer is a credential granting network access, so issuing and
#: revoking one is recorded with the operator who did it.
WIREGUARD_PEER_ADDED = "wireguard.peer.added"
WIREGUARD_PEER_REMOVED = "wireguard.peer.removed"
WIREGUARD_PEER_CHANGED = "wireguard.peer.changed"
WIREGUARD_INTERFACE = "wireguard.interface"
#: UPS safe-shutdown policy (hub/ups_policy.py).  The policy stops and starts
#: real workloads on its own, with nobody at the keyboard, so the trail must
#: answer "why is this stack down / who told it to do that" afterwards: every
#: trigger, every per-target stop/start result, the reset, each config change
#: and each drill leaves a record.  Trigger/step/reset events carry no
#: username — they are the machine acting on policy; the config/drill/halt
#: events name the operator.
UPS_POLICY_TRIGGERED = "ups.policy.triggered"
UPS_POLICY_STEP = "ups.policy.step"
UPS_POLICY_RESET = "ups.policy.reset"
UPS_POLICY_CHANGED = "ups.policy.changed"
UPS_POLICY_DRILL = "ups.policy.drill"
UPS_HALT_CHANGED = "ups.halt.changed"

#: Any field whose name contains one of these is replaced wholesale.  Substring
#: matching rather than exact names, so ``current_password``, ``new_password``
#: and ``setup_token`` are all covered without enumerating every variant a
#: future caller might invent.
_SECRET_HINTS = (
    "password",
    "token",
    "secret",
    "credential",
    "cookie",
    "session",
    "authorization",
    "passwd",
    "api_key",
    "apikey",
    # Key material.  The WireGuard events are the reason: a peer's private key
    # and preshared key are the credential itself, and the callers currently pass
    # only the public half by hand -- which is exactly the "left to each caller to
    # remember" arrangement this module's docstring says it exists to replace.  A
    # field named private_key, psk or preshared_key was not covered by any hint
    # above, so the safety net had a hole precisely where the most sensitive
    # values are.
    "key",
    "psk",
    "preshared",
    "passphrase",
    "private",
    "seed",
    "bearer",
)

#: Field names that contain a secret hint but are genuinely public.
#:
#: ``pubkey`` is a peer's identity -- it is what the operator matches a device by,
#: and dropping it would make the WireGuard trail unreadable.  This list is
#: deliberately tiny and explicit: the default for anything key-shaped is to
#: redact, and an addition here is a claim that the value is safe to write to
#: disk.
_PUBLIC_EXCEPTIONS = (
    "pubkey",
    "public_key",
    "publickey",
)


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
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


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's allow_nan=False encoder cannot 500.

    Infinity in a leftover auth-audit.jsonl field was already dropped; a
    leftover ``\\ud800`` username or key still 500'd GET /api/audit/auth.
    """
    if depth > 32:
        return None
    if value is None or isinstance(value, bool):
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
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if not isinstance(k, (str, bytes, bytearray)):
                try:
                    k = str(k)
                except Exception:
                    continue
            out[_utf8_text(k)] = _jsonable(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v, depth + 1) for v in value]
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/audit.
            return _jsonable(iso(), depth + 1)
        except Exception:
            return None
    try:
        return _utf8_text(value)
    except Exception:
        return None


def _is_secret_key(key: str) -> bool:
    lowered = str(key).lower()
    if any(allowed in lowered for allowed in _PUBLIC_EXCEPTIONS):
        return False
    return any(hint in lowered for hint in _SECRET_HINTS)


def redact(value: Any) -> Any:
    """Drop secret-looking fields anywhere in a nested structure.

    Recurses into dicts and lists so a password nested inside a body dump is
    caught too.  The *key* decides, not the value: guessing whether a string
    "looks like" a password is unreliable, whereas a field named ``password``
    is unambiguous.

    Secret keys are **removed**, not replaced with a placeholder.  Leaving
    ``{"token": "[redacted]"}`` behind still discloses that a token was part of
    the event, and a placeholder invites a later reader to treat the key as
    safe-by-construction and start logging a "shortened" or "hashed" variant of
    it.  An absent key cannot leak anything.
    """
    if isinstance(value, dict):
        return {
            k: redact(v) for k, v in value.items() if not _is_secret_key(k)
        }
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    return value


def _trim(path: Path) -> None:
    """Drop the oldest lines once the log exceeds :data:`MAX_LINES`.

    A cheap size check avoids reading and rewriting the file on every
    sign-in while it is still far below the cap.  The keep-set is tailed
    rather than slurped so a trail that grew well past the cap cannot
    pin the login path.  Publish through ``replace_secret_text``: an
    in-place ``write_secret_text`` (O_TRUNC) emptied the history if the
    process died mid-rewrite.
    """
    try:
        if path.stat().st_size <= _TRIM_SOFT_BYTES:
            return
        lines = tail_file_lines(path, MAX_LINES, max_bytes=MAX_LINES * 1024)
    except OSError:
        return
    if not lines:
        return
    try:
        secure_io.replace_secret_text(path, "\n".join(lines) + "\n")
    except OSError:
        pass


def record(event: str, /, **fields: Any) -> dict:
    """Append one audit entry and return what was written.

    The returned dict is the redacted record, so a caller (or a test) can assert
    on exactly what reached disk rather than on what was passed in.
    """
    extra = redact(fields)
    if not isinstance(extra, dict):
        extra = {}
    # Callers pass **kwargs; a leftover ``ts=`` / ``event=`` must not
    # clobber the stamp or the event name the trail is queried by.
    extra.pop("ts", None)
    extra.pop("event", None)
    entry = _jsonable({
        "ts": strftime_now("%Y-%m-%dT%H:%M:%S%z"),
        "event": _utf8_text(event),
        **extra,
    })
    if not isinstance(entry, dict):
        entry = {
            "ts": strftime_now("%Y-%m-%dT%H:%M:%S%z"),
            "event": _utf8_text(event),
        }
    try:
        # secure_io creates the file 0600 from the first byte.  A plain
        # open("a") would leave it 0644 under the default umask until a later
        # chmod, and this log names accounts and source addresses.
        #
        # Create-if-absent, not "check then write": the write_secret_text form
        # opens with O_TRUNC, so any false negative from exists() emptied the
        # entire audit trail before appending one line to it.  The same shape in
        # config._bootstrap() destroyed a populated services.yaml on every test
        # run, and here the loss would be the security history specifically.
        secure_io.create_secret_text(AUDIT_PATH, "")
        # O_NOFOLLOW: open("a") would follow a replacement symlink onto
        # another file this process can write.
        secure_io.append_text(
            AUDIT_PATH,
            json.dumps(entry, ensure_ascii=False, allow_nan=False, default=str) + "\n",
            mode=0o600,
        )
        # chmod only when the mode drifted.  The create helper already
        # writes 0600; repeating chmod on every login is a metadata write
        # against an otherwise append-only file.
        if AUDIT_PATH.stat().st_mode & 0o777 != 0o600:
            os.chmod(AUDIT_PATH, 0o600)
        _trim(AUDIT_PATH)
    except (OSError, TypeError, ValueError, RecursionError):
        # An unwritable or unencodable log must never turn a valid sign-in
        # into a 500. RecursionError: leftover nested audit row is not ValueError.
        pass
    return entry


def recent(limit: int = 100) -> list[dict]:
    """Tail of the audit trail, newest last."""
    try:
        n = max(1, min(int(limit), 1000))
    except (TypeError, ValueError, OverflowError):
        n = 100
    try:
        # Path.exists() re-raises EIO/ESTALE; that used to 500 GET /api/audit/auth.
        if not AUDIT_PATH.exists():
            return []
        lines = tail_file_lines(AUDIT_PATH, n)
    except OSError:
        return []
    out: list[dict] = []
    for raw in lines:
        try:
            parsed = safe_json_loads(raw)
        except (ValueError, RecursionError):
            continue
        if isinstance(parsed, dict):
            out.append(_jsonable(parsed))
    return out
