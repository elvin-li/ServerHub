"""RFC 6238 TOTP (and its RFC 4226 HOTP core) on the standard library only.

ServerHub deliberately carries no third-party auth dependency: the whole
algorithm is ~30 lines of hmac/struct once the base32 handling is written
down, and a pinned copy here is auditable in one screenful.  Parameters are
fixed to what every authenticator app ships by default — SHA-1, 30-second
step, 6 digits — because interoperability, not agility, is the point of
this factor.  The RFC 6238 appendix vectors are pinned in tests/test_totp.py.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse

#: One time step, seconds (RFC 6238 default; every authenticator app assumes it).
STEP_SECONDS = 30
#: Code length.  Six digits is what the pairing UIs of Google Authenticator,
#: 1Password, Aegis etc. render; eight would refuse to pair with some of them.
DIGITS = 6
#: Accepted clock drift, in steps, on each side of "now".  ±1 step tolerates
#: 30s of phone-vs-server skew without widening the guessing window much.
DRIFT_WINDOW = 1

#: 20 random bytes = 160-bit secret, the RFC 4226 recommended minimum, and it
#: encodes to 32 base32 chars — a clean 8-group manual-entry string.
SECRET_BYTES = 20


def generate_secret() -> str:
    """A fresh base32 shared secret (no padding, upper-case)."""
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode("ascii").rstrip("=")


def decode_secret(secret: str) -> bytes:
    """Base32-decode a stored or user-supplied secret.

    Tolerates the cosmetic variations that appear when a secret has been read
    aloud or typed: lower case, spaces/dashes between groups, missing padding.
    Raises ValueError for anything that is not base32 underneath.
    """
    cleaned = str(secret or "").strip().replace(" ", "").replace("-", "").upper()
    if not cleaned:
        raise ValueError("empty TOTP secret")
    try:
        return base64.b32decode(cleaned + "=" * (-len(cleaned) % 8))
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid base32 TOTP secret") from exc


def hotp(key: bytes, counter: int, digits: int = DIGITS) -> str:
    """RFC 4226 HMAC-based one-time password for one counter value."""
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    (code,) = struct.unpack(">I", mac[offset:offset + 4])
    code &= 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def _step_counter(timestamp, step: int) -> int | None:
    """HOTP counter for *timestamp*, or None when leftover input would OverflowError.

    JSON ``1e309`` is ``inf``; ``int(inf)`` is not ValueError.  A huge finite
    stamp then OverflowError'd ``struct.pack('>Q', counter)`` on verify /
    enroll confirm.
    """
    if isinstance(timestamp, bool) or timestamp is None:
        return None
    if isinstance(step, bool) or not isinstance(step, int) or step <= 0:
        return None
    try:
        now = int(timestamp)
        counter = now // step
    except (TypeError, ValueError, OverflowError):
        return None
    if counter < 0 or counter > 0xFFFFFFFFFFFFFFFF:
        return None
    return counter


def totp_at(secret: str, timestamp: float, *, step: int = STEP_SECONDS, digits: int = DIGITS) -> str:
    """The code a correct authenticator shows at *timestamp*."""
    counter = _step_counter(timestamp, step)
    if counter is None:
        raise ValueError("invalid TOTP timestamp")
    return hotp(decode_secret(secret), counter, digits)


def verify(
    secret: str,
    code: str,
    *,
    timestamp: float | None = None,
    window: int = DRIFT_WINDOW,
    step: int = STEP_SECONDS,
    digits: int = DIGITS,
) -> int | None:
    """Check *code* against ``now ± window`` steps.

    Returns the matched counter (so the caller can persist it and refuse any
    counter at or below it — that is what makes a code single-use within its
    window), or None when nothing matches.  Every candidate is compared in
    constant time, and all candidates are evaluated even after a hit so the
    duration does not reveal which step matched.
    """
    supplied = str(code or "").strip().replace(" ", "")
    # isascii() first: str.isdigit() accepts Unicode digits like "①", and
    # hmac.compare_digest raises TypeError on non-ASCII str — the same trap
    # documented on auth.constant_time_equals.  A network-supplied code must
    # only ever produce True or False here, never an exception.
    if not supplied.isascii() or not supplied.isdigit() or len(supplied) != digits:
        return None
    try:
        key = decode_secret(secret)
    except ValueError:
        return None
    if isinstance(window, bool) or not isinstance(window, int) or window < 0:
        return None
    stamp = time.time() if timestamp is None else timestamp
    counter = _step_counter(stamp, step)
    if counter is None:
        return None
    matched: int | None = None
    for candidate in range(counter - window, counter + window + 1):
        # `_step_counter` allows uint64 max; the +window step then
        # OverflowError'd ``struct.pack('>Q', candidate)`` on leftover
        # huge timestamps (``(2**64-1)*30``).
        if candidate < 0 or candidate > 0xFFFFFFFFFFFFFFFF:
            continue
        if hmac.compare_digest(hotp(key, candidate, digits), supplied):
            matched = candidate
    return matched


def otpauth_uri(secret: str, account: str, issuer: str = "ServerHub") -> str:
    """The otpauth:// URI authenticator apps import (rendered as a QR client-side).

    Label and issuer are percent-encoded; the issuer also rides as a query
    parameter because some apps only read one of the two places.
    """
    # quote() encodes as UTF-8 strict; leftover ``\\ud800`` in an account
    # name used to UnicodeEncodeError POST /api/auth/totp/enroll.
    label = urllib.parse.quote_from_bytes(
        f"{issuer}:{account}".encode("utf-8", "surrogatepass"), safe=""
    )
    query = urllib.parse.urlencode({
        "secret": secret,
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": str(DIGITS),
        "period": str(STEP_SECONDS),
    })
    return f"otpauth://totp/{label}?{query}"


def manual_entry_groups(secret: str) -> str:
    """The secret in 4-char groups for typing into an app by hand."""
    cleaned = str(secret or "").replace(" ", "")
    return " ".join(cleaned[i:i + 4] for i in range(0, len(cleaned), 4))
