"""Guards for values that land in a subprocess argv as positional arguments.

Every subprocess call in this codebase passes a list, never a shell string, so
shell-metacharacter injection is already closed.  What remains is argument
injection: a value in a positional slot that begins with ``-`` is read by the
target program as an *option*.

``docker stop --all`` stops every container.  ``brew services stop --all`` stops
every Homebrew service.  ``dig -f /etc/passwd`` reads a file and, because the
endpoint returns command output, hands it back to the caller.

Three validator styles let such values through before this module existed:

  * a character class containing ``-`` with no anchor on the first character,
    e.g. ``^[\\w@.+-]+$``, which matches ``--all``;
  * an ``int()``-based IP check, because ``int("-0")`` is ``0`` and therefore
    satisfies ``0 <= n <= 255``, making ``-0.0.0.0`` a "valid address";
  * a blocklist of bad characters (`` ;|&$`\\n\\r``) rather than an allowlist of
    good ones, which never considered a leading hyphen at all.

Prefer :func:`require_positional` at the boundary.  Where a CLI supports it, a
``--`` separator before user values is a second, independent layer; this module
is the one that does not depend on the target program's option parser.
"""
from __future__ import annotations

import os
import re

from hub.errors import api_error

# A positional must start with an alphanumeric.  That single anchor is what
# makes an option-like value unrepresentable, regardless of what the rest of the
# name contains.
_SAFE_POSITIONAL = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.@+:-]*\Z")
_SAFE_HOSTNAME = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]*\Z")

MAX_POSITIONAL_LEN = 255
MAX_HOSTNAME_LEN = 253


def as_argv(cmd: object) -> list[str] | None:
    """Return a str argv, or None when a leftover non-str would reach exec.

    YAML ``!!binary`` is a SafeLoader leftover that is ``bytes``.  ``subprocess``
    accepts bytes in argv, so a leftover ``b'--all'`` is still option injection
    after every str validator has refused it.  Nested lists, ints, and bools are
    the same class: they must not be stringified into a positional.
    """
    if not isinstance(cmd, (list, tuple)):
        return None
    out: list[str] = []
    for part in cmd:
        if isinstance(part, (bytes, bytearray)):
            return None
        if isinstance(part, str):
            text = part
        elif isinstance(part, os.PathLike):
            text = os.fspath(part)
            if not isinstance(text, str):
                return None
        else:
            return None
        if "\x00" in text:
            return None
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            # Leftover ``\ud800`` used to UnicodeEncodeError ``subprocess.run``.
            return None
        out.append(text)
    return out


def _normalise(value: object) -> str | None:
    """Trim surrounding blanks, or return None if the value cannot be argv.

    One function so that "the string we validated" and "the string we hand to
    the argv" are always identical.  Earlier drafts of this module checked
    ``value.strip(" \\t")`` but returned ``value.strip()``, which differ on a
    trailing newline -- exactly the mismatch that lets a validated value carry
    something the check already rejected.

    Control characters are refused rather than stripped, for the same reason: a
    caller using the predicate and then passing the original string would still
    put the newline in the argv.
    """
    if not isinstance(value, str):
        return None
    # Unbound ``str.strip`` (the modules6 encode-bomb rule at strip rank): a
    # str *subclass* whose bound ``.strip`` raises passed the isinstance gate
    # above and blew this guard itself — every route that asks "is this
    # argv-safe?" raised out of the very predicate that exists to refuse the
    # value.  The base method also answers an exact str, so the walk below
    # never runs the subclass's own iteration either.
    text = str.strip(value, " \t")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in text):
        return None
    return text


def is_safe_positional(value: object, *, max_len: int = MAX_POSITIONAL_LEN) -> bool:
    """True when ``value`` cannot be mistaken for a command-line option.

    ``\\A``/``\\Z`` rather than ``^``/``$``: ``$`` also matches immediately
    before a trailing newline, so ``^disk\\d+$`` happily accepts ``"disk0\\n"``.
    """
    text = _normalise(value)
    if text is None or not text or len(text) > max_len:
        return False
    return bool(_SAFE_POSITIONAL.match(text))


def require_positional(
    value: object, *, label: str, max_len: int = MAX_POSITIONAL_LEN
) -> str:
    """Return the argv-safe value, or raise HTTP 400 naming ``label``."""
    if not is_safe_positional(value, max_len=max_len):
        raise api_error("cli.invalid_value", label=label)
    return _normalise(value)  # type: ignore[return-value]


def is_safe_hostname(value: object, *, max_len: int = MAX_HOSTNAME_LEN) -> bool:
    """True for a hostname or IP literal that cannot be read as an option.

    Deliberately permits ``:`` for IPv6 and ``.`` for FQDNs, while still
    requiring an alphanumeric first character.
    """
    text = _normalise(value)
    if text is None or not text or len(text) > max_len:
        return False
    return bool(_SAFE_HOSTNAME.match(text))
