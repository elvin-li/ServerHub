"""Single source for `ps aux`.

Three modules read the whole process table and each shelled out on its own:

    native_catalog._PsSnapshot      per listing pass, `/bin/ps aux`, timeout 5
    cloudflared_svc._process_running  per call,       `/bin/ps aux`, timeout 5
    tools_svc.top_processes         5s cache by row,  `/bin/ps aux`, timeout 8

``native_catalog`` had already worked out that the table is identical for every
app in a pass and hoisted it into a per-pass snapshot object -- which is the right
shape, one scope too small.  ``/api/apps/managed`` walks the native catalog *and*
asks cloudflared whether its tunnel process is alive, so the table was still read
twice per request, and the Tools page read it a third time.

Cached for the same reason and with the same shape as :mod:`hub.brew_cache`: the
readers arrive together as branches of one fan-out, so a bare TTL check outside a
lock would let all of them miss and all of them spawn.

No invalidation hook, deliberately.  Unlike a launchd listing or a brew service
table, nothing in the panel changes the process table and then re-reads it in the
same breath -- starting a service goes through launchd, which has its own cache and
its own invalidation.  The window here is bounded by the TTL and by nothing else,
which is what every previous copy already accepted.
"""
from __future__ import annotations

import re

from hub.util import cached_snapshot, sh

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")


def _as_text(value) -> str:
    """``ps`` leftovers arrive as int/None/bytes; leftover ``\\ud800`` used to 500 sensors/Tools JSON."""
    if value is None:
        return ""
    for base in (bytes, bytearray):
        try:
            return base.decode(value, "utf-8", "replace")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
    try:
        return str.encode(str.__str__(value), "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        pass
    try:
        cls = type(value)
        if cls.__str__ is object.__str__ and cls.__repr__ is object.__repr__:
            return ""
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    try:
        text = str(value)
    except RecursionError:
        try:
            return type(value).__name__
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return ""
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    try:
        text = str.encode(text, "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    return "" if _ADDR_REPR_RE.search(text) else text

#: Long enough to collapse the readers inside one request, short enough that the
#: Tools process table still looks live.  ``tools_svc`` had settled on 5s for the
#: same command and the same reason.
_TTL = 5.0

#: The generous end of the three timeouts this replaces.  `ps aux` does not wedge,
#: and a truncated table reads as "that process is not running", which for the
#: liveness probes above is a false negative on a healthy host.
_TIMEOUT = 8


@cached_snapshot(_TTL)
def _ps_table() -> tuple[str, ...]:
    rc, out, _ = sh(["/bin/ps", "aux"], timeout=_TIMEOUT)
    # An empty tuple on failure, matching what every hand-written copy did with a
    # non-zero rc: no rows, so no process is reported as running.
    return tuple(_as_text(out).splitlines()) if rc == 0 else ()


def ps_lines(force: bool = False) -> tuple[str, ...]:
    """`ps aux` output lines including the header, cached for :data:`_TTL`.

    A tuple rather than a list so the cached object can be shared with concurrent
    callers without copying it for each of them, and so a caller cannot mutate the
    shared copy.

    ``cached_snapshot`` supplies the TTL, the single-flight refresh and the ``force``
    bypass, rather than this module hand-writing a seventh copy of that shape.

    An empty table means the read failed -- `ps` prints a header on success -- and is
    not kept: ``cached_snapshot`` holds any non-``None`` value, so one failure would
    otherwise tell every liveness probe in the panel that nothing is running for the
    whole TTL.
    """
    value = _ps_table(force=force)
    if not value:
        _ps_table.invalidate()  # type: ignore[attr-defined]
    return value


#: Exposed for the callers that just changed the table and must observe the change:
#: cloudflared polls for its tunnel process to appear after a bootstrap, and the
#: native app loader does the same after a kickstart.
invalidate_processes = _ps_table.invalidate  # type: ignore[attr-defined]


def ps_pid_commands(force: bool = False) -> tuple[tuple[int, str], ...]:
    """``(pid, command)`` rows from the shared ``ps aux`` table.

    ``sensors_svc``, ``wireguard_wstunnel`` and ``cloudflared_svc.stop`` each
    used to spawn their own ``ps -A`` / ``ps -ax`` / ``ps axo``.  Those
    timed out on this host (serverhub.err.log) while ``ps aux`` was already
    cached for the same request.  The 11-column ``aux`` layout is the
    contract: a short fixture that is only ``USER PID COMMAND`` is not a
    process table.
    """
    lines = ps_lines(force=force)
    if len(lines) < 2:
        return ()
    rows: list[tuple[int, str]] = []
    for line in lines[1:]:
        text = _as_text(line)
        parts = text.split(None, 10)
        if len(parts) < 11:
            continue
        try:
            pid = int(parts[1])
        except (TypeError, ValueError, OverflowError):
            # YAML ``.inf`` as a planted pid column: ``int(inf)`` OverflowError.
            continue
        rows.append((pid, parts[10]))
    return tuple(rows)


def process_matches(needle: str, *, force: bool = False) -> bool:
    """True if any process command line contains *needle* (case-insensitive).

    Skips the line describing this very read, which is what every copy of this
    predicate did: a `ps aux` row for `ps aux` itself would otherwise answer yes
    to a needle that happens to appear in the panel's own argv.
    """
    if not isinstance(needle, str) or not needle:
        return False
    needle = needle.lower()
    for line in ps_lines(force=force):
        low = _as_text(line).lower()
        if needle in low and "ps aux" not in low:
            return True
    return False
