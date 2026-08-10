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

from hub.util import cached_snapshot, sh

#: Long enough to collapse the readers inside one request, short enough that the
#: Tools process table still looks live.  ``tools_svc`` had settled on 5s for the
#: same command and the same reason.
_TTL = 5.0

#: The generous end of the three timeouts this replaces.  `ps aux` does not wedge,
#: and a truncated table reads as "that process is not running", which for the
#: liveness probes above is a false negative on a healthy host.
_TIMEOUT = 8


@cached_snapshot(_TTL)
def ps_lines() -> tuple[str, ...]:
    """`ps aux` output lines including the header, cached for :data:`_TTL`.

    A tuple rather than a list so the cached object can be shared with concurrent
    callers without copying it for each of them, and so a caller cannot mutate the
    shared copy.

    ``cached_snapshot`` supplies the TTL, the single-flight refresh and the ``force``
    bypass, rather than this module hand-writing a seventh copy of that shape.
    """
    rc, out, _ = sh(["/bin/ps", "aux"], timeout=_TIMEOUT)
    # An empty tuple on failure, matching what every hand-written copy did with a
    # non-zero rc: no rows, so no process is reported as running.
    return tuple((out or "").splitlines()) if rc == 0 else ()


#: Exposed for the callers that just changed the table and must observe the change:
#: cloudflared polls for its tunnel process to appear after a bootstrap, and the
#: native app loader does the same after a kickstart.
invalidate_processes = ps_lines.invalidate  # type: ignore[attr-defined]


def process_matches(needle: str, *, force: bool = False) -> bool:
    """True if any process command line contains *needle* (case-insensitive).

    Skips the line describing this very read, which is what every copy of this
    predicate did: a `ps aux` row for `ps aux` itself would otherwise answer yes
    to a needle that happens to appear in the panel's own argv.
    """
    if not needle:
        return False
    needle = needle.lower()
    for line in ps_lines(force=force):
        low = line.lower()
        if needle in low and "ps aux" not in low:
            return True
    return False
