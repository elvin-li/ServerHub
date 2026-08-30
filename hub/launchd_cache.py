"""Single source for `launchctl list`.

Four modules needed the same listing and each shelled out on its own, with the
parse written out again every time and no two copies quite agreeing:

    health_svc._running_labels          `launchctl list`,      numeric-PID labels
    autostart_svc._loaded_labels        `/bin/launchctl list`,  raw text, substring
    native_catalog._LaunchdSnapshot     `/bin/launchctl list`,  numeric-PID labels
    immich_svc (inline)                 `launchctl list`,       line.endswith()

Two costs came out of that.  The obvious one is duplicate spawns: one
`/api/health/checks` ran the listing three times and `/api/apps/managed` twice,
each time to answer the same question about the same launchd session.  The subtler
one is that ``launchctl`` and ``/bin/launchctl`` are not the same argv, so the two
spellings hid half the duplication from any measurement that groups by command --
and the bare spelling depends on the panel's PATH, which a LaunchAgent does not
necessarily set.

The parse divergence mattered more than the spawns.  ``launchctl list`` prints
``PID\\tStatus\\tLabel`` with a header row, and:

* *loaded* means the label appears at all, including with ``-`` for a PID -- an
  agent that is installed but not currently running.
* *running* means column one is a live PID.

``health_svc`` tested ``p[0] not in ("-", "")``, which lets the header through and
put the literal string ``Label`` in a set of running jobs.  ``autostart_svc``
asked ``label in raw_text``, a substring test that answers yes for ``local.foo``
when only ``local.foobar`` is listed.  Both distinctions are kept apart here
rather than collapsed, because callers genuinely want different ones and a wrong
answer in either direction is a wrong autostart toggle in the UI.
"""
from __future__ import annotations

import re
from types import MappingProxyType

from hub.util import cached_snapshot, sh

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")


def _isinst(value, types) -> bool:
    """``isinstance`` that a leftover ``__class__`` bomb cannot 500 through.

    CPython's ``isinstance`` reads the operand's ``__class__`` whenever the
    real-type fast check misses, so a leftover whose ``__class__`` is a
    raising property blew unguarded launchctl row gates — GET
    /api/health/checks answered HTTP 500 instead of dropping the junk cell.
    Fail-closed.
    """
    try:
        return isinstance(value, types)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _as_text(value) -> str:
    """``launchctl`` leftovers arrive as int/None/bytes; leftover ``\\ud800`` used to 500 health/apps JSON."""
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

#: Deliberately short.  This is a dependency cache, not a page cache: every
#: consumer already sits behind a much longer TTL of its own (the health snapshot,
#: the app inventory, the autostart overview), so the only window this has to cover
#: is one request's worth of overlapping readers -- milliseconds apart.
#:
#: A longer TTL would buy nothing and would widen the read-after-write gap for the
#: mutation paths below, every one of which calls :func:`invalidate_launchd`.  What
#: is left is a bootstrap or bootout performed outside the panel, bounded by this.
_TTL = 2.0

#: `launchctl list` on a session with a few hundred jobs answers in ~40ms, but it
#: is still a spawn and it is still on the request path.
_TIMEOUT = 8


class Listing:
    """One `launchctl list` result, parsed every way its callers need.

    Immutable -- ``frozenset`` and a read-only mapping view -- so the cached object
    can be handed to concurrent callers without copying it for each of them, and so
    a caller cannot quietly corrupt the shared copy.
    """

    __slots__ = ("loaded", "running", "jobs")

    def __init__(self, jobs: dict[str, tuple[str, str]]) -> None:
        #: label -> (pid column, status column), verbatim.  ``nginx_svc`` reports the
        #: pid and the discovery pass reports both, so dropping the columns and
        #: keeping only label sets would have left those two shelling out again.
        #:
        #: Coerce pid/status to str: a fixture that stuffed ints used to
        #: AttributeError on ``pid.isdigit()`` and 500 every launchd reader.
        clean: dict[str, tuple[str, str]] = {}
        try:
            items = list((jobs or {}).items())
        except _CONTROL_FLOW:
            raise
        except BaseException:
            items = []
        for label, entry in items:
            name = _as_text(label).strip()
            if not name or name == "Label":
                continue
            if _isinst(entry, (tuple, list)) and len(entry) >= 2:
                pid, status = _as_text(entry[0]), _as_text(entry[1])
            else:
                continue
            clean[name] = (pid, status)
        self.jobs = MappingProxyType(clean)
        #: Every label in the listing, running or not.
        self.loaded = frozenset(clean)
        #: Labels whose pid column is a live pid.
        self.running = frozenset(
            label for label, (pid, _status) in clean.items() if pid.isdigit()
        )

    def pid_for(self, label: str) -> str | None:
        """The pid of *label*, or None when it is not listed or not running."""
        entry = self.jobs.get(label)
        if entry is None:
            return None
        pid = entry[0]
        if not pid or not pid.isdigit():
            return None
        return pid


_EMPTY = Listing({})


def _parse(out: str) -> Listing:
    jobs: dict[str, tuple[str, str]] = {}
    for line in _as_text(out).splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        pid, status, label = parts
        if not label or label == "Label":
            # The header row.  Guarded on the label rather than on the pid column,
            # because `PID` is what the header puts there too -- and testing the pid
            # for "not a dash" is what let the header through as a running job
            # called Label.
            continue
        jobs[label] = (pid, status)
    return Listing(jobs)


@cached_snapshot(_TTL)
def _listing() -> Listing:
    rc, out, _ = sh(["/bin/launchctl", "list"], timeout=_TIMEOUT)
    return _parse(out) if rc == 0 else _EMPTY


def listing(force: bool = False) -> Listing:
    """The launchd session listing, cached for :data:`_TTL` with one refresh.

    ``cached_snapshot`` rather than a sixth hand-written ``{"t": ..., "v": ...}``
    pair: it is the same TTL-plus-single-flight shape, already written once, and it
    publishes the timestamp and the payload under one lock.  The hand-written copies
    it replaced elsewhere in this tree each got one of those two details wrong.

    A failed listing is returned empty, which degrades callers to the per-label
    ``launchctl print`` rather than to a false negative -- but it is *not* kept.
    ``cached_snapshot`` holds any value that is not ``None``, and an empty listing is
    not ``None``, so without dropping it a single failed read would answer four
    modules for the whole TTL.  Each of those modules used to fail independently and
    retry on its own next call, and consolidating them must not turn that into a
    shared sticky failure.
    """
    value = _listing(force=force)
    if not value.loaded:
        _listing.invalidate()  # type: ignore[attr-defined]
    return value


#: Named for what it means at the call sites -- ``invalidate_launchd()`` reads as a
#: statement about launchd rather than about this module's cache -- and exported
#: because every path in hub/ that loads, unloads, kickstarts, enables or disables a
#: job has to call it.  A mutation handler re-reads the state to report what it did,
#: which is precisely the case a TTL answers with the world as it was.
invalidate_launchd = _listing.invalidate  # type: ignore[attr-defined]


def running_labels(force: bool = False) -> frozenset[str]:
    """Labels launchd reports with a live PID."""
    return listing(force=force).running


def loaded_labels(force: bool = False) -> frozenset[str]:
    """Labels present in the listing, whether or not they are running."""
    return listing(force=force).loaded
