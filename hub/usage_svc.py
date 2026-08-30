"""Disk-usage explorer, large-file and duplicate finder, Spotlight index control.

"The array is 94% full and nobody knows why" is the most common NAS support
question, and both Unraid (via plugins) and OMV answer it with a usage tree.  This
module provides that, plus the two follow-up questions an operator actually has:
which files are the biggest, and which ones exist twice.

Everything here is strictly read-only.  Nothing in this module deletes, moves or
modifies a single byte — the point is to tell the operator where to look, and the
existing file manager is where an actual deletion happens, behind its own
confirmation and audit trail.

Scan roots are deliberately wider than the file manager's browse roots (data on a
NAS lives on ``/Volumes`` and in exported shares, not just under ``~/Services``)
but narrower than the whole filesystem, and every candidate still passes through
``files_svc.is_protected``.  System directories are never walked, so a usage report
cannot become a way to enumerate ``/etc`` or someone's dotfiles.

Each walk is bounded twice, by wall-clock seconds and by entry count, and reports
whether it hit either ceiling.  An unbounded ``du`` over a spinning 20 TB array is
how a panel becomes the reason the machine is slow.
"""
from __future__ import annotations

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)

import hashlib
import os
import stat
import threading
import time
from pathlib import Path

from hub import files_svc
from hub.errors import api_error
from hub.util import fan_out, sh, strftime_now

MDUTIL = "/usr/bin/mdutil"

#: Wall-clock and entry ceilings for a single request.
#:
#: Wall clock is the limit meant to bind, because it is the one the operator
#: experiences; the entry counts are a backstop against a pathological tree
#: (millions of empty files) making the clock check itself the bottleneck.  An
#: earlier pass had the entry cap an order of magnitude lower, which made the
#: duplicate scan give up after ~11% of a normal ``~/Services`` tree and report a
#: truthful but useless "0 duplicates, truncated".
SCAN_SECONDS = 20.0
SCAN_ENTRIES = 2_000_000
DUP_SECONDS = 25.0
DUP_CANDIDATES = 2_000_000

#: Only files at least this large are considered for duplicate detection; a NAS
#: has tens of thousands of tiny identical files (icons, __init__.py) and none of
#: them are the reason a disk is full.
DUP_MIN_BYTES = 1024 * 1024

#: Directories never walked, regardless of how a root resolves.
_NEVER_WALK = (
    "/System", "/private/var/db", "/private/var/folders", "/usr", "/bin",
    "/sbin", "/dev", "/cores", "/Library/Caches", "/.Spotlight-V100",
    "/.fseventsd", "/.DocumentRevisions-V100", "/.TemporaryItems",
)

_HASH_CHUNK = 1024 * 1024

#: Concurrent readers per walk.
#:
#: These walks are `os.scandir` + `stat` + `read`: the threads sit in syscalls
#: with the GIL released, so the useful width is set by how many concurrent
#: metadata reads the volume will service, not by core count.
#:
#: Four because that is what measured fastest, and because more is actively
#: worse.  Walking ~421k files under ~/Services, taking the minimum of several
#: rounds (this host has enough background load that a single reading measures the
#: neighbours instead of the code):
#:
#:     serial   13.8s      w=3   9.0s     w=6  10.1s
#:     w=1      13.7s      w=4   6.9s     w=8  10.2s
#:     w=2      13.8s      w=5   8.5s     w=12 10.4s
#:
#: The w=1 row is the control: it runs the concurrent code path with no
#: concurrency and lands on the serial time, so the speedup below it is threads
#: rather than an incidental rewrite of the walk.  Past ~5 the extra threads queue
#: inside APFS rather than overlap and give the time back.
#:
#: Deliberately not `util.MAX_PROBE_WORKERS` (8): that ceiling is for probes
#: blocked on separate subprocesses and sockets, which do not contend with each
#: other.  Every thread here queues against the same volume.
_SCAN_WORKERS = 4

#: Entries a worker claims from the shared ceiling in one go.  See _Budget.
_LEASE = 4096


def _isa(value, kinds) -> bool:
    """``isinstance`` that survives a leftover ``__class__``-property bomb.

    ``isinstance`` consults ``value.__class__`` when the exact-type check
    misses, so a leftover whose ``__class__`` is a *raising property*
    detonated the gate itself: ``scan_roots``' per-row gates 500'd all four
    usage routes on one poisoned root/share row, and ``set_spotlight``'s
    result gate blew POST /api/storage/spotlight one line ahead of the
    laundering built to absorb junk shapes.  A real subclass still matches
    through the C-level type check; only a value that cannot answer what
    it is takes the non-matching branch.
    """
    try:
        return isinstance(value, kinds)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _as_text(value) -> str:
    """JSON-safe text. Leftover ``\\ud800`` in a filename used to 500 usage JSON."""
    if _isa(value, (bytes, bytearray)):
        # Unbound base decode (the modules5 / nas_common rule): a leftover
        # bytes-subclass whose bound ``.decode`` raises used to 500
        # GET /api/storage/usage out of _spotlight_query.  In a try (the
        # modules9 rule): a *lying* ``__class__`` claiming bytes passes the
        # gate but is no bytes underneath, and the descriptor's TypeError
        # rode the same paths — it falls through to the str() probe so a
        # legible impostor still renders.
        base = bytes if _isa(value, bytes) else bytearray
        try:
            value = base.decode(value, "utf-8", "replace")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            pass
    if value is None:
        return ""
    if type(value) is not str:
        try:
            value = str(value)
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
    # Unbound base encode (the nas_common._utf8_text / modules6 rule):
    # ``str()`` of a subclass whose ``__str__`` answers *self* skips
    # CPython's exact-str copy, so the old bound ``value.encode(...)`` ran
    # the subclass override — a leftover encode bomb raised out of
    # set_spotlight's vanish classification and 500'd
    # POST /api/storage/spotlight, and an encode that *returned* a hostile
    # buffer walked its own str back out and 500'd GET /api/storage/usage
    # at ``blob.lower()``.  The base pair answers an exact str always.
    return bytes.decode(str.encode(value, "utf-8", "replace"), "utf-8")


def _truthy(value) -> bool:
    """``bool(value)`` that survives a leftover ``__bool__`` bomb (fails False)."""
    try:
        return bool(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _exact_str(value) -> str | None:
    """*value* as an exact ``str`` (surrogates preserved), or None.

    Unlike :func:`_as_text` this never scrubs: a real path read off
    ``os.scandir`` carries surrogateescape'd bytes that must round-trip to
    ``open()``.  What it does refuse is a str-*subclass* keeping its
    overrides: a leftover whose ``__hash__`` answers a real key's bucket
    while its ``__eq__`` raises detonates *every* later probe of that
    bucket (the wave-10 hash-shadowing class), and one whose ``__lt__``
    raises blows the sort it rides into.  The unbound base encode/decode
    pair walks the real C-level buffer, so the copy carries no override; a
    lying ``__class__`` claiming str fails the base call and reads as
    not-text.
    """
    if type(value) is str:
        return value
    if not _isa(value, str):
        return None
    try:
        return bytes.decode(
            str.encode(value, "utf-8", "surrogatepass"),
            "utf-8", "surrogatepass",
        )
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None


def _safe_bytes(value) -> int:
    """Clamp a ``stat.st_size`` so ``inf``/None cannot 500 the JSON encoder.

    ``int(...)`` with a try only guards *conversions*: a leftover FUSE/SMB
    ``st_size`` that is already a >4300-digit int passed through untouched,
    and CPython's int->str digit limit then ValueError'd Starlette's
    ``json.dumps`` — 500ing GET /api/storage/usage/tree, /largest and
    /duplicates after the walk had already finished.  ``float()`` rejects
    anything beyond float range, the same junk test files_svc._finite_int
    and logs_svc._stat_size apply to their stat numbers.

    The except is total, not the conversion tuple: a leftover ``st_size``
    whose ``__int__``/``__index__`` *raises RuntimeError* (a raising
    descriptor riding a poisoned stat result) sailed past the old
    ``(TypeError, ValueError, OverflowError, OSError)`` list and out of the
    walk loops, whose per-entry catches were just as narrow — a raw 500 on
    /tree and a dead ``_walk_parallel`` worker on /largest and /duplicates.
    Junk of any spelling reads as 0 bytes here.
    """
    try:
        n = int(value)
        float(n)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return 0
    return n if n > 0 else 0


def _json_float(value, ndigits: int = 2, default: float = 0.0) -> float:
    """Finite float for JSON; OverflowError / inf must not 500 allow_nan=False."""
    try:
        n = float(value)
    except (TypeError, ValueError, OverflowError):
        return default
    if n != n or n in (float("inf"), float("-inf")):
        return default
    n = round(n, ndigits)
    if n != n or n in (float("inf"), float("-inf")):
        return default
    return n


def _gb(n: int) -> float:
    try:
        g = n / 2**30
    except (OverflowError, ValueError, ZeroDivisionError, TypeError):
        return 0.0
    return _json_float(g, 2)


def _dup_min_mb(floor: int) -> float:
    try:
        return floor / (1024 * 1024)
    except (OverflowError, ValueError, ZeroDivisionError, TypeError):
        return 1.0


def _is_never_walk(path: Path) -> bool:
    text = str(path)
    for blocked in _NEVER_WALK:
        if text == blocked or text.startswith(blocked + "/"):
            return True
    # Volume-relative variants of the metadata stores above.
    return any(part in {".Spotlight-V100", ".fseventsd", ".DocumentRevisions-V100", ".TemporaryItems"}
               for part in path.parts)


def scan_roots() -> list[dict]:
    """Directories the usage scanner may walk.

    The file manager's roots, plus every mounted volume under ``/Volumes`` and
    every directory currently exported as a share.  Deduplicated by resolved path.
    """
    roots: list[dict] = []
    seen: set[str] = set()

    def add(root_id: str, name: str, path) -> None:
        try:
            resolved = Path(path).resolve()
        except (OSError, ValueError, TypeError, RuntimeError):
            return
        text = str(resolved)
        try:
            if text in seen or not resolved.is_dir():
                return
        except OSError:
            return
        if _is_never_walk(resolved) or files_svc.is_protected(resolved):
            return
        seen.add(text)
        roots.append({
            "id": _as_text(root_id),
            "name": _as_text(name),
            "path": _as_text(text),
        })

    try:
        incoming = files_svc.default_roots()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # The guard below covered *iteration* but not the call: a
        # default_roots that raised outright (a seam replacement, a leftover
        # that slips its own guards) still 500'd GET /api/storage/usage,
        # /tree, /largest and /duplicates at once — the storage_pool_svc
        # _candidates rule, one seam earlier than the iteration bomb.  The
        # sibling seam (shares_svc.list_smb_shares) has carried this guard
        # all along; the volumes and shares below still contribute.
        incoming = []
    # None/int leftover used to TypeError GET /api/storage/usage.
    if not _isa(incoming, (list, tuple)):
        incoming = []
    try:
        incoming = list(incoming)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # A roots listing that refuses *iteration* (odd list subclass passing
        # the isinstance gate above) used to raise out of this loop and 500
        # GET /api/storage/usage, /tree, /largest and /duplicates — the
        # ups_svc/storage_svc materialize-under-guard rule.  The volumes and
        # shares below still contribute their roots.
        incoming = []
    for entry in incoming:
        # _isa: a ``__class__``-property bomb row used to detonate this
        # gate itself and 500 all four usage routes, where every other
        # junk row already drops alone.
        if not _isa(entry, dict):
            continue
        try:
            # Per-row guard, the storage_pool_svc._candidates class: a dict
            # *subclass* passes the isinstance gate with a ``.get`` that
            # raises (or a value whose ``__bool__`` raises under the ``or``),
            # and one such row used to 500 all four usage routes while every
            # healthy sibling root was droppable collateral.  The hostile row
            # drops alone; its siblings keep contributing.
            path = entry.get("path")
            if not _isa(path, str) or not path:
                continue
            # _as_text is a str() probe, not a bare str(): a leftover root id
            # or name that is *already* a >4300-digit int (YAML/plist hex
            # loads with int(x, 16), exempt from the int(str) parse cap) made
            # the old bare str() raise the digit-cap ValueError out of
            # scan_roots and 500 every usage route; sane numeric ids keep
            # their string form.
            rid = _as_text(entry.get("id") or "root") or "root"
            add(rid, _as_text(entry.get("name") or ""), path)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue

    volumes = Path("/Volumes")
    try:
        listed = volumes.is_dir()
    except OSError:
        listed = False
    if listed:
        try:
            children = sorted(volumes.iterdir())
        except OSError:
            children = []
        for child in children:
            try:
                if child.is_symlink() or not child.is_dir():
                    continue
            except OSError:
                continue
            add(f"vol-{child.name}", child.name, child)

    try:
        from hub import shares_svc

        listed = shares_svc.list_smb_shares(include_sizes=False) or []
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # Share enumeration is a convenience here, never a hard dependency.
        listed = []
    if not _isa(listed, (list, tuple)):
        listed = []
    try:
        listed = list(listed)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # Same class as the roots listing above: a share listing that passes
        # the isinstance gate but refuses iteration must cost the shares
        # section, never the request — the roots already gathered survive.
        listed = []
    for share in listed:
        # _isa, same class as the roots loop above: a ``__class__``-bomb
        # share row must drop alone, never 500 the usage routes.
        if not _isa(share, dict):
            continue
        try:
            # Per-row guard, same class as the roots loop above: a dict
            # subclass whose ``.get`` raises passed the isinstance gate and
            # 500'd every usage route; the hostile share drops alone and its
            # sibling shares keep contributing.
            path = share.get("path")
            # Path() TypeError'd a non-str share path and 500'd the usage page.
            if not _isa(path, str) or not path.startswith("/"):
                continue
            # _as_text is a str() probe, not an isinstance gate: a numeric
            # leftover name keeps behaving as its string form, while a
            # >4300-digit *already-int* (plist/YAML hex loads with int(x, 16),
            # exempt from the int(str) parse cap) scrubs to "" and takes the
            # fallback.  The old bare f-string/str() raised the digit-cap
            # ValueError into the loop-wide except, which silently dropped
            # every share after it from the usage roots.
            name = _as_text(share.get("name"))
            add(f"share-{name or 'share'}", name or path, path)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue

    return roots


def _resolve(path: str | None, root_id: str | None) -> Path:
    """Validate *path* against :func:`scan_roots`, mirroring files_svc semantics."""
    roots = scan_roots()
    if not roots:
        raise api_error("files.no_roots")

    base: Path | None = None
    if root_id:
        for root in roots:
            if root["id"] == root_id:
                base = Path(root["path"])
                break
        if base is None:
            raise api_error("files.unknown_root", root_id=root_id)

    if not path or path in (".", "/"):
        return base or Path(roots[0]["path"])

    candidate = files_svc._try_resolve(path)
    if candidate is None:
        # Symlink loops: 3.12 resolve() raised RuntimeError; 3.14 returns the
        # looping path.  Either way this is not a walkable directory.
        raise api_error("files.not_found", path=str(path)[:200])

    allowed = [base] if base else [Path(r["path"]) for r in roots]
    if not any(candidate == a or a in candidate.parents for a in allowed):
        raise api_error("files.path_outside_root")
    if _is_never_walk(candidate) or files_svc.is_protected(candidate):
        raise api_error("files.path_protected")
    try:
        exists = candidate.exists()
        is_dir = candidate.is_dir() if exists else False
    except OSError:
        # exists/is_dir on a dying FUSE mount raise EIO; files_svc.list_dir
        # already maps that to permission_denied.
        raise api_error("files.permission_denied", path=str(candidate))
    if not exists:
        raise api_error("files.not_found", path=str(candidate))
    if not is_dir:
        raise api_error("files.not_a_dir")
    return candidate


class _Budget:
    """Shared wall-clock + entry ceiling for one walk, across any number of threads.

    The entry ceiling is handed out in blocks (:data:`_LEASE`) rather than
    decremented per entry.  A walk calls into the budget hundreds of thousands of
    times, so a lock on every entry would cost more than the concurrency it
    guards: leasing takes the lock once per few thousand entries instead, and the
    only inaccuracy is that a run can stop with up to one unspent lease per
    thread still on the books -- irrelevant against a ceiling in the millions.

    ``deadline`` is written once at construction and only read afterwards, and
    ``truncated`` only ever goes False -> True, so neither needs the lock.

    Callers do not spend directly; each thread takes its own :class:`_Spender`.
    """

    __slots__ = ("deadline", "truncated", "_remaining", "_lock")

    def __init__(self, seconds: float, entries: int):
        self.deadline = time.monotonic() + seconds
        self.truncated = False
        self._remaining = entries
        self._lock = threading.Lock()

    def expired(self) -> bool:
        """Check the clock unconditionally (for use between coarse work items)."""
        if time.monotonic() > self.deadline:
            self.truncated = True
            return True
        return False

    def lease(self, size: int = _LEASE) -> int:
        """Claim up to *size* entries from the shared ceiling; 0 when exhausted."""
        with self._lock:
            granted = min(size, self._remaining)
            self._remaining -= granted
        if granted <= 0:
            self.truncated = True
        return granted

    def spender(self) -> "_Spender":
        return _Spender(self)


class _Spender:
    """One thread's view of a :class:`_Budget`.

    Holds an unshared lease so the common path touches no lock, and samples the
    clock once per :data:`_CLOCK_EVERY` entries -- a walk calls ``spend`` often
    enough that ``time.monotonic()`` stops being free.  The granularity costs at
    most a few milliseconds of overshoot.
    """

    __slots__ = ("_budget", "_left", "_tick")

    def __init__(self, budget: _Budget):
        self._budget = budget
        self._left = 0
        self._tick = 0

    def expired(self) -> bool:
        return self._budget.expired()

    def spend(self, n: int = 1) -> bool:
        self._left -= n
        if self._left <= 0:
            self._left = self._budget.lease()
            if self._left <= 0:
                return False
        self._tick += 1
        if self._tick >= _CLOCK_EVERY:
            self._tick = 0
            return not self._budget.expired()
        return True


#: How many entries pass between wall-clock samples inside a walk.
_CLOCK_EVERY = 512


def _walk_parallel(target: Path, budget: _Budget, make_sink, on_file, *,
                   workers: int = _SCAN_WORKERS) -> list:
    """Walk everything under *target* with *workers* threads; return their sinks.

    A shared stack of pending directories that every worker pops from, rather than
    a static split of the top level.  The tree's own shape then decides the
    parallelism: a root whose entire content hangs off one subdirectory overlaps
    just as well as one with forty children, which a top-level split cannot do.

    *make_sink* is called once per worker and *on_file*(entry, sink) once per file,
    both on the worker's thread -- so a sink is never shared and needs no locking.
    The caller merges the returned sinks.

    Termination is "every worker is idle and the stack is empty".  Exhausting the
    budget ends the walk for everyone: a worker that returned while others waited
    on the condition would hang the request until its timeout.
    """
    stack: list[Path] = [target]
    cond = threading.Condition()
    idle = 0
    finished = False

    def _next() -> Path | None:
        nonlocal idle, finished
        with cond:
            while True:
                if finished:
                    return None
                if stack:
                    return stack.pop()
                idle += 1
                if idle >= workers:
                    # Nobody is walking and nothing is queued: the tree is done.
                    finished = True
                    cond.notify_all()
                    return None
                cond.wait()
                idle -= 1

    def _push(paths: list[Path]) -> None:
        if not paths:
            return
        with cond:
            stack.extend(paths)
            cond.notify_all()

    def _stop() -> None:
        nonlocal finished
        with cond:
            finished = True
            cond.notify_all()

    def run(_index: int):
        sink = make_sink()
        spender = budget.spender()
        # The backstop except is the difference between a degraded walk and
        # a hung route: a worker that raises out of this loop never reaches
        # the all-idle rule, so its siblings wait on the condition forever
        # and the request hangs past every budget (the deadline cannot fire
        # a thread parked in ``cond.wait``).  A leftover ``st_size`` whose
        # ``__int__`` raises RuntimeError did exactly that to /largest and
        # /duplicates: the per-entry catch below was a narrow tuple, the
        # raise killed one worker, and the other three waited forever.
        try:
            while True:
                current = _next()
                if current is None:
                    return sink
                if spender.expired():
                    _stop()
                    return sink
                subdirs: list[Path] = []
                try:
                    with os.scandir(current) as it:
                        for entry in it:
                            if not spender.spend():
                                _stop()
                                return sink
                            try:
                                if entry.is_symlink():
                                    continue
                                if entry.is_dir(follow_symlinks=False):
                                    child = Path(entry.path)
                                    if not _is_never_walk(child):
                                        subdirs.append(child)
                                elif entry.is_file(follow_symlinks=False):
                                    on_file(entry, sink)
                            except _CONTROL_FLOW:
                                raise
                            except BaseException:
                                # Total, not (OSError, ValueError, TypeError):
                                # a poisoned entry whose stat fields raise
                                # RuntimeError must cost its own row, never
                                # the worker (and with it the request).
                                continue
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    pass
                _push(subdirs)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            _stop()
            return sink

    # fan_out builds a pool of exactly len(items) threads here, which is what the
    # all-idle termination rule counts on.
    return fan_out(run, range(workers), max_workers=workers)


def _dir_size(path: Path, spender: _Spender) -> tuple[int, int]:
    """(bytes, file count) under *path*, following no symlinks.

    Takes a :class:`_Spender` rather than the budget itself: several of these run
    at once, one per child of the directory being listed, and each needs its own
    unshared lease.
    """
    total = 0
    files = 0
    stack = [path]
    while stack:
        current = stack.pop()
        if spender.expired():
            break
        try:
            with os.scandir(current) as it:
                for entry in it:
                    if not spender.spend():
                        return total, files
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            child = Path(entry.path)
                            if not _is_never_walk(child):
                                stack.append(child)
                        elif entry.is_file(follow_symlinks=False):
                            total += _safe_bytes(entry.stat(follow_symlinks=False).st_size)
                            files += 1
                    except _CONTROL_FLOW:
                        raise
                    except BaseException:
                        # Total, matching _walk_parallel: a poisoned entry
                        # raising RuntimeError out of a stat descriptor used
                        # to escape the old tuple, ride fan_out's re-raise
                        # and 500 GET /api/storage/usage/tree.
                        continue
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
    return total, files


def tree(path: str | None = None, root_id: str | None = None) -> dict:
    """Immediate children of *path* with recursive sizes, largest first.

    One level at a time, the way a usage explorer is actually driven: the operator
    drills into the big directory rather than waiting for a whole-array report.
    """
    target = _resolve(path, root_id)
    budget = _Budget(SCAN_SECONDS, SCAN_ENTRIES)
    started = time.monotonic()

    children: list[dict] = []
    own_files = 0
    own_bytes = 0
    try:
        with os.scandir(target) as it:
            entries = list(it)
    except FileNotFoundError:
        # _resolve's exists() can lose a race; a vanished dir is not a 403.
        raise api_error("files.not_found", path=str(target))
    except NotADirectoryError:
        raise api_error("files.not_a_dir")
    except OSError:
        raise api_error("files.permission_denied", path=str(target))
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # A scandir iterator dying mid-listing with a non-OSError (a
        # leftover FUSE seam raising RuntimeError) used to 500 the route
        # raw; an unlistable directory is the permission_denied class.
        raise api_error("files.permission_denied", path=str(target))

    # Split the listing first, then size the directories concurrently.  Sizing
    # them one after another was the whole cost of this endpoint: 34 children of
    # ~/Services took 11.3s serially without coming near the budget, so every bit
    # of it was one thread waiting on a device that had capacity to spare.
    subdirs: list[os.DirEntry] = []
    for entry in entries:
        try:
            if entry.is_symlink():
                continue
            if entry.is_dir(follow_symlinks=False):
                child = Path(entry.path)
                if _is_never_walk(child) or files_svc.is_protected(child):
                    continue
                subdirs.append(entry)
            elif entry.is_file(follow_symlinks=False):
                size = _safe_bytes(entry.stat(follow_symlinks=False).st_size)
                own_files += 1
                own_bytes += size
                children.append({
                    "name": _as_text(entry.name),
                    "path": _as_text(entry.path),
                    "kind": "file",
                    "bytes": size,
                    "gb": _gb(size),
                    "files": 1,
                })
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # Total, not (OSError, ValueError, TypeError): a poisoned entry
            # whose ``name``/``path``/stat fields raise RuntimeError used to
            # escape the tuple and 500 GET /api/storage/usage/tree; the
            # hostile entry drops alone, its siblings keep rendering.
            continue

    def _sized(e) -> tuple[int, int]:
        # Guarded per subdir: ``Path(e.path)`` on a poisoned entry raised
        # inside the fan_out worker, and fan_out re-raises on iteration —
        # one hostile subdir used to 500 the whole tree listing.
        try:
            return _dir_size(Path(e.path), budget.spender())
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return 0, 0

    sizes = fan_out(_sized, subdirs, max_workers=_SCAN_WORKERS)
    for entry, (size, files) in zip(subdirs, sizes):
        try:
            children.append({
                "name": _as_text(entry.name),
                "path": _as_text(entry.path),
                "kind": "dir",
                "bytes": size,
                "gb": _gb(size),
                "files": files,
            })
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # Same class one loop later: the row build reads the entry's
            # properties again, and a raising descriptor here sat outside
            # any guard.
            continue

    children.sort(key=lambda c: c["bytes"], reverse=True)
    total = sum(c["bytes"] for c in children)
    for child in children:
        try:
            child["percent"] = (
                _json_float(child["bytes"] / total * 100, 1) if total else 0.0
            )
        except (OverflowError, ValueError, ZeroDivisionError, TypeError):
            child["percent"] = 0.0

    parent = _as_text(target.parent)
    roots = {r["path"] for r in scan_roots()}
    return {
        "path": _as_text(target),
        "parent": parent if _as_text(target) not in roots else "",
        "roots": scan_roots(),
        "total_bytes": total,
        "total_gb": _gb(total),
        "own_files": own_files,
        "own_bytes": own_bytes,
        "children": children[:400],
        "child_count": len(children),
        "truncated": budget.truncated,
        "elapsed_sec": round(time.monotonic() - started, 2),
    }


def largest_files(path: str | None = None, root_id: str | None = None, limit: int = 50) -> dict:
    """The biggest files anywhere under *path*."""
    target = _resolve(path, root_id)
    try:
        cap = max(1, min(int(limit or 50), 500))
    except (TypeError, ValueError, OverflowError):
        cap = 50
    budget = _Budget(SCAN_SECONDS, SCAN_ENTRIES)
    started = time.monotonic()

    # Each worker keeps its own trimmed top list.  Merging per-worker top-N lists
    # is exact for a global top-N as long as each local list is never trimmed
    # below `cap` -- a file that belongs in the global top `cap` cannot have been
    # dropped from its own worker's list while `cap` larger ones from that same
    # worker survive.
    # `scanned` counts files seen, not files kept, so it is tracked separately --
    # deriving it from the retained list would report the trim size instead.
    def _sink() -> dict:
        return {"seen": 0, "top": []}

    def _on_file(entry, sink: dict) -> None:
        # One guard over every read, not just the stat call: a poisoned
        # entry whose ``st_size`` / ``st_mtime`` / ``path`` descriptors
        # raise RuntimeError used to escape the old bare ``except OSError``,
        # kill its _walk_parallel worker and hang the request (see run()).
        # _exact_str on the path: a str-subclass path keeping its overrides
        # would ride the top tuples into ``found.sort`` and ``Path(p)``
        # below; the base copy preserves surrogateescape'd bytes so a real
        # odd filename still renders.
        try:
            st = entry.stat(follow_symlinks=False)
            size = _safe_bytes(st.st_size)
            path = _exact_str(entry.path)
            mtime = st.st_mtime
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return
        if path is None:
            return
        sink["seen"] += 1
        top = sink["top"]
        top.append((size, path, mtime))
        if len(top) > cap * 20:
            top.sort(key=lambda x: x[0], reverse=True)
            del top[cap:]

    sinks = _walk_parallel(target, budget, _sink, _on_file)
    scanned = sum(s["seen"] for s in sinks)
    found = [item for sink in sinks for item in sink["top"]]
    found.sort(key=lambda x: x[0], reverse=True)
    items = []
    for size, p, mtime in found[:cap]:
        try:
            stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(mtime))
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # Corrupt mtimes (network FS, FAT) used to 500 this endpoint;
            # total, not a tuple: a poisoned mtime whose ``__float__``
            # raises RuntimeError rode the top tuple past the old catch.
            stamp = ""
        try:
            items.append({
                "path": _as_text(p),
                "name": _as_text(Path(p).name),
                "bytes": size,
                "gb": _gb(size),
                "mtime": stamp,
            })
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # ``Path(p)`` on a junk path must cost its own row, not the
            # report the walk already finished.
            continue
    return {
        "path": _as_text(target),
        "items": items,
        "scanned": scanned,
        "truncated": budget.truncated,
        "elapsed_sec": round(time.monotonic() - started, 2),
    }


def _hash_file(path: Path, *, partial: bool) -> str | None:
    """SHA-256 of the first chunk, or of the whole file when *partial* is False."""
    digest = hashlib.sha256()
    fd = -1
    try:
        # O_NONBLOCK + the regular-file check (the files_svc read rule): the
        # walk only queues regular files, but the hash stages run after the
        # whole walk finished, and a leftover FIFO occupying the path by then
        # used to park the plain open() until a writer appeared — hanging a
        # fan_out worker and GET /api/storage/usage/duplicates with it, past
        # every budget (the deadline cannot fire inside a blocked syscall).
        # O_NONBLOCK changes nothing for reads of a regular file, and
        # O_NOFOLLOW refuses a symlink swapped in over the same window (the
        # walk never followed one).  A non-regular occupant costs its own
        # hash, exactly like an unreadable file, never the request.
        fd = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        with os.fdopen(fd, "rb") as fh:
            fd = -1  # fdopen owns the descriptor now
            if partial:
                digest.update(fh.read(_HASH_CHUNK))
            else:
                while True:
                    block = fh.read(_HASH_CHUNK)
                    if not block:
                        break
                    digest.update(block)
    except (OSError, ValueError, TypeError):
        # ValueError: leftover ``\\ud800`` in a FUSE name. open() encodes
        # strictly; the duplicates walk used to 500 GET /api/storage/usage/duplicates.
        return None
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
    return digest.hexdigest()


def _hash_group(paths: list[str], budget: _Budget, *, partial: bool) -> list[str | None]:
    """Hash *paths* concurrently, in order, stopping once the budget is spent.

    The deadline is still checked per file rather than only per group: full
    hashing is the expensive stage and a single group of 8 GB files can consume a
    whole budget on its own.  Once expired, the remaining entries come back None,
    which the caller treats the same way it treats an unreadable file.
    """
    def _one(p: str) -> str | None:
        # Guarded whole: ``Path(p)`` sat *outside* _hash_file's try, so a
        # junk path raised inside the fan_out worker and fan_out re-raises
        # on iteration — one unhashable candidate must read as unreadable
        # (None), never 500 GET /api/storage/usage/duplicates.
        try:
            if budget.expired():
                return None
            return _hash_file(Path(p), partial=partial)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None

    return fan_out(_one, paths, max_workers=_SCAN_WORKERS)


def duplicates(path: str | None = None, root_id: str | None = None, min_mb: float = 1.0) -> dict:
    """Groups of byte-identical files under *path*.

    Three-stage funnel so full hashing only touches plausible candidates: group by
    size, then by the hash of the first megabyte, then by the full-content hash.
    Anything smaller than *min_mb* is ignored.
    """
    target = _resolve(path, root_id)
    try:
        mb = float(min_mb or 1.0)
        if mb != mb or mb in (float("inf"), float("-inf")) or mb <= 0:
            raise ValueError
        floor = max(DUP_MIN_BYTES, int(mb * 1024 * 1024))
    except (TypeError, ValueError, OverflowError):
        floor = DUP_MIN_BYTES
    budget = _Budget(DUP_SECONDS, DUP_CANDIDATES)
    started = time.monotonic()

    def _sink() -> dict[int, list[str]]:
        return {}

    def _on_file(entry, sink: dict[int, list[str]]) -> None:
        # Same guard as largest_files._on_file: every entry read under one
        # total except (a raising stat descriptor used to kill the walk
        # worker and hang the request), and the queued path is an exact-str
        # base copy so the sort and ``sorted(matches)`` downstream run base
        # comparisons only.
        try:
            size = _safe_bytes(entry.stat(follow_symlinks=False).st_size)
            path = _exact_str(entry.path)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return
        if path is None:
            return
        if size >= floor:
            sink.setdefault(size, []).append(path)

    by_size: dict[int, list[str]] = {}
    for partial_sink in _walk_parallel(target, budget, _sink, _on_file):
        for size, paths in partial_sink.items():
            by_size.setdefault(size, []).extend(paths)

    groups: list[dict] = []
    wasted = 0
    # Largest sizes first, so a truncated run still reports the groups worth the
    # most reclaimable space rather than an arbitrary prefix of the tree.
    for size, paths in sorted(by_size.items(), key=lambda kv: kv[0], reverse=True):
        if budget.expired():
            break
        if len(paths) < 2:
            continue
        # Both hash stages fan out over the candidate files.  Reading a megabyte
        # (or eight gigabytes) is I/O, and hashlib releases the GIL for buffers
        # this size, so these overlap for real rather than taking turns.
        partial: dict[str, list[str]] = {}
        for p, key in zip(paths, _hash_group(paths, budget, partial=True)):
            if key:
                partial.setdefault(key, []).append(p)
        for candidates in partial.values():
            if len(candidates) < 2 or budget.expired():
                continue
            full: dict[str, list[str]] = {}
            for p, key in zip(candidates, _hash_group(candidates, budget, partial=False)):
                if key:
                    full.setdefault(key, []).append(p)
            for digest, matches in full.items():
                if len(matches) < 2:
                    continue
                reclaimable = size * (len(matches) - 1)
                wasted += reclaimable
                groups.append({
                    "hash": digest[:16],
                    "bytes": size,
                    "gb": _gb(size),
                    "count": len(matches),
                    "reclaimable_bytes": reclaimable,
                    "reclaimable_gb": _gb(reclaimable),
                    "paths": [_as_text(p) for p in sorted(matches)[:20]],
                })

    groups.sort(key=lambda g: g["reclaimable_bytes"], reverse=True)
    return {
        "path": _as_text(target),
        "min_mb": _json_float(_dup_min_mb(floor), 1, default=1.0),
        "groups": groups[:100],
        "group_count": len(groups),
        "reclaimable_bytes": wasted,
        "reclaimable_gb": _gb(wasted),
        "truncated": budget.truncated,
        "elapsed_sec": round(time.monotonic() - started, 2),
        "note": "read-only report; delete duplicates from the file manager",
    }


# ── Spotlight indexing ───────────────────────────────────────────────────────

def _spotlight_query(volume: str) -> tuple[int, str]:
    """``(rc, text)`` from ``mdutil -s`` for one volume.  Never raises.

    A volume that has just been unmounted must cost its own row, not the page:
    ``fan_out`` re-raises on iteration.
    """
    try:
        rc, text, err = sh([MDUTIL, "-s", volume], timeout=8)
        # ``_as_text(text) or _as_text(err)``, never ``text or err``: the old
        # bare ``or`` on the raw output sat *outside* this guard and called
        # ``__bool__`` on the leftover — a bool-bomb (or decode-bomb bytes
        # subclass) in sh() output raised out of fan_out and 500'd
        # GET /api/storage/usage and POST /api/storage/spotlight.  Everything
        # now happens under the guard, and rc is base-coerced so an odd
        # int subclass cannot bomb the ``rc == 0`` reads downstream.
        blob = (_as_text(text) or _as_text(err)).strip()
        return (int.__index__(rc) if _isa(rc, int) else 1), blob
    except _CONTROL_FLOW:
        raise
    except BaseException as exc:  # noqa: BLE001
        return 1, _as_text(exc)


def spotlight_status() -> list[dict]:
    """Per-volume Spotlight indexing state.

    Relevant on a NAS: ``mds_stores`` will happily spend hours and a lot of I/O
    indexing a media array nobody searches from the Finder, and Unraid users
    reach for the equivalent knob on every new share.
    """
    volumes = ["/"]
    root = Path("/Volumes")
    try:
        if root.is_dir():
            for child in sorted(root.iterdir()):
                try:
                    if child.is_dir() and not child.is_symlink():
                        volumes.append(_as_text(child))
                except OSError:
                    continue
    except OSError:
        pass

    # One `mdutil -s` per volume, 8s timeout each, previously in series -- so on
    # the kind of machine this page exists for, with an array of volumes mounted,
    # the latency was the volume count times that.  The queries are independent,
    # and `fan_out` keeps the rows in mount order rather than answer order.
    out = []
    for volume, (rc, blob) in zip(volumes, fan_out(_spotlight_query, volumes)):
        lowered = blob.lower()
        if "indexing enabled" in lowered:
            state = "enabled"
        elif "indexing disabled" in lowered:
            state = "disabled"
        elif "no index" in lowered:
            state = "none"
        else:
            state = "unknown"
        out.append({
            "volume": _as_text(volume),
            "state": state,
            "enabled": state == "enabled",
            "detail": _as_text(blob)[:200],
            "readable": rc == 0,
        })
    return out


def _mdutil_on_disk() -> bool:
    """Fresh disk probe for the mutation-failure path only (raid/smart rule).

    ``Path.is_file()`` can itself raise on a dying volume (EIO/ESTALE); a disk
    that cannot even answer for /usr/bin is not confirmably carrying it.
    """
    try:
        return Path(MDUTIL).is_file()
    except (OSError, ValueError):
        return False


#: What a spawn of a gone binary reads like through run_admin: the shell's own
#: refusal (``sh: /usr/bin/mdutil: command not found`` / ``No such file or
#: directory``) or sh()'s FileNotFoundError sentinel (``not found``).  Purely a
#: message-pattern gate: classification additionally requires the fresh
#: :func:`_mdutil_on_disk` probe to confirm the binary is really gone.
_VANISH_MARKERS = ("command not found", "no such file or directory", "not found")


def set_spotlight(volume: str, enabled: bool) -> dict:
    """Turn Spotlight indexing on or off for one volume (requires authorization)."""
    from hub.macos_admin import run_admin

    # _as_text is a str() probe, not an isinstance gate: the route hands the
    # volume over as str through Pydantic, but the service is also called
    # in-process, and a leftover YAML/plist hex int arrives *already-int*
    # (``int(x, 16)`` is exempt from CPython's 4300-digit parse cap) — the
    # bare ``str()`` here raised the int->str digit-cap ValueError where
    # every other junk volume earns the coded ``bad_volume`` refusal (the
    # raid_svc._req_text / smart_test_svc._schedule_text convention).
    target = _as_text(volume).strip()
    # _truthy on the flag: the route hands over a Pydantic StrictBool, but
    # the service is also called in-process, and a leftover ``__bool__``-bomb
    # flag detonated the ``"on" if enabled else "off"`` argv choice — a raw
    # raise where the coded refusals below are the contract.
    wanted = _truthy(enabled)
    # Guarded call + unbound reads (the nas_storage._known_mount rule): the
    # old set comprehension consumed the status listing raw, so a leftover
    # list-*subclass* whose ``__iter__`` raises, a dict-subclass row whose
    # bound ``.get`` raises, or a str-subclass volume whose ``__hash__`` /
    # ``__eq__`` detonated inside the set build all 500'd
    # POST /api/storage/spotlight ahead of the coded ``bad_volume`` refusal
    # — and a status listing that raised outright took the route with it.
    # ``base.__iter__`` walks the real C-level storage so healthy rows still
    # serve, ``dict.get`` cannot run a subclass override, and ``_as_text``
    # answers an exact str so the set's hash/eq are the base ops.  "/" is
    # pinned because spotlight_status always reports the boot volume first,
    # so it stays toggleable while a hostile listing drops row by row.
    try:
        listing = spotlight_status()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        listing = []
    if not _isa(listing, (list, tuple)):
        listing = []
    known = {"/"}
    base = list if _isa(listing, list) else tuple
    try:
        # The unbound walk in a try (the modules9 rule): a *lying*
        # ``__class__`` claiming list/tuple passed the gate above and the
        # descriptor's TypeError raised raw — a 500 on
        # POST /api/storage/spotlight ahead of the coded ``bad_volume``.
        status_rows = list(base.__iter__(listing))
    except _CONTROL_FLOW:
        raise
    except BaseException:
        status_rows = []
    for v in status_rows:
        # _isa on both reads: a ``__class__``-bomb status row (or volume
        # field) used to detonate the gates themselves ahead of the coded
        # ``bad_volume`` refusal.  The ``dict.get`` in a try: a dict-liar
        # row passes the gate and the descriptor rejects it — the row
        # drops alone, "/" and its siblings stay toggleable.
        if not _isa(v, dict):
            continue
        try:
            vol = dict.get(v, "volume")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
        if _isa(vol, str):
            known.add(_as_text(vol))
    if target not in known:
        return {"ok": False, "error": "bad_volume"}
    try:
        result = run_admin([MDUTIL, "-i", "on" if wanted else "off", target], timeout=60)
    except _CONTROL_FLOW:
        raise
    except BaseException as exc:  # noqa: BLE001
        # Guarded call (the scan_roots default_roots / usage8 spotlight_status
        # rule, one seam later): run_admin answers coded dicts for everything
        # it anticipates, but a seam replacement or a leftover that slips its
        # own guards still raised *out of the call itself* and 500'd
        # POST /api/storage/spotlight raw — the only unguarded seam left on
        # the route.  The synthesized failure keeps the funnel's contract:
        # the vanish classification below still reads the message, so a
        # spawn-of-a-gone-binary raise ("No such file or directory") earns
        # the coded 503 only after the fresh disk probe confirms mdutil is
        # really gone, exactly like the sentinel-shaped failure.
        result = {"ok": False, "error": "failed", "message": _as_text(exc)}
    # _isa: a ``__class__``-property bomb result detonated the bare gate
    # itself — a raw 500 on POST /api/storage/spotlight one line ahead of
    # the laundering built to absorb junk shapes.
    if not _isa(result, dict):
        return {"ok": False, "error": "failed"}
    try:
        # dict() copies through the C-level storage (nas_common._plain_result
        # rule): a dict-*subclass* result whose ``.get`` or ``__setitem__``
        # raises passed the isinstance gate above and 500'd
        # POST /api/storage/spotlight before the router funnel's own
        # laundering could run.  A subclass whose copy itself raises is junk.
        result = dict(result)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return {"ok": False, "error": "failed"}
    # Exact-str keys only (the wave-10 hash-shadowing rule): the plain copy
    # above still *carries* a hostile key — a leftover str-subclass whose
    # ``__hash__`` answers a real key's bucket while its ``__eq__`` raises
    # detonated every later probe of that bucket: ``result["volume"] =
    # target`` and ``result["enabled"]`` on the ok path, ``result.get("ok")``
    # (and the ``result["ok"] = False`` *inside its own except handler*),
    # and the ``result.get("error")`` / ``result.get("message")`` reads of
    # the vanish classification — each a raw 500 on POST
    # /api/storage/spotlight after run_admin had already answered, and the
    # same bomb rode the returned dict into the route funnel's
    # ``result.get("ok")``.  ``dict.items`` walks the C-level storage and
    # ``_exact_str`` strips the overrides, so every bucket probe from here
    # on runs base ``__hash__``/``__eq__``; a torn pair drops alone while
    # its sibling keys keep serving.
    plain: dict = {}
    try:
        for k, v in dict.items(result):
            try:
                key = _exact_str(k)
                if key is not None:
                    plain[key] = v
            except _CONTROL_FLOW:
                raise
            except BaseException:
                continue
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return {"ok": False, "error": "failed"}
    result = plain
    try:
        ok = bool(result.get("ok"))
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # A ``__bool__``-bomb ok value reads as failure (nas_common._truthy
        # rule) instead of raising out of the service as a 500 — and the
        # unreadable flag must not ride along either: the route reads
        # ``bool(result.get("ok"))`` for its audit row, where the same bomb
        # would just fire one frame later.
        ok = False
        result["ok"] = False
    if ok:
        result["volume"] = target
        result["enabled"] = wanted
        return result
    # An mdutil that vanished (OS update mid-flight, dying system volume) used
    # to surface as the generic 500 ``admin.failed`` — "the privileged macOS
    # operation failed" sends the operator to a password dialog that cannot
    # help.  The coded 503 fires only after a fresh disk probe confirms mdutil
    # is gone (the raid/smart/vms rule); timeouts and authorization failures
    # (``password_required`` / ``password_incorrect`` / ``unavailable``) keep
    # their original shape.  The probe runs only on this failure path, never
    # on a successful toggle.
    # _as_text on both reads, no bare ``or``: a ``__bool__``-bomb message (or
    # an error value with a hostile reflected ``__eq__``) on this failure
    # path used to raise out of the vanish classification and 500 the route
    # in place of the coded refusal.
    if _as_text(result.get("error")) == "failed":
        message = _as_text(result.get("message")).lower()
        if any(marker in message for marker in _VANISH_MARKERS) and not _mdutil_on_disk():
            return {"ok": False, "error": "mdutil_missing"}
    return result


def overview() -> dict:
    """Landing payload: roots to pick from, plus Spotlight state."""
    return {
        "ts": strftime_now("%Y-%m-%d %H:%M:%S"),
        "roots": scan_roots(),
        "spotlight": spotlight_status(),
        "limits": {
            "scan_seconds": SCAN_SECONDS,
            "scan_entries": SCAN_ENTRIES,
            "dup_seconds": DUP_SECONDS,
            "dup_min_mb": round(DUP_MIN_BYTES / 1024 / 1024, 1),
        },
    }
