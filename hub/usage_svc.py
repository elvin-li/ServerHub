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

import hashlib
import os
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


def _as_text(value) -> str:
    """JSON-safe text. Leftover ``\\ud800`` in a filename used to 500 usage JSON."""
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    elif value is None:
        return ""
    else:
        try:
            value = str(value)
        except RecursionError:
            try:
                return type(value).__name__
            except Exception:
                return ""
        except Exception:
            return ""
    return value.encode("utf-8", "replace").decode("utf-8")


def _safe_bytes(value) -> int:
    """Clamp a ``stat.st_size`` so ``inf``/None cannot 500 the JSON encoder.

    ``int(...)`` with a try only guards *conversions*: a leftover FUSE/SMB
    ``st_size`` that is already a >4300-digit int passed through untouched,
    and CPython's int->str digit limit then ValueError'd Starlette's
    ``json.dumps`` — 500ing GET /api/storage/usage/tree, /largest and
    /duplicates after the walk had already finished.  ``float()`` rejects
    anything beyond float range, the same junk test files_svc._finite_int
    and logs_svc._stat_size apply to their stat numbers.
    """
    try:
        n = int(value)
        float(n)
    except (TypeError, ValueError, OverflowError, OSError):
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
    except Exception:
        # The guard below covered *iteration* but not the call: a
        # default_roots that raised outright (a seam replacement, a leftover
        # that slips its own guards) still 500'd GET /api/storage/usage,
        # /tree, /largest and /duplicates at once — the storage_pool_svc
        # _candidates rule, one seam earlier than the iteration bomb.  The
        # sibling seam (shares_svc.list_smb_shares) has carried this guard
        # all along; the volumes and shares below still contribute.
        incoming = []
    # None/int leftover used to TypeError GET /api/storage/usage.
    if not isinstance(incoming, (list, tuple)):
        incoming = []
    try:
        incoming = list(incoming)
    except Exception:
        # A roots listing that refuses *iteration* (odd list subclass passing
        # the isinstance gate above) used to raise out of this loop and 500
        # GET /api/storage/usage, /tree, /largest and /duplicates — the
        # ups_svc/storage_svc materialize-under-guard rule.  The volumes and
        # shares below still contribute their roots.
        incoming = []
    for entry in incoming:
        if not isinstance(entry, dict):
            continue
        try:
            # Per-row guard, the storage_pool_svc._candidates class: a dict
            # *subclass* passes the isinstance gate with a ``.get`` that
            # raises (or a value whose ``__bool__`` raises under the ``or``),
            # and one such row used to 500 all four usage routes while every
            # healthy sibling root was droppable collateral.  The hostile row
            # drops alone; its siblings keep contributing.
            path = entry.get("path")
            if not isinstance(path, str) or not path:
                continue
            # _as_text is a str() probe, not a bare str(): a leftover root id
            # or name that is *already* a >4300-digit int (YAML/plist hex
            # loads with int(x, 16), exempt from the int(str) parse cap) made
            # the old bare str() raise the digit-cap ValueError out of
            # scan_roots and 500 every usage route; sane numeric ids keep
            # their string form.
            rid = _as_text(entry.get("id") or "root") or "root"
            add(rid, _as_text(entry.get("name") or ""), path)
        except Exception:
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
    except Exception:
        # Share enumeration is a convenience here, never a hard dependency.
        listed = []
    if not isinstance(listed, (list, tuple)):
        listed = []
    try:
        listed = list(listed)
    except Exception:
        # Same class as the roots listing above: a share listing that passes
        # the isinstance gate but refuses iteration must cost the shares
        # section, never the request — the roots already gathered survive.
        listed = []
    for share in listed:
        if not isinstance(share, dict):
            continue
        try:
            # Per-row guard, same class as the roots loop above: a dict
            # subclass whose ``.get`` raises passed the isinstance gate and
            # 500'd every usage route; the hostile share drops alone and its
            # sibling shares keep contributing.
            path = share.get("path")
            # Path() TypeError'd a non-str share path and 500'd the usage page.
            if not isinstance(path, str) or not path.startswith("/"):
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
        except Exception:
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
                        except (OSError, ValueError, TypeError):
                            continue
            except (OSError, PermissionError, ValueError, TypeError):
                pass
            _push(subdirs)

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
                    except (OSError, ValueError, TypeError):
                        continue
        except (OSError, PermissionError, ValueError, TypeError):
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
        except (OSError, ValueError, TypeError):
            continue

    sizes = fan_out(
        lambda e: _dir_size(Path(e.path), budget.spender()),
        subdirs,
        max_workers=_SCAN_WORKERS,
    )
    for entry, (size, files) in zip(subdirs, sizes):
        children.append({
            "name": _as_text(entry.name),
            "path": _as_text(entry.path),
            "kind": "dir",
            "bytes": size,
            "gb": _gb(size),
            "files": files,
        })

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
        try:
            st = entry.stat(follow_symlinks=False)
        except OSError:
            return
        sink["seen"] += 1
        top = sink["top"]
        top.append((_safe_bytes(st.st_size), entry.path, st.st_mtime))
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
        except (OverflowError, OSError, ValueError, TypeError):
            # Corrupt mtimes (network FS, FAT) used to 500 this endpoint.
            stamp = ""
        items.append({
            "path": _as_text(p),
            "name": _as_text(Path(p).name),
            "bytes": size,
            "gb": _gb(size),
            "mtime": stamp,
        })
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
    try:
        with open(path, "rb") as fh:
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
    return digest.hexdigest()


def _hash_group(paths: list[str], budget: _Budget, *, partial: bool) -> list[str | None]:
    """Hash *paths* concurrently, in order, stopping once the budget is spent.

    The deadline is still checked per file rather than only per group: full
    hashing is the expensive stage and a single group of 8 GB files can consume a
    whole budget on its own.  Once expired, the remaining entries come back None,
    which the caller treats the same way it treats an unreadable file.
    """
    def _one(p: str) -> str | None:
        if budget.expired():
            return None
        return _hash_file(Path(p), partial=partial)

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
        try:
            size = _safe_bytes(entry.stat(follow_symlinks=False).st_size)
        except OSError:
            return
        if size >= floor:
            sink.setdefault(size, []).append(entry.path)

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
    except Exception as exc:  # noqa: BLE001
        return 1, _as_text(exc)
    return rc, _as_text(text or err).strip()


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
    known = {
        v.get("volume")
        for v in spotlight_status()
        if isinstance(v, dict) and isinstance(v.get("volume"), str)
    }
    if target not in known:
        return {"ok": False, "error": "bad_volume"}
    result = run_admin([MDUTIL, "-i", "on" if enabled else "off", target], timeout=60)
    if not isinstance(result, dict):
        return {"ok": False, "error": "failed"}
    if result.get("ok"):
        result["volume"] = target
        result["enabled"] = bool(enabled)
        return result
    # An mdutil that vanished (OS update mid-flight, dying system volume) used
    # to surface as the generic 500 ``admin.failed`` — "the privileged macOS
    # operation failed" sends the operator to a password dialog that cannot
    # help.  The coded 503 fires only after a fresh disk probe confirms mdutil
    # is gone (the raid/smart/vms rule); timeouts and authorization failures
    # (``password_required`` / ``password_incorrect`` / ``unavailable``) keep
    # their original shape.  The probe runs only on this failure path, never
    # on a successful toggle.
    if result.get("error") == "failed":
        message = _as_text(result.get("message") or "").lower()
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
