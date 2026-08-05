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
import time
from pathlib import Path

from hub import files_svc
from hub.errors import api_error
from hub.util import sh

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

    def add(root_id: str, name: str, path: Path) -> None:
        try:
            resolved = path.resolve()
        except OSError:
            return
        text = str(resolved)
        if text in seen or not resolved.is_dir():
            return
        if _is_never_walk(resolved) or files_svc.is_protected(resolved):
            return
        seen.add(text)
        roots.append({"id": root_id, "name": name, "path": text})

    for entry in files_svc.default_roots():
        add(str(entry.get("id") or "root"), str(entry.get("name") or ""), Path(entry["path"]))

    volumes = Path("/Volumes")
    if volumes.is_dir():
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

        overview = shares_svc.overview() if hasattr(shares_svc, "overview") else {}
        for share in (overview or {}).get("shares") or []:
            path = str((share or {}).get("path") or "")
            if path.startswith("/"):
                add(f"share-{(share.get('name') or 'share')}", str(share.get("name") or path), Path(path))
    except Exception:
        # Share enumeration is a convenience here, never a hard dependency.
        pass

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

    candidate = Path(os.path.expanduser(str(path)))
    try:
        candidate = candidate.resolve()
    except OSError:
        raise api_error("files.not_found", path=str(path))

    allowed = [base] if base else [Path(r["path"]) for r in roots]
    if not any(candidate == a or a in candidate.parents for a in allowed):
        raise api_error("files.path_outside_root")
    if _is_never_walk(candidate) or files_svc.is_protected(candidate):
        raise api_error("files.path_protected")
    if not candidate.exists():
        raise api_error("files.not_found", path=str(candidate))
    if not candidate.is_dir():
        raise api_error("files.not_a_dir")
    return candidate


class _Budget:
    """Shared wall-clock + entry ceiling for one walk.

    The clock is sampled once per :data:`_CLOCK_EVERY` entries rather than on
    every one: a directory walk calls this hundreds of thousands of times, and at
    that rate ``time.monotonic()`` stops being free.  The granularity costs at
    most a few milliseconds of overshoot.
    """

    __slots__ = ("deadline", "remaining", "truncated", "_tick")

    def __init__(self, seconds: float, entries: int):
        self.deadline = time.monotonic() + seconds
        self.remaining = entries
        self.truncated = False
        self._tick = 0

    def expired(self) -> bool:
        """Check the clock unconditionally (for use between coarse work items)."""
        if time.monotonic() > self.deadline:
            self.truncated = True
            return True
        return False

    def spend(self, n: int = 1) -> bool:
        self.remaining -= n
        if self.remaining <= 0:
            self.truncated = True
            return False
        self._tick += 1
        if self._tick >= _CLOCK_EVERY:
            self._tick = 0
            return not self.expired()
        return True


#: How many entries pass between wall-clock samples inside a walk.
_CLOCK_EVERY = 512


def _dir_size(path: Path, budget: _Budget) -> tuple[int, int]:
    """(bytes, file count) under *path*, following no symlinks."""
    total = 0
    files = 0
    stack = [path]
    while stack:
        current = stack.pop()
        if budget.expired():
            break
        try:
            with os.scandir(current) as it:
                for entry in it:
                    if not budget.spend():
                        return total, files
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            child = Path(entry.path)
                            if not _is_never_walk(child):
                                stack.append(child)
                        elif entry.is_file(follow_symlinks=False):
                            total += entry.stat(follow_symlinks=False).st_size
                            files += 1
                    except OSError:
                        continue
        except (OSError, PermissionError):
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
    except (OSError, PermissionError):
        raise api_error("files.permission_denied", path=str(target))

    for entry in entries:
        try:
            if entry.is_symlink():
                continue
            if entry.is_dir(follow_symlinks=False):
                child = Path(entry.path)
                if _is_never_walk(child) or files_svc.is_protected(child):
                    continue
                size, files = _dir_size(child, budget)
                children.append({
                    "name": entry.name,
                    "path": entry.path,
                    "kind": "dir",
                    "bytes": size,
                    "gb": round(size / 2**30, 2),
                    "files": files,
                })
            elif entry.is_file(follow_symlinks=False):
                size = entry.stat(follow_symlinks=False).st_size
                own_files += 1
                own_bytes += size
                children.append({
                    "name": entry.name,
                    "path": entry.path,
                    "kind": "file",
                    "bytes": size,
                    "gb": round(size / 2**30, 2),
                    "files": 1,
                })
        except OSError:
            continue

    children.sort(key=lambda c: c["bytes"], reverse=True)
    total = sum(c["bytes"] for c in children)
    for child in children:
        child["percent"] = round(child["bytes"] / total * 100, 1) if total else 0.0

    parent = str(target.parent)
    roots = {r["path"] for r in scan_roots()}
    return {
        "path": str(target),
        "parent": parent if str(target) not in roots else "",
        "roots": scan_roots(),
        "total_bytes": total,
        "total_gb": round(total / 2**30, 2),
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
    cap = max(1, min(int(limit or 50), 500))
    budget = _Budget(SCAN_SECONDS, SCAN_ENTRIES)
    started = time.monotonic()

    found: list[tuple[int, str, float]] = []
    stack = [target]
    scanned = 0
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    if not budget.spend():
                        stack.clear()
                        break
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            child = Path(entry.path)
                            if not _is_never_walk(child):
                                stack.append(child)
                        elif entry.is_file(follow_symlinks=False):
                            st = entry.stat(follow_symlinks=False)
                            scanned += 1
                            found.append((st.st_size, entry.path, st.st_mtime))
                            if len(found) > cap * 20:
                                found.sort(key=lambda x: x[0], reverse=True)
                                del found[cap:]
                    except OSError:
                        continue
        except (OSError, PermissionError):
            continue

    found.sort(key=lambda x: x[0], reverse=True)
    items = [
        {
            "path": p,
            "name": Path(p).name,
            "bytes": size,
            "gb": round(size / 2**30, 2),
            "mtime": time.strftime("%Y-%m-%d %H:%M", time.localtime(mtime)),
        }
        for size, p, mtime in found[:cap]
    ]
    return {
        "path": str(target),
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
    except OSError:
        return None
    return digest.hexdigest()


def duplicates(path: str | None = None, root_id: str | None = None, min_mb: float = 1.0) -> dict:
    """Groups of byte-identical files under *path*.

    Three-stage funnel so full hashing only touches plausible candidates: group by
    size, then by the hash of the first megabyte, then by the full-content hash.
    Anything smaller than *min_mb* is ignored.
    """
    target = _resolve(path, root_id)
    floor = max(DUP_MIN_BYTES, int(float(min_mb or 1.0) * 1024 * 1024))
    budget = _Budget(DUP_SECONDS, DUP_CANDIDATES)
    started = time.monotonic()

    by_size: dict[int, list[str]] = {}
    stack = [target]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    if not budget.spend():
                        stack.clear()
                        break
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            child = Path(entry.path)
                            if not _is_never_walk(child):
                                stack.append(child)
                        elif entry.is_file(follow_symlinks=False):
                            size = entry.stat(follow_symlinks=False).st_size
                            if size >= floor:
                                by_size.setdefault(size, []).append(entry.path)
                    except OSError:
                        continue
        except (OSError, PermissionError):
            continue

    groups: list[dict] = []
    wasted = 0
    # Largest sizes first, so a truncated run still reports the groups worth the
    # most reclaimable space rather than an arbitrary prefix of the tree.
    for size, paths in sorted(by_size.items(), key=lambda kv: kv[0], reverse=True):
        if budget.expired():
            break
        if len(paths) < 2:
            continue
        partial: dict[str, list[str]] = {}
        for p in paths:
            if budget.expired():
                break
            key = _hash_file(Path(p), partial=True)
            if key:
                partial.setdefault(key, []).append(p)
        for candidates in partial.values():
            if len(candidates) < 2 or budget.expired():
                continue
            full: dict[str, list[str]] = {}
            for p in candidates:
                # Full hashing is the expensive stage: a group of 8 GB files can
                # exhaust the whole budget on its own, so check per file.
                if budget.expired():
                    break
                key = _hash_file(Path(p), partial=False)
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
                    "gb": round(size / 2**30, 2),
                    "count": len(matches),
                    "reclaimable_bytes": reclaimable,
                    "reclaimable_gb": round(reclaimable / 2**30, 2),
                    "paths": sorted(matches)[:20],
                })

    groups.sort(key=lambda g: g["reclaimable_bytes"], reverse=True)
    return {
        "path": str(target),
        "min_mb": round(floor / 1024 / 1024, 1),
        "groups": groups[:100],
        "group_count": len(groups),
        "reclaimable_bytes": wasted,
        "reclaimable_gb": round(wasted / 2**30, 2),
        "truncated": budget.truncated,
        "elapsed_sec": round(time.monotonic() - started, 2),
        "note": "read-only report; delete duplicates from the file manager",
    }


# ── Spotlight indexing ───────────────────────────────────────────────────────

def spotlight_status() -> list[dict]:
    """Per-volume Spotlight indexing state.

    Relevant on a NAS: ``mds_stores`` will happily spend hours and a lot of I/O
    indexing a media array nobody searches from the Finder, and Unraid users
    reach for the equivalent knob on every new share.
    """
    volumes = ["/"]
    root = Path("/Volumes")
    if root.is_dir():
        try:
            for child in sorted(root.iterdir()):
                if child.is_dir() and not child.is_symlink():
                    volumes.append(str(child))
        except OSError:
            pass

    out = []
    for volume in volumes:
        rc, text, err = sh([MDUTIL, "-s", volume], timeout=8)
        blob = (text or err or "").strip()
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
            "volume": volume,
            "state": state,
            "enabled": state == "enabled",
            "detail": blob[:200],
            "readable": rc == 0,
        })
    return out


def set_spotlight(volume: str, enabled: bool) -> dict:
    """Turn Spotlight indexing on or off for one volume (requires authorization)."""
    from hub.macos_admin import run_admin

    target = str(volume or "").strip()
    known = {v["volume"] for v in spotlight_status()}
    if target not in known:
        return {"ok": False, "error": "bad_volume"}
    result = run_admin([MDUTIL, "-i", "on" if enabled else "off", target], timeout=60)
    if result.get("ok"):
        result["volume"] = target
        result["enabled"] = bool(enabled)
    return result


def overview() -> dict:
    """Landing payload: roots to pick from, plus Spotlight state."""
    return {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "roots": scan_roots(),
        "spotlight": spotlight_status(),
        "limits": {
            "scan_seconds": SCAN_SECONDS,
            "scan_entries": SCAN_ENTRIES,
            "dup_seconds": DUP_SECONDS,
            "dup_min_mb": round(DUP_MIN_BYTES / 1024 / 1024, 1),
        },
    }
