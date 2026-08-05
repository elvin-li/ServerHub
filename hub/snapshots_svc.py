"""APFS local snapshots + Time Machine — macOS-native point-in-time recovery.

Unraid grows this capability from btrfs/ZFS and OMV from rsync snapshots.  macOS
ships it natively: every APFS volume can carry local snapshots, and Time Machine
drives them on a schedule towards an external or network destination.  This
module surfaces both as first-class panel features so a rollback target exists
before a bad container update or a mistaken bulk delete, not after.

Read paths are unprivileged on purpose so the page renders for any signed-in
operator.  Mutations that macOS reserves for root (deleting snapshots, toggling
Time Machine, changing its destination) go through :mod:`hub.macos_admin`, which
asks macOS to present its own authorization sheet — ServerHub never sees the
administrator password.
"""
from __future__ import annotations

import plistlib
import re
import time
from pathlib import Path

from hub.macos_admin import run_admin, run_admin_sequence
from hub.util import sh

TMUTIL = "/usr/bin/tmutil"
DISKUTIL = "/usr/sbin/diskutil"

#: ``com.apple.TimeMachine.2026-08-03-160000.local`` → ``2026-08-03-160000``.
#: Also matches the bare ``2026-08-03-160000`` that ``tmutil`` prints on some
#: releases, which is the token ``deletelocalsnapshots`` expects back.
_SNAP_DATE = re.compile(r"(\d{4}-\d{2}-\d{2}-\d{6})")

#: Snapshot names macOS creates for its own purposes.  They are surfaced but
#: flagged, because deleting an in-progress OS update snapshot is a bad idea and
#: the UI should say so rather than offering an undifferentiated delete button.
_SYSTEM_SNAPSHOT_PREFIXES = ("com.apple.os.update-", "com.apple.installer")

_overview_cache: dict = {"t": 0.0, "v": None}
_CACHE_TTL = 20.0


def _plist(argv: list[str], *, timeout: int = 15) -> dict | None:
    """Run *argv* and parse its stdout as a plist, or None when unusable.

    ``tmutil`` writes diagnostics to stdout ahead of the XML on some failures,
    so the payload is located by its declaration rather than assumed to start at
    byte zero.
    """
    rc, out, _ = sh(argv, timeout=timeout)
    if rc != 0 or not out:
        return None
    start = out.find("<?xml")
    if start < 0:
        return None
    try:
        parsed = plistlib.loads(out[start:].encode())
    except (plistlib.InvalidFileException, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _snapshot_date(name: str) -> str:
    m = _SNAP_DATE.search(name or "")
    return m.group(1) if m else ""


def _human_date(token: str) -> str:
    """``2026-08-03-160000`` → ``2026-08-03 16:00:00`` (empty when unparseable)."""
    if not token or len(token) != 17:
        return ""
    return f"{token[:10]} {token[11:13]}:{token[13:15]}:{token[15:17]}"


def snapshot_mounts() -> list[str]:
    """Mounted APFS volumes that can hold snapshots.

    ``/`` is reported by ``tmutil`` as the disk covering the whole boot volume
    group, so it is always included; everything else comes from ``/Volumes``.
    Read-only mounts are skipped because a snapshot cannot be created there.
    """
    mounts = ["/"]
    rc, out, _ = sh([DISKUTIL, "list", "-plist"], timeout=10)
    seen = set(mounts)
    try:
        volumes = Path("/Volumes")
        entries = sorted(volumes.iterdir()) if volumes.is_dir() else []
    except OSError:
        entries = []
    for entry in entries:
        try:
            if not entry.is_dir() or entry.is_symlink():
                continue
        except OSError:
            continue
        path = str(entry)
        if path in seen:
            continue
        seen.add(path)
        mounts.append(path)
    del rc, out  # diskutil is probed only to keep the call shape stable
    return mounts


def list_snapshots(mount: str = "/") -> list[dict]:
    """Snapshots on *mount*, newest first.

    ``diskutil apfs listSnapshots -plist`` is the detailed source (UUID, XID,
    purgeable flag).  Its output is unprivileged, unlike much of ``tmutil``.
    """
    data = _plist([DISKUTIL, "apfs", "listSnapshots", "-plist", mount])
    raw = (data or {}).get("Snapshots") or []
    items: list[dict] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("SnapshotName") or "")
        token = _snapshot_date(name)
        system = name.startswith(_SYSTEM_SNAPSHOT_PREFIXES)
        items.append({
            "mount": mount,
            "name": name,
            "uuid": str(entry.get("SnapshotUUID") or ""),
            "xid": entry.get("SnapshotXID"),
            "date_token": token,
            "date": _human_date(token),
            "purgeable": bool(entry.get("Purgeable")),
            "limits_shrink": bool(entry.get("LimitingContainerShrink")),
            "kind": "system" if system else ("timemachine" if token else "other"),
            # An OS-update snapshot is macOS rollback state, not operator
            # backup state.  Deleting one is legal but rarely intended.
            "deletable": bool(token) and not system,
        })
    items.sort(key=lambda x: x["date_token"], reverse=True)
    return items


def time_machine_overview() -> dict:
    """Destinations, schedule and current run state for Time Machine."""
    dest = _plist([TMUTIL, "destinationinfo", "-X"]) or {}
    destinations = []
    for entry in dest.get("Destinations") or []:
        if not isinstance(entry, dict):
            continue
        mount_point = str(entry.get("MountPoint") or "")
        destinations.append({
            "id": str(entry.get("ID") or ""),
            "name": str(entry.get("Name") or ""),
            "kind": str(entry.get("Kind") or ""),
            "mount": mount_point,
            "url": str(entry.get("URL") or ""),
            "last_used": bool(entry.get("LastDestination")),
            "mounted": bool(mount_point) and Path(mount_point).is_dir(),
        })

    status = _plist([TMUTIL, "status", "-X"]) or {}
    running = bool(status.get("Running"))
    progress = status.get("Progress") if isinstance(status.get("Progress"), dict) else {}
    percent = progress.get("Percent") if isinstance(progress, dict) else None
    try:
        percent_val = round(float(percent) * 100, 1) if percent is not None else None
    except (TypeError, ValueError):
        percent_val = None

    rc, latest, _ = sh([TMUTIL, "latestbackup"], timeout=12)
    latest_path = latest.strip() if rc == 0 else ""

    return {
        "configured": bool(destinations),
        "destinations": destinations,
        "running": running,
        "phase": str(status.get("BackupPhase") or ""),
        "percent": percent_val,
        "latest_backup": latest_path,
        "latest_backup_date": _human_date(_snapshot_date(latest_path)),
    }


def overview(force: bool = False) -> dict:
    """Snapshot inventory across volumes plus Time Machine state.

    Cached briefly: ``diskutil apfs listSnapshots`` is one process per volume and
    the page polls, so an uncached read multiplies process spawns by the number
    of attached disks.
    """
    now = time.time()
    if not force and _overview_cache["v"] is not None and now - _overview_cache["t"] < _CACHE_TTL:
        return _overview_cache["v"]

    volumes = []
    total = 0
    for mount in snapshot_mounts():
        snaps = list_snapshots(mount)
        if not snaps and mount != "/":
            # A non-APFS or snapshot-less external volume adds no signal.
            continue
        total += len(snaps)
        newest = snaps[0] if snaps else None
        volumes.append({
            "mount": mount,
            "count": len(snaps),
            "snapshots": snaps,
            "newest": newest["date"] if newest else "",
            "deletable": sum(1 for s in snaps if s["deletable"]),
        })

    data = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "volumes": volumes,
        "total": total,
        "time_machine": time_machine_overview(),
    }
    _overview_cache.update(t=now, v=data)
    return data


def invalidate() -> None:
    _overview_cache.update(t=0.0, v=None)


# ── mutations ────────────────────────────────────────────────────────────────

def create_snapshot() -> dict:
    """Take a local snapshot of every eligible volume.

    ``tmutil localsnapshot`` needs no elevation and covers all snapshot-capable
    mounted volumes in one pass, which is also how macOS itself does it before
    a system update.
    """
    rc, out, err = sh([TMUTIL, "localsnapshot"], timeout=120)
    invalidate()
    message = (out or err or "").strip()
    if rc != 0:
        return {"ok": False, "error": "failed", "message": message[-400:]}
    return {
        "ok": True,
        "message": message[-400:],
        "date_token": _snapshot_date(message),
    }


def delete_snapshot(mount: str, date_token: str) -> dict:
    """Delete one dated local snapshot from *mount* (requires authorization)."""
    if not _SNAP_DATE.fullmatch(date_token or ""):
        return {"ok": False, "error": "bad_token"}
    result = run_admin(
        [TMUTIL, "deletelocalsnapshots", date_token],
        timeout=180,
    )
    invalidate()
    return result


def delete_all_snapshots(mount: str) -> dict:
    """Delete every dated local snapshot on *mount* (requires authorization).

    Snapshot names are re-read here rather than accepted from the caller: the
    argv handed to the authorization sheet must be built from values this
    process validated, never from request data.
    """
    tokens = [
        s["date_token"] for s in list_snapshots(mount)
        if s["deletable"] and _SNAP_DATE.fullmatch(s["date_token"] or "")
    ]
    if not tokens:
        return {"ok": True, "deleted": 0, "message": "no deletable snapshots"}
    commands = [[TMUTIL, "deletelocalsnapshots", token] for token in tokens]
    result = run_admin_sequence(commands, timeout=600)
    invalidate()
    if result.get("ok"):
        result["deleted"] = len(tokens)
    return result


def thin_snapshots(mount: str, urgency: int = 1) -> dict:
    """Ask macOS to reclaim snapshot space on *mount*.

    ``thinlocalsnapshots`` deletes purgeable snapshots until the requested space
    is free.  Urgency 1-4 selects how aggressively macOS is willing to drop
    them; 4 means "free the space even if all snapshots go".
    """
    if urgency not in (1, 2, 3, 4):
        return {"ok": False, "error": "bad_urgency"}
    target = str(10 * 1024 * 1024 * 1024)  # 10 GiB request; macOS frees what it can
    result = run_admin(
        [TMUTIL, "thinlocalsnapshots", mount, target, str(urgency)],
        timeout=300,
    )
    invalidate()
    return result


_TM_ACTIONS = {
    "start": [TMUTIL, "startbackup"],
    "stop": [TMUTIL, "stopbackup"],
    "enable": [TMUTIL, "enable"],
    "disable": [TMUTIL, "disable"],
}


def time_machine_action(action: str) -> dict:
    """Run a Time Machine control verb through the authorization sheet."""
    argv = _TM_ACTIONS.get((action or "").strip().lower())
    if not argv:
        return {"ok": False, "error": "bad_action"}
    result = run_admin(argv, timeout=180)
    invalidate()
    return result
