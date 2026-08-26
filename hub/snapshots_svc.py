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
from pathlib import Path

from hub.macos_admin import run_admin, run_admin_sequence
from hub.util import cached_snapshot, fan_out, sh, strftime_now

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

_CACHE_TTL = 20.0


def _as_text(value) -> str:
    """``sh`` leftovers arrive as int/None/bytes; leftover ``\\ud800`` used to 500 GET /api/snapshots."""
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", "replace")
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


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's ``allow_nan=False`` encoder cannot 500.

    ``tmutil`` / ``run_admin`` leftover ``\\ud800`` / ``Infinity`` still 500'd
    POST /api/snapshots/delete after the plist walk already scrubbed SnapshotName.
    """
    if depth > 16:
        return None
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        try:
            str(value)
        except ValueError:
            # Past CPython's int->str digit cap the encoder cannot render
            # the number at all — same drop as its inf float sibling.
            return None
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if isinstance(value, str):
        return _as_text(value)
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    if isinstance(value, dict):
        try:
            items = list(value.items())
        except Exception:
            # A mapping that refuses iteration (odd dict subclass in a
            # run_admin result): nothing to salvage, but its *siblings* must
            # survive — pre-fix this raised out of _admin_result and 500'd
            # POST /api/snapshots/* (the ups_svc/nginx_svc._jsonable rule).
            return None
        out = {}
        for k, v in items:
            if not isinstance(k, (str, bytes, bytearray)):
                try:
                    k = str(k)
                except Exception:
                    continue
            out[_as_text(k)] = _jsonable(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        try:
            return [_jsonable(v, depth + 1) for v in value]
        except Exception:
            # Same class as the mapping above, at sequence rank: only this
            # field drops, never the payload or the route.
            return None
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/snapshots.
            return _jsonable(iso(), depth + 1)
        except Exception:
            return None
    try:
        return _as_text(value)
    except Exception:
        return None


def _tmutil_on_disk() -> bool:
    """Fresh disk probe for the mutation-failure path only (raid/nfs/vms rule).

    ``Path.is_file()`` can itself raise on a dying volume (EIO/ESTALE); a disk
    that cannot even answer for /usr/bin is not confirmably carrying tmutil.
    """
    try:
        return Path(TMUTIL).is_file()
    except (OSError, ValueError):
        return False


#: What a spawn of a gone binary reads like through run_admin / sh: the
#: shell's own refusal (``sh: /usr/bin/tmutil: command not found`` / ``No
#: such file or directory``) or sh()'s FileNotFoundError sentinel (``not
#: found``).  Purely a message-pattern gate: classification additionally
#: requires the fresh :func:`_tmutil_on_disk` probe, and only the generic
#: ``failed`` shape is eligible — timeouts, cancelled sheets and password
#: failures keep their original shape.
_VANISH_MARKERS = ("command not found", "no such file or directory", "not found")


def _admin_result(result) -> dict:
    cleaned = _jsonable(result) if isinstance(result, dict) else {}
    if not isinstance(cleaned, dict):
        return {"ok": False, "error": "failed"}
    # A tmutil that vanished between boot and the mutation (an OS update
    # mid-flight, a dying system volume) used to surface as the generic 500
    # ``admin.failed`` — "the privileged macOS operation failed" sends the
    # operator back to a password dialog that cannot help.  Every sibling
    # NAS CLI (nfsd, diskutil, smartctl, mdutil) already answers its coded
    # 503; the probe runs only on this failure path, never on a success.
    if not cleaned.get("ok") and cleaned.get("error") == "failed":
        message = _as_text(cleaned.get("message") or "").lower()
        if any(marker in message for marker in _VANISH_MARKERS) and not _tmutil_on_disk():
            return {"ok": False, "error": "tmutil_missing"}
    return cleaned


def _plist(argv: list[str], *, timeout: int = 15) -> dict | None:
    """Run *argv* and parse its stdout as a plist, or None when unusable.

    ``tmutil`` writes diagnostics to stdout ahead of the XML on some failures,
    so the payload is located by its declaration rather than assumed to start at
    byte zero.
    """
    rc, out, _ = sh(argv, timeout=timeout)
    out = _as_text(out)
    if rc != 0 or not out:
        return None
    start = out.find("<?xml")
    if start < 0:
        return None
    try:
        parsed = plistlib.loads(out[start:].encode())
    except Exception:
        # Same ExpatError leftover as raid_svc._plist: a torn tmutil plist
        # used to 500 /api/snapshots instead of rendering an empty page.
        return None
    return parsed if isinstance(parsed, dict) else None


def _snapshot_date(name: str) -> str:
    m = _SNAP_DATE.search(_as_text(name))
    return m.group(1) if m else ""


def _xid(raw):
    """JSON-safe SnapshotXID.

    ``inf`` / ``nan`` used to 500 GET /api/snapshots under Starlette's
    ``allow_nan=False`` encoder; ``bytes`` used to TypeError ``json.dumps``.
    """
    if isinstance(raw, bool) or raw is None:
        return None
    if isinstance(raw, (bytes, bytearray, list, dict, tuple, set)):
        return None
    if isinstance(raw, float) and (raw != raw or raw in (float("inf"), float("-inf"))):
        return None
    if isinstance(raw, int):
        try:
            str(raw)
        except ValueError:
            # A >4300-digit leftover XID is past CPython's int->str digit
            # cap and ValueError'd json.dumps on GET /api/snapshots.
            return None
        return raw
    if isinstance(raw, str):
        # A leftover ``\ud800`` XID string used to 500 the UTF-8 encode the
        # same way an unscrubbed SnapshotName did.
        return _as_text(raw)
    try:
        return int(raw)
    except (TypeError, ValueError, OverflowError):
        return None


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
        path = _as_text(entry)
        if not path or path in seen:
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
    raw = (data or {}).get("Snapshots") if isinstance(data, dict) else []
    if not isinstance(raw, list):
        raw = []
    items: list[dict] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        name = _as_text(entry.get("SnapshotName") or "")
        token = _snapshot_date(name)
        system = name.startswith(_SYSTEM_SNAPSHOT_PREFIXES)
        items.append({
            "mount": _as_text(mount),
            "name": name,
            "uuid": _as_text(entry.get("SnapshotUUID") or ""),
            "xid": _xid(entry.get("SnapshotXID")),
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


def _tm_destinations() -> dict | None:
    return _plist([TMUTIL, "destinationinfo", "-X"])


def _tm_status() -> dict | None:
    return _plist([TMUTIL, "status", "-X"])


def _tm_latest_backup() -> str:
    rc, latest, _ = sh([TMUTIL, "latestbackup"], timeout=12)
    return _as_text(latest).strip() if rc == 0 else ""


def time_machine_overview() -> dict:
    """Destinations, schedule and current run state for Time Machine.

    The three `tmutil` reads answer unrelated questions and none consumes another's
    output, but `latestbackup` alone can block for its full 12s timeout when a
    network destination is unreachable -- which used to delay the destination list
    and the progress percentage behind it. `_plist` returns None and
    `_tm_latest_backup` returns "" on every failure, so nothing here raises into
    fan_out.
    """
    dest, status, latest_path = fan_out(
        lambda probe: probe(),
        [_tm_destinations, _tm_status, _tm_latest_backup],
        max_workers=3,
    )
    dest = dest or {}
    status = status or {}
    destinations = []
    raw_dest = dest.get("Destinations")
    if not isinstance(raw_dest, list):
        raw_dest = []
    for entry in raw_dest:
        if not isinstance(entry, dict):
            continue
        try:
            mount_point = str(entry.get("MountPoint") or "")
        except ValueError:
            # A leftover plist-hex MountPoint arrives *already-int*
            # (plistlib parses ``<integer>0xF…</integer>`` through
            # ``int(x, 16)``, exempt from CPython's 4300-digit parse cap),
            # so the bare str() raised the int->str digit-cap ValueError out
            # of fan_out and 500'd GET /api/snapshots.  An unrenderable
            # mount can never name a directory; treat it as unmounted.
            mount_point = ""
        mounted = False
        if mount_point and "\x00" not in mount_point:
            try:
                mounted = Path(mount_point).is_dir()
            except (OSError, ValueError):
                mounted = False
        destinations.append({
            "id": _as_text(entry.get("ID") or ""),
            "name": _as_text(entry.get("Name") or ""),
            "kind": _as_text(entry.get("Kind") or ""),
            "mount": _as_text(mount_point),
            "url": _as_text(entry.get("URL") or ""),
            "last_used": bool(entry.get("LastDestination")),
            "mounted": mounted,
        })

    running = bool(status.get("Running"))
    progress = status.get("Progress") if isinstance(status.get("Progress"), dict) else {}
    percent = progress.get("Percent") if isinstance(progress, dict) else None
    percent_val = None
    if percent is not None:
        try:
            raw_pct = float(percent)
        except (TypeError, ValueError, OverflowError):
            raw_pct = None
        if raw_pct is not None and raw_pct == raw_pct and raw_pct not in (
            float("inf"), float("-inf"),
        ):
            # Leftover finite ``1e308`` is not inf, then ``* 100`` overflows
            # to inf and 500'd GET /api/snapshots under allow_nan=False.
            try:
                scaled = round(raw_pct * 100, 1)
            except OverflowError:
                scaled = None
            if scaled is not None and scaled == scaled and scaled not in (
                float("inf"), float("-inf"),
            ):
                percent_val = scaled

    return {
        "configured": bool(destinations),
        "destinations": destinations,
        "running": running,
        "phase": _as_text(status.get("BackupPhase") or ""),
        "percent": percent_val,
        "latest_backup": latest_path,
        "latest_backup_date": _human_date(_snapshot_date(latest_path)),
    }


@cached_snapshot(_CACHE_TTL)
def overview(force: bool = False) -> dict:
    """Snapshot inventory across volumes plus Time Machine state.

    Cached briefly: ``diskutil apfs listSnapshots`` is one process per volume and
    the page polls, so an uncached read multiplies process spawns by the number
    of attached disks.
    """

    mounts = snapshot_mounts()
    # One `diskutil apfs listSnapshots` per volume, plus the Time Machine read that
    # used to sit as a serial tail after the whole loop. None of them depends on
    # another, so they all go in one wave: an uncached read now costs one probe
    # instead of one-per-attached-disk-plus-three. `list_snapshots` swallows its own
    # failures via `_plist`, and `fan_out` keeps `snapshot_mounts()` order so the
    # volume table does not reshuffle between refreshes.
    probes = [(lambda m=mount: list_snapshots(m)) for mount in mounts]
    results = fan_out(
        lambda probe: probe(),
        probes + [time_machine_overview],
        max_workers=min(len(probes) + 1, 8),
    )
    per_mount, time_machine = results[:-1], results[-1]

    volumes = []
    total = 0
    for mount, snaps in zip(mounts, per_mount):
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
        "ts": strftime_now("%Y-%m-%d %H:%M:%S"),
        "volumes": volumes,
        "total": total,
        "time_machine": time_machine,
    }
    return data


def invalidate() -> None:
    overview.invalidate()


# ── mutations ────────────────────────────────────────────────────────────────

def create_snapshot() -> dict:
    """Take a local snapshot of every eligible volume.

    ``tmutil localsnapshot`` needs no elevation and covers all snapshot-capable
    mounted volumes in one pass, which is also how macOS itself does it before
    a system update.
    """
    rc, out, err = sh([TMUTIL, "localsnapshot"], timeout=120)
    invalidate()
    message = (_as_text(out) or _as_text(err)).strip()
    if rc != 0:
        return _admin_result({"ok": False, "error": "failed", "message": message[-400:]})
    return _admin_result({
        "ok": True,
        "message": message[-400:],
        "date_token": _snapshot_date(message),
    })


def delete_snapshot(mount: str, date_token: str) -> dict:
    """Delete one dated local snapshot from *mount* (requires authorization)."""
    # _as_text is a str() probe, not an isinstance gate: the route hands the
    # token over as str through Pydantic, but the service is also called
    # in-process, and a non-str leftover TypeError'd fullmatch (a 500) where
    # the coded ``bad_token`` refusal is the contract.  An over-cap
    # already-int (YAML/plist hex loads uncapped through ``int(x, 16)``)
    # scrubs to "" and earns the same refusal.
    token = _as_text(date_token)
    if not _SNAP_DATE.fullmatch(token):
        return {"ok": False, "error": "bad_token"}
    result = run_admin(
        [TMUTIL, "deletelocalsnapshots", token],
        timeout=180,
    )
    invalidate()
    return _admin_result(result)


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
    if isinstance(result, dict) and result.get("ok"):
        result = dict(result)
        result["deleted"] = len(tokens)
    return _admin_result(result)


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
    return _admin_result(result)


_TM_ACTIONS = {
    "start": [TMUTIL, "startbackup"],
    "stop": [TMUTIL, "stopbackup"],
    "enable": [TMUTIL, "enable"],
    "disable": [TMUTIL, "disable"],
}


def time_machine_action(action: str) -> dict:
    """Run a Time Machine control verb through the authorization sheet."""
    # _as_text is a str() probe, not an isinstance gate: the route hands the
    # verb over as str through Pydantic, but the service is also called
    # in-process, and a leftover non-str action AttributeError'd ``.strip()``
    # (a 500) where the coded ``bad_action`` refusal is the contract — the
    # raid_svc._req_text / smart_test_svc._schedule_text convention this
    # module already applies to delete_snapshot's token.  An over-cap
    # already-int (YAML/plist hex loads uncapped through ``int(x, 16)``)
    # coerces to "" and earns the same refusal.
    argv = _TM_ACTIONS.get(_as_text(action).strip().lower())
    if not argv:
        return {"ok": False, "error": "bad_action"}
    result = run_admin(argv, timeout=180)
    invalidate()
    return _admin_result(result)
