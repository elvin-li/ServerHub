"""Read-only storage-pool planner (JBOD union, deliberately not RAID).

What this models
---------------
A *pool* presents several independent disks as one capacity figure, the way
Unraid's array or a mergerfs union does.  Each member disk keeps its own
filesystem and each file lives whole on exactly one disk.  Losing a disk costs
you the files on that disk and nothing else.

Why not the obvious alternatives
--------------------------------
* APFS volume groups / logical volumes stripe across members: one dead disk
  takes the whole group with it.  Rejected — it is the failure mode this module
  exists to avoid.
* RAID0 has the same all-or-nothing exposure; RAID5/6 buys redundancy with a
  parity write on every operation, which is not what was asked for.

Scope
-----
Nothing here mounts, links, formats, or writes to any *disk*: it reads the
existing volume inventory and reports what a pool would look like, including
which member a new file would land on.  Actually presenting a single mount
point needs a union filesystem (macFUSE), which is a host-level change that has
to be approved separately — `union_requirements()` spells that out instead of
doing it.

`save_pool()` is the one exception to "read-only", and it is deliberately
narrow: it persists the *membership list and policy* into services.yaml.  That
is panel configuration, not disk state — no partition table, filesystem, or
mount is touched, and removing a member from the pool never removes data from
the disk.  Files stay exactly where they are; only the panel's view changes.
"""
from __future__ import annotations

import threading
import time
from typing import Any

from hub.config import cfg, update_settings
from hub.errors import api_error
from hub.util import strftime_now

#: Volume kinds that may join a pool.  System volumes are never eligible: the
#: boot disk cannot be a pool member without making the pool undetachable.
POOLABLE_KINDS = frozenset({"external", "data", "other"})

#: Placement strategies.  Both keep whole files on one disk; they differ only in
#: which member a new file is handed to.
PLACEMENT_POLICIES = ("most-free", "least-used-pct", "round-robin")
DEFAULT_POLICY = "most-free"

#: A pool view is derived from `df` output, which is cheap but not free, and the
#: page polls.  Short TTL: mounts appear and vanish on user action.
_TTL = 5.0
_cache: dict[str, Any] = {"t": 0.0, "v": None}
_lock = threading.Lock()
_refresh_lock = threading.Lock()
#: Bumped by `invalidate_pool`, which save_pool/delete_pool call after writing
#: the new membership.  A `df` sweep that started before the write returns the
#: old member set; without this it would publish over the invalidate and the
#: page would show the pool the operator just replaced.
_generation = 0


def _pool_config() -> dict:
    """Pool definitions from services.yaml, or an empty default.

    Absent configuration is the normal state: the panel should show the
    candidate disks and let the operator decide, not invent a pool.
    """
    raw = (cfg().get("settings") or {}).get("storage_pool") or {}
    if not isinstance(raw, dict):
        raw = {}
    members_raw = raw.get("members")
    members = []
    if isinstance(members_raw, list):
        for m in members_raw:
            text = _text(m).strip()
            if text:
                members.append(text)
    policy = _text(raw.get("policy")) or DEFAULT_POLICY
    if policy not in PLACEMENT_POLICIES:
        policy = DEFAULT_POLICY
    try:
        min_free = float(raw.get("min_free_gb") or 0)
    except (TypeError, ValueError, OverflowError):
        min_free = 0.0
    if min_free != min_free or min_free in (float("inf"), float("-inf")):
        min_free = 0.0
    return {
        "name": _text(raw.get("name")) or "pool",
        "members": members,
        "policy": policy,
        "min_free_gb": min_free,
    }


def _text(raw) -> str:
    """Volume string field as a JSON-safe string.

    ``list_volumes`` leftover ``mount: inf`` / ``disk_id: bytes`` used to 500
    GET /api/storage/pool under Starlette's ``allow_nan=False`` encoder.
    A leftover ``\\ud800`` YAML name / mount still 500'd the UTF-8 encode.
    """
    if isinstance(raw, (list, tuple)):
        raw = raw[0] if raw else ""
    if isinstance(raw, (bytes, bytearray)):
        raw = bytes(raw).decode("utf-8", "replace")
    elif isinstance(raw, float) and (raw != raw or raw in (float("inf"), float("-inf"))):
        return ""
    elif raw in (None, False, True, "") or isinstance(raw, (dict, set, frozenset)):
        return ""
    elif not isinstance(raw, str):
        iso = getattr(raw, "isoformat", None)
        if callable(iso):
            try:
                stamped = iso()
            except Exception:
                return ""
            # isoformat() is usually a str; a leftover that returns inf
            # used to TypeError ``.encode`` on GET /api/storage/pool.
            if stamped is raw:
                return ""
            return _text(stamped)
        return ""
    return raw.encode("utf-8", "replace").decode("utf-8")


def _finite_float(raw) -> float:
    if isinstance(raw, bool) or raw in (None, ""):
        return 0.0
    try:
        value = float(raw)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    if value != value or value in (float("inf"), float("-inf")):
        return 0.0
    return value


def _finite_int(raw) -> int:
    if isinstance(raw, bool) or raw in (None, ""):
        return 0
    try:
        return int(float(raw))
    except (TypeError, ValueError, OverflowError):
        return 0


def _json_gb(raw) -> float:
    """Finite GB total. Two leftover ``1e308`` members summed to inf and
    ``int(round(inf/inf*100))`` OverflowError'd GET /api/storage/pool."""
    try:
        value = round(float(raw), 1)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    if value != value or value in (float("inf"), float("-inf")):
        return 0.0
    return value


def _candidates() -> list[dict]:
    """Mounted, writable, non-system volumes that could join a pool."""
    from hub import storage_svc

    out: list[dict] = []
    volumes = storage_svc.list_volumes()
    for vol in volumes if isinstance(volumes, list) else []:
        if not isinstance(vol, dict):
            continue
        if vol.get("kind") not in POOLABLE_KINDS:
            continue
        mount = _text(vol.get("mount"))
        if not mount:
            continue
        disk_id = _text(vol.get("disk_id")) or None
        out.append(
            {
                "mount": mount,
                "device": _text(vol.get("device")),
                "disk_id": disk_id,
                "filesystem": _text(vol.get("filesystem")),
                "total_gb": _finite_float(vol.get("total_gb")),
                "used_gb": _finite_float(vol.get("used_gb")),
                "avail_gb": _finite_float(vol.get("avail_gb")),
                "pct": _finite_int(vol.get("pct")),
            }
        )
    out.sort(key=lambda v: v["mount"])
    return out


def _pick_target(members: list[dict], policy: str, counter: int = 0) -> str | None:
    """Which member a new file would be written to under *policy*.

    Exposed through the API so the operator can see placement before trusting
    it — a pool whose next write goes to an almost-full disk is worth knowing
    about before the write fails.
    """
    usable = [m for m in members if m.get("avail_gb", 0) > 0]
    if not usable:
        return None
    if policy == "least-used-pct":
        return min(usable, key=lambda m: m["pct"])["mount"]
    if policy == "round-robin":
        return usable[counter % len(usable)]["mount"]
    return max(usable, key=lambda m: m["avail_gb"])["mount"]


def _summarise(members: list[dict]) -> dict:
    """Pool totals.

    Capacity adds up because members are independent, but the largest single
    file the pool can accept is bounded by the *biggest single member's* free
    space — not by the sum.  Reporting only the sum is how a JBOD union
    surprises people, so both numbers are returned.
    """
    total = _json_gb(sum(m["total_gb"] for m in members))
    used = _json_gb(sum(m["used_gb"] for m in members))
    avail = _json_gb(sum(m["avail_gb"] for m in members))
    largest_single_write = _json_gb(
        max((m["avail_gb"] for m in members), default=0.0)
    )
    try:
        pct = int(round(used / total * 100)) if total else 0
    except (OverflowError, ValueError, ZeroDivisionError, TypeError):
        pct = 0
    return {
        "total_gb": total,
        "used_gb": used,
        "avail_gb": avail,
        "pct": pct,
        "largest_single_file_gb": largest_single_write,
        "member_count": len(members),
    }


def _fault_model(members: list[dict]) -> list[dict]:
    """Per-member blast radius, stated in the units the operator cares about.

    The point of the whole design: this table would read "all data lost" for
    every row under RAID0 or an APFS volume group.
    """
    total = _json_gb(sum(m["total_gb"] for m in members))
    rows = []
    for m in members:
        rows.append(
            {
                "mount": m["mount"],
                "disk_id": m["disk_id"],
                "at_risk_gb": _json_gb(m["used_gb"]),
                "survives_gb": _json_gb(total - m["total_gb"]),
                # Spelled out rather than implied: independence is the feature.
                "other_members_affected": False,
            }
        )
    return rows


def union_requirements() -> dict:
    """What a single merged mount point would additionally need.

    Deliberately a description, not an action.  Presenting one directory backed
    by several disks needs a union filesystem; on macOS that means macFUSE,
    which is a kernel extension and requires lowering the startup security
    policy from Recovery.  That is a host-configuration decision for the
    operator, so this reports and stops.
    """
    return {
        "single_mount_supported": False,
        "reason": "union_fs_missing",
        "requires": [
            {
                "id": "macfuse",
                "kind": "kernel_extension",
                "reversible": True,
                "needs_recovery_mode": True,
                "needs_reboot": True,
            }
        ],
        # Without a union layer the pool is still useful as an accounting and
        # placement view; it just cannot hand out one path.
        "available_without_it": [
            "aggregate_capacity",
            "placement_preview",
            "fault_model",
            "per_member_browsing",
        ],
    }


def _build() -> dict:
    conf = _pool_config()
    candidates = _candidates()
    by_mount = {c["mount"]: c for c in candidates}

    members = [by_mount[m] for m in conf["members"] if m in by_mount]
    missing = [m for m in conf["members"] if m not in by_mount]
    unassigned = [c for c in candidates if c["mount"] not in set(conf["members"])]

    return {
        "configured": bool(conf["members"]),
        "name": conf["name"],
        "policy": conf["policy"],
        "policies": list(PLACEMENT_POLICIES),
        "members": members,
        # A configured member that is not mounted right now: the pool is degraded
        # in capacity but the remaining members are fully readable.
        "missing_members": missing,
        "unassigned": unassigned,
        "summary": _summarise(members),
        "next_write_target": _pick_target(members, conf["policy"]),
        "fault_model": _fault_model(members),
        "union": union_requirements(),
        # Restated on every response so the UI never has to assume it.
        "raid": False,
        "parity": False,
        "ts": strftime_now("%H:%M:%S"),
    }


def pool_overview(force: bool = False) -> dict:
    """Cached pool view.  Single-flight so a polling page cannot stack `df`."""
    if not force:
        with _lock:
            hit = _cache["v"]
            if hit is not None and time.time() - _cache["t"] < _TTL:
                return dict(hit)

    with _refresh_lock:
        with _lock:
            hit = _cache["v"]
            if hit is not None and time.time() - _cache["t"] < _TTL:
                return dict(hit)
            began = _generation
        data = _build()
        with _lock:
            if _generation == began:
                _cache.update(t=time.time(), v=data)
        return dict(data)


def invalidate_pool() -> None:
    global _generation
    with _lock:
        _generation += 1
        _cache.update(t=0.0, v=None)


def _validate(mounts: list[str], policy: str) -> tuple[list[str], list[dict]]:
    """Shared gate for planning and saving.

    Saving must not be a weaker check than planning: if it were, an operator
    could preview a rejected set, then persist it anyway through the other
    endpoint.  Both paths come through here, so a system volume is refused
    identically either way.

    Returns the de-duplicated mount list and the resolved member records.
    """
    if policy not in PLACEMENT_POLICIES:
        raise api_error("storage_pool.bad_policy", policy=policy)

    wanted: list[str] = []
    for raw in mounts or []:
        m = str(raw).strip()
        # A mount listed twice would double-count its capacity in the summary
        # and make the fault model claim more survives than actually would.
        if m and m not in wanted:
            wanted.append(m)
    if not wanted:
        raise api_error("storage_pool.no_members")

    by_mount = {c["mount"]: c for c in _candidates()}
    unknown = [m for m in wanted if m not in by_mount]
    if unknown:
        raise api_error("storage_pool.not_poolable", mount=unknown[0])

    return wanted, [by_mount[m] for m in wanted]


def plan_pool(mounts: list[str], policy: str = DEFAULT_POLICY) -> dict:
    """What a pool over *mounts* would look like, without saving anything.

    Lets the operator compare candidate sets before committing one to
    configuration.
    """
    _, members = _validate(mounts, policy)
    return {
        "policy": policy,
        "members": members,
        "summary": _summarise(members),
        "next_write_target": _pick_target(members, policy),
        "fault_model": _fault_model(members),
        "union": union_requirements(),
        "raid": False,
        "parity": False,
        # Planning only: nothing was mounted, linked, formatted or persisted.
        "applied": False,
    }


def save_pool(mounts: list[str], policy: str = DEFAULT_POLICY, name: str = "",
              min_free_gb: float = 0) -> dict:
    """Persist the pool's membership and policy into services.yaml.

    The only writing function in this module, and it writes *panel config* —
    which mounts the panel treats as one logical pool, and how it picks a target
    for the next write.  It does not partition, format, mount, unmount or link
    anything, and it never moves or deletes a file.  Dropping a member is
    likewise metadata-only: the disk keeps its files, the panel just stops
    counting them toward the pool.

    Goes through the same ``_validate`` gate as planning, so a system volume
    cannot be persisted via the back door.
    """
    # Members are re-resolved by the overview below; here _validate is called
    # purely for its rejections.
    wanted, _ = _validate(mounts, policy)

    clean_name = str(name or "").strip() or "pool"
    try:
        floor = max(0.0, float(min_free_gb or 0))
    except (TypeError, ValueError, OverflowError):
        floor = 0.0
    if floor != floor or floor in (float("inf"), float("-inf")):
        floor = 0.0

    update_settings({
        "storage_pool": {
            "name": clean_name,
            "members": wanted,
            "policy": policy,
            "min_free_gb": floor,
        }
    })
    # The cached view was built from the previous membership; serving it now
    # would show the operator a pool that no longer matches what was saved.
    invalidate_pool()

    out = pool_overview(force=True)
    # Distinguishes a saved pool from a preview.  Still false for the union
    # mount point, which needs a FUSE layer that is not installed.
    out["applied"] = True
    return out


def clear_pool() -> dict:
    """Forget the pool definition.  Data on the member disks is untouched.

    Worth stating plainly because the UI wording has to match: this is the
    inverse of ``save_pool`` at the config level only.  Every file stays on the
    disk it was already on, and every member stays mounted and browsable.
    """
    update_settings({
        "storage_pool": {
            "name": "pool",
            "members": [],
            "policy": DEFAULT_POLICY,
            "min_free_gb": 0,
        }
    })
    invalidate_pool()
    out = pool_overview(force=True)
    out["applied"] = True
    return out
