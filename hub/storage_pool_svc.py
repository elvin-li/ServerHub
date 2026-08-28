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

import re
import threading
import time
from typing import Any

from hub.config import cfg, update_settings
from hub.errors import api_error
from hub.util import strftime_now

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")

#: Volume kinds that may join a pool.  System volumes are never eligible: the
#: boot disk cannot be a pool member without making the pool undetachable.
POOLABLE_KINDS = frozenset({"external", "data", "other"})

#: Placement strategies.  Both keep whole files on one disk; they differ only in
#: which member a new file is handed to.
PLACEMENT_POLICIES = ("most-free", "least-used-pct", "round-robin")
DEFAULT_POLICY = "most-free"

#: Display-label cap, matching the accounts/apikeys/disk/vms name caps.  The
#: name is persisted into services.yaml: unbounded, a multi-MB label was
#: refused only by the whole-file save cap as a settings.save_failed 503
#: (blaming the disk for oversized input), and a label just under that cap
#: landed with HTTP 200 and ballooned services.yaml toward the 1MB read cap
#: every sibling writer shares.
_NAME_CAP = 64

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


def _isa(value, kinds) -> bool:
    """``isinstance`` that survives a leftover ``__class__``-property bomb.

    ``isinstance`` consults ``value.__class__`` when the exact-type check
    misses, so a leftover whose ``__class__`` is a *raising property*
    detonated the bare gates themselves — planted as the cfg root, the
    ``settings`` map, the ``storage_pool`` block, the ``members`` list, a
    member value, the ``name`` / ``policy`` scalars (through ``_text``'s
    first rank gate), a ``list_volumes`` row, or the listing return — and
    500'd all four pool routes at once, one line ahead of the laundering
    built to absorb junk shapes (the system/status/usage_svc rule).  A real
    subclass still matches through the C-level type check; only a value
    that cannot answer what it is takes the non-matching branch.
    """
    try:
        return isinstance(value, kinds)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _sequence_rows(value) -> list:
    """Materialised rows of a leftover list/tuple, or ``[]`` fail-closed.

    The unbound ``list.__iter__`` walk this replaces guarded against a
    *subclass* ``__iter__`` override, but the descriptor call itself ran
    bare: a leftover whose ``__class__`` property *lies* (answers ``list``
    without being one — or answers once and raises on the next look) passed
    ``_isa`` and then blew the unbound ``list.__iter__`` with a TypeError
    one line outside every try, 500ing all four pool routes at once.  The
    descriptor still bypasses a real subclass's override; an impostor that
    only claims the type takes the empty branch instead of the 500.
    """
    for base in (list, tuple):
        if _isa(value, base):
            try:
                return list(base.__iter__(value))
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return []
    return []


def _mapping_get(mapping, key):
    """Field read that a hostile mapping *key* cannot 500.

    The ``hub.ups_svc._mapping_get`` rule, which this reader's unbound
    ``dict.get`` calls never got: the unbound builtin bypasses a subclass
    ``.get`` override, but the hash probe still runs the *stored keys'*
    own ``__eq__`` — a leftover str-subclass key whose hash shadows
    ``"settings"`` / ``"storage_pool"`` / ``"members"`` / ``"name"`` /
    ``"policy"`` and whose ``__eq__`` raises used to detonate the bare
    ``dict.get`` and 500 all four pool routes at once.  Only the shadowed
    field degrades to its default; the siblings keep their sane data.
    """
    if not _isa(mapping, dict):
        return None
    try:
        return dict.get(mapping, key)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None


def _match_policy(policy):
    """The canonical ``PLACEMENT_POLICIES`` entry equal to *policy*, or ``None``.

    ``policy in PLACEMENT_POLICIES`` compares each known entry against the
    caller's value, and when that value is a leftover the reflected
    ``__eq__`` dispatches into it first — a str-subclass ``__eq__`` bomb, or
    a bare object whose ``__eq__`` raises, detonated the membership gate in
    ``_validate`` with a RuntimeError *outside* every try.  The routes hand
    over a Pydantic-exact ``str``, but ``plan_pool`` / ``save_pool`` are also
    called in-process, and there the bomb 500'd the service where every other
    junk policy earns the coded ``storage_pool.bad_policy`` refusal.

    Comparing under a per-entry try both absorbs the bomb and hands back the
    *exact* known string, so a genuine str-subclass that merely equals a
    policy is never echoed into the response or persisted into services.yaml
    wearing its own ``__eq__`` / ``encode`` overrides.
    """
    for known in PLACEMENT_POLICIES:
        try:
            if known == policy:
                return known
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
    return None


def _wants_refresh(force) -> bool:
    """Truthiness of the overview's refresh flag that a leftover cannot 500.

    ``pool_overview`` opened with ``if not force:``, and ``not`` reflects
    into the flag's own ``__bool__`` (or ``__len__``) — the one public
    parameter this module never laundered after mounts / policy / name /
    min_free_gb were sealed.  The route hands over a FastAPI-exact ``bool``,
    but the overview is also called in-process, and a leftover flag whose
    ``__bool__`` raises detonated the reader itself — the same reader
    ``save_pool`` / ``clear_pool`` re-enter after their config writes.

    A flag that cannot answer whether it is truthy degrades to *refresh*:
    rebuilding from ``df`` costs one sweep and can never lie, while serving
    the cache would answer a caller whose intent is unknowable with data it
    may have been trying to bypass (the invalidate-on-doubt rule the disk
    routes already follow).
    """
    if type(force) is bool:
        return force
    try:
        return bool(force)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return True


def _pool_config() -> dict:
    """Pool definitions from services.yaml, or an empty default.

    Absent configuration is the normal state: the panel should show the
    candidate disks and let the operator decide, not invent a pool.

    ``dict.get`` / ``list.__iter__``, not the bound methods (the
    ``settings_section`` convention this reader predates): ``cfg()`` parses
    YAML to exact types, but the nested values are whatever an in-process
    caller last stored, and a dict-*subclass* settings map (or pool block)
    with a bombing ``.get`` / ``__bool__`` — or a list-subclass ``members``
    whose ``__iter__`` raises — used to detonate this reader and 500 all
    four pool routes at once (GET /api/storage/pool, plan, save, and clear
    *after* its config write had already landed).  The unbound builtins read
    the C-level storage underneath the override, so only the truly hostile
    value degrades to its default.  The ``or {}`` truth tests are gone for
    the same reason: they only existed to turn None into ``{}``, which the
    isinstance gates already do, and they ran a subclass ``__bool__``.
    """
    # Guarded like settings_section: a snapshot provider that raises used to
    # escape this reader and 500 every pool route.
    try:
        data = cfg()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        data = {}
    # _mapping_get, not bare ``dict.get``-under-isinstance: a ``__class__``
    # property bomb detonated each rank gate, and a hash-shadowing key bomb
    # detonated each unbound ``dict.get``'s probe (see the helpers above).
    settings = _mapping_get(data, "settings")
    raw = _mapping_get(settings, "storage_pool")
    if not _isa(raw, dict):
        raw = {}
    # _sequence_rows, not a bare unbound ``list.__iter__``: a leftover whose
    # ``__class__`` lies as ``list`` passed the rank gate and the descriptor
    # call TypeError'd outside every try, 500ing all four pool routes.
    members = []
    for m in _sequence_rows(_mapping_get(raw, "members")):
        text = _text(m).strip()
        if text:
            members.append(text)
    # _match_policy, not a bare ``not in`` gate: ``_text`` hands back an exact
    # str here so the membership test itself is safe, but routing the read
    # through the same guarded matcher the mutations use keeps one policy gate
    # and returns the canonical entry rather than the parsed scalar.
    policy = _match_policy(_text(_mapping_get(raw, "policy"))) or DEFAULT_POLICY
    try:
        # ``except Exception``, not the (TypeError, ValueError, OverflowError)
        # tuple: ``float()`` reflects into the stored value's own
        # ``__float__``, and the ``or 0`` runs its ``__bool__`` — a leftover
        # subclass bomb in either used to raise past the tuple and 500 the
        # same four routes.
        min_free = float(_mapping_get(raw, "min_free_gb") or 0)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        min_free = 0.0
    if min_free != min_free or min_free in (float("inf"), float("-inf")):
        min_free = 0.0
    return {
        "name": _text(_mapping_get(raw, "name")) or "pool",
        "members": members,
        "policy": policy,
        "min_free_gb": min_free,
    }


def _text(raw) -> str:
    """Volume string field as a JSON-safe string.

    ``list_volumes`` leftover ``mount: inf`` / ``disk_id: bytes`` used to 500
    GET /api/storage/pool under Starlette's ``allow_nan=False`` encoder.
    A leftover ``\\ud800`` YAML name / mount still 500'd the UTF-8 encode.

    Ints coerce via the str() probe, not an ``isinstance(str)`` gate:
    services.yaml is hand-editable, so ``name: 2026`` arrives *already-int*
    and used to silently read as the default "pool", and a numeric member
    vanished from the view entirely — not even listed as missing.  Only an
    over-cap leftover (YAML hex/octal loads uncapped; its str() is the same
    digit-cap ValueError json.dumps would raise) still reads as "".

    Unbound-base scrubs throughout (the modules5/cf7 convention): a leftover
    *subclass* passes every isinstance gate here wearing its own protocol
    overrides, and through ``_pool_config`` each of these used to raise out
    of this coercer and 500 all four pool routes at once — an int-subclass
    ``__str__`` bomb (the bare ``str()`` reflected into it and RuntimeError
    is not the digit-cap ValueError), a float-subclass ``__eq__`` bomb (the
    nan/inf probes ran it), a str-subclass self-``__str__`` ``encode`` bomb
    (the bound encode dispatched into the override), a bytes-subclass
    ``__bytes__``/``decode`` bomb, a list-subclass ``__bool__`` /
    ``__getitem__`` bomb, a bare ``__eq__`` bomb (the old
    ``raw in (None, False, True, "")`` tuple probe), and an ``isoformat``
    ``__getattr__`` bomb.  ``int.__index__`` / ``str.encode`` /
    ``bytes.decode`` / ``list.__getitem__`` read the real content underneath
    the override, so the real text still renders and only the truly
    unrenderable degrades to "".

    ``_isa`` on every rank gate, not bare ``isinstance``: a leftover whose
    ``__class__`` is a *raising property* detonated the very first gate here
    — as a member value, the ``name``, or the ``policy`` — and 500'd all
    four pool routes ahead of every scrub below (the system/status rule).
    """
    if _isa(raw, (list, tuple)):
        # _isa again, not the bare ``isinstance`` this line used to run: a
        # leftover whose ``__class__`` property answers ``list`` once and
        # raises on the next look passed the tuple gate above and detonated
        # the base pick itself — 500ing all four pool routes through the
        # name, the policy, or one member value.  A mispicked base for such
        # an impostor just TypeErrors the unbound call inside the try.
        base = list if _isa(raw, list) else tuple
        try:
            raw = base.__getitem__(raw, 0) if base.__len__(raw) else ""
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return ""
    if _isa(raw, (bytes, bytearray)):
        decoded = None
        for base in (bytes, bytearray):
            try:
                decoded = base.decode(raw, "utf-8", "replace")
                break
            except _CONTROL_FLOW:
                raise
            except BaseException:
                continue
        if decoded is not None:
            return decoded
    # Exact-type probe, not ``_isa``: ``type`` never reflects into a lying
    # ``__class__``, and bool cannot be subclassed — so a real int-subclass
    # *claiming* bool now renders its digits through the int gate below
    # instead of silently reading as "".
    if type(raw) is bool:
        return ""
    if _isa(raw, int):
        try:
            # int.__index__ launders a subclass to an exact int ahead of the
            # digit-cap probe; str() of that exact int cannot reflect back
            # into a leftover ``__str__`` override.
            return str(int.__index__(raw))
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return ""
    if _isa(raw, float):
        # Every exact float already read as "" (nan/inf via the explicit
        # probe, finite via the no-isoformat fall-through); stating it as
        # one branch removes the ``!=`` / ``in`` equality probes a subclass
        # ``__eq__`` bomb used to detonate.
        return ""
    if raw is None or _isa(raw, (dict, set, frozenset)):
        return ""
    if not _isa(raw, str):
        try:
            iso = getattr(raw, "isoformat", None)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return ""
        if not callable(iso):
            return ""
        try:
            stamped = iso()
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return ""
        # isoformat() is usually a str; a leftover that returns inf
        # used to TypeError ``.encode`` on GET /api/storage/pool.
        if stamped is raw:
            return ""
        try:
            return _text(stamped)
        except RecursionError:
            # A leftover isoformat *chain* (A stamps B, B stamps A) is not
            # caught by the identity probe above.
            return ""
    try:
        text = str.encode(raw, "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    try:
        cls = type(raw)
        if cls.__str__ is object.__str__ and cls.__repr__ is object.__repr__:
            return ""
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    return "" if _ADDR_REPR_RE.search(text) else text


def _finite_float(raw) -> float:
    """Finite exact float, degrading junk to 0.0 field-level.

    ``type(raw) is bool`` and ``raw is None``, not the old
    ``isinstance(raw, bool) or raw in (None, "")``: the isinstance ran a
    lying/raising ``__class__`` and the tuple ``in`` ran a leftover
    subclass ``__eq__`` — either bomb in one ``df`` field used to throw
    the whole healthy row away through ``_candidates``' per-row try.
    ``except Exception``: ``float()`` reflects into the value's own
    ``__float__``.  ``float.__float__`` launders a subclass result to an
    exact float so the nan/inf probes below cannot run a subclass
    ``__eq__`` either.
    """
    if type(raw) is bool or raw is None:
        return 0.0
    try:
        value = float.__float__(float(raw))
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return 0.0
    if value != value or value in (float("inf"), float("-inf")):
        return 0.0
    return value


def _finite_int(raw) -> int:
    if type(raw) is bool or raw is None:
        return 0
    try:
        return int.__index__(int(float(raw)))
    except _CONTROL_FLOW:
        raise
    except BaseException:
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
    try:
        volumes = storage_svc.list_volumes()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # The pool4 guard below covered *iteration* but not the call: a
        # list_volumes that raised outright (a seam replacement, a leftover
        # that slips its own guards) still 500'd every pool route at once —
        # clear *after* its config write had already landed.  Same honest
        # degrade as the iteration bomb: no candidates, members read missing.
        volumes = []
    # _isa, not bare isinstance: a listing return whose ``__class__`` is a
    # raising property detonated this gate one line past the call guard.
    if not _isa(volumes, list):
        volumes = []
    try:
        volumes = list(volumes)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # A volume listing that passes the isinstance gate but refuses
        # *iteration* (odd list subclass from the seam) used to raise out of
        # this loop and 500 every pool route at once — GET /api/storage/pool,
        # plan, save, and clear *after* its config write had already landed —
        # the ups_svc/storage_svc/usage_svc materialize-under-guard rule this
        # module missed.  No candidates is the honest degrade: the overview
        # reports members as missing, and the mutations answer their coded
        # refusals instead of a bare 500.
        volumes = []
    for vol in volumes:
        # _isa: one row whose ``__class__`` is a raising property used to
        # detonate this per-row gate and 500 all four pool routes, where
        # every other junk row already drops silently.
        if not _isa(vol, dict):
            continue
        try:
            # Per-row guard, same class as the iteration bomb above: a dict
            # *subclass* passes the isinstance gate with a ``.get`` that
            # raises, and one such row used to cost all four pool routes.
            # Dropping the hostile row keeps its healthy siblings rendering.
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
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
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
    # _match_policy, not bare ``policy == ...`` compares: the string compare
    # dispatches into the left operand's ``__eq__`` first, so a leftover
    # policy (a str-subclass ``__eq__`` bomb) detonated the placement pick
    # for a direct in-process caller — the routes reach here only through
    # ``_build`` / ``plan_pool``, which already canonicalized.  An unknown
    # policy keeps falling through to most-free, exactly as before.
    policy = _match_policy(policy) or DEFAULT_POLICY
    if policy == "least-used-pct":
        return min(usable, key=lambda m: m["pct"])["mount"]
    if policy == "round-robin":
        # Guarded unbound ``int.__index__``: ``counter % len(usable)``
        # reflects into the counter's own ``__mod__`` (and a plain int()
        # would reflect into ``__int__``), so the one leftover an advancing
        # round-robin caller could hand this — an int-subclass whose
        # arithmetic raises, a bool, a non-number — detonated the pick
        # where every other junk placement input degrades.  Step 0 (the
        # first usable member) is the same answer a fresh counter gives.
        try:
            step = int.__index__(counter)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            step = 0
        return usable[step % len(usable)]["mount"]
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
    # _wants_refresh, not a bare ``not force``: the reflected ``__bool__``
    # used to detonate the reader itself for in-process callers (see the
    # helper).  The route's FastAPI-exact bool takes the type-is-bool fast
    # path unchanged.
    force = _wants_refresh(force)
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
    # _match_policy, not a bare ``policy not in PLACEMENT_POLICIES``: the
    # tuple membership test runs the caller value's ``__eq__``, and a leftover
    # policy (a str-subclass ``__eq__`` bomb, or a bare object that raises from
    # ``__eq__``) detonated it with a RuntimeError one line outside every try,
    # 500ing plan/save for in-process callers where junk policies already earn
    # the coded refusal.
    if _match_policy(policy) is None:
        raise api_error("storage_pool.bad_policy", policy=policy)

    wanted: list[str] = []
    # Guarded unbound walk (the smart_test_svc.set_schedule rule): the routes
    # hand over Pydantic-exact lists, but the service is also called
    # in-process, and a leftover list-subclass ``__bool__``/``__iter__`` bomb
    # used to blow the old ``(mounts or [])`` raw out of GET-adjacent
    # POST /api/storage/pool/plan and /save for those callers, where junk
    # mounts already earn their coded refusals.  _isa for the same
    # in-process callers: a mounts value whose ``__class__`` is a raising
    # property detonated the bare gate itself.
    # _sequence_rows, not bare unbound ``__iter__`` calls: a mounts value
    # whose ``__class__`` *lies* as list/tuple passed the _isa gates and the
    # descriptor call itself TypeError'd out of plan/save for in-process
    # callers, where junk mounts already earn their coded refusals.
    for raw in _sequence_rows(mounts):
        # _text, not str(): a leftover int already past CPython's int->str
        # digit cap made ``str(raw)`` itself ValueError out of the endpoint
        # instead of the coded refusal every other junk mount gets.
        m = _text(raw).strip()
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
    # _validate accepted it, so the match is guaranteed; take the canonical
    # exact string so the echoed policy and the placement pick below are never
    # the caller's lying str-subclass.
    policy = _match_policy(policy) or DEFAULT_POLICY
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
    # Canonical exact string for the same reason as plan_pool: a genuine
    # str-subclass that merely equals a policy must not be persisted into
    # services.yaml carrying its own ``__eq__`` / ``encode`` overrides.
    policy = _match_policy(policy) or DEFAULT_POLICY

    # _text for the same reason as _validate: a leftover over-digit-cap int
    # name made ``str()`` ValueError, and a leftover ``\ud800`` name would be
    # persisted raw into services.yaml; scrub before writing, not after.
    clean_name = _text(name).strip() or "pool"
    # Cap after the scrub: the scrubbed text is what would be persisted, and
    # code points are the unit the config read cap compares.
    if len(clean_name) > _NAME_CAP:
        raise api_error("storage_pool.name_too_long", max=_NAME_CAP)
    # No ``or 0`` and ``except Exception``, not the narrow tuple: the routes
    # hand over a Pydantic-exact float, but an in-process caller's leftover
    # subclass used to detonate the ``or``'s ``__bool__`` probe (or raise
    # past the tuple from its own ``__float__``) out of save_pool where
    # every other junk floor already degrades to no reservation.
    if min_free_gb is None:
        floor = 0.0
    else:
        try:
            floor = max(0.0, float.__float__(float(min_free_gb)))
        except _CONTROL_FLOW:
            raise
        except BaseException:
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
