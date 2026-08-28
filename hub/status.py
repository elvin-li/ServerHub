"""Aggregate service status with short TTL cache + adaptive discovery."""
from __future__ import annotations

import re
import threading
import time

from hub import __version__
from hub.adaptive import discover_orphan_listeners, nginx_sites, scan_new_compose_projects
from hub.config import cfg, panel_locale
from hub.resource_mode import resource_mode
from hub.host_address import resolve_value
from hub.discovery import (
    collect_apps,
    collect_scripts,
    discover_containers,
    discover_launchd,
    discover_vms,
)
from hub.system import collect_system
from hub.util import LazyPool, strftime_now

# Hot path: 35s TTL + single-flight in low mode. Sidebar and menubar poll
# every 30s; a 20s TTL missed on every one of those ticks.
_STATUS_TTL = 35.0
_STATUS_TTL_HIGH = 20.0


def _status_ttl() -> float:
    from hub.resource_mode import is_high
    return _STATUS_TTL_HIGH if is_high() else _STATUS_TTL
_status_cache = {"t": 0.0, "v": None}
_lock = threading.Lock()
_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")
# Single-flight: only one full refresh at a time; waiters reuse the result.
_refresh_lock = threading.Lock()
# Bumped by invalidate_status().  Every container mutation calls that, and the
# dashboard is polling throughout, so a build that started just before the click
# is the ordinary case — and it read the pre-action host.  Publishing it stamps
# the old snapshot fresh and the stopped container keeps showing as running for
# another TTL. A build from a superseded generation is dropped instead.
#
# Shared by both caches below: invalidate_status() drops them together, so a
# scan is stale for exactly the same reason and at exactly the same moments as
# a status build.  The adaptive one holds it for a minute rather than seconds,
# which is how long a compose project stayed listed after being torn down.
_status_generation = 0
# Adaptive filesystem scans change rarely — cache longer.
_adaptive_cache = {"t": 0.0, "compose": None, "nginx": None}
_ADAPTIVE_TTL = 60.0


def _isa(value, kinds) -> bool:
    """``isinstance`` that a leftover ``__class__``-property bomb cannot 500.

    ``isinstance`` consults ``value.__class__`` when the exact-type check
    misses, so a leftover whose ``__class__`` is a *raising property*
    detonated the gates themselves: planted as (or nested in) the cached
    snapshot it blew ``_stamp_locale`` / ``_jsonable`` on every cache-hit
    GET /api/status; planted as a cfg root or a ``quick_links`` value it
    blew the cold build (the docker_cli / nas8 rule).  A real subclass
    still matches through the C-level type check; only a value that cannot
    answer what it is takes the non-matching branch.
    """
    try:
        return isinstance(value, kinds)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _decode_bytes(value) -> str:
    """Unbound base decode: a leftover subclass ``.decode`` bomb cannot 500."""
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
        return ""


def _mapping_get(mapping, key, default=None):
    """Field read that a hostile mapping *key* cannot 500.

    The health11 / ups / vms rule, which this module's cache subscripts and
    the settings ``.get`` never got: even a plain-dict lookup still runs the
    *stored keys'* own ``__eq__`` during the hash probe, so a leftover
    str-subclass key whose hash shadows the real key and whose ``__eq__``
    raises used to detonate the bare ``_status_cache["v"]`` /
    ``_status_cache["t"]`` reads in ``full_status`` (a raw 500 on every
    GET /api/status), the ``raw_settings.get("adaptive")`` read one line
    past the plain-dict copy in ``_build_status`` (a 500 on the cold
    build), and ``_stamp_locale``'s snapshot reads on every cache hit.
    Only the shadowed field degrades to its default; siblings survive.
    """
    if not _isa(mapping, dict):
        return default
    try:
        return dict.get(mapping, key, default)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return default


def _cache_age(now, stamp) -> float:
    """Age of a cache stamp; an unreadable leftover stamp reads as expired.

    The host_address._cached_detection rule: a leftover planted in the
    ``t`` slot whose ``__float__`` / ``__rsub__`` / comparison raises used
    to detonate the bare ``now - _status_cache["t"]`` arithmetic in
    ``full_status`` and the ``_adaptive_cache`` probe — a raw 500 on every
    GET /api/status.  Junk reads as infinitely old and re-builds.
    """
    try:
        return now - float(stamp)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return float("inf")


def _cache_publish(cache: dict, **fields) -> None:
    """Cache write that a hash-shadowing planted key cannot 500.

    ``dict.update`` with an exact-str keyword still runs the *stored*
    poison key's ``__eq__`` during the insert compare, so a shadow key
    planted in the module cache used to raise at the very end of a
    successful build — the health11 ``_collect_checks`` write, on the
    status surface.  ``clear()`` never compares keys, so evicting the
    poison and rewriting always lands.
    """
    try:
        cache.update(fields)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        try:
            cache.clear()
            cache.update(fields)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            pass


def _cfg_value(key, default=None):
    """One top-level config read that a leftover cfg() bomb cannot 500.

    ``cfg()`` normally returns a plain dict, but a leftover whose root is a
    dict *subclass* with a bombing ``.get`` used to raise out of the bare
    ``cfg().get(...)`` reads in ``_build_status`` — 500ing a cold
    GET /api/status *and* POST /api/alerts/check, which calls
    ``full_status`` before any of its per-check try/excepts exist.
    ``dict.get`` reads the C-level storage underneath the override.
    ``_isa`` on the root gate: a cfg root whose ``__class__`` is a raising
    property used to detonate the bare isinstance the same way.
    """
    try:
        data = cfg()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return default
    if not _isa(data, dict):
        return default
    try:
        return dict.get(data, key, default)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return default


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
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


def _name_text(raw) -> str:
    """Order / resource / state text via a ``str()`` probe; ``""`` drops it.

    YAML numeric values (``groups_order: [2024, Media]``, a member
    ``resources: [8080]``) load as int.  The ``isinstance(g, str)`` gate on
    ``groups_order`` silently lost the numeric group's configured position,
    and the bare ``str()`` calls in ``filter_status_for_resources`` raised
    CPython's int->str digit-cap ValueError on an over-cap hex leftover —
    500ing the member GET /api/status this module exists to serve.  The
    jobs._task_id rule: a renderable value coerces, an over-cap leftover
    drops only itself, bool never becomes ``"True"``.
    """
    if raw is None or _isa(raw, bool):
        return ""
    return _utf8_text(raw)


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's allow_nan=False encoder cannot 500.

    ``int(inf)`` on a yaml ``1e999`` port was already isolated; the service
    row still carried ``port: inf`` / ``ports: [inf]`` and YAML timestamps
    in ``quick_links`` are ``datetime`` objects — both 500 GET /api/status.
    A leftover ``\\ud800`` in a name or key still 500'd the same encoder
    (``ensure_ascii=False`` then UTF-8) on GET /api/status and status peek.
    A >4300-digit leftover int (YAML/plist hex/octal loads uncapped) still
    passed through untouched: CPython's int->str digit limit then
    ValueError'd ``json.dumps`` itself, 500ing GET /api/status,
    GET /api/services and GET /api/services/{id}/detail.
    Nested subclass bombs (bound ``items``/``decode``/``__iter__``/``__str__``
    raising) still blew the probes themselves, so one poisoned collector row
    500'd the same three routes — hence the unbound base-type calls below,
    the modules5 convention.
    """
    if depth > 32:
        return None
    # _isa on every rank gate: a leftover whose ``__class__`` is a raising
    # property — planted as (or nested in) the cached snapshot, a collector
    # row or a config value — used to detonate the *first* isinstance below
    # and 500 GET /api/status and GET /api/services.
    if value is None:
        return value
    if _isa(value, bool):
        # ``bool`` cannot be subclassed, so anything passing this gate that
        # is not the exact type is a *lying* ``__class__`` impostor.  It
        # used to be returned verbatim here — every other liar drops at its
        # unbound base call, but the bool gate had nothing to call — and
        # the C-level JSON encoder then refused it: a raw 500 on cache-hit
        # and cold GET /api/status alike (and through resolve_value, which
        # rightly passes a non-container non-str leaf untouched).
        return value if type(value) is bool else None
    if _isa(value, int):
        if type(value) is not int:
            try:
                # Base coercion to an exact int: a subclass ``__str__``
                # bomb used to blow the digit-cap probe below.
                value = int.__index__(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return None
        try:
            str(value)
        except ValueError:
            # Past CPython's int->str digit cap the encoder cannot render
            # the number at all — same drop as its inf float sibling.
            return None
        return value
    if _isa(value, float):
        if type(value) is not float:
            try:
                # Base coercion to an exact float: a subclass ``__eq__``
                # bomb used to blow the NaN/inf probes below.
                value = float.__float__(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return None
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if _isa(value, str):
        return _utf8_text(value)
    if _isa(value, (bytes, bytearray)):
        try:
            # The try is for a lying ``__class__`` (claims bytes, is not):
            # the unbound decode TypeErrors and the impostor drops.
            return _decode_bytes(value)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
    if _isa(value, dict):
        out = {}
        # Unbound base view: a dict subclass whose ``items()`` raises or
        # yields non-pairs used to 500 the status/services routes.  The
        # try is for a lying-``__class__`` dict impostor, which TypeErrors
        # the unbound view itself.
        try:
            entries = dict.items(value)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return None
        for k, v in entries:
            if _isa(k, (bytes, bytearray)):
                try:
                    k = _decode_bytes(k)
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    continue
            elif not _isa(k, str):
                try:
                    k = str(k)
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    continue
            out[_utf8_text(k)] = _jsonable(v, depth + 1)
        return out
    if _isa(value, (list, tuple, set, frozenset)):
        for base in (list, tuple, set, frozenset):
            if _isa(value, base):
                # Unbound base iteration: a subclass ``__iter__`` bomb
                # cannot 500 and the real elements still survive.  The try
                # is for a lying-``__class__`` impostor, which TypeErrors.
                try:
                    items = base.__iter__(value)
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    return None
                return [_jsonable(v, depth + 1) for v in items]
        return None
    try:
        iso = getattr(value, "isoformat", None)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # getattr's default only swallows AttributeError; a property or
        # ``__getattr__`` bomb still raised out of the probe itself.
        iso = None
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 the encoder.
            return _jsonable(iso(), depth + 1)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            pass
    try:
        return _utf8_text(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None


def _status_quick_links() -> list:
    # _cfg_value, not a bare ``cfg().get``: only the read itself sat in the
    # try, so a ``quick_links`` value whose ``__class__`` is a raising
    # property detonated the isinstance gate below and 500'd a cold
    # GET /api/status.
    raw = _cfg_value("quick_links")
    if not _isa(raw, list):
        return []
    # YAML anchors can make a cyclic mapping. resolve_value is depth-capped
    # so this no longer RecursionError's; still absorb any leftover raise.
    try:
        links = resolve_value(raw)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return []
    return links if _isa(links, list) else []


#: Separate from `_refresh_lock`: the adaptive scans and the status build are
#: independent refreshes, and sharing one lock would make each wait on the other.
_adaptive_refresh_lock = threading.Lock()
_pool = LazyPool(6, "hub-status")


def shutdown_executor() -> None:
    _pool.shutdown()


def peek_status() -> dict | None:
    """Last built status snapshot, or None. Does not trigger discovery.

    Re-sanitizes: a leftover inf / bytes / ``\\ud800`` planted in the cache
    used to 500 GET /api/status and the menubar's peek poll at encode time.
    """
    return cached_status()


def invalidate_status():
    """Bust status cache (and short-lived discovery caches)."""
    global _status_generation
    with _lock:
        _status_generation += 1
        # `v` is kept: /api/health serves it through cached_status() without
        # triggering a build, and a liveness probe must not start returning
        # "no snapshot" because a container was restarted.
        try:
            _status_cache["t"] = 0
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # A hash-shadowing key planted over ``t`` raises out of the
            # C-level insert compare; clear() never compares keys, so evict
            # the poison while keeping the snapshot /api/health serves.
            _cache_publish(_status_cache, t=0, v=_mapping_get(_status_cache, "v"))
    # Related discovery caches so next full_status sees fresh data
    try:
        from hub.discovery.containers import invalidate_containers

        invalidate_containers()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        pass
    try:
        from hub.containers_svc import invalidate_container_lists

        invalidate_container_lists()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        pass
    try:
        from hub import vms_svc

        vms_svc.invalidate_vm_lists()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        pass
    try:
        from hub.adaptive import invalidate_lsof_snapshot

        # Port detection and the orphan-listener scan both read one cached
        # `lsof` snapshot.  A start/stop changes exactly what that snapshot
        # reports, so it has to go with the rest of them or the next refresh
        # reports ports from before the action.
        invalidate_lsof_snapshot()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        pass
    with _lock:
        # `_status_generation` was bumped above, under this same lock, and it
        # covers this cache too -- so a scan already running is dropped rather
        # than allowed to restore the pre-action project list for a minute.
        try:
            _adaptive_cache["t"] = 0
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # Same shadow-key insert-compare class as the status cache above.
            _cache_publish(_adaptive_cache, t=0.0, compose=None, nginx=None)


def _adaptive_info() -> dict:
    now = time.time()
    # _mapping_get / _cache_age throughout: a hash-shadowing key planted
    # over ``compose`` / ``t`` / ``nginx``, or a clock bomb in the ``t``
    # slot, used to detonate these bare subscripts and raise out of a cold
    # ``_build_status`` — a raw 500 on cold GET /api/status.
    with _lock:
        compose_hit = _mapping_get(_adaptive_cache, "compose")
        if (
            compose_hit is not None
            and _cache_age(now, _mapping_get(_adaptive_cache, "t")) < _ADAPTIVE_TTL
        ):
            return {
                "compose_projects": compose_hit,
                "nginx_sites": _mapping_get(_adaptive_cache, "nginx"),
            }
    # Single-flight, matching `full_status` below.  /api/status is the most polled
    # endpoint in the panel, so on a cold cache several requests arrive together, all
    # miss, and each walks the compose tree and the nginx sites directory -- the two
    # scans this cache exists to avoid.
    with _adaptive_refresh_lock:
        with _lock:
            compose_hit = _mapping_get(_adaptive_cache, "compose")
            if (
                compose_hit is not None
                and _cache_age(time.time(), _mapping_get(_adaptive_cache, "t")) < _ADAPTIVE_TTL
            ):
                return {
                    "compose_projects": compose_hit,
                    "nginx_sites": _mapping_get(_adaptive_cache, "nginx"),
                }
            began = _status_generation
        # Two unrelated filesystem scans (compose project tree, nginx sites dir).
        f_compose = _pool.submit(scan_new_compose_projects)
        f_nginx = _pool.submit(nginx_sites)
        try:
            compose = f_compose.result()
        except _CONTROL_FLOW:
            raise
        except BaseException:
            compose = []
        try:
            nginx = f_nginx.result()
        except _CONTROL_FLOW:
            raise
        except BaseException:
            nginx = []
        with _lock:
            if _status_generation == began:
                # _cache_publish: a shadow key planted in the cache used to
                # raise out of the insert compare after a successful scan.
                _cache_publish(_adaptive_cache, t=time.time(), compose=compose, nginx=nginx)
        return {"compose_projects": compose, "nginx_sites": nginx}


def _future_result(fut, fallback):
    """``.result()`` re-raises; one collector must not 500 /api/status."""
    try:
        return fut.result()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return fallback


def _rows(value) -> list:
    # _isa: a collector answering a ``__class__``-property bomb used to
    # detonate this gate and 500 a cold GET /api/status.
    if type(value) is list:
        return value
    if not _isa(value, list):
        return []
    # Copy through the unbound base iterator: a collector answering a
    # *lying* ``__class__`` list impostor used to pass the gate above and
    # TypeError the ``+`` concatenation in ``_build_status``; a real list
    # subclass with an ``__add__``/``__radd__``/``__iter__`` bomb detonated
    # the same seam.  Either way the C-level call reads the real storage
    # (subclass rows survive) and a liar drops here, not on the route.
    try:
        return list(list.__iter__(value))
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return []


def _container_pair(value):
    """``discover_containers`` is ``(items, engine_up)``; a bare list used to unpack-500."""
    try:
        if _isa(value, (tuple, list)) and len(value) == 2:
            items, up = value
            # Guarded truthiness: an ``up`` flag whose ``__bool__`` raises
            # is junk and reads as engine-down, not as a 500.
            try:
                up = bool(up)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                up = False
            return _rows(items), up
    except _CONTROL_FLOW:
        raise
    except BaseException:
        pass
    return [], False


def _remember_port(ports: set, value) -> None:
    # yaml ``port: 1e999`` is inf; ``int(inf)`` OverflowError is not ValueError.
    try:
        ports.add(int(value))
    except (TypeError, ValueError, OverflowError):
        pass


def _build_status() -> dict:
    raw_settings = _cfg_value("settings")
    if _isa(raw_settings, dict):
        # Plain-dict copy (C-level storage): a leftover ``settings`` map that
        # is a dict subclass whose ``.get`` raises passed the isinstance gate
        # and 500'd the very first read of a cold build.
        try:
            raw_settings = dict(raw_settings)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            raw_settings = {}
    else:
        raw_settings = {}
    # _mapping_get, not the bound ``.get``: the plain-dict copy above keeps
    # a leftover hash-shadowing key (str subclass, same hash as
    # ``adaptive``, raising ``__eq__``), and the C-level probe then ran the
    # stored bomb's compare — a raw 500 on the very first read of a cold
    # GET /api/status.  The shadowed flag degrades to its default alone.
    adaptive_on = _mapping_get(raw_settings, "adaptive", True)
    # Guarded truthiness: a leftover ``adaptive`` value whose ``__bool__``
    # raises must not 500 the cold build; junk reads as "off" (the
    # jobs._truthy fail-closed rule).
    try:
        adaptive_on = bool(adaptive_on)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        adaptive_on = False
    f_l = _pool.submit(discover_launchd)
    f_d = _pool.submit(discover_containers)
    f_v = _pool.submit(discover_vms)
    f_s = _pool.submit(collect_system)
    f_sc = _pool.submit(collect_scripts)
    launchd = _rows(_future_result(f_l, []))
    containers, engine_up = _container_pair(_future_result(f_d, ([], False)))
    vms = _rows(_future_result(f_v, []))
    system = _future_result(f_s, {})
    system = system if isinstance(system, dict) else {}
    scripts = _rows(_future_result(f_sc, []))
    try:
        apps = collect_apps(engine_up)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        apps = []
    services = _rows(apps) + scripts + launchd + containers + vms
    # Scrub each collector row up front, not only in the final payload
    # sweep: one poisoned row (a dict-subclass ``.get``/``items`` bomb, an
    # iterbomb ports list, a ``__str__``-bomb int port, a hash-bomb str id
    # hitting the known-names set, a ``__bool__``-bomb port, an ``__eq__``
    # bomb state in the problems filter) used to raise out of the scans
    # below and 500 a cold GET /api/status and GET /api/services.  The
    # hardened ``_jsonable`` reads through unbound base-type calls, so the
    # bomb costs only its own junk fields and the row's real data survives.
    services = [_jsonable(s) for s in services]

    # Adaptive: orphan listeners not covered by known services
    if adaptive_on:
        known_ports = set()
        known_names = set()
        for s in services:
            if not isinstance(s, dict):
                continue
            sid, sname = s.get("id"), s.get("name")
            if isinstance(sid, str):
                known_names.add(sid)
            if isinstance(sname, str):
                known_names.add(sname)
            if s.get("port"):
                _remember_port(known_ports, s["port"])
            meta = s.get("meta") if isinstance(s.get("meta"), dict) else {}
            for p in meta.get("detected_ports") if isinstance(meta.get("detected_ports"), list) else []:
                _remember_port(known_ports, p)
            detail = s.get("detail")
            if isinstance(detail, str):
                for m in re.finditer(r":(\d{2,5})\b", detail):
                    known_ports.add(int(m.group(1)))
        # Collectors are isolated above; this scan sat outside that and
        # 500'd a cold /api/status when lsof raised.
        try:
            orphans = discover_orphan_listeners(known_ports, known_names)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            orphans = []
        # _rows, not a bare ``isinstance`` + ``list.__iter__``: a scan
        # answering a ``__class__``-property bomb detonated the isinstance
        # itself, and a lying-``__class__`` list impostor passed it and
        # TypeError'd the unbound iterator — each a raw 500 on a cold
        # GET /api/status, one line past the try that guards the call.
        # Same per-row scrub as the collector rows above; ``list.extend``
        # of a list subclass falls back to its (bombable) ``__iter__``,
        # which _rows has already neutralized.
        services.extend(_jsonable(o) for o in _rows(orphans))

    # Defensive counts: always include core keys; unknown states get their own bucket.
    groups, counts = {}, {"ok": 0, "warn": 0, "down": 0, "stopped": 0, "unknown": 0}
    for s in services:
        if not isinstance(s, dict):
            continue
        group = s.get("group")
        group = group if isinstance(group, str) and group else "Other"
        groups.setdefault(group, []).append(s)
        st = s.get("state")
        if not isinstance(st, str) or not st:
            st = "unknown"
        if st not in counts:
            counts[st] = 0
        counts[st] += 1
    raw_order = _cfg_value("groups_order")
    # Names via the str() probe.  ``_as_config`` leaves this list unfiltered
    # (it is not a list of mappings); a nested dict used to TypeError on
    # ``g in groups``, and the old ``isinstance(g, str)`` gate silently lost
    # a numeric YAML group name's configured position.  _isa + unbound
    # iteration: a ``__class__``-property bomb (or a lying-``__class__``
    # list impostor) as the order value must not 500 the cold build.
    if _isa(raw_order, list):
        try:
            raw_names = list.__iter__(raw_order)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            raw_names = ()
        order = [name for name in (_name_text(g) for g in raw_names) if name]
    else:
        order = []
    # ensure adaptive groups appear near end unless ordered
    for extra in ("Gateway", "Auto-discovered", "Homebrew Services"):
        if extra not in order:
            order.append(extra)
    ordered = [{"group": g, "services": groups.pop(g)} for g in order if g in groups]
    ordered += [{"group": g, "services": v} for g, v in groups.items()]
    # 主动停止(stopped)不进告警列表；warn/down 才算需要关注
    problems = [
        s for s in services
        if isinstance(s, dict) and s.get("state") not in ("ok", "stopped")
    ]

    adaptive_info = {}
    if adaptive_on:
        extra = _adaptive_info()
        adaptive_info = {
            "orphan_count": sum(
                1 for s in services if isinstance(s, dict) and s.get("kind") == "auto"
            ),
            "auto_labeled": sum(
                1 for s in services if isinstance(s, dict) and s.get("auto")
            ),
            "compose_projects": extra["compose_projects"],
            "nginx_sites": extra["nginx_sites"],
        }

    try:
        from hub.tools_svc import github_update_status
        panel_update = github_update_status(fetch=False, checkout=False)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        panel_update = {}
    if not isinstance(panel_update, dict):
        panel_update = {}

    return _jsonable({
        "version": __version__,
        "ts": strftime_now("%H:%M:%S"),
        "groups": ordered,
        "system": system,
        "counts": counts,
        "links": _status_quick_links(),
        "engine_up": engine_up,
        "problems": problems[:30],
        "service_total": len(services),
        "adaptive": adaptive_info,
        "resource_mode": resource_mode(),
        "locale": panel_locale(),
        "panel_update": panel_update,
    })


_MEMBER_SERVICE_FIELDS = {
    "id", "name", "kind", "state", "detail", "url", "group", "port", "ports",
}


def member_service_summary(service: dict) -> dict:
    """Copy only fields a family member needs to identify and open a service."""
    if not isinstance(service, dict):
        return {"actions": []}
    summary = {
        key: value
        for key, value in service.items()
        if key in _MEMBER_SERVICE_FIELDS
    }
    raw_actions = service.get("actions")
    # ``set(actions)`` TypeError'd a nested mapping and 500'd member /api/status.
    actions = {
        action for action in raw_actions if isinstance(action, str)
    } if isinstance(raw_actions, list) else set()
    summary["actions"] = [action for action in ("open", "detail") if action in actions]
    return summary


def filter_status_for_resources(status: dict, resources: list[str]) -> dict:
    """Return a member-safe status snapshot containing only assigned services.

    The full status object is cached and shared with administrators, so this
    function always builds new group/service lists instead of mutating it.
    Host metrics, global quick links, and adaptive discovery metadata are
    administrator data and are deliberately omitted from member responses.
    """
    # _isa on the two entry gates: a ``__class__``-property bomb passed as
    # the snapshot or the resource list must not 500 the member route.
    if not _isa(status, dict):
        status = {}
    if not _isa(resources, (list, tuple, set, frozenset)):
        resources = []
    # _name_text, not bare str(): an over-cap hex-YAML resource id raised the
    # digit-cap ValueError here and 500'd the member GET /api/status; a
    # numeric YAML id still coerces and matches its row.
    allowed = {
        text for text in (_name_text(resource) for resource in resources)
        if text.strip()
    }
    groups: list[dict] = []
    services: list[dict] = []
    groups_raw = status.get("groups")
    if not isinstance(groups_raw, list):
        groups_raw = []
    for group in groups_raw:
        if not isinstance(group, dict):
            continue
        raw_svcs = group.get("services")
        if not isinstance(raw_svcs, list):
            raw_svcs = []
        visible = [
            member_service_summary(service)
            for service in raw_svcs
            if isinstance(service, dict)
            and _name_text(service.get("id") or "") in allowed
        ]
        if visible:
            groups.append({"group": group.get("group"), "services": visible})
            services.extend(visible)

    counts = {"ok": 0, "warn": 0, "down": 0, "stopped": 0, "unknown": 0}
    for service in services:
        # _name_text: a planted over-cap int state used to ValueError here.
        state = _name_text(service.get("state") or "unknown") or "unknown"
        counts[state] = counts.get(state, 0) + 1

    return _jsonable({
        "version": status.get("version"),
        "ts": status.get("ts"),
        "groups": groups,
        "system": {},
        "counts": counts,
        "links": [],
        "engine_up": status.get("engine_up"),
        "problems": [
            service
            for service in services
            if service.get("state") not in ("ok", "stopped")
        ][:30],
        "service_total": len(services),
        "adaptive": {},
        "resource_mode": status.get("resource_mode") or "low",
        "locale": status.get("locale") or panel_locale(),
    })


def cached_status() -> dict | None:
    """Last built status snapshot, or None if none has been built yet.

    Does not trigger discovery. ``/api/health`` uses this so a liveness probe
    cannot become a 5-way host scan.

    Re-sanitizes: a leftover inf / ``\\ud800`` planted in the cache used to
    500 GET /api/health (``st.get("counts")`` AttributeError'd a scalar
    leftover; leftover inf ``engine_up`` / ``\\ud800`` count keys 500'd
    the encoder).
    """
    with _lock:
        # _mapping_get: a hash-shadowing key planted over ``v`` used to
        # detonate this bare subscript and 500 GET /api/health — the one
        # cache poisoning the _jsonable re-sanitize below could never reach.
        hit = _mapping_get(_status_cache, "v")
    if hit is None:
        return None
    cleaned = _jsonable(hit)
    return cleaned if isinstance(cleaned, dict) else None


def full_status(force=False):
    """Return aggregated status. Cached for _STATUS_TTL; single-flight refresh.

    _mapping_get / _cache_age on every cache touch: a leftover
    hash-shadowing key planted over ``v`` / ``t`` used to detonate the bare
    subscripts here (the C-level probe runs the stored bomb's ``__eq__``),
    and a clock bomb in the ``t`` slot blew the bare age arithmetic — each
    a raw 500 on every GET /api/status, cache hit and cold build alike.
    An unreadable cache reads as a miss and rebuilds; the final write
    falls back to clear+rewrite, which never compares keys.
    """
    now = time.time()
    with _lock:
        hit = _mapping_get(_status_cache, "v")
        if not force and hit is not None and _cache_age(now, _mapping_get(_status_cache, "t")) < _status_ttl():
            return _stamp_locale(hit)

    with _refresh_lock:
        # Double-check after acquiring single-flight lock
        now = time.time()
        with _lock:
            hit = _mapping_get(_status_cache, "v")
            if not force and hit is not None and _cache_age(now, _mapping_get(_status_cache, "t")) < _status_ttl():
                return _stamp_locale(hit)
            began = _status_generation
        try:
            v = _build_status()
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # On failure, serve last good snapshot if available
            with _lock:
                hit = _mapping_get(_status_cache, "v")
            if hit is not None:
                return _stamp_locale(hit)
            raise
        with _lock:
            if _status_generation == began:
                _cache_publish(_status_cache, t=time.time(), v=v)
        # Returned either way: this caller asked before the invalidate landed.
        return _stamp_locale(v)


def _stamp_locale(status: dict) -> dict:
    """Keep ``locale`` current even when the discovery snapshot is cached.

    Changing the panel language must not wait for the 35s status TTL: the
    menu-bar client polls /api/status and rebuilds when this field moves.
    Re-sanitizes so a leftover ``\\ud800`` planted in the peek cache cannot
    500 the encoder on a cache hit.
    """
    # _isa: a leftover planted as the whole cached snapshot whose
    # ``__class__`` is a raising property used to detonate this gate itself
    # and 500 every cache-hit GET /api/status before any scrub ran.
    if not _isa(status, dict):
        return _jsonable(status)
    if type(status) is not dict:
        # Plain-dict copy first (C-level storage): a leftover cached snapshot
        # that is a dict *subclass* whose ``.get``/``__setitem__`` raises used
        # to 500 every cache-hit ``full_status`` — GET /api/status and
        # POST /api/alerts/check alike — before ``_jsonable``'s unbound walk
        # ever ran.  A subclass whose copy itself raises is junk: degrade to
        # the empty snapshot rather than the route.
        try:
            status = dict(status)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return _jsonable({})
    try:
        loc = panel_locale()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        loc = _mapping_get(status, "locale")
        if type(loc) is not str or not loc:
            loc = "zh-CN"
    if type(loc) is not str:
        # A patched/odd panel_locale can answer a str-subclass whose
        # reflected ``__ne__`` bomb detonated the compare below; launder
        # to an exact str so neither the compare nor the write can ask it.
        loc = _utf8_text(loc) or "zh-CN"
    # _mapping_get, not the bound ``.get``: a leftover hash-shadowing
    # ``locale`` key planted in the cached snapshot ran the stored bomb's
    # ``__eq__`` inside the C-level probe — a raw 500 on every cache-hit
    # GET /api/status, one seam ahead of every scrub.
    current = _mapping_get(status, "locale")
    # Type-gated compare: a leftover planted in the cache whose ``__ne__``
    # raises must restamp and scrub, not 500 the cache-hit path.
    if type(current) is not str or current != loc:
        try:
            status["locale"] = loc
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # The same shadow key raises out of the insert compare too.
            # Stamp the laundered copy instead: _jsonable rebuilds with
            # exact-str keys, so this write always lands.
            cleaned = _jsonable(status)
            if _isa(cleaned, dict):
                cleaned["locale"] = loc
            return cleaned
    return _jsonable(status)
