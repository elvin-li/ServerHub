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


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    try:
        text = str(value)
    except RecursionError:
        try:
            return type(value).__name__
        except Exception:
            return ""
    except Exception:
        return ""
    return text.encode("utf-8", "replace").decode("utf-8")


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's allow_nan=False encoder cannot 500.

    ``int(inf)`` on a yaml ``1e999`` port was already isolated; the service
    row still carried ``port: inf`` / ``ports: [inf]`` and YAML timestamps
    in ``quick_links`` are ``datetime`` objects — both 500 GET /api/status.
    A leftover ``\\ud800`` in a name or key still 500'd the same encoder
    (``ensure_ascii=False`` then UTF-8) on GET /api/status and status peek.
    A >4300-digit int (a services.yaml/plist hex leftover — ``0xfff…`` dodges
    the int(str) parse cap) still passed through untouched: CPython's
    int->str digit limit then ValueError'd ``json.dumps`` itself, 500ing
    GET /api/status, GET /api/services and GET /api/services/{id}/detail.
    """
    if depth > 32:
        return None
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        try:
            str(value)
        except ValueError:
            # Past the digit cap the encoder cannot render the number at
            # all — same drop as its inf float sibling (docker_cli rule).
            return None
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if isinstance(value, str):
        return _utf8_text(value)
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if not isinstance(k, (str, bytes, bytearray)):
                try:
                    k = str(k)
                except Exception:
                    continue
            out[_utf8_text(k)] = _jsonable(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v, depth + 1) for v in value]
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 the encoder.
            return _jsonable(iso(), depth + 1)
        except Exception:
            pass
    try:
        return _utf8_text(value)
    except Exception:
        return None


def _status_quick_links() -> list:
    try:
        raw = cfg().get("quick_links")
    except Exception:
        return []
    if not isinstance(raw, list):
        return []
    # YAML anchors can make a cyclic mapping. resolve_value is depth-capped
    # so this no longer RecursionError's; still absorb any leftover raise.
    try:
        links = resolve_value(raw)
    except Exception:
        return []
    return links if isinstance(links, list) else []


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
        _status_cache["t"] = 0
    # Related discovery caches so next full_status sees fresh data
    try:
        from hub.discovery.containers import invalidate_containers

        invalidate_containers()
    except Exception:
        pass
    try:
        from hub.containers_svc import invalidate_container_lists

        invalidate_container_lists()
    except Exception:
        pass
    try:
        from hub import vms_svc

        vms_svc.invalidate_vm_lists()
    except Exception:
        pass
    try:
        from hub.adaptive import invalidate_lsof_snapshot

        # Port detection and the orphan-listener scan both read one cached
        # `lsof` snapshot.  A start/stop changes exactly what that snapshot
        # reports, so it has to go with the rest of them or the next refresh
        # reports ports from before the action.
        invalidate_lsof_snapshot()
    except Exception:
        pass
    with _lock:
        # `_status_generation` was bumped above, under this same lock, and it
        # covers this cache too -- so a scan already running is dropped rather
        # than allowed to restore the pre-action project list for a minute.
        _adaptive_cache["t"] = 0


def _adaptive_info() -> dict:
    now = time.time()
    with _lock:
        if (
            _adaptive_cache["compose"] is not None
            and now - _adaptive_cache["t"] < _ADAPTIVE_TTL
        ):
            return {
                "compose_projects": _adaptive_cache["compose"],
                "nginx_sites": _adaptive_cache["nginx"],
            }
    # Single-flight, matching `full_status` below.  /api/status is the most polled
    # endpoint in the panel, so on a cold cache several requests arrive together, all
    # miss, and each walks the compose tree and the nginx sites directory -- the two
    # scans this cache exists to avoid.
    with _adaptive_refresh_lock:
        with _lock:
            if (
                _adaptive_cache["compose"] is not None
                and time.time() - _adaptive_cache["t"] < _ADAPTIVE_TTL
            ):
                return {
                    "compose_projects": _adaptive_cache["compose"],
                    "nginx_sites": _adaptive_cache["nginx"],
                }
            began = _status_generation
        # Two unrelated filesystem scans (compose project tree, nginx sites dir).
        f_compose = _pool.submit(scan_new_compose_projects)
        f_nginx = _pool.submit(nginx_sites)
        try:
            compose = f_compose.result()
        except Exception:
            compose = []
        try:
            nginx = f_nginx.result()
        except Exception:
            nginx = []
        with _lock:
            if _status_generation == began:
                _adaptive_cache.update(t=time.time(), compose=compose, nginx=nginx)
        return {"compose_projects": compose, "nginx_sites": nginx}


def _future_result(fut, fallback):
    """``.result()`` re-raises; one collector must not 500 /api/status."""
    try:
        return fut.result()
    except Exception:
        return fallback


def _rows(value) -> list:
    return value if isinstance(value, list) else []


def _container_pair(value):
    """``discover_containers`` is ``(items, engine_up)``; a bare list used to unpack-500."""
    if isinstance(value, (tuple, list)) and len(value) == 2:
        items, up = value
        return _rows(items), bool(up)
    return [], False


def _remember_port(ports: set, value) -> None:
    # yaml ``port: 1e999`` is inf; ``int(inf)`` OverflowError is not ValueError.
    try:
        ports.add(int(value))
    except (TypeError, ValueError, OverflowError):
        pass


def _build_status() -> dict:
    raw_settings = cfg().get("settings")
    adaptive_on = (raw_settings if isinstance(raw_settings, dict) else {}).get("adaptive", True)
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
    except Exception:
        apps = []
    services = _rows(apps) + scripts + launchd + containers + vms

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
        except Exception:
            orphans = []
        if isinstance(orphans, list):
            services.extend(orphans)

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
    raw_order = cfg().get("groups_order")
    # Names only.  ``_as_config`` leaves this list unfiltered (it is not a
    # list of mappings); a nested dict used to TypeError on ``g in groups``.
    order = [g for g in raw_order if isinstance(g, str)] if isinstance(raw_order, list) else []
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
    except Exception:
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
    if not isinstance(status, dict):
        status = {}
    if not isinstance(resources, (list, tuple, set, frozenset)):
        resources = []
    allowed = {str(resource) for resource in resources if str(resource).strip()}
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
            if isinstance(service, dict) and str(service.get("id") or "") in allowed
        ]
        if visible:
            groups.append({"group": group.get("group"), "services": visible})
            services.extend(visible)

    counts = {"ok": 0, "warn": 0, "down": 0, "stopped": 0, "unknown": 0}
    for service in services:
        state = str(service.get("state") or "unknown")
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
        hit = _status_cache["v"]
    if hit is None:
        return None
    cleaned = _jsonable(hit)
    return cleaned if isinstance(cleaned, dict) else None


def full_status(force=False):
    """Return aggregated status. Cached for _STATUS_TTL; single-flight refresh."""
    now = time.time()
    with _lock:
        if not force and _status_cache["v"] is not None and now - _status_cache["t"] < _status_ttl():
            return _stamp_locale(_status_cache["v"])

    with _refresh_lock:
        # Double-check after acquiring single-flight lock
        now = time.time()
        with _lock:
            if not force and _status_cache["v"] is not None and now - _status_cache["t"] < _status_ttl():
                return _stamp_locale(_status_cache["v"])
            began = _status_generation
        try:
            v = _build_status()
        except Exception:
            # On failure, serve last good snapshot if available
            with _lock:
                if _status_cache["v"] is not None:
                    return _stamp_locale(_status_cache["v"])
            raise
        with _lock:
            if _status_generation == began:
                _status_cache.update(t=time.time(), v=v)
        # Returned either way: this caller asked before the invalidate landed.
        return _stamp_locale(v)


def _stamp_locale(status: dict) -> dict:
    """Keep ``locale`` current even when the discovery snapshot is cached.

    Changing the panel language must not wait for the 35s status TTL: the
    menu-bar client polls /api/status and rebuilds when this field moves.
    Re-sanitizes so a leftover ``\\ud800`` planted in the peek cache cannot
    500 the encoder on a cache hit.
    """
    if not isinstance(status, dict):
        return _jsonable(status)
    try:
        loc = panel_locale()
    except Exception:
        loc = status.get("locale") or "zh-CN"
    if status.get("locale") != loc:
        status["locale"] = loc
    return _jsonable(status)
