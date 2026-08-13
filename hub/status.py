"""Aggregate service status with short TTL cache + adaptive discovery."""
from __future__ import annotations

import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from hub import __version__
from hub.adaptive import discover_orphan_listeners, nginx_sites, scan_new_compose_projects
from hub.config import cfg
from hub.host_address import resolve_value
from hub.discovery import (
    collect_apps,
    collect_scripts,
    discover_containers,
    discover_launchd,
    discover_vms,
)
from hub.system import collect_system

# Hot path: 20s TTL + single-flight. The shell polls /api/status every 15s,
# so a 10s TTL missed on almost every tick and re-ran docker+launchctl+lsof.
_STATUS_TTL = 20.0
_status_cache = {"t": 0.0, "v": None}
_lock = threading.Lock()
# Single-flight: only one full refresh at a time; waiters reuse the result.
_refresh_lock = threading.Lock()
# Adaptive filesystem scans change rarely — cache longer.
_adaptive_cache = {"t": 0.0, "compose": None, "nginx": None}
_ADAPTIVE_TTL = 60.0
#: Separate from `_refresh_lock`: the adaptive scans and the status build are
#: independent refreshes, and sharing one lock would make each wait on the other.
_adaptive_refresh_lock = threading.Lock()


def invalidate_status():
    """Bust status cache (and short-lived discovery caches)."""
    with _lock:
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
        # Two unrelated filesystem scans (compose project tree, nginx sites dir).
        with ThreadPoolExecutor(max_workers=2) as ex:
            f_compose = ex.submit(scan_new_compose_projects)
            f_nginx = ex.submit(nginx_sites)
            compose = f_compose.result()
            nginx = f_nginx.result()
        with _lock:
            _adaptive_cache.update(t=time.time(), compose=compose, nginx=nginx)
        return {"compose_projects": compose, "nginx_sites": nginx}


def _build_status() -> dict:
    adaptive_on = (cfg().get("settings") or {}).get("adaptive", True)
    with ThreadPoolExecutor(max_workers=5) as ex:
        f_l = ex.submit(discover_launchd)
        f_d = ex.submit(discover_containers)
        f_v = ex.submit(discover_vms)
        f_s = ex.submit(collect_system)
        f_sc = ex.submit(collect_scripts)
        launchd = f_l.result()
        containers, engine_up = f_d.result()
        vms = f_v.result()
        system = f_s.result()
        scripts = f_sc.result()
    services = collect_apps(engine_up) + scripts + launchd + containers + vms

    # Adaptive: orphan listeners not covered by known services
    if adaptive_on:
        known_ports = set()
        known_names = set()
        for s in services:
            known_names.add(s.get("id") or "")
            known_names.add(s.get("name") or "")
            if s.get("port"):
                try:
                    known_ports.add(int(s["port"]))
                except (TypeError, ValueError):
                    pass
            for p in (s.get("meta") or {}).get("detected_ports") or []:
                try:
                    known_ports.add(int(p))
                except (TypeError, ValueError):
                    pass
            for m in re.finditer(r":(\d{2,5})\b", s.get("detail") or ""):
                known_ports.add(int(m.group(1)))
        orphans = discover_orphan_listeners(known_ports, known_names)
        services.extend(orphans)

    # Defensive counts: always include core keys; unknown states get their own bucket.
    groups, counts = {}, {"ok": 0, "warn": 0, "down": 0, "stopped": 0, "unknown": 0}
    for s in services:
        groups.setdefault(s.get("group") or "Other", []).append(s)
        st = s.get("state") or "unknown"
        if st not in counts:
            counts[st] = 0
        counts[st] += 1
    order = list(cfg().get("groups_order") or [])
    # ensure adaptive groups appear near end unless ordered
    for extra in ("Gateway", "Auto-discovered", "Homebrew Services"):
        if extra not in order:
            order.append(extra)
    ordered = [{"group": g, "services": groups.pop(g)} for g in order if g in groups]
    ordered += [{"group": g, "services": v} for g, v in groups.items()]
    # 主动停止(stopped)不进告警列表；warn/down 才算需要关注
    problems = [s for s in services if s.get("state") not in ("ok", "stopped")]

    adaptive_info = {}
    if adaptive_on:
        extra = _adaptive_info()
        adaptive_info = {
            "orphan_count": sum(1 for s in services if s.get("kind") == "auto"),
            "auto_labeled": sum(1 for s in services if s.get("auto")),
            "compose_projects": extra["compose_projects"],
            "nginx_sites": extra["nginx_sites"],
        }

    return {
        "version": __version__,
        "ts": time.strftime("%H:%M:%S"),
        "groups": ordered,
        "system": system,
        "counts": counts,
        "links": resolve_value(cfg().get("quick_links") or []),
        "engine_up": engine_up,
        "problems": problems[:30],
        "service_total": len(services),
        "adaptive": adaptive_info,
    }


_MEMBER_SERVICE_FIELDS = {
    "id", "name", "kind", "state", "detail", "url", "group", "port", "ports",
}


def member_service_summary(service: dict) -> dict:
    """Copy only fields a family member needs to identify and open a service."""
    summary = {
        key: value
        for key, value in service.items()
        if key in _MEMBER_SERVICE_FIELDS
    }
    actions = set(service.get("actions") or [])
    summary["actions"] = [action for action in ("open", "detail") if action in actions]
    return summary


def filter_status_for_resources(status: dict, resources: list[str]) -> dict:
    """Return a member-safe status snapshot containing only assigned services.

    The full status object is cached and shared with administrators, so this
    function always builds new group/service lists instead of mutating it.
    Host metrics, global quick links, and adaptive discovery metadata are
    administrator data and are deliberately omitted from member responses.
    """
    allowed = {str(resource) for resource in resources if str(resource).strip()}
    groups: list[dict] = []
    services: list[dict] = []
    for group in status.get("groups") or []:
        visible = [
            member_service_summary(service)
            for service in (group.get("services") or [])
            if str(service.get("id") or "") in allowed
        ]
        if visible:
            groups.append({"group": group.get("group"), "services": visible})
            services.extend(visible)

    counts = {"ok": 0, "warn": 0, "down": 0, "stopped": 0, "unknown": 0}
    for service in services:
        state = str(service.get("state") or "unknown")
        counts[state] = counts.get(state, 0) + 1

    return {
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
    }


def full_status(force=False):
    """Return aggregated status. Cached for _STATUS_TTL; single-flight refresh."""
    now = time.time()
    with _lock:
        if not force and _status_cache["v"] is not None and now - _status_cache["t"] < _STATUS_TTL:
            return _status_cache["v"]

    with _refresh_lock:
        # Double-check after acquiring single-flight lock
        now = time.time()
        with _lock:
            if not force and _status_cache["v"] is not None and now - _status_cache["t"] < _STATUS_TTL:
                return _status_cache["v"]
        try:
            v = _build_status()
        except Exception:
            # On failure, serve last good snapshot if available
            with _lock:
                if _status_cache["v"] is not None:
                    return _status_cache["v"]
            raise
        with _lock:
            _status_cache.update(t=time.time(), v=v)
        return v
