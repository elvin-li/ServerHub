from __future__ import annotations

import platform
from typing import Optional
from urllib.parse import quote

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, Field

from hub import audit, auth, network_svc, system_settings_svc, tools_svc, vm_console, vms_svc
from hub.docker_cli import engine_up, peek_engine
from hub.errors import api_error
from hub.resource_mode import is_high
from hub.host_address import default_interface, host_ip, interface_address
from hub.paths import DOCKER, ORB
from hub.util import LazyPool, cached_snapshot, fan_out, sh


def _audit_host_change(event: str, request: Request | None, **fields) -> None:
    """One audit line for a host-level mutation.

    Called after the service call returned, so a rejected action that raised
    leaves no record.  FastAPI always injects `request`; the None guard only
    keeps direct in-process calls (tests, tooling) working.
    """
    audit.record(
        event,
        username=auth.request_username(request) if request is not None else "",
        client=auth.request_client_id(request),
        **fields,
    )


def _isa(value, kinds) -> bool:
    """``isinstance`` that a leftover ``__class__``-property bomb cannot 500.

    ``isinstance`` consults ``value.__class__`` when the exact-type check
    misses, so a leftover whose ``__class__`` is a *raising property* — an
    ``sh`` output from a patched/odd ``sh`` — used to detonate ``_as_text``'s
    bytes gate itself and 500 GET /api/system/host (the dash9 host_address
    rule).
    """
    try:
        return isinstance(value, kinds)
    except Exception:
        return False


def _rc_int(rc) -> int:
    """Exact exit status for the ``==``/``!=`` probes; a bomb reads as failure.

    This router does not own ``sh`` (tests and tooling patch it), and an
    rc-*subclass* whose ``__eq__``/``__ne__`` raises used to detonate the
    bare ``rc == 0`` / ``rc != 0`` probes in ``_host_snapshot`` / ``_mem_gb``
    / ``_ncpu_int`` — a raw 500 on GET /api/system/host (the health9 /
    dash9 host_address rule).  ``-255`` is no honest exit status, so a bomb
    keeps the failure branch.
    """
    try:
        if isinstance(rc, bool):
            return int(rc)
        if isinstance(rc, int):
            return int.__index__(rc)
        return int(rc)
    except Exception:
        return -255


def _truthy(value) -> bool:
    """``bool(value)`` that survives a leftover ``__bool__`` bomb (fails False)."""
    try:
        return bool(value)
    except Exception:
        return False


def _as_text(value) -> str:
    """``sh`` leftovers arrive as bytes/None; ``.isdigit`` / JSON need text."""
    decoded = None
    # _isa, not a bare isinstance: a ``__class__``-property bomb in sh
    # output used to detonate this gate one step ahead of the scrub.
    if _isa(value, (bytes, bytearray)):
        try:
            # Unbound base decode (the host_address._as_text rule): the old
            # bound ``value.decode`` dispatched into a bytes-subclass's own
            # override, so a leftover decode bomb raised out of the scrub
            # and 500'd GET /api/system/host.  The try is for a *lying*
            # ``__class__`` (claims bytes, is not): the unbound call
            # TypeErrors and the impostor renders like any junk object below.
            base = bytes if isinstance(value, bytes) else bytearray
            decoded = base.decode(value, "utf-8", "replace")
        except Exception:
            decoded = None
    if decoded is not None:
        value = decoded
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
    try:
        # Unbound str.encode: ``str()`` of a subclass whose ``__str__``
        # answers *self* keeps the subclass, so a bound ``encode`` bomb
        # used to ride this line to a raw 500.
        return str.encode(value, "utf-8", "replace").decode("utf-8")
    except Exception:
        return ""

#: Dashboard heavy tick is 90s in low mode. A 20s snapshot expired before
#: every sit tick, so each one re-ran engine_up (~800ms) plus the iface
#: sweep. 100s lets the 90s poll hit; Settings reopen and first paint still
#: share the same snapshot. Mutations that change engine/iface invalidate.
_HOST_TTL = 100.0

#: Dedicated width for /api/system/host.  The interface sweep itself fans
#: out on the shared probe pool; a shared-pool composer would nest.
_HOST_POOL = LazyPool(5, "system-host")


def shutdown_executor() -> None:
    _HOST_POOL.shutdown()

router = APIRouter(tags=["system"])


@router.get("/api/vms")
def vms():
    return vms_svc.list_all_vms()


class VmActionBody(BaseModel):
    action: str
    name: Optional[str] = None  # clone target name
    force: bool = True


class VmCreateBody(BaseModel):
    distro: str = Field(..., description="ubuntu, debian, ubuntu:24.04 …")
    name: Optional[str] = None
    arch: Optional[str] = None


@router.post("/api/vms/create")
def vm_create(body: VmCreateBody, request: Request = None):
    """Create OrbStack Linux machine (UTM create is GUI-only)."""
    result = vms_svc.create_orb_machine(body.distro, body.name, body.arch)
    _audit_host_change(audit.VM_CHANGED, request,
                       action="create", distro=body.distro, name=body.name or "")
    return result


@router.post("/api/vms/{vm_id}/action")
def vm_action(vm_id: str, body: VmActionBody, request: Request = None):
    # path may contain orb:name — FastAPI decodes
    result = vms_svc.vm_action(vm_id, body.action, name=body.name, force=body.force)
    _audit_host_change(audit.VM_CHANGED, request,
                       action=body.action, target=vm_id)
    return result


@router.post("/api/vms/{console_id}/console/session")
def vm_console_session(console_id: str, request: Request):
    """Mint a single-use console ticket for an allowlisted UTM VM.

    Stricter than the rest of the protected API on purpose: the loopback
    menu-bar token must not be able to open a raw framebuffer bridge, and the
    ticket is bound to the exact browser session that requested it.
    """
    if not auth.browser_authenticated(request):
        raise api_error("vm_console.browser_session_required")

    target = vm_console.resolve_target(console_id)
    if target is None:
        raise api_error("vm_console.unavailable")
    if not vms_svc.utm_vm_running(target.vm_uuid):
        raise api_error("vm_console.unavailable")

    session_token = request.cookies.get(auth.COOKIE_NAME) or ""
    user = auth.session_username(session_token)
    if not user:
        raise api_error("vm_console.browser_session_required")
    if not vm_console.allow_ticket_request(user):
        raise api_error("vm_console.too_many_sessions")

    issued = vm_console.issue_ticket(target, user=user, session_token=session_token)
    # A console ticket is a raw framebuffer into the guest — the record here
    # is the only trace, because the WebSocket upgrade it buys is not audited.
    _audit_host_change(audit.VM_CONSOLE_OPENED, request, target=console_id)
    return {
        # Relative path only: the browser derives ws:// or wss:// from its own
        # origin, so a redirected or proxied host cannot retarget the socket.
        "ws_url": (
            f"/api/vms/{quote(target.console_id, safe='')}"
            f"/console/ws?ticket={quote(issued['ticket'], safe='')}"
        ),
        "expires_in": issued["expires_in"],
        "view_only": issued["view_only"],
        "max_session_seconds": issued["max_session_seconds"],
    }


def _iface_addresses(route_iface: str) -> list[dict]:
    """Resolve the candidate interfaces' IPv4 addresses.

    The `ipconfig getifaddr` calls are independent of one another but must wait on
    default_interface(), which names the first candidate — hence the split: the
    caller overlaps this whole chain with the rest of the host probe.
    """
    candidates = [i for i in dict.fromkeys((route_iface, "en0", "en1", "bridge0", "utun0")) if i]
    # `interface_address` is memoised per interface, so the sweep still runs its
    # lookups concurrently while sharing the default interface's answer with
    # `host_ip()` below -- which asked the same question about the same interface and
    # paid for its own `ipconfig` doing it.
    addresses = fan_out(interface_address, candidates)
    return [
        {"iface": iface, "ip": address}
        for iface, address in zip(candidates, addresses)
        if address
    ]


def _mem_gb(rc, memsize):
    """``hw.memsize`` as GiB, or None.  A 400-digit leftover OverflowError'd ``/``."""
    try:
        # _rc_int: an rc-subclass ``__ne__`` bomb raised RuntimeError past
        # the typed catch below and 500'd GET /api/system/host.
        if _rc_int(rc) != 0 or not memsize.isdigit():
            return None
        gb = round(int(memsize) / 2**30, 1)
    except (TypeError, ValueError, OverflowError, AttributeError):
        return None
    if gb != gb or gb in (float("inf"), float("-inf")):
        return None
    return gb


def _ncpu_int(rc, ncpu):
    """``hw.ncpu`` as int, or None.

    ``isdigit()`` does not bound length: ``int()`` of a >4300-digit leftover
    is ValueError (CPython's str->int cap), which used to 500
    GET /api/system/host — one line below the already-guarded ``_mem_gb``.
    """
    try:
        # _rc_int: same rc-``__ne__`` bomb class as _mem_gb.
        if _rc_int(rc) != 0 or not ncpu.isdigit():
            return None
        return int(ncpu)
    except (TypeError, ValueError, OverflowError, AttributeError):
        return None


@cached_snapshot(_HOST_TTL)
def _host_snapshot() -> dict:
    # The dashboard re-reads this on every heavy tick and Settings on every open.
    # It was nine subprocess spawns in a row: hostname, a route lookup, up to five
    # sequential `ipconfig getifaddr` calls, and two sysctls. Only the interface
    # sweep depends on anything (it needs the default interface name first), so
    # everything else overlaps with it.
    def _ncpu_and_memsize():
        rc_n, ncpu, _ = sh(["/usr/sbin/sysctl", "-n", "hw.ncpu"], timeout=3)
        rc_m, memsize, _ = sh(["/usr/sbin/sysctl", "-n", "hw.memsize"], timeout=3)
        return rc_n, ncpu, rc_m, memsize

    f_hostname = _HOST_POOL.submit(sh, ["/bin/hostname"], timeout=3)
    f_model = _HOST_POOL.submit(sh, ["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"], timeout=3)
    f_hw = _HOST_POOL.submit(_ncpu_and_memsize)
    # Low mode: host identity does not need a live docker info (272–946ms
    # on this machine). Reuse the last probe; high mode still asks.
    f_engine = _HOST_POOL.submit(engine_up) if is_high() else None
    # route lookup → per-interface lookups, kept together in one branch.
    f_ifaces = _HOST_POOL.submit(lambda: _iface_addresses(default_interface()))

    def _result(fut, fallback):
        try:
            return fut.result()
        except Exception:
            return fallback

    # `.result()` re-raises; one sysctl/docker timeout must not 500 /api/system/host.
    rc, hostname, _ = _result(f_hostname, (1, "", ""))
    rc3, model, _ = _result(f_model, (1, "", ""))
    rc4, ncpu, rc_m, memsize = _result(f_hw, (1, "", 1, ""))
    hostname, model = _as_text(hostname), _as_text(model)
    ncpu, memsize = _as_text(ncpu), _as_text(memsize)
    # _truthy, not a bare ``bool``: a leftover ``__bool__`` bomb planted in
    # the engine cache used to detonate the eagerly-evaluated fallback (it
    # ran even when the probe future succeeded) and 500 GET /api/system/host.
    if f_engine is not None:
        engine = _result(f_engine, None)
        orbstack = _truthy(engine if engine is not None else peek_engine())
    else:
        orbstack = _truthy(peek_engine())
    ifaces = _result(f_ifaces, []) or []

    # Was called twice (once as `lan`, once inline); it is the same value both
    # times and both fields are documented to carry it.
    ip = host_ip()
    # _rc_int on the hostname/model probes: an rc-subclass ``__eq__`` bomb
    # from a patched/odd ``sh`` used to detonate these bare reads.
    return {
        "hostname": hostname if _rc_int(rc) == 0 else _as_text(platform.node()),
        "platform": _as_text(platform.platform()),
        "arch": _as_text(platform.machine()),
        "python": _as_text(platform.python_version()),
        "cpu": model if _rc_int(rc3) == 0 else "",
        "ncpu": _ncpu_int(rc4, ncpu),
        "mem_total_gb": _mem_gb(rc_m, memsize),
        "host_ip": ip,
        "lan_ip": ip,
        "interfaces": ifaces,
        "orbstack": orbstack,
        # shutil.which resolves these at import from a surrogateescape-decoded
        # PATH; a leftover lone surrogate served raw 500'd the UTF-8 encode.
        "docker_cli": _as_text(DOCKER),
        "orb_cli": _as_text(ORB),
    }


@router.get("/api/system/host")
def host_info(force: bool = False):
    return _host_snapshot(force)


@router.get("/api/system/network")
def system_network(force: bool = False):
    return network_svc.overview(force=force)


class NetManualBody(BaseModel):
    ip: str
    subnet: str
    router: str = ""


class NetDnsBody(BaseModel):
    servers: list[str] = []


@router.get("/api/system/network/services")
def network_services():
    # The listing wrapper, not the raw read: a vanished networksetup used
    # to answer 200 {"services": []} here — see network_services_listing.
    return {"services": network_svc.network_services_listing()}


@router.post("/api/system/network/services/{service_name}/dhcp")
def network_set_dhcp(service_name: str, request: Request = None):
    result = network_svc.set_service_dhcp(service_name)
    _audit_host_change(audit.NETWORK_CHANGED, request,
                       action="dhcp", service=service_name)
    return result


@router.post("/api/system/network/services/{service_name}/manual")
def network_set_manual(service_name: str, body: NetManualBody, request: Request = None):
    result = network_svc.set_service_manual(service_name, body.ip, body.subnet, body.router)
    _audit_host_change(audit.NETWORK_CHANGED, request,
                       action="manual", service=service_name, ip=body.ip)
    return result


@router.post("/api/system/network/services/{service_name}/dns")
def network_set_dns(service_name: str, body: NetDnsBody, request: Request = None):
    result = network_svc.set_service_dns(service_name, body.servers)
    _audit_host_change(audit.NETWORK_CHANGED, request,
                       action="dns", service=service_name,
                       servers=",".join(body.servers or []))
    return result


@router.post("/api/system/network/wifi/{state}")
def network_wifi(state: str, request: Request = None):
    if state not in ("on", "off"):
        raise api_error("network.bad_wifi_state")
    result = network_svc.set_wifi_power(state == "on")
    _audit_host_change(audit.NETWORK_CHANGED, request,
                       action="wifi_power", enabled=state == "on")
    return result


class NetEnableBody(BaseModel):
    enabled: bool = True


class NetOrderBody(BaseModel):
    services: list[str]


class NetProfileBody(BaseModel):
    profile: str  # wifi | ethernet | wifi_only | ethernet_only


class NetAliasBody(BaseModel):
    device: str
    ip: str
    netmask: str = "255.255.255.255"


@router.post("/api/system/network/services/{service_name}/enabled")
def network_service_enabled(service_name: str, body: NetEnableBody, request: Request = None):
    result = network_svc.set_service_enabled(service_name, body.enabled)
    _audit_host_change(audit.NETWORK_CHANGED, request,
                       action="service_enabled", service=service_name,
                       enabled=bool(body.enabled))
    return result


@router.post("/api/system/network/order")
def network_set_order(body: NetOrderBody, request: Request = None):
    result = network_svc.set_service_order(body.services)
    _audit_host_change(audit.NETWORK_CHANGED, request,
                       action="order", services=",".join(body.services or []))
    return result


@router.post("/api/system/network/profile")
def network_switch_profile(body: NetProfileBody, request: Request = None):
    """Quick switch between Wi‑Fi / wired preference."""
    result = network_svc.switch_profile(body.profile)
    _audit_host_change(audit.NETWORK_CHANGED, request,
                       action="profile", profile=body.profile)
    return result


@router.get("/api/system/network/addresses")
def network_addresses():
    return {"interfaces": network_svc.interface_addresses()}


@router.post("/api/system/network/alias/add")
def network_alias_add(body: NetAliasBody, request: Request = None):
    result = network_svc.add_ip_alias(body.device, body.ip, body.netmask)
    _audit_host_change(audit.NETWORK_CHANGED, request,
                       action="alias_add", device=body.device, ip=body.ip)
    return result


@router.post("/api/system/network/alias/remove")
def network_alias_remove(body: NetAliasBody, request: Request = None):
    result = network_svc.remove_ip_alias(body.device, body.ip)
    _audit_host_change(audit.NETWORK_CHANGED, request,
                       action="alias_remove", device=body.device, ip=body.ip)
    return result


class NetAliasAutoConfig(BaseModel):
    auto_bind: Optional[bool] = None
    ips: Optional[list[str]] = None
    netmask: Optional[str] = None
    interval: Optional[int] = None


@router.get("/api/system/network/alias/auto")
def network_alias_auto_status():
    """Managed IP aliases + preferred active NIC status."""
    return network_svc.alias_auto_status()


@router.post("/api/system/network/alias/auto/run")
def network_alias_auto_run(request: Request = None):
    """Immediately rebind managed aliases onto preferred active NIC."""
    result = network_svc.ensure_aliases_on_preferred(force=True)
    _audit_host_change(audit.NETWORK_CHANGED, request, action="alias_auto_run")
    return result


@router.put("/api/system/network/alias/auto")
def network_alias_auto_config(body: NetAliasAutoConfig, request: Request = None):
    """Update auto-bind settings (settings.ip_aliases)."""
    result = network_svc.update_alias_auto_config(
        auto_bind=body.auto_bind,
        ips=body.ips,
        netmask=body.netmask,
        interval=body.interval,
    )
    _audit_host_change(audit.NETWORK_CHANGED, request,
                       action="alias_auto_config",
                       ips=",".join(body.ips or []))
    return result


@router.get("/api/system/network/failover")
def network_failover_status():
    return network_svc.network_failover_status()


@router.post("/api/system/network/failover/run")
def network_failover_run(request: Request = None):
    """Probe wired connectivity and immediately enforce the failover policy."""
    result = network_svc.network_failover_tick(force=True)
    if result.get("action"):
        result["alias_rebind"] = network_svc.ensure_aliases_on_preferred(force=True)
    _audit_host_change(audit.NETWORK_CHANGED, request, action="failover_run")
    return result


@router.get("/api/system/network/dns-lookup")
def network_dns_lookup(host: str = Query(..., min_length=1, max_length=200)):
    return network_svc.dns_resolve(host)


class DockerNetBody(BaseModel):
    network: str
    container: str
    force: bool = False


class DockerPortsBody(BaseModel):
    ports: list[str] = []  # ["8080:80", "443:443"]


@router.get("/api/system/network/docker-ports")
def network_docker_ports():
    return {"ports": network_svc.docker_published_ports(), "networks": network_svc.docker_networks_detail()}


@router.post("/api/system/network/docker/connect")
def network_docker_connect(body: DockerNetBody, request: Request = None):
    result = network_svc.docker_network_connect(body.network, body.container)
    _audit_host_change(audit.NETWORK_CHANGED, request,
                       action="docker_connect", network=body.network,
                       container=body.container)
    return result


@router.post("/api/system/network/docker/disconnect")
def network_docker_disconnect(body: DockerNetBody, request: Request = None):
    result = network_svc.docker_network_disconnect(body.network, body.container, force=body.force)
    _audit_host_change(audit.NETWORK_CHANGED, request,
                       action="docker_disconnect", network=body.network,
                       container=body.container)
    return result


@router.post("/api/system/network/docker/ports/{container}")
def network_docker_set_ports(container: str, body: DockerPortsBody, request: Request = None):
    """Recreate container with new host port mappings."""
    result = network_svc.docker_update_ports(container, body.ports)
    _audit_host_change(audit.NETWORK_CHANGED, request,
                       action="docker_ports", container=container,
                       ports=",".join(body.ports or []))
    return result


@router.get("/api/system/processes")
def system_processes(limit: int = Query(25, ge=5, le=100)):
    return {"processes": tools_svc.top_processes(limit)}


@router.get("/api/system/diagnostics")
def system_diagnostics():
    return tools_svc.diagnostics()


@router.get("/api/system/scheduler")
def system_scheduler():
    # _json_tree, not a raw passthrough (the /api/scheduler alias rule from
    # host6): this route used to hand the timer rows straight to Starlette
    # while both scheduler siblings sanitized the same data — a leftover
    # ``\ud800`` label, an over-cap plist int or a subclass row bomb
    # answered a raw 500 here and a 200 there.
    timers = system_settings_svc._json_tree(tools_svc.launchd_timers())
    if not isinstance(timers, list):
        timers = []
    return {"timers": timers}


@router.get("/api/docker/df")
def docker_df():
    return tools_svc.docker_disk_usage()


@router.get("/api/docker/sizes")
def docker_sizes():
    return {"containers": tools_svc.container_sizes()}


# ─── Unraid Tools expansions ─────────────────────────────────────────────────

@router.get("/api/tools/catalog")
def tools_catalog():
    return tools_svc.tools_catalog()


@router.get("/api/tools/syslog")
def tools_syslog(
    minutes: int = Query(60, ge=5, le=1440),
    limit: int = Query(80, ge=10, le=300),
    level: str = Query("error"),
    force: bool = False,
):
    return tools_svc.syslog_tail(
        minutes=minutes, limit=limit, level=level, force=force
    )


@router.get("/api/tools/hardware")
def tools_hardware():
    return tools_svc.hardware_profile()


@router.get("/api/tools/updates")
def tools_updates(force: bool = False):
    # First Tools visit pays the probe; later visits and the warmer share it.
    try:
        tools_svc.start_updates_warmer()
    except Exception:
        pass
    return tools_svc.check_updates(force=force)


class ApplyUpdateBody(BaseModel):
    confirm: bool = False
    stash: bool = False


@router.post("/api/tools/updates/apply")
def tools_apply_update(body: ApplyUpdateBody, request: Request = None):
    result = tools_svc.apply_github_update(confirm=body.confirm, stash=body.stash)
    # Recorded even for the unconfirmed dry-run form: both spawn git.
    _audit_host_change(audit.UPDATES_APPLIED, request,
                       kind="github", confirm=bool(body.confirm))
    return result


class BrewUpgradeBody(BaseModel):
    confirm: bool = False


@router.post("/api/tools/updates/brew")
def tools_brew_upgrade(body: BrewUpgradeBody, request: Request = None):
    result = tools_svc.apply_brew_upgrade(confirm=body.confirm)
    _audit_host_change(audit.UPDATES_APPLIED, request,
                       kind="brew", confirm=bool(body.confirm))
    return result


@router.get("/api/tools/about")
def tools_about():
    return tools_svc.about_info()


@router.get("/api/tools/agents")
def tools_agents():
    return tools_svc.launchd_agents_summary()


@router.get("/api/tools/ports")
def tools_ports(limit: int = Query(40, ge=5, le=100)):
    return tools_svc.listening_ports(limit)


class DockerPruneBody(BaseModel):
    what: str = "dangling"  # dangling | build | volumes | all_unused
    confirm: bool = False


@router.post("/api/tools/docker/prune")
def tools_docker_prune(body: DockerPruneBody, request: Request = None):
    result = tools_svc.docker_prune(what=body.what, confirm=body.confirm)
    _audit_host_change(audit.CONTAINER_PRUNED, request,
                       kind=body.what, confirm=bool(body.confirm))
    return result


class NetPingBody(BaseModel):
    host: str
    count: int = 3


@router.post("/api/tools/net/ping")
def tools_net_ping(body: NetPingBody):
    return tools_svc.net_ping(body.host, count=body.count)


#: Distinct from NetDnsBody above: that one carries the resolver list written to
#: a network service, this one carries a single hostname to look up.  They shared
#: a name, so this definition silently replaced the other and the "set DNS
#: servers" route started rejecting {"servers": [...]} as a missing "name".
class NetDnsLookupBody(BaseModel):
    name: str


@router.post("/api/tools/net/dns")
def tools_net_dns(body: NetDnsLookupBody):
    return tools_svc.net_dns_lookup(body.name)


@router.post("/api/tools/net/flush-dns")
def tools_flush_dns(request: Request = None):
    result = tools_svc.flush_dns()
    _audit_host_change(audit.NETWORK_CHANGED, request, action="flush_dns")
    return result
