from __future__ import annotations

import platform

from fastapi import APIRouter, Query, Request

from hub import network_svc, tools_svc
from hub.host_address import default_interface, host_ip
from typing import Optional
from urllib.parse import quote

from pydantic import BaseModel, Field

from hub import auth, vm_console, vms_svc
from hub.docker_cli import engine_up
from hub.errors import api_error
from hub.paths import DOCKER, ORB
from hub.util import sh

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
def vm_create(body: VmCreateBody):
    """Create OrbStack Linux machine (UTM create is GUI-only)."""
    return vms_svc.create_orb_machine(body.distro, body.name, body.arch)


@router.post("/api/vms/{vm_id}/action")
def vm_action(vm_id: str, body: VmActionBody):
    # path may contain orb:name — FastAPI decodes
    return vms_svc.vm_action(vm_id, body.action, name=body.name, force=body.force)


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


@router.get("/api/system/host")
def host_info():
    rc, hostname, _ = sh(["/bin/hostname"], timeout=3)
    lan = host_ip()
    ifaces = []
    route_iface = default_interface()
    for iface in dict.fromkeys((route_iface, "en0", "en1", "bridge0", "utun0")):
        if not iface:
            continue
        r, ip, _ = sh(["/usr/sbin/ipconfig", "getifaddr", iface], timeout=2)
        if r == 0 and ip:
            ifaces.append({"iface": iface, "ip": ip})
    rc3, model, _ = sh(["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"], timeout=3)
    rc4, ncpu, _ = sh(["/usr/sbin/sysctl", "-n", "hw.ncpu"], timeout=3)
    return {
        "hostname": hostname if rc == 0 else platform.node(),
        "platform": platform.platform(),
        "arch": platform.machine(),
        "python": platform.python_version(),
        "cpu": model if rc3 == 0 else "",
        "ncpu": int(ncpu) if rc4 == 0 and ncpu.isdigit() else None,
        "host_ip": host_ip(),
        "lan_ip": lan,
        "interfaces": ifaces,
        "orbstack": engine_up(),
        "docker_cli": DOCKER,
        "orb_cli": ORB,
    }


@router.get("/api/system/network")
def system_network(force: bool = False):
    return network_svc.overview(force=force)


class NetManualBody(BaseModel):
    ip: str
    subnet: str
    router: str = ""


class NetDnsBody(BaseModel):
    servers: list[str] = []


class NetServiceAction(BaseModel):
    action: str  # set_dhcp | wifi_on | wifi_off


@router.get("/api/system/network/services")
def network_services():
    return {"services": network_svc.network_services()}


@router.post("/api/system/network/services/{service_name}/dhcp")
def network_set_dhcp(service_name: str):
    return network_svc.set_service_dhcp(service_name)


@router.post("/api/system/network/services/{service_name}/manual")
def network_set_manual(service_name: str, body: NetManualBody):
    return network_svc.set_service_manual(service_name, body.ip, body.subnet, body.router)


@router.post("/api/system/network/services/{service_name}/dns")
def network_set_dns(service_name: str, body: NetDnsBody):
    return network_svc.set_service_dns(service_name, body.servers)


@router.post("/api/system/network/wifi/{state}")
def network_wifi(state: str):
    if state not in ("on", "off"):
        from fastapi import HTTPException
        raise HTTPException(400, "state must be on|off")
    return network_svc.set_wifi_power(state == "on")


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
def network_service_enabled(service_name: str, body: NetEnableBody):
    return network_svc.set_service_enabled(service_name, body.enabled)


@router.post("/api/system/network/order")
def network_set_order(body: NetOrderBody):
    return network_svc.set_service_order(body.services)


@router.post("/api/system/network/profile")
def network_switch_profile(body: NetProfileBody):
    """Quick switch between Wi‑Fi / wired preference."""
    return network_svc.switch_profile(body.profile)


@router.get("/api/system/network/addresses")
def network_addresses():
    return {"interfaces": network_svc.interface_addresses()}


@router.post("/api/system/network/alias/add")
def network_alias_add(body: NetAliasBody):
    return network_svc.add_ip_alias(body.device, body.ip, body.netmask)


@router.post("/api/system/network/alias/remove")
def network_alias_remove(body: NetAliasBody):
    return network_svc.remove_ip_alias(body.device, body.ip)


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
def network_alias_auto_run():
    """Immediately rebind managed aliases onto preferred active NIC."""
    return network_svc.ensure_aliases_on_preferred(force=True)


@router.put("/api/system/network/alias/auto")
def network_alias_auto_config(body: NetAliasAutoConfig):
    """Update auto-bind settings (settings.ip_aliases)."""
    return network_svc.update_alias_auto_config(
        auto_bind=body.auto_bind,
        ips=body.ips,
        netmask=body.netmask,
        interval=body.interval,
    )


@router.get("/api/system/network/failover")
def network_failover_status():
    return network_svc.network_failover_status()


@router.post("/api/system/network/failover/run")
def network_failover_run():
    """Probe wired connectivity and immediately enforce the failover policy."""
    result = network_svc.network_failover_tick(force=True)
    if result.get("action"):
        result["alias_rebind"] = network_svc.ensure_aliases_on_preferred(force=True)
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
def network_docker_connect(body: DockerNetBody):
    return network_svc.docker_network_connect(body.network, body.container)


@router.post("/api/system/network/docker/disconnect")
def network_docker_disconnect(body: DockerNetBody):
    return network_svc.docker_network_disconnect(body.network, body.container, force=body.force)


@router.post("/api/system/network/docker/ports/{container}")
def network_docker_set_ports(container: str, body: DockerPortsBody):
    """Recreate container with new host port mappings."""
    return network_svc.docker_update_ports(container, body.ports)


@router.get("/api/system/processes")
def system_processes(limit: int = Query(25, ge=5, le=100)):
    return {"processes": tools_svc.top_processes(limit)}


@router.get("/api/system/diagnostics")
def system_diagnostics():
    return tools_svc.diagnostics()


@router.get("/api/system/scheduler")
def system_scheduler():
    return {"timers": tools_svc.launchd_timers()}


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
):
    return tools_svc.syslog_tail(minutes=minutes, limit=limit, level=level)


@router.get("/api/tools/hardware")
def tools_hardware():
    return tools_svc.hardware_profile()


@router.get("/api/tools/updates")
def tools_updates():
    return tools_svc.check_updates()


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
def tools_docker_prune(body: DockerPruneBody):
    return tools_svc.docker_prune(what=body.what, confirm=body.confirm)


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
def tools_flush_dns():
    return tools_svc.flush_dns()
