"""Host + Docker network management (macOS networksetup + docker)."""
from __future__ import annotations

import json
import re
import threading
import time
from typing import Any

from fastapi import HTTPException

from hub import cli_args
from hub.docker_cli import docker, engine_up
from hub.util import fan_out, sh, ttl_memo

_cache = {"t": 0.0, "v": None}
_CACHE_TTL = 6.0
_cache_lock = threading.Lock()
_refresh_lock = threading.Lock()
_cache_generation = 0
_cache_refresh_serial = 0

_services_cache = {"t": 0.0, "v": None}
_SERVICES_CACHE_TTL = 6.0
_services_cache_lock = threading.Lock()
_services_refresh_lock = threading.Lock()
_services_cache_generation = 0
_services_refresh_serial = 0

#: TTL for the reads that are pure dumps of system network configuration:
#: `ifconfig -a`, `networksetup -listallhardwareports` and
#: `networksetup -listnetworkserviceorder`.
#:
#: Each of these is read by several call sites, some of them inside per-interface
#: loops, so a single request ran each command repeatedly for byte-identical output
#: -- six times for the service order before it was memoised at all, and three
#: times after, because the first memo was not single-flight. One call per request
#: window is enough. The TTL matches the caches around them and `_bust()` clears
#: them together, so a configuration change is not masked for longer than the page
#: already allows.
_INTERFACE_CACHE_TTL = 6.0
_ORDER_CACHE_TTL = 6.0

NS = "/usr/sbin/networksetup"


def _hex_netmask_to_dotted(mask: str) -> str:
    """0xffffff00 → 255.255.255.0"""
    if not mask:
        return ""
    if mask.startswith("0x"):
        try:
            n = int(mask, 16)
            return ".".join(str((n >> (8 * i)) & 0xFF) for i in (3, 2, 1, 0))
        except ValueError:
            return mask
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", mask):
        return mask
    return mask


def _interfaces_uncached() -> list:
    items = []
    rc, out, _ = sh(["/sbin/ifconfig", "-a"], timeout=8)
    if rc != 0:
        return items
    cur = None
    for line in out.splitlines():
        m = re.match(r"^([a-zA-Z0-9.\-]+):\s+flags=", line)
        if m:
            if cur:
                items.append(cur)
            name = m.group(1)
            flags = re.search(r"flags=\w+<([^>]+)>", line)
            mtu_m = re.search(r"mtu\s+(\d+)", line)
            cur = {
                "name": name,
                "flags": (flags.group(1).split(",") if flags else []),
                "up": False,
                "ipv4": [],
                "ipv6": [],
                "mac": None,
                "status": None,
                "media": None,
                "mtu": int(mtu_m.group(1)) if mtu_m else None,
            }
            if flags and "UP" in flags.group(1).split(","):
                cur["up"] = True
            continue
        if not cur:
            continue
        s = line.strip()
        if s.startswith("inet "):
            parts = s.split()
            ip = parts[1] if len(parts) > 1 else ""
            mask = ""
            if "netmask" in parts:
                mask = _hex_netmask_to_dotted(parts[parts.index("netmask") + 1])
            bcast = ""
            if "broadcast" in parts:
                bcast = parts[parts.index("broadcast") + 1]
            cur["ipv4"].append({"ip": ip, "netmask": mask, "broadcast": bcast})
        elif s.startswith("inet6 "):
            parts = s.split()
            ip = parts[1].split("%")[0] if len(parts) > 1 else ""
            if ip and not ip.startswith("fe80"):
                cur["ipv6"].append(ip)
        elif "ether " in s:
            cur["mac"] = s.split("ether")[1].strip().split()[0]
        elif s.startswith("status:"):
            cur["status"] = s.split(":", 1)[1].strip()
            if cur["status"] == "active":
                cur["up"] = True
        elif s.startswith("media:"):
            cur["media"] = s.split(":", 1)[1].strip()
    if cur:
        items.append(cur)
    skip_exact = {"lo0"}
    skip_prefix = ("awdl", "llw", "utun", "anpi", "ap", "gif", "stf", "XHC")
    # Devices registered as network services (worth showing even without IPv4)
    svc_devices = {e["device"] for e in _network_service_order_entries() if e.get("device")}
    # Built-in Thunderbolt bridge devices ("Thunderbolt 1/2/3"), not TB-Ethernet adapters
    tb_devices = {
        p["device"] for p in hardware_ports()
        if re.search(r"thunderbolt\s*\d+$", p.get("port") or "", re.I)
    }
    out = []
    for i in items:
        n = i["name"]
        if n in skip_exact:
            continue
        if any(n.startswith(p) for p in skip_prefix) and not i["ipv4"]:
            continue
        if i["ipv4"]:
            out.append(i)
        elif n.startswith("en") and n not in svc_devices and (
            (i.get("media") or "") == "none" or n in tb_devices
        ):
            continue  # phantom (media:none) or unused Thunderbolt bridge
        elif i["up"] or n.startswith(("en", "bridge", "vmenet")):
            out.append(i)
    return out


@ttl_memo(_INTERFACE_CACHE_TTL)
def interfaces() -> list:
    """Every interface and its addresses, from one ``ifconfig -a``.

    Memoised for the reason :data:`_INTERFACE_CACHE_TTL` documents, which turned out
    to apply here just as much: five call sites read this, two of them
    (``interface_addresses`` and ``preferred_active_device``) on the same request,
    so ``/api/system/network/alias/auto`` ran ``ifconfig -a`` twice per read and
    ``/api/system/network`` more than that -- identical output each time.

    Single-flight matters here specifically: these call sites now sit inside
    fan-outs, so without it several workers miss a cold cache together and each
    runs the command, which is the failure mode ``ttl_memo`` exists to prevent.

    TTL matches the surrounding caches and ``_bust()`` clears it with them, so an
    added or removed IP alias is not masked for longer than the page already
    allows.
    """
    return _interfaces_uncached()


def _hardware_ports_uncached() -> list:
    rc, out, _ = sh([NS, "-listallhardwareports"], timeout=8)
    if rc != 0:
        return []
    items = []
    cur: dict | None = None
    for line in out.splitlines():
        if line.startswith("Hardware Port:"):
            if cur:
                items.append(cur)
            cur = {"port": line.split(":", 1)[1].strip(), "device": "", "mac": ""}
        elif cur and line.startswith("Device:"):
            cur["device"] = line.split(":", 1)[1].strip()
        elif cur and line.startswith("Ethernet Address:"):
            cur["mac"] = line.split(":", 1)[1].strip()
    if cur:
        items.append(cur)
    return items


@ttl_memo(_INTERFACE_CACHE_TTL)
def hardware_ports() -> list:
    """Physical ports and their device names, from one ``networksetup`` call.

    Three call sites, two of them inside loops, so this had the same duplication
    as :func:`interfaces`.  The output is a static description of the hardware, not
    live state, which is why a short TTL is enough.
    """
    return _hardware_ports_uncached()


@ttl_memo(_ORDER_CACHE_TTL)
def _network_service_order_entries() -> list[dict]:
    """Read service order without the expensive per-service detail calls.

    Callers treat this as cheap and some of them loop, so the cost has to live here
    rather than in each call site.

    Single-flight, which the hand-rolled memo it replaces was not: that one released
    its lock before running the command, so several fan-out workers reaching a cold
    cache together all missed and all ran it.  ``/api/system/network`` still spawned
    ``networksetup -listnetworkserviceorder`` three times with the old memo in
    place -- better than the six it was written to fix, but the remaining three were
    pure duplication.
    """
    return _network_service_order_uncached()


def _network_service_order_uncached() -> list[dict]:
    rc, out, _ = sh([NS, "-listnetworkserviceorder"], timeout=10)
    if rc != 0:
        return []
    entries = []
    for block in re.split(r"\n(?=\(\d+\))", out):
        match = re.search(r"\((\d+)\)\s+(.+)", block)
        if not match:
            continue
        order, name = int(match.group(1)), match.group(2).strip()
        disabled = name.startswith("*")
        if disabled:
            name = name.lstrip("*").strip()
        hardware = re.search(
            r"Hardware Port:\s*([^,]+),\s*Device:\s*([^)\s]+)", block
        )
        entries.append({
            "order": order,
            "name": name,
            "disabled": disabled,
            "port": hardware.group(1).strip() if hardware else "",
            "device": hardware.group(2).strip().rstrip(")") if hardware else "",
        })
    return entries


def _build_network_services() -> list:
    """Read all networksetup services and their IP/DNS configuration."""
    services = []
    parsed = _network_service_order_entries()

    # service_info() spawns 3 networksetup calls each; fan out so the network
    # page cost is one slow call rather than N-services × 3 sequential calls.
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(parsed)))) as ex:
        infos = list(ex.map(lambda p: service_info(p["name"]), parsed))

    for p, info in zip(parsed, infos):
        services.append({
            "order": p["order"],
            "name": p["name"],
            "disabled": p["disabled"],
            "hardware_port": p["port"],
            "device": p["device"],
            **info,
            "actions": _service_actions(p["name"], info, p["disabled"]),
        })
    return services


def network_services(force: bool = False) -> list:
    """Cached service details with one in-flight networksetup refresh."""
    global _services_refresh_serial

    with _services_cache_lock:
        observed_refresh = _services_refresh_serial
        if not force:
            hit = _services_cache["v"]
            if hit is not None and time.time() - _services_cache["t"] < _SERVICES_CACHE_TTL:
                return list(hit)

    with _services_refresh_lock:
        with _services_cache_lock:
            hit = _services_cache["v"]
            if not force:
                if hit is not None and time.time() - _services_cache["t"] < _SERVICES_CACHE_TTL:
                    return list(hit)
            elif hit is not None and _services_refresh_serial != observed_refresh:
                # A caller that held the refresh lock published while this forced
                # caller waited. Reuse exactly that refresh, not an older warm hit.
                return list(hit)
            build_generation = _services_cache_generation

        services = _build_network_services()
        with _services_cache_lock:
            if _services_cache_generation == build_generation:
                _services_cache.update(t=time.time(), v=services)
                _services_refresh_serial += 1
        return list(services)


def service_info(service: str) -> dict:
    """Parse networksetup -getinfo / DNS for one service."""
    rc, out, err = sh([NS, "-getinfo", service], timeout=8)
    info: dict[str, Any] = {
        "mode": "unknown",  # dhcp | manual | off | unknown
        "ip": "",
        "subnet": "",
        "router": "",
        "client_id": "",
        "ipv6": "",
        "raw": out if rc == 0 else (err or ""),
    }
    if rc != 0:
        info["error"] = err or out
        return info
    for line in out.splitlines():
        line = line.strip()
        low = line.lower()
        if "dhcp configuration" in low:
            info["mode"] = "dhcp"
        elif "manual configuration" in low:
            info["mode"] = "manual"
        elif "disabled" in low and "configuration" in low:
            info["mode"] = "off"
        elif low.startswith("ip address:"):
            info["ip"] = line.split(":", 1)[1].strip()
        elif low.startswith("subnet mask:"):
            info["subnet"] = line.split(":", 1)[1].strip()
        elif low.startswith("router:"):
            info["router"] = line.split(":", 1)[1].strip()
        elif low.startswith("client id:"):
            info["client_id"] = line.split(":", 1)[1].strip()
        elif low.startswith("ipv6:"):
            info["ipv6"] = line.split(":", 1)[1].strip()
    # DNS
    rc2, dns_out, _ = sh([NS, "-getdnsservers", service], timeout=5)
    dns = []
    if rc2 == 0 and dns_out and "aren't any" not in dns_out.lower() and "there aren't" not in dns_out.lower():
        dns = [ln.strip() for ln in dns_out.splitlines() if ln.strip() and not ln.lower().startswith("there")]
    info["dns"] = dns
    rc3, search_out, _ = sh([NS, "-getsearchdomains", service], timeout=5)
    search = []
    if rc3 == 0 and search_out and "aren't any" not in search_out.lower():
        search = [ln.strip() for ln in search_out.splitlines() if ln.strip() and not ln.lower().startswith("there")]
    info["search_domains"] = search
    return info


def _service_actions(name: str, info: dict, disabled: bool) -> list:
    if disabled:
        return ["enable"]
    acts = ["set_dhcp", "set_manual", "set_dns"]
    if name == "Wi-Fi" or "Wi-Fi" in name or "WiFi" in name:
        acts += ["wifi_power_on", "wifi_power_off"]
    return acts


def set_service_dhcp(service: str) -> dict:
    service = _validate_service(service)
    rc, out, err = sh([NS, "-setdhcp", service], timeout=15)
    _bust()
    return {"ok": rc == 0, "message": out or err or ("已切换为 DHCP" if rc == 0 else f"exit {rc}")}


def set_service_manual(service: str, ip: str, subnet: str, router: str = "") -> dict:
    service = _validate_service(service)
    if not _valid_ip(ip) or not _valid_ip(subnet):
        raise HTTPException(400, "IP / 子网掩码格式无效")
    if router and not _valid_ip(router):
        raise HTTPException(400, "网关格式无效")
    args = [NS, "-setmanual", service, ip, subnet]
    if router:
        args.append(router)
    else:
        # networksetup requires router for setmanual on some versions — use 0.0.0.0
        args.append(router or "0.0.0.0")
    rc, out, err = sh(args, timeout=15)
    _bust()
    return {"ok": rc == 0, "message": out or err or ("已设置静态 IP" if rc == 0 else f"exit {rc}")}


def _valid_dns_server(value: str) -> bool:
    """True for a DNS server that networksetup will read as an address.

    Each server occupies its own argv slot, so a value beginning with ``-`` is
    parsed as an option instead.  The previous fallback class
    ``^[a-zA-Z0-9.-]+$`` matched ``-getinfo`` for exactly that reason.
    """
    return _valid_ip(value) or cli_args.is_safe_hostname(value)


def set_service_dns(service: str, servers: list[str] | None = None) -> dict:
    service = _validate_service(service)
    servers = [s.strip() for s in (servers or []) if s and s.strip()]
    if not servers:
        rc, out, err = sh([NS, "-setdnsservers", service, "Empty"], timeout=10)
    else:
        for s in servers:
            if not _valid_dns_server(s):
                raise HTTPException(400, f"非法 DNS: {s}")
        rc, out, err = sh([NS, "-setdnsservers", service, *servers], timeout=10)
    _bust()
    return {"ok": rc == 0, "message": out or err or ("DNS 已更新" if rc == 0 else f"exit {rc}")}


def _wifi_devices() -> list[str]:
    devices = []
    for port in hardware_ports():
        label = port.get("port") or ""
        device = port.get("device") or ""
        if device and re.search(r"wi-?fi|airport|无线", label, re.I):
            devices.append(device)
    return devices


def wifi_power_status() -> dict:
    devices = _wifi_devices()
    if not devices:
        return {"ok": False, "on": None, "device": None, "message": "未发现 Wi-Fi 网卡"}
    device = devices[0]
    rc, out, err = sh([NS, "-getairportpower", device], timeout=8)
    if rc != 0:
        rc, out, err = sh(["sudo", "-n", NS, "-getairportpower", device], timeout=8)
    message = out or err or ""
    match = re.search(r":\s*(On|Off)\s*$", message, re.I)
    return {
        "ok": rc == 0 and bool(match),
        "on": match.group(1).lower() == "on" if match else None,
        "device": device,
        "message": message or f"exit {rc}",
    }


def set_wifi_power(on: bool) -> dict:
    arg = "on" if on else "off"
    devices = _wifi_devices()
    if not devices:
        return {"ok": False, "on": None, "device": None, "message": "未发现 Wi-Fi 网卡"}
    device = devices[0]
    rc, out, err = sh([NS, "-setairportpower", device, arg], timeout=10)
    if rc != 0:
        rc, out, err = sh(
            ["sudo", "-n", NS, "-setairportpower", device, arg], timeout=10
        )
    _bust()
    return {
        "ok": rc == 0,
        "on": on if rc == 0 else None,
        "device": device,
        "message": out or err or f"Wi-Fi {arg}",
    }


def set_service_enabled(service: str, enabled: bool) -> dict:
    """Enable/disable a networksetup service (does not delete it)."""
    service = _validate_service(service)
    rc, out, err = sh(
        [NS, "-setnetworkserviceenabled", service, "on" if enabled else "off"],
        timeout=15,
    )
    _bust()
    return {
        "ok": rc == 0,
        "message": out or err or (f"{'已启用' if enabled else '已禁用'} {service}"),
    }


def set_service_order(services: list[str]) -> dict:
    """Reorder network services (first = preferred path for outbound)."""
    if not services or len(services) < 1:
        raise HTTPException(400, "需要完整的服务顺序列表")
    # validate all names
    current = network_services()
    names = [s["name"] for s in current]
    cleaned = []
    for s in services:
        s = (s or "").strip()
        if not s:
            continue
        if s not in names:
            raise HTTPException(400, f"未知服务: {s}")
        if s not in cleaned:
            cleaned.append(s)
    # append any missing so ordernetworkservices has full set
    for n in names:
        if n not in cleaned:
            cleaned.append(n)
    rc, out, err = sh([NS, "-ordernetworkservices", *cleaned], timeout=20)
    _bust()
    return {
        "ok": rc == 0,
        "order": cleaned,
        "message": out or err or ("服务顺序已更新" if rc == 0 else f"exit {rc}"),
    }


def switch_profile(profile: str) -> dict:
    """Quick switch: wifi | ethernet (wired preferred) | ethernet_only | wifi_only."""
    profile = (profile or "").strip().lower()
    svcs = network_services()
    if not svcs:
        raise HTTPException(500, "无法读取网络服务")

    def is_wifi(s: dict) -> bool:
        n = (s.get("name") or "") + " " + (s.get("hardware_port") or "")
        return bool(re.search(r"wi-?fi|airport|无线", n, re.I))

    def is_ethernet(s: dict) -> bool:
        if is_wifi(s):
            return False
        d = s.get("device") or ""
        n = (s.get("name") or "") + " " + (s.get("hardware_port") or "")
        if d.startswith("en") and d != "en0":
            # en0 often Wi-Fi on MacBooks; other en* often dongles
            return True
        if re.search(r"ethernet|lan|usb.*lan|thunderbolt.*ethernet|有线", n, re.I):
            return True
        # Thunderbolt Bridge usually not primary LAN
        if "bridge" in d or re.search(r"bridge", n, re.I):
            return False
        return False

    def is_junk(s: dict) -> bool:
        n = s.get("name") or ""
        d = s.get("device") or ""
        if "modem" in d.lower() or "Monitor" in n or "iPhone" in n:
            return True
        return False

    wifi = [s for s in svcs if is_wifi(s) and not is_junk(s)]
    eth = [s for s in svcs if is_ethernet(s) and not is_junk(s)]
    other = [s for s in svcs if s not in wifi and s not in eth]

    logs = []
    steps: list[dict] = []
    order_names: list[str] = []

    def record(label: str, result: dict, *, critical: bool = True) -> None:
        step = {"step": label, "critical": critical, **result}
        steps.append(step)
        logs.append(f"{label}: {result.get('message') or ''}".rstrip())

    missing_kind = None
    if profile in ("ethernet", "wired", "lan", "ethernet_only", "wired_only") and not eth:
        missing_kind = chr(0x6709) + chr(0x7EBF)
    elif profile in ("wifi", "wireless", "wifi_only") and not wifi:
        missing_kind = "Wi-Fi"
    if missing_kind:
        return {
            "ok": False,
            "profile": profile,
            "order": [],
            "ethernet_services": [s["name"] for s in eth],
            "wifi_services": [s["name"] for s in wifi],
            "steps": [],
            "alias_rebind": None,
            "message": f"未发现可用的{missing_kind}网络服务，未更改网络配置",
        }

    if profile in ("ethernet", "wired", "lan"):
        # Prefer wired, keep Wi-Fi as fallback.
        order_names = [s["name"] for s in eth] + [s["name"] for s in wifi] + [s["name"] for s in other]
        for s in eth:
            record(f"enable {s['name']}", set_service_enabled(s["name"], True))
    elif profile in ("ethernet_only", "wired_only"):
        order_names = [s["name"] for s in eth] + [s["name"] for s in other] + [s["name"] for s in wifi]
        for s in eth:
            record(f"enable {s['name']}", set_service_enabled(s["name"], True))
        for s in wifi:
            record(f"disable {s['name']}", set_service_enabled(s["name"], False))
    elif profile in ("wifi", "wireless"):
        order_names = [s["name"] for s in wifi] + [s["name"] for s in eth] + [s["name"] for s in other]
        for s in wifi:
            record(f"enable {s['name']}", set_service_enabled(s["name"], True))
        record("enable Wi-Fi radio", set_wifi_power(True), critical=False)
    elif profile == "wifi_only":
        order_names = [s["name"] for s in wifi] + [s["name"] for s in other] + [s["name"] for s in eth]
        for s in wifi:
            record(f"enable {s['name']}", set_service_enabled(s["name"], True))
        for s in eth:
            record(f"disable {s['name']}", set_service_enabled(s["name"], False))
        record("enable Wi-Fi radio", set_wifi_power(True), critical=False)
    else:
        raise HTTPException(400, "profile 可选: wifi | ethernet | wifi_only | ethernet_only")

    ord_r = set_service_order(order_names)
    record("set service order", ord_r)
    _bust()

    # After path change, rebind managed IP aliases onto the new preferred NIC.
    try:
        time.sleep(1.5)  # allow link/DHCP to settle slightly
        alias_r = ensure_aliases_on_preferred(force=True)
    except Exception as e:
        alias_r = {"ok": False, "message": str(e)}
    record("rebind aliases", alias_r, critical=False)

    return {
        "ok": all(
            step.get("ok") is not False
            for step in steps
            if step.get("critical", True)
        ),
        "profile": profile,
        "order": order_names,
        "ethernet_services": [s["name"] for s in eth],
        "wifi_services": [s["name"] for s in wifi],
        "steps": steps,
        "alias_rebind": alias_r,
        "message": "; ".join(x for x in logs if x),
        "hint": "有线优先时请插入网线；若网卡未识别可先 networksetup -detectnewhardware",
    }


def interface_addresses() -> list:
    """All IPv4 addresses per interface, mark primary vs alias (host netmask or secondary)."""
    ifaces = interfaces()
    out = []
    for iface in ifaces:
        addrs = []
        ipv4s = iface.get("ipv4") or []
        for idx, a in enumerate(ipv4s):
            mask = a.get("netmask") or ""
            # /32 or 255.255.255.255 typically alias; first non-/32 is primary-ish
            is_alias = mask in ("255.255.255.255", "0xffffffff", "0xFFFFFFFF") or (
                idx > 0 and mask == (ipv4s[0].get("netmask") or "")
            )
            # if first is /32 and second is normal, still treat /32 as alias
            if mask in ("255.255.255.255", "0xffffffff", "0xFFFFFFFF"):
                is_alias = True
            if idx == 0 and mask not in ("255.255.255.255", "0xffffffff", "0xFFFFFFFF"):
                is_alias = False
            addrs.append({
                "ip": a.get("ip"),
                "netmask": mask,
                "broadcast": a.get("broadcast") or "",
                "alias": is_alias or (idx > 0),
                "primary": idx == 0 and not (mask in ("255.255.255.255", "0xffffffff")),
            })
        # fix primary flag: prefer non-alias
        for a in addrs:
            if not a["alias"]:
                a["primary"] = True
                break
        out.append({
            "device": iface["name"],
            "up": iface.get("up"),
            "mac": iface.get("mac"),
            "status": iface.get("status"),
            "addresses": addrs,
        })
    return out


def add_ip_alias(device: str, ip: str, netmask: str = "255.255.255.255") -> dict:
    """Add secondary IPv4 on interface (ifconfig alias). Good for binding .204 on en0."""
    device = _validate_device(device)
    if not _valid_ip(ip):
        raise HTTPException(400, "非法 IP")
    if not _valid_ip(netmask):
        raise HTTPException(400, "非法掩码")
    # try without sudo first
    rc, out, err = sh(["/sbin/ifconfig", device, "alias", ip, "netmask", netmask], timeout=10)
    if rc != 0:
        rc, out, err = sh(
            ["sudo", "-n", "/sbin/ifconfig", device, "alias", ip, "netmask", netmask],
            timeout=10,
        )
    _bust()
    msg = out or err
    if rc != 0 and ("password" in (msg or "").lower() or "sudo" in (msg or "").lower()):
        msg = (msg or "") + " · 需要配置 sudo 免密 ifconfig，或在终端手动: sudo ifconfig " \
            f"{device} alias {ip} netmask {netmask}"
    return {"ok": rc == 0, "device": device, "ip": ip, "netmask": netmask, "message": msg or ("已添加别名" if rc == 0 else f"exit {rc}")}


def remove_ip_alias(device: str, ip: str) -> dict:
    device = _validate_device(device)
    if not _valid_ip(ip):
        raise HTTPException(400, "非法 IP")
    rc, out, err = sh(["/sbin/ifconfig", device, "-alias", ip], timeout=10)
    if rc != 0:
        rc, out, err = sh(["sudo", "-n", "/sbin/ifconfig", device, "-alias", ip], timeout=10)
    _bust()
    msg = out or err
    if rc != 0:
        msg = (msg or "") + f" · 可手动: sudo ifconfig {device} -alias {ip}"
    return {"ok": rc == 0, "device": device, "ip": ip, "message": msg or ("已删除别名" if rc == 0 else f"exit {rc}")}


# ---------- Auto-bind managed IP aliases to preferred active NIC ----------

_alias_thread = None
_alias_stop = None
_alias_lock = threading.RLock()
_failover_lock = threading.Lock()
_failover_state = {
    "mode": "starting",
    "wired_failures": 0,
    "wired_successes": 0,
    "last_action": None,
    "last_action_at": None,
    "last_check_at": None,
    "last_result": None,
}


def _alias_settings() -> dict:
    from hub.config import cfg

    s = (cfg().get("settings") or {}).get("ip_aliases") or {}
    ips = s.get("ips") or []
    if isinstance(ips, str):
        ips = [x.strip() for x in ips.replace(",", " ").split() if x.strip()]
    # sanitize
    clean = []
    for ip in ips:
        if _valid_ip(str(ip)):
            clean.append(str(ip).strip())
    netmask = s.get("netmask") or "255.255.255.255"
    if not _valid_ip(netmask):
        netmask = "255.255.255.255"
    return {
        "auto_bind": bool(s.get("auto_bind", True)),
        "ips": clean,
        "netmask": netmask,
        "interval": int(s.get("interval") or 60),
        "prefer_wired": bool(s.get("prefer_wired", True)),
    }


def _failover_settings() -> dict:
    from hub.config import cfg

    settings = (cfg().get("settings") or {}).get("network_failover") or {}
    return {
        "enabled": bool(settings.get("enabled", False)),
        "power_save_wifi": bool(settings.get("power_save_wifi", True)),
        "interval": max(10, min(300, int(settings.get("interval") or 15))),
        "fail_threshold": max(1, min(10, int(settings.get("fail_threshold") or 2))),
        "recover_threshold": max(1, min(10, int(settings.get("recover_threshold") or 2))),
        "probe_timeout_ms": max(500, min(5000, int(settings.get("probe_timeout_ms") or 1200))),
    }


def _iface_by_name(name: str) -> dict | None:
    for i in interfaces():
        if i.get("name") == name:
            return i
    return None


def _iface_usable(iface: dict | None) -> bool:
    if not iface:
        return False
    if not iface.get("up"):
        return False
    st = (iface.get("status") or "").lower()
    if st in ("inactive", "not present"):
        return False
    # need at least one IPv4 (primary or already has connectivity)
    ipv4 = iface.get("ipv4") or []
    if not ipv4:
        return False
    # skip pure virtual without real en status active when marked
    if st and st not in ("active", "") and "active" not in st:
        # status field sometimes empty on macOS
        if st not in ("active",):
            # still allow if RUNNING flag implied by up=True and has IP
            pass
    return True


def _is_junk_service(s: dict) -> bool:
    n = (s.get("name") or "") + " " + (s.get("hardware_port") or s.get("port") or "")
    d = (s.get("device") or "").lower()
    if re.search(r"modem|monitor|iphone|ipad|apple.?watch|thunderbolt bridge", n, re.I):
        return True
    if "modem" in d or d.startswith("bridge"):
        return True
    return False


def preferred_active_device() -> dict | None:
    """Pick the highest-priority networkservice that is enabled + interface usable.

    Priority = system Network Service Order (first = preferred outbound path).
    """
    try:
        svcs = _network_service_order_entries()
    except Exception:
        svcs = []
    iface_map = {iface.get("name"): iface for iface in interfaces()}
    candidates = []
    for order, s in enumerate(svcs):
        if s.get("disabled"):
            continue
        if _is_junk_service(s):
            continue
        device = (s.get("device") or "").strip()
        if not device:
            continue
        iface = iface_map.get(device)
        if not _iface_usable(iface):
            continue
        # prefer interfaces with a non-/32 primary address
        primary_ip = None
        for a in iface.get("ipv4") or []:
            mask = a.get("netmask") or ""
            dotted = _hex_netmask_to_dotted(mask)
            if dotted not in ("255.255.255.255",) and not mask.lower() in ("0xffffffff",):
                primary_ip = a.get("ip")
                break
        if not primary_ip:
            # only /32s — still bindable but lower score
            primary_ip = (iface.get("ipv4") or [{}])[0].get("ip")
        candidates.append({
            "order": order,
            "service": s.get("name"),
            "device": device,
            "primary_ip": primary_ip,
            "hardware_port": s.get("port"),
            "status": iface.get("status"),
            "up": iface.get("up"),
        })
    if not candidates:
        return None
    # already in service order; first is best
    return candidates[0]


def find_ip_locations(ip: str, addresses: list | None = None) -> list[dict]:
    """Where an IPv4 currently appears (device + alias flag).

    ``addresses`` lets a caller checking several IPs read the interface table once
    and share it: the table is the same for every IP, but this used to re-read it
    per IP and then discard every row that did not match.
    """
    found = []
    for iface in addresses if addresses is not None else interface_addresses():
        for a in iface.get("addresses") or []:
            if a.get("ip") == ip:
                found.append({
                    "device": iface["device"],
                    "alias": bool(a.get("alias")),
                    "netmask": a.get("netmask"),
                    "up": iface.get("up"),
                })
    return found


def _alias_local_route(ip: str) -> dict:
    """Return whether macOS considers an alias a real local address."""
    rc, out, err = sh(["/sbin/route", "-n", "get", ip], timeout=5)
    interface = ""
    flags = ""
    if rc == 0:
        for line in out.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            if key.strip() == "interface":
                interface = value.strip()
            elif key.strip() == "flags":
                flags = value.strip().strip("<>")
    flag_set = {part.strip().upper() for part in flags.split(",") if part.strip()}
    return {
        "ok": rc == 0 and interface == "lo0" and "LOCAL" in flag_set,
        "interface": interface,
        "flags": sorted(flag_set),
        "message": err or (out if rc != 0 else ""),
    }


def ensure_aliases_on_preferred(force: bool = False) -> dict:
    with _alias_lock:
        return _ensure_aliases_on_preferred(force=force)


def _ensure_aliases_on_preferred(force: bool = False) -> dict:
    """Ensure managed alias IPs live on the preferred active NIC.

    - If IP missing → add on preferred device
    - If IP on wrong device → add on preferred then remove from others
    - If already correct → no-op
    Never removes primary (non-alias) addresses.
    """
    conf = _alias_settings()
    preferred = preferred_active_device()
    result = {
        "ok": True,
        "auto_bind": conf["auto_bind"],
        "preferred": preferred,
        "managed_ips": conf["ips"],
        "actions": [],
        "errors": [],
        "skipped": False,
    }
    if not conf["auto_bind"] and not force:
        result["skipped"] = True
        result["message"] = "自动绑定已关闭"
        return result
    if not conf["ips"]:
        result["message"] = "未配置 managed ips（settings.ip_aliases.ips）"
        return result
    if not preferred:
        result["ok"] = False
        result["message"] = "没有可用的优先网络（请检查网线/Wi‑Fi）"
        return result

    target = preferred["device"]
    netmask = conf["netmask"]
    for ip in conf["ips"]:
        locs = find_ip_locations(ip)
        on_target = [L for L in locs if L["device"] == target]
        on_others = [L for L in locs if L["device"] != target]
        route_state = _alias_local_route(ip) if on_target else {"ok": False}
        if on_target and not on_others and not route_state.get("ok"):
            # A /32 may remain visible in ifconfig while macOS has lost its
            # LOCAL/lo0 route.  Recreate it so local sockets stop hitting a
            # rejected ARP route on the physical interface.
            removed = remove_ip_alias(target, ip)
            if not removed.get("ok"):
                result["ok"] = False
                result["errors"].append(removed.get("message") or f"重建 {ip} 前删除失败")
                result["actions"].append({
                    "ip": ip, "status": "error", "device": target,
                    "message": removed.get("message") or "删除异常 alias 失败",
                })
                continue
            added = add_ip_alias(target, ip, netmask)
            repaired_route = _alias_local_route(ip) if added.get("ok") else {"ok": False}
            repaired = bool(added.get("ok") and repaired_route.get("ok"))
            result["actions"].append({
                "ip": ip,
                "status": "repaired" if repaired else "error",
                "device": target,
                "local_route": repaired_route,
                "message": "已重建本地路由" if repaired else (added.get("message") or "本地路由仍异常"),
            })
            if not repaired:
                result["ok"] = False
                result["errors"].append(added.get("message") or f"{ip} 本地路由修复失败")
            continue
        # already only on target
        if on_target and not on_others:
            result["actions"].append({
                "ip": ip, "status": "ok", "device": target,
                "local_route": route_state,
                "message": f"已在优先网卡 {target}，本地路由正常",
            })
            continue
        # add on target if missing
        if not on_target:
            r = add_ip_alias(target, ip, netmask)
            added_route = _alias_local_route(ip) if r.get("ok") else {"ok": False}
            result["actions"].append({
                "ip": ip, "status": "added" if r.get("ok") and added_route.get("ok") else "error",
                "device": target, "local_route": added_route, "message": r.get("message"),
            })
            if not r.get("ok") or not added_route.get("ok"):
                result["ok"] = False
                result["errors"].append(r.get("message") or f"添加 {ip}@{target} 或建立本地路由失败")
                continue
        else:
            result["actions"].append({
                "ip": ip, "status": "present", "device": target,
                "message": f"优先网卡 {target} 已有",
            })
        # remove from other devices (aliases only)
        for L in on_others:
            if not L.get("alias"):
                result["actions"].append({
                    "ip": ip, "status": "keep_primary", "device": L["device"],
                    "message": f"{L['device']} 上是主地址，不删除",
                })
                continue
            r = remove_ip_alias(L["device"], ip)
            result["actions"].append({
                "ip": ip,
                "status": "moved" if r.get("ok") else "error",
                "from": L["device"],
                "to": target,
                "message": r.get("message") or f"从 {L['device']} 移除",
            })
            if not r.get("ok"):
                result["ok"] = False
                result["errors"].append(r.get("message") or f"从 {L['device']} 删除失败")
        # Removing the old interface's copy can also remove macOS's shared
        # LOCAL route.  Verify once more after a move and repair in place.
        if on_others:
            final_route = _alias_local_route(ip)
            if not final_route.get("ok"):
                removed = remove_ip_alias(target, ip)
                added = add_ip_alias(target, ip, netmask) if removed.get("ok") else {"ok": False}
                final_route = _alias_local_route(ip) if added.get("ok") else {"ok": False}
                repaired = bool(added.get("ok") and final_route.get("ok"))
                result["actions"].append({
                    "ip": ip,
                    "status": "route_repaired" if repaired else "error",
                    "device": target,
                    "local_route": final_route,
                    "message": "迁移后已重建本地路由" if repaired else "迁移后本地路由修复失败",
                })
                if not repaired:
                    result["ok"] = False
                    result["errors"].append(f"{ip} 迁移后本地路由修复失败")

    result["message"] = (
        f"优先网卡 {target}（{preferred.get('service')}）· "
        + ("完成" if result["ok"] else "部分失败")
    )
    _bust()
    return result


def alias_auto_status() -> dict:
    # Three independent opening reads. `_alias_settings` is config, the other two
    # each drive their own subprocesses, and none consumes another's output -- so
    # they were three waves of pure prologue before any per-IP work could start.
    #
    # The interface table answers "where does this IP live" for every configured IP
    # at once, so it is read once here rather than once per IP inside the loop.
    conf, preferred, addresses = fan_out(
        lambda probe: probe(),
        [_alias_settings, preferred_active_device, interface_addresses],
        max_workers=3,
    )

    def route(ip: str) -> dict:
        """Never raises: one bad route lookup should not drop the whole page."""
        try:
            return _alias_local_route(ip)
        except Exception as exc:  # noqa: BLE001 - surfaced in the row
            return {"ok": False, "reason": f"route lookup failed: {exc}"}

    # `route -n get` is genuinely per IP, so those overlap; order follows the
    # configured list, which is what the page renders.
    routes = fan_out(route, conf["ips"])

    ips_state = []
    for ip, local_route in zip(conf["ips"], routes):
        locs = find_ip_locations(ip, addresses=addresses)
        ips_state.append({
            "ip": ip,
            "locations": locs,
            "local_route": local_route,
            "on_preferred": bool(
                preferred
                and any(L["device"] == preferred["device"] for L in locs)
                and local_route.get("ok")
            ),
            "missing": len(locs) == 0,
        })
    return {
        "config": conf,
        "preferred": preferred,
        "ips": ips_state,
    }


def _primary_ipv4_for_device(device: str, iface: dict | None = None) -> str | None:
    iface = iface or _iface_by_name(device)
    if not iface or (iface.get("status") or "").lower() != "active":
        return None
    for address in iface.get("ipv4") or []:
        ip = address.get("ip") or ""
        mask = _hex_netmask_to_dotted(address.get("netmask") or "")
        if ip and not ip.startswith("169.254.") and mask != "255.255.255.255":
            return ip
    return None


def _wired_devices() -> list[dict]:
    """Discover physical LAN adapters; never assumes a fixed en-number."""
    devices = []
    for port in hardware_ports():
        label = port.get("port") or ""
        device = port.get("device") or ""
        if not device or re.search(r"wi-?fi|airport|无线|bridge|thunderbolt", label, re.I):
            continue
        if re.search(r"ethernet|\blan\b|10/100|usb.*network", label, re.I):
            devices.append({"device": device, "port": label})
    return devices


def _service_gateway_for_device(device: str) -> dict:
    entry = next(
        (item for item in _network_service_order_entries() if item.get("device") == device),
        None,
    )
    if not entry:
        return {"service": None, "gateway": None}
    rc, out, _ = sh([NS, "-getinfo", entry["name"]], timeout=8)
    gateway = None
    if rc == 0:
        match = re.search(r"^Router:\s*(\S+)", out, re.M | re.I)
        candidate = match.group(1) if match else ""
        if _valid_ip(candidate) and candidate != "0.0.0.0":
            gateway = candidate
    return {"service": entry["name"], "gateway": gateway}


def _probe_wired_device(device: str, timeout_ms: int, iface: dict | None = None) -> dict:
    ip = _primary_ipv4_for_device(device, iface=iface)
    if not ip:
        return {"ok": False, "device": device, "ip": None, "gateway": None, "reason": "链路或 IPv4 未就绪"}
    service = _service_gateway_for_device(device)
    gateway = service.get("gateway")
    if not gateway:
        return {
            "ok": False,
            "device": device,
            "ip": ip,
            "gateway": None,
            "service": service.get("service"),
            "reason": "有线服务没有有效网关",
        }
    rc, out, err = sh(
        [
            "/sbin/ping", "-c", "1", "-W", str(timeout_ms),
            "-S", ip, gateway,
        ],
        timeout=max(3, int(timeout_ms / 1000) + 2),
    )
    return {
        "ok": rc == 0,
        "device": device,
        "ip": ip,
        "gateway": gateway,
        "service": service.get("service"),
        "reason": "网关可达" if rc == 0 else (err or out or "网关不可达").strip(),
    }


def network_failover_tick(force: bool = False) -> dict:
    """Power-save Wi-Fi while wired is healthy; restore it after stable failure."""
    conf = _failover_settings()
    with _failover_lock:
        if not conf["enabled"]:
            result = {"ok": True, "enabled": False, "mode": "disabled", "action": None}
            _failover_state.update(mode="disabled", last_check_at=time.strftime("%Y-%m-%d %H:%M:%S"), last_result=result)
            return result

        wired = _wired_devices()
        iface_map = {iface.get("name"): iface for iface in interfaces()}

        def probe(item) -> dict:
            """Never raises: `fan_out` re-raises on iteration, and losing the whole
            batch here would read as "no wired link" and switch Wi-Fi back on."""
            device = item["device"]
            try:
                return _probe_wired_device(
                    device, conf["probe_timeout_ms"], iface=iface_map.get(device)
                )
            except Exception as exc:  # noqa: BLE001 - reported, not swallowed
                # The label stays ASCII on purpose: the payload is the operating
                # system's own message ("no route to host"), which has no
                # translation, and hub/errors.py is for text we author.
                return {
                    "ok": False, "device": device, "ip": None, "gateway": None,
                    "reason": f"probe failed: {exc}",
                }

        # Every wired device is probed regardless -- the healthy pick below reads the
        # finished list -- so there is no short-circuit to preserve, and in series a
        # machine with two wired links waited out both ping timeouts on a poll that
        # runs on a timer.  `fan_out` keeps device order, so which link is chosen as
        # healthy stays deterministic rather than depending on which ping returned
        # first.
        probes = fan_out(probe, wired)
        healthy = next((probe_result for probe_result in probes if probe_result.get("ok")), None)
        wifi = wifi_power_status()
        action = None
        action_result = None

        if healthy:
            _failover_state["wired_successes"] += 1
            _failover_state["wired_failures"] = 0
            threshold_met = force or _failover_state["wired_successes"] >= conf["recover_threshold"]
            if conf["power_save_wifi"] and wifi.get("on") is True and threshold_met:
                action = "wifi_off"
                action_result = set_wifi_power(False)
            mode = "wired"
        else:
            _failover_state["wired_failures"] += 1
            _failover_state["wired_successes"] = 0
            threshold_met = force or _failover_state["wired_failures"] >= conf["fail_threshold"]
            if wifi.get("on") is False and threshold_met:
                action = "wifi_on"
                action_result = set_wifi_power(True)
            mode = "wifi_backup" if wifi.get("on") is not False or action == "wifi_on" else "waiting_for_failover"

        if action:
            _failover_state["last_action"] = action
            _failover_state["last_action_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            if action_result and action_result.get("ok"):
                wifi = {**wifi, "on": action == "wifi_on"}
        result = {
            "ok": bool(wired) and (action_result is None or bool(action_result.get("ok"))),
            "enabled": True,
            "mode": mode,
            "wired_healthy": bool(healthy),
            "active_wired": healthy,
            "wired_probes": probes,
            "wifi": wifi,
            "action": action,
            "action_result": action_result,
            "wired_failures": _failover_state["wired_failures"],
            "wired_successes": _failover_state["wired_successes"],
        }
        _failover_state.update(
            mode=mode,
            last_check_at=time.strftime("%Y-%m-%d %H:%M:%S"),
            last_result=result,
        )
        return result


def network_failover_status() -> dict:
    with _failover_lock:
        state = dict(_failover_state)
    return {"config": _failover_settings(), "state": state}


def update_alias_auto_config(
    *,
    auto_bind: bool | None = None,
    ips: list[str] | None = None,
    netmask: str | None = None,
    interval: int | None = None,
) -> dict:
    from hub.config import cfg, update_settings

    cur = dict((cfg().get("settings") or {}).get("ip_aliases") or {})
    if auto_bind is not None:
        cur["auto_bind"] = bool(auto_bind)
    if ips is not None:
        clean = [str(x).strip() for x in ips if _valid_ip(str(x).strip())]
        cur["ips"] = clean
    if netmask is not None and _valid_ip(netmask):
        cur["netmask"] = netmask
    if interval is not None:
        cur["interval"] = max(30, min(600, int(interval)))
    update_settings({"ip_aliases": cur})
    return alias_auto_status()


def start_alias_autobind(interval: int | None = None) -> None:
    """Background loop for alias health and wired/Wi-Fi failover."""
    global _alias_thread, _alias_stop
    if _alias_thread and _alias_thread.is_alive():
        return
    conf = _alias_settings()
    failover_conf = _failover_settings()
    if not conf["auto_bind"] and not failover_conf["enabled"]:
        return
    _alias_stop = threading.Event()

    def loop():
        # initial settle after boot
        if _alias_stop.wait(8):
            return
        next_alias = 0.0
        next_failover = 0.0
        while not _alias_stop.is_set():
            now = time.monotonic()
            alias_conf = _alias_settings()
            fail_conf = _failover_settings()
            failover_action = None
            try:
                if fail_conf["enabled"] and now >= next_failover:
                    fail_result = network_failover_tick(force=False)
                    failover_action = fail_result.get("action")
                    next_failover = now + fail_conf["interval"]
                if alias_conf["auto_bind"] and (now >= next_alias or failover_action):
                    alias_result = ensure_aliases_on_preferred(force=False)
                    # Wi-Fi needs a few seconds for association and DHCP after
                    # power-on; retry soon if no usable target exists yet.
                    if failover_action == "wifi_on" and not alias_result.get("ok"):
                        next_alias = now + 5
                    else:
                        next_alias = now + (interval or alias_conf["interval"] or 60)
            except Exception:
                pass
            deadlines = []
            if alias_conf["auto_bind"]:
                deadlines.append(next_alias)
            if fail_conf["enabled"]:
                deadlines.append(next_failover)
            wait_for = max(1.0, min(deadlines) - time.monotonic()) if deadlines else 30.0
            _alias_stop.wait(wait_for)

    _alias_thread = threading.Thread(target=loop, daemon=True, name="ip-alias-autobind")
    _alias_thread.start()


def stop_alias_autobind(timeout: float = 3.0) -> None:
    """Stop the alias worker cleanly during app shutdown/reload."""
    global _alias_thread, _alias_stop
    stop = _alias_stop
    if stop is not None:
        stop.set()
    thread = _alias_thread
    if thread and thread.is_alive() and thread is not threading.current_thread():
        thread.join(timeout=timeout)
    _alias_thread = None
    _alias_stop = None


def _validate_device(device: str) -> str:
    device = (device or "").strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9]*\d*$", device):
        raise HTTPException(400, f"非法网卡名: {device}")
    # must exist in ifconfig
    names = {i["name"] for i in interfaces()}
    if device not in names:
        raise HTTPException(404, f"网卡不存在: {device}")
    return device


def _validate_service(service: str) -> str:
    service = (service or "").strip()
    if not service or len(service) > 80:
        raise HTTPException(400, "无效的网络服务名")
    # must exist
    names = {s["name"] for s in network_services()}
    if service not in names:
        # allow even if cache empty
        rc, out, _ = sh([NS, "-listallnetworkservices"], timeout=8)
        listed = {ln.strip().lstrip("* ").strip() for ln in (out or "").splitlines()[1:] if ln.strip()}
        if service not in listed:
            raise HTTPException(404, f"找不到网络服务: {service}")
    return service


def _valid_ip(ip: str) -> bool:
    """True for a dotted-quad IPv4 literal.

    Each octet must be digits only.  ``int()`` accepts a sign, so the earlier
    ``0 <= int(p) <= 255`` form treated ``-0.0.0.0`` as valid and let a value
    starting with ``-`` reach an argv positional, where ifconfig and
    networksetup read it as an option.
    """
    parts = (ip or "").strip().split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or not 0 <= int(p) <= 255:
            return False
    return True


def listening_ports(limit: int = 100) -> list:
    rc, out, _ = sh(["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], timeout=12)
    if rc != 0:
        return []
    rows = []
    seen = set()
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        proc, pid, user, name = parts[0], parts[1], parts[2], parts[8]
        port = name.rsplit(":", 1)[-1]
        key = (proc, pid, port, name)
        if key in seen:
            continue
        seen.add(key)
        rows.append({
            "process": proc,
            "pid": pid,
            "user": user,
            "address": name,
            "port": port,
        })
        if len(rows) >= limit:
            break
    return rows


def routes(limit: int = 40) -> list:
    rc, out, _ = sh(["/usr/sbin/netstat", "-rn", "-f", "inet"], timeout=8)
    if rc != 0:
        return []
    rows = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] in ("Destination", "Routing", "Internet:"):
            continue
        if not re.match(r"^[\d./]+$|default", parts[0]):
            continue
        rows.append({
            "destination": parts[0],
            "gateway": parts[1] if len(parts) > 1 else "",
            "flags": parts[2] if len(parts) > 2 else "",
            "netif": parts[3] if len(parts) > 3 else "",
        })
        if len(rows) >= limit:
            break
    return rows


def default_route() -> dict:
    rc, out, _ = sh(["/sbin/route", "-n", "get", "default"], timeout=5)
    info = {}
    if rc == 0:
        for line in out.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                info[k.strip()] = v.strip()
    return {
        "gateway": info.get("gateway"),
        "interface": info.get("interface"),
        "raw": info,
    }


def _valid_lookup_target(host: str) -> bool:
    """A hostname or IP literal that cannot be read as a ``dig`` option.

    ``host`` reaches a bare positional slot (``dig +short <host>``), so a value
    beginning with ``-`` is parsed as a flag rather than as data -- and this
    endpoint returns the command's output to the caller, which makes it a read
    primitive.  ``-f-`` tells dig to take its query list from stdin, ``-p``/``-b``
    retarget the port and source address.

    The previous check was ``^[a-zA-Z0-9._:-]+$``: the hyphen sits inside the
    character class with no anchor on the first character, so ``--help`` and
    ``-p53`` passed it.  ``cli_args.is_safe_hostname`` is the module that exists
    for exactly this, and it is already used elsewhere in this file.
    """
    if cli_args.is_safe_hostname(host):
        return True
    # is_safe_hostname requires an alphanumeric first character, which would
    # reject a bare IPv6 literal such as "::1".  A leading colon cannot be read
    # as an option, so allow it when the whole value really is an address.
    import ipaddress

    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def dns_resolve(host: str) -> dict:
    host = (host or "").strip()
    if not _valid_lookup_target(host):
        raise HTTPException(400, "非法主机名")
    rc, out, err = sh(["/usr/bin/dscacheutil", "-q", "host", "-a", "name", host], timeout=8)
    if rc != 0 or not out.strip():
        rc2, out2, err2 = sh(["/usr/bin/dig", "+short", host], timeout=8)
        return {
            "ok": rc2 == 0 and bool(out2.strip()),
            "host": host,
            "answers": [ln.strip() for ln in (out2 or "").splitlines() if ln.strip()],
            "message": out2 or err2 or err or out,
        }
    ips = re.findall(r"ip_address:\s*(\S+)", out)
    return {"ok": bool(ips), "host": host, "answers": ips, "message": out}


# ---------- Docker networking ----------

def docker_published_ports() -> list:
    """All container host port mappings."""
    if not engine_up():
        return []
    rc, out, err = docker(
        "ps", "-a",
        "--format", "{{.Names}}\t{{.ID}}\t{{.Status}}\t{{.Ports}}",
        timeout=12,
    )
    if rc != 0:
        return []
    rows = []
    for line in out.splitlines():
        p = line.split("\t")
        if len(p) < 4:
            continue
        name, cid, status, ports = p[0], p[1][:12], p[2], p[3]
        mappings = _parse_ports_field(ports)
        for m in mappings:
            rows.append({
                "container": name,
                "cid": cid,
                "status": status,
                "host_ip": m.get("host_ip") or "0.0.0.0",
                "host_port": m.get("host_port"),
                "container_port": m.get("container_port"),
                "protocol": m.get("protocol") or "tcp",
                "raw": ports,
            })
        if not mappings and ports and ports != "":
            rows.append({
                "container": name,
                "cid": cid,
                "status": status,
                "host_ip": "",
                "host_port": "",
                "container_port": "",
                "protocol": "",
                "raw": ports,
            })
    return rows


def _parse_ports_field(ports: str) -> list:
    """Parse docker ps Ports: 0.0.0.0:4000->4000/tcp, :::4000->4000/tcp"""
    if not ports or ports == "":
        return []
    out = []
    for part in ports.split(","):
        part = part.strip()
        m = re.match(
            r"^(?:(\d+\.\d+\.\d+\.\d+|\*|\[::\]|::):)?(\d+)->(\d+)(?:/(tcp|udp))?$",
            part,
        )
        if m:
            out.append({
                "host_ip": (m.group(1) or "0.0.0.0").replace("[::]", "::"),
                "host_port": m.group(2),
                "container_port": m.group(3),
                "protocol": m.group(4) or "tcp",
            })
            continue
        # published without host ip
        m2 = re.match(r"^(\d+)->(\d+)(?:/(tcp|udp))?$", part)
        if m2:
            out.append({
                "host_ip": "0.0.0.0",
                "host_port": m2.group(1),
                "container_port": m2.group(2),
                "protocol": m2.group(3) or "tcp",
            })
    return out


def docker_networks_detail() -> list:
    if not engine_up():
        return []
    rc, out, err = docker("network", "ls", "--format", "{{.ID}}\t{{.Name}}\t{{.Driver}}\t{{.Scope}}", timeout=12)
    if rc != 0:
        return []
    rows = []
    for line in out.splitlines():
        p = line.split("\t")
        if len(p) < 4:
            continue
        rows.append((p[0], p[1], p[2], p[3]))  # id, name, driver, scope

    def _detail(row: tuple) -> dict:
        nid, name, driver, scope = row
        containers: list = []
        subnet = gateway = ""
        rc2, jout, _ = docker("network", "inspect", name, timeout=10)
        if rc2 == 0:
            try:
                arr = json.loads(jout)
                n = arr[0] if arr else {}
                ipam = (n.get("IPAM") or {}).get("Config") or []
                if ipam:
                    subnet = ipam[0].get("Subnet") or ""
                    gateway = ipam[0].get("Gateway") or ""
                for cname, c in (n.get("Containers") or {}).items():
                    containers.append({
                        "id": cname[:12],
                        "name": (c.get("Name") or "").lstrip("/"),
                        "ipv4": c.get("IPv4Address") or "",
                        "ipv6": c.get("IPv6Address") or "",
                    })
            except Exception:
                pass
        return {
            "id": nid[:12],
            "name": name,
            "driver": driver,
            "scope": scope,
            "subnet": subnet,
            "gateway": gateway,
            "containers": containers,
            "builtin": name in ("bridge", "host", "none"),
        }

    if not rows:
        return []
    # `docker network inspect` per network is the bottleneck — fan out.
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=min(8, len(rows))) as ex:
        return list(ex.map(_detail, rows))


def docker_network_connect(network: str, container: str) -> dict:
    if not network or not container:
        raise HTTPException(400, "需要 network 与 container")
    if network in ("host", "none"):
        raise HTTPException(400, "不能 connect 到 host/none")
    rc, out, err = docker("network", "connect", network, container, timeout=30)
    return {"ok": rc == 0, "message": out if rc == 0 else (err or out)}


def docker_network_disconnect(network: str, container: str, force: bool = False) -> dict:
    args = ["network", "disconnect"]
    if force:
        args.append("-f")
    args += [network, container]
    rc, out, err = docker(*args, timeout=30)
    return {"ok": rc == 0, "message": out if rc == 0 else (err or out)}


def docker_update_ports(container: str, ports: list[str]) -> dict:
    """Recreate container with new -p mappings (best-effort from inspect)."""
    from hub import containers_svc
    if not engine_up():
        raise HTTPException(503, "引擎未运行")
    rc, out, err = docker("inspect", container, timeout=15)
    if rc != 0:
        raise HTTPException(404, err or "容器不存在")
    data = json.loads(out)[0]
    image = ((data.get("Config") or {}).get("Image")) or ""
    if not image:
        raise HTTPException(400, "无法解析镜像")
    host = data.get("HostConfig") or {}
    cfg_ = data.get("Config") or {}
    # build run body
    env = []
    for e in cfg_.get("Env") or []:
        if e.startswith("PATH="):
            continue
        env.append(e)
    volumes = list(host.get("Binds") or [])
    network = host.get("NetworkMode") or "bridge"
    if network.startswith("container:"):
        network = "bridge"
    restart = ((host.get("RestartPolicy") or {}).get("Name")) or "unless-stopped"
    # normalize ports
    port_list = []
    for p in ports or []:
        p = str(p).strip()
        if p and re.match(r"^[0-9.:\-/tcpudp]+$", p):
            port_list.append(p)
    # stop & remove then run
    docker("stop", container, timeout=90)
    docker("rm", container, timeout=60)
    body = {
        "image": image,
        "name": container,
        "restart": restart if restart != "no" else "no",
        "ports": port_list,
        "volumes": volumes,
        "env": env,
        "network": network if network not in ("default",) else None,
        "privileged": bool(host.get("Privileged")),
        "command": cfg_.get("Cmd"),
    }
    return containers_svc.create_run_container(body)


def _bust():
    """Invalidate caches and prevent older in-flight builds from publishing."""
    global _cache_generation, _services_cache_generation

    with _cache_lock:
        _cache_generation += 1
        _cache.update(t=0.0, v=None)
    with _services_cache_lock:
        _services_cache_generation += 1
        _services_cache.update(t=0.0, v=None)
    # Cleared with the rest: an added or removed IP alias changes `ifconfig`
    # output, a changed service configuration changes the service order, and
    # `add_ip_alias`/`remove_ip_alias`/`set_service_*` all reach here right after
    # their command runs.
    _network_service_order_entries.invalidate()
    interfaces.invalidate()
    hardware_ports.invalidate()


def _build_overview(force_services: bool = False) -> dict:
    # Every collector below is an independent subprocess-bound call; run them
    # concurrently so page latency ≈ the single slowest call, not their sum.
    from concurrent.futures import ThreadPoolExecutor

    def _safe(fn, default):
        try:
            return fn()
        except Exception:
            return default

    with ThreadPoolExecutor(max_workers=11) as ex:
        f_ifaces = ex.submit(interfaces)
        f_services = ex.submit(network_services, force_services)
        f_hwports = ex.submit(hardware_ports)
        f_addrs = ex.submit(_safe, interface_addresses, [])
        f_listen = ex.submit(_safe, listening_ports, [])
        f_routes = ex.submit(_safe, routes, [])
        f_defroute = ex.submit(_safe, default_route, {})
        f_dports = ex.submit(_safe, docker_published_ports, [])
        f_dnets = ex.submit(_safe, docker_networks_detail, [])
        f_alias = ex.submit(_safe, alias_auto_status, None)
        f_failover = ex.submit(_safe, network_failover_status, None)
        f_engine = ex.submit(engine_up)

        ifaces = _safe(f_ifaces.result, [])
        try:
            services = f_services.result()
            svc_error = None
        except Exception as e:
            services = []
            svc_error = str(e)

    primary = None
    for i in ifaces:
        if i.get("up") and i.get("ipv4") and i["name"].startswith("en"):
            primary = i
            break

    v = {
        "interfaces": ifaces,
        "primary": primary,
        "services": services,
        "services_error": svc_error,
        "hardware_ports": _safe(f_hwports.result, []),
        "interface_addresses": f_addrs.result(),
        "listening": f_listen.result(),
        "routes": f_routes.result(),
        "default_route": f_defroute.result(),
        "docker_ports": f_dports.result(),
        "docker_networks": f_dnets.result(),
        "engine_up": _safe(f_engine.result, False),
        "alias_auto": f_alias.result(),
        "network_failover": f_failover.result(),
        "ts": time.strftime("%H:%M:%S"),
        "profiles": [
            {"id": "wifi", "label": "优先 Wi‑Fi（有线作备选）"},
            {"id": "ethernet", "label": "优先有线（Wi‑Fi 作备选）"},
            {"id": "wifi_only", "label": "仅 Wi‑Fi"},
            {"id": "ethernet_only", "label": "仅有线"},
        ],
    }
    return v


def overview(force: bool = False) -> dict:
    """Cached network overview with one in-flight subprocess refresh."""
    global _cache_refresh_serial

    with _cache_lock:
        observed_refresh = _cache_refresh_serial
        if not force:
            hit = _cache["v"]
            if hit is not None and time.time() - _cache["t"] < _CACHE_TTL:
                return dict(hit)

    with _refresh_lock:
        with _cache_lock:
            hit = _cache["v"]
            if not force:
                if hit is not None and time.time() - _cache["t"] < _CACHE_TTL:
                    return dict(hit)
            elif hit is not None and _cache_refresh_serial != observed_refresh:
                # A caller that held the refresh lock published while this forced
                # caller waited. Reuse exactly that refresh, not an older warm hit.
                return dict(hit)
            build_generation = _cache_generation

        data = _build_overview(force_services=force)
        with _cache_lock:
            if _cache_generation == build_generation:
                _cache.update(t=time.time(), v=data)
                _cache_refresh_serial += 1
        return dict(data)
