"""Render a WireGuard peer config into the formats real clients actually accept.

A ``.conf`` file is only useful to the official WireGuard client.  On a phone the
tunnel is usually driven by Shadowrocket, and on a desktop by Clash/Mihomo, and
both want the same key material expressed completely differently.  Handing the
operator one format and letting them translate by hand is where mistakes happen:
a dropped ``PresharedKey`` or a wrong ``AllowedIPs`` produces a tunnel that comes
up and then silently carries no traffic.

So this module owns the translation, and every format is generated from the one
parsed config rather than assembled independently.  Output shape follows the
reference router panel this feature is modelled on, so configs already handed out
from that panel and configs handed out from here are interchangeable.

Pure functions only: no subprocesses, no filesystem, no config reads.  That keeps
the interesting logic unit-testable without a WireGuard installation.
"""
from __future__ import annotations

from urllib.parse import quote


def _quote(value) -> str:
    """Percent-encode a conf field. Leftover ``\\ud800`` used to 500 format=sr."""
    if isinstance(value, (bytes, bytearray)):
        text = value.decode("utf-8", "replace")
    else:
        text = "" if value is None else str(value)
    return quote(text.encode("utf-8", "replace").decode("utf-8"), safe="")

#: WireGuard's own default is 1420, but a tunnel that traverses PPPoE or a
#: mobile carrier fragments at that size and manifests as "connects, then
#: stalls on large transfers".  1280 is the IPv6 minimum MTU and the value the
#: reference panel settled on for the same reason.
DEFAULT_MTU = 1280

#: Assumed when a peer's Endpoint carries no port. WireGuard's registered port.
DEFAULT_PORT = 51820

#: Formats :func:`render` understands, in the order the UI presents them.
FORMATS = ("wg", "clash", "clashfull", "sr", "wst")


def parse_conf(text: str) -> dict:
    """Parse a wg-quick style config into ``{"interface": {...}, "peers": [...]}``.

    Section-aware rather than a flat key scan, because ``PublicKey`` means two
    different things depending on whether it appears under ``[Interface]`` or
    ``[Peer]``, and a client config contains both.
    """
    interface: dict[str, str] = {}
    peers: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    section = ""

    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        low = line.lower()
        if low == "[interface]":
            section = "interface"
            current = interface
            continue
        if low == "[peer]":
            section = "peer"
            current = {}
            peers.append(current)
            continue
        if current is None or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        # A repeated key inside one section is a malformed config; last wins,
        # matching how wg-quick itself behaves.
        current[key] = value

    del section
    return {"interface": interface, "peers": peers}


def _first_address(interface: dict) -> str:
    """The bare IPv4 from ``Address = 10.10.0.5/32, fd00::5/128``."""
    raw = str(interface.get("Address") or "")
    first = raw.split(",")[0].strip()
    return first.split("/")[0].strip()


def _endpoint(peer: dict) -> tuple[str, str]:
    """``(host, port)`` from a peer's Endpoint, defaulting the port.

    Splitting on the *last* colon is wrong for an unbracketed IPv6 literal: it
    turns ``2408:8248::215`` into host ``2408:8248:`` and port ``215``, so the
    generated Clash proxy and Shadowrocket URL both pointed at a truncated address
    on a v6-only endpoint.  Brackets are the signal that a port follows; without
    them, more than one colon means the whole value is the address.
    """
    raw = str(peer.get("Endpoint") or "").strip()
    if not raw:
        return "", str(DEFAULT_PORT)
    if raw.startswith("["):
        host, _, rest = raw.partition("]")
        return host[1:].strip(), (rest.lstrip(":").strip() or str(DEFAULT_PORT))
    if raw.count(":") > 1:
        return raw, str(DEFAULT_PORT)
    host, _, port = raw.partition(":")
    if not host:
        return raw, str(DEFAULT_PORT)
    return host.strip(), (port.strip() or str(DEFAULT_PORT))


def _csv(value: str) -> list[str]:
    return [part.strip() for part in str(value or "").split(",") if part.strip()]


def _mtu(interface: dict) -> int:
    raw = str(interface.get("MTU") or "").strip()
    if raw.isdigit():
        return int(raw)
    return DEFAULT_MTU


def to_clash_proxy(conf: str, name: str) -> str:
    """One ``proxies:`` entry for Clash.Meta / Mihomo.

    Indented two spaces so it can be pasted straight under ``proxies:`` in an
    existing config, which is the common case for someone who already runs Clash.
    """
    parsed = parse_conf(conf)
    interface = parsed["interface"]
    peer = parsed["peers"][0] if parsed["peers"] else {}
    host, port = _endpoint(peer)

    lines = [
        f'  - name: "{name}"',
        "    type: wireguard",
        f"    server: {host}",
        f"    port: {port}",
        f"    ip: {_first_address(interface)}",
        f"    private-key: {interface.get('PrivateKey', '')}",
        f"    public-key: {peer.get('PublicKey', '')}",
    ]
    if peer.get("PresharedKey"):
        lines.append(f"    pre-shared-key: {peer['PresharedKey']}")
    lines.append("    udp: true")
    dns = _csv(interface.get("DNS", ""))
    if dns:
        lines.append(f"    dns: [{', '.join(dns)}]")
    allowed = _csv(peer.get("AllowedIPs", ""))
    if allowed:
        lines.append("    allowed-ips:")
        lines.extend(f"      - {entry}" for entry in allowed)
    lines.append(f"    mtu: {_mtu(interface)}")
    return "\n".join(lines)


def to_clash_full(
    conf: str,
    name: str,
    *,
    lan_cidr: str = "",
    wg_cidr: str = "",
    group_name: str = "Home",
) -> str:
    """A complete, minimal Clash config built around this one peer.

    The routing rules differ by tunnel mode, and the mode is read from the config
    rather than passed in: a peer whose ``AllowedIPs`` contains ``0.0.0.0/0`` is a
    full tunnel and everything should match it, whereas a split tunnel must only
    capture the home subnets or the client loses its normal internet path.

    *lan_cidr* and *wg_cidr* are parameters, not constants, because the reference
    panel hardcoded one household's subnets into the generated file — which is
    silently wrong for anyone whose LAN is not ``192.168.1.0/24``.
    """
    parsed = parse_conf(conf)
    peer = parsed["peers"][0] if parsed["peers"] else {}
    allowed = _csv(peer.get("AllowedIPs", ""))
    full_tunnel = "0.0.0.0/0" in allowed
    proxy = to_clash_proxy(conf, name)

    if full_tunnel:
        rules = [f"  - MATCH,{group_name}"]
    else:
        rules = []
        for cidr in (lan_cidr, wg_cidr):
            if cidr:
                rules.append(f"  - IP-CIDR,{cidr},{group_name},no-resolve")
        if not rules:
            # Nothing to steer: without a subnet the split-tunnel rule set would
            # be empty and every request would fall through to DIRECT, so state
            # that outcome instead of emitting a config that looks functional.
            rules.append("  # no home subnet configured: nothing is routed over the tunnel")
        rules.append("  - MATCH,DIRECT")

    mode_note = "full-tunnel: all traffic goes home" if full_tunnel else "split-tunnel: only home subnets"
    return f"""# Clash.Meta / Mihomo - minimal complete config
# {mode_note}
mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
ipv6: false
dns:
  enable: true
  ipv6: false
  default-nameserver: [223.5.5.5, 119.29.29.29]
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  fake-ip-range: 198.18.0.1/16
  enhanced-mode: fake-ip
proxies:
{proxy}
proxy-groups:
  - name: "{group_name}"
    type: select
    proxies:
      - {name}
      - DIRECT
rules:
{chr(10).join(rules)}
"""


def to_shadowrocket(conf: str, name: str) -> str:
    """A ``wireguard://`` URL Shadowrocket can import from a QR code."""
    parsed = parse_conf(conf)
    interface = parsed["interface"]
    peer = parsed["peers"][0] if parsed["peers"] else {}
    host, port = _endpoint(peer)

    params = [
        f"publicKey={_quote(peer.get('PublicKey', ''))}",
        f"privateKey={_quote(interface.get('PrivateKey', ''))}",
        f"ip={_first_address(interface)}",
        f"mtu={_mtu(interface)}",
        "udp=1",
    ]
    if interface.get("DNS"):
        params.append(f"dns={_quote(interface['DNS'])}")
    if peer.get("PresharedKey"):
        params.append(f"presharedKey={_quote(peer['PresharedKey'])}")
    if peer.get("AllowedIPs"):
        params.append(f"allowedIPs={_quote(peer['AllowedIPs'])}")
    return f"wireguard://{host}:{port}?{'&'.join(params)}#{_quote(name)}"


def render(
    fmt: str,
    conf: str,
    name: str,
    *,
    lan_cidr: str = "",
    wg_cidr: str = "",
) -> str:
    """Dispatch to one of :data:`FORMATS`, defaulting to the raw config."""
    kind = (fmt or "wg").strip().lower()
    if kind == "clash":
        return to_clash_proxy(conf, name)
    if kind == "clashfull":
        return to_clash_full(conf, name, lan_cidr=lan_cidr, wg_cidr=wg_cidr)
    if kind == "sr":
        return to_shadowrocket(conf, name)
    # ``wst`` is the same wg-quick file with a localhost Endpoint and a
    # wstunnel client command already written in by the caller.
    return conf


def filename_for(fmt: str, name: str) -> str:
    """A safe download filename for *name* in *fmt*.

    ASCII only: the value goes into a ``Content-Disposition`` header, and
    Starlette encodes header values as latin-1.  ``str.isalnum`` is true for
    CJK / Cyrillic / superscripts, so a leftover non-ASCII peer name in
    ``data/wireguard-peers.json`` (hand-edited, or restored from a backup
    written before the name rule existed) used to UnicodeEncodeError the
    header render and answer a bare 500 on GET /api/wireguard/peers/download.
    """
    safe = "".join(
        ch if ((ch.isascii() and ch.isalnum()) or ch in "-_") else "-"
        for ch in (name or "peer")
    )[:48]
    if not any(ch.isalnum() for ch in safe):
        # A fully non-ASCII name would otherwise download as "-----.conf".
        safe = "peer"
    suffix = {
        "wg": f"{safe}.conf",
        "clash": f"{safe}-clash.yaml",
        "clashfull": f"{safe}-clash-full.yaml",
        "sr": f"{safe}-shadowrocket.txt",
        "wst": f"{safe}-wstunnel.conf",
    }
    return suffix.get((fmt or "wg").lower(), f"{safe}.conf")
