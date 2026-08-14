"""Outbound URL checks shared by bookmark probes and notify webhooks.

Two different decisions live here and must stay separate:

* **Literal LAN classification** (:func:`is_lan_host`) decides whether TLS
  verification may be skipped.  It must never consult DNS -- fake-IP proxies
  and split-horizon resolvers map public names into private-looking ranges.
* **Resolved destination checks** (:func:`resolved_probe_blocked`,
  :func:`outbound_url_allowed`) decide whether a socket may be opened at all.
  Those *do* resolve, so a hostname that rebinds to loopback, link-local, or
  (for public names) RFC1918 cannot turn the panel into an SSRF client.
"""
from __future__ import annotations

import ipaddress
import socket
import urllib.parse

_ALLOWED_SCHEMES = frozenset({"http", "https"})

_PRIVATE_SUFFIXES = (".local", ".lan", ".internal", ".home", ".arpa")

_BLOCKED_NAMES = frozenset({
    "localhost",
    "metadata",
    "metadata.google.internal",
})


def _normalize_host(host: str) -> str:
    return (host or "").strip().strip("[]").lower()


def is_blocked_literal_host(host: str) -> bool:
    """Loopback, link-local (including IMDS), unspecified, and known IMDS names."""
    name = _normalize_host(host)
    if not name or name in _BLOCKED_NAMES:
        return True
    try:
        addr = ipaddress.ip_address(name)
    except ValueError:
        return False
    return bool(addr.is_loopback or addr.is_link_local or addr.is_unspecified)


def is_lan_host(host: str) -> bool:
    """Literal LAN name (RFC1918 / .local / short name).  Never resolves DNS."""
    name = _normalize_host(host)
    if not name or is_blocked_literal_host(name):
        return False
    if name.endswith(_PRIVATE_SUFFIXES):
        return True
    try:
        addr = ipaddress.ip_address(name)
    except ValueError:
        return "." not in name
    return bool(addr.is_private)


def _resolved_ips(host: str) -> list[ipaddress._BaseAddress] | None:
    """Resolved A/AAAA addresses, or None when the name cannot be resolved."""
    name = _normalize_host(host)
    if not name:
        return None
    try:
        return [ipaddress.ip_address(name)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return None
    out: list[ipaddress._BaseAddress] = []
    for info in infos:
        try:
            out.append(ipaddress.ip_address(info[4][0]))
        except (ValueError, IndexError, TypeError):
            continue
    return out or None


def _addr_is_probe_forbidden(addr: ipaddress._BaseAddress, *, allow_private: bool) -> bool:
    if addr.is_loopback or addr.is_link_local or addr.is_unspecified:
        return True
    if not allow_private and addr.is_private:
        return True
    return False


def resolved_probe_blocked(host: str) -> bool:
    """True when a bookmark probe must not open a socket to *host*.

    Literal loopback / link-local / IMDS names are blocked without DNS.
    Public DNS names are fail-closed on resolve errors, and any resolved
    address that is loopback, link-local, unspecified, or RFC1918 is refused
    (DNS rebinding).  LAN names may resolve to RFC1918 but still not to
    loopback / link-local / unspecified; an unresolved LAN name is allowed
    through so mDNS (``.local``) keeps working when the resolver is quiet.
    """
    name = _normalize_host(host)
    if is_blocked_literal_host(name):
        return True
    allow_private = is_lan_host(name)
    addrs = _resolved_ips(name)
    if addrs is None:
        # Public names fail closed. Unresolved LAN names pass: home ``.local``
        # names often only answer via mDNS, and refusing them here would turn
        # every NAS bookmark gray on a quiet resolver.
        return not allow_private
    return any(_addr_is_probe_forbidden(a, allow_private=allow_private) for a in addrs)


def outbound_url_allowed(url: str, *, allow_loopback: bool = True) -> tuple[bool, str]:
    """Whether an operator-configured notify/webhook URL may be fetched.

    Home Assistant defaults to ``http://localhost:8123``, so loopback is
    allowed here.  Link-local / IMDS destinations are never allowed, schemes
    outside http(s) are refused, and public names that rebind onto link-local
    or IMDS are refused after resolve.
    """
    text = (url or "").strip()
    if not text:
        return False, "empty url"
    parts = urllib.parse.urlsplit(text)
    scheme = (parts.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        return False, f"unsupported scheme: {scheme or 'none'}"
    host = parts.hostname or ""
    name = _normalize_host(host)
    if not name:
        return False, "missing host"
    if name in _BLOCKED_NAMES and name != "localhost":
        return False, "blocked host"
    try:
        literal = ipaddress.ip_address(name)
    except ValueError:
        literal = None
    if literal is not None:
        if literal.is_link_local or literal.is_unspecified:
            return False, "blocked host"
        if literal.is_loopback and not allow_loopback:
            return False, "blocked host"
        return True, ""
    if name == "localhost":
        return (True, "") if allow_loopback else (False, "blocked host")
    addrs = _resolved_ips(name)
    if addrs is None:
        return False, "unresolved host"
    for addr in addrs:
        if addr.is_link_local or addr.is_unspecified:
            return False, "blocked host"
        if addr.is_loopback and not allow_loopback:
            return False, "blocked host"
    return True, ""
