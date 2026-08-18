"""Guards for panel-originated HTTP: local origins and no redirects.

Several services take an operator-edited URL and then GET/POST it from the
panel process (Ollama, Immich, PhotosHub, notify webhooks).  Validating the
scheme up front is not enough: urllib follows 30x by default and will take
custom headers (API keys, webhook tokens) with it.  A public hostname is
also not a home daemon.

Decision is from the literal hostname, never DNS.
"""
from __future__ import annotations

import ipaddress
import re
import urllib.error
import urllib.request
from urllib.parse import urlsplit

_PRIVATE_SUFFIXES = (".local", ".lan", ".internal", ".home", ".arpa")
_BLOCKED_HOSTS = frozenset({
    "metadata",
    "metadata.google.internal",
})
_BLOCKED_IPS = frozenset({
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("fd00:ec2::254"),
})
_LOOPBACK_NAMES = frozenset({"localhost", "127.0.0.1", "::1"})
_HEX_HOST = re.compile(r"^0x[0-9a-f]+$")


def _ip_from_host(host: str):
    """Parse *host* as an IP, including integer/hex IPv4 and IPv4-mapped IPv6.

    ``http://2852039166/`` is 169.254.169.254 (cloud metadata) written as a
    decimal dword.  ``ipaddress`` rejects that spelling, so the hostname
    branch used to treat it as a single-label LAN name and allow it.
    """
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is None:
        n = None
        if host.isdigit():
            n = int(host)
        elif _HEX_HOST.match(host):
            n = int(host, 16)
        if n is None or n < 0 or n > 0xFFFFFFFF:
            return None
        ip = ipaddress.IPv4Address(n)
    mapped = getattr(ip, "ipv4_mapped", None)
    return mapped if mapped is not None else ip


def _ip_is_local(ip) -> bool:
    if ip.is_loopback:
        return True
    if (
        ip in _BLOCKED_IPS
        or ip.is_unspecified
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_link_local
    ):
        return False
    return bool(ip.is_private)


class RedirectRefused(urllib.error.URLError):
    """The peer tried to 30x.  Local-daemon and token-bearing clients must not follow it."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RedirectRefused(f"redirect to {newurl} refused")


def no_redirect_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(NoRedirect)


def is_local_http_origin(raw: str) -> bool:
    return local_http_origin(raw) is not None


def local_http_origin(raw: str) -> str | None:
    """Return the origin with no trailing slash, or None if it is not local.

    Allowed: loopback, RFC1918 / ULA, single-label LAN names, and
    ``*.local`` / ``*.lan`` / ``*.internal`` / ``*.home`` / ``*.arpa``.
    Rejected: public DNS, public IPs, link-local, multicast, unspecified,
    reserved, and well-known cloud metadata addresses.
    """
    text = str(raw or "").strip()
    parts = urlsplit(text)
    host = (parts.hostname or "").strip("[]").lower()
    if parts.scheme not in ("http", "https") or not host:
        return None
    if host in _BLOCKED_HOSTS:
        return None
    if host in _LOOPBACK_NAMES:
        return text.rstrip("/")
    ip = _ip_from_host(host)
    if ip is not None:
        return text.rstrip("/") if _ip_is_local(ip) else None
    if host.endswith(_PRIVATE_SUFFIXES):
        return text.rstrip("/")
    # Compose / mDNS single-label names ("immich", "nas").  A host with no
    # letter is an integer IP we failed to classify, not a LAN name.
    if "." not in host and ":" not in host and any(c.isalpha() for c in host):
        return text.rstrip("/")
    return None


def is_allowed_webhook_url(raw: str) -> bool:
    """True when a notify webhook may leave the panel.

    Discord / Slack / ntfy live on the public internet, so this is not
    :func:`local_http_origin`.  Cloud metadata and link-local addresses
    are still SSRF, including decimal / hex / IPv4-mapped spellings.
    """
    text = str(raw or "").strip()
    parts = urlsplit(text)
    host = (parts.hostname or "").strip("[]").lower()
    if parts.scheme not in ("http", "https") or not host:
        return False
    if host in _BLOCKED_HOSTS:
        return False
    ip = _ip_from_host(host)
    if ip is None:
        return True
    if (
        ip in _BLOCKED_IPS
        or ip.is_unspecified
        or ip.is_multicast
        or ip.is_link_local
    ):
        return False
    return True
