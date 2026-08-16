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
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        # Loopback first: Python marks ``::1`` as reserved as well as
        # loopback, so a reserved check ahead of this would reject
        # ``http://[0:0:0:0:0:0:0:1]``.
        if ip.is_loopback:
            return text.rstrip("/")
        if (
            ip in _BLOCKED_IPS
            or ip.is_unspecified
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_link_local
        ):
            return None
        if ip.is_private:
            return text.rstrip("/")
        return None
    if host.endswith(_PRIVATE_SUFFIXES) or ("." not in host and ":" not in host):
        return text.rstrip("/")
    return None
