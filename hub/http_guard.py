"""Guards for panel-originated HTTP: local origins and no redirects.

Several services take an operator-edited URL and then GET/POST it from the
panel process (Ollama, Immich, PhotosHub, notify webhooks).  Validating the
scheme up front is not enough: urllib follows 30x by default and will take
custom headers (API keys, webhook tokens) with it.  A public hostname is
also not a home daemon.

Decision is from the literal hostname, never DNS.
"""
from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
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
    ipaddress.ip_address("100.100.100.200"),  # Alibaba IMDS
    ipaddress.ip_address("192.0.0.192"),      # Oracle IMDS
    ipaddress.ip_address("168.63.129.16"),    # Azure WireServer / IMDS
})
_LOOPBACK_NAMES = frozenset({"localhost", "127.0.0.1", "::1"})
_HEX_HOST = re.compile(r"^0x[0-9a-f]+$")


def _ip_from_host(host: str):
    """Parse *host* as an IP, including integer/hex IPv4 and IPv4-mapped IPv6.

    ``http://2852039166/`` is 169.254.169.254 (cloud metadata) written as a
    decimal dword.  ``ipaddress`` rejects that spelling, so the hostname
    branch used to treat it as a single-label LAN name and allow it.
    """
    if not isinstance(host, str):
        return None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is None:
        n = None
        try:
            if host.isascii() and host.isdigit():
                # Unicode digits pass isdigit() (``١٢٣`` → 123) and used to
                # become 0.0.0.123, a leftover "local" origin.  Non-ASCII
                # superscripts that pass isdigit() ValueError ``int()``.
                n = int(host)
            elif _HEX_HOST.match(host):
                n = int(host, 16)
        except (TypeError, ValueError, OverflowError):
            n = None
        if n is None or n < 0 or n > 0xFFFFFFFF:
            # libc accepts 127.1 / 0177.0.0.1; ipaddress does not.
            # inet_aton raises OSError for junk, ValueError for an embedded
            # NUL, and UnicodeEncodeError (a ValueError) for a lone surrogate.
            # Notify save used to 500 those after torn IPv6 was already caught.
            try:
                ip = ipaddress.IPv4Address(socket.inet_aton(host))
            except (OSError, TypeError, ValueError):
                return None
        else:
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
    # Empty ProxyHandler replaces the env-proxy default so HTTP_PROXY cannot
    # take a token-bearing notify POST to a resolver we did not check.
    return urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}))


def is_local_http_origin(raw: str) -> bool:
    return local_http_origin(raw) is not None


def _coerce_text(value) -> str | None:
    """*value* as an exact ``str`` for parsing, or ``None`` when it cannot be.

    The bare ``str(raw or "")`` these helpers used reflected into the
    leftover itself: an over-cap YAML hex/octal int raised CPython's
    4300-digit ``str()`` ValueError, and a subclass ``__bool__``/``__str__``
    bomb raised whatever it liked — either escaped every gate built on
    :func:`_url_parts` / :func:`_utf8_host` instead of answering "not a
    URL / not a hostname".
    """
    if value is None:
        return ""
    if isinstance(value, str):
        if type(value) is str:
            return value
        try:
            # Base copy through the C-level storage so a subclass
            # ``__str__``/``encode`` override cannot fire downstream.
            return str.__str__(value)
        except Exception:
            return None
    if isinstance(value, (bytes, bytearray)):
        try:
            return bytes(value).decode("utf-8", "replace")
        except Exception:
            return None
    try:
        return str(value)
    except Exception:
        return None


def _utf8_host(host: str) -> str | None:
    """Strip brackets and reject leftovers that cannot be a hostname.

    NUL was already refused; leftover ``\\ud800`` still passed the LAN-name
    branch of :func:`local_connect_peer` / :func:`notify_connect_peer` and
    500'd the later UTF-8 encode (or ``create_connection``).
    """
    host = _coerce_text(host)
    if host is None:
        return None
    host = host.strip("[]").lower()
    if not host or "\x00" in host:
        return None
    try:
        host.encode("utf-8")
    except UnicodeEncodeError:
        return None
    return host


def _url_parts(raw: str):
    """``urlsplit`` plus hostname, or ``None`` when the leftover is not a URL.

    ``urlsplit('http://[::1')`` and ``http://[]`` raise ValueError on 3.12.
    Notify save used to 500 POST /api/alerts/channels on a torn IPv6 paste.
    """
    text = _coerce_text(raw)
    if text is None:
        return None
    text = text.strip()
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        # Leftover ``\\ud800`` in the path of an otherwise-local URL used to
        # return an origin Starlette could not UTF-8 encode.
        return None
    try:
        parts = urlsplit(text)
        host = (parts.hostname or "").strip("[]").lower()
        # .port re-parses the netloc tail lazily: a nonnumeric or
        # out-of-range port ("http://127.0.0.1:x", ":-1", ":99999") passed
        # every gate built on this helper, so PUT /api/settings persisted an
        # ollama.url that urllib can never dial (http.client.InvalidURL on
        # every later probe) and whose ``urlsplit(base_url()).port`` read
        # ValueError'd ollama health_checks() outside its try — collapsing
        # every Ollama health row into one generic "check failed".  Same
        # probe-at-validation rule as catalog_remote.validate_source_url.
        parts.port
    except (ValueError, UnicodeError):
        return None
    if "\x00" in text or "\x00" in host:
        return None
    return text, parts, host


def local_http_origin(raw: str) -> str | None:
    """Return the origin with no trailing slash, or None if it is not local.

    Allowed: loopback, RFC1918 / ULA, single-label LAN names, and
    ``*.local`` / ``*.lan`` / ``*.internal`` / ``*.home`` / ``*.arpa``.
    Rejected: public DNS, public IPs, link-local, multicast, unspecified,
    reserved, and well-known cloud metadata addresses.
    """
    parsed = _url_parts(raw)
    if parsed is None:
        return None
    text, parts, host = parsed
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


def is_allowed_webhook_url(raw: str, *, resolve: bool = True) -> bool:
    """True when a notify webhook may leave the panel.

    Discord / Slack / ntfy live on the public internet, so this is not
    :func:`local_http_origin`.  Cloud metadata and link-local addresses
    are still SSRF, including decimal / hex / IPv4-mapped spellings.

    ``resolve=False`` is the send-path shape check: scheme, blocked
    names, and literal IPs only.  The send then calls
    :func:`notify_connect_peer` once and pins TCP to that IP, so a
    second ``getaddrinfo`` cannot rebind to metadata.
    """
    parsed = _url_parts(raw)
    if parsed is None:
        return False
    _text, parts, host = parsed
    if parts.scheme not in ("http", "https") or not host:
        return False
    if host in _BLOCKED_HOSTS:
        return False
    if not resolve and _ip_from_host(host) is None:
        return True
    return is_allowed_notify_host(host, resolve_required=False)


def is_allowed_notify_host(host: str, *, resolve_required: bool = False) -> bool:
    """True when a webhook/SMTP host is not cloud metadata or link-local.

    ``resolve_required`` is for the send path: a resolver blip at save time
    must not reject Discord/ntfy, but sending must not proceed when DNS
    cannot be checked (the later connect would be an unchecked lookup).
    """
    host = _utf8_host(host)
    if not host:
        return False
    if host in _BLOCKED_HOSTS:
        return False
    ip = _ip_from_host(host)
    if ip is not None:
        return not _webhook_ip_blocked(ip)
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        infos = []
    except (UnicodeError, ValueError):
        # Lone surrogates / illegal IDNA — not a resolver blip.  Used to
        # 500 notify save after inet_aton was already guarded.
        return False
    if not infos:
        # Public hosts must not skip the check on a resolver blip (the
        # later connect would be an unchecked lookup).  LAN names such as
        # ha.lan are allowed without DNS — Home Assistant lives there.
        if resolve_required and not (
            host.endswith(_PRIVATE_SUFFIXES)
            or ("." not in host and ":" not in host and any(c.isalpha() for c in host))
        ):
            return False
        return True
    return all(
        not _webhook_ip_blocked(_ip_from_host(item[4][0]))
        for item in infos
    )


def local_connect_peer(host: str) -> str | None:
    """Socket peer for a LAN-only daemon (Immich, Ollama), or ``None``.

    Unlike :func:`notify_connect_peer`, every resolved address must be
    loopback or RFC1918/ULA.  A public or metadata A record refuses the
    send even when the typed hostname looked local.  Unresolved
    ``.lan`` / single-label names are returned as themselves so the
    later connect does the only lookup.
    """
    host = _utf8_host(host)
    if not host or host in _BLOCKED_HOSTS:
        return None
    ip = _ip_from_host(host)
    if ip is not None:
        return format(ip) if _ip_is_local(ip) else None
    try:
        infos = socket.getaddrinfo(host, None)
    except (OSError, UnicodeError, ValueError):
        infos = []
    if not infos:
        if host.endswith(_PRIVATE_SUFFIXES) or (
            "." not in host and ":" not in host and any(c.isalpha() for c in host)
        ):
            return host
        return None
    peers: list[str] = []
    for item in infos:
        cand = _ip_from_host(item[4][0])
        if cand is None or not _ip_is_local(cand):
            return None
        text = format(cand)
        if text not in peers:
            peers.append(text)
    return peers[0] if peers else None


def notify_connect_peer(host: str) -> str | None:
    """Socket peer for a notify send, or ``None`` if the send must not proceed.

    When DNS answered, this is one allowed IP — the caller must connect to
    that address rather than resolving again (a second ``getaddrinfo`` is
    the DNS-rebinding hole).  An unresolved LAN name is returned as itself
    so the later connect does the only lookup.  Public hosts that do not
    resolve, and any name with a metadata / link-local record, return
    ``None``.
    """
    host = _utf8_host(host)
    if not host or host in _BLOCKED_HOSTS:
        return None
    ip = _ip_from_host(host)
    if ip is not None:
        return None if _webhook_ip_blocked(ip) else format(ip)
    try:
        infos = socket.getaddrinfo(host, None)
    except (OSError, UnicodeError, ValueError):
        infos = []
    if not infos:
        if host.endswith(_PRIVATE_SUFFIXES) or (
            "." not in host and ":" not in host and any(c.isalpha() for c in host)
        ):
            return host
        return None
    peers: list[str] = []
    for item in infos:
        cand = _ip_from_host(item[4][0])
        if cand is None:
            continue
        if _webhook_ip_blocked(cand):
            return None
        text = format(cand)
        if text not in peers:
            peers.append(text)
    return peers[0] if peers else None


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """``HTTPConnection`` that dials ``dest_ip`` but keeps ``Host`` as ``host``."""

    def __init__(self, *args, dest_ip=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._dest_ip = dest_ip

    def connect(self):
        self.sock = socket.create_connection(
            (self._dest_ip or self.host, self.port), self.timeout,
        )
        if self._tunnel_host:
            self._tunnel()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Same pin as :class:`_PinnedHTTPConnection`, with SNI on the hostname."""

    def __init__(self, *args, dest_ip=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._dest_ip = dest_ip

    def connect(self):
        sock = socket.create_connection(
            (self._dest_ip or self.host, self.port), self.timeout,
        )
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
            sock = self.sock
        context = self._context or ssl.create_default_context()
        self.sock = context.wrap_socket(sock, server_hostname=self.host)


class PinnedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, dest_ip: str):
        super().__init__()
        self._dest_ip = dest_ip

    def http_open(self, req):
        dest_ip = self._dest_ip

        def factory(*args, **kwargs):
            return _PinnedHTTPConnection(*args, dest_ip=dest_ip, **kwargs)

        return self.do_open(factory, req)


class PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, dest_ip: str, context=None):
        super().__init__(context=context)
        self._dest_ip = dest_ip

    def https_open(self, req):
        dest_ip = self._dest_ip
        context = self._context

        def factory(*args, **kwargs):
            kwargs.setdefault("context", context)
            return _PinnedHTTPSConnection(*args, dest_ip=dest_ip, **kwargs)

        return self.do_open(factory, req)


def pinned_no_redirect_opener(dest_ip: str) -> urllib.request.OpenerDirector:
    """No-redirect opener whose TCP peer is *dest_ip* (Host/SNI stay on the URL)."""
    return urllib.request.build_opener(
        NoRedirect,
        urllib.request.ProxyHandler({}),
        PinnedHTTPHandler(dest_ip),
        PinnedHTTPSHandler(dest_ip),
    )


def _webhook_ip_blocked(ip) -> bool:
    if ip is None:
        return False
    return (
        ip in _BLOCKED_IPS
        or ip.is_unspecified
        or ip.is_multicast
        or ip.is_link_local
    )
