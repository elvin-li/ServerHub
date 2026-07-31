"""Central host-address discovery and configuration-template expansion."""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import threading
import time
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from hub.util import sh

_AUTO_VALUES = {"", "auto", "automatic", "dhcp", "dynamic"}
_VAR_RE = re.compile(r"\$?\{([A-Za-z][A-Za-z0-9_.-]{0,63})\}")
_cache_lock = threading.Lock()
_detect_cache: dict[str, Any] = {"t": 0.0, "value": None}
_DETECT_TTL = 30.0


def configured_host() -> str:
    """Return the configured host selector; auto means route discovery."""
    env_value = (
        os.environ.get("SERVERHUB_HOST")
        or os.environ.get("SERVERHUB_HOST_IP")
        or ""
    ).strip()
    if env_value:
        return env_value
    try:
        from hub.config import cfg

        return str((cfg().get("settings") or {}).get("host_ip") or "auto").strip()
    except Exception:
        return "auto"


def _usable_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address((value or "").strip())
    except ValueError:
        return False
    return not (address.is_loopback or address.is_unspecified or address.is_link_local)


def default_interface() -> str:
    rc, output, _ = sh(["/sbin/route", "-n", "get", "default"], timeout=3)
    if rc != 0:
        return ""
    match = re.search(r"^\s*interface:\s*(\S+)", output, re.MULTILINE)
    return match.group(1) if match else ""


def detect_lan_ip(*, force: bool = False) -> str:
    """Detect the active LAN address without embedding a network-specific IP."""
    now = time.time()
    with _cache_lock:
        if (
            not force
            and _detect_cache["value"]
            and now - float(_detect_cache["t"]) < _DETECT_TTL
        ):
            return str(_detect_cache["value"])

    candidates: list[str] = []
    interface = default_interface()
    if interface:
        rc, output, _ = sh(["/usr/sbin/ipconfig", "getifaddr", interface], timeout=3)
        if rc == 0 and output:
            candidates.append(output.strip())
    try:
        candidates.extend(
            item[4][0]
            for item in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
        )
    except OSError:
        pass

    value = next((candidate for candidate in candidates if _usable_address(candidate)), "")
    if not value:
        local_name = socket.gethostname().strip()
        value = local_name if local_name else "localhost"
    with _cache_lock:
        _detect_cache.update(t=now, value=value)
    return value


def host_ip() -> str:
    """Return the configured host or the currently detected LAN address."""
    value = configured_host()
    if value.lower() not in _AUTO_VALUES:
        return value
    return detect_lan_ip()


def template_variables(extra: dict[str, Any] | None = None) -> dict[str, str]:
    host = host_ip()
    values = {"host": host, "host_ip": host, "localhost": "localhost"}
    try:
        from hub.config import cfg

        address_book = (cfg().get("settings") or {}).get("address_book") or {}
        values.update({
            str(key): str(value)
            for key, value in address_book.items()
            if value is not None
        })
    except Exception:
        pass
    if extra:
        values.update({
            str(key): str(value)
            for key, value in extra.items()
            if value is not None
        })
    return values


def resolve_template(value: str | None, extra: dict[str, Any] | None = None) -> str | None:
    """Expand host and named address-book variables."""
    if value is None or not isinstance(value, str) or "{" not in value:
        return value
    variables = template_variables(extra)
    return _VAR_RE.sub(lambda match: variables.get(match.group(1), match.group(0)), value)


def resolve_value(value: Any, extra: dict[str, Any] | None = None) -> Any:
    """Recursively expand address templates at API/use boundaries."""
    if isinstance(value, str):
        return resolve_template(value, extra)
    if isinstance(value, list):
        return [resolve_value(item, extra) for item in value]
    if isinstance(value, tuple):
        return tuple(resolve_value(item, extra) for item in value)
    if isinstance(value, dict):
        return {key: resolve_value(item, extra) for key, item in value.items()}
    return value


def normalize_local_url(value: str | None) -> str:
    """Store local URLs with {host} so DHCP/interface changes do not stale them."""
    raw = (value or "").strip()
    if not raw or "{host}" in raw:
        return raw
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return raw
    if not parsed.scheme or not parsed.hostname or parsed.username or parsed.password:
        return raw
    try:
        port = parsed.port
    except ValueError:
        return raw
    local_names = {
        "localhost",
        "127.0.0.1",
        "::1",
        host_ip().lower(),
        socket.gethostname().lower(),
    }
    hostname = parsed.hostname.lower()
    if hostname not in local_names:
        return raw
    netloc = "{host}" + (f":{port}" if port else "")
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))
