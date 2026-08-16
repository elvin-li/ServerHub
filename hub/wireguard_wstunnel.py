"""WireGuard obfuscation via wstunnel.

UDP WireGuard is easy to fingerprint and drop.  This host runs a
``wstunnel server`` in front of ``wg0`` so clients can wrap the handshake in a
plain WebSocket on TCP 8444.  The panel has to know that layout: the Network
page's ``lsof`` listing is unprivileged and cannot see a root listener, and
exported peer configs still pointed at the raw UDP port.

Persisted fields live in ``settings.wireguard``.  :func:`status` reports both
the operator's intent and what is actually running, because those diverge the
moment the LAN address in ``--restrict-to`` moves — which is why a loopback
restrict-to is the stable end state.
"""
from __future__ import annotations

import ipaddress
import plistlib
import re
import shlex
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from hub.util import sh, ttl_memo

LABEL = "com.elvin.wstunnel-wg-server"
PLIST_PATH = Path("/Library/LaunchDaemons") / f"{LABEL}.plist"
DEFAULT_LISTEN = "ws://0.0.0.0:8444"
LOG_OUT = "/var/log/wstunnel-wg-server.log"
LOG_ERR = "/var/log/wstunnel-wg-server.err.log"

#: Only these binaries may be written into a root LaunchDaemon.
ALLOWED_BINARIES = (
    "/opt/homebrew/bin/wstunnel",
    "/usr/local/bin/wstunnel",
)

_LISTEN_RE = re.compile(
    r"^(?P<scheme>wss?|https?)://"
    r"(?P<host>\[[0-9A-Fa-f:]+\]|[^/:]+)"
    r":(?P<port>\d{1,5})$"
)
_INET_RE = re.compile(r"\binet (\d+\.\d+\.\d+\.\d+)\b")
_UNSAFE = re.compile(r"[\s;|&$`\\\"'<>]")
_LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost"})


def listen_parts(value: str) -> tuple[str, str, str]:
    """``(scheme, host, port)`` from a ``ws[s]://host:port`` listen URL."""
    match = _LISTEN_RE.match(str(value or "").strip())
    if not match:
        return "", "", ""
    host = match.group("host")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return match.group("scheme"), host, match.group("port")


def valid_listen_url(value: str) -> bool:
    """Whether *value* is a bindable or dialable wstunnel URL with a port.

    No path, userinfo or query: those would be copied into a shell command the
    operator is expected to paste onto a phone.
    """
    raw = str(value or "").strip()
    if not raw or _UNSAFE.search(raw):
        return False
    scheme, host, port = listen_parts(raw)
    if not scheme or not host or not port:
        return False
    if not (1 <= int(port) <= 65535):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(re.match(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$", host))


def parse_argv(argv: list[str]) -> dict[str, str]:
    """Pull ``listen`` and the first ``--restrict-to`` out of a server argv."""
    listen = ""
    restrict_to = ""
    tokens = [str(part) for part in (argv or [])]
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token == "--restrict-to" and i + 1 < len(tokens):
            if not restrict_to:
                restrict_to = tokens[i + 1].strip()
            i += 2
            continue
        if token.startswith(("ws://", "wss://", "http://", "https://")):
            listen = token.strip()
        i += 1
    return {"listen": listen, "restrict_to": restrict_to}


def parse_process_table(text: str) -> dict[str, Any]:
    """Find a ``wstunnel server`` row in ``ps -ax -o pid=,command=`` output."""
    for line in (text or "").splitlines():
        raw = line.strip()
        if not raw:
            continue
        pid_s, _, command = raw.partition(" ")
        if not pid_s.isdigit() or "wstunnel" not in command:
            continue
        try:
            argv = shlex.split(command)
        except ValueError:
            continue
        names = {Path(part).name for part in argv}
        if "wstunnel" not in names or "server" not in argv:
            continue
        parsed = parse_argv(argv)
        parsed["pid"] = int(pid_s)
        parsed["running"] = True
        parsed["binary"] = next((part for part in argv if Path(part).name == "wstunnel"), "")
        return parsed
    return {"listen": "", "restrict_to": "", "pid": 0, "running": False, "binary": ""}


def read_plist(path: Path | None = None) -> dict[str, str]:
    """``listen`` / ``restrict_to`` from the LaunchDaemon, if readable."""
    target = path or PLIST_PATH
    try:
        data = plistlib.loads(target.read_bytes())
    except (OSError, plistlib.InvalidFileException, ValueError):
        return {"listen": "", "restrict_to": ""}
    argv = data.get("ProgramArguments") or []
    if not isinstance(argv, list):
        return {"listen": "", "restrict_to": ""}
    return parse_argv([str(part) for part in argv])


@ttl_memo(6.0)
def live(ps_text: str | None = None) -> dict[str, Any]:
    """Running server first, then the on-disk plist, then empty.

    Memoised so the Network overview and the WireGuard status poll, which
    both call this in the same few seconds, share one ``ps``.
    """
    if ps_text is None:
        _rc, ps_text, _err = sh(["/bin/ps", "-ax", "-o", "pid=,command="], timeout=5)
    found = parse_process_table(ps_text or "")
    plist = read_plist()
    if not found.get("listen"):
        found["listen"] = plist.get("listen") or ""
    if not found.get("restrict_to"):
        found["restrict_to"] = plist.get("restrict_to") or ""
    found["plist"] = str(PLIST_PATH) if PLIST_PATH.is_file() else ""
    return found


@ttl_memo(6.0)
def local_ipv4s() -> frozenset[str]:
    """IPv4 addresses currently on this host, for stale ``--restrict-to`` checks."""
    rc, out, _err = sh(["/sbin/ifconfig", "-a"], timeout=5)
    if rc != 0:
        return frozenset()
    return frozenset(_INET_RE.findall(out or ""))


def find_binary() -> str:
    """First allowed wstunnel binary that exists on disk."""
    for path in ALLOWED_BINARIES:
        if Path(path).is_file():
            return path
    return ""


def rewrite_listen_host(listen: str, host: str) -> str:
    """Keep scheme and port from *listen*, replace the bind address with *host*."""
    scheme, _bind, port = listen_parts(listen)
    public_host = str(host or "").strip()
    if not scheme or not port or not public_host:
        return ""
    if ":" in public_host and not public_host.startswith("["):
        public_host = f"[{public_host}]"
    return f"{scheme}://{public_host}:{port}"


def public_url(listen: str, endpoint: str) -> str:
    """Client-facing URL: same port as the server bind, host from the WG endpoint."""
    raw_endpoint = str(endpoint or "").strip()
    if not raw_endpoint:
        return ""
    if raw_endpoint.startswith("["):
        host, _, _rest = raw_endpoint.partition("]")
        host = host[1:]
    elif raw_endpoint.count(":") == 1:
        host, _, _port = raw_endpoint.partition(":")
    else:
        host = raw_endpoint
    return rewrite_listen_host(listen, host)


def client_command(*, public: str, restrict_to: str, local_port: int | str) -> str:
    """The argv a client runs before bringing its WireGuard interface up.

    Local UDP *local_port* is what the generated ``Endpoint = 127.0.0.1:…``
    line dials.  The remote half of ``-L`` must equal the server's
    ``--restrict-to`` or the server drops the tunnel.
    """
    dest = str(restrict_to or "").strip()
    url = str(public or "").strip()
    try:
        port = int(local_port)
    except (TypeError, ValueError):
        port = 0
    if not dest or not url or not (1 <= port <= 65535):
        return ""
    if _UNSAFE.search(dest) or _UNSAFE.search(url):
        return ""
    return f"wstunnel client -L udp://127.0.0.1:{port}:{dest} {url}"


def local_endpoint(local_port: int | str) -> str:
    """``127.0.0.1:port`` the obfuscated WireGuard config should dial."""
    try:
        port = int(local_port)
    except (TypeError, ValueError):
        return ""
    if not (1 <= port <= 65535):
        return ""
    return f"127.0.0.1:{port}"


def default_restrict_to(listen_port: int | str) -> str:
    """Loopback target: WireGuard is on this Mac, so the LAN IP must not appear."""
    endpoint = local_endpoint(listen_port)
    return endpoint or ""


def restrict_host(restrict_to: str) -> str:
    raw = str(restrict_to or "").strip()
    if raw.startswith("["):
        host, _, _rest = raw.partition("]")
        return host[1:]
    if raw.count(":") == 1:
        return raw.split(":", 1)[0]
    return raw


def valid_restrict_to(value: str) -> bool:
    """``host:port`` (or ``[v6]:port``) safe to paste into ``--restrict-to``."""
    raw = str(value or "").strip()
    if not raw or _UNSAFE.search(raw):
        return False
    if raw.startswith("["):
        _host, _, rest = raw.partition("]")
        port = rest.lstrip(":").strip()
    elif raw.count(":") == 1:
        port = raw.split(":", 1)[1]
    else:
        return False
    if not (port.isdigit() and 1 <= int(port) <= 65535):
        return False
    host = restrict_host(raw)
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(re.match(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$", host))


def restrict_is_stable(restrict_to: str) -> bool:
    """Loopback never moves when the Mac changes LAN address."""
    return restrict_host(restrict_to) in _LOOPBACK


def restrict_is_stale(restrict_to: str, addresses: frozenset[str] | None = None) -> bool:
    """True when ``--restrict-to`` names an IPv4 that is not on this host.

    An empty address set means the probe failed, not that the host has no
    addresses — do not alarm on a question we could not answer.
    """
    host = restrict_host(restrict_to)
    if not host or host in _LOOPBACK:
        return False
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        return False
    present = local_ipv4s() if addresses is None else addresses
    if not present:
        return False
    return host not in present


def render_plist(*, binary: str, listen: str, restrict_to: str) -> str:
    """LaunchDaemon body.  Paths are pinned; values must already be validated."""
    if binary not in ALLOWED_BINARIES:
        raise ValueError("wstunnel binary is not on the allow-list")
    if not valid_listen_url(listen):
        raise ValueError("invalid wstunnel listen URL")
    if not valid_restrict_to(restrict_to):
        raise ValueError("invalid wstunnel restrict-to")
    body = plistlib.dumps(
        {
            "Label": LABEL,
            "ProgramArguments": [
                binary, "server", "--restrict-to", restrict_to, listen,
            ],
            "RunAtLoad": True,
            "KeepAlive": True,
            "StandardOutPath": LOG_OUT,
            "StandardErrorPath": LOG_ERR,
        },
        fmt=plistlib.FMT_XML,
        sort_keys=False,
    )
    return body.decode("utf-8")


def status(settings: dict | None = None) -> dict[str, Any]:
    """Operator intent, live process, and whether those two still agree.

    Client export uses the *live* restrict-to while the server is up: a
    generated command that names a dest the running process will refuse is
    worse than a slightly-unstable LAN address that still works today.
    """
    cfg = dict(settings or {})
    found = live()
    try:
        listen_port = int(cfg.get("listen_port") or 0)
    except (TypeError, ValueError):
        listen_port = 0
    desired_listen = str(cfg.get("wstunnel_listen") or DEFAULT_LISTEN)
    desired_restrict = str(cfg.get("wstunnel_restrict_to") or "") or default_restrict_to(
        listen_port
    )
    live_listen = str(found.get("listen") or "")
    live_restrict = str(found.get("restrict_to") or "")
    running = bool(found.get("running"))
    # Export dest must match the process that will accept it.
    restrict_to = live_restrict if running and live_restrict else desired_restrict
    listen = live_listen if running and live_listen else desired_listen
    stored_public = str(cfg.get("wstunnel_public") or "")
    public = stored_public or public_url(listen, str(cfg.get("endpoint") or ""))
    _scheme, _host, port = listen_parts(listen)
    if not listen_port:
        listen_port = int(port) if str(port).isdigit() else 0
    enabled = bool(cfg.get("wstunnel_enabled"))
    binary = str(found.get("binary") or "") or find_binary()
    aligned = (not running) or (
        live_listen == desired_listen and live_restrict == desired_restrict
    )
    addresses = local_ipv4s()
    stable = restrict_is_stable(restrict_to)
    stale = restrict_is_stale(restrict_to, addresses)
    # Default listen is always filled by settings(); it does not mean the
    # operator turned this on.  A live process or an explicit public/restrict
    # value does.
    configured = bool(
        enabled
        or running
        or found.get("listen")
        or found.get("plist")
        or str(cfg.get("wstunnel_public") or "").strip()
        or str(cfg.get("wstunnel_restrict_to") or "").strip()
    )
    needs_stabilize = enabled and (not stable or stale)
    needs_apply = enabled and (not running or not aligned)
    return {
        "enabled": enabled,
        "configured": configured,
        "running": running,
        "pid": int(found.get("pid") or 0),
        "listen": listen,
        "desired_listen": desired_listen,
        "public": public,
        "restrict_to": restrict_to,
        "desired_restrict_to": desired_restrict,
        "suggest_restrict_to": default_restrict_to(listen_port),
        "port": int(port) if str(port).isdigit() else 0,
        "local_port": listen_port,
        "local_endpoint": local_endpoint(listen_port),
        "client_command": client_command(
            public=public, restrict_to=restrict_to, local_port=listen_port,
        ),
        "plist": found.get("plist") or "",
        "binary": binary,
        "binary_ok": bool(binary) and Path(binary).is_file(),
        "aligned": aligned,
        "stable_restrict": stable,
        "stale_restrict": stale,
        "needs_apply": needs_apply,
        "needs_stabilize": needs_stabilize,
        "label": LABEL,
    }


def listener_row(snapshot: dict | None) -> dict[str, Any] | None:
    """A ports-tab row for a root wstunnel that ``lsof`` without sudo misses."""
    if not snapshot:
        return None
    port = snapshot.get("port")
    if not port:
        parsed = urlparse(str(snapshot.get("listen") or ""))
        if parsed.port:
            port = parsed.port
    if not port:
        return None
    return {
        "process": "wstunnel",
        "pid": snapshot.get("pid") or "",
        "user": "root",
        "address": snapshot.get("listen") or f"*:{port}",
        "port": str(port),
    }
