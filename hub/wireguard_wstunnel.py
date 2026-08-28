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

from hub.util import read_bytes_capped, sh, ttl_memo

LABEL = "com.elvin.wstunnel-wg-server"

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")


def _isa(value, kinds) -> bool:
    """``isinstance`` that survives a leftover ``__class__``-property bomb.

    ``isinstance`` consults ``value.__class__`` when the exact-type check
    misses, so a snapshot (or value) whose ``__class__`` is a *raising
    property* detonated the type gates themselves — a raw 500 on GET
    /api/wireguard and GET /api/wireguard/settings (the wireguard_svc._isa
    rule).  A real subclass still matches through the C-level type check.
    """
    try:
        return isinstance(value, kinds)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _truthy(value) -> bool:
    """``bool(value)`` that survives a leftover ``__bool__``/``__len__`` bomb."""
    try:
        return bool(value)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _rc_int(rc) -> int:
    """Exact exit status; a bomb reads as failure (the health9 rc rule).

    :func:`local_ipv4s` does not own ``sh`` (tests and tooling patch it),
    and an rc-subclass whose ``__eq__``/``__ne__`` raises used to detonate
    the bare ``rc != 0`` probe — a raw 500 on GET /api/wireguard, GET
    /api/wireguard/settings and /readiness through ``status()``'s
    stale-restrict check.  ``int.__index__`` salvages the honest exit.
    """
    try:
        if type(rc) is bool:
            return int(rc)
        if _isa(rc, int):
            return int.__index__(rc)
        return int(rc)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return -255


def _as_text(value) -> str:
    """Drop leftover ``\\ud800`` so GET /api/wireguard cannot UTF-8 500."""
    if value is None:
        return ""
    for base in (bytes, bytearray):
        try:
            return base.decode(value, "utf-8", "replace")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
    try:
        return str.encode(str.__str__(value), "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        pass
    try:
        cls = type(value)
        if cls.__str__ is object.__str__ and cls.__repr__ is object.__repr__:
            return ""
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    try:
        text = str(value)
    except RecursionError:
        try:
            return type(value).__name__
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return ""
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    try:
        text = str.encode(text, "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    return "" if _ADDR_REPR_RE.search(text) else text


def _path_is_file(path) -> bool:
    """``Path.is_file()`` re-raises EIO/ESTALE; that used to 500 GET /api/wireguard."""
    try:
        return Path(path).is_file()
    except (OSError, ValueError, TypeError):
        return False
PLIST_PATH = Path("/Library/LaunchDaemons") / f"{LABEL}.plist"
#: Leftover multi-MB wstunnel LaunchDaemon plist used to OOM GET /api/wireguard.
_PLIST_CAP = 256 * 1024
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
    for line in _as_text(text).splitlines():
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
        try:
            names = {Path(part).name for part in argv}
        except (TypeError, ValueError, OSError):
            continue
        if "wstunnel" not in names or "server" not in argv:
            continue
        parsed = parse_argv(argv)
        try:
            parsed["pid"] = int(pid_s)
        except (TypeError, ValueError, OverflowError):
            # Leftover ``pid: .inf`` OverflowError'd GET /api/wireguard wstunnel.
            continue
        parsed["running"] = True
        try:
            parsed["binary"] = next(
                (part for part in argv if Path(part).name == "wstunnel"), ""
            )
        except (TypeError, ValueError, OSError):
            parsed["binary"] = ""
        return parsed
    return {"listen": "", "restrict_to": "", "pid": 0, "running": False, "binary": ""}


def read_plist(path: Path | None = None) -> dict[str, str]:
    """``listen`` / ``restrict_to`` from the LaunchDaemon, if readable."""
    target = path or PLIST_PATH
    try:
        data = plistlib.loads(read_bytes_capped(target, _PLIST_CAP))
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # An enumerated tuple is a losing game against plistlib's XML path
        # (the files_svc lesson): a torn or truncated LaunchDaemon plist
        # raises xml.parsers.expat.ExpatError, a junk <date> raises
        # AttributeError, a stray <key> outside any dict raises IndexError,
        # and a deeply-nested plist raises RecursionError — none of which the
        # old (OSError, InvalidFileException, ValueError, RecursionError)
        # tuple fully covered, so GET /api/wireguard, /api/wireguard/settings
        # and /api/wireguard/readiness used to 500 on a half-written plist.
        return {"listen": "", "restrict_to": ""}
    if not isinstance(data, dict):
        return {"listen": "", "restrict_to": ""}
    argv = data.get("ProgramArguments") or []
    if not isinstance(argv, list):
        return {"listen": "", "restrict_to": ""}
    # _as_text, not str(): plistlib parses <integer>0x…</integer> through
    # int(x, 16), which CPython's 4300-digit cap does not bound, so a leftover
    # over-cap hex integer in the argv survived plistlib.loads and the bare
    # str() here ValueError'd GET /api/wireguard, GET /api/wireguard/settings,
    # GET /api/wireguard/readiness and GET /api/system/network.
    return parse_argv([_as_text(part) for part in argv])


@ttl_memo(6.0)
def live(ps_text: str | None = None) -> dict[str, Any]:
    """Running server first, then the on-disk plist, then empty.

    Memoised so the Network overview and the WireGuard status poll, which
    both call this in the same few seconds, share one ``ps``.
    """
    if ps_text is None:
        from hub.proc_cache import ps_pid_commands
        ps_text = "\n".join(f"{pid} {cmd}" for pid, cmd in ps_pid_commands())
    found = parse_process_table(ps_text or "")
    plist = read_plist()
    if not found.get("listen"):
        found["listen"] = plist.get("listen") or ""
    if not found.get("restrict_to"):
        found["restrict_to"] = plist.get("restrict_to") or ""
    found["plist"] = str(PLIST_PATH) if _path_is_file(PLIST_PATH) else ""
    return found


@ttl_memo(6.0)
def local_ipv4s() -> frozenset[str]:
    """IPv4 addresses currently on this host, for stale ``--restrict-to`` checks."""
    rc, out, _err = sh(["/sbin/ifconfig", "-a"], timeout=5)
    if _rc_int(rc) != 0:
        return frozenset()
    return frozenset(_INET_RE.findall(_as_text(out)))


def find_binary() -> str:
    """First allowed wstunnel binary that exists on disk."""
    for path in ALLOWED_BINARIES:
        if _path_is_file(path):
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
    except (TypeError, ValueError, OverflowError):
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
    except (TypeError, ValueError, OverflowError):
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
    try:
        if not (port.isdigit() and 1 <= int(port) <= 65535):
            return False
    except ValueError:
        # The port here is split out of the raw value, not a bounded regex
        # capture: isdigit() passes a >4300-digit run (CPython's str->int cap)
        # and superscripts, and the ValueError used to 500 PUT
        # /api/wireguard/settings and POST /api/wireguard/remediate.
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
    # ``dict(settings)`` in a try: a *lying*-``__class__`` impostor
    # (``isinstance`` answers dict, the real object is a plain object)
    # passed the ``_isa`` gate and the bare copy raised TypeError — this
    # function does not own its caller's snapshot, and a liar must read as
    # an empty section like every other junk shape.
    cfg = {}
    if _isa(settings, dict):
        try:
            cfg = dict(settings)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            cfg = {}
    # Laundered snapshot (the settings_section rule): this read does not own
    # its provider — tests and tooling patch ``live`` — and a snapshot that
    # is a dict *subclass* with a bombing ``.get`` used to raise out of the
    # bare method calls below, a raw 500 on GET /api/wireguard, GET
    # /api/wireguard/settings and /readiness.  ``dict(...)`` copies through
    # the C-level storage; the values stay laundered individually below.
    # _isa: a snapshot whose ``__class__`` is a raising property used to
    # detonate the shape gate itself.
    try:
        found = live()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        found = None
    if _isa(found, dict):
        try:
            found = dict(found)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            found = {}
    else:
        found = {}
    # _int_or_zero, not a bare ``int(... or 0)``: the ``or`` blank probe ran
    # a leftover value's own ``__bool__``, and a raising one blew past the
    # old arithmetic-trio except — the launder below degrades every bomb to
    # 0 and already absorbs the over-cap int->str case.
    listen_port = _int_or_zero(cfg.get("listen_port"))
    if not (0 <= listen_port <= 65535):
        # A YAML hex/octal int skips CPython's str->int digit cap, so an
        # over-cap ``listen_port`` reached ``local_port`` here and ValueError'd
        # ``json.dumps`` on GET /api/wireguard and the Network overview.
        listen_port = 0
    # Launder-then-or (the wg9 ``found.get`` rule, on the *stored* side):
    # ``cfg.get(...) or default`` ran a leftover value's own ``__bool__``
    # before the launder could absorb it.
    desired_listen = _as_text(cfg.get("wstunnel_listen")) or DEFAULT_LISTEN
    desired_restrict = _as_text(cfg.get("wstunnel_restrict_to")) or default_restrict_to(
        listen_port
    )
    # _as_text straight on the stored value, no ``or ""`` first: the old
    # blank probe reflected into a leftover value's own ``__bool__`` — a
    # raw 500 on GET /api/wireguard and GET /api/wireguard/settings for a
    # value the launder degrades to "" anyway.  Same for ``running`` and
    # ``binary``/``plist`` below (``_truthy``, launder-then-or).
    live_listen = _as_text(found.get("listen"))
    live_restrict = _as_text(found.get("restrict_to"))
    running = _truthy(found.get("running"))
    # Export dest must match the process that will accept it.
    restrict_to = live_restrict if running and live_restrict else desired_restrict
    listen = live_listen if running and live_listen else desired_listen
    stored_public = _as_text(cfg.get("wstunnel_public"))
    public = stored_public or public_url(listen, _as_text(cfg.get("endpoint")))
    _scheme, _host, port = listen_parts(listen)
    if not listen_port:
        listen_port = int(port) if str(port).isdigit() else 0
    enabled = _truthy(cfg.get("wstunnel_enabled"))
    binary = _as_text(found.get("binary")) or find_binary()
    plist_path = _as_text(found.get("plist"))
    aligned = (not running) or (
        live_listen == desired_listen and live_restrict == desired_restrict
    )
    addresses = local_ipv4s()
    stable = restrict_is_stable(restrict_to)
    stale = restrict_is_stale(restrict_to, addresses)
    # Default listen is always filled by settings(); it does not mean the
    # operator turned this on.  A live process or an explicit public/restrict
    # value does.  Laundered strings, not the raw snapshot values: the raw
    # ``found.get(...)`` truthiness probes reflected into a leftover value's
    # own ``__bool__`` and 500'd the read.
    configured = bool(
        enabled
        or running
        or live_listen
        or plist_path
        or _as_text(cfg.get("wstunnel_public")).strip()
        or _as_text(cfg.get("wstunnel_restrict_to")).strip()
    )
    needs_stabilize = enabled and (not stable or stale)
    needs_apply = enabled and (not running or not aligned)
    return {
        "enabled": enabled,
        "configured": configured,
        "running": running,
        "pid": _int_or_zero(found.get("pid")),
        "listen": _as_text(listen),
        "desired_listen": _as_text(desired_listen),
        "public": _as_text(public),
        "restrict_to": _as_text(restrict_to),
        "desired_restrict_to": _as_text(desired_restrict),
        "suggest_restrict_to": default_restrict_to(listen_port),
        "port": int(port) if str(port).isdigit() else 0,
        "local_port": listen_port,
        "local_endpoint": local_endpoint(listen_port),
        "client_command": client_command(
            public=public, restrict_to=restrict_to, local_port=listen_port,
        ),
        "plist": plist_path,
        "binary": _as_text(binary),
        "binary_ok": bool(binary) and _path_is_file(binary),
        "aligned": aligned,
        "stable_restrict": stable,
        "stale_restrict": stale,
        "needs_apply": needs_apply,
        "needs_stabilize": needs_stabilize,
        "label": LABEL,
    }


def _int_or_zero(value) -> int:
    """Exact bounded int, or 0.

    Base coercions plus a ``str()`` probe: the old bare ``int(value or 0)``
    reflected into a leftover's own ``__bool__``/``__int__`` (raising past
    the arithmetic-trio except), and passed a >4300-digit already-int
    straight through to Starlette's ``json.dumps``, whose int->str digit cap
    ValueError'd GET /api/wireguard one layer later.
    """
    try:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            number = int.__index__(value)
        elif isinstance(value, float):
            probe = float.__float__(value)
            if probe != probe or probe in (float("inf"), float("-inf")):
                return 0
            number = int(probe)
        else:
            text = _as_text(value).strip()
            if not text:
                return 0
            number = int(text)
        str(number)  # CPython's 4300-digit int->str cap; json.dumps enforces it
        return number
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return 0


def listener_row(snapshot: dict | None) -> dict[str, Any] | None:
    """A ports-tab row for a root wstunnel that ``lsof`` without sudo misses."""
    # _isa: a snapshot whose ``__class__`` is a raising property detonated
    # the bare shape gate itself.
    if not _isa(snapshot, dict):
        return None
    # Exact-dict launder in a try: a *lying*-``__class__`` impostor passed
    # the ``_isa`` gate and made the unbound ``dict.get`` descriptors below
    # raise TypeError into the Network ports tab.  ``dict(...)`` copies a
    # real (sub)dict through the C-level storage and refuses the liar.
    try:
        snapshot = dict(snapshot)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None
    # Unbound ``dict.get`` + laundered values: a dict-subclass snapshot with
    # a bombing ``.get``, a listen value whose str-subclass methods raise
    # under urlsplit, or an over-cap port used to raise out of this row
    # builder into the Network ports tab.
    port = _int_or_zero(dict.get(snapshot, "port"))
    listen = _as_text(dict.get(snapshot, "listen"))
    if not port:
        try:
            port = urlparse(listen).port or 0
        except ValueError:
            # Torn IPv6 in the URL ("ws://[::1:8444") and out-of-range ports
            # are both ValueError out of urlsplit/.port.
            return None
    if not port:
        return None
    pid = _int_or_zero(dict.get(snapshot, "pid"))
    return {
        "process": "wstunnel",
        "pid": pid or "",
        "user": "root",
        "address": listen or f"*:{port}",
        "port": str(port),
    }
