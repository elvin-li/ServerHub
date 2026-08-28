"""Adaptive discovery — auto port/url/group for new services without manual yaml.

When you add:
  - a LaunchAgent under ~/Library/LaunchAgents
  - a docker container / compose under ~/Services
  - a listening process
ServerHub infers ports, HTTP URLs, and grouping without requiring overrides.
"""
from __future__ import annotations

import re
import socket
import threading
import time
from pathlib import Path
from typing import Any

from hub.host_address import host_ip as resolved_host_ip
from hub.group_rules import configured_group_rules, resolve_group
from hub.paths import user_home
from hub.service_signatures import configured_signatures, identify, unescape_proc_name
from hub.util import port_open, read_text_capped, sh

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")


def _utf8_text(value) -> str:
    """Drop leftover ``\\ud800`` so GET /api/nginx cannot UTF-8 500."""
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

# Common flags that take a port as next argument
_PORT_FLAGS = {
    "-p", "--port", "--http-port", "--listen-port", "-P",
    "--server-port", "--web-port",
}
_ENV_PORT_KEYS = re.compile(
    r"^(PORT|HTTP_PORT|HTTPS_PORT|SERVER_PORT|WEB_PORT|APP_PORT|LISTEN_PORT)$",
    re.I,
)
_URL_ENV_KEYS = re.compile(r"^(APP_PUBLIC_URL|PUBLIC_URL|BASE_URL|URL)$", re.I)


def host_ip() -> str:
    return resolved_host_ip()


def ports_from_plist(pl: dict) -> list[int]:
    """Extract listen ports from LaunchAgent plist structure."""
    if not isinstance(pl, dict):
        return []
    ports: list[int] = []
    raw_args = pl.get("ProgramArguments")
    if not isinstance(raw_args, list):
        raw_args = []
    # leftover RecursionError on ``str(argv-item)`` / leftover ``\\ud800``
    # used to 500 GET /api/status (adaptive port scan of LaunchAgents).
    args = [_utf8_text(a) for a in raw_args]
    skip_next = False
    for i, a in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        # cloudflared --edge 198.41.192.7:7844 pins the Cloudflare *edge*,
        # not a local listen port. Treating it as one made the zaoxue
        # tunnel sit yellow: process up, localhost:7844 closed.
        if a == "--edge":
            skip_next = True
            continue
        if a in _PORT_FLAGS and i + 1 < len(args):
            try:
                ports.append(int(args[i + 1]))
            except (ValueError, OverflowError):
                pass
        # -p8200 or --port=8200
        m = re.match(r"^(?:-p|--port=)(\d{2,5})$", a)
        if m:
            ports.append(int(m.group(1)))
        # bare :8125 style rare
        m = re.search(r":(\d{4,5})$", a)
        if m and "://" not in a:
            try:
                ports.append(int(m.group(1)))
            except ValueError:
                pass
    env = pl.get("EnvironmentVariables")
    if not isinstance(env, dict):
        env = {}
    for k, v in env.items():
        key, val = _utf8_text(k), _utf8_text(v)
        if _ENV_PORT_KEYS.match(key):
            try:
                ports.append(int(val.strip()))
            except (ValueError, OverflowError, TypeError):
                pass
        if _URL_ENV_KEYS.match(key):
            m = re.search(r":(\d{2,5})(?:/|$)", val)
            if m:
                ports.append(int(m.group(1)))
    # Sockets in plist (rare)
    sockets = pl.get("Sockets")
    if not isinstance(sockets, dict):
        sockets = {}
    for sock in sockets.values():
        if isinstance(sock, dict):
            for key in ("SockServiceName", "SockPortName"):
                try:
                    ports.append(int(sock[key]))
                except (KeyError, ValueError, TypeError, OverflowError):
                    pass
    # unique valid
    out = []
    for p in ports:
        if 1 <= p <= 65535 and p not in out:
            out.append(p)
    return out


def url_from_plist(pl: dict) -> str | None:
    if not isinstance(pl, dict):
        return None
    env = pl.get("EnvironmentVariables")
    if not isinstance(env, dict):
        env = {}
    for k, v in env.items():
        val = _utf8_text(v)
        if _URL_ENV_KEYS.match(_utf8_text(k)) and val.startswith("http"):
            return val.strip()
    return None


# One `lsof -nP -iTCP -sTCP:LISTEN` costs ~61ms and returns every listener on
# the host.  A per-pid `lsof -a -p <pid>` costs ~43ms and returns one process's
# listeners, so resolving N pids the per-pid way costs N*43ms — 644ms of the
# 730ms status refresh on a host with 15 running agents.  One global call
# answers all of them, and the orphan-listener scan needs the exact same
# snapshot, so it shares this cache instead of shelling out a third time.
# The TTL only has to span a single full_status refresh; invalidate_status()
# drops it so a start/stop is never reported from a pre-action snapshot.
_LSOF_TTL = 5.0
_lsof_cache: dict[str, Any] = {"t": 0.0, "v": None}
_lsof_lock = threading.Lock()
# Single-flight: the status refresh fans out across a thread pool, so several
# callers hit a cold cache at once.  Collapse them into one subprocess.
_lsof_refresh_lock = threading.Lock()
#: Bumped on every invalidate so an in-flight refresh cannot republish a
#: pre-action snapshot on top of a start/stop that finished while it ran.
_lsof_generation = 0


def invalidate_lsof_snapshot() -> None:
    """Drop the listener snapshot so the next read reflects current reality."""
    global _lsof_generation
    with _lsof_lock:
        _lsof_generation += 1
        _lsof_cache["t"] = 0.0
        _lsof_cache["v"] = None


def _parse_lsof_listen(out: str) -> list[dict[str, Any]]:
    """Rows of {proc, pid, bind, port} from `lsof -nP -iTCP -sTCP:LISTEN` text."""
    if isinstance(out, (bytes, bytearray)):
        out = out.decode("utf-8", "replace")
    elif not isinstance(out, str):
        return []
    rows: list[dict[str, Any]] = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        # NAME is the last field, unless lsof appended the (LISTEN) state token.
        bind = parts[-2] if parts[-1] == "(LISTEN)" else parts[-1]
        # A rare `addr:port->peer:port` NAME would make `:(\d+)$` take the
        # remote port; the listen we care about is the local side.
        local = bind.split("->", 1)[0]
        m = re.search(r":(\d+)$", local)
        if not m:
            continue
        try:
            port = int(m.group(1))
        except ValueError:
            continue
        if not 1 <= port <= 65535:
            continue
        rows.append({
            "proc": unescape_proc_name(parts[0]),
            "pid": str(parts[1]),
            "bind": bind,
            "port": port,
        })
    return rows


def lsof_listen_snapshot() -> list[dict[str, Any]]:
    """Every listening TCP socket on the host, cached behind a short TTL."""
    now = time.time()
    with _lsof_lock:
        if _lsof_cache["v"] is not None and now - _lsof_cache["t"] < _LSOF_TTL:
            return _lsof_cache["v"]
        gen = _lsof_generation
    with _lsof_refresh_lock:
        # Another thread may have refreshed while we waited for the lock.
        now = time.time()
        with _lsof_lock:
            if _lsof_cache["v"] is not None and now - _lsof_cache["t"] < _LSOF_TTL:
                return _lsof_cache["v"]
            gen = _lsof_generation
        try:
            rc, out, _ = sh(
                ["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN"],
                timeout=10,
            )
            rows = _parse_lsof_listen(out) if rc == 0 else []
        except Exception:
            rows = []
        with _lsof_lock:
            if gen != _lsof_generation:
                # invalidate() landed while we shelled out; do not revive the
                # pre-action snapshot or the next ports_for_pid would miss a
                # real refresh after a start/stop.
                return rows
            _lsof_cache["t"] = time.time()
            _lsof_cache["v"] = rows
        return rows


def ports_for_pid(pid: str | int) -> list[int]:
    """Listening TCP ports owned by pid, read from the shared lsof snapshot.

    This used to shell out `lsof -a -p <pid>` per call (~43ms).  A status
    refresh resolves one pid per running agent, so the cost scaled with the
    number of installed LaunchAgents — 15 agents meant 15 subprocesses and
    644ms.  The shared snapshot answers every pid from one 61ms call.
    """
    try:
        pid = int(pid)
    except (TypeError, ValueError, OverflowError):
        return []
    if pid <= 0:
        return []
    want = str(pid)
    ports: list[int] = []
    snapshot = lsof_listen_snapshot()
    if not isinstance(snapshot, list):
        return []
    for row in snapshot:
        if not isinstance(row, dict):
            continue
        if str(row.get("pid") or "") != want:
            continue
        try:
            port = int(row["port"])
        except (KeyError, TypeError, ValueError, OverflowError):
            continue
        if 1 <= port <= 65535 and port not in ports:
            ports.append(port)
    return ports


# ports that are almost never HTTP UI
# 6380 is here because a second Redis on the +1 port is the standard way to run
# one: sub2api does exactly that, and probing it wrote 6237 "Possible SECURITY
# ATTACK ... sending POST or Host: commands to Redis" lines into its log before
# anyone noticed.  Redis aborts such a connection, so the probe was pure cost.
_NON_HTTP_PORTS = {
    22, 53, 123, 143, 993, 995, 25, 465, 587,
    1883, 8883, 5432, 5433, 3306, 6379, 6380, 27017, 5672, 11211,
    445, 139, 548, 2049, 5353, 5900, 3283,
}
# Ports found to speak neither HTTP nor TLS, so the next refresh does not probe
# them again.  The port list above only knows *default* ports; anything on a
# non-default one (the 6380 case, and any future service like it) is caught only
# by having actually looked.  Bounded TTL because a port that is silent now may
# be a web UI after the operator installs something there.
_NOT_HTTP_TTL = 1800.0
_not_http_cache: dict[int, float] = {}
_not_http_lock = threading.Lock()


def _recently_not_http(port: int) -> bool:
    """Whether *port* failed protocol classification recently."""
    with _not_http_lock:
        seen = _not_http_cache.get(port)
        if seen is None:
            return False
        if time.time() - seen >= _NOT_HTTP_TTL:
            del _not_http_cache[port]
            return False
        return True


def _mark_not_http(port: int) -> None:
    """Remember that *port* answers TCP but speaks no recognised protocol."""
    with _not_http_lock:
        _not_http_cache[port] = time.time()


def invalidate_not_http_cache() -> None:
    """Forget which ports failed classification, so the next call re-probes.

    Needed by tests: they bind ephemeral ports, and the kernel is free to hand
    the same number to a later test that does expect HTTP detection.
    """
    with _not_http_lock:
        _not_http_cache.clear()


#: How long to wait for the peer's first bytes.  A local service that speaks
#: HTTP or TLS answers a request in single-digit milliseconds; anything that has
#: said nothing by now is either not a web server or too slow to link to.
_PROBE_TIMEOUT_S = 0.35


def _classify_head(head: bytes) -> str:
    """What protocol the peer's first bytes indicate: "http", "tls", or "".

    Called with whatever comes back from writing a plaintext HTTP request:

    * an HTTP server answers with a status line
    * a TLS-only server cannot parse the plaintext request and answers with a
      TLS record -- handshake (0x16) when it is mid-negotiation, or alert
      (0x15), which is what OpenSSL sends for a malformed ClientHello
    * everything else (Redis's ``-ERR``, an SSH banner, silence) is not a web
      service, and the caller must not spend a second timeout finding out
    """
    if head.startswith(b"HTTP/"):
        return "http"
    # TLS record: content type, then a major version of 3 for every SSL/TLS
    # version in use.  Two bytes is enough to tell this from ASCII protocols.
    if len(head) >= 2 and head[0] in (0x14, 0x15, 0x16, 0x17) and head[1] == 0x03:
        return "tls"
    return ""


def _probe_protocol(port: int) -> tuple[str, bytes]:
    """One round trip against localhost:port -> (protocol, first bytes seen)."""
    req = (
        f"GET / HTTP/1.1\r\nHost: localhost:{port}\r\n"
        "User-Agent: ServerHub/adapt\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    ).encode()
    try:
        with socket.create_connection(
            ("127.0.0.1", port), timeout=_PROBE_TIMEOUT_S
        ) as s:
            s.settimeout(_PROBE_TIMEOUT_S)
            s.sendall(req)
            head = s.recv(256)
    except Exception:
        return "", b""
    return _classify_head(head), head


def _status_from_head(head: bytes) -> int | None:
    """The status code out of an HTTP status line, if it parses."""
    m = re.match(rb"HTTP/\d\.\d\s+(\d{3})", head)
    return int(m.group(1)) if m else None


def guess_http_url(port: int) -> str | None:
    """Return URL only if port looks like HTTP(S) and responds like a web service.

    Decides from what the port actually speaks rather than trying HTTP and then
    HTTPS in turn.  The old two-scheme fallback cost a full TLS handshake
    timeout for any port that accepts TCP but speaks neither protocol: the
    plaintext attempt failed in ~12ms and the TLS attempt ran to its timeout
    because the peer never sent a ServerHello.  Live Redis on 6380 measured
    802ms that way, and the hardcoded `_NON_HTTP_PORTS` guard did not catch it --
    that set listed only 6379.  6380 is in the set now, but a default-port list
    is the wrong last line of defence, so a port that classifies as neither
    protocol is also remembered and not probed again for `_NOT_HTTP_TTL`.
    """
    try:
        port = int(port)
    except (TypeError, ValueError, OverflowError):
        return None
    if not 1 <= port <= 65535:
        return None
    if port in _NON_HTTP_PORTS:
        return None
    if _recently_not_http(port):
        return None
    try:
        if not port_open(port, host="localhost", timeout=0.35):
            return None
    except Exception:
        return None
    proto, head = _probe_protocol(port)
    if not proto:
        # Remember only a speaking non-web peer (Redis ``-ERR``, SSH).  A
        # timeout or empty close is not a verdict — caching those for
        # 30 minutes hid a restarting TLS UI after one slow poll.
        if head:
            _mark_not_http(port)
        return None
    hip = host_ip()
    if proto == "http":
        code = _status_from_head(head)
        # A TLS-only nginx port replies to a plaintext request with a plaintext
        # `400 Bad Request` -- the request *is* a malformed ClientHello -- so a
        # status line alone does not prove the port serves plaintext.  Live port
        # 8281 is exactly this.  Confirm with a handshake before believing the
        # 400; the old code only got it right because 8281 was hardcoded into
        # its scheme-order tuple.
        if code == 400:
            return _https_url(port, hip)
        # 401/403/404 still mean "a web server is here", which is what the link
        # is for; 5xx means it is broken rather than absent, so no link.
        if code is not None and 200 <= code < 500:
            return f"http://{hip}:{port}"
        return None
    # Speaks TLS: the handshake is required to learn the status, and a real TLS
    # peer completes it promptly, so this is the one case worth urllib's cost.
    return _https_url(port, hip)


def _https_url(port: int, hip: str) -> str | None:
    """Complete a real TLS request against port, or None if it is not HTTPS."""
    import ssl
    import urllib.error
    import urllib.request

    from hub.http_guard import NoRedirect, RedirectRefused

    try:
        req = urllib.request.Request(
            f"https://localhost:{port}/",
            method="GET",
            headers={"User-Agent": "ServerHub/adapt"},
        )
        ctx = ssl._create_unverified_context()
        # Default urlopen follows 30x and honours HTTP_PROXY: a container that
        # answers TLS then 302s to IMDS made this probe an SSRF client.
        opener = urllib.request.build_opener(
            NoRedirect,
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ctx),
        )
        with opener.open(req, timeout=0.8) as r:
            if 200 <= r.status < 500:
                # Status is enough; drain a bounded prefix so a huge body
                # cannot sit on the socket until the context manager closes.
                try:
                    r.read(256)
                except Exception:
                    pass
                return f"https://{hip}:{port}"
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 401, 403, 404, 421):
            return f"https://{hip}:{port}"
    except RedirectRefused:
        # Peer spoke HTTPS and tried to 302.  That is enough to call it HTTPS
        # without fetching the Location (which may be metadata).
        return f"https://{hip}:{port}"
    except Exception:
        return None
    return None


def friendly_name(label: str) -> str:
    """Humanize launchd label when no override name."""
    if not isinstance(label, str):
        label = str(label or "")
    name = label
    for prefix in (
        "local.serverhub.", "local.", "com.homeassistant.",
        "homebrew.mxcl.", "com.",
    ):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    # postgresql@17 → PostgreSQL 17
    name = name.replace("@", " ").replace("-", " ").replace("_", " ").replace(".", " ")
    parts = [p for p in name.split() if p]
    if not parts:
        return _utf8_text(label)
    # Title-case short tokens
    pretty = " ".join(
        p.upper() if p.lower() in ("ha", "api", "ddns", "vm", "ssd") else p.capitalize()
        for p in parts
    )
    return _utf8_text(pretty)


def guess_group(label: str, pl: dict, interval: bool) -> str:
    if interval:
        return "Scheduled Tasks"
    if not isinstance(label, str):
        # leftover RecursionError on ``str(label)`` used to 500 GET /api/status.
        label = _utf8_text(label)
    if not isinstance(pl, dict):
        pl = {}
    low = label.lower()
    raw_args = pl.get("ProgramArguments")
    path = (
        " ".join(_utf8_text(a) for a in raw_args).lower()
        if isinstance(raw_args, list) else ""
    )
    if "nginx" in low or "nginx" in path:
        return "Gateway"
    if "homeassistant" in low or "home-assistant" in path:
        return "Home Assistant"
    if "homebrew" in low or "mxcl" in low:
        return "Homebrew Services"
    if "docker" in low or "orb" in low:
        return "Apps"
    return "Native Services"


def enrich_service(item: dict, *, pl: dict | None = None, pid: str | None = None) -> dict:
    """Fill missing port/url/name/group using adaptive heuristics. Respects overrides already applied."""
    if not isinstance(item, dict):
        return {}
    if not isinstance(pl, dict):
        pl = None
    # name already from override or label
    if not item.get("url") and pl:
        u = url_from_plist(pl)
        if u:
            item["url"] = _utf8_text(u)
            item["auto"] = True
    ports = []
    if pl:
        ports = ports_from_plist(pl)
    if pid and not ports:
        ports = ports_for_pid(pid)
    # pick primary port
    primary = None
    if ports:
        primary = ports[0]
        item["ports"] = ports
        meta = item.get("meta")
        if not isinstance(meta, dict):
            meta = {}
            item["meta"] = meta
        meta["detected_ports"] = ports
        item["auto"] = True
    # re-evaluate port open if we detected
    if primary and not item.get("url"):
        url = guess_http_url(primary)
        if url:
            item["url"] = _utf8_text(url)
    # improve detail with ports if missing
    detail = item.get("detail")
    if primary and isinstance(detail, str) and f":{primary}" not in detail:
        # "运行中" kept alongside "Running": the detail text is produced by
        # hub/discovery/*, which is migrating from Chinese to English prose.
        if item.get("state") == "ok" and ("Running" in detail or "运行中" in detail):  # cjk-input: matches detail prose from hub/discovery/*
            item["detail"] = _utf8_text(detail + f" · :{primary}")
    # mark adaptive
    if item.get("auto"):
        meta = item.get("meta")
        if not isinstance(meta, dict):
            meta = {}
            item["meta"] = meta
        meta["adaptive"] = True
    # FUSE leftover ``\ud800`` in a name / URL / detail used to 500
    # GET /api/status when this row was encoded without a later sanitizer.
    for key in ("url", "detail", "name", "id", "group"):
        val = item.get(key) if key in item else None
        if isinstance(val, (str, bytes, bytearray)):
            item[key] = _utf8_text(val)
    return item


def discover_orphan_listeners(known_ports: set[int], known_names: set[str]) -> list[dict]:
    """Expose listening ports not already owned by a known service (auto-discovered apps)."""
    # Same snapshot ports_for_pid reads: this scan used to be a third global
    # lsof running after the status thread pool had already joined, adding
    # ~106ms of pure serial tail latency to every refresh.
    rows = lsof_listen_snapshot()
    if not isinstance(rows, list):
        rows = []
    if not isinstance(known_ports, (set, list, tuple, frozenset)):
        known_ports = ()
    # group by port
    by_port: dict[int, dict] = {}
    skip_proc = {
        "rapportd", "ControlCe", "ARDAgent", "sharingd", "identitys",
        "SystemUIS", "syncthing", "Cursor", "Code", "Google", "Chrome",
        "WeChat", "QQ", "Spotify", "Music", "Zoom", "Slack",
    }
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            port = int(row["port"])
        except (KeyError, TypeError, ValueError, OverflowError):
            continue
        proc = _utf8_text(unescape_proc_name(row.get("proc")))
        pid = _utf8_text(row.get("pid") or "")
        name = _utf8_text(row.get("bind") or "")
        if any(proc.startswith(s) for s in skip_proc):
            continue
        if port < 1024 and port not in (80, 443):  # skip privileged noise except web
            if port not in (22,):  # skip ssh
                pass
        if port in (22, 53, 88, 137, 138, 139, 445, 548, 631, 3283, 5353, 5900):
            continue
        if port in known_ports:
            continue
        if port in by_port:
            continue
        # skip browser / IDE high ports often ephemeral
        if port > 49000:
            continue
        by_port[port] = {"proc": unescape_proc_name(proc), "pid": pid, "bind": name}

    # Same process, several ports (Redis 6379+6380, a UI plus its metrics
    # port) used to become one card each.  Group by pid so adopt writes one
    # managed entry that health-checks every listen the process owns.
    by_pid: dict[str, list[tuple[int, dict]]] = {}
    names = known_names if isinstance(known_names, (set, list, tuple, frozenset)) else ()
    for port, info in by_port.items():
        proc_l = info["proc"].lower()
        if any(isinstance(n, str) and proc_l in n.lower() for n in names):
            continue
        by_pid.setdefault(info["pid"], []).append((port, info))

    hip = host_ip()
    extras = configured_signatures()
    rules = configured_group_rules()
    items = []
    # Speed: port already LISTEN from lsof → treat as ok; skip extra TCP + HTTP
    # probes.  guess_http_url is one round trip now, but at ~40 ports on a busy
    # host that is still work this scan does not need to do.
    webish = {80, 443, 3000, 3001, 4000, 5000, 8000, 8080, 8086, 8095, 8123, 8125, 8200, 8280, 8281, 8443, 8501, 8765, 9000}
    for pid, pairs in sorted(by_pid.items(), key=lambda kv: min(p for p, _ in kv[1])):
        pairs = sorted(pairs, key=lambda x: x[0])
        ports = [p for p, _ in pairs]
        info = pairs[0][1]
        sig = _best_signature(info["proc"], ports, extras)
        url = None
        for port in ports:
            url = _orphan_url(port, sig, hip, webish)
            if url:
                break
        port_label = " ".join(f":{p}" for p in ports)
        if isinstance(sig, dict) and sig.get("confidence") == "high":
            sig_name = _utf8_text(sig.get("name") or info["proc"])
            name = _utf8_text(f"{sig_name} {port_label}")
            detail = _utf8_text(
                f"Auto-discovered · {sig_name} · pid {pid} · {info['bind']}"
            )
        elif isinstance(sig, dict):
            # Port-only or runtime match is a hint, so the raw process name
            # stays visible; the guess rides along in the detail line.
            name = _utf8_text(f"{info['proc']} {port_label}")
            hint = _utf8_text(sig.get("name") or info["proc"])
            detail = _utf8_text(
                f"Auto-discovered · {hint}? · pid {pid} · {info['bind']}"
            )
        else:
            name = _utf8_text(f"{info['proc']} {port_label}")
            detail = _utf8_text(
                f"Auto-discovered · pid {pid} · {info['bind']}"
            )
        primary = ports[0]
        meta = {
            "port": primary,
            "ports": ports,
            "pid": pid,
            "process": _utf8_text(info["proc"]),
        }
        if isinstance(sig, dict):
            meta["signature"] = sig
        items.append({
            "id": f"auto.port.{primary}",
            "kind": "auto",
            "name": name,
            "state": "ok",
            "detail": detail,
            "url": url,
            "port": primary,
            "ports": ports,
            "group": resolve_group(
                {
                    "id": f"auto.port.{primary}",
                    "port": primary,
                    "ports": ports,
                    "meta": {"process": _utf8_text(info["proc"])},
                },
                fallback="Auto-discovered",
                rules=rules,
            ),
            "actions": ["adopt"],
            "auto": True,
            "signature": sig if isinstance(sig, dict) else None,
            "meta": meta,
        })
    return items[:40]


_SIG_RANK = {"high": 3, "low": 2, "runtime": 1}


def _best_signature(proc: str, ports: list[int], extras: list[dict] | None):
    """Process-name match first; otherwise the strongest port hint among *ports*."""
    best = identify(proc, None, extras=extras)
    rank = _SIG_RANK.get(best.get("confidence"), 0) if isinstance(best, dict) else 0
    if rank >= 3:
        return best
    for port in ports:
        cand = identify(proc, port, extras=extras)
        cand_rank = _SIG_RANK.get(cand.get("confidence"), 0) if isinstance(cand, dict) else 0
        if cand_rank > rank:
            best, rank = cand, cand_rank
    return best if isinstance(best, dict) else None


def _orphan_url(port: int, sig: dict | None, hip: str, webish: set[int]) -> str | None:
    """Clickable URL for one orphan port, or None.

    A signature's ``http`` flag beats the port-number guess in both directions
    — Redis on 8079 gets no link, Syncthing's GUI on 8384 gets one.
    """
    sig_http = sig.get("http") if isinstance(sig, dict) else None
    hip = _utf8_text(hip)
    if sig_http is False:
        return None
    if sig_http is True and (sig or {}).get("confidence") == "high":
        return f"https://{hip}:{port}" if port in (443, 8443) else f"http://{hip}:{port}"
    if port in webish or port >= 8000:
        if port in (443, 8443, 8281):
            return f"https://{hip}:{port}"
        return f"http://{hip}:{port}"
    return None


def scan_new_compose_projects() -> list[dict]:
    """Hint-only list of compose projects under ~/Services (for adaptive stacks)."""
    found: list[dict] = []
    try:
        home = user_home()
        if home is None:
            return found
        root = home / "Services"
        if not root.is_dir():
            return found
    except (OSError, ValueError):
        # Dying mount EIO; leftover NUL in a path is ValueError, not OSError.
        return found
    comps: list[Path] = []
    for pattern in ("*/docker-compose.y*ml", "*/compose.y*ml"):
        try:
            comps.extend(root.glob(pattern))
        except (OSError, ValueError):
            continue
    for comp in sorted(comps):
        # FUSE leftover ``\ud800`` in a stack dir used to 500 GET /api/adaptive/compose-scan.
        found.append({
            "id": _utf8_text(comp.parent.name),
            "path": _utf8_text(comp.parent),
            "compose": _utf8_text(comp),
        })
    return found


#: `listen 80;` / `listen 127.0.0.1:8080;` / `listen [::]:443 ssl;`
#: Leading `#` comments are excluded by the `^` + MULTILINE start.
_NGINX_LISTEN_RE = re.compile(r"^\s*listen\s+(\S+)", re.MULTILINE)


def _nginx_listen_ports(text: str) -> list[int]:
    """Ports from nginx `listen` directives; skip comments and unix sockets."""
    if isinstance(text, (bytes, bytearray)):
        text = text.decode("utf-8", "replace")
    elif not isinstance(text, str):
        return []
    ports: list[int] = []
    for raw in _NGINX_LISTEN_RE.findall(text):
        token = raw.split(";", 1)[0]
        if token.startswith("unix:"):
            continue
        if token.startswith("[") and "]:" in token:
            token = token.split("]:", 1)[1]
        elif ":" in token:
            token = token.rsplit(":", 1)[-1]
        m = re.match(r"(\d+)", token)
        if not m:
            continue
        try:
            port = int(m.group(1))
        except ValueError:
            continue
        if 1 <= port <= 65535:
            ports.append(port)
    return ports


#: Leftover multi-MB ``*.conf`` used to OOM GET /api/nginx.
_NGINX_CONF_CAP = 256 * 1024


def nginx_sites() -> list[dict]:
    """Parse system nginx conf.d for adaptive site inventory."""
    sites: list[dict] = []
    try:
        home = user_home()
        if home is None:
            return sites
        conf_d = home / "Services" / "nginx" / "conf.d"
        if not conf_d.is_dir():
            return sites
        files = sorted(conf_d.glob("*.conf"))
    except (OSError, ValueError):
        # Dying mount EIO; leftover NUL in conf.d is ValueError, not OSError.
        return sites
    for f in files:
        try:
            # Directories named ``*.conf`` and character devices are not sites.
            # MemoryError / ValueError (huge file, embedded NUL) used to 500
            # GET /api/nginx because only OSError was caught.
            if not f.is_file():
                continue
            text = read_text_capped(f, _NGINX_CONF_CAP, errors="replace")
            if isinstance(text, (bytes, bytearray)):
                text = text.decode("utf-8", "replace")
            elif not isinstance(text, str):
                continue
            sites.append({
                "file": _utf8_text(f.name),
                "path": _utf8_text(f),
                "listens": _nginx_listen_ports(text),
                "server_names": [
                    _utf8_text(s.strip())
                    for s in re.findall(r"server_name\s+([^;]+);", text)
                ],
                "upstreams": [
                    _utf8_text(p.strip())
                    for p in re.findall(r"proxy_pass\s+([^;]+);", text)[:8]
                ],
            })
        except (OSError, ValueError, TypeError, MemoryError, UnicodeError):
            continue
    return sites
