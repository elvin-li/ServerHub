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
from hub.service_signatures import configured_signatures, identify
from hub.util import port_open, sh

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
    ports: list[int] = []
    args = [str(a) for a in (pl.get("ProgramArguments") or [])]
    for i, a in enumerate(args):
        if a in _PORT_FLAGS and i + 1 < len(args):
            try:
                ports.append(int(args[i + 1]))
            except ValueError:
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
    env = pl.get("EnvironmentVariables") or {}
    for k, v in env.items():
        if _ENV_PORT_KEYS.match(str(k)):
            try:
                ports.append(int(str(v).strip()))
            except ValueError:
                pass
        if _URL_ENV_KEYS.match(str(k)):
            m = re.search(r":(\d{2,5})(?:/|$)", str(v))
            if m:
                ports.append(int(m.group(1)))
    # Sockets in plist (rare)
    for sock in (pl.get("Sockets") or {}).values():
        if isinstance(sock, dict):
            for key in ("SockServiceName", "SockPortName"):
                try:
                    ports.append(int(sock[key]))
                except (KeyError, ValueError, TypeError):
                    pass
    # unique valid
    out = []
    for p in ports:
        if 1 <= p <= 65535 and p not in out:
            out.append(p)
    return out


def url_from_plist(pl: dict) -> str | None:
    env = pl.get("EnvironmentVariables") or {}
    for k, v in env.items():
        if _URL_ENV_KEYS.match(str(k)) and str(v).startswith("http"):
            return str(v).strip()
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


def invalidate_lsof_snapshot() -> None:
    """Drop the listener snapshot so the next read reflects current reality."""
    with _lsof_lock:
        _lsof_cache["t"] = 0.0
        _lsof_cache["v"] = None


def _parse_lsof_listen(out: str) -> list[dict[str, Any]]:
    """Rows of {proc, pid, bind, port} from `lsof -nP -iTCP -sTCP:LISTEN` text."""
    rows: list[dict[str, Any]] = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        # NAME is the last field, unless lsof appended the (LISTEN) state token.
        bind = parts[-2] if parts[-1] == "(LISTEN)" else parts[-1]
        m = re.search(r":(\d+)$", bind)
        if not m:
            continue
        try:
            port = int(m.group(1))
        except ValueError:
            continue
        rows.append({"proc": parts[0], "pid": parts[1], "bind": bind, "port": port})
    return rows


def lsof_listen_snapshot() -> list[dict[str, Any]]:
    """Every listening TCP socket on the host, cached behind a short TTL."""
    now = time.time()
    with _lsof_lock:
        if _lsof_cache["v"] is not None and now - _lsof_cache["t"] < _LSOF_TTL:
            return _lsof_cache["v"]
    with _lsof_refresh_lock:
        # Another thread may have refreshed while we waited for the lock.
        now = time.time()
        with _lsof_lock:
            if _lsof_cache["v"] is not None and now - _lsof_cache["t"] < _LSOF_TTL:
                return _lsof_cache["v"]
        rc, out, _ = sh(
            ["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN"],
            timeout=10,
        )
        rows = _parse_lsof_listen(out) if rc == 0 else []
        with _lsof_lock:
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
    except (TypeError, ValueError):
        return []
    if pid <= 0:
        return []
    want = str(pid)
    ports: list[int] = []
    for row in lsof_listen_snapshot():
        if row["pid"] != want:
            continue
        if row["port"] not in ports:
            ports.append(row["port"])
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
    if port in _NON_HTTP_PORTS:
        return None
    if _recently_not_http(port):
        return None
    if not port_open(port, host="localhost", timeout=0.35):
        return None
    proto, head = _probe_protocol(port)
    if not proto:
        # Accepts connections but speaks neither HTTP nor TLS.  No URL, and no
        # second timeout spent confirming it.  Remembered so that a service on a
        # non-default port is probed once rather than once per refresh: the probe
        # sends a real `GET / ... Host:` line, which a non-HTTP daemon may log as
        # an attack.
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

    try:
        req = urllib.request.Request(
            f"https://localhost:{port}/",
            method="GET",
            headers={"User-Agent": "ServerHub/adapt"},
        )
        ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(req, timeout=0.8, context=ctx) as r:
            if 200 <= r.status < 500:
                return f"https://{hip}:{port}"
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 401, 403, 404, 421):
            return f"https://{hip}:{port}"
    except Exception:
        return None
    return None


def friendly_name(label: str) -> str:
    """Humanize launchd label when no override name."""
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
        return label
    # Title-case short tokens
    pretty = " ".join(
        p.upper() if p.lower() in ("ha", "api", "ddns", "vm", "ssd") else p.capitalize()
        for p in parts
    )
    return pretty


def guess_group(label: str, pl: dict, interval: bool) -> str:
    if interval:
        return "Scheduled Tasks"
    low = label.lower()
    path = " ".join(str(a) for a in (pl.get("ProgramArguments") or [])).lower()
    if "nginx" in low or "nginx" in path:
        return "Gateway"
    if "homeassistant" in low or "home-assistant" in path:
        return "Home Assistant"
    if "homebrew" in low or "mxcl" in low:
        return "Homebrew Services"
    if "docker" in low or "orb" in low:
        return "Apps"
    if any(x in path for x in ("/services/", "services/")):
        return "Native Services"
    return "Native Services"


def enrich_service(item: dict, *, pl: dict | None = None, pid: str | None = None) -> dict:
    """Fill missing port/url/name/group using adaptive heuristics. Respects overrides already applied."""
    # name already from override or label
    if not item.get("url") and pl:
        u = url_from_plist(pl)
        if u:
            item["url"] = u
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
        item.setdefault("meta", {})
        item["meta"]["detected_ports"] = ports
        item["auto"] = True
    # re-evaluate port open if we detected
    if primary and not item.get("url"):
        url = guess_http_url(primary)
        if url:
            item["url"] = url
    # improve detail with ports if missing
    if primary and item.get("detail") and f":{primary}" not in item["detail"]:
        # "运行中" kept alongside "Running": the detail text is produced by
        # hub/discovery/*, which is migrating from Chinese to English prose.
        if item.get("state") == "ok" and ("Running" in item["detail"] or "运行中" in item["detail"]):
            item["detail"] = item["detail"] + f" · :{primary}"
    # mark adaptive
    if item.get("auto"):
        item.setdefault("meta", {})
        item["meta"]["adaptive"] = True
    return item


def discover_orphan_listeners(known_ports: set[int], known_names: set[str]) -> list[dict]:
    """Expose listening ports not already owned by a known service (auto-discovered apps)."""
    # Same snapshot ports_for_pid reads: this scan used to be a third global
    # lsof running after the status thread pool had already joined, adding
    # ~106ms of pure serial tail latency to every refresh.
    rows = lsof_listen_snapshot()
    # group by port
    by_port: dict[int, dict] = {}
    skip_proc = {
        "rapportd", "ControlCe", "ARDAgent", "sharingd", "identitys",
        "SystemUIS", "syncthing", "Cursor", "Code", "Google", "Chrome",
        "WeChat", "QQ", "Spotify", "Music", "Zoom", "Slack",
    }
    for row in rows:
        proc, pid, name = row["proc"], row["pid"], row["bind"]
        if any(proc.startswith(s) for s in skip_proc):
            continue
        port = row["port"]
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
        by_port[port] = {"proc": proc, "pid": pid, "bind": name}

    # Same process, several ports (Redis 6379+6380, a UI plus its metrics
    # port) used to become one card each.  Group by pid so adopt writes one
    # managed entry that health-checks every listen the process owns.
    by_pid: dict[str, list[tuple[int, dict]]] = {}
    for port, info in by_port.items():
        if any(info["proc"].lower() in n.lower() for n in known_names):
            continue
        by_pid.setdefault(info["pid"], []).append((port, info))

    hip = host_ip()
    extras = configured_signatures()
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
        if sig and sig.get("confidence") == "high":
            name = f"{sig['name']} {port_label}"
            detail = f"Auto-discovered · {sig['name']} · pid {pid} · {info['bind']}"
        elif sig:
            # Port-only or runtime match is a hint, so the raw process name
            # stays visible; the guess rides along in the detail line.
            name = f"{info['proc']} {port_label}"
            detail = f"Auto-discovered · {sig['name']}? · pid {pid} · {info['bind']}"
        else:
            name = f"{info['proc']} {port_label}"
            detail = f"Auto-discovered · pid {pid} · {info['bind']}"
        primary = ports[0]
        meta = {
            "port": primary,
            "ports": ports,
            "pid": pid,
            "process": info["proc"],
        }
        if sig:
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
            "group": "Auto-discovered",
            "actions": ["adopt"],
            "auto": True,
            "signature": sig,
            "meta": meta,
        })
    return items[:40]


_SIG_RANK = {"high": 3, "low": 2, "runtime": 1}


def _best_signature(proc: str, ports: list[int], extras: list[dict] | None):
    """Process-name match first; otherwise the strongest port hint among *ports*."""
    best = identify(proc, None, extras=extras)
    rank = _SIG_RANK.get((best or {}).get("confidence"), 0)
    if rank >= 3:
        return best
    for port in ports:
        cand = identify(proc, port, extras=extras)
        cand_rank = _SIG_RANK.get((cand or {}).get("confidence"), 0)
        if cand_rank > rank:
            best, rank = cand, cand_rank
    return best


def _orphan_url(port: int, sig: dict | None, hip: str, webish: set[int]) -> str | None:
    """Clickable URL for one orphan port, or None.

    A signature's ``http`` flag beats the port-number guess in both directions
    — Redis on 8079 gets no link, Syncthing's GUI on 8384 gets one.
    """
    sig_http = sig.get("http") if sig else None
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
    root = Path.home() / "Services"
    found = []
    if not root.is_dir():
        return found
    for comp in sorted(root.glob("*/docker-compose.y*ml")) + sorted(root.glob("*/compose.y*ml")):
        found.append({
            "id": comp.parent.name,
            "path": str(comp.parent),
            "compose": str(comp),
        })
    return found


def nginx_sites() -> list[dict]:
    """Parse system nginx conf.d for adaptive site inventory."""
    conf_d = Path.home() / "Services" / "nginx" / "conf.d"
    sites = []
    if not conf_d.is_dir():
        return sites
    for f in sorted(conf_d.glob("*.conf")):
        text = f.read_text(errors="replace")
        listens = re.findall(r"listen\s+(\d+)", text)
        servers = re.findall(r"server_name\s+([^;]+);", text)
        proxies = re.findall(r"proxy_pass\s+([^;]+);", text)
        sites.append({
            "file": f.name,
            "path": str(f),
            "listens": [int(x) for x in listens],
            "server_names": [s.strip() for s in servers],
            "upstreams": [p.strip() for p in proxies[:8]],
        })
    return sites
