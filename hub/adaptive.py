"""Adaptive discovery — auto port/url/group for new services without manual yaml.

When you add:
  - a LaunchAgent under ~/Library/LaunchAgents
  - a docker container / compose under ~/Services
  - a listening process
ServerHub infers ports, HTTP URLs, and grouping without requiring overrides.
"""
from __future__ import annotations

import re
from pathlib import Path

from hub.host_address import host_ip as resolved_host_ip
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
_PORT_IN_TEXT = re.compile(r"(?:[:\s=]|^)(\d{2,5})(?:\b|/tcp)")


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


def ports_for_pid(pid: str | int) -> list[int]:
    """Listening TCP ports owned by pid (via lsof)."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return []
    if pid <= 0:
        return []
    rc, out, _ = sh(
        ["/usr/sbin/lsof", "-nP", "-a", "-p", str(pid), "-iTCP", "-sTCP:LISTEN"],
        timeout=6,
    )
    if rc != 0:
        return []
    ports = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        name = parts[-2] if parts[-1] == "(LISTEN)" else parts[-1]
        # *:8125 or 127.0.0.1:8125
        m = re.search(r":(\d+)$", name)
        if m:
            p = int(m.group(1))
            if p not in ports:
                ports.append(p)
    return ports


# ports that are almost never HTTP UI
_NON_HTTP_PORTS = {
    22, 53, 123, 143, 993, 995, 25, 465, 587,
    1883, 8883, 5432, 5433, 3306, 6379, 27017, 5672, 11211,
    445, 139, 548, 2049, 5353, 5900, 3283,
}


def guess_http_url(port: int, prefer_https: bool = False) -> str | None:
    """Return URL only if port looks like HTTP(S) and responds like a web service."""
    if port in _NON_HTTP_PORTS:
        return None
    if not port_open(port, host="localhost", timeout=0.35):
        return None
    hip = host_ip()
    import ssl
    import urllib.error
    import urllib.request
    schemes = ("https", "http") if prefer_https or port in (443, 8443, 8281) else ("http", "https")
    for scheme in schemes:
        url = f"{scheme}://localhost:{port}/"
        try:
            req = urllib.request.Request(url, method="GET", headers={"User-Agent": "ServerHub/adapt"})
            ctx = ssl._create_unverified_context() if scheme == "https" else None
            with urllib.request.urlopen(req, timeout=0.8, context=ctx) as r:
                code = r.status
                if 200 <= code < 500:  # including 401/404 means web server
                    return f"{scheme}://{hip}:{port}"
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 401, 403, 404, 421):
                return f"{scheme}://{hip}:{port}"
        except Exception:
            continue
    return None


def friendly_name(label: str) -> str:
    """Humanize launchd label when no override name."""
    name = label
    for prefix in (
        "local.", "com.elvin.", "com.homeassistant.", "com.gravity.",
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
        return "定时任务"
    low = label.lower()
    path = " ".join(str(a) for a in (pl.get("ProgramArguments") or [])).lower()
    if "nginx" in low or "nginx" in path:
        return "网关"
    if "homeassistant" in low or "home-assistant" in path:
        return "Home Assistant"
    if "gravity" in low or "gravity" in path:
        return "Gravity 量化"
    if "homebrew" in low or "mxcl" in low:
        return "Homebrew 服务"
    if "docker" in low or "orb" in low:
        return "应用"
    if any(x in path for x in ("/services/", "services/")):
        return "原生服务"
    return "原生服务"


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
        if item.get("state") == "ok" and "运行中" in item["detail"]:
            item["detail"] = item["detail"] + f" · :{primary}"
    # mark adaptive
    if item.get("auto"):
        item.setdefault("meta", {})
        item["meta"]["adaptive"] = True
    return item


def discover_orphan_listeners(known_ports: set[int], known_names: set[str]) -> list[dict]:
    """Expose listening ports not already owned by a known service (auto-discovered apps)."""
    rc, out, _ = sh(
        ["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN"],
        timeout=10,
    )
    if rc != 0:
        return []
    # group by port
    by_port: dict[int, dict] = {}
    skip_proc = {
        "rapportd", "ControlCe", "ARDAgent", "sharingd", "identitys",
        "SystemUIS", "syncthing", "Cursor", "Code", "Google", "Chrome",
        "WeChat", "QQ", "Spotify", "Music", "Zoom", "Slack",
    }
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        proc, pid, name = parts[0], parts[1], parts[8]
        if any(proc.startswith(s) for s in skip_proc):
            continue
        m = re.search(r":(\d+)$", name)
        if not m:
            continue
        port = int(m.group(1))
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

    hip = host_ip()
    items = []
    # Speed: port already LISTEN from lsof → treat as ok; skip extra TCP + HTTP probes
    # (guess_http_url can cost 0.5–2s per port).
    webish = {80, 443, 3000, 3001, 4000, 5000, 8000, 8080, 8086, 8095, 8123, 8125, 8200, 8280, 8281, 8501, 8765, 9000}
    for port, info in sorted(by_port.items()):
        if any(info["proc"].lower() in n.lower() for n in known_names):
            continue
        if port in webish or port >= 8000:
            url = f"http://{hip}:{port}" if port not in (443, 8443, 8281) else f"https://{hip}:{port}"
            if port in (443, 8443):
                url = f"https://{hip}:{port}"
        else:
            url = None
        items.append({
            "id": f"auto.port.{port}",
            "kind": "auto",
            "name": f"{info['proc']} :{port}",
            "state": "ok",
            "detail": f"自动发现 · pid {info['pid']} · {info['bind']}",
            "url": url,
            "group": "自动发现",
            "actions": [],
            "auto": True,
            "meta": {"port": port, "pid": info["pid"], "process": info["proc"]},
        })
    return items[:40]


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
