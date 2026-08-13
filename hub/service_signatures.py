"""Generalized service recognition for adaptive discovery.

Orphan listeners used to surface as ``proc :port`` with a port-number
heuristic deciding whether they got a clickable URL.  This module gives the
scan an actual signature library: well-known daemons matched by process name
(strong) or default port (weak hint), each carrying a display name, a
category, and whether the thing serves a web UI at all.

The library is deliberately small and curated — it exists to make the common
homelab daemons recognisable, not to fingerprint arbitrary software.  Process
matches beat port matches because ports get reused; a port-only match is
reported with low confidence so callers can keep the raw process name visible.
"""
from __future__ import annotations

import re

#: One signature per known service.
#:   procs: lowercase process-name tokens.  Matched exact or by prefix in
#:          either direction, because `lsof` truncates COMMAND (e.g. a
#:          "postgres_real" binary reports as "postgres_r").
#:   ports: default listen ports, used only as a hint.
#:   http:  True  → serves a browser UI, link it even off the webish list;
#:          False → never HTTP (linking it only makes the daemon log attacks);
#:          None  → unknown, fall back to the port heuristics.
_SIGNATURES: list[dict] = [
    # Databases
    {"slug": "postgres", "name": "PostgreSQL", "category": "Databases",
     "procs": ("postgres", "postmaster"), "ports": (5432, 5433), "http": False},
    {"slug": "mysql", "name": "MySQL/MariaDB", "category": "Databases",
     "procs": ("mysqld", "mariadbd"), "ports": (3306,), "http": False},
    {"slug": "mongodb", "name": "MongoDB", "category": "Databases",
     "procs": ("mongod",), "ports": (27017,), "http": False},
    {"slug": "redis", "name": "Redis", "category": "Databases",
     "procs": ("redis-server", "redis-serv"), "ports": (6379, 6380), "http": False},
    {"slug": "memcached", "name": "Memcached", "category": "Databases",
     "procs": ("memcached",), "ports": (11211,), "http": False},
    {"slug": "clickhouse", "name": "ClickHouse", "category": "Databases",
     "procs": ("clickhouse",), "ports": (8123, 9000), "http": None},
    {"slug": "influxdb", "name": "InfluxDB", "category": "Databases",
     "procs": ("influxd",), "ports": (8086,), "http": True},
    {"slug": "elasticsearch", "name": "Elasticsearch", "category": "Databases",
     "procs": ("elasticsearch",), "ports": (9200,), "http": True},

    # Message brokers / queues
    {"slug": "mosquitto", "name": "Mosquitto MQTT", "category": "Messaging",
     "procs": ("mosquitto",), "ports": (1883, 8883), "http": False},
    {"slug": "rabbitmq", "name": "RabbitMQ", "category": "Messaging",
     "procs": ("beam.smp", "rabbitmq"), "ports": (5672,), "http": False},
    {"slug": "nats", "name": "NATS", "category": "Messaging",
     "procs": ("nats-server",), "ports": (4222,), "http": False},
    {"slug": "kafka", "name": "Kafka", "category": "Messaging",
     "procs": ("kafka",), "ports": (9092,), "http": False},

    # Web servers / proxies
    {"slug": "nginx", "name": "nginx", "category": "Web Servers",
     "procs": ("nginx",), "ports": (), "http": True},
    {"slug": "caddy", "name": "Caddy", "category": "Web Servers",
     "procs": ("caddy",), "ports": (2019,), "http": True},
    {"slug": "apache", "name": "Apache httpd", "category": "Web Servers",
     "procs": ("httpd", "apache2"), "ports": (), "http": True},
    {"slug": "traefik", "name": "Traefik", "category": "Web Servers",
     "procs": ("traefik",), "ports": (), "http": True},
    {"slug": "haproxy", "name": "HAProxy", "category": "Web Servers",
     "procs": ("haproxy",), "ports": (), "http": None},

    # Media
    {"slug": "plex", "name": "Plex Media Server", "category": "Media",
     "procs": ("plex",), "ports": (32400,), "http": True},
    {"slug": "jellyfin", "name": "Jellyfin", "category": "Media",
     "procs": ("jellyfin",), "ports": (8096,), "http": True},
    {"slug": "emby", "name": "Emby", "category": "Media",
     "procs": ("embyserver",), "ports": (8096,), "http": True},
    {"slug": "navidrome", "name": "Navidrome", "category": "Media",
     "procs": ("navidrome",), "ports": (4533,), "http": True},

    # Downloads / *arr
    {"slug": "transmission", "name": "Transmission", "category": "Downloads",
     "procs": ("transmission",), "ports": (9091,), "http": True},
    {"slug": "qbittorrent", "name": "qBittorrent", "category": "Downloads",
     "procs": ("qbittorrent",), "ports": (), "http": True},
    {"slug": "aria2", "name": "aria2", "category": "Downloads",
     "procs": ("aria2c",), "ports": (6800,), "http": False},
    {"slug": "sonarr", "name": "Sonarr", "category": "Downloads",
     "procs": ("sonarr",), "ports": (8989,), "http": True},
    {"slug": "radarr", "name": "Radarr", "category": "Downloads",
     "procs": ("radarr",), "ports": (7878,), "http": True},
    {"slug": "prowlarr", "name": "Prowlarr", "category": "Downloads",
     "procs": ("prowlarr",), "ports": (9696,), "http": True},
    {"slug": "bazarr", "name": "Bazarr", "category": "Downloads",
     "procs": ("bazarr",), "ports": (6767,), "http": True},

    # Home automation
    {"slug": "home-assistant", "name": "Home Assistant", "category": "Home Automation",
     "procs": ("hass",), "ports": (8123,), "http": True},
    {"slug": "zigbee2mqtt", "name": "Zigbee2MQTT", "category": "Home Automation",
     "procs": ("zigbee2mqt",), "ports": (), "http": True},
    {"slug": "esphome", "name": "ESPHome", "category": "Home Automation",
     "procs": ("esphome",), "ports": (6052,), "http": True},
    {"slug": "homebridge", "name": "Homebridge", "category": "Home Automation",
     "procs": ("homebridge",), "ports": (8581,), "http": True},

    # Monitoring
    {"slug": "grafana", "name": "Grafana", "category": "Monitoring",
     "procs": ("grafana",), "ports": (), "http": True},
    {"slug": "prometheus", "name": "Prometheus", "category": "Monitoring",
     "procs": ("prometheus",), "ports": (9090,), "http": True},
    {"slug": "node-exporter", "name": "Node Exporter", "category": "Monitoring",
     "procs": ("node_expor",), "ports": (9100,), "http": True},
    {"slug": "uptime-kuma", "name": "Uptime Kuma", "category": "Monitoring",
     "procs": (), "ports": (3001,), "http": True},
    {"slug": "netdata", "name": "Netdata", "category": "Monitoring",
     "procs": ("netdata",), "ports": (19999,), "http": True},

    # Dev tools
    {"slug": "gitea", "name": "Gitea", "category": "Dev Tools",
     "procs": ("gitea",), "ports": (), "http": True},
    {"slug": "forgejo", "name": "Forgejo", "category": "Dev Tools",
     "procs": ("forgejo",), "ports": (), "http": True},
    {"slug": "jupyter", "name": "Jupyter", "category": "Dev Tools",
     "procs": ("jupyter",), "ports": (8888,), "http": True},
    {"slug": "code-server", "name": "code-server", "category": "Dev Tools",
     "procs": ("code-serve",), "ports": (), "http": True},

    # Storage / files
    {"slug": "minio", "name": "MinIO", "category": "Storage",
     "procs": ("minio",), "ports": (9001,), "http": True},
    {"slug": "syncthing", "name": "Syncthing", "category": "Storage",
     "procs": ("syncthing",), "ports": (8384,), "http": True},
    {"slug": "filebrowser", "name": "File Browser", "category": "Storage",
     "procs": ("filebrowse",), "ports": (), "http": True},
    {"slug": "smb", "name": "SMB File Sharing", "category": "Storage",
     "procs": ("smbd",), "ports": (445, 139), "http": False},

    # Network / VPN
    {"slug": "adguard", "name": "AdGuard Home", "category": "Network",
     "procs": ("adguardhom", "adguard"), "ports": (), "http": True},
    {"slug": "dnsmasq", "name": "dnsmasq", "category": "Network",
     "procs": ("dnsmasq",), "ports": (53,), "http": False},
    {"slug": "unbound", "name": "Unbound DNS", "category": "Network",
     "procs": ("unbound",), "ports": (53,), "http": False},
    {"slug": "frps", "name": "frp Server", "category": "Network",
     "procs": ("frps",), "ports": (7000,), "http": False},
    {"slug": "frpc", "name": "frp Client", "category": "Network",
     "procs": ("frpc",), "ports": (), "http": False},
    {"slug": "xray", "name": "Xray/V2Ray", "category": "Network",
     "procs": ("xray", "v2ray"), "ports": (), "http": False},
    {"slug": "clash", "name": "Clash/Mihomo", "category": "Network",
     "procs": ("clash", "mihomo"), "ports": (7890, 7891), "http": False},
    {"slug": "tailscale", "name": "Tailscale", "category": "Network",
     "procs": ("tailscaled",), "ports": (), "http": False},
    {"slug": "sshd", "name": "SSH", "category": "Network",
     "procs": ("sshd",), "ports": (22,), "http": False},

    # AI
    {"slug": "ollama", "name": "Ollama", "category": "AI",
     "procs": ("ollama",), "ports": (11434,), "http": False},
    {"slug": "open-webui", "name": "Open WebUI", "category": "AI",
     "procs": ("open-webui", "open_webui"), "ports": (), "http": True},

    # Panels / misc
    {"slug": "portainer", "name": "Portainer", "category": "Panels",
     "procs": ("portainer",), "ports": (9443,), "http": True},
    {"slug": "dockge", "name": "Dockge", "category": "Panels",
     "procs": (), "ports": (5001,), "http": True},
    {"slug": "vaultwarden", "name": "Vaultwarden", "category": "Panels",
     "procs": ("vaultwarde",), "ports": (), "http": True},
]

#: Generic runtimes that host someone else's code: recognising "node" tells the
#: operator nothing about *which* service it is, so these only contribute the
#: category and never rename the entry.
_RUNTIMES = {
    "node": "Node.js", "bun": "Bun", "deno": "Deno",
    "python": "Python", "python3": "Python",
    "gunicorn": "Gunicorn", "uvicorn": "Uvicorn",
    "java": "Java", "ruby": "Ruby", "php": "PHP",
}


def _proc_matches(proc: str, token: str) -> bool:
    """Whether a live process name matches a signature token.

    Prefix matching runs in both directions because `lsof` truncates COMMAND:
    the signature may hold the full name while lsof reports a prefix of it.
    Short tokens must match exactly or "node" would swallow "nodered".
    """
    if not proc or not token:
        return False
    if proc == token:
        return True
    if len(token) >= 5 and proc.startswith(token):
        return True
    if len(proc) >= 5 and token.startswith(proc):
        return True
    return False


def identify(proc: str = "", port: int | None = None) -> dict | None:
    """Recognise a service from its process name and/or listen port.

    Returns ``{"slug", "name", "category", "http", "confidence"}`` or None.
    Confidence is "high" for a process-name match (optionally corroborated by
    the port) and "low" for a port-only match, which callers should treat as a
    hint rather than an identity.
    """
    low = (proc or "").strip().lower()
    port_only: dict | None = None
    for sig in _SIGNATURES:
        by_proc = any(_proc_matches(low, t) for t in sig["procs"])
        by_port = port is not None and port in sig["ports"]
        if by_proc:
            return {
                "slug": sig["slug"], "name": sig["name"],
                "category": sig["category"], "http": sig["http"],
                "confidence": "high",
            }
        if by_port and port_only is None:
            port_only = {
                "slug": sig["slug"], "name": sig["name"],
                "category": sig["category"], "http": sig["http"],
                "confidence": "low",
            }
    if port_only:
        return port_only
    runtime = _RUNTIMES.get(low)
    if runtime:
        return {
            "slug": low, "name": runtime, "category": "Runtimes",
            "http": None, "confidence": "runtime",
        }
    return None


def suggest_id(*candidates: str, taken: set[str] | None = None) -> str:
    """A services.yaml-safe unique id from the first usable candidate."""
    taken = taken or set()
    base = ""
    for cand in candidates:
        slug = re.sub(r"[^a-z0-9]+", "-", str(cand or "").lower()).strip("-")
        if slug:
            base = slug
            break
    if not base:
        base = "service"
    if base not in taken:
        return base
    n = 2
    while f"{base}-{n}" in taken:
        n += 1
    return f"{base}-{n}"
