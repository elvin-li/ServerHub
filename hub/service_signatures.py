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
from pathlib import Path

from hub import cli_args

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")


def _isinst(value, types) -> bool:
    """``isinstance`` that a leftover ``__class__`` bomb cannot 500 through.

    CPython's ``isinstance`` reads the operand's ``__class__`` whenever the
    real-type fast check misses, so a leftover whose ``__class__`` is a
    raising property blew unguarded signature-library gates — GET
    /api/status answered HTTP 500 instead of dropping the junk cell.
    Fail-closed.
    """
    try:
        return isinstance(value, types)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


#: One signature per known service.
#:   procs: lowercase process-name tokens.  Matched exact or by prefix in
#:          either direction, because `lsof` truncates COMMAND (e.g. a
#:          "postgres_real" binary reports as "postgres_r").
#:   ports: default listen ports, used only as a hint.
#:   http:  True  → serves a browser UI, link it even off the webish list;
#:          False → never HTTP (linking it only makes the daemon log attacks);
#:          None  → unknown, fall back to the port heuristics.
#:   brew:  Homebrew formula name when it is unambiguous (used to infer
#:          start/stop as ``brew services …``).  Versioned formulae such as
#:          postgresql@17 are left unset and recovered from the binary path.
_SIGNATURES: list[dict] = [
    # Databases
    {"slug": "postgres", "name": "PostgreSQL", "category": "Databases",
     "procs": ("postgres", "postmaster"), "ports": (5432, 5433), "http": False},
    {"slug": "mysql", "name": "MySQL/MariaDB", "category": "Databases",
     "procs": ("mysqld", "mariadbd"), "ports": (3306,), "http": False},
    {"slug": "mongodb", "name": "MongoDB", "category": "Databases",
     "procs": ("mongod",), "ports": (27017,), "http": False},
    {"slug": "redis", "name": "Redis", "category": "Databases",
     "procs": ("redis-server", "redis-serv"), "ports": (6379, 6380), "http": False,
     "brew": "redis"},
    {"slug": "memcached", "name": "Memcached", "category": "Databases",
     "procs": ("memcached",), "ports": (11211,), "http": False, "brew": "memcached"},
    {"slug": "clickhouse", "name": "ClickHouse", "category": "Databases",
     "procs": ("clickhouse",), "ports": (8123, 9000), "http": None},
    {"slug": "influxdb", "name": "InfluxDB", "category": "Databases",
     "procs": ("influxd",), "ports": (8086,), "http": True},
    {"slug": "elasticsearch", "name": "Elasticsearch", "category": "Databases",
     "procs": ("elasticsearch",), "ports": (9200,), "http": True},

    # Message brokers / queues
    {"slug": "mosquitto", "name": "Mosquitto MQTT", "category": "Messaging",
     "procs": ("mosquitto",), "ports": (1883, 8883), "http": False, "brew": "mosquitto"},
    {"slug": "rabbitmq", "name": "RabbitMQ", "category": "Messaging",
     "procs": ("beam.smp", "rabbitmq"), "ports": (5672,), "http": False},
    {"slug": "nats", "name": "NATS", "category": "Messaging",
     "procs": ("nats-server",), "ports": (4222,), "http": False},
    {"slug": "kafka", "name": "Kafka", "category": "Messaging",
     "procs": ("kafka",), "ports": (9092,), "http": False},

    # Web servers / proxies
    {"slug": "nginx", "name": "nginx", "category": "Web Servers",
     "procs": ("nginx",), "ports": (), "http": True, "brew": "nginx"},
    {"slug": "caddy", "name": "Caddy", "category": "Web Servers",
     "procs": ("caddy",), "ports": (2019,), "http": True, "brew": "caddy"},
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
     "procs": ("syncthing",), "ports": (8384,), "http": True, "brew": "syncthing"},
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
     "procs": ("ollama",), "ports": (11434,), "http": False, "brew": "ollama"},
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

def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
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


#: lsof/ps encode a space in COMMAND as ``\x20`` (hex) or ``\040`` (octal)
#: because the field is whitespace-delimited.  Leaving those sequences literal
#: is what made the Services list show ``Plex\x20M`` instead of ``Plex M``.
_C_HEX_ESC = re.compile(r"\\x([0-9a-fA-F]{2})")
_C_OCT_ESC = re.compile(r"\\([0-7]{3})")


def unescape_proc_name(name: str) -> str:
    """Decode C-style byte escapes that lsof and ps leave in a process name."""
    raw = _utf8_text(name)
    if "\\" not in raw:
        return raw

    def _byte(value: int, original: str) -> str:
        if value == 0:
            return original
        if value < 32 or value == 127:
            return " "
        return chr(value)

    def _hex(match: re.Match[str]) -> str:
        return _byte(int(match.group(1), 16), match.group(0))

    def _oct(match: re.Match[str]) -> str:
        return _byte(int(match.group(1), 8), match.group(0))

    return _C_OCT_ESC.sub(_oct, _C_HEX_ESC.sub(_hex, raw))


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


def _hit(sig: dict, confidence: str) -> dict:
    out = {
        "slug": sig["slug"], "name": sig["name"],
        "category": sig["category"], "http": sig.get("http"),
        "confidence": confidence,
    }
    if sig.get("brew"):
        out["brew"] = sig["brew"]
    return out


def _iter_signatures(extras: list[dict] | None):
    """Operator-defined signatures first, so they override a built-in slug."""
    seen: set[str] = set()
    for sig in extras or []:
        if not _isinst(sig, dict):
            continue
        slug = sig.get("slug")
        if not slug or slug in seen:
            continue
        seen.add(slug)
        yield sig
    for sig in _SIGNATURES:
        if sig["slug"] not in seen:
            yield sig


def image_basename(image: str) -> str:
    """Last path component of a container image, without tag or digest.

    ``grafana/grafana:latest`` → ``grafana``, ``redis:7`` → ``redis``,
    ``sha256:abc…`` → ``""``.  The empty string means "do not match".
    """
    text = (image or "").strip()
    if not text or text.startswith("sha256:"):
        return ""
    text = text.split("@", 1)[0]
    name = text.rsplit("/", 1)[-1]
    if ":" in name:
        name = name.rsplit(":", 1)[0]
    name = name.strip().lower()
    return name if name and name != "sha256" else ""


def identify(
    proc: str = "",
    port: int | None = None,
    extras: list[dict] | None = None,
    image: str = "",
) -> dict | None:
    """Recognise a service from its process name, image, and/or listen port.

    Returns ``{"slug", "name", "category", "http", "confidence"}`` (and
    ``brew`` when known) or None.  Confidence is "high" for a process-name
    or image match and "low" for a port-only match, which callers should
    treat as a hint rather than an identity.  ``extras`` are operator-defined
    signatures from services.yaml; a matching slug replaces the built-in entry.
    """
    low = unescape_proc_name(proc or "").strip().lower()
    img = image_basename(image)
    port_only: dict | None = None
    image_hit: dict | None = None
    for sig in _iter_signatures(extras):
        tokens = tuple(sig.get("procs") or ())
        by_proc = any(_proc_matches(low, t) for t in tokens)
        by_image = bool(img) and (
            any(_proc_matches(img, t) for t in tokens)
            or _proc_matches(img, sig["slug"])
        )
        by_port = port is not None and port in (sig.get("ports") or ())
        if by_proc:
            return _hit(sig, "high")
        if by_image and image_hit is None:
            image_hit = _hit(sig, "high")
        if by_port and port_only is None:
            port_only = _hit(sig, "low")
    if image_hit:
        return image_hit
    if port_only:
        return port_only
    runtime = _RUNTIMES.get(low) or _RUNTIMES.get(img)
    if runtime:
        slug = low if low in _RUNTIMES else img
        return {
            "slug": slug, "name": runtime, "category": "Runtimes",
            "http": None, "confidence": "runtime",
        }
    return None


def parse_signature(raw) -> dict | None:
    """Normalise one operator-defined signature, or None if it is unusable."""
    if not _isinst(raw, dict):
        return None
    # _utf8_text (a str() probe), not bare str(): a hand-edited hex slug
    # (``slug: 0xfff…`` loads uncapped through YAML) raised the int->str
    # digit-cap ValueError here, which 500'd GET/PUT/DELETE
    # /api/services/signatures and silently wiped every discovery row that
    # reads configured_signatures().  A numeric YAML slug (``slug: 123``)
    # still coerces; the over-cap leftover drops only its own row.
    slug = re.sub(r"[^a-z0-9]+", "-", _utf8_text(raw.get("slug") or "").lower()).strip("-")
    if not slug:
        return None
    raw_procs = raw.get("procs")
    # _utf8_text: a JSON ``"\ud800"`` proc/name/category used to reach the
    # stored row and 500 PUT /api/services/signatures on the response encode.
    procs = tuple(
        p
        for p in (
            _utf8_text(item).strip().lower()
            for item in (raw_procs if _isinst(raw_procs, list) else [])
        )
        if p
    )
    ports: list[int] = []
    raw_ports = raw.get("ports")
    # YAML ``ports: !!set`` is a set; ``[.inf]`` OverflowError's ``int()``.
    port_rows = raw_ports if _isinst(raw_ports, (list, tuple, set, frozenset)) else []
    for p in port_rows:
        if type(p) is bool:
            continue
        try:
            n = int(p)
        except (TypeError, ValueError, OverflowError):
            continue
        if 1 <= n <= 65535 and n not in ports:
            ports.append(n)
    http = raw.get("http")
    if http not in (True, False, None):
        http = None
    # Same str() probe: an over-cap ``brew:`` leftover drops the field, not
    # the row (and never the whole signatures listing).
    brew = _utf8_text(raw.get("brew") or "").strip()
    if brew and not cli_args.is_safe_positional(brew):
        brew = ""
    return {
        "slug": slug,
        "name": _utf8_text(raw.get("name") or slug).strip() or slug,
        "category": _utf8_text(raw.get("category") or "Custom").strip() or "Custom",
        "procs": procs,
        "ports": tuple(ports),
        "http": http,
        "brew": brew or None,
    }


def configured_signatures() -> list[dict]:
    """Operator-defined signatures from services.yaml, already normalised."""
    try:
        from hub.config import cfg

        raw = cfg().get("service_signatures") or []
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return []
    if not _isinst(raw, list):
        return []
    out: list[dict] = []
    seen: set[str] = set()
    for item in raw:
        sig = parse_signature(item)
        if not sig or sig["slug"] in seen:
            continue
        seen.add(sig["slug"])
        out.append(sig)
    return out


#: Homebrew cellar / opt layout: …/opt/redis/bin/… or …/Cellar/postgresql@17/…
_BREW_PATH = re.compile(
    r"(?:/opt/homebrew|/usr/local)/(?:opt|Cellar)/([^/]+)"
)


def brew_formula_from_path(path: str) -> str | None:
    """Formula name encoded in a Homebrew binary path, if the name is argv-safe."""
    m = _BREW_PATH.search(path or "")
    if not m:
        return None
    formula = m.group(1)
    return formula if cli_args.is_safe_positional(formula) else None


def control_commands(formula: str | None) -> dict:
    """``brew services`` start/stop for *formula*, or {} if it is not usable.

    The absolute brew path is preferred so a LaunchAgent panel (which often
    has no Homebrew on PATH) can still run the commands later.
    """
    if not formula or not cli_args.is_safe_positional(formula):
        return {}
    try:
        from hub.paths import BREW

        brew = BREW if Path(BREW).is_file() else "brew"
    except _CONTROL_FLOW:
        raise
    except BaseException:
        brew = "brew"
    return {
        "via": "brew",
        "formula": formula,
        "start": f"{brew} services start {formula}",
        "stop": f"{brew} services stop {formula}",
    }


def infer_control(sig: dict | None, command_path: str = "") -> dict:
    """Best start/stop we can infer from a signature and/or the live binary.

    A path under the Homebrew prefix wins: it knows the versioned formula
    (``postgresql@17``) that a static signature cannot.  A high-confidence
    signature's ``brew`` field is the fallback.
    """
    formula = brew_formula_from_path(command_path)
    if not formula and sig and sig.get("confidence") == "high":
        formula = sig.get("brew")
    return control_commands(formula)


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


def is_generic_runtime(proc: str) -> bool:
    """True when *proc* is a language runtime, not a specific service."""
    return (proc or "").strip().lower() in _RUNTIMES


def yaml_signature(sig: dict) -> dict:
    """The services.yaml shape of a normalised signature (no empty keys)."""
    row: dict = {
        "slug": sig["slug"],
        "name": sig["name"],
        "category": sig["category"],
    }
    if sig.get("procs"):
        row["procs"] = list(sig["procs"])
    if sig.get("ports"):
        row["ports"] = list(sig["ports"])
    if sig.get("http") is not None:
        row["http"] = sig["http"]
    if sig.get("brew"):
        row["brew"] = sig["brew"]
    return row


def remember_into(data: dict, sig: dict) -> dict:
    """Upsert *sig* into ``data['service_signatures']``. Returns the stored row.

    Same slug replaces the previous operator rule so renaming on adopt
    updates the learned identity instead of accumulating duplicates.
    """
    row = yaml_signature(sig)
    rows = data.get("service_signatures")
    if not _isinst(rows, list):
        rows = []
        data["service_signatures"] = rows
    slug = row["slug"]
    for i, existing in enumerate(rows):
        parsed = parse_signature(existing)
        if parsed and parsed["slug"] == slug:
            rows[i] = row
            return row
    rows.append(row)
    return row


def remove_from(data: dict, slug: str) -> dict | None:
    """Drop the operator rule with *slug*. Returns the removed row, or None."""
    slug = re.sub(r"[^a-z0-9]+", "-", str(slug or "").lower()).strip("-")
    if not slug:
        return None
    rows = data.get("service_signatures")
    if not _isinst(rows, list):
        return None
    keep = []
    removed = None
    for existing in rows:
        parsed = parse_signature(existing)
        if parsed and parsed["slug"] == slug and removed is None:
            removed = yaml_signature(parsed)
            continue
        keep.append(existing)
    if removed is not None:
        data["service_signatures"] = keep
    return removed


def builtin_count() -> int:
    return len(_SIGNATURES)
