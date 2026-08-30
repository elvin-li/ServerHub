"""Native (non-Docker) one-click deploys for macOS — prefer local over containers.

Methods:
  brew_formula  — brew install X && optional brew services start
  brew_cask     — brew install --cask X
  brew_service  — start existing brew formula as service
  binary_url    — download static binary (rare)
  system        — enable built-in macOS feature (Screen Sharing etc.)
  script        — safe shell snippet under ~/Services
"""
from __future__ import annotations

import contextlib
import logging
import os
import re
import shlex
import shutil
import threading
import time
from pathlib import Path
from typing import Any

from hub.brew_cache import brew_services_list, invalidate_brew_services
from hub.errors import CODES, api_error
from hub.host_address import host_ip
from hub.launchd_cache import invalidate_launchd
from hub.launchd_cache import running_labels as launchd_running_labels
# One definition, in hub.paths: it tries `which brew` before the two standard
# prefixes. The app store is the worst place to disagree about where brew is --
# every install and uninstall goes through it.
from hub.paths import BREW, user_home
from hub.proc_cache import invalidate_processes, process_matches
from hub.util import LazyPool, cached_snapshot, fan_out, run_capped, sh

_pool = LazyPool(3, "hub-native")


def shutdown_executor() -> None:
    _pool.shutdown()


def _default_services_root() -> Path:
    """Services tree under ``~/Services``.  ``Path.home()`` leftover must not 500 import."""
    home = user_home()
    return (home / "Services") if home is not None else Path("/var/empty/serverhub-services")


SERVICES_ROOT = _default_services_root()
_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")

#: Install outcomes go to the panel's own log (~/Library/Logs/serverhub.err.log).
#: An install that fails in a browser leaves no trace anywhere else: the response
#: body is gone as soon as the operator closes the dialog, and "the app store
#: cannot install anything" is unanswerable without knowing what brew said.
log = logging.getLogger("serverhub.appstore")

#: First line of a failed brew_multi message, and all the toast shows.  Named so
#: the store and its tests cannot disagree about it.
_MULTI_FAILED_PREFIX = "The following packages failed to install: "

# Store-owned error codes, registered next to the module that raises them so the
# code -> status mapping travels with it; api_error() degrades unknown codes to
# HTTP 500.  Codes rather than prose because the SPA is localized and text
# originating in Python cannot be translated by the frontend.
CODES.setdefault(
    "catalog.install_busy",
    (409, "{app} is already being installed or uninstalled; wait for it to finish"),
)
CODES.setdefault("catalog.brew_missing", (503, "Homebrew was not found at {path}"))
CODES.setdefault(
    "catalog.entry_incomplete",
    (500, "catalog entry {app} does not list the packages it installs"),
)
CODES.setdefault(
    "catalog.plist_write_failed",
    (409, "could not write LaunchAgent {label}: {detail}"),
)
CODES.setdefault(
    "catalog.path_blocked",
    (409, "could not create {path}: {detail}"),
)


def _brew_env() -> dict:
    env = dict(os.environ)
    path = env.get("PATH", "")
    for p in ("/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"):
        if p not in path:
            path = p + ":" + path
    env["PATH"] = path
    env.setdefault("HOMEBREW_NO_AUTO_UPDATE", "1")
    env.setdefault("HOMEBREW_NO_ANALYTICS", "1")
    env.setdefault("HOMEBREW_NO_ENV_HINTS", "1")
    return env


def _isinst(value, types) -> bool:
    """``isinstance`` a leftover ``__class__``-property bomb cannot 500 through.

    The catalog/docker_cli rule: CPython's ``isinstance`` reads the operand's
    ``__class__`` whenever the real-type fast check misses, so a subprocess
    leftover whose ``__class__`` is a raising property used to detonate
    ``_as_text``'s bytes gate itself — straight out of the screen-sharing
    install/uninstall probes and the filebrowser/homeassistant bootout scrub.
    """
    try:
        return isinstance(value, types)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


def _as_text(value) -> str:
    """Subprocess leftovers (bytes/None/int/``\\ud800``) must not 500 native listing/install."""
    decoded = None
    if _isinst(value, (bytes, bytearray)):
        # Unbound base decode: a leftover subclass ``.decode`` bomb cannot fire.
        base = bytes if _isinst(value, bytes) else bytearray
        try:
            decoded = base.decode(value, "utf-8", "replace")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # A *lying* ``__class__`` (claims bytes, is not): the unbound
            # descriptor rejects the foreign operand.  A raise means "not
            # really bytes" — render like any other object instead of 500ing
            # the launchctl/brew output scrub (the modules9/json9 impostor
            # class).
            decoded = None
    if decoded is not None:
        text = decoded
    elif _isinst(value, str):
        text = value
    elif value is None:
        return ""
    elif _isinst(value, float):
        if type(value) is not float:
            try:
                # Base coercion to an exact float: a subclass ``__eq__``
                # bomb used to blow the NaN/inf probes below.
                value = float.__float__(value)
            except _CONTROL_FLOW:
                raise
            except BaseException:
                return ""
        if value != value or value in (float("inf"), float("-inf")):
            return ""
        text = str(value)
    else:
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
    # Unbound base encode: a str subclass whose ``__str__`` returns self
    # keeps its bound ``.encode`` bomb live (the modules5 unbound convention).
    try:
        text = str.encode(text, "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    return "" if _ADDR_REPR_RE.search(text) else text


def _rc_int(rc) -> int:
    """Exact exit status for the ``==`` / ``!=`` probes; junk reads as failure.

    This module does not own ``sh`` (tests and tooling patch it — the
    docker_cli / nfs_svc ``_rc_int`` rule), and every launchctl helper
    compared the *rc* slot raw while ``_as_text`` laundered only the two
    text streams:

    * an rc-subclass whose ``__eq__`` / ``__ne__`` raises detonated the bare
      ``rc == 0`` probes in ``_screen_sharing_on`` (a raw 500 on
      POST /api/catalog/native-screen-sharing/install and /uninstall) and
      the ``rc != 0`` / ``rc in (0, 3, 5)`` probes in ``_launchctl_unload``
      (a raw 500 on POST /api/catalog/native-filebrowser/uninstall and
      /native-homeassistant/uninstall);
    * a >4300-digit int passed every comparison untouched and then
      ValueError'd ``_launchctl_unload``'s ``f"exit {rc}"`` fallback and
      ``_launchctl_load``'s ``f"bootstrap={…}"`` line past CPython's
      int->str digit cap — the same routes, one step later.

    ``int.__index__`` reads the real value underneath a subclass override;
    a *lying* ``__class__`` impostor (claims int over no int storage)
    TypeErrors on the unbound read and drops with the junk.  ``-255`` is no
    honest exit status and is distinct from the ``-1`` timeout / not-found
    sentinel, so junk can never be misread as a timeout, a vanished CLI, or
    success.
    """
    try:
        if type(rc) is bool:
            return int(rc)
        value = int.__index__(rc) if _isinst(rc, int) else int(rc)
        str(value)
        return value
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return -255


def _exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


def _is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


def _is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def _is_symlink(path: Path) -> bool:
    try:
        return path.is_symlink()
    except OSError:
        return False


def _ensure_dir(path: Path) -> None:
    """mkdir, or a coded 409 when a leftover file / symlink loop occupies *path*."""
    try:
        path.mkdir(parents=True, exist_ok=True)
        if _is_dir(path):
            return
        raise OSError("not a directory")
    except OSError as exc:
        # leftover ``str(exc)`` RecursionError used to 500 native FileBrowser / HA install.
        raise api_error(
            "catalog.path_blocked", path=_as_text(path), detail=_as_text(exc)
        )


def _resolved(path: Path) -> str:
    """``Path.resolve`` raises RuntimeError on a leftover symlink loop."""
    try:
        return str(path.resolve())
    except (OSError, RuntimeError):
        return str(path)


def _which(name: str) -> str | None:
    """Resolve a brew-installed CLI from known prefixes before PATH.

    ``bin:`` install checks and filebrowser linking used to take the first
    PATH hit, so a hijacked ``filebrowser`` would be reported as installed
    and then copied into ~/Services.
    """
    if not name or "/" in name or "\\" in name or name.startswith("-"):
        return None
    for prefix in ("/opt/homebrew/bin", "/usr/local/bin"):
        p = Path(prefix) / name
        if _is_file(p):
            return str(p)
    try:
        found = shutil.which(name)
    except (OSError, ValueError):
        found = None
    if found and Path(found).is_absolute() and _is_file(Path(found)):
        return found
    return None


#: The ollama daemon's API port.  A custom LaunchAgent already serving this
#: port must not be joined by `brew services start ollama`.
OLLAMA_API_PORT = 11434


def ollama_api_already_served() -> bool:
    """True when something already accepts connections on the ollama API port.

    A custom LaunchAgent (com.kiro.ollama on this class of host) owns :11434.
    Starting the brew formula then crash-loops on EADDRINUSE.
    """
    from hub.util import port_open

    return bool(port_open(OLLAMA_API_PORT, host="127.0.0.1"))


#: Immich Valkey (OrbStack ``immich_redis``) owns this port on this class of host.
REDIS_PORT = 6379


def redis_port_already_served() -> bool:
    """True when something already accepts connections on Redis/Valkey :6379.

    Starting Homebrew Redis then abort-loops on missing ``loadmodule`` paths,
    and a clean start would steal the port from Immich Valkey.
    """
    from hub.util import port_open

    return bool(port_open(REDIS_PORT, host="127.0.0.1"))


def _app_exists(name: str) -> bool:
    # Support names with spaces e.g. "Plex Media Server"
    return _exists(Path(f"/Applications/{name}.app")) or _exists(
        Path(f"/Applications/{name}")
    )


def _brew_list_installed() -> set[str]:
    """Formulae and casks installed, as one set.

    The two listings answer different halves of the same question and their results
    are only ever unioned, so nothing about the answer depends on the order they
    arrive in -- yet they ran one after another, each with a 30s timeout, on the
    critical path of the app store.

    Each half returns the empty set on a non-zero exit, exactly as the serial
    version did, so a missing cask listing still leaves the formulae usable.
    """
    if not _is_file(Path(BREW)):
        return set()

    def listing(flag: str) -> set[str]:
        try:
            rc, out, _ = sh([BREW, "list", flag, "-1"], timeout=30)
            return set(out.split()) if rc == 0 else set()
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return set()

    formulas, casks = fan_out(listing, ["--formula", "--cask"], max_workers=2)
    return formulas | casks


def _installed_set(raw) -> set[str]:
    """Laundered installed-package union for the ``pkg in inst`` probes.

    This module does not own the brew snapshot the listing pool hands back
    (tests and tooling patch ``_brew_list_installed``): a set whose
    ``__bool__`` raises detonated the old ``... or set()`` fallback before a
    single row was built, and a *hash-shadowing* member (same hash as a
    catalog package name, raising ``__eq__``) detonated the C-level compare
    inside ``pkg in inst`` — and because ``fan_out`` re-raises, either bomb
    cost every native row of GET /api/catalog, not just itself.  Members are
    rebuilt as exact strs (``_as_text`` reads the honest text underneath a
    subclass override), so a bomb wrapper around a real package name still
    answers that package.
    """
    if not _isinst(raw, (set, frozenset, list, tuple)):
        return set()
    try:
        items = list(raw)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # A lying ``__class__`` claiming a container it is not.
        return set()
    out: set[str] = set()
    for item in items:
        text = _as_text(item)
        if text:
            out.add(text)
    return out


def _service_states(rows) -> dict[str, str]:
    """package -> lowercase status, laundered row by row.

    The shared ``brew services list`` snapshot is another module's payload
    (and a seam tests patch).  The old inline loop read it raw — a bare
    ``isinstance`` (detonated by a ``__class__``-property bomb), a bound
    ``s.get`` (a dict-subclass override), ``or`` truthiness on the name (a
    ``__bool__`` bomb) and bare ``str()`` (a >4300-digit int is the digit-cap
    ValueError) — so one poisoned row raised out of ``list_native_apps`` and
    emptied the entire native half of GET /api/catalog while its honest
    siblings were dropped with it.  Junk rows now cost only themselves.
    """
    states: dict[str, str] = {}
    if not _isinst(rows, (list, tuple)):
        return states
    try:
        items = list(rows)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        # A rows object whose ``__iter__`` bombs, or a lying ``__class__``.
        return states
    for s in items:
        if not _isinst(s, dict):
            continue
        try:
            # Unbound dict.get: reads the C-level storage underneath a
            # subclass ``.get`` override, and rejects a lying dict impostor.
            name = _as_text(dict.get(s, "name"))
            status = _as_text(dict.get(s, "status"))
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
        if not name:
            continue
        states[name] = status.lower()
    return states


def _screen_sharing_on() -> bool:
    # launchctl print system/com.apple.screensharing
    rc, out, _ = sh(
        ["/bin/launchctl", "print", "system/com.apple.screensharing"],
        timeout=5,
    )
    # _rc_int, not a bare compare: a leftover rc-subclass ``__eq__`` bomb
    # used to detonate here, straight out of the screen-sharing install and
    # uninstall routes (this probe runs after every enable/disable attempt).
    if _rc_int(rc) == 0 and "state = running" in _as_text(out):
        return True
    # older
    rc2, out2, _ = sh(
        ["/bin/launchctl", "list", "com.apple.screensharing"],
        timeout=4,
    )
    return _rc_int(rc2) == 0


# Catalog definition (prefer native)
NATIVE_APPS: list[dict[str, Any]] = [
    {
        "id": "native-wireguard",
        "name": "WireGuard (native toolchain)",
        "desc": "wg / wg-quick with userspace implementation · required by the panel's WireGuard page",
        "category": "network",
        "tags": ["vpn", "wireguard", "native"],
        "featured": True,
        # This entry used to be `brew_cask` / `package: wireguard`, which cannot
        # install: `brew info --cask wireguard` answers "No Cask with this name
        # exists".  Homebrew ships WireGuard only as formulae (wireguard-tools and
        # wireguard-go); the official GUI client is a Mac App Store app, not a
        # cask.  So every attempt to install this from the app store failed, and
        # the check `app:WireGuard` never matched either, which left the entry
        # permanently showing as not installed on a host where the tunnel worked.
        "method": "brew_multi",
        "packages": ["wireguard-tools", "wireguard-go"],
        # bin:wg is the thing the panel actually needs; the brew: check keeps
        # reporting it installed if the binary is shadowed.
        "check": ["bin:wg", "brew:wireguard-tools"],
        "notes": (
            "After installing, open the WireGuard page to generate server and client configs. "
            "macOS has no kernel-mode WireGuard; the tunnel runs on wireguard-go's utun device."
        ),
    },
    {
        "id": "native-tailscale",
        "name": "Tailscale (native)",
        "desc": "Zero-config mesh VPN · reach home from any device",
        "category": "network",
        "tags": ["vpn", "tailscale", "native"],
        "featured": True,
        "method": "brew_cask",
        "package": "tailscale-app",
        "check": "app:Tailscale",
        "notes": "Sign in after installing and your devices join the mesh. No public IP required.",
        "open": "Tailscale",
    },
    {
        "id": "native-cloudflared",
        "name": "Cloudflared (native)",
        "desc": "Official Cloudflare Tunnel CLI · expose local services without port forwarding",
        "category": "network",
        "tags": ["tunnel", "cloudflare", "native"],
        "featured": True,
        "method": "brew_formula",
        "package": "cloudflared",
        # bin + brew package (authoritative); process_match if a tunnel is running
        "check": ["bin:cloudflared", "brew:cloudflared"],
        "process_match": "cloudflared",
        "notes": (
            "Sign in, pick a tunnel, start/stop with a token, and read logs from the app "
            "detail panel — no remote desktop needed. "
            "Configure subdomains and public hostnames in the Cloudflare Zero Trust dashboard."
        ),
        "service": False,
        "launchd_label": "local.cloudflared-tunnel",
    },
    {
        "id": "native-screen-sharing",
        "name": "Screen Sharing / VNC (system)",
        "desc": "Turn on the built-in macOS remote desktop (Screen Sharing)",
        "category": "remote",
        "tags": ["vnc", "ard", "native"],
        "featured": True,
        "method": "system",
        "system_action": "enable_screen_sharing",
        "check": "screen_sharing",
        "notes": "Once enabled, Open launches the Screen Sharing client (vnc://). You can also toggle it under System Settings → General → Sharing.",
        "ports": ["5900"],
        "url_hint": "vnc://{{HOST}}",
        # open via vnc:// URL scheme (not -a app name alone)
        "open_protocol": "vnc",
    },
    {
        "id": "native-rustdesk",
        "name": "RustDesk (native client)",
        "desc": "Open-source remote desktop client · works with self-hosted relays",
        "category": "remote",
        "tags": ["remote", "rustdesk", "native"],
        "featured": True,
        "method": "brew_cask",
        "package": "rustdesk",
        "check": "app:RustDesk",
        "open": "RustDesk",
    },
    {
        "id": "native-syncthing",
        "name": "Syncthing (native service)",
        "desc": "P2P file sync · runs as a persistent brew service",
        "category": "files",
        "tags": ["sync", "native"],
        "featured": True,
        "method": "brew_formula",
        "package": "syncthing",
        "check": "bin:syncthing",
        "service": True,
        "ports": ["8384"],
        "url_hint": "http://{{HOST}}:8384",
        "notes": "Installs and runs brew services start syncthing. Web UI defaults to port 8384.",
    },
    {
        "id": "native-rclone",
        "name": "rclone (native)",
        "desc": "CLI for syncing cloud drives / S3 / object storage",
        "category": "files",
        "tags": ["sync", "cloud", "native"],
        "featured": False,
        "method": "brew_formula",
        "package": "rclone",
        "check": "bin:rclone",
    },
    {
        "id": "native-filebrowser",
        "name": "FileBrowser (native binary)",
        "desc": "Lightweight web file manager · no Docker",
        "category": "files",
        "tags": ["files", "native"],
        "featured": True,
        "method": "script",
        "script_id": "filebrowser",
        "check": [
            "path:~/Services/filebrowser/filebrowser-bin",
            "bin:filebrowser",
        ],
        "ports": ["8125"],
        "url_hint": "http://{{HOST}}:8125",
        "launchd_label": "local.filebrowser",
        "process_match": "filebrowser",
        "notes": "One-click install of brew filebrowser + LaunchAgent · port 8125 · root directory ~/Services/media.",
    },
    {
        "id": "native-mosquitto",
        "name": "Mosquitto MQTT (brew)",
        "desc": "Native MQTT broker service · recommended for HA/IoT",
        "category": "iot",
        "tags": ["mqtt", "native"],
        "featured": True,
        "method": "brew_formula",
        "package": "mosquitto",
        "check": "bin:mosquitto",
        "service": True,
        "ports": ["1883"],
        "notes": "brew services start mosquitto. Lighter on resources than Docker.",
    },
    {
        "id": "native-redis",
        "name": "Redis (brew)",
        "desc": "In-memory database · native service",
        "category": "data",
        "tags": ["cache", "native"],
        "featured": False,
        "method": "brew_formula",
        "package": "redis",
        "check": "bin:redis-server",
        "service": True,
        "ports": ["6379"],
        "notes": "Do not start when :6379 is already Immich Valkey. "
                 "Homebrew Redis 8 ships broken relative loadmodule paths and KeepAlive crash-loops.",
    },
    {
        "id": "native-postgresql",
        "name": "PostgreSQL 17 (brew)",
        "desc": "Relational database · if already in use on this host, just start the service",
        "category": "data",
        "tags": ["db", "native"],
        "featured": True,
        "method": "brew_formula",
        "package": "postgresql@17",
        "check": "bin:psql",
        "service": True,
        "ports": ["5432"],
        "notes": "The formula is named postgresql@17. Service: brew services start postgresql@17",
    },
    {
        "id": "native-nginx",
        "name": "Nginx (brew)",
        "desc": "Reverse proxy / static sites · bring your own conf",
        "category": "network",
        "tags": ["proxy", "native"],
        "featured": False,
        "method": "brew_formula",
        "package": "nginx",
        "check": "bin:nginx",
        "service": False,
        "notes": "This host may already run nginx via a custom LaunchAgent; after installing the formula, use your own conf to avoid port conflicts.",
    },
    {
        "id": "native-grafana",
        "name": "Grafana (brew)",
        "desc": "Monitoring dashboards · native service",
        "category": "monitor",
        "tags": ["monitor", "native"],
        "featured": True,
        "method": "brew_formula",
        "package": "grafana",
        # Newer Homebrew builds ship the binary as grafana (older: grafana-server)
        "check": ["bin:grafana", "bin:grafana-server", "brew:grafana"],
        "service": True,
        "ports": ["3000"],
        "url_hint": "http://{{HOST}}:3000",
    },
    {
        "id": "native-prometheus",
        "name": "Prometheus (brew)",
        "desc": "Metrics collection · pairs well with Grafana",
        "category": "monitor",
        "tags": ["monitor", "native"],
        "featured": False,
        "method": "brew_formula",
        "package": "prometheus",
        "check": "bin:prometheus",
        "service": True,
        "ports": ["9090"],
        "url_hint": "http://{{HOST}}:9090",
    },
    {
        "id": "native-node-exporter",
        "name": "node_exporter (brew)",
        "desc": "Host metrics exporter · scraped by Prometheus",
        "category": "monitor",
        "tags": ["monitor", "native"],
        "featured": False,
        "method": "brew_formula",
        "package": "node_exporter",
        "check": "bin:node_exporter",
        "service": True,
        "ports": ["9100"],
    },
    {
        "id": "native-ollama",
        "name": "Ollama (brew)",
        "desc": "Local LLM runtime · REST API on :11434 · Apple Silicon GPU acceleration",
        "category": "dev",
        "tags": ["ai", "llm", "native"],
        "featured": False,
        "method": "brew_formula",
        "package": "ollama",
        # Newer builds may not put the binary on PATH before the shell reloads,
        # so accept the brew receipt as installation proof too.
        "check": ["bin:ollama", "brew:ollama"],
        "service": True,
        "ports": ["11434"],
        # Deliberately no url_hint: :11434 is a JSON API, not a web UI —
        # manage models from the panel's Ollama page instead.
        "notes": "brew services start ollama runs the API server at login. "
                 "If this host already runs ollama through a custom LaunchAgent, "
                 "keep using that agent instead of starting a second daemon on the same port.",
    },
    {
        "id": "native-jellyfin",
        "name": "Jellyfin (native app)",
        "desc": "Media server cask · fits macOS better than Docker",
        "category": "media",
        "tags": ["media", "native"],
        "featured": True,
        "method": "brew_cask",
        "package": "jellyfin",
        "check": "app:Jellyfin",
        "open": "Jellyfin",
        "ports": ["8096"],
        "url_hint": "http://{{HOST}}:8096",
    },
    {
        "id": "native-plex",
        "name": "Plex Media Server (native)",
        "desc": "Plex media server · native macOS app",
        "category": "media",
        "tags": ["media", "plex", "native"],
        "featured": True,
        "method": "brew_cask",
        "package": "plex-media-server",
        "check": "app:Plex Media Server",
        "open": "Plex Media Server",
        "ports": ["32400"],
        "url_hint": "http://{{HOST}}:32400/web",
        "notes": "Can also be installed from plex.tv. Uninstalling runs brew uninstall --cask plex-media-server.",
    },
    {
        "id": "native-navidrome",
        "name": "Navidrome (brew)",
        "desc": "Music library / Subsonic-compatible · native",
        "category": "media",
        "tags": ["music", "native"],
        "featured": True,
        "method": "brew_formula",
        "package": "navidrome",
        "check": "bin:navidrome",
        "service": True,
        "ports": ["4533"],
        "url_hint": "http://{{HOST}}:4533",
        "notes": "Configure your music directory yourself (config file or environment variables).",
    },
    {
        "id": "native-qbittorrent",
        "name": "qBittorrent (native app)",
        "desc": "BitTorrent download client · macOS app",
        "category": "download",
        "tags": ["bt", "native"],
        "featured": True,
        "method": "brew_cask",
        "package": "qbittorrent",
        "check": "app:qBittorrent",
        "open": "qBittorrent",
    },
    {
        "id": "native-utools-iterm",
        "name": "iTerm2 (native)",
        "desc": "Enhanced terminal · handy for home-server troubleshooting",
        "category": "ops",
        "tags": ["terminal", "native"],
        "featured": False,
        "method": "brew_cask",
        "package": "iterm2",
        "check": "app:iTerm",
        "open": "iTerm",
    },
    {
        "id": "native-stats",
        "name": "Stats (menu bar monitor)",
        "desc": "CPU / memory / network speed menu bar widget",
        "category": "monitor",
        "tags": ["monitor", "native"],
        "featured": False,
        "method": "brew_cask",
        "package": "stats",
        "check": "app:Stats",
        "open": "Stats",
    },
    {
        "id": "native-htop",
        "name": "htop / btop (CLI)",
        "desc": "Terminal process monitor · btop looks nicer",
        "category": "ops",
        "tags": ["cli", "native"],
        "featured": False,
        "method": "brew_formula",
        "package": "btop",
        "check": "bin:btop",
        "service": False,
    },
    {
        "id": "native-git",
        "name": "Git + gh (CLI)",
        "desc": "Core development toolchain",
        "category": "dev",
        "tags": ["git", "native"],
        "featured": False,
        "method": "brew_multi",
        "packages": ["git", "gh"],
        "check": "bin:gh",
    },
    {
        "id": "native-gitea",
        "name": "Gitea (brew)",
        "desc": "Lightweight Git service · native process",
        "category": "dev",
        "tags": ["git", "native"],
        "featured": True,
        "method": "brew_formula",
        "package": "gitea",
        "check": "bin:gitea",
        "service": True,
        "ports": ["3000"],
        "url_hint": "http://{{HOST}}:3000",
        "notes": "First run requires configuring ~/Services/gitea or the brew default path.",
    },
    {
        "id": "native-minio",
        "name": "MinIO (brew)",
        "desc": "S3-compatible object storage CLI/server",
        "category": "data",
        "tags": ["s3", "native"],
        "featured": False,
        "method": "brew_formula",
        "package": "minio",
        "check": "bin:minio",
        "service": False,
        "notes": "After installing, start with minio server ~/data, or write your own LaunchAgent.",
    },
    {
        "id": "native-ntfy",
        "name": "ntfy (brew)",
        "desc": "Self-hosted push notifications · native binary",
        "category": "notify",
        "tags": ["notify", "native"],
        "featured": True,
        "method": "brew_formula",
        "package": "ntfy",
        "check": "bin:ntfy",
        "service": False,
        "notes": "Run ntfy serve; for an always-on service, create your own LaunchAgent or use a maintenance script.",
    },
    {
        "id": "native-duplicacy",
        "name": "Duplicacy (CLI)",
        "desc": "Efficient encrypted backup CLI",
        "category": "backup",
        "tags": ["backup", "native"],
        "featured": False,
        # `brew_formula` / `duplicacy` does not exist -- Homebrew answers "No
        # available formula with the name". Duplicacy ships as the cask
        # `duplicacy-cli`, whose `binary` artifact symlinks
        # /opt/homebrew/bin/duplicacy, so `bin:duplicacy` stays the right check
        # and no root is needed (the prefix belongs to the installing account).
        "method": "brew_cask",
        "package": "duplicacy-cli",
        "check": ["bin:duplicacy", "brew:duplicacy-cli"],
        "service": False,
    },
    {
        "id": "native-smartmontools",
        "name": "smartmontools",
        "desc": "Disk SMART checks · required by the Storage Array page",
        "category": "ops",
        "tags": ["disk", "native"],
        "featured": True,
        "method": "brew_formula",
        "package": "smartmontools",
        "check": "bin:smartctl",
        "service": False,
    },
    {
        "id": "native-homeassistant",
        "name": "Home Assistant Core (native)",
        "desc": "Local venv + LaunchAgent · recommended (not Docker/HAOS)",
        "category": "iot",
        "tags": ["ha", "homeassistant", "native", "iot"],
        "featured": True,
        "method": "script",
        "script_id": "homeassistant",
        "check": [
            "path:~/venvs/shared/bin/hass",
            "path:~/Library/LaunchAgents/com.homeassistant.core.plist",
        ],
        "ports": ["8123"],
        "url_hint": "http://{{HOST}}:8123",
        "launchd_label": "com.homeassistant.core",
        "process_match": "venvs/shared/bin/hass",
        "notes": (
            "Runs from shared venv ~/venvs/shared/bin/hass with config under "
            "~/Services/homeassistant (LaunchAgent com.homeassistant.core). "
            "An existing native deployment is detected automatically and can be started/stopped. "
            "Web UI defaults to :8123."
        ),
    },
]


def _check_one(spec: str, brew_installed: set[str] | None = None) -> bool:
    """Evaluate a single check spec: screen_sharing | app:X | bin:X | path:X | brew:X."""
    if not spec:
        return False
    if spec == "screen_sharing":
        return _screen_sharing_on()
    if spec.startswith("app:"):
        return _app_exists(spec.split(":", 1)[1])
    if spec.startswith("bin:"):
        return bool(_which(spec.split(":", 1)[1]))
    if spec.startswith("path:"):
        raw = spec.split(":", 1)[1]
        if "~" in raw:
            home = user_home()
            if home is None:
                return False
            raw = raw.replace("~", str(home))
        return _exists(Path(raw))
    if spec.startswith("brew:"):
        pkg = spec.split(":", 1)[1]
        inst = brew_installed if brew_installed is not None else _brew_list_installed()
        return pkg in inst
    return False


def _is_installed(app: dict, brew_installed: set[str] | None = None) -> bool:
    """True if any check matches. For brew apps also fall back to `brew list` package."""
    check = app.get("check")
    specs: list[str] = []
    if _isinst(check, (list, tuple)):
        specs = [str(c) for c in check if c]
    elif check:
        specs = [str(check)]

    for spec in specs:
        if _check_one(spec, brew_installed):
            return True

    # Brew formula/cask: package presence is authoritative even if bin name changed
    method = app.get("method") or ""
    pkg = app.get("package")
    if pkg and method in ("brew_formula", "brew_cask", "brew_multi"):
        inst = brew_installed if brew_installed is not None else _brew_list_installed()
        if pkg in inst:
            return True
        # multi-package: any package counts
        for p in app.get("packages") or []:
            if p in inst:
                return True
    return False


_LIST_TTL = 30.0

#: Concurrent per-app liveness probes in a catalog listing.  Bounded well under the
#: catalog size: each probe is a `launchctl print`, and launchd serialises requests
#: internally, so a wider pool would queue in the daemon instead of the process.
_PROBE_WORKERS = 8


@cached_snapshot(_LIST_TTL)
def list_native_apps(force: bool = False) -> list[dict]:

    # Three independent reads.  `brew services list --json` costs ~1.3s and is the
    # dominant cost of this whole function, so the package list and the host address
    # are overlapped with it rather than queued behind it.
    #
    # The service table goes through the shared cache rather than shelling out here:
    # this function is also called with force=True by catalog_overview(), and `force`
    # must not bypass that cache — it means "re-read the template dir", not "make
    # brew slow again".
    f_installed = _pool.submit(_brew_list_installed)
    f_services = _pool.submit(brew_services_list)
    f_host = _pool.submit(host_ip)

    def _result(fut, fallback):
        try:
            return fut.result()
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return fallback

    # `.result()` re-raises; a dead brew must not empty the Apps catalog.
    # Laundered shapes, not bare ``or`` fallbacks: a snapshot whose
    # ``__bool__`` raises used to detonate the truthiness probe itself, one
    # step before the row loop — the same whole-half loss as a poisoned row.
    brew_inst = _installed_set(_result(f_installed, None))
    service_states = _service_states(_result(f_services, None))
    # The host is only ever consumed by _resolve_url, which launders it.
    host = _result(f_host, "")

    # Install and liveness probes are independent per app, and each can shell out
    # (`launchctl print`, `brew list`, a `ps` scan).  Resolve them concurrently, then
    # assemble the rows in catalog order below so the grid does not reshuffle by
    # which probe answered first.  The launchd listing and the process table are
    # shared, and shared beyond this pass: see hub/launchd_cache.py.
    launchd_snapshot = _LaunchdSnapshot()

    def probe(app: dict) -> tuple[bool, bool | None]:
        installed = _is_installed(app, brew_inst)
        running = None
        pkg = app.get("package")
        if app.get("service") and pkg and pkg in service_states:
            st = service_states[pkg]
            running = st in ("started", "running")
        # Homebrew Redis is not a daemon this host runs.  `running is False`
        # painted Apps "Redis (brew)" red next to Immich even though Valkey
        # owns :6379.  None = installed, not a required service.
        if app.get("id") == "native-redis" and running is not True:
            running = None
        if app.get("id") == "native-ollama" and running is not True and ollama_api_already_served():
            running = True
        # LaunchAgent / process-based
        label = app.get("launchd_label")
        if running is None and label:
            running = _launchd_or_process_running(
                label, app.get("process_match") or app.get("id") or "",
                launchd_snapshot,
            )
        if running is None and app.get("id") == "native-filebrowser":
            running = _launchd_or_process_running(
                "local.filebrowser", "filebrowser", launchd_snapshot
            )
        # CLI tools with process_match but no brew service / launchd:
        # True only when a matching process is up; otherwise leave None ("installed")
        # so unused CLIs don't show as "stopped".
        if running is None and app.get("process_match") and not app.get("service") and not label:
            if _process_running(str(app["process_match"])):
                running = True
        if running is None and app.get("open"):
            # cask apps: unknown process state unless we probe
            running = None
        return installed, running

    probed = fan_out(probe, NATIVE_APPS, max_workers=_PROBE_WORKERS)

    items = []
    for app, (installed, running) in zip(NATIVE_APPS, probed):
        pkg = app.get("package")
        label = app.get("launchd_label")
        url = _resolve_url(app.get("url_hint") or "", host, _port_list(app.get("ports")))
        items.append({
            "id": app["id"],
            "name": app["name"],
            "desc": app.get("desc") or "",
            "category": app.get("category") or "other",
            "tags": list(app.get("tags") or []),
            "featured": bool(app.get("featured")),
            "notes": app.get("notes") or "",
            "ports": _port_list(app.get("ports")),
            "kind": "native",
            "method": app.get("method"),
            "package": pkg,
            "installed": installed,
            "running": running,
            "url_hint": url,
            "launchd_label": label,
            "vars": [],
            "images": [],
            "prefer_native": True,
        })
    items.sort(key=lambda x: (0 if x.get("featured") else 1, x.get("name") or ""))
    return items


def _process_running(process_substr: str) -> bool:
    """True if any process command line contains substr (best-effort).

    The table comes from :mod:`hub.proc_cache`.  This used to take a pass-scoped
    snapshot object, which was the right idea one scope too small: sharing one
    `ps aux` across the catalog listing still left `/api/apps/managed` reading the
    table twice, because cloudflared's liveness probe kept its own copy of this
    same scan.  The cache is process-wide and short-lived, so a listing pass and
    every other reader in     the same request now share one spawn.

    Guarded: the table is another module's payload (and a seam tests patch).
    A raising provider used to escape every ``probe`` in the listing pass —
    and because ``fan_out`` re-raises, one bad scan emptied the whole native
    half of GET /api/catalog instead of reading as "not running".
    """
    try:
        return bool(process_matches(process_substr))
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False


class _LaunchdSnapshot:
    """Marks a caller as walking a collection, rather than asking about one app.

    The listing itself lives in :mod:`hub.launchd_cache` and is shared with
    ``health_svc``, ``autostart_svc`` and ``immich_svc``, which each used to run
    their own.  What survives here is the *distinction*, because it decides whether
    a spawn is worth paying for:

    * Inside a listing, a label missing from the session is overwhelmingly a job
      that is simply not loaded, and there are dozens of them.  Asking launchd
      about each one individually is what made this thirty subprocesses per page --
      and :data:`_PROBE_WORKERS` already records that widening the pool did not
      help, because launchd serialises those requests internally.  Work the OS
      serialises is not parallelised by fanning it out; it is just spawned.
    * A single-app caller has exactly one label to ask about, so the per-label
      ``launchctl print`` below costs one spawn and is kept: it is the stronger
      probe, and one machine's worth of agreement between the two is not evidence
      that the listing can never miss a job.

    ``launchctl list`` prints ``PID\\tStatus\\tLabel``, and a numeric pid in column
    one means running -- which is exactly what ``state = running`` reports.
    """

    __slots__ = ()

    def running_labels(self) -> frozenset[str]:
        # The shared listing is another module's payload (and a seam tests
        # patch): a raising provider must read as "nothing running", not
        # raise out of the probe and — fan_out re-raises — empty the whole
        # native half of GET /api/catalog.
        try:
            return launchd_running_labels()
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return frozenset()


def _launchd_or_process_running(
    label: str,
    process_substr: str,
    launchd: _LaunchdSnapshot | None = None,
) -> bool:
    if label:
        if launchd is not None:
            try:
                if label in launchd.running_labels():
                    return True
            except _CONTROL_FLOW:
                raise
            except BaseException:
                # A *hash-shadowing* member planted in the shared listing
                # (same hash as this label, raising ``__eq__``) detonates
                # the C-level compare inside ``in`` itself; junk reads as
                # "not running" and the process probe below still answers.
                pass
        else:
            # No shared listing (single-app callers below); ask about this one label.
            rc, out, _ = sh(
                ["/bin/launchctl", "print", f"gui/{os.getuid()}/{label}"],
                timeout=5,
            )
            # _rc_int: a leftover rc bomb must read as "not running", not
            # raise out of the Home Assistant install path.
            if _rc_int(rc) == 0 and "state = running" in _as_text(out):
                return True
    return _process_running(process_substr)


def _port_list(raw) -> list:
    # _isinst gates throughout: a leftover ``__class__``-property bomb must
    # answer False, not raise out of the listing.
    if _isinst(raw, list):
        try:
            # Base copy first: a lying ``__class__`` claiming list is not
            # actually iterable, and must cost only itself.
            items = list(raw)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return []
    elif _isinst(raw, (int, str)):
        try:
            if not str(raw).strip():
                return []
        except _CONTROL_FLOW:
            raise
        except BaseException:
            # Over-digit-cap int (str() is ValueError) or a lying impostor.
            return []
        items = [raw]
    else:
        return []
    out = []
    for p in items:
        # ``p == ""`` used to run first: an item whose ``__eq__`` raises
        # detonated the loop and emptied the whole row's ports instead of
        # costing only itself.  Identity/_isinst gates carry no ``__eq__``;
        # the empty-string drop moved into the str arm below.
        if p is None or _isinst(p, bool):
            continue
        if _isinst(p, float) and type(p) is float and (
            p != p or p in (float("inf"), float("-inf"))
        ):
            continue
        if _isinst(p, int):
            if type(p) is not int:
                try:
                    # Base coercion to an exact int: a subclass ``__str__``/
                    # ``__eq__`` bomb must not outlive this launder — the
                    # row's url resolver and the store's JSON encoder both
                    # render these (the catalog._plain_ports convention).
                    p = int.__index__(p)
                except _CONTROL_FLOW:
                    raise
                except BaseException:
                    continue
            try:
                # Digit-cap probe: a leftover >4300-digit port renders
                # nowhere — ``str(port)`` in _resolve_url was the ValueError
                # that emptied the native half of GET /api/catalog.
                str(p)
            except ValueError:
                continue
            out.append(p)
        elif _isinst(p, str):
            try:
                # Unbound base encode: keeps a plain str (a subclass
                # ``__str__``/``encode`` bomb cannot ride into _resolve_url),
                # and a lying ``__class__`` claiming str drops alone.
                text = str.encode(p, "utf-8", "replace").decode("utf-8")
            except _CONTROL_FLOW:
                raise
            except BaseException:
                continue
            if text:
                out.append(text)
        elif _isinst(p, (bytes, bytearray)):
            # Unbound base decode: a subclass ``.decode`` bomb cannot fire,
            # and a lying ``__class__`` claiming bytes drops alone.
            base = bytes if _isinst(p, bytes) else bytearray
            try:
                text = base.decode(p, "utf-8", "replace").strip()
            except _CONTROL_FLOW:
                raise
            except BaseException:
                continue
            if text:
                out.append(text)
    return out


def _resolve_url(hint: str, host: str, ports: list) -> str:
    """Fill {{HOST}} / build http URL from first web port when hint empty."""
    # _isinst + unbound base encode, not the bare isinstance gate: a host
    # whose ``__class__`` is a raising property detonated the gate itself,
    # a host ``__bool__`` bomb detonated the truthiness probe, and a lying
    # ``__class__`` impostor claiming str passed the old gate and blew
    # ``hint.replace`` — each emptied every native row of GET /api/catalog
    # (fan_out re-raises).  Junk degrades to the same "localhost" the old
    # gate answered for any non-str host.
    if _isinst(host, str):
        try:
            host = str.encode(host, "utf-8", "replace").decode("utf-8")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            host = ""
    else:
        host = ""
    host = host or "localhost"
    if _isinst(hint, str):
        try:
            # Launders a str subclass to an exact str, so a bound
            # ``.replace``/``.encode`` bomb cannot ride into the chain below.
            hint = str.encode(hint, "utf-8", "replace").decode("utf-8")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            hint = ""
    else:
        # A mapping leftover used to raise on hint.replace and 500 the store.
        hint = ""
    if hint:
        return (
            hint.replace("{{HOST}}", host)
            .replace("{{HOST_IP}}", host)
            .replace("127.0.0.1", host)
            .replace("localhost", host)
        )
    # derive from known web ports
    webish = {
        "80", "443", "3000", "3001", "8080", "8081", "8123", "8125",
        "8096", "8384", "9000", "9001", "9090", "4533", "2283", "8200",
        "32400", "51821", "8443", "8888", "3030",
    }
    for p in ports:
        try:
            # _port_list already drops unrenderable ports, but this helper
            # is also handed raw lists by callers under test; a >4300-digit
            # int (str() is the digit-cap ValueError) or a ``__str__`` bomb
            # costs only its own entry, never the whole URL.
            ps = str(p).split("/")[0]
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
        if ps in webish or ps.isdigit():
            # skip pure protocol ports without UI
            if ps in ("1883", "5432", "6379", "3306", "5900", "9100", "22000"):
                continue
            if ps == "32400":
                return f"http://{host}:32400/web"
            if ps == "443":
                return f"https://{host}"
            if ps == "80":
                return f"http://{host}"
            return f"http://{host}:{ps}"
    return ""


def _run(cmd: list[str], timeout: int = 600, shell: bool = False) -> dict:
    try:
        argv: list[str] = list(cmd)
        if shell:
            argv = ["/bin/sh", "-c", cmd[0] if len(cmd) == 1 else " ".join(cmd)]
        rc, msg = run_capped(
            argv, timeout=timeout, env=_brew_env(), cap=4000,
        )
        # _rc_int before anything compares or stores it: the raw slot rode
        # into the result dict, where _brew_vanished's ``== -1`` and
        # _brew_install_ok's ``== 0`` probes ran outside this try.  Junk
        # reads -255 — never the -1 timeout / not-found sentinel, so a bomb
        # cannot impersonate a vanished brew.
        rc, msg = _rc_int(rc), _as_text(msg)
        if rc == -1 and not msg.strip():
            msg = "command timed out"
        return {"ok": rc == 0, "message": (msg or f"exit {rc}").strip(), "rc": rc}
    except _CONTROL_FLOW:
        raise
    except BaseException as e:
        return {"ok": False, "message": _as_text(e), "rc": -1}


def _needs_admin_retry(msg: str) -> bool:
    """True when brew failed because sudo needs an interactive/admin session."""
    low = _as_text(msg).lower()
    if "user canceled" in low or "用户取消" in low:  # cjk-input: matches macOS's own zh-locale cancel message
        return False
    return (
        "sudo: a password is required" in low
        or "sudo: a terminal is required" in low
        or "failure while executing; `/usr/bin/sudo" in low
    )


#: What Homebrew says when it is started as root.  It exempts only `services`,
#: `--prefix`, `setup-sandbox` and `as-console-user`
#: (Library/Homebrew/brew.sh: check-run-command-as-root), so no install or
#: uninstall can be elevated by running brew itself with more privilege.
_BREW_ROOT_REFUSAL = "running homebrew as root"


def _brew_refuses_root(msg: str) -> bool:
    return _BREW_ROOT_REFUSAL in (msg or "").lower()


def _brew_vanished(result: dict) -> bool:
    """Whether a ``_run`` result means the brew binary itself is gone.

    ``run_capped`` reports a FileNotFoundError spawn as the exact sentinel
    ``(-1, "not found")`` — never a real brew exit (the vms_svc / brew_svc /
    hub.backups convention).  A brew that vanished between install_native's
    up-front ``catalog.brew_missing`` gate and the spawn used to fall through
    as an uncoded ``{ok: false, message: "not found"}`` the SPA cannot
    translate.  A timeout keeps its own message ("command timed out") and a
    genuine non-zero brew exit keeps its raw output — that is then the truth.
    """
    return (
        result.get("rc") == -1
        and _as_text(result.get("message")).strip() == "not found"
    )


def _raise_if_brew_vanished(result: dict) -> dict:
    """Map the vanished-brew spawn sentinel to the same coded 503 as the gate.

    Message-pattern first, then confirmed against the filesystem — a brew
    that is still present while a run somehow reports the sentinel keeps its
    raw result, mirroring how the docker classifiers confirm with a forced
    ``engine_up`` probe before mapping to ``container.engine_down``.
    """
    if _brew_vanished(result) and not _is_file(Path(BREW)):
        raise api_error("catalog.brew_missing", path=BREW)
    return result


def _run_brew(
    brew_args: list[str],
    *,
    timeout: int = 900,
    admin_on_sudo_fail: bool = True,
) -> dict:
    """Run brew as the panel's own user, reporting sudo needs instead of hiding them.

    There used to be a retry here that re-ran the whole brew command as root,
    through `osascript ... with administrator privileges`.  It could never
    succeed: Homebrew refuses to run as root outright, exempting only
    `services`, `--prefix`, `setup-sandbox` and `as-console-user`
    (Library/Homebrew/brew.sh: check-run-command-as-root).  So a pkg-based cask
    install popped a password dialog -- on the Mac's own display, which nobody is
    watching when the panel is driven from a phone -- waited up to 900 seconds for
    it, and then failed with Homebrew's root warning as the error message.

    What actually needs root is the macOS package installer that brew invokes
    *internally*, not brew itself.  When the SPA supplies the operator's macOS
    administrator password (``X-Admin-Password``), we prime a sudo ticket with
    ``sudo -v`` and retry brew as the same user — brew's inner ``sudo installer``
    then reuses that ticket.  Without a password we answer ``password_required`` so
    the in-browser admin dialog can collect one and retry.
    """
    from hub.macos_admin import admin_password_supplied, prime_sudo_ticket

    cmd = [BREW, *brew_args]
    r = _raise_if_brew_vanished(_run(cmd, timeout=timeout))
    if r["ok"] or not admin_on_sudo_fail:
        return r

    if _brew_refuses_root(r.get("message") or ""):
        # Should be unreachable: the panel does not run as root. Worth saying
        # plainly rather than passing Homebrew's warning through as-is.
        r["message"] = (
            "Homebrew refuses to run as root; the panel should not be started as root.\n"
            "Run the panel as a regular user and try again.\n\n" + (r.get("message") or "")
        )[-4000:]
        return r

    if not _needs_admin_retry(r.get("message") or ""):
        return r

    if admin_password_supplied():
        prime = prime_sudo_ticket(timeout=min(30, timeout))
        if prime.get("ok"):
            r2 = _raise_if_brew_vanished(_run(cmd, timeout=timeout))
            if r2["ok"] or not _needs_admin_retry(r2.get("message") or ""):
                return r2
            r = r2
        elif prime.get("error") == "password_incorrect":
            r["error"] = "password_incorrect"
            r["message"] = (
                "The macOS administrator password was rejected.\n\n"
                + (r.get("message") or "")
            )[-4000:]
            return r

    r["error"] = "password_required"
    r["message"] = (
        "This package needs the macOS administrator password for its pkg installer.\n"
        "Enter your Mac login password when prompted and try again.\n\n"
        "You can also install manually on this Mac:\n"
        f"  {' '.join(shlex.quote(c) for c in cmd)}\n\n"
        + (r.get("message") or "")
    )[-4000:]
    return r


def _brew_install_ok(msg: str, rc: int) -> bool:
    """Treat 'already installed' as success (brew may still return 0; be defensive)."""
    if rc == 0:
        return True
    low = (msg or "").lower()
    return "already installed" in low or "already up-to-date" in low


def _host_for_url() -> str:
    """The advertised host for install-response URLs, laundered.

    This module does not own ``host_ip`` (tests and tooling patch it): the
    install branches read this raw into f-strings (``f"http://{...}:8125"``)
    *after* the install itself had already succeeded, so a raising provider —
    or a ``__str__``/``__format__`` bomb riding the value — turned a finished
    native install into a raw 500.  Junk degrades to "", which _resolve_url
    and the f-string fallbacks render as the localhost / empty-host shapes a
    legitimately empty probe already produced.
    """
    try:
        host = host_ip()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    if not _isinst(host, str):
        return ""
    try:
        return str.encode(host, "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""


def _app_url(app: dict) -> str:
    return _resolve_url(app.get("url_hint") or "", _host_for_url(), _port_list(app.get("ports")))


def _write_launchagent(label: str, program_args: list[str], *,
                       working_dir: str | None = None,
                       stdout: str | None = None,
                       stderr: str | None = None,
                       run_at_load: bool = True,
                       keep_alive: bool = True,
                       env: dict | None = None) -> Path:
    import plistlib
    from hub.paths import AGENTS_DIR
    pl_path = Path(AGENTS_DIR) / f"{label}.plist"
    pl: dict[str, Any] = {
        "Label": label,
        "ProgramArguments": program_args,
        "RunAtLoad": bool(run_at_load),
        "KeepAlive": bool(keep_alive),
    }
    if working_dir:
        pl["WorkingDirectory"] = working_dir
    if stdout:
        pl["StandardOutPath"] = stdout
    if stderr:
        pl["StandardErrorPath"] = stderr
    if env:
        pl["EnvironmentVariables"] = env
    from hub import secure_io
    try:
        pl_path.parent.mkdir(parents=True, exist_ok=True)
        secure_io.replace_bytes(pl_path, plistlib.dumps(pl))
    except OSError as exc:
        # A leftover directory named <label>.plist used to IsADirectoryError
        # and 500 native FileBrowser / Home Assistant install. leftover
        # ``str(exc)`` RecursionError did the same on the write.
        raise api_error(
            "catalog.plist_write_failed", label=label, detail=_as_text(exc)
        )
    return pl_path


def _forget_host_state() -> None:
    """Drop the shared launchd listing and process table after changing either.

    Both are cached for a couple of seconds so that the readers inside one page load
    share a spawn.  Every mutation here is immediately followed by a read that checks
    whether the mutation worked, which is precisely the case a TTL gets wrong.
    """
    invalidate_launchd()
    invalidate_processes()


def _launchctl_is_loaded(label: str) -> bool:
    from hub.paths import UID
    rc, out, _ = sh(["/bin/launchctl", "print", f"gui/{UID}/{label}"], timeout=5)
    # _rc_int + _as_text: a leftover rc-subclass ``__eq__`` bomb and a
    # stdout whose ``__bool__`` raises each used to detonate this probe —
    # a raw 500 on the filebrowser / homeassistant uninstall routes, which
    # ask it whether the bootout worked.
    return _rc_int(rc) == 0 and bool(_as_text(out))


def _launchctl_load(label: str, plist: Path) -> dict:
    """Start or reload a user LaunchAgent without clobbering a healthy job."""
    from hub.paths import UID
    dom = f"gui/{UID}"
    target = f"{dom}/{label}"
    if not _exists(plist):
        return {"ok": False, "message": f"plist not found: {plist}"}

    # If already loaded, prefer kickstart -k (restart in place)
    if _launchctl_is_loaded(label):
        rc, out, err = sh(["/bin/launchctl", "kickstart", "-k", target], timeout=20)
        if _rc_int(rc) == 0:
            return {"ok": True, "message": f"kickstart ok · {label}"}
        # fall through to re-bootstrap
        sh(["/bin/launchctl", "bootout", target], timeout=10)

    r1 = sh(["/bin/launchctl", "bootstrap", dom, str(plist)], timeout=15)
    # 0 ok, 5 sometimes transient, 17 already bootstrapped
    r2 = sh(["/bin/launchctl", "kickstart", "-k", target], timeout=20)
    # enable for login if available
    sh(["/bin/launchctl", "enable", f"gui/{UID}/{label}"], timeout=5)
    # The launchd session and the process table both just changed, and the checks
    # below read exactly what this call did.  Without dropping the shared snapshots
    # first, the confirmation would be a listing taken before the bootstrap -- so a
    # successful start could be reported as a failure.
    _forget_host_state()
    ok = _rc_int(r2[0]) == 0 or _launchctl_is_loaded(label)
    # process probe fallback
    if not ok:
        time.sleep(0.5)
        ok = _launchd_or_process_running(label, label.split(".")[-1])
    # _rc_int + _as_text on every slot: a >4300-digit rc used to ValueError
    # this f-string past the int->str digit cap, a stream whose ``__bool__``
    # raises used to detonate the ``or`` chain, and a lone-surrogate stream
    # rode raw into the install response body where Starlette's UTF-8
    # encode 500'd it after the install itself had already succeeded.
    msg = (
        f"bootstrap={_rc_int(r1[0])} kickstart={_rc_int(r2[0])} "
        f"{(_as_text(r1[2]) or _as_text(r1[1]))} {(_as_text(r2[2]) or _as_text(r2[1]))}"
    ).strip()
    return {"ok": ok, "message": msg or ("ok" if ok else "start failed")}


def _launchctl_unload(label: str) -> dict:
    from hub.paths import UID
    dom = f"gui/{UID}"
    target = f"{dom}/{label}"
    # prefer bootout; also try legacy unload
    rc, out, err = sh(["/bin/launchctl", "bootout", target], timeout=10)
    # _rc_int next to the text launder: the ``rc != 0`` / ``rc in (0, 3, 5)``
    # probes and the ``f"exit {rc}"`` fallback below each used to be a raw
    # 500 on the filebrowser / homeassistant uninstall routes under an
    # rc-subclass ``__ne__``/``__eq__`` bomb or a >4300-digit leftover rc.
    rc, out, err = _rc_int(rc), _as_text(out), _as_text(err)
    if rc != 0:
        home = user_home()
        pl = (home / "Library/LaunchAgents" / f"{label}.plist") if home is not None else None
        if pl is not None and _exists(pl):
            sh(["/bin/launchctl", "unload", str(pl)], timeout=10)
    # Same reason as the load path: the confirmation below must not read a snapshot
    # taken before the bootout.
    _forget_host_state()
    ok = not _launchctl_is_loaded(label)
    return {
        "ok": ok or rc in (0, 3, 5) or "No such" in (err + out),
        "message": out or err or f"exit {rc}",
    }


def _pick_python() -> str:
    """Prefer a concrete Homebrew or system python3. Never a bare ``python3``.

    A relative name would be resolved from PATH at venv-create time, so a
    hijacked ``python3`` would become Home Assistant's interpreter.
    """
    for c in (
        "/opt/homebrew/opt/python@3.14/bin/python3.14",
        "/opt/homebrew/opt/python@3.14/bin/python3",
        "/opt/homebrew/bin/python3.14",
        "/opt/homebrew/opt/python@3.13/bin/python3.13",
        "/opt/homebrew/bin/python3.13",
        "/opt/homebrew/opt/python@3.12/bin/python3.12",
        "/opt/homebrew/bin/python3.12",
        "/usr/local/opt/python@3.14/bin/python3.14",
        "/usr/local/opt/python@3.13/bin/python3.13",
        "/usr/local/opt/python@3.12/bin/python3.12",
        "/usr/local/bin/python3.14",
        "/usr/local/bin/python3.13",
        "/usr/local/bin/python3.12",
        "/usr/bin/python3",
        shutil.which("python3") or "",
    ):
        if c and _is_file(Path(c)) and Path(c).is_absolute():
            return c
    return ""


def _enable_screen_sharing() -> dict:
    # Try without password first, then sudo -n
    cmds = [
        ["/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart",
         "-activate", "-configure", "-access", "-on",
         "-restart", "-agent", "-privs", "-all"],
        ["/usr/bin/sudo", "-n", "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart",
         "-activate", "-configure", "-access", "-on",
         "-restart", "-agent", "-privs", "-all"],
        ["/usr/bin/sudo", "-n", "/bin/launchctl", "load", "-w",
         "/System/Library/LaunchDaemons/com.apple.screensharing.plist"],
    ]
    logs = []
    for cmd in cmds:
        binary = cmd[2] if cmd[0] == "/usr/bin/sudo" and len(cmd) > 2 else cmd[0]
        # Path.exists() re-raises EIO/ESTALE; that used to 500 Screen Sharing.
        if binary and not _exists(Path(binary)):
            continue
        r = _run(cmd, timeout=30)
        logs.append(f"$ {' '.join(cmd)}\n{r['message']}")
        if r["ok"] or _screen_sharing_on():
            return {
                "ok": True,
                "message": "Screen Sharing enabled (or already running)\n" + "\n".join(logs)[-1500:],
                "url": None,
            }
    # last resort message
    return {
        "ok": _screen_sharing_on(),
        "message": (
            "Could not enable automatically (administrator privileges may be required). "
            "Go to: System Settings → General → Sharing → Screen Sharing.\n"
            + "\n".join(logs)[-1200:]
        ),
        "url": None,
    }


def _stale_app_views() -> None:
    """Drop every snapshot that describes what is installed or running.

    Three separate caches answer "is this app installed?": the store list here,
    the shared `brew services list --json` snapshot, and the Apps page inventory.
    An install or uninstall invalidates the state all three summarise, so they go
    together -- dropping one and not the others is how the store started showing
    an app as installed while the Apps page still listed it as absent.

    Called both before and after the operation.  Before, because an install can
    take minutes and nothing should serve a snapshot taken across it; after,
    because any read that arrived *during* those minutes refilled the caches with
    pre-install state and gave it a fresh timestamp.
    """
    list_native_apps.invalidate()
    invalidate_brew_services()
    # The import is local because these two modules each read from the other;
    # keeping both directions lazy is what stops that from becoming a cycle.
    from hub import apps_manage_svc

    apps_manage_svc.invalidate_inventory()


_op_locks_guard = threading.Lock()
_op_locks: dict[str, threading.Lock] = {}


@contextlib.contextmanager
def _single_flight(app_id: str):
    """One install-or-uninstall at a time per app, and say so when refused.

    Homebrew takes its own lock per formula and answers a concurrent run with
    "Another active Homebrew process is already in progress", which surfaces in
    the panel as an install that failed for no visible reason.  Two clicks on a
    slow install, or two devices looking at the same panel, are enough to hit it.

    Refusing with 409 up front is both faster and explainable.  Acquisition is
    non-blocking on purpose: queueing the second request behind a 900 second cask
    install would hold a request thread for the whole time and then do work the
    operator has long stopped waiting for.
    """
    with _op_locks_guard:
        lock = _op_locks.setdefault(app_id, threading.Lock())
    if not lock.acquire(blocking=False):
        raise api_error("catalog.install_busy", app=app_id)
    _stale_app_views()
    try:
        yield
    finally:
        _stale_app_views()
        lock.release()


def _log_outcome(verb: str, app_id: str, app: dict, result: dict) -> None:
    """Record what brew actually said, at a severity matching the outcome.

    A failure logged at info would be invisible: the record has to outlive the
    dialog the operator closes, and "the app store cannot install anything" is
    unanswerable without it.  Newlines are folded so one attempt is one grep-able
    line.
    """
    log.log(
        logging.INFO if result.get("ok") else logging.WARNING,
        "%s %s method=%s ok=%s: %s",
        verb,
        app_id,
        app.get("method"),
        result.get("ok"),
        _as_text(result.get("message")).replace("\n", " | ")[:600],
    )


def install_native(app_id: str, variables: dict | None = None) -> dict:
    app = next((a for a in NATIVE_APPS if a["id"] == app_id), None)
    if not app:
        raise api_error("catalog.unknown_app", app=app_id)
    if not _is_file(Path(BREW)) and app.get("method", "").startswith("brew"):
        # Name the path actually checked. BREW is resolved at import (`which brew`
        # first, then the two standard prefixes), so quoting a fixed
        # /opt/homebrew path sent operators to look in the wrong place.
        raise api_error("catalog.brew_missing", path=BREW)

    with _single_flight(app_id):
        result = _install_native(app, app_id)
    _log_outcome("install", app_id, app, result)
    return result


def _install_native(app: dict, app_id: str) -> dict:
    method = app.get("method")
    logs: list[str] = []

    if method == "system" and app.get("system_action") == "enable_screen_sharing":
        return {
            **_enable_screen_sharing(),
            "path": None,
            "kind": "native",
            "stack_id": app_id,
            "notes": app.get("notes") or "",
        }

    if method == "brew_cask":
        pkg = app["package"]
        # already installed?
        if _is_installed(app):
            logs.append(f"{pkg} is already installed")
            if app.get("open"):
                _run(["/usr/bin/open", "-a", app["open"]], timeout=15)
            return {
                "ok": True,
                "message": "\n".join(logs)[-2000:] or "already installed",
                "path": f"/Applications/{app.get('open') or pkg}.app",
                "kind": "native",
                "url": _app_url(app),
                "notes": app.get("notes") or "",
                "stack_id": app_id,
            }
        r = _run_brew(["install", "--cask", pkg], timeout=900)
        logs.append(r["message"])
        ok = _brew_install_ok(r["message"], r["rc"]) or _is_installed(app)
        if ok and app.get("open"):
            _run(["/usr/bin/open", "-a", app["open"]], timeout=15)
        out = {
            "ok": ok,
            "message": "\n".join(logs)[-2000:],
            "path": f"/Applications/{app.get('open') or pkg}.app",
            "kind": "native",
            "url": _app_url(app) if ok else None,
            "notes": app.get("notes") or "",
            "stack_id": app_id,
        }
        if not ok and r.get("error"):
            out["error"] = r["error"]
        return out

    if method == "brew_formula":
        pkg = app["package"]
        already = _is_installed(app)
        if not already:
            r = _run_brew(["install", pkg], timeout=900)
            logs.append(r["message"])
            ok = _brew_install_ok(r["message"], r["rc"]) or _is_installed(app)
        else:
            logs.append(f"{pkg} is already installed")
            ok = True
        if ok and app.get("service"):
            # A custom LaunchAgent (com.kiro.ollama on this class of host) already
            # owns :11434.  `brew services start ollama` would load a second
            # KeepAlive job that crash-loops on EADDRINUSE — 2881 exits on the
            # box that prompted this guard — and the Ollama page's Start then
            # toasted launchctl's "Bootstrap failed: 5: Input/output error".
            skip_brew_service = False
            if app_id == "native-ollama" and ollama_api_already_served():
                logs.append("skipped brew services start: :11434 is already served")
                skip_brew_service = True
            if app_id == "native-redis":
                # Always skip: even with :6379 free, KeepAlive crash-loops on
                # broken loadmodule paths and then fights Immich Valkey.
                skip_brew_service = True
                logs.append("skipped brew services start: :6379 is already served")
            # Bare `brew services start cloudflared` has no token/config, so
            # KeepAlive crash-loops on exit 1 and paints the Services page red.
            # The real tunnel is local.cloudflared-tunnel (token file).
            if app_id == "native-cloudflared":
                logs.append("skipped brew services start: use local.cloudflared-tunnel")
                skip_brew_service = True
            if not skip_brew_service:
                r2 = _run([BREW, "services", "start", pkg], timeout=120)
                logs.append(r2["message"])
                # brew services start: already started counts as ok
                if not r2["ok"] and "already" not in (r2["message"] or "").lower():
                    # still try restart
                    r3 = _run([BREW, "services", "restart", pkg], timeout=120)
                    logs.append(r3["message"])
                    ok = ok and (r3["ok"] or r2["ok"])
        return {
            "ok": ok,
            "message": "\n".join(logs)[-2000:],
            "path": _which(pkg.split("@")[0]) or None,
            "kind": "native",
            "url": _app_url(app) if ok else None,
            "notes": app.get("notes") or "",
            "stack_id": app_id,
        }

    if method == "brew_multi":
        # `ok = ok and (_brew_install_ok(...) or True)` used to stand here, which
        # is `ok = ok and True` -- so this branch reported success no matter what
        # brew did, and the `ok = _is_installed(app) or ok` after it could not undo
        # that, because `or` on an already-true value never looks at the left side.
        # Every failed brew_multi install came back with a green tick and an app
        # that was not there, native-wireguard included.
        pkgs = [str(p) for p in (app.get("packages") or []) if p]
        if not pkgs:
            raise api_error("catalog.entry_incomplete", app=app_id)
        failed: list[str] = []
        password_required = False
        for pkg in pkgs:
            r = _run_brew(["install", pkg], timeout=600)
            logs.append(f"[{pkg}] {r['message']}")
            if r.get("error") == "password_required":
                password_required = True
            if not _brew_install_ok(r["message"], r["rc"]):
                failed.append(pkg)
        if failed:
            # brew exits non-zero on states that leave the package present anyway
            # (a failed post-install step, an already-linked keg).  Ask what is
            # installed before calling it a failure -- but only here, so the
            # success path does not pay for the extra `brew list`.
            present = _brew_list_installed()
            failed = [p for p in failed if p not in present]
        out = {
            "ok": not failed,
            "message": "\n".join(logs)[-2000:],
            "kind": "native",
            "notes": app.get("notes") or "",
            "stack_id": app_id,
        }
        if failed:
            # First line, because that is all the toast shows.
            out["message"] = (
                f"{_MULTI_FAILED_PREFIX}{', '.join(failed)}\n" + out["message"]
            )[-2000:]
            if password_required:
                out["error"] = "password_required"
        return out

    if method == "script":
        sid = app.get("script_id")
        if sid == "filebrowser":
            return _install_filebrowser(app, app_id, logs)
        if sid == "homeassistant":
            return _install_homeassistant(app, app_id, logs)
        raise api_error("catalog.unsupported_script", script=sid)

    raise api_error("catalog.unsupported_method", method=method)


def _install_filebrowser(app: dict, app_id: str, logs: list[str]) -> dict:
    dest = SERVICES_ROOT / "filebrowser"
    _ensure_dir(dest)
    bin_path = dest / "filebrowser-bin"
    db_path = dest / "filebrowser.db"
    media = SERVICES_ROOT / "media"
    _ensure_dir(media)

    if not _exists(bin_path):
        r = _run([BREW, "install", "filebrowser"], timeout=600)
        logs.append(r["message"])
        brew_bin = _which("filebrowser")
        if not brew_bin and _is_file(Path("/opt/homebrew/bin/filebrowser")):
            brew_bin = "/opt/homebrew/bin/filebrowser"
        if brew_bin:
            try:
                if _exists(bin_path) or _is_symlink(bin_path):
                    bin_path.unlink()
                bin_path.symlink_to(brew_bin)
                logs.append(f"linked {bin_path} → {brew_bin}")
            except OSError:
                # Dying-mount copy2 EIO used to 500 FileBrowser install after
                # symlink_to / is_symlink already failed the same way.
                try:
                    shutil.copy2(brew_bin, bin_path)
                    bin_path.chmod(0o755)
                    logs.append(f"copied {brew_bin} → {bin_path}")
                except OSError as exc:
                    logs.append(
                        f"could not place {_as_text(brew_bin)}: {_as_text(exc)}"
                    )
        elif not _brew_install_ok(r["message"], r["rc"]):
            return {
                "ok": False,
                "message": "FileBrowser installation failed.\n" + "\n".join(logs)[-1200:],
                "kind": "native",
                "stack_id": app_id,
                "notes": app.get("notes") or "",
            }

    if not _exists(bin_path):
        return {
            "ok": False,
            "message": "filebrowser binary not found.\n" + "\n".join(logs)[-800:],
            "kind": "native",
            "stack_id": app_id,
        }

    # LaunchAgent (on-demand friendly: RunAtLoad true so start works; user can stop)
    label = "local.filebrowser"
    home = user_home()
    if home is None:
        return {
            "ok": False,
            "message": "home directory is unavailable",
            "kind": "native",
            "stack_id": app_id,
        }
    log_dir = home / "Library/Logs"
    _ensure_dir(log_dir)
    plist = _write_launchagent(
        label,
        [
            _resolved(bin_path),
            "-d", str(db_path),
            "-r", str(media),
            "-a", "127.0.0.1",
            "-p", "8125",
        ],
        working_dir=str(dest),
        stdout=str(log_dir / "filebrowser.out.log"),
        stderr=str(log_dir / "filebrowser.err.log"),
        run_at_load=False,
        keep_alive=False,
    )
    logs.append(f"plist {plist}")
    # start now so "install" is usable
    lr = _launchctl_load(label, plist)
    logs.append(lr["message"])
    url = _app_url(app) or f"http://{_host_for_url()}:8125"
    return {
        "ok": _exists(bin_path),
        "message": "FileBrowser is ready\n" + "\n".join(logs)[-1800:],
        "path": str(dest),
        "kind": "native",
        "url": url,
        "notes": app.get("notes") or "",
        "stack_id": app_id,
    }


def _install_homeassistant(app: dict, app_id: str, logs: list[str]) -> dict:
    """Install or adopt native Home Assistant Core (venv + LaunchAgent)."""
    ha_dir = SERVICES_ROOT / "homeassistant"
    venv = ha_dir / "venv"
    hass = venv / "bin" / "hass"
    config = ha_dir / "config"
    label = "com.homeassistant.core"
    home = user_home()
    if home is None:
        return {
            "ok": False,
            "message": "home directory is unavailable",
            "kind": "native",
            "stack_id": app_id,
        }
    log_out = home / "Library/Logs" / "homeassistant.log"
    log_err = home / "Library/Logs" / "homeassistant.error.log"

    _ensure_dir(ha_dir)
    _ensure_dir(config)

    if _is_file(hass):
        logs.append(f"{hass} already exists")
    else:
        py = _pick_python()
        logs.append(f"using Python: {py or '(none)'}")
        # ensure brew python if missing
        if not py or not _is_file(Path(py)):
            r0 = _run([BREW, "install", "python@3.14"], timeout=900)
            logs.append(r0["message"][-500:])
            py = _pick_python()
        if not py:
            return {
                "ok": False,
                "message": "No Python interpreter was found for the Home Assistant venv\n"
                + "\n".join(logs)[-1500:],
                "kind": "native",
                "stack_id": app_id,
            }
        r1 = _run([py, "-m", "venv", str(venv)], timeout=120)
        logs.append(r1["message"] or f"venv rc={r1['rc']}")
        if not _exists(venv / "bin" / "pip"):
            return {
                "ok": False,
                "message": "Failed to create venv\n" + "\n".join(logs)[-1500:],
                "kind": "native",
                "stack_id": app_id,
            }
        pip = str(venv / "bin" / "pip")
        for args, t in (
            ([pip, "install", "--upgrade", "pip", "wheel"], 300),
            ([pip, "install", "homeassistant"], 1200),
        ):
            r = _run(args, timeout=t)
            logs.append(r["message"][-800:] if r["message"] else f"rc={r['rc']}")
            if not r["ok"] and "homeassistant" in " ".join(args):
                return {
                    "ok": False,
                    "message": "pip install homeassistant failed\n" + "\n".join(logs)[-2000:],
                    "kind": "native",
                    "stack_id": app_id,
                }
        if not _is_file(hass):
            return {
                "ok": False,
                "message": "hass executable not found after install\n" + "\n".join(logs)[-1500:],
                "kind": "native",
                "stack_id": app_id,
            }

    # write/update LaunchAgent matching known-good layout
    env = {
        "PATH": f"{venv / 'bin'}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
        "HOME": str(home),
        "DYLD_LIBRARY_PATH": "/opt/homebrew/lib",
    }
    plist = _write_launchagent(
        label,
        [_resolved(hass), "--config", _resolved(config)],
        working_dir=str(ha_dir),
        stdout=str(log_out),
        stderr=str(log_err),
        run_at_load=True,
        keep_alive=True,
        env=env,
    )
    logs.append(f"plist {plist}")

    # start if not already running
    if not _launchd_or_process_running(label, "hass"):
        lr = _launchctl_load(label, plist)
        logs.append(lr["message"])
    else:
        logs.append("Home Assistant is already running")

    # Write the update script only if it is not there, so an operator who has
    # customised it keeps their version.  Created with "x" rather than after an
    # exists() check: the check-then-write form silently overwrites whenever
    # exists() answers wrongly, which is how a populated services.yaml was reset
    # to defaults elsewhere in this codebase.
    upd = ha_dir / "update-homeassistant.sh"
    try:
        with upd.open("x", encoding="utf-8") as fh:
            fh.write(
                "#!/bin/bash\n"
                "set -e\n"
                f'HA_DIR="{ha_dir}"\n'
                'cd "$HA_DIR"\n'
                "./venv/bin/pip install --upgrade homeassistant\n"
                f'launchctl kickstart -k "gui/$(id -u)/{label}"\n'
            )
        upd.chmod(0o755)
    except OSError:
        # Leftover file or directory named like the script; keep the operator's copy.
        pass

    url = _app_url(app) or f"http://{_host_for_url()}:8123"
    return {
        "ok": _is_file(hass),
        "message": "Home Assistant Core is ready\n" + "\n".join(logs)[-2000:],
        "path": str(ha_dir),
        "kind": "native",
        "url": url,
        "notes": app.get("notes") or "",
        "stack_id": app_id,
    }


def _disable_screen_sharing() -> dict:
    cmds = [
        ["/usr/bin/sudo", "-n", "/bin/launchctl", "unload", "-w",
         "/System/Library/LaunchDaemons/com.apple.screensharing.plist"],
        ["/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart",
         "-deactivate", "-stop"],
        ["/usr/bin/sudo", "-n",
         "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart",
         "-deactivate", "-stop"],
    ]
    logs = []
    for cmd in cmds:
        r = _run(cmd, timeout=30)
        logs.append(f"$ {' '.join(cmd)}\n{r['message']}")
        if not _screen_sharing_on():
            return {
                "ok": True,
                "message": "Screen Sharing disabled\n" + "\n".join(logs)[-1200:],
            }
    return {
        "ok": not _screen_sharing_on(),
        "message": (
            "Could not disable automatically (administrator privileges may be required). "
            "Go to: System Settings → General → Sharing → Screen Sharing.\n"
            + "\n".join(logs)[-1000:]
        ),
    }


def uninstall_native(app_id: str, *, remove_data: bool = False) -> dict:
    """Uninstall a native app (brew uninstall / stop service / system off)."""
    app = next((a for a in NATIVE_APPS if a["id"] == app_id), None)
    if not app:
        raise api_error("catalog.unknown_app", app=app_id)

    with _single_flight(app_id):
        result = _uninstall_native(app, app_id, remove_data=remove_data)
    _log_outcome(f"uninstall(remove_data={remove_data})", app_id, app, result)
    return result


def _uninstall_native(app: dict, app_id: str, *, remove_data: bool = False) -> dict:
    method = app.get("method")
    logs: list[str] = []

    if method == "system" and app.get("system_action") == "enable_screen_sharing":
        r = _disable_screen_sharing()
        return {**r, "kind": "native", "stack_id": app_id}

    if method == "brew_cask":
        pkg = app["package"]
        # quit app first if possible.  The app name is passed as an argv
        # parameter (`on run argv`) rather than interpolated into the script
        # source, so a name containing a double quote cannot break out of the
        # string literal — harmless with today's shipped catalog, injection the
        # moment catalog entries become user-editable.
        if app.get("open"):
            _run([
                "/usr/bin/osascript", "-e",
                'on run argv\nquit app (item 1 of argv)\nend run',
                str(app["open"]),
            ], timeout=15)
        r = _run_brew(["uninstall", "--cask", pkg], timeout=300)
        logs.append(r["message"])
        # also try zap if requested
        if remove_data:
            r2 = _run_brew(["uninstall", "--cask", "--zap", pkg], timeout=300)
            logs.append(r2["message"])
        return {
            "ok": r["ok"] or not _is_installed(app),
            "message": "\n".join(logs)[-2000:] or "uninstalled",
            "kind": "native",
            "stack_id": app_id,
        }

    if method == "brew_formula":
        # _raise_if_brew_vanished on every spawn, same as the brew_cask branch's
        # _run_brew: a brew that vanished mid-request used to fall through the
        # `not _is_installed(app)` fallback — which cannot see a formula while
        # `brew list` itself is gone — and report a *successful* uninstall of
        # an app that is still fully installed.
        pkg = app["package"]
        if app.get("service"):
            r0 = _raise_if_brew_vanished(_run([BREW, "services", "stop", pkg], timeout=120))
            logs.append(r0["message"])
        r = _raise_if_brew_vanished(_run([BREW, "uninstall", pkg], timeout=300))
        logs.append(r["message"])
        return {
            "ok": r["ok"] or not _is_installed(app),
            "message": "\n".join(logs)[-2000:] or "uninstalled",
            "kind": "native",
            "stack_id": app_id,
        }

    if method == "brew_multi":
        # No running `ok` accumulator here: it was `ok and (r["ok"] or True)`,
        # which is a no-op, and the return below ignored it anyway.  What the
        # operator asked for is "this app is gone", so that is what gets checked.
        for pkg in reversed(app.get("packages") or []):
            r = _raise_if_brew_vanished(_run([BREW, "uninstall", pkg], timeout=300))
            logs.append(f"[{pkg}] {r['message']}")
        return {
            "ok": not _is_installed(app),
            "message": "\n".join(logs)[-2000:] or "uninstalled",
            "kind": "native",
            "stack_id": app_id,
        }

    if method == "script" and app.get("script_id") == "filebrowser":
        _launchctl_unload("local.filebrowser")
        dest = SERVICES_ROOT / "filebrowser"
        if not _exists(dest):
            return {"ok": True, "message": "~/Services/filebrowser not found", "kind": "native", "stack_id": app_id}
        if remove_data:
            try:
                shutil.rmtree(dest)
                return {
                    "ok": True,
                    "message": f"deleted {dest}",
                    "kind": "native",
                    "stack_id": app_id,
                }
            except _CONTROL_FLOW:
                raise
            except BaseException as e:
                return {"ok": False, "message": _as_text(e), "kind": "native", "stack_id": app_id}
        return {
            "ok": True,
            "message": 'FileBrowser stopped. ~/Services/filebrowser was kept (check "Also delete data" to remove it).',
            "kind": "native",
            "stack_id": app_id,
        }

    if method == "script" and app.get("script_id") == "homeassistant":
        label = app.get("launchd_label") or "com.homeassistant.core"
        _launchctl_unload(label)
        logs.append(f"stopped {label}")
        ha_dir = SERVICES_ROOT / "homeassistant"
        if remove_data and _exists(ha_dir):
            try:
                # keep config backup safety: only remove if remove_data
                shutil.rmtree(ha_dir)
                logs.append(f"removed {ha_dir}")
            except _CONTROL_FLOW:
                raise
            except BaseException as e:
                return {"ok": False, "message": _as_text(e), "kind": "native", "stack_id": app_id}
            # leave plist so reinstall can rewrite; or remove
            home = user_home()
            pl = (home / "Library/LaunchAgents" / f"{label}.plist") if home is not None else None
            if pl is not None and _exists(pl):
                try:
                    pl.unlink()
                except OSError:
                    pass
            return {
                "ok": True,
                "message": "Stopped Home Assistant and deleted its data directory\n" + "\n".join(logs),
                "kind": "native",
                "stack_id": app_id,
            }
        return {
            "ok": True,
            "message": 'Home Assistant stopped (config kept in ~/Services/homeassistant). Check "Also delete data" to remove it.',
            "kind": "native",
            "stack_id": app_id,
        }

    raise api_error("catalog.unsupported_uninstall", method=method)
