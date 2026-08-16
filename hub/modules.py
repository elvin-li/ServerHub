"""Extensible module registry — inspired by CasaOS / plugin dashboards.

Each module declares id, title, APIs it owns, and dashboard widgets.
Keeps ServerHub feature surface discoverable and documentable.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class ModuleInfo:
    id: str
    name: str
    description: str
    category: str  # system | docker | storage | network | apps | ops
    apis: list[str] = field(default_factory=list)
    ui_routes: list[str] = field(default_factory=list)
    inspired_by: list[str] = field(default_factory=list)
    enabled: bool = True


MODULES: list[ModuleInfo] = [
    ModuleInfo(
        id="dashboard",
        name="Dashboard",
        description="System tiles, trends, anomalies, ports and scheduled digests",
        category="system",
        apis=["/api/status", "/api/metrics", "/api/health"],
        ui_routes=["/"],
    ),
    ModuleInfo(
        id="services",
        name="Services",
        description="Unified discovery and start/stop for launchd, scripts, apps and the OrbStack engine",
        category="system",
        apis=["/api/status", "/api/action"],
        ui_routes=["/services"],
    ),
    ModuleInfo(
        id="brew",
        name="Homebrew Services",
        description="brew services list/start/stop/restart",
        category="system",
        apis=["/api/brew/services", "/api/brew/services/{name}/action"],
        ui_routes=["/brew", "/tools"],
    ),
    ModuleInfo(
        id="docker",
        name="Docker / OrbStack",
        description="Container table, batch actions, update checks, console, log SSE",
        category="docker",
        apis=["/api/containers", "/api/images", "/api/volumes", "/api/networks"],
        ui_routes=["/containers"],
    ),
    ModuleInfo(
        id="compose",
        name="Compose Stacks",
        description="Stack list, YAML editing, validation, pull/up/down",
        category="docker",
        apis=["/api/stacks", "/api/compose/{stack_id}"],
        ui_routes=["/apps", "/compose"],
    ),
    ModuleInfo(
        id="catalog",
        name="App Catalog",
        description="One-click deploys from template variable forms",
        category="apps",
        apis=["/api/catalog"],
        ui_routes=["/apps"],
    ),
    ModuleInfo(
        id="storage",
        name="Storage Array",
        description="Multiple volumes + multi-disk SMART + HDD sleep/wake",
        category="storage",
        apis=["/api/storage", "/api/storage/disks", "/api/storage/disks/{id}/power"],
        ui_routes=["/main"],
    ),
    ModuleInfo(
        id="shares",
        name="Shares",
        description="SMB + file service status",
        category="storage",
        apis=["/api/shares"],
        ui_routes=["/shares"],
    ),
    ModuleInfo(
        id="network",
        name="Network",
        description="Interfaces / listening ports / routes",
        category="network",
        apis=["/api/system/network"],
        ui_routes=["/network"],
    ),
    ModuleInfo(
        id="gateway",
        name="System Nginx Gateway",
        description="Site-wide reverse proxy · automatic conf.d site discovery · reload",
        category="network",
        apis=["/api/nginx", "/api/nginx/reload"],
        ui_routes=["/gateway"],
    ),
    ModuleInfo(
        id="adaptive",
        name="Adaptive Discovery",
        description="LaunchAgent port inference, orphaned listeners, Compose/site scanning",
        category="system",
        apis=["/api/status", "/api/adaptive/compose-scan"],
        ui_routes=["/", "/services"],
    ),
    ModuleInfo(
        id="bookmarks",
        name="Bookmark Probes",
        description="HTTP health checks for quick-access links",
        category="apps",
        apis=["/api/bookmarks"],
        ui_routes=["/", "/bookmarks"],
    ),
    ModuleInfo(
        id="sensors",
        name="Sensors",
        description="CPU load details, memory, disk I/O sampling",
        category="system",
        apis=["/api/system/sensors"],
        ui_routes=["/", "/tools"],
    ),
    ModuleInfo(
        id="logs",
        name="Log Center",
        description="Multi-source tail / filter / download",
        category="ops",
        apis=["/api/logs"],
        ui_routes=["/logs"],
    ),
    ModuleInfo(
        id="alerts",
        name="Alerts",
        description="State changes + HA notifications",
        category="ops",
        apis=["/api/alerts"],
        ui_routes=["/alerts"],
    ),
    ModuleInfo(
        id="backups",
        name="Backups",
        description="PG dumps / config tarballs",
        category="ops",
        apis=["/api/backups"],
        ui_routes=["/backups"],
    ),

    ModuleInfo(
        id="photoshub",
        name="PhotosHub",
        description="Family photo pipeline: originals rate, Photos to Immich bridge, delete-review, external HDD backup",
        category="apps",
        apis=["/api/photoshub/status", "/api/photoshub/action", "/api/photoshub/pending-delete", "/api/photoshub/config"],
        ui_routes=["/photoshub"],
    ),

    ModuleInfo(
        id="tools",
        name="Tools",
        description="Diagnostics, processes, Docker usage, scheduled tasks",
        category="ops",
        apis=["/api/system/diagnostics", "/api/system/processes"],
        ui_routes=["/tools"],
    ),
]


def list_modules() -> list[dict]:
    return [asdict(m) for m in MODULES]


def modules_by_category() -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for m in MODULES:
        out.setdefault(m.category, []).append(asdict(m))
    return out
