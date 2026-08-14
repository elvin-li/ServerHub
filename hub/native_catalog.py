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
import shlex
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from fastapi import HTTPException

from hub.brew_cache import brew_services_list, invalidate_brew_services
from hub.errors import CODES, api_error
from hub.host_address import host_ip
from hub.launchd_cache import invalidate_launchd
from hub.launchd_cache import running_labels as launchd_running_labels
from hub.proc_cache import invalidate_processes, process_matches
from hub.util import cached_snapshot, fan_out, sh

SERVICES_ROOT = Path.home() / "Services"
# One definition, in hub.paths: it tries `which brew` before the two standard
# prefixes. The app store is the worst place to disagree about where brew is --
# every install and uninstall goes through it.
from hub.paths import BREW  # noqa: E402

#: Install outcomes go to the panel's own log (~/Library/Logs/serverhub.err.log).
#: An install that fails in a browser leaves no trace anywhere else: the response
#: body is gone as soon as the operator closes the dialog, and "the app store
#: cannot install anything" is unanswerable without knowing what brew said.
log = logging.getLogger("serverhub.appstore")

#: First line of a failed brew_multi message, and all the toast shows.  Named so
#: the store and its tests cannot disagree about it.
_MULTI_FAILED_PREFIX = "以下包安装失败："

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


def _which(name: str) -> str | None:
    return shutil.which(name) or (
        str(p) if (p := Path(f"/opt/homebrew/bin/{name}")).is_file() else None
    )


def _app_exists(name: str) -> bool:
    # Support names with spaces e.g. "Plex Media Server"
    return Path(f"/Applications/{name}.app").exists() or Path(
        f"/Applications/{name}"
    ).exists()


def _brew_list_installed() -> set[str]:
    if not Path(BREW).is_file():
        return set()
    rc, out, _ = sh([BREW, "list", "--formula", "-1"], timeout=30)
    formulas = set(out.split()) if rc == 0 else set()
    rc2, out2, _ = sh([BREW, "list", "--cask", "-1"], timeout=30)
    casks = set(out2.split()) if rc2 == 0 else set()
    return formulas | casks


def _screen_sharing_on() -> bool:
    # launchctl print system/com.apple.screensharing
    rc, out, _ = sh(
        ["/bin/launchctl", "print", "system/com.apple.screensharing"],
        timeout=5,
    )
    if rc == 0 and "state = running" in (out or ""):
        return True
    # older
    rc2, out2, _ = sh(
        ["/bin/launchctl", "list", "com.apple.screensharing"],
        timeout=4,
    )
    return rc2 == 0


# Catalog definition (prefer native)
NATIVE_APPS: list[dict[str, Any]] = [
    {
        "id": "native-wireguard",
        "name": "WireGuard（原生工具链）",
        "desc": "wg / wg-quick + 用户态实现 · 面板「WireGuard」页依赖它",
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
            "装好后到「WireGuard」页生成服务端与客户端配置。"
            "macOS 没有内核态 WireGuard，隧道运行在 wireguard-go 的 utun 设备上。"
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
        "name": "RustDesk（原生客户端）",
        "desc": "开源远程桌面客户端 · 可连自建中继",
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
        "name": "Syncthing（原生服务）",
        "desc": "P2P 文件同步 · brew 服务常驻",
        "category": "files",
        "tags": ["sync", "native"],
        "featured": True,
        "method": "brew_formula",
        "package": "syncthing",
        "check": "bin:syncthing",
        "service": True,
        "ports": ["8384"],
        "url_hint": "http://{{HOST}}:8384",
        "notes": "安装并 brew services start syncthing。Web UI 默认 8384。",
    },
    {
        "id": "native-rclone",
        "name": "rclone（原生）",
        "desc": "网盘 / S3 / 对象存储同步 CLI",
        "category": "files",
        "tags": ["sync", "cloud", "native"],
        "featured": False,
        "method": "brew_formula",
        "package": "rclone",
        "check": "bin:rclone",
    },
    {
        "id": "native-filebrowser",
        "name": "FileBrowser（原生二进制）",
        "desc": "轻量 Web 文件管理 · 无 Docker",
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
        "notes": "一键安装 brew filebrowser + LaunchAgent · 端口 8125 · 根目录 ~/Services/media。",
    },
    {
        "id": "native-mosquitto",
        "name": "Mosquitto MQTT（brew）",
        "desc": "MQTT Broker 原生服务 · HA/IoT 推荐",
        "category": "iot",
        "tags": ["mqtt", "native"],
        "featured": True,
        "method": "brew_formula",
        "package": "mosquitto",
        "check": "bin:mosquitto",
        "service": True,
        "ports": ["1883"],
        "notes": "brew services start mosquitto。比 Docker 更省资源。",
    },
    {
        "id": "native-redis",
        "name": "Redis（brew）",
        "desc": "内存数据库 · 原生服务",
        "category": "data",
        "tags": ["cache", "native"],
        "featured": True,
        "method": "brew_formula",
        "package": "redis",
        "check": "bin:redis-server",
        "service": True,
        "ports": ["6379"],
    },
    {
        "id": "native-postgresql",
        "name": "PostgreSQL 17（brew）",
        "desc": "关系型数据库 · 本机已在用可直接启动服务",
        "category": "data",
        "tags": ["db", "native"],
        "featured": True,
        "method": "brew_formula",
        "package": "postgresql@17",
        "check": "bin:psql",
        "service": True,
        "ports": ["5432"],
        "notes": "formula 名为 postgresql@17。服务：brew services start postgresql@17",
    },
    {
        "id": "native-nginx",
        "name": "Nginx（brew）",
        "desc": "反向代理 / 静态站 · 建议用自有 conf",
        "category": "network",
        "tags": ["proxy", "native"],
        "featured": False,
        "method": "brew_formula",
        "package": "nginx",
        "check": "bin:nginx",
        "service": False,
        "notes": "本机可能已用自定义 LaunchAgent 跑 nginx；安装 formula 后请用你的 conf，避免端口冲突。",
    },
    {
        "id": "native-grafana",
        "name": "Grafana（brew）",
        "desc": "监控可视化 · 原生服务",
        "category": "monitor",
        "tags": ["monitor", "native"],
        "featured": True,
        "method": "brew_formula",
        "package": "grafana",
        # Homebrew 新版二进制为 grafana（旧版 grafana-server）
        "check": ["bin:grafana", "bin:grafana-server", "brew:grafana"],
        "service": True,
        "ports": ["3000"],
        "url_hint": "http://{{HOST}}:3000",
    },
    {
        "id": "native-prometheus",
        "name": "Prometheus（brew）",
        "desc": "指标采集 · 可与 Grafana 搭配",
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
        "name": "node_exporter（brew）",
        "desc": "主机指标导出 · Prometheus 抓取",
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
        "id": "native-jellyfin",
        "name": "Jellyfin（原生 App）",
        "desc": "媒体服务器 cask · 比 Docker 更贴合 macOS",
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
        "name": "Plex Media Server（原生）",
        "desc": "Plex 媒体服务器 · macOS 原生 App（你当前家服已在用）",
        "category": "media",
        "tags": ["media", "plex", "native"],
        "featured": True,
        "method": "brew_cask",
        "package": "plex-media-server",
        "check": "app:Plex Media Server",
        "open": "Plex Media Server",
        "ports": ["32400"],
        "url_hint": "http://{{HOST}}:32400/web",
        "notes": "也可从 plex.tv 官网安装。卸载会 brew uninstall --cask plex-media-server。",
    },
    {
        "id": "native-navidrome",
        "name": "Navidrome（brew）",
        "desc": "音乐库 / Subsonic 兼容 · 原生",
        "category": "media",
        "tags": ["music", "native"],
        "featured": True,
        "method": "brew_formula",
        "package": "navidrome",
        "check": "bin:navidrome",
        "service": True,
        "ports": ["4533"],
        "url_hint": "http://{{HOST}}:4533",
        "notes": "需自行配置音乐目录（config 或环境变量）。",
    },
    {
        "id": "native-qbittorrent",
        "name": "qBittorrent（原生 App）",
        "desc": "BT 下载客户端 · macOS App",
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
        "name": "iTerm2（原生）",
        "desc": "增强终端 · 家服排障常用",
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
        "name": "Stats（菜单栏监控）",
        "desc": "CPU/内存/网速菜单栏小组件",
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
        "name": "htop / btop（CLI）",
        "desc": "终端进程监视 · btop 更漂亮",
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
        "name": "Git + gh（CLI）",
        "desc": "开发基础工具链",
        "category": "dev",
        "tags": ["git", "native"],
        "featured": False,
        "method": "brew_multi",
        "packages": ["git", "gh"],
        "check": "bin:gh",
    },
    {
        "id": "native-gitea",
        "name": "Gitea（brew）",
        "desc": "轻量 Git 服务 · 原生进程",
        "category": "dev",
        "tags": ["git", "native"],
        "featured": True,
        "method": "brew_formula",
        "package": "gitea",
        "check": "bin:gitea",
        "service": True,
        "ports": ["3000"],
        "url_hint": "http://{{HOST}}:3000",
        "notes": "首次需配置 ~/Services/gitea 或 brew 默认路径。",
    },
    {
        "id": "native-minio",
        "name": "MinIO（brew）",
        "desc": "S3 兼容对象存储 CLI/服务",
        "category": "data",
        "tags": ["s3", "native"],
        "featured": False,
        "method": "brew_formula",
        "package": "minio",
        "check": "bin:minio",
        "service": False,
        "notes": "安装后可用 minio server ~/data 启动；或自行写 LaunchAgent。",
    },
    {
        "id": "native-ntfy",
        "name": "ntfy（brew）",
        "desc": "自托管推送 · 原生二进制",
        "category": "notify",
        "tags": ["notify", "native"],
        "featured": True,
        "method": "brew_formula",
        "package": "ntfy",
        "check": "bin:ntfy",
        "service": False,
        "notes": "可 ntfy serve；需要常驻请自建 LaunchAgent 或用维护脚本。",
    },
    {
        "id": "native-duplicacy",
        "name": "Duplicacy（CLI）",
        "desc": "高效加密备份 CLI",
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
        "desc": "磁盘 SMART 检测 · 存储阵列页依赖",
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
        "name": "Home Assistant Core（原生）",
        "desc": "本机 venv + LaunchAgent · 推荐（非 Docker/HAOS）",
        "category": "iot",
        "tags": ["ha", "homeassistant", "native", "iot"],
        "featured": True,
        "method": "script",
        "script_id": "homeassistant",
        "check": [
            "path:~/Services/homeassistant/venv/bin/hass",
            "path:~/Library/LaunchAgents/com.homeassistant.core.plist",
        ],
        "ports": ["8123"],
        "url_hint": "http://{{HOST}}:8123",
        "launchd_label": "com.homeassistant.core",
        "process_match": "homeassistant/venv/bin/hass",
        "notes": (
            "安装到 ~/Services/homeassistant（venv + config + LaunchAgent）。"
            "已存在的原生部署会自动识别并可启停。Web UI 默认 :8123。"
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
        p = spec.split(":", 1)[1].replace("~", str(Path.home()))
        return Path(p).exists()
    if spec.startswith("brew:"):
        pkg = spec.split(":", 1)[1]
        inst = brew_installed if brew_installed is not None else _brew_list_installed()
        return pkg in inst
    return False


def _is_installed(app: dict, brew_installed: set[str] | None = None) -> bool:
    """True if any check matches. For brew apps also fall back to `brew list` package."""
    check = app.get("check")
    specs: list[str] = []
    if isinstance(check, (list, tuple)):
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
    with ThreadPoolExecutor(max_workers=3) as ex:
        f_installed = ex.submit(_brew_list_installed)
        f_services = ex.submit(brew_services_list)
        f_host = ex.submit(host_ip)
        brew_inst = f_installed.result()
        service_rows = f_services.result()
        host = f_host.result()

    service_states: dict[str, str] = {}
    for s in service_rows:
        name = s.get("name") or ""
        if name:
            service_states[name] = (s.get("status") or "").lower()

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
        # True only when a matching process is up; otherwise leave None ("已安装")
        # so unused CLIs don't show as "已停止".
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
        url = _resolve_url(app.get("url_hint") or "", host, app.get("ports") or [])
        items.append({
            "id": app["id"],
            "name": app["name"],
            "desc": app.get("desc") or "",
            "category": app.get("category") or "other",
            "tags": list(app.get("tags") or []),
            "featured": bool(app.get("featured")),
            "notes": app.get("notes") or "",
            "ports": list(app.get("ports") or []),
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
    every other reader in the same request now share one spawn.
    """
    return process_matches(process_substr)


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
        return launchd_running_labels()


def _launchd_or_process_running(
    label: str,
    process_substr: str,
    launchd: _LaunchdSnapshot | None = None,
) -> bool:
    if label:
        if launchd is not None:
            if label in launchd.running_labels():
                return True
        else:
            # No shared listing (single-app callers below); ask about this one label.
            rc, out, _ = sh(
                ["/bin/launchctl", "print", f"gui/{os.getuid()}/{label}"],
                timeout=5,
            )
            if rc == 0 and "state = running" in (out or ""):
                return True
    return _process_running(process_substr)


def _resolve_url(hint: str, host: str, ports: list) -> str:
    """Fill {{HOST}} / build http URL from first web port when hint empty."""
    host = host or "localhost"
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
        ps = str(p).split("/")[0]
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


def _run(cmd: list[str], timeout: int = 600) -> dict:
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_brew_env(),
        )
        msg = ((p.stdout or "") + (p.stderr or "")).strip()
        return {"ok": p.returncode == 0, "message": msg or f"exit {p.returncode}", "rc": p.returncode}
    except subprocess.TimeoutExpired:
        return {"ok": False, "message": "命令超时", "rc": -1}
    except Exception as e:
        return {"ok": False, "message": str(e), "rc": -1}


def _needs_admin_retry(msg: str) -> bool:
    """True when brew failed because sudo needs an interactive/admin session."""
    low = (msg or "").lower()
    if "user canceled" in low or "用户取消" in low:
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
    *internally*, not brew itself.  There is no way to hand that inner sudo a
    password from here without a tty, so this reports the situation precisely and
    tells the operator the one command that does work.  Everything that does not
    need root -- every formula, and every cask whose artifact is an .app, since
    /Applications is admin-writable -- installs normally through this path.
    """
    cmd = [BREW, *brew_args]
    r = _run(cmd, timeout=timeout)
    if r["ok"] or not admin_on_sudo_fail:
        return r

    if _brew_refuses_root(r.get("message") or ""):
        # Should be unreachable: the panel does not run as root. Worth saying
        # plainly rather than passing Homebrew's warning through as-is.
        r["message"] = (
            "Homebrew 拒绝以 root 运行，面板不应以 root 启动。\n"
            "请以普通用户运行面板后重试。\n\n" + (r.get("message") or "")
        )[-4000:]
        return r

    if _needs_admin_retry(r.get("message") or ""):
        r["error"] = "password_required"
        r["message"] = (
            "这个包需要 root 权限运行 macOS 安装器（pkg 类 cask），"
            "而 brew 本身不能以 root 运行，所以面板无法代为授权。\n"
            "请在这台 Mac 上打开终端执行：\n"
            f"  {' '.join(shlex.quote(c) for c in cmd)}\n\n"
            "不需要 root 的包（所有 formula，以及 .app 类 cask）可以直接在面板安装。\n\n"
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
    return host_ip()


def _app_url(app: dict) -> str:
    return _resolve_url(app.get("url_hint") or "", _host_for_url(), app.get("ports") or [])


def _write_launchagent(label: str, program_args: list[str], *,
                       working_dir: str | None = None,
                       stdout: str | None = None,
                       stderr: str | None = None,
                       run_at_load: bool = True,
                       keep_alive: bool = True,
                       env: dict | None = None) -> Path:
    import plistlib
    from hub import secure_io
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
    # Atomic replace refuses a leaf symlink at the LaunchAgent path.
    secure_io.atomic_write_bytes(
        pl_path,
        plistlib.dumps(pl, fmt=plistlib.FMT_XML, sort_keys=False),
        mode=0o644,
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
    return rc == 0 and bool(out)


def _launchctl_load(label: str, plist: Path) -> dict:
    """Start or reload a user LaunchAgent without clobbering a healthy job."""
    from hub.paths import UID
    dom = f"gui/{UID}"
    target = f"{dom}/{label}"
    if not plist.exists():
        return {"ok": False, "message": f"plist 不存在: {plist}"}

    # If already loaded, prefer kickstart -k (restart in place)
    if _launchctl_is_loaded(label):
        rc, out, err = sh(["/bin/launchctl", "kickstart", "-k", target], timeout=20)
        if rc == 0:
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
    ok = r2[0] == 0 or _launchctl_is_loaded(label)
    # process probe fallback
    if not ok:
        time.sleep(0.5)
        ok = _launchd_or_process_running(label, label.split(".")[-1])
    msg = (
        f"bootstrap={r1[0]} kickstart={r2[0]} "
        f"{(r1[2] or r1[1] or '')} {(r2[2] or r2[1] or '')}"
    ).strip()
    return {"ok": ok, "message": msg or ("ok" if ok else "start failed")}


def _launchctl_unload(label: str) -> dict:
    from hub.paths import UID
    dom = f"gui/{UID}"
    target = f"{dom}/{label}"
    # prefer bootout; also try legacy unload
    rc, out, err = sh(["/bin/launchctl", "bootout", target], timeout=10)
    if rc != 0:
        pl = Path.home() / "Library/LaunchAgents" / f"{label}.plist"
        if pl.exists():
            sh(["/bin/launchctl", "unload", str(pl)], timeout=10)
    # Same reason as the load path: the confirmation below must not read a snapshot
    # taken before the bootout.
    _forget_host_state()
    ok = not _launchctl_is_loaded(label)
    return {
        "ok": ok or rc in (0, 3, 5) or "No such" in ((err or "") + (out or "")),
        "message": out or err or f"exit {rc}",
    }


def _pick_python() -> str:
    """Prefer python3.14 (HA native on this host), then 3.13/3.12."""
    for c in (
        "/opt/homebrew/opt/python@3.14/bin/python3.14",
        "/opt/homebrew/opt/python@3.14/bin/python3",
        "/opt/homebrew/bin/python3.14",
        "/opt/homebrew/opt/python@3.13/bin/python3.13",
        "/opt/homebrew/bin/python3.13",
        "/opt/homebrew/opt/python@3.12/bin/python3.12",
        "/opt/homebrew/bin/python3.12",
        shutil.which("python3") or "",
    ):
        if c and Path(c).is_file():
            return c
    return "python3"


def _enable_screen_sharing() -> dict:
    # Try without password first, then sudo -n
    cmds = [
        ["/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart",
         "-activate", "-configure", "-access", "-on",
         "-restart", "-agent", "-privs", "-all"],
        ["sudo", "-n", "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart",
         "-activate", "-configure", "-access", "-on",
         "-restart", "-agent", "-privs", "-all"],
        ["sudo", "-n", "/bin/launchctl", "load", "-w",
         "/System/Library/LaunchDaemons/com.apple.screensharing.plist"],
    ]
    logs = []
    for cmd in cmds:
        if not Path(cmd[0] if cmd[0] != "sudo" else cmd[2] if len(cmd) > 2 else "").exists() and cmd[0] != "sudo":
            # kickstart path
            pass
        r = _run(cmd, timeout=30)
        logs.append(f"$ {' '.join(cmd)}\n{r['message']}")
        if r["ok"] or _screen_sharing_on():
            return {
                "ok": True,
                "message": "屏幕共享已启用（或已在运行）\n" + "\n".join(logs)[-1500:],
                "url": None,
            }
    # last resort message
    return {
        "ok": _screen_sharing_on(),
        "message": (
            "未能自动启用（可能需要管理员权限）。请到：系统设置 → 通用 → 共享 → 屏幕共享。\n"
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
        (result.get("message") or "").replace("\n", " | ")[:600],
    )


def install_native(app_id: str, variables: dict | None = None) -> dict:
    app = next((a for a in NATIVE_APPS if a["id"] == app_id), None)
    if not app:
        raise HTTPException(404, f"unknown native app: {app_id}")
    if not Path(BREW).is_file() and app.get("method", "").startswith("brew"):
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
            logs.append(f"{pkg} 已安装")
            if app.get("open"):
                _run(["/usr/bin/open", "-a", app["open"]], timeout=15)
            return {
                "ok": True,
                "message": "\n".join(logs)[-2000:] or "已安装",
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
        return {
            "ok": ok,
            "message": "\n".join(logs)[-2000:],
            "path": f"/Applications/{app.get('open') or pkg}.app",
            "kind": "native",
            "url": _app_url(app) if ok else None,
            "notes": app.get("notes") or "",
            "stack_id": app_id,
        }

    if method == "brew_formula":
        pkg = app["package"]
        already = _is_installed(app)
        if not already:
            r = _run_brew(["install", pkg], timeout=900)
            logs.append(r["message"])
            ok = _brew_install_ok(r["message"], r["rc"]) or _is_installed(app)
        else:
            logs.append(f"{pkg} 已安装")
            ok = True
        if ok and app.get("service"):
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
        raise HTTPException(400, f"unsupported script_id: {sid}")

    raise HTTPException(400, f"unsupported method: {method}")


def _install_filebrowser(app: dict, app_id: str, logs: list[str]) -> dict:
    dest = SERVICES_ROOT / "filebrowser"
    dest.mkdir(parents=True, exist_ok=True)
    bin_path = dest / "filebrowser-bin"
    db_path = dest / "filebrowser.db"
    media = SERVICES_ROOT / "media"
    media.mkdir(parents=True, exist_ok=True)

    if not bin_path.exists():
        r = _run([BREW, "install", "filebrowser"], timeout=600)
        logs.append(r["message"])
        brew_bin = _which("filebrowser")
        if not brew_bin and Path("/opt/homebrew/bin/filebrowser").is_file():
            brew_bin = "/opt/homebrew/bin/filebrowser"
        if brew_bin:
            try:
                if bin_path.exists() or bin_path.is_symlink():
                    bin_path.unlink()
                bin_path.symlink_to(brew_bin)
                logs.append(f"链接 {bin_path} → {brew_bin}")
            except OSError:
                shutil.copy2(brew_bin, bin_path)
                bin_path.chmod(0o755)
                logs.append(f"复制 {brew_bin} → {bin_path}")
        elif not _brew_install_ok(r["message"], r["rc"]):
            return {
                "ok": False,
                "message": "FileBrowser 安装失败。\n" + "\n".join(logs)[-1200:],
                "kind": "native",
                "stack_id": app_id,
                "notes": app.get("notes") or "",
            }

    if not bin_path.exists():
        return {
            "ok": False,
            "message": "未找到 filebrowser 二进制。\n" + "\n".join(logs)[-800:],
            "kind": "native",
            "stack_id": app_id,
        }

    # LaunchAgent (on-demand friendly: RunAtLoad true so start works; user can stop)
    label = "local.filebrowser"
    log_dir = Path.home() / "Library/Logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    plist = _write_launchagent(
        label,
        [
            str(bin_path.resolve()),
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
        "ok": bin_path.exists(),
        "message": "FileBrowser 已就绪\n" + "\n".join(logs)[-1800:],
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
    log_out = Path.home() / "Library/Logs" / "homeassistant.log"
    log_err = Path.home() / "Library/Logs" / "homeassistant.error.log"

    ha_dir.mkdir(parents=True, exist_ok=True)
    config.mkdir(parents=True, exist_ok=True)

    if hass.is_file():
        logs.append(f"已存在 {hass}")
    else:
        py = _pick_python()
        logs.append(f"使用 Python: {py}")
        # ensure brew python if missing
        if not Path(py).is_file() or py == "python3":
            r0 = _run([BREW, "install", "python@3.14"], timeout=900)
            logs.append(r0["message"][-500:])
            py = _pick_python()
        r1 = _run([py, "-m", "venv", str(venv)], timeout=120)
        logs.append(r1["message"] or f"venv rc={r1['rc']}")
        if not (venv / "bin" / "pip").exists():
            return {
                "ok": False,
                "message": "创建 venv 失败\n" + "\n".join(logs)[-1500:],
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
                    "message": "pip install homeassistant 失败\n" + "\n".join(logs)[-2000:],
                    "kind": "native",
                    "stack_id": app_id,
                }
        if not hass.is_file():
            return {
                "ok": False,
                "message": "安装后未找到 hass 可执行文件\n" + "\n".join(logs)[-1500:],
                "kind": "native",
                "stack_id": app_id,
            }

    # write/update LaunchAgent matching known-good layout
    env = {
        "PATH": f"{venv / 'bin'}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
        "HOME": str(Path.home()),
        "DYLD_LIBRARY_PATH": "/opt/homebrew/lib",
    }
    plist = _write_launchagent(
        label,
        [str(hass.resolve()), "--config", str(config.resolve())],
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
        logs.append("Home Assistant 已在运行")

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
    except FileExistsError:
        pass

    url = _app_url(app) or f"http://{_host_for_url()}:8123"
    return {
        "ok": hass.is_file(),
        "message": "Home Assistant Core 已就绪\n" + "\n".join(logs)[-2000:],
        "path": str(ha_dir),
        "kind": "native",
        "url": url,
        "notes": app.get("notes") or "",
        "stack_id": app_id,
    }


def _disable_screen_sharing() -> dict:
    cmds = [
        ["sudo", "-n", "/bin/launchctl", "unload", "-w",
         "/System/Library/LaunchDaemons/com.apple.screensharing.plist"],
        ["/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart",
         "-deactivate", "-stop"],
        ["sudo", "-n",
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
                "message": "屏幕共享已关闭\n" + "\n".join(logs)[-1200:],
            }
    return {
        "ok": not _screen_sharing_on(),
        "message": (
            "未能自动关闭（可能需要管理员权限）。请到：系统设置 → 通用 → 共享 → 屏幕共享。\n"
            + "\n".join(logs)[-1000:]
        ),
    }


def uninstall_native(app_id: str, *, remove_data: bool = False) -> dict:
    """Uninstall a native app (brew uninstall / stop service / system off)."""
    app = next((a for a in NATIVE_APPS if a["id"] == app_id), None)
    if not app:
        raise HTTPException(404, f"unknown native app: {app_id}")

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
        # quit app first if possible
        if app.get("open"):
            _run(["/usr/bin/osascript", "-e", f'quit app "{app["open"]}"'], timeout=15)
        r = _run_brew(["uninstall", "--cask", pkg], timeout=300)
        logs.append(r["message"])
        # also try zap if requested
        if remove_data:
            r2 = _run_brew(["uninstall", "--cask", "--zap", pkg], timeout=300)
            logs.append(r2["message"])
        return {
            "ok": r["ok"] or not _is_installed(app),
            "message": "\n".join(logs)[-2000:] or "已卸载",
            "kind": "native",
            "stack_id": app_id,
        }

    if method == "brew_formula":
        pkg = app["package"]
        if app.get("service"):
            r0 = _run([BREW, "services", "stop", pkg], timeout=120)
            logs.append(r0["message"])
        r = _run([BREW, "uninstall", pkg], timeout=300)
        logs.append(r["message"])
        return {
            "ok": r["ok"] or not _is_installed(app),
            "message": "\n".join(logs)[-2000:] or "已卸载",
            "kind": "native",
            "stack_id": app_id,
        }

    if method == "brew_multi":
        # No running `ok` accumulator here: it was `ok and (r["ok"] or True)`,
        # which is a no-op, and the return below ignored it anyway.  What the
        # operator asked for is "this app is gone", so that is what gets checked.
        for pkg in reversed(app.get("packages") or []):
            r = _run([BREW, "uninstall", pkg], timeout=300)
            logs.append(f"[{pkg}] {r['message']}")
        return {
            "ok": not _is_installed(app),
            "message": "\n".join(logs)[-2000:] or "已卸载",
            "kind": "native",
            "stack_id": app_id,
        }

    if method == "script" and app.get("script_id") == "filebrowser":
        _launchctl_unload("local.filebrowser")
        dest = SERVICES_ROOT / "filebrowser"
        if not dest.exists():
            return {"ok": True, "message": "未找到 ~/Services/filebrowser", "kind": "native", "stack_id": app_id}
        if remove_data:
            try:
                shutil.rmtree(dest)
                return {
                    "ok": True,
                    "message": f"已删除 {dest}",
                    "kind": "native",
                    "stack_id": app_id,
                }
            except Exception as e:
                return {"ok": False, "message": str(e), "kind": "native", "stack_id": app_id}
        return {
            "ok": True,
            "message": "已停止 FileBrowser。保留 ~/Services/filebrowser（删除数据请勾选「同时删除数据」）。",
            "kind": "native",
            "stack_id": app_id,
        }

    if method == "script" and app.get("script_id") == "homeassistant":
        label = app.get("launchd_label") or "com.homeassistant.core"
        _launchctl_unload(label)
        logs.append(f"stopped {label}")
        ha_dir = SERVICES_ROOT / "homeassistant"
        if remove_data and ha_dir.exists():
            try:
                # keep config backup safety: only remove if remove_data
                shutil.rmtree(ha_dir)
                logs.append(f"removed {ha_dir}")
            except Exception as e:
                return {"ok": False, "message": str(e), "kind": "native", "stack_id": app_id}
            # leave plist so reinstall can rewrite; or remove
            pl = Path.home() / "Library/LaunchAgents" / f"{label}.plist"
            if pl.exists():
                try:
                    pl.unlink()
                except OSError:
                    pass
            return {
                "ok": True,
                "message": "已停止并删除 Home Assistant 数据目录\n" + "\n".join(logs),
                "kind": "native",
                "stack_id": app_id,
            }
        return {
            "ok": True,
            "message": "已停止 Home Assistant（配置保留在 ~/Services/homeassistant）。删除数据请勾选「同时删除数据」。",
            "kind": "native",
            "stack_id": app_id,
        }

    raise HTTPException(400, f"unsupported uninstall method: {method}")
