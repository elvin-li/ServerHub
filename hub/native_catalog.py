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

import json
import os
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from fastapi import HTTPException

from hub.brew_cache import brew_services_list, invalidate_brew_services
from hub.host_address import host_ip
from hub.util import sh

SERVICES_ROOT = Path.home() / "Services"
BREW = "/opt/homebrew/bin/brew"
if not Path(BREW).is_file():
    BREW = "/usr/local/bin/brew"


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


def _brew_service_status(name: str) -> str | None:
    """Return started|stopped|none|None."""
    if not Path(BREW).is_file():
        return None
    rc, out, _ = sh([BREW, "services", "info", name, "--json"], timeout=15)
    if rc != 0 or not out.strip():
        return None
    try:
        data = json.loads(out)
        if isinstance(data, list) and data:
            data = data[0]
        st = (data.get("status") or "").lower()
        return st or "none"
    except Exception:
        return None


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
        "name": "WireGuard (native app)",
        "desc": "Official macOS WireGuard client · steadier than a Docker VPN",
        "category": "network",
        "tags": ["vpn", "wireguard", "native"],
        "featured": True,
        "method": "brew_cask",
        "package": "wireguard",
        "check": "app:WireGuard",
        "notes": "After installing, open WireGuard.app and import your config. Forward the UDP port on your router if you need inbound access.",
        "open": "WireGuard",
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
        "method": "brew_formula",
        "package": "duplicacy",
        "check": "bin:duplicacy",
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


_list_cache: dict = {"t": 0.0, "v": None}
_LIST_TTL = 30.0


def list_native_apps(force: bool = False) -> list[dict]:
    now = time.time()
    if not force and _list_cache["v"] is not None and now - _list_cache["t"] < _LIST_TTL:
        return _list_cache["v"]

    brew_inst = _brew_list_installed()
    # `brew services list --json` costs ~1.3s and four modules want it on the
    # same request.  Go through the shared cache rather than shelling out here:
    # this function is also called with force=True by catalog_overview(), and
    # `force` must not bypass the cache — it means "re-read the template dir",
    # not "make brew slow again".
    service_states: dict[str, str] = {}
    for s in brew_services_list():
        name = s.get("name") or ""
        if name:
            service_states[name] = (s.get("status") or "").lower()

    host = host_ip()

    items = []
    for app in NATIVE_APPS:
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
                label, app.get("process_match") or app.get("id") or ""
            )
        if running is None and app.get("id") == "native-filebrowser":
            running = _launchd_or_process_running("local.filebrowser", "filebrowser")
        # CLI tools with process_match but no brew service / launchd:
        # True only when a matching process is up; otherwise leave None ("已安装")
        # so unused CLIs don't show as "已停止".
        if running is None and app.get("process_match") and not app.get("service") and not label:
            if _process_running(str(app["process_match"])):
                running = True
        if running is None and app.get("open"):
            # cask apps: unknown process state unless we probe
            running = None

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
    _list_cache.update(t=time.time(), v=items)
    return items


def _process_running(process_substr: str) -> bool:
    """True if any process command line contains substr (best-effort)."""
    if not process_substr:
        return False
    rc, out, _ = sh(["/bin/ps", "aux"], timeout=5)
    if rc != 0 or not out:
        return False
    needle = process_substr.lower()
    for line in out.splitlines():
        # skip the ps header and this grep-like self if any
        low = line.lower()
        if needle in low and "ps aux" not in low:
            return True
    return False


def _launchd_or_process_running(label: str, process_substr: str) -> bool:
    if label:
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


def _run(cmd: list[str], timeout: int = 600, shell: bool = False) -> dict:
    try:
        p = subprocess.run(
            cmd if not shell else cmd[0] if len(cmd) == 1 else " ".join(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_brew_env(),
            shell=shell,
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


def _brew_shell_command(cmd: list[str]) -> str:
    """Single shell line for `do shell script` (admin prompt)."""
    env = (
        'export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:$PATH"; '
        "export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 HOMEBREW_NO_ENV_HINTS=1; "
    )
    return env + " ".join(shlex.quote(c) for c in cmd)


def _run_osascript_admin(shell_cmd: str, timeout: int = 900) -> dict:
    script = f"do shell script {json.dumps(shell_cmd)} with administrator privileges"
    return _run(["/usr/bin/osascript", "-e", script], timeout=timeout)


def _run_brew(
    brew_args: list[str],
    *,
    timeout: int = 900,
    admin_on_sudo_fail: bool = True,
) -> dict:
    """Run brew; on pkg/cask sudo failures, retry via macOS admin password dialog."""
    cmd = [BREW, *brew_args]
    r = _run(cmd, timeout=timeout)
    if r["ok"] or not admin_on_sudo_fail or not _needs_admin_retry(r.get("message") or ""):
        return r
    r_admin = _run_osascript_admin(_brew_shell_command(cmd), timeout=timeout)
    if r_admin["ok"]:
        return r_admin
    low = (r_admin.get("message") or "").lower()
    if "user canceled" in low or "canceled" in low or "-128" in (r_admin.get("message") or ""):
        r_admin["message"] = "已取消管理员授权（安装 pkg 类应用需要输入登录密码）。"
        return r_admin
    r_admin["message"] = (
        (r.get("message") or "")
        + "\n\n--- 已尝试管理员授权安装 ---\n"
        + (r_admin.get("message") or "")
    )[-4000:]
    return r_admin


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
    from hub.paths import AGENTS_DIR
    pl_path = Path(AGENTS_DIR) / f"{label}.plist"
    pl_path.parent.mkdir(parents=True, exist_ok=True)
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
    with open(pl_path, "wb") as f:
        plistlib.dump(pl, f)
    return pl_path


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


def install_native(app_id: str, variables: dict | None = None) -> dict:
    app = next((a for a in NATIVE_APPS if a["id"] == app_id), None)
    if not app:
        raise HTTPException(404, f"unknown native app: {app_id}")
    if not Path(BREW).is_file() and app.get("method", "").startswith("brew"):
        raise HTTPException(503, "未找到 Homebrew（/opt/homebrew/bin/brew）")

    # bust list cache after install attempts.  The shared brew snapshot has to
    # go too: installs run `brew services start`, and list_native_apps() reads
    # service state through brew_cache, so leaving that snapshot in place shows
    # the just-started service as stopped for up to its TTL.
    _list_cache["t"] = 0
    _list_cache["v"] = None
    invalidate_brew_services()
    try:
        from hub import apps_manage_svc
        apps_manage_svc._inv_cache["t"] = 0
        apps_manage_svc._inv_cache["v"] = None
    except Exception:
        pass

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
        ok = True
        for pkg in app.get("packages") or []:
            r = _run_brew(["install", pkg], timeout=600)
            logs.append(f"[{pkg}] {r['message']}")
            ok = ok and (_brew_install_ok(r["message"], r["rc"]) or True)
        ok = _is_installed(app) or ok
        return {
            "ok": ok,
            "message": "\n".join(logs)[-2000:],
            "kind": "native",
            "notes": app.get("notes") or "",
            "stack_id": app_id,
        }

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
            "-a", "0.0.0.0",
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

    # keep update script if missing
    upd = ha_dir / "update-homeassistant.sh"
    if not upd.exists():
        upd.write_text(
            "#!/bin/bash\n"
            "set -e\n"
            f'HA_DIR="{ha_dir}"\n'
            'cd "$HA_DIR"\n'
            "./venv/bin/pip install --upgrade homeassistant\n"
            f'launchctl kickstart -k "gui/$(id -u)/{label}"\n'
        )
        upd.chmod(0o755)

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

    _list_cache["t"] = 0
    _list_cache["v"] = None
    # Uninstall runs `brew services stop`; drop the shared snapshot so the next
    # read does not report the stopped service as still running.
    invalidate_brew_services()

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
        ok = True
        for pkg in reversed(app.get("packages") or []):
            r = _run([BREW, "uninstall", pkg], timeout=300)
            logs.append(f"[{pkg}] {r['message']}")
            ok = ok and (r["ok"] or True)  # partial ok if already gone
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
