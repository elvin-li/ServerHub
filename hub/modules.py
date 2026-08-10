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
        name="仪表盘",
        description="系统磁贴、趋势、异常、端口与定时摘要",
        category="system",
        apis=["/api/status", "/api/metrics", "/api/health"],
        ui_routes=["/"],
    ),
    ModuleInfo(
        id="services",
        name="服务",
        description="launchd / 脚本 / App / OrbStack 引擎统一发现与启停",
        category="system",
        apis=["/api/status", "/api/action"],
        ui_routes=["/services"],
    ),
    ModuleInfo(
        id="brew",
        name="Homebrew 服务",
        description="brew services list/start/stop/restart",
        category="system",
        apis=["/api/brew/services", "/api/brew/services/{name}/action"],
        ui_routes=["/brew", "/tools"],
    ),
    ModuleInfo(
        id="docker",
        name="Docker / OrbStack",
        description="容器表、批量、更新检查、控制台、日志 SSE",
        category="docker",
        apis=["/api/containers", "/api/images", "/api/volumes", "/api/networks"],
        ui_routes=["/containers"],
    ),
    ModuleInfo(
        id="compose",
        name="Compose 栈",
        description="栈列表、YAML 编辑、校验、pull/up/down",
        category="docker",
        apis=["/api/stacks", "/api/compose/{stack_id}"],
        ui_routes=["/apps", "/compose"],
    ),
    ModuleInfo(
        id="catalog",
        name="应用目录",
        description="模板变量表单一键部署",
        category="apps",
        apis=["/api/catalog"],
        ui_routes=["/apps"],
    ),
    ModuleInfo(
        id="storage",
        name="存储阵列",
        description="多卷 + SMART 多盘 + 机械盘休眠/唤醒",
        category="storage",
        apis=["/api/storage", "/api/storage/disks", "/api/storage/disks/{id}/power"],
        ui_routes=["/main"],
    ),
    ModuleInfo(
        id="shares",
        name="共享",
        description="SMB + 文件服务状态",
        category="storage",
        apis=["/api/shares"],
        ui_routes=["/shares"],
    ),
    ModuleInfo(
        id="network",
        name="网络",
        description="接口 / LISTEN / 路由",
        category="network",
        apis=["/api/system/network"],
        ui_routes=["/network"],
    ),
    ModuleInfo(
        id="gateway",
        name="系统 Nginx 网关",
        description="全站反向代理 · conf.d 站点自动发现 · 重载",
        category="network",
        apis=["/api/nginx", "/api/nginx/reload"],
        ui_routes=["/gateway"],
    ),
    ModuleInfo(
        id="adaptive",
        name="自适应发现",
        description="LaunchAgent 端口推断、孤儿监听、Compose/站点扫描",
        category="system",
        apis=["/api/status", "/api/adaptive/compose-scan"],
        ui_routes=["/", "/services"],
    ),
    ModuleInfo(
        id="bookmarks",
        name="书签探测",
        description="快捷入口 HTTP 健康检查",
        category="apps",
        apis=["/api/bookmarks"],
        ui_routes=["/", "/bookmarks"],
    ),
    ModuleInfo(
        id="sensors",
        name="传感器",
        description="CPU 负载细节、内存、磁盘 I/O 采样",
        category="system",
        apis=["/api/system/sensors"],
        ui_routes=["/", "/tools"],
    ),
    ModuleInfo(
        id="logs",
        name="日志中心",
        description="多源 tail / 过滤 / 下载",
        category="ops",
        apis=["/api/logs"],
        ui_routes=["/logs"],
    ),
    ModuleInfo(
        id="alerts",
        name="告警",
        description="状态变化 + HA 通知",
        category="ops",
        apis=["/api/alerts"],
        ui_routes=["/alerts"],
    ),
    ModuleInfo(
        id="backups",
        name="备份",
        description="PG dump / 配置 tar",
        category="ops",
        apis=["/api/backups"],
        ui_routes=["/backups"],
    ),
    ModuleInfo(
        id="tools",
        name="工具",
        description="诊断、进程、Docker 占用、定时任务",
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
