# ServerHub v3.4

macOS 家庭服务器管理面板 — 对标 **Unraid** 信息架构，并吸收 **Dockge / Portainer / Glances / Glance / Heimdall / CasaOS / Homebrew** 等开源优秀能力。

**面板：** 默认仅本机 `http://localhost:8086`；远程访问请通过启用 TLS 与身份策略的 Cloudflare Tunnel/反向代理，勿直接暴露 8086。

## 模块地图（`/modules`）

| 类别 | 模块 | 灵感 |
|------|------|------|
| 系统 | 仪表盘、服务、**Brew**、传感器 | Unraid / Glances / Homebrew |
| 容器 | Docker 表、**Compose 编辑器**、应用目录 | dockerMan / **Dockge** / Portainer / CA |
| 存储 | 存储阵列、共享 | Unraid Main / OMV |
| 网络 | 接口 / 端口 / 路由 | Unraid Network |
| 应用 | **书签健康探测** | **Heimdall / Homarr / Glance** |
| 运维 | 日志、告警、备份、工具、维护 | Unraid Tools + Notifications |

## 本版亮点

### Compose（Dockge 风）
- 栈列表 + **YAML 在线编辑**
- `docker compose config` **校验**
- 保存自动 `.bak`
- 新建栈写入 `~/Services/<id>/`
- Up / Down / 更新任务日志

### Homebrew（macOS 特色）
- `brew services list --json`
- 启动 / 停止 / 重启 grafana、postgres、mosquitto 等

### 书签探测（Homarr 风）
- 对 `quick_links` + overrides URL 做 HTTP 探测
- 延迟 ms、401/403 视为在线、自签 HTTPS 兼容
- 仪表盘磁贴 + `/bookmarks` 页

### 传感器（Glances 风）
- CPU user/sys/idle、负载、内存、根盘
- `/api/system/sensors`

### 模块注册表
- `/api/modules` 可发现所有能力与灵感来源

## 技术

- FastAPI 包 `hub/` + Vue 3 (`web/` → `static/`)
- 容器引擎：**OrbStack**
- 菜单栏：原生 `macos/ServerHubLauncher.swift`；`menubar.py` 为旧版实现

## 原生 macOS 菜单栏

原生菜单栏 App 可安装到系统或当前用户的 Applications 目录。用户目录安装不需要覆盖 `/Applications`：

```bash
mkdir -p "$HOME/Applications"
./macos/build_app.sh "$HOME/Applications/ServerHub.app"
open "$HOME/Applications/ServerHub.app"
```

App 跟随 macOS 首选语言：中文语言环境显示简体中文菜单，其他语言环境显示英文。开发和快照测试可通过 `SERVERHUB_LANGUAGE=zh-Hans` 或 `SERVERHUB_LANGUAGE=en` 显式覆盖；空值会回退到系统语言。

面板的“设置 → 面板”页可查看 App、菜单栏进程、后台面板与登录自启状态，并可打开 App、切换登录自启、重启或停止面板。停止面板后，重新打开 `ServerHub.app` 即可恢复；状态读取失败时可使用卡片中的刷新按钮重试。

## 开发

以下命令均从仓库根目录 `~/Services/serverhub` 执行：

```bash
# 后端行为测试
.venv/bin/python -m unittest discover -s tests -p 'test_*.py'

# 前端测试、死代码检查和生产构建
npm --prefix web test
npm --prefix web run check:dead-code
npm --prefix web run build

# Python 未使用代码检查
.venv/bin/python -m pyflakes hub tests app.py menubar.py
.venv/bin/python -m vulture hub tests app.py menubar.py --min-confidence 100
```

生产构建输出到 `static/`。Vite 构建会校验首屏入口 JavaScript 不超过 150 KiB；英语词典作为同步回退，中、日文词典按当前语言异步加载。修改词典时须保持三种语言的键和占位符一致，`npm --prefix web test` 会验证该契约。

构建确认无误后，如需重启本机 LaunchAgent：

```bash
launchctl kickstart -k "gui/$(id -u)/local.serverhub.panel"
```

## 模板目录 `templates/`

uptime-kuma · portainer · navidrome · adguard-home · cloudflared · homarr · glance · dockge · filebrowser
