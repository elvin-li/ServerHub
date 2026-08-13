# ServerHub 对标 OpenMediaVault / Unraid 差距分析与扩展规划

> 调研日期:2026-08。对标版本:OpenMediaVault 7.x "Sandworm"(2024-03 发布,Debian 12;其后继 OMV 8 "Synchrony" 已于 2025-12-24 发布,基于 Debian 13,功能面与 OMV 7 基本一致,新增项已并入本文)与 Unraid 7.x(7.0 2025-01 → 7.1 2025-05 → 7.2 2025-10 → 7.3 2026 稳定版)。
> ServerHub 现状基于仓库实际代码盘点(README.md、`hub/routers/` 22 个路由模块共 242 个端点、`web/src/views/` 31 个视图、关键服务层源码),而非文档描述。
>
> 本文为纯调研与规划产物,不包含任何代码改动。

---

## 1. 对标对象功能基线(2026 年最新状态)

### 1.1 OpenMediaVault 7/8

- **存储**:smartmontools SMART 属性展示 + 计划自检 + 属性变化邮件告警;mdadm RAID(linear/0/1/10/5/6,web 内扩容/移除,降级邮件告警);LVM2(插件);文件系统格式化/挂载(ext4/Btrfs/XFS 等);磁盘配额(per-user);共享文件夹 + ACL(setfacl)+ 服务级 privileges;Btrfs 共享文件夹快照(手动 + 计划任务),自动 scrub 计划 + 邮件通知,快照通过 Samba 暴露为 Windows「以前的版本」(shadow copies)。
- **共享服务**:SMB/CIFS(Samba 全参数)、NFS、rsync(服务端 rsyncd 模块 + 计划 push/pull 客户端任务)、SSH、FTP/TFTP(插件)、avahi/mDNS 服务发现;OMV 8 新增 SMB 共享对 Time Machine 的报告容量限制。
- **计划任务**:cron 语法(不支持范围)、指定运行用户、输出邮件投递。
- **通知**:Postfix 邮件(monit 服务/文件系统/CPU/内存事件、计划任务输出、cron-apt、SMART、mdadm 降级),第三方渠道靠 `notification/sink.d` 脚本挂钩(社区借此接 Telegram/Pushover 等)。
- **监控**:collectd + RRD 长期性能图表、monit 服务监控、系统日志聚合(syslog/journal/samba/rsync 等)。
- **电源**:计划关机/休眠/挂起(S3/S5)、cpufreq 调度、UPS 由 NUT 插件支持。
- **用户**:用户/组管理、共享级 privileges(不触碰 Unix 权限)、ACL、锁定用户巡检邮件。
- **系统**:apt 更新管理 + 无人值守安全更新、SSL 证书管理(含到期巡检邮件)、仪表盘 widget(网络/系统/文件系统/服务,可由插件扩展)。
- **插件生态(OMV-Extras)**:ZFS、mergerfs、SnapRAID、Docker Compose、KVM、WireGuard、BorgBackup、rsnapshot、USB Backup(插盘即备份)、OneDrive 同步、Podman 应用(FileBrowser/PhotoPrism/MinIO S3/WeTTY 等)。

### 1.2 Unraid 7.x

- **存储**:Unraid 校验阵列(奇偶校验 + 计划校验)+ 原生 ZFS(RAIDZ、混合 vdev 子池、LUKS 加密、7.2 起 RAIDZ 扩容、7.3 ARC 调优/损坏文件列表)+ BTRFS/XFS 池;7.0 起阵列可选(全 SSD 场景);7.1 可导入 TrueNAS 池;7.2 增 ext2/3/4、NTFS、exFAT;mover 分层存储(池→阵列);磁盘休眠、SSD 寿命 SMART 属性、HDD/SSD/NVMe 分类温度阈值。
- **VM**:libvirt/QEMU 全功能——克隆、快照、用户模板、GPU/PCI 直通、SR-IOV、CPU pinning,7.3 QEMU 10.2/libvirt 12.2。
- **Docker**:dockerMan 模板化容器管理、自定义网络、PID 限制、7.3 固定 MAC、容器内 Tailscale 一键注入。
- **应用生态**:Community Applications 2000+ 容器/插件商店(分类、更新检查、支持链接)。
- **通知**:内置 agent——邮件、Pushover、Telegram、Discord、Slack,按事件等级逐 agent 路由;自定义 agent 脚本目录;社区 Apprise 插件覆盖 100+ 渠道;7.2 起有基于内建 API 的通知中心面板。
- **远程与网络**:WireGuard 内置、Tailscale 官方集成(webGUI 证书 + 容器注入)、Unraid Connect 云面板(多服务器、flash 备份、动态 UPnP 远程访问)、7.1 内置 WiFi。
- **用户与安全**:共享级 SMB 权限、7.2 OIDC/SSO 登录、内建 GraphQL API + API Key 管理、登录失败锁定倒计时。
- **UI**:7.0 集成文件管理器/全局设置搜索/收藏夹;7.2 全响应式移动端 WebGUI(社区 Flutter App 基于内建 API);仪表盘 tile 可折叠(Docker RAM/VM 用量等)。
- **UPS**:内置 apcupsd(容量手动覆盖),NUT 插件补充。
- **备份**:Connect flash 备份;appdata 备份靠事实标准插件(CA Appdata Backup);Parity Check Tuning 等运维插件。

---

## 2. ServerHub 现状盘点(基于代码核实)

导航六组:**Dashboard** ｜ **Storage**(Main/Pool/Files/Shares/Users)｜ **Apps & Services**(Services/Containers/Compose/VMs/Apps/Brew)｜ **Network**(Interfaces/Gateway/WireGuard/Bookmarks)｜ **Tools**(Diagnostics/Terminal/Health/Scheduler/Logs/Alerts/Audit/Backups/Maintenance/Modules)｜ **Settings**。

- **存储**(`storage.py`/`nas_storage.py`/`raid_svc.py`/`snapshots_svc`/`smart_test_svc.py`/`disk_power_svc.py`/`usage_svc`):diskutil 磁盘清单与管理(格式化/挂载/弹出)、磁盘休眠;SMART 属性读取 + 自检(short/long)+ 面板内调度(daily/weekly/biweekly,`settings.smart_schedule`)+ 历史;AppleRAID(mirror/stripe/concat 创建/删除/修复/成员增删,双重确认短语);APFS 本地快照(创建/删除/thin,基于 tmutil);本机 Time Machine 备份控制(start/stop/enable/disable);用量分析(目录树/最大文件/重复文件/Spotlight 开关)——这项超出 OMV/Unraid 内置能力。
- **共享**(`shares.py`/`shares_svc`/`nfs_svc.py`):SMB 共享 CRUD(guest/readonly/传输加密,走 macOS 原生 smbd + 管理员授权 sheet),系统共享服务开关;NFS 导出管理(整表写 `/etc/exports` + 预览 + nfsd 起停)。**无共享级用户权限、无 Time Machine 目标共享、无 rsync 服务**。
- **容器**(`containers.py`/`compose_svc`/`docker_cli`):OrbStack 引擎;容器全生命周期(批量操作/更新检查/exec/logs/inspect/重启策略/重命名)、镜像/卷/网络/prune、Compose 栈(Dockge 式编辑 + `docker compose config` 验证 + 自动 .bak)。
- **应用目录**(`catalog.py` + `templates/` 35 个模板):placeholder 自适应({{HOME}}/{{HOST_IP}}/{{TZ}}/{{OCR_LANG}} 等)、一键安装/卸载、凭据管理(`service_credentials.py`)、autostart 策略。**无远程/社区模板源**。
- **VM**(`vms_svc.py`/`vm_console.py`):UTM(utmctl)+ OrbStack Linux 机器,启停/创建/控制台会话。无快照/克隆/模板(UTM CLI 能力所限)。
- **网络**:接口/DHCP/DNS/别名/failover/WiFi 开关、Docker 端口映射管理;Gateway 探测页;WireGuard 全功能(peer 管理/批量/导入导出/PSK/pf 转发/自愈 remediate);Cloudflare Tunnel 全流程(login/create/route-dns/token 起停)。
- **告警**(`alerts.py`):后台线程(90s)—— 服务状态转变、CPU/内存/磁盘阈值(冷却 1800s)、SMART 健康(边沿触发 + 冷却 + 增长再触发,按序列号稳定去重);alerts.jsonl 保留 500 条。**通知渠道仅 Home Assistant**(webhook 或 token+service)。
- **计划任务**:`jobs.py` 仅执行 services.yaml `maintenance:` 里的一次性 shell 任务(手动触发、超时看门狗、单并发);`/api/scheduler` 只读展示 launchd timers。**无用户自定义 cron 调度**。
- **备份**(`backups.py`):Postgres dump + 配置归档(services.yaml 等),0600/0700 权限、O_EXCL 防覆盖、保留 14 份。**无 rsync/云备份/appdata 备份**。
- **指标**(`metrics.py`):90s 采样 → metrics.jsonl 环形缓冲 ≈48 小时(2880 点,SSD 友好批量写)。**无长期历史**。
- **用户与安全**(`auth.py`):表单登录 + 签名 Cookie;admin/member 两角色,member 按资源白名单(`allowed_resources`);安装 token 引导;认证/终端/共享变更审计(jsonl)。**无 2FA、无 SSO/OIDC、无正式 API Key 体系**(仅窄用途 local client token)。
- **其他**:容器+宿主机 WebSocket 终端(带审计)、健康检查页、诊断包下载、电源(关机/重启/WoL/屏幕共享开关)、i18n en/zh-CN/ja(键位对齐由测试强制)、暗色主题、导航全局搜索、部分响应式(styles.css 11 处 @media,未做系统性移动适配)。
- **架构资产**(规划新功能时优先复用):`hub/util.py` 的 `fan_out`(并发探测)/`ttl_memo`/`cached_snapshot`(TTL 快照缓存);告警管线(状态机 + 冷却 + jsonl);模板目录(front-matter + placeholder);`secure_io`(密文落盘);`services.yaml` 配置中心 + `data/` 运行时数据;审计管线。

---

## 3. 三方功能矩阵

图例:✅ 已有 ｜ 🟡 部分 ｜ ❌ 缺失 ｜ ➖ 平台不适用

### 3.1 存储管理

| 功能 | ServerHub (macOS) | OMV 7/8 | Unraid 7 |
|---|---|---|---|
| 磁盘清单/格式化/挂载 | ✅ diskutil | ✅ | ✅ |
| SMART 属性 + 告警 | ✅(USB/雷电桥接盘受 macOS 直通限制) | ✅ | ✅ |
| SMART 自检调度 | ✅ daily/weekly/biweekly | ✅ | ✅ |
| RAID | 🟡 AppleRAID mirror/stripe/concat(无 5/6/Z) | ✅ mdadm 六级 | ✅ 校验阵列+ZFS/BTRFS |
| 奇偶校验/scrub 计划 | ❌(APFS 无 scrub;可做计划 verifyVolume) | ✅ Btrfs scrub | ✅ parity check |
| 快照 | 🟡 APFS 快照手动(创建/删除/thin),无计划与保留策略 | ✅ Btrfs 手动+计划+shadow copies | ✅ ZFS 快照 |
| 池/多盘聚合 | 🟡 APFS 容器+AppleRAID | ✅ LVM/mergerfs/SnapRAID(插件) | ✅ ZFS/BTRFS 多池+mover 分层 |
| ZFS / mdadm / Btrfs | ➖ macOS 无商用可支持实现 | 🟡/✅ | ✅ |
| 磁盘休眠 | ✅ | ✅ | ✅ |
| 磁盘加密 | 🟡 APFS 加密卷(diskutil) | ✅ LUKS | ✅ LUKS |
| 磁盘配额(per-user) | ❌(macOS 配额支持名存实亡,近 ➖) | ✅ | 🟡 |
| 用量分析/重复文件 | ✅(超出两者内置) | 🟡 插件 | 🟡 插件 |
| 文件管理器 | ✅ Files + FileBrowser 集成 | 🟡 插件 | ✅ 7.0 内置 |

### 3.2 共享服务

| 功能 | ServerHub | OMV 7/8 | Unraid 7 |
|---|---|---|---|
| SMB | ✅ 原生 smbd(guest/只读/传输加密) | ✅ Samba 全参数 | ✅ |
| 共享级用户权限 | ❌ | ✅ privileges+ACL | ✅ |
| NFS | ✅ /etc/exports 管理+预览 | ✅ | ✅ v4.2 |
| rsync 服务端/计划任务 | ❌ | ✅ | 🟡 插件 |
| Time Machine 备份目标 | ❌(仅控制本机 TM) | ✅ Samba fruit(OMV8 加容量上限) | ✅ fruit |
| FTP / TFTP | ❌ | ✅ 插件 | ❌ |
| AFP | ➖(Apple 已弃用) | 🟡 弃用中 | ❌ |
| mDNS 服务发现 | 🟡 系统自动(面板无感知) | ✅ avahi | ✅ |
| Windows「以前的版本」 | ➖(macOS smbd 不支持 shadow copies) | ✅ Btrfs | ❌ |

### 3.3 容器 / VM / 应用生态

| 功能 | ServerHub | OMV 7/8 | Unraid 7 |
|---|---|---|---|
| 容器管理 | ✅ 全生命周期(OrbStack) | 🟡 Compose 插件 | ✅ dockerMan |
| Compose 栈编辑 | ✅ Dockge 式 | ✅ 插件 | 🟡 |
| 镜像/卷/网络/prune | ✅ | 🟡 | 🟡 |
| 容器更新检查 | ✅(+watchtower 模板) | 🟡 | ✅ |
| 一键应用目录 | 🟡 35 个本地模板 | 🟡 插件+Podman 应用 | ✅ CA 2000+ |
| 社区/远程模板源 | ❌ | 🟡 omv-extras | ✅ |
| 应用凭据管理 | ✅(独有) | ❌ | ❌ |
| VM | 🟡 UTM/OrbStack 启停/创建/控制台 | 🟡 KVM 插件 | ✅ 快照/克隆/模板/直通 |
| GPU/PCI 直通 | ➖ Apple 虚拟化不支持 | 🟡 | ✅ |

### 3.4 用户 / 权限 / 安全

| 功能 | ServerHub | OMV 7/8 | Unraid 7 |
|---|---|---|---|
| 多用户+角色 | ✅ admin/member+资源白名单 | ✅ 用户/组 | ✅ |
| 共享级权限矩阵 | ❌ | ✅ | ✅ |
| ACL | ❌(macOS `chmod +a` 可行但未做) | ✅ | 🟡 |
| 2FA(TOTP) | ❌ | ❌ | ❌ |
| SSO / OIDC | ❌ | ❌ | ✅ 7.2 |
| API Key / 自动化 API | 🟡 窄用途 local token | 🟡 RPC | ✅ GraphQL+API Key |
| 审计日志 | ✅ 认证/共享/终端(独有粒度) | 🟡 syslog | 🟡 |
| 登录防爆破 | 🟡 | 🟡 | ✅ 锁定倒计时 |

### 3.5 备份 / 通知 / 监控 / 调度

| 功能 | ServerHub | OMV 7/8 | Unraid 7 |
|---|---|---|---|
| 面板配置备份 | ✅ 归档+保留 14 份 | ✅ | ✅ Connect flash 备份 |
| 计划 rsync 推/拉 | ❌ | ✅ | 🟡 插件 |
| 云备份(borg/rclone/OneDrive) | 🟡 duplicati 模板 | ✅ 插件群 | 🟡 CA |
| appdata/栈备份 | ❌ | ➖ | ✅ 插件(事实标准) |
| USB 插盘即备份 | ❌ | ✅ 插件 | 🟡 |
| 整机备份 | ✅ Time Machine 控制(平台独有) | ➖ | ➖ |
| 告警引擎(去重/冷却) | ✅ | ✅ monit | ✅ |
| 邮件通知 | ❌ | ✅ | ✅ |
| 推送/IM 渠道 | ❌(仅 Home Assistant,独有但小众) | 🟡 sink 脚本 | ✅ 5 内置+Apprise |
| 按级别路由通知 | 🟡 include_warn/notify_resolve | 🟡 | ✅ per-agent per-level |
| 实时仪表盘 | ✅ | ✅ | ✅ |
| 长期历史图表 | 🟡 48h 环形缓冲 | ✅ collectd/RRD | 🟡 |
| UPS 监控+安全关机 | ❌ | ✅ NUT | ✅ apcupsd+NUT |
| 用户自定义 cron 任务 | ❌(仅手动 maintenance+launchd 只读) | ✅ | 🟡 User Scripts |
| 计划电源(关机/唤醒) | 🟡 | ✅ | ✅ |
| 系统更新管理 | 🟡 检查+brew 任务 | ✅ apt+无人值守 | ✅ |

### 3.6 网络 / 远程 / UI

| 功能 | ServerHub | OMV 7/8 | Unraid 7 |
|---|---|---|---|
| 接口/DNS/DHCP 管理 | ✅(含 alias/failover/WiFi) | ✅ | ✅ |
| WireGuard | ✅ 内置全功能 | 🟡 插件 | ✅ |
| Cloudflare Tunnel | ✅ 内置(独有) | ❌ | 🟡 CA |
| Tailscale | 🟡 可自装(无模板/集成) | 🟡 | ✅ 深度集成 |
| 云端多服务器管理 | ❌ | ❌ | ✅ Connect |
| 反代/证书管理 | 🟡 nginx 检测+NPM 模板 | ✅ 证书到期巡检 | 🟡 |
| 响应式移动端 | 🟡 少量断点 | 🟡 | ✅ 7.2 全响应+社区 App |
| 仪表盘定制 | ❌ 固定布局 | ✅ widget 可选 | 🟡 tile 折叠 |
| 多语言 | ✅ en/zh-CN/ja(键位测试强制) | ✅ | 🟡 |
| 全局搜索 / 暗色主题 | ✅ / ✅ | ✅ / ✅ | ✅ / ✅ |
| 终端(Web PTY) | ✅ 宿主+容器(带审计) | 🟡 WeTTY 插件 | ✅ |

**macOS 平台不适用项(明确不做)**:ZFS/mdadm/Btrfs 原生阵列与 scrub、Unraid 式奇偶校验阵列、LUKS、GPU/PCI 直通、Windows shadow copies(macOS smbd 无 VFS 模块机制)、AFP、per-user 磁盘配额(APFS 配额支持残缺)。对应的平台原生替代:AppleRAID + APFS 快照/加密卷 + Time Machine + `diskutil verifyVolume`。

---

## 4. Top 10 优先级差距清单

排序综合「海外商用用户价值 × macOS 可行性 × 现有架构复用度」。难度:低 ≈ 1 人周内,中 ≈ 2-4 人周,高 > 1 人月。

| # | 差距项 | 对标 | 商业价值 | 难度 | 涉及现有模块 |
|---|---|---|---|---|---|
| 1 | **多渠道通知中心**(SMTP 邮件、ntfy、Telegram、Discord/Slack、通用 Webhook;渠道×级别路由) | Unraid agents / OMV 邮件 | **高**——海外自托管用户第一预期;现状绑定 HA 等于强制前置依赖,商用不可接受 | 低-中 | `hub/alerts.py`(send_ha_notify 单点替换)、`settings_api.py`、`service_credentials.py`(密钥存储)、Settings.vue |
| 2 | **统一计划任务引擎**(cron 语法;任务类型:shell/维护任务/备份/快照/SMART/rsync) | OMV Scheduled Jobs / Unraid 各内置计划 | **高**——OMV 核心心智模型;是 #3/#5/#10 的地基 | 中 | `hub/jobs.py`(执行器复用)、`smart_test_svc.py`(现有调度线程收编)、Scheduler.vue(从只读升级)、services.yaml |
| 3 | **计划 rsync 备份**(push/pull、dry-run 预览、排除规则、SSH 目标) | OMV rsync 任务 | **高**——NAS 3-2-1 备份刚需;macOS 自带 rsync/openrsync,零新依赖 | 中 | `hub/backups.py`、新 `rsync_svc.py`、Backups.vue、依赖 #2 调度 |
| 4 | **Time Machine 备份目标共享**(把 ServerHub 主机变成全家 Mac 的 TM 服务器,含容量上限) | OMV/Unraid Samba fruit | **高**——macOS 平台独有差异化卖点:原生协议支持,比 Linux 对手的 Samba 模拟更可靠 | 低-中 | `shares_svc` + `macos_admin.py`(授权 sheet 复用)、Shares.vue |
| 5 | **Appdata/Compose 栈备份**(停栈→归档 bind+volume→重启,保留策略) | Unraid CA Appdata Backup | **高**——Unraid 迁移用户的硬需求;数据全在 `~/Services/<id>/`,天然可做 | 中 | `backups.py`(_prune/_private_dest 复用)、`compose_svc`、`containers_svc`、Backups.vue |
| 6 | **UPS 监控与安全关机**(USB UPS 状态、掉电告警、低电关机策略) | OMV NUT / Unraid apcupsd | 中-高——商用可靠性标配;macOS 原生识别 USB UPS(pmset),实现成本极低 | 低 | 新 `ups_svc.py`(`cached_snapshot`)、`alerts.py`(新检查项)、`power_svc`、Dashboard/Settings |
| 7 | **2FA(TOTP)+ API Key 体系** | Unraid 7.2 SSO/API Key | 高——商用安全底线;审计管线已就绪,只缺认证因子 | 低-中 | `hub/auth.py`、`auth_api.py`、Login.vue、Settings.vue |
| 8 | **长期指标历史与图表**(分层降采样保留 ≥1 年) | OMV collectd/RRD | 中——"我的服务器上周在干嘛"是常见诉求 | 低-中 | `hub/metrics.py`(环形缓冲加降采样层)、Dashboard.vue |
| 9 | **计划 APFS 快照 + 保留策略**(hourly/daily + 自动 thin) | OMV Btrfs 计划快照 | 中——把已有快照能力从"手动玩具"变成"数据保护" | 低(依赖 #2) | `snapshots_svc`、Scheduler、MainArray/Pool 视图 |
| 10 | **远程应用目录源**(签名的社区/官方模板仓库,面板内更新) | Unraid CA / omv-extras | 中——35 个内置模板 vs CA 2000+,生态差距只能靠可更新目录缩小 | 中 | `hub/catalog.py`(模板解析复用)、Apps.vue |

**次级清单**(有价值但不进 Top 10):全面移动端响应式改造(对标 Unraid 7.2,建议随 UI 迭代渐进);SMB 共享级用户权限矩阵(见 §5.4 第二期);USB 插盘即备份(diskarbitration 监听,依赖 #2/#3);Tailscale 官方模板与集成;计划电源(定时关机/唤醒,`pmset repeat`);`diskutil verifyVolume` 计划巡检(并入 #2 任务类型);mDNS 广播感知(`dns-sd` 只读展示)。

---

## 5. Top 5 实现设计

以下设计可直接派发实现。公共约定:配置进 `services.yaml`(经 `hub/config.py` 的 `cfg()/update_settings()`),密钥进 `data/service-credentials.json`(`service_credentials.py`,注意该文件当前有并发改动在途,合并时协调),运行时产物进 `data/`,新告警一律走 `alerts.py` 管线,写操作过 `audit.record`,三语 i18n 键同步(`web/src/i18n/{en,zh-CN,ja}.js`,测试强制对齐),后端测试放 `tests/test_*.py`(unittest,`.venv/bin/python -m unittest`)。

### 5.1 多渠道通知中心(#1)

**目标**:告警管线的出口从「仅 HA」变成可配置的多渠道,按级别路由,渠道可单独测试。

- **新文件 `hub/notify_channels.py`**:定义渠道接口 `send(title, message, *, level, kind) -> dict`(返回 `{ok, message}`,与现 `send_ha_notify` 返回形状一致)。实现六个渠道,全部标准库(`smtplib`/`urllib`),**零新依赖**:
  - `email`:SMTP(host/port/TLS 模式/用户名/收件人列表);
  - `ntfy`:POST 到 `{server}/{topic}`,Header 带 Title/Priority(level→priority 映射)/可选 Bearer;
  - `telegram`:`https://api.telegram.org/bot{token}/sendMessage`;
  - `discord` / `slack`:incoming webhook JSON;
  - `webhook`:现 `send_ha_notify` 的 webhook 分支泛化(沿用 `_http_url_ok` 的 SSRF scheme 校验);
  - `home_assistant`:现有逻辑原样迁入,保证升级无感。
- **`hub/alerts.py` 改造**:新增 `dispatch(title, message, *, level, kind)` 遍历启用渠道,替换全部 6 处 `send_ha_notify(...)` 调用点;现有 `include_warn`/`notify_resolve` 语义下沉为每渠道的 `min_level ∈ {info, warn, down}` 与 `notify_resolve: bool`。渠道发送失败仅记日志,不抛出(告警线程不可死,沿用现有 try/except 姿态)。`test_notify()` 扩展为按渠道测试。
- **配置**:`services.yaml → settings.notify.channels: [{id, type, enabled, min_level, notify_resolve, ...非密参数}]`;SMTP 密码、bot token 等以 `notify:{id}` 为键存 `service-credentials.json`。旧 `settings.notify.{enabled, ha_*}` 自动迁移为一条 `home_assistant` 渠道(读时兼容,写时升级)。
- **API**(`hub/routers/settings_api.py`):`GET/PUT /api/alerts/channels`(PUT 全量替换,admin);`POST /api/alerts/channels/{id}/test`;保留 `POST /api/alerts/test`(广播所有渠道)。
- **前端**:Settings.vue 通知卡片改为渠道列表(类型下拉 + 动态参数表单 + 级别选择 + 测试按钮);Alerts.vue 不变。
- **测试**:`tests/test_notify_channels.py` mock `urllib.request.urlopen`/`smtplib.SMTP`,覆盖级别过滤、旧配置迁移、渠道异常不影响 dispatch。

### 5.2 统一计划任务引擎(#2)

**目标**:OMV 式「计划任务」页——用户定义 cron 任务,类型化执行,失败进告警。

- **新文件 `hub/scheduler_svc.py`**:
  - 单守护线程 60s tick(与 `start_alerter` 同模式,在 `app_factory.py` 注册启动/关停);
  - 五段 cron 匹配器自实现(支持 `*`、数字、列表、`*/n`;不支持范围——与 OMV 网页同等级,约 80 行,免去新依赖);另支持简化 `interval: hourly|daily|weekly` 快捷写法;
  - 错过的窗口不补跑(记录 `missed`),与 OMV cron 语义一致并显式提示「@daily 关机则不跑」;
  - 任务注册表(type → runner):`command`(bash,复用 `jobs.py` 的看门狗执行器,改为按任务加锁而非全局单并发)、`maintenance`(引用现有 maintenance id)、`backup_pg`/`backup_cfg`(`backups.py`)、`snapshot`(`snapshots_svc.create_snapshot` + 可选 thin)、`smart_test`(收编 `smart_test_svc` 现有的私有调度线程,存量 `settings.smart_schedule` 迁移为一条任务)、`rsync`(§5.3)、`verify_volume`(`diskutil verifyVolume`)。
- **数据**:任务定义存 `services.yaml → schedules: [{id, name, type, cron, enabled, params, timeout}]`;运行历史追加 `data/schedule-runs.jsonl`(沿用 alerts.jsonl 的原子截断法,上限 1000);失败/超时 emit 告警(`kind: "schedule"`)→ 自动进 §5.1 的通知渠道。
- **API**(建议新文件 `hub/routers/scheduler_api.py`):`GET /api/scheduler/jobs`、`POST /api/scheduler/jobs`、`PUT/DELETE /api/scheduler/jobs/{id}`、`POST /api/scheduler/jobs/{id}/run-now`、`GET /api/scheduler/jobs/{id}/runs`。现有 `GET /api/scheduler`(launchd timers 只读)保留。
- **前端**:Scheduler.vue 升级为两个标签页——「面板任务」(CRUD + 立即运行 + 最近运行状态)与「系统任务」(现有 launchd 只读视图);导航位置不变(Tools 组)。
- **测试**:cron 匹配表驱动用例;runner 注册表 mock;`run-now` 与调度触发共用锁的互斥用例。

### 5.3 备份体系:计划 rsync + Appdata 栈备份(#3 + #5)

**目标**:补齐 3-2-1 备份的「复制到别处」与 Unraid 用户最想要的「应用数据备份」。

- **新文件 `hub/rsync_svc.py`**:
  - 任务模型 `{id, name, direction: push|pull, src, dest, delete: bool, compress: bool, exclude: [], bwlimit_kbps, ssh_identity}`;dest 支持本地路径(挂载的外置盘/SMB)与 `user@host:path`;
  - 二进制探测:优先 `/opt/homebrew/bin/rsync`(3.x),回退系统 `/usr/bin/rsync`(新 macOS 为 openrsync,注明 `--bwlimit` 等旗标差异,按探测结果裁剪参数);
  - `POST run` 前提供 `--dry-run --itemize-changes` 预览端点;执行日志流写 `data/backup-runs/<job>/<ts>.log`(目录 0700,复用 `secure_io.make_secret_dir`);退出码非零 → 告警管线;
  - 注册为 §5.2 的 `rsync` 任务类型即获得计划能力。
- **`hub/backups.py` 扩展 appdata 备份** `backup_stack(stack_id, stop_first=True)`:
  1. `compose_svc` 解析栈的 bind 挂载与 named volumes;
  2. `docker compose stop`(可选,默认停;记录原状态);
  3. bind 目录直接 `tar --zstd`;named volume 用 `docker run --rm -v vol:/src -v dest:/out alpine tar` 打包;
  4. `docker compose start` 恢复;产物 `~/Services/backups/appdata/<stack>/<ts>.tar.zst`,复用 `_private_dest`(O_EXCL 防覆盖)与 `_prune`(保留 14);
  5. 全过程单飞锁复用 `_only_one("appdata:"+stack)`;失败路径必须恢复容器(finally 内 start)。
- **API**(`settings_api.py` 或新 `backups_api.py`):`GET/POST/PUT/DELETE /api/backups/rsync`、`POST /api/backups/rsync/{id}/run`(`?dry_run=1`)、`GET /api/backups/rsync/{id}/log`;`POST /api/backups/appdata/{stack_id}`;`GET /api/backups` 返回值增加两类产物。
- **前端**:Backups.vue 增「同步任务」「应用数据」两个卡片区(现有截断测试 Backups.truncation.test.js 需同步);栈列表复用 Compose 页的数据源。
- **云备份定位**:v1 不内置 rclone——远端目标已可由 rsync-over-SSH 覆盖,对象存储场景引导用户装 duplicati 模板(已有);待需求验证后再评估 rclone 集成。

### 5.4 Time Machine 备份目标 + 共享权限(#4)

**目标**:Shares 页一个开关,把任意 SMB 共享变成全家 Mac 的 Time Machine 目的地。macOS 服务端原生支持(System Settings → File Sharing → 高级选项「Share as a Time Machine backup destination」+ 容量上限),不需要 Samba。

- **第一期(TM 开关 + 容量上限)**:
  - `shares_svc.create_smb_share/update_smb_share` 增 `time_machine: bool`、`tm_quota_gb: int|None`;
  - 实现:沿用现有共享写入路径(管理员授权 sheet,`macos_admin.py`),在 sharepoint 记录上设置 Time Machine 属性 —— 通过 `dscl .` 写 `/SharePoints/<name>` 的 `dsAttrTypeNative:timemachine = 1` 及配额属性后 `smbd` 重载;**实现首日任务**:在目标 macOS 版本上用 GUI 打开一次 TM 共享,`dscl . -read /SharePoints/<name>` 抄录确切属性名(timemachine / timeMachineBackupQuota 等随版本有差异),以实测为准;若属性写入在某版本失效,回退到已有的 `open_system_settings()` 深链引导;
  - `shares_overview()` 返回每个共享的 TM 状态与配额,同时给出「客户端如何连接」提示文案(Mac 上 系统设置 → Time Machine 添加,或 `sudo tmutil setdestination "smb://user@host/share"`);
  - Shares.vue 表单加开关与配额输入,共享卡片加 TM 徽标;
  - 联动:该共享目录建议落在 Files 页可见的卷上;告警管线可选新增「TM 卷剩余空间 < 阈值」检查(纳入 `_check_resource_thresholds` 同模式)。
- **第二期(共享级用户权限,可拆单独排期)**:
  - 面板管理 macOS **sharing-only 账户**(`dscl` 创建 `IsHidden=1` 的仅共享用户,不给 shell/Home),与 ServerHub member 账户一对一映射(存 `settings.accounts[].macos_user`);
  - Shares.vue/Users.vue 提供「共享 × 用户」读写矩阵,落地为目录属主/组 + `chmod +a "user allow/deny read,write..."` ACL 项;
  - 这是 OMV privileges 的 macOS 等价物;风险在于与用户手工在 System Settings 里的改动并存,面板须以读回状态为准而非缓存。
- **测试**:`tests/test_shares_timemachine.py` mock `sh`,断言 dscl/授权调用序列与降级路径。

### 5.5 UPS 监控与安全关机(#6)

**目标**:接 USB UPS 即在 Dashboard 出现电源卡片,掉电推送告警,低电按策略安全关机。

- **新文件 `hub/ups_svc.py`**:
  - 数据源:`pmset -g batt`(电源类型/百分比/剩余时间)+ `pmset -g ups`(系统关机阈值);`ioreg -r -c IOPowerSource... ` 兜底细节;包 `cached_snapshot(30.0)`,无 UPS 时返回 `{present: false}`;
  - 关机策略读写:`pmset -u haltlevel <pct> / haltafter <min> / haltremain <min>`(需管理员,复用 `macos_admin.py` 授权流);同时暴露「面板级软策略」——低于阈值时先 `dispatch` 告警并优雅停容器(`containers_svc` 批量 stop),把硬关机留给系统 pmset,双保险;
  - 高级用户装了 NUT(brew)时探测 `upsc` 并展示,只读即可。
- **告警**:`alerts.py` 新增 `_check_ups(prev, new_state, now)`:`onbattery`(level=down,即时)、`low_battery`(阈值)、`restored`(resolved);状态机/冷却与 `_check_smart_health` 同款,包 try/except 保线程。
- **API**:`GET /api/ups`、`PUT /api/ups/policy`(挂 `system_extra.py` 或新 `ups_api.py`);策略存 `settings.ups`。
- **前端**:Dashboard 增 UPS tile(`present` 才渲染);Settings.vue 电源卡片(现有 power 区旁)加阈值编辑。
- **测试**:pmset 输出的表驱动解析用例(市电/电池/无 UPS 三态)、告警转变用例。

---

## 6. 实施顺序建议

1. **第一批(通知即战力)**:#1 通知中心 → #6 UPS(小、独立、直接受益于 #1)。
2. **第二批(调度地基)**:#2 计划任务引擎 → #9 计划快照、`verify_volume` 巡检顺带落地。
3. **第三批(备份主线)**:#3 rsync + #5 appdata(共用 Backups 页改版)。
4. **第四批(平台卖点)**:#4 Time Machine 目标(一期),随后评估共享权限二期。
5. **持续**:#7 2FA/API Key、#8 长期指标、#10 远程目录、移动端响应式,按商用节奏穿插。

## 7. 主要参考

- OMV 7.x/8.x 官方文档(features / plugins / notifications / scheduled jobs / SMART / RAID / ACL 各章),OMV 8 "Synchrony" 发布公告(2025-12-24)。
- Unraid 官方 release notes:7.0.0(ZFS/阵列可选/VM/通知 agent/UPS)、7.1.0(WiFi/TrueNAS 池导入)、7.2.0(响应式 WebGUI/内建 GraphQL API/OIDC SSO/RAIDZ 扩容)、7.3.0(内部引导/TPM 授权/ZFS 调优);Unraid Connect 与 Community Applications 文档;通知 agent 与自定义 agent 脚本文档。
- Apple 官方指南:「在 Mac 上备份到共享文件夹(Time Machine)」;`tmutil`/`sharing`/`pmset` man page。
- ServerHub 仓库:README.md、`hub/`(alerts/jobs/backups/metrics/auth/shares_svc/nfs_svc/raid_svc/smart_test_svc/snapshots_svc/catalog 等)、`hub/routers/` 全部 22 个模块、`web/src/App.vue`(导航)、`web/src/views/`、`templates/`、`services.yaml`。
