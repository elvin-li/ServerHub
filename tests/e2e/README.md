# tests/e2e — 临时实例端到端冒烟

`smoke_serverhub.py` 在**完全隔离的临时实例**上,用真实 HTTP 会话把
"首启引导 → 登录 → 各功能闭环"整条用户路径走一遍。它**不在**
`python -m unittest discover -s tests -p 'test_*.py'` 的默认收集里
(文件名刻意不带 `test_` 前缀,本目录也不是包):它要后台起一个真
uvicorn、耗时约 1–2 分钟,属于按需运行的冒烟层,而非单测基线。

## 运行

```bash
cd /path/to/serverhub
.venv/bin/python tests/e2e/smoke_serverhub.py            # 全量,PASS/FAIL 汇总
.venv/bin/python tests/e2e/smoke_serverhub.py --verbose  # 逐条断言
.venv/bin/python tests/e2e/smoke_serverhub.py --keep     # 失败时保留临时目录排障
.venv/bin/python tests/e2e/smoke_serverhub.py --list     # 列出场景
```

退出码 `0` = 全部通过。仅依赖仓库自带 venv(标准库 HTTP 客户端,无新增依赖)。

## 隔离与安全

- 状态隔离:`SERVERHUB_STATE_DIR` 指向 `mkdtemp` 临时目录(产品原生支持,
  见 `hub/paths.py`),临时实例的 `services.yaml`、`data/` 全部落在里面;
  `SERVERHUB_RUNTIME_DIR` 钉在仓库根,static/、templates/ 照常服务。
- 端口隔离:127.0.0.1 + 18000–19000 随机探测空闲端口;**绝不使用 8086**,
  生产面板与其 launchd 配置不受影响。
- 进程清理:实例跑在独立进程组,正常/异常退出(atexit + SIGINT/SIGTERM/SIGHUP)
  都会 SIGTERM→SIGKILL 整组并删除临时目录。

## 场景(每个都是真实 HTTP 调用 + 响应形状断言)

| # | 场景 |
|---|---|
| S0 | 首启引导:setup-token 信任模型(loopback 读 token → 领取 → token 消费、二次 setup 409) |
| S1 | `/api/health` 匿名快速 200;`/api/status` 鉴权与结构(docker 不可达时结构化降级) |
| S2 | 登录/登出(服务端撤销)/改密后旧 cookie 立即失效 |
| S3 | 2FA:注册→otpauth URI 解析 secret→`hub/totp.py` 算码确认→两步登录→恢复码(用后即焚)→禁用 |
| S4 | API key:创建→Bearer 打 `/api/status`→浏览器专属端点拒 Bearer→吊销立即失效;member key 白名单 |
| S5 | member:创建(带资源)→白名单可用/admin 端点 401/403 矩阵→自改密→admin 重置/删号踢会话 |
| S6 | 通知:webhook 渠道指向本地一次性接收器→测试发送→**断言接收器真收到 payload**→删除 |
| S7 | 计划任务:`* * * * *` shell 任务→run-now→轮询历史见成功→验证产物文件→删除 |
| S8 | 指标:`/api/metrics` 无参(旧契约恰 `{points,latest}`)vs `range=`(tier/since/until) |
| S9 | 目录:恰 50 个内置模板、每个都有 `compose_warnings` / `first_run_credentials`,凭据元数据抽查 |
| S10 | UPS:`GET /api/ups` 形状、shutdown plan/drill 无 UPS 优雅响应、设置校验与往返 |
