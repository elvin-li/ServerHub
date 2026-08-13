#!/usr/bin/env python3
"""ServerHub 临时实例端到端冒烟测试(真实 HTTP 用户路径)。

用一个完全隔离的临时实例把面板真的跑起来,以真实 HTTP 会话从首启引导
(setup token)一路走到各功能闭环:登录/登出/改密、TOTP 2FA、API key、
member 账户、webhook 通知(本地接收器验证真实送达)、计划任务(run-now +
产物文件)、指标、应用目录、UPS、健康检查。

隔离方式(不改产品代码,全部走产品已有的注入点):
  * ``SERVERHUB_STATE_DIR``  → 临时目录,services.yaml 与 data/ 全部落在里面
                               (hub/paths.py 原生支持);
  * ``SERVERHUB_RUNTIME_DIR``→ 显式钉在仓库根(static/、templates/ 照常服务);
  * ``SERVERHUB_HOST=127.0.0.1`` + ``SERVERHUB_PORT=<18000-19000 空闲口>``;
  * 后台 ``python app.py``(与 launchd 生产入口一致),独立进程组,退出时
    对进程组 SIGTERM→SIGKILL;临时目录整树删除。
  * 生产实例(8086、仓库内 services.yaml / data/)绝不触碰。

运行方式(在仓库根):

    .venv/bin/python tests/e2e/smoke_serverhub.py            # 全量冒烟
    .venv/bin/python tests/e2e/smoke_serverhub.py --verbose  # 逐条断言输出
    .venv/bin/python tests/e2e/smoke_serverhub.py --keep     # 失败排查:保留临时目录
    .venv/bin/python tests/e2e/smoke_serverhub.py --list     # 列出场景

退出码 0 = 全部 PASS;非 0 = 有 FAIL(汇总表在 stdout)。
本文件刻意不叫 ``test_*.py``:它要起真服务、耗时约 1-2 分钟,不进
``python -m unittest discover -s tests -p 'test_*.py'`` 的默认收集。
异常退出(Ctrl-C / SIGTERM / SIGHUP)也会触发清理(signal + atexit)。
"""
from __future__ import annotations

import argparse
import atexit
import json
import os
import random
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))

# 纯标准库模块,无任何 hub.config / hub.paths 副作用(不会碰仓库 data/)。
from hub import totp  # noqa: E402

PROD_PORT = 8086  # 生产面板端口,绝不使用。
PORT_RANGE = (18000, 19000)
COOKIE = "serverhub_session"

VERBOSE = False


def log(msg: str) -> None:
    print(msg, flush=True)


def vlog(msg: str) -> None:
    if VERBOSE:
        print(f"    {msg}", flush=True)


# ── 清理登记:atexit + 信号,保证异常退出也回收进程/临时目录 ──────────────────

_CLEANUPS: list = []
_cleanup_done = False


def register_cleanup(fn) -> None:
    _CLEANUPS.append(fn)


def run_cleanups() -> None:
    global _cleanup_done
    if _cleanup_done:
        return
    _cleanup_done = True
    for fn in reversed(_CLEANUPS):
        try:
            fn()
        except Exception:
            pass


atexit.register(run_cleanups)
for _sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(_sig, lambda signum, frame: sys.exit(128 + signum))


# ── HTTP 客户端(标准库,手工 cookie jar,支持 Bearer 与 X-Forwarded-For)────

class Resp:
    def __init__(self, status: int, headers, text: str):
        self.status = status
        self.headers = headers
        self.text = text

    @property
    def json(self):
        try:
            return json.loads(self.text)
        except ValueError:
            return None

    def code(self) -> str:
        """API 错误码 detail.code(hub/errors.py 的机器可读契约)。"""
        j = self.json
        if isinstance(j, dict):
            detail = j.get("detail")
            if isinstance(detail, dict):
                return str(detail.get("code") or "")
        return ""


class Client:
    """一个"浏览器/脚本"身份:独立 cookie、可选 Bearer、独立限流桶。

    ``xff`` 会作为 X-Forwarded-For 发送。uvicorn 默认 proxy_headers=true
    且信任 loopback 直连,会把它改写进 request.client,于是每个场景拿到
    独立的登录限流桶,互不干扰。副作用:带 XFF 的请求不再被视为
    loopback,所以依赖 loopback 信任的流程(S0 引导)必须用无 XFF 客户端。
    """

    def __init__(self, base: str, xff: str | None = None):
        self.base = base.rstrip("/")
        self.cookies: dict[str, str] = {}
        self.xff = xff
        self.bearer: str | None = None

    def _absorb(self, headers) -> None:
        for raw in headers.get_all("Set-Cookie") or []:
            first = raw.split(";", 1)[0]
            name, _, value = first.partition("=")
            name, value = name.strip(), value.strip().strip('"')
            if not name:
                continue
            if value:
                self.cookies[name] = value
            else:
                self.cookies.pop(name, None)

    def request(self, method: str, path: str, body=None, headers=None,
                timeout: float = 30.0) -> Resp:
        url = self.base + path
        data = None
        hdrs = {"Accept": "application/json"}
        if self.xff:
            hdrs["X-Forwarded-For"] = self.xff
        if self.bearer:
            hdrs["Authorization"] = f"Bearer {self.bearer}"
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        if self.cookies:
            hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw, status, rh = r.read(), r.status, r.headers
        except urllib.error.HTTPError as e:
            raw, status, rh = e.read(), e.code, e.headers
        self._absorb(rh)
        return Resp(status, rh, raw.decode("utf-8", "replace"))

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, body=None, **kw):
        return self.request("POST", path, body=body, **kw)

    def put(self, path, body=None, **kw):
        return self.request("PUT", path, body=body, **kw)

    def delete(self, path, **kw):
        return self.request("DELETE", path, **kw)


# ── 临时实例生命周期 ──────────────────────────────────────────────────────────

def free_port() -> int:
    ports = list(range(*PORT_RANGE))
    random.shuffle(ports)
    for p in ports:
        if p == PROD_PORT:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", p))
            except OSError:
                continue
            return p
    raise RuntimeError(f"no free port in {PORT_RANGE}")


class Server:
    """后台 uvicorn(python app.py)+ 进程组级清理。"""

    def __init__(self, python: str, port: int, state_dir: Path, log_path: Path):
        assert port != PROD_PORT, "refusing to use the production port"
        tmp_root = Path(tempfile.gettempdir()).resolve()
        assert str(state_dir.resolve()).startswith(str(tmp_root)), \
            f"state dir {state_dir} is not under {tmp_root}; refusing to run"
        self.python = python
        self.port = port
        self.state_dir = state_dir
        self.log_path = log_path
        self.proc: subprocess.Popen | None = None

    def start(self) -> None:
        env = os.environ.copy()
        env.update({
            "SERVERHUB_RUNTIME_DIR": str(REPO),
            "SERVERHUB_STATE_DIR": str(self.state_dir),
            "SERVERHUB_HOST": "127.0.0.1",
            "SERVERHUB_PORT": str(self.port),
            "PYTHONUNBUFFERED": "1",
        })
        self._log_fh = self.log_path.open("wb")
        self.proc = subprocess.Popen(
            [self.python, "app.py"],
            cwd=str(REPO),
            env=env,
            stdout=self._log_fh,
            stderr=subprocess.STDOUT,
            start_new_session=True,  # 独立进程组:连同子进程一起杀干净
        )
        register_cleanup(self.stop)

    def log_tail(self, lines: int = 60) -> str:
        try:
            text = self.log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return "(no server log)"
        return "\n".join(text.splitlines()[-lines:])

    def wait_ready(self, timeout: float = 60.0) -> None:
        probe = Client(f"http://127.0.0.1:{self.port}")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc and self.proc.poll() is not None:
                raise RuntimeError(
                    f"server exited early (rc={self.proc.returncode})\n--- server log tail ---\n"
                    + self.log_tail()
                )
            try:
                r = probe.get("/api/health", timeout=3.0)
                if r.status == 200 and (r.json or {}).get("ok") is True:
                    return
            except OSError:
                pass
            time.sleep(0.25)
        raise RuntimeError(
            "server did not become ready in time\n--- server log tail ---\n" + self.log_tail()
        )

    def stop(self) -> None:
        proc, self.proc = self.proc, None
        if proc is None:
            return
        try:
            pgid = os.getpgid(proc.pid)
        except ProcessLookupError:
            return
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                break
            time.sleep(0.1)
        if proc.poll() is None:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=5)
        try:
            self._log_fh.close()
        except Exception:
            pass


# ── 本地一次性 webhook 接收器(验证通知真实送达)─────────────────────────────

class WebhookReceiver:
    def __init__(self):
        self.requests: list[dict] = []
        self._lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length)
                try:
                    payload = json.loads(raw.decode("utf-8"))
                except ValueError:
                    payload = None
                with outer._lock:
                    outer.requests.append({
                        "path": self.path,
                        "content_type": self.headers.get("Content-Type") or "",
                        "json": payload,
                    })
                body = b'{"ok": true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):  # 静音
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        register_cleanup(self.stop)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/hook"

    def wait_for(self, pred, timeout: float = 10.0) -> dict | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                for req in self.requests:
                    if pred(req):
                        return req
            time.sleep(0.1)
        return None

    def stop(self) -> None:
        try:
            self.server.shutdown()
            self.server.server_close()
        except Exception:
            pass


# ── TOTP 拨码器:单调递增计数器,避开服务端重放拒绝 ──────────────────────────

class TotpDialer:
    """服务端持久化"最后接受的计数器",同一计数器的码不能花两次。

    每次取 [now-1, now+1] 漂移窗内比上次严格更大的计数器;窗口内没有
    可用计数器时睡到下一个 30s 步进边界(整个流程最多等一次)。
    """

    def __init__(self, secret: str):
        self.key = totp.decode_secret(secret)
        self.last = -1

    def next_code(self) -> str:
        while True:
            counter = int(time.time()) // totp.STEP_SECONDS
            for cand in (counter - 1, counter, counter + 1):
                if cand > self.last:
                    self.last = cand
                    return totp.hotp(self.key, cand)
            time.sleep(totp.STEP_SECONDS - (time.time() % totp.STEP_SECONDS) + 0.5)

    def wrong_code(self) -> str:
        """一个当前窗口内保证无效的 6 位码(避免亿分之一的碰撞翻车)。"""
        counter = int(time.time()) // totp.STEP_SECONDS
        valid = {totp.hotp(self.key, c) for c in (counter - 1, counter, counter + 1)}
        for cand in ("000000", "111111", "222222", "333333"):
            if cand not in valid:
                return cand
        return "999999"


# ── 断言与场景框架 ────────────────────────────────────────────────────────────

class CheckFailure(AssertionError):
    pass


class Checker:
    def __init__(self):
        self.count = 0

    def that(self, cond, label: str, detail: str = "") -> None:
        self.count += 1
        if not cond:
            raise CheckFailure(f"{label}" + (f" | {detail}" if detail else ""))
        vlog(f"ok: {label}")

    def status(self, resp: Resp, expected: int, label: str) -> None:
        self.that(
            resp.status == expected,
            f"{label} -> HTTP {expected}",
            f"got {resp.status}: {resp.text[:300]}",
        )

    def error(self, resp: Resp, expected_status: int, expected_code: str, label: str) -> None:
        self.that(
            resp.status == expected_status and resp.code() == expected_code,
            f"{label} -> {expected_status} {expected_code}",
            f"got {resp.status} code={resp.code()!r}: {resp.text[:300]}",
        )


class Ctx:
    def __init__(self, server: Server, temp: Path):
        self.server = server
        self.base = f"http://127.0.0.1:{server.port}"
        self.temp = temp
        self.state_dir = server.state_dir
        self.artifacts = temp / "artifacts"
        self.artifacts.mkdir(exist_ok=True)
        self.admin_user = "smokeadmin"
        self.admin_password = "E2e-Adm1n-Original!"
        self.totp_dialer: TotpDialer | None = None
        self.receiver: WebhookReceiver | None = None

    def new_client(self, bucket: str) -> Client:
        return Client(self.base, xff=bucket)

    def admin_client(self, bucket: str) -> Client:
        """以当前管理员口令登录一个新"浏览器";2FA 开着时自动走第二步。"""
        c = self.new_client(bucket)
        r = c.post("/api/auth/login",
                   {"username": self.admin_user, "password": self.admin_password})
        j = r.json or {}
        if r.status == 200 and j.get("totp_required") and self.totp_dialer:
            r2 = c.post("/api/auth/totp/verify",
                        {"pending": j.get("pending") or "", "code": self.totp_dialer.next_code()})
            if not (r2.status == 200 and (r2.json or {}).get("ok")):
                raise RuntimeError(f"admin 2FA login failed: {r2.status} {r2.text[:200]}")
        elif not (r.status == 200 and j.get("ok")):
            raise RuntimeError(f"admin login failed: {r.status} {r.text[:200]}")
        return c


SCENARIOS: list[tuple[str, str, bool, object]] = []  # (id, 标题, critical, fn)


def scenario(sid: str, title: str, critical: bool = False):
    def wrap(fn):
        SCENARIOS.append((sid, title, critical, fn))
        return fn
    return wrap


# ── S0 首启引导(setup token 信任模型)───────────────────────────────────────

@scenario("S0", "首启引导:setup-token → 管理员会话", critical=True)
def s0_bootstrap(ctx: Ctx, check: Checker):
    # 不带 X-Forwarded-For:uvicorn 默认 proxy_headers=true 且信任 loopback,
    # 会把 XFF 改写进 request.client,而 setup-token 的信任模型恰恰以
    # "直连对端是不是 loopback" 为准。引导流程必须以真实 loopback 身份走。
    c = Client(ctx.base)

    r = c.get("/api/auth/status")
    check.status(r, 200, "GET /api/auth/status(未引导)")
    j = r.json
    check.that(j.get("setup_required") is True, "全新实例 setup_required=true", repr(j))
    check.that(j.get("authenticated") is False, "未认证", repr(j))
    check.that(j.get("setup_token_mode") == "auto", "setup_token_mode 默认 auto", repr(j))
    check.that(j.get("setup_token_required") is False, "loopback 引导不强制 token", repr(j))

    r = c.get("/api/status")
    check.error(r, 401, "auth.setup_required", "引导前受保护 API 全部关闭")

    r = c.get("/api/auth/setup-token")
    check.status(r, 200, "loopback 可读 setup token")
    token = (r.json or {}).get("setup_token") or ""
    check.that(len(token) >= 32, "token 是随机长串", repr(token[:8]))

    r = c.post("/api/auth/setup", {
        "username": ctx.admin_user, "password": ctx.admin_password,
        "setup_token": "wrong-token-on-purpose",
    })
    check.error(r, 403, "auth.bad_setup_token", "错误 token 被拒(即便 loopback 提供了就必须对)")

    r = c.post("/api/auth/setup", {
        "username": ctx.admin_user, "password": ctx.admin_password,
        "setup_token": token,
    })
    check.status(r, 200, "POST /api/auth/setup 领取实例")
    check.that((r.json or {}).get("ok") is True, "setup ok=true", r.text[:200])
    check.that(COOKIE in c.cookies, "setup 响应即发会话 cookie")

    token_file = ctx.state_dir / "data" / ".setup-token"
    check.that(not token_file.exists(), "setup token 文件被消费删除", str(token_file))

    r = c.get("/api/auth/setup-token")
    check.error(r, 409, "auth.already_setup", "领取后 token 端点关闭")
    r = c.post("/api/auth/setup", {"username": "x", "password": "y" * 12})
    check.error(r, 409, "auth.already_setup", "领取后 setup 端点关闭(原子首claim)")

    r = c.get("/api/auth/status")
    j = r.json
    check.that(j.get("authenticated") is True and j.get("username") == ctx.admin_user,
               "会话生效,身份正确", repr(j))
    check.that(j.get("role") == "admin" and j.get("can_manage") is True,
               "角色 admin / can_manage", repr(j))

    check.that((ctx.state_dir / "services.yaml").exists(),
               "隔离 services.yaml 落在临时 STATE_DIR")
    check.that(not (ctx.state_dir / "services.yaml").samefile(REPO / "services.yaml")
               if (REPO / "services.yaml").exists() else True,
               "与生产 services.yaml 不是同一文件")


# ── S1 健康与状态 ─────────────────────────────────────────────────────────────

@scenario("S1", "健康检查:/api/health 快速 200、/api/status 结构")
def s1_health(ctx: Ctx, check: Checker):
    anon = ctx.new_client("e2e-health")
    t0 = time.monotonic()
    r = anon.get("/api/health")
    dt = time.monotonic() - t0
    check.status(r, 200, "GET /api/health 匿名可达(liveness)")
    j = r.json
    check.that(j.get("ok") is True and isinstance(j.get("ts"), int),
               "health 形状 {ok, ts}", r.text[:120])
    check.that(set(j) == {"ok", "ts"}, "health 不泄露主机信息(仅 ok/ts)", repr(sorted(j)))
    check.that(dt < 2.0, f"health 快速返回({dt * 1000:.0f}ms < 2s)")

    r = anon.get("/api/status")
    check.error(r, 401, "auth.login_required", "匿名 /api/status 拒绝")

    c = ctx.admin_client("e2e-health")
    r = c.get("/api/status", timeout=90.0)
    check.status(r, 200, "GET /api/status(admin,首建快照)")
    j = r.json
    check.that(isinstance(j.get("groups"), list), "status.groups 是列表", str(type(j.get("groups"))))
    check.that(isinstance(j.get("counts"), dict), "status.counts 是字典")
    check.that("engine_up" in j, "docker 引擎状态字段存在(不可达时结构化降级而非 500)",
               repr(sorted(j))[:300])
    check.that(isinstance(j.get("ts"), str) and re.fullmatch(r"\d{2}:\d{2}:\d{2}", j["ts"]),
               "status.ts 是 HH:MM:SS 快照时间", repr(j.get("ts")))
    check.that(isinstance(j.get("service_total"), int) and isinstance(j.get("problems"), list),
               "status.service_total/problems 形状")


# ── S2 登录/登出/会话失效(改密后旧 cookie 失效)─────────────────────────────

@scenario("S2", "会话生命周期:登出撤销、改密踢会话")
def s2_sessions(ctx: Ctx, check: Checker):
    c1 = ctx.admin_client("e2e-sess")
    cookie_a = c1.cookies[COOKIE]

    r = c1.post("/api/auth/logout")
    check.status(r, 200, "POST /api/auth/logout")
    stale = ctx.new_client("e2e-sess")
    stale.cookies[COOKIE] = cookie_a
    r = stale.get("/api/auth/status")
    check.that((r.json or {}).get("authenticated") is False,
               "登出后旧 cookie 服务端已撤销(epoch bump)", r.text[:200])
    r = stale.get("/api/metrics")
    check.error(r, 401, "auth.login_required", "旧 cookie 打受保护 API 被拒")

    bad = ctx.new_client("e2e-sess-bad")
    r = bad.post("/api/auth/login", {"username": ctx.admin_user, "password": "wrong-password-1"})
    check.error(r, 401, "auth.bad_credentials", "错误口令登录被拒")
    r = bad.post("/api/auth/login", {"username": "no-such-user", "password": "wrong-password-1"})
    check.error(r, 401, "auth.bad_credentials", "未知用户名同样报 bad_credentials(不可枚举)")

    c2 = ctx.admin_client("e2e-sess")
    c3 = ctx.admin_client("e2e-sess")  # 第二个并行会话,用于验证改密踢人
    cookie_c3 = c3.cookies[COOKIE]

    old_password = ctx.admin_password
    new_password = "E2e-Adm1n-Rotated!!"
    r = c2.post("/api/auth/change-password", {
        "username": ctx.admin_user,
        "current_password": old_password,
        "new_password": new_password,
    })
    check.status(r, 200, "POST /api/auth/change-password")
    ctx.admin_password = new_password
    check.that((r.json or {}).get("ok") is True, "改密 ok", r.text[:200])

    r = c2.get("/api/auth/status")
    check.that((r.json or {}).get("authenticated") is True,
               "改密的这个浏览器拿到新 cookie 保持登录", r.text[:200])
    stale3 = ctx.new_client("e2e-sess")
    stale3.cookies[COOKIE] = cookie_c3
    r = stale3.get("/api/auth/status")
    check.that((r.json or {}).get("authenticated") is False,
               "改密后另一并行会话的旧 cookie 立即失效", r.text[:200])
    r = stale3.get("/api/metrics")
    check.error(r, 401, "auth.login_required", "旧 cookie 打 API 401")

    r = c2.post("/api/auth/change-password", {
        "username": ctx.admin_user,
        "current_password": new_password,
        "new_password": new_password,
    })
    check.error(r, 400, "auth.password_reused", "新旧口令相同被拒")
    r = c2.post("/api/auth/change-password", {
        "username": ctx.admin_user,
        "current_password": new_password,
        "new_password": "short",
    })
    check.that(r.status in (400, 422), "过短新口令被拒(400 策略 / 422 schema)",
               f"got {r.status}")

    bad2 = ctx.new_client("e2e-sess-bad2")
    r = bad2.post("/api/auth/login", {"username": ctx.admin_user, "password": old_password})
    check.error(r, 401, "auth.bad_credentials", "旧口令不能再登录")
    c4 = ctx.admin_client("e2e-sess")
    r = c4.get("/api/auth/status")
    check.that((r.json or {}).get("authenticated") is True, "新口令登录成功")


# ── S3 2FA 全流程 ────────────────────────────────────────────────────────────

@scenario("S3", "2FA:注册→确认→两步登录→恢复码→禁用")
def s3_twofa(ctx: Ctx, check: Checker):
    c = ctx.admin_client("e2e-2fa")

    r = c.get("/api/auth/totp")
    check.status(r, 200, "GET /api/auth/totp 初始状态")
    j = r.json
    check.that(j.get("enabled") is False and j.get("recovery_remaining") == 0,
               "初始未启用、无恢复码", r.text[:200])

    r = c.post("/api/auth/totp/enroll")
    check.status(r, 200, "POST /api/auth/totp/enroll")
    j = r.json
    secret = j.get("secret") or ""
    otpauth = j.get("otpauth_uri") or ""
    check.that(len(secret) == 32, "secret 是 32 字符 base32", repr(secret[:6]))
    parsed = urllib.parse.urlparse(otpauth)
    qs = urllib.parse.parse_qs(parsed.query)
    check.that(parsed.scheme == "otpauth" and parsed.netloc == "totp",
               "otpauth://totp/ URI", otpauth[:60])
    uri_secret = (qs.get("secret") or [""])[0]
    check.that(uri_secret == secret, "URI 解析出的 secret 与响应一致")
    check.that((qs.get("digits") or [""])[0] == "6" and (qs.get("period") or [""])[0] == "30"
               and (qs.get("algorithm") or [""])[0] == "SHA1",
               "标准参数 SHA1/6 位/30s", otpauth)
    check.that(ctx.admin_user in urllib.parse.unquote(parsed.path), "URI label 含账户名")

    dialer = TotpDialer(uri_secret)  # 以下所有码都从 URI 解析出的 secret 计算
    ctx.totp_dialer = dialer

    r = c.get("/api/auth/totp")
    check.that((r.json or {}).get("pending") is True, "注册后 pending=true(尚未强制)")

    r = c.post("/api/auth/totp/confirm", {"code": dialer.wrong_code()})
    check.error(r, 401, "auth.bad_totp", "错误确认码被拒(不激活)")

    r = c.post("/api/auth/totp/confirm", {"code": dialer.next_code()})
    check.status(r, 200, "确认码激活 2FA")
    codes = (r.json or {}).get("recovery_codes") or []
    check.that(len(codes) == 10, "返回 10 个恢复码", repr(codes))
    check.that(all(re.fullmatch(r"[A-Z0-9]{5}-[A-Z0-9]{5}", x) for x in codes),
               "恢复码格式 XXXXX-XXXXX", repr(codes[:2]))
    check.that((c.get("/api/auth/totp").json or {}).get("enabled") is True, "状态 enabled=true")
    r = c.get("/api/auth/status")
    check.that((r.json or {}).get("authenticated") is True,
               "确认响应携带的新 cookie 保持本浏览器登录(epoch bump 后重发)")

    r = c.post("/api/auth/logout")
    check.status(r, 200, "登出")

    two = ctx.new_client("e2e-2fa")
    r = two.post("/api/auth/login", {"username": ctx.admin_user, "password": ctx.admin_password})
    check.status(r, 200, "第一步:口令")
    j = r.json
    check.that(j.get("ok") is False and j.get("totp_required") is True and j.get("pending"),
               "返回 pending 票据而非会话", r.text[:200])
    pending = j["pending"]
    check.that(COOKIE not in two.cookies, "第一步不发会话 cookie")

    r = two.post("/api/auth/totp/verify", {"pending": "garbage-token", "code": "123456"})
    check.error(r, 401, "auth.totp_pending_invalid", "伪造 pending 被拒")
    r = two.post("/api/auth/totp/verify", {"pending": pending, "code": dialer.wrong_code()})
    check.error(r, 401, "auth.bad_totp", "错误 TOTP 码被拒")
    r = two.post("/api/auth/totp/verify", {"pending": pending, "code": dialer.next_code()})
    check.status(r, 200, "第二步:TOTP 码换会话")
    check.that((r.json or {}).get("ok") is True and COOKIE in two.cookies,
               "两步登录拿到会话", r.text[:200])

    r = two.post("/api/auth/logout")
    check.status(r, 200, "再登出")
    rec = ctx.new_client("e2e-2fa")
    r = rec.post("/api/auth/login", {"username": ctx.admin_user, "password": ctx.admin_password})
    pending2 = (r.json or {}).get("pending") or ""
    check.that(bool(pending2), "重新拿 pending")
    r = rec.post("/api/auth/totp/verify", {"pending": pending2, "code": codes[0]})
    check.status(r, 200, "恢复码完成登录(同一字段两用)")
    r = rec.get("/api/auth/totp")
    check.that((r.json or {}).get("recovery_remaining") == 9, "恢复码用后即焚,剩 9", r.text[:200])

    r = rec.post("/api/auth/logout")
    check.status(r, 200, "登出以测恢复码重放")
    rep = ctx.new_client("e2e-2fa")
    r = rep.post("/api/auth/login", {"username": ctx.admin_user, "password": ctx.admin_password})
    pending3 = (r.json or {}).get("pending") or ""
    r = rep.post("/api/auth/totp/verify", {"pending": pending3, "code": codes[0]})
    check.error(r, 401, "auth.bad_totp", "同一恢复码不能花第二次")
    r = rep.post("/api/auth/totp/verify", {"pending": pending3, "code": dialer.next_code()})
    check.status(r, 200, "TOTP 码重新登录")

    r = rep.post("/api/auth/totp/disable", {"code": dialer.wrong_code()})
    check.error(r, 401, "auth.bad_totp", "禁用必须出示有效码(防走开的浏览器)")
    r = rep.post("/api/auth/totp/disable", {"code": dialer.next_code()})
    check.status(r, 200, "有效码禁用 2FA")
    check.that((rep.get("/api/auth/totp").json or {}).get("enabled") is False, "已禁用")
    ctx.totp_dialer = None

    plain = ctx.new_client("e2e-2fa")
    r = plain.post("/api/auth/login", {"username": ctx.admin_user, "password": ctx.admin_password})
    check.that(r.status == 200 and (r.json or {}).get("ok") is True,
               "禁用后回到单步口令登录", r.text[:200])


# ── S4 API key ───────────────────────────────────────────────────────────────

@scenario("S4", "API key:创建→Bearer→浏览器边界→吊销即失效")
def s4_api_keys(ctx: Ctx, check: Checker):
    c = ctx.admin_client("e2e-key")

    r = c.get("/api/api-keys")
    check.status(r, 200, "GET /api/api-keys(admin 浏览器)")
    check.that(isinstance((r.json or {}).get("keys"), list), "keys 列表")

    r = c.post("/api/api-keys", {"name": "e2e-smoke", "role": "admin", "expires_days": 1})
    check.status(r, 200, "创建 admin key")
    j = r.json or {}
    plaintext = j.get("key") or ""
    record = j.get("record") or {}
    check.that(plaintext.startswith("shk_") and len(plaintext) > 20,
               "明文 key 形如 shk_…(只此一次)", plaintext[:8])
    kid = record.get("id") or ""
    check.that(bool(kid) and record.get("role") == "admin", "record 有 id/role", repr(record))

    bearer = ctx.new_client("e2e-key-bearer")
    bearer.bearer = plaintext
    r = bearer.get("/api/status")
    check.status(r, 200, "Bearer 打 /api/status 通过")
    r = bearer.get("/api/metrics")
    check.status(r, 200, "Bearer(admin)打 /api/metrics 通过")

    r = bearer.get("/api/api-keys")
    check.error(r, 401, "admin.browser_session_required",
                "key 管理端点拒绝任何 Bearer(凭证不能造凭证)")
    r = bearer.post("/api/auth/accounts", {"username": "x1", "password": "p" * 12})
    check.error(r, 401, "admin.browser_session_required", "账户管理拒绝 Bearer")
    r = bearer.post("/api/ups/shutdown/drill")
    check.error(r, 401, "admin.browser_session_required", "UPS 演练拒绝 Bearer(浏览器专属)")

    r = c.post("/api/api-keys", {"name": "e2e-member-key", "role": "member"})
    member_key = (r.json or {}).get("key") or ""
    member_kid = ((r.json or {}).get("record") or {}).get("id") or ""
    check.that(member_key.startswith("shk_"), "创建 member key")
    mb = ctx.new_client("e2e-key-member")
    mb.bearer = member_key
    r = mb.get("/api/status")
    check.status(r, 200, "member key 走只读白名单 /api/status")
    r = mb.get("/api/metrics")
    check.error(r, 403, "auth.admin_required", "member key 打非白名单端点 403")

    r = c.delete(f"/api/api-keys/{kid}")
    check.status(r, 200, "吊销 admin key")
    r = bearer.get("/api/status")
    check.error(r, 401, "auth.bad_api_key", "吊销后立即失效")
    r = c.delete(f"/api/api-keys/{kid}")
    check.error(r, 404, "apikeys.not_found", "重复吊销 404")

    fake = ctx.new_client("e2e-key-fake")
    fake.bearer = "shk_" + "x" * 43
    r = fake.get("/api/status")
    check.error(r, 401, "auth.bad_api_key", "伪造 key 结构化拒绝")

    r = c.delete(f"/api/api-keys/{member_kid}")
    check.status(r, 200, "清理 member key")


# ── S5 member 账户 ───────────────────────────────────────────────────────────

@scenario("S5", "member:创建→白名单/403 矩阵→自改密→删号踢会话")
def s5_member(ctx: Ctx, check: Checker):
    admin = ctx.admin_client("e2e-member-admin")
    muser, mpw1, mpw2, mpw3 = "e2e-member", "Member-Pass-01!", "Member-Pass-02!", "Member-Pass-03!"

    r = admin.post("/api/auth/accounts",
                   {"username": muser, "password": mpw1, "resources": ["e2e-svc"]})
    check.status(r, 200, "admin 创建 member(带资源)")
    acct = (r.json or {}).get("account") or {}
    check.that(acct.get("role") == "member" and acct.get("resources") == ["e2e-svc"],
               "账户角色/资源正确", repr(acct))
    r = admin.post("/api/auth/accounts", {"username": muser, "password": mpw1})
    check.error(r, 409, "accounts.exists", "重名创建 409")
    r = admin.get("/api/auth/accounts")
    names = {a.get("username"): a for a in (r.json or {}).get("accounts") or []}
    check.that(muser in names and ctx.admin_user in names, "账户列表含 admin 与 member")
    check.that("password_hash" not in json.dumps(r.json), "列表不泄露口令哈希")

    m = ctx.new_client("e2e-member")
    r = m.post("/api/auth/login", {"username": muser, "password": mpw1})
    check.status(r, 200, "member 登录")
    j = r.json or {}
    check.that(j.get("role") == "member" and j.get("can_manage") is False
               and j.get("resources") == ["e2e-svc"], "member 身份/资源", r.text[:200])

    for path in ("/api/health", "/api/status", "/api/services"):
        r = m.get(path, timeout=90.0)
        check.status(r, 200, f"member 白名单 GET {path}")
    r = m.get("/api/status")
    j = r.json or {}
    check.that(j.get("system") == {} and j.get("links") == [],
               "member 视图剔除主机指标与全局链接", r.text[:200])
    granted = {s.get("id") for g in j.get("groups") or [] for s in g.get("services") or []}
    check.that(granted <= {"e2e-svc"}, "服务列表只含授权资源", repr(granted))

    r = m.get("/api/services/e2e-svc/detail")
    check.that(r.status not in (401, 403), "授权资源 detail 不被权限拒绝", f"got {r.status}")
    r = m.get("/api/services/not-granted/detail")
    check.error(r, 403, "auth.admin_required", "未授权资源 detail 403")

    admin_only = [
        ("GET", "/api/metrics"), ("GET", "/api/scheduler/jobs"),
        ("GET", "/api/alerts/channels"), ("GET", "/api/catalog"),
        ("POST", "/api/alerts/test"),
        # /api/launcher left the member whitelist (admin install metadata).
        ("GET", "/api/launcher"),
    ]
    for method, path in admin_only:
        r = m.request(method, path, body={} if method == "POST" else None)
        check.error(r, 403, "auth.admin_required", f"member {method} {path}")
    r = m.get("/api/auth/accounts")
    check.error(r, 403, "admin.admin_required", "member 不能列账户")
    r = m.post("/api/api-keys", {"name": "nope", "role": "admin"})
    check.error(r, 403, "admin.admin_required", "member 不能造 API key")
    r = m.delete(f"/api/auth/accounts/{muser}")
    check.error(r, 403, "admin.admin_required", "member 不能删账户(含自己)")
    r = m.post("/api/scheduler/jobs", {"name": "x", "type": "command",
                                       "cron": "* * * * *", "params": {"command": "true"}})
    check.error(r, 403, "auth.admin_required", "member 不能建计划任务")

    r = admin.put(f"/api/auth/accounts/{muser}/resources", {"resources": ["e2e-svc", "second"]})
    check.status(r, 200, "admin 调整资源授权")
    r = m.get("/api/auth/status")
    check.that((r.json or {}).get("resources") == ["e2e-svc", "second"],
               "member 会话仍有效且看到新资源", r.text[:200])

    old_cookie = m.cookies[COOKIE]
    r = m.post("/api/auth/change-password",
               {"username": muser, "current_password": mpw1, "new_password": mpw2})
    check.status(r, 200, "member 自改密")
    stale = ctx.new_client("e2e-member")
    stale.cookies[COOKIE] = old_cookie
    check.that((stale.get("/api/auth/status").json or {}).get("authenticated") is False,
               "自改密后旧 cookie 失效")
    check.that((m.get("/api/auth/status").json or {}).get("authenticated") is True,
               "改密的浏览器自身保持登录")
    r = m.post("/api/auth/change-password",
               {"username": ctx.admin_user, "current_password": mpw2, "new_password": "Zz" * 8})
    check.error(r, 403, "auth.admin_required", "member 不能改别人(admin)的口令")

    r = admin.post(f"/api/auth/accounts/{muser}/password", {"new_password": mpw3})
    check.status(r, 200, "admin 无需旧口令重置 member 口令")
    check.that((m.get("/api/auth/status").json or {}).get("authenticated") is False,
               "重置后 member 现会话被踢")
    bad = ctx.new_client("e2e-member-bad")
    r = bad.post("/api/auth/login", {"username": muser, "password": mpw2})
    check.error(r, 401, "auth.bad_credentials", "旧口令失效")
    m2 = ctx.new_client("e2e-member")
    r = m2.post("/api/auth/login", {"username": muser, "password": mpw3})
    check.status(r, 200, "新口令登录")
    r = admin.post(f"/api/auth/accounts/{ctx.admin_user}/password", {"new_password": "Zz" * 8})
    check.error(r, 400, "accounts.not_member", "admin 账户不存在免密重置路径")

    r = admin.delete(f"/api/auth/accounts/{muser}")
    check.status(r, 200, "admin 删除 member")
    check.that((m2.get("/api/auth/status").json or {}).get("authenticated") is False,
               "删号后会话立即失效")
    r = m2.get("/api/status")
    check.error(r, 401, "auth.login_required", "删号后打 API 401")
    gone = ctx.new_client("e2e-member-bad")
    r = gone.post("/api/auth/login", {"username": muser, "password": mpw3})
    check.error(r, 401, "auth.bad_credentials", "删号后不能再登录")
    r = admin.get("/api/auth/accounts")
    check.that(muser not in {a.get("username") for a in (r.json or {}).get("accounts") or []},
               "账户列表已无该成员")


# ── S6 通知渠道(webhook → 本地接收器)───────────────────────────────────────

@scenario("S6", "通知:webhook 渠道→测试发送→接收器收到 payload")
def s6_notify(ctx: Ctx, check: Checker):
    receiver = ctx.receiver
    check.that(receiver is not None, "本地接收器已起")
    c = ctx.admin_client("e2e-notify")

    r = c.get("/api/alerts/channels")
    check.status(r, 200, "GET /api/alerts/channels")
    j = r.json or {}
    check.that(isinstance(j.get("channels"), list), "channels 列表")
    types = j.get("types") or {}
    check.that("webhook" in types and "url" in (types["webhook"].get("secrets") or []),
               "类型注册表含 webhook(url 是秘密字段)", repr(types.get("webhook")))

    r = c.post("/api/alerts/channels", {
        "id": "e2e-hook", "type": "webhook", "name": "E2E Hook",
        "enabled": True, "min_level": "info",
        "secrets": {"url": "file:///etc/passwd"},
    })
    check.error(r, 400, "notify.bad_url", "SSRF 守卫拒绝非 http(s) URL")
    r = c.post("/api/alerts/channels", {"id": "e2e-hook", "type": "webhook", "name": "E2E Hook"})
    check.error(r, 400, "notify.missing_field", "缺必填 secret(url)被拒")

    r = c.post("/api/alerts/channels", {
        "id": "e2e-hook", "type": "webhook", "name": "E2E Hook",
        "enabled": True, "min_level": "info",
        "secrets": {"url": receiver.url},
    })
    check.status(r, 200, "创建 webhook 渠道(指向本地接收器)")
    ch = (r.json or {}).get("channel") or {}
    check.that(ch.get("id") == "e2e-hook" and (ch.get("has") or {}).get("url") is True,
               "响应带 has.url=true", repr(ch))
    check.that(receiver.url not in r.text, "秘密 URL 不回显")

    r = c.post("/api/alerts/channels", {
        "id": "e2e-hook", "type": "webhook", "name": "dup", "secrets": {"url": receiver.url},
    })
    check.error(r, 409, "notify.exists", "重复 id 409")

    r = c.post("/api/alerts/channels/e2e-hook/test")
    check.status(r, 200, "POST …/test 发送测试")
    j = r.json or {}
    check.that(j.get("ok") is True and j.get("sent") == 1, "dispatch 报告送达 1 个渠道",
               r.text[:200])

    hit = receiver.wait_for(lambda q: isinstance(q.get("json"), dict)
                            and q["json"].get("event") == "test", timeout=10.0)
    check.that(hit is not None, "接收器真的收到了 test POST(10s 内)")
    payload = hit["json"]
    check.that({"title", "message", "text", "level", "event"} <= set(payload),
               "payload 形状 {title,message,text,level,event}", repr(payload))
    check.that(payload.get("title") == "ServerHub test", "title 是测试文案", repr(payload))
    check.that("application/json" in hit.get("content_type", ""), "Content-Type JSON")

    r = c.delete("/api/alerts/channels/e2e-hook")
    check.status(r, 200, "删除渠道")
    r = c.get("/api/alerts/channels")
    check.that("e2e-hook" not in {x.get("id") for x in (r.json or {}).get("channels") or []},
               "列表已无该渠道")
    r = c.post("/api/alerts/channels/e2e-hook/test")
    check.error(r, 404, "notify.not_found", "对已删渠道发测试 404")


# ── S7 计划任务 ──────────────────────────────────────────────────────────────

@scenario("S7", "计划任务:创建 cron 任务→run-now→历史→产物→删除")
def s7_scheduler(ctx: Ctx, check: Checker):
    c = ctx.admin_client("e2e-sched")

    r = c.get("/api/scheduler/jobs")
    check.status(r, 200, "GET /api/scheduler/jobs")
    j = r.json or {}
    check.that(set(j.get("types") or []) >= {"command", "rsync", "stack_backup", "snapshot"},
               "任务类型注册表", repr(j.get("types")))

    r = c.post("/api/scheduler/jobs", {"name": "bad", "type": "command",
                                       "cron": "not a cron", "params": {"command": "true"}})
    check.error(r, 400, "scheduler.bad_cron", "非法 cron 被拒")
    r = c.post("/api/scheduler/jobs", {"name": "bad", "type": "nope",
                                       "cron": "* * * * *", "params": {}})
    check.error(r, 400, "scheduler.bad_type", "非法类型被拒")

    nonce = f"e2e-ok-{uuid.uuid4().hex[:12]}"
    artifact = ctx.artifacts / "sched-echo.txt"
    r = c.post("/api/scheduler/jobs", {
        "id": "e2e-echo", "name": "E2E echo", "type": "command",
        "cron": "* * * * *", "enabled": True, "timeout": 60,
        "params": {"command": f"echo {nonce} > '{artifact}'"},
    })
    check.status(r, 200, "创建 * * * * * shell 任务")
    job = (r.json or {}).get("job") or {}
    check.that(job.get("id") == "e2e-echo" and isinstance(job.get("next_run"), int),
               "启用任务有 next_run", repr(job)[:200])

    r = c.post("/api/scheduler/jobs/no-such-job/run-now")
    check.error(r, 404, "scheduler.not_found", "run-now 未知任务 404")

    r = c.post("/api/scheduler/jobs/e2e-echo/run-now")
    check.status(r, 200, "run-now 触发")
    check.that((r.json or {}).get("ok") is True, "run-now ok", r.text[:200])

    run = None
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        rr = c.get("/api/scheduler/jobs/e2e-echo/runs")
        for rec in (rr.json or {}).get("runs") or []:
            if rec.get("trigger") == "manual":
                run = rec
                break
        if run:
            break
        time.sleep(0.5)
    check.that(run is not None, "30s 内执行历史出现 manual 记录")
    check.that(run.get("status") == "ok" and run.get("rc") == 0,
               "运行成功 status=ok rc=0", repr(run))
    check.that(isinstance(run.get("duration"), (int, float)) and run.get("job") == "e2e-echo",
               "记录形状(job/duration)", repr(run))

    check.that(artifact.exists(), "产物文件已写出", str(artifact))
    check.that(artifact.read_text().strip() == nonce, "产物内容匹配 nonce",
               artifact.read_text()[:80])

    r = c.get("/api/scheduler/runs")
    check.that(any(x.get("job") == "e2e-echo" for x in (r.json or {}).get("runs") or []),
               "全局 run 汇总含该任务")

    r = c.post("/api/scheduler/jobs/e2e-echo/enable", {"enabled": False})
    check.status(r, 200, "停用任务")
    check.that(((r.json or {}).get("job") or {}).get("next_run") is None, "停用后 next_run=null")

    r = c.delete("/api/scheduler/jobs/e2e-echo")
    check.status(r, 200, "删除任务")
    r = c.get("/api/scheduler/jobs")
    check.that("e2e-echo" not in {x.get("id") for x in (r.json or {}).get("jobs") or []},
               "列表已无该任务")
    r = c.delete("/api/scheduler/jobs/e2e-echo")
    check.error(r, 404, "scheduler.not_found", "重复删除 404")


# ── S8 指标 ──────────────────────────────────────────────────────────────────

@scenario("S8", "指标:/api/metrics 无参 vs range= 形状")
def s8_metrics(ctx: Ctx, check: Checker):
    c = ctx.admin_client("e2e-metrics")

    r = c.get("/api/metrics")
    check.status(r, 200, "GET /api/metrics(旧契约)")
    j = r.json or {}
    check.that(set(j) == {"points", "latest"},
               "无参响应恰好两键 {points, latest}(菜单栏兼容契约)", repr(sorted(j)))
    check.that(isinstance(j["points"], list), "points 是列表")
    if j["points"]:
        last = j["points"][-1]
        check.that(isinstance(last, dict) and isinstance(last.get("t"), int),
                   "样本点带 epoch 键 t", repr(last)[:200])
        check.that({"cpu_used_pct", "mem_used_pct", "disk_pct"} <= set(last),
                   "样本点含 cpu/mem/disk 指标", repr(sorted(last))[:200])
        check.that(j["latest"] == last, "latest 即最后一点")

    r = c.get("/api/metrics?range=48h")
    check.status(r, 200, "GET /api/metrics?range=48h(分层存储)")
    j = r.json or {}
    check.that({"points", "latest", "tier", "since", "until"} <= set(j),
               "range 响应含 tier/since/until", repr(sorted(j)))
    check.that(isinstance(j["tier"], str) and j["tier"], "tier 是层名", repr(j.get("tier")))
    span = int(j["until"]) - int(j["since"])
    check.that(abs(span - 48 * 3600) < 120, "窗口≈48h", f"span={span}")

    r = c.get("/api/metrics?range=30d")
    check.that(r.status == 200 and "tier" in (r.json or {}), "range=30d 同形状")
    r = c.get("/api/metrics?range=bogus")
    check.status(r, 400, "非法 range 400")
    now = int(time.time())
    r = c.get(f"/api/metrics?since={now - 3600}")
    check.that(r.status == 200 and "tier" in (r.json or {}), "since= 显式窗口同形状")
    r = c.get(f"/api/metrics?since={now}&until={now - 10}")
    check.status(r, 400, "until<=since 400")


# ── S9 应用目录 ──────────────────────────────────────────────────────────────

@scenario("S9", "目录:50 模板、compose_warnings/first_run_credentials 抽查")
def s9_catalog(ctx: Ctx, check: Checker):
    c = ctx.admin_client("e2e-catalog")

    r = c.get("/api/catalog/templates", timeout=60.0)
    check.status(r, 200, "GET /api/catalog/templates")
    templates = (r.json or {}).get("templates") or []
    check.that(len(templates) == 50, "内置模板恰 50 个", f"got {len(templates)}")

    for t in templates:
        tid = t.get("id")
        check.that(bool(tid) and isinstance(t.get("name"), str), f"模板 {tid!r} 有 id/name")
        check.that("compose_warnings" in t and isinstance(t["compose_warnings"], list),
                   f"{tid}: compose_warnings 字段是列表", repr(t.get("compose_warnings")))
        check.that("first_run_credentials" in t and isinstance(t["first_run_credentials"], str),
                   f"{tid}: first_run_credentials 字段是字符串")
        check.that(isinstance(t.get("ports"), list) and t.get("source") in ("builtin", "remote"),
                   f"{tid}: ports/source 形状")

    by_id = {t["id"]: t for t in templates}
    expected_creds = {
        "calibre-web": "admin / admin123",
        "mealie": "changeme@example.com / MyPassword",
        "nginx-proxy-manager": "admin@example.com / changeme",
    }
    for tid, cred in expected_creds.items():
        check.that(tid in by_id, f"存在模板 {tid}")
        check.that(by_id[tid]["first_run_credentials"] == cred,
                   f"{tid} 首登凭据元数据", repr(by_id[tid].get("first_run_credentials")))
    check.that(all(t["compose_warnings"] == [] for t in templates),
               "内置模板无 compose 警告(警告仅标远程模板)")

    r = c.get("/api/catalog", timeout=60.0)
    check.status(r, 200, "GET /api/catalog 总览")
    j = r.json or {}
    check.that("templates" in j and "categories" in j, "总览含 templates/categories",
               repr(sorted(j))[:200])


# ── S10 UPS ──────────────────────────────────────────────────────────────────

@scenario("S10", "UPS:状态形状、drill/plan 优雅降级、设置往返")
def s10_ups(ctx: Ctx, check: Checker):
    c = ctx.admin_client("e2e-ups")

    r = c.get("/api/ups", timeout=30.0)
    check.status(r, 200, "GET /api/ups")
    j = r.json or {}
    check.that({"present", "on_ac", "on_battery", "battery_percent",
                "settings", "shutdown_state"} <= set(j),
               "UPS 状态形状", repr(sorted(j)))
    check.that(isinstance(j["present"], bool), "present 是布尔(无 UPS 不是错误)")
    settings = j.get("settings") or {}
    check.that({"alerts_enabled", "low_battery_pct", "shutdown"} <= set(settings),
               "settings 形状", repr(sorted(settings)))
    shutdown = settings.get("shutdown") or {}
    check.that({"enabled", "trigger_pct", "trigger_remaining_min",
                "require_both", "stacks", "stop_scripts"} <= set(shutdown),
               "软着陆策略形状", repr(sorted(shutdown)))

    r = c.get("/api/ups/shutdown/plan")
    check.status(r, 200, "GET /api/ups/shutdown/plan")
    j = r.json or {}
    check.that(isinstance(j.get("would_trigger_now"), bool) and isinstance(j.get("steps"), list),
               "plan 形状 {would_trigger_now, steps}", repr(sorted(j))[:200])

    r = c.post("/api/ups/shutdown/drill")
    check.status(r, 200, "POST /api/ups/shutdown/drill(无 UPS 环境优雅响应)")
    j = r.json or {}
    check.that(isinstance(j.get("would_trigger_now"), bool) and isinstance(j.get("steps"), list),
               "drill 形状", repr(sorted(j))[:200])

    r = c.put("/api/ups/settings", {})
    check.error(r, 400, "ups.empty_patch", "空 patch 400")
    r = c.put("/api/ups/settings", {"low_battery_pct": 999})
    check.status(r, 422, "越界 low_battery_pct 由 schema 拒绝")
    r = c.put("/api/ups/settings",
              {"shutdown": {"enabled": True, "trigger_pct": None, "trigger_remaining_min": None}})
    check.error(r, 400, "ups.policy_no_condition", "无条件的启用策略被拒(永不触发的形状)")

    r = c.put("/api/ups/settings", {"low_battery_pct": 33})
    check.status(r, 200, "写入告警阈值(临时实例自己的 services.yaml)")
    r = c.get("/api/ups")
    check.that(((r.json or {}).get("settings") or {}).get("low_battery_pct") == 33,
               "阈值往返一致")


# ── 主流程 ───────────────────────────────────────────────────────────────────

def main() -> int:
    global VERBOSE
    parser = argparse.ArgumentParser(description="ServerHub e2e smoke (isolated temp instance)")
    parser.add_argument("--keep", action="store_true", help="保留临时目录(排障)")
    parser.add_argument("--verbose", action="store_true", help="打印每条断言")
    parser.add_argument("--list", action="store_true", help="仅列出场景")
    parser.add_argument("--port", type=int, default=0, help="指定端口(默认 18000-19000 探测)")
    args = parser.parse_args()
    VERBOSE = args.verbose

    if args.list:
        for sid, title, critical, _fn in SCENARIOS:
            log(f"{sid:>4}  {title}" + ("  [critical]" if critical else ""))
        return 0

    python = str(REPO / ".venv" / "bin" / "python")
    if not Path(python).exists():
        python = sys.executable

    port = args.port or free_port()
    if not (PORT_RANGE[0] <= port < PORT_RANGE[1]) or port == PROD_PORT:
        log(f"refusing port {port} (allowed {PORT_RANGE}, never {PROD_PORT})")
        return 2

    temp = Path(tempfile.mkdtemp(prefix="serverhub-e2e-"))
    state_dir = temp / "state"
    state_dir.mkdir()
    if not args.keep:
        register_cleanup(lambda: shutil.rmtree(temp, ignore_errors=True))

    log(f"[e2e] repo      : {REPO}")
    log(f"[e2e] python    : {python}")
    log(f"[e2e] temp      : {temp}")
    log(f"[e2e] instance  : http://127.0.0.1:{port}  (SERVERHUB_STATE_DIR={state_dir})")

    server = Server(python, port, state_dir, temp / "server.log")
    server.start()
    t0 = time.monotonic()
    server.wait_ready()
    log(f"[e2e] ready in {time.monotonic() - t0:.1f}s\n")

    ctx = Ctx(server, temp)
    ctx.receiver = WebhookReceiver()

    results: list[tuple[str, str, bool, int, str, float]] = []
    aborted = False
    for sid, title, critical, fn in SCENARIOS:
        if aborted:
            results.append((sid, title, False, 0, "skipped: critical scenario failed", 0.0))
            continue
        checker = Checker()
        start = time.monotonic()
        log(f"[{sid}] {title} ...")
        try:
            fn(ctx, checker)
        except CheckFailure as exc:
            dt = time.monotonic() - start
            results.append((sid, title, False, checker.count, str(exc), dt))
            log(f"[{sid}] FAIL after {checker.count} checks: {exc}\n")
            if critical:
                aborted = True
            continue
        except Exception:
            dt = time.monotonic() - start
            tb = traceback.format_exc(limit=6)
            results.append((sid, title, False, checker.count, tb, dt))
            log(f"[{sid}] ERROR:\n{tb}\n")
            if critical:
                aborted = True
            continue
        dt = time.monotonic() - start
        results.append((sid, title, True, checker.count, "", dt))
        log(f"[{sid}] PASS  ({checker.count} checks, {dt:.1f}s)\n")

    failed = [r for r in results if not r[2]]
    total_checks = sum(r[3] for r in results)
    log("=" * 72)
    log("ServerHub e2e smoke — 结果汇总")
    log("=" * 72)
    for sid, title, ok, count, detail, dt in results:
        mark = "PASS" if ok else "FAIL"
        log(f"  [{mark}] {sid:<4} {title}  ({count} checks, {dt:.1f}s)")
        if not ok:
            first = detail.strip().splitlines()
            if first:
                log(f"         ↳ {first[-1][:160]}")
    log("-" * 72)
    log(f"  scenarios: {len(results) - len(failed)}/{len(results)} passed"
        f"   assertions: {total_checks}")
    if failed:
        log("\n--- server log tail (排障) ---")
        log(server.log_tail(50))
        if args.keep:
            log(f"\n[e2e] temp dir kept: {temp}")
    log("=" * 72)

    server.stop()
    run_cleanups()
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
