"""Immich hybrid-stack health checks.

Immich here is not a plain compose stack, so `docker ps` alone cannot tell you
whether it works.  The pieces that must all be alive:

  * container immich_server  — API only (web UI on :2283)
  * container immich_redis   — valkey, the BullMQ broker on 127.0.0.1:6379
  * native worker            — microservices/`dist/main.js`, does the actual
                               transcode + ML jobs.  Immich rewrites
                               process.title to "immich", so it can only be
                               located through its pidfile, never by pgrep on
                               the script path.
  * native ML service        — Swift/Metal CLIP + Vision on :3003
  * PostgreSQL 18            — 127.0.0.1:5433, separate cluster from PG17
                               (TeslaMate), so a PG17-only check says nothing
                               about Immich.
  * ffmpeg VideoToolbox shim — the wrapper that turns Immich's software encode
                               request into hevc_videotoolbox.

Everything below is read-only: sockets, HTTP GETs, pidfile stats.  No action is
taken and no secret is read (the DB password lives in the accelerator config and
is deliberately not touched — reachability is probed at the socket level).
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

from hub.docker_cli import engine_up
from hub.util import port_open, sh

_cache: dict = {"t": 0.0, "v": None}
_TTL = 30.0

BASE = Path.home() / "Services" / "immich"
ACCEL = Path.home() / ".immich-accelerator"
WORKER_PID = ACCEL / "pids" / "worker.pid"
#: Explicit quarantine marker written by ops/keepalive when the media volume
#: shows write faults; keep-immich-alive.sh refuses to start the worker while
#: it exists, so "worker stopped" has a different meaning in that state.
QUARANTINE = ACCEL / "worker.quarantine"
#: The wrapper is installed as plain `bin/ffmpeg` so it wins on PATH ahead of
#: the real binary; it is not named *-wrapper.sh on disk.
FFMPEG_SHIM = ACCEL / "bin" / "ffmpeg"

WEB_PORT = 2283
ML_PORT = 3003
REDIS_PORT = 6379
PG_PORT = 5433


def _check(id_: str, name: str, level: str, ok: bool, detail: str, fix: str = "") -> dict:
    return {
        "id": id_,
        "name": name,
        "level": "ok" if ok else level,
        "ok": ok,
        "detail": detail,
        "fix": "" if ok else fix,
    }


def _http(url: str, timeout: float = 3.0):
    """GET url, returning (status, body) or (None, error-string)."""
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:  # URLError, socket.timeout, ...
        return None, str(e)


def worker_pid() -> int | None:
    """Return the live native-worker pid, or None.

    The pidfile alone is not proof: after a crash the number can be recycled by
    an unrelated process.  Require that the pid exists *and* that its command is
    Immich's ("immich" after the process.title rewrite, or a node/main.js form if
    a future version stops renaming itself).
    """
    try:
        # Line 1 is the pid; start-worker-native.sh writes the process' `lstart`
        # on line 2 so a recycled pid can be told apart from the real worker.
        raw = WORKER_PID.read_text().splitlines()
        pid = int(raw[0].strip())
    except (OSError, ValueError, IndexError):
        return None
    if pid <= 1:
        return None
    rc, out, _ = sh(["/bin/ps", "-o", "lstart=,command=", "-p", str(pid)], timeout=4)
    if rc != 0 or not out.strip():
        return None
    line = out.strip()
    # `ps -o lstart=` prints a fixed-width 24-char date, then the command.
    started, cmd = line[:24].strip(), line[24:].strip()

    # Both conditions must hold; either one alone gives a false positive.
    #
    # Command alone: a loose substring test ("immich" in cmd) accepts any
    # unrelated process whose arguments merely mention an immich path, e.g.
    # `tail -f ~/Services/immich/logs/worker.log`.
    #
    # Start time alone: a recycled pid whose lstart happens to be written into a
    # stale pidfile would pass — which is exactly what a crash-then-reuse looks
    # like.  So require the command to be the worker as well.
    #
    # Immich rewrites process.title to "immich", so that is the expected value;
    # "dist/main.js" covers a future version that stops renaming itself.
    if cmd != "immich" and "dist/main.js" not in cmd:
        return None
    recorded = raw[1].strip() if len(raw) > 1 else ""
    if recorded and started and recorded != started:
        return None  # pid was recycled by a different process
    return pid


def _worker_uptime(pid: int) -> str:
    rc, out, _ = sh(["/bin/ps", "-o", "etime=", "-p", str(pid)], timeout=4)
    return out.strip() if rc == 0 else "?"


def _container_state(name: str) -> tuple[bool, str]:
    from hub.paths import DOCKER

    rc, out, _ = sh(
        [DOCKER, "ps", "-a", "--filter", f"name=^{name}$",
         "--format", "{{.State}}\t{{.Status}}"],
        timeout=8,
    )
    if rc != 0 or not out.strip():
        return False, "未找到容器"
    state, _, status = out.strip().partition("\t")
    return state == "running" and "unhealthy" not in status, status or state


def run_checks(force: bool = False) -> dict:
    if not force and _cache["v"] and time.time() - _cache["t"] < _TTL:
        return _cache["v"]

    checks: list[dict] = []

    # --- containers ---
    if engine_up():
        for cname, label in (("immich_server", "Immich Server 容器"),
                             ("immich_redis", "Immich Valkey 容器")):
            ok, detail = _container_state(cname)
            checks.append(_check(
                f"immich_ct_{cname}", label, "error", ok, detail,
                f"cd ~/Services/immich && docker compose up -d {cname}",
            ))
    else:
        checks.append(_check(
            "immich_engine", "容器引擎", "error", False, "OrbStack 未运行",
            "open -a OrbStack",
        ))

    # --- web UI ---
    status, body = _http(f"http://127.0.0.1:{WEB_PORT}/api/server/ping")
    pong = status == 200 and "pong" in body
    checks.append(_check(
        "immich_web", f"Immich Web/API :{WEB_PORT}", "error", pong,
        "ping 正常" if pong else f"无响应（{status or body[:60]}）",
        "docker compose restart immich-server",
    ))

    # --- native worker ---
    # Failure prose lives in errors.CODES + the SPA's err.* i18n keys (the
    # panel translates codes like api_error payloads); hub/ must not grow
    # hardcoded user-facing Chinese.
    pid = worker_pid()
    if pid:
        w_detail = f"pid={pid} 运行 {_worker_uptime(pid)}"
        w_fix = ""
    elif QUARANTINE.is_file():
        # Not a crash: keepalive deliberately keeps the worker stopped because
        # the media volume had write faults.  Say so, otherwise the panel
        # looks like it is reporting an ordinary failure that can simply be
        # restarted away.
        w_detail = "immich.worker_quarantined"
        w_fix = "immich.worker_lift_quarantine"
    else:
        w_detail = "immich.worker_down"
        w_fix = "~/Services/immich/start-worker-native.sh"
    checks.append(_check(
        "immich_worker", "原生 worker（转码/ML 队列）", "error", pid is not None,
        w_detail, w_fix,
    ))

    # --- native ML ---
    status, body = _http(f"http://127.0.0.1:{ML_PORT}/ping", timeout=3)
    ml_ok = status == 200
    checks.append(_check(
        "immich_ml", f"原生 ML 服务 :{ML_PORT}（CLIP/人脸/OCR）", "error", ml_ok,
        "ping 正常" if ml_ok else f"无响应（{status or body[:60]}）",
        "~/Services/immich/start-ml-native.sh",
    ))

    # --- valkey / queue broker ---
    redis_ok = bool(port_open(REDIS_PORT, "127.0.0.1"))
    checks.append(_check(
        "immich_redis_port", f"队列 Valkey :{REDIS_PORT}", "error", redis_ok,
        "端口可达" if redis_ok else "端口无响应，队列无法派发",
        "docker compose restart redis",
    ))

    # --- PostgreSQL 18 (Immich cluster, distinct from PG17/TeslaMate) ---
    pg_ok = bool(port_open(PG_PORT, "127.0.0.1"))
    checks.append(_check(
        "immich_pg18", f"PostgreSQL 18 :{PG_PORT}（Immich 库）", "error", pg_ok,
        "端口可达" if pg_ok else "端口无响应",
        "brew services start postgresql@18",
    ))

    # --- VideoToolbox ffmpeg shim ---
    shim_ok = FFMPEG_SHIM.is_file() and os.access(FFMPEG_SHIM, os.X_OK)
    checks.append(_check(
        "immich_ffmpeg_shim", "VideoToolbox ffmpeg 包装器", "warn", shim_ok,
        str(FFMPEG_SHIM) if shim_ok else "缺失或不可执行 —— 转码会退回 CPU 软编",
        "~/Services/immich/patch-ffmpeg-shim.sh",
    ))

    # --- ML URL contamination guard ---
    # Saving any setting makes the *container* broadcast ConfigUpdate carrying
    # its own IMMICH_MACHINE_LEARNING_URL (host.docker.internal), a name the host
    # cannot resolve; ml_url_shim.js rewrites it back to 127.0.0.1.  Without the
    # shim, CLIP/face/OCR fail silently after the next settings save.
    shim_js = BASE / "hooks" / "ml_url_shim.js"
    wired = False
    try:
        wired = "ml_url_shim" in (BASE / "start-worker-native.sh").read_text()
    except OSError:
        pass
    guard_ok = shim_js.is_file() and wired
    checks.append(_check(
        "immich_ml_url_shim", "ML 地址污染防护", "warn", guard_ok,
        "已加载（保存设置不会打断 ML）" if guard_ok
        else "未生效：保存任意设置后 ML 会静默失效",
        "确认 hooks/ml_url_shim.js 存在且已在 start-worker-native.sh 中 --require",
    ))

    # --- keepalive agent ---
    _, lc, _ = sh(["launchctl", "list"], timeout=5)
    ka = any(line.endswith("local.immich-keepalive") for line in lc.splitlines())
    checks.append(_check(
        "immich_keepalive", "worker 看护 LaunchAgent", "warn", ka,
        "已加载（每 120s 巡检）" if ka else "未加载，worker 崩溃后不会自动恢复",
        "launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/local.immich-keepalive.plist",
    ))

    errors = sum(1 for c in checks if not c["ok"] and c["level"] == "error")
    warns = sum(1 for c in checks if not c["ok"] and c["level"] == "warn")
    v = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "ok": sum(1 for c in checks if c["ok"]),
            "warn": warns,
            "error": errors,
            "total": len(checks),
        },
        "checks": checks,
        "healthy": errors == 0,
    }
    _cache.update(t=time.time(), v=v)
    return v


if __name__ == "__main__":
    print(json.dumps(run_checks(force=True), ensure_ascii=False, indent=2))
