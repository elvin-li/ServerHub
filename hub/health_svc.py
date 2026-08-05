"""Fix Common Problems style health checks (Unraid plugin inspiration)."""
from __future__ import annotations

import os
import shutil
import time

from hub.docker_cli import engine_up
from hub.nginx_svc import overview as nginx_overview, test_config as nginx_test
from hub.util import port_open, sh
from hub.brew_cache import brew_services_list
from pathlib import Path

_cache = {"t": 0.0, "v": None}
_TTL = 45.0


def _check(id_: str, name: str, level: str, ok: bool, detail: str, fix: str = "") -> dict:
    return {
        "id": id_,
        "name": name,
        "level": level if not ok else "ok",  # ok | warn | error
        "ok": ok,
        "detail": detail,
        "fix": fix,
    }


def run_checks(force: bool = False) -> dict:
    if not force and _cache["v"] and time.time() - _cache["t"] < _TTL:
        return _cache["v"]
    checks = []

    # Disk space root
    du = shutil.disk_usage("/")
    pct = du.used / du.total * 100
    checks.append(_check(
        "disk_root", "系统盘空间",
        "error" if pct >= 95 else "warn",
        pct < 90,
        f"已用 {pct:.0f}%（{du.used//2**30}/{du.total//2**30} GB）",
        "清理大文件/Docker 镜像，或扩容" if pct >= 90 else "",
    ))

    # OrbStack / docker
    eng = engine_up()
    checks.append(_check(
        "orbstack", "OrbStack / Docker 引擎",
        "error", eng,
        "引擎运行中" if eng else "引擎未运行",
        "在面板服务页启动 OrbStack，或 open -a OrbStack" if not eng else "",
    ))

    # nginx system
    try:
        ngx = nginx_overview()
        ok = bool(ngx.get("running"))
        checks.append(_check(
            "nginx", "系统 Nginx 网关",
            "error", ok,
            f"运行中 pid={ngx.get('pid')} · 站点 {ngx.get('site_count')}" if ok else "未运行",
            "launchctl kickstart -k gui/$(id -u)/local.system-nginx" if not ok else "",
        ))
        t = nginx_test()
        checks.append(_check(
            "nginx_conf", "Nginx 配置语法",
            "error", t.get("ok"),
            (t.get("message") or "")[:160],
            "检查 ~/Services/nginx/conf.d/" if not t.get("ok") else "",
        ))
    except Exception as e:
        checks.append(_check("nginx", "系统 Nginx", "error", False, str(e), "检查 LaunchAgent local.system-nginx"))

    # key ports
    for port, name, fix in (
        (8086, "ServerHub 面板 :8086", "launchctl kickstart local.serverhub.panel"),
        (8123, "Home Assistant :8123", "检查 com.homeassistant.core"),
        (8281, "Nginx HTTPS :8281", "检查系统 Nginx / 证书"),
    ):
        up = port_open(port)
        checks.append(_check(
            f"port_{port}", name,
            "warn", up,
            "端口可达" if up else "端口无响应",
            fix if not up else "",
        ))

    # brew critical
    brew_states = brew_services_list()
    if brew_states:
        try:
            for s in brew_states:
                n = s.get("name") or ""
                # postgresql@18 is a *separate* cluster (:5433) holding the
                # Immich database; @17 (:5432) holds TeslaMate.  Checking only
                # @17 reports "database fine" while Immich's DB is down.
                if n not in ("postgresql@17", "postgresql@18", "mosquitto", "grafana"):
                    continue
                st = (s.get("status") or "").lower()
                ok = st in ("started", "running")
                if not ok and st in ("none", ""):
                    # 未经 brew services 纳管但由 LaunchAgent 直接加载时 brew 显示 none，
                    # 需回查 launchctl 实际运行状态，避免误报
                    rc_l, out_l, _ = sh(["launchctl", "list", f"homebrew.mxcl.{n}"], timeout=3)
                    if rc_l == 0 and '"PID"' in out_l:
                        ok, st = True, "running (launchd)"
                checks.append(_check(
                    f"brew_{n}", f"Homebrew {n}",
                    "error" if n.startswith("postgres") else "warn",
                    ok,
                    st or "unknown",
                    f"brew services start {n}" if not ok else "",
                ))
        except Exception:
            pass

    # LaunchAgents with KeepAlive that are not running
    import glob, plistlib
    agents = Path.home() / "Library/LaunchAgents"
    _, lc, _ = sh(["launchctl", "list"], timeout=5)
    running_labels = set()
    for line in lc.splitlines():
        p = line.split("\t")
        if len(p) == 3 and p[0] not in ("-", ""):
            running_labels.add(p[2])
    for path in glob.glob(str(agents / "*.plist")):
        try:
            with open(path, "rb") as f:
                pl = plistlib.load(f)
        except Exception:
            continue
        label = pl.get("Label") or Path(path).stem
        if not pl.get("KeepAlive"):
            continue
        if pl.get("StartInterval") or pl.get("StartCalendarInterval"):
            continue
        ok = label in running_labels
        if not ok:
            checks.append(_check(
                f"la_{label}", f"KeepAlive 未运行: {label}",
                "warn", False,
                "LaunchAgent 已配置 KeepAlive 但未在运行",
                f"launchctl kickstart -k gui/$(id -u)/{label}",
            ))

    # SMART quick (cached style)
    rc, out, _ = sh(["sudo", "-n", "/opt/homebrew/bin/smartctl", "-H", "/dev/disk0"], timeout=10)
    if rc in (0, 4) and out:
        ok = "PASSED" in out.upper() or "OK" in out.upper()
        checks.append(_check(
            "smart_disk0", "系统盘 SMART",
            "error", ok,
            out.strip().splitlines()[-1][:120] if out.strip() else "unknown",
            "备份数据并检查磁盘" if not ok else "",
        ))

    # Time Machine / backup dir writable
    bdir = Path.home() / "Services" / "backups"
    try:
        bdir.mkdir(parents=True, exist_ok=True)
        ok = os.access(bdir, os.W_OK)
    except Exception:
        ok = False
    checks.append(_check(
        "backup_dir", "备份目录可写",
        "warn", ok,
        str(bdir),
        "检查 ~/Services/backups 权限" if not ok else "",
    ))

    # Immich hybrid stack (containers + native worker + native ML + PG18).
    # Kept in its own module because `docker ps` says nothing about the native
    # halves: the worker and ML service run outside Docker, and a green
    # immich_server tells you the web UI is up while thumbnails, transcode and
    # face recognition are all silently dead.
    try:
        from hub import immich_svc

        checks.extend(immich_svc.run_checks().get("checks") or [])
    except Exception as e:
        checks.append(_check(
            "immich", "Immich 混合栈检测", "warn", False, f"检测失败: {e}"[:160],
            "查看 hub/immich_svc.py",
        ))

    errors = sum(1 for c in checks if not c["ok"] and c["level"] == "error")
    warns = sum(1 for c in checks if not c["ok"] and c["level"] == "warn")
    oks = sum(1 for c in checks if c["ok"])
    v = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {"ok": oks, "warn": warns, "error": errors, "total": len(checks)},
        "checks": checks,
        "healthy": errors == 0,
    }
    _cache.update(t=time.time(), v=v)
    return v
