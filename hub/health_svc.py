"""Fix Common Problems style health checks (Unraid plugin inspiration)."""
from __future__ import annotations

import os
import shutil
import time

from hub.docker_cli import engine_up
from hub.nginx_svc import overview as nginx_overview, test_config as nginx_test
from hub.paths import SMARTCTL
from hub.util import fan_out, port_open, sh
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


def _probe_port(port) -> bool | None:
    """Port reachability that never raises, for use inside the pool."""
    try:
        return port_open(port)
    except Exception:
        return False


#: Ports whose reachability is reported, in the order the page renders them.
_KEY_PORTS = (
    (8086, "ServerHub 面板 :8086", "launchctl kickstart local.serverhub.panel"),
    (8123, "Home Assistant :8123", "检查 com.homeassistant.core"),
    (8281, "Nginx HTTPS :8281", "检查系统 Nginx / 证书"),
)


def _engine_up() -> bool:
    try:
        return bool(engine_up())
    except Exception:
        return False


def _nginx_pair() -> list[dict]:
    """Both nginx checks -- or the single combined failure the page has always shown.

    One try/except spanning both calls is deliberate rather than sloppy: when nginx
    is not installed at all, `nginx_overview()` raises and the page shows one
    "系统 Nginx" error instead of that plus a second, redundant config-syntax
    failure. Returning the checks as a list preserves that all-or-one behaviour now
    that the pair runs inside a worker, where an escaping exception would cost the
    entire batch.
    """
    try:
        ngx = nginx_overview()
        ok = bool(ngx.get("running"))
        pair = [_check(
            "nginx", "系统 Nginx 网关",
            "error", ok,
            f"运行中 pid={ngx.get('pid')} · 站点 {ngx.get('site_count')}" if ok else "未运行",
            "launchctl kickstart -k gui/$(id -u)/local.system-nginx" if not ok else "",
        )]
        t = nginx_test()
        pair.append(_check(
            "nginx_conf", "Nginx 配置语法",
            "error", t.get("ok"),
            (t.get("message") or "")[:160],
            "检查 ~/Services/nginx/conf.d/" if not t.get("ok") else "",
        ))
        return pair
    except Exception as e:
        return [_check(
            "nginx", "系统 Nginx", "error", False, str(e),
            "检查 LaunchAgent local.system-nginx",
        )]


def _port_checks() -> list[dict]:
    """Reachability for every key port, probed together.

    Each connect waits out its full timeout when nothing is listening, so three
    dead ports charged the health page that wait three times in a row.
    """
    return [
        _check(
            f"port_{port}", name,
            "warn", up,
            "端口可达" if up else "端口无响应",
            fix if not up else "",
        )
        for (port, name, fix), up in zip(
            _KEY_PORTS, fan_out(_probe_port, [port for port, _, _ in _KEY_PORTS])
        )
    ]


def _running_labels() -> set[str]:
    """Labels with a live PID, from one `launchctl list` for the whole function.

    This replaced per-service `launchctl` probes in the brew loop below: a label with
    a PID in column one is running, which is exactly what those probes asked.
    """
    _, lc, _ = sh(["launchctl", "list"], timeout=5)
    labels = set()
    for line in lc.splitlines():
        p = line.split("\t")
        if len(p) == 3 and p[0] not in ("-", ""):
            labels.add(p[2])
    return labels


def _brew_snapshot() -> list:
    """brew service states, or an empty list.

    Failure is swallowed here rather than propagated because this now runs in a
    worker, where a raise would discard every other probe in the batch instead of
    just this one; the page then renders without the brew rows.
    """
    try:
        return brew_services_list() or []
    except Exception:
        return []


def _smart_checks() -> list[dict]:
    """System-disk SMART health, empty when smartctl is unavailable.

    SMARTCTL, not a literal /opt/homebrew path: the sudoers policy grants the
    root-owned copy under /usr/local/libexec/serverhub (Homebrew's prefix is
    writable by the panel's own account, so granting it would be passwordless
    root).  A hardcoded Homebrew path here matches no rule, so this probe would
    ask for a password nobody can type and the health card would go blank.
    """
    rc, out, _ = sh(["sudo", "-n", SMARTCTL, "-H", "/dev/disk0"], timeout=10)
    if rc in (0, 4) and out:
        ok = "PASSED" in out.upper() or "OK" in out.upper()
        return [_check(
            "smart_disk0", "系统盘 SMART",
            "error", ok,
            out.strip().splitlines()[-1][:120] if out.strip() else "unknown",
            "备份数据并检查磁盘" if not ok else "",
        )]
    return []


def _immich_checks() -> list[dict]:
    """Immich hybrid stack (containers + native worker + native ML + PG18).

    Kept in its own module because `docker ps` says nothing about the native
    halves: the worker and ML service run outside Docker, and a green
    immich_server tells you the web UI is up while thumbnails, transcode and
    face recognition are all silently dead.
    """
    try:
        from hub import immich_svc

        return list(immich_svc.run_checks().get("checks") or [])
    except Exception as e:
        return [_check(
            "immich", "Immich 混合栈检测", "warn", False, f"检测失败: {e}"[:160],
            "查看 hub/immich_svc.py",
        )]


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

    # Every remaining probe in one wave.
    #
    # These ask unrelated questions of unrelated subsystems -- the container engine,
    # nginx, three TCP ports, launchd, brew, smartctl and the Immich stack -- and none
    # of them reads another's answer, yet the page used to wait out their sum. The
    # slow ones are also the ones most likely to be slow together on a sick host,
    # which is exactly when this page gets opened.
    #
    # Order is restored below, not taken from completion: `fan_out` returns results in
    # submission order, and each probe returns its checks already assembled, so the
    # rendered sequence is identical to when this ran top to bottom.
    eng, nginx_checks, port_checks, running_labels, brew_states, smart, immich = fan_out(
        lambda probe: probe(),
        [
            _engine_up,
            _nginx_pair,
            _port_checks,
            _running_labels,
            _brew_snapshot,
            _smart_checks,
            _immich_checks,
        ],
        max_workers=7,
    )

    # OrbStack / docker
    checks.append(_check(
        "orbstack", "OrbStack / Docker 引擎",
        "error", eng,
        "引擎运行中" if eng else "引擎未运行",
        "在面板服务页启动 OrbStack，或 open -a OrbStack" if not eng else "",
    ))

    # nginx system
    checks.extend(nginx_checks)

    # key ports
    checks.extend(port_checks)

    # brew critical
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
                    # 需回查 launchctl 实际运行状态，避免误报。用上面那份全量列表，
                    # 不再为每个服务单独开一个子进程。
                    if f"homebrew.mxcl.{n}" in running_labels:
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

    # LaunchAgents with KeepAlive that are not running.
    # running_labels was built once at the top of this function.
    import glob, plistlib
    agents = Path.home() / "Library/LaunchAgents"
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

    # SMART quick (cached style) — probed in the wave above.
    checks.extend(smart)

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

    # Immich hybrid stack — probed in the wave above.
    checks.extend(immich)

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
