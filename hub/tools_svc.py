"""Tools / diagnostics — Unraid Tools parity for macOS home server.

Useful Unraid Tools mapped here:
  System Information, Diagnostics, Syslog, Processes, Hardware Profile,
  About, Docker (df/prune), Scheduler, Update check, Network helpers.

Inspired by Cockpit (logs/services), OMV (SMART/updates), CasaOS (simple tiles).
"""
from __future__ import annotations

import os
import platform
import re
import shutil
import socket
import threading
import time
import glob
from pathlib import Path

from hub import __version__, metrics
from hub import cli_args
from hub.host_address import host_ip
from hub.docker_cli import docker, engine_up
from hub.paths import BASE, DOCKER, ORB
from hub.util import sh


# ─── Catalog (Unraid Tools home tiles) ───────────────────────────────────────

def tools_catalog() -> dict:
    """Tile map like Unraid /Tools — labels localized via label_key on the frontend."""
    tiles = [
        {"id": "sysinfo", "label_key": "tools.tile_sysinfo", "desc_key": "tools.tile_sysinfo_desc", "tab": "diag", "icon": "info"},
        {"id": "diagnostics", "label_key": "tools.tile_diagnostics", "desc_key": "tools.tile_diagnostics_desc", "tab": "diag", "action": "download_diag", "icon": "zip"},
        {"id": "syslog", "label_key": "tools.tile_syslog", "desc_key": "tools.tile_syslog_desc", "tab": "syslog", "icon": "log"},
        {"id": "processes", "label_key": "tools.tile_proc", "desc_key": "tools.tile_proc_desc", "tab": "proc", "icon": "cpu"},
        {"id": "hardware", "label_key": "tools.tile_hw", "desc_key": "tools.tile_hw_desc", "tab": "hw", "icon": "chip"},
        {"id": "docker", "label_key": "tools.tile_docker", "desc_key": "tools.tile_docker_desc", "tab": "docker", "icon": "docker"},
        {"id": "scheduler", "label_key": "tools.tile_sched", "desc_key": "tools.tile_sched_desc", "tab": "sched", "icon": "clock"},
        {"id": "updates", "label_key": "tools.tile_updates", "desc_key": "tools.tile_updates_desc", "tab": "updates", "icon": "update"},
        {"id": "network", "label_key": "tools.tile_net", "desc_key": "tools.tile_net_desc", "tab": "net", "icon": "net"},
        {"id": "fcp", "label_key": "tools.tile_health", "desc_key": "tools.tile_health_desc", "href": "/health", "icon": "shield"},
        {"id": "userscripts", "label_key": "tools.tile_maint", "desc_key": "tools.tile_maint_desc", "href": "/maintenance", "icon": "script"},
        {"id": "appstore", "label_key": "tools.tile_apps", "desc_key": "tools.tile_apps_desc", "href": "/apps", "icon": "apps"},
        {"id": "logs", "label_key": "tools.tile_logs", "desc_key": "tools.tile_logs_desc", "href": "/logs", "icon": "file"},
        {"id": "backups", "label_key": "tools.tile_backups", "desc_key": "tools.tile_backups_desc", "href": "/backups", "icon": "backup"},
        {"id": "alerts", "label_key": "tools.tile_alerts", "desc_key": "tools.tile_alerts_desc", "href": "/alerts", "icon": "bell"},
        {"id": "about", "label_key": "tools.tile_about", "desc_key": "tools.tile_about_desc", "tab": "about", "icon": "about"},
    ]
    return {
        "tiles": tiles,
        "hint_key": "tools.catalog_hint",
    }


# ─── Processes ───────────────────────────────────────────────────────────────

_proc_cache: dict = {"t": 0.0, "v": None, "limit": 0}
_PROC_TTL = 5.0


def top_processes(limit: int = 25) -> list:
    now = time.time()
    limit = max(5, min(int(limit or 25), 100))
    if (
        _proc_cache["v"] is not None
        and _proc_cache["limit"] >= limit
        and now - _proc_cache["t"] < _PROC_TTL
    ):
        return _proc_cache["v"][:limit]
    rc, out, _ = sh(["/bin/ps", "aux"], timeout=8)
    if rc != 0:
        return []
    lines = out.splitlines()
    if len(lines) < 2:
        return []
    rows = []
    for line in lines[1:]:
        parts = line.split(None, 10)
        if len(parts) < 11:
            continue
        try:
            cpu = float(parts[2])
            mem = float(parts[3])
        except ValueError:
            continue
        rows.append({
            "user": parts[0],
            "pid": parts[1],
            "cpu": cpu,
            "mem": mem,
            "vsz": parts[4],
            "rss": parts[5],
            "stat": parts[7],
            "time": parts[9],
            "command": parts[10][:160],
        })
    rows.sort(key=lambda r: (r["cpu"], r["mem"]), reverse=True)
    out = rows[:limit]
    _proc_cache.update(t=time.time(), v=out, limit=limit)
    return out


# ─── Docker ──────────────────────────────────────────────────────────────────

def docker_disk_usage() -> dict:
    if not engine_up():
        return {"engine_up": False, "raw": "", "lines": []}
    rc, out, err = docker("system", "df", timeout=30)
    lines = []
    for line in (out or "").splitlines():
        if not line.strip() or line.startswith("TYPE"):
            continue
        m = re.match(
            r"^(.+?)\s+(\d+)\s+(\d+)\s+(\S+)\s+(.+)$",
            line.strip(),
        )
        if m:
            lines.append({
                "type": m.group(1).strip(),
                "total": m.group(2),
                "active": m.group(3),
                "size": m.group(4),
                "reclaimable": m.group(5).strip(),
            })
    return {"engine_up": True, "raw": out or err, "lines": lines}


def container_sizes() -> list:
    if not engine_up():
        return []
    # -s/--size is what populates {{.Size}}.  OrbStack happens to fill it in
    # anyway, but stock Docker Engine leaves the column empty without it, so the
    # size table would render blank on any other host.  It costs nothing here
    # (measured: same 0.06s with and without on 4 containers).
    rc, out, _ = docker(
        "ps", "-a", "-s",
        "--format", "{{.Names}}\t{{.Size}}\t{{.Image}}\t{{.Status}}",
        timeout=60,
    )
    items = []
    if rc == 0:
        for line in out.splitlines():
            p = line.split("\t")
            if len(p) >= 2:
                items.append({
                    "name": p[0],
                    "size": p[1],
                    "image": p[2] if len(p) > 2 else "",
                    "status": p[3] if len(p) > 3 else "",
                })
    return items


def docker_prune(what: str = "dangling", confirm: bool = False) -> dict:
    """Safe-ish Docker cleanup. what: dangling | build | volumes | all_unused.

    Never force-removes running containers. Requires confirm=True.
    """
    if not confirm:
        return {"ok": False, "message": "需要 confirm=true"}
    if not engine_up():
        return {"ok": False, "message": "Docker 引擎未运行"}
    what = (what or "dangling").strip().lower()
    cmds = {
        "dangling": ["image", "prune", "-f"],
        "build": ["builder", "prune", "-f"],
        "volumes": ["volume", "prune", "-f"],
        "all_unused": ["system", "prune", "-f"],  # unused images/networks/stopped containers
    }
    if what not in cmds:
        return {
            "ok": False,
            "message": f"未知类型: {what}",
            "allowed": list(cmds.keys()),
        }
    rc, out, err = docker(*cmds[what], timeout=180)
    return {
        "ok": rc == 0,
        "what": what,
        "message": (out or err or "").strip()[:2000] or ("完成" if rc == 0 else "失败"),
        "df": docker_disk_usage() if rc == 0 else None,
    }


# ─── Diagnostics / system info ───────────────────────────────────────────────

def diagnostics() -> dict:
    load1, load5, load15 = os.getloadavg()
    rc, hostname, _ = sh(["/bin/hostname"], timeout=3)
    rc2, model, _ = sh(["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"], timeout=3)
    rc3, ncpu, _ = sh(["/usr/sbin/sysctl", "-n", "hw.ncpu"], timeout=3)
    rc4, memsize, _ = sh(["/usr/sbin/sysctl", "-n", "hw.memsize"], timeout=3)
    mem_gb = None
    if rc4 == 0 and memsize.isdigit():
        mem_gb = round(int(memsize) / 2**30, 1)
    eng = engine_up()
    df = docker_disk_usage() if eng else {}
    uptime_s = None
    try:
        # kern.boottime
        rc5, boot, _ = sh(["/usr/sbin/sysctl", "-n", "kern.boottime"], timeout=3)
        if rc5 == 0 and "sec =" in boot:
            m = re.search(r"sec\s*=\s*(\d+)", boot)
            if m:
                uptime_s = int(time.time()) - int(m.group(1))
    except Exception:
        pass
    du = shutil.disk_usage("/")
    return {
        "hostname": hostname if rc == 0 else platform.node(),
        "platform": platform.platform(),
        "arch": platform.machine(),
        "cpu": model if rc2 == 0 else "",
        "ncpu": int(ncpu) if rc3 == 0 and ncpu.isdigit() else None,
        "mem_gb": mem_gb,
        "load": [round(load1, 2), round(load5, 2), round(load15, 2)],
        "uptime_sec": uptime_s,
        "uptime_human": _fmt_uptime(uptime_s) if uptime_s else None,
        "root_disk_pct": round(du.used / du.total * 100, 1),
        "root_disk_free_gb": round(du.free / 2**30, 1),
        "orbstack": eng,
        "docker_cli": DOCKER,
        "orb_cli": ORB,
        "python": platform.python_version(),
        "host_ip": host_ip(),
        "docker_df": df,
        "metrics_points": len(metrics.history(60)),
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "version": __version__,
    }


def _fmt_uptime(sec: int | None) -> str:
    if not sec or sec < 0:
        return "—"
    d, r = divmod(int(sec), 86400)
    h, r = divmod(r, 3600)
    m, _ = divmod(r, 60)
    if d:
        return f"{d}d {h}h {m}m"
    if h:
        return f"{h}h {m}m"
    return f"{m}m"


# ─── Syslog (Unraid Syslog) ──────────────────────────────────────────────────

def syslog_tail(
    minutes: int = 60,
    limit: int = 80,
    level: str = "error",
) -> dict:
    """Recent unified log entries (macOS log show).

    level: error | fault | default (broader) | all
    """
    minutes = max(5, min(int(minutes or 60), 24 * 60))
    limit = max(10, min(int(limit or 80), 300))
    level = (level or "error").lower()
    # Prefer lightweight predicates
    if level == "error":
        predicate = 'eventType == "logEvent" AND messageType == "error"'
    elif level == "fault":
        predicate = 'eventType == "logEvent" AND messageType IN {"error","fault"}'
    elif level == "default":
        predicate = 'eventType == "logEvent" AND messageType IN {"error","fault","default"}'
    else:
        predicate = 'eventType == "logEvent"'

    # log show can be slow; keep last short and timeout tight
    cmd = [
        "/usr/bin/log", "show",
        "--last", f"{minutes}m",
        "--predicate", predicate,
        "--style", "compact",
    ]
    if level == "all":
        cmd.append("--info")
    rc, out, err = sh(cmd, timeout=25)

    lines = []
    if rc == 0 and out:
        raw_lines = [ln for ln in out.splitlines() if ln.strip()]
        raw_lines = [ln for ln in raw_lines if not ln.startswith("Timestamp")]
        lines = raw_lines[-limit:]
    elif rc != 0:
        syslog_path = Path("/var/log/system.log")
        if syslog_path.exists():
            try:
                raw = syslog_path.read_text(errors="replace").splitlines()
                lines = raw[-limit:]
                err = "fallback:/var/log/system.log"
                rc = 0
            except OSError as e:
                err = str(e)

    return {
        "ok": rc == 0,
        "minutes": minutes,
        "level": level,
        "count": len(lines),
        "lines": lines,
        "message": (err or "")[:300] if rc != 0 else "",
        "hint": "macOS 统一日志",
    }


# ─── Hardware Profile ────────────────────────────────────────────────────────

_hw_cache: dict = {"t": 0.0, "v": None}
_HW_TTL = 300.0  # system_profiler is heavy
_updates_cache: dict = {"t": 0.0, "v": None}
_UPDATES_TTL = 600.0  # softwareupdate is very expensive

#: Held only across a refresh, never across a cache read.  Separate locks so a
#: slow `softwareupdate -l` cannot block a hardware-profile request.
_hw_refresh_lock = threading.Lock()
_updates_refresh_lock = threading.Lock()


def _hw_fresh() -> dict | None:
    v = _hw_cache["v"]
    if v is not None and time.time() - _hw_cache["t"] < _HW_TTL:
        return v
    return None


def hardware_profile(force: bool = False) -> dict:
    """Unraid Hardware Profile — system_profiler subsets (cached 5 min).

    Single-flight: four ``system_profiler`` subsets at up to 12s each is far too
    expensive to run once per concurrent caller.  Waiters re-check the cache
    after acquiring the lock, so the second arrival returns the first one's
    result instead of paying again.  ``force`` skips the fast path but still
    joins the refresh, so a page full of parallel widgets cannot stampede.
    """
    if not force:
        hit = _hw_fresh()
        if hit is not None:
            return hit
    with _hw_refresh_lock:
        hit = _hw_fresh()
        if hit is not None:
            return hit
        return _hardware_profile_uncached()


def _hardware_profile_uncached() -> dict:
    sections = {}
    # Keep only quick types — skip network/displays by default (slow & rarely needed)
    types = [
        ("hardware", "SPHardwareDataType"),
        ("memory", "SPMemoryDataType"),
        ("storage", "SPStorageDataType"),
        ("power", "SPPowerDataType"),
    ]
    for key, dt in types:
        rc, out, err = sh(
            ["/usr/sbin/system_profiler", dt, "-detailLevel", "mini"],
            timeout=12,
        )
        text = (out or err or "").strip()
        if len(text) > 4000:
            text = text[:4000] + "\n…(truncated)"
        sections[key] = {
            "ok": rc == 0,
            "data_type": dt,
            "text": text,
        }
    disks = []
    try:
        from hub import disk_power_svc
        for d in disk_power_svc.list_power_disks()[:12]:
            disks.append({
                "id": d.get("id"),
                "name": d.get("name"),
                "size_gb": d.get("size_gb"),
                "ssd": d.get("ssd"),
                "power_state": d.get("power_state"),
                "system": d.get("system"),
            })
    except Exception:
        pass
    v = {
        "sections": sections,
        "disks": disks,
        "ts": time.strftime("%H:%M:%S"),
        "hint": "硬件信息缓存 5 分钟",
        "cached": True,
    }
    _hw_cache.update(t=time.time(), v=v)
    return v


# ─── Updates ─────────────────────────────────────────────────────────────────

def _updates_fresh() -> dict | None:
    v = _updates_cache["v"]
    if v is not None and time.time() - _updates_cache["t"] < _UPDATES_TTL:
        return v
    return None


def check_updates(force: bool = False) -> dict:
    """Lightweight update overview (cached 10 min — softwareupdate is expensive).

    Single-flight, same reasoning as ``hardware_profile``: ``brew outdated`` plus
    ``softwareupdate -l`` is up to 90s of subprocess time, and the Tools page can
    ask for it from several widgets at once.
    """
    if not force:
        hit = _updates_fresh()
        if hit is not None:
            return hit
    with _updates_refresh_lock:
        hit = _updates_fresh()
        if hit is not None:
            return hit
        return _check_updates_uncached()


def _check_updates_uncached() -> dict:
    result = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "brew": {"ok": False, "outdated": [], "count": 0, "raw": ""},
        "macos": {"ok": False, "lines": [], "raw": ""},
        "hint": "仅检查不安装 · 安装请到「维护」页 · 结果缓存 10 分钟",
        "cached_ttl": _UPDATES_TTL,
    }
    brew = shutil.which("brew") or "/opt/homebrew/bin/brew"
    if Path(brew).exists():
        rc, out, err = sh([brew, "outdated", "--verbose"], timeout=45)
        lines = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
        result["brew"] = {
            "ok": rc == 0,
            "outdated": lines[:40],
            "count": len(lines),
            "raw": (err or "")[:200] if rc != 0 else "",
        }
    # softwareupdate -l is slow; run with shorter timeout and accept partial
    rc2, out2, err2 = sh(
        ["/usr/sbin/softwareupdate", "-l"],
        timeout=45,
    )
    raw = (out2 or err2 or "").strip()
    interesting = [
        ln for ln in raw.splitlines()
        if ln.strip() and not ln.startswith("Software Update Tool")
    ]
    result["macos"] = {
        "ok": rc2 == 0,
        "lines": interesting[:30],
        "raw": raw[:1500],
        "has_updates": any(
            "Label:" in ln or "recommended" in ln.lower() or "*" in ln
            for ln in interesting
        ),
    }
    _updates_cache.update(t=time.time(), v=result)
    return result


# ─── Network helpers ─────────────────────────────────────────────────────────

def net_ping(host: str, count: int = 3) -> dict:
    # The old blocklist enumerated shell metacharacters and never considered a
    # leading hyphen, so `-f` / `--flood` landed in ping's option position.
    if not cli_args.is_safe_hostname(host):
        return {"ok": False, "message": "主机名含非法字符"}
    host = host.strip()
    count = max(1, min(int(count or 3), 10))
    rc, out, err = sh(
        ["/sbin/ping", "-c", str(count), "-W", "2000", host],
        timeout=count * 3 + 5,
    )
    return {
        "ok": rc == 0,
        "host": host,
        "count": count,
        "output": (out or err or "").strip()[:3000],
    }


def net_dns_lookup(name: str) -> dict:
    if not (name or "").strip():
        return {"ok": False, "message": "空域名"}
    # `dig -f /etc/passwd` treats the file as a query list, and this endpoint
    # returns command output -- an arbitrary-file-read primitive from one
    # unanchored blocklist.  Require an alphanumeric first character instead.
    if not cli_args.is_safe_hostname(name):
        return {"ok": False, "message": "非法字符"}
    name = name.strip()
    results = []
    try:
        infos = socket.getaddrinfo(name, None)
        seen = set()
        for fam, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            if ip in seen:
                continue
            seen.add(ip)
            results.append({
                "ip": ip,
                "family": "IPv6" if fam == socket.AF_INET6 else "IPv4",
            })
    except socket.gaierror as e:
        return {"ok": False, "name": name, "message": str(e), "results": []}
    # also dig if available for NS/info
    dig = shutil.which("dig") or "/usr/bin/dig"
    dig_out = ""
    if Path(dig).exists():
        rc, out, _ = sh([dig, "+short", name], timeout=8)
        if rc == 0:
            dig_out = (out or "").strip()[:500]
    return {
        "ok": True,
        "name": name,
        "results": results,
        "dig": dig_out,
    }


def parse_lsof_listen_line(line: str) -> dict | None:
    """Parse one `lsof -nP -iTCP -sTCP:LISTEN` row.

    Layout is COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME [(STATE)].
    The NAME column is the last field once the trailing "(LISTEN)" state token
    is dropped; DEVICE/SIZE-OFF widths vary, so counting from the right is the
    only reliable way. NAME looks like "*:8086", "127.0.0.1:8086" or
    "[::1]:8086" — IPv6 literals contain colons, so split on the LAST one.
    """
    parts = line.split()
    if len(parts) < 9:
        return None
    # Drop trailing state token(s) such as "(LISTEN)" to expose NAME.
    while len(parts) > 9 and parts[-1].startswith("(") and parts[-1].endswith(")"):
        parts.pop()
    name = parts[-1]
    if ":" not in name:
        return None
    address, _, port_s = name.rpartition(":")
    if not address or not port_s.isdigit():
        return None
    return {
        # existing keys the Tools view already renders
        "command": parts[0][:40],
        "pid": parts[1],
        "user": parts[2],
        "name": name[:80],
        # added: structured fields for the port-conflict pre-check
        "process": parts[0][:40],
        "address": address[:64],
        "port": int(port_s),
    }


def listening_ports(limit: int = 40) -> dict:
    """Quick lsof listen summary (Unraid-ish net tools)."""
    rc, out, err = sh(
        ["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN"],
        timeout=12,
    )
    rows = []
    if rc == 0:
        for line in out.splitlines()[1:]:
            row = parse_lsof_listen_line(line)
            if row:
                rows.append(row)
    rows = rows[: max(5, min(int(limit or 40), 100))]
    return {
        "ok": rc == 0,
        "count": len(rows),
        "ports": rows,
        "message": (err or "")[:200] if rc != 0 else "",
    }


def flush_dns() -> dict:
    """Flush macOS DNS caches (common admin tool)."""
    msgs = []
    ok_any = False
    for cmd in [
        ["/usr/bin/dscacheutil", "-flushcache"],
        ["/usr/bin/killall", "-HUP", "mDNSResponder"],
    ]:
        rc, out, err = sh(cmd, timeout=8)
        msgs.append(f"{' '.join(cmd)} → rc={rc} {(out or err or '').strip()[:80]}")
        if rc == 0:
            ok_any = True
    # may need sudo for killall
    if not ok_any:
        rc, out, err = sh(
            ["sudo", "-n", "/usr/bin/killall", "-HUP", "mDNSResponder"],
            timeout=8,
        )
        msgs.append(f"sudo killall mDNSResponder → rc={rc}")
        ok_any = rc == 0
    return {
        "ok": ok_any,
        "message": "DNS 缓存已刷新" if ok_any else "部分失败（可能需要管理员权限）",
        "detail": msgs,
    }


# ─── LaunchAgents (broader than timers) ──────────────────────────────────────

def launchd_timers() -> list:
    """List StartInterval / calendar agents for Scheduler-like view."""
    import plistlib

    agents = os.path.expanduser("~/Library/LaunchAgents")
    items = []
    for path in sorted(glob.glob(f"{agents}/*.plist")):
        try:
            with open(path, "rb") as f:
                pl = plistlib.load(f)
        except Exception:
            continue
        label = pl.get("Label") or Path(path).stem
        interval = pl.get("StartInterval")
        calendar = pl.get("StartCalendarInterval")
        if not interval and not calendar:
            continue
        items.append({
            "label": label,
            "path": path,
            "interval_sec": interval,
            "calendar": calendar,
            "program": " ".join(pl.get("ProgramArguments") or [])[:120],
        })
    return items


def launchd_agents_summary() -> dict:
    import plistlib

    agents_dir = Path(os.path.expanduser("~/Library/LaunchAgents"))
    items = []
    for path in sorted(agents_dir.glob("*.plist")):
        try:
            with open(path, "rb") as f:
                pl = plistlib.load(f)
        except Exception:
            items.append({"label": path.stem, "path": str(path), "error": "parse"})
            continue
        label = pl.get("Label") or path.stem
        run_at = bool(pl.get("RunAtLoad"))
        keep = pl.get("KeepAlive")
        interval = pl.get("StartInterval")
        calendar = pl.get("StartCalendarInterval")
        disabled = bool(pl.get("Disabled"))
        items.append({
            "label": label,
            "path": str(path),
            "run_at_load": run_at,
            "keep_alive": bool(keep) if not isinstance(keep, dict) else True,
            "interval_sec": interval,
            "calendar": bool(calendar),
            "disabled": disabled,
            "program": " ".join(pl.get("ProgramArguments") or [])[:100],
        })
    return {
        "count": len(items),
        "agents": items,
        "dir": str(agents_dir),
        "hint": "用户级 LaunchAgents · 定时见调度页",
    }


# ─── About ───────────────────────────────────────────────────────────────────

def about_info() -> dict:
    return {
        "name": "ServerHub",
        "version": __version__,
        "tagline_key": "tools.about_tagline",
        "host_ip": host_ip(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "base": str(BASE),
        "credit_keys": [
            "tools.credit_stack",
            "tools.credit_services",
        ],
        "links": [
            {"label_key": "nav.settings", "href": "/settings"},
            {"label_key": "nav.health", "href": "/health"},
            {"label_key": "nav.modules", "href": "/modules"},
            {"label_key": "nav.maintenance", "href": "/maintenance"},
        ],
    }
