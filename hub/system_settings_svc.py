"""Unraid-style system settings aggregates for macOS (read + safe writes).

Inspired by:
  Unraid Settings (Identification, DateTime, Disk, Network, Docker, Notify,
  Management Access, Scheduler, Diagnostics, Other)
  OpenMediaVault (SMART, notifications thresholds, services)
  Cockpit (system overview, logs, power)
  CasaOS / TrueNAS (simple panels, resource alerts)
"""
from __future__ import annotations

import json
import platform
import re
import time
from pathlib import Path

from hub import __version__
from hub.config import cfg
from hub.host_address import configured_host, host_ip
from hub.util import sh

BASE = Path(__file__).resolve().parent.parent
DEFAULT_THRESHOLDS = {
    "enabled": True,
    "cpu_pct": 90,
    "mem_pct": 90,
    "disk_pct": 90,
    "cooldown_sec": 1800,
}
_bundle_cache: dict = {"t": 0.0, "v": None}
_BUNDLE_TTL = 25.0  # settings page is interactive but not real-time


def get_datetime_info() -> dict:
    """Date / timezone / NTP-ish info (macOS)."""
    from hub.identity_svc import time_zone

    rc, now, _ = sh(["/bin/date", "+%Y-%m-%d %H:%M:%S %Z"], timeout=3)
    tz = time_zone()
    ntp_on = None
    ntp_server = None
    rc2, out2, _ = sh(["/usr/sbin/systemsetup", "-getusingnetworktime"], timeout=4)
    if rc2 == 0 and out2:
        ntp_on = "on" in out2.lower()
    rc3, out3, _ = sh(["/usr/sbin/systemsetup", "-getnetworktimeserver"], timeout=4)
    if rc3 == 0 and out3 and ":" in out3:
        ntp_server = out3.split(":", 1)[-1].strip()
    return {
        "now": now if rc == 0 else time.strftime("%Y-%m-%d %H:%M:%S"),
        "timezone": tz or "",
        "ntp_enabled": ntp_on,
        "ntp_server": ntp_server,
        "unix": int(time.time()),
        "hint": "修改系统时区/NTP 通常需要管理员权限（系统设置 → 通用 → 日期与时间）",
    }


def get_ups_info() -> dict:
    """Power source / battery (Unraid UPS-ish; Mac uses AC + internal battery)."""
    rc, out, _ = sh(["/usr/bin/pmset", "-g", "batt"], timeout=5)
    lines = (out or "").strip().splitlines() if rc == 0 else []
    source = "unknown"
    percent = None
    charging = None
    present = None
    raw = "\n".join(lines[:8])
    for line in lines:
        low = line.lower()
        if "ac power" in low:
            source = "ac"
        elif "battery power" in low:
            source = "battery"
        if "internalbattery" in low.replace(" ", "") or "internalbattery" in low:
            m = re.search(r"(\d+)%", line)
            if m:
                percent = int(m.group(1))
            charging = "charging" in low and "not charging" not in low
            present = "present: true" in low
    return {
        "source": source,
        "on_ac": source == "ac",
        "battery_percent": percent,
        "charging": charging,
        "battery_present": present,
        "raw": raw,
        "hint": "Mac 无外接 UPS 时显示内置电池/市电；有 APC UPS 时可另装 apcupsd。",
    }


def get_power_info() -> dict:
    """Power management snapshot (pmset)."""
    rc, out, _ = sh(["/usr/bin/pmset", "-g"], timeout=5)
    settings: dict = {}
    if rc == 0:
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("System-wide") or line.startswith("Currently"):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0].isalpha():
                key = parts[0]
                val = parts[1]
                try:
                    if val.isdigit():
                        settings[key] = int(val)
                    else:
                        settings[key] = val
                except Exception:
                    settings[key] = val
    sleep_prevented_by = []
    rc2, out2, _ = sh(["/usr/bin/pmset", "-g", "assertions"], timeout=5)
    if rc2 == 0:
        for line in out2.splitlines():
            if "pid " in line and "named:" in line:
                sleep_prevented_by.append(line.strip()[:160])
            if "sleep prevented by" in line.lower():
                sleep_prevented_by.append(line.strip())
    ups = get_ups_info()
    return {
        "settings": settings,
        "displaysleep": settings.get("displaysleep"),
        "disksleep": settings.get("disksleep"),
        "sleep": settings.get("sleep"),
        "womp": settings.get("womp"),
        "lowpowermode": settings.get("lowpowermode"),
        "assertions": sleep_prevented_by[:12],
        "ups": ups,
        "hint": "磁盘休眠 disksleep=0 表示不休眠（家用 NAS 常用）。改 pmset 可能需 sudo。",
    }


def set_power_pref(key: str, value: int) -> dict:
    """Best-effort pmset -a KEY VALUE (may need sudo)."""
    key = (key or "").strip()
    allowed = {
        "disksleep", "displaysleep", "sleep", "womp", "powernap",
        "networkoversleep", "ttyskeepawake", "lowpowermode",
    }
    if key not in allowed:
        return {"ok": False, "message": f"不允许的键: {key}"}
    try:
        value = int(value)
    except (TypeError, ValueError):
        return {"ok": False, "message": "value 必须是整数"}
    if value < 0 or value > 180:
        return {"ok": False, "message": "value 超出范围 0–180"}
    rc, out, err = sh(["/usr/bin/pmset", "-a", key, str(value)], timeout=8)
    if rc != 0:
        rc, out, err = sh(["sudo", "-n", "/usr/bin/pmset", "-a", key, str(value)], timeout=8)
    msg = out or err or ""
    if rc != 0:
        msg = (msg or "失败") + f" · 可手动: sudo pmset -a {key} {value}"
    # bust settings bundle cache so UI sees new pmset values
    _bundle_cache["t"] = 0
    _bundle_cache["v"] = None
    return {"ok": rc == 0, "key": key, "value": value, "message": msg or "已应用", "power": get_power_info()}


def get_disk_settings() -> dict:
    """Disk-related settings summary for Settings page."""
    power = get_power_info()
    smart = {}
    try:
        from hub import storage_svc
        st = storage_svc.collect_storage(force=False)
        smart = (st.get("system") or {}).get("smart") or st.get("smart") or {}
        disks = st.get("disks") or []
    except Exception:
        disks = []
        st = {}
    power_disks = []
    try:
        from hub import disk_power_svc
        power_disks = disk_power_svc.list_power_disks()
    except Exception:
        pass
    return {
        "disksleep_minutes": power.get("disksleep"),
        "smart": smart,
        "disk_count": len(disks) or len(power_disks),
        "power_disks": [
            {
                "id": d.get("id"),
                "name": d.get("name") or d.get("id"),
                "power_state": d.get("power_state"),
                "size_gb": d.get("size_gb"),
            }
            for d in (power_disks or [])[:20]
        ],
        "hint": "HDD 休眠/唤醒请到「存储阵列」页操作；此处调整系统 disksleep 策略。",
    }


def get_management_access() -> dict:
    """Unraid Management Access style summary."""
    s = cfg().get("settings") or {}
    auth = s.get("auth") or {}
    return {
        "panel_port": 8086,
        "auth_enabled": bool(auth.get("enabled")),
        "allow_localhost": auth.get("allow_localhost", True),
        "username": auth.get("username") or "admin",
        "host_ip": host_ip(),
        "host_ip_config": configured_host(),
        "ssl_via_nginx": True,
        "nginx_https": f"https://{host_ip()}:8281",
        "export_yaml": "/api/export/services-yaml",
        "version": __version__,
        "paths": {
            "base": str(BASE),
            "services_yaml": str(BASE / "services.yaml"),
            "data": str(BASE / "data"),
        },
    }


def get_share_globals() -> dict:
    """SMB/share-ish globals (macOS file sharing status)."""
    rc, out, _ = sh(["/usr/sbin/sharing", "-l"], timeout=8)
    share_count = 0
    if rc == 0:
        share_count = len(re.findall(r"name:\s+", out or "", re.I))
    rc2, out2, _ = sh(["/bin/launchctl", "print", "system/com.apple.smbd"], timeout=4)
    smb_running = rc2 == 0 and "state = running" in (out2 or "")
    return {
        "smb_running": smb_running,
        "share_count": share_count,
        "hint": "详细共享请到「共享」页；系统「文件共享」在系统设置 → 通用 → 共享。",
    }


def get_thresholds() -> dict:
    s = (cfg().get("settings") or {}).get("thresholds") or {}
    out = dict(DEFAULT_THRESHOLDS)
    out.update({k: v for k, v in s.items() if v is not None})
    return out


def get_other_settings() -> dict:
    """Unraid Other Settings + OMV-style toggles."""
    s = cfg().get("settings") or {}
    alias = s.get("ip_aliases") or {}
    return {
        "adaptive": s.get("adaptive", True),
        "metrics_interval": s.get("metrics_interval", 90),
        "alert_interval": s.get("alert_interval", 90),
        "ip_aliases": {
            "auto_bind": alias.get("auto_bind", True),
            "prefer_wired": alias.get("prefer_wired", True),
            "interval": alias.get("interval", 60),
            "ips": list(alias.get("ips") or []),
            "netmask": alias.get("netmask") or "255.255.255.255",
        },
        "thresholds": get_thresholds(),
        "ssd_friendly": {
            "metrics_batch": True,
            "alert_write_if_changed": True,
            "yaml_bak_keep": 5,
            "hint": "指标批量落盘、告警状态仅变更时写盘，减轻 SSD 磨损",
        },
        "hint": "高级开关：自适应发现、别名、资源阈值、采集间隔",
    }


def get_scheduler_summary() -> dict:
    try:
        from hub.tools_svc import launchd_timers
        timers = launchd_timers() or []
    except Exception as e:
        return {"timers": [], "count": 0, "error": str(e)}
    slim = []
    for t in timers[:40]:
        slim.append({
            "label": t.get("label") or t.get("id") or t.get("name"),
            "interval": t.get("interval") or t.get("StartInterval"),
            "calendar": t.get("calendar") or t.get("StartCalendarInterval"),
            "path": t.get("path") or t.get("plist"),
        })
    return {
        "timers": slim,
        "count": len(timers),
        "hint": "LaunchAgents 定时任务",
    }


def get_vm_settings() -> dict:
    """Unraid VM Manager settings-style summary."""
    try:
        from hub import vms_svc
        data = vms_svc.list_all_vms()
        utm = data.get("utm") or data.get("utm_vms") or []
        orb = data.get("orb") or data.get("orb_machines") or []
        if isinstance(data.get("vms"), list):
            # fallback if different shape
            items = data["vms"]
            running = sum(1 for v in items if v.get("state") in ("ok", "running", "started"))
            return {
                "utm_available": vms_svc._utm_available(),
                "orb_available": vms_svc._orb_available(),
                "total": len(items),
                "running": running,
                "items": [
                    {"id": v.get("id"), "name": v.get("name"), "state": v.get("state"), "backend": v.get("backend")}
                    for v in items[:20]
                ],
                "hint": "详细管理请到「虚拟机」页",
            }
        items = []
        for v in utm:
            items.append({
                "id": v.get("id") or v.get("uuid") or v.get("name"),
                "name": v.get("display_name") or v.get("name"),
                "state": v.get("state") or v.get("status"),
                "backend": "utm",
            })
        for v in orb:
            items.append({
                "id": v.get("id") or v.get("name"),
                "name": v.get("display_name") or v.get("name"),
                "state": v.get("state") or v.get("status"),
                "backend": "orb",
            })
        running = sum(
            1 for v in items
            if str(v.get("state") or "").lower() in ("ok", "running", "started", "active")
        )
        return {
            "utm_available": vms_svc._utm_available(),
            "orb_available": vms_svc._orb_available(),
            "total": len(items),
            "running": running,
            "items": items[:20],
            "hint": "UTM + OrbStack 虚拟机",
        }
    except Exception as e:
        return {"error": str(e), "total": 0, "running": 0, "items": []}


def collect_diagnostics() -> dict:
    """Unraid Diagnostics-style snapshot (JSON, not full syslog dump)."""
    bundle: dict = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "hostname": platform.node(),
    }
    try:
        from hub import identity_svc
        bundle["identity"] = identity_svc.get_identity()
    except Exception as e:
        bundle["identity"] = {"error": str(e)}
    bundle["datetime"] = get_datetime_info()
    bundle["power"] = {
        k: v for k, v in get_power_info().items() if k != "assertions"
    }
    bundle["power"]["assertions_count"] = len(get_power_info().get("assertions") or [])
    bundle["management"] = get_management_access()
    bundle["other"] = get_other_settings()
    try:
        from hub import docker_info_svc
        di = docker_info_svc.engine_info()
        bundle["docker"] = {
            "engine_up": di.get("engine_up"),
            "version": (di.get("info") or {}).get("ServerVersion"),
            "containers_running": (di.get("info") or {}).get("ContainersRunning"),
            "orb_version": di.get("orb_version"),
        }
    except Exception as e:
        bundle["docker"] = {"error": str(e)}
    try:
        from hub import network_svc
        bundle["alias_auto"] = network_svc.alias_auto_status()
    except Exception as e:
        bundle["alias_auto"] = {"error": str(e)}
    try:
        from hub import alerts
        bundle["recent_alerts"] = alerts.list_alerts(20)
    except Exception:
        bundle["recent_alerts"] = []
    try:
        from hub import health_svc
        bundle["health"] = health_svc.run_checks()
    except Exception as e:
        bundle["health"] = {"error": str(e)}
    try:
        from hub import metrics
        hist = metrics.history(30)
        bundle["metrics_latest"] = hist[-1] if hist else None
    except Exception:
        bundle["metrics_latest"] = None
    try:
        vm = get_vm_settings()
        bundle["vms"] = {"total": vm.get("total"), "running": vm.get("running")}
    except Exception:
        pass
    # Persist last diagnostics for download convenience
    try:
        ddir = BASE / "data"
        ddir.mkdir(exist_ok=True)
        path = ddir / "diagnostics-latest.json"
        path.write_text(json.dumps(bundle, ensure_ascii=False, indent=2, default=str))
        bundle["saved_path"] = str(path)
    except Exception:
        pass
    return bundle


def unraid_settings_bundle(force: bool = False) -> dict:
    """Aggregate for Settings page (Unraid parity). Cached ~25s to avoid shell storms."""
    now = time.time()
    if (
        not force
        and _bundle_cache["v"] is not None
        and now - _bundle_cache["t"] < _BUNDLE_TTL
    ):
        return _bundle_cache["v"]

    from hub import identity_svc, network_svc

    try:
        identity = identity_svc.get_identity()
    except Exception as e:
        identity = {"error": str(e)}
    try:
        alias = network_svc.alias_auto_status()
    except Exception:
        alias = None
    # defer heavy pieces only once per cache window
    try:
        shares = get_share_globals()
    except Exception as e:
        shares = {"error": str(e), "smb_running": False, "share_count": 0}
    try:
        sched = get_scheduler_summary()
    except Exception as e:
        sched = {"timers": [], "count": 0, "error": str(e)}
    try:
        vms = get_vm_settings()
    except Exception as e:
        vms = {"total": 0, "running": 0, "items": [], "error": str(e)}

    v = {
        "ts": time.strftime("%H:%M:%S"),
        "identity": identity,
        "datetime": get_datetime_info(),
        "power": get_power_info(),
        "disk": get_disk_settings(),
        "management": get_management_access(),
        "shares": shares,
        "alias_auto": alias,
        "other": get_other_settings(),
        "scheduler": sched,
        "vms": vms,
        "thresholds": get_thresholds(),
        "sections": [
            {"id": "appearance", "label": "显示设置", "unraid": "Display Settings"},
            {"id": "identity", "label": "标识", "unraid": "Identification"},
            {"id": "datetime", "label": "日期时间", "unraid": "Date & Time"},
            {"id": "network", "label": "网络 / 别名", "unraid": "Network Settings"},
            {"id": "disk", "label": "磁盘", "unraid": "Disk Settings"},
            {"id": "power", "label": "电源 / UPS", "unraid": "UPS / Power"},
            {"id": "docker", "label": "Docker", "unraid": "Docker"},
            {"id": "vms", "label": "虚拟机", "unraid": "VM Manager"},
            {"id": "notify", "label": "通知", "unraid": "Notifications"},
            {"id": "shares", "label": "共享", "unraid": "SMB / Shares"},
            {"id": "scheduler", "label": "调度", "unraid": "Scheduler"},
            {"id": "access", "label": "管理访问", "unraid": "Management Access"},
            {"id": "advanced", "label": "高级", "unraid": "Other Settings"},
            {"id": "diagnostics", "label": "诊断", "unraid": "Diagnostics"},
            {"id": "panel", "label": "面板", "unraid": "User Preferences"},
        ],
        "cached_ttl": _BUNDLE_TTL,
    }
    _bundle_cache.update(t=time.time(), v=v)
    return v
