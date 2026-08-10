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
from concurrent.futures import ThreadPoolExecutor

from hub import __version__
from hub.config import cfg
from hub.host_address import configured_host, host_ip
from hub.paths import BASE, CONFIG_FILE, DATA_DIR
from hub.util import fan_out, sh
DEFAULT_THRESHOLDS = {
    "enabled": True,
    "cpu_pct": 90,
    "mem_pct": 90,
    "disk_pct": 90,
    "cooldown_sec": 1800,
}
_bundle_cache: dict = {"t": 0.0, "v": None}
_BUNDLE_TTL = 25.0  # settings page is interactive but not real-time


def _clock_now() -> str:
    rc, now, _ = sh(["/bin/date", "+%Y-%m-%d %H:%M:%S %Z"], timeout=3)
    return now if rc == 0 else time.strftime("%Y-%m-%d %H:%M:%S")


def _ntp_enabled() -> bool | None:
    """None when systemsetup would not say, which the page renders as unknown."""
    rc, out, _ = sh(["/usr/sbin/systemsetup", "-getusingnetworktime"], timeout=4)
    return "on" in out.lower() if rc == 0 and out else None


def _ntp_server() -> str | None:
    rc, out, _ = sh(["/usr/sbin/systemsetup", "-getnetworktimeserver"], timeout=4)
    return out.split(":", 1)[-1].strip() if rc == 0 and out and ":" in out else None


def get_datetime_info() -> dict:
    """Date / timezone / NTP-ish info (macOS).

    The two `systemsetup` reads are the slow ones -- it is a notoriously unhurried
    binary and each carries its own 4s timeout -- and neither depends on the other
    or on the clock and timezone reads beside them.
    """
    from hub.identity_svc import time_zone

    now, tz, ntp_on, ntp_server = fan_out(
        lambda probe: probe(),
        [_clock_now, time_zone, _ntp_enabled, _ntp_server],
        max_workers=4,
    )
    return {
        "now": now,
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


def _pmset_settings() -> dict:
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
    return settings


def _pmset_assertions() -> list[str]:
    sleep_prevented_by: list[str] = []
    rc, out, _ = sh(["/usr/bin/pmset", "-g", "assertions"], timeout=5)
    if rc == 0:
        for line in out.splitlines():
            if "pid " in line and "named:" in line:
                sleep_prevented_by.append(line.strip()[:160])
            if "sleep prevented by" in line.lower():
                sleep_prevented_by.append(line.strip())
    return sleep_prevented_by


def get_power_info() -> dict:
    """Power management snapshot (pmset).

    Two `pmset` reads and the UPS probe answer unrelated questions; the settings
    dump says nothing about what is currently holding the machine awake.
    """
    settings, sleep_prevented_by, ups = fan_out(
        lambda probe: probe(),
        [_pmset_settings, _pmset_assertions, get_ups_info],
        max_workers=3,
    )
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


def _storage_snapshot() -> tuple[dict, list]:
    try:
        from hub import storage_svc
        st = storage_svc.collect_storage(force=False)
        smart = (st.get("system") or {}).get("smart") or st.get("smart") or {}
        return smart, st.get("disks") or []
    except Exception:
        return {}, []


def _power_disks() -> list:
    try:
        from hub import disk_power_svc
        return disk_power_svc.list_power_disks()
    except Exception:
        return []


def get_disk_settings() -> dict:
    """Disk-related settings summary for Settings page.

    Three independent reads, each of which is a page payload in its own right:
    the pmset snapshot, the storage inventory and the per-disk power states. Each
    absorbs its own failure, as it did serially -- a missing storage module left
    the disk list empty rather than failing the settings page.
    """
    power, (smart, disks), power_disks = fan_out(
        lambda probe: probe(),
        [get_power_info, _storage_snapshot, _power_disks],
        max_workers=3,
    )
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
            "services_yaml": str(CONFIG_FILE),
            "data": str(DATA_DIR),
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


def _diag_identity() -> dict:
    try:
        from hub import identity_svc
        return {"identity": identity_svc.get_identity()}
    except Exception as e:
        return {"identity": {"error": str(e)}}


def _diag_datetime() -> dict:
    try:
        return {"datetime": get_datetime_info()}
    except Exception as e:
        return {"datetime": {"error": str(e)}}


def _diag_power() -> dict:
    """The power section, from one reading.

    ``get_power_info()`` was called twice here -- once for the body and once for the
    assertion count -- which ran ``pmset`` twice to answer one question.
    """
    try:
        info = get_power_info()
    except Exception as e:
        return {"power": {"error": str(e)}}
    return {"power": {
        **{k: v for k, v in info.items() if k != "assertions"},
        "assertions_count": len(info.get("assertions") or []),
    }}


def _diag_management() -> dict:
    try:
        return {"management": get_management_access()}
    except Exception as e:
        return {"management": {"error": str(e)}}


def _diag_other() -> dict:
    try:
        return {"other": get_other_settings()}
    except Exception as e:
        return {"other": {"error": str(e)}}


def _diag_docker() -> dict:
    try:
        from hub import docker_info_svc
        di = docker_info_svc.engine_info()
        return {"docker": {
            "engine_up": di.get("engine_up"),
            "version": (di.get("info") or {}).get("ServerVersion"),
            "containers_running": (di.get("info") or {}).get("ContainersRunning"),
            "orb_version": di.get("orb_version"),
        }}
    except Exception as e:
        return {"docker": {"error": str(e)}}


def _diag_alias_auto() -> dict:
    try:
        from hub import network_svc
        return {"alias_auto": network_svc.alias_auto_status()}
    except Exception as e:
        return {"alias_auto": {"error": str(e)}}


def _diag_alerts() -> dict:
    try:
        from hub import alerts
        return {"recent_alerts": alerts.list_alerts(20)}
    except Exception:
        return {"recent_alerts": []}


def _diag_health() -> dict:
    try:
        from hub import health_svc
        return {"health": health_svc.run_checks()}
    except Exception as e:
        return {"health": {"error": str(e)}}


def _diag_metrics() -> dict:
    try:
        from hub import metrics
        hist = metrics.history(30)
        return {"metrics_latest": hist[-1] if hist else None}
    except Exception:
        return {"metrics_latest": None}


def _diag_vms() -> dict:
    """Empty on failure, not ``{"vms": None}``.

    The serial version used a bare ``except: pass`` after assigning nothing, so a
    failure left the key out of the bundle entirely.  Returning ``{}`` reproduces
    that rather than inventing a null the download schema never contained.
    """
    try:
        vm = get_vm_settings()
        return {"vms": {"total": vm.get("total"), "running": vm.get("running")}}
    except Exception:
        return {}


#: The diagnostics sections, in the order they appear in the saved JSON.
_DIAG_SECTIONS = (
    _diag_identity,
    _diag_datetime,
    _diag_power,
    _diag_management,
    _diag_other,
    _diag_docker,
    _diag_alias_auto,
    _diag_alerts,
    _diag_health,
    _diag_metrics,
    _diag_vms,
)


def collect_diagnostics() -> dict:
    """Unraid Diagnostics-style snapshot (JSON, not full syslog dump).

    Eleven sections, each interrogating a different subsystem and none reading
    another's output.  Collected in turn this was the deepest serial path in the
    API -- 23 subprocesses back to back, several of them whole page payloads in
    their own right (``health_svc.run_checks``, ``docker_info_svc.engine_info``),
    so the bundle cost roughly the sum of every page it summarises.

    Every section absorbs its own failure and reports it as ``{"error": ...}`` in
    its own slot.  Four of them -- ``datetime``, ``power``, ``management``,
    ``other`` -- used not to, so a raise from any one of them failed the whole
    request.  That is the opposite of what this endpoint is for: the page offers it
    as a "download diagnostics" button, which is pressed exactly when a subsystem is
    broken, and the section that fails is usually the one the operator needs to see.
    The seven that already worked this way set the shape.

    ``fan_out`` returns results in submission order, so the saved JSON keeps its
    section order.
    """
    bundle: dict = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "hostname": platform.node(),
    }
    for section in fan_out(
        lambda probe: probe(), _DIAG_SECTIONS, max_workers=len(_DIAG_SECTIONS)
    ):
        bundle.update(section)
    # Persist last diagnostics for download convenience.  Generation and
    # persistence are separate outcomes: callers can still render the in-memory
    # snapshot when the state directory is full or read-only, but must not claim
    # that a downloadable file was saved.
    saved_path, save_error = _persist_diagnostics(bundle)
    bundle["saved_path"] = saved_path
    bundle["save_error"] = save_error
    return bundle


def _persist_diagnostics(bundle: dict) -> tuple[str | None, str | None]:
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        path = DATA_DIR / "diagnostics-latest.json"
        path.write_text(json.dumps(bundle, ensure_ascii=False, indent=2, default=str))
        return str(path), None
    except Exception as e:
        return None, str(e)


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

    # Twelve independent collectors, each shelling out one to three times
    # (systemsetup, pmset, sharing, launchctl, diskutil, scutil …). They were run
    # one after another — several of them inline in the dict literal below — so
    # the Settings page paid for the whole chain in sequence on every cache miss.
    # Nothing here reads another's output, so the sequence bought nothing.
    #
    # Failure semantics are preserved exactly: the five collectors that had a
    # try/except keep their specific fallback, and the rest still propagate, since
    # .result() re-raises in this thread just as a direct call would have.
    with ThreadPoolExecutor(max_workers=12) as ex:
        f_identity = ex.submit(identity_svc.get_identity)
        f_alias = ex.submit(network_svc.alias_auto_status)
        f_shares = ex.submit(get_share_globals)
        f_sched = ex.submit(get_scheduler_summary)
        f_vms = ex.submit(get_vm_settings)
        f_datetime = ex.submit(get_datetime_info)
        f_power = ex.submit(get_power_info)
        f_disk = ex.submit(get_disk_settings)
        f_mgmt = ex.submit(get_management_access)
        f_other = ex.submit(get_other_settings)
        f_thresholds = ex.submit(get_thresholds)

        try:
            identity = f_identity.result()
        except Exception as e:
            identity = {"error": str(e)}
        try:
            alias = f_alias.result()
        except Exception:
            alias = None
        try:
            shares = f_shares.result()
        except Exception as e:
            shares = {"error": str(e), "smb_running": False, "share_count": 0}
        try:
            sched = f_sched.result()
        except Exception as e:
            sched = {"timers": [], "count": 0, "error": str(e)}
        try:
            vms = f_vms.result()
        except Exception as e:
            vms = {"total": 0, "running": 0, "items": [], "error": str(e)}

    v = {
        "ts": time.strftime("%H:%M:%S"),
        "identity": identity,
        "datetime": f_datetime.result(),
        "power": f_power.result(),
        "disk": f_disk.result(),
        "management": f_mgmt.result(),
        "shares": shares,
        "alias_auto": alias,
        "other": f_other.result(),
        "scheduler": sched,
        "vms": vms,
        "thresholds": f_thresholds.result(),
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
