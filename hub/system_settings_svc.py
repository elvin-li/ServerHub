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
from hub import __version__
from hub.config import cfg
from hub.host_address import configured_host, host_ip
from hub.paths import BASE, CONFIG_FILE, DATA_DIR
from hub.errors import soft_fail
from hub.util import LazyPool, cached_snapshot, fan_out, sh, ttl_memo

_pool = LazyPool(12, "hub-syssettings")


def shutdown_executor() -> None:
    _pool.shutdown()
DEFAULT_THRESHOLDS = {
    "enabled": True,
    "cpu_pct": 90,
    "mem_pct": 90,
    "disk_pct": 90,
    "cooldown_sec": 1800,
    # SMART disk health gets its own switch instead of riding on `enabled` above.
    # `enabled` is the mute button for the CPU/mem/disk-usage alerts, which trip on
    # ordinary load spikes and are the ones an operator switches off during a big
    # build or a backup run.  A disk reporting FAILED, or growing reallocated
    # sectors, is not that kind of noise -- it is data being lost right now -- and
    # must not disappear with the same click.
    "smart_enabled": True,
    # Consumer NVMe/SATA drives are rated to roughly 70C and throttle before it, so
    # 60C reads as "this enclosure has no airflow", not "this disk is busy".
    "smart_temp_c": 60,
    # NVMe "Percentage Used": 100% means the rated write endurance is spent, so 90%
    # is the last comfortable moment to plan a replacement rather than react to one.
    "smart_wear_pct": 90,
    # NVMe "Available Spare" counts *down* from 100% as the over-provisioning pool
    # is consumed, so this threshold trips when the value falls to or below it --
    # the opposite direction from every other number in this dict.
    "smart_spare_pct": 10,
}
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

    def _safe(item):
        probe, fallback = item
        try:
            return probe()
        except Exception:
            return fallback

    now, tz, ntp_on, ntp_server = fan_out(
        _safe,
        [
            (_clock_now, time.strftime("%Y-%m-%d %H:%M:%S")),
            (time_zone, ""),
            (_ntp_enabled, None),
            (_ntp_server, None),
        ],
        max_workers=4,
    )
    return {
        "now": now,
        "timezone": tz or "",
        "ntp_enabled": ntp_on,
        "ntp_server": ntp_server,
        "unix": int(time.time()),
        "hint": "Changing the system time zone / NTP usually requires administrator rights (System Settings → General → Date & Time)",
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
        "hint": "Without an external UPS a Mac reports its internal battery / AC power; with an APC UPS you can install apcupsd.",
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


#: Assertion lines handed to the page.  This was 12, which a plain desktop
#: already reaches -- a remote screen-sharing session plus one `caffeinate`
#: accounts for 9 -- and the truncation was silent, so the assertion an operator
#: is hunting ("what is keeping this NAS awake?") could be the one dropped.  The
#: panel renders these in a scrolling block, so a low cap bought nothing; keep a
#: bound against a pathological `pmset` and report the real count beside it.
MAX_ASSERTIONS = 40


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


@ttl_memo(5.0)
def get_power_info() -> dict:
    """Power management snapshot (pmset).

    Two `pmset` reads and the UPS probe answer unrelated questions; the settings
    dump says nothing about what is currently holding the machine awake.

    Memoised briefly because the Settings bundle wants it twice -- once directly and
    once through :func:`get_disk_settings` for the disk-sleep value -- so one
    ``/api/settings/system`` read ran all three ``pmset`` commands twice. The TTL is
    short rather than matching the bundle's 25s: this is also the whole payload of
    ``/api/settings/power``, and an operator who has just changed a setting should not
    wait out a long cache. :func:`set_power_pref` drops it explicitly, because after
    changing pmset the re-read must see the new value and not the memo.
    """
    def _safe(item):
        probe, fallback = item
        try:
            return probe()
        except Exception:
            return fallback

    settings, sleep_prevented_by, ups = fan_out(
        _safe,
        [
            (_pmset_settings, {}),
            (_pmset_assertions, []),
            (get_ups_info, {"source": "unknown", "on_ac": False}),
        ],
        max_workers=3,
    )
    return {
        "settings": settings,
        "displaysleep": settings.get("displaysleep"),
        "disksleep": settings.get("disksleep"),
        "sleep": settings.get("sleep"),
        "womp": settings.get("womp"),
        "lowpowermode": settings.get("lowpowermode"),
        "assertions": sleep_prevented_by[:MAX_ASSERTIONS],
        "assertion_count": len(sleep_prevented_by),
        "ups": ups,
        "hint": "disksleep=0 means disks never sleep (common for a home NAS). Changing pmset may require sudo.",
    }


def set_power_pref(key: str, value: int) -> dict:
    """Best-effort pmset -a KEY VALUE (may need sudo)."""
    key = (key or "").strip()
    allowed = {
        "disksleep", "displaysleep", "sleep", "womp", "powernap",
        "networkoversleep", "ttyskeepawake", "lowpowermode",
    }
    if key not in allowed:
        return soft_fail("power.bad_key", key=key)
    try:
        value = int(value)
    except (TypeError, ValueError):
        return soft_fail("power.bad_value")
    if value < 0 or value > 180:
        return soft_fail("power.value_range")
    rc, out, err = sh(["/usr/bin/pmset", "-a", key, str(value)], timeout=8)
    if rc != 0:
        rc, out, err = sh(["/usr/bin/sudo", "-n", "/usr/bin/pmset", "-a", key, str(value)], timeout=8)
    msg = out or err or ""
    if rc != 0:
        msg = (msg or "failed") + f" · run manually: sudo pmset -a {key} {value}"
    # Bust the caches so the UI sees the new pmset values. Order matters: the return
    # value below re-reads get_power_info(), and without dropping its memo first that
    # read would report the setting as it was before this call changed it.
    get_power_info.invalidate()
    unraid_settings_bundle.invalidate()
    return {"ok": rc == 0, "key": key, "value": value, "message": msg or "applied", "power": get_power_info()}


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
        "hint": "Sleep / wake HDDs from the Storage Array page; this adjusts the system disksleep policy.",
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
        "hint": "Manage shares on the Shares page; macOS File Sharing lives in System Settings → General → Sharing.",
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
        "resource_mode": (
            s.get("resource_mode") if s.get("resource_mode") in ("low", "high") else "low"
        ),
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
            "hint": "Metrics are flushed in batches and alert state is written only on change, reducing SSD wear",
        },
        "hint": "Advanced toggles: adaptive discovery, IP aliases, resource thresholds, sampling intervals",
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
        "hint": "LaunchAgents scheduled tasks",
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
                "hint": "Manage VMs on the Virtual Machines page",
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
            "hint": "UTM + OrbStack virtual machines",
        }
    except Exception as e:
        return {"error": str(e), "total": 0, "running": 0, "items": []}


def _diag_host() -> dict:
    """Interpreter and OS identity.

    Goes through ``identity_svc.platform_string`` rather than ``platform.platform()``
    so that this and the ``identity`` section beside it -- which also wants it -- share
    one answer instead of racing to shell out twice.
    """
    from hub.identity_svc import platform_string

    return {
        "platform": platform_string(),
        "python": platform.python_version(),
        "hostname": platform.node(),
    }


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
    bundle: dict = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    # `platform.platform()` is not the pure string-formatting call it looks like: on
    # macOS it shells out to `uname -p` and then `file -b` on the Python binary, and
    # both ran before the wave started, adding two serial spawns to the front of the
    # bundle. It joins the wave instead. Python memoises the result internally, so on
    # every later request this costs nothing at all.
    for section in fan_out(
        lambda probe: probe(),
        (_diag_host, *_DIAG_SECTIONS),
        max_workers=len(_DIAG_SECTIONS) + 1,
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


@cached_snapshot(_BUNDLE_TTL)
def unraid_settings_bundle(force: bool = False) -> dict:
    """Aggregate for Settings page (Unraid parity). Cached ~25s to avoid shell storms."""

    from hub import identity_svc, network_svc

    # Twelve independent collectors, each shelling out one to three times
    # (systemsetup, pmset, sharing, launchctl, diskutil, scutil …). They were run
    # one after another — several of them inline in the dict literal below — so
    # the Settings page paid for the whole chain in sequence on every cache miss.
    # Nothing here reads another's output, so the sequence bought nothing.
    #
    # Every collector is absorbed: `.result()` re-raises, and one wedged
    # ``pmset`` / ``systemsetup`` used to 500 the whole Settings page.
    f_identity = _pool.submit(identity_svc.get_identity)
    f_alias = _pool.submit(network_svc.alias_auto_status)
    f_shares = _pool.submit(get_share_globals)
    f_sched = _pool.submit(get_scheduler_summary)
    f_vms = _pool.submit(get_vm_settings)
    f_datetime = _pool.submit(get_datetime_info)
    f_power = _pool.submit(get_power_info)
    f_disk = _pool.submit(get_disk_settings)
    f_mgmt = _pool.submit(get_management_access)
    f_other = _pool.submit(get_other_settings)
    f_thresholds = _pool.submit(get_thresholds)

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
    try:
        datetime_info = f_datetime.result()
    except Exception as e:
        datetime_info = {"error": str(e)}
    try:
        power = f_power.result()
    except Exception as e:
        power = {"error": str(e)}
    try:
        disk = f_disk.result()
    except Exception as e:
        disk = {"error": str(e)}
    try:
        mgmt = f_mgmt.result()
    except Exception as e:
        mgmt = {"error": str(e)}
    try:
        other = f_other.result()
    except Exception as e:
        other = {"error": str(e)}
    try:
        thresholds = f_thresholds.result()
    except Exception as e:
        thresholds = {**DEFAULT_THRESHOLDS, "error": str(e)}

    v = {
        "ts": time.strftime("%H:%M:%S"),
        "identity": identity,
        "datetime": datetime_info,
        "power": power,
        "disk": disk,
        "management": mgmt,
        "shares": shares,
        "alias_auto": alias,
        "other": other,
        "scheduler": sched,
        "vms": vms,
        "thresholds": thresholds,
        "sections": [
            {"id": "appearance", "label": "Display", "unraid": "Display Settings"},
            {"id": "identity", "label": "Identification", "unraid": "Identification"},
            {"id": "datetime", "label": "Date & Time", "unraid": "Date & Time"},
            {"id": "network", "label": "Network / Aliases", "unraid": "Network Settings"},
            {"id": "disk", "label": "Disks", "unraid": "Disk Settings"},
            {"id": "power", "label": "Power / UPS", "unraid": "UPS / Power"},
            {"id": "docker", "label": "Docker", "unraid": "Docker"},
            {"id": "vms", "label": "Virtual Machines", "unraid": "VM Manager"},
            {"id": "notify", "label": "Notifications", "unraid": "Notifications"},
            {"id": "shares", "label": "Shares", "unraid": "SMB / Shares"},
            {"id": "scheduler", "label": "Scheduler", "unraid": "Scheduler"},
            {"id": "access", "label": "Management Access", "unraid": "Management Access"},
            {"id": "advanced", "label": "Advanced", "unraid": "Other Settings"},
            {"id": "diagnostics", "label": "Diagnostics", "unraid": "Diagnostics"},
            {"id": "panel", "label": "Panel", "unraid": "User Preferences"},
        ],
        "cached_ttl": _BUNDLE_TTL,
    }
    return v
