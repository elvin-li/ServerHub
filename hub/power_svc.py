"""Host power control + remote desktop (Screen Sharing / VNC).

Power actions:
  - sleep     : `pmset sleepnow` (no sudo)
  - shutdown  : osascript System Events → fallback `sudo -n shutdown -h now`
  - restart   : osascript System Events → fallback `sudo -n shutdown -r now`
  Shutdown/restart run after a short delay so the HTTP response is sent first,
  and require confirm=True at the API layer.

"Power on" a fully-off Mac is impossible from software — only Wake-on-LAN can
wake a *sleeping* machine, and the magic packet must come from another LAN
device. We expose the WOL toggle (pmset womp) + this host's MAC for that.

Remote desktop uses the built-in macOS Screen Sharing (VNC, port 5900). The web
UI just offers a `vnc://host:5900` button that opens the client's Screen
Sharing app — best Mac↔Mac performance, no extra proxy process.
"""
from __future__ import annotations

import re
import threading
import time

from fastapi import HTTPException

from hub.host_address import host_ip
from hub.util import port_open, sh

VNC_PORT = 5900


# ─── host identity (default NIC + MAC) ───────────────────────────────────────

def _default_iface() -> str:
    rc, out, _ = sh(["/sbin/route", "-n", "get", "default"], timeout=5)
    if rc == 0:
        m = re.search(r"interface:\s*(\S+)", out)
        if m:
            return m.group(1)
    return ""


def _iface_mac(dev: str) -> str:
    if not dev:
        return ""
    rc, out, _ = sh(["/sbin/ifconfig", dev], timeout=5)
    if rc == 0:
        m = re.search(r"\bether\s+([0-9a-fA-F:]{17})", out)
        if m:
            return m.group(1)
    return ""


def _host_ip() -> str:
    return host_ip()


# ─── Wake-on-LAN (womp) ──────────────────────────────────────────────────────

def _womp_enabled() -> bool | None:
    rc, out, _ = sh(["/usr/bin/pmset", "-g"], timeout=5)
    if rc != 0:
        return None
    m = re.search(r"\bwomp\s+(\d)", out)
    return bool(int(m.group(1))) if m else None


def set_wol(enabled: bool) -> dict:
    val = "1" if enabled else "0"
    rc, out, err = sh(["/usr/bin/pmset", "-a", "womp", val], timeout=8)
    if rc != 0:
        rc, out, err = sh(["sudo", "-n", "/usr/bin/pmset", "-a", "womp", val], timeout=8)
    ok = rc == 0
    msg = (out or err or "").strip()
    if not ok:
        msg = (msg or "失败") + f" · 可手动: sudo pmset -a womp {val}"
    return {
        "ok": ok,
        "enabled": enabled if ok else _womp_enabled(),
        "message": msg or ("网络唤醒已" + ("开启" if enabled else "关闭")),
    }


# ─── Screen Sharing (VNC) ────────────────────────────────────────────────────

def _screensharing_running() -> bool:
    return bool(port_open(VNC_PORT, host="localhost", timeout=0.4))


def screensharing_status() -> dict:
    running = _screensharing_running()
    host = _host_ip()
    return {
        "running": running,
        "port": VNC_PORT,
        "host": host,
        "vnc_url": f"vnc://{host}:{VNC_PORT}",
        "hint": (
            "已开启：点「远程连接」用系统「屏幕共享」App 连入"
            if running
            else "未开启：点「启用屏幕共享」，或到 系统设置 › 通用 › 共享 › 屏幕共享 手动开启"
        ),
    }


# ─── Power actions ───────────────────────────────────────────────────────────

_ACTIONS = ("shutdown", "restart", "sleep")
_last_power = {"action": None, "at": 0.0}


def _do_power(action: str) -> None:
    """Run the actual power command (in a delayed thread)."""
    if action == "sleep":
        sh(["/usr/bin/pmset", "sleepnow"], timeout=10)
        return
    verb = "shut down" if action == "shutdown" else "restart"
    # Prefer osascript (no sudo). Fall back to `sudo -n shutdown`.
    rc, _, _ = sh(
        ["/usr/bin/osascript", "-e", f'tell app "System Events" to {verb}'],
        timeout=20,
    )
    if rc != 0:
        flag = "-h" if action == "shutdown" else "-r"
        sh(["sudo", "-n", "/sbin/shutdown", flag, "now"], timeout=15)


def power_action(action: str, confirm: bool = False, delay_sec: float = 2.0) -> dict:
    action = (action or "").strip().lower()
    if action not in _ACTIONS:
        raise HTTPException(400, f"未知电源操作: {action}（可选 {', '.join(_ACTIONS)}）")
    if not confirm:
        raise HTTPException(400, "需要 confirm=true")

    _last_power.update(action=action, at=time.time())

    def job():
        time.sleep(max(0.0, delay_sec))
        try:
            _do_power(action)
        except Exception:
            pass

    threading.Thread(target=job, daemon=True, name=f"power-{action}").start()
    label = {"shutdown": "关机", "restart": "重启", "sleep": "睡眠"}[action]
    return {
        "ok": True,
        "action": action,
        "scheduled_in_sec": round(delay_sec, 1),
        "message": f"{label}指令已下发，约 {delay_sec:.0f} 秒后执行",
    }


# ─── Aggregate status for the page ───────────────────────────────────────────

def power_overview() -> dict:
    dev = _default_iface()
    return {
        "actions": list(_ACTIONS),
        "wol": {
            "enabled": _womp_enabled(),
            "iface": dev,
            "mac": _iface_mac(dev),
            "hint": "网络唤醒仅能唤醒「睡眠中」的机器，且需局域网内其他设备发送唤醒包；无法从关机状态开机。",
        },
        "screen_sharing": screensharing_status(),
        "host_ip": _host_ip(),
        "perf_tips": [
            "客户端「屏幕共享」App 菜单 › 显示 › 选「自适应质量」，弱网下更跟手。",
            "被控端降低分辨率/关闭动态壁纸与透明效果，可显著提升 VNC 流畅度。",
            "同为 Mac 时优先用系统「屏幕共享」而非第三方 VNC，走 Apple 优化的编码。",
            "远程时保持机器不睡眠：电源管理里把 displaysleep 调大或用咖啡因类工具。",
        ],
    }
