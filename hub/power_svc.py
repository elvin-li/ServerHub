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
from hub.errors import api_error
from hub.host_address import default_interface, host_ip
from hub.util import LazyPool, port_open, sh

_pool = LazyPool(3, "hub-power")


def shutdown_executor() -> None:
    _pool.shutdown()

VNC_PORT = 5900


# ─── host identity (default NIC + MAC) ───────────────────────────────────────

def _default_iface() -> str:
    """The interface holding the default route.

    One definition, in hub.host_address.  This module's own copy meant
    `/api/system/power` ran `route -n get default` twice for one answer: once here
    for the WOL NIC, and once inside `host_ip()` for the Screen Sharing URL.
    """
    return default_interface()


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
        rc, out, err = sh(["/usr/bin/sudo", "-n", "/usr/bin/pmset", "-a", "womp", val], timeout=8)
    ok = rc == 0
    msg = (out or err or "").strip()
    if not ok:
        msg = (msg or "failed") + f" · run manually: sudo pmset -a womp {val}"
    return {
        "ok": ok,
        "enabled": enabled if ok else _womp_enabled(),
        "message": msg or ("Wake-on-LAN " + ("enabled" if enabled else "disabled")),
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
            "Enabled: click \u201cRemote Connect\u201d to connect with the built-in Screen Sharing app"
            if running
            else "Disabled: click \u201cEnable Screen Sharing\u201d, or turn it on manually in "
                 "System Settings › General › Sharing › Screen Sharing"
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
        sh(["/usr/bin/sudo", "-n", "/sbin/shutdown", flag, "now"], timeout=15)


def power_action(action: str, confirm: bool = False, delay_sec: float = 2.0) -> dict:
    action = (action or "").strip().lower()
    if action not in _ACTIONS:
        raise api_error("power.unknown_action", action=action, choices=", ".join(_ACTIONS))
    if not confirm:
        raise api_error("power.confirm_required")

    _last_power.update(action=action, at=time.time())

    def job():
        time.sleep(max(0.0, delay_sec))
        try:
            _do_power(action)
        except Exception:
            pass

    threading.Thread(target=job, daemon=True, name=f"power-{action}").start()
    label = {"shutdown": "Shutdown", "restart": "Restart", "sleep": "Sleep"}[action]
    return {
        "ok": True,
        "action": action,
        "scheduled_in_sec": round(delay_sec, 1),
        "message": f"{label} command sent; it will run in about {delay_sec:.0f} seconds",
    }


# ─── Aggregate status for the page ───────────────────────────────────────────

def _nic() -> tuple[str, str]:
    """Default interface and its MAC. Serial by necessity: the MAC lookup needs
    the interface name."""
    dev = _default_iface()
    return dev, _iface_mac(dev)


def power_overview() -> dict:
    # Three independent branches: the NIC chain (route → ifconfig), `pmset -g`,
    # and the Screen Sharing probe. `pmset -g` alone is the slow one, and the
    # dashboard refreshes this tile on every heavy tick, so overlapping them
    # removes the part of the wait that was pure sequencing.
    f_nic = _pool.submit(_nic)
    f_womp = _pool.submit(_womp_enabled)
    f_ss = _pool.submit(screensharing_status)
    dev, mac = f_nic.result()
    womp = f_womp.result()
    screen_sharing = f_ss.result()
    return {
        "actions": list(_ACTIONS),
        "wol": {
            "enabled": womp,
            "iface": dev,
            "mac": mac,
            "hint": "Wake-on-LAN can only wake a sleeping machine, and the magic packet "
                    "must come from another device on the LAN; it cannot power on a Mac "
                    "that is fully shut down.",
        },
        "screen_sharing": screen_sharing,
        # Already resolved inside screensharing_status(); host_ip() is cached, so
        # this is a dict read rather than another lookup.
        "host_ip": screen_sharing.get("host") or _host_ip(),
        "perf_tips": [
            "In the client's Screen Sharing app, choose View › Adaptive Quality for a "
            "more responsive session on weak networks.",
            "On the controlled Mac, lowering the resolution and disabling dynamic "
            "wallpaper/transparency noticeably improves VNC smoothness.",
            "Between two Macs, prefer the built-in Screen Sharing over third-party VNC "
            "clients — it uses Apple-optimized encoding.",
            "Keep the machine awake while remoting: raise displaysleep in power "
            "management or use a caffeinate-style tool.",
        ],
    }
