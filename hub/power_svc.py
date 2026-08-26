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
from pathlib import Path

from hub.errors import api_error
from hub.host_address import default_interface, host_ip
from hub.util import LazyPool, port_open, sh

_pool = LazyPool(3, "hub-power")

#: The binary every power probe and mutation spawns.  Module-level so the
#: vanished-CLI probe re-checks the exact path the spawn used.
PMSET = "/usr/bin/pmset"


def shutdown_executor() -> None:
    _pool.shutdown()


def _as_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    elif value is None:
        return ""
    else:
        try:
            value = str(value)
        except RecursionError:
            try:
                return type(value).__name__
            except Exception:
                return ""
        except Exception:
            return ""
    return value.encode("utf-8", "replace").decode("utf-8")


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's allow_nan=False encoder cannot 500.

    Leftover ``\\ud800`` in ``host_ip`` / ifconfig MAC / pmset stderr still
    500'd GET /api/system/power and PUT /api/system/power/wol.
    """
    if depth > 32:
        return None
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        try:
            str(value)
        except ValueError:
            # Past CPython's int->str digit cap the encoder cannot render
            # the number at all (YAML/plist hex loads uncapped, so an
            # over-cap int arrives already-int) — same drop as its inf
            # float sibling.  It used to leak through this sanitizer and
            # 500 POST /api/system/screensharing/enable's ok payload.
            return None
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if isinstance(value, str):
        return _as_text(value)
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if not isinstance(k, (str, bytes, bytearray)):
                try:
                    k = str(k)
                except Exception:
                    continue
            out[_as_text(k)] = _jsonable(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v, depth + 1) for v in value]
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/system/power.
            return _jsonable(iso(), depth + 1)
        except Exception:
            return None
    try:
        return _as_text(value)
    except Exception:
        return None

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
        m = re.search(r"\bether\s+([0-9a-fA-F:]{17})", _as_text(out))
        if m:
            return m.group(1)
    return ""


def _host_ip() -> str:
    return host_ip()


# ─── Wake-on-LAN (womp) ──────────────────────────────────────────────────────

def _pmset_missing(rc, err) -> bool:
    """Whether an ``sh()`` result means pmset itself is gone.

    ``sh`` reports a FileNotFoundError spawn as ``(-1, "", "not found")`` — a
    sentinel, never a real pmset exit.  The sentinel alone must not classify:
    rc -1 is also what a timeout or a signal-killed run reports, so the disk
    is re-probed *on this failure path only* (the identity ``_scutil_missing``
    / vms ``_cli_missing`` rule — a successful spawn never pays the stat).
    Timeouts keep their own sentinel and are deliberately not classified;
    a permission failure is a real pmset exit and never matches.
    """
    if rc != -1 or _as_text(err).strip() != "not found":
        return False
    try:
        return not Path(PMSET).is_file()
    except (OSError, ValueError):
        # An unreadable /usr/bin must not upgrade the failure to a 503.
        return False


def _womp_enabled() -> bool | None:
    rc, out, _ = sh([PMSET, "-g"], timeout=5)
    if rc != 0:
        return None
    m = re.search(r"\bwomp\s+(\d)", _as_text(out))
    return bool(int(m.group(1))) if m else None


def set_wol(enabled: bool) -> dict:
    val = "1" if enabled else "0"
    rc, out, err = sh([PMSET, "-a", "womp", val], timeout=8)
    if rc != 0:
        if _pmset_missing(rc, err):
            # A vanished pmset used to answer ok:false with a message telling
            # the operator to run ``sudo pmset -a womp`` by hand — blaming
            # privileges for a binary the disk confirm just proved is gone
            # (the sudo fallback below cannot spawn it either).  Coded so the
            # panel can say what actually happened.
            raise api_error("power.pmset_missing")
        rc, out, err = sh(["/usr/bin/sudo", "-n", PMSET, "-a", "womp", val], timeout=8)
    ok = rc == 0
    msg = (_as_text(out) or _as_text(err)).strip()
    if not ok:
        msg = (msg or "failed") + f" · run manually: sudo pmset -a womp {val}"
    return _jsonable({
        "ok": ok,
        "enabled": enabled if ok else _womp_enabled(),
        "message": msg or ("Wake-on-LAN " + ("enabled" if enabled else "disabled")),
    })


# ─── Screen Sharing (VNC) ────────────────────────────────────────────────────

def _screensharing_running() -> bool:
    return bool(port_open(VNC_PORT, host="localhost", timeout=0.4))


def screensharing_status() -> dict:
    running = _screensharing_running()
    try:
        host = _as_text(_host_ip())
    except Exception:
        host = ""
    return _jsonable({
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
    })


# ─── Power actions ───────────────────────────────────────────────────────────

_ACTIONS = ("shutdown", "restart", "sleep")
_last_power = {"action": None, "at": 0.0}


def _do_power(action: str) -> None:
    """Run the actual power command (in a delayed thread)."""
    if action == "sleep":
        sh([PMSET, "sleepnow"], timeout=10)
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


def _clamp_delay(raw, default: float = 2.0) -> float:
    """Seconds the power thread actually sleeps.

    The response used to clamp leftover ``.inf`` / ``1e308`` *after* starting
    the worker, so POST /api/system/power/action reported ``scheduled_in_sec: 2``
    while ``time.sleep(inf)`` OverflowError'd (or hung) and the action never ran.
    """
    if isinstance(raw, bool) or raw is None:
        return default
    try:
        delay = float(raw)
    except (TypeError, ValueError, OverflowError):
        return default
    if delay != delay or delay in (float("inf"), float("-inf")):
        return default
    return max(0.0, min(delay, 30.0))


def power_action(action: str, confirm: bool = False, delay_sec: float = 2.0) -> dict:
    action = (action or "").strip().lower()
    if action not in _ACTIONS:
        raise api_error("power.unknown_action", action=action, choices=", ".join(_ACTIONS))
    if not confirm:
        raise api_error("power.confirm_required")

    delay = _clamp_delay(delay_sec)
    _last_power.update(action=action, at=time.time())

    def job():
        time.sleep(delay)
        try:
            _do_power(action)
        except Exception:
            pass

    threading.Thread(target=job, daemon=True, name=f"power-{action}").start()
    label = {"shutdown": "Shutdown", "restart": "Restart", "sleep": "Sleep"}[action]
    return _jsonable({
        "ok": True,
        "action": action,
        "scheduled_in_sec": round(delay, 1),
        "message": f"{label} command sent; it will run in about {delay:.0f} seconds",
    })


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

    def _result(fut, fallback):
        try:
            return fut.result()
        except Exception:
            return fallback

    # `.result()` re-raises; a wedged `pmset` must not drop the power tile.
    nic = _result(f_nic, ("", ""))
    if not isinstance(nic, (tuple, list)) or len(nic) < 2:
        dev, mac = "", ""
    else:
        dev, mac = nic[0], nic[1]
    womp = _result(f_womp, None)
    screen_sharing = _result(f_ss, {}) or {}
    if not isinstance(screen_sharing, dict):
        screen_sharing = {}
    try:
        host = screen_sharing.get("host") or _host_ip()
    except Exception:
        host = ""
    return _jsonable({
        "actions": list(_ACTIONS),
        "wol": {
            "enabled": womp,
            "iface": _as_text(dev),
            "mac": _as_text(mac),
            "hint": "Wake-on-LAN can only wake a sleeping machine, and the magic packet "
                    "must come from another device on the LAN; it cannot power on a Mac "
                    "that is fully shut down.",
        },
        "screen_sharing": screen_sharing,
        # Already resolved inside screensharing_status(); host_ip() is cached, so
        # this is a dict read rather than another lookup.
        "host_ip": _as_text(host),
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
    })
