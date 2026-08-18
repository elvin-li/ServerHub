"""System identification (Unraid Identification settings)."""
from __future__ import annotations

import platform

from hub.config import cfg, update_settings
from hub.host_address import configured_host, host_ip as effective_host_ip
from hub.util import LazyPool, sh, ttl_memo

_pool = LazyPool(7, "hub-identity")


def shutdown_executor() -> None:
    _pool.shutdown()


@ttl_memo(300.0)
def platform_string() -> str:
    """``platform.platform()``, which is not the string formatting it looks like.

    On macOS it shells out twice: ``uname -p``, and then ``file -b`` on the Python
    binary via ``platform.architecture()``. ``platform.uname()`` is cached inside the
    standard library but ``architecture()`` is not, and two callers reaching it
    concurrently on a cold interpreter each pay -- which is what one
    ``/api/diagnostics`` bundle did, since both this module and the bundle header want
    the string. Single-flight, so they share one answer.

    Process-static in practice: the OS version and the interpreter do not change under
    a running panel.
    """
    return platform.platform()


def get_identity() -> dict:
    # Seven independent reads that used to run partly in series: five in a pool, and
    # then `platform.platform()` (two spawns) and the LAN address (two more) after it,
    # in the return dict itself -- four spawns of pure tail on a request the Settings
    # page makes on every open. Nothing here feeds anything else, so it is one wave.
    f_host = _pool.submit(sh, ["/bin/hostname"], timeout=3)
    f_comp = _pool.submit(sh, ["/usr/sbin/scutil", "--get", "ComputerName"], timeout=3)
    f_local = _pool.submit(sh, ["/usr/sbin/scutil", "--get", "LocalHostName"], timeout=3)
    f_model = _pool.submit(sh, ["/usr/sbin/sysctl", "-n", "hw.model"], timeout=3)
    f_tz = _pool.submit(time_zone)
    f_platform = _pool.submit(platform_string)
    f_ip = _pool.submit(effective_host_ip)

    def _result(fut, fallback):
        try:
            return fut.result()
        except Exception:
            return fallback

    # `.result()` re-raises; one scutil/sysctl miss must not 500 Settings.
    rc, hostname, _ = _result(f_host, (1, "", ""))
    rc2, comp, _ = _result(f_comp, (1, "", ""))
    rc3, local, _ = _result(f_local, (1, "", ""))
    rc4, model, _ = _result(f_model, (1, "", ""))
    tz = _result(f_tz, "") or ""
    platform_name = _result(f_platform, "") or ""
    host_ip = _result(f_ip, "") or ""
    s = cfg().get("settings") or {}
    return {
        "hostname": hostname if rc == 0 else platform.node(),
        "computer_name": comp if rc2 == 0 else "",
        "local_hostname": local if rc3 == 0 else "",
        "model": model if rc4 == 0 else platform.machine(),
        "platform": platform_name,
        "arch": platform.machine(),
        "host_ip": host_ip,
        "host_ip_config": configured_host(),
        "comment": s.get("server_comment") or s.get("description") or "",
        "timezone": tz,
    }


@ttl_memo(60.0)
def time_zone() -> str:
    """The zone name behind /etc/localtime.

    Memoised because two of the sections in one ``/api/diagnostics`` bundle want it --
    ``get_datetime_info`` and ``get_identity`` -- and they run concurrently, so the
    read happened twice per request. The panel has no path that changes the timezone
    (the Settings page points the operator at System Settings for it), and the symlink
    does not move on its own, so a short TTL is enough and there is nothing to
    invalidate on.

    Single-flight matters here rather than incidentally: both callers sit inside the
    same fan-out, so without it they miss the cold cache together and each pays.

    The second probe is a fallback, not a second question: `ls -l` is tried first
    because it works when /etc/localtime is a regular file, and `readlink` covers the
    symlink case. Only one of them runs on a given host.
    """
    rc, out, _ = sh(["/bin/ls", "-l", "/etc/localtime"], timeout=3)
    if rc == 0 and "zoneinfo/" in out:
        return out.split("zoneinfo/")[-1].strip()
    rc, out, _ = sh(["/usr/bin/readlink", "/etc/localtime"], timeout=3)
    if "zoneinfo/" in (out or ""):
        return out.split("zoneinfo/")[-1].strip()
    return ""


def set_identity(computer_name: str | None = None, comment: str | None = None, host_ip: str | None = None) -> dict:
    """Update panel-stored identity; ComputerName needs user approval via scutil (may need admin)."""
    patch = {}
    msgs = []
    if comment is not None:
        patch["server_comment"] = comment
    if host_ip is not None:
        patch["host_ip"] = host_ip.strip()
    if patch:
        update_settings(patch)
        msgs.append("Panel settings updated")
    if computer_name:
        # Try without sudo first
        rc, out, err = sh(["/usr/sbin/scutil", "--set", "ComputerName", computer_name], timeout=5)
        if rc != 0:
            msgs.append(f"Setting ComputerName needs administrator privileges: {err or out}")
        else:
            msgs.append("ComputerName set")
            sh(["/usr/sbin/scutil", "--set", "LocalHostName", computer_name.replace(" ", "-")[:63]], timeout=5)
    return {"ok": True, "message": "; ".join(msgs) or "No changes", "identity": get_identity()}
