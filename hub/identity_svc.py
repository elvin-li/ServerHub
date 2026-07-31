"""System identification (Unraid Identification settings)."""
from __future__ import annotations

import platform

from hub.config import cfg, update_settings
from hub.host_address import configured_host, host_ip as effective_host_ip
from hub.util import sh


def get_identity() -> dict:
    rc, hostname, _ = sh(["/bin/hostname"], timeout=3)
    rc2, comp, _ = sh(["/usr/sbin/scutil", "--get", "ComputerName"], timeout=3)
    rc3, local, _ = sh(["/usr/sbin/scutil", "--get", "LocalHostName"], timeout=3)
    rc4, model, _ = sh(["/usr/sbin/sysctl", "-n", "hw.model"], timeout=3)
    s = cfg().get("settings") or {}
    return {
        "hostname": hostname if rc == 0 else platform.node(),
        "computer_name": comp if rc2 == 0 else "",
        "local_hostname": local if rc3 == 0 else "",
        "model": model if rc4 == 0 else platform.machine(),
        "platform": platform.platform(),
        "arch": platform.machine(),
        "host_ip": effective_host_ip(),
        "host_ip_config": configured_host(),
        "comment": s.get("server_comment") or s.get("description") or "",
        "timezone": time_zone(),
    }


def time_zone() -> str:
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
        msgs.append("已更新面板设置")
    if computer_name:
        # Try without sudo first
        rc, out, err = sh(["/usr/sbin/scutil", "--set", "ComputerName", computer_name], timeout=5)
        if rc != 0:
            msgs.append(f"ComputerName 需管理员权限: {err or out}")
        else:
            msgs.append("已设置 ComputerName")
            sh(["/usr/sbin/scutil", "--set", "LocalHostName", computer_name.replace(" ", "-")[:63]], timeout=5)
    return {"ok": True, "message": "; ".join(msgs) or "无变更", "identity": get_identity()}
