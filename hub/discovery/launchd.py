from __future__ import annotations

import glob
import plistlib
from pathlib import Path

from hub.adaptive import (
    enrich_service,
    friendly_name,
    guess_group,
    ports_for_pid,
    ports_from_plist,
    url_from_plist,
)
from hub.config import override
from hub.host_address import resolve_template
from hub.paths import AGENTS_DIR
from hub.util import port_open, sh


def launchctl_table():
    _, out, _ = sh(["launchctl", "list"], timeout=5)
    t = {}
    for line in out.splitlines():
        p = line.split("\t")
        if len(p) == 3:
            t[p[2]] = (p[0], p[1])
    return t


def discover_launchd():
    table = launchctl_table()
    items = []
    for path in sorted(glob.glob(f"{AGENTS_DIR}/*.plist")):
        label = Path(path).stem
        ov = override(label)
        if ov.get("hide"):
            continue
        try:
            with open(path, "rb") as f:
                pl = plistlib.load(f)
        except Exception:
            pl = {}
        interval = bool(pl.get("StartInterval") or pl.get("StartCalendarInterval"))
        pid, last = table.get(label, (None, None))
        loaded, running = pid is not None, pid not in (None, "-")

        # Adaptive port: override → plist args/env → live pid lsof
        port = ov.get("port")
        detected = ports_from_plist(pl)
        if port is None and detected:
            port = detected[0]
        if port is None and running and pid not in (None, "-"):
            live = ports_for_pid(pid)
            if live:
                port = live[0]
                detected = live

        url = resolve_template(ov.get("url") or url_from_plist(pl))
        name = ov.get("name") or friendly_name(label)
        group = ov.get("group") or guess_group(label, pl, interval)

        p = port_open(port) if port else None
        if interval:
            state = "ok" if loaded and last in ("0", None) else ("down" if not loaded else "warn")
            detail = (
                ("已加载 · 定时任务" + (f" · 上次退出码 {last}" if last not in (None, "0") else ""))
                if loaded else "未加载"
            )
            actions = ["run", "logs"] + (["stop"] if loaded else ["start"])
        elif running and (p is None or p):
            state = "ok"
            detail = f"运行中 · pid {pid}" + (f" · :{port}" if port else "")
            actions = ["restart", "stop", "logs"]
        elif running:
            state, detail, actions = "warn", f"进程在但端口 :{port} 未响应", ["restart", "stop", "logs"]
        else:
            state, detail, actions = "down", ("已加载未运行" if loaded else "未加载"), ["start", "logs"]
        if url and "open" not in actions:
            actions = list(actions) + ["open"]

        item = {
            "id": label,
            "kind": "launchd",
            "name": name,
            "state": state,
            "detail": detail,
            "url": url,
            "group": group,
            "actions": actions,
            "port": port,
        }
        if detected:
            item["meta"] = {"detected_ports": detected, "adaptive": not bool(ov.get("port"))}
            if not ov.get("port") or not ov.get("url") or not ov.get("name"):
                item["auto"] = True
        # keep enrich for any remaining gaps
        item = enrich_service(item, pl=pl, pid=pid if running else None)
        items.append(item)
    return items
