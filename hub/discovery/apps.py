from __future__ import annotations

from hub.config import cfg
from hub.host_address import resolve_value
from hub.util import port_open, sh


def collect_apps(engine_up):
    items = []
    for raw in cfg().get("apps") or []:
        a = resolve_value(raw)
        if a.get("container_engine") or a.get("docker_engine"):
            items.append({"id": a["id"], "kind": "app-engine", "name": a.get("name", "OrbStack"),
                          "state": "ok" if engine_up else "down",
                          "detail": "OrbStack 引擎运行中" if engine_up else "OrbStack 引擎未运行",
                          "url": a.get("url"), "group": a.get("group", "应用"),
                          "actions": ["stop"] if engine_up else ["start"]})
            continue
        rc, _, _ = sh(["pgrep", "-x", a["process"]], timeout=3)
        running = rc == 0
        p = port_open(a.get("port"))
        state = "ok" if running and p in (None, True) else ("warn" if running else "down")
        detail = (f"运行中 · :{a['port']}" if p else "运行中") if running else "已停止"
        items.append({"id": a["id"], "kind": "app", "name": a.get("name", a["id"]),
                      "state": state, "detail": detail, "url": a.get("url"),
                      "group": a.get("group", "应用"),
                      "actions": ["restart", "stop"] if running else ["start"]})
    return items


def collect_scripts():
    items = []
    for raw in cfg().get("scripts") or []:
        s = resolve_value(raw)
        ports = s.get("ports") or []
        up = [p for p in ports if port_open(p)]
        if len(up) == len(ports) and ports:
            state, detail = "ok", "运行中 · " + " ".join(f":{p}" for p in ports)
        elif up:
            state = "warn"
            downp = [p for p in ports if p not in up]
            detail = f"部分运行 · 缺 {' '.join(':'+str(p) for p in downp)}"
        else:
            state, detail = "down", "已停止"
        items.append({"id": s["id"], "kind": "script", "name": s.get("name", s["id"]),
                      "state": state, "detail": detail, "url": s.get("url"),
                      "group": s.get("group", "自定义"), "links": s.get("links"),
                      "actions": ["restart", "stop"] if up else ["start"]})
    return items
