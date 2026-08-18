#!/usr/bin/env python3
"""ServerHub menu bar — dynamic thin client over the panel API (:8086)."""
import json
import gc
import os
import subprocess
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path
from urllib.parse import urlsplit

import rumps
from rumps.rumps import NSApp

# Port must match the panel (install.sh writes SERVERHUB_PORT into the plist).
API = f"http://127.0.0.1:{os.environ.get('SERVERHUB_PORT', '8086')}"
#: install.sh writes local.serverhub.panel; older trees used the other two.
_PANEL_LABELS = (
    "local.serverhub.panel",
    "local.serverhub",
    "com.elvin.serverhub",
)
LOCAL_TOKEN_FILE = Path(__file__).resolve().parent / "data" / ".local-client-token"
REFRESH_SECONDS = 30
DOT = {"ok": "🟢", "warn": "🟡", "down": "🔴"}
_SCHEME_PORTS = {"http": 80, "https": 443}

_MENU = {
    "zh-CN": {
        "open_panel": "打开 ServerHub 面板",
        "needs_attention": "⚠️ 需处理（{n}）",
        "summary": "{ok} 正常 · {warn} 警告 · {down} 停止",
        "backend_down": "⚠️ 面板后端 (8086) 无响应",
        "start_panel": "▶️ 启动面板服务",
        "quit": "❌ 退出图标",
        "open_url": "🌐 打开 {url}",
        "restart": "🔄 重启",
        "stop": "⏹ 停止",
        "start": "▶️ 启动",
        "run": "⚡ 立即运行",
    },
    "en": {
        "open_panel": "Open ServerHub Panel",
        "needs_attention": "⚠️ Needs Attention ({n})",
        "summary": "{ok} OK · {warn} warnings · {down} down",
        "backend_down": "⚠️ ServerHub Backend Unavailable",
        "start_panel": "▶️ Start ServerHub",
        "quit": "❌ Quit Menu Bar App",
        "open_url": "🌐 Open {url}",
        "restart": "🔄 Restart",
        "stop": "⏹ Stop",
        "start": "▶️ Start",
        "run": "⚡ Run Now",
    },
    "ja": {
        "open_panel": "ServerHub パネルを開く",
        "needs_attention": "⚠️ 要確認（{n}）",
        "summary": "{ok} 正常 · {warn} 警告 · {down} 障害",
        "backend_down": "⚠️ ServerHub バックエンドが応答しません",
        "start_panel": "▶️ ServerHub を起動",
        "quit": "❌ メニューバーアプリを終了",
        "open_url": "🌐 {url} を開く",
        "restart": "🔄 再起動",
        "stop": "⏹ 停止",
        "start": "▶️ 開始",
        "run": "⚡ 今すぐ実行",
    },
}


def _normalize_locale(raw):
    text = str(raw or "").strip().lower()
    if text.startswith("zh"):
        return "zh-CN"
    if text.startswith("ja"):
        return "ja"
    if text.startswith("en"):
        return "en"
    return "zh-CN"


def _t(locale, key, **params):
    table = _MENU.get(locale) or _MENU["zh-CN"]
    template = table.get(key) or _MENU["en"].get(key) or key
    return template.format(**params) if params else template


def _act(locale):
    return {
        "restart": _t(locale, "restart"),
        "stop": _t(locale, "stop"),
        "start": _t(locale, "start"),
        "run": _t(locale, "run"),
    }


def _port_of(url):
    """Best-effort port for a service URL, or None.

    Services configured with an explicit ``port`` are easy; the rest only carry
    a URL, so recover the number from it — an explicit ``:port`` when present,
    otherwise the scheme default. Never raises: a malformed URL just yields no
    port, and the row falls back to showing the name alone.
    """
    if not url:
        return None
    try:
        parts = urlsplit(str(url))
        if parts.port:
            return parts.port
        return _SCHEME_PORTS.get(parts.scheme)
    except ValueError:
        return None


def _json(url, method="GET", data=None, timeout=10):
    body = None
    headers = {}
    try:
        token = LOCAL_TOKEN_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        token = ""
    if token:
        headers["X-ServerHub-Local-Token"] = token
    if data is not None:
        body = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, method=method, data=body, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def api_status():
    return _json(f"{API}/api/status", timeout=5)


def api_action(target, action):
    try:
        return _json(f"{API}/api/action", method="POST",
                     data={"target": target, "action": action}, timeout=120)
    except Exception as e:
        return {"ok": False, "message": str(e)}


def _kickstart_panel():
    """Start whichever panel launchd label is actually installed."""
    uid = os.getuid()
    for label in _PANEL_LABELS:
        try:
            result = subprocess.run(
                ["/bin/launchctl", "kickstart", "-k", f"gui/{uid}/{label}"],
                capture_output=True,
                timeout=10,
            )
        except subprocess.TimeoutExpired:
            continue
        if result.returncode == 0:
            return


def _menu_signature(status, tasks):
    """Return only the state that changes menu structure or callbacks.

    Volatile metrics such as load average are deliberately excluded so a
    normal polling tick does not rebuild the native NSMenu object graph.
    """
    groups = []
    for group in status.get("groups") or []:
        services = []
        for service in group.get("services") or []:
            services.append({
                "id": service.get("id"),
                "name": service.get("name"),
                "state": service.get("state"),
                "url": service.get("url"),
                # Part of the row label now, so a port change must rebuild.
                "port": service.get("port"),
                "actions": service.get("actions") or [],
                "links": service.get("links") or [],
            })
        groups.append({"group": group.get("group"), "services": services})
    shape = {
        "locale": _normalize_locale(status.get("locale")),
        "counts": status.get("counts") or {},
        "groups": groups,
        "problems": [p.get("id") for p in (status.get("problems") or [])],
        "links": status.get("links") or [],
        "tasks": [
            {
                "id": task.get("id"),
                "name": task.get("name"),
                "running": bool(task.get("running")),
                "confirm": bool(task.get("confirm")),
            }
            for task in tasks
        ],
    }
    return json.dumps(shape, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _forget_callbacks(menu):
    """Release rumps' global callback references before removing a menu.

    rumps keeps callbacks in a process-global dictionary and Menu.clear()
    does not remove them. Rebuilding a menu on every poll therefore retains
    every old NSMenuItem and callback indefinitely.
    """
    for item in tuple(menu.values()):
        if hasattr(item, "values"):
            _forget_callbacks(item)
        native_item = getattr(item, "_menuitem", None)
        if native_item is not None:
            NSApp._ns_to_py_and_callback.pop(native_item, None)


class ServerHubBar(rumps.App):
    def __init__(self):
        super().__init__(name="ServerHub", title="🖥", quit_button=None)
        self._menu_state = None
        self._summary_item = None
        self._locale = "zh-CN"
        self.timer = rumps.Timer(self.tick, REFRESH_SECONDS)
        self.timer.start()
        self.tick(None)

    def replace_menu(self, menu, state, summary_item=None):
        _forget_callbacks(self.menu)
        self.menu.clear()
        self.menu = menu
        self._menu_state = state
        self._summary_item = summary_item
        gc.collect()

    def make_action(self, target, action, name):
        def cb(_):
            res = api_action(target, action)
            rumps.notification(
                "ServerHub", name,
                ("✅ 完成 " if res.get("ok") else "❌ 失败 ")
                + str(res.get("message", ""))[:120],
            )
            self.tick(None)
        return cb

    def make_maint(self, t):
        def cb(_):
            if t.get("confirm"):
                if rumps.alert(
                    title="ServerHub", message=f"确定执行「{t['name']}」？",
                    ok="执行", cancel="取消",
                ) != 1:
                    return
            try:
                _json(f"{API}/api/maintenance/{t['id']}/run", method="POST", timeout=10)
                rumps.notification("ServerHub", t["name"], "🚀 已开始，日志在面板查看")
                webbrowser.open(API)
            except Exception as e:
                rumps.notification("ServerHub", t["name"], f"❌ 启动失败 {e}")
        return cb

    def docker_all(self, action):
        def cb(_):
            labels = {"start": "启动全部容器", "stop": "停止全部容器", "restart": "重启全部容器"}
            if action in ("stop", "restart"):
                if rumps.alert(
                    title="ServerHub", message=f"确定{labels.get(action, action)}？",
                    ok="执行", cancel="取消",
                ) != 1:
                    return
            try:
                j = _json(
                    f"{API}/api/containers/all", method="POST",
                    data={"action": action}, timeout=180,
                )
                rumps.notification(
                    "ServerHub", "Docker",
                    f"{labels.get(action, action)} {j.get('done', 0)}/{j.get('total', 0)}",
                )
            except Exception as e:
                rumps.notification("ServerHub", "Docker", f"❌ {e}")
            self.tick(None)
        return cb

    def svc_item(self, s):
        # Show the port on the row itself.  Knowing a service is green is only
        # half the answer — the next question is always "on which port", and
        # opening the panel just to read a number is a detour.  Prefer the
        # port the API reports, else recover it from the URL (an explicit
        # :port, otherwise the scheme default).
        port = s.get("port") or _port_of(s.get("url"))
        title = f"{DOT.get(s['state'], '⚪')} {s['name']}"
        if port:
            title += f"  :{port}"
        item = rumps.MenuItem(title)
        act = _act(self._locale)
        if s.get("url"):
            # Spell out the target so the click is predictable, and so the LAN
            # address can be read off (and typed into a phone) directly.
            item.add(rumps.MenuItem(
                _t(self._locale, "open_url", url=s["url"]),
                callback=lambda _, u=s["url"]: webbrowser.open(u),
            ))
        for l in s.get("links") or []:
            item.add(rumps.MenuItem(
                f"🌐 {l['name']}",
                callback=lambda _, u=l["url"]: webbrowser.open(u),
            ))
        for a in s.get("actions") or []:
            if a not in act:
                continue
            item.add(rumps.MenuItem(
                act[a], callback=self.make_action(s["id"], a, s["name"]),
            ))
        return item

    def tick(self, _):
        try:
            d = api_status()
        except Exception:
            loc = self._locale
            self.title = "🖥⚠️"
            if self._menu_state != "offline":
                self.replace_menu([
                    rumps.MenuItem(_t(loc, "backend_down")),
                    rumps.MenuItem(_t(loc, "start_panel"), callback=lambda _: _kickstart_panel()),
                    None,
                    rumps.MenuItem(_t(loc, "quit"), callback=lambda _: rumps.quit_application()),
                ], "offline")
            return

        self._locale = _normalize_locale(d.get("locale"))
        loc = self._locale
        c = d["counts"]
        self.title = (
            "🖥" if not (c["down"] or c["warn"])
            else f"🖥{'🔴' + str(c['down']) if c['down'] else '🟡'}"
        )

        try:
            tasks = _json(f"{API}/api/maintenance", timeout=4)
        except Exception:
            tasks = []

        summary_title = _t(loc, "summary", ok=c["ok"], warn=c["warn"], down=c["down"])
        if d.get("system"):
            summary_title += f" · load {d.get('system', {}).get('load1', '')}"
        state = _menu_signature(d, tasks)
        if state == self._menu_state and self._summary_item is not None:
            self._summary_item.title = summary_title
            return

        summary_item = rumps.MenuItem(summary_title, callback=lambda _: webbrowser.open(API))
        menu = [
            summary_item,
            rumps.MenuItem(_t(loc, "open_panel"), callback=lambda _: webbrowser.open(API)),
            rumps.MenuItem("📦 Docker 页", callback=lambda _: webbrowser.open(API + "/containers")),
            rumps.MenuItem("💾 存储阵列", callback=lambda _: webbrowser.open(API + "/main")),
            None,
        ]

        # Problems first (Unraid-style attention)
        problems = d.get("problems") or []
        if problems:
            pi = rumps.MenuItem(_t(loc, "needs_attention", n=len(problems)))
            for s in problems[:12]:
                pi.add(self.svc_item(s))
            menu.append(pi)
            menu.append(None)

        for grp in d["groups"]:
            items = grp["services"]
            bad = [s for s in items if s["state"] not in ("ok", "stopped")]
            if len(items) == 1:
                menu.append(self.svc_item(items[0]))
                continue
            head = DOT["ok"] if not bad else DOT[
                "down" if any(s["state"] == "down" for s in bad) else "warn"
            ]
            gi = rumps.MenuItem(
                f"{head} {grp['group']}（{len(items)-len(bad)}/{len(items)}）"
            )
            for s in items:
                gi.add(self.svc_item(s))
            menu.append(gi)

        menu.append(None)
        di = rumps.MenuItem("📦 Docker 快捷")
        di.add(rumps.MenuItem("▶️ 全部启动", callback=self.docker_all("start")))
        di.add(rumps.MenuItem("⏹ 全部停止", callback=self.docker_all("stop")))
        di.add(rumps.MenuItem("🔄 全部重启", callback=self.docker_all("restart")))
        menu.append(di)

        if tasks:
            mi = rumps.MenuItem("🧰 维护与更新")
            for t in tasks:
                lbl = ("⏳ " if t.get("running") else "") + t["name"]
                mi.add(rumps.MenuItem(lbl, callback=self.make_maint(t)))
            menu.append(mi)

        for l in (d.get("links") or [])[:6]:
            menu.append(rumps.MenuItem(
                f"🔗 {l['name']}",
                callback=lambda _, u=l["url"]: webbrowser.open(u),
            ))
        menu += [
            None,
            rumps.MenuItem(_t(self._locale, "quit"), callback=lambda _: rumps.quit_application()),
        ]
        self.replace_menu(menu, state, summary_item)


if __name__ == "__main__":
    ServerHubBar().run()
