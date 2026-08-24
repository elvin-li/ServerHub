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

from hub.util import safe_json_loads

# Port must match the panel (install.sh writes SERVERHUB_PORT into the plist).
API = f"http://127.0.0.1:{os.environ.get('SERVERHUB_PORT', '8086')}"
#: install.sh writes local.serverhub.panel; older trees used the other two.
_PANEL_LABELS = (
    "local.serverhub.panel",
    "local.serverhub",
    "com.elvin.serverhub",
)
LOCAL_TOKEN_FILE = Path(__file__).resolve().parent / "data" / ".local-client-token"
#: Leftover multi-MB junk in the token file used to OOM every 30s poll.
_TOKEN_CAP = 4096
#: ``json.load(urlopen(...))`` of leftover multi-MB /api/status used to OOM
#: the same rumps timer.  A full status peek is tens of KB.
_BODY_CAP = 256 * 1024
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
        "notify_done": "✅ 完成 {message}",
        "notify_fail": "❌ 失败 {message}",
        "confirm_maint": "确定执行「{name}」？",
        "alert_ok": "执行",
        "alert_cancel": "取消",
        "maint_started": "🚀 已开始，日志在面板查看",
        "maint_start_fail": "❌ 启动失败 {e}",
        "docker_start_all": "启动全部容器",
        "docker_stop_all": "停止全部容器",
        "docker_restart_all": "重启全部容器",
        "confirm_docker": "确定{action}？",
        "docker_error": "❌ {e}",
        "docker_page": "📦 Docker 页",
        "storage_array": "💾 存储阵列",
        "docker_shortcuts": "📦 Docker 快捷",
        "start_all": "▶️ 全部启动",
        "stop_all": "⏹ 全部停止",
        "restart_all": "🔄 全部重启",
        "maintenance": "🧰 维护与更新",
        "group_counts": "{head} {group}（{ok}/{total}）",
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
        "notify_done": "✅ Done {message}",
        "notify_fail": "❌ Failed {message}",
        "confirm_maint": "Run “{name}”?",
        "alert_ok": "Run",
        "alert_cancel": "Cancel",
        "maint_started": "🚀 Started — view logs in the panel",
        "maint_start_fail": "❌ Failed to start {e}",
        "docker_start_all": "Start all containers",
        "docker_stop_all": "Stop all containers",
        "docker_restart_all": "Restart all containers",
        "confirm_docker": "{action}?",
        "docker_error": "❌ {e}",
        "docker_page": "📦 Docker Page",
        "storage_array": "💾 Storage Array",
        "docker_shortcuts": "📦 Docker Shortcuts",
        "start_all": "▶️ Start All",
        "stop_all": "⏹ Stop All",
        "restart_all": "🔄 Restart All",
        "maintenance": "🧰 Maintenance & Updates",
        "group_counts": "{head} {group} ({ok}/{total})",
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
        "notify_done": "✅ 完了 {message}",
        "notify_fail": "❌ 失敗 {message}",
        "confirm_maint": "「{name}」を実行しますか？",
        "alert_ok": "実行",
        "alert_cancel": "キャンセル",
        "maint_started": "🚀 開始しました。ログはパネルで確認",
        "maint_start_fail": "❌ 起動に失敗 {e}",
        "docker_start_all": "すべてのコンテナを起動",
        "docker_stop_all": "すべてのコンテナを停止",
        "docker_restart_all": "すべてのコンテナを再起動",
        "confirm_docker": "{action}しますか？",
        "docker_error": "❌ {e}",
        "docker_page": "📦 Docker ページ",
        "storage_array": "💾 ストレージ",
        "docker_shortcuts": "📦 Docker ショートカット",
        "start_all": "▶️ すべて起動",
        "stop_all": "⏹ すべて停止",
        "restart_all": "🔄 すべて再起動",
        "maintenance": "🧰 メンテナンスと更新",
        "group_counts": "{head} {group}（{ok}/{total}）",
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
    if not params:
        return template
    safe = {}
    for name, value in params.items():
        try:
            safe[name] = _utf8_text(value)
        except Exception:
            continue
    try:
        out = template.format(**safe)
    except (KeyError, IndexError, ValueError, TypeError, RecursionError, OverflowError):
        # RecursionError: leftover recursive ``__format__``/``__str__`` is not
        # ValueError; OverflowError: leftover inf width/precision. Either used
        # to take the 30s rumps timer down after api_status already succeeded.
        out = template
    try:
        return _utf8_text(out)
    except Exception:
        return template


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


def _utf8_text(value):
    """Drop leftover lone surrogates so dumps(ensure_ascii=False) can encode."""
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    return str(value).encode("utf-8", "replace").decode("utf-8")


def _jsonable(value, depth=0):
    """Coerce leftovers so json.dumps(..., allow_nan=False) cannot crash.

    Leftover ``inf`` / ``bytes`` / ``\\ud800`` in a status peek, sensors
    light row, or action body used to TypeError / ValueError the menu
    signature and POST body dumps.
    """
    if depth > 32:
        return None
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if isinstance(value, str):
        return _utf8_text(value)
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
            out[_utf8_text(k)] = _jsonable(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v, depth + 1) for v in value]
    try:
        return _utf8_text(value)
    except Exception:
        return None


def _as_dict(value):
    return value if isinstance(value, dict) else {}


def _as_list(value):
    return value if isinstance(value, list) else []


def _local_token() -> str:
    """Loopback token. Leftover multi-MB junk used to OOM every poll."""
    try:
        with open(LOCAL_TOKEN_FILE, "rb") as fh:
            raw = fh.read(_TOKEN_CAP + 1)
    except OSError:
        return ""
    if len(raw) > _TOKEN_CAP:
        return ""
    return raw.decode("utf-8", "replace").strip()


def _json(url, method="GET", data=None, timeout=10):
    body = None
    headers = {}
    token = _local_token()
    if token:
        headers["X-ServerHub-Local-Token"] = token
    if data is not None:
        try:
            body = json.dumps(
                _jsonable(data), ensure_ascii=False, allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError, OverflowError) as exc:
            return {"ok": False, "message": str(exc)}
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, method=method, data=body, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        try:
            raw = r.read(_BODY_CAP + 1)
        except OSError:
            return {}
        if len(raw) > _BODY_CAP:
            return {}
        try:
            return safe_json_loads(raw)
        except (ValueError, RecursionError, TypeError):
            return {}


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
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
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
    Leftover inf / bytes / ``\\ud800`` used to crash ``json.dumps`` here
    (no ``allow_nan=False``) and take the rumps timer down with it.
    """
    status = _as_dict(status)
    groups = []
    for group in _as_list(status.get("groups")):
        if not isinstance(group, dict):
            continue
        services = []
        for service in _as_list(group.get("services")):
            if not isinstance(service, dict):
                continue
            services.append({
                "id": service.get("id"),
                "name": service.get("name"),
                "state": service.get("state"),
                "url": service.get("url"),
                # Part of the row label now, so a port change must rebuild.
                "port": service.get("port"),
                "actions": _as_list(service.get("actions")),
                "links": _as_list(service.get("links")),
            })
        groups.append({"group": group.get("group"), "services": services})
    shape = {
        "locale": _normalize_locale(status.get("locale")),
        "counts": _as_dict(status.get("counts")),
        "groups": groups,
        "problems": [
            p.get("id") for p in _as_list(status.get("problems"))
            if isinstance(p, dict)
        ],
        "links": [
            link for link in _as_list(status.get("links"))
            if isinstance(link, dict)
        ],
        "tasks": [
            {
                "id": task.get("id"),
                "name": task.get("name"),
                "running": bool(task.get("running")),
                "confirm": bool(task.get("confirm")),
            }
            for task in _as_list(tasks)
            if isinstance(task, dict)
        ],
    }
    return json.dumps(
        _jsonable(shape),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


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
            loc = self._locale
            key = "notify_done" if res.get("ok") else "notify_fail"
            rumps.notification(
                "ServerHub", name,
                _t(loc, key, message=str(res.get("message", ""))[:120]),
            )
            self.tick(None)
        return cb

    def make_maint(self, t):
        def cb(_):
            loc = self._locale
            if t.get("confirm"):
                if rumps.alert(
                    title="ServerHub",
                    message=_t(loc, "confirm_maint", name=t["name"]),
                    ok=_t(loc, "alert_ok"), cancel=_t(loc, "alert_cancel"),
                ) != 1:
                    return
            try:
                _json(f"{API}/api/maintenance/{t['id']}/run", method="POST", timeout=10)
                rumps.notification("ServerHub", t["name"], _t(loc, "maint_started"))
                webbrowser.open(API)
            except Exception as e:
                rumps.notification(
                    "ServerHub", t["name"], _t(loc, "maint_start_fail", e=e),
                )
        return cb

    def docker_all(self, action):
        def cb(_):
            loc = self._locale
            labels = {
                "start": _t(loc, "docker_start_all"),
                "stop": _t(loc, "docker_stop_all"),
                "restart": _t(loc, "docker_restart_all"),
            }
            if action in ("stop", "restart"):
                if rumps.alert(
                    title="ServerHub",
                    message=_t(loc, "confirm_docker", action=labels.get(action, action)),
                    ok=_t(loc, "alert_ok"), cancel=_t(loc, "alert_cancel"),
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
                rumps.notification(
                    "ServerHub", "Docker", _t(loc, "docker_error", e=e),
                )
            self.tick(None)
        return cb

    def svc_item(self, s):
        # Show the port on the row itself.  Knowing a service is green is only
        # half the answer — the next question is always "on which port", and
        # opening the panel just to read a number is a detour.  Prefer the
        # port the API reports, else recover it from the URL (an explicit
        # :port, otherwise the scheme default).
        s = _as_dict(s)
        port = s.get("port") or _port_of(s.get("url"))
        title = f"{DOT.get(s.get('state'), '⚪')} {s.get('name') or s.get('id') or '?'}"
        if port:
            title += f"  :{port}"
        item = rumps.MenuItem(_utf8_text(title))
        act = _act(self._locale)
        if s.get("url"):
            # Spell out the target so the click is predictable, and so the LAN
            # address can be read off (and typed into a phone) directly.
            item.add(rumps.MenuItem(
                _t(self._locale, "open_url", url=s["url"]),
                callback=lambda _, u=s["url"]: webbrowser.open(u),
            ))
        for l in _as_list(s.get("links")):
            if not isinstance(l, dict) or not l.get("url"):
                continue
            item.add(rumps.MenuItem(
                f"🌐 {_utf8_text(l.get('name') or l.get('url'))}",
                callback=lambda _, u=l["url"]: webbrowser.open(u),
            ))
        for a in _as_list(s.get("actions")):
            if a not in act:
                continue
            item.add(rumps.MenuItem(
                act[a], callback=self.make_action(s.get("id"), a, s.get("name") or s.get("id")),
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

        try:
            self._rebuild_menu(d)
        except Exception:
            # Status already arrived. Leftover group/action values used to
            # RecursionError ``_t`` / rebuild and kill the 30s timer; keep the
            # last menu instead of flipping offline.
            return

    def _rebuild_menu(self, d):
        self._locale = _normalize_locale(d.get("locale") if isinstance(d, dict) else None)
        loc = self._locale
        c = _as_dict(_as_dict(d).get("counts"))
        down, warn, ok_n = c.get("down") or 0, c.get("warn") or 0, c.get("ok") or 0
        self.title = (
            "🖥" if not (down or warn)
            else f"🖥{'🔴' + str(down) if down else '🟡'}"
        )

        try:
            tasks = _json(f"{API}/api/maintenance", timeout=4)
        except Exception:
            tasks = []
        if not isinstance(tasks, list):
            tasks = []

        summary_title = _t(loc, "summary", ok=ok_n, warn=warn, down=down)
        system = _as_dict(_as_dict(d).get("system"))
        if system:
            summary_title += f" · load {system.get('load1', '')}"
        state = _menu_signature(d, tasks)
        if state == self._menu_state and self._summary_item is not None:
            self._summary_item.title = summary_title
            return

        summary_item = rumps.MenuItem(summary_title, callback=lambda _: webbrowser.open(API))
        menu = [
            summary_item,
            rumps.MenuItem(_t(loc, "open_panel"), callback=lambda _: webbrowser.open(API)),
            rumps.MenuItem(_t(loc, "docker_page"), callback=lambda _: webbrowser.open(API + "/containers")),
            rumps.MenuItem(_t(loc, "storage_array"), callback=lambda _: webbrowser.open(API + "/main")),
            None,
        ]

        # Problems first (Unraid-style attention)
        problems = [
            s for s in _as_list(_as_dict(d).get("problems")) if isinstance(s, dict)
        ]
        if problems:
            pi = rumps.MenuItem(_t(loc, "needs_attention", n=len(problems)))
            for s in problems[:12]:
                pi.add(self.svc_item(s))
            menu.append(pi)
            menu.append(None)

        for grp in _as_list(_as_dict(d).get("groups")):
            if not isinstance(grp, dict):
                continue
            items = [s for s in _as_list(grp.get("services")) if isinstance(s, dict)]
            bad = [s for s in items if s.get("state") not in ("ok", "stopped")]
            if len(items) == 1:
                menu.append(self.svc_item(items[0]))
                continue
            if not items:
                continue
            head = DOT["ok"] if not bad else DOT[
                "down" if any(s.get("state") == "down" for s in bad) else "warn"
            ]
            gi = rumps.MenuItem(
                _t(
                    loc, "group_counts",
                    head=head,
                    group=grp.get("group") or "Other",
                    ok=len(items) - len(bad),
                    total=len(items),
                )
            )
            for s in items:
                gi.add(self.svc_item(s))
            menu.append(gi)

        menu.append(None)
        di = rumps.MenuItem(_t(loc, "docker_shortcuts"))
        di.add(rumps.MenuItem(_t(loc, "start_all"), callback=self.docker_all("start")))
        di.add(rumps.MenuItem(_t(loc, "stop_all"), callback=self.docker_all("stop")))
        di.add(rumps.MenuItem(_t(loc, "restart_all"), callback=self.docker_all("restart")))
        menu.append(di)

        if tasks:
            mi = rumps.MenuItem(_t(loc, "maintenance"))
            for t in tasks:
                if not isinstance(t, dict):
                    continue
                lbl = ("⏳ " if t.get("running") else "") + str(t.get("name") or t.get("id") or "")
                mi.add(rumps.MenuItem(lbl, callback=self.make_maint(t)))
            menu.append(mi)

        for l in _as_list(_as_dict(d).get("links"))[:6]:
            if not isinstance(l, dict) or not l.get("url"):
                continue
            menu.append(rumps.MenuItem(
                f"🔗 {l.get('name') or l.get('url')}",
                callback=lambda _, u=l["url"]: webbrowser.open(u),
            ))
        menu += [
            None,
            rumps.MenuItem(_t(self._locale, "quit"), callback=lambda _: rumps.quit_application()),
        ]
        self.replace_menu(menu, state, summary_item)


if __name__ == "__main__":
    ServerHubBar().run()
