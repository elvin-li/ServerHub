"""Service alert engine + optional Home Assistant notify."""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request

from hub.config import cfg
from hub.paths import BASE
from hub.status import full_status

ALERTS_FILE = BASE / "data" / "alerts.jsonl"
STATE_FILE = BASE / "data" / "alert_state.json"
MAX_ALERTS = 500
_lock = threading.Lock()
_thread: threading.Thread | None = None
_stop = threading.Event()


def _load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {}


def _save_state(st: dict):
    STATE_FILE.parent.mkdir(exist_ok=True)
    STATE_FILE.write_text(json.dumps(st, ensure_ascii=False, indent=2))


def _append_alert(alert: dict):
    ALERTS_FILE.parent.mkdir(exist_ok=True)
    with _lock:
        with open(ALERTS_FILE, "a") as f:
            f.write(json.dumps(alert, ensure_ascii=False) + "\n")
        try:
            lines = ALERTS_FILE.read_text().splitlines()
            if len(lines) > MAX_ALERTS:
                ALERTS_FILE.write_text("\n".join(lines[-MAX_ALERTS:]) + "\n")
        except OSError:
            pass


def list_alerts(limit: int = 50) -> list:
    if not ALERTS_FILE.exists():
        return []
    try:
        lines = [ln for ln in ALERTS_FILE.read_text().splitlines() if ln.strip()]
    except OSError:
        return []
    out = []
    for ln in lines[-limit:]:
        try:
            out.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
    out.reverse()
    return out


def notify_settings() -> dict:
    return ((cfg().get("settings") or {}).get("notify") or {})


def send_ha_notify(title: str, message: str) -> dict:
    n = notify_settings()
    if not n.get("enabled"):
        return {"ok": False, "message": "notify disabled"}
    url = n.get("ha_webhook_url") or n.get("webhook_url")
    if not url:
        base = (n.get("ha_url") or "http://localhost:8123").rstrip("/")
        token = n.get("ha_token")
        service = n.get("ha_service") or "notify.notify"
        if not token:
            return {"ok": False, "message": "no webhook or token configured"}
        parts = service.split(".", 1)
        domain = parts[0] if len(parts) == 2 else "notify"
        svc = parts[1] if len(parts) == 2 else parts[0]
        url = f"{base}/api/services/{domain}/{svc}"
        body = json.dumps({"title": title, "message": message}).encode()
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
    else:
        body = json.dumps({
            "title": title,
            "message": message,
            "text": f"{title}: {message}",
        }).encode()
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return {
                "ok": True,
                "status": r.status,
                "body": r.read()[:200].decode(errors="replace"),
            }
    except urllib.error.HTTPError as e:
        detail = e.read()[:200].decode(errors="replace")
        return {"ok": False, "message": f"HTTP {e.code}: {detail}"}
    except Exception as e:
        return {"ok": False, "message": str(e)}


def _resource_thresholds() -> dict:
    from hub.system_settings_svc import get_thresholds
    return get_thresholds()


def _check_resource_thresholds(prev: dict, new_state: dict, now: int) -> list:
    """OMV/TrueNAS-style CPU/mem/disk threshold alerts with cooldown."""
    th = _resource_thresholds()
    if not th.get("enabled", True):
        return []
    emitted = []
    try:
        from hub import metrics
        # Prefer in-memory last sample — never re-read metrics.jsonl every alert tick
        latest = metrics.latest_sample()
        if latest is None:
            hist = metrics.history(5)
            latest = hist[-1] if hist else None
    except Exception:
        latest = None
    if not latest:
        return []
    cpu_val = latest.get("cpu_used_pct")
    if cpu_val is None:
        cpu_val = latest.get("load_pct")
    checks = [
        ("cpu", cpu_val, th.get("cpu_pct", 90), "CPU"),
        ("mem", latest.get("mem_used_pct"), th.get("mem_pct", 90), "内存"),
        ("disk", latest.get("disk_pct"), th.get("disk_pct", 90), "磁盘"),
    ]
    cooldown = int(th.get("cooldown_sec") or 1800)
    last_fire = prev.get("_resource_last") or {}
    if not isinstance(last_fire, dict):
        last_fire = {}
    new_last = dict(last_fire)
    n = notify_settings()
    for rid, val, limit, label in checks:
        if val is None or limit is None:
            continue
        try:
            val_f = float(val)
            limit_f = float(limit)
        except (TypeError, ValueError):
            continue
        key = f"resource:{rid}"
        over = val_f >= limit_f
        new_state[key] = "warn" if over else "ok"
        old = prev.get(key)
        last_t = int(last_fire.get(rid) or 0)
        if over and (old != "warn" or (now - last_t) >= cooldown):
            alert = {
                "t": now,
                "id": key,
                "name": f"资源 · {label}",
                "kind": "resource",
                "group": "system",
                "level": "warn",
                "event": "problem",
                "detail": f"{val_f:.0f}% ≥ {limit_f:.0f}%",
                "message": f"{label}使用率 {val_f:.0f}%（阈值 {limit_f:.0f}%）",
            }
            _append_alert(alert)
            emitted.append(alert)
            new_last[rid] = now
            if n.get("enabled") and n.get("include_warn", True):
                send_ha_notify("ServerHub 资源告警", alert["message"])
        elif old == "warn" and not over:
            alert = {
                "t": now,
                "id": key,
                "name": f"资源 · {label}",
                "kind": "resource",
                "group": "system",
                "level": "ok",
                "event": "resolved",
                "detail": f"{val_f:.0f}%",
                "message": f"{label}使用率已回落至 {val_f:.0f}%",
            }
            _append_alert(alert)
            emitted.append(alert)
            if n.get("enabled") and n.get("notify_resolve", True):
                send_ha_notify("ServerHub 资源恢复", alert["message"])
    new_state["_resource_last"] = new_last
    return emitted


def check_once(force_status: bool = False) -> list:
    """Emit alerts on transition to down/warn and recovery.

    SSD-friendly: reuses status cache; only rewrites alert_state.json when changed.
    """
    st = full_status(force=force_status)
    prev = _load_state()
    services = {}
    for g in st.get("groups") or []:
        for s in g.get("services") or []:
            services[s["id"]] = s
    now = int(time.time())
    emitted = []
    new_state = {}
    # preserve resource cooldown map
    if isinstance(prev.get("_resource_last"), dict):
        new_state["_resource_last"] = prev["_resource_last"]
    for sid, s in services.items():
        state = s.get("state", "unknown")
        new_state[sid] = state
        old = prev.get(sid)
        if old is None:
            continue
        if state != old and state in ("down", "warn"):
            alert = {
                "t": now,
                "id": sid,
                "name": s.get("name", sid),
                "kind": s.get("kind"),
                "group": s.get("group"),
                "level": state,
                "event": "problem",
                "detail": s.get("detail", ""),
                "message": f"{s.get('name', sid)} 变为 {state}: {s.get('detail', '')}",
            }
            _append_alert(alert)
            emitted.append(alert)
            n = notify_settings()
            if n.get("enabled") and (state == "down" or n.get("include_warn")):
                send_ha_notify("ServerHub 告警", alert["message"])
        elif old in ("down", "warn") and state == "ok":
            alert = {
                "t": now,
                "id": sid,
                "name": s.get("name", sid),
                "kind": s.get("kind"),
                "group": s.get("group"),
                "level": "ok",
                "event": "resolved",
                "detail": s.get("detail", ""),
                "message": f"{s.get('name', sid)} 已恢复",
            }
            _append_alert(alert)
            emitted.append(alert)
            n = notify_settings()
            if n.get("enabled") and n.get("notify_resolve", True):
                send_ha_notify("ServerHub 恢复", alert["message"])
    try:
        emitted.extend(_check_resource_thresholds(prev, new_state, now))
    except Exception:
        pass
    # Only rewrite state file when map actually changed (huge SSD win)
    if new_state != prev:
        _save_state(new_state)
    return emitted


def _loop(interval: int = 90):
    try:
        st = full_status(force=False)
        baseline = {}
        for g in st.get("groups") or []:
            for s in g.get("services") or []:
                baseline[s["id"]] = s.get("state")
        if not STATE_FILE.exists():
            _save_state(baseline)
    except Exception:
        pass
    while not _stop.is_set():
        try:
            # Prefer cache; force at most occasionally via TTL
            check_once(force_status=False)
        except Exception:
            pass
        _stop.wait(max(30, int(interval)))


def start_alerter(interval: int = 90):
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(
        target=_loop, args=(max(30, int(interval)),), daemon=True, name="alert-engine"
    )
    _thread.start()


def stop_alerter(timeout: float = 3.0) -> None:
    """Stop the alert worker cleanly during app shutdown/reload."""
    global _thread
    _stop.set()
    thread = _thread
    if thread and thread.is_alive() and thread is not threading.current_thread():
        thread.join(timeout=timeout)
    _thread = None


def test_notify() -> dict:
    return send_ha_notify("ServerHub 测试", f"通知通道测试 {time.strftime('%H:%M:%S')}")
