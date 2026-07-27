"""Bookmark / quick_link health checks — green / gray / red.

health:
  ok      — 可达（绿）
  stopped — 关联服务/VM 主动停止（灰）
  error   — 预期在线但探测失败 / 意外异常（红）
"""
from __future__ import annotations

import concurrent.futures
import time
import urllib.error
import urllib.request

from hub.config import cfg
from hub.host_address import resolve_value

_cache = {"t": 0.0, "v": None}
_TTL = 45.0


def _probe(url: str, timeout: float = 3.0) -> dict:
    import ssl
    t0 = time.time()
    try:
        req = urllib.request.Request(
            url,
            method="GET",
            headers={"User-Agent": "ServerHub-BookmarkProbe/1.0"},
        )
        ctx = ssl._create_unverified_context() if url.startswith("https") else None
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            code = r.status
            r.read(256)
        ms = int((time.time() - t0) * 1000)
        ok = 200 <= code < 400
        return {"ok": ok, "status": code, "ms": ms, "error": None}
    except urllib.error.HTTPError as e:
        ms = int((time.time() - t0) * 1000)
        # 401/403 still means service is up
        ok = e.code in (401, 403)
        return {"ok": ok, "status": e.code, "ms": ms, "error": str(e.reason)}
    except Exception as e:
        ms = int((time.time() - t0) * 1000)
        return {"ok": False, "status": None, "ms": ms, "error": str(e)[:120]}


def _backend_index() -> dict:
    """Map id / name / url → backend runtime info for expected-state checks."""
    idx: dict[str, dict] = {}

    def put(key: str | None, info: dict):
        if not key:
            return
        idx[str(key)] = info
        # also strip common prefixes
        s = str(key)
        if s.startswith("orb:"):
            idx[s[4:]] = info

    try:
        from hub import vms_svc
        for v in (vms_svc.list_utm_vms() or []) + (vms_svc.list_orb_machines() or []):
            info = {
                "state": v.get("state") or "down",
                "status": v.get("status"),
                "kind": "vm",
                "backend": v.get("backend"),
                "name": v.get("name") or v.get("id"),
                "id": v.get("id"),
            }
            put(v.get("id"), info)
            put(v.get("uuid"), info)
            put(v.get("orb_name"), info)
            put(v.get("name"), info)
            if v.get("url"):
                put(f"url:{v['url'].rstrip('/')}", info)
    except Exception:
        pass

    try:
        from hub.discovery.containers import discover_containers
        items, _ = discover_containers()
        for c in items or []:
            info = {
                "state": c.get("state") or "down",
                "status": c.get("detail") or c.get("status"),
                "kind": "container",
                "name": c.get("name") or c.get("id"),
                "id": c.get("id"),
            }
            put(c.get("id"), info)
            put(c.get("name"), info)
            if c.get("url"):
                put(f"url:{c['url'].rstrip('/')}", info)
    except Exception:
        pass

    # overrides: map sid + url → best-effort (may fill gaps for launchd etc.)
    for sid, raw in (cfg().get("overrides") or {}).items():
        ov = resolve_value(raw)
        if sid in idx:
            continue
        # only mark intentionally hidden/disabled as stopped if flag set
        if ov.get("expected") == "stopped" or ov.get("disabled") is True:
            info = {
                "state": "stopped",
                "status": "disabled",
                "kind": "override",
                "name": ov.get("name") or sid,
                "id": sid,
            }
            put(sid, info)
            if ov.get("url"):
                put(f"url:{ov['url'].rstrip('/')}", info)

    return idx


def _resolve_backend(link: dict, idx: dict) -> dict | None:
    """Find linked backend for a bookmark entry."""
    for key in (
        link.get("service"),
        link.get("id"),
        link.get("vm"),
        link.get("backend_id"),
    ):
        if key and key in idx:
            return idx[key]
    url = (link.get("url") or "").rstrip("/")
    if url and f"url:{url}" in idx:
        return idx[f"url:{url}"]
    # match override sid by identical url
    for sid, raw in (cfg().get("overrides") or {}).items():
        ov = resolve_value(raw)
        ou = (ov.get("url") or "").rstrip("/")
        if ou and ou == url and sid in idx:
            return idx[sid]
    return None


def _compose_result(link: dict, probe: dict | None, backend: dict | None) -> dict:
    """Merge HTTP probe + backend expected-state into tri-state health."""
    base = {
        "name": link.get("name"),
        "url": link.get("url"),
        "id": link.get("id") or link.get("service"),
        "service": link.get("service") or link.get("id"),
    }
    b_state = (backend or {}).get("state")
    # intentional stop / suspended (treat suspended as stopped-ish warn gray? user said 主动停止=灰)
    if b_state in ("stopped", "down") and (backend or {}).get("kind") == "vm":
        # VM: "stopped" = intentional; legacy "down" from old code treated as stopped for VMs
        # after our fix VMs use "stopped"; keep both
        if b_state == "stopped" or (backend or {}).get("status") in (
            "stopped", "stop", "exited", "created", "shutdown"
        ):
            return {
                **base,
                "ok": False,
                "health": "stopped",
                "status": None,
                "ms": None,
                "error": None,
                "reason": "backend_stopped",
                "backend": {
                    "id": backend.get("id"),
                    "name": backend.get("name"),
                    "kind": backend.get("kind"),
                    "state": backend.get("state"),
                    "status": backend.get("status"),
                },
            }
    if b_state == "stopped":
        return {
            **base,
            "ok": False,
            "health": "stopped",
            "status": None,
            "ms": None,
            "error": None,
            "reason": "backend_stopped",
            "backend": {
                "id": (backend or {}).get("id"),
                "name": (backend or {}).get("name"),
                "kind": (backend or {}).get("kind"),
                "state": b_state,
                "status": (backend or {}).get("status"),
            },
        }

    probe = probe or {"ok": False, "status": None, "ms": None, "error": "no probe"}
    if probe.get("ok"):
        health = "ok"
    else:
        # expected online (or unlinked) but unreachable → red
        health = "error"

    return {
        **base,
        "ok": health == "ok",
        "health": health,
        "status": probe.get("status"),
        "ms": probe.get("ms"),
        "error": probe.get("error"),
        "reason": None if health == "ok" else "probe_failed",
        "backend": (
            {
                "id": backend.get("id"),
                "name": backend.get("name"),
                "kind": backend.get("kind"),
                "state": backend.get("state"),
                "status": backend.get("status"),
            }
            if backend
            else None
        ),
    }


def list_bookmarks(force: bool = False) -> dict:
    if not force and _cache["v"] and time.time() - _cache["t"] < _TTL:
        return _cache["v"]

    links = resolve_value(list(cfg().get("quick_links") or []))
    # also from overrides urls
    for sid, raw in (cfg().get("overrides") or {}).items():
        ov = resolve_value(raw)
        if ov.get("url") and ov.get("hide") is not True:
            name = ov.get("name") or sid
            if not any(l.get("url") == ov["url"] for l in links):
                links.append({
                    "name": name,
                    "url": ov["url"],
                    "id": sid,
                    "service": sid,
                })

    idx = _backend_index()

    # decide which need probe
    to_probe = []
    preassigned: dict[int, dict] = {}  # link index → result without probe
    for i, link in enumerate(links):
        if not link.get("url"):
            continue
        backend = _resolve_backend(link, idx)
        b_state = (backend or {}).get("state")
        if b_state == "stopped" or (
            backend
            and backend.get("kind") == "vm"
            and (backend.get("status") or "").lower() in (
                "stopped", "stop", "exited", "created", "shutdown"
            )
        ):
            preassigned[i] = _compose_result(link, None, backend)
        else:
            to_probe.append((i, link, backend))

    probes: dict[int, dict] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futs = {
            ex.submit(_probe, link["url"]): (i, link, backend)
            for i, link, backend in to_probe
        }
        for fut, (i, link, backend) in futs.items():
            try:
                probe = fut.result()
            except Exception as e:
                probe = {"ok": False, "status": None, "ms": 0, "error": str(e)}
            probes[i] = _compose_result(link, probe, backend)

    ordered = []
    seen = set()
    for i, link in enumerate(links):
        u = link.get("url")
        if not u or u in seen:
            continue
        if i in preassigned:
            ordered.append(preassigned[i])
            seen.add(u)
        elif i in probes:
            ordered.append(probes[i])
            seen.add(u)

    up = sum(1 for r in ordered if r.get("health") == "ok")
    stopped = sum(1 for r in ordered if r.get("health") == "stopped")
    down = sum(1 for r in ordered if r.get("health") == "error")
    v = {
        "bookmarks": ordered,
        "up": up,
        "stopped": stopped,
        "down": down,
        "checked_at": time.strftime("%H:%M:%S"),
    }
    _cache.update(t=time.time(), v=v)
    return v
