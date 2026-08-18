"""Unified application management: Docker stacks, native (brew/system), VMs.

Provides inventory + detail (ports/network/data paths/logs) + actions
(start/stop/restart/uninstall) for the Apps console.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from hub import cli_args
from hub.docker_cli import docker, engine_up, inspect_object
from hub.errors import api_error, soft_fail
from hub.host_address import host_ip
from hub.paths import DOCKER
from hub.util import cached_snapshot, fan_out, sh, tail_file_lines

SERVICES_ROOT = Path.home() / "Services"
#: Apps page polls every 15s. An 8s snapshot missed on every sit tick
#: (~940ms rebuild). 22s lets the 15s poll hit; brew_cache._TTL must stay
#: strictly longer so inventory rebuilds do not re-run brew services list.
_INV_TTL = 22.0


def invalidate_inventory() -> None:
    """Drop the app inventory snapshot so the next read reflects a change.

    Public because the app store installs and uninstalls without going through
    :func:`action`, and it has to be able to say "this list is stale now".  It
    used to reach in and assign ``_inv_cache["t"] = 0`` from native_catalog,
    wrapped in ``except Exception: pass`` -- so renaming this cache would have
    turned invalidation into a silent no-op and left an uninstalled app showing
    as installed.  The cache now lives inside the ``cached_snapshot`` decorator,
    which is another reason to go through this function rather than the dict.
    """
    inventory.invalidate()


def _host_ip() -> str:
    return host_ip()


# ─── Docker stacks ───────────────────────────────────────────────────────────

def _docker_stacks() -> list[dict]:
    items = []
    try:
        from hub import containers_svc
        stacks = containers_svc.list_stacks()
    except Exception:
        stacks = []
    # map stack path → containers via compose project label or cwd
    containers = []
    try:
        from hub import containers_svc
        containers = (containers_svc.list_containers(with_stats=False).get("containers") or [])
    except Exception:
        pass

    for s in stacks:
        sid = s.get("id") or Path(s.get("path") or "").name
        path = s.get("path") or str(SERVICES_ROOT / sid)
        compose = Path(path) / (s.get("compose_file") or "docker-compose.yml")
        # match containers by compose project name or name prefix
        related = []
        for c in containers:
            proj = c.get("project") or ""
            cid = c.get("id") or ""
            if proj == sid or cid == sid or cid in (s.get("running_containers") or []):
                related.append(c)
        # use stack's own list when project labels missing
        if not related and s.get("running_containers"):
            by_id = {c.get("id"): c for c in containers}
            for n in s["running_containers"]:
                if n in by_id:
                    related.append(by_id[n])
        running = sum(1 for c in related if c.get("state") == "ok" or c.get("raw_state") == "running")
        st = s.get("status") or ("ok" if running else "down")
        ports = []
        for c in related:
            p = c.get("ports") or ""
            if p:
                ports.append(str(p))
        # stack autostart: any related container has restart policy
        auto_n = sum(1 for c in related if c.get("autostart"))
        url = _url_from_docker_ports(ports) or _url_from_known_stack(sid)
        acts = _docker_actions(running, len(related), bool(s.get("compose_path") or compose.exists()))
        if url and "open" not in acts:
            acts = list(acts) + ["open"]
        items.append({
            "id": f"docker:{sid}",
            "source_id": sid,
            "kind": "docker",
            "name": s.get("name") or sid,
            "state": "ok" if running or st == "ok" else ("warn" if related else "down"),
            "status_text": f"{running}/{len(related) or len(s.get('running_containers') or [])} containers running" if (related or s.get("running_containers")) else st,
            "path": path,
            "compose_file": s.get("compose_path") or (str(compose) if compose.exists() else None),
            "installed": True,
            "ports_summary": " · ".join(ports[:4]) if ports else "",
            "container_count": len(related) or len(s.get("running_containers") or []),
            "running_count": running,
            "autostart": auto_n > 0,
            "autostart_detail": f"{auto_n}/{len(related)} containers autostart" if related else None,
            "actions": acts,
            "category": "docker",
            "url": url,
        })
    # orphan compose dirs under Services with docker-compose.yml not in stacks
    try:
        known = {s.get("id") for s in stacks}
        if SERVICES_ROOT.is_dir():
            for d in sorted(SERVICES_ROOT.iterdir()):
                if not d.is_dir() or d.name in known:
                    continue
                if (d / "docker-compose.yml").exists() or (d / "compose.yml").exists():
                    items.append({
                        "id": f"docker:{d.name}",
                        "source_id": d.name,
                        "kind": "docker",
                        "name": d.name,
                        "state": "down",
                        "status_text": "compose directory (not registered)",
                        "path": str(d),
                        "compose_file": str(d / "docker-compose.yml") if (d / "docker-compose.yml").exists() else str(d / "compose.yml"),
                        "installed": True,
                        "ports_summary": "",
                        "container_count": 0,
                        "running_count": 0,
                        "actions": ["start", "uninstall", "logs", "detail"],
                        "category": "docker",
                        "url": None,
                    })
    except Exception:
        pass
    return items


def _docker_actions(running: int, total: int, has_compose: bool) -> list[str]:
    acts = ["detail", "logs", "autostart"]
    if has_compose:
        if running:
            acts += ["stop", "restart"]
        else:
            acts += ["start"]
        acts += ["update", "uninstall"]
    return acts


def _url_from_docker_ports(port_strs: list[str]) -> str | None:
    """Parse '0.0.0.0:4000->4000/tcp' → http://host:4000"""
    host = _host_ip()
    for ps in port_strs:
        # 0.0.0.0:4000->4000/tcp  or  [::]:8123->8123/tcp
        m = re.search(r"(?:0\.0\.0\.0|127\.0\.0\.1|\[::\]):(\d+)->", ps or "")
        if not m:
            m = re.search(r":(\d+)->", ps or "")
        if m:
            port = m.group(1)
            if port in ("1883", "5432", "6379", "3306", "5672", "9092"):
                continue  # no browser UI
            return f"http://{host}:{port}"
    return None


def _url_from_known_stack(sid: str) -> str | None:
    host = _host_ip()
    known = {
        "teslamate": f"http://{host}:4000",
        "music-assistant": f"http://{host}:8095",
        "homeassistant": f"http://{host}:8123",
        "jellyfin": f"http://{host}:8096",
        "immich": f"http://{host}:2283",
        "portainer": f"http://{host}:9000",
        "uptime-kuma": f"http://{host}:3001",
        "navidrome": f"http://{host}:4533",
        "grafana": f"http://{host}:3000",
        "filebrowser": f"http://{host}:8125",
        "vaultwarden": f"http://{host}:8222",
        "nextcloud": f"http://{host}:8084",
        "paperless-ngx": f"http://{host}:8010",
        "qbittorrent": f"http://{host}:8081",
        "code-server": f"http://{host}:8443",
        "duplicati": f"http://{host}:8200",
        "ntfy": f"http://{host}:2586",
        "dozzle": f"http://{host}:8888",
        "homepage": f"http://{host}:3002",
        "homarr": f"http://{host}:7575",
        "glance": f"http://{host}:8087",
        "dockge": f"http://{host}:5001",
        "stirling-pdf": f"http://{host}:8082",
        "it-tools": f"http://{host}:8083",
        "gitea": f"http://{host}:3000",
        "syncthing": f"http://{host}:8384",
        "wg-easy": f"http://{host}:51821",
        "nginx-proxy-manager": f"http://{host}:81",
        "ubuntu-vnc": f"http://{host}:6080",
        "webtop": f"http://{host}:3000",
        "minio": f"http://{host}:9001",
        "adguard-home": f"http://{host}:3000",
    }
    key = (sid or "").lower()
    return known.get(sid) or known.get(key)


def _compose_cmd(compose_path: str, *args: str, timeout: int = 180) -> dict:
    if not DOCKER or not Path(DOCKER).exists():
        return soft_fail("services.docker_unavailable")
    p = Path(compose_path)
    if not p.exists():
        return soft_fail("compose.file_missing", path=str(p))
    import subprocess
    try:
        r = subprocess.run(
            [DOCKER, "compose", "-f", str(p), *args],
            cwd=str(p.parent),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=dict(os.environ),
        )
        msg = ((r.stdout or "") + (r.stderr or "")).strip()
        return {"ok": r.returncode == 0, "message": msg or f"exit {r.returncode}"}
    except Exception as e:
        return {"ok": False, "message": str(e)}


def _container_log(lines: int):
    """A tail-reader for one container, bound to *lines*.  Never raises.

    Returns the same "stdout or stderr, last 4000 chars" body the serial version
    produced, so a failing container still contributes its error text rather
    than removing its section from the document.
    """
    def read(name: str) -> str:
        if not cli_args.is_safe_positional(name):
            return ""
        try:
            _, out, err = docker("logs", "--tail", str(lines), name, timeout=30)
        except Exception as exc:  # noqa: BLE001 - one container must not lose the rest
            return str(exc)[-4000:]
        return (out or err or "")[-4000:]

    return read


def _inspect(name: str) -> tuple[int, str]:
    """``(rc, stdout)`` for one container inspect.  Never raises.

    ``fan_out`` re-raises on iteration, so an exception here would lose every
    container's detail rather than one container's.  A non-zero rc is already a
    case the caller handles by falling back to the list fields.
    """
    if not cli_args.is_safe_positional(name):
        return 1, ""
    try:
        rc, out, _ = docker("inspect", name, timeout=15)
        return rc, out
    except Exception:
        return 1, ""


def _docker_detail(source_id: str) -> dict:
    from hub import containers_svc
    path = str(SERVICES_ROOT / source_id)
    compose = Path(path) / "docker-compose.yml"
    if not compose.exists():
        compose = Path(path) / "compose.yml"
    containers = containers_svc.list_containers(with_stats=False).get("containers") or []
    related = []
    for c in containers:
        proj = c.get("project") or ""
        cid = c.get("id") or c.get("name") or ""
        if proj == source_id or cid == source_id or cid.startswith(source_id):
            related.append(c)

    mounts = []
    networks = []
    ports = []
    env_sample = []
    # `docker inspect` carries a 15s timeout and was issued once per container in
    # series, so a stack of six put up to a minute and a half on the critical path
    # of one detail page.  The inspects are independent reads, so they overlap;
    # parsing and list-building stay in this loop, in `related` order, because the
    # four lists below are rendered as tables and appending from workers would
    # interleave rows differently on every refresh.
    inspected = fan_out(
        lambda name: _inspect(name),
        [c.get("id") or c.get("name") for c in related],
    )

    for c, (rc, out) in zip(related, inspected):
        name = c.get("id") or c.get("name")
        if rc != 0:
            # fall back to list fields
            if c.get("ports"):
                ports.append({"container": name, "published": c.get("ports"), "target": ""})
            continue
        data = inspect_object(out)
        if data is None:
            continue
        net_settings = data.get("NetworkSettings") or {}
        for m in (data.get("Mounts") or []):
            mounts.append({
                "container": name,
                "type": m.get("Type"),
                "source": m.get("Source"),
                "destination": m.get("Destination"),
                "rw": m.get("RW"),
            })
        for net_name, net in (net_settings.get("Networks") or {}).items():
            networks.append({
                "container": name,
                "network": net_name,
                "ip": net.get("IPAddress"),
                "gateway": net.get("Gateway"),
            })
        ports_map = net_settings.get("Ports") or {}
        for cport, binds in ports_map.items():
            if binds:
                for b in binds:
                    ports.append({
                        "container": name,
                        "published": f"{b.get('HostIp') or '0.0.0.0'}:{b.get('HostPort')}",
                        "target": cport,
                    })
            else:
                ports.append({"container": name, "published": None, "target": cport})
        for e in (data.get("Config") or {}).get("Env") or []:
            if any(k in e.upper() for k in ("PASSWORD", "SECRET", "TOKEN", "KEY=")):
                env_sample.append(f"{e.split('=', 1)[0]}=***")
            else:
                env_sample.append(e)

    data_paths = []
    root = Path(path)
    if root.is_dir():
        for sub in ("data", "config", "pgdata", "redis", "media", "library", "uploads", "downloads"):
            p = root / sub
            if p.exists():
                data_paths.append(str(p))
        data_paths.append(str(root))

    db_hints = []
    for m in mounts:
        dest = (m.get("destination") or "").lower()
        src = m.get("source") or ""
        if any(x in dest or x in src.lower() for x in ("postgres", "mysql", "mariadb", "mongo", "redis", "pgdata")):
            db_hints.append({"type": "volume/mount", "path": src, "mount": m.get("destination")})

    running = sum(1 for c in related if c.get("state") == "ok" or c.get("raw_state") == "running")
    display_name = source_id
    try:
        from hub import containers_svc as cs
        for s in cs.list_stacks():
            if s.get("id") == source_id:
                display_name = s.get("name") or source_id
                break
    except Exception:
        pass

    return {
        "id": f"docker:{source_id}",
        "source_id": source_id,
        "kind": "docker",
        "name": display_name,
        "state": "ok" if running else "down",
        "path": path,
        "compose_file": str(compose) if compose.exists() else None,
        "containers": [
            {
                "name": c.get("id") or c.get("name"),
                "image": c.get("image"),
                "state": c.get("state") or c.get("status"),
                "ports": c.get("ports"),
                "id": c.get("cid") or c.get("id"),
            }
            for c in related
        ],
        "ports": ports[:40],
        "networks": networks[:40],
        "mounts": mounts[:40],
        "data_paths": data_paths[:20],
        "databases": db_hints[:10],
        "env_sample": env_sample[:30],
        "actions": _docker_actions(running, len(related), compose.exists()) + (
            ["open"] if (_url_from_docker_ports(
                [c.get("ports") or "" for c in related if c.get("ports")]
            ) or _url_from_known_stack(source_id)) else []
        ),
        "url": _url_from_docker_ports(
            [c.get("ports") or "" for c in related if c.get("ports")]
        ) or _url_from_known_stack(source_id),
        "host_ip": _host_ip(),
    }


def _docker_logs(source_id: str, lines: int = 120) -> dict:
    path = SERVICES_ROOT / source_id
    compose = path / "docker-compose.yml"
    if not compose.exists():
        compose = path / "compose.yml"
    if compose.exists():
        r = _compose_cmd(str(compose), "logs", "--no-color", "--tail", str(lines), timeout=60)
        return {"ok": r["ok"], "log": r["message"], "source": str(compose)}
    # fallback: logs of matching containers
    from hub import containers_svc
    containers = containers_svc.list_containers(with_stats=False).get("containers") or []
    matching = []
    for c in containers:
        name = c.get("name") or ""
        labels = c.get("labels") or {}
        proj = labels.get("com.docker.compose.project") or ""
        if proj == source_id or name.startswith(source_id):
            matching.append(name)

    # `docker logs` carries a 30s timeout and ran once per container in series, so
    # a stack of five could sit for two and a half minutes before returning any
    # log at all.  The reads are independent; `fan_out` preserves order, which
    # matters because the chunks are concatenated into one document and the
    # operator should not see the sections reshuffle between refreshes.
    chunks = [
        f"===== {name} =====\n{body}"
        for name, body in zip(matching, fan_out(_container_log(lines), matching))
    ]
    return {"ok": bool(chunks), "log": "\n\n".join(chunks) or "no logs", "source": "docker logs"}


# ─── Native ──────────────────────────────────────────────────────────────────

def _native_apps(force: bool = False) -> list[dict]:
    from hub import native_catalog
    installed = [a for a in native_catalog.list_native_apps(force=force)
                 if a.get("installed")]

    # Both autostart lookups used to be issued *inside* the per-app loop, so a
    # whole `brew services` enumeration ran once for every brew-backed app.  On
    # this machine that is 480ms x 8 apps, which was the single largest cost on
    # the Apps page -- larger than Docker and the VM listing put together.  They
    # answer the same question for every app, so they are read once here and
    # indexed; the loop below does a dict lookup instead of a subprocess.
    #
    # Failures stay non-fatal, matching the per-app try/except this replaces: an
    # unavailable brew or launchctl leaves the autostart flag unknown, exactly as
    # before, rather than dropping the app from the inventory.
    brew_autostart: dict = {}
    launchd_autostart: dict = {}
    try:
        from hub import autostart_svc

        if any(a.get("package") and a.get("method") in ("brew_formula", "brew_cask")
               for a in installed):
            brew_autostart = {
                bi.get("name"): bi.get("autostart")
                for bi in autostart_svc._brew_service_items()
            }
        launchd_autostart = {
            bi.get("label"): bi.get("autostart")
            for bi in autostart_svc._launchd_items()
        }
    except Exception:
        pass

    items = []
    for a in installed:
        running = a.get("running")
        # CLI-only tools (no service): treat installed as ok, not "down"
        state = "ok" if running else ("down" if running is False else "ok")
        # Always expose uninstall + detail for every installed native app
        acts = ["detail", "logs", "uninstall"]
        if a.get("method") in ("brew_formula", "brew_cask") and a.get("package"):
            if running:
                acts = ["stop", "restart", "detail", "logs", "uninstall"]
            elif running is False:
                acts = ["start", "detail", "logs", "uninstall"]
            else:
                acts = ["detail", "logs", "uninstall"]
            # cask apps: open + quit via open/osascript
            if a.get("method") == "brew_cask":
                if running:
                    acts = ["stop", "detail", "uninstall"]
                else:
                    acts = ["start", "detail", "uninstall"]
        url = a.get("url_hint") or ""
        if url and "open" not in acts:
            acts.append("open")
        # also open when we can derive from ports only
        if not url and a.get("ports"):
            from hub.native_catalog import _resolve_url
            url = _resolve_url("", _host_ip(), a.get("ports") or [])
            if url and "open" not in acts:
                acts.append("open")

        # map brew package → autostart from brew services / launchd
        auto = None
        auto_id = None
        if a.get("package") and a.get("method") in ("brew_formula", "brew_cask"):
            auto_id = f"brew:{a['package']}"
            auto = brew_autostart.get(a["package"])
        elif a.get("launchd_label") or a.get("id") in ("native-filebrowser", "native-homeassistant"):
            label = a.get("launchd_label") or (
                "local.filebrowser" if a.get("id") == "native-filebrowser" else "com.homeassistant.core"
            )
            auto_id = f"launchd:{label}"
            auto = launchd_autostart.get(label)
            if running:
                acts = ["stop", "restart", "detail", "logs", "uninstall", "open", "autostart"]
            else:
                acts = ["start", "detail", "logs", "uninstall", "open", "autostart"]
            if not url and a.get("url_hint"):
                url = a.get("url_hint")
        elif a.get("id") == "native-screen-sharing":
            auto = True  # system feature when enabled
            auto_id = None
            # Always expose VNC open (Screen Sharing client via vnc://)
            url = f"vnc://{_host_ip()}"
            acts = [x for x in acts if x not in ("logs",)]
            if "open" not in acts:
                acts.append("open")
            if "start" not in acts:
                # open also re-enables if needed is separate; keep open primary
                pass

        # Cloudflare Tunnel: managed LaunchAgent (local.cloudflared-tunnel)
        cf_extra = None
        if a.get("id") == "native-cloudflared":
            try:
                from hub import cloudflared_svc
                cf = cloudflared_svc.status()
                running = bool(cf.get("running"))
                state = "ok" if running else "down"
                auto_id = f"launchd:{cloudflared_svc.LABEL}"
                auto = cloudflared_svc.PLIST.is_file()
                acts = (
                    ["stop", "restart", "detail", "logs", "uninstall", "autostart"]
                    if running
                    else ["start", "detail", "logs", "uninstall", "autostart"]
                )
                cf_extra = {
                    "logged_in": cf.get("logged_in"),
                    "active_tunnel": cf.get("active_tunnel"),
                    "tunnels": cf.get("tunnels") or [],
                }
                notes_extra = cf.get("notes") or ""
                if a.get("notes"):
                    a = {**a, "notes": (a.get("notes") or "") + " · " + notes_extra}
                else:
                    a = {**a, "notes": notes_extra}
            except Exception:
                state = "down"
                acts = ["start", "detail", "logs", "uninstall"]

        if auto is not None and "autostart" not in acts:
            acts = list(acts) + ["autostart"]

        item = {
            "id": f"native:{a['id']}",
            "source_id": a["id"],
            "kind": "native",
            "name": a.get("name") or a["id"],
            # already filtered to installed; state from running (None → ok)
            "state": state,
            "status_text": (
                "running" if running else ("stopped" if running is False or state == "down" else "installed")
            ),
            "path": None,
            "package": a.get("package"),
            "method": a.get("method"),
            "installed": True,
            "ports_summary": ", ".join(a.get("ports") or []),
            "autostart": auto,
            "autostart_id": auto_id,
            "actions": acts,
            "category": a.get("category") or "other",
            "url": url or None,
            "notes": a.get("notes") or "",
        }
        if cf_extra:
            item["cloudflared"] = cf_extra
            if cf_extra.get("active_tunnel"):
                item["status_text"] = (
                    f"running · {cf_extra['active_tunnel']}"
                    if running
                    else f"stopped · {cf_extra['active_tunnel']}"
                )
        items.append(item)
    return items


def _native_detail(source_id: str) -> dict:
    from hub import native_catalog
    app = next((a for a in native_catalog.NATIVE_APPS if a["id"] == source_id), None)
    if not app:
        raise api_error("apps.native_not_found")
    listed = next((a for a in native_catalog.list_native_apps(force=True) if a["id"] == source_id), {})
    pkg = app.get("package")
    data_paths = []
    # common brew prefixes
    for base in (
        Path("/opt/homebrew/var"),
        Path("/usr/local/var"),
        Path.home() / "Library/Application Support",
        SERVICES_ROOT,
    ):
        if not base.exists() or not pkg:
            continue
        # look for package-named dirs
        for cand in base.glob(f"*{pkg.split('@')[0]}*"):
            if cand.is_dir():
                data_paths.append(str(cand))
    if source_id == "native-filebrowser":
        data_paths.append(str(SERVICES_ROOT / "filebrowser"))
    if app.get("open"):
        app_path = Path(f"/Applications/{app['open']}.app")
        if app_path.exists():
            data_paths.append(str(app_path))

    ports = [{"published": f"0.0.0.0:{p}", "target": p} for p in (app.get("ports") or [])]
    # live listen check
    listen = []
    try:
        from hub import tools_svc
        for row in (tools_svc.listening_ports(80).get("ports") or []):
            name = row.get("name") or ""
            for p in (app.get("ports") or []):
                if f":{p}" in name or name.endswith(str(p)):
                    listen.append(row)
    except Exception:
        pass

    db_hints = []
    for p in data_paths:
        low = p.lower()
        if any(x in low for x in ("postgres", "mysql", "redis", "mongo", "db")):
            db_hints.append({"type": "path", "path": p})

    out = {
        "id": f"native:{source_id}",
        "source_id": source_id,
        "kind": "native",
        "name": app.get("name") or source_id,
        "state": "ok" if listed.get("running") else ("down" if listed.get("running") is False else "ok"),
        "package": pkg,
        "method": app.get("method"),
        "ports": ports,
        "listening": listen[:20],
        "networks": [{"network": "host", "ip": _host_ip()}],
        "mounts": [],
        "data_paths": data_paths[:20],
        "databases": db_hints,
        "notes": app.get("notes") or "",
        "url": app.get("url_hint") or listed.get("url_hint"),
        "actions": listed.get("actions") or ["detail", "uninstall"],
        "host_ip": _host_ip(),
        "plist_hint": f"~/Library/LaunchAgents/homebrew.mxcl.{pkg}.plist" if pkg else None,
    }
    if source_id == "native-cloudflared":
        try:
            from hub import cloudflared_svc
            cf = cloudflared_svc.status()
            out["state"] = "ok" if cf.get("running") else "down"
            out["cloudflared"] = cf
            out["plist_hint"] = str(cloudflared_svc.PLIST)
            out["path"] = str(cloudflared_svc.STATE_DIR)
            out["actions"] = (
                ["stop", "restart", "detail", "logs", "uninstall"]
                if cf.get("running")
                else ["start", "detail", "logs", "uninstall"]
            )
            out["notes"] = (out.get("notes") or "") + " · " + (cf.get("notes") or "")
            if cf.get("active_tunnel"):
                out["status_text"] = (
                    f"running · {cf['active_tunnel']}"
                    if cf.get("running")
                    else f"stopped · {cf['active_tunnel']}"
                )
        except Exception as e:
            out["cloudflared"] = {"ok": False, "message": str(e)}
    return out


def _native_logs(source_id: str, lines: int = 120) -> dict:
    from hub import native_catalog
    app = next((a for a in native_catalog.NATIVE_APPS if a["id"] == source_id), None)
    if not app:
        return {"ok": False, "log": "unknown app"}
    if source_id == "native-cloudflared":
        from hub import cloudflared_svc
        return cloudflared_svc.logs(lines=lines)
    pkg = app.get("package")
    chunks = []
    # brew services log paths
    for logp in (
        Path(f"/opt/homebrew/var/log/{pkg}.log") if pkg else None,
        Path(f"/opt/homebrew/var/log/{pkg}/error.log") if pkg else None,
        Path.home() / f"Library/Logs/{pkg}.log" if pkg else None,
    ):
        if logp and logp.exists():
            try:
                chunks.append(
                    f"===== {logp} =====\n" + "\n".join(tail_file_lines(logp, lines))
                )
            except Exception as e:
                chunks.append(f"{logp}: {e}")
    # launchctl print for brew services
    if pkg:
        rc, out, err = sh(
            ["/bin/launchctl", "print", f"gui/{os.getuid()}/homebrew.mxcl.{pkg}"],
            timeout=8,
        )
        if rc != 0:
            rc, out, err = sh(
                ["/bin/launchctl", "print", f"homebrew.mxcl.{pkg}"],
                timeout=8,
            )
        if out or err:
            chunks.append(f"===== launchctl =====\n{(out or err or '')[-3000:]}")
    if not chunks:
        chunks.append("No dedicated log file found. System-level logs are available under Tools → System Logs.")
    return {"ok": True, "log": "\n\n".join(chunks), "source": "native"}


# ─── User LaunchAgents (self-hosted, not brew / not the panel) ───────────────

_BREW_AGENT_PREFIXES = ("homebrew.mxcl.", "homebrew.au.")


def _catalog_launchd_labels() -> set[str]:
    from hub import native_catalog
    return {
        str(app.get("launchd_label") or "").lower()
        for app in native_catalog.NATIVE_APPS
        if app.get("launchd_label")
    }


def _launchd_apps() -> list[dict]:
    """LaunchAgents that the Apps page can start, stop, and uninstall.

    Brew formulae already appear as native apps; the panel's own agents are
    refused by the uninstall guard.  What remains is the self-hosted set
    (Kiro-Go and the like) that used to show on Services only, with no
    uninstall on this page.
    """
    import plistlib

    from hub import config
    from hub.launchd_cache import Listing
    from hub.launchd_cache import listing as launchd_listing
    from hub.paths import AGENTS_DIR
    from hub.services_uninstall_svc import PROTECTED_LABELS

    _EMPTY_LISTING = Listing({})

    agents = Path(AGENTS_DIR)
    if not agents.is_dir():
        return []
    try:
        listing = launchd_listing()
    except Exception:
        listing = _EMPTY_LISTING
    catalog = _catalog_launchd_labels()
    items = []
    for path in sorted(agents.glob("*.plist")):
        label = path.stem
        low = label.lower()
        if low in PROTECTED_LABELS or low in catalog:
            continue
        if any(low.startswith(prefix) for prefix in _BREW_AGENT_PREFIXES):
            continue
        program = ""
        workdir = ""
        try:
            data = plistlib.loads(path.read_bytes())
            args = data.get("ProgramArguments") or []
            program = str(args[0]) if args else str(data.get("Program") or "")
            workdir = str(data.get("WorkingDirectory") or "")
            label = str(data.get("Label") or label)
        except Exception:
            pass
        # launchctl prints "-" in the pid column for a loaded-but-idle agent,
        # so the raw column is truthy for a job that is not running at all.
        # pid_for() tests it for digits; loaded says whether launchd knows the
        # label, which is the difference between idle and not installed.
        pid = listing.pid_for(label)
        running = pid is not None
        loaded = label in listing.loaded
        ov = config.override(label) or {}
        name = ov.get("name") or label
        acts = (
            ["stop", "restart", "detail", "logs", "uninstall"]
            if running
            else ["start", "detail", "logs", "uninstall"]
        )
        items.append({
            "id": f"launchd:{label}",
            "source_id": label,
            "kind": "launchd",
            "name": name,
            "state": "ok" if running else "down",
            "status_text": f"Running · pid {pid}" if running else (
                "Loaded but not running" if loaded else "Not loaded"
            ),
            "path": workdir or (str(Path(program).parent) if program else ""),
            "package": None,
            "method": "launchd",
            "installed": True,
            "ports_summary": str(ov.get("port") or ""),
            "autostart": True,
            "autostart_id": f"launchd:{label}",
            "actions": acts,
            "category": ov.get("group") or "other",
            "url": ov.get("url") or None,
        })
    return items


def _launchd_detail(label: str) -> dict:
    from hub import services_uninstall_svc
    listed = next((item for item in _launchd_apps() if item.get("source_id") == label), None)
    if not listed:
        raise api_error("apps.launchd_not_found")
    preview = services_uninstall_svc.preview(label)
    return {
        **listed,
        "program": preview.get("program") or "",
        "workdir": preview.get("workdir") or "",
        "plist": preview.get("plist") or "",
        "can_remove_data": preview.get("can_remove_data"),
        "remove_data_path": preview.get("remove_data_path") or "",
        "data_paths": [preview["remove_data_path"]] if preview.get("remove_data_path") else [],
    }


def _launchd_logs(label: str, lines: int = 120) -> dict:
    import plistlib

    from hub.paths import AGENTS_DIR

    path = Path(AGENTS_DIR) / f"{label}.plist"
    if not path.is_file():
        raise api_error("apps.launchd_not_found")
    chunks = []
    try:
        data = plistlib.loads(path.read_bytes())
    except Exception as exc:
        return {"ok": False, "log": str(exc), "source": "launchd"}
    for key in ("StandardOutPath", "StandardErrorPath"):
        logp = data.get(key)
        if not logp:
            continue
        p = Path(str(logp)).expanduser()
        if not p.is_file():
            chunks.append(f"===== {p} =====\n(missing)")
            continue
        try:
            chunks.append(
                f"===== {p} =====\n" + "\n".join(tail_file_lines(p, lines))
            )
        except OSError as exc:
            chunks.append(f"{p}: {exc}")
    if not chunks:
        chunks.append("No StandardOutPath / StandardErrorPath on this agent.")
    return {"ok": True, "log": "\n\n".join(chunks), "source": "launchd"}


# ─── VMs ─────────────────────────────────────────────────────────────────────

def _vms() -> list[dict]:
    from hub import vms_svc
    data = vms_svc.list_all_vms()
    items = []
    for v in data.get("vms") or []:
        state = v.get("state") or v.get("status") or "unknown"
        running = state in ("ok", "running", "started")
        vid = v.get("id") or v.get("uuid") or v.get("name")
        items.append({
            "id": f"vm:{vid}",
            "source_id": vid,
            "kind": "vm",
            "name": v.get("display_name") or v.get("name") or vid,
            "state": "ok" if running else ("stopped" if state in ("stopped", "stop") else state),
            "status_text": v.get("detail") or state,
            "backend": v.get("backend"),
            "path": None,
            "installed": True,
            "ports_summary": "",
            "ips": v.get("ips") or [],
            "url": v.get("url"),
            "actions": _vm_actions(v),
            "category": "vm",
        })
    return items


def _vm_actions(v: dict) -> list[str]:
    acts = list(v.get("actions") or [])
    # normalize
    out = ["detail"]
    state = v.get("state") or ""
    if state in ("ok", "running", "started"):
        out += ["stop", "restart"]
        if "suspend" in acts or "pause" in acts:
            out.append("suspend")
    else:
        out.append("start")
    if "clone" in acts:
        out.append("clone")
    if "delete" in acts:
        out.append("uninstall")
    if v.get("url"):
        out.append("open")
    return out


def _vm_detail(source_id: str) -> dict:
    from hub import vms_svc
    data = vms_svc.list_all_vms()
    v = next((x for x in (data.get("vms") or []) if (x.get("id") or x.get("uuid") or x.get("name")) == source_id), None)
    if not v:
        raise api_error("apps.vm_not_found")
    return {
        "id": f"vm:{source_id}",
        "source_id": source_id,
        "kind": "vm",
        "name": v.get("display_name") or v.get("name") or source_id,
        "state": v.get("state"),
        "backend": v.get("backend"),
        "uuid": v.get("uuid"),
        "ips": v.get("ips") or [],
        "url": v.get("url"),
        "detail": v.get("detail"),
        "ports": [],
        "networks": [{"network": "vm", "ip": ip} for ip in (v.get("ips") or [])],
        "mounts": [],
        "data_paths": [],
        "databases": [],
        "actions": _vm_actions(v),
        "host_ip": _host_ip(),
        "notes": "UTM disk images live in the UTM library directory; OrbStack machine data is managed by OrbStack.",
    }


def _vm_logs(source_id: str, lines: int = 80) -> dict:
    # VMs rarely expose easy logs; return status dump
    try:
        d = _vm_detail(source_id)
        return {
            "ok": True,
            "log": json.dumps(d, ensure_ascii=False, indent=2)[:8000],
            "source": "vm-status",
        }
    except Exception as e:
        return {"ok": False, "log": str(e)}


# ─── Public API ──────────────────────────────────────────────────────────────

#: Fallbacks for a collector that failed outright.  A backend being unreachable
#: should cost its own section of the Apps page, not the page.
_COLLECTOR_FALLBACK = {
    "docker": [], "native": [], "launchd": [], "vms": [], "engine": False, "host": "",
}


def _collect(entry):
    """Run one inventory collector by name, absorbing its own failure.

    Dispatched by name rather than by passing callables so the fallback for a
    failure is declared next to it: ``fan_out`` re-raises on iteration, and an
    unreachable Docker socket must not empty the native and VM sections too.
    """
    which, argument = entry
    try:
        if which == "docker":
            return _docker_stacks()
        if which == "native":
            return _native_apps(force=bool(argument))
        if which == "launchd":
            return _launchd_apps()
        if which == "vms":
            return _vms()
        if which == "engine":
            return engine_up()
        return _host_ip()
    except Exception:
        return _COLLECTOR_FALLBACK[which]


@cached_snapshot(_INV_TTL)
def inventory(force: bool = False) -> dict:
    # The three collectors are independent aggregations over different backends --
    # compose stacks, Homebrew/native installs, and VMs -- and each shells out
    # several times.  Run in series their latencies simply added, so the Apps page
    # waited for Docker, then brew, then utmctl before rendering anything, even
    # though each collector is internally overlapped already.
    #
    # engine_up() and _host_ip() join the same batch: both are cheap but neither
    # depends on the others, and engine_up in particular can block on a Docker
    # socket that is not answering.
    #
    # Nested pools are fine here: each fan_out builds and disposes its own, and no
    # inner task waits on an outer one, so there is nothing to deadlock against.
    # force=True must re-probe brew/bin so the panel picks up just-installed natives.
    docker_items, native_items, launchd_items, vm_items, engine, host = fan_out(
        _collect,
        [
            ("docker", None),
            ("native", force),
            ("launchd", None),
            ("vms", None),
            ("engine", None),
            ("host", None),
        ],
    )
    all_items = native_items + docker_items + launchd_items + vm_items
    # sort: running first, then kind, name
    def sort_key(x):
        st = x.get("state")
        kind_rank = {"native": 0, "docker": 1, "launchd": 2}.get(x.get("kind"), 3)
        return (
            0 if st == "ok" else 1 if st == "warn" else 2,
            kind_rank,
            x.get("name") or "",
        )
    all_items.sort(key=sort_key)
    counts = {
        "total": len(all_items),
        "native": len(native_items),
        "docker": len(docker_items),
        "launchd": len(launchd_items),
        "vm": len(vm_items),
        "running": sum(1 for x in all_items if x.get("state") == "ok"),
        "stopped": sum(1 for x in all_items if x.get("state") in ("down", "stopped")),
    }
    v = {
        "ts": time.strftime("%H:%M:%S"),
        "items": all_items,
        "counts": counts,
        "host_ip": host,
        "engine_up": engine,
    }
    return v


def detail(app_id: str) -> dict:
    kind, _, source_id = app_id.partition(":")
    if not source_id:
        # allow bare ids
        if app_id.startswith("native-"):
            kind, source_id = "native", app_id
        else:
            raise api_error("apps.bad_id")
    source_id = cli_args.require_positional(source_id, label="app id")
    if kind == "docker":
        return _docker_detail(source_id)
    if kind == "native":
        return _native_detail(source_id)
    if kind == "launchd":
        return _launchd_detail(source_id)
    if kind == "vm":
        return _vm_detail(source_id)
    raise api_error("apps.unknown_kind", kind=kind)


def logs(app_id: str, lines: int = 120) -> dict:
    kind, _, source_id = app_id.partition(":")
    if not source_id and app_id.startswith("native-"):
        kind, source_id = "native", app_id
    if source_id:
        source_id = cli_args.require_positional(source_id, label="app id")
    lines = max(20, min(int(lines or 120), 500))
    if kind == "docker":
        return _docker_logs(source_id, lines)
    if kind == "native":
        return _native_logs(source_id, lines)
    if kind == "launchd":
        return _launchd_logs(source_id, lines)
    if kind == "vm":
        return _vm_logs(source_id, lines)
    raise api_error("apps.unknown_kind", kind=kind)


def action(app_id: str, action_name: str, **kwargs) -> dict:
    """start|stop|restart|update|uninstall|suspend|autostart_on|autostart_off"""
    action_name = (action_name or "").strip().lower()
    kind, _, source_id = app_id.partition(":")
    if not source_id and app_id.startswith("native-"):
        kind, source_id = "native", app_id
    if source_id:
        source_id = cli_args.require_positional(source_id, label="app id")
    invalidate_inventory()

    # Autostart toggles
    if action_name in ("autostart_on", "autostart_off", "enable_autostart", "disable_autostart"):
        enabled = action_name in ("autostart_on", "enable_autostart")
        from hub import autostart_svc
        if kind == "docker":
            # enable for all containers in stack / or single container name
            from hub import containers_svc
            containers = containers_svc.list_containers(with_stats=False).get("containers") or []
            related = [
                c for c in containers
                if (c.get("project") == source_id or c.get("id") == source_id
                    or (c.get("id") or "").startswith(source_id))
            ]
            if not related:
                # try treat source_id as container name
                return autostart_svc.set_docker_autostart(source_id, enabled)
            results = []
            ok = True
            for c in related:
                r = autostart_svc.set_docker_autostart(c.get("id"), enabled)
                results.append(f"{c.get('id')}: {r.get('message')}")
                ok = ok and r.get("ok")
            return {"ok": ok, "message": "\n".join(results)[-2000:], "autostart": enabled}
        if kind == "launchd":
            return autostart_svc.set_launchd_autostart(source_id, enabled)
        if kind == "native":
            # map to brew/launchd
            from hub import native_catalog
            app = next((a for a in native_catalog.NATIVE_APPS if a["id"] == source_id), None)
            if not app:
                raise api_error("apps.native_not_found")
            if source_id == "native-cloudflared":
                from hub import cloudflared_svc
                if enabled:
                    if not cloudflared_svc.TOKEN_FILE.is_file():
                        raise api_error("apps.cloudflared_token_required")
                    cloudflared_svc._write_launchagent_token()
                    return cloudflared_svc._launchctl_bootstrap()
                return cloudflared_svc.stop()
            if app.get("package") and app.get("method") in ("brew_formula", "brew_cask"):
                return autostart_svc.set_brew_autostart(app["package"], enabled)
            label = app.get("launchd_label")
            if source_id == "native-filebrowser":
                label = label or "local.filebrowser"
            if label:
                return autostart_svc.set_launchd_autostart(label, enabled)
            raise api_error("apps.autostart_unsupported")
        if kind == "vm":
            raise api_error("apps.vm_autostart_external")
        raise api_error("apps.bad_autostart_kind", kind=kind)

    if kind == "docker":
        path = SERVICES_ROOT / source_id
        compose = path / "docker-compose.yml"
        if not compose.exists():
            compose = path / "compose.yml"
        if action_name == "start":
            return _compose_cmd(str(compose), "up", "-d")
        if action_name == "stop":
            return _compose_cmd(str(compose), "stop")
        if action_name == "restart":
            return _compose_cmd(str(compose), "restart")
        if action_name == "update":
            r1 = _compose_cmd(str(compose), "pull", timeout=600)
            r2 = _compose_cmd(str(compose), "up", "-d", timeout=300)
            return {
                "ok": r1["ok"] and r2["ok"],
                "message": (r1["message"] + "\n" + r2["message"])[-2500:],
            }
        if action_name == "uninstall":
            from hub import catalog
            return catalog.uninstall_template(
                source_id,
                remove_data=bool(kwargs.get("remove_data", True)),
                confirm=True,
            )
        raise api_error("apps.docker_action_unsupported", action=action_name)

    if kind == "launchd":
        if action_name == "uninstall":
            from hub import services_uninstall_svc
            return services_uninstall_svc.uninstall(
                source_id, remove_data=bool(kwargs.get("remove_data", False)),
            )
        if action_name in ("start", "stop", "restart", "run"):
            from hub import actions
            rc, out, err = actions.run_action(source_id, action_name)
            return {"ok": rc == 0, "message": (out or err or "").strip() or action_name}
        raise api_error("apps.native_action_unsupported", action=action_name)

    if kind == "native":
        from hub import native_catalog
        app = next((a for a in native_catalog.NATIVE_APPS if a["id"] == source_id), None)
        if not app:
            raise api_error("apps.native_not_found")
        pkg = app.get("package")
        if action_name == "uninstall":
            return native_catalog.uninstall_native(
                source_id, remove_data=bool(kwargs.get("remove_data", False))
            )
        # Generic LaunchAgent apps (filebrowser, homeassistant, …)
        label = app.get("launchd_label")
        if source_id == "native-filebrowser":
            label = label or "local.filebrowser"
        if label and action_name in ("start", "stop", "restart"):
            from hub.native_catalog import _launchctl_load, _launchctl_unload
            from hub.paths import AGENTS_DIR
            plist = Path(AGENTS_DIR) / f"{label}.plist"
            if action_name == "start":
                if not plist.exists():
                    # re-run install to materialize plist if missing
                    from hub import native_catalog as nc
                    r = nc.install_native(source_id)
                    return r
                return _launchctl_load(label, plist)
            if action_name == "stop":
                return _launchctl_unload(label)
            if action_name == "restart":
                if plist.exists():
                    return _launchctl_load(label, plist)
                return {"ok": False, "message": f"{plist} not found"}

        # Screen Sharing / VNC — open activates macOS Screen Sharing client
        if source_id == "native-screen-sharing" and action_name == "open":
            from hub.native_catalog import _run
            host = _host_ip() or "localhost"
            # Prefer loopback when panel runs on the same Mac (reliable client launch)
            targets = [f"vnc://{host}"]
            if host not in ("127.0.0.1", "localhost"):
                targets.append("vnc://localhost")
            last = {"ok": False, "message": "could not open Screen Sharing"}
            for uri in targets:
                # open URL scheme → launches /System/Library/CoreServices/RemoteManagement/Screensharing.app
                r = _run(["/usr/bin/open", uri], timeout=15)
                if r.get("ok"):
                    return {"ok": True, "message": f"Screen Sharing client launched · {uri}", "url": uri}
                last = r
            # Fallback: open Screen Sharing app directly
            r2 = _run(
                ["/usr/bin/open", "-a", "Screen Sharing", f"vnc://{host}"],
                timeout=15,
            )
            if r2.get("ok"):
                return {
                    "ok": True,
                    "message": f"Screen Sharing opened · vnc://{host}",
                    "url": f"vnc://{host}",
                }
            return last

        # Cloudflare Tunnel — never use bare brew services (needs token/config)
        if source_id == "native-cloudflared":
            from hub import cloudflared_svc
            if action_name == "start":
                # Prefer last known tunnel / existing token
                st = cloudflared_svc._load_state()
                name = st.get("tunnel_name")
                if cloudflared_svc.TOKEN_FILE.is_file():
                    return cloudflared_svc.restart()
                if name and cloudflared_svc._logged_in():
                    return cloudflared_svc.start_with_tunnel(name)
                return {
                    "ok": False,
                    "message": (
                        "Select a tunnel in the detail page and start it first, or paste a Zero Trust token. "
                        "(Panel → Cloudflared detail → Tunnel maintenance)"
                    ),
                }
            if action_name == "stop":
                return cloudflared_svc.stop()
            if action_name == "restart":
                return cloudflared_svc.restart()

        if pkg and app.get("method") in ("brew_formula", "brew_cask"):
            from hub.native_catalog import _run, BREW
            if action_name == "start":
                if app.get("method") == "brew_formula":
                    if source_id == "native-ollama" and native_catalog.ollama_api_already_served():
                        return {
                            "ok": True,
                            "message": "Ollama is already serving :11434; not starting a second brew daemon",
                        }
                    if source_id == "native-redis" and native_catalog.redis_port_already_served():
                        return {
                            "ok": True,
                            "message": "Valkey/Redis is already serving :6379; not starting Homebrew Redis",
                        }
                    return _run([BREW, "services", "start", pkg], timeout=120)
                if app.get("open"):
                    return _run(["/usr/bin/open", "-a", app["open"]], timeout=15)
            if action_name == "stop":
                if app.get("method") == "brew_formula":
                    return _run([BREW, "services", "stop", pkg], timeout=120)
                if app.get("open"):
                    return _run(
                        ["/usr/bin/osascript", "-e", f'quit app "{app["open"]}"'],
                        timeout=15,
                    )
            if action_name == "restart":
                if app.get("method") == "brew_formula":
                    return _run([BREW, "services", "restart", pkg], timeout=120)
            if action_name == "open" and app.get("open"):
                return _run(["/usr/bin/open", "-a", app["open"]], timeout=15)
        raise api_error("apps.native_action_unsupported", action=action_name)

    if kind == "vm":
        from hub import vms_svc
        if action_name == "uninstall":
            action_name = "delete"
        if action_name == "suspend":
            action_name = "pause"  # map
        # map restart
        return vms_svc.vm_action(source_id, action_name)

    raise api_error("apps.unknown_kind", kind=kind)
