"""Unified application management: Docker stacks, native (brew/system), VMs.

Provides inventory + detail (ports/network/data paths/logs) + actions
(start/stop/restart/uninstall) for the Apps console.
"""
from __future__ import annotations

import json
import os
import plistlib
import re
from pathlib import Path

from fastapi import HTTPException

from hub import cli_args
from hub.docker_cli import (
    _jsonable, cli_on_disk, docker, engine_up, inspect_object,
    looks_cli_vanished, looks_engine_down,
)
from hub.errors import api_error, exc_detail, soft_fail
from hub.host_address import host_ip
from hub.paths import DOCKER, user_home
from hub.util import cached_snapshot, fan_out, read_bytes_capped, run_capped, sh, strftime_now, tail_file_lines


def _default_services_root() -> Path:
    """Services tree under ``~/Services``.  ``Path.home()`` leftover must not 500 import."""
    home = user_home()
    return (home / "Services") if home is not None else Path("/var/empty/serverhub-services")


SERVICES_ROOT = _default_services_root()
#: Leftover multi-MB LaunchAgent plist used to OOM GET /api/apps/managed.
_PLIST_CAP = 256 * 1024


def _plist_dict(path: Path) -> dict | None:
    try:
        # read_bytes_capped, not a bare open(): a plain open of a leftover FIFO
        # occupying ``*.plist`` parks until a writer appears, which hung
        # GET /api/apps/managed (and detail/logs via _launchd_apps) forever.
        # The capped reader opens O_NONBLOCK, refuses non-regular files with
        # the OSError this except already turns into "no plist", and keeps the
        # oversize cap as OSError(EFBIG).
        raw = read_bytes_capped(path, _PLIST_CAP)
    except OSError:
        return None
    try:
        data = plistlib.loads(raw)
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    try:
        text = str(value)
    except RecursionError:
        try:
            return type(value).__name__
        except Exception:
            return ""
    except Exception:
        return ""
    # Unbound base encode — ``str()`` of a str subclass whose ``__str__``
    # returns self keeps the subclass, so a bound ``.encode`` bomb could
    # still fire here (the modules5 unbound convention, like docker_cli).
    return str.encode(text, "utf-8", "replace").decode("utf-8")


def _mapping_get(mapping, key, default=None):
    """Field read that a dict-subclass ``.get`` bomb cannot 500.

    The ups_svc convention: ``isinstance(x, dict)`` passes an odd subclass
    whose ``get`` raises, and one such ``list_containers()`` /
    ``list_all_vms()`` payload used to raise out of ``_container_rows`` /
    ``_vm_detail`` and 500 the Apps detail, logs and autostart-action
    routes.  ``dict.get`` reads the real storage underneath the override,
    so a subclass that only poisoned its method keeps its sane data.
    """
    if not isinstance(mapping, dict):
        return default
    return dict.get(mapping, key, default)


def _truthy(value) -> bool:
    """``bool(value)`` that survives a leftover ``__bool__`` bomb (jobs)."""
    try:
        return bool(value)
    except Exception:
        return False


def _clean_rows(raw) -> list[dict]:
    """Laundered dict rows from another service's list payload.

    ``_jsonable`` copies a dict subclass through the C-level storage and
    scrubs every nested value, so a leftover ``.get``/``items``/``__bool__``
    /``__eq__`` bomb — or a >4300-digit int, a lone surrogate, raw bytes —
    in one row cannot raise out of the loops (or Starlette's encoder)
    downstream.  ``list.__iter__`` walks the real storage of a list
    subclass whose own ``__iter__`` raises (the modules convention).  A
    row that is not a dict at all costs itself, never its siblings.
    """
    if not isinstance(raw, list):
        return []
    out: list[dict] = []
    for row in list.__iter__(raw):
        cleaned = _jsonable(row) if isinstance(row, dict) else None
        if isinstance(cleaned, dict):
            out.append(cleaned)
    return out


def _as_text(value) -> str:
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    if isinstance(value, str):
        return _utf8_text(value)
    if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
        return ""
    if value is None:
        return ""
    try:
        # RecursionError on leftover ``str(e)`` is handled inside ``_utf8_text``.
        # Calling ``str(value)`` here used to skip that and return "".
        return _utf8_text(value)
    except Exception:
        return ""


def _field_text(value, fallback: str = "") -> str:
    """JSON-safe leftover YAML field (``.inf`` / dates / ``!!binary`` / ``!!set`` / ``\\ud800``)."""
    if value is None or isinstance(value, bool):
        return fallback
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return fallback
        return str(value)
    if isinstance(value, int):
        # A YAML hex/octal leftover dodges the int(str) digit cap, so an
        # override ``port: 0xfff…`` arrives as a >4300-digit int whose str()
        # is ValueError — it used to escape this helper and 500
        # GET /api/apps/managed/detail (and cost inventory whole sections).
        try:
            return str(value)
        except ValueError:
            return fallback
    if isinstance(value, str):
        return _utf8_text(value)
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    if isinstance(value, (dict, list, tuple, set, frozenset)):
        return fallback
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        try:
            text = iso()
            return _utf8_text(text) if isinstance(text, str) and text else fallback
        except Exception:
            return fallback
    try:
        text = str(value)
    except Exception:
        return fallback
    return _utf8_text(text) if text else fallback


def _optional_text(value) -> str | None:
    text = _field_text(value, "")
    return text or None


def _exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


def _is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


def _is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def _scrub_utf8(value, depth: int = 0):
    if depth > 32:
        return None
    if isinstance(value, str):
        return _utf8_text(value)
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            try:
                key = k if isinstance(k, str) else str(k)
                key = _utf8_text(key)
            except Exception:
                continue
            out[key] = _scrub_utf8(v, depth + 1)
        return out
    if isinstance(value, list):
        return [_scrub_utf8(v, depth + 1) for v in value]
    return value


def _safe_payload(payload):
    """Starlette encodes with allow_nan=False; leftover inf/bytes/dates/``\\ud800`` 500 the Apps page."""
    if not isinstance(payload, dict):
        return payload
    cleaned = _jsonable(payload)
    if not isinstance(cleaned, dict):
        return payload
    return _scrub_utf8(cleaned)
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
        # _clean_rows: one hostile row (subclass ``.get``/``__bool__`` bomb,
        # huge int, surrogate) used to raise out of this loop and cost the
        # whole docker section of the Apps page via _collect's fallback.
        stacks = _clean_rows(containers_svc.list_stacks())
    except Exception:
        stacks = []
    # map stack path → containers via compose project label or cwd
    containers = []
    try:
        from hub import containers_svc
        containers = _container_rows(
            containers_svc.list_containers(with_stats=False)
        )
    except Exception:
        pass

    for s in stacks:
        sid = s.get("id") if isinstance(s.get("id"), str) else ""
        raw_path = s.get("path") if isinstance(s.get("path"), str) else ""
        if not sid:
            try:
                sid = Path(raw_path).name
            except (OSError, ValueError, TypeError):
                continue
        if not sid:
            continue
        path = raw_path or str(SERVICES_ROOT / sid)
        compose_file = s.get("compose_file")
        if not isinstance(compose_file, str) or not compose_file:
            compose_file = "docker-compose.yml"
        try:
            compose = Path(path) / compose_file
        except (OSError, ValueError, TypeError):
            continue
        # match containers by compose project name or name prefix
        related = []
        running_names = s.get("running_containers")
        if not isinstance(running_names, list):
            running_names = []
        for c in containers:
            if not isinstance(c, dict):
                continue
            proj = str(c.get("project") or "")
            cid = str(c.get("id") or "")
            if proj == sid or cid == sid or cid in running_names or c.get("id") in running_names:
                related.append(c)
        # use stack's own list when project labels missing
        if not related and running_names:
            by_id = {}
            for c in containers:
                if not isinstance(c, dict):
                    continue
                ident = c.get("id")
                if isinstance(ident, bool) or not isinstance(ident, (str, int)):
                    continue
                by_id[ident] = c
                by_id[str(ident)] = c
            for n in running_names:
                if isinstance(n, bool) or not isinstance(n, (str, int)):
                    continue
                if n in by_id:
                    related.append(by_id[n])
        n_running = sum(1 for c in related if c.get("state") == "ok" or c.get("raw_state") == "running")
        st = s.get("status") or ("ok" if n_running else "down")
        ports = []
        for c in related:
            p = c.get("ports") or ""
            if p:
                ports.append(str(p))
        # stack autostart: any related container has restart policy
        auto_n = sum(1 for c in related if c.get("autostart"))
        url = _url_from_docker_ports(ports) or _url_from_known_stack(sid)
        acts = _docker_actions(n_running, len(related), bool(s.get("compose_path") or _exists(compose)))
        if url and "open" not in acts:
            acts = list(acts) + ["open"]
        n_known = len(related) or len(running_names)
        items.append({
            "id": f"docker:{sid}",
            "source_id": sid,
            "kind": "docker",
            "name": _field_text(s.get("name"), sid) or sid,
            "state": "ok" if n_running or st == "ok" else ("warn" if related else "down"),
            "status_text": (
                f"{n_running}/{n_known} containers running"
                if n_known
                else (_field_text(st, "down") or "down")
            ),
            "path": path,
            "compose_file": _optional_text(s.get("compose_path")) or (
                str(compose) if _exists(compose) else None
            ),
            "installed": True,
            "ports_summary": " · ".join(ports[:4]) if ports else "",
            "container_count": n_known,
            "running_count": n_running,
            "autostart": auto_n > 0,
            "autostart_detail": f"{auto_n}/{len(related)} containers autostart" if related else None,
            "actions": acts,
            "category": "docker",
            "url": url,
        })
    # orphan compose dirs under Services with docker-compose.yml not in stacks
    try:
        known = {s.get("id") for s in stacks if isinstance(s, dict)}
        if _is_dir(SERVICES_ROOT):
            for d in sorted(SERVICES_ROOT.iterdir()):
                if not _is_dir(d) or d.name in known:
                    continue
                if _exists(d / "docker-compose.yml") or _exists(d / "compose.yml"):
                    items.append({
                        "id": f"docker:{d.name}",
                        "source_id": d.name,
                        "kind": "docker",
                        "name": d.name,
                        "state": "down",
                        "status_text": "compose directory (not registered)",
                        "path": str(d),
                        "compose_file": str(d / "docker-compose.yml") if _exists(d / "docker-compose.yml") else str(d / "compose.yml"),
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
    for raw in port_strs:
        ps = raw if isinstance(raw, str) else (str(raw) if raw not in (None, "") else "")
        if not ps:
            continue
        # 0.0.0.0:4000->4000/tcp  or  [::]:8123->8123/tcp
        m = re.search(r"(?:0\.0\.0\.0|127\.0\.0\.1|\[::\]):(\d+)->", ps)
        if not m:
            m = re.search(r":(\d+)->", ps)
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
    if not DOCKER or not _exists(Path(DOCKER)):
        return soft_fail("services.docker_unavailable")
    p = Path(compose_path)
    if not _exists(p):
        return soft_fail("compose.file_missing", path=str(p))
    try:
        rc, msg = run_capped(
            [DOCKER, "compose", "-f", str(p), *args],
            cwd=str(p.parent),
            timeout=timeout,
            env=dict(os.environ),
            cap=4000,
        )
        text = (_as_text(msg) or f"exit {rc}").strip()
        unreachable = looks_engine_down(text) or (
            # The DOCKER binary vanished between the _exists() gate above and
            # this spawn: run_capped's exact ``(-1, "not found")`` sentinel,
            # which used to fall through as an uncoded ``ok: false`` the SPA
            # cannot translate.  The sentinel is any FileNotFoundError spawn
            # — a stack directory (the compose cwd) deleted between the
            # _exists(p) gate and the spawn raises identically — so the
            # binary must be confirmed gone from disk before it reads as a
            # vanished CLI (the compose_svc / actions convention): with the
            # CLI still present and the engine merely off, the coded 503
            # pointed the operator at the wrong remedy.
            rc == -1 and looks_cli_vanished(text) and not cli_on_disk()
        )
        if rc != 0 and unreachable and not engine_up(force=True):
            # Every Apps-page compose action (up/stop/restart/pull/logs) used
            # to hand the raw untranslated daemon stderr back as ok:false,
            # pointing away from the real remedy (start the engine).  Same
            # convention as network_svc._classify_docker_failure, kept as the
            # coded soft-fail because this helper's contract is a dict the SPA
            # renders.  The probe is *forced*: the memoised answer has a 5s
            # TTL and the seconds right after the engine stops are when a
            # stale "up" would misclassify this.  A failure while the engine
            # really is up keeps the daemon's message -- it is then the truth.
            return soft_fail("container.engine_down")
        return {"ok": rc == 0, "message": text}
    except Exception as e:
        return {"ok": False, "message": _as_text(e)}


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
            # leftover ``str(exc)`` RecursionError / ``\\ud800`` used to 500 GET /api/apps.
            return _as_text(exc)[-4000:]
        return _as_text(out or err)[-4000:]

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


def _container_rows(payload) -> list:
    """``list_containers()`` rows, laundered, or [] for the wrong shape.

    A list leftover (or ``containers: 5``) used to raise on ``.get`` /
    ``for c in 5`` and 500 the Apps detail and logs pages.  _mapping_get +
    _clean_rows: a dict-subclass payload whose ``.get`` bombs, a
    list-subclass ``containers`` whose ``__iter__`` bombs, and per-row
    subclass ``.get`` / value ``__bool__``/``__eq__`` bombs all still
    500'd GET /api/apps/managed/detail, GET /api/apps/managed/logs and
    the POST /api/apps/managed/action autostart branch after that.
    """
    return _clean_rows(_mapping_get(payload, "containers"))


def _docker_detail(source_id: str) -> dict:
    from hub import containers_svc
    path = str(SERVICES_ROOT / source_id)
    compose = Path(path) / "docker-compose.yml"
    if not _exists(compose):
        compose = Path(path) / "compose.yml"
    try:
        containers = _container_rows(containers_svc.list_containers(with_stats=False))
    except Exception:
        # list_containers itself can raise (a hostile cached row KeyErrors
        # its own aggregation, or the engine backend is unreachable); that
        # must cost the containers section of the detail page, never the
        # route — _docker_stacks already absorbs this same call.
        containers = []
    related = []
    for c in containers:
        if not isinstance(c, dict):
            continue
        proj = str(c.get("project") or "")
        cid = str(c.get("id") or c.get("name") or "")
        # A numeric inspect Id used to reach startswith as an int and 500 the
        # Apps detail page.  Skip the empty-prefix match that would attach
        # every container to a blank source_id.
        if proj == source_id or cid == source_id or (source_id and cid.startswith(str(source_id))):
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
        net_settings = data.get("NetworkSettings") if isinstance(data.get("NetworkSettings"), dict) else {}
        for m in data.get("Mounts") if isinstance(data.get("Mounts"), list) else []:
            if not isinstance(m, dict):
                continue
            mounts.append({
                "container": name,
                "type": m.get("Type"),
                "source": m.get("Source"),
                "destination": m.get("Destination"),
                "rw": m.get("RW"),
            })
        nets = net_settings.get("Networks") if isinstance(net_settings.get("Networks"), dict) else {}
        for net_name, net in nets.items():
            if not isinstance(net, dict):
                continue
            networks.append({
                "container": name,
                "network": net_name,
                "ip": net.get("IPAddress"),
                "gateway": net.get("Gateway"),
            })
        ports_map = net_settings.get("Ports") if isinstance(net_settings.get("Ports"), dict) else {}
        for cport, binds in ports_map.items():
            if binds and isinstance(binds, list):
                for b in binds:
                    if not isinstance(b, dict):
                        continue
                    ports.append({
                        "container": name,
                        "published": f"{b.get('HostIp') or '0.0.0.0'}:{b.get('HostPort')}",
                        "target": cport,
                    })
            else:
                ports.append({"container": name, "published": None, "target": cport})
        cfg_app = data.get("Config") if isinstance(data.get("Config"), dict) else {}
        for e in cfg_app.get("Env") if isinstance(cfg_app.get("Env"), list) else []:
            if not isinstance(e, str):
                continue
            if any(k in e.upper() for k in ("PASSWORD", "SECRET", "TOKEN", "KEY=")):
                env_sample.append(f"{e.split('=', 1)[0]}=***")
            else:
                env_sample.append(e)

    data_paths = []
    root = Path(path)
    if _is_dir(root):
        for sub in ("data", "config", "pgdata", "redis", "media", "library", "uploads", "downloads"):
            p = root / sub
            if _exists(p):
                data_paths.append(str(p))
        data_paths.append(str(root))

    db_hints = []
    for m in mounts:
        if not isinstance(m, dict):
            continue
        dest = str(m.get("destination") or "").lower()
        src = str(m.get("source") or "")
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
        "compose_file": str(compose) if _exists(compose) else None,
        "containers": [
            {
                "name": str(c.get("id") or c.get("name") or ""),
                "image": _optional_text(c.get("image")),
                "state": _optional_text(c.get("state") or c.get("status")),
                "ports": _optional_text(c.get("ports")) if not isinstance(c.get("ports"), (dict, list)) else c.get("ports"),
                "id": str(c.get("cid") or c.get("id") or ""),
            }
            for c in related
        ],
        "ports": ports[:40],
        "networks": networks[:40],
        "mounts": mounts[:40],
        "data_paths": data_paths[:20],
        "databases": db_hints[:10],
        "env_sample": env_sample[:30],
        "actions": _docker_actions(running, len(related), _exists(compose)) + (
            ["open"] if (_url_from_docker_ports(
                [str(c.get("ports") or "") for c in related if c.get("ports")]
            ) or _url_from_known_stack(source_id)) else []
        ),
        "url": _url_from_docker_ports(
            [str(c.get("ports") or "") for c in related if c.get("ports")]
        ) or _url_from_known_stack(source_id),
        "host_ip": _host_ip(),
    }


def _docker_logs(source_id: str, lines: int = 120) -> dict:
    path = SERVICES_ROOT / source_id
    compose = path / "docker-compose.yml"
    if not _exists(compose):
        compose = path / "compose.yml"
    if _exists(compose):
        r = _compose_cmd(str(compose), "logs", "--no-color", "--tail", str(lines), timeout=60)
        out = {"ok": r["ok"], "log": r["message"], "source": str(compose)}
        if isinstance(r.get("code"), str):
            # engine-down (or another coded soft-fail): keep the code so the
            # SPA can translate it instead of rendering raw daemon stderr.
            out["code"] = r["code"]
        return out
    # fallback: logs of matching containers
    from hub import containers_svc
    try:
        containers = _container_rows(containers_svc.list_containers(with_stats=False))
    except Exception:
        # Same guard as _docker_detail: a raising list_containers used to
        # 500 GET /api/apps/managed/logs instead of answering "no logs".
        containers = []
    matching = []
    for c in containers:
        if not isinstance(c, dict):
            continue
        name = c.get("name") if isinstance(c.get("name"), str) else str(c.get("id") or "")
        labels = c.get("labels") if isinstance(c.get("labels"), dict) else {}
        proj = labels.get("com.docker.compose.project") or ""
        if proj == source_id or (isinstance(name, str) and name.startswith(source_id or "")):
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
    # _clean_rows: one hostile row (subclass ``.get``/``__bool__`` bomb, a
    # huge int, a lone surrogate) used to raise out of this loop and cost
    # the whole native section of the Apps page via _collect's fallback.
    raw = _clean_rows(native_catalog.list_native_apps(force=force))
    installed = [
        a for a in raw
        if a.get("installed") and isinstance(a.get("id"), str)
    ]

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
        # isinstance(str) gates: a leftover junk ``package`` /
        # ``launchd_label`` (a dict or list from a torn native listing) is
        # unhashable, and the ``.get`` lookups below used to raise
        # TypeError — costing the whole native section via _collect.
        pkg_name = a.get("package")
        launchd_label = a.get("launchd_label")
        if not isinstance(launchd_label, str):
            launchd_label = ""
        if isinstance(pkg_name, str) and pkg_name and a.get("method") in ("brew_formula", "brew_cask"):
            auto_id = f"brew:{pkg_name}"
            auto = brew_autostart.get(pkg_name)
        elif launchd_label or a.get("id") in ("native-filebrowser", "native-homeassistant"):
            label = launchd_label or (
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
                auto = _is_file(cloudflared_svc.PLIST)
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
            "name": _field_text(a.get("name"), a["id"]) or a["id"],
            # already filtered to installed; state from running (None → ok)
            "state": state,
            "status_text": (
                "running" if running else ("stopped" if running is False or state == "down" else "installed")
            ),
            "path": None,
            "package": a.get("package"),
            "method": a.get("method"),
            "installed": True,
            "ports_summary": ", ".join(
                str(p) for p in (a.get("ports") if isinstance(a.get("ports"), list) else [])
                if p not in (None, "")
            ),
            "autostart": auto,
            "autostart_id": auto_id,
            "actions": acts,
            "category": _field_text(a.get("category"), "other") or "other",
            "url": _optional_text(url) if url else None,
            "notes": _field_text(a.get("notes"), ""),
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
    # _clean_rows: a subclass ``.get``/``__eq__`` bomb row, or a value
    # ``__bool__`` bomb behind ``listed.get("running")`` below, used to 500
    # GET /api/apps/managed/detail for every native app while the listing
    # itself rendered fine.  The try: a *raising* listing (brew backend
    # torn mid-probe) must fall back to the static catalog entry, never
    # 500 the route — _native_apps reaches this same call through
    # _collect's fallback.
    try:
        listed_rows = _clean_rows(native_catalog.list_native_apps(force=True))
    except Exception:
        listed_rows = []
    listed = next(
        (a for a in listed_rows if a.get("id") == source_id),
        {},
    )
    pkg = app.get("package")
    pkg_key = pkg.split("@", 1)[0] if isinstance(pkg, str) and pkg else ""
    data_paths = []
    home = user_home()
    # common brew prefixes
    bases = [Path("/opt/homebrew/var"), Path("/usr/local/var")]
    if home is not None:
        bases.append(home / "Library/Application Support")
    bases.append(SERVICES_ROOT)
    for base in bases:
        if not _exists(base) or not pkg_key:
            continue
        # look for package-named dirs
        try:
            candidates = list(base.glob(f"*{pkg_key}*"))
        except (OSError, ValueError):
            continue
        for cand in candidates:
            if _is_dir(cand):
                data_paths.append(str(cand))
    if source_id == "native-filebrowser":
        data_paths.append(str(SERVICES_ROOT / "filebrowser"))
    if app.get("open"):
        app_path = Path(f"/Applications/{app['open']}.app")
        if _exists(app_path):
            data_paths.append(str(app_path))

    from hub.native_catalog import _port_list
    port_nums = _port_list(app.get("ports"))
    ports = [{"published": f"0.0.0.0:{p}", "target": p} for p in port_nums]
    # live listen check
    listen = []
    try:
        from hub import tools_svc
        for row in (tools_svc.listening_ports(80).get("ports") or []):
            if not isinstance(row, dict):
                continue
            name = row.get("name") or ""
            for p in port_nums:
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
            out["cloudflared"] = {"ok": False, "message": _as_text(e)}
    return out


def _native_logs(source_id: str, lines: int = 120) -> dict:
    from hub import native_catalog
    app = next((a for a in native_catalog.NATIVE_APPS if a["id"] == source_id), None)
    if not app:
        return {"ok": False, "log": "unknown app"}
    if source_id == "native-cloudflared":
        from hub import cloudflared_svc
        try:
            return cloudflared_svc.logs(lines=lines)
        except Exception as e:
            # A raising backend used to 500 the logs modal; exc_detail, not
            # bare str(e): a leftover ``\ud800`` / RecursionError in the
            # message must cost the message, never the modal (the _vm_logs
            # convention).
            return {"ok": False, "log": exc_detail(e)}
    pkg = app.get("package")
    chunks = []
    home = user_home()
    # brew services log paths
    for logp in (
        Path(f"/opt/homebrew/var/log/{pkg}.log") if pkg else None,
        Path(f"/opt/homebrew/var/log/{pkg}/error.log") if pkg else None,
        (home / f"Library/Logs/{pkg}.log") if pkg and home is not None else None,
    ):
        if logp and _exists(logp):
            try:
                chunks.append(
                    f"===== {logp} =====\n" + "\n".join(tail_file_lines(logp, lines))
                )
            except Exception as e:
                chunks.append(f"{logp}: {_as_text(e)}")
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
            chunks.append(f"===== launchctl =====\n{_as_text(out or err)[-3000:]}")
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
    from hub import config
    from hub.launchd_cache import Listing
    from hub.launchd_cache import listing as launchd_listing
    from hub.paths import AGENTS_DIR
    from hub.services_uninstall_svc import PROTECTED_LABELS

    _EMPTY_LISTING = Listing({})

    agents = Path(AGENTS_DIR)
    if not _is_dir(agents):
        return []
    try:
        listing = launchd_listing()
    except Exception:
        listing = _EMPTY_LISTING
    catalog = _catalog_launchd_labels()
    items = []
    try:
        plists = sorted(agents.glob("*.plist"))
    except OSError:
        return []
    for path in plists:
        label = path.stem
        low = label.lower()
        if low in PROTECTED_LABELS or low in catalog:
            continue
        if any(low.startswith(prefix) for prefix in _BREW_AGENT_PREFIXES):
            continue
        program = ""
        workdir = ""
        data = _plist_dict(path)
        if data is None:
            program = ""
            workdir = ""
        else:
            args = data.get("ProgramArguments") or []
            if not isinstance(args, list):
                args = []
            # leftover RecursionError on ``str(Label)`` / argv used to 500 GET /api/apps.
            program = _as_text(args[0] if args else data.get("Program"))
            workdir = _as_text(data.get("WorkingDirectory"))
            label = _as_text(data.get("Label") or label) or path.stem
            if program and not workdir:
                workdir = _as_text(Path(program).parent)
        # launchctl prints "-" in the pid column for a loaded-but-idle agent,
        # so the raw column is truthy for a job that is not running at all.
        # pid_for() tests it for digits; loaded says whether launchd knows the
        # label, which is the difference between idle and not installed.
        pid = listing.pid_for(label)
        running = pid is not None
        loaded = label in listing.loaded
        entry = listing.jobs.get(label)
        last = entry[1] if entry else None
        keep = bool(data.get("KeepAlive")) if data else False
        ov = config.override(label) or {}
        name = _field_text(ov.get("name"), label) or label
        acts = (
            ["stop", "restart", "detail", "logs", "uninstall"]
            if running
            else ["start", "detail", "logs", "uninstall"]
        )
        if running:
            status_text = f"Running · pid {pid}"
        elif loaded and last not in (None, "", "-", "0") and keep:
            status_text = f"Crash-looping · last exit {last}"
        elif loaded and last not in (None, "", "-", "0"):
            status_text = f"Exited · last exit {last}"
        elif loaded:
            status_text = "Loaded but not running"
        else:
            status_text = "Not loaded"
        items.append({
            "id": f"launchd:{label}",
            "source_id": label,
            "kind": "launchd",
            "name": name,
            "state": "ok" if running else "down",
            "status_text": status_text,
            "path": workdir,
            "package": None,
            "method": "launchd",
            "installed": True,
            "ports_summary": _field_text(ov.get("port"), ""),
            "autostart": True,
            "autostart_id": f"launchd:{label}",
            "actions": acts,
            "category": _field_text(ov.get("group"), "other") or "other",
            "url": _optional_text(ov.get("url")),
        })
    return items


def _launchd_detail(label: str) -> dict:
    from hub import services_uninstall_svc
    listed = next((item for item in _launchd_apps() if item.get("source_id") == label), None)
    if not listed:
        raise api_error("apps.launchd_not_found")
    # Laundered like every other cross-module payload merged into a detail
    # page: a subclass ``.get`` bomb or ``__bool__`` bomb value in the
    # uninstall preview must cost its field, never the whole detail route.
    # The try covers a *raising* preview the same way — the agent is
    # already confirmed listed, so a preview that cannot be computed (the
    # plist vanished mid-request, a torn reader) costs the preview fields
    # only; the coded not-found for a vanished agent is raised above.
    try:
        preview = _jsonable(services_uninstall_svc.preview(label))
    except Exception:
        preview = None
    if not isinstance(preview, dict):
        preview = {}
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
    from hub.paths import AGENTS_DIR

    path = Path(AGENTS_DIR) / f"{label}.plist"
    if not _is_file(path):
        raise api_error("apps.launchd_not_found")
    chunks = []
    data = _plist_dict(path)
    if data is None:
        return {"ok": False, "log": "invalid plist", "source": "launchd"}
    for key in ("StandardOutPath", "StandardErrorPath"):
        logp = data.get(key)
        if not logp:
            continue
        try:
            p = Path(str(logp)).expanduser()
        except (OSError, ValueError, TypeError, RuntimeError):
            # RuntimeError: leftover HOME unset on ``~/Library/Logs/…``.
            # _as_text, not ``{logp!s}``: an over-cap plist ``<integer>``
            # (hex spelling dodges the int(str) parse cap) lands here via
            # the digit-cap ValueError, and formatting it again raised the
            # same ValueError *inside* the handler — 500ing
            # GET /api/apps/managed/logs instead of reporting the bad path.
            chunks.append(f"===== {_as_text(logp) or '(unprintable)'} =====\n(invalid path)")
            continue
        if not _is_file(p):
            chunks.append(f"===== {p} =====\n(missing)")
            continue
        try:
            chunks.append(
                f"===== {p} =====\n" + "\n".join(tail_file_lines(p, lines))
            )
        except OSError as exc:
            chunks.append(f"{p}: {_as_text(exc)}")
    if not chunks:
        chunks.append("No StandardOutPath / StandardErrorPath on this agent.")
    return {"ok": True, "log": "\n\n".join(chunks), "source": "launchd"}


# ─── VMs ─────────────────────────────────────────────────────────────────────

def _vm_rows(payload) -> list[dict]:
    """``list_all_vms()`` rows, laundered.

    A dict-subclass payload whose ``.get`` bombs, per-row subclass
    ``.get``/``__eq__`` bombs, a list-subclass ``ips`` whose ``__iter__``
    bombs, and value ``__bool__`` bombs behind ``v.get("state") or ""``
    all still 500'd GET /api/apps/managed/detail for VMs (and cost the
    whole VM section of the inventory via _collect's fallback).
    """
    return _clean_rows(_mapping_get(payload, "vms"))


def _vms() -> list[dict]:
    from hub import vms_svc
    items = []
    for v in _vm_rows(vms_svc.list_all_vms()):
        state = v.get("state") or v.get("status") or "unknown"
        running = state in ("ok", "running", "started")
        vid = v.get("id") or v.get("uuid") or v.get("name")
        items.append({
            "id": f"vm:{vid}",
            "source_id": vid,
            "kind": "vm",
            "name": _field_text(v.get("display_name") or v.get("name"), str(vid) if vid else "") or (
                _field_text(vid, "") or ""
            ),
            "state": "ok" if running else ("stopped" if state in ("stopped", "stop") else _field_text(state, "unknown")),
            "status_text": _field_text(v.get("detail"), "") or _field_text(state, ""),
            "backend": _optional_text(v.get("backend")),
            "path": None,
            "installed": True,
            "ports_summary": "",
            "ips": [
                ip for ip in (v.get("ips") if isinstance(v.get("ips"), list) else [])
                if isinstance(ip, str) or (isinstance(ip, (int, float)) and ip == ip and ip not in (float("inf"), float("-inf")))
            ],
            "url": _optional_text(v.get("url")),
            "actions": _vm_actions(v),
            "category": "vm",
        })
    return items


def _vm_actions(v: dict) -> list[str]:
    raw_acts = v.get("actions")
    acts = list(raw_acts) if isinstance(raw_acts, list) else []
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
    try:
        vm_rows = _vm_rows(vms_svc.list_all_vms())
    except Exception:
        # A raising list_all_vms (utmctl torn mid-listing) used to 500 the
        # detail route; with no rows the lookup below answers the same
        # coded 404 an unusable payload already does.
        vm_rows = []
    v = next(
        (
            x for x in vm_rows
            if (x.get("id") or x.get("uuid") or x.get("name")) == source_id
        ),
        None,
    )
    if not v:
        raise api_error("apps.vm_not_found")
    ips = v.get("ips") if isinstance(v.get("ips"), list) else []
    return {
        "id": f"vm:{source_id}",
        "source_id": source_id,
        "kind": "vm",
        "name": v.get("display_name") or v.get("name") or source_id,
        "state": v.get("state"),
        "backend": v.get("backend"),
        "uuid": v.get("uuid"),
        "ips": ips,
        "url": v.get("url"),
        "detail": v.get("detail"),
        "ports": [],
        "networks": [{"network": "vm", "ip": ip} for ip in ips],
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
        try:
            log = json.dumps(
                _jsonable(d), ensure_ascii=False, indent=2, allow_nan=False,
            )[:8000]
        except (TypeError, ValueError, OverflowError, RecursionError):
            log = ""
        return {
            "ok": True,
            "log": log,
            "source": "vm-status",
        }
    except HTTPException:
        # apps.vm_not_found (the row vanished between the list and the logs
        # click) used to be swallowed into ``str(e)`` — the Python dict repr
        # ``404: {'code': …}`` that the logs modal rendered verbatim.  The
        # coded 404 is what the SPA translates, exactly as the launchd
        # branch already answers for a vanished agent.
        raise
    except Exception as e:
        # exc_detail, not bare str(e): a leftover ``\ud800`` / RecursionError
        # in a backend message must cost the message, never the modal.
        return {"ok": False, "log": exc_detail(e)}


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
            str(x.get("name") or ""),
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
        "ts": strftime_now("%H:%M:%S"),
        "items": all_items,
        "counts": counts,
        "host_ip": host,
        # _truthy: a non-bool leftover from the engine probe used to be
        # stringified into the payload as an object repr; the flag's
        # contract is a bool, and a value that cannot even answer
        # __bool__ reads as down (the tools7 convention).
        "engine_up": engine if isinstance(engine, bool) else _truthy(engine),
    }
    return _safe_payload(v)


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
        return _safe_payload(_docker_detail(source_id))
    if kind == "native":
        return _safe_payload(_native_detail(source_id))
    if kind == "launchd":
        return _safe_payload(_launchd_detail(source_id))
    if kind == "vm":
        return _safe_payload(_vm_detail(source_id))
    raise api_error("apps.unknown_kind", kind=kind)


def logs(app_id: str, lines: int = 120) -> dict:
    kind, _, source_id = app_id.partition(":")
    if not source_id:
        # Same bare-id rule as detail(): an empty source used to fall through
        # — ``_docker_logs("")`` prefix-matched *every* container, so
        # GET /api/apps/managed/logs?id=docker answered the whole fleet's
        # logs concatenated for an id that names nothing.
        if app_id.startswith("native-"):
            kind, source_id = "native", app_id
        else:
            raise api_error("apps.bad_id")
    source_id = cli_args.require_positional(source_id, label="app id")
    try:
        lines = max(20, min(int(lines or 120), 500))
    except (TypeError, ValueError, OverflowError):
        lines = 120
    if kind == "docker":
        return _safe_payload(_docker_logs(source_id, lines))
    if kind == "native":
        return _safe_payload(_native_logs(source_id, lines))
    if kind == "launchd":
        return _safe_payload(_launchd_logs(source_id, lines))
    if kind == "vm":
        return _safe_payload(_vm_logs(source_id, lines))
    raise api_error("apps.unknown_kind", kind=kind)


def action(app_id: str, action_name: str, **kwargs) -> dict:
    """start|stop|restart|update|uninstall|suspend|autostart_on|autostart_off

    The result is laundered like detail() and logs(): most branches hand
    back another module's payload verbatim (autostart toggles, vm_action,
    uninstall previews), and a lone surrogate, a >4300-digit int or raw
    bytes in one of those used to 500 Starlette's encoder *after* the
    action had already run.
    """
    return _safe_payload(_action(app_id, action_name, **kwargs))


def _action(app_id: str, action_name: str, **kwargs) -> dict:
    action_name = (action_name or "").strip().lower()
    kind, _, source_id = app_id.partition(":")
    if not source_id:
        # Same bare-id rule as detail(): an empty source used to fall
        # through and act on the Services root itself (``docker compose``
        # at ~/Services, autostart across every prefix-matched container).
        if app_id.startswith("native-"):
            kind, source_id = "native", app_id
        else:
            raise api_error("apps.bad_id")
    source_id = cli_args.require_positional(source_id, label="app id")
    invalidate_inventory()

    # Autostart toggles
    if action_name in ("autostart_on", "autostart_off", "enable_autostart", "disable_autostart"):
        enabled = action_name in ("autostart_on", "enable_autostart")
        from hub import autostart_svc
        if kind == "docker":
            # enable for all containers in stack / or single container name
            from hub import containers_svc
            # _container_rows: the raw ``.get("containers") or []`` on a
            # dict-subclass payload (or hostile rows) used to 500
            # POST /api/apps/managed/action before any toggle ran.  The
            # try: a *raising* list_containers falls through to the
            # single-container toggle below, same as an empty listing.
            try:
                containers = _container_rows(
                    containers_svc.list_containers(with_stats=False)
                )
            except Exception:
                containers = []
            related = []
            for c in containers:
                cid = str(c.get("id") or "")
                if (
                    str(c.get("project") or "") == source_id
                    or cid == source_id
                    or (source_id and cid.startswith(str(source_id)))
                ):
                    related.append(c)
            if not related:
                # try treat source_id as container name
                return autostart_svc.set_docker_autostart(source_id, enabled)
            results = []
            ok = True
            for c in related:
                ident = str(c.get("id") or "")
                if not ident:
                    continue
                r = autostart_svc.set_docker_autostart(ident, enabled)
                # _mapping_get/_truthy/_as_text: the toggle result is another
                # module's payload — a subclass ``.get`` bomb or ``__bool__``
                # bomb here used to 500 the action after toggles already ran.
                results.append(f"{ident}: {_as_text(_mapping_get(r, 'message'))}")
                ok = ok and _truthy(_mapping_get(r, "ok"))
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
                    if not _is_file(cloudflared_svc.TOKEN_FILE):
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
        if not _exists(compose):
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
            out = {
                "ok": r1["ok"] and r2["ok"],
                "message": (r1["message"] + "\n" + r2["message"])[-2500:],
            }
            code = next(
                (r.get("code") for r in (r1, r2) if isinstance(r.get("code"), str)),
                None,
            )
            if code:
                out["code"] = code
            return out
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
            try:
                rc, out, err = actions.run_action(source_id, action_name)
            except HTTPException:
                # actions.unknown_target and friends: the coded answer the
                # SPA translates.
                raise
            except Exception as e:
                # A torn registry row / raising backend used to 500 the
                # action instead of reporting the failure.
                return {"ok": False, "message": _as_text(e)}
            return {
                "ok": rc == 0,
                "message": _as_text(out or err).strip() or action_name,
            }
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
                if not _exists(plist):
                    # re-run install to materialize plist if missing
                    from hub import native_catalog as nc
                    r = nc.install_native(source_id)
                    return r
                return _launchctl_load(label, plist)
            if action_name == "stop":
                return _launchctl_unload(label)
            if action_name == "restart":
                if _exists(plist):
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
                if _is_file(cloudflared_svc.TOKEN_FILE):
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
            # _raise_if_brew_vanished: these are the same ``brew services``
            # spawns as autostart_svc.set_brew_autostart and _run_brew, but
            # this path handed the uncoded ``{ok: false, message: "not
            # found"}`` sentinel straight back to the SPA when brew vanished
            # between inventory and the click.  The disk confirmation inside
            # keeps a raw sentinel from a still-present brew untouched.
            from hub.native_catalog import _raise_if_brew_vanished, _run, BREW
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
                    return _raise_if_brew_vanished(
                        _run([BREW, "services", "start", pkg], timeout=120)
                    )
                if app.get("open"):
                    return _run(["/usr/bin/open", "-a", app["open"]], timeout=15)
            if action_name == "stop":
                if app.get("method") == "brew_formula":
                    return _raise_if_brew_vanished(
                        _run([BREW, "services", "stop", pkg], timeout=120)
                    )
                if app.get("open"):
                    return _run(
                        ["/usr/bin/osascript", "-e", f'quit app "{app["open"]}"'],
                        timeout=15,
                    )
            if action_name == "restart":
                if app.get("method") == "brew_formula":
                    return _raise_if_brew_vanished(
                        _run([BREW, "services", "restart", pkg], timeout=120)
                    )
            if action_name == "open" and app.get("open"):
                return _run(["/usr/bin/open", "-a", app["open"]], timeout=15)
        raise api_error("apps.native_action_unsupported", action=action_name)

    if kind == "vm":
        from hub import vms_svc
        if action_name == "uninstall":
            action_name = "delete"
        if action_name == "pause":
            # "suspend" is the verb vms_svc speaks (``utmctl suspend``); the
            # mapping used to run the other way (suspend → "pause", an action
            # no backend has), so the Apps-page suspend button on a running
            # UTM VM — offered by _vm_actions — always answered the coded
            # vms.utm_unsupported_action 400 instead of suspending.
            action_name = "suspend"
        return vms_svc.vm_action(source_id, action_name)

    raise api_error("apps.unknown_kind", kind=kind)
