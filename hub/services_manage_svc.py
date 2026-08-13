"""Per-service management for the Services page: detail, logs, overrides."""
from __future__ import annotations

import glob
import os
import plistlib
from pathlib import Path

from fastapi import HTTPException

from hub import config
from hub.config import cfg, override, set_override
from hub.errors import api_error
from hub.host_address import host_ip, normalize_local_url, resolve_value
from hub.paths import AGENTS_DIR, DOCKER, UID
from hub.service_signatures import suggest_id
from hub.status import full_status, invalidate_status
from hub.util import sh


def _flat_services(force: bool = False) -> list[dict]:
    st = full_status(force=force)
    items = []
    for g in st.get("groups") or []:
        for s in g.get("services") or []:
            items.append(s)
    return items


def find_service(sid: str, force: bool = False) -> dict | None:
    sid = (sid or "").strip()
    if not sid:
        return None
    for s in _flat_services(force=force):
        if s.get("id") == sid:
            return s
    return None


def _plist_path(label: str) -> Path | None:
    p = Path(AGENTS_DIR) / f"{label}.plist"
    if p.is_file():
        return p
    for path in glob.glob(f"{AGENTS_DIR}/*.plist"):
        if Path(path).stem == label:
            return Path(path)
    return None


def _load_plist(label: str) -> dict:
    p = _plist_path(label)
    if not p:
        return {}
    try:
        with open(p, "rb") as f:
            return plistlib.load(f) or {}
    except Exception:
        return {}


def _tail_file(path: str | Path, lines: int = 150) -> str:
    p = Path(os.path.expanduser(str(path)))
    if not p.is_file():
        return f"(log file does not exist: {p})"
    lines = max(10, min(int(lines), 2000))
    try:
        with open(p, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            data = b""
            block = 4096
            while size > 0 and data.count(b"\n") <= lines:
                step = min(block, size)
                size -= step
                f.seek(size)
                data = f.read(step) + data
            text = data.decode("utf-8", errors="replace")
            return "\n".join(text.splitlines()[-lines:])
    except Exception as e:
        return f"(read failed: {e})"


def _docker_inspect(name: str) -> dict:
    if not DOCKER or not Path(DOCKER).exists():
        return {}
    rc, out, _ = sh([DOCKER, "inspect", name, "--format", "{{json .}}"], timeout=15)
    if rc != 0 or not out:
        return {}
    try:
        import json
        return json.loads(out)
    except Exception:
        return {}


def _docker_ports_summary(insp: dict) -> list[str]:
    out = []
    net = (insp.get("NetworkSettings") or {}).get("Ports") or {}
    for cont_port, binds in net.items():
        if not binds:
            out.append(f"{cont_port} (not published)")
            continue
        for b in binds:
            host = b.get("HostIp") or "0.0.0.0"
            hp = b.get("HostPort") or "?"
            out.append(f"{host}:{hp}→{cont_port}")
    return out


def _url_from_inspect(insp: dict) -> str | None:
    host = host_ip()
    skip = {"1883", "5432", "6379", "3306", "5672", "9092", "9100"}
    net = (insp.get("NetworkSettings") or {}).get("Ports") or {}
    for cont_port, binds in net.items():
        if not binds:
            continue
        cp = str(cont_port).split("/")[0]
        if cp in skip:
            continue
        for b in binds:
            hp = b.get("HostPort")
            if hp:
                return f"http://{host}:{hp}"
    return None


def service_detail(sid: str) -> dict:
    svc = find_service(sid, force=True)
    if not svc:
        raise HTTPException(404, f"service not found: {sid}")
    ov = resolve_value(override(sid))
    kind = svc.get("kind") or ""
    detail: dict = {
        "id": sid,
        "name": svc.get("name") or sid,
        "kind": kind,
        "state": svc.get("state"),
        "detail": svc.get("detail"),
        "url": svc.get("url"),
        "group": svc.get("group"),
        "port": svc.get("port"),
        "ports": svc.get("ports") or [],
        "links": svc.get("links") or [],
        "actions": list(svc.get("actions") or []),
        "meta": svc.get("meta") or {},
        "auto": bool(svc.get("auto")),
        "backend": svc.get("backend"),
        "override": ov,
        "can_logs": kind in ("container", "launchd", "script", "app", "app-engine"),
        "can_hide": True,
        "can_edit": True,
    }

    # Ensure open/logs/hide appear as logical actions for UI
    acts = set(detail["actions"])
    if detail.get("url") or ov.get("url"):
        acts.add("open")
    if detail["can_logs"]:
        acts.add("logs")
    acts.update({"detail", "hide", "edit"})
    if kind == "container":
        st = (svc.get("state") or "")
        if st == "ok":
            acts.update({"restart", "stop", "pause"})
        elif st == "stopped":
            acts.update({"start", "remove"})
        else:
            acts.update({"start", "stop", "restart"})
    detail["actions"] = sorted(acts)

    if kind == "launchd":
        pl = _load_plist(sid)
        pp = _plist_path(sid)
        detail["plist"] = str(pp) if pp else None
        detail["program"] = pl.get("Program") or (
            " ".join(pl.get("ProgramArguments") or []) if pl.get("ProgramArguments") else None
        )
        detail["working_dir"] = pl.get("WorkingDirectory")
        detail["run_at_load"] = bool(pl.get("RunAtLoad"))
        detail["keep_alive"] = pl.get("KeepAlive")
        detail["start_interval"] = pl.get("StartInterval")
        detail["calendar"] = pl.get("StartCalendarInterval")
        detail["stdout_path"] = pl.get("StandardOutPath")
        detail["stderr_path"] = pl.get("StandardErrorPath")
        # launchctl print snapshot (short)
        rc, out, err = sh(["/bin/launchctl", "print", f"gui/{UID}/{sid}"], timeout=6)
        if rc == 0 and out:
            # keep first ~40 lines
            detail["launchctl"] = "\n".join(out.splitlines()[:40])
        elif err:
            detail["launchctl"] = err[:500]
        # live ports from meta
        if not detail.get("port") and (svc.get("meta") or {}).get("detected_ports"):
            detail["ports"] = (svc.get("meta") or {}).get("detected_ports")

    elif kind == "container":
        insp = _docker_inspect(sid)
        if insp:
            cfg_c = insp.get("Config") or {}
            state = insp.get("State") or {}
            host_cfg = insp.get("HostConfig") or {}
            detail["image"] = cfg_c.get("Image")
            detail["created"] = insp.get("Created")
            detail["status_raw"] = state.get("Status")
            detail["started_at"] = state.get("StartedAt")
            detail["finished_at"] = state.get("FinishedAt")
            detail["restart_policy"] = (host_cfg.get("RestartPolicy") or {}).get("Name")
            detail["network_mode"] = host_cfg.get("NetworkMode")
            detail["ports"] = _docker_ports_summary(insp)
            if not detail.get("url"):
                detail["url"] = ov.get("url") or _url_from_inspect(insp)
            labels = cfg_c.get("Labels") or {}
            detail["compose_project"] = labels.get("com.docker.compose.project")
            detail["compose_service"] = labels.get("com.docker.compose.service")
            mounts = []
            for m in insp.get("Mounts") or []:
                mounts.append({
                    "source": m.get("Source"),
                    "destination": m.get("Destination"),
                    "type": m.get("Type"),
                    "rw": m.get("RW"),
                })
            detail["mounts"] = mounts[:30]
            env = cfg_c.get("Env") or []
            # Redact by key AND by value.  This detail is reachable by member
            # accounts for services on their list, and a key-name allowlist
            # leaks secrets carried under innocuous names: DATABASE_URL=
            # postgres://user:pass@host, DSNs, connection strings.  So also
            # redact any value that embeds credentials in a URL (scheme://…@…)
            # or is a long opaque token.
            redacted = []
            for e in env[:40]:
                if "=" in e:
                    k, v = e.split("=", 1)
                    if any(x in k.upper() for x in ("PASS", "SECRET", "TOKEN", "KEY", "PWD", "CRED", "AUTH")):
                        redacted.append(f"{k}=***")
                    elif "://" in v and "@" in v.split("://", 1)[1].split("/", 1)[0]:
                        # credentials embedded in a URL authority
                        redacted.append(f"{k}=***")
                    else:
                        redacted.append(e if len(e) < 120 else e[:117] + "…")
                else:
                    redacted.append(e)
            detail["env_sample"] = redacted

    elif kind == "vm":
        try:
            from hub import vms_svc
            v = vms_svc.get_vm(sid) if hasattr(vms_svc, "get_vm") else None
            if not v:
                # search lists
                for fn in ("list_all", "list_vms", "overview"):
                    if hasattr(vms_svc, fn):
                        try:
                            data = getattr(vms_svc, fn)()
                            arr = data if isinstance(data, list) else (data.get("vms") or data.get("items") or [])
                            v = next((x for x in arr if x.get("id") == sid or x.get("name") == sid), None)
                            if v:
                                break
                        except Exception:
                            pass
            if v:
                detail.update({k: v.get(k) for k in ("backend", "uuid", "ips", "cpu", "memory", "path") if v.get(k) is not None})
                if v.get("url") and not detail.get("url"):
                    detail["url"] = v["url"]
        except Exception:
            pass

    elif kind in ("app", "app-engine"):
        # from services.yaml apps section
        for a in cfg().get("apps") or []:
            if a.get("id") == sid:
                detail["process"] = a.get("process")
                detail["config"] = {k: a.get(k) for k in a if k not in ("id",)}
                break

    elif kind == "script":
        for s in cfg().get("scripts") or []:
            if s.get("id") == sid:
                detail["start_cmd"] = s.get("start")
                detail["stop_cmd"] = s.get("stop")
                detail["check"] = s.get("check") or s.get("ports")
                detail["config"] = s
                break

    elif kind == "auto":
        detail["notes"] = "Auto-discovered listening port; you can edit the display name/URL, or hide it."
        detail["can_logs"] = False
        meta = svc.get("meta") or {}
        detail["process"] = meta.get("process")
        detail["pid"] = meta.get("pid")
        detail["signature"] = meta.get("signature")
        detail["can_adopt"] = True
        detail["adopt_defaults"] = adopt_defaults(svc)
        detail["actions"] = sorted(set(detail["actions"]) | {"adopt"})

    # resolve final open url
    if not detail.get("url") and ov.get("url"):
        detail["url"] = ov["url"]
    if detail.get("url") and "open" not in detail["actions"]:
        detail["actions"] = list(detail["actions"]) + ["open"]

    return detail


def service_logs(sid: str, lines: int = 150) -> dict:
    svc = find_service(sid, force=False) or find_service(sid, force=True)
    kind = (svc or {}).get("kind") or ""
    lines = max(10, min(int(lines), 2000))
    log = ""
    source = ""

    if kind == "container" or (not kind and _docker_inspect(sid)):
        if not DOCKER:
            raise api_error("services.docker_unavailable")
        rc, out, err = sh([DOCKER, "logs", "--tail", str(lines), sid], timeout=30)
        log = (out or err or "").strip() or f"(no output · exit {rc})"
        source = f"docker logs {sid}"
        kind = kind or "container"

    elif kind == "launchd" or _plist_path(sid):
        pl = _load_plist(sid)
        paths = []
        for key in ("StandardErrorPath", "StandardOutPath"):
            if pl.get(key):
                paths.append(pl[key])
        # common defaults
        home_logs = Path.home() / "Library/Logs"
        for guess in (
            home_logs / f"{sid}.err.log",
            home_logs / f"{sid}.log",
            home_logs / f"{sid}.out.log",
        ):
            if guess.is_file() and str(guess) not in paths:
                paths.append(str(guess))
        chunks = []
        for p in paths[:4]:
            chunks.append(f"===== {p} =====\n{_tail_file(p, lines)}")
        if not chunks:
            # launchctl print as fallback diagnostic
            rc, out, err = sh(["/bin/launchctl", "print", f"gui/{UID}/{sid}"], timeout=6)
            chunks.append(out or err or "(no StandardErrorPath / log file)")
            source = "launchctl print"
        else:
            source = "plist log paths"
        log = "\n\n".join(chunks)
        kind = kind or "launchd"

    elif kind == "script":
        # Match configured log sources by exact or fuzzy service ID.
        try:
            from hub import logs_svc
            sources = logs_svc.log_sources()
            hit = next((s for s in sources if s["id"] == sid or sid in (s.get("name") or "").lower()), None)
            if not hit:
                # fuzzy
                for s in sources:
                    if sid.replace("_", "-") in s["id"] or s["id"] in sid:
                        hit = s
                        break
            if hit:
                r = logs_svc.tail_log(hit["id"], lines)
                log = r.get("log") or ""
                source = hit.get("path") or hit["id"]
            else:
                log = "(no script log source configured; add one under settings / log_sources)"
                source = "none"
        except Exception as e:
            log = str(e)
            source = "error"

    elif kind in ("app", "app-engine"):
        log = "(desktop apps have no unified log; check Console.app or the app's own logs)"
        source = "n/a"

    else:
        # try docker then launchd without recursion
        if DOCKER:
            rc, out, err = sh([DOCKER, "logs", "--tail", str(lines), sid], timeout=20)
            if rc == 0 and (out or err):
                return {
                    "id": sid,
                    "kind": "container",
                    "source": f"docker logs {sid}",
                    "log": (out or err).strip(),
                    "lines": lines,
                }
        pp = _plist_path(sid)
        if pp:
            pl = _load_plist(sid)
            chunks = []
            for key in ("StandardErrorPath", "StandardOutPath"):
                if pl.get(key):
                    chunks.append(f"===== {pl[key]} =====\n{_tail_file(pl[key], lines)}")
            if not chunks:
                rc, out, err = sh(["/bin/launchctl", "print", f"gui/{UID}/{sid}"], timeout=6)
                chunks.append(out or err or "(no log paths)")
                source = "launchctl print"
            else:
                source = "plist log paths"
            return {
                "id": sid,
                "kind": "launchd",
                "name": (svc or {}).get("name") or sid,
                "source": source,
                "log": "\n\n".join(chunks),
                "lines": lines,
            }
        raise HTTPException(404, f"no logs for {sid}")

    return {
        "id": sid,
        "kind": kind,
        "name": (svc or {}).get("name") or sid,
        "source": source,
        "log": log,
        "lines": lines,
    }


def update_override(sid: str, patch: dict) -> dict:
    """Update display override: name, group, url, port, hide."""
    if not sid:
        raise HTTPException(400, "sid required")
    allowed = {"name", "group", "url", "port", "hide"}
    clean = {}
    for k, v in (patch or {}).items():
        if k not in allowed:
            continue
        if k == "port":
            if v is None or v == "":
                clean[k] = None
            else:
                try:
                    clean[k] = int(v)
                except (TypeError, ValueError):
                    raise HTTPException(400, "port must be int")
        elif k == "hide":
            clean[k] = bool(v) if v is not None else None
        elif k in ("name", "group", "url"):
            if v is None or (isinstance(v, str) and not v.strip()):
                clean[k] = None  # clear
            else:
                clean[k] = (
                    normalize_local_url(str(v))
                    if k == "url"
                    else str(v).strip()
                )
    cur = set_override(sid, clean)
    invalidate_status()
    return {"ok": True, "id": sid, "override": cur}


def hide_service(sid: str, hide: bool = True) -> dict:
    return update_override(sid, {"hide": hide if hide else None})


def _full_process_name(pid) -> str:
    """The process's real image name — lsof truncates COMMAND to ~9 chars."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return ""
    if pid <= 0:
        return ""
    rc, out, _ = sh(["/bin/ps", "-p", str(pid), "-o", "comm="], timeout=5)
    if rc != 0 or not out.strip():
        return ""
    return Path(out.strip().splitlines()[0]).name


def _taken_service_ids() -> set[str]:
    data = cfg()
    taken = set()
    for key in ("apps", "scripts", "stacks"):
        for entry in data.get(key) or []:
            if isinstance(entry, dict) and entry.get("id"):
                taken.add(str(entry["id"]))
    return taken


def adopt_defaults(svc: dict) -> dict:
    """Suggested services.yaml entry for an auto-discovered listener.

    Shown by the UI as the pre-filled adopt form, and used verbatim when the
    caller adopts without overriding anything.
    """
    meta = svc.get("meta") or {}
    sig = meta.get("signature") or {}
    process = _full_process_name(meta.get("pid")) or meta.get("process") or ""
    recognised = sig.get("confidence") == "high"
    name = sig["name"] if recognised else (process or svc.get("name") or "")
    group = sig.get("category") if recognised else None
    return {
        "id": suggest_id(
            sig.get("slug") if recognised else "",
            process,
            f"port-{meta.get('port')}" if meta.get("port") else "",
            taken=_taken_service_ids(),
        ),
        "name": name,
        "group": group or "Adopted",
        "ports": [meta["port"]] if meta.get("port") else [],
        "url": svc.get("url"),
        "process": process,
    }


def adopt_service(sid: str, patch: dict | None = None) -> dict:
    """Promote an auto-discovered listener into a managed services.yaml script.

    A `scripts` entry rather than an `apps` one: scripts are checked by TCP
    port, which is exactly the evidence adaptive discovery has.  An `apps`
    entry would be checked by `pgrep -x`, and the process name lsof reports is
    truncated, so the adopted service would immediately show as down.
    """
    patch = patch or {}
    svc = find_service(sid, force=True)
    if not svc:
        raise api_error("services.adopt_not_found", id=sid)
    if svc.get("kind") != "auto":
        raise api_error("services.adopt_not_auto", id=sid)

    defaults = adopt_defaults(svc)
    ports = []
    for p in (patch.get("ports") or defaults["ports"]):
        try:
            p = int(p)
        except (TypeError, ValueError):
            continue
        if 1 <= p <= 65535 and p not in ports:
            ports.append(p)
    if not ports:
        raise api_error("services.adopt_no_port", id=sid)

    new_id = suggest_id(
        str(patch.get("id") or "").strip() or defaults["id"],
        taken=_taken_service_ids(),
    )
    entry: dict = {
        "id": new_id,
        "name": str(patch.get("name") or "").strip() or defaults["name"] or new_id,
        "group": str(patch.get("group") or "").strip() or defaults["group"],
        "ports": ports,
    }
    url = str(patch.get("url") or "").strip() or defaults.get("url")
    if url:
        entry["url"] = normalize_local_url(url)
    # Provenance, so the operator can later tell adopted entries from
    # hand-written ones when editing services.yaml.
    entry["adopted_from"] = {
        "process": defaults.get("process") or (svc.get("meta") or {}).get("process"),
        "auto_id": sid,
    }

    def apply(data: dict) -> None:
        scripts = data.setdefault("scripts", [])
        scripts.append(entry)
        # The auto row disappears on its own once the port is claimed, but a
        # stale hide/override for it would silently apply to nothing forever.
        (data.get("overrides") or {}).pop(sid, None)

    config.mutate(apply)
    invalidate_status()
    return {"ok": True, "id": new_id, "entry": entry}


def enrich_service_list_item(s: dict) -> dict:
    """Add management action hints used by Services UI (non-breaking)."""
    acts = list(s.get("actions") or [])
    kind = s.get("kind") or ""
    if s.get("url") and "open" not in acts:
        acts.append("open")
    if kind in ("container", "launchd", "script") and "logs" not in acts:
        acts.append("logs")
    if "detail" not in acts:
        acts.append("detail")
    s = dict(s)
    s["actions"] = acts
    return s


def list_manageable(force: bool = False) -> dict:
    st = full_status(force=force)
    groups = []
    for g in st.get("groups") or []:
        svcs = [enrich_service_list_item(s) for s in (g.get("services") or [])]
        groups.append({"group": g.get("group"), "services": svcs})
    return {
        **st,
        "groups": groups,
    }
