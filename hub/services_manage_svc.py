"""Per-service management for the Services page: detail, logs, overrides."""
from __future__ import annotations

import glob
import os
import plistlib
from pathlib import Path

from hub import cli_args, config
from hub.config import cfg, override, set_override
from hub.errors import api_error
from hub.group_rules import match_group
from hub.host_address import host_ip, normalize_local_url, resolve_value
from hub.paths import AGENTS_DIR, DOCKER, UID, user_home
from hub.service_signatures import (
    builtin_count,
    configured_signatures,
    identify,
    infer_control,
    is_generic_runtime,
    parse_signature,
    remember_into,
    remove_from,
    suggest_id,
    unescape_proc_name,
    yaml_signature,
)
from hub.status import _jsonable, full_status, invalidate_status
from hub.util import read_bytes_capped, sh, tail_file_lines


def _as_text(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    if value is None:
        return ""
    try:
        return str(value)
    except RecursionError:
        try:
            return type(value).__name__
        except Exception:
            return ""
    except Exception:
        return ""


def _as_int(value):
    """Finite int, or None.  ``int(inf)`` OverflowError is not ValueError."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _clamp_lines(raw, default: int = 150) -> int:
    value = _as_int(raw)
    if value is None:
        value = default
    return max(10, min(value, 2000))


def _flat_services(force: bool = False) -> list[dict]:
    st = full_status(force=force)
    items = []
    for g in st.get("groups") or []:
        if not isinstance(g, dict):
            continue
        rows = g.get("services")
        if not isinstance(rows, list):
            continue
        for s in rows:
            if isinstance(s, dict):
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


def _svc_meta(svc: dict | None) -> dict:
    """Discovery ``meta`` must be a mapping; a list leftover must not 500."""
    raw = (svc or {}).get("meta")
    return raw if isinstance(raw, dict) else {}


#: Leftover multi-MB LaunchAgent plist used to OOM GET /api/services.
_PLIST_CAP = 256 * 1024


def _plist_dict(path: Path) -> dict | None:
    try:
        data = plistlib.loads(read_bytes_capped(path, _PLIST_CAP))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _plist_label(path: Path) -> str:
    """The job launchd registered, not the filename stem."""
    pl = _plist_dict(path)
    if pl and pl.get("Label"):
        # leftover RecursionError on ``str(Label)`` used to 500 GET /api/services.
        return _as_text(pl["Label"]) or path.stem
    return path.stem


def _plist_path(label: str) -> Path | None:
    """Resolve a launchd job to its plist by Label, then filename stem.

    Discovery keys rows on ``Label``.  A renamed file used to make detail
    and logs look for ``<label>.plist`` and miss the job.
    """
    wanted = str(label or "")
    if not wanted:
        return None
    p = Path(AGENTS_DIR) / f"{wanted}.plist"
    try:
        if p.is_file() and _plist_label(p) == wanted:
            return p
    except OSError:
        pass
    try:
        paths = sorted(glob.glob(f"{AGENTS_DIR}/*.plist"))
    except OSError:
        return None
    for path in paths:
        candidate = Path(path)
        if _plist_label(candidate) == wanted:
            return candidate
    return None


def _load_plist(label: str) -> dict:
    p = _plist_path(label)
    if not p:
        return {}
    return _plist_dict(p) or {}


def _tail_file(path: str | Path, lines: int = 150) -> str:
    try:
        p = Path(os.path.expanduser(_as_text(path)))
    except (OSError, ValueError, TypeError, RuntimeError):
        # RuntimeError: leftover HOME unset on a ``~/…`` StandardOutPath.
        return f"(invalid log path: {path!s})"
    try:
        if not p.is_file():
            return f"(log file does not exist: {p})"
        return "\n".join(tail_file_lines(p, _clamp_lines(lines)))
    except (OSError, ValueError, RuntimeError, RecursionError) as e:
        # leftover ``str(e)`` RecursionError used to 500 GET /api/services logs.
        return f"(read failed: {_as_text(e)})"


def _docker_inspect(name: str) -> dict:
    try:
        docker_ok = bool(DOCKER) and Path(DOCKER).exists()
    except (OSError, ValueError, TypeError):
        docker_ok = False
    if not docker_ok:
        return {}
    if not cli_args.is_safe_positional(name):
        return {}
    rc, out, _ = sh(
        [DOCKER, "inspect", "--format", "{{json .}}", "--", name], timeout=15
    )
    if rc != 0 or not out:
        return {}
    try:
        import json
        parsed = json.loads(out)
    except (TypeError, ValueError, RecursionError):
        # RecursionError: leftover deeply-nested ``{{json .}}`` is not ValueError.
        return {}
    if not isinstance(parsed, dict):
        return {}
    cleaned = _jsonable(parsed)
    return cleaned if isinstance(cleaned, dict) else {}


def _docker_ports_summary(insp: dict) -> list[str]:
    out = []
    ns = insp.get("NetworkSettings") or {}
    if not isinstance(ns, dict):
        ns = {}
    net = ns.get("Ports") or {}
    if not isinstance(net, dict):
        return out
    for cont_port, binds in net.items():
        if not binds:
            out.append(f"{cont_port} (not published)")
            continue
        if not isinstance(binds, list):
            continue
        for b in binds:
            if not isinstance(b, dict):
                continue
            host = b.get("HostIp") or "0.0.0.0"
            hp = b.get("HostPort") or "?"
            out.append(f"{host}:{hp}→{cont_port}")
    return out


def _url_from_inspect(insp: dict) -> str | None:
    host = host_ip()
    skip = {"1883", "5432", "6379", "3306", "5672", "9092", "9100"}
    ns = insp.get("NetworkSettings") or {}
    if not isinstance(ns, dict):
        ns = {}
    net = ns.get("Ports") or {}
    if not isinstance(net, dict):
        return None
    for cont_port, binds in net.items():
        if not binds or not isinstance(binds, list):
            continue
        cp = str(cont_port).split("/")[0]
        if cp in skip:
            continue
        for b in binds:
            if not isinstance(b, dict):
                continue
            hp = b.get("HostPort")
            if hp:
                return f"http://{host}:{hp}"
    return None


def service_detail(sid: str) -> dict:
    sid = cli_args.require_positional(sid, label="service id")
    svc = find_service(sid, force=True)
    if not svc:
        raise api_error("services.not_found", id=sid)
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
        "ports": svc.get("ports") if isinstance(svc.get("ports"), list) else [],
        "links": svc.get("links") if isinstance(svc.get("links"), list) else [],
        "actions": [a for a in svc.get("actions") if isinstance(a, str)] if isinstance(svc.get("actions"), list) else [],
        "meta": _svc_meta(svc),
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
        argv = pl.get("ProgramArguments")
        # leftover RecursionError on ``str(argv-item)`` used to 500 GET detail.
        argv = [_as_text(a) for a in argv] if isinstance(argv, list) else []
        detail["program"] = pl.get("Program") or (" ".join(argv) if argv else None)
        detail["working_dir"] = pl.get("WorkingDirectory")
        detail["run_at_load"] = bool(pl.get("RunAtLoad"))
        detail["keep_alive"] = pl.get("KeepAlive")
        detail["start_interval"] = pl.get("StartInterval")
        detail["calendar"] = pl.get("StartCalendarInterval")
        detail["stdout_path"] = pl.get("StandardOutPath")
        detail["stderr_path"] = pl.get("StandardErrorPath")
        # launchctl print snapshot (short)
        rc, out, err = sh(["/bin/launchctl", "print", f"gui/{UID}/{sid}"], timeout=6)
        out, err = _as_text(out), _as_text(err)
        if rc == 0 and out:
            # keep first ~40 lines
            detail["launchctl"] = "\n".join(out.splitlines()[:40])
        elif err:
            detail["launchctl"] = err[:500]
        # live ports from meta
        meta = _svc_meta(svc)
        if not detail.get("port") and meta.get("detected_ports"):
            detail["ports"] = meta.get("detected_ports")

    elif kind == "container":
        insp = _docker_inspect(sid)
        if insp:
            cfg_c = insp.get("Config") if isinstance(insp.get("Config"), dict) else {}
            state = insp.get("State") if isinstance(insp.get("State"), dict) else {}
            host_cfg = insp.get("HostConfig") if isinstance(insp.get("HostConfig"), dict) else {}
            detail["image"] = cfg_c.get("Image")
            detail["created"] = insp.get("Created")
            detail["status_raw"] = state.get("Status")
            detail["started_at"] = state.get("StartedAt")
            detail["finished_at"] = state.get("FinishedAt")
            rp = host_cfg.get("RestartPolicy") if isinstance(host_cfg.get("RestartPolicy"), dict) else {}
            detail["restart_policy"] = rp.get("Name")
            detail["network_mode"] = host_cfg.get("NetworkMode")
            detail["ports"] = _docker_ports_summary(insp)
            if not detail.get("url"):
                detail["url"] = ov.get("url") or _url_from_inspect(insp)
            labels = cfg_c.get("Labels") if isinstance(cfg_c.get("Labels"), dict) else {}
            detail["compose_project"] = labels.get("com.docker.compose.project")
            detail["compose_service"] = labels.get("com.docker.compose.service")
            mounts = []
            for m in insp.get("Mounts") if isinstance(insp.get("Mounts"), list) else []:
                if not isinstance(m, dict):
                    continue
                mounts.append({
                    "source": m.get("Source"),
                    "destination": m.get("Destination"),
                    "type": m.get("Type"),
                    "rw": m.get("RW"),
                })
            detail["mounts"] = mounts[:30]
            env = cfg_c.get("Env") if isinstance(cfg_c.get("Env"), list) else []
            # Redact by key AND by value.  This detail is reachable by member
            # accounts for services on their list, and a key-name allowlist
            # leaks secrets carried under innocuous names: DATABASE_URL=
            # postgres://user:pass@host, DSNs, connection strings.  So also
            # redact any value that embeds credentials in a URL (scheme://…@…)
            # or is a long opaque token.
            redacted = []
            for e in env[:40]:
                if isinstance(e, str) and "=" in e:
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
            if not isinstance(a, dict):
                continue
            if a.get("id") == sid:
                detail["process"] = a.get("process")
                detail["config"] = {k: a.get(k) for k in a if k not in ("id",)}
                break

    elif kind == "script":
        for s in cfg().get("scripts") or []:
            if not isinstance(s, dict):
                continue
            if s.get("id") == sid:
                detail["start_cmd"] = s.get("start")
                detail["stop_cmd"] = s.get("stop")
                detail["check"] = s.get("check") or s.get("ports")
                detail["config"] = s
                detail["can_edit_script"] = True
                detail["can_forget"] = True
                detail["script_defaults"] = {
                    "name": s.get("name") or sid,
                    "group": s.get("group") or "Custom",
                    "url": s.get("url") or "",
                    "ports": list(s.get("ports")) if isinstance(s.get("ports"), list) else [],
                    "start": s.get("start") or "",
                    "stop": s.get("stop") or "",
                    "adopted": bool(s.get("adopted_from")),
                }
                detail["actions"] = sorted(set(detail["actions"]) | {"forget"})
                break

    elif kind == "auto":
        detail["notes"] = "Auto-discovered listening port; you can edit the display name/URL, or hide it."
        detail["can_logs"] = False
        meta = _svc_meta(svc)
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

    cleaned = _jsonable(detail)
    return cleaned if isinstance(cleaned, dict) else {"id": sid}


def service_logs(sid: str, lines: int = 150) -> dict:
    sid = cli_args.require_positional(sid, label="service id")
    svc = find_service(sid, force=False) or find_service(sid, force=True)
    kind = (svc or {}).get("kind") or ""
    lines = _clamp_lines(lines)
    log = ""
    source = ""

    if kind == "container" or (not kind and _docker_inspect(sid)):
        if not DOCKER:
            raise api_error("services.docker_unavailable")
        rc, out, err = sh([DOCKER, "logs", "--tail", str(lines), sid], timeout=30)
        log = (_as_text(out) or _as_text(err)).strip() or f"(no output · exit {rc})"
        source = f"docker logs {sid}"
        kind = kind or "container"

    elif kind == "launchd" or _plist_path(sid):
        pl = _load_plist(sid)
        paths = []
        for key in ("StandardErrorPath", "StandardOutPath"):
            if pl.get(key):
                paths.append(pl[key])
        # common defaults
        home = user_home()
        home_logs = None if home is None else home / "Library/Logs"
        if home_logs is not None:
            for guess in (
                home_logs / f"{sid}.err.log",
                home_logs / f"{sid}.log",
                home_logs / f"{sid}.out.log",
            ):
                try:
                    exists = guess.is_file()
                except OSError:
                    exists = False
                if exists and str(guess) not in paths:
                    paths.append(str(guess))
        chunks = []
        for p in paths[:4]:
            chunks.append(f"===== {p} =====\n{_tail_file(p, lines)}")
        if not chunks:
            # launchctl print as fallback diagnostic
            rc, out, err = sh(["/bin/launchctl", "print", f"gui/{UID}/{sid}"], timeout=6)
            chunks.append(_as_text(out) or _as_text(err) or "(no StandardErrorPath / log file)")
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
            def _src_name(row):
                n = row.get("name")
                return n.lower() if isinstance(n, str) else ""
            hit = next(
                (s for s in sources if s["id"] == sid or sid in _src_name(s)),
                None,
            )
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
            log = _as_text(e)
            source = "error"

    elif kind in ("app", "app-engine"):
        log = "(desktop apps have no unified log; check Console.app or the app's own logs)"
        source = "n/a"

    else:
        # try docker then launchd without recursion
        if DOCKER:
            rc, out, err = sh([DOCKER, "logs", "--tail", str(lines), sid], timeout=20)
            text = (_as_text(out) or _as_text(err)).strip()
            if rc == 0 and text:
                return _jsonable({
                    "id": sid,
                    "kind": "container",
                    "source": f"docker logs {sid}",
                    "log": text,
                    "lines": lines,
                })
        pp = _plist_path(sid)
        if pp:
            pl = _load_plist(sid)
            chunks = []
            for key in ("StandardErrorPath", "StandardOutPath"):
                if pl.get(key):
                    chunks.append(f"===== {pl[key]} =====\n{_tail_file(pl[key], lines)}")
            if not chunks:
                rc, out, err = sh(["/bin/launchctl", "print", f"gui/{UID}/{sid}"], timeout=6)
                chunks.append(_as_text(out) or _as_text(err) or "(no log paths)")
                source = "launchctl print"
            else:
                source = "plist log paths"
            return _jsonable({
                "id": sid,
                "kind": "launchd",
                "name": (svc or {}).get("name") or sid,
                "source": source,
                "log": "\n\n".join(chunks),
                "lines": lines,
            })
        raise api_error("services.no_logs", id=sid)

    return _jsonable({
        "id": sid,
        "kind": kind,
        "name": (svc or {}).get("name") or sid,
        "source": source,
        "log": log,
        "lines": lines,
    })


def update_override(sid: str, patch: dict) -> dict:
    """Update display override: name, group, url, port, hide."""
    sid = cli_args.require_positional(sid, label="service id")
    allowed = {"name", "group", "url", "port", "hide"}
    clean = {}
    for k, v in (patch or {}).items():
        if k not in allowed:
            continue
        if k == "port":
            if v is None or v == "":
                clean[k] = None
            else:
                n = _as_int(v)
                if n is None:
                    raise api_error("services.bad_port")
                clean[k] = n
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
    pid = _as_int(pid)
    if pid is None or pid <= 0:
        return ""
    rc, out, _ = sh(["/bin/ps", "-p", str(pid), "-o", "comm="], timeout=5)
    out = _as_text(out)
    if rc != 0 or not out.strip():
        return ""
    comm = out.strip().splitlines()[0]
    try:
        name = Path(comm).name
    except (OSError, ValueError, TypeError):
        name = comm.rsplit("/", 1)[-1]
    return unescape_proc_name(name)


def _process_command_path(pid) -> str:
    """First argv token of the live process — the binary, never the rest.

    The remainder of ``ps -o command=`` often carries tokens and passwords,
    and this value is shown on the Services page and written into
    services.yaml provenance.  The path alone is enough to recover a
    Homebrew formula (``…/opt/postgresql@17/bin/postgres``).
    """
    pid = _as_int(pid)
    if pid is None or pid <= 0:
        return ""
    rc, out, _ = sh(["/bin/ps", "-p", str(pid), "-o", "command="], timeout=5)
    out = _as_text(out)
    if rc != 0 or not out.strip():
        return ""
    line = out.strip().splitlines()[0]
    try:
        import shlex

        parts = shlex.split(line)
    except ValueError:
        parts = line.split()
    return parts[0] if parts else ""


def _clean_cmd(value) -> str | None:
    """A single-line command, or None. Newlines would become extra argv later."""
    if value is None:
        return None
    text = str(value).strip()
    if not text or "\n" in text or "\r" in text:
        return None
    return text


def _taken_service_ids() -> set[str]:
    data = cfg()
    taken = set()
    for key in ("apps", "scripts", "stacks"):
        entries = data.get(key)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, dict) and entry.get("id"):
                taken.add(str(entry["id"]))
    return taken


def adopt_defaults(svc: dict) -> dict:
    """Suggested services.yaml entry for an auto-discovered listener.

    Shown by the UI as the pre-filled adopt form, and used verbatim when the
    caller adopts without overriding anything.
    """
    meta = _svc_meta(svc)
    process = _full_process_name(meta.get("pid")) or meta.get("process") or ""
    command_path = _process_command_path(meta.get("pid"))
    raw_ports = meta.get("ports")
    if not isinstance(raw_ports, list):
        raw_ports = [meta["port"]] if meta.get("port") else []
    ports = []
    for p in raw_ports:
        n = _as_int(p)
        if n is None:
            continue
        if 1 <= n <= 65535 and n not in ports:
            ports.append(n)
    # Re-identify at adopt time so brew/http follow the current library and
    # any operator signatures in services.yaml, not a stale list snapshot.
    sig = identify(
        process or meta.get("process") or "",
        ports[0] if ports else None,
        extras=configured_signatures(),
    )
    if not isinstance(sig, dict):
        sig = meta.get("signature")
    if not isinstance(sig, dict):
        sig = svc.get("signature")
    if not isinstance(sig, dict):
        sig = {}
    recognised = sig.get("confidence") == "high"
    name = sig["name"] if recognised else (process or svc.get("name") or "")
    group = sig.get("category") if recognised else None
    matched = match_group({
        "id": svc.get("id"),
        "image": svc.get("image") or meta.get("image") or "",
        "compose_project": svc.get("compose_project") or meta.get("compose_project") or "",
        "port": ports[0] if ports else None,
        "ports": ports,
        "meta": {"process": process or meta.get("process") or ""},
    })
    if matched:
        group = matched
    control = infer_control(sig, command_path)
    return {
        "id": suggest_id(
            sig.get("slug") if recognised else "",
            process,
            f"port-{ports[0]}" if ports else "",
            taken=_taken_service_ids(),
        ),
        "name": name,
        "group": group or "Adopted",
        "ports": ports,
        "url": svc.get("url"),
        "process": process,
        "command": command_path,
        "start": control.get("start"),
        "stop": control.get("stop"),
        "control_via": control.get("via"),
        "formula": control.get("formula"),
        # Already-recognised daemons do not need another rule; unknowns do.
        "remember": not recognised,
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
        p = _as_int(p)
        if p is None:
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
    # start/stop: an explicit key (even empty) wins so the operator can
    # clear an inferred brew command; an omitted key keeps the inference.
    if "start" in patch:
        start = _clean_cmd(patch.get("start"))
    else:
        start = defaults.get("start")
    if "stop" in patch:
        stop = _clean_cmd(patch.get("stop"))
    else:
        stop = defaults.get("stop")
    if start:
        entry["start"] = start
    if stop:
        entry["stop"] = stop
    # Provenance, so the operator can later tell adopted entries from
    # hand-written ones when editing services.yaml.
    adopted_from = {
        "process": defaults.get("process") or _svc_meta(svc).get("process"),
        "auto_id": sid,
    }
    if defaults.get("formula"):
        adopted_from["brew"] = defaults["formula"]
    if defaults.get("command"):
        adopted_from["command"] = defaults["command"]
    entry["adopted_from"] = adopted_from

    remember = patch.get("remember")
    if remember is None:
        remember = defaults.get("remember")
    learned = None
    if remember:
        learned = _signature_from_adopt(
            slug=new_id,
            name=entry["name"],
            category=entry["group"],
            process=defaults.get("process"),
            ports=ports,
            url=entry.get("url"),
            formula=defaults.get("formula"),
        )
        if learned is not None and not entry.get("url"):
            live = identify(
                defaults.get("process") or "",
                ports[0] if ports else None,
                extras=configured_signatures(),
            )
            if live and live.get("http") is False:
                learned["http"] = False

    stored_sig = None

    def apply(data: dict) -> None:
        nonlocal stored_sig
        scripts = data.get("scripts")
        if not isinstance(scripts, list):
            scripts = []
            data["scripts"] = scripts
        scripts.append(entry)
        # The auto row disappears on its own once the port is claimed, but a
        # stale hide/override for it would silently apply to nothing forever.
        ov = data.get("overrides")
        if isinstance(ov, dict):
            ov.pop(sid, None)
        if learned:
            stored_sig = remember_into(data, learned)

    config.mutate(apply)
    invalidate_status()
    result = {"ok": True, "id": new_id, "entry": entry}
    if stored_sig:
        result["signature"] = stored_sig
    return result


def _signature_from_adopt(
    *,
    slug: str,
    name: str,
    category: str,
    process: str | None,
    ports: list[int],
    url: str | None,
    formula: str | None,
) -> dict | None:
    """A learnable signature from an adopt form, or None if it would be noise.

    Generic runtimes (node, python, …) are omitted from ``procs`` so remembering
    "My API" running on node does not rename every other node listener.
    """
    procs = []
    if process and not is_generic_runtime(process):
        procs.append(process)
    http = True if url else None
    return parse_signature({
        "slug": slug,
        "name": name,
        "category": category,
        "procs": procs,
        "ports": ports,
        "http": http,
        "brew": formula,
    })


def _parse_ports(raw) -> list[int]:
    ports: list[int] = []
    rows = raw if isinstance(raw, (list, tuple, set, frozenset)) else []
    for p in rows:
        n = _as_int(p)
        if n is None:
            continue
        if 1 <= n <= 65535 and n not in ports:
            ports.append(n)
    return ports


def update_script(sid: str, patch: dict | None = None) -> dict:
    """Rewrite a services.yaml ``scripts`` entry (adopted or hand-written)."""
    sid = cli_args.require_positional(sid, label="service id")
    patch = patch or {}
    scripts = cfg().get("scripts")
    if not any(
        isinstance(s, dict) and s.get("id") == sid
        for s in (scripts if isinstance(scripts, list) else [])
    ):
        raise api_error("services.script_not_found", id=sid)
    if "ports" in patch:
        ports = _parse_ports(patch.get("ports"))
        if not ports:
            raise api_error("services.adopt_no_port", id=sid)
        patch = {**patch, "ports": ports}

    updated: dict = {}

    def apply(data: dict) -> None:
        for entry in data.get("scripts") or []:
            if not isinstance(entry, dict) or entry.get("id") != sid:
                continue
            if "name" in patch:
                name = str(patch.get("name") or "").strip()
                if name:
                    entry["name"] = name
            if "group" in patch:
                group = str(patch.get("group") or "").strip()
                if group:
                    entry["group"] = group
            if "url" in patch:
                url = str(patch.get("url") or "").strip()
                if url:
                    entry["url"] = normalize_local_url(url)
                else:
                    entry.pop("url", None)
            if "ports" in patch:
                entry["ports"] = list(patch["ports"])
            if "start" in patch:
                start = _clean_cmd(patch.get("start"))
                if start:
                    entry["start"] = start
                else:
                    entry.pop("start", None)
            if "stop" in patch:
                stop = _clean_cmd(patch.get("stop"))
                if stop:
                    entry["stop"] = stop
                else:
                    entry.pop("stop", None)
            updated.update(entry)
            return

    config.mutate(apply)
    if not updated:
        raise api_error("services.script_not_found", id=sid)
    invalidate_status()
    return {"ok": True, "id": sid, "entry": updated}


def forget_script(sid: str) -> dict:
    """Remove a ``scripts`` entry so a still-listening port can be rediscovered.

    The learned ``service_signatures`` rule is kept: forgetting the managed
    card should not make the next discovery anonymous again.
    """
    sid = cli_args.require_positional(sid, label="service id")
    removed: dict = {}

    def apply(data: dict) -> None:
        scripts = data.get("scripts")
        if not isinstance(scripts, list):
            scripts = []
        keep = []
        for entry in scripts:
            if isinstance(entry, dict) and entry.get("id") == sid:
                removed.update(entry)
                continue
            keep.append(entry)
        data["scripts"] = keep
        ov = data.get("overrides")
        if isinstance(ov, dict):
            ov.pop(sid, None)

    config.mutate(apply)
    if not removed:
        raise api_error("services.script_not_found", id=sid)
    invalidate_status()
    return {"ok": True, "id": sid, "removed": removed}


def list_signatures() -> dict:
    """Operator-defined recognition rules, plus how many builtins exist."""
    cleaned = _jsonable({
        "signatures": [yaml_signature(s) for s in configured_signatures()],
        "builtin_count": builtin_count(),
    })
    return cleaned if isinstance(cleaned, dict) else {"signatures": [], "builtin_count": 0}


def upsert_signature(patch: dict | None = None) -> dict:
    """Write or replace one operator recognition rule in services.yaml."""
    parsed = parse_signature(patch or {})
    if not parsed:
        raise api_error("services.signature_invalid")
    stored: dict = {}

    def apply(data: dict) -> None:
        stored.update(remember_into(data, parsed))

    config.mutate(apply)
    invalidate_status()
    return {"ok": True, "signature": stored}


def forget_signature(slug: str) -> dict:
    """Drop one operator recognition rule. Built-in signatures are untouched."""
    parsed = parse_signature({"slug": slug, "name": slug})
    if not parsed:
        raise api_error("services.signature_invalid")
    removed: dict = {}

    def apply(data: dict) -> None:
        row = remove_from(data, parsed["slug"])
        if row:
            removed.update(row)

    config.mutate(apply)
    if not removed:
        raise api_error("services.signature_not_found", slug=parsed["slug"])
    invalidate_status()
    return {"ok": True, "slug": parsed["slug"], "removed": removed}


def list_group_rules() -> dict:
    """Effective grouping rules plus whether they came from yaml or seeds."""
    from hub import group_rules

    cleaned = _jsonable(group_rules.list_rules())
    if not isinstance(cleaned, dict):
        return {"rules": [], "source": "seed"}
    rules = cleaned.get("rules")
    cleaned["rules"] = rules if isinstance(rules, list) else []
    source = cleaned.get("source")
    cleaned["source"] = source if source in ("yaml", "seed") else "seed"
    return cleaned


def _bust_group_rule_views() -> None:
    invalidate_status()
    try:
        from hub.discovery.containers import invalidate_containers

        invalidate_containers()
    except Exception:
        pass


def save_group_rules(payload: dict | None = None) -> dict:
    """Upsert one grouping rule, or replace the whole list."""
    from hub import group_rules

    result = group_rules.save_rules(payload if isinstance(payload, dict) else {})
    _bust_group_rule_views()
    cleaned = _jsonable(result)
    return cleaned if isinstance(cleaned, dict) else {"ok": True}


def delete_group_rule(rule_id: str) -> dict:
    """Drop one grouping rule. Materialises seeds into yaml when needed."""
    from hub import group_rules

    result = group_rules.delete_rule(rule_id)
    _bust_group_rule_views()
    cleaned = _jsonable(result)
    return cleaned if isinstance(cleaned, dict) else {"ok": True}


def enrich_service_list_item(s: dict) -> dict:
    """Add management action hints used by Services UI (non-breaking)."""
    if not isinstance(s, dict):
        return {"actions": []}
    raw = s.get("actions")
    acts = list(raw) if isinstance(raw, list) else []
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
    raw_groups = st.get("groups") if isinstance(st.get("groups"), list) else []
    for g in raw_groups:
        if not isinstance(g, dict):
            continue
        rows = g.get("services") if isinstance(g.get("services"), list) else []
        svcs = [enrich_service_list_item(s) for s in rows if isinstance(s, dict)]
        groups.append({"group": g.get("group"), "services": svcs})
    return {
        **st,
        "groups": groups,
    }
