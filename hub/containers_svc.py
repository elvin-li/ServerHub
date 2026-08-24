"""Container / image / volume / network / compose management."""
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import threading
import time
from pathlib import Path

from fastapi import HTTPException

from hub import cli_args
from hub.config import cfg, maintenance_env, override
from hub.errors import api_error
from hub.docker_cli import _as_text, _jsonable, docker, docker_json, engine_up, inspect_object, redact_env
from hub.paths import DATA_DIR, DOCKER, user_home
from hub.host_address import resolve_value
from hub.secure_io import replace_bytes
from hub.status import invalidate_status
from hub.util import iter_capped_lines, read_text_capped, run_capped, safe_json_loads, strftime_now, ttl_memo, utf8_env

# long-running compose / pull jobs (reuse pattern of maintenance)
_cjobs: dict = {}
_cjobs_lock = threading.Lock()

#: Ceiling for a single compose/pull command.  Jobs hold a global mutex (only one
#: container job runs at a time), so a command that never returns would lock the
#: whole subsystem until the panel restarts.
JOB_CMD_TIMEOUT = 1800
#: Cap the retained log so a chatty pull cannot grow a job dict without bound.
JOB_LOG_MAX_LINES = 1000
JOB_LOG_TRIM_LINES = 200
#: Byte-denominated caps beside the line trim above: one enormous line (or a
#: thousand near-cap ones) must not balloon the job dict either.  Same shape
#: as hub/jobs.LOG_LINE_CAP / LOG_TOTAL_CAP.
JOB_LOG_LINE_CAP = 4096
JOB_LOG_TOTAL_CAP = 512 * 1024
#: Cap the number of retained jobs.  Job ids embed a timestamp
#: (``stack-<id>-<action>-<epoch>``), so every run used to add a permanent entry
#: holding up to JOB_LOG_MAX_LINES lines; a panel left running for weeks grew
#: until restart.  The UI only ever shows recent jobs, so old ones are dropped.
JOB_HISTORY_MAX = 40


def _job_epoch() -> int:
    """Finite unix timestamp. Leftover ``time.time() = inf`` OverflowError'd job ids."""
    try:
        return int(time.time())
    except (TypeError, ValueError, OverflowError):
        return 0


def _evict_old_jobs() -> None:
    """Drop the oldest finished jobs until the store fits JOB_HISTORY_MAX.

    Running jobs are never evicted: their ``run()`` thread holds a reference to
    the dict and still writes into it, and callers poll them by id.  Insertion
    order is creation order (dicts preserve it), so the oldest finished job is
    simply the first non-running key.

    Caller must hold ``_cjobs_lock``.
    """
    if len(_cjobs) <= JOB_HISTORY_MAX:
        return
    for key in [
        k for k, v in _cjobs.items()
        if not (isinstance(v, dict) and v.get("running"))
    ]:
        if len(_cjobs) <= JOB_HISTORY_MAX:
            break
        _cjobs.pop(key, None)


def _register_job(tid: str, *, stack_id: str, action: str) -> dict:
    """The one way to add a job.  Enforces the mutex and the history cap.

    Every call site used to inline ``_cjobs[tid] = {...}`` under the lock, which
    meant a new call site could silently reopen the leak.  An AST test forbids
    subscript writes to ``_cjobs`` outside this module's two helpers.

    Returns the live job dict (the ``run()`` thread mutates it in place).
    """
    tid = tid if isinstance(tid, str) else str(tid)
    stack_id = stack_id if isinstance(stack_id, str) else ""
    action = action if isinstance(action, str) else str(action or "")
    with _cjobs_lock:
        if any(isinstance(j, dict) and j.get("running") for j in _cjobs.values()):
            raise api_error("container.job_running")
        _cjobs[tid] = {
            "running": True,
            "rc": None,
            "log": [],
            "started": strftime_now("%H:%M:%S"),
            "finished": None,
            "stack_id": stack_id,
            "action": action,
        }
        _evict_old_jobs()
        return _cjobs[tid]


def _stream_job_command(cmd: list[str], j: dict, *, cwd=None, env=None,
                        timeout: int = JOB_CMD_TIMEOUT) -> int:
    """Run *cmd*, stream its output into ``j["log"]``, and always reap it.

    ``for line in p.stdout`` blocks until the child writes or closes the
    pipe, so an in-loop deadline check alone only fires while output keeps
    flowing — a child that hangs *silently* (a wedged daemon socket, a pull
    stalled before its first byte) blocked the read loop forever, and with it
    the one-job-at-a-time mutex for the whole subsystem.  The deadline is
    therefore enforced by an independent watchdog timer that kills the
    process group (same executor shape as hub/jobs.run_watchdog), which
    closes the pipe and releases the reader.  The child is started in its own
    session so a stuck ``docker compose`` takes its descendants down with it.

    Output is bounded three ways: the existing line-count trim, a per-line
    character cap (``iter_capped_lines`` — one giant line would otherwise be
    buffered whole before the trim could see it), and a total-characters cap.

    Returns the exit status, or 124 when the deadline was hit.
    """
    timed_out = threading.Event()
    argv = cli_args.as_argv(cmd)
    if argv is None:
        j["log"].append("!! invalid argv")
        return -1
    try:
        p = subprocess.Popen(
            argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            # errors="replace": binary junk in CLI output must not kill the read.
            text=True, errors="replace", env=utf8_env(env), start_new_session=True,
        )
    except (OSError, ValueError, TypeError) as exc:
        # Leftover ``\\ud800`` env/cwd UnicodeEncodeError is ValueError, not OSError.
        j["log"].append(f"!! error: {_as_text(exc)}")
        return -1

    with p:
        def _reap():
            # Signal the process group: killing only the docker CLI would
            # leave its children holding the pipe open.
            for sig, grace in ((signal.SIGTERM, 10), (signal.SIGKILL, 5)):
                if p.poll() is not None:
                    return
                try:
                    os.killpg(os.getpgid(p.pid), sig)
                except (ProcessLookupError, PermissionError):
                    return
                try:
                    p.wait(timeout=grace)
                    return
                except subprocess.TimeoutExpired:
                    continue

        def _on_deadline():
            if p.poll() is None:
                timed_out.set()
                j["log"].append(f"!! timeout after {timeout}s - terminating")
                _reap()

        watchdog = threading.Timer(timeout, _on_deadline)
        watchdog.daemon = True
        watchdog.start()
        try:
            assert p.stdout is not None
            total = sum(len(x) for x in j["log"])
            for line in iter_capped_lines(p.stdout, JOB_LOG_LINE_CAP):
                j["log"].append(line)
                total += len(line)
                if len(j["log"]) > JOB_LOG_MAX_LINES:
                    del j["log"][:JOB_LOG_TRIM_LINES]
                    total = sum(len(x) for x in j["log"])
                while total > JOB_LOG_TOTAL_CAP and len(j["log"]) > 1:
                    total -= len(j["log"].pop(0))
        finally:
            watchdog.cancel()
            _reap()
        return 124 if timed_out.is_set() else (p.returncode if p.returncode is not None else -1)


UPDATE_STATUS_PATH = DATA_DIR / "docker-update-status.json"
#: Leftover multi-MB docker-update-status.json used to OOM GET /api/containers.
_UPDATE_STATUS_CAP = 256 * 1024

# docker stats --no-stream is ~2s; cache aggressively for snappy UI.
# Containers page polls every 20s. A 5s list / 15s stats window missed on
# every sit tick (list ~470ms, stats ~2.1s). 22s / 25s lets the poll hit.
_LIST_TTL = 22.0
_STATS_TTL = 25.0


#: Both reads go through ``ttl_memo`` rather than a hand-rolled TTL dict.
#:
#: The dicts these replace checked the cache, released the lock, and only then ran
#: the command -- which is correct only while callers arrive one at a time.  They do
#: not: the panel polls, the menu-bar client polls, and a browser refresh adds a
#: third reader, all landing within milliseconds.  Measured with four concurrent
#: readers on a cold cache: four `docker ps`, four `docker inspect` and four
#: `docker stats`, where one of each would have served all of them -- and
#: `docker stats --no-stream` is the ~2s call, so that is four of those queued on the
#: daemon at once.  ``ttl_memo`` holds the refresh lock across the computation, so
#: the readers that arrive second join the first one's result.
@ttl_memo(_LIST_TTL)
def _container_list_cached() -> tuple[bool, list]:
    return _build_container_list()


@ttl_memo(_STATS_TTL)
def _stats_cached() -> dict:
    """Stats for whatever is currently running.

    Deliberately zero-argument.  Keying this by the running-name tuple would look
    tidier but would buy nothing: every caller wants the current set, so a second
    key can only ever be a set that is already out of date.  One entry on a 15s
    TTL is also exactly what the dict this replaces did.
    """
    engine_ok, items = _container_list_cached()
    if not engine_ok:
        return {}
    return _fetch_stats([i["id"] for i in items if i.get("raw_state") == "running"])


def invalidate_container_lists():
    _container_list_cached.invalidate()
    _stats_cached.invalidate()


def _load_update_status() -> dict:
    try:
        # Path.exists() re-raises EIO/ESTALE; that used to 500 GET /api/containers.
        if not UPDATE_STATUS_PATH.exists():
            return {}
        data = safe_json_loads(read_text_capped(UPDATE_STATUS_PATH, _UPDATE_STATUS_CAP))
        if not isinstance(data, dict):
            return {}
        cleaned = _jsonable(data)
        return cleaned if isinstance(cleaned, dict) else {}
    except (OSError, TypeError, ValueError, RecursionError):
        # RecursionError: leftover deeply-nested update status is not ValueError.
        return {}


def _save_update_status(data: dict) -> None:
    payload = _jsonable(data) if isinstance(data, dict) else {}
    if not isinstance(payload, dict):
        payload = {}
    try:
        UPDATE_STATUS_PATH.parent.mkdir(exist_ok=True)
        replace_bytes(
            UPDATE_STATUS_PATH,
            json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False).encode("utf-8"),
        )
    except (OSError, TypeError, ValueError, OverflowError, RecursionError):
        # RecursionError: leftover nested update status after _jsonable is not
        # OSError; a leftover file occupying the parent used to 500 docker check.
        pass


def _field_text(value, fallback: str = "") -> str:
    """JSON-safe display string for a leftover YAML field.

    ``name: .inf``, ``group: 2026-08-19``, ``!!binary`` and a ``!!set`` each
    used to leak into GET /api/containers and /api/stacks.
    """
    if value is None or isinstance(value, bool):
        return fallback
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return fallback
        return str(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        text = value
    elif isinstance(value, (bytes, bytearray)):
        text = value.decode("utf-8", "replace")
    elif isinstance(value, (dict, list, tuple, set, frozenset)):
        return fallback
    else:
        try:
            text = str(value)
        except Exception:
            return fallback
    if not text:
        return fallback
    return text.encode("utf-8", "replace").decode("utf-8")


def _optional_text(value) -> str | None:
    text = _field_text(value, "")
    return text or None


def _str_list(raw) -> list[str]:
    """Stack ``containers:`` as strings.  ``.inf`` / a scalar leftover must not 500."""
    if not isinstance(raw, list):
        return []
    out = []
    for n in raw:
        if not isinstance(n, str) or not n:
            continue
        text = _field_text(n)
        if text:
            out.append(text)
    return out


def _parse_k8s_name(name: str) -> dict | None:
    """Kubernetes/dockershim container name → readable parts.

    Format: k8s_<container>_<pod>_<namespace>_<pod-uid>_<restart>
    The `k8s_POD_...` variant is the pause/sandbox container for a pod.
    """
    if not name.startswith("k8s_"):
        return None
    parts = name.split("_")
    if len(parts) < 6:
        return None
    container, pod, namespace, restart = parts[1], parts[2], parts[3], parts[-1]
    sandbox = container == "POD"
    return {
        "container": container,
        "pod": pod,
        "namespace": namespace,
        "restart": restart,
        "sandbox": sandbox,
        # app role = pod name without the replicaset/pod hash suffixes
        "app": re.sub(r"-[0-9a-f]{6,10}(-[0-9a-z]{5})?$", "", pod) or pod,
    }


def _friendly_container(name: str, ov: dict) -> dict:
    """Compute display_name / subtitle / grouping for a raw container name."""
    display = _field_text(ov.get("name"))
    if display:
        return {"display_name": display, "subtitle": None, "k8s": None,
                "system": False, "sandbox": False}
    k = _parse_k8s_name(name)
    if not k:
        return {"display_name": name, "subtitle": None, "k8s": None,
                "system": False, "sandbox": False}
    if k["sandbox"]:
        display = f"{k['app']} (pause)"
    else:
        display = k["container"]
    return {
        "display_name": display,
        "subtitle": f"{k['pod']} · {k['namespace']}",
        "k8s": k,
        "system": True,
        "sandbox": k["sandbox"],
    }


def _build_container_list() -> tuple[bool, list]:
    """ps + inspect (no stats). ~50–100ms typical."""
    if not engine_up():
        return False, []
    rc, out, err = docker(
        "ps", "-a",
        "--format",
        "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}\t{{.Ports}}\t"
        '{{.Label "com.docker.compose.project"}}\t{{.Label "com.docker.compose.service"}}\t{{.Size}}',
        timeout=12,
    )
    items = []
    if rc != 0:
        return True, items
    for line in _as_text(out).splitlines():
        p = line.split("\t")
        if len(p) < 6:
            continue
        cid, name, image, state, status = p[0], p[1], p[2], p[3], p[4]
        ports = p[5] if len(p) > 5 else ""
        project = p[6] if len(p) > 6 else ""
        service = p[7] if len(p) > 7 else ""
        size = p[8] if len(p) > 8 else ""
        ov = resolve_value(override(name))
        if not isinstance(ov, dict):
            ov = {}
        if ov.get("hide"):
            continue
        if state == "running" and "unhealthy" in status:
            st = "warn"
        elif state == "running":
            st = "ok"
        elif state in ("exited", "created"):
            st = "stopped"
        elif state == "paused":
            st = "warn"
        else:
            st = "down"
        paused = state == "paused"
        fr = _friendly_container(name, ov)
        # k8s containers have no compose project — bucket them by namespace so
        # they cluster together (and out of the way) under group-by-project.
        eff_project = project or (
            f"k8s/{fr['k8s']['namespace']}" if fr.get("k8s") else None
        )
        items.append({
            "id": name,
            "cid": cid[:12],
            "name": fr["display_name"],
            "raw_name": name,
            "subtitle": fr["subtitle"],
            "k8s": fr["k8s"],
            "system": fr["system"],
            "sandbox": fr["sandbox"],
            "image": image,
            "state": st,
            "raw_state": state,
            "paused": paused,
            "status": status,
            "ports": ports,
            "project": eff_project,
            "service": service or None,
            "size": size,
            "url": _optional_text(ov.get("url")),
            "group": _field_text(ov.get("group")) or (
                f"Containers · {project}" if project else "Containers · other"
            ),
            "network": None,
            "ip": None,
            "restart_policy": None,
            "mounts": [],
            "autostart": False,
            "update": None,
            "shell": "/bin/sh",
            "actions": (
                ["restart", "stop", "pause", "logs", "inspect", "update"]
                if state == "running"
                else (["unpause", "stop", "logs", "inspect"] if paused
                      else ["start", "remove", "logs", "inspect"])
            ),
        })
    # enrich: inspect is cheap (~30ms); keep
    upd = _load_update_status()
    names = [i["id"] for i in items]
    if names:
        rc2, jout, _ = docker("inspect", *names, timeout=15)
        if rc2 == 0:
            try:
                arr = safe_json_loads(jout)
            except (TypeError, ValueError, RecursionError):
                # RecursionError: leftover deeply-nested inspect JSON is not ValueError.
                arr = []
            if isinstance(arr, dict):
                arr = [arr]
            if not isinstance(arr, list):
                arr = []
            by = {}
            for a in arr:
                if not isinstance(a, dict):
                    continue
                a = _jsonable(a)
                if not isinstance(a, dict):
                    continue
                raw_name = a.get("Name")
                if not isinstance(raw_name, str):
                    continue
                key = raw_name.lstrip("/")
                if key:
                    by[key] = a
            for it in items:
                a = by.get(it["id"])
                if not a:
                    continue
                try:
                    host = a.get("HostConfig") if isinstance(a.get("HostConfig"), dict) else {}
                    ns = a.get("NetworkSettings") if isinstance(a.get("NetworkSettings"), dict) else {}
                    nets = ns.get("Networks") if isinstance(ns.get("Networks"), dict) else {}
                    nmode = host.get("NetworkMode")
                    it["network"] = (
                        nmode if isinstance(nmode, str) and nmode
                        else (",".join(str(k) for k in nets.keys()) or "bridge")
                    )
                    ips = []
                    for _nname, nd in nets.items():
                        if not isinstance(nd, dict):
                            continue
                        ip = nd.get("IPAddress")
                        if isinstance(ip, str) and ip:
                            ips.append(ip)
                    it["ip"] = ", ".join(ips) if ips else None
                    rp_obj = host.get("RestartPolicy") if isinstance(host.get("RestartPolicy"), dict) else {}
                    rp = rp_obj.get("Name")
                    rp = rp if isinstance(rp, str) and rp else "no"
                    it["restart_policy"] = rp
                    it["autostart"] = rp in ("always", "unless-stopped", "on-failure")
                    mounts = []
                    for m in a.get("Mounts") if isinstance(a.get("Mounts"), list) else []:
                        if not isinstance(m, dict):
                            continue
                        mounts.append({
                            "src": m.get("Source") or m.get("Name") or "",
                            "dst": m.get("Destination") or "",
                            "type": m.get("Type") or "",
                        })
                    it["mounts"] = mounts
                    created = a.get("Created")
                    created = created if isinstance(created, str) else (
                        "" if created is None else str(created)
                    )
                    it["created"] = created[:19].replace("T", " ")
                    img = it["image"] if isinstance(it.get("image"), str) else ""
                    cfg_obj = a.get("Config") if isinstance(a.get("Config"), dict) else {}
                    cfg_img = cfg_obj.get("Image")
                    if not isinstance(cfg_img, str) or not cfg_img:
                        cfg_img = img
                    it["image"] = cfg_img
                    st_u = None
                    if isinstance(upd, dict):
                        if cfg_img:
                            st_u = upd.get(cfg_img)
                        if not isinstance(st_u, dict) and img:
                            st_u = upd.get(img)
                    if not isinstance(st_u, dict):
                        st_u = None
                    if st_u and st_u.get("status") in ("true", "false", True, False):
                        it["update"] = st_u.get("status") in (True, "true", "update")
                    elif st_u and st_u.get("status") == "undef":
                        it["update"] = None
                    else:
                        it["update"] = st_u.get("update") if st_u else None
                    it["shell"] = "/bin/sh"
                except Exception:
                    continue
    return True, items


def _fetch_stats(running_names: list[str]) -> dict:
    """docker stats is ~2s; only call for running containers."""
    running_names = [n for n in running_names if isinstance(n, str) and n]
    if not running_names:
        return {}
    # Named args slightly faster than scanning all when few containers
    rc, sout, _ = docker(
        "stats", "--no-stream", "--format",
        "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}",
        *running_names,
        timeout=12,
    )
    stats = {}
    if rc == 0:
        for line in _as_text(sout).splitlines():
            sp = line.split("\t")
            if len(sp) >= 6:
                stats[sp[0]] = {
                    "cpu": sp[1], "mem": sp[2], "mem_pct": sp[3],
                    "net": sp[4], "block": sp[5],
                }
    return stats


def list_containers(with_stats: bool = True) -> dict:
    engine_up_flag, cached_items = _container_list_cached()
    # Shallow copy per item, as before: the cached list is now shared with every
    # other reader of this TTL window, so a caller that edits a row -- or a
    # serialiser that adds to it -- must not reach into the cache.
    items = [dict(x) for x in cached_items]

    if not engine_up_flag:
        return {"engine_up": False, "containers": [], "stats": {}, "projects": []}

    stats = {}
    if with_stats:
        stats = dict(_stats_cached())

    projects = {}
    for it in items:
        key = it.get("project") or "_ungrouped"
        projects.setdefault(key, {"name": key if key != "_ungrouped" else "other", "count": 0, "running": 0})
        projects[key]["count"] += 1
        if it["raw_state"] == "running":
            projects[key]["running"] += 1

    return {
        "engine_up": True,
        "containers": items,
        "stats": stats,
        "projects": list(projects.values()),
        "update_checked_at": (_load_update_status() or {}).get("_checked_at"),
    }


def container_action(name: str, action: str) -> dict:
    allowed = {"start", "stop", "restart", "remove", "kill", "pause", "unpause"}
    if action not in allowed:
        raise api_error("container.bad_action", action=action)
    # Without this, POST /api/containers/batch with {"names": ["--all"]} became
    # `docker stop --all` and stopped every container on the host.  The name is a
    # bare positional, so an option-like value is read by docker as a flag.
    name = cli_args.require_positional(name, label="container name")
    cmd = "rm" if action == "remove" else action
    args = [cmd, "-f", "--", name] if action == "remove" else [cmd, "--", name]
    rc, out, err = docker(*args, timeout=90)
    invalidate_container_lists()
    invalidate_status()
    ok = rc == 0
    return {"ok": ok, "message": out if ok else (err or out or f"exit {rc}")}


def batch_action(names: list[str], action: str) -> dict:
    if not names:
        raise api_error("container.empty_names")
    results = []
    ok_n = 0
    for n in names:
        # _as_text: a JSON ``"\ud800"`` name echoed back as ``id`` used to
        # 500 POST /api/containers/batch on Starlette's UTF-8 encode.
        try:
            r = container_action(n, action)
            results.append({"id": _as_text(n), **r})
            if r.get("ok"):
                ok_n += 1
        except HTTPException as e:
            results.append({"id": _as_text(n), "ok": False, "message": _as_text(e.detail)})
        except Exception as e:
            results.append({"id": _as_text(n), "ok": False, "message": _as_text(e)})
    return {"ok": ok_n == len(names), "done": ok_n, "total": len(names), "results": results}


def _container_rows(payload) -> list:
    """``list_containers()`` rows, or [] when the payload is the wrong shape.

    ``containers: 5`` (or a bare list leftover) used to raise on ``.get`` /
    ``for c in 5`` and 500 Start All / stack listing.
    """
    rows = payload.get("containers") if isinstance(payload, dict) else []
    return rows if isinstance(rows, list) else []


def action_all(action: str) -> dict:
    """Start/stop/pause/unpause all containers (Unraid Start All / Stop All)."""
    names = []
    for c in _container_rows(list_containers(with_stats=False)):
        if not isinstance(c, dict):
            continue
        ident = c.get("id")
        if not isinstance(ident, str) or not ident:
            continue
        rs = c.get("raw_state")
        if action == "start" and rs not in ("running", "paused"):
            names.append(ident)
        elif action == "stop" and rs in ("running", "paused"):
            names.append(ident)
        elif action == "pause" and rs == "running":
            names.append(ident)
        elif action == "unpause" and rs == "paused":
            names.append(ident)
        elif action == "restart" and rs in ("running", "paused"):
            names.append(ident)
    if not names:
        return {"ok": True, "done": 0, "total": 0, "message": "nothing to do", "results": []}
    return batch_action(names, action)


def _local_image_digest(image: str) -> str | None:
    rc, out, _ = docker(
        "image", "inspect", image,
        "--format", "{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}",
        timeout=15,
    )
    if rc != 0 or not out.strip():
        # fallback image id
        rc, out, _ = docker("image", "inspect", image, "--format", "{{.Id}}", timeout=15)
        return out.strip() if rc == 0 and out.strip() else None
    dig = out.strip()
    if "@" in dig:
        return dig.split("@", 1)[1]
    return dig


def check_image_update(image: str) -> dict:
    """Pull image and compare id — Unraid-style update check (actually pulls layers if newer)."""
    local_before = _local_image_digest(image)
    rc, out, err = docker("pull", image, timeout=600)
    local_after = _local_image_digest(image)
    combined = (out or "") + "\n" + (err or "")
    up_to_date = "Image is up to date" in combined or (
        local_before and local_after and local_before == local_after and rc == 0
    )
    newer = ("Downloaded newer image" in combined) or (
        local_before and local_after and local_before != local_after
    )
    status = "false" if up_to_date and not newer else ("true" if newer else ("undef" if rc != 0 else "false"))
    return {
        "image": image,
        "status": status,  # true=update available was pulled, false=current, undef=error
        "update": status == "true",
        "local": local_after or local_before,
        "message": combined[-400:] if combined.strip() else f"exit {rc}",
        "ok": rc == 0,
    }


def start_check_updates_job(images: list[str] | None = None) -> dict:
    """Background: check updates for all (or given) images used by containers."""
    if not engine_up():
        raise api_error("container.engine_down")
    if not images:
        images = sorted({
            str(c["image"])
            for c in _container_rows(list_containers(with_stats=False))
            if isinstance(c, dict) and isinstance(c.get("image"), str) and c.get("image")
        })
    tid = f"docker-check-{_job_epoch()}"
    j0 = _register_job(tid, stack_id="_docker_update", action="check")

    def run():
        j = j0
        status = _load_update_status()
        try:
            j["log"].append(f"Checking {len(images)} images for updates…")
            for img in images:
                j["log"].append(f"→ {img}")
                try:
                    r = check_image_update(img)
                    status[img] = {
                        "status": r["status"],
                        "update": r["update"],
                        "local": r.get("local"),
                        "checked_at": strftime_now("%Y-%m-%d %H:%M:%S"),
                    }
                    flag = "update available" if r["update"] else ("up to date" if r["status"] == "false" else "unknown")
                    j["log"].append(f"  {flag}")
                except Exception as e:
                    j["log"].append(f"  !! {_as_text(e)}")
                    status[img] = {"status": "undef", "update": None, "error": _as_text(e)}
            status["_checked_at"] = strftime_now("%Y-%m-%d %H:%M:%S")
            _save_update_status(status)
            j["rc"] = 0
            j["log"].append("== check complete ==")
        except Exception as e:
            j["log"].append(f"!! {_as_text(e)}")
            j["rc"] = -1
        finally:
            j["running"] = False
            j["finished"] = strftime_now("%H:%M:%S")
            invalidate_status()

    threading.Thread(target=run, daemon=True).start()
    return {"ok": True, "job_id": tid, "message": f"Checking {len(images)} images", "images": images}


def _recreate_simple(name: str, image: str, j: dict, env: dict) -> bool:
    """Best-effort recreate without compose: dump run args from inspect via docker CLI."""
    # Strategy: docker stop; docker rm; docker run with network/ports/volumes from inspect JSON
    rc, out, err = docker("inspect", name, timeout=15)
    if rc != 0:
        # might already be renamed
        j["log"].append(err or "inspect failed")
        return False
    data = inspect_object(out)
    if data is None:
        j["log"].append("inspect returned unusable JSON")
        return False
    host = data.get("HostConfig")
    host = host if isinstance(host, dict) else {}
    cfg_ = data.get("Config")
    cfg_ = cfg_ if isinstance(cfg_, dict) else {}
    args = [DOCKER, "run", "-d", "--name", name]
    # restart policy
    rp_obj = host.get("RestartPolicy")
    rp = str((rp_obj.get("Name") or "") if isinstance(rp_obj, dict) else "")
    if rp and rp != "no":
        args += ["--restart", rp]
    # network
    nmode = str(host.get("NetworkMode") or "bridge")
    if nmode and nmode not in ("default",):
        if nmode == "host":
            args += ["--network", "host"]
        elif not nmode.startswith("container:"):
            args += ["--network", nmode]
    # privileged
    if host.get("Privileged"):
        args.append("--privileged")
    # binds
    binds = host.get("Binds")
    for b in binds if isinstance(binds, list) else []:
        if isinstance(b, str) and b:
            args += ["-v", b]
    # ports (skip if host network)
    if nmode != "host":
        pb = host.get("PortBindings") or {}
        if not isinstance(pb, dict):
            pb = {}
        for cport, binds in pb.items():
            if not binds:
                continue
            if not isinstance(binds, list):
                continue
            cport_s = str(cport or "")
            if not cport_s:
                continue
            for b in binds:
                if not isinstance(b, dict):
                    continue
                hp = str(b.get("HostPort") or "")
                hip = str(b.get("HostIp") or "")
                left = f"{hip+':' if hip else ''}{hp}" if hp else ""
                # cport like 4000/tcp
                cp = cport_s.split("/")[0]
                proto = cport_s.split("/")[1] if "/" in cport_s else "tcp"
                if left:
                    args += ["-p", f"{left}:{cp}/{proto}" if proto != "tcp" else f"{left}:{cp}"]
                else:
                    args += ["-p", cport_s]
    # env (skip PATH noise partially)
    env_list = cfg_.get("Env")
    for e in env_list if isinstance(env_list, list) else []:
        if not isinstance(e, str):
            continue
        if e.startswith("PATH="):
            continue
        args += ["-e", e]
    if not isinstance(image, str) or not image.strip():
        j["log"].append("image name is unusable")
        return False
    args.append(image)
    # cmd
    cmd = cfg_.get("Cmd")
    if isinstance(cmd, (list, tuple)):
        args += [str(part) for part in cmd if part is not None]
    elif isinstance(cmd, str) and cmd:
        args.append(cmd)

    j["log"].append("$ docker stop " + name)
    rc_stop, stop_text = run_capped([DOCKER, "stop", name], timeout=120, env=env, cap=2000)
    stop_text = _as_text(stop_text)
    if rc_stop not in (0,):
        j["log"].append(stop_text or f"stop exit {rc_stop}")
    j["log"].append("$ docker rm " + name)
    rc_rm, rm_text = run_capped([DOCKER, "rm", name], timeout=60, env=env, cap=2000)
    rm_text = _as_text(rm_text)
    if rc_rm not in (0,):
        j["log"].append(rm_text or f"rm exit {rc_rm}")
    j["log"].append("$ " + " ".join(args[:12]) + " …")
    rc, text = run_capped(args, timeout=120, env=env, cap=2000)
    text = _as_text(text)
    if rc != 0:
        j["log"].append(text or f"exit {rc}")
        return False
    j["log"].append((text or "").strip() or "recreated")
    return True


def start_update_container_job(name: str) -> dict:
    """Pull image and recreate container (docker compose style recreate via force)."""
    name = cli_args.require_positional(name, label="container name")
    rc, out, err = docker("inspect", "--", name, timeout=15)
    if rc != 0:
        raise api_error("container.not_found")
    data = inspect_object(out)
    if data is None:
        raise api_error("container.not_found")
    cfg_upd = data.get("Config") if isinstance(data.get("Config"), dict) else {}
    image = cfg_upd.get("Image")
    image = image if isinstance(image, str) else ""
    # Prefer compose project update if labeled
    labels = cfg_upd.get("Labels") if isinstance(cfg_upd.get("Labels"), dict) else {}
    project = labels.get("com.docker.compose.project")
    project = project if isinstance(project, str) else ""
    workdir = labels.get("com.docker.compose.project.working_dir")
    workdir = workdir if isinstance(workdir, str) else ""
    compose_files = labels.get("com.docker.compose.project.config_files")
    compose_files = compose_files if isinstance(compose_files, str) else ""

    tid = f"docker-update-{name}-{_job_epoch()}"
    j0 = _register_job(tid, stack_id=project or name, action="update_container")

    def run():
        j = j0
        env = dict(os.environ)
        env.update(maintenance_env())
        try:
            if workdir and compose_files:
                cf = compose_files.split(",")[0]
                svc_name = labels.get("com.docker.compose.service")
                svc_name = svc_name if isinstance(svc_name, str) else ""
                cmds = [
                    [DOCKER, "compose", "-f", cf, "pull", name if svc_name else ""],
                    [DOCKER, "compose", "-f", cf, "up", "-d", "--force-recreate",
                     svc_name or name],
                ]
                # clean empty args
                cmds = [[a for a in c if isinstance(a, str) and a] for c in cmds]
                for cmd in cmds:
                    j["log"].append("$ " + " ".join(cmd))
                    rc = _stream_job_command(cmd, j, cwd=workdir, env=env)
                    if rc != 0:
                        j["rc"] = rc
                        j["log"].append(f"!! exit {rc}")
                        break
                else:
                    j["rc"] = 0
            else:
                # Try match services.yaml stacks by container name / directory
                stack_hit = None
                for s in _stack_paths():
                    if s.get("compose_path") and (
                        name in (s.get("containers") or [])
                        or s.get("id") == name
                        or (s.get("path") and Path(s["path"]).name == name)
                    ):
                        stack_hit = s
                        break
                if stack_hit:
                    cf = stack_hit["compose_path"]
                    wd = stack_hit["path"]
                    for cmd in (
                        [DOCKER, "compose", "-f", cf, "pull"],
                        [DOCKER, "compose", "-f", cf, "up", "-d", "--force-recreate"],
                    ):
                        j["log"].append("$ " + " ".join(cmd))
                        rc = _stream_job_command(cmd, j, cwd=wd, env=env)
                        if rc != 0:
                            j["rc"] = rc
                            j["log"].append(f"!! exit {rc}")
                            break
                    else:
                        j["rc"] = 0
                else:
                    if not image:
                        j["log"].append("!! no image name on inspect")
                        j["rc"] = 1
                    else:
                        j["log"].append(f"$ docker pull {image}")
                        rc = _stream_job_command([DOCKER, "pull", image], j, env=env)
                        if rc != 0:
                            j["rc"] = rc
                            j["log"].append("!! pull failed")
                        else:
                            # pull alone does not switch running container; try force recreate
                            # via stop/rm/create using docker's --force recreate if available
                            j["log"].append("Image pulled. No compose metadata; recreating via stop→rm→create…")
                            ok_re = _recreate_simple(name, image, j, env)
                            j["rc"] = 0 if ok_re else 1
            # mark image current
            if image:
                st = _load_update_status()
                st[image] = {
                    "status": "false", "update": False,
                    "checked_at": strftime_now("%Y-%m-%d %H:%M:%S"),
                }
                _save_update_status(st)
            if j.get("rc") is None:
                j["rc"] = 0
            j["log"].append("== done ==")
        except Exception as e:
            j["log"].append(f"!! {_as_text(e)}")
            j["rc"] = -1
        finally:
            j["running"] = False
            j["finished"] = strftime_now("%H:%M:%S")
            invalidate_status()

    threading.Thread(target=run, daemon=True).start()
    return {"ok": True, "job_id": tid, "message": f"Updating {name}"}


_ALLOWED_EXEC_SHELLS = frozenset({
    "/bin/sh", "/bin/bash", "/bin/ash", "/bin/zsh", "sh", "bash",
})


def exec_in_container(name: str, command: str, shell: str = "/bin/sh") -> dict:
    """One-shot exec (Unraid console simplified)."""
    if not command or not command.strip():
        raise api_error("container.empty_command")
    # A bare positional: an option-shaped container name (`-e…`, `--privileged`)
    # would otherwise be read by docker as a flag, not a container. Same guard
    # the action/restart paths already apply.
    name = cli_args.require_positional(name, label="container name")
    sh = (shell or "/bin/sh").strip() or "/bin/sh"
    if sh not in _ALLOWED_EXEC_SHELLS:
        raise api_error("container.bad_shell")
    rc, out, err = docker(
        "exec", "--", name, sh, "-c", command,
        timeout=60,
    )
    out, err = _as_text(out), _as_text(err)
    return {
        "ok": rc == 0,
        "rc": rc,
        "output": out + (("\n" + err) if err else ""),
    }


def set_restart_policy(name: str, policy: str = "unless-stopped") -> dict:
    """Toggle Unraid-style Autostart via restart policy."""
    allowed = {"no", "always", "unless-stopped", "on-failure"}
    if policy not in allowed:
        raise api_error("container.bad_policy", policy=policy)
    # `name` is a bare positional, so an option-shaped value would be read by
    # docker as a flag instead of as a container. The autostart route derives it
    # from a caller-supplied "docker-ctr:<name>" id, so it needs the same guard
    # the brew autostart path already uses.
    name = cli_args.require_positional(name, label="container name")
    rc, out, err = docker("update", f"--restart={policy}", "--", name, timeout=30)
    invalidate_status()
    return {"ok": rc == 0, "message": out if rc == 0 else (err or out), "policy": policy}


def inspect_container(name: str) -> dict:
    name = cli_args.require_positional(name, label="container name")
    rc, out, err = docker("inspect", "--", name, timeout=15)
    if rc != 0:
        raise api_error("container.not_found")
    data = inspect_object(out)
    if data is None:
        raise api_error("container.not_found")
    # redact env
    cfg_raw = data.get("Config")
    if isinstance(cfg_raw, dict) and "Env" in cfg_raw:
        data["Config"]["Env"] = redact_env(cfg_raw.get("Env"))
    # slim response for UI
    cfg_ = cfg_raw if isinstance(cfg_raw, dict) else {}
    host = data.get("HostConfig") if isinstance(data.get("HostConfig"), dict) else {}
    state = data.get("State") if isinstance(data.get("State"), dict) else {}
    health = state.get("Health") if isinstance(state.get("Health"), dict) else {}
    ns = data.get("NetworkSettings") if isinstance(data.get("NetworkSettings"), dict) else {}
    nets = ns.get("Networks") if isinstance(ns.get("Networks"), dict) else {}
    mounts = data.get("Mounts") if isinstance(data.get("Mounts"), list) else []
    labels = cfg_.get("Labels") if isinstance(cfg_.get("Labels"), dict) else {}
    env = [
        e for e in (cfg_.get("Env") if isinstance(cfg_.get("Env"), list) else [])
        if isinstance(e, str)
    ]
    ident = data.get("Id")
    ident = str(ident) if ident is not None else ""
    raw_name = data.get("Name")
    raw_name = str(raw_name) if raw_name is not None else ""
    return {
        "Id": ident[:12],
        "Name": raw_name.lstrip("/"),
        "Image": cfg_.get("Image"),
        "Created": data.get("Created"),
        "State": {
            "Status": state.get("Status"),
            "Running": state.get("Running"),
            "Paused": state.get("Paused"),
            "Restarting": state.get("Restarting"),
            "ExitCode": state.get("ExitCode"),
            "StartedAt": state.get("StartedAt"),
            "FinishedAt": state.get("FinishedAt"),
            "Health": health.get("Status"),
        },
        "Env": env,
        "Cmd": cfg_.get("Cmd"),
        "Entrypoint": cfg_.get("Entrypoint"),
        "Labels": labels,
        "Binds": [
            b for b in (host.get("Binds") if isinstance(host.get("Binds"), list) else [])
            if isinstance(b, str)
        ],
        "PortBindings": host.get("PortBindings") if isinstance(host.get("PortBindings"), dict) else {},
        "RestartPolicy": host.get("RestartPolicy"),
        "NetworkMode": host.get("NetworkMode"),
        "Networks": list(nets.keys()),
        "Mounts": [
            {"Source": m.get("Source"), "Destination": m.get("Destination"),
             "Type": m.get("Type"), "RW": m.get("RW")}
            for m in mounts if isinstance(m, dict)
        ],
        "raw": data,
    }


def _raise_list_failure(kind: str):
    """Fail an inventory read as 503 when the engine is simply not running.

    A stopped container engine is an ordinary state this panel models
    everywhere else -- ``engine_up`` rides along on /api/status, the
    Containers page renders "engine is down", and every other
    engine-dependent entry point raises ``container.engine_down`` (503).
    The three inventory reads instead mapped *any* non-zero exit to
    ``container.list_failed`` (500), so with OrbStack stopped the Images,
    Volumes and Networks tabs reported a panel fault rather than a
    dependency that is off.

    ``engine_up`` is consulted only after a failure, so the healthy path
    does not pay for an extra ``docker info``.  The probe is *forced*:
    the memoised value has a 5s TTL, so for the first seconds after the
    engine stops the cache still says "up" and the failure this function
    exists to classify would be misreported as ``container.list_failed``
    (500).  A fresh probe on the failure path is cheap -- failures are
    rare -- and is the one moment the cached answer must not be trusted.
    """
    if not engine_up(force=True):
        raise api_error("container.engine_down")
    raise api_error("container.list_failed", kind=kind)


def list_images() -> list:
    data, rc, err = docker_json(
        ["images", "--format", "{{json .}}"], timeout=15)
    if rc != 0:
        _raise_list_failure("images")
    if isinstance(data, dict):
        data = [data]
    elif not isinstance(data, list):
        data = []
    return [row for row in data if isinstance(row, dict)]


def list_volumes() -> list:
    rc, out, err = docker("volume", "ls", "--format", "{{.Name}}\t{{.Driver}}\t{{.Mountpoint}}", timeout=12)
    if rc != 0:
        _raise_list_failure("volumes")
    items = []
    for line in _as_text(out).splitlines():
        p = line.split("\t")
        if len(p) >= 2:
            items.append({"Name": p[0], "Driver": p[1], "Mountpoint": p[2] if len(p) > 2 else ""})
    return items


def list_networks() -> list:
    rc, out, err = docker("network", "ls", "--format", "{{.ID}}\t{{.Name}}\t{{.Driver}}\t{{.Scope}}", timeout=12)
    if rc != 0:
        _raise_list_failure("networks")
    items = []
    for line in _as_text(out).splitlines():
        p = line.split("\t")
        if len(p) >= 4:
            items.append({"Id": p[0][:12], "Name": p[1], "Driver": p[2], "Scope": p[3]})
    return items


def prune(kind: str = "system") -> dict:
    if kind == "images":
        rc, out, err = docker("image", "prune", "-af", timeout=300)
    elif kind == "volumes":
        rc, out, err = docker("volume", "prune", "-f", timeout=120)
    elif kind == "networks":
        rc, out, err = docker("network", "prune", "-f", timeout=60)
    elif kind == "containers":
        rc, out, err = docker("container", "prune", "-f", timeout=120)
    elif kind == "system":
        rc, out, err = docker("system", "prune", "-af", timeout=300)
    else:
        raise api_error("container.bad_action", action=kind)
    invalidate_status()
    return {"ok": rc == 0, "message": out or err}


def remove_image(image: str, force: bool = False) -> dict:
    if not image or not re_match_image(image):
        raise api_error("container.image_ref_required" if not image else "container.bad_image_name")
    args = ["rmi"]
    if force:
        args.append("-f")
    args += ["--", image]
    rc, out, err = docker(*args, timeout=120)
    invalidate_status()
    return {"ok": rc == 0, "message": out if rc == 0 else (err or out)}


def remove_volume(name: str, force: bool = False) -> dict:
    if not name:
        raise api_error("container.volume_name_required")
    name = cli_args.require_positional(name, label="volume name")
    args = ["volume", "rm"]
    if force:
        args.append("-f")
    args += ["--", name]
    rc, out, err = docker(*args, timeout=60)
    return {"ok": rc == 0, "message": out if rc == 0 else (err or out)}


def remove_network(name: str) -> dict:
    if not name:
        raise api_error("container.network_name_required")
    name = cli_args.require_positional(name, label="network name")
    if name in ("bridge", "host", "none"):
        raise api_error("container.builtin_network")
    rc, out, err = docker("network", "rm", "--", name, timeout=30)
    return {"ok": rc == 0, "message": out if rc == 0 else (err or out)}


def pull_image(image: str) -> dict:
    if not image or not re_match_image(image):
        raise api_error("container.bad_image_name")
    rc, out, err = docker("pull", image, timeout=600)
    return {"ok": rc == 0, "message": (_as_text(out) or _as_text(err) or "")[-2000:]}


def re_match_image(image: str) -> bool:
    import re
    return bool(re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._/:@-]{0,200}$", image or ""))


def rename_container(name: str, new_name: str) -> dict:
    name = cli_args.require_positional(name, label="container name")
    if not new_name or not re_match_image(new_name.replace("/", "x")):
        # name only [a-zA-Z0-9][a-zA-Z0-9_.-]*
        import re
        if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$", new_name or ""):
            raise api_error("container.bad_new_name")
    rc, out, err = docker("rename", "--", name, new_name, timeout=30)
    invalidate_status()
    return {"ok": rc == 0, "message": out if rc == 0 else (err or out)}


def create_run_container(body: dict) -> dict:
    """docker run -d with common options from panel form."""
    import re
    if not engine_up():
        raise api_error("container.engine_down")
    # leftover RecursionError on ``str(env-item)`` / leftover ``\\ud800``
    # used to 500 POST /api/containers/run.
    image = _as_text(body.get("image") or "").strip()
    name = _as_text(body.get("name") or "").strip()
    if not image or not re_match_image(image):
        raise api_error("container.image_required")
    if name and not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$", name):
        raise api_error("container.bad_container_name")

    args = ["run", "-d"]
    if name:
        args += ["--name", name]
    restart = _as_text(body.get("restart") or "unless-stopped").strip()
    allowed_restart = {"no", "always", "unless-stopped", "on-failure"}
    if restart not in allowed_restart:
        raise api_error("container.bad_policy", policy=restart)
    if restart != "no":
        args += ["--restart", restart]
    if body.get("privileged"):
        args.append("--privileged")
    network = _as_text(body.get("network") or "").strip()
    if network:
        # Same class of bug as ``docker stop --all``: an option-shaped value
        # in the ``--network`` slot is read as another flag.
        network = cli_args.require_positional(network, label="network name")
        args += ["--network", network]
    # ports: ["8080:80", "443:443"]
    for p in body.get("ports") if isinstance(body.get("ports"), list) else []:
        p = _as_text(p).strip()
        if p and re.match(r"^[0-9.:\-/tcpudp]+$", p):
            args += ["-p", p]
    # volumes: ["/host:/container", "vol:/data"]
    for v in body.get("volumes") if isinstance(body.get("volumes"), list) else []:
        v = _as_text(v).strip()
        if v and ":" in v:
            args += ["-v", v]
    # env: ["KEY=val"]
    for e in body.get("env") if isinstance(body.get("env"), list) else []:
        e = _as_text(e).strip()
        if e and "=" in e:
            args += ["-e", e]
    # extra args carefully not allowed for safety
    # `--` so a later command token cannot be read as a docker-run option.
    args.append("--")
    args.append(image)
    cmd = body.get("command")
    if isinstance(cmd, str) and cmd.strip():
        # simple shell form — split
        args += _as_text(cmd).strip().split()
    elif isinstance(cmd, list):
        args += [_as_text(x) for x in cmd if _as_text(x)]

    rc, out, err = docker(*args, timeout=180)
    invalidate_status()
    out, err = _as_text(out), _as_text(err)
    return {
        "ok": rc == 0,
        "message": out.strip() if rc == 0 else (err or out),
        "name": name or None,
        "image": image,
    }


def create_volume(name: str, driver: str = "local") -> dict:
    import re
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$", name or ""):
        raise api_error("container.bad_volume_name")
    name = cli_args.require_positional(name, label="volume name")
    args = ["volume", "create"]
    driver = (driver or "local").strip()
    if driver != "local":
        driver = cli_args.require_positional(driver, label="volume driver")
        args += ["--driver", driver]
    args.append(name)
    rc, out, err = docker(*args, timeout=30)
    return {"ok": rc == 0, "message": out if rc == 0 else (err or out)}


def create_network(name: str, driver: str = "bridge") -> dict:
    import re
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$", name or ""):
        raise api_error("container.bad_network_name")
    name = cli_args.require_positional(name, label="network name")
    allowed_drivers = {"bridge", "host", "overlay", "macvlan", "ipvlan", "none"}
    driver = (driver or "bridge").strip()
    if driver not in allowed_drivers:
        raise api_error("container.bad_network_name")
    args = ["network", "create"]
    if driver != "bridge":
        args += ["--driver", driver]
    args.append(name)
    rc, out, err = docker(*args, timeout=30)
    return {"ok": rc == 0, "message": out if rc == 0 else (err or out)}


def _stack_paths() -> list[dict]:
    """Resolve compose stacks from config + auto-scan Services/*."""
    stacks = []
    seen = set()
    for s in cfg().get("stacks") or []:
        if not isinstance(s, dict):
            continue
        path = s.get("path")
        if isinstance(path, str) and path:
            try:
                p = Path(path)
                compose_name = s.get("compose_file") or "docker-compose.yml"
                if not isinstance(compose_name, str) or not compose_name:
                    compose_name = "docker-compose.yml"
                compose = p / compose_name
            except (OSError, ValueError, TypeError):
                continue
            try:
                present = compose.exists()
            except (OSError, ValueError):
                present = False
            if not present:
                for alt in ("compose.yml", "docker-compose.yaml", "compose.yaml"):
                    try:
                        if (p / alt).exists():
                            compose = p / alt
                            present = True
                            break
                    except (OSError, ValueError):
                        continue
            sid = s.get("id")
            if not isinstance(sid, str) or not sid:
                sid = p.name
            stacks.append({
                "id": _field_text(sid) or "stack",
                "name": _field_text(s.get("name")) or _field_text(p.name) or "stack",
                "path": _field_text(str(p)),
                "compose_file": _field_text(compose.name) if present else None,
                "compose_path": _field_text(str(compose)) if present else None,
                "containers": _str_list(s.get("containers")),
                "source": "config",
            })
            try:
                seen.add(str(p.resolve()))
            except (OSError, ValueError, RuntimeError):
                # Path.resolve() raises RuntimeError on a leftover symlink loop.
                seen.add(str(p))
        elif s.get("containers"):
            sid = s.get("id")
            if not isinstance(sid, str) or not sid:
                continue
            stacks.append({
                "id": sid,
                "name": _field_text(s.get("name")) or sid,
                "path": None,
                "compose_file": None,
                "compose_path": None,
                "containers": _str_list(s.get("containers")),
                "source": "config",
            })

    home = user_home()
    services_root = (home / "Services") if home is not None else None
    try:
        scanned = (
            sorted(services_root.glob("*/docker-compose.y*ml"))
            + sorted(services_root.glob("*/compose.y*ml"))
            if services_root is not None and services_root.is_dir()
            else []
        )
    except OSError:
        scanned = []
    for comp in scanned:
        try:
            root = str(comp.parent.resolve())
        except (OSError, RuntimeError, ValueError):
            continue
        if root in seen:
            continue
        seen.add(root)
        stacks.append({
            "id": _field_text(comp.parent.name) or "stack",
            "name": _field_text(comp.parent.name) or "stack",
            "path": _field_text(str(comp.parent)),
            "compose_file": _field_text(comp.name),
            "compose_path": _field_text(str(comp)),
            "containers": [],
            "source": "scan",
        })
    return stacks


def list_stacks() -> list:
    stacks = _stack_paths()
    by_project: dict[str, list] = {}
    by_name: dict[str, dict] = {}
    for c in _container_rows(list_containers(with_stats=False)):
        if not isinstance(c, dict):
            continue
        cid = c.get("id")
        if not isinstance(cid, str) or not cid:
            continue
        by_name[cid] = c
        proj = c.get("project")
        if isinstance(proj, str) and proj:
            by_project.setdefault(proj, []).append(cid)
    for s in stacks:
        if not isinstance(s, dict):
            continue
        found: list[str] = []
        sid = s.get("id") if isinstance(s.get("id"), str) else None
        if s.get("path"):
            proj = Path(s["path"]).name
            found = list(by_project.get(proj) or (by_project.get(sid) if sid else None) or [])
        names = s.get("containers")
        if isinstance(names, list):
            for name in names:
                if isinstance(name, str) and name in by_name and name not in found:
                    found.append(name)
        # compose project often equals directory name; also match container_name == stack id
        if sid and sid in by_name and sid not in found:
            found.append(sid)
        # music-assistant style: container name equals stack id even without compose labels
        s["running_containers"] = found
        running_ok = any(by_name.get(n, {}).get("raw_state") == "running" for n in found)
        s["status"] = "ok" if running_ok else ("exists" if found else "idle")
    return stacks


def start_stack_job(stack_id: str, action: str = "update") -> dict:
    """action: update (pull+up), up, down, pull"""
    stacks = {s["id"]: s for s in _stack_paths()}
    stack = stacks.get(stack_id)
    if not stack:
        raise api_error("container.unknown_stack", stack=stack_id)
    if not stack.get("compose_path"):
        raise api_error("container.no_compose_file")

    tid = f"stack-{stack_id}-{action}-{_job_epoch()}"
    j0 = _register_job(tid, stack_id=stack_id, action=action)

    compose_path = stack["compose_path"]
    workdir = stack["path"]

    def run():
        j = j0
        env = dict(os.environ)
        env.update(maintenance_env())
        cmds = []
        if action == "pull":
            cmds = [[DOCKER, "compose", "-f", compose_path, "pull"]]
        elif action == "up":
            cmds = [[DOCKER, "compose", "-f", compose_path, "up", "-d", "--remove-orphans"]]
        elif action == "down":
            cmds = [[DOCKER, "compose", "-f", compose_path, "down"]]
        else:  # update
            cmds = [
                [DOCKER, "compose", "-f", compose_path, "pull"],
                [DOCKER, "compose", "-f", compose_path, "up", "-d", "--remove-orphans"],
                [DOCKER, "image", "prune", "-f"],
            ]
        try:
            for cmd in cmds:
                j["log"].append(f"$ {' '.join(cmd)}")
                rc = _stream_job_command(cmd, j, cwd=workdir, env=env)
                if rc != 0:
                    j["rc"] = rc
                    j["log"].append(f"!! failed exit {rc}")
                    break
            else:
                j["rc"] = 0
                j["log"].append("== done ==")
        except Exception as e:
            j["log"].append(f"!! {_as_text(e)}")
            j["rc"] = -1
        finally:
            j["running"] = False
            j["finished"] = strftime_now("%H:%M:%S")
            invalidate_status()

    threading.Thread(target=run, daemon=True).start()
    return {"ok": True, "job_id": tid, "message": "job started"}


def stack_job_log(job_id: str) -> dict:
    if not isinstance(job_id, str):
        return {"running": False, "rc": None, "log": "(not started yet)", "job_id": ""}
    j = _cjobs.get(job_id)
    if not isinstance(j, dict):
        # also allow latest job for stack
        j = None
        for k, v in reversed(list(_cjobs.items())):
            if not isinstance(v, dict):
                continue
            if v.get("stack_id") == job_id or k == job_id:
                j = v
                job_id = k
                break
    if not isinstance(j, dict):
        return {"running": False, "rc": None, "log": "(not started yet)", "job_id": job_id}
    raw_log = j.get("log") if isinstance(j.get("log"), list) else []
    return {"running": j.get("running"), "rc": j.get("rc"), "started": j.get("started"),
            "finished": j.get("finished"),
            "log": "\n".join(_as_text(x) for x in raw_log) or "(waiting for output…)",
            "job_id": job_id, "stack_id": j.get("stack_id"), "action": j.get("action")}


def latest_stack_jobs() -> list:
    # return recent unique by stack
    by = {}
    for k, v in _cjobs.items():
        if not isinstance(v, dict):
            continue
        sid = v.get("stack_id")
        if isinstance(sid, str) and sid:
            by[sid] = {**job_public(k, v)}
    return list(by.values())


def job_public(jid, j):
    if not isinstance(j, dict):
        j = {}
    return {"job_id": jid, "stack_id": j.get("stack_id"), "action": j.get("action"),
            "running": j.get("running"), "rc": j.get("rc"), "finished": j.get("finished")}
