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
from hub.config import cfg, override
from hub.errors import api_error
from hub.docker_cli import docker, docker_json, engine_up, redact_env
from hub.paths import DATA_DIR, DOCKER
from hub.status import invalidate_status

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
#: Cap the number of retained jobs.  Job ids embed a timestamp
#: (``stack-<id>-<action>-<epoch>``), so every run used to add a permanent entry
#: holding up to JOB_LOG_MAX_LINES lines; a panel left running for weeks grew
#: until restart.  The UI only ever shows recent jobs, so old ones are dropped.
JOB_HISTORY_MAX = 40


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
    for key in [k for k, v in _cjobs.items() if not v.get("running")]:
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
    with _cjobs_lock:
        if any(j.get("running") for j in _cjobs.values()):
            raise api_error("container.job_running")
        _cjobs[tid] = {
            "running": True,
            "rc": None,
            "log": [],
            "started": time.strftime("%H:%M:%S"),
            "finished": None,
            "stack_id": stack_id,
            "action": action,
        }
        _evict_old_jobs()
        return _cjobs[tid]


def _stream_job_command(cmd: list[str], j: dict, *, cwd=None, env=None,
                        timeout: int = JOB_CMD_TIMEOUT) -> int:
    """Run *cmd*, stream its output into ``j["log"]``, and always reap it.

    ``for line in p.stdout`` blocks until the child closes the pipe, so a
    ``p.wait(timeout=...)`` placed after the loop can never fire — the timeout
    has to be enforced while reading.  The child is started in its own session
    so a stuck ``docker compose`` takes its descendants down with it.

    Returns the exit status, or 124 when the deadline was hit.
    """
    deadline = time.monotonic() + timeout
    timed_out = False
    with subprocess.Popen(
        cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, env=env, start_new_session=True,
    ) as p:
        try:
            assert p.stdout is not None
            for line in p.stdout:
                j["log"].append(line.rstrip())
                if len(j["log"]) > JOB_LOG_MAX_LINES:
                    del j["log"][:JOB_LOG_TRIM_LINES]
                if time.monotonic() > deadline:
                    timed_out = True
                    j["log"].append(f"!! timeout after {timeout}s - terminating")
                    break
        finally:
            if p.poll() is None:
                # Signal the process group: killing only the docker CLI would
                # leave its children holding the pipe open.
                for sig, grace in ((signal.SIGTERM, 10), (signal.SIGKILL, 5)):
                    try:
                        os.killpg(os.getpgid(p.pid), sig)
                    except (ProcessLookupError, PermissionError):
                        break
                    try:
                        p.wait(timeout=grace)
                        break
                    except subprocess.TimeoutExpired:
                        continue
    return 124 if timed_out else (p.returncode if p.returncode is not None else -1)
UPDATE_STATUS_PATH = DATA_DIR / "docker-update-status.json"

# docker stats --no-stream is ~2s; cache aggressively for snappy UI
_list_cache = {"t": 0.0, "items": None, "engine_up": True}
_stats_cache = {"t": 0.0, "stats": {}}
_LIST_TTL = 5.0
_STATS_TTL = 15.0
_cache_lock = threading.Lock()


def invalidate_container_lists():
    with _cache_lock:
        _list_cache["t"] = 0
        _stats_cache["t"] = 0


def _load_update_status() -> dict:
    if UPDATE_STATUS_PATH.exists():
        try:
            return json.loads(UPDATE_STATUS_PATH.read_text())
        except Exception:
            pass
    return {}


def _save_update_status(data: dict) -> None:
    UPDATE_STATUS_PATH.parent.mkdir(exist_ok=True)
    UPDATE_STATUS_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2))


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
    if ov.get("name"):
        return {"display_name": ov["name"], "subtitle": None, "k8s": None,
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
    for line in out.splitlines():
        p = line.split("\t")
        if len(p) < 6:
            continue
        cid, name, image, state, status = p[0], p[1], p[2], p[3], p[4]
        ports = p[5] if len(p) > 5 else ""
        project = p[6] if len(p) > 6 else ""
        service = p[7] if len(p) > 7 else ""
        size = p[8] if len(p) > 8 else ""
        ov = override(name)
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
            "url": ov.get("url"),
            "group": ov.get("group") or (f"容器 · {project}" if project else "容器 · 其他"),
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
                arr = json.loads(jout)
                by = {a.get("Name", "").lstrip("/"): a for a in arr}
                for it in items:
                    a = by.get(it["id"])
                    if not a:
                        continue
                    host = a.get("HostConfig") or {}
                    nets = (a.get("NetworkSettings") or {}).get("Networks") or {}
                    it["network"] = host.get("NetworkMode") or ",".join(nets.keys()) or "bridge"
                    ips = []
                    for _nname, nd in nets.items():
                        ip = nd.get("IPAddress")
                        if ip:
                            ips.append(ip)
                    it["ip"] = ", ".join(ips) if ips else None
                    rp = (host.get("RestartPolicy") or {}).get("Name") or "no"
                    it["restart_policy"] = rp
                    it["autostart"] = rp in ("always", "unless-stopped", "on-failure")
                    mounts = []
                    for m in a.get("Mounts") or []:
                        mounts.append({
                            "src": m.get("Source") or m.get("Name") or "",
                            "dst": m.get("Destination") or "",
                            "type": m.get("Type") or "",
                        })
                    it["mounts"] = mounts
                    it["created"] = (a.get("Created") or "")[:19].replace("T", " ")
                    img = it["image"]
                    cfg_img = ((a.get("Config") or {}).get("Image")) or img
                    it["image"] = cfg_img
                    st_u = upd.get(cfg_img) or upd.get(img)
                    if st_u and st_u.get("status") in ("true", "false", True, False):
                        it["update"] = st_u.get("status") in (True, "true", "update")
                    elif st_u and st_u.get("status") == "undef":
                        it["update"] = None
                    else:
                        it["update"] = st_u.get("update") if st_u else None
                    it["shell"] = "/bin/sh"
            except Exception:
                pass
    return True, items


def _fetch_stats(running_names: list[str]) -> dict:
    """docker stats is ~2s; only call for running containers."""
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
        for line in sout.splitlines():
            sp = line.split("\t")
            if len(sp) >= 6:
                stats[sp[0]] = {
                    "cpu": sp[1], "mem": sp[2], "mem_pct": sp[3],
                    "net": sp[4], "block": sp[5],
                }
    return stats


def list_containers(with_stats: bool = True) -> dict:
    now = time.time()
    with _cache_lock:
        if _list_cache["items"] is not None and now - _list_cache["t"] < _LIST_TTL:
            engine_up_flag = _list_cache["engine_up"]
            items = [dict(x) for x in _list_cache["items"]]  # shallow copy per item
        else:
            engine_up_flag, items = None, None

    if items is None:
        engine_up_flag, items = _build_container_list()
        with _cache_lock:
            _list_cache.update(t=time.time(), items=[dict(x) for x in items], engine_up=engine_up_flag)

    if not engine_up_flag:
        return {"engine_up": False, "containers": [], "stats": {}, "projects": []}

    stats = {}
    if with_stats:
        with _cache_lock:
            if _stats_cache["stats"] is not None and now - _stats_cache["t"] < _STATS_TTL:
                stats = dict(_stats_cache["stats"])
            else:
                stats = None
        if stats is None:
            running = [i["id"] for i in items if i.get("raw_state") == "running"]
            stats = _fetch_stats(running)
            with _cache_lock:
                _stats_cache.update(t=time.time(), stats=dict(stats))

    projects = {}
    for it in items:
        key = it.get("project") or "_ungrouped"
        projects.setdefault(key, {"name": key if key != "_ungrouped" else "其他", "count": 0, "running": 0})
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
        raise HTTPException(400, f"bad action {action}")
    # Without this, POST /api/containers/batch with {"names": ["--all"]} became
    # `docker stop --all` and stopped every container on the host.  The name is a
    # bare positional, so an option-like value is read by docker as a flag.
    name = cli_args.require_positional(name, label="container name")
    cmd = "rm" if action == "remove" else action
    args = [cmd, "-f", name] if action == "remove" else [cmd, name]
    rc, out, err = docker(*args, timeout=90)
    invalidate_container_lists()
    invalidate_status()
    ok = rc == 0
    return {"ok": ok, "message": out if ok else (err or out or f"exit {rc}")}


def batch_action(names: list[str], action: str) -> dict:
    if not names:
        raise HTTPException(400, "empty names")
    results = []
    ok_n = 0
    for n in names:
        try:
            r = container_action(n, action)
            results.append({"id": n, **r})
            if r.get("ok"):
                ok_n += 1
        except HTTPException as e:
            results.append({"id": n, "ok": False, "message": str(e.detail)})
        except Exception as e:
            results.append({"id": n, "ok": False, "message": str(e)})
    return {"ok": ok_n == len(names), "done": ok_n, "total": len(names), "results": results}


def action_all(action: str) -> dict:
    """Start/stop/pause/unpause all containers (Unraid Start All / Stop All)."""
    info = list_containers(with_stats=False)
    names = []
    for c in info.get("containers") or []:
        rs = c.get("raw_state")
        if action == "start" and rs not in ("running", "paused"):
            names.append(c["id"])
        elif action == "stop" and rs in ("running", "paused"):
            names.append(c["id"])
        elif action == "pause" and rs == "running":
            names.append(c["id"])
        elif action == "unpause" and rs == "paused":
            names.append(c["id"])
        elif action == "restart" and rs in ("running", "paused"):
            names.append(c["id"])
    if not names:
        return {"ok": True, "done": 0, "total": 0, "message": "无需操作", "results": []}
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
        raise HTTPException(503, "engine down")
    if not images:
        info = list_containers(with_stats=False)
        images = sorted({c["image"] for c in info.get("containers") or [] if c.get("image")})
    tid = f"docker-check-{int(time.time())}"
    j0 = _register_job(tid, stack_id="_docker_update", action="check")

    def run():
        j = j0
        status = _load_update_status()
        try:
            j["log"].append(f"检查 {len(images)} 个镜像更新…")
            for img in images:
                j["log"].append(f"→ {img}")
                try:
                    r = check_image_update(img)
                    status[img] = {
                        "status": r["status"],
                        "update": r["update"],
                        "local": r.get("local"),
                        "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                    }
                    flag = "有更新" if r["update"] else ("最新" if r["status"] == "false" else "未知")
                    j["log"].append(f"  {flag}")
                except Exception as e:
                    j["log"].append(f"  !! {e}")
                    status[img] = {"status": "undef", "update": None, "error": str(e)}
            status["_checked_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            _save_update_status(status)
            j["rc"] = 0
            j["log"].append("== 检查完成 ==")
        except Exception as e:
            j["log"].append(f"!! {e}")
            j["rc"] = -1
        finally:
            j["running"] = False
            j["finished"] = time.strftime("%H:%M:%S")
            invalidate_status()

    threading.Thread(target=run, daemon=True).start()
    return {"ok": True, "job_id": tid, "message": f"开始检查 {len(images)} 个镜像", "images": images}


def _recreate_simple(name: str, image: str, j: dict, env: dict) -> bool:
    """Best-effort recreate without compose: dump run args from inspect via docker CLI."""
    # Strategy: docker stop; docker rm; docker run with network/ports/volumes from inspect JSON
    rc, out, err = docker("inspect", name, timeout=15)
    if rc != 0:
        # might already be renamed
        j["log"].append(err or "inspect failed")
        return False
    data = json.loads(out)[0]
    host = data.get("HostConfig") or {}
    cfg_ = data.get("Config") or {}
    args = [DOCKER, "run", "-d", "--name", name]
    # restart policy
    rp = (host.get("RestartPolicy") or {}).get("Name") or ""
    if rp and rp != "no":
        args += ["--restart", rp]
    # network
    nmode = host.get("NetworkMode") or "bridge"
    if nmode and nmode not in ("default",):
        if nmode == "host":
            args += ["--network", "host"]
        elif not nmode.startswith("container:"):
            args += ["--network", nmode]
    # privileged
    if host.get("Privileged"):
        args.append("--privileged")
    # binds
    for b in host.get("Binds") or []:
        args += ["-v", b]
    # ports (skip if host network)
    if nmode != "host":
        pb = host.get("PortBindings") or {}
        for cport, binds in pb.items():
            if not binds:
                continue
            for b in binds:
                hp = b.get("HostPort") or ""
                hip = b.get("HostIp") or ""
                left = f"{hip+':' if hip else ''}{hp}" if hp else ""
                # cport like 4000/tcp
                cp = cport.split("/")[0]
                proto = cport.split("/")[1] if "/" in cport else "tcp"
                if left:
                    args += ["-p", f"{left}:{cp}/{proto}" if proto != "tcp" else f"{left}:{cp}"]
                else:
                    args += ["-p", cport]
    # env (skip PATH noise partially)
    for e in cfg_.get("Env") or []:
        if e.startswith("PATH="):
            continue
        args += ["-e", e]
    args.append(image)
    # cmd
    cmd = cfg_.get("Cmd")
    if cmd:
        args += list(cmd)

    j["log"].append("$ docker stop " + name)
    subprocess.run([DOCKER, "stop", name], timeout=120, env=env)
    j["log"].append("$ docker rm " + name)
    subprocess.run([DOCKER, "rm", name], timeout=60, env=env)
    j["log"].append("$ " + " ".join(args[:12]) + " …")
    r = subprocess.run(args, capture_output=True, text=True, timeout=120, env=env)
    if r.returncode != 0:
        j["log"].append(r.stderr or r.stdout or f"exit {r.returncode}")
        return False
    j["log"].append((r.stdout or "").strip() or "recreated")
    return True


def start_update_container_job(name: str) -> dict:
    """Pull image and recreate container (docker compose style recreate via force)."""
    rc, out, err = docker("inspect", name, timeout=15)
    if rc != 0:
        raise HTTPException(404, err or "container not found")
    data = json.loads(out)[0]
    image = (data.get("Config") or {}).get("Image") or ""
    # Prefer compose project update if labeled
    labels = (data.get("Config") or {}).get("Labels") or {}
    project = labels.get("com.docker.compose.project")
    workdir = labels.get("com.docker.compose.project.working_dir")
    compose_files = labels.get("com.docker.compose.project.config_files")

    tid = f"docker-update-{name}-{int(time.time())}"
    j0 = _register_job(tid, stack_id=project or name, action="update_container")

    def run():
        j = j0
        env = dict(os.environ)
        env.update({
            k: str(v)
            for k, v in ((cfg().get("settings") or {}).get("maintenance_env") or {}).items()
        })
        try:
            if workdir and compose_files:
                cf = compose_files.split(",")[0]
                cmds = [
                    [DOCKER, "compose", "-f", cf, "pull", name if labels.get("com.docker.compose.service") else ""],
                    [DOCKER, "compose", "-f", cf, "up", "-d", "--force-recreate",
                     labels.get("com.docker.compose.service") or name],
                ]
                # clean empty args
                cmds = [[a for a in c if a] for c in cmds]
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
                    j["log"].append(f"$ docker pull {image}")
                    rc = _stream_job_command([DOCKER, "pull", image], j, env=env)
                    if rc != 0:
                        j["rc"] = rc
                        j["log"].append("!! pull failed")
                    else:
                        # pull alone does not switch running container; try force recreate
                        # via stop/rm/create using docker's --force recreate if available
                        j["log"].append("镜像已拉取。无 compose 元数据，执行 stop→rm→create 重建…")
                        ok_re = _recreate_simple(name, image, j, env)
                        j["rc"] = 0 if ok_re else 1
            # mark image current
            st = _load_update_status()
            st[image] = {
                "status": "false", "update": False,
                "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            _save_update_status(st)
            if j.get("rc") is None:
                j["rc"] = 0
            j["log"].append("== 完成 ==")
        except Exception as e:
            j["log"].append(f"!! {e}")
            j["rc"] = -1
        finally:
            j["running"] = False
            j["finished"] = time.strftime("%H:%M:%S")
            invalidate_status()

    threading.Thread(target=run, daemon=True).start()
    return {"ok": True, "job_id": tid, "message": f"开始更新 {name}"}


def exec_in_container(name: str, command: str, shell: str = "/bin/sh") -> dict:
    """One-shot exec (Unraid console simplified)."""
    if not command or not command.strip():
        raise HTTPException(400, "empty command")
    rc, out, err = docker(
        "exec", name, shell, "-c", command,
        timeout=60,
    )
    return {
        "ok": rc == 0,
        "rc": rc,
        "output": (out or "") + (("\n" + err) if err else ""),
    }


def set_restart_policy(name: str, policy: str = "unless-stopped") -> dict:
    """Toggle Unraid-style Autostart via restart policy."""
    allowed = {"no", "always", "unless-stopped", "on-failure"}
    if policy not in allowed:
        raise HTTPException(400, f"bad policy {policy}")
    # `name` is a bare positional, so an option-shaped value would be read by
    # docker as a flag instead of as a container. The autostart route derives it
    # from a caller-supplied "docker-ctr:<name>" id, so it needs the same guard
    # the brew autostart path already uses.
    name = cli_args.require_positional(name, label="container name")
    rc, out, err = docker("update", f"--restart={policy}", name, timeout=30)
    invalidate_status()
    return {"ok": rc == 0, "message": out if rc == 0 else (err or out), "policy": policy}


def inspect_container(name: str) -> dict:
    rc, out, err = docker("inspect", name, timeout=15)
    if rc != 0:
        raise HTTPException(404, err or out or "not found")
    data = json.loads(out)[0]
    # redact env
    if "Config" in data and "Env" in data["Config"]:
        data["Config"]["Env"] = redact_env(data["Config"]["Env"])
    # slim response for UI
    cfg_ = data.get("Config") or {}
    host = data.get("HostConfig") or {}
    state = data.get("State") or {}
    return {
        "Id": data.get("Id", "")[:12],
        "Name": data.get("Name", "").lstrip("/"),
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
            "Health": (state.get("Health") or {}).get("Status"),
        },
        "Env": cfg_.get("Env") or [],
        "Cmd": cfg_.get("Cmd"),
        "Entrypoint": cfg_.get("Entrypoint"),
        "Labels": cfg_.get("Labels") or {},
        "Binds": host.get("Binds") or [],
        "PortBindings": host.get("PortBindings") or {},
        "RestartPolicy": host.get("RestartPolicy"),
        "NetworkMode": host.get("NetworkMode"),
        "Networks": list((data.get("NetworkSettings") or {}).get("Networks") or {}.keys()),
        "Mounts": [
            {"Source": m.get("Source"), "Destination": m.get("Destination"),
             "Type": m.get("Type"), "RW": m.get("RW")}
            for m in (data.get("Mounts") or [])
        ],
        "raw": data,
    }


def list_images() -> list:
    data, rc, err = docker_json(
        ["images", "--format", "{{json .}}"], timeout=15)
    if rc != 0:
        raise HTTPException(500, err or "images failed")
    if not isinstance(data, list):
        data = [data] if data else []
    return data


def list_volumes() -> list:
    rc, out, err = docker("volume", "ls", "--format", "{{.Name}}\t{{.Driver}}\t{{.Mountpoint}}", timeout=12)
    if rc != 0:
        raise HTTPException(500, err or out)
    items = []
    for line in out.splitlines():
        p = line.split("\t")
        if len(p) >= 2:
            items.append({"Name": p[0], "Driver": p[1], "Mountpoint": p[2] if len(p) > 2 else ""})
    return items


def list_networks() -> list:
    rc, out, err = docker("network", "ls", "--format", "{{.ID}}\t{{.Name}}\t{{.Driver}}\t{{.Scope}}", timeout=12)
    if rc != 0:
        raise HTTPException(500, err or out)
    items = []
    for line in out.splitlines():
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
    else:
        rc, out, err = docker("system", "prune", "-af", timeout=300)
    invalidate_status()
    return {"ok": rc == 0, "message": out or err}


def remove_image(image: str, force: bool = False) -> dict:
    if not image:
        raise api_error("container.image_ref_required")
    args = ["rmi"]
    if force:
        args.append("-f")
    args.append(image)
    rc, out, err = docker(*args, timeout=120)
    invalidate_status()
    return {"ok": rc == 0, "message": out if rc == 0 else (err or out)}


def remove_volume(name: str, force: bool = False) -> dict:
    if not name:
        raise api_error("container.volume_name_required")
    args = ["volume", "rm"]
    if force:
        args.append("-f")
    args.append(name)
    rc, out, err = docker(*args, timeout=60)
    return {"ok": rc == 0, "message": out if rc == 0 else (err or out)}


def remove_network(name: str) -> dict:
    if not name:
        raise api_error("container.network_name_required")
    if name in ("bridge", "host", "none"):
        raise api_error("container.builtin_network")
    rc, out, err = docker("network", "rm", name, timeout=30)
    return {"ok": rc == 0, "message": out if rc == 0 else (err or out)}


def pull_image(image: str) -> dict:
    if not image or not re_match_image(image):
        raise api_error("container.bad_image_name")
    rc, out, err = docker("pull", image, timeout=600)
    return {"ok": rc == 0, "message": (out or err or "")[-2000:]}


def re_match_image(image: str) -> bool:
    import re
    return bool(re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._/:@-]{0,200}$", image or ""))


def rename_container(name: str, new_name: str) -> dict:
    if not new_name or not re_match_image(new_name.replace("/", "x")):
        # name only [a-zA-Z0-9][a-zA-Z0-9_.-]*
        import re
        if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$", new_name or ""):
            raise api_error("container.bad_new_name")
    rc, out, err = docker("rename", name, new_name, timeout=30)
    invalidate_status()
    return {"ok": rc == 0, "message": out if rc == 0 else (err or out)}


def create_run_container(body: dict) -> dict:
    """docker run -d with common options from panel form."""
    import re
    if not engine_up():
        raise api_error("container.engine_down")
    image = (body.get("image") or "").strip()
    name = (body.get("name") or "").strip()
    if not image or not re_match_image(image):
        raise api_error("container.image_required")
    if name and not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$", name):
        raise api_error("container.bad_container_name")

    args = ["run", "-d"]
    if name:
        args += ["--name", name]
    restart = (body.get("restart") or "unless-stopped").strip()
    if restart and restart != "no":
        args += ["--restart", restart]
    if body.get("privileged"):
        args.append("--privileged")
    network = (body.get("network") or "").strip()
    if network:
        args += ["--network", network]
    # ports: ["8080:80", "443:443"]
    for p in body.get("ports") or []:
        p = str(p).strip()
        if p and re.match(r"^[0-9.:\-/tcpudp]+$", p):
            args += ["-p", p]
    # volumes: ["/host:/container", "vol:/data"]
    for v in body.get("volumes") or []:
        v = str(v).strip()
        if v and ":" in v:
            args += ["-v", v]
    # env: ["KEY=val"]
    for e in body.get("env") or []:
        e = str(e).strip()
        if e and "=" in e:
            args += ["-e", e]
    # extra args carefully not allowed for safety
    args.append(image)
    cmd = body.get("command")
    if isinstance(cmd, str) and cmd.strip():
        # simple shell form — split
        args += cmd.strip().split()
    elif isinstance(cmd, list):
        args += [str(x) for x in cmd]

    rc, out, err = docker(*args, timeout=180)
    invalidate_status()
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
    args = ["volume", "create"]
    if driver and driver != "local":
        args += ["--driver", driver]
    args.append(name)
    rc, out, err = docker(*args, timeout=30)
    return {"ok": rc == 0, "message": out if rc == 0 else (err or out)}


def create_network(name: str, driver: str = "bridge") -> dict:
    import re
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$", name or ""):
        raise api_error("container.bad_network_name")
    args = ["network", "create"]
    if driver:
        args += ["--driver", driver]
    args.append(name)
    rc, out, err = docker(*args, timeout=30)
    return {"ok": rc == 0, "message": out if rc == 0 else (err or out)}


def _stack_paths() -> list[dict]:
    """Resolve compose stacks from config + auto-scan Services/*."""
    stacks = []
    seen = set()
    for s in cfg().get("stacks") or []:
        path = s.get("path")
        if path:
            p = Path(path)
            compose = p / (s.get("compose_file") or "docker-compose.yml")
            if not compose.exists():
                for alt in ("compose.yml", "docker-compose.yaml", "compose.yaml"):
                    if (p / alt).exists():
                        compose = p / alt
                        break
            stacks.append({
                "id": s.get("id") or p.name,
                "name": s.get("name") or p.name,
                "path": str(p),
                "compose_file": compose.name if compose.exists() else None,
                "compose_path": str(compose) if compose.exists() else None,
                "containers": s.get("containers") or [],
                "source": "config",
            })
            seen.add(str(p.resolve()) if p.exists() else str(p))
        elif s.get("containers"):
            stacks.append({
                "id": s.get("id"),
                "name": s.get("name") or s.get("id"),
                "path": None,
                "compose_file": None,
                "compose_path": None,
                "containers": s.get("containers") or [],
                "source": "config",
            })

    services_root = Path.home() / "Services"
    if services_root.is_dir():
        for comp in sorted(services_root.glob("*/docker-compose.y*ml")) + sorted(services_root.glob("*/compose.y*ml")):
            root = str(comp.parent.resolve())
            if root in seen:
                continue
            seen.add(root)
            stacks.append({
                "id": comp.parent.name,
                "name": comp.parent.name,
                "path": str(comp.parent),
                "compose_file": comp.name,
                "compose_path": str(comp),
                "containers": [],
                "source": "scan",
            })
    return stacks


def list_stacks() -> list:
    stacks = _stack_paths()
    info = list_containers(with_stats=False)
    by_project: dict[str, list] = {}
    by_name: dict[str, dict] = {}
    for c in info.get("containers") or []:
        by_name[c["id"]] = c
        if c.get("project"):
            by_project.setdefault(c["project"], []).append(c["id"])
    for s in stacks:
        found: list[str] = []
        if s.get("path"):
            proj = Path(s["path"]).name
            found = list(by_project.get(proj) or by_project.get(s["id"]) or [])
        for name in s.get("containers") or []:
            if name in by_name and name not in found:
                found.append(name)
        # compose project often equals directory name; also match container_name == stack id
        if s["id"] in by_name and s["id"] not in found:
            found.append(s["id"])
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
        raise HTTPException(404, "unknown stack")
    if not stack.get("compose_path"):
        raise api_error("container.no_compose_file")

    tid = f"stack-{stack_id}-{action}-{int(time.time())}"
    j0 = _register_job(tid, stack_id=stack_id, action=action)

    compose_path = stack["compose_path"]
    workdir = stack["path"]

    def run():
        j = j0
        env = dict(os.environ)
        env.update({k: str(v) for k, v in ((cfg().get("settings") or {}).get("maintenance_env") or {}).items()})
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
                    j["log"].append(f"!! 失败 exit {rc}")
                    break
            else:
                j["rc"] = 0
                j["log"].append("== 完成 ==")
        except Exception as e:
            j["log"].append(f"!! {e}")
            j["rc"] = -1
        finally:
            j["running"] = False
            j["finished"] = time.strftime("%H:%M:%S")
            invalidate_status()

    threading.Thread(target=run, daemon=True).start()
    return {"ok": True, "job_id": tid, "message": "任务已开始"}


def stack_job_log(job_id: str) -> dict:
    j = _cjobs.get(job_id)
    if not j:
        # also allow latest job for stack
        for k, v in reversed(list(_cjobs.items())):
            if v.get("stack_id") == job_id or k == job_id:
                j = v
                job_id = k
                break
    if not j:
        return {"running": False, "rc": None, "log": "（尚未运行）", "job_id": job_id}
    return {"running": j["running"], "rc": j["rc"], "started": j.get("started"),
            "finished": j.get("finished"), "log": "\n".join(j["log"]) or "（等待输出…）",
            "job_id": job_id, "stack_id": j.get("stack_id"), "action": j.get("action")}


def latest_stack_jobs() -> list:
    # return recent unique by stack
    by = {}
    for k, v in _cjobs.items():
        sid = v.get("stack_id")
        if sid:
            by[sid] = {**job_public(k, v)}
    return list(by.values())


def job_public(jid, j):
    return {"job_id": jid, "stack_id": j.get("stack_id"), "action": j.get("action"),
            "running": j.get("running"), "rc": j.get("rc"), "finished": j.get("finished")}
