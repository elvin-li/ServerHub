"""Container management API."""
from __future__ import annotations

import asyncio
import re
from typing import Optional

from fastapi import APIRouter, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from hub import audit, auth, cli_args
from hub import containers_svc as svc
from hub.errors import api_error
from hub.paths import DOCKER

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")


def _as_text(value) -> str:
    """Drop leftover RecursionError / ``\\ud800`` so SSE log start cannot 500."""
    if value is None:
        return ""
    for base in (bytes, bytearray):
        try:
            return base.decode(value, "utf-8", "replace")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
    if type(value) is not bool:
        try:
            if isinstance(value, float):
                finite = float.__float__(value)
                if finite != finite or finite in (float("inf"), float("-inf")):
                    return ""
                return str(finite)
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return ""
    try:
        return str.encode(str.__str__(value), "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        pass
    try:
        cls = type(value)
        if cls.__str__ is object.__str__ and cls.__repr__ is object.__repr__:
            return ""
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    try:
        text = str(value)
    except RecursionError:
        try:
            return type(value).__name__
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return ""
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    try:
        text = str.encode(text, "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    return "" if _ADDR_REPR_RE.search(text) else text


router = APIRouter(tags=["containers"])


def _audit_mutation(event: str, request: Request | None, **fields) -> None:
    """One audit line for a container-engine mutation.

    Called after the service call returned, so a rejected or failed docker
    invocation that raised leaves no record — the 4xx/5xx is its own trace.
    FastAPI always injects `request`; the None guard only keeps direct
    in-process calls (tests, tooling) working.
    """
    audit.record(
        event,
        username=auth.request_username(request) if request is not None else "",
        client=auth.request_client_id(request),
        **fields,
    )


class CAction(BaseModel):
    action: str


class BatchBody(BaseModel):
    action: str
    names: list[str] = []


class AllBody(BaseModel):
    action: str  # start|stop|pause|unpause|restart


class ExecBody(BaseModel):
    command: str
    shell: str = "/bin/sh"


class RestartPolicyBody(BaseModel):
    policy: str = "unless-stopped"


class StackAction(BaseModel):
    action: str = "update"


class PruneBody(BaseModel):
    kind: str = "system"


class RunBody(BaseModel):
    image: str
    name: Optional[str] = None
    restart: str = "unless-stopped"
    ports: list[str] = []
    volumes: list[str] = []
    env: list[str] = []
    network: Optional[str] = None
    privileged: bool = False
    command: Optional[str] = None


class ImageBody(BaseModel):
    image: str
    force: bool = False


class NameBody(BaseModel):
    name: str
    force: bool = False


class RenameBody(BaseModel):
    new_name: str


class CreateVolBody(BaseModel):
    name: str
    driver: str = "local"


class CreateNetBody(BaseModel):
    name: str
    driver: str = "bridge"


# ---- static paths first ----
@router.get("/api/containers")
def list_containers(stats: bool = True):
    return svc.list_containers(with_stats=stats)


@router.post("/api/containers/run")
def containers_run(body: RunBody, request: Request = None):
    result = svc.create_run_container(body.model_dump())
    # The mounts and the privilege flag are what an investigator needs: a
    # privileged container with / bind-mounted is host access.
    _audit_mutation(
        audit.CONTAINER_RUN, request,
        name=body.name or "", image=body.image,
        volumes=",".join(body.volumes), privileged=bool(body.privileged),
    )
    return result


@router.post("/api/containers/batch")
def containers_batch(body: BatchBody, request: Request = None):
    result = svc.batch_action(body.names, body.action)
    # One line per request, not per name, so a wide batch cannot evict real
    # events from the capped trail.
    _audit_mutation(
        audit.CONTAINER_ACTION, request,
        action=body.action, targets=",".join(body.names),
    )
    return result


@router.post("/api/containers/all")
def containers_all(body: AllBody, request: Request):
    if (
        getattr(request.state, "serverhub_auth_kind", "") == "local-client"
        and body.action not in {"start", "stop", "restart"}
    ):
        raise api_error("auth.admin_required")
    result = svc.action_all(body.action)
    _audit_mutation(audit.CONTAINER_ACTION, request,
                    action=body.action, targets="all")
    return result


@router.post("/api/containers/check-updates")
def containers_check_updates():
    return svc.start_check_updates_job()


@router.get("/api/images")
def images():
    return {"images": svc.list_images()}


@router.post("/api/images/pull")
def images_pull(body: ImageBody, request: Request = None):
    result = svc.pull_image(body.image)
    _audit_mutation(audit.CONTAINER_IMAGE_CHANGED, request,
                    action="pull", image=body.image)
    return result


@router.post("/api/images/remove")
def images_remove(body: ImageBody, request: Request = None):
    result = svc.remove_image(body.image, force=body.force)
    _audit_mutation(audit.CONTAINER_IMAGE_CHANGED, request,
                    action="remove", image=body.image, force=bool(body.force))
    return result


@router.get("/api/volumes")
def volumes():
    return {"volumes": svc.list_volumes()}


@router.post("/api/volumes/create")
def volumes_create(body: CreateVolBody, request: Request = None):
    result = svc.create_volume(body.name, body.driver)
    _audit_mutation(audit.CONTAINER_VOLUME_CHANGED, request,
                    action="create", name=body.name)
    return result


@router.post("/api/volumes/remove")
def volumes_remove(body: NameBody, request: Request = None):
    result = svc.remove_volume(body.name, force=body.force)
    _audit_mutation(audit.CONTAINER_VOLUME_CHANGED, request,
                    action="remove", name=body.name, force=bool(body.force))
    return result


@router.get("/api/networks")
def networks():
    return {"networks": svc.list_networks()}


@router.post("/api/networks/create")
def networks_create(body: CreateNetBody, request: Request = None):
    result = svc.create_network(body.name, body.driver)
    _audit_mutation(audit.CONTAINER_NETWORK_CHANGED, request,
                    action="create", name=body.name)
    return result


@router.post("/api/networks/remove")
def networks_remove(body: NameBody, request: Request = None):
    result = svc.remove_network(body.name)
    _audit_mutation(audit.CONTAINER_NETWORK_CHANGED, request,
                    action="remove", name=body.name)
    return result


@router.post("/api/prune")
def prune(body: PruneBody, request: Request = None):
    result = svc.prune(body.kind)
    _audit_mutation(audit.CONTAINER_PRUNED, request, kind=body.kind)
    return result


@router.get("/api/stacks")
def stacks():
    return {"stacks": svc.list_stacks(), "jobs": svc.latest_stack_jobs()}


@router.post("/api/stacks/{stack_id}/run")
def stack_run(stack_id: str, body: StackAction, request: Request = None):
    result = svc.start_stack_job(stack_id, body.action)
    _audit_mutation(audit.CONTAINER_ACTION, request,
                    action=body.action, targets=f"stack:{stack_id}")
    return result


@router.get("/api/stacks/jobs/{job_id}")
def stack_job(job_id: str):
    return svc.stack_job_log(job_id)


# ---- per-container ----
@router.post("/api/containers/{name}/action")
def container_action(name: str, body: CAction, request: Request = None):
    if body.action == "update":
        result = svc.start_update_container_job(name)
    else:
        result = svc.container_action(name, body.action)
    _audit_mutation(audit.CONTAINER_ACTION, request,
                    action=body.action, targets=name)
    return result


@router.post("/api/containers/{name}/update")
def container_update(name: str, request: Request = None):
    result = svc.start_update_container_job(name)
    _audit_mutation(audit.CONTAINER_ACTION, request,
                    action="update", targets=name)
    return result


@router.post("/api/containers/{name}/exec")
def container_exec(name: str, body: ExecBody, request: Request = None):
    result = svc.exec_in_container(name, body.command, body.shell)
    # The Terminal page's docker-exec twin has always written the command it
    # ran into its 0600 trail; this endpoint runs the same class of command
    # and recorded nothing.  Capped so one pasted script cannot evict half
    # the capped trail.
    _audit_mutation(
        audit.CONTAINER_EXEC, request,
        container=name, shell=body.shell,
        command=(body.command or "")[:300],
        ok=bool(result.get("ok")) if isinstance(result, dict) else None,
    )
    return result


@router.post("/api/containers/{name}/restart-policy")
def container_restart_policy(name: str, body: RestartPolicyBody, request: Request = None):
    result = svc.set_restart_policy(name, body.policy)
    _audit_mutation(audit.CONTAINER_CONFIG_CHANGED, request,
                    container=name, field="restart_policy", value=body.policy)
    return result


@router.post("/api/containers/{name}/rename")
def container_rename(name: str, body: RenameBody, request: Request = None):
    result = svc.rename_container(name, body.new_name)
    _audit_mutation(audit.CONTAINER_CONFIG_CHANGED, request,
                    container=name, field="name", value=body.new_name)
    return result


@router.get("/api/containers/{name}/inspect")
def inspect(name: str):
    return svc.inspect_container(name)


@router.get("/api/containers/{name}/logs")
async def logs_sse(name: str, tail: int = Query(200, ge=1, le=5000), follow: bool = True):
    # Reject an option-shaped container name before it reaches the docker argv,
    # where `--since=…`/`-f` would be read as flags rather than a container.
    name = cli_args.require_positional(name, label="container name")

    async def gen():
        cmd = [DOCKER, "logs", "--tail", str(tail), "--timestamps"]
        if follow:
            cmd.append("-f")
        cmd.append("--")
        cmd.append(name)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except Exception as e:
            yield f"data: !! could not start log stream: {_as_text(e)}\n\n"
            return
        try:
            assert proc.stdout
            while True:
                try:
                    line = await asyncio.wait_for(proc.stdout.readline(), timeout=25)
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
                    if proc.returncode is not None:
                        break
                    if not follow:
                        break
                    continue
                except ValueError:
                    # asyncio StreamReader.readline() raises ValueError when a
                    # leftover log line exceeds the 64KiB limit — that used to
                    # 500 GET /api/containers/{name}/logs.
                    try:
                        while True:
                            chunk = await asyncio.wait_for(proc.stdout.read(4096), timeout=5)
                            if not chunk or b"\n" in chunk:
                                break
                    except Exception:
                        pass
                    yield "data: …[line truncated]\n\n"
                    continue
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").rstrip()
                yield f"data: {text}\n\n"
        finally:
            # Killing without reaping leaves the child unwaited and keeps its
            # stdout pipe transport alive until GC, so every opened-and-closed
            # log view leaked a defunct `docker logs` plus its FDs.
            if proc.returncode is None:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                except Exception:
                    pass
            try:
                await proc.wait()
            except Exception:
                pass

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
