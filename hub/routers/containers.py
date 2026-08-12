"""Container management API."""
from __future__ import annotations

import asyncio
from typing import Optional

from fastapi import APIRouter, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from hub import cli_args
from hub import containers_svc as svc
from hub.errors import api_error
from hub.paths import DOCKER

router = APIRouter(tags=["containers"])


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
def containers_run(body: RunBody):
    return svc.create_run_container(body.model_dump())


@router.post("/api/containers/batch")
def containers_batch(body: BatchBody):
    return svc.batch_action(body.names, body.action)


@router.post("/api/containers/all")
def containers_all(body: AllBody, request: Request):
    if (
        getattr(request.state, "serverhub_auth_kind", "") == "local-client"
        and body.action not in {"start", "stop", "restart"}
    ):
        raise api_error("auth.admin_required")
    return svc.action_all(body.action)


@router.post("/api/containers/check-updates")
def containers_check_updates():
    return svc.start_check_updates_job()


@router.get("/api/images")
def images():
    return {"images": svc.list_images()}


@router.post("/api/images/pull")
def images_pull(body: ImageBody):
    return svc.pull_image(body.image)


@router.post("/api/images/remove")
def images_remove(body: ImageBody):
    return svc.remove_image(body.image, force=body.force)


@router.get("/api/volumes")
def volumes():
    return {"volumes": svc.list_volumes()}


@router.post("/api/volumes/create")
def volumes_create(body: CreateVolBody):
    return svc.create_volume(body.name, body.driver)


@router.post("/api/volumes/remove")
def volumes_remove(body: NameBody):
    return svc.remove_volume(body.name, force=body.force)


@router.get("/api/networks")
def networks():
    return {"networks": svc.list_networks()}


@router.post("/api/networks/create")
def networks_create(body: CreateNetBody):
    return svc.create_network(body.name, body.driver)


@router.post("/api/networks/remove")
def networks_remove(body: NameBody):
    return svc.remove_network(body.name)


@router.post("/api/prune")
def prune(body: PruneBody):
    return svc.prune(body.kind)


@router.get("/api/stacks")
def stacks():
    return {"stacks": svc.list_stacks(), "jobs": svc.latest_stack_jobs()}


@router.post("/api/stacks/{stack_id}/run")
def stack_run(stack_id: str, body: StackAction):
    return svc.start_stack_job(stack_id, body.action)


@router.get("/api/stacks/jobs/{job_id}")
def stack_job(job_id: str):
    return svc.stack_job_log(job_id)


# ---- per-container ----
@router.post("/api/containers/{name}/action")
def container_action(name: str, body: CAction):
    if body.action == "update":
        return svc.start_update_container_job(name)
    return svc.container_action(name, body.action)


@router.post("/api/containers/{name}/update")
def container_update(name: str):
    return svc.start_update_container_job(name)


@router.post("/api/containers/{name}/exec")
def container_exec(name: str, body: ExecBody):
    return svc.exec_in_container(name, body.command, body.shell)


@router.post("/api/containers/{name}/restart-policy")
def container_restart_policy(name: str, body: RestartPolicyBody):
    return svc.set_restart_policy(name, body.policy)


@router.post("/api/containers/{name}/rename")
def container_rename(name: str, body: RenameBody):
    return svc.rename_container(name, body.new_name)


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
            yield f"data: !! could not start log stream: {e}\n\n"
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
