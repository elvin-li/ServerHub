"""Docker/OrbStack engine info (Unraid Docker Settings equivalent)."""
from __future__ import annotations

import json

from hub.docker_cli import docker, engine_up
from hub.paths import DOCKER, ORB
from hub.util import fan_out, sh


def _slim_info() -> dict:
    rc, out, err = docker("info", "--format", "{{json .}}", timeout=15)
    info = {}
    if rc == 0 and out.strip():
        try:
            info = json.loads(out)
        except json.JSONDecodeError:
            info = {"raw": out[:2000]}
    # slim fields like Unraid docker settings summary
    slim = {
        "ServerVersion": info.get("ServerVersion"),
        "OperatingSystem": info.get("OperatingSystem"),
        "OSType": info.get("OSType"),
        "Architecture": info.get("Architecture"),
        "NCPU": info.get("NCPU"),
        "MemTotal": info.get("MemTotal"),
        "DockerRootDir": info.get("DockerRootDir"),
        "Driver": info.get("Driver"),
        "LoggingDriver": info.get("LoggingDriver"),
        "CgroupDriver": info.get("CgroupDriver"),
        "Name": info.get("Name"),
        "KernelVersion": info.get("KernelVersion"),
        "Containers": info.get("Containers"),
        "ContainersRunning": info.get("ContainersRunning"),
        "ContainersPaused": info.get("ContainersPaused"),
        "ContainersStopped": info.get("ContainersStopped"),
        "Images": info.get("Images"),
        "HttpProxy": info.get("HttpProxy"),
        "HttpsProxy": info.get("HttpsProxy"),
        "NoProxy": info.get("NoProxy"),
    }
    return slim


def _version() -> dict:
    rc, ver, _ = docker("version", "--format", "{{json .}}", timeout=10)
    if rc == 0 and ver.strip():
        try:
            return json.loads(ver)
        except json.JSONDecodeError:
            pass
    return {}


def _orb_version() -> str:
    rc, orb_v, _ = sh([ORB, "version"], timeout=5)
    return orb_v if rc == 0 else ""


def engine_info() -> dict:
    if not engine_up():
        return {
            "engine_up": False,
            "docker_cli": DOCKER,
            "orb_cli": ORB,
            "message": "引擎未运行",
        }

    # `docker info`, `docker version` and `orb version` ask three unrelated questions
    # of two different binaries, so the page waited out the sum of their timeouts
    # (15s + 10s + 5s worst case) to render one panel. None of them reads the others'
    # output. Each helper swallows its own failure and returns an empty value, which
    # is what fan_out requires, so one slow engine no longer holds up the other two.
    slim, version, orb_v = fan_out(
        lambda probe: probe(), [_slim_info, _version, _orb_version], max_workers=3
    )
    return {
        "engine_up": True,
        "docker_cli": DOCKER,
        "orb_cli": ORB,
        "orb_version": orb_v,
        "info": slim,
        "version": version,
    }
