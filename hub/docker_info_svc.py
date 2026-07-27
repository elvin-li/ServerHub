"""Docker/OrbStack engine info (Unraid Docker Settings equivalent)."""
from __future__ import annotations

import json

from hub.docker_cli import docker, engine_up
from hub.paths import DOCKER, ORB
from hub.util import sh


def engine_info() -> dict:
    if not engine_up():
        return {
            "engine_up": False,
            "docker_cli": DOCKER,
            "orb_cli": ORB,
            "message": "引擎未运行",
        }
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
    rc2, ver, _ = docker("version", "--format", "{{json .}}", timeout=10)
    version = {}
    if rc2 == 0 and ver.strip():
        try:
            version = json.loads(ver)
        except json.JSONDecodeError:
            pass
    # orb version
    rc3, orb_v, _ = sh([ORB, "version"], timeout=5)
    return {
        "engine_up": True,
        "docker_cli": DOCKER,
        "orb_cli": ORB,
        "orb_version": orb_v if rc3 == 0 else "",
        "info": slim,
        "version": version,
    }
