"""Docker/OrbStack engine info (Unraid Docker Settings equivalent)."""
from __future__ import annotations

import json
import re

from hub.docker_cli import _jsonable, docker, engine_up, parse_int_capped
from hub.paths import DOCKER, ORB
from hub.util import fan_out, safe_json_loads, sh

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")


def _as_text(value) -> str:
    if value is None:
        return ""
    for base in (bytes, bytearray):
        try:
            return base.decode(value, "utf-8", "replace")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
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


def _payload(value) -> dict:
    cleaned = _jsonable(value)
    return cleaned if isinstance(cleaned, dict) else {}


def _slim_info() -> dict:
    rc, out, err = docker("info", "--format", "{{json .}}", timeout=15)
    info = {}
    text = _as_text(out).strip()
    if rc == 0 and text:
        try:
            # parse_int_capped: one leftover >4300-digit number used to
            # ValueError the decode and collapse every field into "raw".
            parsed = safe_json_loads(text, parse_int=parse_int_capped)
        except (TypeError, ValueError, json.JSONDecodeError, RecursionError):
            # RecursionError: leftover deeply-nested ``{{json .}}`` is not ValueError.
            info = {"raw": text[:2000]}
        else:
            info = parsed if isinstance(parsed, dict) else {"raw": text[:2000]}
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
    text = _as_text(ver).strip()
    if rc == 0 and text:
        try:
            parsed = safe_json_loads(text, parse_int=parse_int_capped)
        except (TypeError, ValueError, json.JSONDecodeError, RecursionError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _orb_version() -> str:
    rc, orb_v, _ = sh([ORB, "version"], timeout=5)
    return _as_text(orb_v) if rc == 0 else ""


def engine_info() -> dict:
    try:
        up = bool(engine_up())
    except Exception:
        up = False
    if not up:
        return _payload({
            "engine_up": False,
            "docker_cli": DOCKER,
            "orb_cli": ORB,
            "message": "engine is not running",
        })

    # `docker info`, `docker version` and `orb version` ask three unrelated questions
    # of two different binaries, so the page waited out the sum of their timeouts
    # (15s + 10s + 5s worst case) to render one panel. None of them reads the others'
    # output. Each helper swallows its own failure and returns an empty value, which
    # is what fan_out requires, so one slow engine no longer holds up the other two.
    def _safe(item):
        probe, fallback = item
        try:
            return probe()
        except Exception:
            return fallback

    slim, version, orb_v = fan_out(
        _safe,
        [(_slim_info, {}), (_version, {}), (_orb_version, "")],
        max_workers=3,
    )
    return _payload({
        "engine_up": True,
        "docker_cli": DOCKER,
        "orb_cli": ORB,
        "orb_version": orb_v,
        "info": slim,
        "version": version,
    })
