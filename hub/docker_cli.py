"""OrbStack Docker-compatible CLI helpers."""
from __future__ import annotations

import json
import re
from typing import Any

from hub.paths import DOCKER
from hub.util import sh

SENSITIVE = re.compile(r"(PASSWORD|SECRET|TOKEN|API_KEY|KEY|PASS|CREDENTIAL)", re.I)


def docker(*args, timeout=30) -> tuple[int, str, str]:
    return sh([DOCKER, *args], timeout=timeout)


def docker_json(args: list[str], timeout=30) -> Any:
    rc, out, err = docker(*args, timeout=timeout)
    if rc != 0:
        return None, rc, err or out
    if not out.strip():
        return [] if "--format" in " ".join(args) else None, 0, ""
    try:
        # docker --format '{{json .}}' produces NDJSON
        lines = [ln for ln in out.splitlines() if ln.strip()]
        if len(lines) > 1 or (lines and lines[0].startswith("{") and "\n" not in out.strip()):
            # multi-line NDJSON or single object
            if all(ln.lstrip().startswith("{") or ln.lstrip().startswith("[") for ln in lines):
                objs = []
                for ln in lines:
                    objs.append(json.loads(ln))
                # if single array line
                if len(objs) == 1 and isinstance(objs[0], list):
                    return objs[0], 0, ""
                return objs, 0, ""
        return json.loads(out), 0, ""
    except json.JSONDecodeError:
        return out, 0, ""


def engine_up() -> bool:
    rc, _, _ = docker("info", timeout=8)
    return rc == 0


def redact_env(env_list: list[str] | None) -> list[str]:
    out = []
    for e in env_list or []:
        if "=" in e:
            k, v = e.split("=", 1)
            if SENSITIVE.search(k):
                out.append(f"{k}=***")
            else:
                out.append(e)
        else:
            out.append(e)
    return out
