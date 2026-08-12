"""OrbStack / docker container discovery."""
from __future__ import annotations

import threading
import time

from hub.config import override
from hub.host_address import resolve_value
from hub.paths import DOCKER
from hub.util import sh

_TTL = 4.0
_cache: dict = {"t": 0.0, "v": None}
_lock = threading.Lock()
#: Serialises the refresh itself.  Without it, every poller that arrives while
#: the cache is cold spawns its own `docker ps -a`; the dashboard, bookmarks and
#: containers page routinely land in the same tick.
_refresh_lock = threading.Lock()


def invalidate_containers():
    with _lock:
        _cache["t"] = 0
        _cache["v"] = None


def _cached(force: bool):
    """Return the cached value when it is still fresh, else None."""
    if force:
        return None
    with _lock:
        if _cache["v"] is not None and time.time() - _cache["t"] < _TTL:
            items, engine_up = _cache["v"]
            return list(items), engine_up
    return None


def discover_containers(force: bool = False):
    """Return (items, engine_up). Uses Docker-compatible CLI from OrbStack.

    Short TTL cache avoids redundant `docker ps -a` when status, bookmarks,
    and container pages hit within the same few seconds.
    """
    hit = _cached(force)
    if hit is not None:
        return hit

    with _refresh_lock:
        # Re-check on freshness alone, not on `force`.  Whoever held the lock has
        # just refreshed, so a caller that asked to bypass a *stale* cache is
        # still served correctly — and a burst of manual refreshes collapses into
        # one `docker ps -a` instead of one per click.
        hit = _cached(force=False)
        if hit is not None:
            return hit
        return _refresh()


def _refresh():
    rc, out, _ = sh(
        [
            DOCKER,
            "ps",
            "-a",
            "--format",
            '{{.Names}}\t{{.State}}\t{{.Status}}\t{{.Label "com.docker.compose.project"}}',
        ],
        timeout=8,
    )
    items, engine_up = [], rc == 0
    if rc == 0:
        for line in out.splitlines():
            # maxsplit=3: the last field is a Docker *label*, which is an
            # arbitrary string.  A plain split() turned a label containing a tab
            # into five fields, and the four-way unpack below then raised
            # ValueError -- uncaught, straight out of discover_containers() and
            # into /api/status, so one crafted `docker run --label` broke the
            # dashboard for everyone.  Capping the split keeps any extra tabs
            # inside the project field where they are harmless.
            p = line.split("\t", 3)
            if len(p) < 4:
                continue
            name, st, status, project = p
            ov = resolve_value(override(name))
            if ov.get("hide"):
                continue
            # ok=运行 / warn=不健康 / stopped=主动退出(灰) / down=异常
            if st == "running" and "unhealthy" in status:
                state = "warn"
            elif st == "running":
                state = "ok"
            elif st in ("exited", "created", "paused"):
                state = "stopped"
            else:
                state = "down"
            if st == "running":
                acts = ["restart", "stop", "pause", "logs"]
            elif st == "paused":
                acts = ["unpause", "stop", "logs"]
            else:
                acts = ["start", "logs"]
            if ov.get("url"):
                acts = list(acts) + ["open"]
            items.append(
                {
                    "id": name,
                    "kind": "container",
                    "name": ov.get("name", name),
                    "state": state,
                    "detail": status,
                    "url": ov.get("url"),
                    "group": ov.get("group", f"Containers · {project or 'other'}"),
                    "actions": acts,
                    "compose_project": project or None,
                }
            )
    with _lock:
        _cache.update(t=time.time(), v=(items, engine_up))
    return list(items), engine_up
