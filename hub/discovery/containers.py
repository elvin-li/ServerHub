"""OrbStack / docker container discovery."""
from __future__ import annotations

import threading
import time

from hub.config import override
from hub.group_rules import configured_group_rules, resolve_group
from hub.host_address import resolve_value
from hub.paths import DOCKER
from hub.service_signatures import configured_signatures, identify, image_basename
from hub.util import sh

_TTL = 4.0
_cache: dict = {"t": 0.0, "v": None}
_lock = threading.Lock()
#: Serialises the refresh itself.  Without it, every poller that arrives while
#: the cache is cold spawns its own `docker ps -a`; the dashboard, bookmarks and
#: containers page routinely land in the same tick.
_refresh_lock = threading.Lock()

#: How many *consecutive* probe timeouts may re-serve the last real observation
#: before the engine is reported down anyway.  A stopped engine is not affected:
#: `docker ps` against a dead daemon fails fast ("Cannot connect to the Docker
#: daemon"), it does not time out.  A timeout means the host was too loaded to
#: answer inside the budget -- one overnight load storm turned that into fifteen
#: "OrbStack engine not running" alerts while the engine had two days of uptime.
#: The cap keeps a genuinely wedged daemon visible: when every probe times out,
#: the tolerance runs out and the report flips to down.
_TIMEOUT_TOLERANCE = 3
#: Consecutive timeout count.  Only touched under `_refresh_lock`, apart from
#: the reset in `invalidate_containers`, which is a whole-word int store.
_timeouts = 0
#: Bumped by `invalidate_containers`.  Starting, stopping or removing a
#: container ends there, and the dashboard polls the whole time, so a
#: `docker ps -a` launched a moment before the click is the ordinary case
#: rather than a narrow one -- and it saw the container in its old state.
#: Publishing that answer afterwards stamps it fresh, and the row the operator
#: just acted on stays wrong for another TTL. Superseded refreshes are dropped.
_generation = 0


def _aligned_container_name(name: str, image: str, sig: dict) -> bool:
    """True when the container id is just the image/slug, so renaming is safe.

    ``grafana`` or ``redis-1`` can become "Grafana" / "Redis".  A custom name
    like ``cache`` keeps its name and only gets the signature chip.
    """
    n = (name or "").lower().replace("_", "-")
    if not n:
        return False
    base = image_basename(image)
    slug = str(sig.get("slug") or "").lower()
    if base and n == base:
        return True
    if slug and (n == slug or n.startswith(f"{slug}-") or n.endswith(f"-{slug}")):
        return True
    return False


def invalidate_containers():
    global _timeouts, _generation
    with _lock:
        _generation += 1
        _cache["t"] = 0
        _cache["v"] = None
    _timeouts = 0


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
    global _timeouts
    with _lock:
        began = _generation
    rc, out, err = sh(
        [
            DOCKER,
            "ps",
            "-a",
            "--format",
            '{{.Names}}\t{{.State}}\t{{.Status}}\t{{.Image}}\t{{.Label "com.docker.compose.project"}}',
        ],
        timeout=8,
    )
    if rc == -1 and err == "timeout":
        # No evidence either way -- do not turn "the probe was slow" into
        # "the engine is down" (and every container gone) while a previous
        # real observation exists and the tolerance is not exhausted.
        _timeouts += 1
        if _timeouts < _TIMEOUT_TOLERANCE:
            with _lock:
                prev = _cache["v"]
                if prev is not None and _generation == began:
                    _cache["t"] = time.time()
                    prev_items, prev_engine_up = prev
                    return list(prev_items), prev_engine_up
    else:
        _timeouts = 0
    items, engine_up = [], rc == 0
    extras = configured_signatures() if rc == 0 else []
    rules = configured_group_rules() if rc == 0 else []
    if rc == 0:
        for line in out.splitlines():
            # maxsplit=4: the last field is a Docker *label*, which is an
            # arbitrary string.  A plain split() turned a label containing a tab
            # into extra fields, and the unpack below then raised ValueError --
            # uncaught, straight out of discover_containers() and into
            # /api/status, so one crafted `docker run --label` broke the
            # dashboard for everyone.  Capping the split keeps any extra tabs
            # inside the project field where they are harmless.
            p = line.split("\t", 4)
            if len(p) < 5:
                continue
            name, st, status, image, project = p
            ov = resolve_value(override(name))
            if not isinstance(ov, dict):
                ov = {}
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
            sig = identify(image=image, extras=extras)
            if sig and sig.get("confidence") != "high":
                sig = None
            display = ov.get("name") or name
            if sig and not ov.get("name") and _aligned_container_name(name, image, sig):
                display = sig["name"]
            group = ov.get("group")
            if not group:
                if project:
                    fallback = f"Containers · {project}"
                elif sig:
                    fallback = sig["category"]
                else:
                    fallback = "Containers · other"
                group = resolve_group(
                    {
                        "id": name,
                        "compose_project": project,
                        "image": image,
                    },
                    fallback=fallback,
                    rules=rules,
                )
            item = {
                "id": name,
                "kind": "container",
                "name": display,
                "state": state,
                "detail": status,
                "url": ov.get("url"),
                "group": group,
                "actions": acts,
                "compose_project": project or None,
                "image": image or None,
            }
            if sig:
                item["signature"] = sig
                item.setdefault("meta", {})["signature"] = sig
            items.append(item)
    with _lock:
        if _generation == began:
            _cache.update(t=time.time(), v=(items, engine_up))
    return list(items), engine_up
