"""Single source for `brew services list --json`.

That command costs ~1.25s.  Four modules needed it (brew_svc, autostart_svc,
health_svc, native_catalog) and each shelled out on its own, so one
`/api/apps/managed` request paid for it eight times — 10 of the endpoint's 12
seconds.  This caches the parsed result behind a short TTL and collapses
concurrent callers into a single invocation.
"""
from __future__ import annotations

import json
import threading
import time
from typing import Any

from hub.paths import BREW
from hub.util import sh

#: Service state changes only on user action, and every caller in a single
#: request wants the same snapshot.  Short enough that the UI stays truthful.
_TTL = 6.0

_cache: dict[str, Any] = {"t": 0.0, "v": None}
_lock = threading.Lock()
#: Serialises the refresh so N concurrent cold callers run one subprocess.
_refresh_lock = threading.Lock()


def invalidate_brew_services() -> None:
    """Drop the snapshot after a start/stop so the next read is truthful."""
    with _lock:
        _cache["t"] = 0.0
        _cache["v"] = None


def _fresh() -> list[dict] | None:
    with _lock:
        if _cache["v"] is not None and time.time() - _cache["t"] < _TTL:
            # Copy: callers annotate the dicts they get back.
            return [dict(x) for x in _cache["v"]]
    return None


def _load() -> list[dict]:
    rc, out, _ = sh([BREW, "services", "list", "--json"], timeout=20)
    items: list[dict] = []
    if rc == 0 and out.strip():
        try:
            parsed = json.loads(out)
            if isinstance(parsed, list):
                items = [x for x in parsed if isinstance(x, dict)]
        except ValueError:
            items = []
    with _lock:
        _cache.update(t=time.time(), v=items)
    return [dict(x) for x in items]


def brew_services(force: bool = False) -> list[dict]:
    """Parsed `brew services list --json`, cached for a few seconds."""
    if not force:
        hit = _fresh()
        if hit is not None:
            return hit

    with _refresh_lock:
        # A concurrent caller may have refreshed while this one waited; reuse
        # that result rather than paying for a second subprocess.
        hit = _fresh()
        if hit is not None:
            return hit
        return _load()


#: Callers (brew_svc, autostart_svc, health_svc) import this name.  Keep both
#: spellings exported so neither side of the rename can break the panel: a
#: missing symbol here is an ImportError at module load, which takes down every
#: route, not just the one that wanted brew state.
brew_services_list = brew_services


def service_state(name: str) -> str:
    """`status` for one formula, or "" when brew does not know it."""
    for item in brew_services():
        if item.get("name") == name:
            return str(item.get("status") or "")
    return ""
