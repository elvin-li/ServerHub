"""Hot-reloaded services.yaml + safe writes."""
from __future__ import annotations

import copy
import shutil
import threading
import time
from typing import Any

import yaml

from hub.paths import BASE

_cfg = {"mtime": 0.0, "data": {}}
_write_lock = threading.Lock()
_cfg_lock = threading.RLock()
YAML_PATH = BASE / "services.yaml"
DATA_DIR = BASE / "data"
DATA_DIR.mkdir(exist_ok=True)


#: Minimal config written on first run.  Without this a fresh install raises
#: FileNotFoundError inside cfg() and *every* API route returns 500, because
#: services.yaml was previously expected to already exist on disk.
DEFAULT_CONFIG: dict[str, Any] = {
    "settings": {
        "host_ip": "",
        "metrics_interval": 90,
        "alert_interval": 90,
        "adaptive": True,
        "auth": {"enabled": True, "allow_localhost": False},
        # VM consoles are disabled until an operator maps a UTM VM to a
        # loopback-only VNC listener.  Browser requests never supply endpoints.
        "vm_console": {"allowlist": {}},
        "ui": {"theme": "auto"},
        "thresholds": {
            "enabled": True,
            "cpu_pct": 90,
            "mem_pct": 90,
            "disk_pct": 90,
            "cooldown_sec": 1800,
        },
    },
    "groups_order": [],
    "overrides": {},
    "apps": [],
    "stacks": [],
    "quick_links": [],
    "log_sources": [],
    "maintenance": [],
    "scripts": [],
}


def _bootstrap() -> None:
    """Create services.yaml on first run so a fresh install can boot.

    Prefers services.yaml.example (shipped in the repo) so packagers can adjust
    the starting point without touching code.
    """
    if YAML_PATH.exists():
        return
    example = BASE / "services.yaml.example"
    try:
        if example.exists():
            shutil.copy2(example, YAML_PATH)
        else:
            YAML_PATH.write_text(_dump(copy.deepcopy(DEFAULT_CONFIG)))
        # Holds the admin password hash once setup runs — keep it owner-only.
        YAML_PATH.chmod(0o600)
    except OSError:
        # Read-only install dir: fall through and let cfg() surface the error.
        pass


def cfg():
    with _cfg_lock:
        p = YAML_PATH
        if not p.exists():
            _bootstrap()
        m = p.stat().st_mtime
        if m != _cfg["mtime"]:
            data = yaml.safe_load(p.read_text()) or {}
            # Publish a complete parse atomically; readers never see half-loaded data.
            _cfg["data"] = data
            _cfg["mtime"] = m
        return _cfg["data"]


def override(sid):
    return (cfg().get("overrides") or {}).get(sid, {})


def set_override(sid: str, patch: dict) -> dict:
    """Merge patch into overrides[sid] and persist services.yaml."""
    if not sid:
        raise ValueError("sid required")
    data = copy.deepcopy(cfg())
    ov = data.setdefault("overrides", {})
    cur = dict(ov.get(sid) or {})
    for k, v in (patch or {}).items():
        if v is None:
            cur.pop(k, None)
        else:
            cur[k] = v
    ov[sid] = cur
    save_full(data)
    return cur


def reload_cfg():
    with _cfg_lock:
        _cfg["mtime"] = 0
        return cfg()


def _dump(data: dict) -> str:
    return yaml.dump(
        data,
        allow_unicode=True,
        sort_keys=False,
        width=120,
        default_flow_style=False,
    )


def save_full(data: dict) -> None:
    """Atomically rewrite services.yaml (with timestamped backup)."""
    with _write_lock:
        if YAML_PATH.exists():
            bak = DATA_DIR / f"services.yaml.bak.{int(time.time())}"
            shutil.copy2(YAML_PATH, bak)
            # Keep fewer YAML backups to cut SSD churn on settings saves
            baks = sorted(DATA_DIR.glob("services.yaml.bak.*"), reverse=True)
            for old in baks[5:]:
                try:
                    old.unlink()
                except OSError:
                    pass
        tmp = YAML_PATH.with_suffix(".yaml.tmp")
        tmp.write_text(_dump(data))
        tmp.chmod(0o600)
        tmp.replace(YAML_PATH)
        reload_cfg()


def deep_merge(base: dict, patch: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in patch.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def update_settings(patch: dict[str, Any]) -> dict:
    """Merge into settings key and return new settings."""
    data = copy.deepcopy(cfg())
    cur = data.get("settings") or {}
    data["settings"] = deep_merge(cur, patch)
    save_full(data)
    return data["settings"]


def update_section(section: str, value: Any) -> None:
    data = copy.deepcopy(cfg())
    data[section] = value
    save_full(data)
