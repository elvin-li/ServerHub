"""Hot-reloaded services.yaml + safe writes."""
from __future__ import annotations

import copy
import threading
import time
from typing import Any

import yaml

from hub import secure_io
from hub.paths import BASE, CONFIG_FILE, DATA_DIR, ensure_state_dirs

_cfg = {"mtime": 0.0, "data": {}}
_write_lock = threading.Lock()
_cfg_lock = threading.RLock()
YAML_PATH = CONFIG_FILE
ensure_state_dirs()


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
        # This file holds the admin password hash the moment setup runs, plus
        # service credentials and tunnel tokens thereafter.  Neither branch may
        # create it and tighten it afterwards: shutil.copy2 *copies the example's
        # mode*, which is world-readable in the repo, and write_text() lands at
        # the umask default.  Both left a window where any local user could read
        # the config, so both now go through the helper that creates the file
        # 0600 from its first byte.
        body = (
            example.read_text(encoding="utf-8")
            if example.exists()
            else _dump(copy.deepcopy(DEFAULT_CONFIG))
        )
        secure_io.write_secret_text(YAML_PATH, body)
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
            # Not shutil.copy2: it creates the destination at the umask and
            # copies the mode afterwards, so a verbatim copy of the admin
            # password hash and every service credential sits at 0644 for the
            # length of the copy.  The backup is exactly as sensitive as the
            # original, so it is 0600 from its first byte.
            secure_io.copy_secret_file(YAML_PATH, bak)
            # Keep fewer YAML backups to cut SSD churn on settings saves
            baks = sorted(DATA_DIR.glob("services.yaml.bak.*"), reverse=True)
            for old in baks[5:]:
                try:
                    old.unlink()
                except OSError:
                    pass
        # services.yaml carries service credentials, tunnel tokens and admin
        # passwords.  The previous write_text()+chmod() left the staging file
        # world-readable at the default umask for the whole duration of the
        # write, which is exactly the window hub.secure_io exists to close: the
        # file is now 0600 from the moment it first exists.  The replace stays
        # atomic, so a reader never observes a half-written config.
        secure_io.replace_secret_text(YAML_PATH, _dump(data))
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
