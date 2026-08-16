"""Hot-reloaded services.yaml + safe writes."""
from __future__ import annotations

import copy
import fcntl
import os
import threading
import time
from contextlib import contextmanager
from typing import Any

import yaml

from hub import secure_io
from hub.paths import BASE, CONFIG_FILE, DATA_DIR, ensure_state_dirs

_cfg = {"mtime": 0.0, "data": {}}
_write_lock = threading.Lock()
_cfg_lock = threading.RLock()
YAML_PATH = CONFIG_FILE
ensure_state_dirs()

#: Cross-process write lock for services.yaml.
#:
#: ``_write_lock`` is a threading.Lock, so it only serialises writers inside one
#: interpreter. More than one ServerHub can share this file at once -- the
#: LaunchAgent panel and the packaged ServerHub.app both load hub.config -- and
#: because every writer rewrites the file whole from an in-memory snapshot, the
#: second writer silently reverted the first. Observed in practice: the
#: administrator's username and password_hash disappeared from settings.auth
#: repeatedly, flipping back and forth as the two instances took turns, which
#: put the panel into "setup required" with the credentials gone.
#:
#: A separate lock file is used rather than locking services.yaml itself so the
#: lock survives the atomic replace (which swaps in a new inode).
_LOCK_PATH = DATA_DIR / ".services.yaml.lock"

#: How many services.yaml pre-images to keep. See the retention note in
#: :func:`_save_full_locked` for why this is not a small number.
BACKUP_RETENTION = 30


@contextmanager
def _file_lock():
    """Hold an exclusive flock across every process writing services.yaml."""
    fd = os.open(_LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _read_disk() -> dict:
    """Parse services.yaml straight from disk, bypassing the mtime cache.

    Used inside the write lock so a mutation merges onto what is actually stored
    now, not onto a snapshot this process may have taken minutes ago.
    """
    try:
        return yaml.safe_load(YAML_PATH.read_text()) or {}
    except FileNotFoundError:
        return {}


#: Minimal config written on first run.  Without this a fresh install raises
#: FileNotFoundError inside cfg() and *every* API route returns 500, because
#: services.yaml was previously expected to already exist on disk.
DEFAULT_CONFIG: dict[str, Any] = {
    "settings": {
        "host_ip": "",
        "metrics_interval": 90,
        "alert_interval": 90,
        "resource_mode": "low",
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
    example = BASE / "services.yaml.example"
    try:
        # This file holds the admin password hash the moment setup runs, plus
        # service credentials and tunnel tokens thereafter.  Neither branch may
        # create it and tighten it afterwards: shutil.copy2 *copies the example's
        # mode*, which is world-readable in the repo, and write_text() lands at
        # the umask default.  Both left a window where any local user could read
        # the config, so both now go through a helper that creates the file 0600
        # from its first byte.
        #
        # The creation is EXCLUSIVE, and this function no longer checks exists()
        # first.  Bootstrapping used to be "if the file is missing, write the
        # defaults", which destroys the installation the moment anything makes
        # exists() answer False about a file that is really there.  That is not
        # hypothetical: a test patching pathlib.Path.exists process-wide reduced a
        # populated services.yaml to 407 bytes of defaults on every run, taking
        # the admin account, both apps, three stacks and twelve bookmarks with it.
        # With O_EXCL the kernel decides, and a wrong guess is a no-op.
        try:
            body = example.read_text(encoding="utf-8")
        except OSError:
            body = _dump(copy.deepcopy(DEFAULT_CONFIG))
        secure_io.create_secret_text(YAML_PATH, body)
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
    result: dict = {}

    def apply(data: dict) -> None:
        ov = data.setdefault("overrides", {})
        cur = dict(ov.get(sid) or {})
        for k, v in (patch or {}).items():
            if v is None:
                cur.pop(k, None)
            else:
                cur[k] = v
        ov[sid] = cur
        result.update(cur)

    mutate(apply)
    return result


def drop_override(sid: str) -> None:
    """Remove overrides[sid] so an uninstalled agent does not linger as a ghost."""
    if not sid:
        return

    def apply(data: dict) -> None:
        (data.get("overrides") or {}).pop(sid, None)

    mutate(apply)


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
    """Atomically rewrite services.yaml (with timestamped backup).

    Callers that build *data* from an earlier ``cfg()`` snapshot should prefer
    :func:`mutate`, which re-reads the file under the same lock; passing a stale
    snapshot here still overwrites concurrent changes made by another process.
    """
    with _write_lock, _file_lock():
        _save_full_locked(data)


def _save_full_locked(data: dict) -> None:
    """Body of :func:`save_full`; assumes both write locks are held."""
    if YAML_PATH.exists():
        # Nanoseconds, not seconds: two save_full() calls in the same second
        # used to overwrite one backup and silently shrink the recovery window.
        # Under the write lock a collision is still possible on a very fast
        # host, so step the suffix until the name is free.
        suffix = time.time_ns()
        bak = DATA_DIR / f"services.yaml.bak.{suffix}"
        while bak.exists():
            suffix += 1
            bak = DATA_DIR / f"services.yaml.bak.{suffix}"
        # Not shutil.copy2: it creates the destination at the umask and
        # copies the mode afterwards, so a verbatim copy of the admin
        # password hash and every service credential sits at 0644 for the
        # length of the copy.  The backup is exactly as sensitive as the
        # original, so it is 0600 from its first byte.
        secure_io.copy_secret_file(YAML_PATH, bak)
        # Retention is a recovery window, not just churn control. At 5 copies a
        # burst of writes rotates the whole history within minutes: the admin
        # username and password_hash were once lost from services.yaml and by the
        # time it was noticed every one of the 5 pre-images had already rotated
        # past the point where the credential still existed, leaving a months-old
        # archive as the only source. These files are a few KB, so a deeper
        # window costs almost nothing next to being unable to recover at all.
        #
        # Sorted by name, which is sound because the suffix is a fixed-width
        # epoch: lexicographic and numeric order coincide.
        baks = sorted(DATA_DIR.glob("services.yaml.bak.*"), reverse=True)
        for old in baks[BACKUP_RETENTION:]:
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


def mutate(mutator) -> dict:
    """Apply *mutator* to the stored config under the cross-process write lock.

    ``mutator(data)`` receives the config as it exists on disk *right now* and
    mutates it in place. This is the safe way to change one key: the read and the
    write happen inside one lock, so a concurrent ServerHub cannot interleave and
    lose the change (or have its own change lost). Returns the written config.
    """
    with _write_lock, _file_lock():
        data = _read_disk()
        mutator(data)
        _save_full_locked(data)
        return data


def deep_merge(base: dict, patch: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in patch.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def update_settings(patch: dict[str, Any]) -> dict:
    """Merge into settings key and return new settings.

    Merges onto the on-disk config rather than this process's cached snapshot:
    the background alias/SMART timers call this on their own schedule, and with a
    snapshot the merge could carry stale sibling keys back over a change another
    process had already committed.
    """
    def apply(data: dict) -> None:
        data["settings"] = deep_merge(data.get("settings") or {}, patch)

    return mutate(apply)["settings"]
