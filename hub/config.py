"""Hot-reloaded services.yaml + safe writes."""
from __future__ import annotations

import copy
import fcntl
import os
import stat
import threading
import time
from contextlib import contextmanager
from typing import Any

import yaml

from hub import secure_io
from hub.errors import api_error
from hub.paths import BASE, CONFIG_FILE, DATA_DIR, ensure_state_dirs
from hub.util import read_text_capped

_cfg = {"mtime": 0.0, "data": {}}
_write_lock = threading.Lock()
_cfg_lock = threading.RLock()
YAML_PATH = CONFIG_FILE
ensure_state_dirs()

#: Leftover multi-MB services.yaml used to OOM every cfg() request.
_YAML_CAP = 1024 * 1024

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


def _drop_leftover_nonfile(path, *, keep_symlink: bool = False) -> None:
    """Unlink a leftover directory/socket occupying services.yaml or its lock."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError:
        return
    if stat.S_ISREG(st.st_mode):
        return
    if keep_symlink and stat.S_ISLNK(st.st_mode):
        return
    try:
        if stat.S_ISDIR(st.st_mode):
            os.rmdir(path)
        else:
            os.unlink(path)
    except OSError:
        pass


def _lock_fd() -> int | None:
    """flock fd, or None when a leftover node / EIO blocks creating it."""
    try:
        _LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
        try:
            st = os.lstat(_LOCK_PATH)
        except FileNotFoundError:
            st = None
        if st is not None and not stat.S_ISREG(st.st_mode):
            try:
                if stat.S_ISDIR(st.st_mode):
                    os.rmdir(_LOCK_PATH)
                else:
                    os.unlink(_LOCK_PATH)
            except OSError:
                return None
        return os.open(_LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError:
        return None


@contextmanager
def _file_lock():
    """Hold an exclusive flock across every process writing services.yaml.

    A leftover directory named ``.services.yaml.lock``, or EIO creating it,
    must not 500 PUT /api/settings — fall back to the in-process write lock.

    Taking (or releasing) the flock gets the same degrade as creating it:
    EIO/ENOLCK out of ``fcntl.flock`` on a dying mount under data/ used to
    raise raw OSError out of every mutate() — POST /api/storage/pool/save
    and /clear answered a bare 500 after validation had already passed,
    while the identical failure one syscall earlier (``os.open``) already
    fell back cleanly.
    """
    fd = _lock_fd()
    if fd is None:
        yield
        return
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except OSError:
            yield
            return
        try:
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


#: Top-level keys every route indexes with ``.get`` / ``.items``.  A hand-edit
#: or torn write leaving ``settings: []`` used to 500 the lifespan (metrics
#: interval) and every page that did ``(cfg().get("settings") or {}).get(...)``.
_MAP_KEYS = ("settings", "overrides")
_LIST_KEYS = (
    "apps", "stacks", "quick_links", "log_sources",
    "maintenance", "scripts", "groups_order", "schedules",
    "group_rules",
)


class _CappedIntSafeLoader(yaml.SafeLoader):
    """SafeLoader whose int constructor survives CPython's digit cap."""


def _construct_yaml_int_capped(loader, node):
    try:
        return loader.construct_yaml_int(node)
    except ValueError:
        # Past CPython's 4300-digit int(str) cap the scalar can neither
        # become an int nor ever be re-rendered; load it as None — the same
        # drop docker_cli.parse_int_capped applies to JSON journals — so one
        # poisoned scalar no longer costs the document it sits in.
        return None


_CappedIntSafeLoader.add_constructor(
    "tag:yaml.org,2002:int", _construct_yaml_int_capped,
)


def load_yaml_int_capped(text):
    """``yaml.safe_load`` that survives a >4300-digit decimal int scalar.

    PyYAML builds decimal ints with ``int(str)``, so one over-cap scalar
    raises *bare ValueError* — not YAMLError — out of ``safe_load``.  The
    corrupt-document fallback in :func:`_read_disk` then answered ``{}``
    for the WHOLE config: the admin account read as "setup required", and
    the next :func:`mutate` (PUT /api/settings, a notify/override save)
    rewrote services.yaml from that ``{}`` — persisting the wipe of every
    sibling key.  Retry with a loader whose int constructor drops the
    unrenderable scalar to None; everything genuinely unparseable
    (``!!timestamp .inf``, ``2026-13-01``, ``!!bool 2``, 12k-deep nests)
    still raises to the caller's existing fallback.
    """
    try:
        return yaml.safe_load(text)
    except ValueError as exc:
        if isinstance(exc, UnicodeDecodeError):
            raise
        # May re-raise ValueError for non-digit-cap corruption (a bad
        # ``2026-13-01`` date): the caller's corrupt-document path applies.
        return yaml.load(text, Loader=_CappedIntSafeLoader)


def _as_config(data) -> dict:
    """YAML that is not a mapping cannot answer ``.get`` and 500s every route."""
    if not isinstance(data, dict):
        return {}
    patch = {}
    for key in _MAP_KEYS:
        if key in data and not isinstance(data[key], dict):
            patch[key] = {}
    for key in _LIST_KEYS:
        if key not in data:
            continue
        raw = data[key]
        if not isinstance(raw, list):
            patch[key] = []
        elif key != "groups_order":
            cleaned = [x for x in raw if isinstance(x, dict)]
            if cleaned != raw:
                patch[key] = cleaned
    if not patch:
        return data
    out = dict(data)
    out.update(patch)
    return out


def _read_disk() -> dict:
    """Parse services.yaml straight from disk, bypassing the mtime cache.

    Reader shape: anything unreadable or unparseable degrades to ``{}`` so a
    page can still render defaults.  :func:`mutate` must NOT use this — its
    write-back would persist that ``{}`` as the new config — it reads through
    :func:`_read_disk_for_mutate`, which refuses instead.
    """
    try:
        return _as_config(
            load_yaml_int_capped(read_text_capped(YAML_PATH, _YAML_CAP)) or {}
        )
    except (
        OSError, UnicodeDecodeError, yaml.YAMLError, RecursionError,
        TypeError, ValueError, AttributeError, KeyError,
    ):
        # UnicodeDecodeError is a ValueError, not an OSError or YAMLError: a
        # torn write after power loss used to raise out of mutate()/cfg() and
        # 500 every route that touches settings.  RecursionError is leftover
        # deeply nested YAML — not YAMLError.  TypeError/ValueError/AttributeError
        # /KeyError: leftover ``!!timestamp .inf``, ``2026-13-01`` or ``!!bool 2``
        # are not YAMLError.  A >4300-digit decimal int no longer lands here:
        # load_yaml_int_capped drops that one scalar so a mutate() on this
        # snapshot cannot wipe every sibling key from services.yaml.
        return {}


def _read_disk_for_mutate() -> dict:
    """The read side of :func:`mutate`: refuse rather than wipe.

    :func:`_read_disk`'s corrupt-document ``{}`` is the right shape for
    *readers* — a route that cannot parse the file can still render defaults.
    Under :func:`mutate` that same ``{}`` became the snapshot the mutator
    patched and :func:`_save_full_locked` wrote back: a services.yaml that
    was merely *unreadable* (grown past the 1MB read cap by a hand edit or a
    restored ``services.yaml.bak.*``, torn to non-UTF-8 bytes by power loss,
    over-deep, genuinely unparseable, or replaced whole by a stray paste)
    was silently rewritten as ``{}``-plus-patch with an HTTP 200 — the admin
    account, apps, stacks and bookmarks all gone.  Worse, for the oversize
    case even the pre-save backup was skipped (``copy_secret_file`` reads
    capped and its OSError is deliberately swallowed), so that wipe had no
    pre-image to recover from.  Refuse with the coded 503 instead; the file
    the operator could still fix stays byte-identical on disk.

    A *missing* file stays writable — first-run setup creates the config
    through this path — and an empty or comments-only file parses to ``{}``
    legitimately.  A leftover non-file node (directory/FIFO squatting the
    path) also proceeds: it holds no YAML to lose, and
    :func:`_save_full_locked` already knows how to clear it.
    """
    try:
        regular = stat.S_ISREG(os.stat(YAML_PATH).st_mode)
    except (OSError, ValueError):
        # Missing, dangling symlink, or a name the filesystem cannot even
        # represent (UnicodeEncodeError is a ValueError): nothing readable
        # sits there, so there is nothing this save could destroy.
        regular = False
    if not regular:
        return {}
    try:
        text = read_text_capped(YAML_PATH, _YAML_CAP)
    except FileNotFoundError:
        # Vanished between the stat and the read: same as missing.
        return {}
    except (OSError, UnicodeDecodeError):
        raise api_error("settings.config_unreadable")
    try:
        data = load_yaml_int_capped(text) or {}
    except (
        UnicodeDecodeError, yaml.YAMLError, RecursionError,
        TypeError, ValueError, AttributeError, KeyError,
    ):
        raise api_error("settings.config_unreadable")
    if not isinstance(data, dict):
        # A whole-document paste (a compose file, a bare list) is content the
        # operator can still rescue by hand; overwriting it with settings
        # would not be.
        raise api_error("settings.config_unreadable")
    return _as_config(data)


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
            # Leftover multi-MB / non-UTF-8 example used to OOM or
            # UnicodeDecodeError out of cfg() on first boot (decode is
            # ValueError, not OSError).
            body = read_text_capped(example, _YAML_CAP)
        except (OSError, UnicodeDecodeError):
            body = _dump(copy.deepcopy(DEFAULT_CONFIG))
        secure_io.create_secret_text(YAML_PATH, body)
    except OSError:
        # Read-only install dir: fall through and let cfg() surface the error.
        pass


def cfg():
    with _cfg_lock:
        p = YAML_PATH
        # Path.exists() only swallows ENOENT/ELOOP.  EIO/ESTALE on a dying
        # mount used to raise out of the unguarded lifespan ``cfg()`` call
        # and abort the LaunchAgent before uvicorn bound the port.
        try:
            missing = not p.exists()
        except OSError:
            missing = False
        if missing:
            _bootstrap()
        try:
            m = p.stat().st_mtime
        except OSError:
            return _cfg["data"]
        if m != _cfg["mtime"]:
            try:
                data = _as_config(
                    load_yaml_int_capped(read_text_capped(p, _YAML_CAP)) or {}
                )
            except (
                OSError, UnicodeDecodeError, yaml.YAMLError, RecursionError,
                TypeError, ValueError, AttributeError, KeyError,
            ):
                data = {}
            # Publish a complete parse atomically; readers never see half-loaded data.
            _cfg["data"] = data
            _cfg["mtime"] = m
        return _cfg["data"]


def settings_section(name: str) -> dict:
    """``settings.<name>`` as a mapping, or ``{}`` if missing or the wrong type.

    Nested sections (``notify``, ``files``, ``wireguard``, ``thresholds``,
    ``maintenance_env``) are not covered by :func:`_as_config`.  A hand-edit
    like ``notify: []`` used to 500 the alerter, Settings, file manager, and
    every job that merged ``maintenance_env``.
    """
    # ``dict.get(...)``, not ``s.get(...)``: ``cfg()`` normally returns a plain
    # dict, but a leftover whose ``settings`` map (or the config root) is a
    # dict *subclass* with a bombing ``.get`` used to raise straight out of
    # this hot helper — and every route that reads a nested section
    # (ip_aliases/notify/thresholds/terminal/ollama…) inherited the 500 unless
    # it happened to wrap the call.  The unbound builtin reads the C-level
    # storage, bypassing the override at no copy cost; the returned section is
    # laundered with ``dict(...)`` so the caller's own ``.get`` is safe too.
    data = cfg()
    if not isinstance(data, dict):
        return {}
    s = dict.get(data, "settings")
    if not isinstance(s, dict):
        return {}
    raw = dict.get(s, name)
    if not isinstance(raw, dict):
        return {}
    try:
        return dict(raw)
    except Exception:
        return {}


def _env_text(value) -> str:
    """subprocess env keys/values. Leftover ``str()`` RecursionError / ``\\ud800``
    used to 500 POST backups and maintenance jobs (Popen UTF-8 argv/env).

    Unbound base-type calls only (``bytes.decode`` / ``str.encode``, the
    audit._utf8_text convention): a leftover subclass overriding ``decode``
    or ``encode`` to raise used to blow this scrub from inside every job
    thread that merges ``maintenance_env`` — the container-update runner
    died *before* its try block and left its row running forever — instead
    of degrading that one entry.
    """
    if isinstance(value, (bytes, bytearray)):
        base = bytes if isinstance(value, bytes) else bytearray
        try:
            value = base.decode(value, "utf-8", "replace")
        except Exception:
            return ""
    elif value is None:
        return ""
    elif not isinstance(value, str):
        try:
            value = str(value)
        except RecursionError:
            try:
                return type(value).__name__
            except Exception:
                return ""
        except Exception:
            return ""
    try:
        return str.encode(value, "utf-8", "replace").decode("utf-8")
    except Exception:
        return ""


def maintenance_env() -> dict:
    """Extra env for backups / scheduled jobs / container updates."""
    out = {}
    for k, v in settings_section("maintenance_env").items():
        key = _env_text(k)
        if key:
            out[key] = _env_text(v)
    return out


def override(sid):
    # dict.get, not .get: a leftover cfg() whose root / overrides map is a
    # dict subclass with a bombing .get must not raise out of this reader
    # (services and bookmarks call it per row); the returned override is
    # laundered so the caller's own .get is safe too.
    data = cfg()
    if not isinstance(data, dict):
        return {}
    ov = dict.get(data, "overrides")
    if not isinstance(ov, dict):
        return {}
    val = dict.get(ov, sid, {})
    if not isinstance(val, dict):
        return {}
    try:
        return dict(val)
    except Exception:
        return {}


def set_override(sid: str, patch: dict) -> dict:
    """Merge patch into overrides[sid] and persist services.yaml."""
    if not sid:
        raise ValueError("sid required")
    result: dict = {}

    def apply(data: dict) -> None:
        ov = data.get("overrides")
        if not isinstance(ov, dict):
            ov = {}
            data["overrides"] = ov
        cur = ov.get(sid)
        cur = dict(cur) if isinstance(cur, dict) else {}
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
        ov = data.get("overrides")
        if isinstance(ov, dict):
            ov.pop(sid, None)

    mutate(apply)


def reload_cfg():
    with _cfg_lock:
        _cfg["mtime"] = 0
        return cfg()


#: Sentinel: a node yaml.safe_dump cannot render (over-cap int); the entry is
#: dropped rather than failing the whole save.
_UNRENDERABLE = object()


def _renderable_tree(value, depth: int = 0):
    """Drop over-cap ints so one leftover cannot wedge every save forever.

    A ``str()`` probe, not an isinstance-str gate: the poison is an
    *already-parsed* int (YAML hex/octal loads through ``int(x, 16)``, which
    CPython's 4300-digit cap does not bound), and it can sit in a value, a
    mapping key, a list item or a ``!!set`` member.  Everything else --
    surrogate strings, dates, normal ints -- passes through untouched.
    """
    if depth > 64:
        return value
    if isinstance(value, bool) or not isinstance(
        value, (int, dict, list, tuple, set, frozenset)
    ):
        return value
    if isinstance(value, int):
        try:
            str(value)
        except ValueError:
            return _UNRENDERABLE
        return value
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            k2 = _renderable_tree(k, depth + 1)
            if k2 is _UNRENDERABLE:
                continue
            v2 = _renderable_tree(v, depth + 1)
            if v2 is _UNRENDERABLE:
                continue
            out[k2] = v2
        return out
    if isinstance(value, (set, frozenset)):
        cleaned = (_renderable_tree(v, depth + 1) for v in value)
        return {v for v in cleaned if v is not _UNRENDERABLE}
    cleaned = [_renderable_tree(v, depth + 1) for v in value]
    return [v for v in cleaned if v is not _UNRENDERABLE]


def _dump(data: dict) -> str:
    # SafeDumper, not Dumper: a leftover tuple in a hand-built patch used to
    # emit ``!!python/tuple`` into services.yaml.  The next yaml.safe_load then
    # ConstructorError'd and cfg() returned {}, wiping the admin account from
    # the in-process view; Dumper is also the representer that would write a
    # real ``!!python/object`` if any non-plain type ever landed in the dict.
    try:
        return yaml.safe_dump(
            data,
            allow_unicode=True,
            sort_keys=False,
            width=120,
            default_flow_style=False,
        )
    except RecursionError:
        # Leftover deeply nested services.yaml used to RecursionError PUT /api/settings.
        raise api_error("settings.save_failed")
    except ValueError:
        # A leftover YAML hex int past CPython's int->str digit cap loads fine
        # (``int(x, 16)`` is uncapped) but cannot be re-dumped.  The coded 503
        # alone left every settings save stuck for good: the auth sweep scrubs
        # its own block, but a huge leftover *outside* it (a stray settings
        # key, a stack port) rode through every mutate() and PUT /api/settings,
        # PUT /api/identity, alias/notify saves all 503'd until services.yaml
        # was hand-edited.  Retry once with only the unrenderable nodes
        # dropped -- the value cannot be persisted either way; losing the rest
        # of the save with it bought nothing.
        try:
            return yaml.safe_dump(
                _renderable_tree(data),
                allow_unicode=True,
                sort_keys=False,
                width=120,
                default_flow_style=False,
            )
        except (ValueError, RecursionError, yaml.YAMLError):
            raise api_error("settings.save_failed")


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
    # A leftover empty directory occupying services.yaml used to
    # IsADirectoryError copy_secret_file / replace and 500 every settings save.
    _drop_leftover_nonfile(YAML_PATH, keep_symlink=True)
    try:
        is_file = YAML_PATH.is_file()
    except OSError:
        is_file = False
    if is_file:
        # Nanoseconds, not seconds: two save_full() calls in the same second
        # used to overwrite one backup and silently shrink the recovery window.
        # Under the write lock a collision is still possible on a very fast
        # host, so step the suffix until the name is free.
        suffix = time.time_ns()
        bak = DATA_DIR / f"services.yaml.bak.{suffix}"
        while True:
            try:
                taken = bak.exists()
            except OSError:
                # Dying FUSE/SMB: exists() re-raises EIO/ESTALE and used to
                # 500 PUT /api/settings.  Treat as a free name so the save
                # can still land; copy_secret_file already swallows OSError.
                taken = False
            if not taken:
                break
            suffix += 1
            bak = DATA_DIR / f"services.yaml.bak.{suffix}"
        # Not shutil.copy2: it creates the destination at the umask and
        # copies the mode afterwards, so a verbatim copy of the admin
        # password hash and every service credential sits at 0644 for the
        # length of the copy.  The backup is exactly as sensitive as the
        # original, so it is 0600 from its first byte.
        try:
            secure_io.copy_secret_file(YAML_PATH, bak, max_bytes=_YAML_CAP)
        except OSError:
            # Dying FUSE / leftover node: skip the pre-image rather than
            # 500 PUT /api/settings while the new file can still be written.
            pass
        else:
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
            #
            # The scandir under glob() re-raises EIO/ESTALE on a dying data/
            # mount.  The pre-image copy just landed and the new config is
            # about to be written — losing the *retention trim* is
            # housekeeping, but the raw OSError used to 500 the save that had
            # otherwise succeeded (POST /api/storage/pool/save was the found
            # route; every mutate() shares this path).
            try:
                baks = sorted(DATA_DIR.glob("services.yaml.bak.*"), reverse=True)
            except OSError:
                baks = []
            for old in baks[BACKUP_RETENTION:]:
                try:
                    old.unlink()
                except OSError:
                    pass
    text = _dump(data)
    if len(text) > _YAML_CAP:
        # A config larger than the read cap can never be loaded back: every
        # later cfg()/_read_disk() would answer {} — the admin account and
        # every sibling setting gone from the panel's view — and the next
        # mutate() would persist that wipe from the empty snapshot.  One
        # unbounded notify-channel value used to do exactly this with a
        # single 200 response.  Refusing the save keeps the on-disk file
        # (and everything in it) intact; read_text_capped compares
        # characters, so len() is the right unit.
        raise api_error("settings.save_failed")
    # services.yaml carries service credentials, tunnel tokens and admin
    # passwords.  The previous write_text()+chmod() left the staging file
    # world-readable at the default umask for the whole duration of the
    # write, which is exactly the window hub.secure_io exists to close: the
    # file is now 0600 from the moment it first exists.  The replace stays
    # atomic, so a reader never observes a half-written config.
    try:
        secure_io.replace_secret_text(YAML_PATH, text)
    except OSError:
        # Leftover nonempty directory / EIO replacing the file must not 500.
        raise api_error("settings.save_failed")
    reload_cfg()


def mutate(mutator) -> dict:
    """Apply *mutator* to the stored config under the cross-process write lock.

    ``mutator(data)`` receives the config as it exists on disk *right now* and
    mutates it in place. This is the safe way to change one key: the read and the
    write happen inside one lock, so a concurrent ServerHub cannot interleave and
    lose the change (or have its own change lost). Returns the written config.

    Raises the coded 503 ``settings.config_unreadable`` when services.yaml
    exists but cannot be read back (oversize, torn, unparseable): patching a
    ``{}`` fallback snapshot and writing it out used to *persist* the wipe of
    every sibling key with an HTTP 200 — see :func:`_read_disk_for_mutate`.
    """
    with _write_lock, _file_lock():
        data = _read_disk_for_mutate()
        mutator(data)
        _save_full_locked(data)
        return data


def deep_merge(base: dict, patch: dict, _merging: frozenset = frozenset()) -> dict:
    """Merge *patch* onto a deep copy of *base*, dict-by-dict.

    Cycle-guarded by identity along the current merge path: a recursive YAML
    anchor (``ip_aliases: &a {self: *a}``) survives ``yaml.safe_load`` and
    ``settings_section``, so a handler that copies its stored section and
    writes it back through :func:`update_settings` hands this function a
    patch that contains itself.  The recursion then never terminated —
    ``copy.deepcopy`` is memo'd against cycles, but this walk was not — and
    PUT /api/system/network/alias/auto answered a RecursionError 500 instead
    of saving.  On re-entering a dict already being merged the base copy wins
    unchanged (there is nothing new underneath: it is the same mapping).  The
    guard is per-path, not global, so a non-cyclic alias reused by two
    sibling keys still merges into both.
    """
    out = copy.deepcopy(base)
    if id(patch) in _merging:
        return out
    _merging = _merging | {id(patch)}
    for k, v in patch.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v, _merging)
        else:
            out[k] = v
    return out


#: Panel / menu-bar UI languages.  Must stay in lockstep with web/src/i18n
#: and macos/ServerHubLauncher.swift.
UI_LOCALES = ("zh-CN", "en", "ja")
DEFAULT_UI_LOCALE = "zh-CN"


def panel_locale() -> str:
    """Locale the web panel last saved, defaulting like GET /api/settings.

    The native menu-bar client follows this rather than macOS
    ``AppleLanguages``: this host's preferred list is ``en-CN`` then
    ``zh-Hans-CN``, so a first-match would keep the menu in English while
    the panel is zh-CN.
    """
    # dict.get, not .get: a leftover cfg() root / settings map that is a dict
    # subclass with a bombing .get must not 500 the menu-bar locale probe
    # (GET /api/status reads this on a cold cache).
    data = cfg()
    settings = dict.get(data, "settings") if isinstance(data, dict) else None
    ui = dict.get(settings, "ui") if isinstance(settings, dict) else None
    ui = ui if isinstance(ui, dict) else {}
    try:
        _locale_raw = dict.get(ui, "locale")
        # Guarded str(), not a bare one: a hand-edited YAML hex/octal locale
        # (``locale: 0xF…``) parses uncapped through ``int(x, 16)`` and the
        # bare ``str()`` raised CPython's 4300-digit ValueError here.  That
        # 500'd GET /api/status forever on a cold cache (_build_status has no
        # last-good snapshot to fall back to on first boot) and the member
        # status/services filters the same way.  A numeric YAML ``locale:
        # 2023`` still coerces and falls through to the default below.
        raw = str(_locale_raw or DEFAULT_UI_LOCALE).strip()
    except ValueError:
        return DEFAULT_UI_LOCALE
    if raw in UI_LOCALES:
        return raw
    low = raw.lower()
    if low.startswith("zh"):
        return "zh-CN"
    if low.startswith("ja"):
        return "ja"
    if low.startswith("en"):
        return "en"
    return DEFAULT_UI_LOCALE


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
