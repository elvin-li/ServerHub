"""Backup helpers: list artifacts + run common backup jobs."""
from __future__ import annotations

import contextlib
import gzip
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from hub import secure_io
from hub.config import cfg
from hub.errors import CODES, api_error
from hub.paths import CONFIG_FILE, DATA_DIR

BACKUP_ROOT = Path.home() / "Services" / "backups"

#: This host's Immich cluster is PostgreSQL 18 on :5433.  PATH ``pg_dump`` is
#: 17.x and a version-mismatched dump of that database is empty or truncated,
#: which is why the neighbouring ``~/Services/immich/backup-db.sh`` pins the
#: Homebrew @18 binary and writes ``immich_*.sql.gz``.  The Backups page used
#: to expose that job; after postgres targets became configuration only
#: TeslaMate remained on the button.  These paths rediscover the Immich dump
#: without putting its password in services.yaml.
IMMICH_ROOT = Path.home() / "Services" / "immich"
IMMICH_SCRIPT = IMMICH_ROOT / "backup-db.sh"
IMMICH_DB_ENV = IMMICH_ROOT / "db.env"
_PG18_DUMPS = (
    Path("/opt/homebrew/opt/postgresql@18/bin/pg_dump"),
    Path("/usr/local/opt/postgresql@18/bin/pg_dump"),
)
IMMICH_RETAIN = 7
_DUMP_COMPLETE = "PostgreSQL database dump complete"
_IMMICH_TIMEOUT = 600
#: Enough trailing plaintext to hold pg_dump's closing comment.
_DUMP_TAIL_BYTES = 4096
_DUMP_CHUNK = 1 << 20
#: PhotosHub holds the post-2026-08-14 Immich layout (Apple Photos originals,
#: PhotosBridge index, generated media on PhotoVault).  Read-only: the Backups
#: page needs those paths to explain *what* to back up; it must not ``du`` the
#: USB volume on every load.
PHOTOSHUB_CFG = Path.home() / "PhotosHub" / "config" / "config.json"
PHOTOSHUB_STATE = Path.home() / "PhotosHub" / "state"
_GENERATED_DIRS = ("thumbs", "encoded-video", "upload", "library")
# 0700, not the umask default: a config backup contains services.yaml verbatim,
# which holds the admin password hash and any tunnel/API tokens, and a database
# dump contains whatever the database holds.  The originals are 0600, so leaving
# the copies at 0644 in a traversable directory handed every other local account
# the exact secrets the originals protect.
secure_io.make_secret_dir(BACKUP_ROOT)

log = logging.getLogger("serverhub.backups")


#: Name collisions to step past before refusing.  A collision needs two runs in
#: the same second, so more than a handful means something is badly wrong.
_MAX_COLLISIONS = 50

CODES.setdefault(
    "backup.name_taken",
    (500, "could not find a free backup filename beside {path}"),
)
CODES.setdefault(
    "backup.busy",
    (409, "a {job} backup is already running; wait for it to finish"),
)


def _private_dest(base: Path) -> Path:
    """Create an owner-only file at *base*, or at the next free name beside it.

    O_EXCL, not O_TRUNC.  The stamp in a backup name has second resolution, so
    two runs starting within the same second resolved to the same path and the
    second one truncated the first one's output -- then both reported success,
    because success is judged by "a non-empty file is there".  A backup that
    reports success and cannot be restored is worse than no backup at all.

    An in-process lock cannot prevent it: the `backup-pg` and `backup-cfg`
    maintenance tasks shell out to their own python process, so the scheduled run
    and a button press are two processes racing for one filename.  Refusing to
    reuse a name works across processes; a lock does not.  A clock step backwards
    reproduces the same collision with runs minutes apart.

    Overwriting an existing backup is never what the caller wanted, so a taken
    name becomes ``name-2``, ``name-3``, ... .

    0600 because a config archive contains services.yaml verbatim (admin password
    hash, tunnel and API tokens) and a database dump contains whatever the
    database holds.  Created private up front rather than chmod'ed afterwards, so
    the archive is never briefly readable by anyone else.

    Callers must judge success by :func:`_written_bytes` rather than by the file
    existing, because after this it always does -- and must use the returned path,
    not the one they passed in.
    """
    base.parent.mkdir(parents=True, exist_ok=True)
    head, dot, tail = base.name.partition(".")
    for attempt in range(1, _MAX_COLLISIONS + 1):
        candidate = (
            base if attempt == 1 else base.with_name(f"{head}-{attempt}{dot}{tail}")
        )
        try:
            os.close(os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
            return candidate
        except FileExistsError:
            continue
        except OSError:
            # Unwritable directory, read-only volume: let the command that
            # follows fail and be reported the way any other failure is.
            return candidate
    raise api_error("backup.name_taken", path=str(base))


_job_locks_guard = threading.Lock()
_job_locks: dict[str, threading.Lock] = {}


@contextlib.contextmanager
def _only_one(job: str):
    """Refuse a second concurrent run of the same backup job in this process.

    Distinct from the filename guard above, which stops two runs corrupting one
    file.  This stops them happening at all: five clicks on "dump the database"
    used to start five pg_dumps, each reading the whole database and each writing
    its own multi-gigabyte file.  Non-blocking, because the honest answer is "one
    is already running" rather than a request that sits for ten minutes and then
    produces a redundant archive.
    """
    with _job_locks_guard:
        lock = _job_locks.setdefault(job, threading.Lock())
    if not lock.acquire(blocking=False):
        raise api_error("backup.busy", job=job)
    try:
        yield
    finally:
        lock.release()


#: Copies of each job's own artefact to keep.  Nothing pruned these before, and
#: unbounded is a real number here: the TeslaMate dump on this host is 167 MB, so
#: a nightly schedule is ~5 GB a month, forever.  14 matches what the immich
#: backup script next door already keeps, so the two jobs agree.
RETAIN = 14


def _prune(pattern: str, retain: int = RETAIN) -> None:
    """Delete all but the newest *retain* artefacts (default :data:`RETAIN`).

    Job-scoped glob, never a blanket ``*``.  BACKUP_ROOT also holds files this
    module did not write -- other tooling's pre-images, a large manual dump -- and
    a wide glob would delete them.

    Sorting by name rather than mtime is sound because the stamp is a fixed-width
    ``%Y%m%d_%H%M%S``, so lexicographic and chronological order coincide; the same
    reasoning the services.yaml rotation in hub/config.py relies on.

    Called only after a run has been judged successful, so a failing job can never
    rotate away the last good copy.  Removals are logged: a backup disappearing is
    something an operator should be able to account for afterwards.
    """
    retain = max(1, int(retain))
    try:
        found = sorted(BACKUP_ROOT.glob(pattern), reverse=True)
    except OSError:
        return
    for old in found[retain:]:
        try:
            old.unlink()
        except OSError:
            continue
        log.info("pruned old backup (keeping %d): %s", retain, old.name)


def _written_bytes(dest: Path) -> int:
    """Size of a produced archive, or 0 when it is missing or still empty."""
    try:
        return dest.stat().st_size
    except OSError:
        return 0


def _discard(dest: Path) -> None:
    """Remove the pre-created placeholder after a failed run."""
    try:
        dest.unlink()
    except OSError:
        pass


# ── configurable backup targets (services.yaml `backups:`) ───────────────────
#
# The machine-specific parts of the one-click backups used to be hardcoded
# here: the pg_dump connection named one specific TeslaMate database (with a
# literal fallback password), and the config archive carried two compose paths
# from this host's ~/Services.  On any other install those were dead code at
# best and a dump of a database that does not exist at worst.  They are
# configuration now:
#
#   backups:
#     postgres:                 # pg_dump targets, one artefact per entry
#       - id: teslamate         # names the artefact: <id>_<stamp>.sql.bak
#         host: localhost
#         port: 5432            # the default port is omitted from argv
#         db: teslamate
#         user: teslamate       # defaults to db
#         password_env: VAR     # optional, see the password note below
#     config_archive:
#       agent_keywords: [...]   # merged after DEFAULT_AGENT_KEYWORDS
#       extra_paths: [...]      # archived beside services.yaml
#
# Passwords never enter services.yaml: that file is returned verbatim by the
# settings export and archived verbatim by backup_configs, so a password in it
# would leak into every copy.  Following the split notify_channels.py uses
# (non-secret parameters in services.yaml, secrets in a 0600 data/ file), a
# target's password is looked up in data/backup-credentials.json
# (``{"<id>": {"password": "..."}}``), then in the environment variable named
# by ``password_env``, and otherwise left to the ambient environment
# (PGPASSWORD / ~/.pgpass), which is what unconfigured installs relied on.

BACKUP_SECRETS_FILE = DATA_DIR / "backup-credentials.json"

#: Target ids become filenames and prune globs, so the charset is pinned the
#: same way volume names are below: no separators, no wildcards.
_PG_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


def _pg_conninfo_chars(value: str) -> bool:
    """True if *value* could act as a libpq connection string rather than a
    plain host/db/role name (contains whitespace or a ``key=value`` ``=``)."""
    return "=" in value or any(c.isspace() for c in value)


def _backups_cfg() -> dict:
    raw = cfg().get("backups")
    return raw if isinstance(raw, dict) else {}


def _config_archive_cfg() -> dict:
    raw = _backups_cfg().get("config_archive")
    return raw if isinstance(raw, dict) else {}


def pg_targets(raw: list | None = None) -> list[dict]:
    """Validated ``backups.postgres`` entries, in file order.

    Malformed entries are dropped one by one rather than raising: one mistyped
    row must not take the dump of a healthy target (or the whole Backups page)
    down with it.  Defaults follow pg_dump's own: localhost, port 5432, and
    the role named after the database.
    """
    if raw is None:
        raw = _backups_cfg().get("postgres")
    if not isinstance(raw, list):
        return []
    out: list[dict] = []
    seen: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        tid = str(entry.get("id") or "").strip()
        db = str(entry.get("db") or "").strip()
        host = str(entry.get("host") or "").strip() or "localhost"
        user = str(entry.get("user") or "").strip() or db
        port_raw = entry.get("port", 5432)
        try:
            # None/"" mean "unset" and take the default; 0 is a typo, not a port.
            port = int(5432 if port_raw in (None, "") else port_raw)
        except (TypeError, ValueError):
            continue
        if not _PG_ID_RE.fullmatch(tid) or tid in seen or not db:
            continue
        if not 1 <= port <= 65535:
            continue
        # pg_dump's -d/-U/-h accept a full libpq connection string ("host=...
        # dbname=..."), whose keywords override the other flags — a value with
        # whitespace or '=' could redirect this dump (and its resolved
        # PGPASSWORD) to another server.  These are argv, not a shell, so this
        # is connection redirection rather than command injection, but a real
        # database/host/role name never needs those characters, so reject them.
        if any(_pg_conninfo_chars(v) for v in (host, db, user)):
            continue
        seen.add(tid)
        out.append({
            "id": tid,
            "host": host,
            "port": port,
            "db": db,
            "user": user,
            "password_env": str(entry.get("password_env") or "").strip(),
        })
    return out


def _ensure_secret_mode(path: Path) -> None:
    """Tighten a plaintext-secret file to 0600 if it was left group/world
    readable.  DATA_DIR is 0700 so the exposure is already contained, but this
    file holds database passwords and there is no reason for it to carry looser
    bits — matching the 0600-at-creation guarantee the other secret stores make.
    """
    try:
        mode = path.stat().st_mode
    except OSError:
        return
    if mode & 0o077:
        try:
            os.chmod(path, 0o600)
            log.warning("tightened %s from %o to 0600", path.name, mode & 0o777)
        except OSError:
            pass


def _pg_password(target_id: str) -> str:
    """The stored password for one pg target, or "" when none is on file."""
    _ensure_secret_mode(BACKUP_SECRETS_FILE)
    try:
        raw = json.loads(BACKUP_SECRETS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    entry = raw.get(target_id) if isinstance(raw, dict) else None
    if not isinstance(entry, dict):
        return ""
    return str(entry.get("password") or "")


def _pg_dump_argv(target: dict, dest: Path) -> list[str]:
    """The pg_dump invocation for one target.

    Split out so tests (and an operator comparing against an older install)
    can inspect the exact command without running anything.
    """
    argv = ["pg_dump", "-h", target["host"]]
    if target["port"] != 5432:
        # The default port is omitted rather than pinned so PGPORT and
        # ~/.pgpass keep meaning what they meant before this was configurable.
        argv += ["-p", str(target["port"])]
    argv += ["-U", target["user"], "-d", target["db"],
             "-F", "c", "-b", "-f", str(dest)]
    return argv


def _pg_env(target: dict) -> dict:
    """Subprocess environment for one dump: maintenance_env over os.environ,
    plus the target's password resolved per the note above."""
    env = dict(os.environ)
    env.update({
        k: str(v)
        for k, v in ((cfg().get("settings") or {}).get("maintenance_env") or {}).items()
    })
    password = _pg_password(target["id"])
    if not password and target["password_env"]:
        password = str(env.get(target["password_env"]) or "")
    if password:
        env["PGPASSWORD"] = password
    return env


#: How to put each kind of artefact back, keyed by a filename test.
#:
#: A backup nobody knows how to restore is a filesystem full of reassurance.
#: None of these artefacts had a restore path anywhere -- no code, no script,
#: no note -- and the pg dumps actively mislead: `pg_dump -F c` writes a
#: *custom-format* archive, so the `.sql.bak` name points a restorer at
#: `psql`, which cannot read it.  The command belongs next to the file rather
#: than in someone's memory.
#:
#: Hints are commands, deliberately not run by anything here: restoring
#: overwrites live data and is the operator's decision, not a button.  This
#: table holds the fixed hints; hints for configured pg targets are derived
#: from their connection parameters in :func:`restore_hint`.
_RESTORE_HINTS: tuple[tuple[str, str], ...] = (
    (
        "immich_",
        # Plain SQL, gzipped, PG18 on 5433, and it carries CREATE EXTENSION vchord,
        # so it wants an empty database with that extension available.
        "gunzip -c {path} | psql -h localhost -p 5433 -U immich -d immich",
    ),
    (
        "configs_",
        # tar strips the leading "/" from absolute members, so extraction lands in
        # $PWD: unpack somewhere scratch and copy back deliberately.
        "mkdir -p /tmp/restore && tar xzf {path} -C /tmp/restore  "
        "# then copy members back to their absolute paths",
    ),
)


def restore_hint(name: str) -> str:
    """The command that puts *name* back, or "" when this module cannot say.

    Matched on the filename so it also answers for artefacts written before this
    existed, and for the ones the neighbouring scripts produce.  pg dumps match
    on their target id, so the hint carries the same host/user/db the dump was
    taken with -- and an artefact whose target has since left the config gets
    "" rather than a guessed connection.
    """
    for prefix, template in _RESTORE_HINTS:
        if name.startswith(prefix):
            return template
    for target in pg_targets():
        if name.startswith(f"{target['id']}_"):
            port = "" if target["port"] == 5432 else f" -p {target['port']}"
            return (
                f"pg_restore -h {target['host']}{port} -U {target['user']} "
                f"-d {target['db']} --clean --if-exists {{path}}"
            )
    return ""


def scan_backups() -> list:
    """Every backup artefact found, newest first and not truncated.

    Split out from :func:`list_backups` so a caller can report how many exist
    without walking the trees twice.  The page needs both numbers: it renders a
    capped list, and silently dropping the rest is how an operator comes to
    believe backups older than the cap were deleted.
    """
    items = []
    roots = [
        BACKUP_ROOT,
        Path.home() / "Services" / "teslamate" / "backups",
        DATA_DIR,
    ]
    for root in roots:
        if not root.is_dir():
            continue
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            name = p.name
            if not (
                p.suffix in (".bak", ".sql", ".gz", ".tgz", ".zip")
                or ".bak." in name
                or name.endswith(".sql.bak")
            ):
                continue
            try:
                st = p.stat()
                hint = restore_hint(name)
                items.append({
                    "path": str(p),
                    "name": name,
                    "dir": str(p.parent),
                    "size_mb": round(st.st_size / 1024 / 1024, 2),
                    "mtime": int(st.st_mtime),
                    "restore": hint.format(path=str(p)) if hint else "",
                })
            except OSError:
                pass
    items.sort(key=lambda x: x["mtime"], reverse=True)
    return items


def list_backups(limit: int = 40) -> list:
    """The newest *limit* backups.  Kept for callers that only want the rows."""
    return scan_backups()[:limit]


def _pg18_dump() -> Path | None:
    for path in _PG18_DUMPS:
        if path.is_file() and os.access(path, os.X_OK):
            return path
    return None


def _immich_latest() -> dict | None:
    if not BACKUP_ROOT.is_dir():
        return None
    found = sorted(
        BACKUP_ROOT.glob("immich_*.sql.gz"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not found:
        return None
    latest = found[0]
    return {
        "name": latest.name,
        "mtime": int(latest.stat().st_mtime),
        "size_mb": round(latest.stat().st_size / 1024 / 1024, 2),
    }


def _json_object(path: Path) -> dict:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return raw if isinstance(raw, dict) else {}


def _path_state(raw: object) -> dict:
    text = str(raw or "").strip()
    if not text:
        return {"path": "", "present": False}
    return {"path": text, "present": Path(text).is_dir()}


def _status_snippet(raw: dict) -> dict:
    """Keep only the fields the Backups page renders — never the whole file."""
    if not isinstance(raw, dict):
        return {}
    out = {}
    for key in ("ok", "last_success", "last_attempt", "size_human", "reason"):
        if key in raw and raw[key] not in (None, ""):
            out[key] = raw[key]
    return out


def _immich_media_from_env() -> str:
    env = IMMICH_ROOT / ".env"
    if not env.is_file():
        return ""
    try:
        lines = env.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ""
    for line in lines:
        if line.startswith("IMMICH_MEDIA_LOCATION="):
            return line.split("=", 1)[1].strip().strip("\"'")
    return ""


def immich_layers() -> dict:
    """The Immich data map after the 2026-08-14 redesign.

    Originals left Immich's ``upload/`` / ``library/`` trees and live in the
    Apple Photos package.  Immich now indexes a read-only PhotosBridge export
    and only *generates* thumbs / encoded-video under the media root.  A
    compose-stack tarball of ``immich_server`` therefore misses the database
    (native PG18) and the originals, which is why those generic cards look
    empty on this host.
    """
    cfg = _json_object(PHOTOSHUB_CFG)
    immich = cfg.get("immich") if isinstance(cfg.get("immich"), dict) else {}
    media = str(immich.get("media_location") or _immich_media_from_env() or "").strip()
    originals = _path_state(cfg.get("photos_library"))
    bridge = _path_state(immich.get("bridge_mount") or cfg.get("bridge_dir"))
    generated_root = _path_state(media)
    generated_dirs = []
    if generated_root["path"]:
        root = Path(generated_root["path"])
        generated_dirs = [
            {"name": name, "present": (root / name).is_dir()}
            for name in _GENERATED_DIRS
        ]
    last = _immich_latest()
    restore = ""
    if last:
        hint = restore_hint(last["name"])
        restore = hint.format(path=str(BACKUP_ROOT / last["name"])) if hint else ""
    panel = _json_object(PHOTOSHUB_STATE / "panel_status.json")
    orig_snap = panel.get("originals") if isinstance(panel.get("originals"), dict) else {}
    bridge_snap = panel.get("bridge") if isinstance(panel.get("bridge"), dict) else {}
    backup = _status_snippet(_json_object(PHOTOSHUB_STATE / "backup_status.json"))
    if not backup:
        backup = _status_snippet(panel.get("backup") if isinstance(panel.get("backup"), dict) else {})
    external = _status_snippet(_json_object(PHOTOSHUB_STATE / "external_backup_status.json"))
    if not external:
        external = _status_snippet(
            panel.get("external_backup") if isinstance(panel.get("external_backup"), dict) else {}
        )
    originals_extra = {}
    if orig_snap.get("local_original_pct") is not None:
        originals_extra["pct"] = orig_snap.get("local_original_pct")
    if orig_snap.get("originals_human"):
        originals_extra["size_human"] = orig_snap.get("originals_human")
    if orig_snap.get("assets_active") is not None:
        originals_extra["assets"] = orig_snap.get("assets_active")
    bridge_extra = {}
    if bridge_snap.get("last_success"):
        bridge_extra["last_success"] = bridge_snap.get("last_success")
    if bridge_snap.get("exported_files") is not None:
        bridge_extra["exported_files"] = bridge_snap.get("exported_files")
    return {
        "db": {
            "port": 5433,
            "last": last,
            "restore": restore,
        },
        "originals": {
            **originals,
            **originals_extra,
            "backup": backup,
        },
        "bridge": {**bridge, **bridge_extra},
        "generated": {**generated_root, "dirs": generated_dirs},
        "external": external,
    }


def immich_backup_info() -> dict:
    """Whether the Immich dump can run here, plus the post-redesign layout."""
    via = ""
    if IMMICH_SCRIPT.is_file() and os.access(IMMICH_SCRIPT, os.X_OK):
        via = "script"
    elif _pg18_dump() is not None and IMMICH_DB_ENV.is_file():
        via = "native"
    layers = immich_layers()
    has_layout = bool(
        layers["originals"]["path"]
        or layers["bridge"]["path"]
        or layers["generated"]["path"]
        or layers["db"]["last"]
        or via
    )
    return {
        "available": bool(via),
        "via": via,
        "last": layers["db"]["last"],
        "layers": layers if has_layout else None,
    }


def _immich_conn() -> dict:
    """Read host/port/user/db/password from Immich's db.env.  Never log this."""
    from urllib.parse import unquote, urlparse

    raw = ""
    for line in IMMICH_DB_ENV.read_text(encoding="utf-8").splitlines():
        if line.startswith("DB_URL="):
            raw = line.split("=", 1)[1].strip().strip("\"'")
            break
    parsed = urlparse(raw) if raw else None
    password = unquote(parsed.password) if parsed and parsed.password else ""
    if not password:
        raise RuntimeError("Immich db.env has no usable DB_URL password")
    return {
        "host": (parsed.hostname if parsed and parsed.hostname else "127.0.0.1"),
        "port": (parsed.port if parsed and parsed.port else 5433),
        "user": unquote(parsed.username) if parsed and parsed.username else "immich",
        "db": (parsed.path or "/immich").lstrip("/") or "immich",
        "password": password,
    }


def backup_immich() -> dict:
    """Dump the Immich PostgreSQL 18 database to ``immich_*.sql.gz``."""
    with _only_one("immich"):
        return _backup_immich()


def _backup_immich() -> dict:
    info = immich_backup_info()
    if not info["available"]:
        return {
            "ok": False,
            "error": "not_configured",
            "message": "Immich backup is not available "
                       "(need ~/Services/immich/backup-db.sh or "
                       "postgresql@18 plus db.env)",
        }
    if info["via"] == "script":
        return _backup_immich_script()
    return _backup_immich_native()


def _backup_immich_script() -> dict:
    """The host script already pins PG18, gzips, checks the tail, and prunes."""
    before = {p.name for p in BACKUP_ROOT.glob("immich_*.sql.gz")} if BACKUP_ROOT.is_dir() else set()
    try:
        p = subprocess.run(
            [str(IMMICH_SCRIPT)],
            capture_output=True,
            text=True,
            timeout=600,
            cwd=str(IMMICH_ROOT),
        )
    except Exception as exc:
        return {"ok": False, "message": str(exc)[:500]}
    latest = _immich_latest()
    created = latest and latest["name"] not in before
    ok = p.returncode == 0 and bool(created)
    return {
        "ok": ok,
        "path": str(BACKUP_ROOT / latest["name"]) if ok and latest else None,
        "message": ((p.stdout or p.stderr or f"exit {p.returncode}")[:500]),
        "size_mb": latest["size_mb"] if ok and latest else 0,
    }


def _kill_tree(proc: subprocess.Popen) -> None:
    """Kill *proc* and anything it spawned.

    Killing only the direct child is not enough to unblock a read: a descendant
    inherits the stdout pipe, so the write end stays open and ``read()`` keeps
    waiting for a process nobody is watching any more.  The child is started in
    its own session (``start_new_session``) so the whole group can go at once.
    """
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (OSError, ProcessLookupError):
        with contextlib.suppress(Exception):
            proc.kill()


def _backup_immich_native() -> dict:
    """Same artefact as the host script, when the script itself is absent.

    pg_dump's plaintext is compressed in this process instead of being piped
    through ``gzip(1)``.  A two-process pipeline cannot drain pg_dump's stderr
    until gzip has already exited, so a dump chatty enough to fill the 64 KiB
    stderr pipe wedges both children against each other; stderr goes to a
    temporary file here, which cannot fill.  Streaming also makes the
    completeness check free: the trailing plaintext is kept as it goes past,
    rather than decompressing the finished artefact -- all of it, into memory --
    to read its last few KiB.
    """
    pg18 = _pg18_dump()
    if pg18 is None:
        return {"ok": False, "message": "postgresql@18 pg_dump is not installed"}
    try:
        conn = _immich_conn()
    except Exception as exc:
        return {"ok": False, "message": str(exc)[:200]}

    stamp = time.strftime("%Y%m%d_%H%M%S")
    dest = _private_dest(BACKUP_ROOT / f"immich_{stamp}.sql.gz")
    env = dict(os.environ)
    env["PGPASSWORD"] = conn["password"]
    argv = [
        str(pg18),
        "-h", conn["host"],
        "-p", str(conn["port"]),
        "-U", conn["user"],
        "-d", conn["db"],
        "--no-owner",
        "--no-privileges",
    ]
    dump: subprocess.Popen | None = None
    tail = b""
    err_text = ""
    expired = threading.Event()
    try:
        with tempfile.TemporaryFile() as errfile:
            dump = subprocess.Popen(
                argv, stdout=subprocess.PIPE, stderr=errfile, env=env,
                start_new_session=True,
            )

            def _expire() -> None:
                """Enforce the deadline from outside the read.

                Checking the clock between reads cannot work: ``read()`` blocks
                until the chunk is full or the pipe closes, so a pg_dump that
                stalls mid-dump (a lock wait, a wedged server) never comes back
                to be checked and parks this thread -- and the job lock -- for
                the life of the process.  Killing the child turns the blocking
                read into EOF, which is the only thing that unsticks it.
                """
                expired.set()
                _kill_tree(dump)

            watchdog = threading.Timer(_IMMICH_TIMEOUT, _expire)
            watchdog.daemon = True
            watchdog.start()
            try:
                stream = dump.stdout
                if stream is None:
                    raise RuntimeError("pg_dump produced no output stream")
                # gzip.open() reuses the 0600 file _private_dest() pre-created,
                # so the artefact is never briefly world-readable.
                with gzip.open(dest, "wb") as out:
                    while True:
                        chunk = stream.read(_DUMP_CHUNK)
                        if not chunk:
                            break
                        out.write(chunk)
                        tail = (tail + chunk)[-_DUMP_TAIL_BYTES:]
                stream.close()
                # Stand the watchdog down before anything reaps the child: once
                # wait() collects it the pid is free to be reused, and a timer
                # firing after that would killpg a stranger. Everything past
                # this point is bounded by its own timeout.
                watchdog.cancel()
                # Advisory only -- see the completeness test below.
                with contextlib.suppress(subprocess.TimeoutExpired):
                    dump.wait(timeout=30)
            finally:
                watchdog.cancel()
                errfile.seek(0)
                err_text = errfile.read().decode("utf-8", "replace")
    except Exception as exc:
        _discard(dest)
        return {"ok": False, "message": (err_text or str(exc))[:500]}
    finally:
        # A write error leaves pg_dump holding a connection to the live
        # database; without this it outlives the request that started it.
        if dump is not None and dump.poll() is None:
            _kill_tree(dump)
            with contextlib.suppress(Exception):
                dump.wait(timeout=10)

    size = _written_bytes(dest)
    # pg_dump writes _DUMP_COMPLETE as its very last line, so its presence -- not
    # the exit status -- is what proves the artefact is whole.  Letting the exit
    # status veto meant a dump that had already written every byte was deleted
    # because the process took a moment longer than expected to go away.
    ok = size > 0 and _DUMP_COMPLETE.encode() in tail
    if not ok:
        reason = "immich dump timed out" if expired.is_set() else (
            err_text or "immich dump failed or truncated"
        )
        _discard(dest)
        return {"ok": False, "message": reason[:500]}
    _prune("immich_*.sql.gz", retain=IMMICH_RETAIN)
    return {
        "ok": True,
        "path": str(dest),
        "message": f"immich backup ok: {dest.name}",
        "size_mb": round(size / 1024 / 1024, 2),
    }


def backup_postgres() -> dict:
    """Dump every configured PostgreSQL target (``backups.postgres``)."""
    with _only_one("postgres"):
        return _backup_postgres()


def _backup_postgres() -> dict:
    targets = pg_targets()
    if not targets:
        # Not an exception: an install with no pg targets is a normal install,
        # and the Backups page should report a sentence, not a stack trace.
        return {
            "ok": False,
            "error": "not_configured",
            "message": "no PostgreSQL dump targets configured "
                       "(services.yaml: backups.postgres)",
        }
    results = [_dump_one_postgres(t) for t in targets]
    if len(results) == 1:
        # The single-target answer keeps its historical shape verbatim; every
        # existing consumer (Backups page, backup-pg maintenance task) reads it.
        return results[0]
    ok = all(r.get("ok") for r in results)
    return {
        "ok": ok,
        "targets": results,
        "message": "; ".join(
            f"{t['id']}: {'ok' if r.get('ok') else (r.get('message') or 'fail')}"
            for t, r in zip(targets, results)
        )[:500],
    }


def _dump_one_postgres(target: dict) -> dict:
    stamp = time.strftime("%Y%m%d_%H%M%S")
    dest = _private_dest(BACKUP_ROOT / f"{target['id']}_{stamp}.sql.bak")
    cmd = _pg_dump_argv(target, dest)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=600,
                           env=_pg_env(target))
        # Size, not existence: the destination was pre-created 0600 so pg_dump
        # could not publish it, which means it exists even when the dump failed.
        size = _written_bytes(dest)
        ok = p.returncode == 0 and size > 0
        if not ok:
            _discard(dest)
        else:
            _prune(f"{target['id']}_*.sql.bak")
        return {
            "ok": ok,
            "path": str(dest) if ok else None,
            "message": (p.stdout or p.stderr or f"exit {p.returncode}")[:500],
            "size_mb": round(size / 1024 / 1024, 2) if ok else 0,
        }
    except Exception as e:
        _discard(dest)
        return {"ok": False, "message": str(e)}


#: Substrings that pick which ~/Library/LaunchAgents/*.plist go into a config
#: archive, before the install's own additions from services.yaml
#: (``backups.config_archive.agent_keywords``) are merged in.
#:
#: This list is a forensics tool, not just a restore convenience.  On the night
#: of 2026-08-10 an overnight session rewrote several agent plists and broke
#: their calendar triggers; none of the damaged files (local.config-backup,
#: local.immich-backup, com.gravity.rotate-logs) matched the five keywords this
#: started with, so no archive held a pre-damage copy to diff against --
#: ironically including the plist of the agent that runs this very backup.
#: Every user-managed agent on the host must match.  The built-ins cover the
#: panel's own agents and the products it integrates with (its backup and
#: log-rotation agents, Home Assistant, FileBrowser, cloudflared, Immich);
#: agents named after one install's private apps belong in agent_keywords,
#: not here.  Vendor-generated plists (homebrew.mxcl.*, com.google.*) stay
#: out deliberately: brew and Google rewrite them on upgrade and they carry
#: no local edits worth archiving.  ``*.plist.bak.<stamp>`` clutter is
#: excluded by the ``*.plist`` glob at the call site, not by this list.
DEFAULT_AGENT_KEYWORDS: tuple[str, ...] = (
    "serverhub", "config-backup", "services-logrotate",
    "homeassistant", "filebrowser", "cloudflare", "immich",
)


def agent_keywords() -> tuple[str, ...]:
    """Built-in keywords plus the install's own; defaults first, deduplicated.

    Config can only widen the manifest, never narrow it: the defaults cover
    the panel's own agents (including the one that runs this very backup), and
    a key that could remove them would let a single bad edit re-open the
    2026-08-10 blind spot.  Non-string entries are ignored for the same
    reason: a malformed list must degrade to the defaults, not to nothing.
    """
    merged = list(DEFAULT_AGENT_KEYWORDS)
    extras = _config_archive_cfg().get("agent_keywords")
    if isinstance(extras, list):
        for kw in extras:
            if isinstance(kw, str):
                kw = kw.strip()
                if kw and kw not in merged:
                    merged.append(kw)
    return tuple(merged)


def config_archive_extra_paths() -> list[Path]:
    """Absolute paths from ``backups.config_archive.extra_paths``.

    Relative entries are dropped: tar archives members under the path given,
    and a member relative to whatever cwd the panel started from is a file
    nobody can predictably restore.  Missing files are kept and filtered at
    archive time like every other member, so a temporarily absent compose
    file does not silently fall out of the configuration.
    """
    out: list[Path] = []
    raw = _config_archive_cfg().get("extra_paths")
    if not isinstance(raw, list):
        return out
    for entry in raw:
        if not isinstance(entry, str) or not entry.strip():
            continue
        path = Path(os.path.expanduser(entry.strip()))
        if path.is_absolute() and path not in out:
            out.append(path)
    return out


def _wanted_agent(name: str, keywords: tuple[str, ...] | None = None) -> bool:
    """Whether a LaunchAgents filename belongs in a config archive."""
    return any(k in name for k in (agent_keywords() if keywords is None else keywords))


def backup_configs() -> dict:
    """Tar key configs -- services.yaml, the data/ credential and state
    files, selected LaunchAgent plists, configured extras -- into
    Services/backups."""
    with _only_one("configs"):
        return _backup_configs()


# ── compose-stack (appdata) backup ───────────────────────────────────────────

#: Docker's own volume-name grammar; anything else never reaches an argv.
_VOLUME_NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,254}\Z")


def _run_argv(argv: list[str], *, timeout: int) -> tuple[int, str, str]:
    """All subprocesses of the stack backup go through one seam.

    Exists so the tests can replace every docker/tar invocation with a fake
    and assert on the exact call order — most importantly that ``compose
    start`` happens even when the archive step blows up.
    """
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except Exception as e:  # noqa: BLE001 — a backup step must report, not raise
        return -1, "", str(e)


def _engine_up() -> bool:
    from hub.docker_cli import engine_up
    return engine_up()


def _find_stack(stack_id: str) -> dict | None:
    from hub.containers_svc import _stack_paths
    for s in _stack_paths():
        if s.get("id") == stack_id:
            return s
    return None


def _stack_mounts(compose_path: str, workdir: str | None) -> tuple[list[str], list[str], str]:
    """(bind sources, named volume names, error) for one compose file.

    ``docker compose config --format json`` is used rather than parsing the
    YAML by hand because it resolves everything this function would otherwise
    have to reimplement: env interpolation, relative bind paths, and the
    project-prefixed real names of named volumes.
    """
    from hub.paths import DOCKER
    rc, out, err = _run_argv(
        [DOCKER, "compose", "-f", compose_path, "config", "--format", "json"],
        timeout=60,
    )
    if rc != 0 or not out.strip():
        return [], [], (err or out or f"compose config exit {rc}").strip()[:300]
    try:
        resolved = json.loads(out)
    except ValueError as e:
        return [], [], f"unparsable compose config: {e}"

    volume_names: dict[str, str] = {}
    for key, spec in (resolved.get("volumes") or {}).items():
        name = (spec or {}).get("name") if isinstance(spec, dict) else None
        volume_names[key] = str(name or key)

    binds: list[str] = []
    volumes: list[str] = []
    for svc in (resolved.get("services") or {}).values():
        for entry in (svc or {}).get("volumes") or []:
            if not isinstance(entry, dict):
                continue
            kind = entry.get("type")
            source = str(entry.get("source") or "")
            if kind == "bind" and source.startswith("/"):
                p = Path(source)
                try:
                    # Sockets (docker.sock) and device nodes are wiring, not data.
                    if not (p.is_dir() or p.is_file()) or p.is_socket():
                        continue
                except OSError:
                    continue
                if source not in binds:
                    binds.append(source)
            elif kind == "volume" and source:
                real = volume_names.get(source, source)
                if _VOLUME_NAME_RE.match(real) and real not in volumes:
                    volumes.append(real)
    # Drop binds nested inside another included bind: tar would store them twice.
    binds = [
        b for b in binds
        if not any(b != other and b.startswith(other.rstrip("/") + "/") for other in binds)
    ]
    return binds, volumes, ""


# ── crash recovery for interrupted stack backups ─────────────────────────────
#
# The try/finally in _backup_stack only protects against Python exceptions.
# The scheduler runner is a daemon thread: a uvicorn shutdown, a watchdog
# kickstart or a plain SIGKILL between `compose stop` and the finally leaves
# the stack stopped with nobody left to start it.  A marker file bridges the
# process boundary: written just before the stop is issued, removed in the
# finally, and any marker still present at panel startup means a backup died
# mid-flight and its stack needs a `compose start`.

_INFLIGHT_PREFIX = "stack-backup-inflight-"


def _inflight_marker(stack_id: str) -> Path:
    return DATA_DIR / f"{_INFLIGHT_PREFIX}{stack_id}"


def _write_inflight(stack_id: str, compose_path: str) -> None:
    """Best-effort: an unwritable data dir must not block the backup itself."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        _inflight_marker(stack_id).write_text(json.dumps({
            "stack": stack_id,
            "compose_path": str(compose_path),
            "ts": int(time.time()),
        }) + "\n")
    except OSError:
        pass


def _clear_inflight(stack_id: str) -> None:
    try:
        _inflight_marker(stack_id).unlink()
    except OSError:
        pass


def recover_interrupted_stack_backups() -> list[dict]:
    """Start any stack whose backup was cut short by a panel death.

    Called once from the app lifespan (on a background thread — a compose
    start can take minutes and must not delay startup).  Each leftover marker
    gets a `compose start`, an operator-visible alert, and is then removed:
    the alert is the durable record, and keeping a stale marker would re-run
    this on every subsequent restart.
    """
    from hub.paths import DOCKER

    recovered: list[dict] = []
    try:
        markers = sorted(DATA_DIR.glob(f"{_INFLIGHT_PREFIX}*"))
    except OSError:
        return recovered
    for marker in markers:
        try:
            info = json.loads(marker.read_text())
        except (OSError, ValueError):
            info = {}
        if not isinstance(info, dict):
            info = {}
        stack_id = str(info.get("stack") or marker.name[len(_INFLIGHT_PREFIX):])
        compose_path = str(info.get("compose_path") or "")
        if not compose_path:
            stack = _find_stack(stack_id)
            compose_path = str((stack or {}).get("compose_path") or "")
        started = None
        detail = "no compose file recorded for this stack"
        if compose_path:
            rc, out, err = _run_argv(
                [DOCKER, "compose", "-f", compose_path, "start"], timeout=300,
            )
            started = rc == 0
            detail = "restarted" if started else (
                f"compose start exit {rc}: {(err or out).strip()[:200]}"
            )
        log.warning("interrupted stack backup found for %s: %s", stack_id, detail)
        try:
            from hub import alerts
            alerts.emit_alert(
                kind="backup",
                level="warn",
                alert_id=f"backup:stack:{stack_id}",
                title="ServerHub stack backup interrupted",
                message=(
                    f"the panel died during a backup of stack '{stack_id}' "
                    f"(after compose stop); automatic recovery: {detail}"
                ),
            )
        except Exception:
            # Recovery must finish even when the alert pipeline is broken.
            pass
        try:
            marker.unlink()
        except OSError:
            pass
        recovered.append({"stack": stack_id, "started": started, "detail": detail})
    return recovered


def backup_stack(stack_id: str, *, retain: int = RETAIN, stop_first: bool = True,
                 log: list | None = None) -> dict:
    """Stop a compose stack, archive its data, and restart it — always.

    The contract that matters most: **once ``compose stop`` has been issued,
    ``compose start`` runs no matter what** (try/finally).  A failed backup is
    an inconvenience; a stack left stopped overnight because tar hit a full
    disk is an outage.

    Archive contents: the compose file itself, every bind-mounted host
    directory/file, and every named volume (exported by a throwaway alpine
    container, since named volumes live inside the Docker VM on macOS and have
    no host path to tar).  Product lands in
    ``BACKUP_ROOT/appdata/<stack>/<stack>_<stamp>.tgz`` with the same
    O_EXCL/0600/prune discipline as the other backups in this module.
    """
    with _only_one(f"appdata:{stack_id}"):
        return _backup_stack(stack_id, retain=retain, stop_first=stop_first,
                             log=log if log is not None else [])


def _backup_stack(stack_id: str, *, retain: int, stop_first: bool, log: list) -> dict:
    from hub.paths import DOCKER

    stack = _find_stack(stack_id)
    if stack is None:
        return {"ok": False, "error": "stack_unknown", "message": f"unknown stack: {stack_id}"}
    compose_path = stack.get("compose_path")
    if not compose_path:
        return {"ok": False, "error": "stack_no_compose",
                "message": f"stack {stack_id} has no compose file"}
    if not _engine_up():
        return {"ok": False, "error": "engine_down",
                "message": "the Docker engine is not running"}

    binds, volumes, mounts_err = _stack_mounts(compose_path, stack.get("path"))
    if mounts_err:
        log.append(f"!! {mounts_err}")
        return {"ok": False, "error": "compose_config_failed", "message": mounts_err}

    stamp = time.strftime("%Y%m%d_%H%M%S")
    dest_dir = BACKUP_ROOT / "appdata" / stack_id
    secure_io.make_secret_dir(BACKUP_ROOT / "appdata")
    secure_io.make_secret_dir(dest_dir)

    stopped = False
    restarted = None
    archive_ok = False
    dest = None
    staging = None
    message = ""
    error = ""
    try:
        if stop_first:
            # Marker first: if the panel is killed anywhere past this point,
            # the startup scan (recover_interrupted_stack_backups) still finds
            # out a stop was in flight and starts the stack back up.
            _write_inflight(stack_id, str(compose_path))
            log.append(f"$ docker compose -f {compose_path} stop")
            rc, out, err = _run_argv([DOCKER, "compose", "-f", compose_path, "stop"],
                                     timeout=300)
            # Even a non-zero stop may have taken containers down, so the
            # finally-restart below keys off "stop was attempted", not rc.
            stopped = True
            if rc != 0:
                log.append(f"!! compose stop exit {rc}: {(err or out).strip()[:200]}")

        # No early returns inside this try: the result must be assembled after
        # the finally has run, or it could not truthfully report `restarted`.
        staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=dest_dir))
        vol_dir = staging / "volumes"
        vol_dir.mkdir()
        for name in volumes:
            log.append(f"exporting volume {name}")
            rc, out, err = _run_argv(
                [DOCKER, "run", "--rm",
                 "-v", f"{name}:/src:ro",
                 "-v", f"{vol_dir}:/out",
                 "alpine", "tar", "-cf", f"/out/{name}.tar", "-C", "/src", "."],
                timeout=1800,
            )
            if rc != 0:
                error = "volume_export_failed"
                message = f"volume export failed for {name}: {(err or out).strip()[:200]}"
                log.append(f"!! {message}")
                break

        if not error:
            dest = _private_dest(dest_dir / f"{stack_id}_{stamp}.tgz")
            tar_argv = ["/usr/bin/tar", "czf", str(dest), str(compose_path), *binds]
            if volumes:
                tar_argv += ["-C", str(staging), "volumes"]
            log.append(f"$ {' '.join(tar_argv)}")
            rc, out, err = _run_argv(tar_argv, timeout=3600)
            size = _written_bytes(dest)
            archive_ok = rc == 0 and size > 0
            if not archive_ok:
                error = "archive_failed"
                message = (err or out or f"tar exit {rc}").strip()[:300]
                log.append(f"!! archive failed: {message}")
            else:
                message = f"archived {len(binds)} bind mount(s), {len(volumes)} volume(s)"
                log.append(f"== {message} -> {dest} ({round(size / 1024 / 1024, 2)} MB)")
    finally:
        # The one promise this function makes: an attempted stop is always
        # followed by a start, whatever happened in between.
        if stopped:
            log.append(f"$ docker compose -f {compose_path} start")
            rc, out, err = _run_argv([DOCKER, "compose", "-f", compose_path, "start"],
                                     timeout=300)
            restarted = rc == 0
            if not restarted:
                log.append(f"!! compose start exit {rc}: {(err or out).strip()[:200]}")
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
        if dest is not None and not archive_ok:
            _discard(dest)
        if stop_first:
            # The in-process restart above already ran (or was skipped because
            # no stop happened); either way this backup is no longer in flight.
            _clear_inflight(stack_id)

    if archive_ok:
        _prune(f"appdata/{stack_id}/{stack_id}_*.tgz", retain=retain)
    if restarted is False:
        # Archive state is secondary to "the stack did not come back".
        message = f"{message}; STACK DID NOT RESTART — start it manually".strip("; ")
    result = {
        "ok": archive_ok and restarted is not False,
        "path": str(dest) if archive_ok else None,
        "size_mb": round(_written_bytes(dest) / 1024 / 1024, 2) if archive_ok and dest else 0,
        "stack": stack_id,
        "stopped": stopped,
        "restarted": restarted,
        "binds": len(binds),
        "volumes": len(volumes),
        "message": message,
    }
    if error:
        result["error"] = error
    return result


# ── data/ state & secret files in the config archive ─────────────────────────
#
# services.yaml alone does not bring a panel back.  What stands between a
# restored install and an admin lockout lives under data/: twofa.json (TOTP
# secrets -- without it every 2FA-enrolled account is locked out),
# api-keys.json, notify-credentials.json, backup-credentials.json,
# service-credentials.json, .session-secret, .local-client-token,
# wireguard-peers.json, and whatever secret store ships next.  Losing data/
# used to mean lockout plus every integration token gone, because the config
# archive carried none of it.
#
# Selection is a rule rather than a filename allowlist, for the reason
# DEFAULT_AGENT_KEYWORDS documents: an under-matching manifest is a blind
# spot nobody notices until the restore fails.  A secret store added next
# month must land in the archive without anyone remembering to extend a list
# here.  The rule -- every small regular file directly under data/ -- minus
# the classes that are bulk, derived, or harmful to restore:
#
#   * anything with .jsonl in the name: alert/audit/metrics history, the
#     multi-megabyte bulk this archive must not carry;
#   * services.yaml.bak.*: up to BACKUP_RETENTION pre-images of a file the
#     archive already contains live;
#   * *.lock: flock targets, contentless by design;
#   * *.out: stray process logs (audit_monitor.out);
#   * stack-backup-inflight-*: crash markers -- restoring one makes the next
#     panel boot "recover" a stack that was never stopped (a compose start
#     plus a spurious alert);
#   * anything over _DATA_FILE_MAX: no state file is anywhere near that
#     size, so a runaway file must not quietly bloat every nightly archive;
#   * symlinks: every writer under data/ creates regular files; a link is
#     not panel state, and tar would archive the link rather than the state.
_DATA_EXCLUDE_PREFIXES: tuple[str, ...] = ("services.yaml.bak.", _INFLIGHT_PREFIX)
_DATA_EXCLUDE_SUFFIXES: tuple[str, ...] = (".lock", ".out")
_DATA_FILE_MAX = 1024 * 1024


def data_state_paths() -> list[Path]:
    """The data/ files a config archive carries, sorted for determinism."""
    out: list[Path] = []
    try:
        entries = sorted(DATA_DIR.iterdir())
    except OSError:
        return out
    for p in entries:
        name = p.name
        if ".jsonl" in name:
            continue
        if name.endswith(_DATA_EXCLUDE_SUFFIXES):
            continue
        if name.startswith(_DATA_EXCLUDE_PREFIXES):
            continue
        try:
            if p.is_symlink() or not p.is_file():
                continue
            if p.stat().st_size > _DATA_FILE_MAX:
                continue
        except OSError:
            continue
        out.append(p)
    return out


def _backup_configs() -> dict:
    stamp = time.strftime("%Y%m%d_%H%M%S")
    # services.yaml first (the member a restorer looks for), then the data/
    # credential and state files, then the install's own extras.  tar records
    # each member's mode, so the 0600 files come back 0600 -- the archive
    # itself is 0600 in a 0700 directory via _private_dest, same as before.
    paths = [CONFIG_FILE, *data_state_paths(), *config_archive_extra_paths()]
    # include launchagents selectively
    agents = Path.home() / "Library" / "LaunchAgents"
    if agents.is_dir():
        for pl in agents.glob("*.plist"):
            if _wanted_agent(pl.name):
                paths.append(pl)
    existing = [str(p) for p in paths if p.exists()]
    # "At least one file exists" was the old guard, and it let the one member
    # anyone would ever restore from go missing silently: with services.yaml
    # absent but a single plist present, tar succeeded, the size was plausible,
    # and the row in the table looked exactly like a good backup.  A config
    # archive without the config is not a partial success, it is a failure.
    if str(CONFIG_FILE) not in existing:
        return {
            "ok": False,
            "message": (
                f"refusing to write a config backup without {CONFIG_FILE.name}: "
                f"{CONFIG_FILE} is missing or unreadable"
            ),
        }
    # Created only now that there is something to archive, so a no-op call does
    # not leave an empty placeholder behind in the backup listing.  The *returned*
    # path is what tar writes to: passing the original back in would reintroduce
    # the truncation this function is guarding against, because _private_dest
    # hands back a different name when the first one is taken.
    dest = _private_dest(BACKUP_ROOT / f"configs_{stamp}.tgz")
    try:
        p = subprocess.run(
            ["/usr/bin/tar", "czf", str(dest)] + existing,
            capture_output=True,
            text=True,
            timeout=120,
        )
        # This archive contains services.yaml, so judge success by size: the
        # placeholder always exists after _private_dest.
        size = _written_bytes(dest)
        ok = p.returncode == 0 and size > 0
        if not ok:
            _discard(dest)
        else:
            _prune("configs_*.tgz")
        return {
            "ok": ok,
            "path": str(dest) if ok else None,
            "message": (p.stderr or p.stdout or "")[:500] or ("ok" if ok else "fail"),
            "size_mb": round(size / 1024 / 1024, 2) if ok else 0,
        }
    except Exception as e:
        _discard(dest)
        return {"ok": False, "message": str(e)}
