"""Backup helpers: list artifacts + run common backup jobs."""
from __future__ import annotations

import contextlib
import logging
import os
import subprocess
import threading
import time
from pathlib import Path

from hub import secure_io
from hub.config import cfg
from hub.errors import CODES, api_error
from hub.paths import CONFIG_FILE, DATA_DIR

BACKUP_ROOT = Path.home() / "Services" / "backups"
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


def _prune(pattern: str) -> None:
    """Delete all but the newest :data:`RETAIN` artefacts matching *pattern*.

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
    try:
        found = sorted(BACKUP_ROOT.glob(pattern), reverse=True)
    except OSError:
        return
    for old in found[RETAIN:]:
        try:
            old.unlink()
        except OSError:
            continue
        log.info("pruned old backup (keeping %d): %s", RETAIN, old.name)


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


#: How to put each kind of artefact back, keyed by a filename test.
#:
#: A backup nobody knows how to restore is a filesystem full of reassurance.  None
#: of these artefacts had a restore path anywhere -- no code, no script, no note --
#: and the TeslaMate one actively misleads: `pg_dump -F c` writes a *custom-format*
#: archive, so the `.sql.bak` name points a restorer at `psql`, which cannot read
#: it.  The command belongs next to the file rather than in someone's memory.
#:
#: Hints are commands, deliberately not run by anything here: restoring overwrites
#: live data and is the operator's decision, not a button.
_RESTORE_HINTS: tuple[tuple[str, str], ...] = (
    (
        "teslamate_",
        # -F c archive: pg_restore, never psql. --clean --if-exists so a re-run
        # into a populated database replaces rather than collides.
        "pg_restore -h localhost -U teslamate -d teslamate --clean --if-exists {path}",
    ),
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
    existed, and for the ones the neighbouring scripts produce.
    """
    for prefix, template in _RESTORE_HINTS:
        if name.startswith(prefix):
            return template
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


def backup_postgres() -> dict:
    """Dump TeslaMate DB (native PG17)."""
    with _only_one("postgres"):
        return _backup_postgres()


def _backup_postgres() -> dict:
    stamp = time.strftime("%Y%m%d_%H%M%S")
    dest = _private_dest(BACKUP_ROOT / f"teslamate_{stamp}.sql.bak")
    env = dict(os.environ)
    env.update({
        k: str(v)
        for k, v in ((cfg().get("settings") or {}).get("maintenance_env") or {}).items()
    })
    env.setdefault("PGPASSWORD", os.environ.get("PGPASSWORD", "teslamate_secret"))
    cmd = [
        "pg_dump", "-h", "localhost", "-U", "teslamate", "-d", "teslamate",
        "-F", "c", "-b", "-f", str(dest),
    ]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=600, env=env)
        # Size, not existence: the destination was pre-created 0600 so pg_dump
        # could not publish it, which means it exists even when the dump failed.
        size = _written_bytes(dest)
        ok = p.returncode == 0 and size > 0
        if not ok:
            _discard(dest)
        else:
            _prune("teslamate_*.sql.bak")
        return {
            "ok": ok,
            "path": str(dest) if ok else None,
            "message": (p.stdout or p.stderr or f"exit {p.returncode}")[:500],
            "size_mb": round(size / 1024 / 1024, 2) if ok else 0,
        }
    except Exception as e:
        _discard(dest)
        return {"ok": False, "message": str(e)}


def backup_configs() -> dict:
    """Tar key configs into Services/backups."""
    with _only_one("configs"):
        return _backup_configs()


def _backup_configs() -> dict:
    stamp = time.strftime("%Y%m%d_%H%M%S")
    paths = [
        CONFIG_FILE,
        Path.home() / "Services" / "teslamate" / "docker-compose.yml",
        Path.home() / "Services" / "music-assistant" / "docker-compose.yml",
    ]
    # include launchagents selectively
    agents = Path.home() / "Library" / "LaunchAgents"
    if agents.is_dir():
        for pl in agents.glob("*.plist"):
            if any(x in pl.name for x in ("serverhub", "homeassistant", "filebrowser", "onedrive", "cloudflare")):
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
            ["tar", "czf", str(dest)] + existing,
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
