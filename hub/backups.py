"""Backup helpers: list artifacts + run common backup jobs."""
from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import shutil
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


#: Substrings that pick which ~/Library/LaunchAgents/*.plist go into a config
#: archive.
#:
#: This list is a forensics tool, not just a restore convenience.  On the night
#: of 2026-08-10 an overnight session rewrote several agent plists and broke
#: their calendar triggers; none of the damaged files (local.config-backup,
#: local.immich-backup, com.gravity.rotate-logs) matched the five keywords this
#: started with, so no archive held a pre-damage copy to diff against --
#: ironically including the plist of the agent that runs this very backup.
#: Every user-managed agent on the host must match.  Vendor-generated plists
#: (homebrew.mxcl.*, com.google.*) stay out deliberately: brew and Google
#: rewrite them on upgrade and they carry no local edits worth archiving.
#: ``*.plist.bak.<stamp>`` clutter is excluded by the ``*.plist`` glob at the
#: call site, not by this list.
_AGENT_KEYWORDS = (
    "serverhub", "homeassistant", "filebrowser", "onedrive", "cloudflare",
    "config-backup", "immich", "gravity", "sgcc", "kiro-go", "kidsmusic",
    "esphome", "sub2api", "system-nginx", "services-logrotate", "cf-ips",
    "remote-desktop", "server-autostart",
)


def _wanted_agent(name: str) -> bool:
    """Whether a LaunchAgents filename belongs in a config archive."""
    return any(k in name for k in _AGENT_KEYWORDS)


def backup_configs() -> dict:
    """Tar key configs into Services/backups."""
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
            tar_argv = ["tar", "czf", str(dest), str(compose_path), *binds]
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
