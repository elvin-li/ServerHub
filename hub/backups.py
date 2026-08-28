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

from fastapi import HTTPException

from hub import secure_io
from hub.config import cfg
from hub.errors import CODES, api_error
from hub.paths import CONFIG_FILE, DATA_DIR, user_home
from hub.util import read_text_capped, run_capped, safe_json_loads, strftime_now, utf8_env


def _decode_bytes(value) -> str:
    """Unbound base decode: a leftover subclass ``.decode`` bomb cannot 500."""
    base = bytes if _isa(value, bytes) else bytearray
    return base.decode(value, "utf-8", "replace")


def _as_text(value) -> str:
    """``run_capped`` leftovers arrive as bytes/None; JSON and ``.strip`` need text."""
    # _isa on the gate, try on the decode (the ollama10 rule): a lying
    # ``__class__`` impostor (claims bytes, is not — the dash10/json9 shape)
    # passed the bare isinstance and the unbound ``bytes.decode`` TypeError'd
    # *inside* the broad catches around the immich/postgres/configs jobs —
    # the successful artefact was ``_discard``'ed and the 200 lied ok:false
    # with descriptor gibberish as the run's failure.  The impostor drops to
    # "", so the message falls back to the honest ``_exit_text(rc)``.
    if _isa(value, (bytes, bytearray)):
        try:
            return _decode_bytes(value)
        except Exception:
            return ""
    if value is None:
        return ""
    try:
        value = str(value)
    except RecursionError:
        try:
            return type(value).__name__
        except Exception:
            return ""
    except Exception:
        return ""
    # Unbound base encode (the hub.modules._utf8_text rule): ``str()`` of a
    # subclass whose ``__str__`` answers *self* skips CPython's exact-str
    # copy, so a leftover bound ``encode`` bomb rode this line out of the
    # broad catches around the postgres/configs jobs — the *successful*
    # artefact was discarded and reported as the dump's failure.  The
    # round-trip also hands every caller an exact str, so the ``[:500]`` /
    # ``.strip()`` that follow cannot hit another poisoned override.
    return str.encode(value, "utf-8", "replace").decode("utf-8")


def _home_dir() -> Path:
    """Best-effort HOME.  ``Path.home()`` leftover used to 500 import."""
    return user_home() or Path("/var/empty/serverhub-backups")


_HOME = _home_dir()
BACKUP_ROOT = _HOME / "Services" / "backups"

#: Leftover multi-MB panel_status / .env / inflight markers used to OOM
#: GET /api/backups and POST /api/backups/immich.
_JSON_CAP = 256 * 1024
_ENV_CAP = 64 * 1024
_MARKER_CAP = 64 * 1024
#: Resolved compose JSON is typically tens of KB.  ``run_capped`` keeps a
#: *trailing* window, so the 4KB chatter cap turned every real
#: ``compose config --format json`` into a torn suffix and backup_stack
#: refused with ``compose_config_failed``.
_COMPOSE_JSON_CAP = 256 * 1024

#: This host's Immich cluster is PostgreSQL 18 on :5433.  PATH ``pg_dump`` is
#: 17.x and a version-mismatched dump of that database is empty or truncated,
#: which is why the neighbouring ``~/Services/immich/backup-db.sh`` pins the
#: Homebrew @18 binary and writes ``immich_*.sql.gz``.  The Backups page used
#: to expose that job; after postgres targets became configuration only
#: TeslaMate remained on the button.  These paths rediscover the Immich dump
#: without putting its password in services.yaml.
IMMICH_ROOT = _HOME / "Services" / "immich"
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
PHOTOSHUB_CFG = _HOME / "PhotosHub" / "config" / "config.json"
PHOTOSHUB_STATE = _HOME / "PhotosHub" / "state"
_GENERATED_DIRS = ("thumbs", "encoded-video", "upload", "library")
# 0700, not the umask default: a config backup contains services.yaml verbatim,
# which holds the admin password hash and any tunnel/API tokens, and a database
# dump contains whatever the database holds.  The originals are 0600, so leaving
# the copies at 0644 in a traversable directory handed every other local account
# the exact secrets the originals protect.
# Skip mkdir when HOME is the /var/empty fallback: that used to 500 import.
if user_home() is not None:
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
    try:
        base.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        # Leftover file occupying the backup directory, dying volume: let
        # the writer fail the same way as any other unwritable dest.
        return base
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
    try:
        retain = max(1, int(retain))
    except (TypeError, ValueError, OverflowError):
        retain = RETAIN
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
    """Size of a produced archive, or 0 when it is missing, empty, or leftover junk.

    A FUSE/network fs reporting ``st_size = inf`` used to leak into
    POST /api/backups/* ``size_mb`` and 500 Starlette's ``allow_nan=False``
    encoder.  A 400-digit leftover size OverflowError'd ``size / 1024``.
    """
    try:
        st = dest.stat()
    except OSError:
        return 0
    nums = _stat_numbers(st)
    return nums[0] if nums is not None else 0


def _stat_numbers(st) -> tuple[int, int] | None:
    """``(size, mtime)`` as finite ints, or None when the stat is leftover junk.

    A FUSE/network fs reporting ``st_mtime = inf`` used to OverflowError
    ``int()`` inside :func:`scan_backups` and 500 GET /api/backups.
    A 400-digit leftover ``st_size`` is a valid int, then ``size / 1024``
    OverflowError'd the size_mb field on the same path.
    """
    try:
        size = int(st.st_size)
        mtime = int(st.st_mtime)
    except (TypeError, ValueError, OverflowError, AttributeError):
        return None
    if size < 0:
        return None
    try:
        float(size)
        float(mtime)
    except OverflowError:
        return None
    return size, mtime


def _discard(dest: Path) -> None:
    """Remove the pre-created placeholder after a failed run."""
    try:
        dest.unlink()
    except OSError:
        pass


def _tool_on_disk(tool) -> bool:
    """Fresh disk probe for the vanished-CLI classifier below.

    Bare names (``pg_dump``) resolve the way the spawn resolved them — over
    PATH — and absolute paths (``/usr/bin/tar``, the Immich script) stat
    directly.  A probe that raises (EIO under a dying volume) counts as
    gone: the CLI is unreachable either way (the photoshub ``_ctl_on_disk``
    rule).
    """
    try:
        text = str(tool or "")
    except Exception:
        return False
    if not text:
        return False
    try:
        if os.sep in text:
            return Path(text).is_file()
        return shutil.which(text) is not None
    except (OSError, TypeError, ValueError):
        return False


def _exit_code(rc):
    """*rc* as an exact int, or None when it is seam junk (never raises).

    ``run_capped`` results are the same seam the backups7 sweep sealed for
    *text* — and the *rc* half still ran raw dunders everywhere it landed.
    An int subclass whose ``__eq__``/``__ne__`` raises passed
    ``isinstance`` and detonated ``_cli_vanished``'s ``rc != -1`` (a bare
    500 out of POST /api/backups/immich, whose comparisons sit outside the
    spawn's try) and the jobs' ``ok = rc == 0`` — inside the postgres /
    configs broad catches, where the raise ``_discard``'ed an artefact that
    had already written every byte and reported a 200 that lied ok:false
    with the bomb's text as the dump's failure.  ``int.__index__`` is the
    unbound base coercion ``_jsonable`` already uses: it reads the real
    exit status underneath the override, so a bomb wrapping a genuine 0
    keeps its successful run.  Anything uncoercible is junk, not an exit
    status — None fails every ``== 0`` / ``!= -1`` probe closed.
    """
    if type(rc) is int:
        return rc
    try:
        return int.__index__(rc)
    except Exception:
        return None


def _exit_text(rc) -> str:
    """``exit <rc>`` for result messages, or ``exit unknown`` when *rc* cannot
    be rendered at all (the brew_svc rule).

    Past CPython's 4300-digit int->str cap the bare f-string raises the
    digit-cap ValueError.  In ``_backup_immich_script`` that render sat
    outside every try and 500'd POST /api/backups/immich after the run had
    already finished; the postgres dump's broad catch kept the 200 but
    answered with CPython's digit-cap internals as the whole message.  The
    compose stop/start/config and tar renders feed the scheduler journal
    through the same f-strings.
    """
    if rc is None:
        return "exit unknown"
    try:
        return f"exit {rc}"
    except Exception:
        # ValueError past the digit cap — but the f-string's empty format
        # spec also dispatches to a subclass ``__str__``, so a seam rc
        # bomb raised RuntimeError past the old narrow tuple and 500'd
        # POST /api/backups/immich on the empty-output failure path.
        return "exit unknown"


def _cli_vanished(rc, text, tool) -> bool:
    """Whether a ``run_capped`` result means the job's own binary is gone.

    ``run_capped`` reports a FileNotFoundError spawn as ``(-1, "not found")``
    — a sentinel, never a real CLI exit (the vms_svc._cli_missing /
    brew_svc convention).  A binary that vanished between a job's up-front
    probe (or its install) and the spawn used to fall through as an uncoded
    ``{ok: false, message: "not found"}`` the SPA cannot translate.  A
    timeout keeps its own shape and a genuine non-zero exit keeps its raw
    output — that message is then the truth.

    The sentinel alone must not classify: rc -1 is also what a SIGHUP-killed
    run reports through ``subprocess.run``, so a *still-present* tool whose
    trailing output happened to read exactly ``not found`` was answered with
    the vanished-binary 503 instead of its raw result.  Only when a fresh
    disk probe confirms *tool* actually left the disk does the coded answer
    apply — the vms ``_cli_missing`` / ollama ``delete_model`` rule.  The
    re-check runs only on this failure path, never on a successful spawn.
    """
    # _exit_code, not the bare compare: ``!=`` dispatches to the value's
    # own ``__ne__`` first, so a seam rc bomb 500'd POST /api/backups/immich
    # out of this very probe.  The spawn sentinel is a literal exact -1, so
    # junk that cannot coerce (None) is never the sentinel.
    if _exit_code(rc) != -1 or _as_text(text).strip() != "not found":
        return False
    return not _tool_on_disk(tool)


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
#: Leftover multi-MB credentials used to OOM POST /api/backups/postgres.
_SECRETS_CAP = 256 * 1024

#: Target ids become filenames and prune globs, so the charset is pinned the
#: same way volume names are below: no separators, no wildcards.
_PG_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


def _pg_conninfo_chars(value: str) -> bool:
    """True if *value* could act as a libpq connection string rather than a
    plain host/db/role name (contains whitespace or a ``key=value`` ``=``)."""
    return "=" in value or any(c.isspace() for c in value)


def _cfg_text(value) -> str | None:
    """A ``backups.postgres`` scalar as clean text, or None when it cannot be.

    YAML hex/octal integers load uncapped (``int(x, 16)`` is exempt from
    CPython's 4300-digit conversion limit), so a leftover ``db: 0xFF…`` was
    an *already-int* here and the bare ``str()`` raised the digit-cap
    ValueError — 500ing GET /api/backups and POST /api/backups/postgres
    through :func:`pg_targets`, which promises to drop malformed entries
    one by one instead.  A quoted ``"\\ud800…"`` loads as a lone-surrogate
    str, passed every check, and 500'd Starlette's UTF-8 encode on the same
    routes.  No real host/db/role name is un-encodable, so both shapes mean
    "drop this entry", never "raise".
    """
    if value is None:
        return ""
    try:
        text = str(value)
    except Exception:
        # ValueError past the int->str digit cap; RecursionError on a
        # leftover self-referential __str__.
        return None
    try:
        # Unbound base encode, and the round-trip rather than a bare probe:
        # ``str()`` of a subclass whose ``__str__`` answers *self* skips
        # CPython's exact-str copy, so a leftover bound ``encode`` bomb
        # raised RuntimeError past the UnicodeEncodeError catch and 500'd
        # GET /api/backups — and the subclass's ``.strip()`` / ``__eq__``
        # were the next overrides in pg_targets' path.  The decode of the
        # exact bytes hands back an exact str.
        return str.encode(text, "utf-8").decode("utf-8")
    except UnicodeEncodeError:
        return None
    except Exception:
        return None


def _exact_str(value) -> str | None:
    """Exact-str copy of *value* without calling any overridable method.

    ``agent_keywords`` / ``extra_paths`` entries pass ``isinstance(x, str)``
    as odd subclasses too, and the bound ``.strip()`` that followed used to
    raise out of :func:`agent_keywords` / :func:`config_archive_extra_paths`
    and 500 POST /api/backups/configs.  surrogatepass, not the
    :func:`_cfg_text` reject: these values name real on-disk files, and an
    undecodable filename legitimately carries lone surrogates
    (os surrogateescape) all the way into tar's argv.
    """
    if type(value) is str:
        return value
    try:
        return str.encode(value, "utf-8", "surrogatepass").decode(
            "utf-8", "surrogatepass"
        )
    except Exception:
        return None


def _isa(value, kinds) -> bool:
    """``isinstance`` that survives a leftover ``__class__``-property bomb.

    ``isinstance`` consults ``value.__class__`` when the exact-type check
    misses, so a poisoned ``backups`` / ``config_archive`` / ``postgres``
    value (or one of its entries) whose ``__class__`` is a *raising
    property* detonated the very type gates below — every one of which sits
    *outside* a try — and 500'd GET /api/backups, POST /api/backups/postgres
    and POST /api/backups/configs before any of this module's ``_mapping_get``
    / ``_truthy`` / ``_iter_list`` unbound reads got a turn.  A real subclass
    still matches through the C-level type check; only a value that cannot
    answer what it is takes the non-matching branch (the worker_health /
    smart_test_svc ``_isa`` rule) — which for these gates means "drop this
    entry" or "treat as unset", never a raise.
    """
    try:
        return isinstance(value, kinds)
    except Exception:
        return False


def _truthy(value) -> bool:
    """``bool(value)`` that survives a leftover ``__bool__`` bomb.

    The ``hub.jobs._truthy`` rule: the truth test hidden in
    ``entry.get(key) or ""`` used to detonate a junk config value whose
    ``__bool__`` raises and 500 GET /api/backups.  Fails closed to False —
    a bomb value is junk, not a name.
    """
    try:
        return bool(value)
    except Exception:
        return False


def _mapping_get(mapping, key):
    """Field read that a dict-subclass ``.get`` bomb cannot 500.

    The ``hub.ups_svc._mapping_get`` rule, which these cfg-readers never
    got: ``isinstance(x, dict)`` passes an odd subclass whose ``get``
    raises, and one such block planted as ``backups`` / ``config_archive``
    / a postgres entry used to raise out of :func:`pg_targets` /
    :func:`config_archive_extra_paths` and 500 GET /api/backups,
    POST /api/backups/postgres and POST /api/backups/configs at once.
    ``dict.get`` reads the real storage underneath the override.
    """
    if not _isa(mapping, dict):
        return None
    try:
        return mapping.get(key)
    except Exception:
        try:
            return dict.get(mapping, key)
        except Exception:
            return None


def _iter_list(value):
    """Unbound base iteration over a list (the ``hub.modules._jsonable``
    rule): a list-subclass ``__iter__`` bomb planted as
    ``backups.postgres`` / ``agent_keywords`` / ``extra_paths`` used to
    raise out of the ``for`` and 500 the route; the real elements still
    come through.

    The unbound call runs in a try (the ollama10 rule): ``_isa`` lets a
    *lying* ``__class__`` impostor through — a plain object whose
    ``__class__`` property *returns* ``list`` passes ``isinstance``, and
    the descriptor TypeError then detonated at the ``for`` itself, a bare
    500 out of GET /api/backups, POST /api/backups/postgres (via
    ``pg_targets``) and POST /api/backups/configs (via ``agent_keywords``
    / ``config_archive_extra_paths``).  The impostor has no real list
    storage to read, so it degrades to "no entries" — the same treat-as-
    unset answer a raising ``__class__`` bomb already gets — and a real
    list subclass still yields its real elements.
    """
    try:
        return list(list.__iter__(value))
    except Exception:
        return []


def _cfg_map() -> dict:
    """The config snapshot as a dict — or ``{}`` when the provider itself
    raises (the ``hub.config.settings_section`` rule these readers never got).

    Every cfg read in this module goes through ``_mapping_get`` — but the
    ``cfg()`` *call* sat outside every guard, so a snapshot provider that
    raises 500'd GET /api/backups and POST /api/backups/postgres straight
    out of ``pg_targets`` (and once more per listed row via ``scan_backups``
    → ``restore_hint``), and POST /api/backups/configs out of
    ``config_archive_extra_paths`` (outside the tar try) and
    ``agent_keywords`` (inside a catch that only covers OSError) — all
    before any job's broad catch got a turn.  In ``_pg_env`` the same raise
    landed *inside* the dump's broad catch instead, which ``_discard``'ed
    the finished artefact and blamed pg_dump for a config leftover the dump
    never read.  A snapshot that cannot be read means the same thing an
    empty services.yaml means: nothing is configured.
    """
    try:
        raw = cfg()
    except Exception:
        return {}
    return raw if _isa(raw, dict) else {}


def _user_home() -> Path | None:
    """Best-effort HOME through the module seam (never raises, always a Path).

    ``hub.paths.user_home`` already guards ``Path.home()`` — but the seam
    itself is a snapshot provider like ``cfg``, and this module joined its
    answer bare: ``home / "Services" / …`` in :func:`scan_backups` and the
    LaunchAgents join in :func:`_backup_configs`.  A leftover provider that
    raises — or answers *text* instead of a Path — detonated those joins
    (TypeError on ``str.__truediv__``) and 500'd GET /api/backups and
    POST /api/backups/configs outside every catch.  A textual answer still
    names a real directory, so it is kept as a Path (``_exact_str``:
    surrogates in an undecodable HOME are legitimate there); junk that
    cannot name one degrades to None — the same "no home" answer an
    unresolvable HOME already gets.
    """
    try:
        home = user_home()
    except Exception:
        return None
    if home is None:
        return None
    if _isa(home, (bytes, bytearray)):
        try:
            text = _decode_bytes(home)
        except Exception:
            return None
    elif _isa(home, str):
        text = _exact_str(home)
    else:
        # Path and any real os.PathLike; a lying-``__class__`` Path impostor
        # has no __fspath__ to answer with and drops here.  The fspath
        # round-trip also flattens a Path subclass carrying bound bombs.
        try:
            text = os.fspath(home)
        except Exception:
            return None
        if not _isa(text, str):
            return None
        text = _exact_str(text)
    if not text:
        return None
    try:
        return Path(text)
    except Exception:
        return None


def _backups_cfg() -> dict:
    # _isa, not bare isinstance: a ``backups:`` value whose ``__class__`` is a
    # raising property detonated this gate itself — a 500 on GET /api/backups
    # and both POST dumps before any reader ran.
    raw = _mapping_get(_cfg_map(), "backups")
    return raw if _isa(raw, dict) else {}


def _config_archive_cfg() -> dict:
    raw = _mapping_get(_backups_cfg(), "config_archive")
    return raw if _isa(raw, dict) else {}


def pg_targets(raw: list | None = None) -> list[dict]:
    """Validated ``backups.postgres`` entries, in file order.

    Malformed entries are dropped one by one rather than raising: one mistyped
    row must not take the dump of a healthy target (or the whole Backups page)
    down with it.  Defaults follow pg_dump's own: localhost, port 5432, and
    the role named after the database.
    """
    if raw is None:
        raw = _mapping_get(_backups_cfg(), "postgres")
    # _isa, not bare isinstance: a ``backups.postgres`` value (or one of its
    # entries) whose ``__class__`` is a raising property detonated these gates
    # and 500'd GET /api/backups instead of dropping the one bad entry.
    if not _isa(raw, list):
        return []
    out: list[dict] = []
    seen: set[str] = set()
    for entry in _iter_list(raw):
        if not _isa(entry, dict):
            continue
        # _cfg_text, not str(): a YAML hex over-cap int or lone-surrogate
        # value in any of these fields used to raise out of this loop and
        # 500 GET /api/backups instead of dropping the one bad entry.
        # _mapping_get / _truthy, not ``entry.get(key) or ""``: a
        # dict-subclass ``.get`` bomb or a value whose ``__bool__`` raises
        # used to 500 the same routes instead of costing its entry.
        fields = {}
        for key in ("id", "db", "host", "user", "password_env"):
            value = _mapping_get(entry, key)
            fields[key] = _cfg_text(value if _truthy(value) else "")
        if any(v is None for v in fields.values()):
            continue
        tid = fields["id"].strip()
        db = fields["db"].strip()
        host = fields["host"].strip() or "localhost"
        user = fields["user"].strip() or db
        port_raw = _mapping_get(entry, "port")
        try:
            # None/"" mean "unset" and take the default; 0 is a typo, not a port.
            # YAML ``port: .inf`` used to OverflowError GET /api/backups.
            port = int(5432 if port_raw in (None, "") else port_raw)
        except (TypeError, ValueError, OverflowError):
            continue
        except Exception:
            # A leftover comparison / __int__ bomb in ``port`` (the ``in``
            # check runs the value's ``__eq__``) is the same "drop this
            # entry", never a 500 out of GET /api/backups.
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
            "password_env": fields["password_env"].strip(),
        })
    return out


def _ensure_secret_mode(path: Path) -> None:
    """Tighten a plaintext-secret file to 0600 if it was left group/world
    readable.  DATA_DIR is 0700 so the exposure is already contained, but this
    file holds database passwords and there is no reason for it to carry looser
    bits — matching the 0600-at-creation guarantee the other secret stores make.
    """
    try:
        # A leftover directory named backup-credentials.json is not a secret
        # file; chmod 0600 would lock the directory itself, not fix a mode.
        if not path.is_file():
            return
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
        if not BACKUP_SECRETS_FILE.is_file():
            return ""
        raw = safe_json_loads(
            read_text_capped(BACKUP_SECRETS_FILE, _SECRETS_CAP, encoding="utf-8"),
            # One leftover >4300-digit stamp anywhere in the store used to
            # ValueError the whole decode, read every password back as ""
            # and send pg_dump off unauthenticated (see _capped_json_int).
            parse_int=_capped_json_int,
        )
    except (OSError, ValueError, RecursionError):
        # RecursionError: leftover deeply-nested credentials is not ValueError.
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
    # Read through this module's ``cfg`` so a test (or a future caller)
    # that stubs ``backups.cfg`` also stubs the overlay.  ``maintenance_env()``
    # always goes back to ``hub.config.cfg`` and would silently pick up the
    # live services.yaml PATH instead.
    # _mapping_get / dict.items: a dict-subclass ``.get`` / ``items()``
    # bomb in settings used to be swallowed by the broad catch around the
    # dump and reported as its failure ("leftover .get bomb") — a lie that
    # blamed pg_dump for a config leftover the dump never even read.
    # _cfg_map, not a bare cfg(): a snapshot provider that raises was the
    # same swallowed-and-blamed lie — the finished artefact discarded and
    # the provider's text reported as pg_dump's failure.
    settings = _mapping_get(_cfg_map(), "settings")
    raw = _mapping_get(settings, "maintenance_env")
    # _isa + a try around the unbound view: a raising ``__class__`` bomb
    # detonated the bare isinstance, and a *lying* ``__class__`` dict
    # impostor passed it and TypeError'd ``dict.items`` — both inside the
    # broad catch around the dump, which ``_discard``'ed the successful
    # artefact and reported descriptor gibberish as pg_dump's failure.
    # A junk overlay is junk, not an environment: skip it, keep the dump.
    if _isa(raw, dict):
        try:
            entries = list(dict.items(raw))
        except Exception:
            entries = []
        # leftover RecursionError on ``str(env-item)`` / leftover ``\\ud800``
        # used to UnicodeEncodeError Popen on POST /api/backups.
        env.update({
            _as_text(k): _as_text(v) for k, v in entries if _as_text(k)
        })
    password = _pg_password(target["id"])
    if not password and target["password_env"]:
        password = _as_text(env.get(target["password_env"]) or "")
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


def apply_restore_path(hint: str, path: str) -> str:
    """Put *path* into a hint without treating the rest as format fields.

    Hints for configured pg targets already interpolate host/user/db via an
    f-string.  ``str.format(path=…)`` then re-parses the whole string, so a
    user or database name containing braces raised KeyError and 500'd the
    Backups page.  The only placeholder these templates use is ``{path}``.
    """
    if not hint:
        return ""
    return hint.replace("{path}", str(path))


def backup_root_text() -> str:
    """:data:`BACKUP_ROOT` as UTF-8-clean text for the GET /api/backups payload.

    A BACKUP_ROOT under an undecodable HOME carries lone surrogates
    (os surrogateescape); the route's bare ``str()`` used to 500 the whole
    Backups page at Starlette's UTF-8 encode while every row it listed was
    already scrubbed.
    """
    return _as_text(BACKUP_ROOT)


def scan_backups() -> list:
    """Every backup artefact found, newest first and not truncated.

    The page needs both the rows and how many exist: it renders a capped list,
    and silently dropping the rest is how an operator comes to believe backups
    older than the cap were deleted.
    """
    items = []
    # _user_home, not the bare seam: a raising or text-answering provider
    # used to 500 this join — and with it the whole GET /api/backups page.
    home = _user_home()
    roots = [BACKUP_ROOT, DATA_DIR]
    if home is not None:
        roots.insert(1, home / "Services" / "teslamate" / "backups")
    for root in roots:
        try:
            if not root.is_dir():
                continue
            found = list(root.rglob("*"))
        except OSError:
            continue
        for p in found:
            try:
                if not p.is_file():
                    continue
            except OSError:
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
            except OSError:
                continue
            nums = _stat_numbers(st)
            if nums is None:
                continue
            size, mtime = nums
            try:
                hint = restore_hint(name)
                items.append({
                    "path": _as_text(p),
                    "name": _as_text(name),
                    "dir": _as_text(p.parent),
                    "size_mb": round(size / 1024 / 1024, 2),
                    "mtime": mtime,
                    "restore": _as_text(apply_restore_path(hint, str(p))),
                })
            except OSError:
                pass
    items.sort(key=lambda x: x["mtime"], reverse=True)
    return items


def _pg18_dump() -> Path | None:
    for path in _PG18_DUMPS:
        try:
            if path.is_file() and os.access(path, os.X_OK):
                return path
        except OSError:
            # Dying FUSE/SMB: is_file() re-raises EIO/ESTALE.
            continue
    return None


def _immich_latest() -> dict | None:
    try:
        if not BACKUP_ROOT.is_dir():
            return None
        paths = list(BACKUP_ROOT.glob("immich_*.sql.gz"))
    except OSError:
        return None
    ranked: list[tuple[float, Path]] = []
    for p in paths:
        try:
            ranked.append((p.stat().st_mtime, p))
        except OSError:
            continue
    if not ranked:
        return None
    ranked.sort(key=lambda item: item[0], reverse=True)
    latest = ranked[0][1]
    try:
        st = latest.stat()
    except OSError:
        return None
    nums = _stat_numbers(st)
    if nums is None:
        return None
    size, mtime = nums
    return {
        "name": latest.name,
        "mtime": mtime,
        "size_mb": round(size / 1024 / 1024, 2),
    }


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
    # _isa on the gate, try on the decode: a raising ``__class__`` bomb
    # detonated the bare isinstance; a lying ``__class__`` impostor (claims
    # bytes, is not) TypeErrors the unbound decode and renders below.
    if _isa(value, (bytes, bytearray)):
        try:
            return _decode_bytes(value)
        except Exception:
            return ""
    try:
        text = str(value)
    except RecursionError:
        try:
            return type(value).__name__
        except Exception:
            return ""
    except Exception:
        return ""
    # Unbound base encode: ``str()`` of a subclass whose ``__str__`` answers
    # *self* skips CPython's exact-str copy, so a leftover bound ``encode``
    # bomb rode this line to a 500 — at value, nested and mapping-key rank.
    return str.encode(text, "utf-8", "replace").decode("utf-8")


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's encoder cannot 500 GET /api/backups.

    PhotosHub ``1e400`` floats in dicts/lists were already dropped; bytes,
    tuple-inf, and ``.inf`` keys still leaked into the page payload.
    A leftover ``\\ud800`` in ``reason`` / ``size_human`` / a status key
    still 500'd the same encoder (``ensure_ascii=False`` then UTF-8).
    A >4300-digit int still passed through untouched: CPython's int->str
    digit limit then ValueError'd ``json.dumps`` itself.
    Subclass bombs (the hub.modules._jsonable unbound convention this copy
    never got) each 500'd the page out of ``_json_object``, whose
    ``_jsonable(raw)`` call sits outside its load-time catch: a dict whose
    ``items()`` raises, a container whose ``__iter__`` raises, an int whose
    ``__str__`` blows the digit-cap probe, a float whose ``__eq__`` blows
    the NaN/inf probes, bytes whose ``decode`` raises, and an ``isoformat``
    probe on an object whose ``__getattr__`` raises.
    """
    if depth > 32:
        return None
    # _isa on every rank gate (the ollama10 parity): a raising ``__class__``
    # bomb used to detonate the first bare isinstance; a *lying* ``__class__``
    # impostor passes the gate and must drop at its unbound base call instead
    # of riding the claimed rank into the encoder.
    if value is None:
        return value
    if _isa(value, bool):
        # ``bool`` cannot be subclassed, so anything passing this gate that
        # is not the exact type is a lying ``__class__`` impostor (the
        # dash10/json9 shape).  It used to be returned verbatim — every
        # other liar drops at its unbound base call, but the bool gate had
        # nothing to call — and the C-level JSON encoder then refused it.
        return value if type(value) is bool else None
    if _isa(value, int):
        if type(value) is not int:
            try:
                # Base coercion to an exact int: a subclass ``__str__``
                # bomb used to blow the digit-cap probe below.
                value = int.__index__(value)
            except Exception:
                return None
        try:
            str(value)
        except ValueError:
            # Past CPython's int->str digit cap the encoder cannot render
            # the number at all — same drop as its inf float sibling.
            return None
        return value
    if _isa(value, float):
        if type(value) is not float:
            try:
                # Base coercion to an exact float: a subclass ``__eq__``
                # bomb used to blow the NaN/inf probes below.
                value = float.__float__(value)
            except Exception:
                return None
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if _isa(value, str):
        return _utf8_text(value)
    if _isa(value, (bytes, bytearray)):
        try:
            # The try is for a lying ``__class__`` (claims bytes, is not):
            # the unbound decode TypeErrors and the impostor drops.
            return _decode_bytes(value)
        except Exception:
            return None
    if _isa(value, dict):
        out = {}
        # Unbound base view: a dict subclass whose ``items()`` raises used
        # to 500 the page; the real storage underneath still comes through.
        # The try is for a lying-``__class__`` dict impostor, which
        # TypeErrors the unbound view itself.
        try:
            entries = list(dict.items(value))
        except Exception:
            return None
        for k, v in entries:
            if _isa(k, (bytes, bytearray)):
                try:
                    k = _decode_bytes(k)
                except Exception:
                    continue
            elif not _isa(k, str):
                try:
                    k = str(k)
                except Exception:
                    continue
            out[_utf8_text(k)] = _jsonable(v, depth + 1)
        return out
    if _isa(value, (list, tuple, set, frozenset)):
        for base in (list, tuple, set, frozenset):
            if _isa(value, base):
                # Unbound base iteration: a subclass ``__iter__`` bomb
                # cannot 500 and the real elements still survive.  The
                # try is for a lying-``__class__`` impostor, which
                # TypeErrors the unbound iteration itself.
                try:
                    items = list(base.__iter__(value))
                except Exception:
                    return None
                return [_jsonable(v, depth + 1) for v in items]
    try:
        iso = getattr(value, "isoformat", None)
    except Exception:
        # getattr's default only swallows AttributeError; a property or
        # ``__getattr__`` bomb still raised out of the probe itself.
        iso = None
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/backups.
            return _jsonable(iso(), depth + 1)
        except Exception:
            return None
    try:
        return _utf8_text(value)
    except Exception:
        return None


def _capped_json_int(text):
    """``json.loads`` parse_int hook: an over-cap digit run drops to None.

    ``int()`` of a >4300-digit number is the digit-cap *ValueError* (not
    JSONDecodeError) for the whole document.  One poisoned number used to
    wipe whole Backups stores at once: a status counter in
    panel_status.json / backup_status.json blanked every layer card on the
    page; a stray stamp beside a target's entry in backup-credentials.json
    read the *password* back as "" (the dump then ran unauthenticated and
    failed); a huge label in resolved compose JSON refused the whole stack
    backup as ``compose_config_failed``; and one in an inflight marker made
    crash recovery forget which compose file to ``start``.  Dropping just
    the number keeps the document, same as the notify_channels /
    smart_test_svc / docker_cli hooks.
    """
    try:
        return int(text)
    except ValueError:
        return None


def _json_object(path: Path) -> dict:
    try:
        # Leftover directory named backup_status.json is IsADirectoryError;
        # a dying FUSE mount re-raises EIO from is_file() itself.
        if not path.is_file():
            return {}
        raw = safe_json_loads(
            read_text_capped(path, _JSON_CAP, encoding="utf-8"),
            parse_int=_capped_json_int,
        )
    except (OSError, ValueError, RecursionError):
        # ValueError covers json.JSONDecodeError *and* UnicodeDecodeError:
        # a torn panel_status.json used to 500 the Backups page.
        # RecursionError: leftover deeply-nested status is not ValueError.
        return {}
    raw = _jsonable(raw) if isinstance(raw, dict) else {}
    return raw if isinstance(raw, dict) else {}


def _path_state(raw: object) -> dict:
    text = str(raw or "").strip()
    if not text:
        return {"path": "", "present": False}
    try:
        present = Path(text).is_dir()
    except (OSError, ValueError):
        present = False
    return {"path": text, "present": present}


def _status_snippet(raw: dict) -> dict:
    """Keep only the fields the Backups page renders — never the whole file."""
    if not isinstance(raw, dict):
        return {}
    out = {}
    for key in ("ok", "last_success", "last_attempt", "size_human", "reason"):
        if key not in raw:
            continue
        value = _jsonable(raw[key])
        if value not in (None, ""):
            out[key] = value
    return out


def _immich_media_from_env() -> str:
    env = IMMICH_ROOT / ".env"
    try:
        if not env.is_file():
            return ""
        lines = read_text_capped(env, _ENV_CAP, encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
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
        try:
            root = Path(generated_root["path"])
        except (OSError, ValueError, TypeError):
            root = None
        if root is not None:
            generated_dirs = []
            for name in _GENERATED_DIRS:
                try:
                    present = (root / name).is_dir()
                except OSError:
                    present = False
                generated_dirs.append({"name": name, "present": present})
    last = _immich_latest()
    restore = ""
    if last:
        hint = restore_hint(last["name"])
        restore = apply_restore_path(hint, str(BACKUP_ROOT / last["name"]))
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
    payload = {
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
    # Leftover Infinity in backup_status.json / panel_status.json used to
    # leak into GET /api/backups under Starlette's allow_nan=False encoder.
    cleaned = _jsonable(payload)
    return cleaned if isinstance(cleaned, dict) else payload


def immich_backup_info() -> dict:
    """Whether the Immich dump can run here, plus the post-redesign layout."""
    via = ""
    try:
        script_ok = IMMICH_SCRIPT.is_file() and os.access(IMMICH_SCRIPT, os.X_OK)
    except OSError:
        script_ok = False
    if script_ok:
        via = "script"
    else:
        try:
            native_ok = _pg18_dump() is not None and IMMICH_DB_ENV.is_file()
        except OSError:
            native_ok = False
        if native_ok:
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
    try:
        lines = read_text_capped(IMMICH_DB_ENV, _ENV_CAP, encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise RuntimeError("Immich db.env is unreadable") from exc
    for line in lines:
        if line.startswith("DB_URL="):
            raw = line.split("=", 1)[1].strip().strip("\"'")
            break
    try:
        # A torn IPv6 literal in the netloc ("[::1" with no closing bracket)
        # makes urlsplit — which urlparse calls — raise ValueError("Invalid
        # IPv6 URL"), the catalog5 leftover class.  That is a raw stdlib error,
        # not this helper's documented RuntimeError, and but for the caller's
        # broad catch it would surface CPython-internal text ("Invalid IPv6
        # URL") as the immich dump's failure instead of a coded reason.  A
        # torn DB_URL means the same operator-facing state every other bad
        # db.env here gets: unusable, raise the coded refusal.
        parsed = urlparse(raw) if raw else None
    except ValueError as exc:
        raise RuntimeError("Immich db.env has an unparsable DB_URL") from exc
    password = unquote(parsed.password) if parsed and parsed.password else ""
    if not password:
        raise RuntimeError("Immich db.env has no usable DB_URL password")
    try:
        # ``.port`` re-parses the netloc and raises ValueError on an
        # out-of-range or non-numeric port ("host:99999999999999999999",
        # "host:notaport") — the same raw stdlib leak as the torn bracket
        # above, and accessed unguarded twice below.  Read it once, coded.
        port = parsed.port if parsed and parsed.port else 5433
    except ValueError as exc:
        raise RuntimeError("Immich db.env DB_URL port is out of range") from exc
    return {
        "host": (parsed.hostname if parsed and parsed.hostname else "127.0.0.1"),
        "port": port,
        "user": unquote(parsed.username) if parsed and parsed.username else "immich",
        "db": (parsed.path or "/immich").lstrip("/") or "immich",
        "password": password,
    }


def backup_immich() -> dict:
    """Dump the Immich PostgreSQL 18 database to ``immich_*.sql.gz``."""
    with _only_one("immich"):
        return _backup_immich()


def _immich_unavailable() -> dict:
    """The coded refusal the up-front availability gate gives.

    Shared with the vanished-binary path below, so a script that disappears
    between the ``immich_backup_info()`` probe and the spawn answers exactly
    like one that was never there.
    """
    return {
        "ok": False,
        "error": "not_configured",
        "message": "Immich backup is not available "
                   "(need ~/Services/immich/backup-db.sh or "
                   "postgresql@18 plus db.env)",
    }


def _backup_immich() -> dict:
    info = immich_backup_info()
    if not info["available"]:
        return _immich_unavailable()
    if info["via"] == "script":
        return _backup_immich_script()
    return _backup_immich_native()


def _backup_immich_script() -> dict:
    """The host script already pins PG18, gzips, checks the tail, and prunes."""
    try:
        before = (
            {p.name for p in BACKUP_ROOT.glob("immich_*.sql.gz")}
            if BACKUP_ROOT.is_dir() else set()
        )
    except OSError:
        before = set()
    try:
        rc, text = run_capped(
            [str(IMMICH_SCRIPT)], timeout=600, cwd=str(IMMICH_ROOT),
        )
        text = _as_text(text)
        # _exit_code beside _as_text: the rc half of the seam still ran raw
        # dunders through ``rc == 0`` and ``_exit_text`` *outside* this try,
        # so an int-subclass ``__eq__`` / ``__str__`` bomb 500'd the route
        # after the script had already produced its artefact.
        rc = _exit_code(rc)
    except Exception as exc:
        # leftover ``str(exc)`` RecursionError / ``\\ud800`` used to 500 POST /api/backups.
        return {"ok": False, "message": _as_text(exc)[:500]}
    if _cli_vanished(rc, text, IMMICH_SCRIPT):
        # immich_backup_info() said "script", but it vanished between that
        # probe and this spawn.  Answer with the same coded refusal the
        # up-front gate gives instead of the bare "not found" sentinel
        # run_capped leaves in message.
        return _immich_unavailable()
    latest = _immich_latest()
    created = latest and latest["name"] not in before
    ok = rc == 0 and bool(created)
    return {
        "ok": ok,
        # _as_text: an artefact whose on-disk name is undecodable surfaces
        # as lone surrogates (os surrogateescape); raw, it used to 500
        # POST /api/backups/immich at Starlette's UTF-8 encode.  The
        # created-check above stays raw on purpose — it compares glob
        # results with glob results.
        "path": _as_text(BACKUP_ROOT / latest["name"]) if ok and latest else None,
        "message": (text or _exit_text(rc))[:500],
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
        return {"ok": False, "message": _as_text(exc)[:200]}

    stamp = strftime_now("%Y%m%d_%H%M%S", "0")
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
            try:
                dump = subprocess.Popen(
                    argv, stdout=subprocess.PIPE, stderr=errfile, env=utf8_env(env),
                    start_new_session=True,
                )
            except FileNotFoundError:
                # pg18 vanished between the _pg18_dump() probe and this spawn
                # (a brew uninstall mid-request, a dying mount).  Answer with
                # the same message the up-front probe gives instead of an
                # uncoded "[Errno 2] ..." the SPA cannot translate.  Only the
                # missing-binary spawn classifies: a PermissionError or any
                # other OSError keeps the raw message below — that is then
                # the truth.
                _discard(dest)
                return {"ok": False,
                        "message": "postgresql@18 pg_dump is not installed"}

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
                # Callers only surface [:500]; an unbounded read of a
                # chatty pg_dump stderr used to RSS-bomb the panel.
                err_text = errfile.read(2048).decode("utf-8", "replace")
    except RecursionError:
        _discard(dest)
        return {"ok": False, "message": (err_text or "immich dump failed")[:500]}
    except Exception as exc:
        _discard(dest)
        return {"ok": False, "message": (err_text or _as_text(exc))[:500]}
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
        # _as_text on both: a BACKUP_ROOT under an undecodable HOME carries
        # lone surrogates, and raw they 500'd POST /api/backups/immich at
        # Starlette's UTF-8 encode — on the successful run.
        "path": _as_text(dest),
        "message": f"immich backup ok: {_as_text(dest.name)}",
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
    stamp = strftime_now("%Y%m%d_%H%M%S", "0")
    dest = _private_dest(BACKUP_ROOT / f"{target['id']}_{stamp}.sql.bak")
    cmd = _pg_dump_argv(target, dest)
    try:
        rc, text = run_capped(cmd, timeout=600, env=_pg_env(target))
        text = _as_text(text)
        # _exit_code beside _as_text: an int-subclass ``__eq__`` bomb in the
        # rc half of the seam used to raise at ``ok = rc == 0`` inside this
        # broad catch — the *successful* dump was ``_discard``'ed and the
        # 200 lied ok:false with the bomb's text as the dump's failure.
        rc = _exit_code(rc)
        if _cli_vanished(rc, text, cmd[0]):
            # pg_dump itself could not be spawned — never installed, or
            # uninstalled while this ran.  The coded 503 instead of the
            # two-word "not found" the sentinel leaves in message.
            _discard(dest)
            raise api_error("backup.tool_missing", tool="pg_dump")
        # Size, not existence: the destination was pre-created 0600 so pg_dump
        # could not publish it, which means it exists even when the dump failed.
        size = _written_bytes(dest)
        ok = rc == 0 and size > 0
        if not ok:
            _discard(dest)
        else:
            _prune(f"{target['id']}_*.sql.bak")
        return {
            "ok": ok,
            # _as_text: a BACKUP_ROOT under an undecodable HOME surfaces as
            # lone surrogates (os surrogateescape); raw, the *successful*
            # dump used to 500 POST /api/backups/postgres at Starlette's
            # UTF-8 encode.  _discard/_prune above keep the raw Path.
            "path": _as_text(dest) if ok else None,
            "message": (text or _exit_text(rc))[:500],
            "size_mb": round(size / 1024 / 1024, 2) if ok else 0,
        }
    except HTTPException:
        # The coded refusal above must reach the route, not be flattened
        # into an uncoded ok:false by the broad catch below.
        raise
    except RecursionError:
        _discard(dest)
        return {"ok": False, "message": "dump failed"}
    except Exception as e:
        _discard(dest)
        return {"ok": False, "message": _as_text(e)}


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
    extras = _mapping_get(_config_archive_cfg(), "agent_keywords")
    # _isa, not bare isinstance: a keywords list (or entry) whose ``__class__``
    # is a raising property detonated these gates and 500'd
    # POST /api/backups/configs instead of degrading to the defaults.
    if _isa(extras, list):
        for kw in _iter_list(extras):
            if _isa(kw, str):
                # _exact_str first: a str-subclass entry whose bound
                # ``.strip()`` / ``__eq__`` raises used to 500
                # POST /api/backups/configs as soon as one LaunchAgents
                # plist was up for the _wanted_agent test.
                kw = _exact_str(kw)
                if kw is None:
                    continue
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
    raw = _mapping_get(_config_archive_cfg(), "extra_paths")
    # _isa, not bare isinstance: an extra_paths list (or entry) whose
    # ``__class__`` is a raising property detonated these gates and 500'd
    # POST /api/backups/configs out of this loop.
    if not _isa(raw, list):
        return out
    for entry in _iter_list(raw):
        if not _isa(entry, str):
            continue
        # _exact_str first: a str-subclass entry whose bound ``.strip()``
        # raises used to 500 POST /api/backups/configs out of this loop.
        entry = _exact_str(entry)
        if entry is None or not entry.strip():
            continue
        try:
            path = Path(os.path.expanduser(entry.strip()))
        except (OSError, ValueError, RuntimeError):
            # RuntimeError: leftover HOME unset on a ``~/…`` extra_paths entry.
            continue
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


def _run_argv(argv: list[str], *, timeout: int, cap: int = 4000) -> tuple[int, str, str]:
    """All subprocesses of the stack backup go through one seam.

    Exists so the tests can replace every docker/tar invocation with a fake
    and assert on the exact call order — most importantly that ``compose
    start`` happens even when the archive step blows up.

    *cap* defaults to a 4KB trailing window for chatter (stop/start/tar).
    Callers that parse structured stdout (resolved compose JSON) pass a
    larger cap so ``run_capped``'s tail window still covers the whole
    document.
    """
    try:
        rc, text = run_capped(argv, timeout=timeout, cap=cap)
        # Combined stream: callers already do ``(err or out)``.
        # Leftover bytes/None used to TypeError ``.strip()`` / JSON-encode
        # POST /api/backups/stack and the postgres/immich/config dumps.
        # _exit_code on the rc half: _backup_stack compares ``rc != 0``
        # bare (including in its finally-restart), so a seam rc bomb used
        # to raise past the one promise this module makes — the compose
        # start after an attempted stop — and out into the scheduler run.
        # Junk that cannot coerce maps to the same -1 the except arm uses.
        rc = _exit_code(rc)
        return (-1 if rc is None else rc), _as_text(text), ""
    except Exception as e:  # noqa: BLE001 — a backup step must report, not raise
        return -1, "", _as_text(e)


def _engine_up(force: bool = False) -> bool:
    from hub.docker_cli import engine_up
    return engine_up(force=force)


def _looks_engine_down(text) -> bool:
    from hub.docker_cli import looks_engine_down
    return looks_engine_down(text)


def _docker_vanished(text) -> bool:
    """True when a stack-backup docker step's failure text is run_capped's
    FileNotFoundError sentinel: the docker CLI itself could not be spawned
    (vanished between the entry engine probe and this exec).

    Purely a message-pattern gate like :func:`_looks_engine_down` — callers
    must still confirm with a forced ``_engine_up`` probe, which cannot
    answer "up" while the CLI is gone, so a step whose real output happens
    to read "not found" while the engine answers "up" keeps its original
    failure mapping.
    """
    return _as_text(text).strip() == "not found"


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
        cap=_COMPOSE_JSON_CAP,
    )
    if rc != 0 or not out.strip():
        return [], [], (err or out or f"compose config {_exit_text(rc)}").strip()[:300]
    try:
        # parse_int hook: one leftover >4300-digit number anywhere in the
        # resolved config (a label, an x- extension) used to ValueError the
        # decode itself and refuse the whole stack backup as
        # ``compose_config_failed`` — a number tar never even looks at.
        resolved = safe_json_loads(out, loads=json.loads, parse_int=_capped_json_int)
    except (TypeError, ValueError, RecursionError) as e:
        # RecursionError: leftover deeply-nested compose JSON is not ValueError.
        return [], [], "unparsable compose config: " + (_as_text(e) or "error")
    if not isinstance(resolved, dict):
        return [], [], "compose config is not an object"

    volume_names: dict[str, str] = {}
    declared = resolved.get("volumes") or {}
    if not isinstance(declared, dict):
        declared = {}
    for key, spec in declared.items():
        name = (spec or {}).get("name") if isinstance(spec, dict) else None
        volume_names[key] = str(name or key)

    binds: list[str] = []
    volumes: list[str] = []
    services = resolved.get("services") or {}
    if not isinstance(services, dict):
        services = {}
    for svc in services.values():
        if not isinstance(svc, dict):
            continue
        raw_vols = svc.get("volumes")
        if not isinstance(raw_vols, list):
            continue
        for entry in raw_vols:
            if not isinstance(entry, dict):
                continue
            kind = entry.get("type")
            source = str(entry.get("source") or "")
            if kind == "bind" and source.startswith("/"):
                try:
                    p = Path(source)
                    # Sockets (docker.sock) and device nodes are wiring, not data.
                    if not (p.is_dir() or p.is_file()) or p.is_socket():
                        continue
                except (OSError, ValueError):
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
        try:
            ts = int(time.time())
        except (TypeError, ValueError, OverflowError):
            ts = 0
        payload = _jsonable({
            "stack": stack_id,
            "compose_path": compose_path,
            "ts": ts,
        })
        if not isinstance(payload, dict):
            payload = {}
        secure_io.replace_bytes(
            _inflight_marker(stack_id),
            (json.dumps(payload, allow_nan=False) + "\n").encode("utf-8"),
        )
    except (OSError, TypeError, ValueError, OverflowError, RecursionError):
        # RecursionError: leftover nested inflight marker after _jsonable is not ValueError.
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
            # parse_int hook: a leftover >4300-digit ``ts`` used to ValueError
            # the decode, so recovery forgot the recorded compose_path and —
            # unless the stack was still discoverable — left it stopped.
            info = safe_json_loads(
                read_text_capped(marker, _MARKER_CAP), parse_int=_capped_json_int,
            )
        except (OSError, ValueError, RecursionError):
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
                f"compose start {_exit_text(rc)}: {(err or out).strip()[:200]}"
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
        # _as_text on both: an undecodable marker *filename* (os
        # surrogateescape) or a ``\ud800`` escape in the marker JSON put lone
        # surrogates in this row, and the returned list feeds JSON encoders
        # the same way every other result in this module does.  The raw
        # stack_id above stays raw on purpose — _find_stack must keep
        # matching a stack whose own id carries the same surrogates.
        recovered.append({
            "stack": _as_text(stack_id),
            "started": started,
            "detail": _as_text(detail),
        })
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
        # The _engine_up() gate above trusts a 5s memo, so an engine that dies
        # inside the TTL still reaches `compose config` — classify with a
        # forced probe instead of blaming the compose file.  A docker CLI
        # that vanished in the same window is the same operator-facing state
        # (docker is unreachable) and takes the same coded path.  A failure
        # while the engine answers "up" keeps compose_config_failed and its
        # message.
        if (
            (_looks_engine_down(mounts_err) or _docker_vanished(mounts_err))
            and not _engine_up(force=True)
        ):
            log.append("!! the Docker engine is not running")
            return {"ok": False, "error": "engine_down",
                    "message": "the Docker engine is not running"}
        log.append(f"!! {mounts_err}")
        return {"ok": False, "error": "compose_config_failed", "message": mounts_err}

    stamp = strftime_now("%Y%m%d_%H%M%S", "0")
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
                log.append(f"!! compose stop {_exit_text(rc)}: {(err or out).strip()[:200]}")

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
                text = (err or out).strip()
                if (
                    (_looks_engine_down(text) or _docker_vanished(text))
                    and not _engine_up(force=True)
                ):
                    # The engine died mid-job — or the docker CLI itself
                    # vanished: the coded state, not the raw daemon stderr or
                    # the spawn sentinel, is what the scheduler log should
                    # carry.
                    error = "engine_down"
                    message = "the Docker engine is not running"
                else:
                    error = "volume_export_failed"
                    message = f"volume export failed for {name}: {text[:200]}"
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
                message = (err or out or f"tar {_exit_text(rc)}").strip()[:300]
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
                log.append(f"!! compose start {_exit_text(rc)}: {(err or out).strip()[:200]}")
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
        # _as_text: this result lands in the scheduler journal and its JSON
        # encoders; a surrogate-HOME dest is the same 500 class as the
        # postgres/configs paths above.
        "path": _as_text(dest) if archive_ok else None,
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
    stamp = strftime_now("%Y%m%d_%H%M%S", "0")
    # services.yaml first (the member a restorer looks for), then the data/
    # credential and state files, then the install's own extras.  tar records
    # each member's mode, so the 0600 files come back 0600 -- the archive
    # itself is 0600 in a 0700 directory via _private_dest, same as before.
    paths = [CONFIG_FILE, *data_state_paths(), *config_archive_extra_paths()]
    # include launchagents selectively
    # _user_home, not the bare seam: a raising or text-answering provider
    # used to 500 POST /api/backups/configs at this join, outside the tar try.
    home = _user_home()
    agents = (home / "Library" / "LaunchAgents") if home is not None else None
    try:
        if agents is not None and agents.is_dir():
            for pl in agents.glob("*.plist"):
                if _wanted_agent(pl.name):
                    paths.append(pl)
    except OSError:
        pass
    existing = []
    for p in paths:
        try:
            if p.exists():
                existing.append(str(p))
        except OSError:
            continue
    # "At least one file exists" was the old guard, and it let the one member
    # anyone would ever restore from go missing silently: with services.yaml
    # absent but a single plist present, tar succeeded, the size was plausible,
    # and the row in the table looked exactly like a good backup.  A config
    # archive without the config is not a partial success, it is a failure.
    if str(CONFIG_FILE) not in existing:
        return {
            "ok": False,
            # _as_text: CONFIG_FILE under an undecodable HOME carries lone
            # surrogates; raw, this refusal itself used to 500 the route.
            "message": (
                f"refusing to write a config backup without "
                f"{_as_text(CONFIG_FILE.name)}: "
                f"{_as_text(CONFIG_FILE)} is missing or unreadable"
            ),
        }
    # Created only now that there is something to archive, so a no-op call does
    # not leave an empty placeholder behind in the backup listing.  The *returned*
    # path is what tar writes to: passing the original back in would reintroduce
    # the truncation this function is guarding against, because _private_dest
    # hands back a different name when the first one is taken.
    dest = _private_dest(BACKUP_ROOT / f"configs_{stamp}.tgz")
    try:
        rc, text = run_capped(
            ["/usr/bin/tar", "czf", str(dest)] + existing,
            timeout=120,
        )
        text = _as_text(text)
        # _exit_code beside _as_text: same rc-seam rule as the postgres dump
        # — a subclass ``__eq__`` bomb used to discard the finished archive
        # inside the broad catch and report a 200 that lied ok:false.
        rc = _exit_code(rc)
        if _cli_vanished(rc, text, "/usr/bin/tar"):
            # tar itself could not be spawned: the coded 503 instead of the
            # bare "not found" sentinel in an uncoded ok:false.
            _discard(dest)
            raise api_error("backup.tool_missing", tool="/usr/bin/tar")
        # This archive contains services.yaml, so judge success by size: the
        # placeholder always exists after _private_dest.
        size = _written_bytes(dest)
        ok = rc == 0 and size > 0
        if not ok:
            _discard(dest)
        else:
            _prune("configs_*.tgz")
        return {
            "ok": ok,
            # _as_text: same surrogate-HOME rule as the postgres dump above.
            "path": _as_text(dest) if ok else None,
            "message": (text or "")[:500] or ("ok" if ok else "fail"),
            "size_mb": round(size / 1024 / 1024, 2) if ok else 0,
        }
    except HTTPException:
        # The coded refusal above must reach the route, not be flattened
        # into an uncoded ok:false by the broad catch below.
        raise
    except Exception as e:
        _discard(dest)
        return {"ok": False, "message": _as_text(e)}
