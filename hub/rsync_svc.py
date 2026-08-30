"""Scheduled rsync backups: binary detection, hardened argv, dry-run preview.

macOS ships two very different rsyncs.  Homebrew installs rsync 3.x
(``/opt/homebrew/bin/rsync``), which has ``--itemize-changes``,
``--info=progress2``, ``-z`` and ``--bwlimit``; stock macOS since Sequoia
ships openrsync at ``/usr/bin/rsync``, which speaks the same protocol but
supports only the classic flag set.  The probe below records which one is in
use and every command is built strictly from its advertised capabilities, so
a job configured with compression on a brew machine still runs (without
compression) after the operator uninstalls brew — degraded, not broken.

Argument hardening: every user-controlled value lands in the argv either as a
validated absolute path (must start with ``/``), a validated ``user@host:path``
remote spec (must start with an alphanumeric), or glued into a single
``--exclude=PATTERN`` token — so no configured value can ever be parsed as an
rsync option (the ``dig -f /etc/passwd`` class of injection hub/cli_args.py
exists to stop).
"""
from __future__ import annotations

import os
import re
import signal
import subprocess
import threading
from pathlib import Path

from hub import secure_io
from hub.errors import api_error
from hub.jobs import run_watchdog
from hub.paths import DATA_DIR
from hub.util import cached_snapshot, iter_capped_lines, sh, strftime_now, utf8_env

#: Probe order: brew's rsync 3.x first (both prefixes), Apple's last.
CANDIDATES = (
    "/opt/homebrew/bin/rsync",
    "/usr/local/bin/rsync",
    "/usr/bin/rsync",
)

RUN_LOG_ROOT = DATA_DIR / "backup-runs"
#: Logs kept per job; one file per run.
KEEP_LOGS = 20

DIRECTIONS = ("push", "pull")

#: ``user@host:path`` — the leading alphanumeric is what makes the whole spec
#: unable to masquerade as an option, mirroring hub/cli_args.py.
_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ADDR_REPR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")


def _isinst(value, types) -> bool:
    """``isinstance`` that a leftover ``__class__`` bomb cannot 500 through.

    CPython's ``isinstance`` reads the operand's ``__class__`` whenever the
    real-type fast check misses, so a leftover whose ``__class__`` is a
    raising property blew unguarded gates in :func:`_local_path_ok`,
    :func:`_remote_ok`, :func:`validated` and the capability dict walk —
    POST rsync preview / scheduled backup argv answered HTTP 500 instead
    of a coded ``rsync.bad_params``.  Fail-closed.  Bool leftovers stay
    ``type(x) is bool``.
    """
    try:
        return isinstance(value, types)
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return False

_REMOTE_RE = re.compile(
    r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}@[A-Za-z0-9][A-Za-z0-9._-]{0,252}:(.+)\Z",
    re.DOTALL,
)

def _has_control_chars(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        # Leftover ``\ud800`` used to UnicodeEncodeError Popen on POST preview.
        return True
    return any(ord(c) < 0x20 or ord(c) == 0x7F for c in text)


def _as_text(value) -> str:
    """``sh`` leftovers arrive as int/None/bytes; leftover ``\\ud800`` used to 500 rsync preview JSON."""
    if value is None:
        return ""
    for base in (bytes, bytearray):
        try:
            return base.decode(value, "utf-8", "replace")
        except _CONTROL_FLOW:
            raise
        except BaseException:
            continue
    try:
        return str.encode(str.__str__(value), "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        pass
    try:
        cls = type(value)
        if cls.__str__ is object.__str__ and cls.__repr__ is object.__repr__:
            return ""
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    try:
        text = str(value)
    except RecursionError:
        try:
            return type(value).__name__
        except _CONTROL_FLOW:
            raise
        except BaseException:
            return ""
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    try:
        text = str.encode(text, "utf-8", "replace").decode("utf-8")
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return ""
    return "" if _ADDR_REPR_RE.search(text) else text


def probe_rsync() -> dict:
    """Locate a usable rsync and record what it can do.  Uncached."""
    for path in CANDIDATES:
        try:
            if not Path(path).is_file():
                continue
        except (OSError, ValueError):
            # Dying FUSE/SMB: is_file() re-raises EIO/ESTALE; leftover NUL is ValueError.
            continue
        rc, out, err = sh([path, "--version"], timeout=10)
        if rc != 0:
            continue
        blob = f"{_as_text(out)}\n{_as_text(err)}"
        lowered = blob.lower()
        if "openrsync" in lowered:
            variant = "openrsync"
        elif re.search(r"version\s+[3-9]\.", blob):
            variant = "rsync3"
        else:
            variant = "unknown"
        modern = variant == "rsync3"
        m = re.search(r"version\s+([\d.]+)", blob)
        return {
            "available": True,
            "path": path,
            "variant": variant,
            "version": m.group(1) if m else "",
            # Conservative by design: anything not positively identified as
            # rsync 3.x gets the lowest-common-denominator flag set.
            "supports": {
                "itemize": modern,
                "progress2": modern,
                "compress": modern,
                "bwlimit": modern,
            },
        }
    return {
        "available": False, "path": "", "variant": "none", "version": "",
        "supports": {"itemize": False, "progress2": False,
                     "compress": False, "bwlimit": False},
    }


@cached_snapshot(300.0)
def binary_info() -> dict:
    """Cached :func:`probe_rsync`; the installed binaries do not change per request."""
    return probe_rsync()


def invalidate() -> None:
    binary_info.invalidate()


# ── parameter validation ─────────────────────────────────────────────────────

def _local_path_ok(value: object) -> bool:
    """An absolute local path that cannot be read as an option."""
    if not _isinst(value, str):
        return False
    text = value
    if not text or text != text.strip() or _has_control_chars(text):
        return False
    return text.startswith("/") and len(text) <= 1024


def _remote_ok(value: object) -> bool:
    if not _isinst(value, str) or _has_control_chars(value) or len(value) > 1024:
        return False
    m = _REMOTE_RE.match(value)
    if not m:
        return False
    # The path half rides inside the same argv token, but a leading dash there
    # is still nonsense worth refusing at the boundary.
    return not m.group(1).startswith("-")


def validated(params: dict) -> dict:
    """Normalise and validate one rsync job's parameters, or raise api_error.

    Returns ``{direction, src, dest, delete, compress, bwlimit_kbps, exclude}``
    with exactly the values that will be placed into the argv.
    """
    if params is None:
        params = {}
    elif not _isinst(params, dict):
        raise api_error("rsync.bad_params", field="params")
    direction = str(params.get("direction") or "push").strip().lower()
    if direction not in DIRECTIONS:
        raise api_error("rsync.bad_direction", direction=direction)

    src = params.get("src")
    dest = params.get("dest")
    # push: the panel's own data leaves this machine, so the source must be a
    # local path; pull is the mirror image.  The far side of each may be either
    # a second local path (external disk, SMB mount) or user@host:path.
    if direction == "push":
        if not _local_path_ok(src):
            raise api_error("rsync.bad_path", field="src")
        if not (_local_path_ok(dest) or _remote_ok(dest)):
            raise api_error("rsync.bad_dest", field="dest")
    else:
        if not (_local_path_ok(src) or _remote_ok(src)):
            raise api_error("rsync.bad_dest", field="src")
        if not _local_path_ok(dest):
            raise api_error("rsync.bad_path", field="dest")

    exclude: list[str] = []
    raw_ex = params.get("exclude")
    if not _isinst(raw_ex, list):
        raw_ex = []
    for raw in raw_ex:
        pat = str(raw).strip()
        if not pat:
            continue
        if pat.startswith("-") or _has_control_chars(pat) or len(pat) > 256:
            raise api_error("rsync.bad_exclude", pattern=pat[:80])
        exclude.append(pat)

    bwlimit = params.get("bwlimit_kbps")
    if bwlimit not in (None, "", 0):
        try:
            bwlimit = int(bwlimit)
        except (TypeError, ValueError, OverflowError):
            raise api_error("rsync.bad_params", field="bwlimit_kbps")
        if not 1 <= bwlimit <= 10_000_000:
            raise api_error("rsync.bad_params", field="bwlimit_kbps")
    else:
        bwlimit = None

    return {
        "direction": direction,
        "src": str(src),
        "dest": str(dest),
        # --delete is the sharpest edge rsync has; it stays opt-in.
        "delete": bool(params.get("delete")),
        "compress": bool(params.get("compress")),
        "bwlimit_kbps": bwlimit,
        "exclude": exclude,
    }


def build_argv(params: dict, *, dry_run: bool = False, info: dict | None = None) -> list[str]:
    """The exact argv for one run.  Flags degrade to what the binary supports."""
    info = info or binary_info()
    if not info.get("available"):
        raise api_error("rsync.unavailable")
    p = validated(params)
    supports = info.get("supports")
    supports = supports if _isinst(supports, dict) else {}
    argv = [info["path"], "-a"]
    if dry_run:
        argv.append("-n")
    if supports.get("itemize"):
        argv.append("--itemize-changes")
    else:
        # openrsync: -v lists transferred names, the closest itemize substitute.
        argv.append("-v")
    if p["delete"]:
        argv.append("--delete")
    if p["compress"] and supports.get("compress"):
        argv.append("-z")
    if p["bwlimit_kbps"] and supports.get("bwlimit"):
        argv.append(f"--bwlimit={p['bwlimit_kbps']}")
    for pat in p["exclude"]:
        # One token: even a hostile pattern cannot become its own argv element.
        argv.append(f"--exclude={pat}")
    argv.extend([p["src"], p["dest"]])
    return argv


# ── dry-run preview ──────────────────────────────────────────────────────────

_ITEMIZE_CREATE = re.compile(r"\A[<>ch][fdLDS]\+{5,}")
_ITEMIZE_CHANGE = re.compile(r"\A[<>ch][fdLDS]")

#: openrsync/-v noise that is not a file name.
_VERBOSE_NOISE = re.compile(
    r"\A(sending incremental|building file list|sent \d|total size|created directory|\s*\Z)"
)

#: Sample lines kept for the UI; everything past them is counted and dropped.
PREVIEW_SAMPLES = 200
#: Preview deadline.  This runs synchronously inside a request; a tree that a
#: dry-run cannot even *list* in two minutes needs a scheduled job, not a
#: click-and-wait preview.  (Was 600s, which held a request thread — and the
#: browser — for up to ten minutes.)
PREVIEW_TIMEOUT = 120


class _DryRunCounter:
    """Incremental ``--dry-run`` line classifier.

    Exists so :func:`preview` can consume rsync's output as a stream: a
    dry-run over millions of files emits hundreds of MB of listing, and
    buffering it whole (the old ``sh()`` path) put all of it in the panel's
    memory at once.  Only counts and the first :data:`PREVIEW_SAMPLES` sample
    lines survive.
    """

    def __init__(self, *, itemize: bool):
        self.itemize = itemize
        self.creates = self.updates = self.deletes = 0
        self.samples: list[str] = []

    def feed(self, raw: str) -> None:
        line = _as_text(raw).rstrip()
        if not line:
            return
        if line.startswith("*deleting") or line.startswith("deleting "):
            self.deletes += 1
        elif self.itemize:
            if not _ITEMIZE_CHANGE.match(line):
                return
            if _ITEMIZE_CREATE.match(line):
                self.creates += 1
            else:
                self.updates += 1
        else:
            if _VERBOSE_NOISE.match(line):
                return
            # -v cannot tell "new" from "changed"; count everything as update.
            self.updates += 1
        if len(self.samples) < PREVIEW_SAMPLES:
            self.samples.append(line[:300])

    def result(self) -> dict:
        return {
            "creates": self.creates,
            "updates": self.updates,
            "deletes": self.deletes,
            "total": self.creates + self.updates + self.deletes,
            "samples": self.samples,
        }


def parse_dry_run(out: str, *, itemize: bool) -> dict:
    """Summarise a ``--dry-run`` listing into create/update/delete counts."""
    counter = _DryRunCounter(itemize=itemize)
    for raw in _as_text(out).splitlines():
        counter.feed(raw)
    return counter.result()


#: Non-blocking single-flight per parameter set, the backups._only_one refusal
#: pattern: a preview holds a request-thread token for up to PREVIEW_TIMEOUT,
#: and a client that disconnects does not kill the child — so double-clicking
#: "dry run" used to stack full-tree scans until the thread pool starved.
_preview_guard = threading.Lock()
_preview_running: set[tuple] = set()


def _preview_key(p: dict) -> tuple:
    return (p["direction"], p["src"], p["dest"], p["delete"], tuple(p["exclude"]))


def _kill_group(proc: subprocess.Popen) -> None:
    """SIGTERM then SIGKILL the child's whole process group."""
    for sig, grace in ((signal.SIGTERM, 5), (signal.SIGKILL, 5)):
        if proc.poll() is not None:
            return
        try:
            os.killpg(os.getpgid(proc.pid), sig)
        except (ProcessLookupError, PermissionError):
            return
        try:
            proc.wait(timeout=grace)
            return
        except subprocess.TimeoutExpired:
            continue


def _binary_on_disk(path) -> bool:
    """Fresh existence probe for the spawn-failure path only (vms/brew rule)."""
    if not path:
        return False
    try:
        return Path(path).is_file()
    except (OSError, ValueError):
        # Dying FUSE/SMB EIO / leftover NUL: not confirmably present.
        return False


def _run_preview(argv: list[str], *, itemize: bool, timeout: int) -> dict:
    """Stream one dry-run: bounded memory, group-kill on deadline.

    Same executor shape as jobs.run_watchdog (deadline enforced by a timer
    that kills the process group, because the pipe read below blocks), but
    lines are folded into counts instead of a log list, and stderr is drained
    on its own thread so an error-spewing rsync cannot deadlock the pipe.
    """
    counter = _DryRunCounter(itemize=itemize)
    timed_out = threading.Event()
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, errors="replace", env=utf8_env(), start_new_session=True,
        )
    except FileNotFoundError as e:
        # The probe said available, but the spawn could not find the binary —
        # usually rsync vanished between that check and the spawn (a brew
        # uninstall mid-request, a dying mount).  The exception alone must
        # not classify: execve also ENOENTs for a *still-present* file whose
        # interpreter/loader is gone, and answering that with "no usable
        # rsync binary was found on this host" — while dropping a truthful
        # probe — misdirects the operator.  The vanished-CLI 503 fires only
        # after a fresh disk probe confirms the recorded binary is gone
        # (the vms/brew rule); the disk check runs only on this failure
        # path, never on a successful spawn.
        if not _binary_on_disk(argv[0] if argv else ""):
            # Confirmed gone: the same coded 503 the up-front build_argv
            # check raises instead of an uncoded ``{ok: false, message:
            # "[Errno 2] ..."}`` the SPA cannot translate — and drop the
            # cached probe so the next GET /api/backups/rsync/binary and
            # preview are truthful.
            invalidate()
            raise api_error("rsync.unavailable")
        summary = counter.result()
        summary.update({"ok": False, "rc": -1, "message": _as_text(e)})
        return summary
    except (OSError, ValueError, TypeError, RecursionError) as e:
        # UnicodeEncodeError (a ValueError) on leftover ``\ud800`` in argv/env.
        # RecursionError: leftover ``str(e)`` on a nested exception is not ValueError.
        summary = counter.result()
        summary.update({"ok": False, "rc": -1, "message": _as_text(e)})
        return summary

    stderr_tail: list[str] = []

    def _drain_stderr():
        try:
            for line in iter_capped_lines(proc.stderr, 4096):
                stderr_tail.append(line)
                del stderr_tail[:-20]
        except (OSError, ValueError):
            pass

    drainer = threading.Thread(target=_drain_stderr, daemon=True)
    drainer.start()

    def _on_deadline():
        if proc.poll() is None:
            timed_out.set()
            _kill_group(proc)

    watchdog = threading.Timer(timeout, _on_deadline)
    watchdog.daemon = True
    watchdog.start()
    try:
        for line in iter_capped_lines(proc.stdout, 4096):
            counter.feed(line)
    finally:
        watchdog.cancel()
        _kill_group(proc)
        try:
            proc.wait()
        except _CONTROL_FLOW:
            raise
        except BaseException:
            pass
        drainer.join(timeout=2)
        # text=True wraps the pipes; leaving them open is the unittest
        # ResourceWarning and a leaked fd in the panel process.
        for stream in (proc.stdout, proc.stderr):
            close = getattr(stream, "close", None)
            if close is None:
                continue
            try:
                close()
            except OSError:
                pass

    rc = 124 if timed_out.is_set() else (proc.returncode if proc.returncode is not None else -1)
    summary = counter.result()
    summary.update({
        "ok": rc == 0,
        "rc": rc,
        "message": (
            f"timeout: dry-run exceeded {timeout}s and was terminated"
            if timed_out.is_set()
            else "\n".join(_as_text(x) for x in stderr_tail).strip()[-500:]
        ),
    })
    return summary


def preview(params: dict, *, timeout: int = PREVIEW_TIMEOUT) -> dict:
    """Run ``--dry-run`` and report what a real run would create/change/delete.

    This is the confirmation step the UI shows before any real transfer, and
    it is the only rsync entry point that runs synchronously in a request.
    Output is streamed (counts + samples, not the whole listing), a second
    concurrent preview of the same job is refused with ``rsync.preview_busy``,
    and the deadline kills the rsync process group rather than abandoning it.
    """
    if type(timeout) is bool or timeout is None:
        timeout = PREVIEW_TIMEOUT
    else:
        try:
            timeout = int(timeout)
        except (TypeError, ValueError, OverflowError):
            timeout = PREVIEW_TIMEOUT
    timeout = max(1, min(timeout, PREVIEW_TIMEOUT))
    info = binary_info()
    argv = build_argv(params, dry_run=True, info=info)
    key = _preview_key(validated(params))
    with _preview_guard:
        if key in _preview_running:
            raise api_error("rsync.preview_busy")
        _preview_running.add(key)
    try:
        summary = _run_preview(
            argv,
            itemize=bool(
                (info.get("supports") if _isinst(info.get("supports"), dict) else {})
                .get("itemize")
            ),
            timeout=timeout,
        )
    finally:
        with _preview_guard:
            _preview_running.discard(key)
    summary["binary"] = {k: info.get(k) for k in ("path", "variant", "version")}
    return summary


# ── execution (scheduler runner + manual run) ────────────────────────────────

def _write_run_log(job_id: str, lines: list[str]) -> None:
    """Persist one run's full output under data/backup-runs/<job>/, 0700.

    Best-effort: the journal in schedule-runs.jsonl keeps the tail either way.
    """
    if not job_id:
        return
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", job_id)[:64] or "job"
    try:
        job_dir = secure_io.make_secret_dir(RUN_LOG_ROOT / safe)
        stamp = strftime_now("%Y%m%d_%H%M%S", "0")
        secure_io.replace_secret_text(job_dir / f"{stamp}.log", "\n".join(lines) + "\n")
        # Fixed-width stamp: lexicographic == chronological, as in backups._prune.
        old = sorted(job_dir.glob("*.log"), reverse=True)[KEEP_LOGS:]
        for p in old:
            try:
                p.unlink()
            except OSError:
                pass
    except OSError:
        pass


def run_job(params: dict, *, log: list[str], timeout: int = 3600,
            job_id: str = "") -> int:
    """Execute one rsync job under the shared watchdog.  Returns the exit code.

    Runner contract (hub/scheduler_svc.py): append output to *log*, never
    raise.  Validation errors become log lines and a non-zero code so they
    land in the run history like any other failure.
    """
    try:
        argv = build_argv(params)
    except RecursionError:
        log.append("!! rsync failed")
        return -1
    except _CONTROL_FLOW:
        raise
    except BaseException as e:
        detail = getattr(e, "detail", None)
        message = detail.get("message") if _isinst(detail, dict) else _as_text(e)
        log.append(f"!! {message}")
        return -1
    p = validated(params)
    if p["src"].startswith("/"):
        try:
            missing = not Path(p["src"]).exists()
        except (OSError, ValueError):
            # Dying mount EIO; leftover NUL / ``\ud800`` is ValueError, not OSError.
            missing = True
        if missing:
            # Refusing beats an rsync error: with --delete a vanished source can
            # otherwise translate into "empty the destination".
            log.append(f"!! source does not exist: {p['src']}")
            return -1
    log.append(f"$ {' '.join(argv)}")
    rc = run_watchdog(argv, timeout=timeout, log=log, env=dict(os.environ))
    log.append(f"== rsync exit {rc}")
    _write_run_log(job_id, log)
    return rc
