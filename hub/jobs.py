"""Background maintenance job runner."""
from __future__ import annotations

import os
import signal
import subprocess
import threading

from hub import cli_args
from hub.config import cfg, maintenance_env
from hub.errors import api_error
from hub.status import invalidate_status
from hub.util import iter_capped_lines, strftime_now, utf8_env

_jobs = {}
_jobs_lock = threading.Lock()

#: Per-line character cap for captured output.  The line-count trim below
#: bounds how many lines are retained, but a single line has no natural
#: bound — one giant line (a dumped blob, a \r-driven progress bar) used to
#: be buffered whole before the trim could see it.
LOG_LINE_CAP = 4096
#: Total characters retained across the log window.  The 800-line trim alone
#: still admits 800 × LOG_LINE_CAP ≈ 3 MB per job of pathological output;
#: past this cap the oldest lines are dropped first, same direction as the
#: line trim.
LOG_TOTAL_CAP = 512 * 1024

#: Default / ceiling for ``threading.Timer`` on the watchdog thread.
JOB_TIMEOUT_DEFAULT = 600
JOB_TIMEOUT_MAX = 24 * 3600


def _clamp_timeout(raw, default: int = JOB_TIMEOUT_DEFAULT) -> int:
    """Positive seconds for ``threading.Timer`` / ``Event.wait``.

    YAML ``timeout: true`` is a bool subclass of int (1s). ``1e308`` and a
    400-digit leftover int used to OverflowError the Timer thread
    (``finished.wait`` → C ``_PyTime_t``). Inf/NaN/bytes/datetime took the
    same path after a bare ``int()``.
    """
    if isinstance(raw, bool) or raw is None:
        return default
    if isinstance(raw, (bytes, bytearray)):
        return default
    if isinstance(raw, float) and (raw != raw or raw in (float("inf"), float("-inf"))):
        return default
    try:
        n = int(raw)
    except (TypeError, ValueError, OverflowError):
        return default
    if n < 1:
        return default
    if n > JOB_TIMEOUT_MAX:
        return JOB_TIMEOUT_MAX
    return n


def run_watchdog(argv, *, timeout, log, env=None, cwd=None):
    """Run *argv* under a kill-the-group watchdog, streaming output into *log*.

    Extracted from :func:`start_job` so the scheduler engine
    (hub/scheduler_svc.py) reuses the exact same executor semantics instead of
    growing a second, subtly different one:

    * ``for line in p.stdout`` blocks until the child writes or closes the
      pipe, so the deadline cannot be enforced from inside the read loop: a
      silent command (no output at all) never iterates once.  A watchdog timer
      runs independently and kills the process group, which closes the pipe
      and releases the reader.  ``start_new_session`` lets killpg take the
      child's descendants down with it.
    * *log* is a caller-owned list; it is trimmed in place so a chatty command
      cannot grow memory without bound.  The caller keeps whatever reference it
      handed in, so live tailing keeps working.
    * Output is additionally byte-capped, per line and in total
      (:data:`LOG_LINE_CAP` / :data:`LOG_TOTAL_CAP`): the line trim alone
      cannot defend against one enormous line, which ``for line in stdout``
      would buffer whole before the trim ever saw it.

    Returns the exit code: 124 on timeout (matching GNU timeout), the child's
    own code otherwise, and -1 when the process could not be run at all.
    """
    timed_out = threading.Event()
    argv = cli_args.as_argv(argv)
    if argv is None:
        log.append("!! invalid argv")
        return -1
    timeout = _clamp_timeout(timeout)
    try:
        with subprocess.Popen(
            argv,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            # errors="replace": a stray non-UTF-8 byte in job output must
            # degrade to a replacement character, not kill the read loop.
            text=True, errors="replace", env=utf8_env(env), cwd=cwd, start_new_session=True,
        ) as p:
            def _reap():
                """Signal the whole group; SIGTERM first, then SIGKILL."""
                for sig, grace in ((signal.SIGTERM, 10), (signal.SIGKILL, 5)):
                    if p.poll() is not None:
                        return
                    try:
                        os.killpg(os.getpgid(p.pid), sig)
                    except (ProcessLookupError, PermissionError):
                        return
                    try:
                        p.wait(timeout=grace)
                        return
                    except subprocess.TimeoutExpired:
                        continue

            def _on_deadline():
                if p.poll() is None:
                    timed_out.set()
                    log.append(f"!! timeout after {timeout}s - terminating")
                    _reap()

            watchdog = threading.Timer(timeout, _on_deadline)
            watchdog.daemon = True
            watchdog.start()
            try:
                # Cheap running total; recomputed after every line trim so
                # the two caps cannot drift apart.  Seeded from the caller's
                # pre-existing lines (the "$ command" header and friends).
                total = sum(len(x) for x in log)
                for line in iter_capped_lines(p.stdout, LOG_LINE_CAP):
                    log.append(line)
                    total += len(line)
                    if len(log) > 800:
                        del log[:200]
                        total = sum(len(x) for x in log)
                    while total > LOG_TOTAL_CAP and len(log) > 1:
                        total -= len(log.pop(0))
            finally:
                watchdog.cancel()
                _reap()
        if timed_out.is_set():
            return 124
        return p.returncode if p.returncode is not None else -1
    except Exception as e:
        log.append(f"!! error: {_utf8_text(e)}")
        return -1


def _utf8_text(value) -> str:
    """Drop leftover lone surrogates so Starlette's UTF-8 encode cannot 500."""
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    try:
        text = str(value)
    except RecursionError:
        try:
            return type(value).__name__
        except Exception:
            return ""
    except Exception:
        return ""
    return text.encode("utf-8", "replace").decode("utf-8")


def _jsonable(value, depth: int = 0):
    """Coerce leftovers so Starlette's allow_nan=False encoder cannot 500.

    YAML ``name: .inf`` / ``desc: .nan`` were already dropped; ``!!binary``
    names, ``!!set`` descriptions, and inf ``rc`` in a live job row still
    leaked into GET /api/maintenance. A leftover ``\\ud800`` in a task name
    still 500'd the same encoder (``ensure_ascii=False`` then UTF-8).
    A >4300-digit ``rc`` in a junk job row still passed through untouched:
    CPython's int->str digit limit then ValueError'd ``json.dumps`` itself.
    """
    if depth > 32:
        return None
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        try:
            str(value)
        except ValueError:
            # Past CPython's int->str digit cap the encoder cannot render
            # the number at all — same drop as its inf float sibling.
            return None
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if isinstance(value, str):
        return _utf8_text(value)
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if not isinstance(k, (str, bytes, bytearray)):
                try:
                    k = str(k)
                except Exception:
                    continue
            out[_utf8_text(k)] = _jsonable(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v, depth + 1) for v in value]
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        try:
            # isoformat() is usually a str; a leftover that returns inf
            # used to skip the float sanitizer and 500 GET /api/maintenance.
            return _jsonable(iso(), depth + 1)
        except Exception:
            return None
    try:
        return _utf8_text(value)
    except Exception:
        return None


def maintenance_tasks():
    out = {}
    raw = cfg().get("maintenance")
    for t in raw if isinstance(raw, list) else []:
        if not isinstance(t, dict):
            continue
        tid = t.get("id")
        if not isinstance(tid, str) or not tid.strip():
            continue
        row = dict(t)
        row["id"] = tid.strip()
        cleaned = _jsonable(row)
        if isinstance(cleaned, dict):
            out[row["id"]] = cleaned
    return out


def job_state(tid):
    empty = {"running": False, "rc": None, "finished": None}
    if not isinstance(tid, str):
        return empty
    j = _jobs.get(tid, {})
    if not isinstance(j, dict):
        return empty
    cleaned = _jsonable({
        "running": bool(j.get("running")),
        "rc": j.get("rc"),
        "finished": j.get("finished"),
    })
    return cleaned if isinstance(cleaned, dict) else empty


def get_job(tid):
    if not isinstance(tid, str):
        return None
    j = _jobs.get(tid)
    return j if isinstance(j, dict) else None


def _log_lines(raw) -> list[str]:
    """String lines from a leftover job-row ``log`` field.  Never raises."""
    if isinstance(raw, str):
        return [raw] if raw else []
    if not isinstance(raw, (list, tuple)):
        return []
    out: list[str] = []
    for item in raw:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, (bytes, bytearray)):
            out.append(item.decode("utf-8", "replace"))
    return out


def job_log(tid):
    """Live tail payload for GET /api/maintenance/{tid}/log.  Never raises.

    A junk in-memory row used to AttributeError; an incomplete dict still
    KeyError'd, and ``log: [bytes, None]`` TypeError'd ``str.join``.
    """
    missing = {"running": False, "rc": None, "log": "(not run yet)"}
    if not isinstance(tid, str):
        return missing
    j = get_job(tid)
    if j is None:
        return missing
    text = "\n".join(_log_lines(j.get("log")))
    cleaned = _jsonable({
        "running": bool(j.get("running")),
        "rc": j.get("rc"),
        "started": j.get("started"),
        "finished": j.get("finished"),
        "log": text or "(waiting for output…)",
    })
    return cleaned if isinstance(cleaned, dict) else missing


def start_job(task):
    tid = task.get("id") if isinstance(task, dict) else None
    if not isinstance(tid, str) or not tid:
        return None
    with _jobs_lock:
        if any(isinstance(j, dict) and j.get("running") for j in _jobs.values()):
            raise api_error("jobs.already_running")
        _jobs[tid] = {"running": True, "rc": None, "log": [],
                      "started": strftime_now("%H:%M:%S"), "finished": None}

    def run():
        j = _jobs[tid]
        try:
            env = dict(os.environ)
            env.update(maintenance_env())
            timeout = _clamp_timeout(task.get("timeout"))
            command = task.get("command")
            if not isinstance(command, str) or not command.strip():
                j["rc"] = -1
                return
            j["rc"] = run_watchdog(
                ["/bin/bash", "-c", command],
                timeout=timeout, log=j["log"], env=env,
            )
        except Exception:
            j["rc"] = -1
        finally:
            j["running"] = False
            j["finished"] = strftime_now("%H:%M:%S")
            invalidate_status()
    threading.Thread(target=run, daemon=True).start()
