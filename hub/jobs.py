"""Background maintenance job runner."""
from __future__ import annotations

import os
import signal
import subprocess
import threading
import time

from hub.config import cfg
from hub.errors import api_error
from hub.status import invalidate_status

_jobs = {}
_jobs_lock = threading.Lock()


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

    Returns the exit code: 124 on timeout (matching GNU timeout), the child's
    own code otherwise, and -1 when the process could not be run at all.
    """
    timeout = int(timeout)
    timed_out = threading.Event()
    try:
        with subprocess.Popen(
            list(argv),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, env=env, cwd=cwd, start_new_session=True,
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
                for line in p.stdout:
                    log.append(line.rstrip())
                    if len(log) > 800:
                        del log[:200]
            finally:
                watchdog.cancel()
                _reap()
        if timed_out.is_set():
            return 124
        return p.returncode if p.returncode is not None else -1
    except Exception as e:
        log.append(f"!! error: {e}")
        return -1


def maintenance_tasks():
    return {t["id"]: t for t in cfg().get("maintenance") or []}


def job_state(tid):
    j = _jobs.get(tid, {})
    return {"running": j.get("running", False), "rc": j.get("rc"),
            "finished": j.get("finished")}


def get_job(tid):
    return _jobs.get(tid)


def start_job(task):
    tid = task["id"]
    with _jobs_lock:
        if any(j.get("running") for j in _jobs.values()):
            raise api_error("jobs.already_running")
        _jobs[tid] = {"running": True, "rc": None, "log": [],
                      "started": time.strftime("%H:%M:%S"), "finished": None}

    def run():
        j = _jobs[tid]
        env = dict(os.environ)
        env.update({k: str(v) for k, v in
                    ((cfg().get("settings") or {}).get("maintenance_env") or {}).items()})
        timeout = int(task.get("timeout", 600))
        try:
            j["rc"] = run_watchdog(
                ["/bin/bash", "-c", task["command"]],
                timeout=timeout, log=j["log"], env=env,
            )
        finally:
            j["running"] = False
            j["finished"] = time.strftime("%H:%M:%S")
            invalidate_status()
    threading.Thread(target=run, daemon=True).start()
