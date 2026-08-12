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
        timed_out = threading.Event()
        try:
            # ``for line in p.stdout`` blocks until the child writes or closes
            # the pipe, so the deadline cannot be enforced from inside the read
            # loop: a silent command (no output at all) never iterates once.
            # A watchdog timer runs independently and kills the process group,
            # which closes the pipe and releases the reader.  start_new_session
            # lets killpg take the child's descendants down with it.
            with subprocess.Popen(
                ["/bin/bash", "-c", task["command"]],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, env=env, start_new_session=True,
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
                        j["log"].append(f"!! timeout after {timeout}s - terminating")
                        _reap()

                watchdog = threading.Timer(timeout, _on_deadline)
                watchdog.daemon = True
                watchdog.start()
                try:
                    for line in p.stdout:
                        j["log"].append(line.rstrip())
                        if len(j["log"]) > 800:
                            del j["log"][:200]
                finally:
                    watchdog.cancel()
                    _reap()
            j["rc"] = 124 if timed_out.is_set() else (
                p.returncode if p.returncode is not None else -1)
        except Exception as e:
            j["log"].append(f"!! error: {e}")
            j["rc"] = -1
        finally:
            j["running"] = False
            j["finished"] = time.strftime("%H:%M:%S")
            invalidate_status()
    threading.Thread(target=run, daemon=True).start()
