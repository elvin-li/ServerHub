"""CLI-missing leftovers, scheduler sweep: rsync preview carries the coded 503.

``sh()`` / ``run_capped()`` report a FileNotFoundError spawn with the exact
sentinel ``(-1, "not found")`` — never a real CLI exit — and a direct
``subprocess.Popen`` spawn raises the FileNotFoundError itself.  Every route
in this sweep checks binary presence up front and answers with a coded 503
when the tool is absent, but a binary that vanished *between* that check and
the spawn (a brew uninstall mid-request, a dying mount) used to fall through:

* ``rsync_svc._run_preview`` (POST /api/backups/rsync/preview) swallowed the
  FileNotFoundError into its broad OSError catch and answered an uncoded
  ``{ok: false, rc: -1, message: "[Errno 2] ..."}`` the SPA cannot translate
  — while ``binary_info``'s 300s cached probe kept claiming the binary was
  there.  It now raises the same coded ``rsync.unavailable`` 503 the
  up-front ``build_argv`` check raises, and drops the stale probe so the
  next GET /api/backups/rsync/binary is truthful.

Deliberately narrow, pinned by the negative cases below: only the
FileNotFoundError spawn classifies.  A generic spawn OSError (a dying pipe,
a hostile env) keeps the uncoded ok:false shape — that message is then the
truth — and an rsync that ran and failed keeps its own exit code.

The scheduler engine and maintenance runner were audited in the same sweep
and found already safe; their behavior is pinned rather than changed: the
runner contract (hub/scheduler_svc.py) turns a vanished rsync into a logged,
journalled run failure — POST /api/scheduler/jobs/{id}/run-now never becomes
a 500 — and a maintenance command whose binary is gone records the failure
in the job log instead of erroring the run/log routes.
"""
from __future__ import annotations

import json
import os
import shutil
import time
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from hub import jobs, rsync_svc, scheduler_svc
from hub.errors import CODES

#: A probe result whose recorded path no longer exists on disk: exactly what
#: the 300s cache serves after the binary vanished mid-request.
VANISHED = {
    "available": True,
    "path": "/definitely/not/a/real/rsync-xyz",
    "variant": "rsync3",
    "version": "3.2.7",
    "supports": {"itemize": True, "progress2": True,
                 "compress": True, "bwlimit": True},
}

PARAMS = {"direction": "push", "src": "/", "dest": "/backup-target"}


def _detail(ctx) -> dict:
    detail = ctx.exception.detail
    return detail if isinstance(detail, dict) else {"code": str(detail)}


class CodeStatusPins(unittest.TestCase):
    """The code this sweep maps to must stay 503 — a demotion would silently
    turn the "install rsync" answer back into a generic failure."""

    def test_unavailable_code_is_503(self):
        self.assertEqual(CODES["rsync.unavailable"][0], 503)


class RsyncPreviewCliMissingTests(unittest.TestCase):
    """POST /api/backups/rsync/preview answers a vanished binary with the
    coded 503 — through a *real* spawn of the probe's recorded path."""

    def setUp(self):
        # No test may inherit another's in-flight preview registration.
        with rsync_svc._preview_guard:
            rsync_svc._preview_running.clear()

    def _patched(self, invalidate=None):
        return (
            mock.patch.object(rsync_svc, "binary_info", lambda force=False: dict(VANISHED)),
            mock.patch.object(rsync_svc, "invalidate", invalidate or mock.Mock()),
        )

    def test_vanished_rsync_carries_the_code(self):
        binary, invalidate = self._patched()
        with binary, invalidate:
            with self.assertRaises(HTTPException) as ctx:
                rsync_svc.preview(dict(PARAMS))
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_detail(ctx)["code"], "rsync.unavailable")

    def test_stale_probe_is_dropped_so_the_next_check_is_truthful(self):
        dropped = mock.Mock()
        binary, invalidate = self._patched(invalidate=dropped)
        with binary, invalidate:
            with self.assertRaises(HTTPException):
                rsync_svc.preview(dict(PARAMS))
        dropped.assert_called_once_with()

    def test_busy_token_is_released_after_the_coded_raise(self):
        binary, invalidate = self._patched()
        with binary, invalidate:
            with self.assertRaises(HTTPException):
                rsync_svc.preview(dict(PARAMS))
        with rsync_svc._preview_guard:
            self.assertEqual(rsync_svc._preview_running, set(),
                             "a coded refusal must not leave the job marked busy")

    def test_upfront_absence_raises_the_same_code(self):
        gone = {**VANISHED, "available": False, "path": ""}
        with mock.patch.object(rsync_svc, "binary_info", lambda force=False: gone):
            with self.assertRaises(HTTPException) as ctx:
                rsync_svc.preview(dict(PARAMS))
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_detail(ctx)["code"], "rsync.unavailable")

    def test_generic_spawn_oserror_is_not_classified(self):
        """A dying pipe is not a missing binary: the ok:false shape survives
        and the stale-probe drop is not triggered."""
        dropped = mock.Mock()
        with (
            mock.patch.object(rsync_svc, "binary_info", lambda force=False: dict(VANISHED)),
            mock.patch.object(rsync_svc, "invalidate", dropped),
            mock.patch.object(rsync_svc.subprocess, "Popen",
                              side_effect=OSError("kaboom")),
        ):
            summary = rsync_svc.preview(dict(PARAMS))
        self.assertFalse(summary["ok"])
        self.assertEqual(summary["rc"], -1)
        self.assertIn("kaboom", summary["message"])
        dropped.assert_not_called()
        json.dumps(summary, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_permission_error_is_not_classified(self):
        """A present-but-unexecutable rsync is not a missing one."""
        with (
            mock.patch.object(rsync_svc, "binary_info", lambda force=False: dict(VANISHED)),
            mock.patch.object(rsync_svc.subprocess, "Popen",
                              side_effect=PermissionError(13, "Permission denied")),
        ):
            summary = rsync_svc.preview(dict(PARAMS))
        self.assertFalse(summary["ok"])
        self.assertIn("Permission denied", summary["message"])


class SchedulerRsyncRunnerSafePins(unittest.TestCase):
    """The scheduler was audited in this sweep and is already safe: the
    runner contract (append to *log*, return a code, never raise) turns a
    vanished rsync into a journalled run failure, so run-now and the engine
    thread never see an exception.  Pinned so it stays that way."""

    def setUp(self):
        root = Path(os.environ.get("TMPDIR", "/tmp")) / f"serverhub-cli-missing-{os.getpid()}-{id(self)}"
        root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        for patched in (
            mock.patch.object(scheduler_svc, "RUNS_PATH", root / "schedule-runs.jsonl"),
            mock.patch.object(rsync_svc, "RUN_LOG_ROOT", root / "backup-runs"),
            mock.patch.object(rsync_svc, "binary_info", lambda force=False: dict(VANISHED)),
            mock.patch.object(scheduler_svc, "_last_trim", 0.0),
        ):
            patched.start()
            self.addCleanup(patched.stop)
        with scheduler_svc._running_guard:
            scheduler_svc._running.clear()
        scheduler_svc._fail_counts.clear()
        self.addCleanup(scheduler_svc._fail_counts.clear)

    def test_vanished_rsync_is_a_logged_run_failure(self):
        """run_job spawns the probe's recorded path for real: the missing
        binary becomes a log line and rc -1, never a raise."""
        log: list[str] = []
        rc = rsync_svc.run_job(dict(PARAMS), log=log, timeout=5)
        self.assertEqual(rc, -1)
        self.assertTrue(any(line.startswith("!! error") for line in log))

    def test_execute_journals_the_failure(self):
        job = {"id": "rsync-gone", "name": "rsync-gone", "type": "rsync",
               "cron": "* * * * *", "enabled": True, "timeout": 5,
               "params": dict(PARAMS)}
        entry = scheduler_svc._execute(job, "schedule")
        self.assertEqual(entry["status"], "failed")
        self.assertEqual(entry["rc"], -1)
        json.dumps(entry, ensure_ascii=False, allow_nan=False).encode("utf-8")
        lines = scheduler_svc.RUNS_PATH.read_text().splitlines()
        records = [json.loads(ln) for ln in lines if ln.strip()]
        self.assertEqual([r["status"] for r in records], ["failed"])

    def test_run_now_wait_reports_the_failure_without_raising(self):
        """The shape POST /api/scheduler/jobs/{id}/run-now builds on."""
        job = {"id": "rsync-gone-now", "name": "rsync-gone-now", "type": "rsync",
               "cron": "* * * * *", "enabled": True, "timeout": 5,
               "params": dict(PARAMS)}
        with mock.patch.object(scheduler_svc, "get_job", lambda _: dict(job)):
            result = scheduler_svc.run_job_now("rsync-gone-now", wait=True)
        self.assertFalse(result["ok"])
        self.assertEqual(result["run"]["status"], "failed")
        json.dumps(result, ensure_ascii=False, allow_nan=False).encode("utf-8")


class MaintenanceSpawnSafePins(unittest.TestCase):
    """Maintenance was audited in this sweep and is already safe: the spawn
    happens on the job thread, so POST /api/maintenance/{tid}/run returns
    "started" and a gone command becomes a logged job result the log route
    serves as JSON — never an HTTP error.  Pinned so it stays that way."""

    def test_missing_command_binary_is_a_logged_job_result(self):
        tid = "cli-missing-spawn-pin"
        self.addCleanup(jobs._jobs.pop, tid, None)
        jobs.start_job({"id": tid, "command": "/definitely/not/a/real/cli-xyz",
                        "timeout": 10})
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            row = jobs._jobs.get(tid) or {}
            if not row.get("running"):
                break
            time.sleep(0.05)
        state = jobs.job_state(tid)
        self.assertFalse(state["running"], "the job thread must finish")
        # bash ran, the command inside it is gone: 127 by contract.
        self.assertEqual(state["rc"], 127)
        payload = jobs.job_log(tid)
        self.assertIn("cli-xyz", payload["log"])
        json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


if __name__ == "__main__":
    unittest.main()
