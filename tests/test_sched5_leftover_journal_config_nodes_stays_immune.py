"""Fifth scheduler leftover sweep — non-regular *nodes* under the HTTP surface.

Prior sched sweeps hardened what the run journal and services.yaml *contain*
(surrogates in keys and values, over-cap hex ints, Infinity/NaN literals,
huge decimal literals, deep nests).  This file pins what happens when the
files themselves are replaced by hostile filesystem nodes, driven through
``create_app()`` + ``TestClient(raise_server_exceptions=False)`` — the routes
the Scheduler page actually calls:

* **A leftover FIFO occupying data/schedule-runs.jsonl** must not park
  ``os.open`` until a writer appears: GET /api/scheduler/runs,
  GET /api/scheduler/jobs/{id}/runs and GET /api/scheduler/jobs (which folds
  the journal in per row) all answer 200 promptly with the journal treated as
  empty, and the FIFO is left in place — reading never heals or consumes it.
  Same class for a symlink loop, a symlink pointing at a FIFO, and a
  directory squatting the journal path (``tail_file_lines`` opens
  ``O_NONBLOCK`` and refuses non-regular nodes with the OSError
  ``_journal_lines`` already handles).

* **services.yaml squatted by a FIFO or an empty directory** holds no YAML to
  lose: reads degrade to the empty config (GET jobs answers 200 with no
  rows), and a mutation *clears the squatter* — POST /api/scheduler/jobs
  answers 200 and the path is a regular file holding exactly the new job
  (the documented ``_read_disk_for_mutate`` / ``_save_full_locked``
  contract).

* **services.yaml unreadable but recoverable** (grown past the 1MB read cap,
  torn to non-UTF-8 bytes) must never be wiped by a scheduler mutation:
  reads degrade to empty, the create answers the coded 503
  ``settings.config_unreadable``, and the on-disk bytes stay identical so
  the operator can still rescue the file.
"""
from __future__ import annotations

import json
import os
import shutil
import stat as stat_mod
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from fastapi.testclient import TestClient  # noqa: E402

from hub import audit, config, scheduler_svc  # noqa: E402
from hub.app_factory import create_app  # noqa: E402
from hub.auth import require_auth  # noqa: E402

_app = None


def _the_app():
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return _app


def _client() -> TestClient:
    return TestClient(_the_app(), raise_server_exceptions=False)


def _encodable(body) -> None:
    """The exact render Starlette performs: ensure_ascii=False then UTF-8."""
    json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")


_NEW_JOB = {
    "id": "fresh", "name": "fresh", "type": "command", "cron": "30 3 * * *",
    "enabled": True, "params": {"command": "echo hi"},
}


class _Sandbox(unittest.TestCase):
    """Scratch services.yaml + run journal, audit captured away."""

    #: Generous next to the ~0s expected runtime, tiny next to a real hang.
    JOIN_TIMEOUT = 10.0

    def setUp(self):
        root = Path(os.environ.get("TMPDIR", "/tmp")) / (
            f"serverhub-sched5-nodes-{os.getpid()}-{id(self)}"
        )
        (root / "data").mkdir(parents=True, exist_ok=True)
        self.root = root
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        for target, value in (
            ("YAML_PATH", root / "services.yaml"),
            ("DATA_DIR", root / "data"),
            ("BASE", root),
        ):
            patched = mock.patch.object(config, target, value)
            patched.start()
            self.addCleanup(patched.stop)
        self.addCleanup(config.reload_cfg)
        runs = mock.patch.object(
            scheduler_svc, "RUNS_PATH", root / "data" / "schedule-runs.jsonl"
        )
        runs.start()
        self.addCleanup(runs.stop)
        recorder = mock.patch.object(audit, "record", lambda event, **f: {})
        recorder.start()
        self.addCleanup(recorder.stop)

    def _write_yaml(self, text: str) -> None:
        (self.root / "services.yaml").write_text(text, encoding="utf-8")
        config.reload_cfg()

    def _request_with_watchdog(self, method: str, path: str, **kw):
        """One TestClient request on a daemon thread; a hang fails the test."""
        box: dict = {}

        def worker():
            try:
                box["resp"] = getattr(_client(), method)(path, **kw)
            except BaseException as exc:  # surfaced below, not swallowed
                box["exc"] = exc

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        t.join(self.JOIN_TIMEOUT)
        self.assertFalse(
            t.is_alive(),
            f"{method.upper()} {path} blocked on the planted node instead of returning",
        )
        if "exc" in box:
            raise box["exc"]
        return box["resp"]


_ONE_JOB_YAML = """
schedules:
  - id: j1
    name: n
    type: command
    cron: "30 3 * * *"
    enabled: true
    params: {command: echo hi}
"""


@unittest.skipUnless(hasattr(os, "mkfifo"), "mkfifo required")
class JournalNonRegularNodes(_Sandbox):
    """The run journal replaced by FIFO / symlink loop / symlink→FIFO / dir."""

    def _runs_path(self) -> Path:
        p = Path(scheduler_svc.RUNS_PATH)
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def _assert_reads_degrade_to_empty(self):
        for path in ("/api/scheduler/runs", "/api/scheduler/jobs/j1/runs"):
            resp = self._request_with_watchdog("get", path)
            self.assertEqual(resp.status_code, 200, resp.text[:300])
            body = resp.json()
            _encodable(body)
            self.assertEqual(body["runs"], [])
        resp = self._request_with_watchdog("get", "/api/scheduler/jobs")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _encodable(body)
        rows = {j["id"]: j for j in body["jobs"]}
        self.assertIn("j1", rows)
        self.assertIsNone(rows["j1"]["last"])

    def test_fifo_journal_answers_promptly_and_is_left_alone(self):
        self._write_yaml(_ONE_JOB_YAML)
        p = self._runs_path()
        os.mkfifo(p)
        self._assert_reads_degrade_to_empty()
        # Reading never heals, consumes or replaces the planted node.
        self.assertTrue(stat_mod.S_ISFIFO(os.lstat(p).st_mode))

    def test_symlink_loop_journal_answers_promptly(self):
        self._write_yaml(_ONE_JOB_YAML)
        p = self._runs_path()
        p.symlink_to(p)
        self._assert_reads_degrade_to_empty()
        self.assertTrue(os.path.islink(p))

    def test_symlink_to_fifo_journal_answers_promptly(self):
        self._write_yaml(_ONE_JOB_YAML)
        p = self._runs_path()
        target = p.parent / "fifo-target"
        os.mkfifo(target)
        p.symlink_to(target)
        self._assert_reads_degrade_to_empty()
        self.assertTrue(stat_mod.S_ISFIFO(os.lstat(target).st_mode))

    def test_directory_journal_answers_promptly(self):
        self._write_yaml(_ONE_JOB_YAML)
        p = self._runs_path()
        p.mkdir()
        self._assert_reads_degrade_to_empty()
        self.assertTrue(p.is_dir())


@unittest.skipUnless(hasattr(os, "mkfifo"), "mkfifo required")
class ConfigNonRegularNodes(_Sandbox):
    """services.yaml squatted by a FIFO / empty directory: nothing to lose,
    so reads degrade to empty and a mutation clears the squatter."""

    def _assert_list_is_empty(self):
        resp = self._request_with_watchdog("get", "/api/scheduler/jobs")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _encodable(body)
        self.assertEqual(body["jobs"], [])

    def _assert_create_clears_squatter(self):
        resp = self._request_with_watchdog(
            "post", "/api/scheduler/jobs", json=_NEW_JOB,
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _encodable(resp.json())
        yaml_path = Path(config.YAML_PATH)
        self.assertTrue(stat_mod.S_ISREG(os.lstat(yaml_path).st_mode))
        config.reload_cfg()
        self.assertEqual(
            [scheduler_svc._job_id(j) for j in scheduler_svc.list_jobs()],
            ["fresh"],
        )

    def test_fifo_config_reads_empty_then_create_replaces_it(self):
        p = Path(config.YAML_PATH)
        os.mkfifo(p)
        config.reload_cfg()
        self._assert_list_is_empty()
        self._assert_create_clears_squatter()

    def test_empty_dir_config_reads_empty_then_create_replaces_it(self):
        p = Path(config.YAML_PATH)
        p.mkdir()
        config.reload_cfg()
        self._assert_list_is_empty()
        self._assert_create_clears_squatter()


class ConfigUnreadableButRecoverable(_Sandbox):
    """Oversize / torn services.yaml: reads degrade, mutations refuse with the
    coded 503, and the on-disk bytes stay identical (never wiped)."""

    def _assert_read_empty_create_refused(self, payload: bytes):
        p = Path(config.YAML_PATH)
        p.write_bytes(payload)
        config.reload_cfg()
        resp = _client().get("/api/scheduler/jobs")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _encodable(body)
        self.assertEqual(body["jobs"], [])
        resp = _client().post("/api/scheduler/jobs", json=_NEW_JOB)
        self.assertEqual(resp.status_code, 503, resp.text[:300])
        detail = resp.json()["detail"]
        self.assertEqual(detail["code"], "settings.config_unreadable")
        _encodable(resp.json())
        # The recoverable file was not rewritten, backed over, or emptied.
        self.assertEqual(p.read_bytes(), payload)
        # The delete side degrades to the coded 404 (read saw no such job),
        # never a 500 and never a write.
        resp = _client().delete("/api/scheduler/jobs/fresh")
        self.assertEqual(resp.status_code, 404, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "scheduler.not_found")
        self.assertEqual(p.read_bytes(), payload)

    def test_oversize_config_is_refused_not_wiped(self):
        self._assert_read_empty_create_refused(
            b"schedules: [" + b"x" * (2 * 1024 * 1024) + b"]"
        )

    def test_torn_non_utf8_config_is_refused_not_wiped(self):
        self._assert_read_empty_create_refused(
            b"schedules:\n  - id: \xff\xfe\n    name: x\n"
        )


if __name__ == "__main__":
    unittest.main()
