"""Scheduler job writes must read and write under one lock.

Two real races lived in the job store:

* ``set_enabled`` was ``get_job()`` → mutate → ``save_job()``: the snapshot was
  taken outside the cross-process write lock (through the mtime-cached
  ``cfg()``), and the *whole* stale record was written back.  A concurrent
  PUT /api/scheduler/jobs/{id} landing between the read and the write — the
  other panel process, or just another uvicorn worker thread — was silently
  reverted by a toggle that only meant to flip one boolean.

* The router pre-checked existence with ``get_job()`` and then called the
  unconditional upsert.  Two concurrent creates with the same id both passed
  the check and the loser overwrote the winner's job with a 200; an update
  racing a delete re-created the job the delete had just removed.

The fix folds each read-modify-write into a single ``config.mutate`` body, so
the existence check and the write happen under the same flock that serialises
every services.yaml writer.  These tests pin that by handing the *stale* path
(the ``cfg()`` snapshot) a different answer than the file on disk: only an
implementation that re-reads under the lock survives them.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI  # noqa: E402

from hub import audit, config, scheduler_svc  # noqa: E402
from hub.routers.scheduler_api import router as scheduler_router  # noqa: E402


async def _asgi_request(method, path, *, payload=None, query=None):
    app = FastAPI()
    app.include_router(scheduler_router)
    body = json.dumps(payload).encode() if payload is not None else b""
    sent = False
    messages: list[dict] = []

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1", "method": method, "scheme": "http",
        "path": path, "raw_path": path.encode(),
        "query_string": urlencode(query or {}).encode(), "root_path": "",
        "headers": [(b"content-type", b"application/json")],
        "server": ("localhost", 8086), "client": ("127.0.0.1", 1), "state": {},
    }
    await app(scope, receive, send)
    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    raw = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    return status, json.loads(raw or b"{}")


def request(method, path, *, payload=None, query=None):
    return asyncio.run(_asgi_request(method, path, payload=payload, query=query))


class _Sandbox(unittest.TestCase):
    """Scratch services.yaml, silenced audit trail."""

    def setUp(self):
        root = Path(os.environ.get("TMPDIR", "/tmp")) / (
            f"serverhub-schedrace-{os.getpid()}-{id(self)}"
        )
        (root / "data").mkdir(parents=True, exist_ok=True)
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
        self.yaml_path = root / "services.yaml"
        recorder = mock.patch.object(audit, "record", lambda event, **fields: {})
        recorder.start()
        self.addCleanup(recorder.stop)

    def _seed(self, **overrides) -> dict:
        record = {
            "id": "job-race1", "name": "nightly", "type": "command",
            "cron": "30 3 * * *", "enabled": True,
            "params": {"command": "echo new"},
        }
        record.update(overrides)
        self.assertTrue(scheduler_svc.save_job(record))
        return record

    def _on_disk(self) -> list[dict]:
        rows = config._read_disk().get("schedules")
        return rows if isinstance(rows, list) else []


class ToggleLostUpdateTests(_Sandbox):
    def test_a_toggle_does_not_write_back_a_stale_snapshot(self):
        """The lost update itself: cfg() answers with the pre-edit record
        (exactly what the mtime cache serves while another process edits the
        file), and the toggle must still leave the on-disk edit standing."""
        self._seed()
        stale = {
            "schedules": [{
                "id": "job-race1", "name": "nightly", "type": "command",
                "cron": "30 3 * * *", "enabled": True,
                "params": {"command": "echo OLD"},
            }]
        }
        with mock.patch.object(scheduler_svc, "cfg", lambda: stale):
            job = scheduler_svc.set_enabled("job-race1", False)
        self.assertIsNotNone(job)
        self.assertIs(job["enabled"], False)
        rows = self._on_disk()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["params"]["command"], "echo new",
                         "the toggle reverted a concurrent edit")
        self.assertIs(rows[0]["enabled"], False)

    def test_toggle_of_a_missing_job_returns_none_and_writes_nothing(self):
        self._seed()
        before = self.yaml_path.read_bytes()
        self.assertIsNone(scheduler_svc.set_enabled("job-ghost", True))
        self.assertEqual(self.yaml_path.read_bytes(), before,
                         "a no-op toggle must not rewrite services.yaml")

    def test_toggle_returns_the_fresh_record(self):
        self._seed(params={"command": "echo current"})
        job = scheduler_svc.set_enabled("job-race1", False)
        self.assertEqual(job["params"]["command"], "echo current")


class SaveJobModeTests(_Sandbox):
    def test_create_mode_refuses_an_existing_id_under_the_lock(self):
        self._seed(name="first")
        loser = {
            "id": "job-race1", "name": "second", "type": "command",
            "cron": "* * * * *", "enabled": True,
            "params": {"command": "echo overwrite"},
        }
        self.assertFalse(scheduler_svc.save_job(loser, mode="create"))
        rows = self._on_disk()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "first",
                         "a losing create overwrote the existing job")

    def test_create_mode_refusal_leaves_the_file_untouched(self):
        self._seed(name="first")
        before = self.yaml_path.read_bytes()
        scheduler_svc.save_job({"id": "job-race1", "name": "x"}, mode="create")
        self.assertEqual(self.yaml_path.read_bytes(), before)

    def test_update_mode_refuses_a_missing_id(self):
        self._seed()
        ghost = {
            "id": "job-deleted", "name": "zombie", "type": "command",
            "cron": "* * * * *", "enabled": True,
            "params": {"command": "echo back"},
        }
        self.assertFalse(scheduler_svc.save_job(ghost, mode="update"))
        self.assertEqual([r["id"] for r in self._on_disk()], ["job-race1"],
                         "an update of a deleted job re-created it")

    def test_upsert_stays_the_default(self):
        self._seed(name="v1")
        self.assertTrue(scheduler_svc.save_job(self._record(name="v2")))
        self.assertEqual(self._on_disk()[0]["name"], "v2")

    def _record(self, **overrides) -> dict:
        record = {
            "id": "job-race1", "name": "nightly", "type": "command",
            "cron": "30 3 * * *", "enabled": True,
            "params": {"command": "echo new"},
        }
        record.update(overrides)
        return record


class RouterRaceTests(_Sandbox):
    def _create(self, **overrides):
        body = {
            "id": "job-api1", "name": "nightly", "type": "command",
            "cron": "30 3 * * *", "enabled": True,
            "params": {"command": "echo v1"},
        }
        body.update(overrides)
        return request("POST", "/api/scheduler/jobs", payload=body)

    def test_duplicate_create_is_refused_not_overwritten(self):
        status, _body = self._create()
        self.assertEqual(status, 200)
        status, body = self._create(name="impostor", params={"command": "echo v2"})
        self.assertEqual(status, 409)
        self.assertEqual(body["detail"]["code"], "scheduler.exists")
        rows = self._on_disk()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["params"]["command"], "echo v1")

    def test_update_of_a_deleted_job_is_404_not_a_resurrection(self):
        status, _body = self._create()
        self.assertEqual(status, 200)
        status, _body = request("DELETE", "/api/scheduler/jobs/job-api1")
        self.assertEqual(status, 200)
        status, body = request(
            "PUT", "/api/scheduler/jobs/job-api1",
            payload={
                "name": "zombie", "type": "command", "cron": "* * * * *",
                "enabled": True, "params": {"command": "echo back"},
            },
        )
        self.assertEqual(status, 404, body)
        self.assertEqual(body["detail"]["code"], "scheduler.not_found")
        self.assertEqual(self._on_disk(), [])


if __name__ == "__main__":
    unittest.main()
