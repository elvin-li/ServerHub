"""Scheduler API: validation, audit trail, storage round-trip.

The router is mounted without the auth dependency — admin gating is
hub/auth.py's contract (members only reach a fixed read-only whitelist, which
contains no /api/scheduler/jobs path), and what *this* file pins is the part
the router owns: what gets stored, what gets refused, and what lands in the
audit trail (the shell command text must be part of it).
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
    """Scratch services.yaml + run journal + captured audit records."""

    def setUp(self):
        root = Path(os.environ.get("TMPDIR", "/tmp")) / f"serverhub-schedapi-{os.getpid()}-{id(self)}"
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
        runs = mock.patch.object(scheduler_svc, "RUNS_PATH", root / "data" / "runs.jsonl")
        runs.start()
        self.addCleanup(runs.stop)
        self.audited: list[tuple[str, dict]] = []
        recorder = mock.patch.object(
            audit, "record",
            lambda event, **fields: self.audited.append((event, fields)) or {},
        )
        recorder.start()
        self.addCleanup(recorder.stop)

    def _create(self, **overrides):
        body = {
            "name": "nightly cleanup", "type": "command", "cron": "30 3 * * *",
            "enabled": True, "params": {"command": "echo hi"},
        }
        body.update(overrides)
        return request("POST", "/api/scheduler/jobs", payload=body)


class CrudTests(_Sandbox):
    def test_create_stores_and_lists_with_next_run(self):
        status, created = self._create()
        self.assertEqual(status, 200, created)
        jid = created["job"]["id"]
        self.assertIsNotNone(created["job"]["next_run"])
        status, listed = request("GET", "/api/scheduler/jobs")
        self.assertEqual(status, 200)
        self.assertEqual([j["id"] for j in listed["jobs"]], [jid])
        self.assertIn("command", listed["types"])

    def test_create_rejects_bad_cron(self):
        status, body = self._create(cron="61 * * * *")
        self.assertEqual(status, 400)
        self.assertEqual(body["detail"]["code"], "scheduler.bad_cron")

    def test_create_rejects_bad_type(self):
        status, body = self._create(type="teleport")
        self.assertEqual(status, 400)
        self.assertEqual(body["detail"]["code"], "scheduler.bad_type")

    def test_create_rejects_empty_command(self):
        status, body = self._create(params={"command": "  "})
        self.assertEqual(status, 400)
        self.assertEqual(body["detail"]["code"], "scheduler.bad_params")

    def test_rsync_params_are_normalised_by_rsync_svc(self):
        status, body = self._create(
            type="rsync",
            params={"direction": "push", "src": "/data", "dest": "/backup",
                    "exclude": ["*.tmp", ""], "delete": True},
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["job"]["params"]["exclude"], ["*.tmp"])
        self.assertTrue(body["job"]["params"]["delete"])

    def test_rsync_injection_is_refused_with_rsync_code(self):
        status, body = self._create(
            type="rsync", params={"direction": "push", "src": "-rf", "dest": "/b"})
        self.assertEqual(status, 400)
        self.assertEqual(body["detail"]["code"], "rsync.bad_path")

    def test_stack_backup_params(self):
        status, body = self._create(
            type="stack_backup", params={"stack_id": "photoprism", "retain": 7})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["job"]["params"], {"stack_id": "photoprism", "retain": 7})
        status, body = self._create(
            type="stack_backup", params={"stack_id": "../etc"})
        self.assertEqual(status, 400)

    def test_update_and_delete(self):
        _, created = self._create()
        jid = created["job"]["id"]
        status, body = request("PUT", f"/api/scheduler/jobs/{jid}", payload={
            "name": "renamed", "type": "command", "cron": "0 4 * * 0",
            "enabled": False, "params": {"command": "true"},
        })
        self.assertEqual(status, 200, body)
        self.assertEqual(scheduler_svc.get_job(jid)["name"], "renamed")
        status, _ = request("DELETE", f"/api/scheduler/jobs/{jid}")
        self.assertEqual(status, 200)
        self.assertIsNone(scheduler_svc.get_job(jid))

    def test_update_unknown_job_404(self):
        status, body = request("PUT", "/api/scheduler/jobs/ghost", payload={
            "name": "x", "type": "command", "cron": "* * * * *",
            "params": {"command": "true"},
        })
        self.assertEqual(status, 404)
        self.assertEqual(body["detail"]["code"], "scheduler.not_found")

    def test_enable_toggle(self):
        _, created = self._create()
        jid = created["job"]["id"]
        status, body = request("POST", f"/api/scheduler/jobs/{jid}/enable",
                               payload={"enabled": False})
        self.assertEqual(status, 200)
        self.assertFalse(scheduler_svc.get_job(jid)["enabled"])
        # A disabled job advertises no next run.
        self.assertIsNone(body["job"]["next_run"])

    def test_duplicate_id_conflicts(self):
        self._create(id="fixed-id")
        status, body = self._create(id="fixed-id")
        self.assertEqual(status, 409)
        self.assertEqual(body["detail"]["code"], "scheduler.exists")


class AuditTests(_Sandbox):
    def test_mutations_are_audited_with_command_text(self):
        _, created = self._create()
        jid = created["job"]["id"]
        request("PUT", f"/api/scheduler/jobs/{jid}", payload={
            "name": "renamed", "type": "command", "cron": "30 3 * * *",
            "params": {"command": "rm -rf /tmp/scratch"},
        })
        request("DELETE", f"/api/scheduler/jobs/{jid}")
        events = [e for e, _ in self.audited]
        self.assertEqual(events, [
            audit.SCHEDULE_JOB_CREATED,
            audit.SCHEDULE_JOB_UPDATED,
            audit.SCHEDULE_JOB_DELETED,
        ])
        create_fields = self.audited[0][1]
        self.assertEqual(create_fields["command"], "echo hi")
        update_fields = self.audited[1][1]
        self.assertEqual(update_fields["command"], "rm -rf /tmp/scratch")

    def test_run_now_is_audited(self):
        _, created = self._create()
        jid = created["job"]["id"]
        with mock.patch.object(scheduler_svc, "run_job_now",
                               lambda *_a, **_k: {"ok": True, "started": True}):
            status, _ = request("POST", f"/api/scheduler/jobs/{jid}/run-now")
        self.assertEqual(status, 200)
        self.assertEqual(self.audited[-1][0], audit.SCHEDULE_JOB_RUN)


class RunEndpointTests(_Sandbox):
    def test_run_now_unknown_404(self):
        status, body = request("POST", "/api/scheduler/jobs/ghost/run-now")
        self.assertEqual(status, 404)

    def test_run_now_refused_while_running(self):
        _, created = self._create()
        jid = created["job"]["id"]
        with mock.patch.object(scheduler_svc, "is_running", lambda _jid: True):
            status, body = request("POST", f"/api/scheduler/jobs/{jid}/run-now")
        self.assertEqual(status, 409)
        self.assertEqual(body["detail"]["code"], "scheduler.running")

    def test_runs_endpoint_filters_by_job(self):
        _, created = self._create()
        jid = created["job"]["id"]
        scheduler_svc._record_run({"ts": 1, "job": jid, "status": "ok"})
        scheduler_svc._record_run({"ts": 2, "job": "other", "status": "ok"})
        status, body = request("GET", f"/api/scheduler/jobs/{jid}/runs")
        self.assertEqual(status, 200)
        self.assertEqual([r["job"] for r in body["runs"]], [jid])


class ListEfficiencyTests(_Sandbox):
    def test_list_reads_the_run_journal_once_not_once_per_job(self):
        """GET /api/scheduler/jobs used to call last_run() per job, and each
        call re-read and re-parsed the whole journal (jobs × MAX_RUNS json
        loads per page poll).  The list path must use the single-read map."""
        for jid in ("job-a", "job-b", "job-c"):
            self._create(id=jid)
        scheduler_svc._record_run({"ts": 10, "job": "job-a", "status": "ok", "rc": 0})
        scheduler_svc._record_run({"ts": 20, "job": "job-a", "status": "failed", "rc": 1})
        scheduler_svc._record_run({"ts": 30, "job": "job-c", "status": "ok", "rc": 0})

        with mock.patch.object(
            scheduler_svc, "last_run",
            side_effect=AssertionError("list_jobs must not read the journal per job"),
        ):
            status, body = request("GET", "/api/scheduler/jobs")
        self.assertEqual(status, 200)
        by_id = {j["id"]: j for j in body["jobs"]}
        self.assertEqual(by_id["job-a"]["last"]["ts"], 20, "newest run wins")
        self.assertEqual(by_id["job-a"]["last"]["status"], "failed")
        self.assertEqual(by_id["job-b"]["last"], None)
        self.assertEqual(by_id["job-c"]["last"]["ts"], 30)


class BridgedSmartTests(_Sandbox):
    def test_smart_schedule_appears_read_only(self):
        schedule = {"interval": "weekly", "kind": "short", "last_run": 1000,
                    "devices": ["/dev/disk4"]}
        with mock.patch("hub.smart_test_svc.get_schedule", lambda: dict(schedule)):
            status, body = request("GET", "/api/scheduler/jobs")
        self.assertEqual(status, 200)
        bridged = body["system"]
        self.assertEqual(len(bridged), 1)
        self.assertTrue(bridged[0]["readonly"])
        self.assertTrue(bridged[0]["enabled"])
        self.assertEqual(bridged[0]["next_run"], 1000 + 7 * 86400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
