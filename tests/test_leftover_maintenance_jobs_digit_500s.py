"""Leftover >4300-digit ints on maintenance/jobs and the panel scheduler.

Prior passes clamped the timeout paths (``jobs._clamp_timeout``,
``scheduler_svc._job_timeout``) and dropped inf/NaN timestamps, but the
encoder-facing sanitizers — hub/jobs.py, hub/scheduler_svc.py,
hub/backups.py ``_jsonable`` — passed ``int`` through untouched.  A
>4300-digit leftover (a junk in-memory job row's ``rc``, a poisoned
``timeout``/param on a scheduled job) then hit CPython's int->str digit
limit *inside* Starlette's ``json.dumps`` — a ValueError 500 on
GET /api/maintenance, GET /api/maintenance/{tid}/log,
GET /api/scheduler/jobs and /api/scheduler/runs after the handler itself
had already succeeded.  Fixed: an int the encoder cannot render is dropped
to None, the same rule as its inf float sibling; anything ``str()`` can
render — a 400-digit int included — still passes.

``audit._jsonable`` is deliberately *not* in this sweep: record()'s own
guarded ``json.dumps`` drops the whole poisoned line (never half-written)
and recent() skips such a line at ``json.loads`` — both pinned in
test_leftover_logs_journal_audit_digit_500s — so no encoder-facing audit
path carries an over-cap int.

Already safe, pinned rather than changed:

* the timeout clamps absorb a huge int object at the ceiling and a
  >4300-digit string at the default, and ``run_watchdog`` still runs a
  command under a huge-int deadline instead of OverflowError'ing the Timer;
* the bridged SMART row's ``float(last_run)`` OverflowErrors to 0 and its
  huge ``kind`` is dropped by the (now guarded) sanitizer;
* a huge-int dict key is dropped, not stringified into a ValueError;
* a vanished CLI stays a job *result* (503-vs-500 sweep contract): POST
  /api/maintenance/{tid}/run answers "Task started" and the log route serves
  the failure as JSON — never an HTTP 500.
"""
from __future__ import annotations

import asyncio
import json
import time
import unittest
from unittest import mock
from urllib.parse import urlencode

from fastapi import FastAPI
from fastapi.encoders import jsonable_encoder

from hub import audit, backups, jobs, scheduler_svc
from hub.routers import api as api_router
from hub.routers.scheduler_api import router as scheduler_router

#: Past CPython's default 4300-digit int<->str conversion limit.
_HUGE_INT = 10 ** 5000
#: Under the cap: ``json.dumps`` renders it, so it must survive.
_BIG_INT = 10 ** 400


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


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


class JsonableHugeIntFamilyTests(unittest.TestCase):
    """The encoder-facing sanitizers behave as one family (see the
    isoformat-inf pin in test_scheduler_backup_leftover_500s): an over-cap
    int is dropped, an under-cap one survives, an over-cap key vanishes."""

    _FNS = (jobs._jsonable, scheduler_svc._jsonable, backups._jsonable)

    def test_over_cap_int_is_dropped_not_500(self):
        for fn in self._FNS:
            with self.subTest(fn=fn.__module__):
                out = fn({
                    "rc": _HUGE_INT,
                    "nested": {"timeout": _HUGE_INT},
                    "list": [_HUGE_INT, 1],
                })
                _starlette(out)
                self.assertIsNone(out["rc"])
                self.assertIsNone(out["nested"]["timeout"])
                self.assertEqual(out["list"], [None, 1])

    def test_under_cap_int_survives(self):
        for fn in self._FNS:
            with self.subTest(fn=fn.__module__):
                out = fn({"rc": _BIG_INT, "n": 7})
                _starlette(out)
                self.assertEqual(out["rc"], _BIG_INT)
                self.assertEqual(out["n"], 7)

    def test_over_cap_int_key_is_dropped(self):
        for fn in self._FNS:
            with self.subTest(fn=fn.__module__):
                out = fn({_HUGE_INT: "x", "keep": "y"})
                _starlette(out)
                self.assertEqual(out, {"keep": "y"})


class MaintenanceHugeIntTests(unittest.TestCase):
    def tearDown(self):
        jobs._jobs.clear()

    def test_huge_rc_in_a_job_row_does_not_500_the_list(self):
        jobs._jobs["backup-pg"] = {
            "running": False, "rc": _HUGE_INT, "finished": "00:00:01",
        }
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": [
            {"id": "backup-pg", "name": "Backup"},
        ]}):
            rows = api_router.api_maintenance()
        _starlette(jsonable_encoder(rows))
        self.assertEqual(rows[0]["id"], "backup-pg")
        self.assertIsNone(rows[0]["rc"])
        self.assertEqual(rows[0]["finished"], "00:00:01")

    def test_huge_desc_and_timeout_do_not_500_the_list(self):
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": [
            {"id": "backup-pg", "name": "Backup", "desc": _HUGE_INT,
             "timeout": _HUGE_INT},
        ]}):
            rows = api_router.api_maintenance()
            tasks = jobs.maintenance_tasks()
        _starlette(jsonable_encoder(rows))
        _starlette(tasks)
        self.assertEqual(rows[0]["id"], "backup-pg")
        self.assertIsNone(rows[0]["desc"])
        self.assertIsNone(tasks["backup-pg"]["timeout"])

    def test_under_cap_desc_int_still_renders(self):
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": [
            {"id": "backup-pg", "name": "Backup", "desc": _BIG_INT},
        ]}):
            rows = api_router.api_maintenance()
        _starlette(jsonable_encoder(rows))
        self.assertEqual(rows[0]["desc"], _BIG_INT)

    def test_huge_rc_in_a_job_row_does_not_500_the_log(self):
        jobs._jobs["ghost"] = {
            "running": False, "rc": _HUGE_INT,
            "started": "00:00:00", "finished": "00:00:01",
            "log": ["$ true", "done"],
        }
        body = api_router.api_maintenance_log("ghost")
        _starlette(jsonable_encoder(body))
        self.assertIsNone(body["rc"])
        self.assertIn("done", body["log"])


class SchedulerHugeIntTests(unittest.TestCase):
    def test_huge_timeout_and_params_do_not_500_the_list(self):
        job = {
            "id": "job-huge", "name": "nightly", "type": "command",
            "cron": "* * * * *", "enabled": True,
            "timeout": _HUGE_INT,
            "params": {"command": "true", "retries": _HUGE_INT,
                       "load": [_HUGE_INT, 1.0]},
        }
        with mock.patch.object(scheduler_svc, "list_jobs", return_value=[job]):
            status, body = request("GET", "/api/scheduler/jobs")
        self.assertEqual(status, 200, body)
        _starlette(body)
        row = body["jobs"][0]
        self.assertEqual(row["id"], "job-huge")
        self.assertIsNone(row.get("timeout"))
        params = row.get("params") or {}
        self.assertIsNone(params.get("retries"))
        self.assertEqual(params.get("load"), [None, 1.0])

    def test_under_cap_timeout_still_renders(self):
        job = {
            "id": "job-big", "name": "nightly", "type": "command",
            "cron": "* * * * *", "enabled": True,
            "timeout": _BIG_INT,
            "params": {"command": "true"},
        }
        with mock.patch.object(scheduler_svc, "list_jobs", return_value=[job]):
            status, body = request("GET", "/api/scheduler/jobs")
        self.assertEqual(status, 200, body)
        _starlette(body)
        self.assertEqual(body["jobs"][0]["timeout"], _BIG_INT)

    def test_huge_last_run_and_kind_do_not_500_the_job_list(self):
        schedule = {
            "interval": "weekly", "kind": _HUGE_INT,
            "last_run": _HUGE_INT, "devices": ["/dev/disk4"],
        }
        with mock.patch("hub.smart_test_svc.get_schedule", lambda: dict(schedule)):
            status, body = request("GET", "/api/scheduler/jobs")
        self.assertEqual(status, 200, body)
        _starlette(body)
        row = body["system"][0]
        self.assertEqual(row["last_run"], 0)
        self.assertIsNone(row.get("kind"))

    def test_huge_run_record_field_does_not_500_runs(self):
        """A journal record whose int loaded under the cap must render; the
        sanitizer keeps it (json.dumps can)."""
        rec = {"ts": 1, "job": "backup", "status": "ok", "rc": _BIG_INT}
        with mock.patch.object(
            scheduler_svc, "_journal_lines",
            return_value=[json.dumps(rec)],
        ):
            status, body = request("GET", "/api/scheduler/runs")
        self.assertEqual(status, 200, body)
        _starlette(body)
        self.assertEqual(body["runs"][0]["rc"], _BIG_INT)


class TimeoutClampAlreadySafePins(unittest.TestCase):
    """The timeout clamps were audited in this sweep and found already safe:
    a huge int object clamps at the ceiling, a >4300-digit string falls to
    the default (the str->int ValueError is caught).  Pinned."""

    def test_maintenance_clamp_absorbs_digit_leftovers(self):
        self.assertEqual(jobs._clamp_timeout(_HUGE_INT), jobs.JOB_TIMEOUT_MAX)
        self.assertEqual(jobs._clamp_timeout("9" * 5000), jobs.JOB_TIMEOUT_DEFAULT)
        self.assertEqual(jobs._clamp_timeout(_BIG_INT), jobs.JOB_TIMEOUT_MAX)

    def test_scheduler_clamp_absorbs_digit_leftovers(self):
        self.assertEqual(
            scheduler_svc._job_timeout({"timeout": _HUGE_INT}),
            scheduler_svc.MAX_TIMEOUT,
        )
        self.assertEqual(
            scheduler_svc._job_timeout({"timeout": "9" * 5000}),
            scheduler_svc.DEFAULT_TIMEOUT,
        )

    def test_run_watchdog_survives_a_huge_int_deadline(self):
        """The clamped deadline must reach threading.Timer as a finite number
        — a bare huge int used to OverflowError the watchdog machinery."""
        log: list[str] = []
        rc = jobs.run_watchdog(["/bin/echo", "leftover"], timeout=_HUGE_INT, log=log)
        self.assertEqual(rc, 0)
        self.assertIn("leftover", "\n".join(log))
        _starlette({"rc": rc, "log": log})


class MaintenanceVanishedCliRoutePins(unittest.TestCase):
    """503-vs-500 sweep contract, at the router: a command whose binary is
    gone is a job *result*.  POST /api/maintenance/{tid}/run answers "Task
    started" and the log route serves the failure as JSON — never a 500."""

    _TASK = {
        "id": "cli-gone-route-pin",
        "name": "CLI gone",
        "command": "/definitely/not/a/real/cli-xyz",
        "timeout": 10,
    }

    def tearDown(self):
        jobs._jobs.pop(self._TASK["id"], None)

    def test_run_route_starts_and_log_route_serves_the_failure(self):
        with (
            mock.patch.object(jobs, "cfg", return_value={"maintenance": [dict(self._TASK)]}),
            mock.patch.object(audit, "record", lambda *a, **k: {}),
            mock.patch.object(api_router.audit, "record", lambda *a, **k: {}),
        ):
            body = api_router.api_maintenance_run(self._TASK["id"])
        self.assertEqual(body, {"ok": True, "message": "Task started"})
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            row = jobs._jobs.get(self._TASK["id"]) or {}
            if isinstance(row, dict) and not row.get("running"):
                break
            time.sleep(0.05)
        state = jobs.job_state(self._TASK["id"])
        self.assertFalse(state["running"], "the job thread must finish")
        # bash ran, the command inside it is gone: 127 by contract.
        self.assertEqual(state["rc"], 127)
        payload = api_router.api_maintenance_log(self._TASK["id"])
        _starlette(jsonable_encoder(payload))
        self.assertIn("cli-xyz", payload["log"])


if __name__ == "__main__":
    unittest.main()
