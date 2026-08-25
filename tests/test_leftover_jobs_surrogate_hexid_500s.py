"""Leftover surrogate / hex-int maintenance task ids on the jobs surface.

Prior sweeps made ``jobs._jsonable`` scrub the row *values* (a ``\\ud800``
name, an over-cap ``rc``), but ``maintenance_tasks()`` still keyed its
mapping by the RAW configured id:

* a leftover lone surrogate in the id (a hand-edited services.yaml escape)
  kept the surrogate in the mapping *key* while the row's ``id`` value was
  scrubbed to ``?`` — so GET /api/maintenance listed an id that POST
  /api/maintenance/{tid}/run could never match (the run button 404'd a task
  the panel showed), and the mapping itself was not UTF-8 encodable;
* a YAML hex/octal id (``id: 0x2A5F`` loads *already-int*, uncapped —
  ``int(x, 16)`` is exempt from CPython's 4300-digit conversion limit) was
  silently dropped by the strict ``isinstance(str)`` gate: the configured
  task vanished from the list and could never be run.

Fixed with the logs_svc._config_text family rule: a renderable int id
coerces through the ``str()`` probe, an over-cap leftover drops only its
entry, bool never becomes ``"True"``, and the id is surrogate-scrubbed
*before* it becomes the mapping key, so key == listed id == routable id.

Already safe, pinned rather than changed (the other two sweep classes):

* a vanished command binary stays a job *result* — ``run_watchdog`` logs
  the spawn failure and returns -1; the run/log routes never 500/503 for it
  (the 503-vs-500 sweep contract, route-level pin in
  test_leftover_maintenance_jobs_digit_500s);
* the watchdog deadline clamps bool-as-int (YAML ``timeout: true`` is an
  int subclass worth 1s) and over-cap ints, so ``threading.Timer`` /
  ``killpg`` never see a pid/deadline they would OverflowError on.
"""
from __future__ import annotations

import json
import time
import unittest
from unittest import mock

from fastapi import HTTPException
from fastapi.encoders import jsonable_encoder

from hub import audit, jobs
from hub.routers import api as api_router

#: Past CPython's default 4300-digit int<->str conversion limit.
_HUGE_INT = 10 ** 5000
#: What YAML ``id: 0x2A5F`` loads as (hex parses straight to int).
_HEX_ID = 0x2A5F


def _starlette(payload) -> None:
    """Exactly what Starlette's JSONResponse does to the payload."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _wait_finished(tid: str, timeout: float = 20.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = jobs._jobs.get(tid) or {}
        if isinstance(row, dict) and not row.get("running"):
            return row
        time.sleep(0.05)
    raise AssertionError(f"job {tid!r} did not finish")


class SurrogateTaskIdTests(unittest.TestCase):
    """A leftover ``\\ud800`` in the configured id: the mapping key must be
    the same scrubbed id the list serves, or the task is listed-but-dead."""

    _CFG = {"maintenance": [
        {"id": "task-\ud800", "name": "Ghost \ud800 task",
         "desc": "sur\ud800rogate", "command": "echo surrogate-ok",
         "timeout": 10},
    ]}

    def tearDown(self):
        jobs._jobs.clear()

    def test_mapping_is_utf8_encodable_keys_included(self):
        with mock.patch.object(jobs, "cfg", return_value=dict(self._CFG)):
            tasks = jobs.maintenance_tasks()
        _starlette(tasks)
        self.assertEqual(list(tasks), ["task-?"])

    def test_listed_id_is_the_mapping_key(self):
        with mock.patch.object(jobs, "cfg", return_value=dict(self._CFG)):
            rows = api_router.api_maintenance()
            tasks = jobs.maintenance_tasks()
        _starlette(jsonable_encoder(rows))
        self.assertEqual(rows[0]["id"], "task-?")
        self.assertIn(rows[0]["id"], tasks)
        # values are scrubbed too — keys AND values, the sweep contract
        self.assertEqual(rows[0]["name"], "Ghost ? task")
        self.assertEqual(rows[0]["desc"], "sur?rogate")

    def test_run_and_log_routes_accept_the_listed_id(self):
        """POST run with the id GET served used to 404 maintenance.unknown_task."""
        with (
            mock.patch.object(jobs, "cfg", return_value=dict(self._CFG)),
            mock.patch.object(audit, "record", lambda *a, **k: {}),
            mock.patch.object(api_router.audit, "record", lambda *a, **k: {}),
        ):
            listed = api_router.api_maintenance()[0]["id"]
            body = api_router.api_maintenance_run(listed)
        self.assertEqual(body, {"ok": True, "message": "Task started"})
        _wait_finished(listed)
        state = jobs.job_state(listed)
        self.assertEqual(state["rc"], 0)
        payload = api_router.api_maintenance_log(listed)
        _starlette(jsonable_encoder(payload))
        self.assertIn("surrogate-ok", payload["log"])


class HexIntTaskIdTests(unittest.TestCase):
    """YAML ``id: 0x2A5F`` loads as int; the task must not silently vanish."""

    _CFG = {"maintenance": [
        {"id": _HEX_ID, "name": "Hex task", "command": "echo hex-ok",
         "timeout": 10},
    ]}

    def tearDown(self):
        jobs._jobs.clear()

    def test_hex_int_id_is_listed_via_the_str_probe(self):
        with mock.patch.object(jobs, "cfg", return_value=dict(self._CFG)):
            rows = api_router.api_maintenance()
        _starlette(jsonable_encoder(rows))
        self.assertEqual([r["id"] for r in rows], [str(_HEX_ID)])

    def test_hex_int_id_round_trips_run_and_log(self):
        with (
            mock.patch.object(jobs, "cfg", return_value=dict(self._CFG)),
            mock.patch.object(audit, "record", lambda *a, **k: {}),
            mock.patch.object(api_router.audit, "record", lambda *a, **k: {}),
        ):
            body = api_router.api_maintenance_run(str(_HEX_ID))
        self.assertEqual(body, {"ok": True, "message": "Task started"})
        _wait_finished(str(_HEX_ID))
        payload = api_router.api_maintenance_log(str(_HEX_ID))
        _starlette(jsonable_encoder(payload))
        self.assertIn("hex-ok", payload["log"])

    def test_over_cap_int_id_drops_only_its_entry(self):
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": [
            {"id": _HUGE_INT, "name": "Huge", "command": "true"},
            {"id": "keep", "name": "Keep", "command": "true"},
        ]}):
            rows = api_router.api_maintenance()
            tasks = jobs.maintenance_tasks()
        _starlette(jsonable_encoder(rows))
        _starlette(tasks)
        self.assertEqual([r["id"] for r in rows], ["keep"])

    def test_bool_and_junk_ids_never_become_task_ids(self):
        """bool passes isinstance(int); ``True`` must not list as ``"True"``."""
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": [
            {"id": True, "name": "Bool", "command": "true"},
            {"id": None, "name": "NoneId", "command": "true"},
            {"id": float("inf"), "name": "Inf", "command": "true"},
            {"id": b"bin", "name": "Bytes", "command": "true"},
            {"id": "   ", "name": "Blank", "command": "true"},
        ]}):
            rows = api_router.api_maintenance()
        _starlette(jsonable_encoder(rows))
        self.assertEqual(rows, [])


class AlreadySafeSweepPins(unittest.TestCase):
    """The other two hunted classes were audited and found guarded; pinned."""

    def test_vanished_command_binary_is_a_job_result_not_an_error(self):
        """run_watchdog's own spawn failure lands in the log as rc -1 —
        never an exception the route would turn into a 500/503."""
        log: list[str] = []
        rc = jobs.run_watchdog(
            ["/definitely/not/a/real/cli-xyz"], timeout=10, log=log,
        )
        self.assertEqual(rc, -1)
        text = "\n".join(log)
        self.assertIn("!! error", text)
        _starlette({"rc": rc, "log": log})

    def test_bool_timeout_never_becomes_a_one_second_deadline(self):
        """YAML ``timeout: true`` is an int subclass worth 1 — a bool-as-int
        leftover must fall to the default, not arm a 1s killpg watchdog."""
        self.assertEqual(jobs._clamp_timeout(True), jobs.JOB_TIMEOUT_DEFAULT)
        self.assertEqual(jobs._clamp_timeout(False), jobs.JOB_TIMEOUT_DEFAULT)
        log: list[str] = []
        rc = jobs.run_watchdog(
            ["/bin/sh", "-c", "sleep 1.2; echo bool-clamp-ok"],
            timeout=True, log=log,
        )
        self.assertEqual(rc, 0)
        self.assertIn("bool-clamp-ok", "\n".join(log))
        self.assertNotIn("!! timeout", "\n".join(log))


if __name__ == "__main__":
    unittest.main()
