"""Third leftover-500s sweep of the Jobs domain, pinned at the real ASGI layer.

The hunted classes were re-reproduced against the live routes (a FastAPI app
running hub/routers/api.py end to end, not in-process handler calls) and the
domain was found immune — prior sweeps installed ``jobs._jsonable`` (surrogate
scrub for keys AND values, the ``str()`` digit probe for ints),
``jobs._task_id`` (hex/octal already-int ids coerce instead of vanishing
behind an ``isinstance(str)`` gate; an over-cap id drops only its entry),
``jobs._log_lines`` / ``jobs.job_log`` (junk rows), and the vanished-CLI
job-result contract.  Those pins live in test_leftover_jobs_surrogate_hexid_
500s, test_leftover_maintenance_jobs_digit_500s and
test_maintenance_leftover_sweep_pins — all exercising handlers in-process
with a simulated Starlette encode.  This file pins the same contracts one
layer up, through real request routing, path-parameter decoding and response
rendering, so a regression in the route signatures or response classes fails
too.

One live bug WAS left and is fixed here (hub/jobs.py ``start_job``): a task
whose ``command`` is missing from services.yaml — or was a junk leftover
(``command: 0x`` + 4400 hex digits) that ``_jsonable``'s digit probe dropped
to None — ran to ``rc: -1`` with a completely EMPTY log.  GET
/api/maintenance/{tid}/log then served ``"(waiting for output…)"`` under a
failure badge forever: a silent loss of the only diagnostic the page has.
The invalid-command branch now logs ``!! invalid command``, and the outer
``except Exception`` swallow logs ``!! error: <reason>`` instead of erasing
the cause.
"""
from __future__ import annotations

import asyncio
import json
import time
import unittest
from unittest import mock
from urllib.parse import quote

import yaml
from fastapi import FastAPI

from hub import audit, jobs
from hub.routers import api as api_router

#: Past CPython's default 4300-digit int<->str conversion limit.
_HUGE_INT = 10 ** 5000


async def _asgi_request(method, path, *, raw_path=None):
    """Drive hub/routers/api.py through a real ASGI cycle."""
    app = FastAPI()
    app.include_router(api_router.router)
    sent = False
    messages: list[dict] = []

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": b"", "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1", "method": method, "scheme": "http",
        # scope["path"] is the DECODED path (what routing matches);
        # raw_path carries the on-the-wire percent-encoded bytes.
        "path": path,
        "raw_path": (raw_path if raw_path is not None
                     else quote(path, safe="/").encode()),
        "query_string": b"", "root_path": "",
        "headers": [(b"content-type", b"application/json")],
        "server": ("localhost", 8086), "client": ("127.0.0.1", 1), "state": {},
    }
    await app(scope, receive, send)
    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    raw = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    # The body must already be valid UTF-8 JSON — decode strictly on purpose.
    return status, json.loads(raw.decode("utf-8")) if raw else None


def request(method, path, *, raw_path=None):
    return asyncio.run(_asgi_request(method, path, raw_path=raw_path))


def _wait_finished(tid: str, timeout: float = 20.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = jobs._jobs.get(tid) or {}
        if isinstance(row, dict) and not row.get("running"):
            return row
        time.sleep(0.05)
    raise AssertionError(f"job {tid!r} did not finish")


def _patched(cfg):
    """cfg + audit stubs for route-level runs (audit is not under test)."""
    return (
        mock.patch.object(jobs, "cfg", return_value=cfg),
        mock.patch.object(audit, "record", lambda *a, **k: {}),
        mock.patch.object(api_router.audit, "record", lambda *a, **k: {}),
    )


#: Real services.yaml text: hex/octal ids load already-int, the 4400-hex-digit
#: id loads uncapped (``int(x, 16)`` is exempt from the digit limit), and the
#: escapes load as lone surrogates in the id, a value, AND a non-id key.
_YAML_TEXT = (
    "maintenance:\n"
    '  - id: "task-\\ud800"\n'
    '    name: "Ghost \\ud800 task"\n'
    '    "de\\udfffsc": "leftover"\n'
    "    command: echo asgi-surrogate-ok\n"
    "    timeout: 10\n"
    "  - id: 0x2A5F\n"
    "    name: Hex\n"
    "    command: 'true'\n"
    "  - id: 0755\n"
    "    name: Octal\n"
    "    command: 'true'\n"
    "  - id: 0x" + "F" * 4400 + "\n"
    "    name: Overcap\n"
    "    command: 'true'\n"
)


class AsgiListPins(unittest.TestCase):
    """GET /api/maintenance over real ASGI with loader-produced leftovers."""

    @classmethod
    def setUpClass(cls):
        cls.cfg = yaml.safe_load(_YAML_TEXT)

    def tearDown(self):
        jobs._jobs.clear()

    def test_list_is_http_200_utf8_and_serves_routable_ids(self):
        with (p := _patched(self.cfg))[0], p[1], p[2]:
            status, rows = request("GET", "/api/maintenance")
        self.assertEqual(status, 200)
        # surrogate id scrubbed, hex/octal ids coerced, over-cap id dropped —
        # and only the over-cap entry, not the whole list.
        self.assertEqual([r["id"] for r in rows],
                         ["task-?", str(0x2A5F), str(0o755)])
        self.assertEqual(rows[0]["name"], "Ghost ? task")

    def test_listed_surrogate_id_round_trips_run_and_log_over_asgi(self):
        """The id GET serves must be the id POST /run matches — through real
        path-parameter decoding, not an in-process function call."""
        with (p := _patched(self.cfg))[0], p[1], p[2]:
            _, rows = request("GET", "/api/maintenance")
            listed = rows[0]["id"]
            status, body = request(
                "POST", f"/api/maintenance/{listed}/run",
                raw_path=f"/api/maintenance/{quote(listed)}/run".encode(),
            )
            self.assertEqual(status, 200, body)
            self.assertEqual(body, {"ok": True, "message": "Task started"})
            _wait_finished(listed)
            status, payload = request(
                "GET", f"/api/maintenance/{listed}/log",
                raw_path=f"/api/maintenance/{quote(listed)}/log".encode(),
            )
        self.assertEqual(status, 200)
        self.assertEqual(payload["rc"], 0)
        self.assertIn("asgi-surrogate-ok", payload["log"])


class AsgiJobRowJunkPins(unittest.TestCase):
    """GET /api/maintenance/{tid}/log over real ASGI with poisoned rows."""

    def tearDown(self):
        jobs._jobs.clear()

    def test_mixed_junk_log_items_and_surrogate_times_stay_http_200(self):
        jobs._jobs["ghost"] = {
            "running": False, "rc": _HUGE_INT, "started": _HUGE_INT,
            "finished": "12:\ud80000",
            "log": ["l\ud800ine", b"\xff\xfe", None, _HUGE_INT, 3.5, "done"],
        }
        status, body = request("GET", "/api/maintenance/ghost/log")
        self.assertEqual(status, 200)
        self.assertIsNone(body["rc"])
        self.assertIsNone(body["started"])
        self.assertEqual(body["finished"], "12:?00")
        # str/bytes items kept (scrubbed), None/int/float dropped, no 500.
        self.assertIn("l?ine", body["log"])
        self.assertIn("done", body["log"])
        self.assertNotIn("\ud800", body["log"])

    def test_non_dict_row_and_unknown_tid_serve_the_missing_shape(self):
        jobs._jobs["junk"] = "not-a-dict"
        for tid in ("junk", "never-ran"):
            with self.subTest(tid=tid):
                status, body = request("GET", f"/api/maintenance/{tid}/log")
                self.assertEqual(status, 200)
                self.assertEqual(
                    body, {"running": False, "rc": None, "log": "(not run yet)"})


class AsgiFailureShapePins(unittest.TestCase):
    """Coded failure shapes survive the sweep guards at the HTTP layer, and a
    vanished CLI stays a job *result* (the 503-vs-500 contract this domain
    pinned: there is no synchronous CLI on the run path to probe, so nothing
    here may be reshaped into a 503)."""

    _CFG = {"maintenance": [
        {"id": "gone", "name": "CLI gone",
         "command": "/definitely/not/a/real/cli-xyz", "timeout": 10},
    ]}

    def tearDown(self):
        jobs._jobs.clear()

    def test_unknown_task_is_a_coded_404_over_asgi(self):
        with (p := _patched({"maintenance": []}))[0], p[1], p[2]:
            status, body = request("POST", "/api/maintenance/nope/run")
        self.assertEqual(status, 404)
        self.assertEqual(body["detail"]["code"], "maintenance.unknown_task")

    def test_concurrent_second_run_is_a_coded_409_over_asgi(self):
        jobs._jobs["busy"] = {"running": True, "rc": None, "log": []}
        with (p := _patched(self._CFG))[0], p[1], p[2]:
            status, body = request("POST", "/api/maintenance/gone/run")
        self.assertEqual(status, 409)
        self.assertEqual(body["detail"]["code"], "jobs.already_running")

    def test_vanished_cli_is_a_job_result_never_a_500_or_503(self):
        with (p := _patched(self._CFG))[0], p[1], p[2]:
            status, body = request("POST", "/api/maintenance/gone/run")
            self.assertEqual(status, 200, body)
            _wait_finished("gone")
            status, payload = request("GET", "/api/maintenance/gone/log")
        self.assertEqual(status, 200)
        # bash ran, the binary inside it is gone: 127 by contract.
        self.assertEqual(payload["rc"], 127)
        self.assertIn("cli-xyz", payload["log"])


class InvalidCommandSilentLossTests(unittest.TestCase):
    """The one live leftover this sweep fixed: an unusable command must leave
    a reason in the log, not rc -1 over ``"(waiting for output…)"``."""

    _CFG = {"maintenance": [
        {"id": "no-cmd", "name": "No command", "timeout": 10},
        # _jsonable's digit probe drops the over-cap int command to None
        # before start_job sees it — the junk-leftover flavour of the same
        # empty-log failure.
        {"id": "huge-cmd", "name": "Huge command",
         "command": _HUGE_INT, "timeout": 10},
        {"id": "blank-cmd", "name": "Blank command",
         "command": "   ", "timeout": 10},
    ]}

    def tearDown(self):
        jobs._jobs.clear()

    def test_unusable_command_leaves_a_reason_in_the_log(self):
        for tid in ("no-cmd", "huge-cmd", "blank-cmd"):
            with self.subTest(tid=tid):
                jobs._jobs.clear()
                with (p := _patched(self._CFG))[0], p[1], p[2]:
                    status, body = request("POST", f"/api/maintenance/{tid}/run")
                    self.assertEqual(status, 200, body)
                    _wait_finished(tid)
                    status, payload = request("GET", f"/api/maintenance/{tid}/log")
                self.assertEqual(status, 200)
                self.assertEqual(payload["rc"], -1)
                self.assertFalse(payload["running"])
                self.assertIn("!! invalid command", payload["log"])
                self.assertNotIn("waiting for output", payload["log"])

    def test_pre_watchdog_exception_leaves_a_reason_in_the_log(self):
        """A failure before run_watchdog (a poisoned maintenance_env read)
        used to be erased to a bare rc -1 by the except swallow."""
        def _boom():
            raise RuntimeError("env read fail\ud800ed")

        with (
            mock.patch.object(jobs, "cfg", return_value={"maintenance": [
                {"id": "env-boom", "name": "Env boom", "command": "true"},
            ]}),
            mock.patch.object(jobs, "maintenance_env", _boom),
            mock.patch.object(audit, "record", lambda *a, **k: {}),
            mock.patch.object(api_router.audit, "record", lambda *a, **k: {}),
        ):
            status, body = request("POST", "/api/maintenance/env-boom/run")
            self.assertEqual(status, 200, body)
            _wait_finished("env-boom")
            status, payload = request("GET", "/api/maintenance/env-boom/log")
        self.assertEqual(status, 200)
        self.assertEqual(payload["rc"], -1)
        self.assertIn("!! error", payload["log"])
        # the reason survives, surrogate-scrubbed for the encoder
        self.assertIn("env read fail?ed", payload["log"])


if __name__ == "__main__":
    unittest.main()
