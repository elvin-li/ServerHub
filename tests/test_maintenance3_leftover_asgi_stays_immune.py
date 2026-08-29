"""Third leftover-500s sweep of the Maintenance page, pinned over real ASGI.

The four hunted classes (lone UTF-8 surrogates in keys AND values, the
CPython 4300-digit int cap via uncapped YAML hex, numeric YAML ids behind
``isinstance(str)`` gates, vanished-CLI 503-vs-500) were re-reproduced
against the live routes and the domain was found immune — the guards from
the prior passes (``jobs._jsonable`` / ``_task_id`` / ``_log_lines``,
``config._env_text``, ``audit._jsonable``) hold.  The live leftovers this
sweep DID find were both in the SPA: web/src/api/client.js interpolated the
raw task id into the run/log URLs (a listed ``task-?`` id 404'd as
maintenance.unknown_task because ``?`` became the query separator), and the
Maintenance.vue filter crashed on the int name/desc values the API
deliberately serves.  Those fixes are pinned in web/src tests; this file
pins the backend corners the existing four files do not cover, all through
real request routing and response rendering:

* GET /api/maintenance merges *poisoned in-memory job rows* into listed
  tasks (huge ``rc``, NaN ``started``, surrogate ``finished``, a bool
  ``rc``, a non-dict row) — the prior ASGI list pin only fed loader
  leftovers, and the in-process junk-row pins never crossed job_state's
  merge on the list route.
* A YAML timestamp id (``id: 2026-08-25`` loads as ``datetime.date``) and
  a ``maintenance:`` section of the wrong shape drop cleanly instead of
  reshaping the list into a 500.
* A tid that decodes to a lone surrogate stays the coded 404 on run and
  the missing shape on log — the error body itself must stay UTF-8
  encodable with the junk id in hand.
* A poisoned ``settings.maintenance_env`` (huge-int key from uncapped YAML
  hex, huge-int value, surrogate key) ingested from real YAML text still
  lets POST run start the job and the command still executes: the env
  degrades per-entry, never the whole run (the "drop the field, keep the
  event" rule).
"""
from __future__ import annotations

import asyncio
import datetime
import json
import time
import unittest
from unittest import mock
from urllib.parse import quote

import yaml
from fastapi import FastAPI

from hub import audit, config, jobs
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


class ListMergesPoisonedJobRowsPins(unittest.TestCase):
    """GET /api/maintenance merges job_state() into every listed task; the
    junk-row pins so far only exercised the *log* route over ASGI."""

    _CFG = {"maintenance": [
        {"id": "huge-rc", "name": "Huge rc", "command": "true"},
        {"id": "nan-start", "name": "NaN start", "command": "true"},
        {"id": "bool-rc", "name": "Bool rc", "command": "true"},
        {"id": "junk-row", "name": "Junk row", "command": "true"},
    ]}

    def setUp(self):
        jobs._jobs.clear()
        jobs._jobs.update({
            "huge-rc": {"running": False, "rc": _HUGE_INT, "finished": "12:\ud80000"},
            "nan-start": {"running": False, "rc": 0,
                          "started": float("nan"), "finished": float("inf")},
            "bool-rc": {"running": False, "rc": True, "finished": "00:00:09"},
            "junk-row": "not-a-dict",
        })

    def tearDown(self):
        jobs._jobs.clear()

    def test_list_stays_http_200_with_junk_rows_merged_in(self):
        with (p := _patched(self._CFG))[0], p[1], p[2]:
            status, rows = request("GET", "/api/maintenance")
        self.assertEqual(status, 200)
        by_id = {r["id"]: r for r in rows}
        self.assertEqual(sorted(by_id), ["bool-rc", "huge-rc", "junk-row", "nan-start"])
        # over-cap rc dropped like its inf sibling; the surrogate is scrubbed
        self.assertIsNone(by_id["huge-rc"]["rc"])
        self.assertEqual(by_id["huge-rc"]["finished"], "12:?00")
        # NaN/inf timestamps drop to null, the row itself survives
        self.assertIsNone(by_id["nan-start"]["finished"])
        self.assertEqual(by_id["nan-start"]["rc"], 0)
        # bool rc is not reshaped into 1 — job_state serves it verbatim
        self.assertIs(by_id["bool-rc"]["rc"], True)
        # a non-dict row degrades to the never-ran shape, not a 500
        self.assertEqual(by_id["junk-row"]["running"], False)
        self.assertIsNone(by_id["junk-row"]["rc"])


class LoaderShapeLeftoverPins(unittest.TestCase):
    """Real yaml.safe_load text — ids/sections the guards must drop whole."""

    def test_date_id_drops_only_its_entry(self):
        # PyYAML resolves the bare scalar to datetime.date; _task_id must
        # treat it like any other non-str/non-int leftover.
        data = yaml.safe_load(
            "maintenance:\n"
            "  - id: 2026-08-25\n"
            "    name: Dated\n"
            "    command: 'true'\n"
            "  - id: keep\n"
            "    name: Keep\n"
            "    command: 'true'\n"
        )
        self.assertIsInstance(data["maintenance"][0]["id"], datetime.date)
        with (p := _patched(data))[0], p[1], p[2]:
            status, rows = request("GET", "/api/maintenance")
        self.assertEqual(status, 200)
        self.assertEqual([r["id"] for r in rows], ["keep"])

    def test_wrong_shaped_maintenance_section_is_an_empty_200(self):
        for section in ({"id": "x"}, "text", 7, None):
            with self.subTest(section=section):
                cfg = {"maintenance": section}
                with (p := _patched(cfg))[0], p[1], p[2]:
                    status, rows = request("GET", "/api/maintenance")
                self.assertEqual(status, 200)
                self.assertEqual(rows, [])

    def test_nan_desc_and_inf_confirm_from_yaml_stay_http_200(self):
        data = yaml.safe_load(
            "maintenance:\n"
            "  - id: odd\n"
            "    name: Odd\n"
            "    desc: .nan\n"
            "    confirm: .inf\n"
            "    command: 'true'\n"
        )
        with (p := _patched(data))[0], p[1], p[2]:
            status, rows = request("GET", "/api/maintenance")
        # allow_nan=False: a 200 proves the NaN never reached the encoder.
        self.assertEqual(status, 200)
        self.assertIsNone(rows[0]["desc"])
        # inf is dropped by the row sanitizer *before* bool() ever sees it,
        # so a junk confirm fails closed to the unconfirmed default.
        self.assertIs(rows[0]["confirm"], False)


class SurrogateTidPathPins(unittest.TestCase):
    """A tid that *decodes* to a lone surrogate must keep the coded failure
    shapes; the round-trip pin only covered the scrubbed (listed) form."""

    def tearDown(self):
        jobs._jobs.clear()

    def test_run_stays_the_coded_404_and_the_body_encodes(self):
        with (p := _patched({"maintenance": []}))[0], p[1], p[2]:
            status, body = request(
                "POST", "/api/maintenance/task-\ud800/run",
                raw_path=b"/api/maintenance/task-%ED%A0%80/run",
            )
        self.assertEqual(status, 404)
        self.assertEqual(body["detail"]["code"], "maintenance.unknown_task")

    def test_log_serves_the_missing_shape_not_a_500(self):
        status, body = request(
            "GET", "/api/maintenance/task-\ud800/log",
            raw_path=b"/api/maintenance/task-%ED%A0%80/log",
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, {"running": False, "rc": None, "log": "(not run yet)"})


class PoisonedMaintenanceEnvRunPins(unittest.TestCase):
    """POST run with a poisoned settings.maintenance_env loaded from real
    YAML text: entries degrade one by one, the job itself still runs."""

    #: The huge-int key needs YAML's explicit-key form: implicit block keys
    #: are capped at 1024 characters by the scanner, explicit ones are not.
    _YAML_TEXT = (
        "settings:\n"
        "  maintenance_env:\n"
        "    ? 0x" + "F" * 4400 + "\n"
        "    : from-huge-key\n"
        "    HUGE_VALUE: 0x" + "F" * 4400 + "\n"
        '    "SURRO\\ud800GATE": kept\n'
        "    MAINT_PROBE: probe-ok\n"
        "maintenance:\n"
        "  - id: env-run\n"
        "    name: Env run\n"
        "    command: echo \"probe=$MAINT_PROBE huge=$HUGE_VALUE\"\n"
        "    timeout: 10\n"
    )

    def tearDown(self):
        jobs._jobs.clear()

    def test_run_starts_and_the_command_sees_the_degraded_env(self):
        data = yaml.safe_load(self._YAML_TEXT)
        # the loader really produced the leftovers the guards were built for
        env_section = data["settings"]["maintenance_env"]
        self.assertTrue(any(isinstance(k, int) for k in env_section))
        self.assertIn("SURRO\ud800GATE", env_section)
        with (
            mock.patch.object(jobs, "cfg", return_value=data),
            mock.patch.object(config, "cfg", return_value=data),
            mock.patch.object(audit, "record", lambda *a, **k: {}),
            mock.patch.object(api_router.audit, "record", lambda *a, **k: {}),
        ):
            # the env every job inherits degrades per entry, never wholesale
            env = config.maintenance_env()
            self.assertEqual(env["MAINT_PROBE"], "probe-ok")
            self.assertEqual(env["HUGE_VALUE"], "")
            self.assertEqual(env["SURRO?GATE"], "kept")
            for key, value in env.items():
                key.encode("utf-8")
                value.encode("utf-8")
            status, body = request("POST", "/api/maintenance/env-run/run")
            self.assertEqual(status, 200, body)
            _wait_finished("env-run")
            status, payload = request("GET", "/api/maintenance/env-run/log")
        self.assertEqual(status, 200)
        self.assertEqual(payload["rc"], 0)
        # the sane entry reached the child; the over-cap value degraded to ""
        self.assertIn("probe=probe-ok huge=", payload["log"])
        self.assertNotIn("from-huge-key", payload["log"])


if __name__ == "__main__":
    unittest.main()
