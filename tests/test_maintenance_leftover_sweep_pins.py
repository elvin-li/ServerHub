"""Leftover-500s sweep pins for the Maintenance page backends.

This sweep re-hunted the four leftover classes on GET /api/maintenance,
POST /api/maintenance/{tid}/run and GET /api/maintenance/{tid}/log and
found the domain already immune — prior passes installed ``jobs._jsonable``
(surrogate scrub for keys AND values, the ``str()`` digit probe for ints),
``jobs._task_id`` (hex/octal int ids coerce instead of vanishing behind an
``isinstance(str)`` gate), ``config._env_text``, and the vanished-CLI
job-result contract.  These tests pin the corners the existing files
(test_leftover_jobs_surrogate_hexid_500s, test_leftover_maintenance_jobs_
digit_500s, test_settings_config_modules_leftover_500s) do not cover, and
they pin them from the real ingestion side: ``yaml.safe_load`` text, not
Python-built ints, so a regression in the loader assumptions fails too.

* YAML ``id: 0x2A5F`` / ``id: 0755`` parse straight to int (PyYAML 1.1 hex
  and octal), *uncapped* — ``0x`` + 4400 hex digits loads fine because
  ``int(x, 16)`` is exempt from CPython's 4300-digit conversion limit — and
  a YAML ``"\\ud800"`` escape really does load as a lone surrogate.
* A surrogate in a NON-id task dict key (``"de\\ud800sc":``) must be
  scrubbed like the values are: Starlette encodes the whole mapping.
* A >4300-digit ``maintenance_env`` value degrades to ``""`` through the
  same ``str()`` probe family (ValueError is not special-cased away), while
  an under-cap int still renders — jobs keep their env instead of 500ing.
* Junk in-memory job rows (huge ``started``, surrogate ``finished``) stay
  servable on the log route.
* Failure shapes stay coded: unknown task is 404 ``maintenance.unknown_task``
  and a concurrent second run is 409 ``jobs.already_running`` — never a
  bare 500, and never silently reshaped by the sweep guards.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

import yaml
from fastapi import HTTPException
from fastapi.encoders import jsonable_encoder

from hub import config, jobs
from hub.routers import api as api_router

#: Past CPython's default 4300-digit int<->str conversion limit.
_HUGE_INT = 10 ** 5000
#: Under the cap: ``str()`` renders it, so it must survive.
_BIG_INT = 10 ** 400


def _starlette(payload) -> None:
    """Exactly what Starlette's JSONResponse does to the payload."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


#: Real services.yaml text, not Python-built objects: hex and octal ids load
#: already-int, the 4400-hex-digit id loads uncapped, and the double-quoted
#: escapes load as a lone surrogate in a value AND in a non-id mapping key.
_YAML_TEXT = (
    "maintenance:\n"
    "  - id: 0x2A5F\n"
    '    name: "up\\ud800grade"\n'
    '    "de\\ud800sc": "leftover"\n'
    "    command: echo hex-ok\n"
    "  - id: 0755\n"
    "    name: Octal\n"
    "    command: 'true'\n"
    "  - id: 0x" + "F" * 4400 + "\n"
    "    name: Overcap\n"
    "    command: 'true'\n"
)


class YamlIngestionPins(unittest.TestCase):
    """The loader really produces the leftovers the guards were built for."""

    @classmethod
    def setUpClass(cls):
        cls.data = yaml.safe_load(_YAML_TEXT)

    def test_yaml_loader_assumptions_still_hold(self):
        rows = self.data["maintenance"]
        self.assertEqual(rows[0]["id"], 0x2A5F)
        self.assertEqual(rows[1]["id"], 0o755)
        self.assertGreater(rows[2]["id"].bit_length(), 4300 * 3)
        self.assertIn("\ud800", rows[0]["name"])
        self.assertIn("de\ud800sc", rows[0])

    def test_hex_and_octal_ids_list_and_over_cap_drops_only_its_entry(self):
        with mock.patch.object(jobs, "cfg", return_value=self.data):
            rows = api_router.api_maintenance()
            tasks = jobs.maintenance_tasks()
        _starlette(jsonable_encoder(rows))
        _starlette(tasks)
        self.assertEqual([r["id"] for r in rows], [str(0x2A5F), str(0o755)])

    def test_surrogate_in_a_non_id_key_is_scrubbed_with_the_values(self):
        """Keys AND values — a ``"de\\ud800sc":`` key used to be the one
        spot _jsonable's value scrub could not reach before it grew the
        key pass; pin that the whole mapping stays UTF-8 encodable."""
        with mock.patch.object(jobs, "cfg", return_value=self.data):
            tasks = jobs.maintenance_tasks()
        _starlette(tasks)
        row = tasks[str(0x2A5F)]
        self.assertEqual(row["name"], "up?grade")
        self.assertEqual(row.get("de?sc"), "leftover")
        blob = "".join(k for t in tasks.values() for k in t)
        self.assertNotIn("\ud800", blob)


class MaintenanceEnvDigitPins(unittest.TestCase):
    """The env every job inherits takes the same ``str()`` probe: a
    >4300-digit value degrades to ``""`` (the str->text ValueError is not a
    500 and not a dropped job), an under-cap int still renders."""

    def test_over_cap_env_value_degrades_under_cap_survives(self):
        section = {"HUGE": _HUGE_INT, "BIG": _BIG_INT, "PATH": "/bin"}
        with mock.patch.object(config, "settings_section", return_value=section):
            env = config.maintenance_env()
        self.assertEqual(env["HUGE"], "")
        self.assertEqual(env["BIG"], str(_BIG_INT))
        self.assertEqual(env["PATH"], "/bin")
        for key, value in env.items():
            key.encode("utf-8")
            value.encode("utf-8")


class JobRowJunkPins(unittest.TestCase):
    def tearDown(self):
        jobs._jobs.clear()

    def test_huge_started_and_surrogate_finished_do_not_500_the_log(self):
        jobs._jobs["ghost"] = {
            "running": False, "rc": 0,
            "started": _HUGE_INT, "finished": "12:\ud80000",
            "log": ["$ true", "done"],
        }
        body = api_router.api_maintenance_log("ghost")
        _starlette(jsonable_encoder(body))
        self.assertIsNone(body["started"])
        self.assertEqual(body["finished"], "12:?00")
        self.assertIn("done", body["log"])


class FailureShapePins(unittest.TestCase):
    """Timeout/auth-style failures keep their coded shape — the sweep guards
    must not flatten them into 200s or bare 500s."""

    def tearDown(self):
        jobs._jobs.clear()

    def test_unknown_task_stays_a_coded_404(self):
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": []}):
            with self.assertRaises(HTTPException) as raised:
                api_router.api_maintenance_run("no-such-task")
        self.assertEqual(raised.exception.status_code, 404)
        self.assertEqual(raised.exception.detail["code"], "maintenance.unknown_task")

    def test_concurrent_second_run_stays_a_coded_409(self):
        jobs._jobs["busy"] = {"running": True, "rc": None, "log": []}
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": [
            {"id": "other", "name": "Other", "command": "true"},
        ]}):
            with self.assertRaises(HTTPException) as raised:
                api_router.api_maintenance_run("other")
        self.assertEqual(raised.exception.status_code, 409)
        self.assertEqual(raised.exception.detail["code"], "jobs.already_running")
        # the refused run must not have replaced the running row
        self.assertNotIn("other", jobs._jobs)


if __name__ == "__main__":
    unittest.main()
