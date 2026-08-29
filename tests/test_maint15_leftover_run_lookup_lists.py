"""Fifteenth leftover-500s sweep of the Maintenance surface.

maint14 sealed mid-walk mutation, heap-address reprs, wrong-rank recovery,
and unbound sequence iteration on the listing/log pipe.  A leftover hunt
over the same mounted tree (create_app + TestClient,
raise_server_exceptions=False) drove the rank those sweeps left bare: the
**run-route lookup**.

POST /api/maintenance/{tid}/run still walked
``jobs.maintenance_tasks().get(tid)`` and then ``if not task`` — a leftover
dict-*subclass* listing whose bound ``.get`` bombs, or a leftover row whose
``__bool__`` bombs, 500'd every Run from the surface itself.  The lookup now
lives in :func:`hub.jobs.lookup_maintenance_task` (``_mapping_get`` +
``_plain_dict``; never raises).

The SPA half of the same hunt: leftover *lists* that are not arrays, leftover
null cells inside a real list, and leftover log *mappings* that are lists,
used to throw out of ``.length`` / ``.filter`` / ``.some`` / ``j.log`` on
Maintenance.vue.  Those pins live in web/src/views/Maintenance.test.js.
"""
from __future__ import annotations

import time
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import config, jobs
from hub.app_factory import create_app
from hub.auth import require_auth

_app = None


def _the_app():
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return _app


def _client() -> TestClient:
    return TestClient(_the_app(), raise_server_exceptions=False)


def _clean(response) -> None:
    text = response.text
    assert "\ud800" not in text, text[:300]
    text.encode("utf-8")


def _wait_finished(tid: str, timeout: float = 20.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = jobs._jobs_row(tid) or {}
        if isinstance(row, dict) and not row.get("running"):
            return row
        time.sleep(0.05)
    raise AssertionError(f"job {tid!r} did not finish")


class _GetBomb(dict):
    """Bound ``.get`` detonates — the pre-fix run route called this."""

    def get(self, *a, **k):  # noqa: D102
        raise RuntimeError("leftover listing get bomb")


class _BoolBombRow(dict):
    """A found row whose truth test detonates the pre-fix ``if not task``."""

    def __bool__(self):
        raise RuntimeError("leftover row bool bomb")


class _DiskYamlSandbox(unittest.TestCase):
    YAML_TEXT = "maintenance:\n  - id: plain\n    name: Plain\n    command: 'true'\n    timeout: 10\n"

    def setUp(self):
        try:
            self._original = config.YAML_PATH.read_bytes()
        except FileNotFoundError:
            self._original = None
        config.YAML_PATH.parent.mkdir(parents=True, exist_ok=True)
        config.YAML_PATH.write_text(self.YAML_TEXT, encoding="utf-8")
        config.reload_cfg()
        self.addCleanup(self._restore)
        jobs._jobs.clear()
        self.addCleanup(jobs._jobs.clear)

    def _restore(self):
        try:
            config.YAML_PATH.unlink()
        except FileNotFoundError:
            pass
        if self._original is not None:
            config.YAML_PATH.write_bytes(self._original)
        config.reload_cfg()


class RunRouteLookupTests(_DiskYamlSandbox):
    """The fixed 500s: a leftover listing mapping used to crash POST run."""

    def test_get_bomb_listing_still_starts_the_configured_task(self):
        honest = jobs.maintenance_tasks()
        poisoned = _GetBomb(honest)
        with mock.patch.object(jobs, "maintenance_tasks", return_value=poisoned):
            response = _client().post("/api/maintenance/plain/run")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        body = response.json()
        self.assertTrue(body.get("ok"))
        _wait_finished("plain")

    def test_bool_bomb_row_still_starts_the_configured_task(self):
        honest = jobs.maintenance_tasks()
        row = honest["plain"]
        poisoned = {"plain": _BoolBombRow(row)}
        with mock.patch.object(jobs, "maintenance_tasks", return_value=poisoned):
            response = _client().post("/api/maintenance/plain/run")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        _wait_finished("plain")

    def test_unknown_id_is_still_404_not_500(self):
        response = _client().post("/api/maintenance/no-such-task/run")
        self.assertEqual(response.status_code, 404, response.text[:300])
        _clean(response)


class ListingAndLogStayUp(_DiskYamlSandbox):
    """The maint12–14 union must not weaken: list and log still 200."""

    def test_list_and_log_are_json(self):
        listing = _client().get("/api/maintenance")
        self.assertEqual(listing.status_code, 200, listing.text[:300])
        _clean(listing)
        rows = listing.json()
        self.assertTrue(any(r.get("id") == "plain" for r in rows))
        log = _client().get("/api/maintenance/plain/log")
        self.assertEqual(log.status_code, 200, log.text[:300])
        _clean(log)
        self.assertIn("log", log.json())


class ControlFlowStillPropagates(unittest.TestCase):
    def test_keyboardinterrupt_from_tasks_is_not_swallowed(self):
        def boom():
            raise KeyboardInterrupt
        with mock.patch.object(jobs, "maintenance_tasks", side_effect=boom):
            with self.assertRaises(KeyboardInterrupt):
                jobs.lookup_maintenance_task("plain")
