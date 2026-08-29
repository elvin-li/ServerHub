"""Fifteenth leftover-500s sweep of the Jobs domain: listing JSON walk.

jobs14 sealed mid-walk mutation, default-repr heap addresses, and lying
``__class__`` recovery on ``hub.jobs``.  The scheduler listing walk
(GET /api/scheduler/jobs) still used a live ``dict.items`` iteration, bound
``list()`` on sequences, and dispatching ``str()`` on junk keys — the same
leftover classes 500'd the jobs table the SPA reads.

These tests plant each leftover against the scheduler listing and assert 200
bodies with valid UTF-8 JSON, never a raw raise and never a heap address.
"""
from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import jobs, scheduler_svc  # noqa: E402

_APP = None
_ADDR = re.compile(r" at 0x[0-9a-fA-F]+>")


def _client():
    global _APP
    from fastapi.testclient import TestClient

    if _APP is None:
        from hub.app_factory import create_app
        from hub.auth import require_auth

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _MidWalkMutator:
    def __init__(self):
        self.host = None
        self.fired = False

    @property
    def __class__(self):
        if not self.fired and self.host is not None:
            self.fired = True
            self.host.pop("victim", None)
        raise AttributeError("leftover class probe")


def _mutating_row(jid="job-1"):
    bomb = _MidWalkMutator()
    row = {"id": jid, "name": "n", "type": "command", "cron": "0 3 * * *",
           "enabled": False, "params": {}, "junk": bomb, "victim": 1}
    bomb.host = row
    return row


class _Junk:
    """No ``__str__`` / ``__repr__`` override: default heap-address repr."""


class _LyingIntStr(str):
    @property
    def __class__(self):
        return int


class _LyingStrDict(dict):
    @property
    def __class__(self):
        return str


class _IterBombList(list):
    def __iter__(self):
        raise RuntimeError("iter bomb")


class ListingJsonWalkTests(unittest.TestCase):
    def test_jsonable_snapshots_the_dict_walk(self):
        row = _mutating_row()
        cleaned = scheduler_svc._jsonable(row)
        self.assertIsInstance(cleaned, dict)
        self.assertEqual(cleaned["id"], "job-1")
        _starlette(cleaned)

    def test_listing_keeps_siblings_of_a_mid_walk_mutator(self):
        rows = [_mutating_row("junk"), {
            "id": "ok", "name": "ok", "type": "command",
            "cron": "0 3 * * *", "enabled": False, "params": {},
        }]
        with mock.patch.object(scheduler_svc, "cfg",
                               return_value={"schedules": rows}):
            r = _client().get("/api/scheduler/jobs")
        self.assertEqual(r.status_code, 200, r.text[:300])
        payload = r.json()
        _starlette(payload)
        by_id = {j.get("id"): j for j in payload.get("jobs") or []}
        self.assertIn("ok", by_id)
        self.assertIn("junk", by_id)

    def test_listing_carries_no_heap_address(self):
        rows = [{
            "id": "job-1", "name": "n", "type": "command",
            "cron": "0 3 * * *", "enabled": False, "params": {},
            "note": _Junk(), _Junk(): "junk-keyed",
        }]
        with mock.patch.object(scheduler_svc, "cfg",
                               return_value={"schedules": rows}):
            r = _client().get("/api/scheduler/jobs")
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertIsNone(_ADDR.search(r.text), r.text[:300])

    def test_jsonable_recovers_str_storage_lying_int(self):
        self.assertEqual(
            scheduler_svc._jsonable(_LyingIntStr("Nightly")), "Nightly")

    def test_jsonable_recovers_mapping_storage_lying_str(self):
        self.assertEqual(
            scheduler_svc._jsonable(_LyingStrDict({"a": 1})), {"a": 1})

    def test_jsonable_recovers_iter_bomb_list_storage(self):
        # jobs recovers C-level sequence storage; scheduler_svc keeps the
        # jobs5/jobs13 guarded drop so an __iter__ bomb cannot inflate
        # GET /api/scheduler/jobs.
        self.assertEqual(jobs._jsonable(_IterBombList([1, "x"])), [1, "x"])
        self.assertIsNone(scheduler_svc._jsonable(_IterBombList([1, "x"])))

    def test_list_jobs_recovers_iter_bomb_schedules(self):
        rows = _IterBombList([{
            "id": "ok", "name": "ok", "type": "command",
            "cron": "0 3 * * *", "enabled": False, "params": {},
        }])
        with mock.patch.object(scheduler_svc, "cfg",
                               return_value={"schedules": rows}):
            listed = scheduler_svc.list_jobs()
        self.assertEqual(listed, [])

    def test_name_lying_int_survives_into_the_listing(self):
        rows = [{
            "id": "job-1", "name": _LyingIntStr("Nightly cleanup"),
            "type": "command", "cron": "0 3 * * *",
            "enabled": False, "params": {},
        }]
        with mock.patch.object(scheduler_svc, "cfg",
                               return_value={"schedules": rows}):
            r = _client().get("/api/scheduler/jobs")
        self.assertEqual(r.status_code, 200, r.text[:300])
        by_id = {j.get("id"): j for j in r.json().get("jobs") or []}
        self.assertEqual(by_id["job-1"]["name"], "Nightly cleanup")

    def test_utf8_text_drops_a_default_repr_object(self):
        self.assertEqual(scheduler_svc._utf8_text(_Junk()), "")

    def test_utf8_text_keeps_real_text_verbatim(self):
        literal = "grep for ' at 0x1234>' in the log"
        self.assertEqual(scheduler_svc._utf8_text(literal), literal)


class ControlFlowPassthroughTests(unittest.TestCase):
    def test_jsonable_walk_reraises_control_flow(self):
        class _Flow:
            def __str__(self):
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            scheduler_svc._jsonable(_Flow())
