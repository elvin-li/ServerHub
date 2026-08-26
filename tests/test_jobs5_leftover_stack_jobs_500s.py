"""Fifth leftover-500s sweep of the Jobs domain: the container job store.

``containers_svc._cjobs`` rows outlive the request that created them, and the
read paths behind GET /api/stacks and GET /api/stacks/jobs/{job_id} trusted
them far more than hub/jobs.py trusts its own store:

* ``stack_job_log`` called ``j.get(...)`` behind a bare isinstance gate — a
  leftover dict-*subclass* row whose ``.get()`` raised 500'd the poll; the
  latest-job fallback scan compared ``v.get("stack_id") == job_id`` raw, so
  an ``__eq__``-bomb stack_id (or store key) in ANY row 500'd the poll for
  every *other* job.
* The scalar fields were echoed raw: a ``__bool__``-bomb ``running``, an
  over-digit-cap ``rc`` (CPython's int->str limit ValueErrors Starlette's
  own json.dumps) and a lone-surrogate ``started`` all 500'd the encoder;
  a list-subclass ``log`` whose ``__iter__`` raised 500'd the join.
* ``latest_stack_jobs`` / ``job_public`` (the GET /api/stacks job strip) had
  the same raw ``.get()`` reads and raw field echoes.
* The single-runner mutex scan in ``_register_job`` — and the eviction scan
  in ``_evict_old_jobs`` — read ``j.get("running")`` raw, so one poisoned
  row raised inside every job-*starting* route until the panel restarted.

Fixes mirror hub.jobs: ``_plain_job`` C-level copies, fail-closed
``_truthy`` (a junk row is not a live job — it must not wedge the mutex),
``_job_log_lines`` guarded iteration, isinstance-gated str compares, and a
final ``_jsonable`` funnel over both public payloads (docker_cli._jsonable
itself gained the dict()-copy / safe-list-iteration nested-bomb guards).
"""
from __future__ import annotations

import unittest

from hub import containers_svc

#: Past CPython's default 4300-digit int<->str conversion limit.
_HUGE_INT = 10 ** 5000


class _GetBomb(dict):
    def get(self, *a, **k):
        raise RuntimeError("boom get")


class _KeysIterBomb(dict):
    """dict() itself raises: overriding __iter__ sends CPython to keys()."""

    def keys(self):
        raise RuntimeError("boom keys")

    def __iter__(self):
        raise RuntimeError("boom iter")


class _IterBombList(list):
    def __iter__(self):
        raise RuntimeError("boom list iter")


class _BoolBomb:
    def __bool__(self):
        raise RuntimeError("boom bool")


class _EqBomb:
    def __eq__(self, other):
        raise RuntimeError("boom eq")

    __hash__ = None


class MountedStackJobLeftoverTests(unittest.TestCase):
    """The poisoned store over the real mounted app."""

    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient

        from hub.app_factory import create_app
        from hub.auth import require_auth

        cls._app = create_app()
        cls._app.dependency_overrides[require_auth] = lambda: True
        cls.client = TestClient(cls._app, raise_server_exceptions=False)

    @classmethod
    def tearDownClass(cls):
        cls._app.dependency_overrides.clear()

    def setUp(self):
        containers_svc._cjobs.clear()

    def tearDown(self):
        containers_svc._cjobs.clear()

    def assert_utf8_json(self, r):
        self.assertNotEqual(r.status_code, 500, r.text[:400])
        r.content.decode("utf-8")

    def test_get_bomb_row_stays_200(self):
        containers_svc._cjobs["j-getbomb"] = _GetBomb(
            running=False, rc=0, log=["fine"], stack_id="s1", action="up")
        r = self.client.get("/api/stacks/jobs/j-getbomb")
        self.assert_utf8_json(r)
        self.assertEqual(r.status_code, 200)
        payload = r.json()
        # readable through the C-level copy: the row's data survives
        self.assertEqual(payload["rc"], 0)
        self.assertIn("fine", payload["log"])
        self.assertEqual(payload["stack_id"], "s1")

    def test_unreadable_subclass_row_serves_the_missing_shape(self):
        containers_svc._cjobs["j-junk"] = _KeysIterBomb(running=False)
        r = self.client.get("/api/stacks/jobs/j-junk")
        self.assert_utf8_json(r)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["log"], "(not started yet)")

    def test_bomb_fields_stay_200_and_scrubbed(self):
        containers_svc._cjobs["j-fields"] = {
            "running": _BoolBomb(), "rc": _HUGE_INT, "started": "0\ud8009",
            "finished": float("inf"), "log": _IterBombList(["x"]),
            "stack_id": "s\ud800", "action": _EqBomb(), "code": _HUGE_INT,
        }
        r = self.client.get("/api/stacks/jobs/j-fields")
        self.assert_utf8_json(r)
        self.assertEqual(r.status_code, 200)
        payload = r.json()
        self.assertIs(payload["running"], False)   # bomb fails closed
        self.assertIsNone(payload["rc"])           # over-cap int drops
        self.assertEqual(payload["started"], "0?9")
        self.assertIsNone(payload["finished"])     # inf drops
        self.assertEqual(payload["stack_id"], "s?")
        self.assertIsNone(payload["action"])       # non-str field drops
        self.assertNotIn("\ud800", r.text)

    def test_eq_bomb_in_the_scan_cannot_500_other_jobs(self):
        """The latest-for-stack fallback walks every row; one bomb used to
        take the poll down for every job id that missed the direct get."""
        containers_svc._cjobs["j-eq"] = {"running": False, "rc": 0,
                                         "stack_id": _EqBomb(), "log": ["ok"]}
        containers_svc._cjobs["j-good"] = {"running": False, "rc": 0,
                                           "stack_id": "media", "log": ["done"]}
        r = self.client.get("/api/stacks/jobs/media")
        self.assert_utf8_json(r)
        self.assertEqual(r.status_code, 200)
        payload = r.json()
        self.assertEqual(payload["job_id"], "j-good")
        self.assertIn("done", payload["log"])

    def test_stacks_listing_survives_the_poisoned_store(self):
        containers_svc._cjobs["j-junk"] = _KeysIterBomb(running=False)
        containers_svc._cjobs["j-getbomb"] = _GetBomb(running=False)
        containers_svc._cjobs["j-fields"] = {
            "running": _BoolBomb(), "rc": _HUGE_INT, "stack_id": "s\ud800",
            "finished": "9\udfff9", "action": "up", "code": None,
        }
        r = self.client.get("/api/stacks")
        self.assert_utf8_json(r)
        self.assertEqual(r.status_code, 200)
        jobs = r.json()["jobs"]
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["stack_id"], "s?")
        self.assertIsNone(jobs[0]["rc"])
        self.assertIs(jobs[0]["running"], False)
        self.assertNotIn("\ud800", r.text)


class JobStoreMutexLeftoverTests(unittest.TestCase):
    """The single-runner mutex and eviction scans with poisoned rows."""

    def setUp(self):
        containers_svc._cjobs.clear()

    def tearDown(self):
        containers_svc._cjobs.clear()

    def test_junk_rows_do_not_wedge_or_500_the_mutex(self):
        """A bomb row is junk, not a live job: registration must neither
        raise the bomb (a 500 on every job-starting route) nor treat the
        junk as running forever (a wedged subsystem)."""
        containers_svc._cjobs["junk"] = _KeysIterBomb(running=True)
        containers_svc._cjobs["bomb"] = {"running": _BoolBomb()}
        containers_svc._cjobs["str"] = "not-a-dict"
        row = containers_svc._register_job("t-new", stack_id="s", action="up")
        self.assertTrue(row["running"])
        row["running"] = False

    def test_readable_subclass_row_claiming_running_still_holds_the_mutex(self):
        """The C-level copy sees running=True: the coded 409 stands."""
        from fastapi import HTTPException

        containers_svc._cjobs["live"] = _GetBomb(running=True)
        with self.assertRaises(HTTPException) as ctx:
            containers_svc._register_job("t-new", stack_id="s", action="up")
        self.assertEqual(ctx.exception.status_code, 409)

    def test_eviction_scan_survives_poisoned_rows(self):
        for i in range(containers_svc.JOB_HISTORY_MAX + 3):
            containers_svc._cjobs[f"old-{i}"] = {"running": False, "rc": 0}
        containers_svc._cjobs["junk"] = _KeysIterBomb(running=True)
        containers_svc._evict_old_jobs()
        self.assertLessEqual(len(containers_svc._cjobs),
                             containers_svc.JOB_HISTORY_MAX)


class DockerJsonableNestedBombPins(unittest.TestCase):
    """docker_cli._jsonable gained the same nested-bomb guards as
    hub.jobs._jsonable; the stack-job payload funnel relies on them."""

    def test_nested_subclass_bombs_drop_to_none(self):
        from hub.docker_cli import _jsonable

        self.assertIsNone(_jsonable(_KeysIterBomb(a=1)))
        self.assertIsNone(_jsonable(_IterBombList([1])))
        self.assertEqual(_jsonable({"deep": _KeysIterBomb(a=1)}),
                         {"deep": None})
        self.assertEqual(_jsonable({"xs": _IterBombList([1])}), {"xs": None})


if __name__ == "__main__":
    unittest.main(verbosity=2)
