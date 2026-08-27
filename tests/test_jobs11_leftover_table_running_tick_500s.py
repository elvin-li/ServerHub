"""Eleventh leftover-500s sweep of the Jobs domain: the poisoned *containers*
themselves — the ``_jobs`` table, the ``_running`` set, the ``_fail_counts``
streak table, and the ``_last_minute`` high-water mark.

jobs9/maint9 sealed the impostor seams inside the rows and the cfg root;
every previous wave planted bombs *inside* the module-level containers.  A
fresh hunt over the same mounted tree (create_app + TestClient,
raise_server_exceptions=False) found the containers *themselves* still bare —
an in-process leftover that replaces the whole mapping/set, or plants a
hash-shadow member, detonated bound calls from outside every net:

* **``jobs._jobs`` table rank.**  ``_jobs.get`` / ``_jobs.items()`` /
  ``_jobs.values()`` were bound calls, so a leftover table that is a
  dict-*subclass* with bombing overrides 500'd all three Maintenance routes
  (``.get`` blew ``_jobs_row``'s first probe, ``.items`` blew the rescue scan
  that existed to save it, ``.values`` blew ``start_job``'s single-runner
  scan), and a liar table whose ``__class__`` merely *answers* dict (no dict
  storage at all) took the same three down (:class:`JobsTableBombHttpTests`
  fails on the pre-fix tree).  All table traffic now goes through the
  unbound dict builtins in a try; a subclass table degrades to its C-level
  storage and a liar table to the not-run-yet shape (reads) or a fresh
  plain table (the insert).

* **``scheduler_svc._running`` set rank.**  ``job_id in _running`` compared
  the probe against every colliding stored member, and a str-*subclass*
  member with a job id's text gets its reflected ``__eq__`` called *first* —
  so one leftover shadow member 500'd GET /api/scheduler/jobs (every row
  reads ``is_running``) and POST run-now, and raised out of
  :func:`_execute`'s overlap check, breaking its "never raises" contract.  A
  set-subclass table's ``__contains__``/``add``/``discard`` overrides
  detonated the same callers (:class:`RunningSetBombHttpTests` fails on the
  pre-fix tree).  Membership now goes through ``set.__contains__`` with an
  exact-str-only rescue scan: ids this module writes are exact by
  construction, so a subclass twin is junk, not a live run — reading it as
  "running" would skip the job forever, the wedged-mutex fail direction
  ``hub.jobs._truthy`` refuses.

* **``scheduler_svc._fail_counts`` streak rank.**  ``.pop`` / ``.get`` /
  ``[jid] =`` hash-probe the table, so a leftover shadow key — or a
  subclass/liar table — raised out of :func:`_alert_on_failure` *after* the
  run was journalled, killing the run thread past ``_execute``'s nets
  (:class:`ExecuteNeverRaisesTests` fails on the pre-fix tree).  The streak
  ops now go through the unbound builtins; a poisoned write rebuilds the
  table with laundered exact keys so the streak (and the alert it earned)
  survives the junk twin.

* **``scheduler_svc._last_minute`` high-water rank.**  ``key == _last_minute``
  / ``key < _last_minute`` reflect into a junk mark's own comparisons, so a
  leftover tuple-subclass mark with bombing ``__eq__``/``__lt__`` (or plain
  junk the tuple compare refuses) raised out of :func:`_tick_once` on every
  tick forever — every job's every minute was lost while ``_loop``'s broad
  except kept the thread alive (:class:`TickHighWaterJunkTests` fails on the
  pre-fix tree).  A junk mark carries no usable timeline: the engine
  re-anchors on the current minute with boot semantics (marked evaluated,
  not fired) and the very next minute fires normally.

Stays-immune pins ride along for the shapes this hunt confirmed already
coded: journal lines whose numbers json.loads itself refuses (a >4300-digit
int is ValueError under CPython's digit cap; ``1e999`` parses to inf and is
dropped field-level), huge-number create bodies (400/422, never 500), and
the vixie backward-step semantics the high-water guard must not weaken.
"""
from __future__ import annotations

import time
import unittest
from unittest import mock

from hub import jobs, scheduler_svc


class _Lie:
    """``__class__`` answers a type the object is not — a claim, not a raise.

    The maint9/modules9 impostor: ``isinstance`` (so ``_isinst``) honours the
    claim, but none of the unbound base descriptors apply to the real object.
    """

    def __init__(self, claim):
        self._claim = claim

    @property
    def __class__(self):  # type: ignore[override]
        return self._claim

    def __hash__(self):  # usable as a mapping key
        return 17


class _BombTableDict(dict):
    """A real dict subclass whose every bound entry point raises."""

    def get(self, *a, **k):  # noqa: D102
        raise RuntimeError("leftover table get bomb")

    def items(self):  # noqa: D102
        raise RuntimeError("leftover table items bomb")

    def values(self):  # noqa: D102
        raise RuntimeError("leftover table values bomb")

    def keys(self):  # noqa: D102
        raise RuntimeError("leftover table keys bomb")

    def __contains__(self, key):  # noqa: D105
        raise RuntimeError("leftover table contains bomb")


class _ShadowStr(str):
    """Same text and hash as a real id, bombing ``__eq__`` — every hash
    probe of the container dispatches into it reflected (subclass first)."""

    def __eq__(self, other):  # noqa: D105
        raise RuntimeError("leftover shadow eq bomb")

    __ne__ = __eq__

    def __hash__(self):  # noqa: D105
        return str.__hash__(self)


class _BombSet(set):
    """A real set subclass whose bound membership/mutation ops raise."""

    def __contains__(self, item):  # noqa: D105
        raise RuntimeError("leftover set contains bomb")

    def add(self, item):  # noqa: D102
        raise RuntimeError("leftover set add bomb")

    def discard(self, item):  # noqa: D102
        raise RuntimeError("leftover set discard bomb")


class _LtBombTuple(tuple):
    """A real tuple subclass mark whose comparisons raise."""

    def __eq__(self, other):  # noqa: D105
        raise RuntimeError("leftover mark eq bomb")

    __ne__ = __eq__

    def __lt__(self, other):  # noqa: D105
        raise RuntimeError("leftover mark lt bomb")

    def __hash__(self):  # noqa: D105
        return 3


def _maint_cfg():
    return mock.patch.object(
        jobs, "cfg",
        lambda: {"maintenance": [{"id": "t", "name": "T", "command": "true"}]})


def _sched_row(jid, **over):
    row = {"id": jid, "name": "n", "type": "command", "cron": "* * * * *",
           "enabled": True, "params": {"command": "true"}}
    row.update(over)
    return row


def _sched_cfg(rows):
    return mock.patch.object(scheduler_svc, "cfg", lambda: {"schedules": rows})


class _MountedClientMixin:
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

    def assert_utf8_not_500(self, r):
        self.assertNotEqual(r.status_code, 500, r.text[:400])
        r.content.decode("utf-8")


class JobsTableBombHttpTests(_MountedClientMixin, unittest.TestCase):
    """A leftover ``_jobs`` *table* (not just a row) no longer 500s the
    Maintenance routes."""

    def test_subclass_table_serves_through_the_c_storage(self):
        # The overrides bomb, but the C-level storage is intact: the row's
        # real state must still be served, not just "no 500".
        table = _BombTableDict()
        dict.__setitem__(table, "t", {"running": False, "rc": 3,
                                      "finished": "x", "log": ["ran"]})
        with _maint_cfg(), mock.patch.object(jobs, "_jobs", table):
            r = self.client.get("/api/maintenance")
            self.assert_utf8_not_500(r)
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()[0]["rc"], 3)
            r2 = self.client.get("/api/maintenance/t/log")
            self.assert_utf8_not_500(r2)
            self.assertEqual(r2.status_code, 200)
            self.assertEqual(r2.json()["log"], "ran")

    def test_liar_table_degrades_to_not_run_yet(self):
        with _maint_cfg(), mock.patch.object(jobs, "_jobs", _Lie(dict)):
            r = self.client.get("/api/maintenance")
            self.assert_utf8_not_500(r)
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()[0]["running"], False)
            r2 = self.client.get("/api/maintenance/t/log")
            self.assert_utf8_not_500(r2)
            self.assertEqual(r2.status_code, 200)
            self.assertEqual(r2.json()["log"], "(not run yet)")

    def test_liar_table_is_replaced_by_the_run_route(self):
        # No dict storage at all: the insert rebuilds a fresh plain table
        # and the run still starts.
        with _maint_cfg(), mock.patch.object(jobs, "_jobs", _Lie(dict)):
            r = self.client.post("/api/maintenance/t/run")
            self.assert_utf8_not_500(r)
            self.assertEqual(r.status_code, 200, r.text[:300])
            self.assertTrue(r.json()["ok"])
            self.assertIs(type(jobs._jobs), dict)
            self.assertIn("t", jobs._jobs)

    def test_shadow_key_inside_subclass_table_still_serves(self):
        # The jobs9 rescue scan used bound ``.items()``: a shadow key *and*
        # a subclass table together used to 500 the scan itself.
        table = _BombTableDict()
        dict.__setitem__(table, _ShadowStr("t"),
                         {"running": False, "rc": 7, "finished": "x",
                          "log": ["tail"]})
        with _maint_cfg(), mock.patch.object(jobs, "_jobs", table):
            r = self.client.get("/api/maintenance")
            self.assert_utf8_not_500(r)
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()[0]["rc"], 7)
            r2 = self.client.get("/api/maintenance/t/log")
            self.assert_utf8_not_500(r2)
            self.assertEqual(r2.json()["rc"], 7)

    def test_run_route_survives_subclass_table_values_bomb(self):
        # ``start_job``'s single-runner scan used bound ``.values()``.
        table = _BombTableDict()
        with _maint_cfg(), mock.patch.object(jobs, "_jobs", table):
            r = self.client.post("/api/maintenance/t/run")
            self.assert_utf8_not_500(r)
            self.assertEqual(r.status_code, 200, r.text[:300])
            self.assertTrue(r.json()["ok"])

    def test_running_row_in_bombed_table_still_answers_the_coded_409(self):
        # The mutex verdict comes from the C storage, not the overrides.
        table = _BombTableDict()
        dict.__setitem__(table, "other", {"running": True, "rc": None,
                                          "log": []})
        with _maint_cfg(), mock.patch.object(jobs, "_jobs", table):
            r = self.client.post("/api/maintenance/t/run")
            self.assert_utf8_not_500(r)
            self.assertEqual(r.status_code, 409)
            self.assertEqual(
                (r.json().get("detail") or {}).get("code"),
                "jobs.already_running")


class RunningSetBombHttpTests(_MountedClientMixin, unittest.TestCase):
    """A poisoned ``_running`` set no longer 500s the scheduler routes."""

    def test_shadow_member_does_not_500_list_or_run_now(self):
        with _sched_cfg([_sched_row("good")]), \
                mock.patch.object(scheduler_svc, "_running",
                                  {_ShadowStr("good")}):
            r = self.client.get("/api/scheduler/jobs")
            self.assert_utf8_not_500(r)
            self.assertEqual(r.status_code, 200)
            by_id = {j.get("id"): j for j in r.json()["jobs"]}
            # A subclass twin is junk, not a live run: reading it as
            # "running" would block the job forever.
            self.assertIs(by_id["good"]["running"], False)
            r2 = self.client.post("/api/scheduler/jobs/good/run-now")
            self.assert_utf8_not_500(r2)
            self.assertEqual(r2.status_code, 200, r2.text[:300])
            self.assertTrue(r2.json()["ok"])

    def test_subclass_set_does_not_500_list_or_run_now(self):
        with _sched_cfg([_sched_row("good")]), \
                mock.patch.object(scheduler_svc, "_running", _BombSet()):
            r = self.client.get("/api/scheduler/jobs")
            self.assert_utf8_not_500(r)
            self.assertEqual(r.status_code, 200)
            r2 = self.client.post("/api/scheduler/jobs/good/run-now")
            self.assert_utf8_not_500(r2)
            self.assertEqual(r2.status_code, 200, r2.text[:300])

    def test_liar_set_does_not_500_list_or_run_now(self):
        with _sched_cfg([_sched_row("good")]), \
                mock.patch.object(scheduler_svc, "_running", _Lie(set)):
            r = self.client.get("/api/scheduler/jobs")
            self.assert_utf8_not_500(r)
            self.assertEqual(r.status_code, 200)
            r2 = self.client.post("/api/scheduler/jobs/good/run-now")
            self.assert_utf8_not_500(r2)
            self.assertEqual(r2.status_code, 200, r2.text[:300])

    def test_genuine_live_marker_still_answers_the_coded_409(self):
        # The guard must not weaken the overlap contract: an exact-str
        # member is a real live run and run-now keeps refusing it.
        with _sched_cfg([_sched_row("good")]), \
                mock.patch.object(scheduler_svc, "_running", {"good"}):
            r = self.client.post("/api/scheduler/jobs/good/run-now")
            self.assert_utf8_not_500(r)
            self.assertEqual(r.status_code, 409)
            self.assertEqual(
                (r.json().get("detail") or {}).get("code"),
                "scheduler.running")

    def test_shadow_beside_genuine_marker_still_reads_running(self):
        # The rescue scan must find the exact marker past the bombing twin.
        # The bomb is armed only after construction: building the two-member
        # set already compares the colliding pair.
        class _LateShadow(str):
            armed = False

            def __eq__(self, other):  # noqa: D105
                if _LateShadow.armed:
                    raise RuntimeError("leftover shadow eq bomb")
                # Unequal while unarmed so the genuine twin coexists.
                return False

            __ne__ = __eq__

            def __hash__(self):  # noqa: D105
                return str.__hash__(self)

        planted = {_LateShadow("good"), "good"}
        self.assertEqual(len(planted), 2)
        _LateShadow.armed = True
        try:
            with mock.patch.object(scheduler_svc, "_running", planted):
                self.assertTrue(scheduler_svc.is_running("good"))
        finally:
            _LateShadow.armed = False


class ExecuteNeverRaisesTests(unittest.TestCase):
    """_execute's "never raises" contract now survives poisoned containers."""

    ROW = _sched_row("good")

    def _run(self, rc=1, **patches):
        entries = []
        stack = [
            mock.patch.dict(scheduler_svc._RUNNERS,
                            {"command": lambda job, log: rc}),
            mock.patch.object(scheduler_svc, "_record_run", entries.append),
        ]
        with stack[0], stack[1]:
            entry = scheduler_svc._execute(dict(self.ROW), "manual")
        return entry, entries

    def test_shadow_running_member_neither_raises_nor_skips(self):
        with mock.patch.object(scheduler_svc, "_running",
                               {_ShadowStr("good")}):
            entry, journalled = self._run(rc=0)
        self.assertEqual(entry.get("status"), "ok")
        self.assertEqual(len(journalled), 1)

    def test_bomb_set_add_and_discard_never_raise(self):
        with mock.patch.object(scheduler_svc, "_running", _BombSet()):
            entry, journalled = self._run(rc=0)
            self.assertEqual(entry.get("status"), "ok")
            # The finally-discard completed: nothing is left marked live.
            self.assertFalse(scheduler_svc.is_running("good"))

    def test_shadow_fail_counts_key_neither_raises_nor_loses_the_streak(self):
        emitted = []
        with mock.patch.object(scheduler_svc, "_fail_counts",
                               {_ShadowStr("good"): 1}), \
                mock.patch("hub.alerts.emit_alert",
                           lambda **kw: emitted.append(kw)):
            entry1, _ = self._run(rc=1)
            self.assertEqual(entry1.get("status"), "failed")
            # The poisoned twin restarted the streak at 1; the second
            # failure completes it and the alert still fires.
            entry2, _ = self._run(rc=1)
            self.assertEqual(entry2.get("status"), "failed")
        self.assertEqual(len(emitted), 1)
        self.assertEqual(emitted[0].get("alert_id"), "schedule:good")

    def test_subclass_and_liar_fail_counts_tables_never_raise(self):
        class _FCBomb(dict):
            def get(self, *a, **k):  # noqa: D102
                raise RuntimeError("leftover streak get bomb")

            def pop(self, *a, **k):  # noqa: D102
                raise RuntimeError("leftover streak pop bomb")

            def __setitem__(self, *a):  # noqa: D105
                raise RuntimeError("leftover streak set bomb")

        for table in (_FCBomb(), _Lie(dict)):
            with mock.patch.object(scheduler_svc, "_fail_counts", table):
                entry, journalled = self._run(rc=1)
                self.assertEqual(entry.get("status"), "failed")
                self.assertEqual(len(journalled), 1)

    def test_ok_run_over_poisoned_streak_table_never_raises(self):
        with mock.patch.object(scheduler_svc, "_fail_counts",
                               {_ShadowStr("good"): 1}):
            entry, _ = self._run(rc=0)
        self.assertEqual(entry.get("status"), "ok")


class TickHighWaterJunkTests(unittest.TestCase):
    """A junk ``_last_minute`` mark re-anchors instead of aborting forever."""

    ANCHOR = 1_900_000_000 - (1_900_000_000 % 60)

    def _cfg(self):
        return _sched_cfg([_sched_row("good")])

    def test_junk_tuple_mark_costs_one_minute_not_all_of_them(self):
        ran: list[str] = []
        junk = _LtBombTuple((9999, 1, 1, 0, 0))
        with self._cfg(), \
                mock.patch.object(scheduler_svc, "_execute",
                                  lambda job, trigger: ran.append(
                                      scheduler_svc._job_id(job))), \
                mock.patch.object(scheduler_svc, "_last_minute", junk):
            # The poisoned tick re-anchors quietly (boot semantics)…
            self.assertEqual(scheduler_svc._tick_once(self.ANCHOR), [])
            # …and the very next minute fires normally.
            self.assertEqual(scheduler_svc._tick_once(self.ANCHOR + 60),
                             ["good"])

    def test_plain_junk_mark_re_anchors_too(self):
        with self._cfg(), \
                mock.patch.object(scheduler_svc, "_execute",
                                  lambda job, trigger: None), \
                mock.patch.object(scheduler_svc, "_last_minute", "junk"):
            self.assertEqual(scheduler_svc._tick_once(self.ANCHOR), [])
            self.assertEqual(
                scheduler_svc._last_minute,
                scheduler_svc._minute_key(time.localtime(self.ANCHOR)))

    def test_vixie_backward_semantics_are_not_weakened(self):
        launched = []
        with self._cfg(), \
                mock.patch.object(scheduler_svc, "_execute",
                                  lambda job, trigger: None), \
                mock.patch.object(scheduler_svc, "_last_minute", None):
            self.assertEqual(scheduler_svc._tick_once(self.ANCHOR + 3600),
                             ["good"])
            mark = scheduler_svc._last_minute
            # A small backward step stays quiet and keeps the mark.
            self.assertEqual(scheduler_svc._tick_once(self.ANCHOR), [])
            self.assertEqual(scheduler_svc._last_minute, mark)
            # A large backward step re-anchors without firing.
            far_back = self.ANCHOR - 4 * 3600
            self.assertEqual(scheduler_svc._tick_once(far_back), [])
            self.assertEqual(
                scheduler_svc._last_minute,
                scheduler_svc._minute_key(time.localtime(far_back)))


class StaysImmunePins(_MountedClientMixin, unittest.TestCase):
    """Shapes this hunt probed and found already coded — pinned so a
    refactor cannot quietly reopen them."""

    def test_journal_numbers_jsonloads_refuses_degrade_field_level(self):
        # A >4300-digit int is ValueError inside json.loads itself (CPython's
        # digit cap); 1e999 parses to inf and the field is dropped, never
        # the route.
        lines = [
            '{"job": "good", "ts": ' + "9" * 5000 + ', "status": "ok"}',
            '{"job": "good", "rc": 1e999, "status": "ok", "ts": 5}',
            '{"job": "good", "status": "ok", "ts": 6, "rc": 0}',
        ]
        with mock.patch.object(scheduler_svc, "_journal_lines",
                               lambda: lines):
            r = self.client.get("/api/scheduler/runs")
            self.assert_utf8_not_500(r)
            self.assertEqual(r.status_code, 200)
            runs = r.json()["runs"]
            # The digit-capped line is unparsable and skipped whole; the
            # inf rc survives as a record with the junk field dropped.
            self.assertEqual(len(runs), 2)
            self.assertIsNone(runs[1].get("rc"))
            r2 = self.client.get("/api/scheduler/jobs/good/runs")
            self.assert_utf8_not_500(r2)
            self.assertEqual(r2.status_code, 200)

    def test_huge_number_create_bodies_never_500(self):
        head = ('{"name":"n","type":"command","cron":"* * * * *",'
                '"params":{"command":"true"},"timeout":')
        for tail, expected in (("9" * 5000 + "}", 400), ("1e999}", 422)):
            r = self.client.post(
                "/api/scheduler/jobs", content=head + tail,
                headers={"content-type": "application/json"})
            self.assert_utf8_not_500(r)
            self.assertEqual(r.status_code, expected, r.text[:200])

    def test_shadow_key_in_plain_jobs_table_still_rescued(self):
        # The jobs9 rescue path itself must keep working after this wave's
        # unbound rewrite.
        table = {_ShadowStr("t"): {"running": False, "rc": 5,
                                   "finished": "x", "log": ["l"]}}
        with _maint_cfg(), mock.patch.object(jobs, "_jobs", table):
            r = self.client.get("/api/maintenance")
            self.assert_utf8_not_500(r)
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()[0]["rc"], 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
