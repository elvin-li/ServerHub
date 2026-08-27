"""Eighth leftover-500s sweep of the Jobs domain: the ``__class__``-property
seam in isinstance, liar-``__class__`` impostors, and runner-seam rc bombs.

The jobs7 wave folded the Maintenance cfg-read and the cron-tick mapping
sniff; modules8/bookmarks8/assistant8 then established that CPython's
``isinstance`` reads the operand's ``__class__`` whenever the real-type fast
check misses — so a leftover value whose ``__class__`` is a *raising
property* detonates the gate itself, outside any try.  Neither hub/jobs.py
nor hub/scheduler_svc.py had the ``_isinst`` rule yet.  Confirmed live on
the pre-fix tree, all as raw 500s over the mounted app (create_app +
TestClient, raise_server_exceptions=False) unless noted:

* GET /api/maintenance — a ``__class__``-bomb task value (``desc``), a bomb
  ``id``, a *whole-row* bomb, and a bomb ``rc`` in a leftover ``_jobs`` row
  all blew the first isinstance that missed their real type
  (``_plain_dict`` / ``_task_id`` / ``_jsonable``).  POST
  /api/maintenance/{tid}/run walks the same list and 500'd with it.
* GET /api/maintenance/{tid}/log — a bomb entry in a leftover row's ``log``
  list blew ``_log_lines``'s item gate.
* GET /api/scheduler/jobs — bomb job ``id`` / ``enabled`` / ``cron`` /
  ``name`` / params value / params *key* each 500'd via ``_job_id`` /
  ``job_enabled`` / ``_cron_field_tokens`` / ``_jsonable``; a whole-row bomb
  also 500'd DELETE and run-now on *healthy* siblings through
  ``_plain_dict``'s gate in the get_job scan.
* the engine tick — the same bombs raised out of ``_job_id`` /
  ``job_enabled`` / ``cron_matches`` past ``_tick_once``'s
  (ValueError, TypeError) net and aborted the whole tick, costing every
  *other* job its matching minute.
* liars — a leftover whose ``__class__`` *answers* a type it is not: a
  bool-liar rode ``_jsonable``'s bool arm raw into json.dumps (TypeError),
  a bytes-liar TypeError'd the unbound ``bytes.decode``, and a str-liar
  cron / ``enabled`` TypeError'd the unbound ``str.split`` / ``str.strip``.
* runner seams — an int-subclass ``__eq__``-bomb rc raised out of
  ``_execute``'s status compare *after* the runner finished (the run was
  never journalled and the "Never raises" contract broke); float-subclass
  clock bombs raised out of ``_epoch_int`` / ``_finite_duration`` the same
  way; ``_clamp_timeout`` blew on ``__class__`` and float-``__eq__`` bombs
  before run_watchdog's try; ``start_job`` raised on a bomb id straight
  into the calling route.

The fix is the modules8 shape: ``_isinst`` (isinstance in a try, a raise
means "not this type"), exact ``type(x) is bool`` gates so bool-liars fall
to the numeric arms' unbound coercions, guarded unbound calls for the
liar TypeErrors, and a guarded rc compare in ``_execute``.

Stays-immune pins ride along for the vectors this hunt probed and found
already dead: str-liar values (the unbound ``str.encode`` refuses them
inside an existing try), dict-*subclass* rows carrying a ``__class__`` bomb
(the subclass passes the real-type fast check, so ``__class__`` is never
read), rc float-subclass bombs in ``_jsonable`` (unbound ``float.__float__``
first), a FIFO occupying the run journal (tail_file_lines opens O_NONBLOCK),
and an over-digit-cap number in a journal row (json.loads raises ValueError,
not JSONDecodeError, and ``runs()`` already catches ValueError).
"""
from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest import mock

from hub import audit, scheduler_svc
from hub import jobs as hub_jobs


class ClassBomb:
    """A leftover whose ``__class__`` access raises — isinstance's blind spot."""

    @property
    def __class__(self):
        raise RuntimeError("class access bomb")

    def __hash__(self):  # usable as a mapping key
        return 1


class DictClassBomb(dict):
    """A real dict subclass whose ``__class__`` still bombs the earlier gates."""

    @property
    def __class__(self):
        raise RuntimeError("dict class access bomb")


def _liar(claim):
    class Liar:
        @property
        def __class__(self):
            return claim

        def __hash__(self):
            return 1

    return Liar()


class EqBombInt(int):
    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    __ne__ = __eq__

    def __hash__(self):
        return 0


class FloatClockBomb(float):
    def __float__(self):
        raise RuntimeError("float bomb")

    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    __ne__ = __eq__

    def __hash__(self):
        return 0


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


def _maint_cfg(rows):
    return mock.patch.object(hub_jobs, "cfg", lambda: {"maintenance": rows})


def _sched_cfg(rows):
    return mock.patch.object(scheduler_svc, "cfg", lambda: {"schedules": rows})


def _sched_row(jid, **over):
    row = {"id": jid, "name": "n", "type": "command", "cron": "* * * * *",
           "enabled": True, "params": {"command": "true"}}
    row.update(over)
    return row


class MaintenanceClassBombTests(_MountedClientMixin, unittest.TestCase):
    """GET /api/maintenance, the run route and the log route over bombs."""

    def tearDown(self):
        hub_jobs._jobs.clear()

    def test_bomb_task_value_renders_and_the_task_survives(self):
        rows = [{"id": "ok", "name": "fine", "desc": ClassBomb(), "command": "true"}]
        with _maint_cfg(rows):
            r = self.client.get("/api/maintenance")
        self.assert_utf8_not_500(r)
        self.assertEqual(r.status_code, 200)
        (task,) = r.json()
        self.assertEqual(task["id"], "ok")
        self.assertEqual(task["name"], "fine")
        # The bomb degrades through repr (real type, never __class__).
        self.assertIsInstance(task["desc"], str)

    def test_bomb_task_id_drops_only_its_entry(self):
        rows = [{"id": ClassBomb(), "command": "true"},
                {"id": "ok", "command": "true"}]
        with _maint_cfg(rows):
            r = self.client.get("/api/maintenance")
        self.assert_utf8_not_500(r)
        self.assertEqual(r.status_code, 200)
        self.assertEqual([t["id"] for t in r.json()], ["ok"])

    def test_whole_row_bomb_drops_only_its_row(self):
        rows = [ClassBomb(), {"id": "ok", "command": "true"}]
        with _maint_cfg(rows):
            r = self.client.get("/api/maintenance")
        self.assert_utf8_not_500(r)
        self.assertEqual(r.status_code, 200)
        self.assertEqual([t["id"] for t in r.json()], ["ok"])

    def test_run_over_row_bomb_still_starts_the_healthy_task(self):
        rows = [ClassBomb(), {"id": "ok", "command": "true"}]
        with _maint_cfg(rows), \
                mock.patch.object(audit, "record", lambda event, **f: {}):
            r = self.client.post("/api/maintenance/ok/run")
        self.assert_utf8_not_500(r)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json().get("ok"))

    def test_bomb_rc_in_a_leftover_jobs_row_keeps_list_and_log_up(self):
        hub_jobs._jobs["ok"] = {"running": False, "rc": ClassBomb(),
                                "finished": None}
        with _maint_cfg([{"id": "ok", "command": "true"}]):
            r = self.client.get("/api/maintenance")
        self.assert_utf8_not_500(r)
        self.assertEqual(r.status_code, 200)
        r2 = self.client.get("/api/maintenance/ok/log")
        self.assert_utf8_not_500(r2)
        self.assertEqual(r2.status_code, 200)

    def test_bomb_and_str_liar_log_entries_keep_the_real_lines(self):
        hub_jobs._jobs["ok"] = {
            "running": False, "rc": 0,
            "log": ["first", ClassBomb(), _liar(str), "last"],
        }
        r = self.client.get("/api/maintenance/ok/log")
        self.assert_utf8_not_500(r)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["log"], "first\nlast")

    def test_bool_and_bytes_liar_values_degrade_not_500(self):
        rows = [{"id": "ok", "name": _liar(bool), "desc": _liar(bytes),
                 "command": "true"}]
        with _maint_cfg(rows):
            r = self.client.get("/api/maintenance")
        self.assert_utf8_not_500(r)
        self.assertEqual(r.status_code, 200)
        (task,) = r.json()
        # bool-liar drops through the int arm's unbound coercion to None
        # (the list route's ``or`` then falls back to the id); the
        # bytes-liar degrades to "" through the guarded unbound decode.
        self.assertEqual(task["name"], "ok")
        self.assertEqual(task["desc"], "")


class SchedulerListClassBombTests(_MountedClientMixin, unittest.TestCase):
    """GET /api/scheduler/jobs over per-field and per-row bombs."""

    def _list(self, rows):
        with _sched_cfg(rows):
            r = self.client.get("/api/scheduler/jobs")
        self.assert_utf8_not_500(r)
        self.assertEqual(r.status_code, 200)
        return r.json()["jobs"]

    def test_bomb_id_keeps_both_rows_rendering(self):
        jobs = self._list([_sched_row(ClassBomb()), _sched_row("good")])
        self.assertIn("good", [j.get("id") for j in jobs])

    def test_bomb_enabled_cron_name_params_all_render(self):
        jobs = self._list([
            _sched_row("b1", enabled=ClassBomb()),
            _sched_row("b2", cron=ClassBomb()),
            _sched_row("b3", name=ClassBomb()),
            _sched_row("b4", params={"command": "true", "x": ClassBomb()}),
            _sched_row("b5", params={ClassBomb(): "v"}),
            _sched_row("good"),
        ])
        ids = [j.get("id") for j in jobs]
        self.assertEqual(ids, ["b1", "b2", "b3", "b4", "b5", "good"])

    def test_str_liar_cron_and_enabled_degrade_not_500(self):
        jobs = self._list([
            _sched_row("b1", cron=_liar(str)),
            _sched_row("b2", enabled=_liar(str)),
            _sched_row("good"),
        ])
        by_id = {j.get("id"): j for j in jobs}
        # The liar cron cannot parse: no next run, never a raise.
        self.assertIsNone(by_id["b1"]["next_run"])
        # The liar enabled reads as off (str.strip refuses the impostor).
        self.assertIsNone(by_id["b2"]["next_run"])
        self.assertIsNotNone(by_id["good"]["next_run"])

    def test_mutations_on_healthy_jobs_survive_a_row_bomb_sibling(self):
        with _sched_cfg([ClassBomb(), _sched_row("good")]), \
                mock.patch.object(audit, "record", lambda event, **f: {}):
            r = self.client.post("/api/scheduler/jobs/good/run-now")
            self.assert_utf8_not_500(r)
            self.assertEqual(r.status_code, 200)
            self.assertTrue(r.json().get("ok"))
            r2 = self.client.delete("/api/scheduler/jobs/good")
            self.assert_utf8_not_500(r2)
            # The scan finds the job; the disk write answers its own coded
            # outcome.  Either way the bomb sibling costs nothing.
            self.assertIn(r2.status_code, (200, 404))


class TickClassBombTests(unittest.TestCase):
    """A bombed sibling row no longer costs the healthy job its minute."""

    def _tick(self, rows):
        ran: list[str] = []
        with _sched_cfg(rows), \
                mock.patch.object(scheduler_svc, "_execute",
                                  lambda job, trigger: ran.append(
                                      scheduler_svc._job_id(job))), \
                mock.patch.object(scheduler_svc, "_last_minute", None):
            return scheduler_svc._tick_once()

    def test_bomb_id_does_not_abort_the_tick(self):
        self.assertEqual(self._tick([_sched_row(ClassBomb()),
                                     _sched_row("good")]), ["good"])

    def test_bomb_enabled_does_not_abort_the_tick(self):
        self.assertEqual(self._tick([_sched_row("b", enabled=ClassBomb()),
                                     _sched_row("good")]), ["good"])

    def test_bomb_cron_does_not_abort_the_tick(self):
        self.assertEqual(self._tick([_sched_row("b", cron=ClassBomb()),
                                     _sched_row("good")]), ["good"])

    def test_str_liar_cron_does_not_abort_the_tick(self):
        self.assertEqual(self._tick([_sched_row("b", cron=_liar(str)),
                                     _sched_row("good")]), ["good"])

    def test_bomb_matcher_value_in_exact_dict_cron_does_not_abort(self):
        parsed = dict(scheduler_svc.parse_cron("* * * * *"), minute=ClassBomb())
        self.assertEqual(self._tick([_sched_row("b", cron=parsed),
                                     _sched_row("good")]), ["good"])


class RunnerSeamBombTests(unittest.TestCase):
    """rc / clock / timeout bombs at the executor seams."""

    def test_execute_journals_an_eq_bomb_rc_as_failed(self):
        recorded: list[dict] = []
        with mock.patch.dict(scheduler_svc._RUNNERS,
                             {"command": lambda j, log: EqBombInt(1)}), \
                mock.patch.object(scheduler_svc, "_record_run",
                                  recorded.append):
            entry = scheduler_svc._execute(_sched_row("rcbomb"), "manual")
        self.assertEqual(entry.get("status"), "failed")
        self.assertEqual(len(recorded), 1)
        # The runner's id is out of the running set again.
        self.assertFalse(scheduler_svc.is_running("rcbomb"))

    def test_epoch_int_and_finite_duration_survive_clock_bombs(self):
        self.assertEqual(scheduler_svc._epoch_int(FloatClockBomb(2.0)), 2)
        self.assertEqual(
            scheduler_svc._finite_duration(FloatClockBomb(2.0), 1.0), 0.0)

    def test_clamp_timeout_survives_class_and_float_bombs(self):
        self.assertEqual(hub_jobs._clamp_timeout(ClassBomb()),
                         hub_jobs.JOB_TIMEOUT_DEFAULT)
        self.assertEqual(hub_jobs._clamp_timeout(FloatClockBomb(5.0)), 5)
        self.assertEqual(scheduler_svc._job_timeout({"timeout": ClassBomb()}),
                         scheduler_svc.DEFAULT_TIMEOUT)

    def test_start_job_refuses_a_bomb_id_without_raising(self):
        before = dict(hub_jobs._jobs)
        try:
            self.assertIsNone(
                hub_jobs.start_job({"id": ClassBomb(), "command": "true"}))
            self.assertEqual(hub_jobs._jobs, before)
        finally:
            hub_jobs._jobs.clear()
            hub_jobs._jobs.update(before)


class StaysImmunePins(_MountedClientMixin, unittest.TestCase):
    """Vectors this hunt probed and found already dead — pin them."""

    def tearDown(self):
        hub_jobs._jobs.clear()

    def test_str_liar_task_value_stays_scrubbed(self):
        # The unbound str.encode refuses the impostor inside an existing
        # try, so this was never a 500; pin the degrade.
        rows = [{"id": "ok", "desc": _liar(str), "command": "true"}]
        with _maint_cfg(rows):
            r = self.client.get("/api/maintenance")
        self.assert_utf8_not_500(r)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()[0]["desc"], "")

    def test_dict_subclass_class_bomb_row_stays_laundered(self):
        # A *real* dict subclass passes isinstance's real-type fast check,
        # so its bombing __class__ is never read; _plain_dict copies it
        # through the C storage before any other gate can miss.
        rows = [DictClassBomb(id="sub", command="true"),
                {"id": "ok", "command": "true"}]
        with _maint_cfg(rows):
            r = self.client.get("/api/maintenance")
        self.assert_utf8_not_500(r)
        self.assertEqual(r.status_code, 200)
        self.assertEqual([t["id"] for t in r.json()], ["sub", "ok"])
        with _sched_cfg([DictClassBomb(_sched_row("sub")), _sched_row("ok")]):
            r2 = self.client.get("/api/scheduler/jobs")
        self.assert_utf8_not_500(r2)
        self.assertEqual(r2.status_code, 200)
        self.assertEqual([j.get("id") for j in r2.json()["jobs"]],
                         ["sub", "ok"])

    def test_float_subclass_rc_stays_coerced_through_the_unbound_base(self):
        hub_jobs._jobs["ok"] = {"running": False, "rc": FloatClockBomb(1.0),
                                "finished": None}
        with _maint_cfg([{"id": "ok", "command": "true"}]):
            r = self.client.get("/api/maintenance")
        self.assert_utf8_not_500(r)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()[0]["rc"], 1.0)

    def test_fifo_occupying_the_run_journal_stays_an_empty_list(self):
        # tail_file_lines opens O_NONBLOCK and refuses non-regular files,
        # so a leftover FIFO answers [] instead of hanging the route.
        fifo = Path(os.environ["SERVERHUB_STATE_DIR"]) / "jobs8-runs.fifo"
        fifo.parent.mkdir(parents=True, exist_ok=True)
        if fifo.exists():
            fifo.unlink()
        os.mkfifo(fifo)
        try:
            with mock.patch.object(scheduler_svc, "RUNS_PATH", fifo):
                r = self.client.get("/api/scheduler/runs")
            self.assert_utf8_not_500(r)
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["runs"], [])
        finally:
            fifo.unlink()

    def test_over_digit_cap_journal_row_stays_skipped(self):
        # json.loads of a >4300-digit number raises ValueError (the int
        # digit cap), not JSONDecodeError; runs() already catches ValueError.
        journal = Path(os.environ["SERVERHUB_STATE_DIR"]) / "jobs8-runs.jsonl"
        journal.parent.mkdir(parents=True, exist_ok=True)
        journal.write_text(
            '{"job": "good", "status": "ok", "rc": 0}\n' + "1" * 5000 + "\n",
            encoding="utf-8",
        )
        try:
            with mock.patch.object(scheduler_svc, "RUNS_PATH", journal):
                r = self.client.get("/api/scheduler/runs")
            self.assert_utf8_not_500(r)
            self.assertEqual(r.status_code, 200)
            self.assertEqual([x["job"] for x in r.json()["runs"]], ["good"])
        finally:
            journal.unlink()


if __name__ == "__main__":
    unittest.main(verbosity=2)
