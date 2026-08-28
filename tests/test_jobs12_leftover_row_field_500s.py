"""Twelfth leftover-500s sweep of the Jobs domain: hash-shadowing bomb *keys*
inside scheduler job rows — the row-field rank.

jobs11 sealed the module-level containers (the ``_jobs`` table, the
``_running`` set, the streak table, the tick's high-water mark); maint11 gave
``hub.jobs`` the ``_mapping_get`` seam for shadow keys inside its own rows.
A fresh hunt over the same mounted tree (create_app + TestClient,
``raise_server_exceptions=False``) found the *scheduler* side never got that
seam: ``scheduler_svc.list_jobs`` hands out ``_plain_dict`` copies with the
rows' keys intact, and every bound ``job.get(...)`` — plus every
``out[...] =`` insert into a raw ``dict(job)`` copy — hash-probes the
mapping, comparing the interned field name against every stored key whose
hash collides and dispatching into that key's own ``__eq__``.  One leftover
str-*subclass* key whose text shadows a real field name and whose ``__eq__``
raises detonated from outside every net:

* **``_job_id`` rank.**  The bare ``job.get("id")`` 500'd
  GET /api/scheduler/jobs (the list comprehension calls it per row), and —
  via :func:`scheduler_svc._matches_id`'s :func:`get_job` scan — DELETE /
  PUT / enable / run-now on *healthy* sibling jobs, and aborted the engine
  tick (:class:`RowShadowKeyHttpTests` / :class:`TickShadowKeyTests` fail on
  the pre-fix tree).

* **``job_enabled`` / tick ``cron`` rank.**  ``job.get("enabled")`` 500'd the
  list route; ``job.get("cron")`` in :func:`_tick_once` raised RuntimeError
  past its (ValueError, TypeError) net and aborted the whole tick — every
  *other* job's matching minute was lost while ``_loop``'s broad except kept
  the thread alive.

* **``_public_job`` insert rank.**  The router copied the row raw
  (``dict(job)``) and only laundered *after* writing ``id`` / ``next_run`` /
  ``running`` / ``last`` onto it, so a shadow key with any of those texts
  blew the insert itself and 500'd the list route (and the create/update/
  enable echoes) before ``_jsonable`` ever ran; its bare ``job.get("cron")``
  500'd the same route.

* **``_audit_fields`` rank.**  The delete/enable/run-now routes pass the
  *stored* row, and five bare ``record.get(...)`` probes (plus the params
  copy's ``params.get("command")``) 500'd the audited mutation after
  validation had already passed.

* **``_execute`` contract rank.**  Both entry builds read ``job.get("type")``
  *outside* the try (the skipped build before it, the final build after the
  finally), so a shadow "type" key broke the "never raises" contract — after
  the runner had already finished, so the run was never journalled
  (:class:`ExecuteNeverRaisesShadowTests` fails on the pre-fix tree).

Every row-field read now goes through ``scheduler_svc._mapping_get`` (the
unbound ``dict.get`` in a try — the hub.jobs convention), and the router
launders the copy *before* the state inserts.  Only the shadowed field
degrades to its default; sibling fields, sibling rows, and sibling jobs'
minutes keep their sane data.  A junk-shadowed ``enabled`` fails *closed*:
junk must not fire operator-configured shell.

Stays-immune pins ride along for the guards this hunt leaned on and must not
weaken: the guarded raw equality in ``_matches_id`` (an eq-bomb id *value*
on a junk sibling), and genuine rows' semantics (a real ``enabled: false``
still parks ``next_run``, a real cron still schedules).
"""
from __future__ import annotations

import unittest
from unittest import mock

from hub import scheduler_svc


class _ShadowStr(str):
    """Same text and hash as a real field name, bombing ``__eq__`` — every
    hash probe of the row dispatches into it reflected (subclass first)."""

    def __eq__(self, other):  # noqa: D105
        raise RuntimeError("leftover shadow eq bomb")

    __ne__ = __eq__

    def __hash__(self):  # noqa: D105
        return str.__hash__(self)


class _EqBombValue:
    """An id *value* whose equality raises — the _matches_id guarded rank."""

    def __eq__(self, other):  # noqa: D105
        raise RuntimeError("leftover id value eq bomb")

    __ne__ = __eq__

    def __hash__(self):  # noqa: D105
        return 5


def _row(jid="good", **over):
    row = {"id": jid, "name": "n", "type": "command", "cron": "* * * * *",
           "enabled": True, "params": {"command": "true"}}
    row.update(over)
    return row


def _shadowed(field, base=None):
    """*base* with *field*'s key replaced by a same-text bomb subclass key."""
    row = dict(base if base is not None else _row())
    value = row.pop(field, None)
    row[_ShadowStr(field)] = value
    return row


def _sched_cfg(rows):
    return mock.patch.object(scheduler_svc, "cfg", lambda: {"schedules": rows})


def _disk(rows):
    """mutate() re-reads services.yaml, not the cfg() snapshot; give the
    mutation routes an in-memory stand-in so a hit really lands."""
    store = {"schedules": rows}

    def fake_mutate(mutator):
        mutator(store)
        return store

    return mock.patch.object(scheduler_svc, "mutate", fake_mutate)


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


class RowShadowKeyHttpTests(_MountedClientMixin, unittest.TestCase):
    """A shadow bomb key inside a job row no longer 500s the scheduler routes."""

    def _list_by_id(self):
        r = self.client.get("/api/scheduler/jobs")
        self.assert_utf8_not_500(r)
        self.assertEqual(r.status_code, 200, r.text[:300])
        return {j.get("id"): j for j in r.json()["jobs"]}

    def test_shadow_id_key_does_not_500_list_and_sibling_survives(self):
        with _sched_cfg([_shadowed("id", _row("junk")), _row("good")]):
            by_id = self._list_by_id()
            self.assertIn("good", by_id)
            # The healthy sibling keeps its full scheduling state.
            self.assertIsInstance(by_id["good"]["next_run"], int)
            self.assertIs(by_id["good"]["running"], False)

    def test_shadow_enabled_key_fails_closed_not_500(self):
        with _sched_cfg([_shadowed("enabled")]):
            by_id = self._list_by_id()
            # A junk-shadowed flag must not fire operator shell: the row
            # reads as disabled, so no next run is scheduled.
            self.assertIsNone(by_id["good"]["next_run"])

    def test_shadow_cron_key_does_not_500_list(self):
        with _sched_cfg([_shadowed("cron")]):
            by_id = self._list_by_id()
            self.assertIsNone(by_id["good"]["next_run"])

    def test_shadow_state_field_keys_do_not_500_the_public_inserts(self):
        # "id" / "next_run" / "running" / "last" are exactly the keys the
        # router writes onto its copy: the raw-copy inserts used to
        # detonate each shadow twin before the trailing launder ran.
        row = _row()
        for field in ("next_run", "running", "last"):
            row[_ShadowStr(field)] = None
        with _sched_cfg([row]):
            by_id = self._list_by_id()
            self.assertIn("good", by_id)
            self.assertIsInstance(by_id["good"]["next_run"], int)

    def test_delete_on_healthy_sibling_survives_junk_row(self):
        rows = [_shadowed("id", _row("junk")), _row("good")]
        with _sched_cfg(rows), _disk([_row("good")]):
            r = self.client.delete("/api/scheduler/jobs/good")
            self.assert_utf8_not_500(r)
            self.assertEqual(r.status_code, 200, r.text[:300])
            self.assertTrue(r.json()["ok"])

    def test_enable_on_healthy_sibling_survives_junk_row(self):
        rows = [_shadowed("id", _row("junk")), _row("good")]
        with _sched_cfg(rows), _disk([_row("good")]):
            r = self.client.post("/api/scheduler/jobs/good/enable",
                                 json={"enabled": False})
            self.assert_utf8_not_500(r)
            self.assertEqual(r.status_code, 200, r.text[:300])
            self.assertIs(r.json()["job"]["enabled"], False)

    def test_run_now_survives_shadow_type_key_in_audit_fields(self):
        with _sched_cfg([_shadowed("type")]):
            r = self.client.post("/api/scheduler/jobs/good/run-now")
            self.assert_utf8_not_500(r)
            self.assertEqual(r.status_code, 200, r.text[:300])
            self.assertTrue(r.json()["ok"])

    def test_run_now_survives_shadow_params_key_in_audit_fields(self):
        with _sched_cfg([_shadowed("params")]):
            r = self.client.post("/api/scheduler/jobs/good/run-now")
            self.assert_utf8_not_500(r)
            self.assertEqual(r.status_code, 200, r.text[:300])
            self.assertTrue(r.json()["ok"])


class TickShadowKeyTests(unittest.TestCase):
    """A shadow bomb key costs only its own row, never the whole tick."""

    ANCHOR = 1_900_000_000 - (1_900_000_000 % 60) + 60

    def _launched(self, rows):
        ran: list[str] = []
        with _sched_cfg(rows), \
                mock.patch.object(scheduler_svc, "_execute",
                                  lambda job, trigger: ran.append(
                                      scheduler_svc._job_id(job))), \
                mock.patch.object(scheduler_svc, "_last_minute", None):
            return scheduler_svc._tick_once(self.ANCHOR), ran

    def test_shadow_cron_key_costs_only_its_row(self):
        # The RuntimeError used to escape the (ValueError, TypeError) net
        # and abort the tick before the healthy sibling was reached.
        launched, ran = self._launched(
            [_shadowed("cron", _row("junk")), _row("good")])
        self.assertEqual(launched, ["good"])
        self.assertEqual(ran, ["good"])

    def test_shadow_id_key_row_is_skipped_not_the_tick(self):
        launched, _ = self._launched(
            [_shadowed("id", _row("junk")), _row("good")])
        self.assertEqual(launched, ["good"])

    def test_shadow_enabled_key_fails_closed_in_the_engine(self):
        # Junk must not fire operator shell: the shadowed row stays parked
        # while its sibling keeps the minute.
        launched, _ = self._launched(
            [_shadowed("enabled", _row("junk")), _row("good")])
        self.assertEqual(launched, ["good"])


class ExecuteNeverRaisesShadowTests(unittest.TestCase):
    """_execute's "never raises" contract now survives shadow row keys."""

    def _run(self, job, running=frozenset()):
        journalled: list[dict] = []
        with mock.patch.object(scheduler_svc, "_record_run",
                               journalled.append), \
                mock.patch.object(scheduler_svc, "_running", set(running)):
            entry = scheduler_svc._execute(job, "manual")
        return entry, journalled

    def test_shadow_type_key_journals_a_failed_run(self):
        # The final entry build read job.get("type") after the finally —
        # the raise lost the whole journal record.
        entry, journalled = self._run(_shadowed("type"))
        self.assertEqual(entry.get("status"), "failed")
        self.assertEqual(len(journalled), 1)
        self.assertIn("unknown job type", entry.get("tail", ""))

    def test_shadow_type_key_skipped_entry_still_journals(self):
        # The skipped build ran before the try ever started.
        entry, journalled = self._run(_shadowed("type"), running={"good"})
        self.assertEqual(entry.get("status"), "skipped")
        self.assertEqual(len(journalled), 1)

    def test_shadow_params_key_keeps_the_no_command_diagnosis(self):
        # Caught by the broad net either way, but the field-level degrade
        # keeps the actionable message instead of an opaque "!! error".
        entry, journalled = self._run(_shadowed("params"))
        self.assertEqual(entry.get("status"), "failed")
        self.assertEqual(len(journalled), 1)
        self.assertIn("no command configured", entry.get("tail", ""))

    def test_shadow_command_key_inside_params_degrades_the_same_way(self):
        job = _row(params={_ShadowStr("command"): "true"})
        entry, _ = self._run(job)
        self.assertEqual(entry.get("status"), "failed")
        self.assertIn("no command configured", entry.get("tail", ""))


class StaysImmunePins(_MountedClientMixin, unittest.TestCase):
    """Guards this hunt leaned on, pinned so a refactor cannot weaken them."""

    def test_eq_bomb_id_value_on_junk_sibling_still_guarded(self):
        # _matches_id's guarded raw equality: the bomb is a *value*, not a
        # key, and the scan must step past it to the healthy sibling.
        rows = [_row("junk", id=_EqBombValue()), _row("good")]
        with _sched_cfg(rows), _disk([_row("good")]):
            r = self.client.delete("/api/scheduler/jobs/good")
            self.assert_utf8_not_500(r)
            self.assertEqual(r.status_code, 200, r.text[:300])

    def test_genuine_disabled_row_still_parks_next_run(self):
        # The fail-closed degrade must not be a blanket "everything off":
        # a genuine False parks the job, a genuine True schedules it.
        with _sched_cfg([_row("off", enabled=False), _row("on")]):
            r = self.client.get("/api/scheduler/jobs")
            self.assert_utf8_not_500(r)
            self.assertEqual(r.status_code, 200)
            by_id = {j.get("id"): j for j in r.json()["jobs"]}
            self.assertIsNone(by_id["off"]["next_run"])
            self.assertIsInstance(by_id["on"]["next_run"], int)

    def test_genuine_rows_still_fire_on_their_minute(self):
        ran: list[str] = []
        anchor = 1_900_000_000 - (1_900_000_000 % 60) + 60
        with _sched_cfg([_row("good")]), \
                mock.patch.object(scheduler_svc, "_execute",
                                  lambda job, trigger: ran.append(
                                      scheduler_svc._job_id(job))), \
                mock.patch.object(scheduler_svc, "_last_minute", None):
            self.assertEqual(scheduler_svc._tick_once(anchor), ["good"])

    def test_shadow_name_key_never_loses_the_audit_or_the_mutation(self):
        # _audit_fields' remaining probes: name/cron/enabled shadows on the
        # row the mutation itself targets.
        for field in ("name", "cron", "enabled"):
            row = _shadowed(field)
            with self.subTest(field=field), \
                    _sched_cfg([row]), _disk([_row("good")]):
                r = self.client.delete("/api/scheduler/jobs/good")
                self.assert_utf8_not_500(r)
                self.assertEqual(r.status_code, 200, r.text[:300])


if __name__ == "__main__":
    unittest.main(verbosity=2)
