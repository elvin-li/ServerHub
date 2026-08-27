"""Ninth leftover-500s sweep of the Jobs domain: the scheduler's cfg-root
liar and the cron-matcher dict's shadow-key / member-eq / star-bool bombs.

jobs8 routed every leftover-reachable type check in hub/jobs.py and
hub/scheduler_svc.py through ``_isinst`` and the unbound base coercions;
maint9 then sealed the two impostor seams left on the Maintenance side (the
cfg-root ``dict.get`` and the ``_jobs`` rescue scan's ``str.__eq__``).  A
fresh hunt over the same mounted tree (create_app + TestClient,
raise_server_exceptions=False) found the scheduler siblings of exactly those
classes still live:

* **cfg-root rank** (``scheduler_svc.list_jobs``).  ``dict.get(data,
  "schedules")`` ran bare whenever ``_isinst(data, dict)`` held — the maint9
  hole, one module over.  A liar whose ``__class__`` *answers* dict is no
  dict at all, and the unbound descriptor's TypeError 500'd
  GET /api/scheduler/jobs, DELETE / run-now (whose get_job scan walks the
  same listing) and aborted the engine tick, all from outside every net
  (:class:`SchedulerCfgRootLiarHttpTests` fails on the pre-fix tree).  The
  unbound call now runs in a try; a raise means "not really a dict" and the
  impostor root degrades to the empty job list.

* **matcher-dict ranks** (``_parsed_matcher`` / ``_day_matches`` /
  ``cron_matches``).  Three leftover shapes inside an exact-dict cron raised
  RuntimeError past ``_tick_once``'s (ValueError, TypeError) net and
  aborted the whole tick — every *other* job's matching minute was lost
  (:class:`MatcherDictBombTickTests` fails on the pre-fix tree):

  - a **hash-shadow key** — a str *subclass* carrying a matcher key's text
    and a bombing ``__eq__`` — detonated the ``_MATCHER_KEYS <= expr.keys()``
    probe itself (the subset test hash-probes the dict and compares the
    interned key against every stored key whose hash collides);
  - an **``__eq__``-bomb member** in a set-typed field passed the gate and
    detonated the ``in`` membership tests (set lookup dispatches into the
    stored member's own reflected ``__eq__``);
  - a **``__bool__``-bomb star flag** passed the old gate (only the five
    field values were type-checked) and detonated ``_day_matches``'s raw
    truth reads.

  The gate is *strengthened*, never weakened: the probes run in a try (a
  raise means "not a parse_cron product" and the dict goes to parse_cron's
  ValueError, the one signal every caller catches), the star flags must be
  exact bools (parse_cron only ever writes exact bools), and the membership
  tests go through guarded ``_in_field`` (a bombed field matches nothing, so
  the job never fires — the unparsable-expression contract).  Genuine
  parse_cron products still take the identical fast path.

Stays-immune pins ride along for the ranks the same hunt confirmed already
coded: the jobs5/jobs7 root union (try/except around cfg() plus the unbound
``dict.get`` for a genuine subclass ``.get`` bomb, which must both survive
this sweep's edit), a liar ``schedules`` value (guarded ``list()``), the
matcher fast path itself, and the bombed-cron rows rendering over HTTP
(next_run_ts already fed dict crons to parse_cron's ValueError, and
``_jsonable`` already coerced the bombed members through the unbound bases).
"""
from __future__ import annotations

import time
import unittest
from unittest import mock

from hub import scheduler_svc


class _Lie:
    """``__class__`` answers a type the object is not — a claim, not a raise.

    The maint9/modules9 impostor: ``isinstance`` (so ``_isinst``) honours the
    claim, but none of the unbound base descriptors (``dict.get``,
    ``list.__iter__``…) apply to the real object.
    """

    def __init__(self, claim):
        self._claim = claim

    @property
    def __class__(self):  # type: ignore[override]
        return self._claim

    def __hash__(self):  # usable as a mapping key
        return 17


class _ShadowKey(str):
    """A *real* str subclass: same text and hash as a matcher key, bombing
    ``__eq__`` — the dict's own hash probe dispatches into it reflected."""

    def __eq__(self, other):  # noqa: D105
        raise RuntimeError("leftover shadow key eq bomb")

    def __hash__(self):  # noqa: D105
        return str.__hash__(self)


class _EqBombInt(int):
    """A real int subclass member: the set lookup's hash hit reaches its
    reflected ``__eq__`` before the exact-int probe can answer."""

    def __eq__(self, other):  # noqa: D105
        raise RuntimeError("leftover member eq bomb")

    __ne__ = __eq__

    def __hash__(self):  # noqa: D105
        return int.__hash__(int(self))


class _BoolBomb:
    def __bool__(self):
        raise RuntimeError("leftover star bool bomb")


def _shadow_cron() -> dict:
    parsed = scheduler_svc.parse_cron("* * * * *")
    return {_ShadowKey("minute") if k == "minute" else k: v
            for k, v in parsed.items()}


def _member_bomb_cron() -> dict:
    parsed = dict(scheduler_svc.parse_cron("* * * * *"))
    parsed["minute"] = {_EqBombInt(m) for m in range(60)}
    return parsed


def _star_bomb_cron(star=None) -> dict:
    # dom AND dow restricted, so _day_matches must read both star flags.
    parsed = dict(scheduler_svc.parse_cron("* * 1 * 1"))
    parsed["dom_star"] = _BoolBomb() if star is None else star
    return parsed


def _sched_cfg(rows):
    return mock.patch.object(scheduler_svc, "cfg", lambda: {"schedules": rows})


def _sched_row(jid, **over):
    row = {"id": jid, "name": "n", "type": "command", "cron": "* * * * *",
           "enabled": True, "params": {"command": "true"}}
    row.update(over)
    return row


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


class SchedulerCfgRootLiarHttpTests(_MountedClientMixin, unittest.TestCase):
    """The fixed leak, config side: a cfg() root whose ``__class__`` answers
    dict passed ``_isinst`` and blew the bare unbound ``dict.get`` — a raw
    500 on the list route AND every mutation's get_job scan on the pre-fix
    tree."""

    def test_dict_liar_cfg_root_degrades_to_empty_list(self):
        with mock.patch.object(scheduler_svc, "cfg", return_value=_Lie(dict)):
            r = self.client.get("/api/scheduler/jobs")
        self.assert_utf8_not_500(r)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["jobs"], [])

    def test_dict_liar_cfg_root_answers_coded_404_not_500_on_mutations(self):
        with mock.patch.object(scheduler_svc, "cfg", return_value=_Lie(dict)):
            r = self.client.delete("/api/scheduler/jobs/good")
            self.assert_utf8_not_500(r)
            self.assertEqual(r.status_code, 404)
            self.assertEqual(
                (r.json().get("detail") or {}).get("code"),
                "scheduler.not_found")
            r2 = self.client.post("/api/scheduler/jobs/good/run-now")
            self.assert_utf8_not_500(r2)
            self.assertEqual(r2.status_code, 404)
            self.assertEqual(
                (r2.json().get("detail") or {}).get("code"),
                "scheduler.not_found")

    def test_healthy_cfg_serves_again_after_the_liar_root_passes(self):
        # The impostor costs only the requests it poisons.
        with mock.patch.object(scheduler_svc, "cfg", return_value=_Lie(dict)):
            self.assertEqual(
                self.client.get("/api/scheduler/jobs").json()["jobs"], [])
        with _sched_cfg([_sched_row("good")]):
            r = self.client.get("/api/scheduler/jobs")
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertEqual([j.get("id") for j in r.json()["jobs"]], ["good"])

    def test_dict_liar_cfg_root_does_not_abort_the_tick(self):
        with mock.patch.object(scheduler_svc, "cfg", return_value=_Lie(dict)), \
                mock.patch.object(scheduler_svc, "_last_minute", None):
            self.assertEqual(scheduler_svc._tick_once(), [])


class MatcherDictBombTickTests(unittest.TestCase):
    """A bombed matcher-dict cron no longer costs the sibling its minute."""

    def _tick(self, rows):
        ran: list[str] = []
        with _sched_cfg(rows), \
                mock.patch.object(scheduler_svc, "_execute",
                                  lambda job, trigger: ran.append(
                                      scheduler_svc._job_id(job))), \
                mock.patch.object(scheduler_svc, "_last_minute", None):
            return scheduler_svc._tick_once()

    def test_shadow_key_cron_does_not_abort_the_tick(self):
        self.assertEqual(
            self._tick([_sched_row("bombed", cron=_shadow_cron()),
                        _sched_row("good")]),
            ["good"])

    def test_member_eq_bomb_cron_does_not_abort_the_tick(self):
        self.assertEqual(
            self._tick([_sched_row("bombed", cron=_member_bomb_cron()),
                        _sched_row("good")]),
            ["good"])

    def test_star_bool_bomb_cron_does_not_abort_the_tick(self):
        self.assertEqual(
            self._tick([_sched_row("bombed", cron=_star_bomb_cron()),
                        _sched_row("good")]),
            ["good"])

    def test_star_bool_liar_cron_does_not_abort_the_tick(self):
        # A liar star claims bool but its exact type is not: the strengthened
        # gate refuses it before _day_matches can read it as truth.
        self.assertEqual(
            self._tick([_sched_row("bombed", cron=_star_bomb_cron(_Lie(bool))),
                        _sched_row("good")]),
            ["good"])

    def test_bombed_crons_can_never_fire(self):
        # The unparsable-expression contract: a bombed field matches nothing.
        now = time.localtime()
        for cron in (_member_bomb_cron(),):
            self.assertFalse(scheduler_svc.cron_matches(cron, now))
        for cron in (_shadow_cron(), _star_bomb_cron(),
                     _star_bomb_cron(_Lie(bool))):
            # The gate refuses these; parse_cron answers the one signal
            # every caller catches.
            with self.assertRaises(ValueError):
                scheduler_svc.cron_matches(cron, now)


class MatcherDictBombHttpTests(_MountedClientMixin, unittest.TestCase):
    """The same bombed crons render over the list route (next_run_ts already
    fed dict crons to parse_cron's ValueError; _jsonable coerces the bombed
    members through the unbound bases)."""

    def test_bombed_cron_rows_render_and_the_sibling_keeps_next_run(self):
        rows = [
            _sched_row("b1", cron=_shadow_cron()),
            _sched_row("b2", cron=_member_bomb_cron()),
            _sched_row("b3", cron=_star_bomb_cron()),
            _sched_row("good"),
        ]
        with _sched_cfg(rows):
            r = self.client.get("/api/scheduler/jobs")
        self.assert_utf8_not_500(r)
        self.assertEqual(r.status_code, 200)
        by_id = {j.get("id"): j for j in r.json()["jobs"]}
        self.assertEqual(sorted(by_id), ["b1", "b2", "b3", "good"])
        # A dict cron is never a schedulable expression from the list route.
        self.assertIsNone(by_id["b1"]["next_run"])
        self.assertIsNone(by_id["b2"]["next_run"])
        self.assertIsNone(by_id["b3"]["next_run"])
        self.assertIsNotNone(by_id["good"]["next_run"])


class StaysImmunePins(_MountedClientMixin, unittest.TestCase):
    """Ranks this hunt probed and found already coded — pinned so a refactor
    back toward the bare unbound call (or a weakened matcher gate) trips."""

    def test_jobs5_and_jobs7_root_union_still_holds(self):
        # The conflict-policy union: try/except around cfg(), and the
        # unbound dict.get still reading under a genuine subclass override.
        with mock.patch.object(scheduler_svc, "cfg",
                               side_effect=RuntimeError("cfg down")):
            r = self.client.get("/api/scheduler/jobs")
            self.assert_utf8_not_500(r)
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["jobs"], [])

        class _GetBomb(dict):
            def get(self, *a, **k):  # noqa: D102
                raise RuntimeError("leftover root get bomb")

        poisoned = _GetBomb({"schedules": [_sched_row("good")]})
        with mock.patch.object(scheduler_svc, "cfg", return_value=poisoned):
            r = self.client.get("/api/scheduler/jobs")
            self.assert_utf8_not_500(r)
            self.assertEqual(r.status_code, 200)
            self.assertEqual([j.get("id") for j in r.json()["jobs"]], ["good"])

    def test_list_liar_schedules_value_degrades_to_empty(self):
        # The guarded ``list()`` refuses a non-iterable impostor claiming list.
        with mock.patch.object(scheduler_svc, "cfg",
                               return_value={"schedules": _Lie(list)}):
            r = self.client.get("/api/scheduler/jobs")
        self.assert_utf8_not_500(r)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["jobs"], [])

    def test_matcher_fast_path_is_not_weakened(self):
        # A genuine parse_cron product still takes the identical fast path
        # (returned by identity, no re-parse) and still matches its minute.
        parsed = scheduler_svc.parse_cron("* * * * *")
        self.assertIs(scheduler_svc._parsed_matcher(parsed), parsed)
        self.assertTrue(scheduler_svc.cron_matches(parsed, time.localtime()))
        restricted = scheduler_svc.parse_cron("*/5 3 1-7 * 1")
        self.assertIs(scheduler_svc._parsed_matcher(restricted), restricted)

    def test_job_mapping_cron_still_goes_to_parse_cron(self):
        # A job dict is also a dict: it must keep raising ValueError (the
        # caught signal), never take the matcher fast path.
        with self.assertRaises(ValueError):
            scheduler_svc.cron_matches(_sched_row("x"), time.localtime())


if __name__ == "__main__":
    unittest.main(verbosity=2)
