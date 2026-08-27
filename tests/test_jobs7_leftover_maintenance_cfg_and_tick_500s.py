"""Seventh leftover-500s sweep of the Jobs domain: the Maintenance config-read
seam and the engine tick's cron-mapping sniff.

The jobs6 wave sealed the self-``__str__`` encode bombs and the stack config
walk, and sched7 gave ``scheduler_svc.list_jobs`` the guarded-cfg / unbound
``dict.get`` read — but the Maintenance twin never got the same fold, and one
engine sniff still reflected into the leftover itself.  Confirmed live on the
pre-fix tree:

* ``hub.jobs.maintenance_tasks`` read ``cfg().get("maintenance")`` raw: a
  dict-*subclass* config root whose ``.get`` raised — or a cfg() snapshot
  provider that raised outright — 500'd GET /api/maintenance and
  POST /api/maintenance/{tid}/run (the log route never reads cfg and stayed
  up).  Fixed with the sched7 shape: guarded ``cfg()`` call, then the
  unbound ``dict.get``, which reads the C-level storage underneath the
  override so the real tasks still serve.
* ``scheduler_svc.cron_matches``'s parsed-matcher sniff called
  ``expr.get("minute")`` behind a bare isinstance: a leftover dict-subclass
  cron whose ``.get`` raised detonated the probe, and a YAML mapping cron
  carrying a ``!!set`` ``minute`` passed the sniff and KeyError'd
  ``_day_matches`` on the matcher keys it did not have.  Either escaped
  ``_tick_once``'s (ValueError, TypeError) net and aborted the whole tick —
  every *other* job's matching minute was lost (the sched7 thread-name
  class).  Only an exact parse_cron product takes the fast path now;
  everything else funnels into parse_cron's ValueError.

HTTP pins run over the real mounted app (create_app + TestClient,
raise_server_exceptions=False); module-layer contracts ride along, plus
stays-immune pins for the neighbours probed and found already dead.
"""
from __future__ import annotations

import time
import unittest
from unittest import mock

from hub import audit, containers_svc, scheduler_svc
from hub import jobs as hub_jobs


class GetBomb(dict):
    def get(self, *a, **k):
        raise RuntimeError("boom get")


def _raising_cfg():
    raise RuntimeError("boom cfg")


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


class MaintenanceCfgSeamTests(_MountedClientMixin, unittest.TestCase):
    """GET /api/maintenance and POST run over a poisoned — or raising — cfg."""

    def tearDown(self):
        hub_jobs._jobs.clear()

    def test_dict_get_bomb_config_root_still_lists_the_tasks(self):
        root = GetBomb(maintenance=[{"id": "ok", "name": "fine", "command": "true"}])
        with mock.patch.object(hub_jobs, "cfg", lambda: root):
            r = self.client.get("/api/maintenance")
        self.assert_utf8_not_500(r)
        self.assertEqual(r.status_code, 200)
        # The unbound read serves the real storage underneath the override.
        self.assertEqual([t["id"] for t in r.json()], ["ok"])

    def test_raising_cfg_provider_answers_an_empty_list_not_500(self):
        with mock.patch.object(hub_jobs, "cfg", _raising_cfg):
            r = self.client.get("/api/maintenance")
        self.assert_utf8_not_500(r)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), [])

    def test_run_over_raising_cfg_is_the_coded_404_not_500(self):
        with mock.patch.object(hub_jobs, "cfg", _raising_cfg):
            r = self.client.post("/api/maintenance/anything/run")
        self.assert_utf8_not_500(r)
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.json()["detail"]["code"], "maintenance.unknown_task")

    def test_run_over_dict_get_bomb_root_still_starts_the_task(self):
        root = GetBomb(maintenance=[{"id": "ok", "name": "fine", "command": "true"}])
        with mock.patch.object(hub_jobs, "cfg", lambda: root), \
                mock.patch.object(audit, "record", lambda event, **f: {}):
            r = self.client.post("/api/maintenance/ok/run")
        self.assert_utf8_not_500(r)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json().get("ok"))


class TickCronMappingSniffTests(unittest.TestCase):
    """A poisoned cron mapping no longer costs the healthy sibling its minute."""

    def _tick(self, rows):
        ran: list[str] = []
        with mock.patch.object(scheduler_svc, "cfg",
                               lambda: {"schedules": rows}), \
                mock.patch.object(scheduler_svc, "_execute",
                                  lambda job, trigger: ran.append(
                                      scheduler_svc._job_id(job))), \
                mock.patch.object(scheduler_svc, "_last_minute", None):
            return scheduler_svc._tick_once()

    def _row(self, jid, cron):
        return {"id": jid, "enabled": True, "cron": cron,
                "type": "command", "params": {"command": "true"}}

    def test_dict_subclass_get_bomb_cron_does_not_abort_the_tick(self):
        launched = self._tick([
            self._row("bombed", GetBomb(minute="*")),
            self._row("healthy", "* * * * *"),
        ])
        self.assertEqual(launched, ["healthy"])

    def test_partial_set_mapping_cron_does_not_abort_the_tick(self):
        """YAML ``cron: {minute: !!set {...}}`` used to pass the sniff and
        KeyError _day_matches on the matcher keys it did not have."""
        launched = self._tick([
            self._row("partial", {"minute": frozenset({0})}),
            self._row("healthy", "* * * * *"),
        ])
        self.assertEqual(launched, ["healthy"])


class ModuleLayerPins(unittest.TestCase):
    """The contracts behind the pins above."""

    _MATCH_T = time.struct_time((2026, 8, 13, 3, 30, 0, 3, 225, -1))

    def test_cron_matches_get_bomb_mapping_is_a_valueerror(self):
        with self.assertRaises(ValueError):
            scheduler_svc.cron_matches(GetBomb(minute="*"), self._MATCH_T)

    def test_cron_matches_partial_set_mapping_is_a_valueerror_not_keyerror(self):
        with self.assertRaises(ValueError):
            scheduler_svc.cron_matches({"minute": frozenset({0})}, self._MATCH_T)

    def test_parse_cron_product_keeps_the_fast_path(self):
        parsed = scheduler_svc.parse_cron("30 3 * * *")
        self.assertIs(scheduler_svc._parsed_matcher(parsed), parsed)
        self.assertTrue(scheduler_svc.cron_matches(parsed, self._MATCH_T))

    def test_parsed_matcher_rejects_subclasses_and_junk_shapes(self):
        parsed = scheduler_svc.parse_cron("* * * * *")
        self.assertIsNone(scheduler_svc._parsed_matcher(GetBomb(parsed)))
        self.assertIsNone(scheduler_svc._parsed_matcher({"minute": frozenset()}))
        self.assertIsNone(
            scheduler_svc._parsed_matcher(dict(parsed, minute="*")))

    def test_maintenance_tasks_survives_bomb_root_and_raising_cfg(self):
        root = GetBomb(maintenance=[{"id": "t1", "command": "true"}])
        with mock.patch.object(hub_jobs, "cfg", lambda: root):
            self.assertEqual(list(hub_jobs.maintenance_tasks()), ["t1"])
        with mock.patch.object(hub_jobs, "cfg", _raising_cfg):
            self.assertEqual(hub_jobs.maintenance_tasks(), {})


class StaysImmunePins(_MountedClientMixin, unittest.TestCase):
    """Neighbours probed in this sweep and found already dead."""

    def test_maintenance_log_route_never_read_cfg_and_stays_200(self):
        with mock.patch.object(hub_jobs, "cfg", _raising_cfg):
            r = self.client.get("/api/maintenance/anything/log")
        self.assert_utf8_not_500(r)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["log"], "(not run yet)")

    def test_stacks_config_root_bombs_stay_coded(self):
        """containers_svc already reads its snapshot defensively; pin it."""
        root = GetBomb(stacks=[{"id": "keep", "containers": ["c"]}])
        with mock.patch.object(containers_svc, "cfg", lambda: root):
            r = self.client.get("/api/stacks")
            self.assert_utf8_not_500(r)
            self.assertEqual(r.status_code, 200)
        with mock.patch.object(containers_svc, "cfg", _raising_cfg):
            r = self.client.get("/api/stacks")
            self.assert_utf8_not_500(r)
            self.assertEqual(r.status_code, 200)
            r2 = self.client.post("/api/stacks/media/run", json={"action": "up"})
            self.assert_utf8_not_500(r2)
            self.assertEqual(r2.status_code, 404)

    def test_scheduler_list_keeps_its_sched7_guard(self):
        with mock.patch.object(scheduler_svc, "cfg", _raising_cfg):
            r = self.client.get("/api/scheduler/jobs")
        self.assert_utf8_not_500(r)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["jobs"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
