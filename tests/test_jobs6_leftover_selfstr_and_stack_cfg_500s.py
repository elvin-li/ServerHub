"""Sixth leftover-500s sweep of the Jobs domain: self-``__str__`` bombs and
the stack config walk.

The jobs5 wave hardened the scheduler/maintenance/stack-job surfaces against
the plain subclass-bomb classes, but two families were still live, confirmed
as raw HTTP 500s over the mounted app before the fix:

* The modules6/docker6 self-``__str__`` encode-bomb class: ``str()`` of a
  str subclass whose ``__str__`` returns *self* skips CPython's exact-str
  copy, so the final bound ``.encode("utf-8", "replace")`` scrub in
  ``scheduler_svc._utf8_text`` and ``hub.jobs._utf8_text`` dispatched to the
  override.  One poisoned id/name/params value (or mapping key) 500'd
  GET /api/scheduler/jobs, GET /api/maintenance and the maintenance log
  route — and blew ``_record_run``'s shaping, silently dropping the run's
  journal record.  Fixed with the unbound ``str.encode`` convention.
* ``containers_svc``'s *config*-side stack walk trusted services.yaml far
  more than the job store it was hardened beside: ``_stack_paths`` iterated
  a list-subclass ``stacks`` raw, read dict-subclass rows with bare
  ``.get()``, put a ``__bool__``-bomb ``compose_file`` through a bare
  ``or``, gated on ``elif s.get("containers"):`` raw, and ``_field_text`` /
  ``_str_list`` kept bound ``.encode`` / raw truthiness probes — each one a
  500 on GET /api/stacks (and, through ``_stack_paths``, on
  POST /api/stacks/{id}/run) until the config was hand-fixed.
* ``scheduler_svc._cron_field_tokens`` list arm: a list-subclass cron whose
  ``__len__``/``__iter__`` raised, or a token whose overridden ``strip()``
  returned another bomb, escaped ``next_run_ts``'s (ValueError,
  RecursionError) net via ``_parse_field`` and 500'd the scheduler list.

Everything is pinned over the real mounted app (create_app + TestClient,
raise_server_exceptions=False) plus module-layer contracts.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import containers_svc, scheduler_svc
from hub import jobs as hub_jobs


class SelfStr(str):
    """``str()`` answers *self* — no exact-str copy — and ``encode`` bombs."""

    def __str__(self):
        return self

    def encode(self, *a, **k):
        raise RuntimeError("boom encode")


class StrLenBomb(str):
    def __len__(self):
        raise RuntimeError("boom len")


class BytesDecodeBomb(bytes):
    def decode(self, *a, **k):
        raise RuntimeError("boom decode")


class SelfStrStripBomb(str):
    """strip() answers self, so the token stays a subclass whose split bombs."""

    def __str__(self):
        return self

    def strip(self, *a):
        return self

    def split(self, *a):
        raise RuntimeError("boom split")


class LenBombList(list):
    def __len__(self):
        raise RuntimeError("boom list len")


class IterBombList(list):
    def __iter__(self):
        raise RuntimeError("boom list iter")


class GetBomb(dict):
    def get(self, *a, **k):
        raise RuntimeError("boom get")


class KeysIterBomb(dict):
    """dict() itself raises: overriding __iter__ sends CPython to keys()."""

    def keys(self):
        raise RuntimeError("boom keys")

    def __iter__(self):
        raise RuntimeError("boom iter")


class BoolBomb:
    def __bool__(self):
        raise RuntimeError("boom bool")


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

    def assert_utf8_json(self, r):
        """A raw 500 with traceback is a leftover; the body must be UTF-8."""
        self.assertNotEqual(r.status_code, 500, r.text[:400])
        r.content.decode("utf-8")


class SchedulerSelfStrLeftoverTests(_MountedClientMixin, unittest.TestCase):
    """GET /api/scheduler/jobs with the self-__str__ encode-bomb class."""

    def _get(self, cfg):
        with mock.patch.object(scheduler_svc, "cfg", return_value=cfg):
            return self.client.get("/api/scheduler/jobs")

    def test_selfstr_id_and_name_stay_200_and_keep_their_text(self):
        r = self._get({"schedules": [
            {"id": SelfStr("sid"), "name": SelfStr("N"), "type": "command",
             "cron": "* * * * *", "enabled": True,
             "params": {"command": "true"}}]})
        self.assert_utf8_json(r)
        self.assertEqual(r.status_code, 200)
        job = r.json()["jobs"][0]
        # The unbound scrub keeps the real characters, not a None drop.
        self.assertEqual(job["id"], "sid")
        self.assertEqual(job["name"], "N")

    def test_selfstr_nested_params_value_and_mapping_key_stay_200(self):
        r = self._get({"schedules": [
            {"id": "p", "name": "n", "type": "command", "cron": "* * * * *",
             "enabled": False,
             "params": {"note": SelfStr("x"), "k": {SelfStr("kk"): "v"}}}]})
        self.assert_utf8_json(r)
        self.assertEqual(r.status_code, 200)
        params = r.json()["jobs"][0]["params"]
        self.assertEqual(params["note"], "x")
        self.assertEqual(params["k"], {"kk": "v"})

    def test_cron_list_subclass_len_and_iter_bombs_stay_200(self):
        for cron in (LenBombList(["*"] * 5), IterBombList(["*"] * 5)):
            with self.subTest(cron=type(cron).__name__):
                r = self._get({"schedules": [
                    {"id": "c", "enabled": True, "cron": cron}]})
                self.assert_utf8_json(r)
                self.assertEqual(r.status_code, 200)
                self.assertIsNone(r.json()["jobs"][0]["next_run"])

    def test_cron_token_whose_strip_returns_a_bomb_still_parses(self):
        """The unbound str.strip view yields exact tokens: a well-formed
        schedule whose token subclass merely bombs ``split`` keeps its
        next_run instead of 500ing _parse_field."""
        r = self._get({"schedules": [
            {"id": "c1", "enabled": True,
             "cron": [SelfStrStripBomb("*"), "*", "*", "*", "*"]}]})
        self.assert_utf8_json(r)
        self.assertEqual(r.status_code, 200)
        job = r.json()["jobs"][0]
        self.assertEqual(job["cron"], ["*"] * 5)
        self.assertIsNotNone(job["next_run"])


class SchedulerJournalSelfStrTests(unittest.TestCase):
    """_record_run's shaping survives the encode bomb: the record lands."""

    def test_record_run_with_selfstr_name_still_journals(self):
        tmp = Path(tempfile.mkdtemp(prefix="jobs6-journal-")) / "runs.jsonl"
        entry = {"ts": 1, "end": 1, "job": "j1", "name": SelfStr("N"),
                 "type": "command", "trigger": "manual", "status": "ok",
                 "rc": 0, "tail": "", "duration": 0}
        with mock.patch.object(scheduler_svc, "RUNS_PATH", tmp):
            scheduler_svc._record_run(entry)
            rows = scheduler_svc.runs("j1")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "N")


class MaintenanceSelfStrLeftoverTests(_MountedClientMixin, unittest.TestCase):
    """GET /api/maintenance and the log route with the same bomb class."""

    def tearDown(self):
        hub_jobs._jobs.clear()

    def test_selfstr_task_id_and_name_stay_200(self):
        cfg = {"maintenance": [
            {"id": SelfStr("mid"), "name": SelfStr("MN"), "command": "true"}]}
        with mock.patch.object(hub_jobs, "cfg", return_value=cfg):
            r = self.client.get("/api/maintenance")
        self.assert_utf8_json(r)
        self.assertEqual(r.status_code, 200)
        task = r.json()[0]
        self.assertEqual(task["id"], "mid")
        self.assertEqual(task["name"], "MN")

    def test_selfstr_job_row_fields_stay_200_on_list_and_log(self):
        hub_jobs._jobs["t1"] = {
            "running": False, "rc": 0, "log": [SelfStr("boom")],
            "started": "10:00:00", "finished": SelfStr("f"),
        }
        cfg = {"maintenance": [{"id": "t1", "name": "T", "command": "true"}]}
        with mock.patch.object(hub_jobs, "cfg", return_value=cfg):
            r = self.client.get("/api/maintenance")
            self.assert_utf8_json(r)
            self.assertEqual(r.status_code, 200)
            r2 = self.client.get("/api/maintenance/t1/log")
        self.assert_utf8_json(r2)
        self.assertEqual(r2.status_code, 200)
        payload = r2.json()
        self.assertEqual(payload["log"], "boom")
        self.assertEqual(payload["finished"], "f")


class StackConfigLeftoverTests(_MountedClientMixin, unittest.TestCase):
    """GET /api/stacks / POST /api/stacks/{id}/run over a poisoned config."""

    def _get_stacks(self, cfg):
        with mock.patch.object(containers_svc, "cfg", return_value=cfg):
            return self.client.get("/api/stacks")

    def test_dict_subclass_rows_drop_and_siblings_survive(self):
        r = self._get_stacks({"stacks": [
            GetBomb(id="junk"), KeysIterBomb(id="junk2"), "not-a-dict",
            {"id": "keep", "containers": ["c"]}]})
        self.assert_utf8_json(r)
        self.assertEqual(r.status_code, 200)
        self.assertEqual([s["id"] for s in r.json()["stacks"]], ["keep"])

    def test_list_subclass_stacks_iter_bomb_stays_200(self):
        r = self._get_stacks({"stacks": IterBombList([{"id": "a"}])})
        self.assert_utf8_json(r)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["stacks"], [])

    def test_bool_bomb_compose_file_and_containers_stay_200(self):
        r = self._get_stacks({"stacks": [
            {"id": "b", "path": "/nonexistent/jobs6", "compose_file": BoolBomb()},
            {"id": "b2", "containers": BoolBomb()},
        ]})
        self.assert_utf8_json(r)
        self.assertEqual(r.status_code, 200)
        stacks = r.json()["stacks"]
        # The path row survives with the bomb treated as unset; the
        # pathless row with junk containers is not a stack and drops.
        self.assertEqual([s["id"] for s in stacks], ["b"])

    def test_selfstr_and_lenbomb_fields_stay_200_and_scrubbed(self):
        r = self._get_stacks({"stacks": [
            {"id": SelfStr("stk"), "name": SelfStr("SN"),
             "containers": ["c1", StrLenBomb("lb")]},
            {"id": "p", "path": StrLenBomb("/nonexistent/jobs6-two"),
             "compose_file": SelfStr("compose.yml")},
        ]})
        self.assert_utf8_json(r)
        self.assertEqual(r.status_code, 200)
        stacks = r.json()["stacks"]
        self.assertEqual(stacks[0]["id"], "stk")
        self.assertEqual(stacks[0]["name"], "SN")
        self.assertIn("c1", stacks[0]["containers"])
        self.assertEqual(stacks[1]["id"], "p")

    def test_bytes_subclass_decode_bomb_field_stays_200(self):
        r = self._get_stacks({"stacks": [
            {"id": "bt", "name": BytesDecodeBomb(b"NN"), "containers": ["c"]}]})
        self.assert_utf8_json(r)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["stacks"][0]["name"], "NN")

    def test_stack_run_with_poisoned_sibling_rows_answers_coded(self):
        """POST /api/stacks/{id}/run walks _stack_paths too: a bomb row used
        to 500 the run for every stack, known or not."""
        cfg = {"stacks": [GetBomb(id="junk")]}
        with mock.patch.object(containers_svc, "cfg", return_value=cfg):
            r = self.client.post("/api/stacks/media/run", json={"action": "up"})
        self.assert_utf8_json(r)
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.json()["detail"]["code"], "container.unknown_stack")


class ModuleLayerPins(unittest.TestCase):
    """The module-level contracts behind the HTTP pins."""

    def test_scheduler_utf8_text_selfstr_scrubs_to_exact_str(self):
        out = scheduler_svc._utf8_text(SelfStr("a\ud800b"))
        self.assertEqual(out, "a?b")
        self.assertIs(type(out), str)

    def test_jobs_utf8_text_selfstr_scrubs_to_exact_str(self):
        out = hub_jobs._utf8_text(SelfStr("a\ud800b"))
        self.assertEqual(out, "a?b")
        self.assertIs(type(out), str)

    def test_scheduler_job_id_selfstr_is_a_plain_hashable_str(self):
        jid = scheduler_svc._job_id({"id": SelfStr("  sid ")})
        self.assertEqual(jid, "sid")
        self.assertIs(type(jid), str)
        {jid}  # must not raise

    def test_cron_field_tokens_bomb_shapes_are_valueerrors(self):
        for expr in (LenBombList(["*"] * 5), IterBombList(["*"] * 5)):
            with self.subTest(expr=type(expr).__name__):
                with self.assertRaises(ValueError):
                    scheduler_svc._cron_field_tokens(expr)
                self.assertIsNone(scheduler_svc.next_run_ts(expr))

    def test_cron_field_tokens_strip_bomb_tokens_come_back_exact(self):
        tokens = scheduler_svc._cron_field_tokens(
            [SelfStrStripBomb("*"), "*", "*", "*", "*"])
        self.assertEqual(tokens, ["*"] * 5)
        for t in tokens:
            self.assertIs(type(t), str)
        self.assertIsNotNone(
            scheduler_svc.next_run_ts([SelfStrStripBomb("*"), "*", "*", "*", "*"]))

    def test_field_text_bomb_shapes_keep_their_text(self):
        self.assertEqual(containers_svc._field_text(SelfStr("x")), "x")
        self.assertEqual(containers_svc._field_text(StrLenBomb("y")), "y")
        self.assertEqual(containers_svc._field_text(BytesDecodeBomb(b"z")), "z")

    def test_str_list_bomb_shapes_drop_only_their_items(self):
        self.assertEqual(containers_svc._str_list(IterBombList(["a"])), [])
        self.assertEqual(
            containers_svc._str_list(["a", StrLenBomb("b"), 5, ""]),
            ["a", "b"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
