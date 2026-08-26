"""Fifth leftover-500s sweep of the Jobs domain: the panel scheduler surfaces.

Prior sweeps hardened hub/jobs.py (Maintenance) against the subclass-bomb /
surrogate / digit-cap leftover classes, but the *scheduler* half of the Jobs
domain — hub/scheduler_svc.py behind /api/scheduler/jobs — kept the unguarded
shapes and was found live-500able:

* ``list_jobs()`` copied rows with a bare ``dict(j)`` behind an isinstance
  gate: a leftover dict-*subclass* row whose ``dict()`` copy raises (CPython
  falls back to ``keys()`` when ``__iter__`` is overridden) 500'd
  GET /api/scheduler/jobs; a list-subclass ``schedules`` whose ``__iter__``
  raises 500'd it one line earlier.
* ``scheduler_svc._jsonable`` walked ``value.items()`` / list ``__iter__``
  raw, so a *nested* subclass bomb (a poisoned ``params`` mapping) survived
  the row copy and 500'd the encoder walk (hub.jobs._jsonable already
  carried the dict()-copy guard).
* ``_job_id`` called ``raw.strip()`` on the raw value: a str-subclass id
  whose ``strip()`` raised 500'd the list route.
* ``_cron_field_tokens`` only converted RecursionError to ValueError: a cron
  list item whose ``str()`` raised anything else escaped ``next_run_ts``'s
  ``(ValueError, RecursionError)`` net and 500'd the list route.
* ``_matches_id`` compared ``job.get("id") == job_id`` raw: a leftover
  ``__eq__``-bomb id value on ANY sibling row raised out of ``get_job``'s
  scan and 500'd DELETE / PUT / enable / run-now for *healthy* jobs.
* ``_audit_fields`` read ``params.get("command")`` behind a bare isinstance:
  a dict-subclass ``params`` whose ``.get()`` raised 500'd the audited
  mutation after validation had already passed.

Everything else probed here was found immune and is pinned as such: journal
poisoning (huge JSON ints — a ValueError, not JSONDecodeError — invalid
UTF-8, surrogate escapes, deep nesting), a leftover FIFO occupying the runs
journal (must answer, not hang), hostile LaunchAgent plists on the read-only
scheduler views (ExpatError junk, oversize, FIFO, hex-int overcap), and a
4300+-digit int in a JSON request body (FastAPI's body-parse guard answers a
coded 400 even though ``json.loads`` raises ValueError, not JSONDecodeError).
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import scheduler_svc

#: Past CPython's default 4300-digit int<->str conversion limit.
_HUGE_INT = 10 ** 5000


# ── the hunted leftover bomb classes ─────────────────────────────────────────

class _GetBomb(dict):
    def get(self, *a, **k):
        raise RuntimeError("boom get")


class _ItemsBomb(dict):
    def items(self):
        raise RuntimeError("boom items")


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

    __hash__ = None  # unhashable too


class _StrBomb:
    def __str__(self):
        raise TypeError("boom str")


class _StripBomb(str):
    def strip(self, *a):
        raise RuntimeError("boom strip")

    def __hash__(self):
        raise RuntimeError("boom hash")


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


class SchedulerListLeftoverTests(_MountedClientMixin, unittest.TestCase):
    """GET /api/scheduler/jobs with the hunted leftover row shapes."""

    def _get(self, cfg):
        with mock.patch.object(scheduler_svc, "cfg", return_value=cfg):
            return self.client.get("/api/scheduler/jobs")

    def test_list_subclass_schedules_iter_bomb_stays_200(self):
        r = self._get({"schedules": _IterBombList([{"id": "a"}])})
        self.assert_utf8_json(r)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["jobs"], [])

    def test_dict_subclass_row_whose_copy_raises_drops_only_its_row(self):
        r = self._get({"schedules": [
            _KeysIterBomb(id="junk"),
            {"id": "keep", "name": "K", "type": "command",
             "cron": "* * * * *", "enabled": False,
             "params": {"command": "true"}},
        ]})
        self.assert_utf8_json(r)
        self.assertEqual(r.status_code, 200)
        self.assertEqual([j["id"] for j in r.json()["jobs"]], ["keep"])

    def test_readable_subclass_rows_survive_via_the_c_level_copy(self):
        """.get()/.items() bombs whose dict() copy works keep their row."""
        for row in (_GetBomb(id="a"), _ItemsBomb(id="a")):
            with self.subTest(row=type(row).__name__):
                r = self._get({"schedules": [row]})
                self.assert_utf8_json(r)
                self.assertEqual(r.status_code, 200)
                self.assertEqual([j["id"] for j in r.json()["jobs"]], ["a"])

    def test_nested_params_subclass_bombs_stay_200(self):
        """The metrics5/usage5 nested-bomb class: past the row copy, inside
        _jsonable's walk."""
        for params, expect in (
            (_ItemsBomb(command="true"), {"command": "true"}),  # copy works
            (_KeysIterBomb(command="true"), None),              # copy raises
        ):
            with self.subTest(params=type(params).__name__):
                r = self._get({"schedules": [
                    {"id": "p", "name": "n", "type": "command",
                     "cron": "* * * * *", "enabled": False, "params": params}]})
                self.assert_utf8_json(r)
                self.assertEqual(r.status_code, 200)
                self.assertEqual(r.json()["jobs"][0]["params"], expect)

    def test_nested_list_subclass_iter_bomb_stays_200(self):
        r = self._get({"schedules": [
            {"id": "p", "name": "n", "type": "command", "cron": "* * * * *",
             "enabled": False, "params": {"xs": _IterBombList([1])}}]})
        self.assert_utf8_json(r)
        self.assertEqual(r.status_code, 200)
        self.assertIsNone(r.json()["jobs"][0]["params"]["xs"])

    def test_str_subclass_id_strip_bomb_stays_200_and_serves_plain_text(self):
        r = self._get({"schedules": [{"id": _StripBomb("sb")}]})
        self.assert_utf8_json(r)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["jobs"][0]["id"], "sb")

    def test_cron_item_str_bomb_stays_200_with_no_next_run(self):
        """str(part) raising a non-ValueError used to escape next_run_ts."""
        r = self._get({"schedules": [
            {"id": "c", "enabled": True,
             "cron": ["*", "*", "*", "*", _StrBomb()]}]})
        self.assert_utf8_json(r)
        self.assertEqual(r.status_code, 200)
        self.assertIsNone(r.json()["jobs"][0]["next_run"])

    def test_surrogates_huge_ints_and_bool_bombs_stay_200(self):
        r = self._get({"schedules": [
            {"id": "s\ud800id", "name": "N\udfff", "k\ud800ey": "v\udc80",
             "type": "command", "cron": "* * * * *", "enabled": True,
             "params": {"command": "true"}},
            {"id": _HUGE_INT, "name": "H", "timeout": _HUGE_INT,
             "cron": "* * * * *", "enabled": True,
             "params": {"n": _HUGE_INT}},
            {"id": "b", "cron": "* * * * *", "enabled": _BoolBomb()},
            {"id": _EqBomb()},
        ]})
        self.assert_utf8_json(r)
        self.assertEqual(r.status_code, 200)
        jobs = r.json()["jobs"]
        self.assertEqual(jobs[0]["id"], "s?id")
        self.assertEqual(jobs[0]["name"], "N?")
        self.assertNotIn("\ud800", r.text)
        # over-cap ints drop to null instead of ValueError-ing json.dumps
        self.assertIsNone(jobs[1]["id"])
        self.assertIsNone(jobs[1]["timeout"])
        self.assertIsNone(jobs[1]["params"]["n"])


class SchedulerMutationLeftoverTests(_MountedClientMixin, unittest.TestCase):
    """Mutation routes with an __eq__-bomb sibling row in the stored config.

    ``_matches_id``'s raw ``job.get("id") == job_id`` used to raise out of
    ``get_job``'s scan and 500 every DELETE / PUT / enable / run-now — for a
    job whose own record was perfectly healthy.
    """

    _CFG = {"schedules": [
        {"id": _EqBomb()},
        {"id": "tgt", "name": "T", "type": "command", "cron": "* * * * *",
         "enabled": False, "params": {"command": "true"}},
    ]}

    def _patched(self):
        return mock.patch.object(scheduler_svc, "cfg", return_value=self._CFG)

    def test_run_now_with_eq_bomb_sibling_is_a_200(self):
        with self._patched():
            r = self.client.post("/api/scheduler/jobs/tgt/run-now")
        self.assert_utf8_json(r)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["ok"])

    def test_delete_put_enable_with_eq_bomb_sibling_stay_coded(self):
        """The write half goes through mutate() against the real (empty)
        config file, so the coded 404 is the honest answer — the pin is
        that the *read* scan no longer 500s first."""
        with self._patched():
            for label, r in (
                ("delete", self.client.delete("/api/scheduler/jobs/tgt")),
                ("enable", self.client.post(
                    "/api/scheduler/jobs/tgt/enable", json={"enabled": False})),
                ("put", self.client.put("/api/scheduler/jobs/tgt", json={
                    "name": "T", "type": "command", "cron": "* * * * *",
                    "params": {"command": "true"}})),
            ):
                with self.subTest(route=label):
                    self.assert_utf8_json(r)
                    self.assertIn(r.status_code, (200, 404))

    def test_run_now_with_get_bomb_params_survives_the_audit_read(self):
        """_audit_fields' params.get() used to raise past validation."""
        cfg = {"schedules": [
            {"id": "pb", "name": "PB", "type": "command", "cron": "* * * * *",
             "enabled": False, "params": _GetBomb(command="true")}]}
        with mock.patch.object(scheduler_svc, "cfg", return_value=cfg):
            r = self.client.post("/api/scheduler/jobs/pb/run-now")
        self.assert_utf8_json(r)
        self.assertEqual(r.status_code, 200, r.text)


class SchedulerJournalStaysImmuneTests(_MountedClientMixin, unittest.TestCase):
    """Poisoned run-journal shapes stay coded 200s (found immune; pinned)."""

    def _with_journal(self, payload: bytes):
        tmp = Path(tempfile.mkdtemp(prefix="jobs5-journal-")) / "runs.jsonl"
        tmp.write_bytes(payload)
        return mock.patch.object(scheduler_svc, "RUNS_PATH", tmp)

    def test_huge_ints_bad_utf8_surrogates_and_junk_lines_stay_200(self):
        # json.loads of a 5000-digit number raises ValueError (the int
        # digit cap), NOT JSONDecodeError — runs() must catch it as the
        # corrupt-line signal it is.
        payload = (
            b'{"job": "j1", "rc": ' + b"9" * 5000 + b', "ts": 1}\n'
            b'{"job": "j\xff1", "bad": true}\n'
            b'{"job": "j1", "tail": "\\ud800torn", "ts": 2, "status": "ok"}\n'
            b"not json at all\n"
            + b"[" * 100000 + b"\n"
        )
        with self._with_journal(payload):
            r = self.client.get("/api/scheduler/runs")
            self.assert_utf8_json(r)
            self.assertEqual(r.status_code, 200)
            runs = r.json()["runs"]
            self.assertTrue(any(rec.get("tail") == "?torn" for rec in runs))
            r2 = self.client.get("/api/scheduler/jobs/j1/runs")
        self.assert_utf8_json(r2)
        self.assertEqual(r2.status_code, 200)

    def test_leftover_fifo_journal_answers_instead_of_hanging(self):
        tmp = Path(tempfile.mkdtemp(prefix="jobs5-fifo-")) / "runs.jsonl"
        os.mkfifo(tmp)
        with mock.patch.object(scheduler_svc, "RUNS_PATH", tmp):
            r = self.client.get("/api/scheduler/runs")
        self.assert_utf8_json(r)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), {"runs": []})


class LaunchdSchedulerViewsStayImmuneTests(_MountedClientMixin, unittest.TestCase):
    """GET /api/scheduler and /api/system/scheduler with hostile plists
    (found immune; pinned): ExpatError junk, oversize, a leftover FIFO that
    must not hang, and an over-cap hex ``<integer>`` that dodges the
    parse-time digit limit."""

    def test_hostile_launchagents_stay_200(self):
        home = Path(tempfile.mkdtemp(prefix="jobs5-home-"))
        agents = home / "Library" / "LaunchAgents"
        agents.mkdir(parents=True)
        (agents / "a-expat.plist").write_bytes(
            b"<?xml version='1.0'?><plist><dict><key>")
        (agents / "b-junk.plist").write_bytes(b"\xff\xfe\x00garbage")
        (agents / "c-hexint.plist").write_bytes(
            b"<?xml version='1.0'?><plist version='1.0'><dict>"
            b"<key>Label</key><string>c</string>"
            b"<key>StartInterval</key><integer>0x" + b"F" * 4400
            + b"</integer></dict></plist>")
        (agents / "d-oversize.plist").write_bytes(b"x" * (8 * 1024 * 1024))
        os.mkfifo(agents / "e-fifo.plist")
        (agents / "f-weird.plist").write_bytes(
            b"<?xml version='1.0'?><plist version='1.0'><dict>"
            b"<key>Label</key><integer>7</integer>"
            b"<key>StartInterval</key><real>inf</real>"
            b"<key>StartCalendarInterval</key><dict>"
            b"<key>Minute</key><real>nan</real></dict>"
            b"<key>ProgramArguments</key><array><integer>1</integer>"
            b"<data>/w==</data></array></dict></plist>")
        with mock.patch.dict(os.environ, {"HOME": str(home)}):
            for path in ("/api/scheduler", "/api/system/scheduler"):
                with self.subTest(path=path):
                    r = self.client.get(path)
                    self.assert_utf8_json(r)
                    self.assertEqual(r.status_code, 200, r.text[:200])
                    timers = r.json()["timers"]
                    # the one salvageable agent is listed, with its
                    # inf/nan calendar scrubbed
                    self.assertEqual(len(timers), 1)
                    self.assertEqual(timers[0]["label"], "f-weird")
                    self.assertIsNone(timers[0]["interval_sec"])


class HugeJsonBodyStaysImmuneTests(_MountedClientMixin, unittest.TestCase):
    """A 4300+-digit int in a JSON request body raises ValueError (not
    JSONDecodeError) from json.loads; FastAPI's body-parse guard must keep
    answering a coded 4xx (found immune; pinned)."""

    def test_huge_json_int_body_is_a_coded_4xx(self):
        body = ('{"name": "x", "type": "command", "cron": "* * * * *", '
                '"timeout": ' + "9" * 5000
                + ', "params": {"command": "true"}}')
        r = self.client.post(
            "/api/scheduler/jobs", content=body,
            headers={"content-type": "application/json"})
        self.assert_utf8_json(r)
        self.assertIn(r.status_code, (400, 422))


class SchedulerModuleLayerPins(unittest.TestCase):
    """The module-level contracts behind the HTTP pins."""

    def test_jsonable_nested_bombs_drop_to_none(self):
        self.assertIsNone(scheduler_svc._jsonable(_KeysIterBomb(a=1)))
        self.assertIsNone(scheduler_svc._jsonable(_IterBombList([1])))
        self.assertEqual(scheduler_svc._jsonable(_ItemsBomb(a=1)), {"a": 1})
        self.assertEqual(
            scheduler_svc._jsonable({"deep": {"params": _KeysIterBomb(x=1)}}),
            {"deep": {"params": None}})

    def test_job_id_strip_bomb_coerces_to_a_plain_hashable_str(self):
        jid = scheduler_svc._job_id({"id": _StripBomb("  sb ")})
        self.assertEqual(jid, "sb")
        self.assertIs(type(jid), str)  # usable as a _running set member
        {jid}  # must not raise

    def test_cron_field_tokens_str_bomb_is_a_valueerror(self):
        with self.assertRaises(ValueError):
            scheduler_svc._cron_field_tokens(["*", "*", "*", "*", _StrBomb()])
        self.assertIsNone(
            scheduler_svc.next_run_ts(["*", "*", "*", "*", _StrBomb()]))

    def test_matches_id_eq_bomb_never_raises(self):
        self.assertFalse(scheduler_svc._matches_id({"id": _EqBomb()}, "tgt"))
        self.assertTrue(scheduler_svc._matches_id({"id": "tgt"}, "tgt"))

    def test_list_jobs_drops_junk_rows_and_keeps_readable_ones(self):
        cfg = {"schedules": [
            _KeysIterBomb(id="junk"), "not-a-dict", _GetBomb(id="ok"),
            {"id": "plain"}]}
        with mock.patch.object(scheduler_svc, "cfg", return_value=cfg):
            rows = scheduler_svc.list_jobs()
        self.assertEqual([r.get("id") for r in rows], ["ok", "plain"])
        for r in rows:
            self.assertIs(type(r), dict)


if __name__ == "__main__":
    unittest.main(verbosity=2)
