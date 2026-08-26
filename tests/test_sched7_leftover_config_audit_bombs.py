"""Seventh scheduler leftover sweep — config-read and audit-seam bomb 500s.

The sched6 wave sealed ``scheduler_svc._jsonable``'s nested unbound
coercions, but two seams around them still detonated.  Driven through
``create_app()`` + ``TestClient(raise_server_exceptions=False)``, these
were live raw HTTP 500s on the pre-fix tree:

* GET /api/scheduler/jobs (and every mutation's ``get_job`` scan) — the
  config root itself wearing a dict-subclass ``.get`` bomb: ``list_jobs``'s
  bound ``cfg().get("schedules")`` dispatched into the override.  A cfg()
  snapshot provider that raised outright escaped the same reader.
* POST run-now / DELETE on a job whose ``type`` carries an ``__eq__`` bomb
  — ``_audit_fields``'s ``record.get("type") == "command"`` reflected into
  the stored value's own ``__eq__`` after validation had already passed.

Fixes, the established pool7/modules5 conventions: ``list_jobs`` reads the
snapshot through unbound ``dict.get`` behind a guarded ``cfg()`` call (the
storage_pool_svc._pool_config shape), and ``_audit_fields`` wraps its type
equality like ``_matches_id`` does.  The unbound view reads the real
storage underneath the override, so the schedules list still serves.

Two engine-contract seals ride along (no HTTP surface, but the same bomb
family): ``_execute``'s ``job.get("name") or jid`` ran a leftover name
value's own ``__bool__`` *after* the runner finished — the run journalled
nothing and the "Never raises" docstring broke — and ``_tick_once``'s
thread-name f-string ran a leftover id value's ``__format__``/``__str__``,
aborting the whole tick so every other job's matching minute was lost.

Stays-immune pins for the neighbours probed and found dead: surrogate
escapes in create bodies (coded 400/422, never a 500), a >4300-digit
``timeout`` in a raw JSON body (json.loads raises the digit-cap ValueError,
not JSONDecodeError; FastAPI's generic body-parse 400 absorbs it), huge
``1e999`` / ``NaN`` journal numerics, and dict-subclass ``.get``-bomb
timer rows on the launchd alias routes.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from fastapi.testclient import TestClient  # noqa: E402

from hub import audit, config, scheduler_svc, tools_svc  # noqa: E402
from hub.app_factory import create_app  # noqa: E402
from hub.auth import require_auth  # noqa: E402

_app = None


def _the_app():
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return _app


def _client() -> TestClient:
    return TestClient(_the_app(), raise_server_exceptions=False)


def _encodable(body) -> None:
    """The exact render Starlette performs: ensure_ascii=False then UTF-8."""
    json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")


# ── the hunted leftover bomb classes ─────────────────────────────────────────

class _DictGetBomb(dict):
    def get(self, *a, **k):
        raise RuntimeError("dict get bomb")


class _StrEqBomb(str):
    def __eq__(self, other):
        raise RuntimeError("str eq bomb")

    __ne__ = __eq__
    __hash__ = str.__hash__


class _EqBomb:
    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    __ne__ = __eq__
    __hash__ = object.__hash__


class _StrBoolBomb(str):
    def __bool__(self):
        raise RuntimeError("str bool bomb")


class _IntStrBomb(int):
    def __str__(self):
        raise RuntimeError("int str bomb")

    __repr__ = __str__


def _sane(jid="victim", **over) -> dict:
    row = {"id": jid, "name": "n", "type": "command",
           "cron": "* * * * *", "enabled": True,
           "params": {"command": "echo hi"}}
    row.update(over)
    return row


class ConfigRootBombs(unittest.TestCase):
    """list_jobs's snapshot read survives a poisoned — or raising — cfg()."""

    def test_dict_get_bomb_config_root_still_lists_the_jobs(self):
        root = _DictGetBomb(schedules=[_sane()])
        with mock.patch.object(scheduler_svc, "cfg", lambda: root):
            resp = _client().get("/api/scheduler/jobs")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _encodable(body)
        # The unbound read serves the real storage underneath the override.
        self.assertEqual([j["id"] for j in body["jobs"]], ["victim"])

    def test_raising_cfg_provider_answers_an_empty_list_not_500(self):
        def _boom():
            raise RuntimeError("cfg bomb")

        with mock.patch.object(scheduler_svc, "cfg", _boom):
            resp = _client().get("/api/scheduler/jobs")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["jobs"], [])

    def test_dict_get_bomb_config_root_cannot_500_run_now(self):
        root = _DictGetBomb(schedules=[_sane()])
        with mock.patch.object(audit, "record", lambda event, **f: {}), \
                mock.patch.object(scheduler_svc, "cfg", lambda: root):
            resp = _client().post("/api/scheduler/jobs/victim/run-now")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _encodable(resp.json())
        self.assertTrue(resp.json().get("started"))


class _MutationSandbox(unittest.TestCase):
    """Victim job on disk; the read path (cfg) carries the bombed fields."""

    def setUp(self):
        root = Path(os.environ.get("TMPDIR", "/tmp")) / (
            f"serverhub-sched7-mut-{os.getpid()}-{id(self)}"
        )
        (root / "data").mkdir(parents=True, exist_ok=True)
        self.root = root
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        for target, value in (
            ("YAML_PATH", root / "services.yaml"),
            ("DATA_DIR", root / "data"),
            ("BASE", root),
        ):
            patched = mock.patch.object(config, target, value)
            patched.start()
            self.addCleanup(patched.stop)
        self.addCleanup(config.reload_cfg)
        runs = mock.patch.object(
            scheduler_svc, "RUNS_PATH", root / "data" / "schedule-runs.jsonl"
        )
        runs.start()
        self.addCleanup(runs.stop)
        recorder = mock.patch.object(audit, "record", lambda event, **f: {})
        recorder.start()
        self.addCleanup(recorder.stop)
        (root / "services.yaml").write_text(
            "schedules:\n"
            "  - id: victim\n"
            "    name: v\n"
            "    type: command\n"
            "    cron: '30 3 * * *'\n"
            "    enabled: true\n"
            "    params: {command: echo hi}\n",
            encoding="utf-8",
        )
        config.reload_cfg()

    def _with_bombed_victim(self, **over):
        cfg_value = {"schedules": [_sane(**over)]}
        return mock.patch.object(scheduler_svc, "cfg", lambda: cfg_value)


class AuditFieldsEqBombs(_MutationSandbox):
    """_audit_fields's type equality no longer reflects into the bomb."""

    def test_run_now_survives_str_eq_bomb_type(self):
        with self._with_bombed_victim(type=_StrEqBomb("command")):
            resp = _client().post("/api/scheduler/jobs/victim/run-now")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _encodable(resp.json())
        self.assertTrue(resp.json().get("started"))

    def test_run_now_survives_bare_eq_bomb_type(self):
        with self._with_bombed_victim(type=_EqBomb()):
            resp = _client().post("/api/scheduler/jobs/victim/run-now")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _encodable(resp.json())

    def test_delete_survives_eq_bomb_type_on_the_victim(self):
        with self._with_bombed_victim(type=_StrEqBomb("command")):
            resp = _client().delete("/api/scheduler/jobs/victim")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(scheduler_svc.list_jobs(), [])


class ExecuteNeverRaisesContract(unittest.TestCase):
    """__bool__/__format__ bombs in job values no longer break the engine."""

    def setUp(self):
        import tempfile
        tmp = Path(tempfile.mkdtemp(prefix="serverhub-sched7-exec-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        runs = mock.patch.object(
            scheduler_svc, "RUNS_PATH", tmp / "schedule-runs.jsonl"
        )
        runs.start()
        self.addCleanup(runs.stop)

    def test_bool_bomb_name_still_journals_the_run(self):
        """Pre-fix the entry build raised *after* the runner finished, so
        the run journalled nothing and _execute's contract broke."""
        job = _sane(name=_StrBoolBomb("bombed"))
        entry = scheduler_svc._execute(job, "manual")
        self.assertEqual(entry.get("status"), "ok", entry)
        # Truthiness is unknowable through the bomb; the label falls back
        # to the id and the record still lands in the journal.
        self.assertEqual(entry.get("name"), "victim")
        recorded = scheduler_svc.runs("victim", limit=5)
        self.assertEqual(len(recorded), 1, recorded)
        self.assertEqual(recorded[0]["status"], "ok")

    def test_tick_launches_every_job_over_an_id_format_bomb(self):
        """Pre-fix the thread-name f-string ran the raw id's __str__ and
        aborted the tick — the healthy sibling lost its minute."""
        rows = [_sane(id=_IntStrBomb(5)), _sane(jid="ok")]
        ran: list[str] = []
        with mock.patch.object(scheduler_svc, "cfg",
                               lambda: {"schedules": rows}), \
                mock.patch.object(scheduler_svc, "_execute",
                                  lambda job, trigger: ran.append(
                                      scheduler_svc._job_id(job))), \
                mock.patch.object(scheduler_svc, "_last_minute", None):
            launched = scheduler_svc._tick_once()
        self.assertEqual(launched, ["5", "ok"])


class StaysImmunePins(unittest.TestCase):
    """Neighbours probed in this sweep and found already dead."""

    def test_surrogate_escape_create_bodies_answer_coded_4xx(self):
        """A lone-surrogate JSON escape decodes server-side into the real
        character; every field answers its coded refusal, never a 500."""
        cases = (
            (b'{"name":"\\ud800","type":"command","cron":"* * * * *",'
             b'"params":{"command":"echo hi"}}', 422, None),
            (b'{"id":"\\ud800x","name":"n","type":"command",'
             b'"cron":"* * * * *","params":{"command":"echo hi"}}',
             400, "scheduler.bad_id"),
            (b'{"name":"n","type":"command","cron":"* * * * *",'
             b'"params":{"command":"\\ud800"}}', 400, "scheduler.bad_params"),
            (b'{"name":"n","type":"command","cron":"\\ud800",'
             b'"params":{"command":"echo hi"}}', 400, "scheduler.bad_cron"),
        )
        for raw, status, code in cases:
            resp = _client().post(
                "/api/scheduler/jobs", content=raw,
                headers={"content-type": "application/json"})
            self.assertEqual(resp.status_code, status, (raw, resp.text[:300]))
            _encodable(resp.json())
            if code:
                self.assertEqual(resp.json()["detail"]["code"], code)

    def test_huge_int_body_is_the_generic_body_parse_400(self):
        """json.loads on a >4300-digit number raises ValueError (the digit
        cap), not JSONDecodeError; FastAPI's body-parse 400 absorbs it."""
        raw = (b'{"name":"n","type":"command","cron":"* * * * *",'
               b'"timeout":' + b"9" * 5000 +
               b',"params":{"command":"echo hi"}}')
        resp = _client().post(
            "/api/scheduler/jobs", content=raw,
            headers={"content-type": "application/json"})
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        _encodable(resp.json())

    def test_huge_and_nan_journal_numerics_stay_scrubbed(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp) / "schedule-runs.jsonl"
            runs.write_text(
                '{"job": "v", "status": "ok", "ts": 1, "duration": 1e999}\n'
                '{"job": "v", "status": "ok", "ts": 2, "duration": NaN}\n',
                encoding="utf-8",
            )
            with mock.patch.object(scheduler_svc, "RUNS_PATH", runs):
                resp = _client().get("/api/scheduler/runs")
            self.assertEqual(resp.status_code, 200, resp.text[:300])
            body = resp.json()
            _encodable(body)
            self.assertEqual(len(body["runs"]), 2)
            self.assertTrue(all(r["duration"] is None for r in body["runs"]))

    def test_dict_get_bomb_timer_rows_stay_200_on_the_alias_routes(self):
        timers = [_DictGetBomb(label="x", interval=1)]
        with mock.patch.object(tools_svc, "launchd_timers", lambda: timers):
            for path in ("/api/scheduler", "/api/settings/scheduler"):
                resp = _client().get(path)
                self.assertEqual(resp.status_code, 200,
                                 (path, resp.text[:300]))
                _encodable(resp.json())


if __name__ == "__main__":
    unittest.main()
