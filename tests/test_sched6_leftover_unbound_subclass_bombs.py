"""Sixth scheduler/jobs leftover sweep — nested unbound subclass-bomb 500s.

The jobs5 sweep routed ``scheduler_svc._jsonable``'s mapping/sequence walks
through plain-dict copies, but the Scheduler and Maintenance halves of the
Jobs domain never adopted the rest of the modules5 unbound convention
(``int.__index__``, ``float.__float__``, unbound ``bytes``/``bytearray``
``.decode``, unbound ``str.split``/``str.strip``).  Driven through
``create_app()`` + ``TestClient(raise_server_exceptions=False)``, these junk
shapes were live raw HTTP 500s on the pre-fix tree:

* GET /api/scheduler/jobs — an int-subclass ``__str__`` bomb as a job id
  (``_job_id``'s digit-cap probe only caught ValueError) or nested in
  ``params``/``timeout`` (``_jsonable``'s probe, same hole); a
  float-subclass ``__eq__``/``__ne__`` bomb as an id, ``enabled``, or a
  params value (the NaN/inf probes fired the override); a str-subclass
  ``strip()`` bomb as ``enabled`` (``raw.strip().lower()``); a str-subclass
  ``split()`` bomb as ``cron`` (escaped ``next_run_ts``'s
  ``(ValueError, RecursionError)`` net); and a bytes/bytearray-subclass
  ``decode`` bomb as a name, type, or params value (bound
  ``value.decode(...)`` in ``_utf8_text``/``_jsonable``).
* DELETE / run-now on a *healthy* job over a poisoned sibling — the same
  int/float-subclass id bombs raised out of ``_matches_id``'s ``_job_id``
  coercion during ``get_job``'s scan.
* GET /api/maintenance — the same int-subclass ``__str__`` bomb as a task id
  (``_task_id``) or nested anywhere in a row, the float ``__eq__`` bomb, the
  bytes-subclass ``decode`` bomb as a value AND as a mapping key
  (``hub.jobs._jsonable`` routes bytes keys through ``_utf8_text``'s bound
  decode), each 500'd the whole task list.
* GET /api/maintenance/{tid}/log and the merged state on the list route —
  the same bombs in a leftover in-memory ``_jobs`` row (``rc``,
  ``started``, a log line).

Fixes, all in hub/scheduler_svc.py and hub/jobs.py, all the established
modules5 conventions: ``_decode_bytes`` (unbound base decode), base
coercion via ``int.__index__`` / ``float.__float__`` ahead of every probe
(``_jsonable``, ``_job_id``, ``job_enabled``, ``_task_id``), unbound
``str.split`` in ``_cron_field_tokens`` and ``str.strip`` in
``job_enabled``.  The unbound view reads the real content underneath the
override, so the poison scrubs field-level: the bombed id still lists (and
mutates) as its number, the bombed cron still schedules, the bombed bytes
still decode.

Stays-immune pins ride along for the neighbours that were probed and found
dead: nested triples-``items()`` / iterbomb / isoformat-property /
``__getattr__`` bombs (the dict-copy and list() guards), an over-cap plain
int id (digit-cap drop, row survives), huge-int journal lines
(``json.loads``'s ValueError-not-JSONDecodeError), and torn-IPv6 rsync
preview remotes (the coded 400 grammar refusal).
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

from hub import audit, config, jobs, scheduler_svc  # noqa: E402
from hub.app_factory import create_app  # noqa: E402
from hub.auth import require_auth  # noqa: E402

#: Built arithmetically: ``int("9" * 5000)`` itself trips the digit cap.
_HUGE_INT = 10 ** 5000

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

class _IntStrBomb(int):
    def __str__(self):
        raise RuntimeError("int str bomb")

    __repr__ = __str__


class _IntEqBomb(int):
    def __eq__(self, other):
        raise RuntimeError("int eq bomb")

    __ne__ = __eq__
    __hash__ = int.__hash__


class _FloatEqBomb(float):
    def __eq__(self, other):
        raise RuntimeError("float eq bomb")

    __ne__ = __eq__
    __hash__ = float.__hash__


class _BytesDecodeBomb(bytes):
    def decode(self, *a, **k):
        raise RuntimeError("bytes decode bomb")


class _BytearrayDecodeBomb(bytearray):
    def decode(self, *a, **k):
        raise RuntimeError("bytearray decode bomb")


class _StrSplitBomb(str):
    def split(self, *a, **k):
        raise RuntimeError("str split bomb")


class _StrStripBomb(str):
    def strip(self, *a, **k):
        raise RuntimeError("str strip bomb")


class _TriplesItems(dict):
    def items(self):
        return [("a", 1, 2)]


class _IterBombList(list):
    def __iter__(self):
        raise RuntimeError("list iter bomb")


class _IsoPropertyBomb:
    @property
    def isoformat(self):
        raise RuntimeError("isoformat bomb")


class _GetattrBomb:
    def __getattr__(self, name):
        raise RuntimeError(f"getattr bomb: {name}")


def _sane(jid="victim", **over) -> dict:
    row = {"id": jid, "name": "n", "type": "command",
           "cron": "* * * * *", "enabled": True,
           "params": {"command": "echo hi"}}
    row.update(over)
    return row


class _SchedulerCfg(unittest.TestCase):
    """Drive GET /api/scheduler/jobs over one leftover-poisoned cfg overlay."""

    def _list(self, rows) -> dict:
        cfg_value = {"schedules": rows}
        with mock.patch.object(scheduler_svc, "cfg", lambda: cfg_value):
            resp = _client().get("/api/scheduler/jobs")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _encodable(body)
        return body

    def _one(self, **over) -> dict:
        body = self._list([_sane(**over)])
        self.assertEqual(len(body["jobs"]), 1, body)
        return body["jobs"][0]


class SchedulerListIdentityBombs(_SchedulerCfg):
    """id / enabled / cron bombs — the unbound view keeps the real content."""

    def test_int_subclass_str_bomb_id_lists_as_its_number(self):
        row = self._one(id=_IntStrBomb(5))
        self.assertEqual(row["id"], "5")

    def test_float_subclass_eq_bomb_id_lists_as_its_number(self):
        row = self._one(id=_FloatEqBomb(5.0))
        self.assertEqual(row["id"], "5")

    def test_overcap_int_wearing_the_bomb_subclass_still_drops_the_id(self):
        """Coercion cannot resurrect the unrenderable: past CPython's digit
        cap the id drops exactly like its plain-int sibling — row survives."""
        body = self._list([
            _sane(id=_IntStrBomb(_HUGE_INT)), _sane(jid="ok")])
        self.assertEqual(len(body["jobs"]), 2)
        self.assertIsNone(body["jobs"][0]["id"])
        self.assertEqual(body["jobs"][1]["id"], "ok")

    def test_float_eq_bomb_enabled_still_reads_on(self):
        row = self._one(enabled=_FloatEqBomb(1.0))
        self.assertIsNotNone(row["next_run"])

    def test_int_eq_bomb_enabled_still_reads_on(self):
        row = self._one(enabled=_IntEqBomb(1))
        self.assertIsNotNone(row["next_run"])

    def test_str_strip_bomb_enabled_still_reads_on(self):
        row = self._one(enabled=_StrStripBomb("true"))
        self.assertIsNotNone(row["next_run"])

    def test_str_split_bomb_cron_still_schedules(self):
        """Unbound str.split reads the real expression under the override."""
        row = self._one(cron=_StrSplitBomb("* * * * *"))
        self.assertIsInstance(row["next_run"], int)


class SchedulerListValueBombs(_SchedulerCfg):
    """Nested params / name / type / timeout bombs — scrubbed field-level."""

    def test_nested_int_str_bomb_param_keeps_its_number(self):
        row = self._one(params={"command": "echo", "x": _IntStrBomb(3)})
        self.assertEqual(row["params"]["x"], 3)

    def test_nested_overcap_int_wearing_the_bomb_drops_to_none(self):
        row = self._one(params={"command": "echo", "x": _IntStrBomb(_HUGE_INT)})
        self.assertIsNone(row["params"]["x"])

    def test_nested_float_eq_bomb_param_keeps_its_value(self):
        row = self._one(params={"command": "echo", "x": _FloatEqBomb(1.5)})
        self.assertEqual(row["params"]["x"], 1.5)

    def test_inf_wearing_the_eq_bomb_subclass_still_drops(self):
        row = self._one(
            params={"command": "echo", "x": _FloatEqBomb(float("inf"))})
        self.assertIsNone(row["params"]["x"])

    def test_bytes_decode_bomb_values_still_decode(self):
        row = self._one(name=_BytesDecodeBomb(b"hi"),
                        type=_BytesDecodeBomb(b"command"),
                        params={"command": "echo",
                                "x": _BytearrayDecodeBomb(b"pay\xffload")})
        self.assertEqual(row["name"], "hi")
        self.assertEqual(row["type"], "command")
        self.assertEqual(row["params"]["x"], "pay\ufffdload")

    def test_timeout_bombs_render_their_numbers(self):
        row = self._one(timeout=_IntStrBomb(5))
        self.assertEqual(row["timeout"], 5)
        row = self._one(timeout=_FloatEqBomb(5.0))
        self.assertEqual(row["timeout"], 5.0)


class _MutationSandbox(unittest.TestCase):
    """Victim job on disk; the read path (cfg) carries the bomb siblings."""

    def setUp(self):
        root = Path(os.environ.get("TMPDIR", "/tmp")) / (
            f"serverhub-sched6-mut-{os.getpid()}-{id(self)}"
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

    def _with_bomb_siblings(self, bomb_id):
        rows = [_sane(id=bomb_id, jid=None), _sane()]
        cfg_value = {"schedules": rows}
        return mock.patch.object(scheduler_svc, "cfg", lambda: cfg_value)


class MutationsOverBombSiblings(_MutationSandbox):
    """get_job's scan coerces every sibling id; the bombs no longer 500 the
    healthy job's mutations."""

    def test_delete_survives_int_str_bomb_sibling(self):
        with self._with_bomb_siblings(_IntStrBomb(5)):
            resp = _client().delete("/api/scheduler/jobs/victim")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(scheduler_svc.list_jobs(), [])

    def test_run_now_survives_float_eq_bomb_sibling(self):
        with self._with_bomb_siblings(_FloatEqBomb(5.0)):
            resp = _client().post("/api/scheduler/jobs/victim/run-now")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _encodable(resp.json())
        self.assertTrue(resp.json().get("started"))

    def test_put_and_enable_survive_int_str_bomb_sibling(self):
        with self._with_bomb_siblings(_IntStrBomb(5)):
            resp = _client().put("/api/scheduler/jobs/victim", json={
                "name": "renamed", "type": "command", "cron": "0 4 * * *",
                "enabled": True, "params": {"command": "echo hi"}})
            self.assertEqual(resp.status_code, 200, resp.text[:300])
            resp = _client().post(
                "/api/scheduler/jobs/victim/enable", json={"enabled": False})
            self.assertEqual(resp.status_code, 200, resp.text[:300])
        rows = scheduler_svc.list_jobs()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "renamed")
        self.assertFalse(rows[0]["enabled"])


class _MaintenanceCfg(unittest.TestCase):
    """Drive GET /api/maintenance over one leftover-poisoned cfg overlay."""

    def _list(self, tasks) -> list:
        cfg_value = {"maintenance": tasks}
        with mock.patch.object(jobs, "cfg", lambda: cfg_value):
            resp = _client().get("/api/maintenance")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _encodable(body)
        return body

    @staticmethod
    def _task(**over) -> dict:
        row = {"id": "t1", "name": "n", "desc": "d", "command": "echo hi"}
        row.update(over)
        return row


class MaintenanceSubclassBombs(_MaintenanceCfg):

    def test_int_str_bomb_id_lists_as_its_number(self):
        body = self._list([self._task(id=_IntStrBomb(7))])
        self.assertEqual([t["id"] for t in body], ["7"])

    def test_overcap_bomb_id_drops_only_its_row(self):
        body = self._list([
            self._task(id=_IntStrBomb(_HUGE_INT)), self._task(id="t2")])
        self.assertEqual([t["id"] for t in body], ["t2"])

    def test_float_eq_bomb_desc_keeps_its_value(self):
        body = self._list([self._task(desc=_FloatEqBomb(1.5))])
        self.assertEqual(body[0]["desc"], 1.5)

    def test_bytes_decode_bomb_name_still_decodes(self):
        body = self._list([self._task(name=_BytesDecodeBomb(b"panel"))])
        self.assertEqual(body[0]["name"], "panel")
        body = self._list([self._task(name=_BytearrayDecodeBomb(b"pa\xffnel"))])
        self.assertEqual(body[0]["name"], "pa\ufffdnel")

    def test_bytes_decode_bomb_mapping_key_still_decodes(self):
        poisoned = self._task()
        poisoned[_BytesDecodeBomb(b"extra")] = "kept"
        body = self._list([poisoned])
        self.assertEqual([t["id"] for t in body], ["t1"])
        cfg_value = {"maintenance": [poisoned]}
        with mock.patch.object(jobs, "cfg", lambda: cfg_value):
            tasks = jobs.maintenance_tasks()
        self.assertEqual(tasks["t1"]["extra"], "kept")

    def test_int_str_bomb_confirm_and_timeout_render(self):
        body = self._list([
            self._task(timeout=_IntStrBomb(5), confirm=_FloatEqBomb(1.0))])
        self.assertEqual(body[0]["id"], "t1")
        self.assertTrue(body[0]["confirm"])


class MaintenanceJobRowBombs(_MaintenanceCfg):
    """The same bombs in a leftover in-memory ``_jobs`` row."""

    def _with_job_row(self, row):
        return mock.patch.dict(jobs._jobs, {"t1": row}, clear=True)

    def test_rc_bombs_render_on_the_list_and_log_routes(self):
        cfg_value = {"maintenance": [self._task()]}
        with mock.patch.object(jobs, "cfg", lambda: cfg_value):
            with self._with_job_row({"running": False, "rc": _IntStrBomb(3),
                                     "log": ["x"], "started": None,
                                     "finished": None}):
                resp = _client().get("/api/maintenance")
                self.assertEqual(resp.status_code, 200, resp.text[:300])
                _encodable(resp.json())
                self.assertEqual(resp.json()[0]["rc"], 3)
                resp = _client().get("/api/maintenance/t1/log")
                self.assertEqual(resp.status_code, 200, resp.text[:300])
                self.assertEqual(resp.json()["rc"], 3)
            with self._with_job_row({"running": False, "rc": _FloatEqBomb(1.5),
                                     "log": [_BytesDecodeBomb(b"line")],
                                     "started": _BytesDecodeBomb(b"12:00"),
                                     "finished": None}):
                resp = _client().get("/api/maintenance/t1/log")
                self.assertEqual(resp.status_code, 200, resp.text[:300])
                body = resp.json()
                _encodable(body)
                self.assertEqual(body["rc"], 1.5)
                self.assertEqual(body["started"], "12:00")
                self.assertEqual(body["log"], "line")


class StaysImmunePins(_SchedulerCfg):
    """Neighbours probed in this sweep and found already dead."""

    def test_nested_mapping_and_sequence_bombs_stay_dead(self):
        body = self._list([
            _sane(params=_TriplesItems(command="echo")),
            _sane(jid="v2", params={"x": _IterBombList([1]),
                                    "command": "echo"}),
            _sane(jid="v3", params={"x": _IsoPropertyBomb(),
                                    "y": _GetattrBomb(),
                                    "command": "echo"}),
        ])
        self.assertEqual(len(body["jobs"]), 3)
        # The dict-copy guard reads the triples-items row's real storage.
        self.assertEqual(body["jobs"][0]["params"], {"command": "echo"})

    def test_overcap_plain_int_id_still_drops_only_the_id(self):
        body = self._list([_sane(id=_HUGE_INT), _sane(jid="ok")])
        self.assertEqual(len(body["jobs"]), 2)
        self.assertIsNone(body["jobs"][0]["id"])

    def test_huge_int_journal_lines_stay_skipped_not_500(self):
        """json.loads on a >4300-digit number raises ValueError (the digit
        cap), not JSONDecodeError — the journal readers' net already
        catches it."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp) / "schedule-runs.jsonl"
            runs.write_text(
                '{"job": "victim", "ts": ' + "9" * 5000 + "}\n"
                '{"job": "victim", "status": "ok", "ts": 1}\n',
                encoding="utf-8",
            )
            with mock.patch.object(scheduler_svc, "RUNS_PATH", runs):
                resp = _client().get("/api/scheduler/runs")
                self.assertEqual(resp.status_code, 200, resp.text[:300])
                body = resp.json()
                _encodable(body)
                self.assertEqual(len(body["runs"]), 1)
                self.assertEqual(body["runs"][0]["status"], "ok")

    def test_torn_ipv6_rsync_remotes_stay_the_coded_400(self):
        from hub import rsync_svc
        available = {
            "available": True, "path": "/bin/false", "variant": "rsync3",
            "version": "3.2.7",
            "supports": {"itemize": True, "progress2": True,
                         "compress": True, "bwlimit": True},
        }
        with mock.patch.object(rsync_svc, "binary_info",
                               return_value=available):
            for dest in ("[::1", "user@[::1:/x", "user@[::1]:/x"):
                resp = _client().post("/api/backups/rsync/preview", json={
                    "direction": "push", "src": "/tmp", "dest": dest})
                self.assertEqual(
                    resp.status_code, 400, (dest, resp.text[:300]))
                self.assertEqual(
                    resp.json()["detail"]["code"], "rsync.bad_dest")
                _encodable(resp.json())


if __name__ == "__main__":
    unittest.main()
