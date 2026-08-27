"""Eleventh leftover-500s sweep of the Maintenance page, over the real mounted app.

The maint9 sweep sealed the lying-``__class__`` impostor ranks (cfg root and
``_jobs`` key); the maint10-era union added ``type(x) is bool`` gates, the
guarded unbound coercions in ``_jsonable``, and the ``_jobs_row`` rescue
scan.  A fresh hunt over the same mounted tree (create_app + TestClient,
raise_server_exceptions=False) drove the vms/ups **hash-shadowing mapping
key** class instead — a leftover str-*subclass* key stored inside an
otherwise-plain row dict, same text (hence same hash) as a real field name,
whose ``__eq__`` raises (or returns a ``__bool__``-bomb).  ``_plain_dict``
launders methods, not *keys*: even a plain ``dict.get`` probe compares the
probe against every stored key whose hash collides, dispatching into the
stored key's own ``__eq__``.  Four seams let that raise out over —

    GET  /api/maintenance
    POST /api/maintenance/{tid:path}/run
    GET  /api/maintenance/{tid:path}/log

* **cfg-row field rank** (``maintenance_tasks``).  ``row.get("id")`` ran on
  the plain-dict copy bare, so a bomb key shadowing ``id`` 500'd GET
  /api/maintenance AND POST /api/maintenance/{tid}/run (which walks the same
  listing) — and the follow-up ``row["id"] = tid`` insert probed the same
  poisoned slot.  The read now goes through :func:`hub.jobs._mapping_get`
  (unbound ``dict.get`` in a try; a raise means the field is junk-shadowed)
  and the id is written onto the *cleaned* copy, whose keys are all
  laundered exact strs (:class:`CfgRowBombKeyHttpTests` fails pre-fix).

* **job-state field rank** (``job_state``).  ``j.get("running")`` /
  ``j.get("rc")`` / ``j.get("finished")`` on a leftover ``_jobs`` row 500'd
  GET /api/maintenance for every task
  (:class:`JobsRowBombKeyHttpTests` fails pre-fix).

* **job-log field rank** (``job_log``).  All five field probes — ``log``,
  ``running``, ``rc``, ``started``, ``finished`` — took the log route down
  the same way (:class:`JobsRowBombKeyHttpTests` again).

* **mutex-scan rank** (``_row_running`` / ``start_job``).  The single-runner
  scan probed ``row.get("running")`` over every leftover row, so one bomb
  key 500'd POST /api/maintenance/{tid}/run for every task; ``start_job``'s
  own ``task.get("id")`` had the same seam for the dicts tools_svc hands it
  (:class:`RunRouteBombKeyHttpTests` fails pre-fix).

Stays-immune pins ride along for the wave-10/11 shapes the same hunt
confirmed already coded: a bomb key at the cfg *root* rank (the maint7/8/9
union's guarded unbound ``dict.get`` already refuses it), an ``__eq__`` that
returns a truth-bomb on a ``_jobs`` key (the rescue scan's unbound compare),
>4300-digit / ``__str__``-bomb / ``__eq__``-bomb rc subclasses
(``_jsonable``'s unbound coercions and digit-cap probe), isoformat property
bombs and non-AttributeError ``__getattr__`` bombs, self-``__str__`` encode
bombs and bytes ``decode`` bombs in log lines, and circular / 100-deep
nested structures (the depth cap).
"""
from __future__ import annotations

import time
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import config, jobs
from hub.app_factory import create_app
from hub.auth import require_auth

_app = None


def _the_app():
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return _app


def _client() -> TestClient:
    # raise_server_exceptions=False: a real 500 must arrive as HTTP 500, not
    # as a re-raised exception that would mask which route crashed.
    return TestClient(_the_app(), raise_server_exceptions=False)


def _clean(response) -> None:
    """The body decoded, carries no lone surrogate, and re-encodes as UTF-8."""
    text = response.text
    assert "\ud800" not in text, text[:300]
    text.encode("utf-8")


def _wait_finished(tid: str, timeout: float = 20.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = jobs._jobs_row(tid) or {}
        if isinstance(row, dict) and not row.get("running"):
            return row
        time.sleep(0.05)
    raise AssertionError(f"job {tid!r} did not finish")


class _EqBombStr(str):
    """The hash-shadowing key: a real str subclass, so it carries the same
    hash as its text and lands in the same dict slot as the real field name
    — and its ``__eq__`` raises when the lookup probe compares against it.
    (It can never coexist with a same-text sibling key: inserting either
    second dispatches this ``__eq__`` at plant time, so the shadowed field
    is genuinely lost, not merely duplicated.)"""

    def __eq__(self, other):  # noqa: D105
        raise RuntimeError("leftover shadow-key eq bomb")

    def __hash__(self):  # noqa: D105
        return str.__hash__(self)


class _TruthBomb:
    def __bool__(self):
        raise RuntimeError("leftover truth bomb")


class _EqTruthBombStr(str):
    """``__eq__`` *returns* a ``__bool__``-bomb instead of raising: the dict
    probe's C-level truth test detonates one step later, same crater."""

    def __eq__(self, other):  # noqa: D105
        return _TruthBomb()

    def __hash__(self):  # noqa: D105
        return str.__hash__(self)


class _DiskYamlSandbox(unittest.TestCase):
    """One plain task on the REAL config path — the request walks
    disk → load_yaml_int_capped → _as_config → route, like maint4-maint9."""

    YAML_TEXT = "maintenance:\n  - id: plain\n    name: Plain\n    command: 'true'\n    timeout: 10\n"

    def setUp(self):
        try:
            self._original = config.YAML_PATH.read_bytes()
        except FileNotFoundError:
            self._original = None
        config.YAML_PATH.parent.mkdir(parents=True, exist_ok=True)
        config.YAML_PATH.write_text(self.YAML_TEXT, encoding="utf-8")
        config.reload_cfg()
        self.addCleanup(self._restore)
        jobs._jobs.clear()
        self.addCleanup(jobs._jobs.clear)

    def _restore(self):
        try:
            config.YAML_PATH.unlink()
        except FileNotFoundError:
            pass
        if self._original is not None:
            config.YAML_PATH.write_bytes(self._original)
        config.reload_cfg()


class CfgRowBombKeyHttpTests(_DiskYamlSandbox):
    """The fixed leak, config side: a bomb key shadowing ``id`` inside an
    otherwise-plain row used to 500 the list route from ``row.get("id")``
    and the run route through the same listing walk."""

    def test_shadowed_id_costs_only_its_own_row(self):
        rows = [
            {_EqBombStr("id"): "junk", "command": "true"},
            {"id": "plain", "name": "Plain", "command": "true", "timeout": 10},
        ]
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": rows}):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        # The bomb row has no readable id, so only it drops.
        self.assertEqual([r["id"] for r in response.json()], ["plain"])

    def test_shadowed_id_cannot_take_down_the_run_route(self):
        rows = [
            {_EqBombStr("id"): "junk", "command": "true"},
            {"id": "plain", "name": "Plain", "command": "true", "timeout": 10},
        ]
        client = _client()
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": rows}):
            response = client.post("/api/maintenance/plain/run")
            self.assertEqual(response.status_code, 200, response.text[:300])
            self.assertEqual(response.json(),
                             {"ok": True, "message": "Task started"})
            self.assertEqual(_wait_finished("plain").get("rc"), 0)

    def test_truth_bomb_eq_key_takes_the_same_seam(self):
        # ``__eq__`` returning a ``__bool__``-bomb detonates inside the
        # probe's C-level truth test instead — same degrade, same survivors.
        rows = [
            {_EqTruthBombStr("id"): "junk", "command": "true"},
            {"id": "plain", "name": "Plain", "command": "true", "timeout": 10},
        ]
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": rows}):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        self.assertEqual([r["id"] for r in response.json()], ["plain"])

    def test_bomb_key_beside_a_real_id_costs_only_that_field(self):
        # A bomb key shadowing a *non-id* field: the row keeps its identity,
        # the shadowed name degrades through _jsonable's laundered-key walk
        # (the key text survives; only same-text sibling access dies), and
        # every route keeps serving.
        rows = [
            {"id": "plain", _EqBombStr("name"): "Shadowed", "command": "true"},
        ]
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": rows}):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        self.assertEqual([r["id"] for r in response.json()], ["plain"])


class JobsRowBombKeyHttpTests(_DiskYamlSandbox):
    """The fixed leak, ``_jobs`` side: a bomb key inside a leftover job row
    used to 500 the list route (``job_state``'s three probes) and the log
    route (``job_log``'s five probes)."""

    FIELDS = ("running", "rc", "log", "started", "finished")

    def test_each_shadowed_field_keeps_the_list_route_up(self):
        client = _client()
        for field in self.FIELDS:
            with self.subTest(field=field):
                jobs._jobs.clear()
                jobs._jobs["plain"] = {_EqBombStr(field): "junk"}
                response = client.get("/api/maintenance")
                self.assertEqual(response.status_code, 200, response.text[:300])
                _clean(response)
                row = next(r for r in response.json() if r["id"] == "plain")
                # The shadowed field degrades to its empty default.
                self.assertFalse(row["running"])
                self.assertIsNone(row["rc"])

    def test_each_shadowed_field_keeps_the_log_route_up(self):
        client = _client()
        for field in self.FIELDS:
            with self.subTest(field=field):
                jobs._jobs.clear()
                jobs._jobs["plain"] = {_EqBombStr(field): "junk"}
                response = client.get("/api/maintenance/plain/log")
                self.assertEqual(response.status_code, 200, response.text[:300])
                _clean(response)
                payload = response.json()
                self.assertFalse(payload["running"])
                self.assertIsNone(payload["rc"])
                self.assertEqual(payload["log"], "(waiting for output…)")

    def test_sane_sibling_fields_survive_the_shadowed_one(self):
        # Only the shadowed field is lost: rc and the log text keep serving
        # beside a bombed "finished" slot.
        jobs._jobs["plain"] = {_EqBombStr("finished"): "junk",
                               "running": False, "rc": 7, "log": ["kept line"]}
        client = _client()
        response = client.get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        row = next(r for r in response.json() if r["id"] == "plain")
        self.assertEqual(row["rc"], 7)
        response = client.get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        payload = response.json()
        self.assertEqual(payload["rc"], 7)
        self.assertEqual(payload["log"], "kept line")


class RunRouteBombKeyHttpTests(_DiskYamlSandbox):
    """The fixed leak, mutex side: the single-runner scan probes every
    leftover row, so one bomb key shadowing ``running`` used to 500
    POST /api/maintenance/{tid}/run for every task."""

    def test_bomb_row_cannot_take_down_or_wedge_the_run_route(self):
        jobs._jobs["stale"] = {_EqBombStr("running"): True}
        client = _client()
        response = client.post("/api/maintenance/plain/run")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json(), {"ok": True, "message": "Task started"})
        # The shadowed "running" fails closed to False: junk is not a live
        # job, so the mutex stays free and the task runs end-to-end.
        self.assertEqual(_wait_finished("plain").get("rc"), 0)

    def test_a_genuinely_running_job_still_holds_the_mutex(self):
        # The degrade must not eat the 409: a real live row keeps refusing a
        # second runner with the coded conflict, never a 500.
        jobs._jobs["other"] = {"running": True, "rc": None, "log": []}
        response = _client().post("/api/maintenance/plain/run")
        self.assertEqual(response.status_code, 409, response.text[:300])
        detail = response.json().get("detail") or {}
        self.assertEqual(detail.get("code"), "jobs.already_running")

    def test_start_job_survives_a_bomb_key_beside_id(self):
        # tools_svc hands start_job its own dicts: a shadowing bomb key on
        # "id" must return None (no job), not raise into the calling route.
        self.assertIsNone(jobs.start_job({_EqBombStr("id"): "junk",
                                          "command": "true"}))
        self.assertEqual(dict(jobs._jobs), {})


class StaysImmunePinTests(_DiskYamlSandbox):
    """Wave-10/11 shapes probed and found already coded — pinned so a
    refactor back toward bare probes (or away from the maint7/8/9 root
    union and the guarded unbound coercions) trips loudly."""

    def test_cfg_root_bomb_key_degrades_to_the_empty_listing(self):
        # The maint7/8/9 union already runs the unbound dict.get in a try:
        # a bomb key shadowing "maintenance" at the *root* rank costs the
        # listing, never the process.
        client = _client()
        with mock.patch.object(jobs, "cfg",
                               return_value={_EqBombStr("maintenance"): []}):
            response = client.get("/api/maintenance")
            self.assertEqual(response.status_code, 200, response.text[:300])
            self.assertEqual(response.json(), [])
            response = client.post("/api/maintenance/plain/run")
            self.assertEqual(response.status_code, 404, response.text[:300])
            detail = response.json().get("detail") or {}
            self.assertEqual(detail.get("code"), "maintenance.unknown_task")

    def test_truth_bomb_jobs_key_keeps_all_three_routes_up(self):
        # A _jobs key whose ``__eq__`` returns a truth-bomb blows the plain
        # lookup one step later than a raise; the rescue scan's unbound
        # str.__eq__ still reads under it.
        jobs._jobs[_EqTruthBombStr("plain")] = {"running": False, "rc": 3,
                                                "log": ["rescued"]}
        client = _client()
        response = client.get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        row = next(r for r in response.json() if r["id"] == "plain")
        self.assertEqual(row["rc"], 3)
        response = client.get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["log"], "rescued")
        response = client.post("/api/maintenance/plain/run")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(_wait_finished("plain").get("rc"), 0)

    def test_junk_rc_subclasses_degrade_field_level(self):
        class _StrBombInt(int):
            def __str__(self):  # noqa: D105
                raise RuntimeError("leftover str bomb")

            def __repr__(self):  # noqa: D105
                raise RuntimeError("leftover repr bomb")

        class _EqBombInt(int):
            def __eq__(self, other):  # noqa: D105
                raise RuntimeError("leftover eq bomb")

            def __hash__(self):  # noqa: D105
                return int.__hash__(self)

        class _EqBombFloat(float):
            def __eq__(self, other):  # noqa: D105
                raise RuntimeError("leftover eq bomb")

            def __hash__(self):  # noqa: D105
                return float.__hash__(self)

        client = _client()
        for rc, expect in ((10 ** 5000, None), (_StrBombInt(3), 3),
                           (_EqBombInt(4), 4), (_EqBombFloat(1.5), 1.5)):
            with self.subTest(rc=type(rc).__name__):
                jobs._jobs.clear()
                jobs._jobs["plain"] = {"running": False, "rc": rc, "log": []}
                response = client.get("/api/maintenance")
                self.assertEqual(response.status_code, 200, response.text[:300])
                _clean(response)
                row = next(r for r in response.json() if r["id"] == "plain")
                # >4300 digits cannot render at all (the json.dumps digit
                # cap) and drops; a subclass bomb launders to its base value
                # through the unbound coercions.
                self.assertEqual(row["rc"], expect)

    def test_isoformat_and_getattr_bombs_cost_only_their_fields(self):
        class _IsoPropertyBomb:
            @property
            def isoformat(self):
                raise RuntimeError("leftover iso bomb")

        class _IsoInf:
            def isoformat(self):
                return float("inf")

        class _GetattrBomb:
            def __getattr__(self, name):
                # Not AttributeError: escapes getattr's default arm.
                raise RuntimeError("leftover getattr bomb")

        jobs._jobs["plain"] = {"running": False, "rc": 0, "log": [],
                               "started": _IsoPropertyBomb(),
                               "finished": _IsoInf()}
        client = _client()
        response = client.get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        self.assertEqual(response.json()["rc"], 0)
        rows = [{"id": "plain", "name": _GetattrBomb(), "command": "true"}]
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": rows}):
            response = client.get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        self.assertEqual([r["id"] for r in response.json()], ["plain"])

    def test_self_str_encode_bomb_and_decode_bomb_log_lines(self):
        class _SelfStrEncodeBomb(str):
            def __str__(self):  # noqa: D105
                return self

            def encode(self, *a, **k):  # noqa: D102
                raise RuntimeError("leftover encode bomb")

        class _DecodeBombBytes(bytes):
            def decode(self, *a, **k):  # noqa: D102
                raise RuntimeError("leftover decode bomb")

        jobs._jobs["plain"] = {"running": False, "rc": 0,
                               "log": [_SelfStrEncodeBomb("x\ud800y"),
                                       _DecodeBombBytes(b"ok\xff")]}
        response = _client().get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        # The surrogate scrubs through the unbound str.encode (whose
        # "replace" form is "?"); the bytes line decodes through the
        # unbound bytes.decode with the U+FFFD replacement.
        payload = response.json()
        self.assertIn("x?y", payload["log"])
        self.assertIn("ok\ufffd", payload["log"])

    def test_circular_and_deep_leftovers_hit_the_depth_cap(self):
        circular = ["line"]
        circular.append(circular)
        jobs._jobs["plain"] = {"running": False, "rc": 0, "log": circular,
                               "finished": None}
        client = _client()
        response = client.get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["log"], "line")
        deep = {"id": "plain", "command": "true"}
        cursor = deep
        for _ in range(100):
            cursor["nest"] = {"v": 1}
            cursor = cursor["nest"]
        with mock.patch.object(jobs, "cfg",
                               return_value={"maintenance": [deep]}):
            response = client.get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        self.assertEqual([r["id"] for r in response.json()], ["plain"])

    def test_maint9_liar_union_still_holds(self):
        # The maint9 impostor fixes must survive this sweep's edit: a liar
        # cfg root claiming dict degrades to the empty listing; healthy
        # config serves again immediately after.
        class _Lie:
            @property
            def __class__(self):  # noqa: D105
                return dict

        client = _client()
        with mock.patch.object(jobs, "cfg", return_value=_Lie()):
            response = client.get("/api/maintenance")
            self.assertEqual(response.status_code, 200, response.text[:300])
            self.assertEqual(response.json(), [])
        response = client.get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual([r["id"] for r in response.json()], ["plain"])


if __name__ == "__main__":
    unittest.main()
