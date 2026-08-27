"""Eighth leftover-500s sweep of the Maintenance page, over the real mounted app.

The hunted classes were re-driven against the three routes the page mounts —

    GET  /api/maintenance
    POST /api/maintenance/{tid:path}/run
    GET  /api/maintenance/{tid:path}/log

— through ``create_app()`` with ``raise_server_exceptions=False``.  One live
leftover family was found and is fixed with this battery:

* **``__class__``-property bombs** (the modules8/bookmarks8 ``_isinst``
  rule).  CPython's ``isinstance`` reads the operand's ``__class__`` whenever
  the real-type fast check misses, so a leftover whose ``__class__`` is a
  raising property blew every bare ``isinstance`` gate in ``hub/jobs.py``
  from *outside* every try/except net the earlier sweeps built — at cfg-root
  rank (``isinstance(data, dict)`` in ``maintenance_tasks``), maintenance-
  value rank (``isinstance(raw, list)``), row rank (``_plain_dict``), id rank
  (``_task_id``), nested-value rank (``_jsonable``'s whole arm chain plus
  ``_utf8_text``), ``_jobs``-row rank (``job_state`` / ``get_job``) and
  log-line rank (``_log_lines``).  Thirteen probed shapes returned raw 500s
  on the pre-fix tree; every ``isinstance`` on leftover-reachable values now
  routes through a guarded ``_isinst`` that fails closed to False, so a bomb
  costs only its own entry while siblings keep serving
  (:class:`CfgClassBombHttpTests` / :class:`JobsRowClassBombHttpTests` fail
  on the pre-fix tree).

* **Truth-test bomb in ``_log_lines``'s str arm.**  A leftover str-subclass
  ``log`` value whose ``__bool__``/``__len__`` raises used to blow the bare
  ``if raw`` truth probe past the isinstance gate; the line is now laundered
  through ``_utf8_text`` to an exact str before the test
  (:class:`LogTruthBombHttpTests` fails on the pre-fix tree).

Plus stays-immune pins for the neighbours that were probed and found already
coded: a FIFO squatting services.yaml (the cfg root read rides
``read_text_capped``'s O_NONBLOCK + S_ISREG guard and degrades to the empty
config), the maint7 guarded-cfg()/unbound-dict.get root union, and
rc-subclass ``__eq__``/``__float__`` bombs already dropped by ``_jsonable``'s
unbound base coercion.
"""
from __future__ import annotations

import os
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


class _ClassBomb:
    """Real type is a plain object; reading ``__class__`` raises.

    The exact shape that blew every bare ``isinstance`` gate: the real-type
    fast check misses (object subclasses nothing interesting), so CPython
    falls back to reading ``__class__`` — and detonates.
    """

    @property
    def __class__(self):  # noqa: D105
        raise RuntimeError("leftover __class__ bomb")


class _StrClassBomb(str):
    """Passes ``isinstance(str)`` on the fast path; every *miss* detonates.

    ``isinstance(x, (bytes, bytearray))`` inside ``_utf8_text`` used to read
    ``__class__`` (real type is no bytes subclass) and 500 the scrub itself.
    """

    @property
    def __class__(self):  # noqa: D105
        raise RuntimeError("leftover str __class__ bomb")


class _BoolBombStr(str):
    """Passes the str gate; the bare ``if raw`` truth probe then raises."""

    def __bool__(self):  # noqa: D105
        raise RuntimeError("leftover __bool__ bomb")

    def __len__(self):  # noqa: D105
        raise RuntimeError("leftover __len__ bomb")


class _EqBombFloat(float):
    """rc-subclass whose comparisons raise; ``float.__float__`` reads under it."""

    def __eq__(self, other):  # noqa: D105
        raise RuntimeError("leftover float eq bomb")

    def __ne__(self, other):  # noqa: D105
        raise RuntimeError("leftover float ne bomb")

    def __hash__(self):  # noqa: D105
        return float.__hash__(self)


class _DiskYamlSandbox(unittest.TestCase):
    """One plain task on the REAL config path — the request walks
    disk → load_yaml_int_capped → _as_config → route, like maint4-maint7."""

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


class CfgClassBombHttpTests(_DiskYamlSandbox):
    """The fixed leak, config side: ``__class__`` bombs at every cfg rank
    used to 500 the list route (and the run route, which walks the same
    listing) on the pre-fix tree."""

    def test_class_bomb_cfg_root_degrades_to_empty_list_and_coded_404(self):
        client = _client()
        with mock.patch.object(jobs, "cfg", return_value=_ClassBomb()):
            response = client.get("/api/maintenance")
            self.assertEqual(response.status_code, 200, response.text[:300])
            _clean(response)
            self.assertEqual(response.json(), [])
            response = client.post("/api/maintenance/plain/run")
            self.assertEqual(response.status_code, 404, response.text[:300])
            detail = response.json().get("detail") or {}
            self.assertEqual(detail.get("code"), "maintenance.unknown_task")

    def test_class_bomb_maintenance_value_degrades_to_empty_list(self):
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": _ClassBomb()}):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json(), [])

    def test_class_bomb_row_costs_only_its_own_entry(self):
        rows = [
            {"id": "plain", "name": "Plain", "command": "true", "timeout": 10},
            _ClassBomb(),
        ]
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": rows}):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        ids = [r["id"] for r in response.json()]
        self.assertEqual(ids, ["plain"])

    def test_class_bomb_id_costs_only_its_own_entry(self):
        rows = [
            {"id": _ClassBomb(), "name": "Junk", "command": "true"},
            {"id": "plain", "name": "Plain", "command": "true"},
        ]
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": rows}):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        rows_out = {r["id"]: r for r in response.json()}
        self.assertEqual(sorted(rows_out), ["plain"])
        self.assertEqual(rows_out["plain"]["name"], "Plain")

    def test_class_bomb_nested_value_keeps_the_task_listed(self):
        rows = [{"id": "plain", "name": _ClassBomb(), "command": "true"}]
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": rows}):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        row = next(r for r in response.json() if r["id"] == "plain")
        # The bomb misses every typed arm and renders through the repr
        # fallthrough — an entry survives, never a 500.
        self.assertIsInstance(row["name"], str)

    def test_str_subclass_class_bomb_id_still_lists_and_runs(self):
        # Passes isinstance(str) on the fast path; the pre-fix _utf8_text
        # bytes probe then read __class__ and 500'd the scrub itself.
        rows = [{"id": _StrClassBomb("plain"), "name": "Plain", "command": "echo strsub-ok",
                 "timeout": 10}]
        client = _client()
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": rows}):
            response = client.get("/api/maintenance")
            self.assertEqual(response.status_code, 200, response.text[:300])
            listed = {r["id"] for r in response.json()}
            self.assertEqual(listed, {"plain"})
            response = client.post("/api/maintenance/plain/run")
            self.assertEqual(response.status_code, 200, response.text[:300])
            row = _wait_finished("plain")
        self.assertEqual(row.get("rc"), 0)
        self.assertIn("strsub-ok", row.get("log"))
        # The laundered mapping key is an exact str, pollable by plain text.
        self.assertIs(type(next(iter(jobs._jobs))), str)


class JobsRowClassBombHttpTests(_DiskYamlSandbox):
    """The fixed leak, ``_jobs`` side: a bomb row/value in the in-memory job
    table used to 500 all three routes on the pre-fix tree."""

    def test_class_bomb_job_row_keeps_all_three_routes_up(self):
        jobs._jobs["plain"] = _ClassBomb()
        client = _client()
        response = client.get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        row = next(r for r in response.json() if r["id"] == "plain")
        # A junk row is no job state at all: the coded empty shape serves.
        self.assertFalse(row["running"])
        self.assertIsNone(row["rc"])
        response = client.get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["log"], "(not run yet)")
        # The junk row is not "running", so the single-runner mutex is not
        # wedged: the task still runs end-to-end.
        response = client.post("/api/maintenance/plain/run")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json(), {"ok": True, "message": "Task started"})
        row = _wait_finished("plain")
        self.assertEqual(row.get("rc"), 0)

    def test_class_bomb_log_field_keeps_the_log_route_up(self):
        jobs._jobs["plain"] = {"running": False, "rc": 0, "log": _ClassBomb(),
                               "finished": "10:00:00"}
        response = _client().get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        payload = response.json()
        self.assertEqual(payload["rc"], 0)
        self.assertEqual(payload["log"], "(waiting for output…)")

    def test_class_bomb_rc_value_keeps_list_and_log_up(self):
        jobs._jobs["plain"] = {"running": False, "rc": _ClassBomb(), "log": ["kept line"],
                               "finished": "10:00:00"}
        client = _client()
        response = client.get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        response = client.get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        self.assertEqual(response.json()["log"], "kept line")


class LogTruthBombHttpTests(_DiskYamlSandbox):
    """The fixed leak, truth-test side: a str-subclass ``log`` whose
    ``__bool__``/``__len__`` raises used to blow ``_log_lines``'s bare
    ``if raw`` and 500 the log route on the pre-fix tree."""

    def test_bool_bomb_log_string_keeps_the_log_route_up(self):
        jobs._jobs["plain"] = {"running": False, "rc": 0,
                               "log": _BoolBombStr("bomb line kept"),
                               "finished": "10:00:00"}
        response = _client().get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        self.assertEqual(response.json()["log"], "bomb line kept")

    def test_bool_bomb_log_line_in_a_list_keeps_the_log_route_up(self):
        jobs._jobs["plain"] = {"running": False, "rc": 0,
                               "log": ["first", _BoolBombStr("second")],
                               "finished": "10:00:00"}
        response = _client().get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["log"], "first\nsecond")


class StaysImmunePinTests(_DiskYamlSandbox):
    """Neighbours probed and found already coded — pinned so they stay so."""

    def test_fifo_at_services_yaml_degrades_to_the_empty_config(self):
        # The cfg root read rides read_text_capped's O_NONBLOCK + S_ISREG
        # guard: a FIFO squatting services.yaml raises the OSError the
        # reader already degrades to {} — the list serves empty at once,
        # it neither hangs nor 500s.
        if not hasattr(os, "mkfifo"):
            self.skipTest("platform has no mkfifo")
        config.YAML_PATH.unlink()
        os.mkfifo(config.YAML_PATH)
        config.reload_cfg()
        client = _client()
        response = client.get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json(), [])
        response = client.post("/api/maintenance/plain/run")
        self.assertEqual(response.status_code, 404, response.text[:300])
        detail = response.json().get("detail") or {}
        self.assertEqual(detail.get("code"), "maintenance.unknown_task")

    def test_maint7_guarded_cfg_root_union_still_holds(self):
        # The maint7 union — try/except around cfg() plus the unbound
        # dict.get — must not have been dropped by this sweep's edits.
        client = _client()
        with mock.patch.object(jobs, "cfg", side_effect=RuntimeError("cfg down")):
            response = client.get("/api/maintenance")
            self.assertEqual(response.status_code, 200, response.text[:300])
            self.assertEqual(response.json(), [])

        class _GetBomb(dict):
            def get(self, *a, **k):  # noqa: D102
                raise RuntimeError("leftover root get bomb")

        poisoned = _GetBomb({"maintenance": [
            {"id": "plain", "name": "Plain", "command": "true", "timeout": 10},
        ]})
        with mock.patch.object(jobs, "cfg", return_value=poisoned):
            response = client.get("/api/maintenance")
            self.assertEqual(response.status_code, 200, response.text[:300])
            self.assertEqual([r["id"] for r in response.json()], ["plain"])

    def test_eq_bomb_float_rc_is_dropped_not_500(self):
        # _jsonable's unbound float.__float__ coercion reads under the
        # subclass override, so the poisoned rc degrades to its exact value.
        jobs._jobs["plain"] = {"running": False, "rc": _EqBombFloat(2.0),
                               "log": ["kept"], "finished": "10:00:00"}
        client = _client()
        response = client.get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        row = next(r for r in response.json() if r["id"] == "plain")
        self.assertEqual(row["rc"], 2.0)
        response = client.get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["rc"], 2.0)

    def test_bool_bomb_running_value_still_fails_closed(self):
        class _BoolBomb:
            def __bool__(self):  # noqa: D105
                raise RuntimeError("leftover bool bomb")

        jobs._jobs["plain"] = {"running": _BoolBomb(), "rc": None, "log": [],
                               "finished": None}
        client = _client()
        response = client.get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        row = next(r for r in response.json() if r["id"] == "plain")
        self.assertFalse(row["running"])
        # A bomb row is junk, not a live job: the mutex must not wedge.
        response = client.post("/api/maintenance/plain/run")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(_wait_finished("plain").get("rc"), 0)

    def test_len_bomb_log_list_costs_only_the_log_text(self):
        class _LenBombList(list):
            def __len__(self):  # noqa: D105
                raise RuntimeError("leftover len bomb")

        jobs._jobs["plain"] = {"running": False, "rc": 5,
                               "log": _LenBombList(["kept"]),
                               "finished": "10:00:00"}
        response = _client().get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        payload = response.json()
        self.assertEqual(payload["rc"], 5)
        # list() presizing consults __len__ and the try/except degrades to
        # the placeholder; the route itself stays up.
        self.assertIn(payload["log"], ("kept", "(waiting for output…)"))


if __name__ == "__main__":
    unittest.main()
