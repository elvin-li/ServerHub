"""Thirteenth leftover-500s sweep of the Maintenance listing, over the real mounted app.

maint12 consolidated the GET /api/maintenance emitted-view shaping into
:func:`hub.jobs.maintenance_view` and routed every field read through the
module's union guards.  A fresh hunt over the same mounted tree (create_app +
TestClient, raise_server_exceptions=False) drove the one shape those guards
never covered: every catch along the listing pipe stopped at ``except
Exception``, so a leftover whose hook raises a *BaseException* subclass (the
nas13/modules12/logs12/json13 watchdog shape) sailed past all of them at once —

* a ``__class__`` property bomb blew :func:`hub.jobs._isinst`, the gate every
  other arm stands on, straight out of ``_plain_dict``'s row check;
* a hash-shadowing key whose ``__eq__`` raises a BaseException subclass blew
  ``_mapping_get`` (field probes) and ``_jobs_row`` (the ``_jobs`` lookup and
  its rescue scan);
* a ``__bool__`` bomb ``running`` value in a live ``_jobs`` row blew
  ``_truthy`` under ``job_state``'s merge into the view row;
* ``__str__`` / ``__iter__`` bombs blew ``_utf8_text`` / ``_jsonable`` / the
  ``maintenance:`` list materialiser;
* a cfg() snapshot provider raising outright blew ``maintenance_tasks``, and a
  raising ``maintenance_tasks`` blew ``maintenance_view``'s own outer catch —

each one a raw 500 on GET /api/maintenance from the surface the SPA reads.

Every guard on the pipe now re-raises genuine control flow
(KeyboardInterrupt, SystemExit — swallowing a Ctrl-C or an interpreter
shutdown to save one listing field would turn the sanitizer into a hang) and
launders everything else BaseException-shaped exactly like its Exception
twin: a poisoned row costs only itself, an unreadable field only its default,
a poisoned root or provider only the empty listing.
:class:`BaseExceptionBombListingTests` fails on the pre-fix tree;
:class:`ControlFlowStillPropagates` pins the passthrough so the laundering
can never widen into a hang; :class:`HealthyShapeUnchanged` pins the SPA
contract so the edit cannot weaken the maint12 union.
"""
from __future__ import annotations

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


class _Boom(BaseException):
    """A BaseException *subclass* that is not control flow: past every
    ``except Exception`` net, but no guard may re-raise it as if it were a
    Ctrl-C.  The nas13/modules12 watchdog shape."""


class _ClassBomb:
    """``__class__`` is a raising property: CPython's isinstance reaches for
    it when the real-type fast check misses, so the bomb detonates the
    ``_isinst`` gate itself — with a BaseException it used to ride past the
    gate's own net and out of the route."""

    @property
    def __class__(self):  # noqa: D105
        raise _Boom("leftover base-exception class bomb")


class _EqBombStr(str):
    """The hash-shadowing key, BaseException edition: same text hence the
    same hash as the real field, ``__eq__`` raises past ``except Exception``
    when a lookup probe compares against it."""

    def __eq__(self, other):  # noqa: D105
        raise _Boom("leftover base-exception eq bomb")

    def __hash__(self):  # noqa: D105
        return str.__hash__(self)


class _BoolBomb:
    """A truth test that detonates with a BaseException subclass."""

    def __bool__(self):
        raise _Boom("leftover base-exception bool bomb")


class _StrBomb:
    """``str()`` of the leftover detonates with a BaseException subclass —
    ``_jsonable``'s fallback arm and ``_utf8_text`` both dispatch it."""

    def __str__(self):
        raise _Boom("leftover base-exception str bomb")


class _IterBombList(list):
    """A real list subclass whose ``__iter__`` raises a BaseException
    subclass: passes the ``_isinst(raw, list)`` gate, then blows the
    ``list()`` materialiser past its old net."""

    def __iter__(self):  # noqa: D105
        raise _Boom("leftover base-exception iter bomb")


class _DiskYamlSandbox(unittest.TestCase):
    """One plain task on the REAL config path — the request walks
    disk -> load_yaml_int_capped -> _as_config -> route, like maint4-maint12."""

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


class BaseExceptionBombListingTests(_DiskYamlSandbox):
    """The fixed leak: each BaseException-shaped bomb fed at the seam it
    detonates.  Pre-fix every one of these was a raw 500 on
    GET /api/maintenance; each now degrades exactly like its Exception twin."""

    def test_class_bomb_row_costs_only_its_row(self):
        # The _isinst gate itself: the raising ``__class__`` property fires
        # inside _plain_dict's isinstance check, before any copy runs.
        rows = [_ClassBomb(), {"id": "plain", "name": "Plain", "command": "true"}]
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": rows}):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        self.assertEqual([r["id"] for r in response.json()], ["plain"])

    def test_iter_bomb_task_list_survives_without_a_500(self):
        # maint13 pinned the guarded drop ([]); maint14's unbound
        # ``list.__iter__`` snapshot now reads the perfectly walkable real
        # storage underneath the bomb (the bookmarks14 recovered-shape
        # rule), so the honest row lists — and the raise still never
        # escapes the route.
        raw = _IterBombList([{"id": "plain", "command": "true"}])
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": raw}):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        self.assertEqual([r["id"] for r in response.json()], ["plain"])

    def test_shadow_key_eq_bomb_costs_only_its_row(self):
        rows = [
            {_EqBombStr("id"): "junk", "command": "true"},
            {"id": "plain", "name": "Plain", "command": "true"},
        ]
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": rows}):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        self.assertEqual([r["id"] for r in response.json()], ["plain"])

    def test_str_bomb_name_falls_back_to_the_id(self):
        rows = [{"id": "plain", "name": _StrBomb(), "command": "true"}]
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": rows}):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        row = response.json()[0]
        # _jsonable's fallback arm launders the unreadable name to "", and
        # the view's name-or-id fall-back keeps the task listed under its id.
        self.assertEqual(row["id"], "plain")
        self.assertEqual(row["name"], "plain")

    def test_cfg_raising_base_exception_degrades_to_empty_listing(self):
        with mock.patch.object(jobs, "cfg", side_effect=_Boom("cfg bomb")):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json(), [])

    def test_maintenance_tasks_raising_base_exception_degrades_to_empty(self):
        # The view's own outer catch stopped at Exception too.
        with mock.patch.object(jobs, "maintenance_tasks",
                               side_effect=_Boom("tasks bomb")):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json(), [])

    def test_jobs_table_eq_bomb_key_degrades_to_not_run_shape(self):
        # dict.get(_jobs, tid) compares the probe against the stored bomb
        # key (same text, same hash) — the raise now falls to the rescue
        # scan, whose str.__eq__ reads the C-level storage.
        jobs._jobs[_EqBombStr("plain")] = {"running": False, "rc": 7}
        response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        row = next(r for r in response.json() if r["id"] == "plain")
        # The rescue scan still finds the row through the unbound compare.
        self.assertEqual(row["rc"], 7)
        self.assertIs(row["running"], False)

    def test_bool_bomb_running_value_in_live_row_reads_false(self):
        # The one seam real config laundering never touches: _jobs rows are
        # raw in-memory state, so the __bool__ bomb reaches _truthy through
        # job_state's merge into the view row.
        jobs._jobs["plain"] = {"running": _BoolBomb(), "rc": 0, "finished": None}
        response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        row = next(r for r in response.json() if r["id"] == "plain")
        # Fails closed: a bomb row is junk, not a live job.
        self.assertIs(row["running"], False)
        self.assertEqual(row["rc"], 0)

    def test_confirm_bool_bomb_at_the_view_seam_reads_false(self):
        # Fed at the maintenance_tasks output rank (the maint12 seam): the
        # BaseException edition of the __bool__ bomb maint12 sealed for
        # Exception.
        rows = {"plain": {"id": "plain", "name": "Plain", "confirm": _BoolBomb()}}
        with mock.patch.object(jobs, "maintenance_tasks", return_value=rows):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        row = response.json()[0]
        self.assertIs(row["confirm"], False)
        self.assertEqual(row["id"], "plain")


class ControlFlowStillPropagates(unittest.TestCase):
    """The laundering must never widen into a hang: genuine control flow
    (KeyboardInterrupt, SystemExit) raised out of a hook keeps propagating
    through every upgraded guard.  Pinned at the helper rank — through the
    client it would only tear down the test server thread."""

    def test_truthy_reraises_keyboard_interrupt(self):
        class _KI:
            def __bool__(self):
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            jobs._truthy(_KI())

    def test_isinst_reraises_system_exit(self):
        class _SE:
            @property
            def __class__(self):
                raise SystemExit(3)

        with self.assertRaises(SystemExit):
            jobs._isinst(_SE(), dict)

    def test_mapping_get_reraises_keyboard_interrupt_from_a_stored_key(self):
        class _KIKey(str):
            def __eq__(self, other):
                raise KeyboardInterrupt

            def __hash__(self):
                return str.__hash__(self)

        with self.assertRaises(KeyboardInterrupt):
            jobs._mapping_get({_KIKey("id"): "x"}, "id")

    def test_maintenance_view_reraises_system_exit_from_the_provider(self):
        with mock.patch.object(jobs, "maintenance_tasks",
                               side_effect=SystemExit(4)):
            with self.assertRaises(SystemExit):
                jobs.maintenance_view()


class HealthyShapeUnchanged(_DiskYamlSandbox):
    """The SPA contract re-pinned so the maint13 upgrade trips loudly if it
    weakens the maint12 shaping union."""

    def test_healthy_rows_keep_the_exact_contract(self):
        config.YAML_PATH.write_text(
            "maintenance:\n"
            "  - id: backup\n    name: Backup\n    desc: dump\n"
            "    confirm: true\n    command: 'true'\n"
            "  - id: bare\n    command: 'true'\n",
            encoding="utf-8")
        config.reload_cfg()
        response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        by_id = {r["id"]: r for r in response.json()}
        self.assertEqual(by_id["backup"], {
            "id": "backup", "name": "Backup", "desc": "dump", "confirm": True,
            "running": False, "rc": None, "finished": None})
        self.assertEqual(by_id["bare"]["name"], "bare")
        self.assertEqual(by_id["bare"]["desc"], "")
        self.assertIs(by_id["bare"]["confirm"], False)

    def test_exception_shaped_bombs_still_degrade_the_same(self):
        # The Exception twins of the upgraded guards must keep degrading —
        # the BaseException widening cannot have narrowed the original net.
        class _ExcBoolBomb:
            def __bool__(self):
                raise RuntimeError("leftover exception bool bomb")

        rows = {"plain": {"id": "plain", "name": "Plain",
                          "confirm": _ExcBoolBomb()}}
        with mock.patch.object(jobs, "maintenance_tasks", return_value=rows):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        self.assertIs(response.json()[0]["confirm"], False)


if __name__ == "__main__":
    unittest.main()
