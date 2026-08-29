"""Twelfth leftover-500s sweep of the Maintenance page, over the real mounted app.

maint11 degraded the **hash-shadowing bomb keys** field-level *inside*
:func:`hub.jobs.maintenance_tasks` / ``job_state`` / ``job_log`` (the read now
goes through :func:`hub.jobs._mapping_get`); jobs11 then routed all
``_jobs``-table traffic through the unbound dict builtins so a poisoned table
could not 500 the three routes either.  A fresh hunt over the same mounted
tree (create_app + TestClient, raise_server_exceptions=False) drove the one
rank those sweeps left bare: the **emitted-view shaping**.

``maintenance_tasks`` laundered the rows it *returns*, but GET /api/maintenance
re-derived the row it actually *emits* one step outside every sanitizer —

    return [
        {"id": t["id"],
         "name": t.get("name") or t["id"],
         "desc": t.get("desc", ""),
         "confirm": bool(t.get("confirm")),
         **jobs.job_state(t["id"])}
        for t in jobs.maintenance_tasks().values()
    ]

so a row reaching that build with a ``__bool__``-bomb ``confirm`` detonated
``bool(...)``, and a hash-shadowing bomb key riding ``id`` / ``name`` /
``confirm`` (same text, ``__eq__`` raising) detonated the ``t["id"]`` /
``t.get(...)`` probe — the exact ``_mapping_get`` / ``_truthy`` seam maint11
sealed *inside* ``maintenance_tasks``, left bare at the surface the SPA reads.
GET /api/maintenance 500'd from the route itself.

The shape now lives in :func:`hub.jobs.maintenance_view`, which reads every
field through the module's union guards (``_plain_dict`` for the row,
``_mapping_get`` for each field, ``_truthy`` for ``confirm`` and the
``name or id`` fall-back, ``_jsonable`` for the whole entry before Starlette's
encoder) and can never raise.  :class:`ListViewShapingTests` fails on the
pre-fix tree; every other class pins a shape the same hunt confirmed already
coded so the edit cannot weaken the maint11/jobs11 union.
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
    """The hash-shadowing key: a real str subclass carrying the same hash as
    its text, landing in the real field's slot, whose ``__eq__`` raises when a
    lookup probe compares against it."""

    def __eq__(self, other):  # noqa: D105
        raise RuntimeError("leftover shadow-key eq bomb")

    def __hash__(self):  # noqa: D105
        return str.__hash__(self)


class _BoolBomb:
    """A ``confirm`` value whose truth test detonates."""

    def __bool__(self):
        raise RuntimeError("leftover bool bomb")


class _SelfStrEncodeBomb(str):
    """``__str__`` answers *self* (skipping CPython's exact-str copy) so a
    bound ``.encode`` would dispatch the override — the health13 class."""

    def __str__(self):  # noqa: D105
        return self

    def encode(self, *a, **k):  # noqa: D102
        raise RuntimeError("leftover encode bomb")


class _FspathBomb:
    """An opaque path-like leftover whose ``__fspath__`` raises — no numeric
    protocol, no isoformat; it must launder to its ``str()`` form or drop."""

    def __fspath__(self):
        raise RuntimeError("leftover fspath bomb")


class _DiskYamlSandbox(unittest.TestCase):
    """One plain task on the REAL config path — the request walks
    disk -> load_yaml_int_capped -> _as_config -> route, like maint4-maint11."""

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


class ListViewShapingTests(_DiskYamlSandbox):
    """The fixed leak: the GET /api/maintenance emitted-view build.

    Each poisoned row is fed at the rank the route re-reads — the value
    :func:`hub.jobs.maintenance_tasks` hands the list comprehension — so the
    test isolates the shaping seam (the bare ``t["id"]`` / ``bool(t.get(...))``
    probes) rather than the row-return laundering maint11 already sealed.
    Pre-fix each row 500'd GET /api/maintenance; :func:`hub.jobs.maintenance_view`
    degrades every one field-level."""

    def test_bool_bomb_confirm_keeps_the_list_route_up(self):
        rows = {"plain": {"id": "plain", "name": "Plain", "confirm": _BoolBomb()}}
        with mock.patch.object(jobs, "maintenance_tasks", return_value=rows):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        row = response.json()[0]
        # bool(confirm) at the route dispatched the bomb; _truthy fails closed.
        self.assertIs(row["confirm"], False)
        self.assertEqual(row["id"], "plain")

    def test_shadow_key_on_confirm_degrades_to_false(self):
        rows = {"plain": {"id": "plain", "name": "Plain",
                          _EqBombStr("confirm"): "junk"}}
        with mock.patch.object(jobs, "maintenance_tasks", return_value=rows):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        self.assertIs(response.json()[0]["confirm"], False)

    def test_shadow_key_on_name_falls_back_to_id(self):
        rows = {"plain": {"id": "plain", _EqBombStr("name"): "junk"}}
        with mock.patch.object(jobs, "maintenance_tasks", return_value=rows):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        row = response.json()[0]
        # ``t.get("name") or t["id"]`` used to blow the shadowed probe; the
        # unreadable name falls back to the id, like an absent name.
        self.assertEqual(row["name"], "plain")

    def test_shadow_key_on_id_still_lists_under_its_task_id(self):
        # The row's own ``id`` slot is shadowed, but the view keys off the
        # id ``maintenance_tasks`` already resolved (the mapping key), so the
        # task still lists — the bare ``t["id"]`` probe used to 500 here.
        rows = {"plain": {_EqBombStr("id"): "junk", "command": "true"}}
        with mock.patch.object(jobs, "maintenance_tasks", return_value=rows):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        self.assertEqual([r["id"] for r in response.json()], ["plain"])

    def test_healthy_row_shape_is_unchanged(self):
        # The consolidation must serve the exact SPA contract: id/name/desc/
        # confirm plus the merged job_state, name-or-id fall-back, desc "".
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


class RealSeamRoutePins(_DiskYamlSandbox):
    """Newest-class bombs on the real config / ``_jobs`` seams — pinned so the
    maint12 edit keeps every one degrading through the whole listing pipe
    (``maintenance_tasks`` -> ``maintenance_view``) rather than 500ing."""

    def test_self_str_encode_bomb_confirm_costs_only_its_field(self):
        # A ``__str__``-returns-self encode bomb riding a config ``confirm``:
        # _jsonable's unbound str.encode launders it and _truthy reads it, so
        # only the field degrades and the task keeps listing.
        rows = [{"id": "plain", "name": "Plain",
                 "confirm": _SelfStrEncodeBomb("x\ud800")}]
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": rows}):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        self.assertEqual([r["id"] for r in response.json()], ["plain"])

    def test_fspath_like_opaque_leftover_name_lists_the_task(self):
        rows = [{"id": "plain", "name": _FspathBomb(), "command": "true"}]
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": rows}):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        # The opaque leftover launders to its str() form (a truthy name), so
        # the row keeps its own name rather than the id fall-back.
        self.assertEqual([r["id"] for r in response.json()], ["plain"])

    def test_poisoned_jobs_table_keeps_all_three_routes_up(self):
        class _ValuesBombTable(dict):
            def values(self, *a, **k):  # noqa: D102
                raise RuntimeError("leftover values bomb")

            def get(self, *a, **k):  # noqa: D102
                raise RuntimeError("leftover get bomb")

        saved = jobs._jobs
        jobs._jobs = _ValuesBombTable(plain={"running": False, "rc": 0, "log": []})
        try:
            client = _client()
            response = client.get("/api/maintenance")
            self.assertEqual(response.status_code, 200, response.text[:300])
            _clean(response)
            response = client.get("/api/maintenance/plain/log")
            self.assertEqual(response.status_code, 200, response.text[:300])
            response = client.post("/api/maintenance/plain/run")
            self.assertEqual(response.status_code, 200, response.text[:300])
            # Drain the started job while the poisoned table is still installed
            # (``_jobs_row`` reads it through the unbound ``dict.get``); the run
            # route stored the fresh row through ``_store_job_row``'s unbound
            # ``dict.__setitem__``, so the single-runner mutex still tracked it.
            self.assertEqual(_wait_finished("plain").get("rc"), 0)
        finally:
            jobs._jobs = saved if isinstance(saved, dict) else {}


class Maint11UnionStillHolds(_DiskYamlSandbox):
    """maint11/jobs11 shapes re-pinned through the mounted routes so the
    maint12 view edit trips loudly if it weakens the union."""

    def test_hash_shadow_id_key_costs_only_its_row(self):
        rows = [
            {_EqBombStr("id"): "junk", "command": "true"},
            {"id": "plain", "name": "Plain", "command": "true", "timeout": 10},
        ]
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": rows}):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        self.assertEqual([r["id"] for r in response.json()], ["plain"])

    def test_hash_shadow_running_key_keeps_list_and_log_up(self):
        jobs._jobs.clear()
        jobs._jobs["plain"] = {_EqBombStr("running"): True}
        client = _client()
        response = client.get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        row = next(r for r in response.json() if r["id"] == "plain")
        self.assertIs(row["running"], False)
        response = client.get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertIs(response.json()["running"], False)

    def test_cfg_root_bomb_key_degrades_to_empty_listing(self):
        with mock.patch.object(jobs, "cfg",
                               return_value={_EqBombStr("maintenance"): []}):
            response = _client().get("/api/maintenance")
            self.assertEqual(response.status_code, 200, response.text[:300])
            self.assertEqual(response.json(), [])

    def test_run_route_still_refuses_a_second_runner_with_409(self):
        jobs._jobs["other"] = {"running": True, "rc": None, "log": []}
        response = _client().post("/api/maintenance/plain/run")
        self.assertEqual(response.status_code, 409, response.text[:300])
        detail = response.json().get("detail") or {}
        self.assertEqual(detail.get("code"), "jobs.already_running")

    def test_unknown_task_run_is_a_coded_404(self):
        response = _client().post("/api/maintenance/no-such/run")
        self.assertEqual(response.status_code, 404, response.text[:300])
        detail = response.json().get("detail") or {}
        self.assertEqual(detail.get("code"), "maintenance.unknown_task")


if __name__ == "__main__":
    unittest.main()
