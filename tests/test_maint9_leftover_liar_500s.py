"""Ninth leftover-500s sweep of the Maintenance page, over the real mounted app.

The maint8 sweep routed every leftover-reachable type check in ``hub/jobs.py``
through ``_isinst`` (``isinstance`` in a try), so a *raising* ``__class__``
bomb can no longer 500 the three routes the page mounts —

    GET  /api/maintenance
    POST /api/maintenance/{tid:path}/run
    GET  /api/maintenance/{tid:path}/log

A fresh hunt over the same mounted tree (create_app + TestClient,
raise_server_exceptions=False) re-drove the modules9/assistant9 class instead:
**lying ``__class__`` impostors** — a plain object whose ``__class__``
property *answers* a builtin type it is not.  ``isinstance`` (so ``_isinst``)
honours the claim; the unbound base descriptor the arm then calls is bound to
the real layout of that builtin and refuses the impostor with TypeError.  Two
seams still let that TypeError out raw:

* **cfg-root rank** (``maintenance_tasks``).  ``dict.get(data,
  "maintenance")`` ran bare whenever ``_isinst(data, dict)`` held — the
  unbound builtin was the maint7 fix for a dict-*subclass* ``.get`` bomb, but
  a liar claiming dict is no dict at all, and the descriptor's TypeError
  500'd GET /api/maintenance AND POST /api/maintenance/{tid}/run (which walks
  the same listing) from outside every net.  The unbound call now runs in a
  try; a raise means "not really a dict" and the impostor root degrades to
  the empty listing (:class:`CfgRootLiarHttpTests` fails on the pre-fix tree).

* **``_jobs``-key rank** (``_jobs_row``'s rescue scan).  The scan only runs
  after a poisoned ``_jobs.get(tid)`` raised, and compared through the
  unbound ``str.__eq__(k, tid)`` behind an ``_isinst(k, str)`` gate — so a
  liar key claiming str (same hash as a configured id, raising ``__eq__``)
  blew the very scan built to rescue the lookup, and 500'd the list and log
  routes (:class:`JobsLiarKeyHttpTests` fails on the pre-fix tree).  The
  unbound compare now runs in a try; a raise means "not really a str", and a
  junk impostor key can never be the probed tid.

Stays-immune pins ride along for the impostor ranks the same hunt confirmed
already coded: a liar ``maintenance`` value (guarded ``list()``), a liar row
(``_plain_dict``'s guarded copy), a liar id (``_utf8_text``'s unbound
``str.encode`` degrades it to ``""``), liar nested/job-row values
(``_jsonable``'s guarded unbound arms + the exact ``type(value) is bool``
gate), a liar whole job row (junk, so the single-runner mutex must not
wedge), and the maint7/maint8 root union (try/except around ``cfg()`` plus
the unbound ``dict.get``, which must both survive this sweep's edit).
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


class _Lie:
    """``__class__`` answers a type the object is not — a claim, not a raise.

    The modules9/assistant9 impostor: ``isinstance`` (so ``_isinst``) honours
    the claim, but the real object is an ordinary ``_Lie`` — none of the
    unbound base descriptors (``dict.get``, ``str.__eq__``, ``bytes.decode``,
    ``dict.items``, ``list.__iter__``…) apply to it.
    """

    def __init__(self, claim, hash_as=None, eq_raises=False):
        self._claim = claim
        self._hash = 17 if hash_as is None else hash_as
        self._eq_raises = eq_raises

    @property
    def __class__(self):  # type: ignore[override]
        return self._claim

    def __hash__(self):  # usable as a mapping key
        return self._hash

    def __eq__(self, other):
        if self._eq_raises:
            raise RuntimeError("leftover impostor eq bomb")
        return NotImplemented


class _EqBombStr(str):
    """A *real* str subclass whose ``__eq__`` raises — the key the rescue
    scan was built for; the unbound ``str.__eq__`` reads under the override."""

    def __eq__(self, other):  # noqa: D105
        raise RuntimeError("leftover subclass eq bomb")

    def __hash__(self):  # noqa: D105
        return str.__hash__(self)


class _DiskYamlSandbox(unittest.TestCase):
    """One plain task on the REAL config path — the request walks
    disk → load_yaml_int_capped → _as_config → route, like maint4-maint8."""

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


class CfgRootLiarHttpTests(_DiskYamlSandbox):
    """The fixed leak, config side: a cfg() root whose ``__class__`` answers
    dict passed ``_isinst`` and blew the bare unbound ``dict.get`` — a raw
    500 on the list route AND the run route on the pre-fix tree."""

    def test_dict_liar_cfg_root_degrades_to_empty_list_and_coded_404(self):
        client = _client()
        with mock.patch.object(jobs, "cfg", return_value=_Lie(dict)):
            response = client.get("/api/maintenance")
            self.assertEqual(response.status_code, 200, response.text[:300])
            _clean(response)
            self.assertEqual(response.json(), [])
            response = client.post("/api/maintenance/plain/run")
            self.assertEqual(response.status_code, 404, response.text[:300])
            detail = response.json().get("detail") or {}
            self.assertEqual(detail.get("code"), "maintenance.unknown_task")

    def test_healthy_cfg_serves_again_after_the_liar_root_passes(self):
        # The impostor costs only the requests it poisons: the very next
        # request over the healthy on-disk config lists and runs normally.
        client = _client()
        with mock.patch.object(jobs, "cfg", return_value=_Lie(dict)):
            self.assertEqual(client.get("/api/maintenance").json(), [])
        response = client.get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual([r["id"] for r in response.json()], ["plain"])
        response = client.post("/api/maintenance/plain/run")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(_wait_finished("plain").get("rc"), 0)


class JobsLiarKeyHttpTests(_DiskYamlSandbox):
    """The fixed leak, ``_jobs`` side: a liar key claiming str (colliding
    hash, raising ``__eq__``) used to blow the rescue scan's unbound
    ``str.__eq__`` and 500 the list and log routes on the pre-fix tree."""

    def _liar_key(self):
        return _Lie(str, hash_as=hash("plain"), eq_raises=True)

    def test_liar_key_keeps_list_and_log_up(self):
        jobs._jobs[self._liar_key()] = {"running": False, "rc": 0, "log": ["x"]}
        client = _client()
        response = client.get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        row = next(r for r in response.json() if r["id"] == "plain")
        # A junk impostor key can never be the probed tid: the coded empty
        # job state serves for the real task.
        self.assertFalse(row["running"])
        self.assertIsNone(row["rc"])
        response = client.get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["log"], "(not run yet)")

    def test_liar_key_cannot_wedge_the_run_route(self):
        # start_job's insert also collides with the impostor key; the
        # laundering rebuild drops it (a liar launders to "") and the task
        # runs end-to-end, pollable through the rescued lookup.
        jobs._jobs[self._liar_key()] = {"running": False, "rc": 0, "log": []}
        client = _client()
        response = client.post("/api/maintenance/plain/run")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json(), {"ok": True, "message": "Task started"})
        self.assertEqual(_wait_finished("plain").get("rc"), 0)
        self.assertEqual([type(k) for k in jobs._jobs], [str])

    def test_liar_key_cannot_mask_the_genuine_rescue(self):
        # The scan exists to find a *real* str-subclass key whose bound
        # ``__eq__`` bombs the plain lookup; an impostor sitting beside it
        # (scanned first — the scan walks every key, so no colliding hash
        # is needed to reach it) must cost only itself, not the rescue.
        jobs._jobs[_Lie(str, eq_raises=True)] = {"running": False, "rc": 1,
                                                 "log": []}
        jobs._jobs[_EqBombStr("plain")] = {"running": False, "rc": 7,
                                           "log": ["rescued line"],
                                           "finished": "10:00:00"}
        client = _client()
        response = client.get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        row = next(r for r in response.json() if r["id"] == "plain")
        self.assertEqual(row["rc"], 7)
        response = client.get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        payload = response.json()
        self.assertEqual(payload["rc"], 7)
        self.assertEqual(payload["log"], "rescued line")


class StaysImmunePinTests(_DiskYamlSandbox):
    """Impostor ranks probed and found already coded — pinned so a refactor
    back toward bare unbound calls (or away from the maint7/maint8 root
    union) trips loudly."""

    def test_list_liar_maintenance_value_degrades_to_empty_list(self):
        # The guarded ``list()`` refuses a non-iterable impostor claiming
        # list; the listing serves empty, never a 500.
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": _Lie(list)}):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json(), [])

    def test_dict_liar_row_costs_only_its_own_entry(self):
        # _plain_dict's guarded ``dict()`` copy refuses the impostor row;
        # the sane sibling keeps serving.
        rows = [
            _Lie(dict),
            {"id": "plain", "name": "Plain", "command": "true", "timeout": 10},
        ]
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": rows}):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        self.assertEqual([r["id"] for r in response.json()], ["plain"])

    def test_str_liar_id_costs_only_its_own_entry(self):
        # _task_id launders through _utf8_text, whose unbound ``str.encode``
        # refuses the impostor and drops the entry to "".
        rows = [
            {"id": _Lie(str), "name": "Junk", "command": "true"},
            {"id": "plain", "name": "Plain", "command": "true"},
        ]
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": rows}):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(sorted(r["id"] for r in response.json()), ["plain"])

    def test_liar_nested_values_keep_the_task_listed(self):
        # _jsonable's guarded unbound arms drop each impostor to None/"":
        # bytes (unbound decode), dict (guarded copy), bool (final type, the
        # exact gate misses and the int arm's unbound coercion refuses it),
        # int and float (unbound coercions).  The route's ``or`` fallback
        # then serves the id for the dropped name.
        rows = [{"id": "plain", "name": _Lie(dict), "desc": _Lie(bytes),
                 "confirm": _Lie(bool), "command": "true",
                 "timeout": _Lie(int), "weight": _Lie(float)}]
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": rows}):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        row = next(r for r in response.json() if r["id"] == "plain")
        self.assertEqual(row["name"], "plain")
        self.assertEqual(row["desc"], "")
        self.assertIs(row["confirm"], False)

    def test_liar_job_row_values_keep_list_and_log_up(self):
        jobs._jobs["plain"] = {"running": False, "rc": _Lie(int),
                               "log": _Lie(list), "started": _Lie(bytes),
                               "finished": _Lie(str)}
        client = _client()
        response = client.get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        row = next(r for r in response.json() if r["id"] == "plain")
        self.assertIsNone(row["rc"])
        response = client.get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        payload = response.json()
        self.assertIsNone(payload["rc"])
        self.assertEqual(payload["log"], "(waiting for output…)")

    def test_dict_liar_whole_job_row_cannot_wedge_the_mutex(self):
        # _plain_dict refuses the impostor row, so it is junk, not a live
        # job: all three routes stay up and the task still runs end-to-end.
        jobs._jobs["plain"] = _Lie(dict)
        client = _client()
        response = client.get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        row = next(r for r in response.json() if r["id"] == "plain")
        self.assertFalse(row["running"])
        response = client.get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["log"], "(not run yet)")
        response = client.post("/api/maintenance/plain/run")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(_wait_finished("plain").get("rc"), 0)

    def test_maint7_and_maint8_root_union_still_holds(self):
        # The conflict-policy union — try/except around cfg(), the unbound
        # dict.get for a genuine subclass ``.get`` bomb, and the guarded
        # ``list()`` — must all survive this sweep's edit.
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


if __name__ == "__main__":
    unittest.main()
