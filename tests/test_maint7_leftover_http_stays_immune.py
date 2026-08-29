"""Seventh leftover-500s sweep of the Maintenance page, over the real mounted app.

The hunted classes were re-driven against the three routes the page mounts —

    GET  /api/maintenance
    POST /api/maintenance/{tid:path}/run
    GET  /api/maintenance/{tid:path}/log

— through ``create_app()`` with ``raise_server_exceptions=False``.  Two live
leftover families were found and are fixed with this battery:

* **Poisoned config snapshot at the ``maintenance_tasks`` root.**  Every row
  and value below the root already rode ``_plain_dict`` / ``_jsonable`` /
  the unbound-scrub net, but the very first read was still the *bound*
  ``cfg().get("maintenance")``: a leftover dict-subclass root whose ``.get``
  raises (the settings_section/override class, one module over) — or a
  snapshot provider that raises outright — blew past every downstream guard
  and 500'd GET /api/maintenance AND POST /api/maintenance/{tid}/run (which
  walks ``maintenance_tasks()`` before matching the id), while the log route
  stayed up over the very same poisoned state.  The root now reads through
  a guarded ``cfg()`` plus the unbound ``dict.get`` — the
  config.settings_section convention
  (:class:`CfgRootBombHttpTests` fails on the pre-fix tree).

* **Bomb *keys* in the ``_jobs`` table.**  Every prior sweep poisoned the
  row values; the mapping key itself was still trusted.  A plain
  ``dict.get(tid)`` compares the probe against every stored key whose hash
  collides, and that comparison dispatches into the stored key's own
  ``__eq__`` — so a leftover str-subclass key with a bombing ``__eq__``
  (same text as a configured id, hence the same hash) raised out of
  ``job_state`` / ``get_job`` and 500'd all three routes: the list via
  ``job_state``, the log via ``get_job``, and POST run at the ``_jobs[tid]``
  insert, whose collision probe runs the same comparison.  Lookups now fall
  back to a scan comparing through the unbound base (``str.__eq__`` reads
  the C-level character storage), the insert rebuilds the table with
  laundered exact-str keys on a poisoned collision, and the job thread
  keeps the row *reference* instead of re-looking ``_jobs[tid]`` up — the
  pre-fix re-lookup could die before the thread's try block and wedge the
  single-runner mutex with a row parked "running" forever
  (:class:`EqBombKeyHttpTests` fails on the pre-fix tree).

Plus stays-immune pins for the neighbours that were probed and found
already coded: a bomb key under a *different* id costs nothing (different
hash, no comparison), ``_jobs_row`` serves the poisoned row's own content
through the fallback scan, and the laundered rebuild preserves sibling rows.
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


class _GetBombDict(dict):
    """Passes the isinstance gate; the bound ``.get`` then raises.

    The exact shape that used to blow ``maintenance_tasks``'s root read from
    outside every downstream guard.
    """

    def get(self, *a, **k):  # noqa: D102
        raise RuntimeError("leftover root get bomb")


class _EqBombStr(str):
    """Same text (hence same hash) as a real id; the comparison then raises.

    The dict-lookup collision probe dispatches into the *stored* key's
    ``__eq__``, so this key bombs every ``_jobs.get(tid)`` / ``_jobs[tid]``
    that probes its text.
    """

    def __eq__(self, other):  # noqa: D105
        raise RuntimeError("leftover eq bomb key")

    def __ne__(self, other):  # noqa: D105
        raise RuntimeError("leftover ne bomb key")

    def __hash__(self):  # noqa: D105
        return str.__hash__(self)


class _DiskYamlSandbox(unittest.TestCase):
    """One plain task on the REAL config path — the request walks
    disk → load_yaml_int_capped → _as_config → route, like maint4-maint6."""

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
        if self._original is None:
            try:
                config.YAML_PATH.unlink()
            except FileNotFoundError:
                pass
        else:
            config.YAML_PATH.write_bytes(self._original)
        config.reload_cfg()


class CfgRootBombHttpTests(_DiskYamlSandbox):
    """The fixed leak, snapshot side: a dict-subclass cfg root whose ``.get``
    raises — or a provider that raises — used to 500 the list AND run routes."""

    POISONED = _GetBombDict({
        "maintenance": [
            {"id": "plain", "name": "Plain", "command": "echo root-ok",
             "timeout": 10},
        ]
    })

    def test_get_bomb_root_keeps_the_list_route_up(self):
        with mock.patch.object(jobs, "cfg", return_value=self.POISONED):
            response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        rows = {r["id"]: r for r in response.json()}
        # The unbound dict.get reads the real storage, so the task list the
        # poisoned root actually carries still serves.
        self.assertEqual(sorted(rows), ["plain"])
        self.assertEqual(rows["plain"]["name"], "Plain")

    def test_get_bomb_root_keeps_the_run_route_up(self):
        client = _client()
        with mock.patch.object(jobs, "cfg", return_value=self.POISONED):
            response = client.post("/api/maintenance/plain/run")
            self.assertEqual(response.status_code, 200, response.text[:300])
            self.assertEqual(response.json(), {"ok": True, "message": "Task started"})
            row = _wait_finished("plain")
        self.assertEqual(row.get("rc"), 0)
        self.assertIn("root-ok", row.get("log"))

    def test_raising_snapshot_provider_degrades_to_the_coded_shapes(self):
        # A cfg() that raises outright is a dependency failure, not a route
        # defect: the list serves empty, the run route answers its coded 404.
        client = _client()
        with mock.patch.object(jobs, "cfg", side_effect=RuntimeError("cfg down")):
            response = client.get("/api/maintenance")
            self.assertEqual(response.status_code, 200, response.text[:300])
            self.assertEqual(response.json(), [])
            response = client.post("/api/maintenance/plain/run")
            self.assertEqual(response.status_code, 404, response.text[:300])
            detail = response.json().get("detail") or {}
            self.assertEqual(detail.get("code"), "maintenance.unknown_task")
            # The log route never reads cfg and stays up regardless.
            response = client.get("/api/maintenance/plain/log")
            self.assertEqual(response.status_code, 200, response.text[:300])


class EqBombKeyHttpTests(_DiskYamlSandbox):
    """The fixed leak, mapping-key side: a leftover str-subclass ``_jobs``
    key whose ``__eq__`` raises (same text as a configured id) used to 500
    all three routes on the pre-fix tree."""

    def _poison(self):
        jobs._jobs[_EqBombStr("plain")] = {
            "running": False, "rc": 7, "log": ["leftover line"],
            "finished": "10:00:00",
        }

    def test_eq_bomb_key_keeps_the_list_route_up(self):
        self._poison()
        response = _client().get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        row = next(r for r in response.json() if r["id"] == "plain")
        # The fallback scan serves the poisoned key's own row content.
        self.assertEqual(row["rc"], 7)
        self.assertEqual(row["finished"], "10:00:00")

    def test_eq_bomb_key_keeps_the_log_route_up(self):
        self._poison()
        response = _client().get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        _clean(response)
        payload = response.json()
        self.assertEqual(payload["rc"], 7)
        self.assertEqual(payload["log"], "leftover line")

    def test_eq_bomb_key_keeps_the_run_route_up(self):
        # The insert's collision probe used to dispatch into the bomb key's
        # __eq__ and 500 POST run; the laundered rebuild overwrites the twin.
        self._poison()
        client = _client()
        response = client.post("/api/maintenance/plain/run")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json(), {"ok": True, "message": "Task started"})
        row = _wait_finished("plain")
        self.assertEqual(row.get("rc"), 0)
        # The rebuilt table holds exact-str keys only: pollable by plain text.
        self.assertIs(type(next(iter(jobs._jobs))), str)
        response = client.get("/api/maintenance/plain/log")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["rc"], 0)

    def test_rebuild_preserves_sibling_rows(self):
        # Laundering must not cost an unrelated leftover row its state.
        jobs._jobs["sibling"] = {"running": False, "rc": 3, "log": ["kept"]}
        self._poison()
        _client().post("/api/maintenance/plain/run")
        _wait_finished("plain")
        self.assertEqual(jobs._jobs.get("sibling", {}).get("rc"), 3)

    def test_bomb_key_under_a_different_id_costs_nothing(self):
        # Stays-immune: a different text hashes differently, so the lookup
        # never compares against the bomb and the plain task is untouched.
        jobs._jobs[_EqBombStr("other")] = {"running": False, "rc": 1, "log": []}
        client = _client()
        response = client.get("/api/maintenance")
        self.assertEqual(response.status_code, 200, response.text[:300])
        response = client.post("/api/maintenance/plain/run")
        self.assertEqual(response.status_code, 200, response.text[:300])
        row = _wait_finished("plain")
        self.assertEqual(row.get("rc"), 0)

    def test_jobs_row_fallback_returns_the_poisoned_rows_content(self):
        self._poison()
        row = jobs._jobs_row("plain")
        self.assertIsInstance(row, dict)
        self.assertEqual(row.get("rc"), 7)
        # A miss through the fallback is still a clean None.
        self.assertIsNone(jobs._jobs_row("absent"))


if __name__ == "__main__":
    unittest.main()
