"""Compose leftover sweep #8: str-subclass KEY bombs in stack/job rows.

An eighth adversarial pass over the Compose surfaces (GET /api/stacks,
GET/PUT /api/compose/{id}, POST /api/compose/{id}/validate,
POST /api/stacks/{id}/run, GET /api/stacks/jobs/{id}) through the real
``create_app`` wiring with ``TestClient(raise_server_exceptions=False)``
found one live unhandled-500 class every prior compose sweep missed — in
the *keys* of the rows rather than their values:

* ``_plain_job`` laundered a row's mapping type (``dict()`` C-level copy of
  a dict-subclass) but kept the row's KEYS verbatim.  One str-*subclass*
  key anywhere in a ``stacks:`` row makes every later ``row.get("field")``
  fall off CPython's exact-str fast path onto generic comparison, and when
  the poisoned key's hash collides with the looked-up field name (same
  string content) the reflected operand hands the subclass ``__eq__``
  priority — the bomb raised straight out of ``_stack_paths``'s
  ``s.get("id")`` / ``s.get("path")`` / ``s.get("name")`` /
  ``s.get("compose_file")`` / ``s.get("containers")`` and 500'd
  GET /api/stacks, GET/PUT /api/compose/{id}, POST /api/compose/{id}/validate
  and POST /api/stacks/{id}/run.  The compose7 fix (docker7 convention)
  guarded the cfg *root* with try/except plus the unbound ``dict.get``; a
  bombing key one level down, inside a row, was still live.

* The same shape poisoned ``_cjobs`` rows: a subclass key riding a job row
  detonated ``row.get("running")`` inside the single-runner mutex scan and
  ``row.get("stack_id")`` / ``row.get("rc")`` in the job renderers — 500ing
  GET /api/stacks and GET /api/stacks/jobs/{id} until the panel restarted.

The fix launders the keys in ``_plain_job`` (the one funnel every stack/job
row reader already goes through): a str-subclass key is copied to an exact
``str`` through the C storage (``str.__str__``, the docker6 unbound
convention — the override cannot fire), and non-str keys drop, since no
reader ever looks a row up by one.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import compose_svc, containers_svc  # noqa: E402
from hub.containers_svc import _plain_job  # noqa: E402

VALID_COMPOSE = "services:\n  web:\n    image: nginx:alpine\n"


# ---- leftover subclass key bombs ----
class _EqBombKey(str):
    """A str-subclass key whose comparison detonates on hash collision.

    ``__hash__`` mirrors the plain content so a lookup of the equal exact
    str lands in the same bucket, where the reflected operand gives this
    subclass's ``__eq__`` priority — the exact shape that raised out of
    ``dict.get`` in the stack reader.
    """

    def __eq__(self, other):  # noqa: D401
        raise RuntimeError("boom key __eq__")

    def __ne__(self, other):
        raise RuntimeError("boom key __ne__")

    def __hash__(self):
        return str.__hash__(str.__str__(self))


class _BenignSubKey(str):
    """A str-subclass key whose bombs never fire once laundered."""

    def __len__(self):
        raise RuntimeError("boom key __len__")

    def encode(self, *a, **k):
        raise RuntimeError("boom key encode")


class _BombGetItemsDict(dict):
    """A dict-subclass whose bound ``.get``/``items`` bomb; copy still works."""

    def get(self, *a, **k):
        raise RuntimeError("boom .get")

    def items(self):
        raise RuntimeError("boom items")


class _BombKeysDict(dict):
    """A dict-subclass whose ``dict()`` copy itself raises.

    CPython's copy fast path survives either override alone; only a subclass
    that overrides BOTH ``keys`` and ``__iter__`` forces the generic merge,
    which calls the bombing ``keys()``.
    """

    def keys(self):
        raise RuntimeError("boom keys")

    def __iter__(self):
        raise RuntimeError("boom iter")


class PlainJobKeyLaunderingUnitTests(unittest.TestCase):
    """``_plain_job`` returns rows no field lookup can detonate on."""

    def test_eq_bomb_key_is_laundered_to_exact_str(self):
        row = _plain_job({_EqBombKey("id"): "s1", "path": "/tmp/x"})
        self.assertIsNotNone(row)
        # The laundered key answers the exact-str lookup without raising.
        self.assertEqual(row.get("id"), "s1")
        self.assertEqual(row.get("path"), "/tmp/x")
        self.assertTrue(all(type(k) is str for k in row))

    def test_benign_subclass_key_keeps_its_value(self):
        row = _plain_job({_BenignSubKey("name"): "web"})
        self.assertEqual(row, {"name": "web"})
        self.assertTrue(all(type(k) is str for k in row))

    def test_non_str_keys_drop(self):
        row = _plain_job({42: "a", None: "b", (1, 2): "c", "id": "s1"})
        self.assertEqual(row, {"id": "s1"})

    def test_plain_row_returns_identity(self):
        src = {"id": "s1", "running": False}
        self.assertIs(_plain_job(src), src)

    def test_subclass_row_with_bound_method_bombs_still_copies(self):
        # dict() of a dict-subclass copies the C storage, so a bound
        # ``.get``/``items`` override cannot fire — the row survives plain.
        row = _plain_job(_BombGetItemsDict({"id": "s1"}))
        self.assertEqual(row, {"id": "s1"})
        self.assertIs(type(row), dict)

    def test_subclass_row_whose_copy_raises_drops(self):
        # A ``keys`` override disables the copy fast path, so the copy
        # itself raises: that row is junk and drops (existing behavior).
        self.assertIsNone(_plain_job(_BombKeysDict({"id": "s1"})))

    def test_non_dict_is_none(self):
        self.assertIsNone(_plain_job(["not", "a", "row"]))
        self.assertIsNone(_plain_job(None))


class _Compose8Sandbox(unittest.TestCase):
    """Real app wiring + a real stack on disk under a temp home."""

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

    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="compose8-8k1b-"))
        self.addCleanup(lambda: shutil.rmtree(self.home, ignore_errors=True))
        self.stack_dir = self.home / "Services" / "app-8k1b"
        self.stack_dir.mkdir(parents=True)
        (self.stack_dir / "docker-compose.yml").write_text(VALID_COMPOSE)
        p = mock.patch.object(compose_svc, "user_home", return_value=self.home)
        p.start()
        self.addCleanup(p.stop)
        cp = mock.patch.object(containers_svc, "user_home", return_value=self.home)
        cp.start()
        self.addCleanup(cp.stop)
        self._saved_jobs = dict(containers_svc._cjobs)
        containers_svc._cjobs.clear()
        self.addCleanup(self._restore_jobs)

    def _restore_jobs(self):
        containers_svc._cjobs.clear()
        containers_svc._cjobs.update(self._saved_jobs)

    def _with_cfg(self, value):
        return mock.patch.object(containers_svc, "cfg", return_value=value)

    def _assert_renders(self, resp):
        self.assertLess(resp.status_code, 500, resp.text)
        self.assertNotIn("\ud800", json.dumps(resp.json()))

    def _sweep(self, sid: str = "app-8k1b"):
        self._assert_renders(self.client.get("/api/stacks"))
        self._assert_renders(self.client.get(f"/api/compose/{sid}"))
        self._assert_renders(self.client.post(f"/api/compose/{sid}/validate"))
        self._assert_renders(self.client.put(
            f"/api/compose/{sid}",
            content=json.dumps({"content": VALID_COMPOSE + "# e\n", "check": False}),
            headers={"Content-Type": "application/json"},
        ))


class StackRowKeyBombHttpTests(_Compose8Sandbox):
    """A subclass-key bomb in a ``stacks:`` row never 500s the routes."""

    def _row(self, extra=None):
        # dict.update, never ``**`` unpacking: kwargs binding compares the
        # keyword names and would fire the bomb inside the test itself.
        row = {"id": "app-8k1b", "path": str(self.stack_dir)}
        if extra:
            row.update(extra)
        return row

    def test_eq_bomb_key_colliding_with_id_never_500s(self):
        row = {_EqBombKey("id"): "app-8k1b", "path": str(self.stack_dir)}
        with self._with_cfg({"stacks": [row]}):
            self._sweep()

    def test_eq_bomb_key_colliding_with_path_never_500s(self):
        row = {_EqBombKey("path"): str(self.stack_dir), "id": "app-8k1b"}
        with self._with_cfg({"stacks": [row]}):
            self._sweep()

    def test_eq_bomb_key_colliding_with_name_never_500s(self):
        with self._with_cfg({"stacks": [self._row({_EqBombKey("name"): "n"})]}):
            self._sweep()

    def test_eq_bomb_key_colliding_with_compose_file_never_500s(self):
        row = self._row({_EqBombKey("compose_file"): "docker-compose.yml"})
        with self._with_cfg({"stacks": [row]}):
            self._sweep()

    def test_eq_bomb_key_colliding_with_containers_never_500s(self):
        row = self._row({_EqBombKey("containers"): ["c1"]})
        with self._with_cfg({"stacks": [row]}):
            self._sweep()

    def test_laundered_row_still_lists_the_stack(self):
        # The bomb key is laundered, not dropped: the row keeps working.
        row = {_EqBombKey("id"): "app-8k1b", "path": str(self.stack_dir)}
        with self._with_cfg({"stacks": [row]}):
            resp = self.client.get("/api/stacks")
            self.assertLess(resp.status_code, 500, resp.text)
            ids = [s.get("id") for s in resp.json().get("stacks", [])]
            self.assertIn("app-8k1b", ids)

    def test_root_eq_bomb_key_stays_immune(self):
        # The cfg ROOT with a bombing "stacks" key was already sealed by the
        # docker7 try/except around the unbound dict.get; pin it.
        root = {_EqBombKey("stacks"): [self._row()], "other": 1}
        with self._with_cfg(root):
            self._assert_renders(self.client.get("/api/stacks"))


class JobRowKeyBombHttpTests(_Compose8Sandbox):
    """A subclass-key bomb in a ``_cjobs`` row never 500s the job routes."""

    def test_job_row_field_key_bombs_never_500(self):
        containers_svc._cjobs.update({
            "stack-app-8k1b-up-1": {
                _EqBombKey("running"): False,
                _EqBombKey("stack_id"): "app-8k1b",
                "rc": 0,
                "log": ["ok"],
            },
            "j2": {
                _EqBombKey("rc"): 1,
                _EqBombKey("log"): ["x"],
                "stack_id": "app-8k1b",
                "running": False,
            },
        })
        with self._with_cfg({"stacks": [
            {"id": "app-8k1b", "path": str(self.stack_dir)},
        ]}):
            self._assert_renders(self.client.get("/api/stacks"))
            self._assert_renders(self.client.get("/api/stacks/jobs/stack-app-8k1b-up-1"))
            self._assert_renders(self.client.get("/api/stacks/jobs/j2"))
            self._assert_renders(self.client.get("/api/stacks/jobs/app-8k1b"))

    def test_job_start_survives_poisoned_row_in_mutex_scan(self):
        # The single-runner scan reads every row's "running" through
        # _plain_job; a poisoned non-running row must not block or 500 it.
        containers_svc._cjobs["old"] = {
            _EqBombKey("running"): False, "stack_id": "app-8k1b", "log": [],
        }
        with self._with_cfg({"stacks": [
            {"id": "app-8k1b", "path": str(self.stack_dir)},
        ]}):
            resp = self.client.post(
                "/api/stacks/app-8k1b/run", json={"action": "down"},
            )
            self.assertLess(resp.status_code, 500, resp.text)


if __name__ == "__main__":
    unittest.main()
