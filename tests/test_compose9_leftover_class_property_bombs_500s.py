"""Compose leftover sweep #9: ``__class__``-property bomb 500s.

A ninth adversarial pass over the Compose/stacks surfaces (GET /api/stacks,
GET/PUT /api/compose/{id}, POST /api/compose/{id}/validate,
POST /api/stacks/{id}/run, GET /api/stacks/jobs/{id}) through the real
``create_app`` wiring with ``TestClient(raise_server_exceptions=False)`` found
a live unhandled-500 class every prior compose sweep missed — the
**``__class__``-property bomb** (the files12/jobs/modules8 ``_isinst`` rule).

CPython's ``isinstance`` reads the operand's ``__class__`` whenever the
real-type fast check misses, so a leftover value whose ``__class__`` is a
raising *property* blows straight through a bare ``isinstance`` gate that sits
outside a try.  compose7/compose8 laundered subclass VALUE bombs and subclass
KEY bombs, but every gate that decides *which* launderer to run was still a
bare ``isinstance`` — so the bomb detonated one step before the guard:

* ``_field_text`` opened with ``value is None or isinstance(value, bool)`` and
  chained bare ``isinstance`` gates for float/int/str/bytes.  A leftover stack
  ``id`` / ``name`` / ``containers`` item whose ``__class__`` raises 500'd
  GET /api/stacks and GET /api/compose/{id}.
* ``_stack_paths`` gated ``path`` and ``compose_file`` with bare
  ``isinstance`` (the ``compose_file`` one inside a try that only caught
  ``OSError``/``ValueError``/``TypeError`` — not the bomb's ``RuntimeError``).
  A ``__class__``-bomb ``path`` / ``compose_file`` 500'd the same routes plus
  POST /api/stacks/{id}/run and the compose read/save.
* ``_str_list`` gated its ``containers`` list and each item with bare
  ``isinstance``.
* ``_plain_text`` / ``_job_field`` gated a job row's ``stack_id`` / ``action``
  / ``code`` with bare ``isinstance``, and ``stack_job_log`` / ``job_public``
  handed ``rc`` / ``started`` / ``finished`` and each log line to
  ``_jsonable`` / ``_as_text`` raw — whose own entry ``isinstance`` gates read
  the bomb's ``__class__`` and 500'd GET /api/stacks and
  GET /api/stacks/jobs/{id}.

The fix routes every such gate through a guarded ``_isinst`` (fail closed to
"none of these types"), laundering the raw job scalars through ``_job_scalar``
and each log line through ``_log_text`` so one poisoned field degrades to a
dropped value while its siblings — and the whole listing — survive.

The rest pins the neighbouring shapes as **stays-immune**: a FIFO occupying a
compose path (the O_NONBLOCK read cap → 400, never a hung/500 handler), the
compose8 str-subclass ``__eq__`` KEY bomb, and a *lying* ``__class__`` that
answers a real type (not an error — still rendered).
"""
from __future__ import annotations

import json
import os
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
from hub.containers_svc import (  # noqa: E402
    _field_text, _isinst, _job_field, _job_scalar, _log_text, _plain_text,
    _str_list,
)

VALID_COMPOSE = "services:\n  web:\n    image: nginx:alpine\n"


# ── The leftover bomb classes ───────────────────────────────────────────────
class ClassBomb:
    """``__class__`` is a raising property.

    ``isinstance(x, T)`` reads it on the real-type miss and raises unless the
    gate is guarded.  ``str(x)`` still renders (the repr), so a value poisoned
    only here degrades to a string rather than dropping.
    """

    @property
    def __class__(self):  # noqa: D401
        raise RuntimeError("boom __class__")


class LyingClass:
    """``__class__`` answers ``str`` though the real type is neither.

    A *lying* ``__class__`` is not an error: ``_isinst`` must still report the
    claim (the modules8 rule), and the downstream unbound coercion drops it.
    """

    @property
    def __class__(self):  # noqa: D401
        return str


class _EqBombKey(str):
    """A str-subclass key whose comparison detonates on hash collision.

    The compose8 shape: ``_plain_job`` launders it, so it stays immune.
    """

    def __eq__(self, other):  # noqa: D401
        raise RuntimeError("boom key __eq__")

    def __ne__(self, other):
        raise RuntimeError("boom key __ne__")

    def __hash__(self):
        return str.__hash__(str.__str__(self))


# ── Unit tests: the guarded gates ───────────────────────────────────────────
class IsInstUnitTests(unittest.TestCase):
    def test_class_bomb_reports_false_not_raises(self):
        b = ClassBomb()
        self.assertFalse(_isinst(b, str))
        self.assertFalse(_isinst(b, bool))
        self.assertFalse(_isinst(b, (bytes, bytearray)))

    def test_lying_class_still_reports_its_claim(self):
        self.assertTrue(_isinst(LyingClass(), str))

    def test_real_types_unaffected(self):
        self.assertTrue(_isinst("x", str))
        self.assertTrue(_isinst(5, int))
        self.assertFalse(_isinst(5, str))


class FieldTextUnitTests(unittest.TestCase):
    def test_class_bomb_never_raises(self):
        # str(bomb) still renders, so it degrades to the repr, never a raise.
        out = _field_text(ClassBomb(), "fb")
        self.assertIsInstance(out, str)
        self.assertTrue(out)

    def test_str_list_class_bomb_items_drop_not_raise(self):
        self.assertEqual(_str_list([ClassBomb(), "web", ClassBomb()]), ["web"])

    def test_str_list_class_bomb_container_returns_empty(self):
        self.assertEqual(_str_list(ClassBomb()), [])

    def test_plain_scalars_unaffected(self):
        self.assertEqual(_field_text(42), "42")
        self.assertEqual(_field_text("web"), "web")


class JobScalarUnitTests(unittest.TestCase):
    def test_job_scalar_class_bomb_drops_to_none(self):
        self.assertIsNone(_job_scalar(ClassBomb()))

    def test_job_scalar_keeps_plain_values(self):
        self.assertEqual(_job_scalar(0), 0)
        self.assertIsNone(_job_scalar(None))

    def test_log_text_class_bomb_drops_to_empty(self):
        self.assertEqual(_log_text(ClassBomb()), "")

    def test_log_text_keeps_plain_line(self):
        self.assertEqual(_log_text("== done =="), "== done ==")

    def test_job_field_class_bomb_drops_to_none(self):
        self.assertIsNone(_job_field(ClassBomb()))

    def test_plain_text_class_bomb_drops_to_none(self):
        self.assertIsNone(_plain_text(ClassBomb()))


# ── HTTP sandbox: real app wiring + a real stack on disk ─────────────────────
class _Compose9Sandbox(unittest.TestCase):
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
        self.home = Path(tempfile.mkdtemp(prefix="compose9-9c1c-"))
        self.addCleanup(lambda: shutil.rmtree(self.home, ignore_errors=True))
        self.stack_dir = self.home / "Services" / "app-9c1c"
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

    def _sweep(self, sid: str = "app-9c1c"):
        self._assert_renders(self.client.get("/api/stacks"))
        self._assert_renders(self.client.get(f"/api/compose/{sid}"))
        self._assert_renders(self.client.post(f"/api/compose/{sid}/validate"))
        self._assert_renders(self.client.put(
            f"/api/compose/{sid}",
            content=json.dumps({"content": VALID_COMPOSE + "# e\n", "check": False}),
            headers={"Content-Type": "application/json"},
        ))
        self._assert_renders(self.client.post(
            f"/api/stacks/{sid}/run", json={"action": "down"},
        ))


class ConfigRowClassBombHttpTests(_Compose9Sandbox):
    """A ``__class__``-bomb value in a ``stacks:`` row never 500s the routes."""

    def _row(self, extra):
        row = {"id": "app-9c1c", "path": str(self.stack_dir)}
        row.update(extra)
        return row

    def test_class_bomb_id_never_500s(self):
        with self._with_cfg({"stacks": [{"id": ClassBomb(), "path": str(self.stack_dir)}]}):
            self._sweep()

    def test_class_bomb_path_never_500s(self):
        with self._with_cfg({"stacks": [{"id": "app-9c1c", "path": ClassBomb()}]}):
            self._sweep()

    def test_class_bomb_compose_file_never_500s(self):
        with self._with_cfg({"stacks": [self._row({"compose_file": ClassBomb()})]}):
            self._sweep()

    def test_class_bomb_name_never_500s(self):
        with self._with_cfg({"stacks": [self._row({"name": ClassBomb()})]}):
            self._sweep()

    def test_class_bomb_containers_never_500s(self):
        with self._with_cfg({"stacks": [self._row({"containers": ClassBomb()})]}):
            self._sweep()

    def test_class_bomb_container_item_never_500s(self):
        with self._with_cfg({"stacks": [self._row({"containers": [ClassBomb(), "c1"]})]}):
            self._sweep()

    def test_clean_stack_still_listed_beside_a_bomb_row(self):
        # The bomb row degrades; a sibling clean row must still list.
        clean_dir = self.home / "Services" / "app-clean"
        clean_dir.mkdir(parents=True)
        (clean_dir / "docker-compose.yml").write_text(VALID_COMPOSE)
        with self._with_cfg({"stacks": [
            {"id": ClassBomb(), "path": str(self.stack_dir)},
            {"id": "app-clean", "path": str(clean_dir)},
        ]}):
            resp = self.client.get("/api/stacks")
            self.assertLess(resp.status_code, 500, resp.text)
            ids = [s.get("id") for s in resp.json().get("stacks", [])]
            self.assertIn("app-clean", ids)


class JobRowClassBombHttpTests(_Compose9Sandbox):
    """A ``__class__``-bomb field in a ``_cjobs`` row never 500s the job routes."""

    def _drive(self):
        with self._with_cfg({"stacks": [
            {"id": "app-9c1c", "path": str(self.stack_dir)},
        ]}):
            self._assert_renders(self.client.get("/api/stacks"))
            self._assert_renders(self.client.get("/api/stacks/jobs/jb"))
            self._assert_renders(self.client.get("/api/stacks/jobs/app-9c1c"))

    def test_class_bomb_stack_id_never_500s(self):
        containers_svc._cjobs["jb"] = {
            "stack_id": ClassBomb(), "running": False, "rc": 0, "log": [],
        }
        self._drive()

    def test_class_bomb_rc_never_500s(self):
        containers_svc._cjobs["jb"] = {
            "stack_id": "app-9c1c", "running": False, "rc": ClassBomb(), "log": [],
        }
        self._drive()

    def test_class_bomb_started_finished_never_500s(self):
        containers_svc._cjobs["jb"] = {
            "stack_id": "app-9c1c", "running": False, "rc": 0,
            "started": ClassBomb(), "finished": ClassBomb(), "log": [],
        }
        self._drive()

    def test_class_bomb_action_code_never_500s(self):
        containers_svc._cjobs["jb"] = {
            "stack_id": "app-9c1c", "running": False, "rc": 0,
            "action": ClassBomb(), "code": ClassBomb(), "log": [],
        }
        self._drive()

    def test_class_bomb_log_line_never_500s(self):
        containers_svc._cjobs["jb"] = {
            "stack_id": "app-9c1c", "running": False, "rc": 0,
            "log": ["ok", ClassBomb(), "done"],
        }
        self._drive()

    def test_class_bomb_running_never_500s(self):
        containers_svc._cjobs["jb"] = {
            "stack_id": "app-9c1c", "running": ClassBomb(), "rc": 0, "log": [],
        }
        self._drive()


class StaysImmuneHttpTests(_Compose9Sandbox):
    """Neighbouring shapes the earlier sweeps already sealed — pin them."""

    def test_fifo_compose_path_degrades_not_hangs_or_500s(self):
        # read_text_capped opens O_NONBLOCK and rejects a non-regular file, so
        # a FIFO occupying the compose path answers 400, never parking the
        # handler or 500ing.  Vanished/blocking files stay a coded refusal.
        fifo_dir = self.home / "Services" / "app-fifo"
        fifo_dir.mkdir(parents=True)
        os.mkfifo(fifo_dir / "docker-compose.yml")
        with self._with_cfg({"stacks": [{"id": "app-fifo", "path": str(fifo_dir)}]}):
            self._assert_renders(self.client.get("/api/stacks"))
            resp = self.client.get("/api/compose/app-fifo")
            self.assertEqual(resp.status_code, 400, resp.text)

    def test_eq_bomb_key_stays_immune(self):
        # compose8 launders a str-subclass ``__eq__`` KEY bomb in _plain_job.
        row = {_EqBombKey("id"): "app-9c1c", "path": str(self.stack_dir)}
        with self._with_cfg({"stacks": [row]}):
            self._sweep()

    def test_lying_class_id_is_not_an_error(self):
        # A ``__class__`` that answers ``str`` is a claim, not a bomb: the
        # unbound coercion drops the (non-str real) value, and the row falls
        # back to the directory name — never a 500.
        with self._with_cfg({"stacks": [{"id": LyingClass(), "path": str(self.stack_dir)}]}):
            resp = self.client.get("/api/stacks")
            self.assertLess(resp.status_code, 500, resp.text)
            ids = [s.get("id") for s in resp.json().get("stacks", [])]
            self.assertIn("app-9c1c", ids)


if __name__ == "__main__":
    unittest.main()
