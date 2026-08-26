"""Compose leftover sweep #7: subclass-bomb 500s in the stack reader.

A seventh adversarial pass over the Compose surfaces (GET /api/stacks,
GET/PUT /api/compose/{id}, POST /api/compose/{id}/validate) through the real
``create_app`` wiring with ``TestClient(raise_server_exceptions=False)`` found
three live unhandled 500s that every prior compose sweep missed — all in
``containers_svc``'s config-stack reader, where a value the isinstance gate
lets through then detonates on the bound operator that consults it:

* ``_field_text`` laundered an int only through a ValueError-only ``str()``
  guard (for CPython's digit cap) and a float only through a bare finite
  probe.  A leftover int-*subclass* whose ``__str__``/``__index__`` raises
  anything else, or a float-*subclass* whose ``__eq__``/``__float__`` bombs
  the ``value != value or value in (...)`` check, escaped and 500'd
  GET /api/stacks and GET /api/compose/{id} — the same routes its sibling
  ``docker_cli._jsonable`` already guards with ``int.__index__`` /
  ``float.__float__`` base coercion.  The fix copies that convention.

* ``_stack_paths`` read the stack list with ``cfg().get("stacks")`` — the one
  cfg consumer in this module still using the *bound* ``.get``.  A leftover
  cfg() root that is a dict-*subclass* with a bombing ``.get`` raised straight
  out of the reader and 500'd GET /api/stacks, GET /api/compose/{id} and every
  stack-job start.  ``config.settings_section`` / ``override`` /
  ``panel_locale`` already read the root through the unbound ``dict.get``; the
  fix brings the compose reader into line.

These bomb classes are exactly the leftover shapes the earlier waves sealed in
``docker_cli._jsonable`` (poisoned job-row ``rc``) and ``config`` (a
dict-subclass config root); the compose stack reader was the surface that had
not yet been hardened against them.
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
from hub.containers_svc import _field_text  # noqa: E402

VALID_COMPOSE = "services:\n  web:\n    image: nginx:alpine\n"


# ---- leftover subclass bombs (the shapes a poisoned reader must survive) ----
class _BombGetDict(dict):
    """A dict whose bound ``.get`` detonates; ``dict.get`` still reads it."""

    def get(self, *a, **k):  # noqa: D401
        raise RuntimeError("boom .get")


class _BombStrInt(int):
    """An int-subclass whose ``__str__`` raises a non-ValueError."""

    def __str__(self):
        raise RuntimeError("boom int __str__")


class _BombIndexInt(int):
    """An int-subclass whose ``__index__`` raises."""

    def __index__(self):
        raise RuntimeError("boom int __index__")

    def __str__(self):
        raise RuntimeError("boom int __str__")


class _BombEqFloat(float):
    """A float-subclass whose ``__eq__`` bombs the finite probe."""

    def __eq__(self, other):
        raise RuntimeError("boom float __eq__")

    def __hash__(self):
        return 0


class _BombFloatFloat(float):
    """A float-subclass whose ``__float__`` raises."""

    def __float__(self):
        raise RuntimeError("boom __float__")


class _FieldTextUnitTests(unittest.TestCase):
    """``_field_text`` launders every subclass bomb through the base type.

    ``int.__index__`` / ``float.__float__`` read the C-level value and bypass
    the Python-level override, so a finite/renderable value is *recovered*
    rather than dropped — the point being that the bombing method never fires.
    Only a value the base type genuinely cannot render (over-cap-digit int,
    inf) still falls back.
    """

    def test_int_subclass_str_bomb_is_laundered_not_raised(self):
        # The overridden __str__ never fires: the value is read at C level.
        self.assertEqual(_field_text(_BombStrInt(5), "fb"), "5")

    def test_int_subclass_index_bomb_is_laundered_not_raised(self):
        self.assertEqual(_field_text(_BombIndexInt(5), "fb"), "5")

    def test_over_cap_int_subclass_still_falls_back(self):
        huge = type("_HugeInt", (int,), {})(int("f" * 4400, 16))
        self.assertEqual(_field_text(huge, "fb"), "fb")

    def test_float_subclass_eq_bomb_is_laundered_not_raised(self):
        self.assertEqual(_field_text(_BombEqFloat(1.5)), "1.5")

    def test_float_subclass_float_bomb_is_laundered_not_raised(self):
        self.assertEqual(_field_text(_BombFloatFloat(1.5), "fb"), "1.5")

    def test_inf_float_subclass_still_falls_back(self):
        self.assertEqual(_field_text(_BombEqFloat(float("inf")), "fb"), "fb")

    def test_plain_scalars_are_unaffected(self):
        self.assertEqual(_field_text(42), "42")
        self.assertEqual(_field_text(3.5), "3.5")
        self.assertEqual(_field_text(float("inf"), "fb"), "fb")
        self.assertEqual(_field_text(True, "fb"), "fb")


class _Compose7Sandbox(unittest.TestCase):
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
        self.home = Path(tempfile.mkdtemp(prefix="compose7-7c1a-"))
        self.addCleanup(lambda: shutil.rmtree(self.home, ignore_errors=True))
        self.stack_dir = self.home / "Services" / "app-7c1a"
        self.stack_dir.mkdir(parents=True)
        (self.stack_dir / "docker-compose.yml").write_text(VALID_COMPOSE)
        p = mock.patch.object(compose_svc, "user_home", return_value=self.home)
        p.start()
        self.addCleanup(p.stop)

    def _with_cfg(self, value):
        return mock.patch.object(containers_svc, "cfg", return_value=value)

    def _assert_renders(self, resp):
        self.assertLess(resp.status_code, 500, resp.text)
        self.assertNotIn("\ud800", json.dumps(resp.json()))

    def _sweep(self, sid: str = "app-7c1a"):
        self._assert_renders(self.client.get("/api/stacks"))
        self._assert_renders(self.client.get(f"/api/compose/{sid}"))
        self._assert_renders(self.client.post(f"/api/compose/{sid}/validate"))
        self._assert_renders(self.client.put(
            f"/api/compose/{sid}",
            content=json.dumps({"content": VALID_COMPOSE + "# e\n", "check": False}),
            headers={"Content-Type": "application/json"},
        ))


class StackReaderSubclassBombHttpTests(_Compose7Sandbox):
    """Subclass-bomb values in the config stack reader never 500 the routes."""

    def test_dict_subclass_cfg_root_with_bombing_get_never_500s(self):
        root = _BombGetDict(
            {"stacks": [{"id": "app-7c1a", "path": str(self.stack_dir)}]}
        )
        with self._with_cfg(root):
            self._sweep()

    def test_int_subclass_id_str_bomb_never_500s(self):
        row = {"id": _BombStrInt(42), "path": str(self.stack_dir)}
        with self._with_cfg({"stacks": [row]}):
            # The id is unrenderable, so the row falls back to the directory
            # name — still fully usable, and never a 500.
            self._assert_renders(self.client.get("/api/stacks"))
            self._sweep()

    def test_int_subclass_name_index_bomb_never_500s(self):
        row = {"id": "app-7c1a", "name": _BombIndexInt(7), "path": str(self.stack_dir)}
        with self._with_cfg({"stacks": [row]}):
            self._sweep()

    def test_float_subclass_name_eq_bomb_never_500s(self):
        row = {"id": "app-7c1a", "name": _BombEqFloat(1.0), "path": str(self.stack_dir)}
        with self._with_cfg({"stacks": [row]}):
            self._sweep()

    def test_float_subclass_id_float_bomb_never_500s(self):
        row = {"id": _BombFloatFloat(1.0), "path": str(self.stack_dir)}
        with self._with_cfg({"stacks": [row]}):
            self._sweep()

    def test_containers_only_int_subclass_id_never_500s(self):
        # The containers-only branch renders the id through the same probe.
        row = {"id": _BombStrInt(7), "containers": ["c1"]}
        with self._with_cfg({"stacks": [row]}):
            self._assert_renders(self.client.get("/api/stacks"))


if __name__ == "__main__":
    unittest.main()
