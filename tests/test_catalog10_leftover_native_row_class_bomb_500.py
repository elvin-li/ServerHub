"""Tenth leftover-500s sweep of the Apps catalog surface: one live 500.

The live leftover
=================
``catalog.catalog_overview`` (the GET /api/catalog store overview) merges the
*native* catalog's rows — another module's payload — into its response.  The
row filter that gates that merge was a bare ``isinstance(a, dict)``:

    native = [
        row for row in (_jsonable(a) for a in native if isinstance(a, dict))
        if isinstance(row, dict)
    ]

CPython's ``isinstance`` reads the operand's ``__class__`` whenever the
real-type fast check misses, so a single leftover row whose ``__class__`` is a
raising property detonated that gate *before* ``_jsonable`` could launder
anything — the whole store overview 500'd on one poisoned row, reproduced over
``create_app()`` + ``TestClient(raise_server_exceptions=False)``.  Every other
value bomb the native listing can carry (``.get`` / ``__bool__`` / ``__str__``
/ lone-surrogate / huge-int) was already defused by ``_jsonable`` — this
``__class__``-property bomb was the one shape that raised *at the gate*, the
same class the account8/jobs sweeps sealed with a ``_isinst`` helper.

The fix routes both merge gates through ``catalog._isinst`` (the jobs/auth
rule: ``isinstance`` wrapped so a ``__class__`` bomb answers False instead of
raising).  The poisoned row is dropped; its native siblings and the entire
docker half of the store survive.  A *lying* ``__class__`` (one that answers
``dict``) is not an error and still reports its claim, so ``_jsonable`` copies
it through the C-level storage exactly as before.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import catalog, catalog_remote, native_catalog  # noqa: E402
from hub.routers import catalog as catalog_router  # noqa: E402

_app = None
_client = None


def _the_client():
    """One app for the module: create_app() is expensive and stateless here."""
    global _app, _client
    if _client is None:
        from fastapi.testclient import TestClient

        from hub.app_factory import create_app
        from hub.auth import require_auth

        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
        _client = TestClient(_app, raise_server_exceptions=False)
    return _client


class _ClassBomb:
    """``__class__`` is a raising property: the bare isinstance gate's kryptonite."""

    @property
    def __class__(self):  # noqa: A003
        raise RuntimeError("class bomb")


class _LyingDict(dict):
    """A real dict whose ``__class__`` lies (answers ``dict``): not an error."""

    @property
    def __class__(self):  # noqa: A003
        return dict


class _BoolBombRow:
    """Not a mapping at all, and ``__bool__`` raises: dropped by the gate."""

    def __bool__(self):
        raise RuntimeError("bool bomb")


class _CatalogSandbox(unittest.TestCase):
    """Template dir + services root + remote dir in a per-test temp tree."""

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        tmp = Path(self._tmp.name)
        self.templates = tmp / "templates"
        self.templates.mkdir()
        self.services = tmp / "services"
        self.services.mkdir()
        self.remote_dir = tmp / "catalog-remote"
        self.remote_dir.mkdir()
        # One shipped docker template so the docker half is non-empty and its
        # survival is observable when a native row is poisoned.
        (self.templates / "app.yml").write_text(
            "---\nname: App\ndesc: d\n---\nservices:\n  a:\n    image: x\n",
            encoding="utf-8",
        )
        catalog.invalidate_listing()
        self.addCleanup(catalog.invalidate_listing)
        for module, name, value in (
            (catalog, "TEMPLATES", self.templates),
            (catalog, "SERVICES_ROOT", self.services),
            (catalog_remote, "REMOTE_DIR", self.remote_dir),
            (catalog_remote, "STATE_PATH", self.remote_dir / "state.json"),
        ):
            self.stack.enter_context(mock.patch.object(module, name, value))
        self.client = _the_client()

    def _store(self, native_rows):
        def fake_list(force=False):
            return native_rows

        with mock.patch.object(native_catalog, "list_native_apps", fake_list):
            catalog.invalidate_listing()
            return self.client.get("/api/catalog")


_GOOD_NATIVE = {
    "id": "native-x",
    "name": "X",
    "kind": "native",
    "installed": False,
    "featured": False,
}


class NativeRowClassBombTests(_CatalogSandbox):
    """GET /api/catalog drops a ``__class__``-bomb native row, keeps siblings."""

    def test_class_bomb_row_no_longer_500s(self):
        resp = self._store([_GOOD_NATIVE, _ClassBomb()])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        resp.content.decode("utf-8")
        body = resp.json()
        native_ids = [t["id"] for t in body["templates"] if t.get("kind") == "native"]
        self.assertEqual(native_ids, ["native-x"])
        # The whole docker half survives the poisoned native row.
        docker_ids = [t["id"] for t in body["templates"] if t.get("kind") == "docker"]
        self.assertIn("app", docker_ids)
        self.assertEqual(body["native_count"], 1)

    def test_class_bomb_as_the_only_native_row(self):
        resp = self._store([_ClassBomb()])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertEqual(body["native_count"], 0)
        self.assertIn("app", [t["id"] for t in body["templates"]])

    def test_non_dict_bool_bomb_row_is_dropped(self):
        # Real type is not a dict, so the gate answers False (never touching
        # __bool__): the row is skipped, the store stays 200.
        resp = self._store([_GOOD_NATIVE, _BoolBombRow()])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["native_count"], 1)

    def test_lying_class_dict_row_is_kept_and_laundered(self):
        # A real dict whose __class__ answers ``dict`` is not an error: it is
        # accepted and copied through _jsonable's C-level storage.
        row = _LyingDict(_GOOD_NATIVE)
        resp = self._store([row])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertEqual(
            [t["id"] for t in body["templates"] if t.get("kind") == "native"],
            ["native-x"],
        )

    def test_control_clean_native_row_present(self):
        resp = self._store([_GOOD_NATIVE])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["native_count"], 1)


class IsInstHelperTests(unittest.TestCase):
    """catalog._isinst: the jobs/auth rule, unit-pinned."""

    def test_class_bomb_answers_false_not_raise(self):
        self.assertFalse(catalog._isinst(_ClassBomb(), dict))

    def test_lying_class_still_reports_its_claim(self):
        self.assertTrue(catalog._isinst(_LyingDict({}), dict))

    def test_ordinary_values_unchanged(self):
        self.assertTrue(catalog._isinst({}, dict))
        self.assertFalse(catalog._isinst("x", dict))
        self.assertTrue(catalog._isinst(5, int))


if __name__ == "__main__":
    unittest.main()
