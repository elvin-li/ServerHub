"""Modules-page leftover sweep #8: the ``__class__``-property seam in isinstance.

Sweep #7 dropped ``_module_row``'s ``dict(m)`` pre-copy so a mapping-protocol
bomb can no longer 500 GET /api/modules, and #5/#6 routed every value probe
through unbound base calls.  A fresh hunt over the same mounted route
(create_app + TestClient, raise_server_exceptions=False) found one seam still
open: every gate in the serializer is an ``isinstance`` call, and CPython's
``isinstance`` reads the operand's ``__class__`` whenever the real-type fast
check misses.  A leftover value whose ``__class__`` is a *raising property*
therefore blew the first ``isinstance`` that did not match its real type —
outside any try — and rode out of the unguarded handler as a raw HTTP 500.
Confirmed live before the fix at four ranks:

* a nested value (e.g. in ``apis``) — ``_jsonable``'s ``bool`` gate is the
  first miss and reads ``__class__``;
* a top-level field value (``name``) — same gate, one level up;
* a mapping *key* — ``_jsonable``'s dict arm gates the key on
  ``(bytes, bytearray)`` first;
* a *whole* registry row — ``_module_row``'s ``ModuleInfo`` gate reads it
  before the row is ever serialized, so the bomb wiped the whole response
  (every sibling row with it);
* even a genuine ``dict`` subclass value is caught, because the ``bool``
  gate misses its real type first and reaches for ``__class__``.

The fix wraps the type checks in ``_isinst`` (isinstance in a try, a raise
means "not this type").  A bombing ``__class__`` then falls through to the
text fallback and renders via ``repr`` (which uses the real type, never
``__class__``); the row and every sane sibling keep rendering.

Stays-immune pins ride along for the vector the same hunt found already safe:
a *lying* ``__class__`` (answers ``int`` while the real type is not) is not an
error, so ``_isinst`` still reports the claim and the numeric arm's unbound
``int.__index__`` coercion drops the impostor to ``None`` — exactly as a plain
non-int leftover would.
"""
from __future__ import annotations

import json
import unittest

from fastapi.testclient import TestClient

from hub import modules
from hub.auth import require_auth

_APP = None


def _client() -> TestClient:
    global _APP
    if _APP is None:
        from hub.app_factory import create_app

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _ClassPropBomb:
    """A leftover whose ``__class__`` access raises — isinstance's blind spot."""

    @property
    def __class__(self):
        raise RuntimeError("class access bomb")

    def __hash__(self):  # usable as a mapping key
        return 1


class _DictClassBomb(dict):
    """A real dict subclass whose ``__class__`` still bombs the earlier gate."""

    @property
    def __class__(self):
        raise RuntimeError("dict class access bomb")


class _ClassLie:
    """``__class__`` answers a type it is not — a claim, not an error."""

    @property
    def __class__(self):
        return int


class _RegistrySandbox(unittest.TestCase):
    def setUp(self):
        self._saved = list(modules.MODULES)
        self.addCleanup(
            lambda: modules.MODULES.__setitem__(slice(None), self._saved)
        )
        self.client = _client()

    def _get_modules(self) -> dict:
        resp = self.client.get("/api/modules")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        return body

    def _row(self, **fields) -> dict:
        row = {"id": "x8", "name": "n", "category": "ops",
               "apis": [], "ui_routes": []}
        row.update(fields)
        modules.MODULES.append(row)
        body = self._get_modules()
        row = next(r for r in body["modules"] if r.get("id") == "x8")
        self.assertIn("dashboard", [r.get("id") for r in body["modules"]])
        return row


class ClassPropertyBombTests(_RegistrySandbox):
    """Each vector was a live raw 500 through an ``isinstance`` gate before."""

    def test_nested_value_bomb_keeps_the_row_and_its_siblings(self):
        row = self._row(apis=[_ClassPropBomb(), "/api/x"])
        # The bomb renders via its (real-type) repr; the sane element stays.
        self.assertIn("/api/x", row["apis"])
        self.assertEqual(row["name"], "n")

    def test_top_level_value_bomb_keeps_the_row(self):
        row = self._row(name=_ClassPropBomb())
        self.assertIsInstance(row["name"], str)
        self.assertEqual(row["apis"], [])

    def test_mapping_key_bomb_drops_only_the_entry(self):
        modules.MODULES.append({
            "id": "kb8", "name": "n", "category": "ops",
            _ClassPropBomb(): "kept", "apis": [], "ui_routes": [],
        })
        body = self._get_modules()
        row = next(r for r in body["modules"] if r.get("id") == "kb8")
        self.assertEqual(row["name"], "n")

    def test_dict_subclass_value_bomb_keeps_the_row(self):
        row = self._row(apis=[_DictClassBomb({"a": 1}), "/api/x"])
        self.assertIn("/api/x", row["apis"])

    def test_whole_row_bomb_drops_alone_without_wiping_the_registry(self):
        sane = len(modules.list_modules())
        modules.MODULES.extend([
            _ClassPropBomb(),
            {"id": "sane8", "name": "S", "category": "ops",
             "apis": [], "ui_routes": []},
        ])
        body = self._get_modules()
        ids = [r.get("id") for r in body["modules"]]
        self.assertNotIn("x8", ids)  # the bomb produced no row
        self.assertIn("sane8", ids)
        self.assertIn("dashboard", ids)
        self.assertEqual(len(ids), sane + 1)
        grouped = sum(len(v) for v in body["by_category"].values())
        self.assertEqual(grouped, sane + 1)


class StaysImmuneTests(_RegistrySandbox):
    """A lying ``__class__`` is a claim, not a raise — pinned so ``_isinst``
    keeps honoring it and the numeric-coercion drop stays intact."""

    def test_class_lie_impostor_is_coerced_to_none_not_a_500(self):
        # ``_isinst(x, int)`` believes the ``int`` claim; the unbound
        # ``int.__index__`` coercion then rejects the non-int and drops it.
        row = self._row(apis=[_ClassLie(), "/api/x"])
        self.assertEqual(row["apis"], [None, "/api/x"])


if __name__ == "__main__":
    unittest.main()
