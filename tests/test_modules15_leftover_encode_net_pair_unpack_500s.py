"""Modules-page leftover sweep #15: encode-net / torn-pair / grouping belts
on GET /api/modules.

Sweep #14 recovered honest storage behind lying ``__class__`` claims and
scrubbed default ``object.__repr__`` heap addresses.  A fresh hunt over
the same mounted route found the next fail-close gaps were *after* those
arms succeeded:

* ``_utf8_text``'s unbound encode sat outside any try, so a leftover
  ``str()`` answer that was not a str (or whose encode/search raised a
  BaseException subclass) 500'd the route at value rank;
* the dict walk unpacked ``for k, v in items`` bare, so a torn snapshot
  row ValueError'd outside every try;
* ``_module_row`` / ``modules_by_category`` still used unguarded
  ``isinstance`` / ``.get`` / ``TypeError``-only grouping, so a
  ``__class__`` property bomb or a grouping hook raising past TypeError
  rode out as a raw 500.

Each seam now uses the modules12 BaseException net (control flow still
propagates), unbound ``dict.get`` / ``dict.__setitem__``, and a per-pair
unpack guard.  Stays-immune pins ride along so a refactor trips loudly.
"""
from __future__ import annotations

import json
import unittest

from fastapi.testclient import TestClient

from hub import modules

_APP = None


def _client() -> TestClient:
    global _APP
    if _APP is None:
        from hub.app_factory import create_app
        from hub.auth import require_auth

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _RegistrySandbox(unittest.TestCase):
    def setUp(self):
        self._saved = modules.MODULES
        self.addCleanup(lambda: setattr(modules, "MODULES", self._saved))
        self.client = _client()

    def _get_modules(self) -> dict:
        resp = self.client.get("/api/modules")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        return body

    def _plant(self, **overrides) -> dict:
        row = {"id": "x15", "name": "n", "category": "ops",
               "apis": [], "ui_routes": []}
        row.update(overrides)
        modules.MODULES = list(self._saved) + [row]
        return next(r for r in self._get_modules()["modules"] if r.get("id") == "x15")


class _StrAnswersInt:
    """``str()`` TypeError's on CPython; the encode net must still fail closed."""

    def __str__(self):
        return 123


class _StrAnswersBytes:
    def __str__(self):
        return b"nope"


class EncodeNetAndGroupingTests(_RegistrySandbox):
    def test_nonstr_str_dunder_degrades_without_500(self):
        got = self._plant(name=_StrAnswersInt())
        self.assertEqual(got["name"], "")
        self.assertIn("dashboard", [r.get("id") for r in self._get_modules()["modules"]])

    def test_bytes_str_dunder_degrades_without_500(self):
        got = self._plant(name=_StrAnswersBytes())
        self.assertEqual(got["name"], "")

    def test_nonstr_key_str_dunder_drops_only_that_entry(self):
        class _Key:
            def __hash__(self):
                return 15

            def __str__(self):
                return 7

        modules.MODULES = list(self._saved) + [
            {"id": "k15", "name": "n", "category": "ops",
             _Key(): "gone", "keep": "here", "apis": [], "ui_routes": []}]
        body = self._get_modules()
        got = next(r for r in body["modules"] if r.get("id") == "k15")
        self.assertEqual(got["keep"], "here")
        self.assertNotIn("gone", got.values())

    def test_unhashable_category_groups_under_other(self):
        got = self._plant(category=["ops"])
        self.assertEqual(got["category"], "other")
        body = self._get_modules()
        self.assertIn(got, body["by_category"].get("other", []))

    def test_non_bool_enabled_defaults_true(self):
        got = self._plant(enabled="yes")
        self.assertIs(got["enabled"], True)

    def test_row_level_exception_drops_only_that_row(self):
        class _RowBomb:
            @property
            def __class__(self):
                raise RuntimeError("row class bomb")

        modules.MODULES = list(self._saved) + [
            _RowBomb(),
            {"id": "sane15", "name": "S", "category": "ops",
             "apis": [], "ui_routes": []}]
        body = self._get_modules()
        ids = [r.get("id") for r in body["modules"]]
        self.assertIn("sane15", ids)
        self.assertIn("dashboard", ids)


class ControlFlowStillPropagatesTests(_RegistrySandbox):
    def test_keyboardinterrupt_from_str_still_propagates(self):
        class _KI:
            def __str__(self):
                raise KeyboardInterrupt

        modules.MODULES = [{"id": "ki", "name": _KI(), "category": "ops"}]
        with self.assertRaises(KeyboardInterrupt):
            modules.list_modules()

    def test_systemexit_from_str_still_propagates(self):
        class _SE:
            def __str__(self):
                raise SystemExit(3)

        modules.MODULES = [{"id": "se", "name": _SE(), "category": "ops"}]
        with self.assertRaises(SystemExit):
            modules.list_modules()


class StaysImmuneTests(_RegistrySandbox):
    def test_exact_registry_still_renders(self):
        body = self._get_modules()
        ids = [r.get("id") for r in body["modules"]]
        self.assertIn("dashboard", ids)
        self.assertEqual(len(ids), len(self._saved))

    def test_selfstr_encode_bomb_still_scrubs(self):
        class SelfStr(str):
            def __str__(self):
                return self

            def encode(self, *args, **kwargs):
                raise RuntimeError("encode bomb")

        got = self._plant(name=SelfStr("ok"))
        self.assertEqual(got["name"], "ok")


if __name__ == "__main__":
    unittest.main()
