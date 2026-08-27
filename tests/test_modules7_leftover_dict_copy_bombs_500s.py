"""Modules-page leftover sweep #7: the row pre-copy's mapping-protocol seam.

Sweep #5 moved ``_jsonable``'s dict arm to the unbound ``dict.items`` view
and #6 sealed the self-``__str__`` encode bombs, but ``_module_row`` still
funneled every dict registry row through ``row = dict(m)`` first.  That
constructor only takes CPython's fast storage copy when the operand's
``tp_iter`` is the stock dict iterator; a subclass that overrides
``__iter__`` is diverted to the generic mapping path — ``keys()`` then
``__getitem__`` per key — running the subclass's own methods outside any
try.  Confirmed against the mounted route (create_app + TestClient,
raise_server_exceptions=False) — each of these was a raw HTTP 500 before
the fix:

* a row whose ``keys()`` raises (with ``__iter__`` overridden, so the
  slow merge path is taken);
* a row whose ``__getitem__`` raises — the slow path reads every value
  through it;
* a row whose ``keys()`` returns a non-iterable — ``PyMapping_Keys``'s
  result blows up the merge loop.

The fix drops the pre-copy: ``_module_row`` hands the mapping straight to
``_jsonable``, whose dict arm already copies via unbound ``dict.items``
off the real storage, so the genuine fields survive and every sibling row
keeps rendering.

Stays-immune pins ride along for the neighbouring protocol slots the same
hunt found already safe — ``__iter__``-only, ``get``, ``items``,
``__bool__`` and ``__len__`` bombs at row rank (the unbound view never
consults them), plus a nested keys/getitem-bomb mapping value.
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


class KeysBomb(dict):
    """Overridden ``__iter__`` forces the slow merge; ``keys()`` bombs."""

    def __iter__(self):
        return dict.__iter__(self)

    def keys(self):
        raise RuntimeError("keys bomb")


class GetItemBomb(dict):
    """Slow merge reads every value through ``__getitem__``."""

    def __iter__(self):
        return dict.__iter__(self)

    def __getitem__(self, key):
        raise RuntimeError("getitem bomb")


class JunkKeys(dict):
    """``keys()`` answers a non-iterable — the merge loop used to raise."""

    def __iter__(self):
        return dict.__iter__(self)

    def keys(self):
        return 7


class IterBomb(dict):
    def __iter__(self):
        raise RuntimeError("iter bomb")


class GetBomb(dict):
    def get(self, *args):
        raise RuntimeError("get bomb")


class ItemsBomb(dict):
    def items(self):
        raise RuntimeError("items bomb")


class BoolBomb(dict):
    def __bool__(self):
        raise RuntimeError("bool bomb")


class LenBomb(dict):
    def __len__(self):
        raise RuntimeError("len bomb")


def _base_row(row_id: str) -> dict:
    return {"id": row_id, "name": "n", "category": "ops",
            "apis": ["/api/x"], "ui_routes": []}


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

    def _poisoned_row(self, cls, row_id: str) -> dict:
        modules.MODULES.append(cls(_base_row(row_id)))
        body = self._get_modules()
        ids = [r.get("id") for r in body["modules"]]
        self.assertIn("dashboard", ids, "sane siblings must survive")
        row = next(r for r in body["modules"] if r.get("id") == row_id)
        self.assertIn(
            row_id,
            [r.get("id") for r in body["by_category"].get("ops", [])],
        )
        return row


class DictCopyBombTests(_RegistrySandbox):
    """Each subclass was a live raw 500 through ``dict(m)`` before the fix."""

    def test_keys_bomb_row_survives_with_its_real_fields(self):
        row = self._poisoned_row(KeysBomb, "kb7")
        self.assertEqual(row["name"], "n")
        self.assertEqual(row["apis"], ["/api/x"])

    def test_getitem_bomb_row_survives_with_its_real_fields(self):
        row = self._poisoned_row(GetItemBomb, "gib7")
        self.assertEqual(row["name"], "n")
        self.assertEqual(row["apis"], ["/api/x"])

    def test_junk_keys_row_survives_with_its_real_fields(self):
        row = self._poisoned_row(JunkKeys, "jk7")
        self.assertEqual(row["name"], "n")

    def test_all_three_at_once_never_wipe_the_registry(self):
        sane = len(modules.list_modules())
        modules.MODULES.extend([
            KeysBomb(_base_row("kb7")),
            GetItemBomb(_base_row("gib7")),
            JunkKeys(_base_row("jk7")),
        ])
        body = self._get_modules()
        ids = [r.get("id") for r in body["modules"]]
        self.assertEqual(len(ids), sane + 3)
        for row_id in ("dashboard", "kb7", "gib7", "jk7"):
            self.assertIn(row_id, ids)
        grouped = sum(len(v) for v in body["by_category"].values())
        self.assertEqual(grouped, sane + 3)


class StaysImmuneTests(_RegistrySandbox):
    """Protocol slots the unbound view never consults — pinned so a future
    refactor back toward bound calls trips loudly."""

    def test_iter_only_bomb_row_takes_the_fast_copy(self):
        # Stock ``keys``/``__getitem__`` keep ``dict.items`` untouched by
        # the override; only the iterator slot is poisoned.
        row = self._poisoned_row(IterBomb, "ib7")
        self.assertEqual(row["name"], "n")

    def test_get_items_bool_len_bomb_rows_survive(self):
        for cls, row_id in ((GetBomb, "gb7"), (ItemsBomb, "itb7"),
                            (BoolBomb, "bb7"), (LenBomb, "lb7")):
            with self.subTest(cls=cls.__name__):
                row = self._poisoned_row(cls, row_id)
                self.assertEqual(row["name"], "n")

    def test_nested_mapping_bombs_keep_the_row_and_the_value(self):
        modules.MODULES.append({
            **_base_row("nm7"),
            "extra_a": KeysBomb({"a": 1}),
            "extra_b": GetItemBomb({"b": 2}),
        })
        body = self._get_modules()
        row = next(r for r in body["modules"] if r.get("id") == "nm7")
        self.assertEqual(row["extra_a"], {"a": 1})
        self.assertEqual(row["extra_b"], {"b": 2})


if __name__ == "__main__":
    unittest.main()
