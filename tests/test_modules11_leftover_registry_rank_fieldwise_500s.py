"""Modules-page leftover sweep #11: registry-rank iterator bombs and
field-level salvage for ``ModuleInfo`` rows.

Sweeps #5-#9 hardened every rank *inside* the registry — rows, fields,
nested values, mapping keys, lying/raising ``__class__`` — but the walk
itself still trusted the registry object: ``for m in MODULES`` dispatches
through the *bound* ``__iter__``, one opcode ahead of every guard.  A fresh
hunt over the same mounted route (create_app + TestClient,
raise_server_exceptions=False) found five live raw 500s at that new rank:

* a leftover ``list`` subclass registry whose ``__iter__`` raises — the
  bomb fired before ``_module_row`` ever saw a row and wiped the whole
  response;
* the same subclass answering a generator that yields once then bombs
  mid-walk — the partial output was discarded and the raise rode out raw;
* a ``dict`` subclass and a ``str`` subclass with the same override — the
  for-loop honours any bound ``__iter__``, whatever the container claims;
* a lying ``__class__`` impostor answering ``list`` while its real type
  carries no sequence layout at all.

The fix snapshots the registry off its real C-level storage via the unbound
base ``__iter__`` (the modules5 sequence rule at registry rank): every
genuine row a list/tuple subclass really holds still renders, and an
impostor the descriptor rejects fails *closed* to an empty registry — a
valid 200 body, never a 500.

The same hunt found ``_module_row``'s ``asdict`` arm degrading a rank too
coarsely: ``asdict`` walks every dataclass field eagerly (``getattr`` then
``copy.deepcopy``), so one raising property on a leftover ``ModuleInfo``
subclass — or one nested ``__reduce_ex__``/``__deepcopy__`` bomb inside
``apis`` — dropped the *whole* row even though every sibling field was
sane.  Not a 500, but the opposite of field-level degrade.  The salvage arm
now pulls each declared field individually inside its own try; the bombed
field vanishes alone, ``_jsonable`` sanitizes the survivors, and a lying
``ModuleInfo`` impostor (no declared fields at all) still drops whole
exactly as before.

Stays-immune pins ride along: an exact-list registry and genuine
``ModuleInfo`` rows render identically, and the modules8/9 in-row bombs
stay closed alongside the new registry-rank guard.
"""
from __future__ import annotations

import json
import unittest

from fastapi.testclient import TestClient

from hub import modules
from hub.auth import require_auth
from hub.modules import ModuleInfo

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


class _BoomIterList(list):
    """A leftover list subclass whose bound ``__iter__`` raises."""

    def __iter__(self):
        raise RuntimeError("registry iter bomb")


class _MidwalkList(list):
    """Bound ``__iter__`` answers a generator that bombs after one row."""

    def __iter__(self):
        def gen():
            yield {"id": "midwalk", "name": "n", "category": "ops",
                   "apis": [], "ui_routes": []}
            raise RuntimeError("registry midwalk bomb")
        return gen()


class _BoomIterTuple(tuple):
    def __iter__(self):
        raise RuntimeError("registry tuple iter bomb")


class _BoomIterDict(dict):
    def __iter__(self):
        raise RuntimeError("registry dict iter bomb")


class _BoomIterStr(str):
    def __iter__(self):
        raise RuntimeError("registry str iter bomb")


class _ListLie:
    """``__class__`` answers ``list`` — a claim, not a raise; the real type
    has no sequence storage the unbound descriptor could read."""

    @property
    def __class__(self):  # type: ignore[override]
        return list


class _ModuleInfoLie:
    """Claims ``ModuleInfo`` while carrying none of its declared fields."""

    @property
    def __class__(self):  # type: ignore[override]
        return ModuleInfo


class _FieldPropBombInfo(ModuleInfo):
    """A real ``ModuleInfo`` subclass with one raising field property."""

    @property
    def description(self):  # type: ignore[override]
        raise RuntimeError("field property bomb")


def _field_bomb_row() -> _FieldPropBombInfo:
    # The raising property has no setter, so bypass the dataclass __init__.
    row = object.__new__(_FieldPropBombInfo)
    row.id = "fb11"
    row.name = "FB"
    row.category = "ops"
    row.apis = ["/api/x"]
    row.ui_routes = []
    row.inspired_by = []
    row.enabled = True
    return row


class _DeepcopyBomb:
    """Blows ``asdict``'s ``copy.deepcopy`` however copy reaches for it."""

    def __reduce_ex__(self, proto):
        raise RuntimeError("reduce bomb")

    def __deepcopy__(self, memo):
        raise RuntimeError("deepcopy bomb")

    def __str__(self):
        return "dcb"


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


class RegistryRankIterBombTests(_RegistrySandbox):
    """Each vector was a live raw 500 wiping the whole response before the
    unbound registry snapshot landed."""

    def test_list_subclass_iter_bomb_keeps_every_real_row(self):
        modules.MODULES = _BoomIterList(self._saved)
        body = self._get_modules()
        ids = [r.get("id") for r in body["modules"]]
        self.assertIn("dashboard", ids)
        self.assertEqual(len(ids), len(self._saved))
        grouped = sum(len(v) for v in body["by_category"].values())
        self.assertEqual(grouped, len(self._saved))

    def test_list_subclass_midwalk_generator_bomb_reads_real_storage(self):
        # The bound generator yields a decoy row then raises; the unbound
        # walk never runs it — only the real storage (the saved registry)
        # renders, and nothing 500s.
        modules.MODULES = _MidwalkList(self._saved)
        body = self._get_modules()
        ids = [r.get("id") for r in body["modules"]]
        self.assertNotIn("midwalk", ids)
        self.assertIn("dashboard", ids)
        self.assertEqual(len(ids), len(self._saved))

    def test_tuple_subclass_iter_bomb_keeps_every_real_row(self):
        modules.MODULES = _BoomIterTuple(self._saved)
        body = self._get_modules()
        ids = [r.get("id") for r in body["modules"]]
        self.assertIn("dashboard", ids)
        self.assertEqual(len(ids), len(self._saved))

    def test_dict_subclass_registry_fails_closed_to_empty_not_500(self):
        modules.MODULES = _BoomIterDict()
        body = self._get_modules()
        self.assertEqual(body["modules"], [])
        self.assertEqual(body["by_category"], {})

    def test_str_subclass_registry_fails_closed_to_empty_not_500(self):
        modules.MODULES = _BoomIterStr("abc")
        body = self._get_modules()
        self.assertEqual(body["modules"], [])
        self.assertEqual(body["by_category"], {})

    def test_lying_class_list_impostor_fails_closed_to_empty_not_500(self):
        modules.MODULES = _ListLie()
        body = self._get_modules()
        self.assertEqual(body["modules"], [])
        self.assertEqual(body["by_category"], {})


class FieldLevelSalvageTests(_RegistrySandbox):
    """One bombed field used to drop the whole ``ModuleInfo`` row; now it
    vanishes alone and every sane sibling field still renders."""

    def test_raising_field_property_drops_only_that_field(self):
        modules.MODULES = list(self._saved) + [_field_bomb_row()]
        body = self._get_modules()
        row = next(r for r in body["modules"] if r.get("id") == "fb11")
        self.assertEqual(row["name"], "FB")
        self.assertEqual(row["apis"], ["/api/x"])
        self.assertNotIn("description", row)
        # _module_row's defaults still apply to the salvaged row.
        self.assertEqual(row["category"], "ops")
        self.assertIs(row["enabled"], True)

    def test_deepcopy_bomb_nested_in_apis_keeps_the_row(self):
        mi = ModuleInfo(id="dc11", name="DC", description="d",
                        category="ops", apis=[_DeepcopyBomb(), "/api/x"])
        modules.MODULES = list(self._saved) + [mi]
        body = self._get_modules()
        row = next(r for r in body["modules"] if r.get("id") == "dc11")
        self.assertEqual(row["name"], "DC")
        # The salvage hands _jsonable the raw list; the bomb renders via
        # the text fallback and the sane element survives beside it.
        self.assertEqual(row["apis"], ["dcb", "/api/x"])
        self.assertEqual(row["description"], "d")

    def test_lying_moduleinfo_impostor_still_drops_whole_without_wiping(self):
        # No declared field survives the salvage, so the impostor drops
        # exactly as before — and never takes a sibling row with it.
        modules.MODULES = list(self._saved) + [
            _ModuleInfoLie(),
            {"id": "sane11", "name": "S", "category": "ops",
             "apis": [], "ui_routes": []},
        ]
        body = self._get_modules()
        ids = [r.get("id") for r in body["modules"]]
        self.assertIn("sane11", ids)
        self.assertIn("dashboard", ids)
        self.assertEqual(len(ids), len(self._saved) + 1)


class StaysImmuneTests(_RegistrySandbox):
    """Neighbours the same hunt confirmed already safe — pinned so a
    refactor back toward the bound walk trips loudly."""

    def test_exact_list_registry_renders_identically(self):
        body = self._get_modules()
        ids = [r.get("id") for r in body["modules"]]
        self.assertIn("dashboard", ids)
        self.assertEqual(len(ids), len(self._saved))

    def test_genuine_moduleinfo_still_renders_all_fields(self):
        mi = ModuleInfo(id="ok11", name="OK", description="d",
                        category="ops", apis=["/api/x"])
        modules.MODULES = list(self._saved) + [mi]
        body = self._get_modules()
        row = next(r for r in body["modules"] if r.get("id") == "ok11")
        self.assertEqual(row["description"], "d")
        self.assertEqual(row["apis"], ["/api/x"])
        self.assertIs(row["enabled"], True)

    def test_in_row_bombs_stay_closed_alongside_registry_guard(self):
        # modules8/9 coverage must survive the new snapshot: a raising
        # __class__ row drops alone even when the registry is a subclass.
        class _ClassPropBomb:
            @property
            def __class__(self):
                raise RuntimeError("class access bomb")

        modules.MODULES = _BoomIterList(
            list(self._saved) + [
                _ClassPropBomb(),
                {"id": "sane11b", "name": "S", "category": "ops",
                 "apis": [], "ui_routes": []},
            ]
        )
        body = self._get_modules()
        ids = [r.get("id") for r in body["modules"]]
        self.assertIn("sane11b", ids)
        self.assertIn("dashboard", ids)
        self.assertEqual(len(ids), len(self._saved) + 1)


if __name__ == "__main__":
    unittest.main()
