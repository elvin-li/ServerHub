"""Modules-page leftover sweep #14: lying-``__class__`` wrong-rank recovery
and the default ``object.__repr__`` heap-address leaks on GET /api/modules.

Sweep #13 snapshotted both container walks and taught the *sequence* arm to
recover honest storage behind a lying claim.  A fresh hunt over the same
mounted route (create_app + TestClient, raise_server_exceptions=False)
found the same wrong-rank degrade still live at every *other* rank —
``isinstance`` consults ``__class__`` only after the real-MRO check misses,
so a lying claim steered the value into the arm of its claim, the unbound
descriptor there rejected the real layout, and an early ``return`` threw
honest renderable storage away (the files16/notify13 shape):

* **registry rank** — a genuine tuple registry whose ``__class__`` lied
  ``list`` was handed to ``list.__iter__``, rejected, and
  ``_registry_entries`` answered ``[]``: the whole Modules page wiped;
* **row rank** — a genuine dict row claiming ``ModuleInfo`` failed
  ``asdict`` and every ``getattr`` salvage, and the empty-salvage early
  return unlisted a row whose entries the dict arm renders verbatim;
* **value rank** — a genuine str/float claiming ``int`` (and a genuine
  int claiming final ``bool``) dropped to ``None`` off the rejected
  ``int.__index__`` / ``type is bool`` gates; a genuine tuple claiming
  ``dict`` vanished off the rejected ``dict.items``; a genuine dict
  claiming ``bytes`` fell to the both-bases decode rejection; a genuine
  dict claiming ``str`` rendered as its ``str()`` text blob instead of a
  mapping;
* **mapping-key rank** — a genuine str key claiming ``bytes`` failed both
  base decodes and the old ``continue`` dropped an entry whose real key
  text renders fine.

The fix lets every rejected claimed arm fall through to the arm the *real*
storage matches (probed via ``type(value)``, which a lying ``__class__``
property cannot swap); total impostors — a claim with no usable layout
underneath — keep the established drop shapes (``None`` values, dropped
key entries, the empty registry).

Beside the rank bugs, the free-text coercion arms ran ``str()`` on any
leftover shape, and a type that never overrode ``__str__``/``__repr__``
answered the default ``object.__repr__`` — ``<X object at 0x7f…>``, a raw
heap address — which GET /api/modules carried verbatim as field values,
sequence elements and JSON *keys*.  The slot probe on the real type plus
the ``' at 0x…>'`` regex belt (functions and other C-level ``__repr__``
overrides) scrub only the coercion arms; real str/bytes storage is data
and stays verbatim.

Control flow keeps its lane through every new seam, and stays-immune pins
ride along so a refactor trips loudly.
"""
from __future__ import annotations

import json
import unittest

from fastapi.testclient import TestClient

from hub import modules
from hub.modules import ModuleInfo

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
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _lie(base, claim):
    """A genuine ``base`` subclass whose ``__class__`` claims ``claim``."""

    class _Lie(base):
        @property
        def __class__(self):  # type: ignore[override]
            return claim

    return _Lie


class _RegistryTupleLyingList(tuple):
    """Genuine tuple registry storage; ``__class__`` claims ``list``."""

    @property
    def __class__(self):  # type: ignore[override]
        return list


class _DictRowLyingModuleInfo(dict):
    """Genuine dict row storage; ``__class__`` claims ``ModuleInfo``."""

    @property
    def __class__(self):  # type: ignore[override]
        return ModuleInfo


class _TotalImpostor:
    """Claims whatever it is told while carrying no usable layout."""

    def __init__(self, claim):
        self._claim = claim

    @property
    def __class__(self):  # type: ignore[override]
        return self._claim

    def __hash__(self):
        return 14


class _BlankObject:
    """Never overrides ``__str__``/``__repr__`` — the default render is
    ``object.__repr__``, a raw heap address."""


class _BlankKey:
    """Default-render leftover usable as a mapping key."""

    def __hash__(self):
        return 41


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

    def _row(self, body: dict, row_id: str) -> dict:
        return next(r for r in body["modules"] if r.get("id") == row_id)

    def _plant(self, **overrides) -> dict:
        row = {"id": "x14", "name": "n", "category": "ops",
               "apis": [], "ui_routes": []}
        row.update(overrides)
        modules.MODULES = list(self._saved) + [row]
        return self._row(self._get_modules(), overrides.get("id", "x14"))


class WrongRankRecoveryTests(_RegistrySandbox):
    """Honest storage behind a lying ``__class__`` used to vanish at the
    claimed arm; the arm the real layout matches now renders it."""

    def test_tuple_registry_lying_list_keeps_every_row(self):
        # The worst case: ``_registry_entries`` stopped at the claimed
        # base, ``list.__iter__`` rejected the tuple layout, and the
        # whole Modules page wiped to an empty registry.
        modules.MODULES = _RegistryTupleLyingList(
            tuple(self._saved) + (
                {"id": "reg14", "name": "n", "category": "ops",
                 "apis": [], "ui_routes": []},))
        body = self._get_modules()
        ids = [r.get("id") for r in body["modules"]]
        self.assertIn("reg14", ids)
        self.assertIn("dashboard", ids)
        self.assertEqual(len(ids), len(self._saved) + 1)
        grouped = sum(len(v) for v in body["by_category"].values())
        self.assertEqual(grouped, len(self._saved) + 1)

    def test_dict_row_lying_moduleinfo_still_renders_its_entries(self):
        # ``asdict`` and every ``getattr`` salvage reject the dict layout,
        # and the empty-salvage early return unlisted the whole row.
        modules.MODULES = list(self._saved) + [
            _DictRowLyingModuleInfo(
                {"id": "row14", "name": "N", "category": "ops",
                 "apis": ["/api/a"], "ui_routes": []})]
        body = self._get_modules()
        got = self._row(body, "row14")
        self.assertEqual(got["name"], "N")
        self.assertEqual(got["apis"], ["/api/a"])
        self.assertEqual(len(body["modules"]), len(self._saved) + 1)

    def test_str_value_lying_int_keeps_its_text(self):
        got = self._plant(name=_lie(str, int)("hello"))
        self.assertEqual(got["name"], "hello")

    def test_float_value_lying_int_keeps_its_number(self):
        got = self._plant(name=_lie(float, int)(3.5))
        self.assertEqual(got["name"], 3.5)

    def test_int_value_lying_bool_keeps_its_number(self):
        # ``bool`` is final, so the claim is always a lie — but ``bool``
        # subtypes ``int``, and genuine int storage behind the lie used to
        # drop to ``None`` although ``int.__index__`` renders it fine.
        got = self._plant(name=_lie(int, bool)(7))
        self.assertEqual(got["name"], 7)

    def test_tuple_value_lying_dict_keeps_its_elements(self):
        got = self._plant(apis=_lie(tuple, dict)(("/api/a", "/api/b")))
        self.assertEqual(got["apis"], ["/api/a", "/api/b"])

    def test_dict_value_lying_bytes_keeps_its_mapping(self):
        got = self._plant(meta=_lie(dict, bytes)({"a": "b"}))
        self.assertEqual(got["meta"], {"a": "b"})

    def test_dict_value_lying_str_renders_as_mapping_not_text_blob(self):
        # This one degraded a rank sideways instead of down: the str arm
        # rendered the mapping as its ``str()`` text ("{'a': 'b'}").
        got = self._plant(meta=_lie(dict, str)({"a": "b"}))
        self.assertEqual(got["meta"], {"a": "b"})

    def test_str_key_lying_bytes_keeps_the_entry_under_its_real_text(self):
        key = _lie(str, bytes)("realkey")
        modules.MODULES = list(self._saved) + [
            {"id": "k14", "name": "n", "category": "ops",
             key: "kept", "apis": [], "ui_routes": []}]
        body = self._get_modules()
        got = self._row(body, "k14")
        self.assertEqual(got["realkey"], "kept")


class ReprAddressLeakTests(_RegistrySandbox):
    """The free-text coercion arms used to carry the default
    ``object.__repr__`` — a raw heap address — verbatim into the body."""

    def test_default_repr_value_no_longer_leaks_an_address(self):
        got = self._plant(name=_BlankObject())
        # Degrades through the text fallback like before — but to the
        # address-free shape, never ``<X object at 0x7f…>``.
        self.assertEqual(got["name"], "")

    def test_function_element_is_scrubbed_by_the_belt(self):
        # Functions carry a C-level ``__repr__`` override the slot probe
        # cannot see — ``<function <lambda> at 0x…>`` — the regex belt
        # catches the rendered address instead.
        got = self._plant(apis=[lambda: 1, "/api/x"])
        self.assertEqual(got["apis"], ["", "/api/x"])

    def test_default_repr_key_drops_its_entry_without_an_address_key(self):
        modules.MODULES = list(self._saved) + [
            {"id": "rk14", "name": "n", "category": "ops",
             _BlankKey(): "v", "apis": [], "ui_routes": []}]
        body = self._get_modules()
        got = self._row(body, "rk14")
        self.assertEqual(got["name"], "n")
        self.assertNotIn("v", got.values())
        for key in got:
            self.assertNotIn(" at 0x", key)

    def test_whole_body_is_address_free_under_a_leftover_pile(self):
        modules.MODULES = list(self._saved) + [
            {"id": "pile14", "name": _BlankObject(), "category": "ops",
             "apis": [lambda: 1], "ui_routes": [],
             "meta": {"fn": _BlankKey.__hash__, "obj": _BlankObject()}}]
        body = self._get_modules()
        self.assertNotIn(" at 0x", json.dumps(body, ensure_ascii=False))
        # Every sane sibling still renders beside the pile.
        self.assertIn("dashboard", [r.get("id") for r in body["modules"]])

    def test_real_str_storage_stays_verbatim_even_when_it_looks_reprish(self):
        # The scrub is for the coercion arms only: genuine str/bytes
        # storage is data, even when the text resembles an angle-repr.
        text = "<thing at 0xDEADBEEF>"
        got = self._plant(name=text, description=text.encode())
        self.assertEqual(got["name"], text)
        self.assertEqual(got["description"], text)


class TotalImpostorDropShapeTests(_RegistrySandbox):
    """A claim with no usable layout underneath keeps the established
    drops — the fall-through never lets the lie steer the walk twice."""

    def test_value_impostors_still_drop_to_none(self):
        for claim in (bool, int, float, bytes, dict, list):
            with self.subTest(claim=claim.__name__):
                got = self._plant(name=_TotalImpostor(claim))
                self.assertIsNone(got["name"])
                modules.MODULES = self._saved

    def test_registry_impostor_still_fails_closed_to_empty(self):
        modules.MODULES = _TotalImpostor(list)
        body = self._get_modules()
        self.assertEqual(body["modules"], [])
        self.assertEqual(body["by_category"], {})

    def test_row_impostor_lying_moduleinfo_still_drops_alone(self):
        modules.MODULES = list(self._saved) + [
            _TotalImpostor(ModuleInfo),
            {"id": "sane14", "name": "S", "category": "ops",
             "apis": [], "ui_routes": []}]
        body = self._get_modules()
        ids = [r.get("id") for r in body["modules"]]
        self.assertIn("sane14", ids)
        self.assertEqual(len(ids), len(self._saved) + 1)

    def test_key_impostor_lying_bytes_still_drops_only_the_entry(self):
        modules.MODULES = list(self._saved) + [
            {"id": "ki14", "name": "n", "category": "ops",
             _TotalImpostor(bytes): "gone", "keep": "here",
             "apis": [], "ui_routes": []}]
        body = self._get_modules()
        got = self._row(body, "ki14")
        self.assertEqual(got["keep"], "here")
        self.assertNotIn("gone", got.values())


class ControlFlowStillPropagatesTests(_RegistrySandbox):
    """The recovery moves *which arm* renders a value, never whether
    genuine control flow escapes the hooks that run along the way."""

    def test_keyboardinterrupt_from_a_coercion_str_propagates(self):
        class _KIStr:
            def __str__(self):
                raise KeyboardInterrupt

        modules.MODULES = [
            {"id": "ki", "name": _KIStr(), "category": "ops"}]
        with self.assertRaises(KeyboardInterrupt):
            modules.list_modules()

    def test_systemexit_from_a_key_coercion_propagates(self):
        class _SEKey:
            def __hash__(self):
                return 5

            def __str__(self):
                raise SystemExit(3)

        modules.MODULES = [
            {"id": "se", "name": "n", "category": "ops", _SEKey(): "v"}]
        with self.assertRaises(SystemExit):
            modules.list_modules()


class StaysImmuneTests(_RegistrySandbox):
    """Neighbours the same hunt confirmed already safe, pinned so a
    refactor trips loudly."""

    def test_exact_registry_renders_identically(self):
        body = self._get_modules()
        ids = [r.get("id") for r in body["modules"]]
        self.assertIn("dashboard", ids)
        self.assertEqual(len(ids), len(self._saved))
        grouped = sum(len(v) for v in body["by_category"].values())
        self.assertEqual(grouped, len(self._saved))

    def test_bytes_value_lying_str_still_decodes_off_real_storage(self):
        # Already safe on the old code (the ``_utf8_text`` bytes gate reads
        # the real layout first) — pinned beside the new recovery arms.
        got = self._plant(name=_lie(bytes, str)(b"hello"))
        self.assertEqual(got["name"], "hello")

    def test_genuine_bools_and_ints_still_render_raw(self):
        got = self._plant(apis=[True, False, 3, "/api/x"])
        self.assertEqual(got["apis"], [True, False, 3, "/api/x"])
        self.assertIs(got["enabled"], True)

    def test_overridden_str_still_renders_through_the_coercion_arm(self):
        # The slot probe only silences types that *never* render
        # themselves; a leftover with a real ``__str__`` keeps its text.
        class _Renders:
            def __str__(self):
                return "self-rendered"

        got = self._plant(name=_Renders())
        self.assertEqual(got["name"], "self-rendered")

    def test_modules13_raising_class_bomb_still_degrades_in_place(self):
        class _ClassBomb:
            @property
            def __class__(self):  # type: ignore[override]
                raise RuntimeError("class bomb")

        got = self._plant(name=_ClassBomb())
        # Fail-closed gates fall to the text fallback like before — now
        # to the address-free shape.
        self.assertIsInstance(got["name"], str)
        self.assertNotIn(" at 0x", got["name"])


if __name__ == "__main__":
    unittest.main()
