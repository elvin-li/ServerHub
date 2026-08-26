"""Modules-page leftover sweep #5: nested subclass bombs on GET /api/modules.

Sweep #4 pinned that the ``dict(m)`` copy in ``modules._module_row``
neutralizes a *top-level* dict subclass whose ``items()`` raises — the C
fast path never calls the override.  A fresh hunt over the same mounted
route (create_app + TestClient, raise_server_exceptions=False) found that
the copy is shallow: poison one level down still reached ``_jsonable``'s
bound-method calls and raised out of the handler.  Nine live 500s:

* a nested dict-subclass value whose ``items()`` raises blew the
  ``for k, v in value.items()`` iteration, and one whose ``items()``
  yields 3-tuples blew the same line as an unpack ValueError;
* a list-subclass or set-subclass ``__iter__`` iterbomb blew the
  sequence-arm comprehension;
* an int-subclass ``__str__`` bomb blew the digit-cap str() probe
  (only ValueError was caught);
* a float-subclass ``__eq__``/``__ne__`` bomb blew the NaN probe
  (``value != value``) and the inf tuple-membership probe;
* a bytes- or bytearray-subclass ``decode`` bomb blew the byte-scrub in
  ``_utf8_text`` / ``_jsonable`` — as a value and as a mapping key;
* an object whose ``isoformat`` is a raising property, or whose
  ``__getattr__`` raises for any missing name, blew the
  ``getattr(value, "isoformat", None)`` probe itself — the default only
  swallows AttributeError.

The fix routes every probe through unbound base-type calls
(``dict.items``, ``base.__iter__``, ``int.__index__``,
``float.__float__``, ``bytes``/``bytearray.decode``) and guards the
getattr, so the poison is scrubbed field-level and the real content
survives: the iterbomb's elements still list, the int keeps its number,
the bomb-keyed bytes still decode.

Stays-immune pins ride along for the vectors that were already dead: a
top-level ``get()``/``__bool__``/``keys()`` bomb subclass (the C copy),
a str-subclass ``encode`` bomb (``str()`` of a subclass returns an exact
str), and an over-cap int wearing a ``__str__``-bomb subclass (base
coercion first, then the digit-cap drop).
"""
from __future__ import annotations

import json
import unittest

from fastapi.testclient import TestClient

from hub import modules
from hub.auth import require_auth

#: Built arithmetically: int("9" * 5000) itself trips the digit cap.
_HUGE_INT = 10 ** 5000

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


class _ItemsBomb(dict):
    def items(self):
        raise RuntimeError("items bomb")


class _TriplesItems(dict):
    def items(self):
        return [("a", 1, 2)]  # unpack ValueError in ``for k, v in ...``


class _IterBombList(list):
    def __iter__(self):
        raise RuntimeError("list iter bomb")


class _IterBombSet(set):
    def __iter__(self):
        raise RuntimeError("set iter bomb")


class _StrBombInt(int):
    def __str__(self):
        raise RuntimeError("int str bomb")

    __repr__ = __str__


class _EqBombFloat(float):
    def __eq__(self, other):
        raise RuntimeError("float eq bomb")

    def __ne__(self, other):
        raise RuntimeError("float ne bomb")

    __hash__ = float.__hash__


class _DecodeBombBytes(bytes):
    def decode(self, *args, **kwargs):
        raise RuntimeError("bytes decode bomb")


class _DecodeBombBytearray(bytearray):
    def decode(self, *args, **kwargs):
        raise RuntimeError("bytearray decode bomb")


class _IsoPropertyBomb:
    @property
    def isoformat(self):
        raise RuntimeError("isoformat access bomb")


class _GetattrBomb:
    def __getattr__(self, name):
        raise RuntimeError(f"getattr bomb: {name}")


class _RegistrySandbox(unittest.TestCase):
    def setUp(self):
        self._saved = list(modules.MODULES)
        self.addCleanup(
            lambda: modules.MODULES.__setitem__(slice(None), self._saved)
        )
        self.client = _client()

    def _row(self, **fields) -> dict:
        """Append one dict row, GET the route, return the row back."""
        row = {"id": "x5", "name": "n", "category": "ops",
               "apis": [], "ui_routes": []}
        row.update(fields)
        modules.MODULES.append(row)
        body = self._get_modules()
        return next(r for r in body["modules"] if r.get("id") == "x5")

    def _get_modules(self) -> dict:
        resp = self.client.get("/api/modules")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        return body


class NestedMappingBombTests(_RegistrySandbox):
    """The shallow ``dict(m)`` copy never reached nested mapping poison."""

    def test_nested_items_bomb_is_read_through_the_base_view(self):
        row = self._row(apis=_ItemsBomb(a=1))
        # Unbound dict.items sees the real storage: the entry survives.
        self.assertEqual(row["apis"], {"a": 1})
        self.assertEqual(row["name"], "n")

    def test_nested_items_yielding_triples_cannot_blow_the_unpack(self):
        row = self._row(apis=_TriplesItems(real="kept"))
        self.assertEqual(row["apis"], {"real": "kept"})


class SequenceIterbombTests(_RegistrySandbox):
    """Subclass ``__iter__`` bombs — the elements still list."""

    def test_list_subclass_iterbomb_keeps_its_elements(self):
        row = self._row(apis=_IterBombList(["/api/x", "/api/y"]))
        self.assertEqual(row["apis"], ["/api/x", "/api/y"])

    def test_set_subclass_iterbomb_keeps_its_elements(self):
        row = self._row(apis=_IterBombSet({"/api/x"}))
        self.assertEqual(row["apis"], ["/api/x"])


class NumericSubclassBombTests(_RegistrySandbox):
    """Base coercion first, then the existing digit-cap / NaN-inf probes."""

    def test_int_subclass_str_bomb_keeps_its_number(self):
        row = self._row(apis=[_StrBombInt(3)])
        self.assertEqual(row["apis"], [3])

    def test_overcap_int_wearing_the_bomb_subclass_still_drops(self):
        """Coercion cannot resurrect the unrenderable: past CPython's
        digit cap the value drops exactly like its plain-int sibling."""
        row = self._row(apis=[_StrBombInt(_HUGE_INT), "/api/x"])
        self.assertEqual(row["apis"], [None, "/api/x"])

    def test_float_subclass_eq_bomb_keeps_its_value(self):
        row = self._row(apis=[_EqBombFloat(1.5)], enabled=_EqBombFloat(1.5))
        self.assertEqual(row["apis"], [1.5])
        # Non-bool enabled still reads True — the bomb never reached the probe.
        self.assertIs(row["enabled"], True)

    def test_inf_wearing_the_eq_bomb_subclass_still_drops(self):
        row = self._row(apis=[_EqBombFloat(float("inf")), "/api/x"])
        self.assertEqual(row["apis"], [None, "/api/x"])


class ByteDecodeBombTests(_RegistrySandbox):
    """Subclass ``decode`` bombs — value and mapping-key sides."""

    def test_bytes_decode_bomb_value_still_decodes(self):
        row = self._row(name=_DecodeBombBytes(b"panel"))
        self.assertEqual(row["name"], "panel")

    def test_bytearray_decode_bomb_value_still_decodes(self):
        row = self._row(name=_DecodeBombBytearray(b"panel\xff"))
        self.assertEqual(row["name"], "panel\ufffd")

    def test_bytes_decode_bomb_key_still_decodes(self):
        modules.MODULES.append({
            "id": "bk", "name": "n", "category": "ops",
            _DecodeBombBytes(b"extra"): "kept", "apis": [], "ui_routes": [],
        })
        body = self._get_modules()
        row = next(r for r in body["modules"] if r.get("id") == "bk")
        self.assertEqual(row["extra"], "kept")


class IsoformatProbeBombTests(_RegistrySandbox):
    """The getattr default only swallows AttributeError — both bombs pinned."""

    def test_isoformat_property_bomb_falls_back_to_text(self):
        row = self._row(apis=[_IsoPropertyBomb(), "/api/x"])
        self.assertIn("/api/x", row["apis"])
        # The object itself still renders via its (sane) str().
        self.assertIn("_IsoPropertyBomb", row["apis"][0])

    def test_getattr_bomb_falls_back_to_text(self):
        row = self._row(apis=[_GetattrBomb(), "/api/x"])
        self.assertIn("/api/x", row["apis"])
        self.assertIn("_GetattrBomb", row["apis"][0])


class StaysImmuneTests(_RegistrySandbox):
    """Vectors that were already dead — pinned so a refactor cannot reopen."""

    def test_top_level_subclass_bombs_are_neutralized_by_the_copy(self):
        class TopBomb(dict):
            def get(self, *args, **kwargs):
                raise RuntimeError("get bomb")

            def keys(self):
                raise RuntimeError("keys bomb")

            def __bool__(self):
                raise RuntimeError("bool bomb")

        modules.MODULES.append(
            TopBomb(id="tb", name="n", category="ops", apis=[], ui_routes=[])
        )
        body = self._get_modules()
        row = next(r for r in body["modules"] if r.get("id") == "tb")
        self.assertEqual(row["name"], "n")

    def test_str_subclass_encode_bomb_never_fires(self):
        """``str()`` of a subclass returns an exact str (CPython copies),
        so the UTF-8 scrub never touches the override."""
        class EncodeBomb(str):
            def encode(self, *args, **kwargs):
                raise RuntimeError("encode bomb")

        row = self._row(name=EncodeBomb("pan\ud800el"))
        # Encode-side "replace" substitutes "?" for the lone surrogate.
        self.assertEqual(row["name"], "pan?el")

    def test_poisoned_rows_never_wipe_the_sane_siblings(self):
        sane = len(modules.list_modules())
        modules.MODULES.extend([
            {"id": "p1", "name": "n", "category": "ops",
             "apis": _ItemsBomb(a=1), "ui_routes": []},
            {"id": "p2", "name": "n", "category": _IterBombList(["ops"]),
             "apis": _IterBombSet({"/x"}), "ui_routes": []},
        ])
        body = self._get_modules()
        ids = [r.get("id") for r in body["modules"]]
        self.assertIn("dashboard", ids)
        self.assertIn("p1", ids)
        self.assertIn("p2", ids)
        self.assertEqual(len(ids), sane + 2)
        grouped = sum(len(v) for v in body["by_category"].values())
        self.assertEqual(grouped, sane + 2)


if __name__ == "__main__":
    unittest.main()
