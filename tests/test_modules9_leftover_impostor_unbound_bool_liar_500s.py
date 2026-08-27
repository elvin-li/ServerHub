"""Modules-page leftover sweep #9: lying ``__class__`` impostors escape the
unbound base coercions, and the bool gate trusts ``isinstance`` over ``type``.

Sweep #8 wrapped every serializer type check in ``_isinst`` (``isinstance`` in
a try) so a *raising* ``__class__`` can no longer 500 GET /api/modules, and it
pinned that a *lying* ``__class__`` answering ``int`` is coerced to ``None`` by
the numeric arm's unbound ``int.__index__``.  A fresh hunt over the same
mounted route (create_app + TestClient, raise_server_exceptions=False) found
the lie still had open seams in the *non-numeric* arms:

* the ``bytes``/``bytearray`` arm calls the unbound ``bytes.decode`` /
  ``bytearray.decode`` — a descriptor bound to the real bytes layout, so a
  value whose ``__class__`` answers ``bytes`` (real type is neither) made it
  raise ``TypeError`` outside any try;
* the ``dict`` arm calls the unbound ``dict.items`` — a lie answering
  ``dict`` blew that descriptor, and at *row* rank (``_module_row`` hands a
  ``dict``-claiming leftover straight to ``_jsonable``) it wiped the whole
  registry, not just its own row;
* the ``list``/``tuple``/``set``/``frozenset`` arm calls the unbound
  ``base.__iter__`` — a lie answering any of those blew it too.

Separately, the very first gate returned the value raw whenever
``_isinst(value, bool)`` held.  ``bool`` cannot be subclassed, so any value
that answers that gate while its real type is not ``bool`` is a lying
``__class__`` impostor — handing it back raw fed the ``allow_nan=False``
encoder a non-serializable object, a raw 500 at value rank and as ``enabled``.

The fix mirrors sweep #8's numeric coercion: each unbound base call runs in a
try, a raise means "not really this type" and the impostor drops to ``None``
(the ``bytes``/``dict``/``list`` arms), and the bool gate renders only a
genuine ``type(value) is bool`` and otherwise drops the impostor.  Every sane
sibling — and, at row rank, the entire rest of the registry — keeps rendering.

Each vector below was a live raw 500 (or, for the ``dict`` row case, a full
registry wipe) before the fix.  Stays-immune pins ride along for the neighbours
the same hunt confirmed already safe: a genuine bool still renders true/false,
sweep #8's lying-``int`` coercion still drops to ``None``, and a lying-``float``
impostor is still coerced by the unbound ``float.__float__``.
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


class _Lie:
    """``__class__`` answers a type the object is not — a claim, not a raise.

    ``isinstance`` (so ``_isinst``) honours the claim, but the real object is
    an ordinary ``_Lie`` — none of the unbound base descriptors apply to it.
    """

    def __init__(self, claim):
        self._claim = claim

    @property
    def __class__(self):  # type: ignore[override]
        return self._claim

    def __hash__(self):  # usable as a mapping key
        return 17


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
        row = {"id": "x9", "name": "n", "category": "ops",
               "apis": [], "ui_routes": []}
        row.update(fields)
        modules.MODULES.append(row)
        body = self._get_modules()
        self.assertIn("dashboard", [r.get("id") for r in body["modules"]])
        return next(r for r in body["modules"] if r.get("id") == "x9")


class ImpostorUnboundArmTests(_RegistrySandbox):
    """A lying ``__class__`` that answers a non-numeric container base used to
    blow the arm's unbound base descriptor straight out of the handler."""

    def test_bytes_impostor_nested_value_drops_and_keeps_the_row(self):
        row = self._row(apis=[_Lie(bytes), "/api/x"])
        self.assertEqual(row["apis"], [None, "/api/x"])
        self.assertEqual(row["name"], "n")

    def test_bytearray_impostor_nested_value_drops_and_keeps_the_row(self):
        row = self._row(apis=[_Lie(bytearray), "/api/x"])
        self.assertEqual(row["apis"], [None, "/api/x"])

    def test_dict_impostor_nested_value_drops_and_keeps_the_row(self):
        row = self._row(apis=[_Lie(dict), "/api/x"])
        self.assertEqual(row["apis"], [None, "/api/x"])

    def test_sequence_impostors_nested_value_drop_and_keep_the_row(self):
        for claim in (list, tuple, set, frozenset):
            with self.subTest(claim=claim.__name__):
                row = self._row(apis=[_Lie(claim), "/api/x"])
                self.assertEqual(row["apis"], [None, "/api/x"])
                modules.MODULES[:] = self._saved

    def test_bytes_impostor_mapping_key_drops_only_the_entry(self):
        modules.MODULES.append({
            "id": "kb9", "name": "n", "category": "ops",
            _Lie(bytes): "gone", "keep": "here", "apis": [], "ui_routes": [],
        })
        body = self._get_modules()
        row = next(r for r in body["modules"] if r.get("id") == "kb9")
        self.assertEqual(row["name"], "n")
        self.assertEqual(row["keep"], "here")

    def test_dict_impostor_whole_row_drops_alone_without_wiping_registry(self):
        # ``_module_row`` gates on ``_isinst(m, dict)`` and hands the lie to
        # ``_jsonable`` whole, so the blown ``dict.items`` used to wipe every
        # sibling row too — the worst case, a full registry outage.
        sane = len(modules.list_modules())
        modules.MODULES.extend([
            _Lie(dict),
            {"id": "sane9", "name": "S", "category": "ops",
             "apis": [], "ui_routes": []},
        ])
        body = self._get_modules()
        ids = [r.get("id") for r in body["modules"]]
        self.assertIn("sane9", ids)
        self.assertIn("dashboard", ids)
        self.assertEqual(len(ids), sane + 1)
        grouped = sum(len(v) for v in body["by_category"].values())
        self.assertEqual(grouped, sane + 1)


class BoolLiarTests(_RegistrySandbox):
    """``bool`` is final; a value answering the bool gate that is not a real
    bool is a lying ``__class__`` and used to reach the encoder raw."""

    def test_bool_impostor_nested_value_drops_and_keeps_the_row(self):
        row = self._row(apis=[_Lie(bool), "/api/x"])
        self.assertEqual(row["apis"], [None, "/api/x"])

    def test_bool_impostor_as_enabled_falls_back_to_default_true(self):
        # ``_jsonable`` drops the impostor to ``None``; ``_module_row`` then
        # coerces a non-bool ``enabled`` back to the ``True`` default.
        row = self._row(enabled=_Lie(bool))
        self.assertEqual(row["enabled"], True)


class StaysImmuneTests(_RegistrySandbox):
    """Neighbours the same hunt confirmed already safe — pinned so a refactor
    back toward bound calls or an ``isinstance`` bool gate trips loudly."""

    def test_genuine_bool_values_still_render_true_and_false(self):
        row = self._row(apis=[True, False, "/api/x"])
        self.assertEqual(row["apis"], [True, False, "/api/x"])
        self.assertEqual(row["enabled"], True)

    def test_lying_int_impostor_still_coerced_to_none(self):
        # Sweep #8's guarantee: the unbound ``int.__index__`` rejects the
        # non-int and drops it — must survive alongside the new arms.
        row = self._row(apis=[_Lie(int), "/api/x"])
        self.assertEqual(row["apis"], [None, "/api/x"])

    def test_lying_float_impostor_still_coerced_to_none(self):
        row = self._row(apis=[_Lie(float), "/api/x"])
        self.assertEqual(row["apis"], [None, "/api/x"])


if __name__ == "__main__":
    unittest.main()
