"""Modules-page leftover sweep #12: BaseException-shaped bombs and the
claimed-base decode fidelity gap on GET /api/modules.

Sweeps #5-#11 sealed every rank of the registry serializer against bombs
that raise ``Exception`` — but every one of those guards stopped at
``except Exception``.  A fresh hunt over the same mounted route
(create_app + TestClient, raise_server_exceptions=False) re-armed the
already-sealed vectors with a *BaseException* subclass (the shape a
watchdog/timeout-style leftover raises) and found six of them live again
as raw 500s:

* a row whose ``__class__`` property raises BaseException — past
  ``_isinst``'s catch and out of every isinstance gate at once;
* a leftover ``ModuleInfo`` subclass field property with the same raise —
  past both the ``asdict`` try and the field-level salvage try;
* a nested ``__reduce_ex__`` bomb inside ``apis`` with the same raise —
  ``asdict``'s deepcopy blew past the salvage arm entirely;
* a value ``__str__`` bomb — past ``_utf8_text``'s catch at value, nested
  and mapping-key rank;
* an ``isoformat()`` bomb and a ``__getattr__`` bomb on the isoformat
  probe — past both tries in ``_jsonable``'s tail.

The launder reaches every swallow site down to ``except BaseException``
while re-raising genuine control flow (``KeyboardInterrupt``,
``SystemExit``) untouched: a leftover data bomb can no longer 500 the
route, and a real Ctrl-C or interpreter shutdown still propagates.

The same hunt found ``_decode_bytes`` degrading a rank too coarsely: it
picked the decode base off the *claimed* ``__class__``, so a genuine
``bytearray`` whose ``__class__`` lied ``bytes`` was handed to
``bytes.decode``, rejected by the descriptor, and its perfectly decodable
content vanished to ``None``.  Not a 500, but the wrong degrade rank.
Both base decodes are now tried against the real storage: the honest
layout wins and the content survives; a total impostor (real type is
neither) still fails both and drops exactly as before.

Stays-immune pins ride along: the unbound-descriptor seams (registry
snapshot, ``dict.items``, sequence iteration) never execute subclass code,
so a bound BaseException override there stays inert, and the modules11
Exception-shaped bombs stay closed beside the new guards.
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


class _Watchdog(BaseException):
    """A leftover raise that is BaseException-shaped but *not* Exception."""


class _ClassBaseBomb:
    """``__class__`` property raises a BaseException subclass."""

    @property
    def __class__(self):  # type: ignore[override]
        raise _Watchdog("class access bomb")


class _FieldBaseBombInfo(ModuleInfo):
    """A real ``ModuleInfo`` subclass with one BaseException field property."""

    @property
    def description(self):  # type: ignore[override]
        raise _Watchdog("field property bomb")


def _field_bomb_row() -> _FieldBaseBombInfo:
    # The raising property has no setter, so bypass the dataclass __init__.
    row = object.__new__(_FieldBaseBombInfo)
    row.id = "fb12"
    row.name = "FB"
    row.category = "ops"
    row.apis = ["/api/x"]
    row.ui_routes = []
    row.inspired_by = []
    row.enabled = True
    return row


class _ReduceBaseBomb:
    """Blows ``asdict``'s deepcopy with a BaseException subclass."""

    def __reduce_ex__(self, proto):
        raise _Watchdog("reduce bomb")

    def __deepcopy__(self, memo):
        raise _Watchdog("deepcopy bomb")

    def __str__(self):
        return "rbb"


class _StrBaseBomb:
    def __str__(self):
        raise _Watchdog("str bomb")


class _IsoBaseBomb:
    def isoformat(self):
        raise _Watchdog("isoformat bomb")


class _GetattrBaseBomb:
    def __getattr__(self, name):
        raise _Watchdog("getattr probe bomb")


class _ByteArrayLyingBytes(bytearray):
    """Genuine bytearray storage; ``__class__`` claims ``bytes``."""

    @property
    def __class__(self):  # type: ignore[override]
        return bytes


class _BytesImpostor:
    """Claims ``bytes`` while carrying neither bytes-like layout."""

    @property
    def __class__(self):  # type: ignore[override]
        return bytes


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


class BaseExceptionBombTests(_RegistrySandbox):
    """Each vector was a live raw 500 before the guards reached past
    ``Exception`` — the same ranks modules8/11 sealed, re-armed."""

    def test_row_class_property_baseexception_drops_row_alone(self):
        modules.MODULES = list(self._saved) + [
            _ClassBaseBomb(),
            {"id": "sane12", "name": "S", "category": "ops",
             "apis": [], "ui_routes": []},
        ]
        body = self._get_modules()
        ids = [r.get("id") for r in body["modules"]]
        self.assertIn("sane12", ids)
        self.assertIn("dashboard", ids)
        self.assertEqual(len(ids), len(self._saved) + 1)

    def test_field_property_baseexception_drops_only_that_field(self):
        modules.MODULES = list(self._saved) + [_field_bomb_row()]
        body = self._get_modules()
        row = next(r for r in body["modules"] if r.get("id") == "fb12")
        self.assertEqual(row["name"], "FB")
        self.assertEqual(row["apis"], ["/api/x"])
        self.assertNotIn("description", row)
        self.assertEqual(row["category"], "ops")
        self.assertIs(row["enabled"], True)

    def test_deepcopy_baseexception_nested_in_apis_keeps_the_row(self):
        mi = ModuleInfo(id="rb12", name="RB", description="d",
                        category="ops", apis=[_ReduceBaseBomb(), "/api/x"])
        modules.MODULES = list(self._saved) + [mi]
        body = self._get_modules()
        row = next(r for r in body["modules"] if r.get("id") == "rb12")
        self.assertEqual(row["name"], "RB")
        # Field salvage hands _jsonable the raw list; the bomb renders via
        # the text fallback and the sane element survives beside it.
        self.assertEqual(row["apis"], ["rbb", "/api/x"])
        self.assertEqual(row["description"], "d")

    def test_str_baseexception_value_degrades_without_500(self):
        modules.MODULES = list(self._saved) + [
            {"id": "sb12", "name": _StrBaseBomb(), "category": "ops",
             "apis": [], "ui_routes": []},
        ]
        body = self._get_modules()
        row = next(r for r in body["modules"] if r.get("id") == "sb12")
        # _utf8_text fails closed to "" for the bombed value; siblings keep.
        self.assertEqual(row["name"], "")
        self.assertEqual(row["category"], "ops")

    def test_str_baseexception_mapping_key_drops_entry_alone(self):
        modules.MODULES = list(self._saved) + [
            {"id": "kb12", "name": "K", "category": "ops",
             _StrBaseBomb(): "junk", "apis": [], "ui_routes": []},
        ]
        body = self._get_modules()
        row = next(r for r in body["modules"] if r.get("id") == "kb12")
        self.assertEqual(row["name"], "K")
        self.assertNotIn("junk", row.values())

    def test_isoformat_baseexception_falls_to_text_without_500(self):
        modules.MODULES = list(self._saved) + [
            {"id": "ib12", "name": "I", "category": "ops",
             "apis": [_IsoBaseBomb()], "ui_routes": []},
        ]
        body = self._get_modules()
        row = next(r for r in body["modules"] if r.get("id") == "ib12")
        self.assertEqual(len(row["apis"]), 1)
        self.assertIsInstance(row["apis"][0], str)

    def test_getattr_baseexception_on_isoformat_probe_without_500(self):
        modules.MODULES = list(self._saved) + [
            {"id": "gb12", "name": "G", "category": "ops",
             "apis": [_GetattrBaseBomb()], "ui_routes": []},
        ]
        body = self._get_modules()
        row = next(r for r in body["modules"] if r.get("id") == "gb12")
        self.assertEqual(len(row["apis"]), 1)
        self.assertIsInstance(row["apis"][0], str)


class ControlFlowStillPropagatesTests(_RegistrySandbox):
    """The launder must not eat genuine control flow: a Ctrl-C or an
    interpreter shutdown raised mid-serialize keeps propagating."""

    def test_keyboardinterrupt_from_class_property_propagates(self):
        class _KIBomb:
            @property
            def __class__(self):  # type: ignore[override]
                raise KeyboardInterrupt

        modules.MODULES = list(self._saved) + [_KIBomb()]
        with self.assertRaises(KeyboardInterrupt):
            modules.list_modules()

    def test_systemexit_from_str_propagates(self):
        class _SEBomb:
            def __str__(self):
                raise SystemExit(3)

        modules.MODULES = [
            {"id": "se", "name": _SEBomb(), "category": "ops"}]
        with self.assertRaises(SystemExit):
            modules.list_modules()

    def test_systemexit_from_isoformat_propagates(self):
        class _SEIso:
            def isoformat(self):
                raise SystemExit(4)

        modules.MODULES = [
            {"id": "sei", "name": "n", "category": "ops", "apis": [_SEIso()]}]
        with self.assertRaises(SystemExit):
            modules.list_modules()


class DecodeFidelityTests(_RegistrySandbox):
    """The claimed-base decode gap: real content behind a lying
    ``__class__`` used to vanish; a total impostor still drops."""

    def test_bytearray_lying_bytes_value_keeps_its_content(self):
        modules.MODULES = list(self._saved) + [
            {"id": "ba12", "name": _ByteArrayLyingBytes(b"hello"),
             "category": "ops", "apis": [], "ui_routes": []},
        ]
        body = self._get_modules()
        row = next(r for r in body["modules"] if r.get("id") == "ba12")
        self.assertEqual(row["name"], "hello")

    def test_total_bytes_impostor_still_drops_to_none(self):
        modules.MODULES = list(self._saved) + [
            {"id": "im12", "name": _BytesImpostor(), "category": "ops",
             "apis": [], "ui_routes": []},
        ]
        body = self._get_modules()
        row = next(r for r in body["modules"] if r.get("id") == "im12")
        self.assertIsNone(row["name"])


class StaysImmuneTests(_RegistrySandbox):
    """Neighbours the same hunt confirmed already safe — the unbound
    seams never run subclass code, so a bound BaseException override
    there stays inert; pinned so a refactor trips loudly."""

    def test_registry_iter_baseexception_stays_inert_via_snapshot(self):
        class _IterBaseBombList(list):
            def __iter__(self):
                raise _Watchdog("registry iter bomb")

        modules.MODULES = _IterBaseBombList(self._saved)
        body = self._get_modules()
        ids = [r.get("id") for r in body["modules"]]
        self.assertIn("dashboard", ids)
        self.assertEqual(len(ids), len(self._saved))

    def test_dict_items_baseexception_stays_inert_via_unbound_view(self):
        class _ItemsBaseBomb(dict):
            def items(self):
                raise _Watchdog("items bomb")

        modules.MODULES = list(self._saved) + [
            _ItemsBaseBomb({"id": "it12", "name": "n", "category": "ops",
                            "apis": [], "ui_routes": []})]
        body = self._get_modules()
        ids = [r.get("id") for r in body["modules"]]
        self.assertIn("it12", ids)

    def test_exact_registry_renders_identically(self):
        body = self._get_modules()
        ids = [r.get("id") for r in body["modules"]]
        self.assertIn("dashboard", ids)
        self.assertEqual(len(ids), len(self._saved))
        grouped = sum(len(v) for v in body["by_category"].values())
        self.assertEqual(grouped, len(self._saved))

    def test_exception_shaped_bombs_stay_closed_beside_new_guards(self):
        # modules8/11 coverage must survive the widened catch: a plain
        # Exception __class__ bomb still drops alone.
        class _ClassExcBomb:
            @property
            def __class__(self):  # type: ignore[override]
                raise RuntimeError("class access bomb")

        modules.MODULES = list(self._saved) + [
            _ClassExcBomb(),
            {"id": "sane12b", "name": "S", "category": "ops",
             "apis": [], "ui_routes": []},
        ]
        body = self._get_modules()
        ids = [r.get("id") for r in body["modules"]]
        self.assertIn("sane12b", ids)
        self.assertEqual(len(ids), len(self._saved) + 1)


if __name__ == "__main__":
    unittest.main()
