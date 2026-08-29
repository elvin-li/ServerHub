"""Sixth leftover-500s sweep of the Services / launchd surfaces: subclass
bombs riding a discovery-collector row into the status build.

Driven over the real ``create_app()`` with
``TestClient(raise_server_exceptions=False)``: a genuine unhandled leftover
arrives as Starlette's plain ``Internal Server Error`` 500, while a coded
4xx/422/503 or the designed ``{ok, message}`` contract is not a leftover.

svc/svc2/…/svc5 closed the hex/over-cap int, surrogate, numeric-YAML-id,
vanished-CLI, FIFO and plist-zoo classes.  This sweep re-drove the routes
with the *subclass bomb* classes (the modules5 / tools5 / ups5 convention)
planted in one collector row, and found **fifteen live 500s** on a cold
GET /api/status and GET /api/services — every one rooted in
``hub.status``:

* ``_jsonable`` probed values through *bound* calls, so a nested
  dict-subclass ``items()`` bomb (or one yielding torn pairs), a
  list-subclass ``__iter__`` iterbomb, an int-subclass ``__str__`` bomb
  (only ValueError was caught around the digit-cap probe), a
  float-subclass ``__eq__``/``__ne__`` bomb, a bytes-subclass ``decode``
  bomb (as value and as mapping key) and an object whose ``isoformat``
  getattr itself raises all blew the sanitizer instead of being scrubbed;
* ``_build_status`` read raw collector rows bare, so a dict-subclass row
  whose bound ``get()`` raises, a hash-bomb str id/name hitting the
  known-names **set membership**, a ``__bool__``-bomb port truth test and
  an ``__eq__``-bomb state in the problems filter each killed the whole
  build — every sane sibling row died with the poison;
* a bomb planted in the status cache blew ``_stamp_locale``'s re-sanitize
  on the *cache-hit* path, so the poison outlived the request that
  planted it.

The fix routes ``_jsonable`` through unbound base-type calls
(``dict.items``, ``base.__iter__``, ``int.__index__``,
``float.__float__``, ``bytes``/``bytearray.decode``, guarded getattr),
scrubs each collector row up front in ``_build_status`` so a bomb costs
only its own junk fields, and type-gates ``_stamp_locale``'s locale
compare.  The real content survives the scrub: the get-bomb row still
lists its fields and the hash-bomb id still renders.

A stays-immune pin rides along: a list-subclass ``__iter__`` bomb as the
*collector return value* was already neutralized by the ``+``
concatenation (``list.__add__`` reads the base storage).
"""
from __future__ import annotations

import json
import time
import unittest
from unittest import mock

from fastapi.testclient import TestClient

import hub.status as status
from hub.app_factory import create_app
from hub.auth import require_auth

#: Built arithmetically: int("9" * 5000) itself trips the digit cap.
_HUGE_INT = 10 ** 5000

_APP = None


def _client() -> TestClient:
    global _APP
    if _APP is None:
        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: None
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _GetBombRow(dict):
    def get(self, *args, **kwargs):
        raise RuntimeError("get bomb")


class _ItemsBomb(dict):
    def items(self):
        raise RuntimeError("items bomb")


class _ItemsTorn(dict):
    def items(self):
        return [("solo",), ("name", "x")]


class _IterBombList(list):
    def __iter__(self):
        raise RuntimeError("iter bomb")


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


class _HashBombStr(str):
    def __hash__(self):
        raise RuntimeError("hash bomb")


class _BoolBomb:
    def __bool__(self):
        raise RuntimeError("bool bomb")


class _EqBombVal:
    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    __hash__ = object.__hash__


class _GetattrBomb:
    def __getattr__(self, name):
        raise RuntimeError("getattr bomb")


def _row(**kw):
    base = {"id": "svc6.probe", "kind": "launchd", "name": "probe",
            "state": "ok", "detail": "d", "group": "SixG", "actions": ["logs"]}
    base.update(kw)
    return base


class _StatusSandbox(unittest.TestCase):
    """Cold status cache + one patched collector, restored afterwards."""

    def setUp(self):
        self._reset()
        self.addCleanup(self._reset)

    @staticmethod
    def _reset():
        with status._lock:
            status._status_cache.update(t=0.0, v=None)

    def _get(self, rows, path="/api/status?force=true"):
        self._reset()
        with mock.patch.object(status, "discover_launchd", lambda: rows):
            response = _client().get(path)
        self.assertEqual(response.status_code, 200, response.text[:300])
        body = response.json()
        _starlette(body)
        return body

    @staticmethod
    def _probe_row(body):
        for group in body["groups"]:
            for svc in group["services"]:
                if "svc6" in str(svc.get("id") or ""):
                    return svc
        return None


class BuildRowBombsTests(_StatusSandbox):
    """Bomb rows from a collector cost only their own junk fields."""

    def test_get_bomb_row_survives_with_its_real_fields(self):
        body = self._get([_GetBombRow(_row()), _row(id="svc6.sane")])
        row = self._probe_row(body)
        self.assertIsNotNone(row)
        self.assertEqual(row["name"], "probe")
        ids = [s["id"] for g in body["groups"] for s in g["services"]]
        self.assertIn("svc6.sane", ids)

    def test_hash_bomb_str_id_renders_and_does_not_500_the_set_add(self):
        body = self._get([_row(id=_HashBombStr("svc6.hash"))])
        row = self._probe_row(body)
        self.assertEqual(row["id"], "svc6.hash")

    def test_hash_bomb_str_name_renders(self):
        body = self._get([_row(name=_HashBombStr("hashname"))])
        self.assertEqual(self._probe_row(body)["name"], "hashname")

    def test_bool_bomb_port_does_not_500_the_adaptive_scan(self):
        body = self._get([_row(port=_BoolBomb())])
        self.assertEqual(self._probe_row(body)["state"], "ok")

    def test_eq_bomb_state_does_not_500_the_problems_filter(self):
        body = self._get([_row(state=_EqBombVal()), _row(id="svc6.sane")])
        ids = [s["id"] for g in body["groups"] for s in g["services"]]
        self.assertIn("svc6.sane", ids)

    def test_services_route_rides_the_same_scrub(self):
        body = self._get(
            [_GetBombRow(_row()), _row(id="svc6.sane")],
            path="/api/services?force=true",
        )
        ids = [s["id"] for g in body["groups"] for s in g["services"]]
        self.assertIn("svc6.sane", ids)
        # list_manageable enriched the surviving rows.
        row = self._probe_row(body)
        self.assertIn("detail", row["actions"])


class JsonableNestedBombsTests(_StatusSandbox):
    """Nested subclass bombs are scrubbed field-level, never a 500."""

    def test_items_bomb_row_and_nested_meta(self):
        for rows in (
            [_ItemsBomb(_row())],
            [_row(meta=_ItemsBomb({"x": 1}))],
            [_row(meta=_ItemsTorn())],
        ):
            body = self._get(rows)
            self.assertTrue(body["groups"], rows)

    def test_iter_bomb_ports_list_keeps_its_elements(self):
        body = self._get([_row(ports=_IterBombList([80, 81]))])
        self.assertEqual(self._probe_row(body)["ports"], [80, 81])

    def test_int_subclass_str_bomb_keeps_its_number(self):
        body = self._get([_row(port=_StrBombInt(8080))])
        self.assertEqual(self._probe_row(body)["port"], 8080)

    def test_overcap_int_wearing_the_bomb_subclass_still_drops(self):
        body = self._get([_row(port=_StrBombInt(_HUGE_INT))])
        self.assertIsNone(self._probe_row(body)["port"])

    def test_float_eq_bomb_keeps_its_number(self):
        body = self._get([_row(cpu=_EqBombFloat(1.5))])
        self.assertEqual(self._probe_row(body)["cpu"], 1.5)

    def test_decode_bomb_bytes_value_and_key_still_decode(self):
        body = self._get([{**_row(), "detail": _DecodeBombBytes(b"det"),
                           _DecodeBombBytes(b"extra"): 1}])
        row = self._probe_row(body)
        self.assertEqual(row["detail"], "det")
        self.assertEqual(row["extra"], 1)

    def test_getattr_bomb_value_survives_the_isoformat_probe(self):
        body = self._get([_row(extra=_GetattrBomb())])
        self.assertIn("extra", self._probe_row(body))


class WarmCachePoisonTests(_StatusSandbox):
    """Bombs planted in the status cache degrade on the cache-hit path."""

    def _poison(self, value):
        with status._lock:
            status._status_cache.update(t=time.time(), v=value)
        response = _client().get("/api/status")
        self.assertEqual(response.status_code, 200, response.text[:300])
        body = response.json()
        _starlette(body)
        return body

    def test_items_bomb_group_in_cache(self):
        body = self._poison({"groups": [_ItemsBomb({"services": []})],
                             "counts": {}})
        self.assertEqual(body["groups"], [{"services": []}])

    def test_decode_bomb_and_str_bomb_values_in_cache(self):
        body = self._poison({"groups": [], "counts": {},
                             "ts": _DecodeBombBytes(b"t"),
                             "service_total": _StrBombInt(3)})
        self.assertEqual(body["ts"], "t")
        self.assertEqual(body["service_total"], 3)

    def test_ne_bomb_locale_in_cache_is_restamped(self):
        body = self._poison({"groups": [], "counts": {},
                             "locale": _EqBombVal()})
        self.assertIsInstance(body["locale"], str)


class StaysImmunePinsTests(_StatusSandbox):
    """Vectors this sweep re-tested and found already dead — pinned."""

    def test_iter_bomb_collector_return_is_neutralized_by_the_concat(self):
        body = self._get(_IterBombList([_row()]))
        self.assertEqual(self._probe_row(body)["id"], "svc6.probe")

    def test_member_summary_actions_over_a_scrubbed_row(self):
        # After the scrub the actions list holds exact strs; the summary's
        # set comprehension cannot meet a hash bomb from a collector row.
        row = status._jsonable(
            _row(url="http://x", actions=[_HashBombStr("open"), "detail"]),
        )
        for action in row["actions"]:
            self.assertIs(type(action), str)
        summary = status.member_service_summary(row)
        self.assertEqual(summary["actions"], ["open", "detail"])


class JsonableUnitPins(unittest.TestCase):
    """Base-coercion shapes, mirroring the modules5 unit pins."""

    def test_base_coercions(self):
        self.assertEqual(status._jsonable(_StrBombInt(7)), 7)
        self.assertIsNone(status._jsonable(_StrBombInt(_HUGE_INT)))
        self.assertIsNone(status._jsonable(_HUGE_INT))
        self.assertEqual(status._jsonable(_EqBombFloat(2.5)), 2.5)
        self.assertIsNone(status._jsonable(float("nan")))
        self.assertEqual(status._jsonable(_DecodeBombBytes(b"x")), "x")
        self.assertEqual(status._jsonable(_ItemsTorn({"k": "v"})), {"k": "v"})
        self.assertEqual(status._jsonable(_IterBombList([1])), [1])
        self.assertIsInstance(status._jsonable(_GetattrBomb()), str)


if __name__ == "__main__":
    unittest.main()
