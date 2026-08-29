"""Sixth leftover-500s sweep of the Dashboard: subclass bombs in the sensors
and SMART caches, over the real mounted app.

dash/dash2/…/dash5 closed the surrogate, over-cap-int, numeric-YAML-id,
vanished-CLI, FIFO, plist-zoo, torn-IPv6 and subprocess-choke-point classes
across the whole tile set.  This sweep re-drove the Dashboard's tiles with
the *subclass bomb* classes (the modules5 / svc6 / health6 convention)
planted in the module-level caches the tiles re-serve — the exact ingress
prior sensors fixes already used ("a leftover dict-subclass planted in the
peek cache") — and found live leftovers in the two sanitizers that had only
the partial (dash-era) hardening:

* ``sensors_svc._jsonable`` probed values through *bound* calls, so an int
  subclass whose ``__str__`` raises (only ValueError was caught around the
  digit-cap probe — plain and over-cap), a float subclass whose
  ``__eq__``/``__ne__`` raises (the NaN probe and the inf tuple-membership
  probe both call it — plain and inf), and a bytes/bytearray subclass whose
  ``decode`` raises — as a value and as a mapping key (``_utf8_text``'s
  bound decode) — each answered a raw 500 on GET /api/system/sensors, on
  BOTH the cache-hit path (``collect_sensors``) and the light peek
  (``peek_sensors`` → the Dashboard's 20s light tick).  **Eight live
  500s.**  A float ``__eq__`` bomb riding the *top* cache 500'd the cold
  collect the same way through the final payload sweep.
* ``system._jsonable`` had the full old pattern (bound ``items``/
  ``decode``/``__str__``/``__eq__``, bare sequence iteration, bare
  ``getattr``), so ANY of the bomb classes in ``system._smart_cache``
  raised out of ``collect_system`` — the status build's fallback then
  **silently wiped the whole ``system`` tile** from GET /api/status: load,
  disk and uptime died with the poison, and the sane ``wear`` sibling died
  with the bomb ``temp`` field.  Any direct ``collect_system`` caller got
  the raise itself.

The fix routes both sanitizers through unbound base-type calls
(``int.__index__``, ``float.__float__``, ``bytes``/``bytearray.decode``,
``dict.items``, ``base.__iter__``, guarded getattr — the modules5
convention), so the poison is scrubbed field-level and the real content
survives: the int keeps its number, the bomb-keyed bytes still decode, the
iterbomb's elements still list, and the SMART ``wear`` sibling outlives the
bomb ``temp``.

Stays-immune pins ride along for the vectors the dash-era partial fix had
already killed (nested ``items()`` bombs, torn-pair ``items()``, getattr
bombs, the top-cache ``get``/``__bool__`` bomb guard).
"""
from __future__ import annotations

import json
import time
import unittest

from fastapi.testclient import TestClient

from hub import sensors_svc, system
from hub.auth import require_auth

#: Built arithmetically: int("9" * 5000) itself trips the digit cap.
_HUGE_INT = 10 ** 5000

_APP = None


def _client() -> TestClient:
    global _APP
    if _APP is None:
        from hub.app_factory import create_app

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: None
    # raise_server_exceptions=False: a real 500 must arrive as HTTP 500, not
    # as a re-raised exception that would mask which route crashed.
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _IntStrBomb(int):
    def __str__(self):
        raise RuntimeError("int str bomb")

    __repr__ = __str__


class _FloatEqBomb(float):
    def __eq__(self, other):
        raise RuntimeError("float eq bomb")

    def __ne__(self, other):
        raise RuntimeError("float ne bomb")

    __hash__ = float.__hash__


class _BytesDecodeBomb(bytes):
    def decode(self, *args, **kwargs):
        raise RuntimeError("bytes decode bomb")


class _BytearrayDecodeBomb(bytearray):
    def decode(self, *args, **kwargs):
        raise RuntimeError("bytearray decode bomb")


class _ItemsBomb(dict):
    def items(self):
        raise RuntimeError("items bomb")


class _TriplesItems(dict):
    def items(self):
        return [("a", 1, 2)]  # unpack ValueError in ``for k, v in ...``


class _IterBombList(list):
    def __iter__(self):
        raise RuntimeError("list iter bomb")


class _GetattrBomb:
    def __getattr__(self, name):
        raise RuntimeError(f"getattr bomb: {name}")


class _GetBoolBomb(dict):
    def get(self, *args, **kwargs):
        raise RuntimeError("get bomb")

    def __bool__(self):
        raise RuntimeError("bool bomb")


class _SensorsCacheSandbox(unittest.TestCase):
    """Save/restore the sensors + top caches around each planted bomb."""

    def setUp(self):
        self._cache = dict(sensors_svc._cache)
        self._top = dict(sensors_svc._top_cache)
        self.addCleanup(lambda: sensors_svc._cache.update(self._cache))
        self.addCleanup(lambda: sensors_svc._top_cache.update(self._top))
        self.client = _client()

    def _plant(self, bomb) -> None:
        sensors_svc._cache.update(
            t=time.time(), v={"cpu": {"x": bomb}, "light": False})

    def _get(self, path: str) -> dict:
        resp = self.client.get(path)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        return body


class SensorsCacheHitBombTests(_SensorsCacheSandbox):
    """The cache-hit re-sanitize (collect_sensors) — eight ex-500s."""

    def test_int_subclass_str_bomb_keeps_its_number(self):
        self._plant(_IntStrBomb(3))
        body = self._get("/api/system/sensors")
        self.assertEqual(body["cpu"]["x"], 3)

    def test_overcap_int_wearing_the_bomb_subclass_still_drops(self):
        """Coercion cannot resurrect the unrenderable: past CPython's digit
        cap the value drops exactly like its plain-int sibling."""
        self._plant(_IntStrBomb(_HUGE_INT))
        body = self._get("/api/system/sensors")
        self.assertIsNone(body["cpu"]["x"])

    def test_float_subclass_eq_bomb_keeps_its_value(self):
        self._plant(_FloatEqBomb(1.5))
        body = self._get("/api/system/sensors")
        self.assertEqual(body["cpu"]["x"], 1.5)

    def test_inf_wearing_the_eq_bomb_subclass_still_drops(self):
        self._plant(_FloatEqBomb(float("inf")))
        body = self._get("/api/system/sensors")
        self.assertIsNone(body["cpu"]["x"])

    def test_bytes_decode_bomb_value_still_decodes(self):
        self._plant(_BytesDecodeBomb(b"panel"))
        body = self._get("/api/system/sensors")
        self.assertEqual(body["cpu"]["x"], "panel")

    def test_bytearray_decode_bomb_value_still_decodes(self):
        self._plant(_BytearrayDecodeBomb(b"panel\xff"))
        body = self._get("/api/system/sensors")
        self.assertEqual(body["cpu"]["x"], "panel\ufffd")

    def test_bytes_decode_bomb_key_still_decodes(self):
        sensors_svc._cache.update(
            t=time.time(),
            v={"cpu": {_BytesDecodeBomb(b"k"): 1}, "light": False},
        )
        body = self._get("/api/system/sensors")
        self.assertEqual(body["cpu"]["k"], 1)


class SensorsLightPeekBombTests(_SensorsCacheSandbox):
    """The Dashboard's 20s light tick serves peek_sensors — same bombs."""

    def test_int_subclass_str_bomb_on_the_light_tick(self):
        self._plant(_IntStrBomb(3))
        body = self._get("/api/system/sensors?light=true")
        self.assertEqual(body["cpu"]["x"], 3)

    def test_float_subclass_eq_bomb_on_the_light_tick(self):
        self._plant(_FloatEqBomb(1.5))
        body = self._get("/api/system/sensors?light=true")
        self.assertEqual(body["cpu"]["x"], 1.5)

    def test_bytes_decode_bomb_on_the_light_tick(self):
        self._plant(_BytesDecodeBomb(b"panel"))
        body = self._get("/api/system/sensors?light=true")
        self.assertEqual(body["cpu"]["x"], "panel")


class TopCacheBombTests(_SensorsCacheSandbox):
    """A float ``__eq__`` bomb riding the top cache 500'd the cold collect
    through the final payload sweep."""

    def test_float_eq_bomb_in_the_top_cache_cannot_500_the_cold_collect(self):
        sensors_svc._cache.update(t=0.0, v=None)
        sensors_svc._top_cache.update(
            t=time.time(),
            v={"mem_used_gb": _FloatEqBomb(1.5),
               "cpu_used_pct": _FloatEqBomb(50.0)},
        )
        body = self._get("/api/system/sensors")
        self.assertIn("cpu", body)


class SmartCacheBombTests(unittest.TestCase):
    """system._smart_cache bombs silently wiped the whole system tile."""

    def setUp(self):
        import hub.status as status

        self._smart = dict(system._smart_cache)
        self.addCleanup(lambda: system._smart_cache.update(self._smart))
        self.addCleanup(status.invalidate_status)
        self.client = _client()

    def _status_system(self, bomb) -> dict:
        import hub.status as status

        system._smart_cache.update(t=time.time(), v={"temp": bomb, "wear": "3%"})
        status.invalidate_status()
        resp = self.client.get("/api/status?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        sysobj = body.get("system")
        self.assertIsInstance(sysobj, dict)
        # The whole tile used to wipe: load/disk/uptime died with the poison.
        self.assertTrue(sysobj, "system tile wiped by the smart-cache bomb")
        self.assertIn("uptime_hours", sysobj)
        return sysobj

    def _assert_wear_survives(self, sysobj: dict) -> None:
        # The sane sibling field outlives the bomb it shared a dict with.
        self.assertEqual((sysobj.get("smart") or {}).get("wear"), "3%")

    def test_int_str_bomb_keeps_the_tile_and_the_wear_sibling(self):
        sysobj = self._status_system(_IntStrBomb(3))
        self._assert_wear_survives(sysobj)
        self.assertEqual(sysobj["smart"]["temp"], 3)

    def test_float_eq_bomb_keeps_the_tile_and_the_wear_sibling(self):
        sysobj = self._status_system(_FloatEqBomb(1.5))
        self._assert_wear_survives(sysobj)

    def test_bytes_decode_bomb_keeps_the_tile_and_the_wear_sibling(self):
        sysobj = self._status_system(_BytesDecodeBomb(b"41 C"))
        self._assert_wear_survives(sysobj)
        self.assertEqual(sysobj["smart"]["temp"], "41 C")

    def test_items_bomb_keeps_the_tile_and_the_wear_sibling(self):
        sysobj = self._status_system(_ItemsBomb(a=1))
        self._assert_wear_survives(sysobj)
        # Unbound dict.items sees the real storage: the entry survives.
        self.assertEqual(sysobj["smart"]["temp"], {"a": 1})

    def test_iterbomb_keeps_the_tile_and_its_elements(self):
        sysobj = self._status_system(_IterBombList(["41 C"]))
        self._assert_wear_survives(sysobj)
        self.assertEqual(sysobj["smart"]["temp"], ["41 C"])

    def test_getattr_bomb_keeps_the_tile_and_the_wear_sibling(self):
        sysobj = self._status_system(_GetattrBomb())
        self._assert_wear_survives(sysobj)

    def test_direct_collect_system_no_longer_raises(self):
        system._smart_cache.update(
            t=time.time(), v={"temp": _IntStrBomb(3), "wear": "3%"})
        out = system.collect_system()
        self.assertIsInstance(out, dict)
        self.assertEqual((out.get("smart") or {}).get("wear"), "3%")


class StaysImmuneTests(_SensorsCacheSandbox):
    """Vectors the dash-era partial fix had already killed — pinned so a
    refactor cannot reopen them."""

    def test_nested_items_bomb_is_read_through_the_base_view(self):
        self._plant(_ItemsBomb(a=1))
        body = self._get("/api/system/sensors")
        self.assertEqual(body["cpu"]["x"], {"a": 1})

    def test_items_yielding_triples_cannot_blow_the_unpack(self):
        self._plant(_TriplesItems(real="kept"))
        body = self._get("/api/system/sensors")
        self.assertEqual(body["cpu"]["x"], {"real": "kept"})

    def test_list_subclass_iterbomb_keeps_its_elements(self):
        self._plant(_IterBombList(["a", "b"]))
        body = self._get("/api/system/sensors")
        self.assertEqual(body["cpu"]["x"], ["a", "b"])

    def test_getattr_bomb_falls_back_to_text(self):
        self._plant(_GetattrBomb())
        body = self._get("/api/system/sensors")
        self.assertEqual(body["cpu"]["x"], "")

    def test_top_cache_get_bool_bomb_is_neutralized_by_the_plain_dict(self):
        """_cpu_and_mem_from_top_cached plain-dicts a subclass hit, so the
        ``get``/``__bool__`` bombs never fire on the cold collect."""
        sensors_svc._cache.update(t=0.0, v=None)
        sensors_svc._top_cache.update(
            t=time.time(), v=_GetBoolBomb(mem_used_gb=2.0))
        body = self._get("/api/system/sensors")
        self.assertIn("cpu", body)


if __name__ == "__main__":
    unittest.main()
