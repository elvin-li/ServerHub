"""Seventh leftover-500s sweep of the Dashboard: self-``__str__`` encode
bombs in the sensors / top / SMART caches, over the real mounted app.

dash6 routed ``sensors_svc._jsonable`` and ``system._jsonable`` through
unbound base-type calls (``dict.items``, ``base.__iter__``,
``int.__index__``, ``float.__float__``, unbound ``bytes.decode``), which
killed the int/float/bytes/dict/list subclass-bomb classes.  One text bomb
survived that wave: CPython's default ``str.__str__`` copies a *subclass* to
an exact str, so the ``str(value)`` probe in the text scrubs looked safe —
but a str subclass whose ``__str__`` answers **self** (or any object whose
``__str__`` returns such a subclass) skips that exact-str copy, and the
scrubs' *bound* ``value.encode("utf-8", "replace")`` then dispatched into
the subclass's ``encode`` bomb:

* ``sensors_svc._utf8_text`` / ``_as_text`` — the bomb planted in the
  sensors cache 500'd GET /api/system/sensors as a value AND as a mapping
  key, on the cache-hit re-sanitize (``collect_sensors``) and the light
  peek (``peek_sensors`` → the Dashboard's 20s light tick); planted in the
  top cache it 500'd the *cold* collect through the final payload sweep.
  **Five live 500s.**
* ``system._as_text`` — the bomb in ``system._smart_cache`` raised out of
  ``collect_system``; the status build's fallback then **silently wiped
  the whole ``system`` tile** from GET /api/status (load, disk and uptime
  died with the poison, and the sane ``wear`` sibling died with the bomb
  ``temp``).  Any direct ``collect_system`` caller got the raise itself.

The fix is the status.py convention: unbound ``str.encode(text, "utf-8",
"replace")`` reads the C-level storage underneath the override, so the
poisoned string keeps its real text (and its lone surrogates still scrub)
instead of costing the route or the tile.

Stays-immune pins ride along for the sibling vector CPython itself
neutralizes (a plain encode-bomb subclass with the *default* ``__str__`` is
copied to exact str before the scrub) so a refactor of the probe order
cannot silently rely on the wrong half of that behavior.
"""
from __future__ import annotations

import json
import time
import unittest

from fastapi.testclient import TestClient

from hub import sensors_svc, system
from hub.auth import require_auth

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


class _SelfStrEncodeBomb(str):
    """``__str__`` answers self, so ``str()`` cannot copy the bomb away."""

    def __str__(self):
        return self

    def encode(self, *args, **kwargs):
        raise RuntimeError("encode bomb")


class _PlainEncodeBomb(str):
    """Default ``__str__``: CPython copies to exact str before the scrub."""

    def encode(self, *args, **kwargs):
        raise RuntimeError("encode bomb")


class _StrReturnsBomb:
    """An object whose ``__str__`` hands the scrub an encode-bomb subclass."""

    def __str__(self):
        return _SelfStrEncodeBomb("made by __str__")


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


class SensorsEncodeBombTests(_SensorsCacheSandbox):
    """The five ex-500s on GET /api/system/sensors."""

    def test_self_str_encode_bomb_value_keeps_its_text(self):
        self._plant(_SelfStrEncodeBomb("panel"))
        body = self._get("/api/system/sensors")
        self.assertEqual(body["cpu"]["x"], "panel")

    def test_self_str_encode_bomb_on_the_light_tick(self):
        self._plant(_SelfStrEncodeBomb("panel"))
        body = self._get("/api/system/sensors?light=true")
        self.assertEqual(body["cpu"]["x"], "panel")

    def test_self_str_encode_bomb_key_keeps_its_entry(self):
        sensors_svc._cache.update(
            t=time.time(),
            v={"cpu": {_SelfStrEncodeBomb("k"): 1}, "light": False},
        )
        body = self._get("/api/system/sensors")
        self.assertEqual(body["cpu"]["k"], 1)

    def test_str_returning_the_bomb_subclass_keeps_the_text(self):
        self._plant(_StrReturnsBomb())
        body = self._get("/api/system/sensors")
        self.assertEqual(body["cpu"]["x"], "made by __str__")

    def test_bomb_in_the_top_cache_cannot_500_the_cold_collect(self):
        """The bomb rode ``physmem_raw`` through the top-cache hit into the
        cold collect's final payload sweep."""
        sensors_svc._cache.update(t=0.0, v=None)
        sensors_svc._top_cache.update(
            t=time.time(), v={"physmem_raw": _SelfStrEncodeBomb("30G used")})
        body = self._get("/api/system/sensors")
        self.assertIn("cpu", body)
        self.assertEqual(body["memory"]["physmem_raw"], "30G used")

    def test_surrogate_riding_the_bomb_subclass_still_scrubs(self):
        """The unbound encode must keep doing the scrub's original job:
        a lone surrogate inside the bomb string is replaced (encode-side
        ``replace`` yields ``?``, same as a plain str), not served."""
        self._plant(_SelfStrEncodeBomb("a\ud800b"))
        body = self._get("/api/system/sensors")
        self.assertEqual(body["cpu"]["x"], "a?b")


class SmartCacheEncodeBombTests(unittest.TestCase):
    """system._smart_cache bombs silently wiped the whole system tile."""

    def setUp(self):
        import hub.status as status

        self._smart = dict(system._smart_cache)
        self.addCleanup(lambda: system._smart_cache.update(self._smart))
        self.addCleanup(status.invalidate_status)
        self.client = _client()

    def _status_system(self, smart: dict) -> dict:
        import hub.status as status

        system._smart_cache.update(t=time.time(), v=smart)
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

    def test_bomb_temp_keeps_the_tile_the_text_and_the_wear_sibling(self):
        sysobj = self._status_system(
            {"temp": _SelfStrEncodeBomb("41 C"), "wear": "3%"})
        smart = sysobj.get("smart") or {}
        self.assertEqual(smart.get("temp"), "41 C")
        self.assertEqual(smart.get("wear"), "3%")

    def test_bomb_key_keeps_the_tile_and_its_entry(self):
        sysobj = self._status_system(
            {_SelfStrEncodeBomb("temp"): "41 C", "wear": "3%"})
        smart = sysobj.get("smart") or {}
        self.assertEqual(smart.get("temp"), "41 C")
        self.assertEqual(smart.get("wear"), "3%")

    def test_direct_collect_system_no_longer_raises(self):
        system._smart_cache.update(
            t=time.time(),
            v={"temp": _SelfStrEncodeBomb("41 C"), "wear": "3%"})
        out = system.collect_system()
        self.assertIsInstance(out, dict)
        self.assertEqual((out.get("smart") or {}).get("temp"), "41 C")
        self.assertEqual((out.get("smart") or {}).get("wear"), "3%")


class StaysImmuneTests(_SensorsCacheSandbox):
    """The default-``__str__`` sibling was never live — CPython's exact-str
    copy neutralizes it before the scrub — pinned so a probe reorder cannot
    start trusting the bound ``encode`` again."""

    def test_plain_encode_bomb_subclass_value_stays_immune(self):
        self._plant(_PlainEncodeBomb("panel"))
        body = self._get("/api/system/sensors")
        self.assertEqual(body["cpu"]["x"], "panel")

    def test_plain_encode_bomb_subclass_in_the_smart_cache_stays_immune(self):
        import hub.status as status

        smart = dict(system._smart_cache)
        self.addCleanup(lambda: system._smart_cache.update(smart))
        self.addCleanup(status.invalidate_status)
        system._smart_cache.update(
            t=time.time(), v={"temp": _PlainEncodeBomb("41 C"), "wear": "3%"})
        out = system.collect_system()
        self.assertEqual((out.get("smart") or {}).get("temp"), "41 C")


if __name__ == "__main__":
    unittest.main()
