"""Tenth leftover-500s sweep of the Dashboard: *lying* ``__class__``
impostors past the dash9 gates, over the real mounted app.

dash9 sealed the ``__class__``-property *raising* bombs with ``_isa`` and
put every unbound base call in a try — except two seams where the liar
class (the health10 / json9 impostor: a ``__class__`` property that
*returns* a claimed type while the real object is a plain object) still
had nothing to refuse it:

* The bool gate in all three ``_jsonable``s (``status`` / ``sensors_svc``
  / ``system``) returned anything answering ``isinstance(value, bool)``
  verbatim.  Every other liar drops when its unbound base call
  (``dict.items`` / ``list.__iter__`` / ``bytes.decode``) TypeErrors, but
  the bool gate had no call to make — and ``bool`` cannot be subclassed,
  so the C-level JSON encoder then refused the impostor downstream.
  Nested in the sensors cache it 500'd GET /api/system/sensors; nested in
  (or planted as) the status cache it 500'd every cache-hit
  GET /api/status; nested in the SMART cache it rode ``collect_system``
  into a cold GET /api/status?force; riding a ``quick_links`` row it
  passed ``resolve_value`` untouched (a leaf is not junk to the walker —
  no raise, per the bookmarks5 / docker9 pin) and blew the encoder the
  same way.  **Five live 500s.**
* ``status._rows`` passed a liar-list collector answer through its
  ``_isa`` gate, so the ``+`` concatenation in ``_build_status``
  TypeError'd a cold GET /api/status; a *real* list subclass with an
  ``__add__``/``__radd__`` bomb detonated the same seam.  And the
  orphan-listener block used a bare ``isinstance(orphans, list)`` (a
  raising-``__class__`` bomb detonated it) plus an unguarded
  ``list.__iter__`` (a liar TypeError'd it) one line past the try that
  guards the scan call.  **Four more live 500s.**

The fix keeps the conventions: the bool gate now requires the exact type
(``bool`` has no subclasses, so nothing legitimate is lost) and drops the
impostor like its dict/list/bytes siblings; ``_rows`` copies non-exact
lists through the unbound base iterator, so a liar or an ``__add__`` bomb
costs only itself and real subclass rows survive.

``resolve_value`` stays raise-on-junk (the bookmarks5 / docker9 pin): a
junk *container* still raises out of the walk; the bool-liar *leaf* still
passes through untouched, and the downstream ``_jsonable`` is what drops
it now.
"""
from __future__ import annotations

import json
import time
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import host_address, sensors_svc, system
import hub.status as status_mod
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


class _LyingBool:
    """Claims to be a bool; is not — and bool has no unbound call to refuse it."""

    @property
    def __class__(self):
        return bool


class _LyingInt:
    @property
    def __class__(self):
        return int


class _LyingFloat:
    @property
    def __class__(self):
        return float


class _LyingStr:
    @property
    def __class__(self):
        return str


class _LyingList:
    @property
    def __class__(self):
        return list


class _ClassBomb:
    """A leftover that cannot answer what it is: ``isinstance`` itself raises."""

    @property
    def __class__(self):
        raise RuntimeError("class bomb")


class _AddBombList(list):
    """A real list subclass whose concatenation raises."""

    def __add__(self, other):
        raise RuntimeError("add bomb")

    def __radd__(self, other):
        raise RuntimeError("radd bomb")


class _IterBombList(list):
    """A real list subclass whose iteration raises."""

    def __iter__(self):
        raise RuntimeError("iter bomb")


# ---------------------------------------------------------------------------
# sensors: the bool-liar through the sensors cache
# ---------------------------------------------------------------------------


class _SensorsCacheSandbox(unittest.TestCase):
    def setUp(self):
        self._cache = dict(sensors_svc._cache)
        self.addCleanup(lambda: sensors_svc._cache.update(self._cache))
        self.client = _client()

    def _plant(self, cpu: dict) -> None:
        sensors_svc._cache.update(
            t=time.time(), v={"cpu": cpu, "light": False})

    def _get(self, path: str) -> dict:
        resp = self.client.get(path)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        return body


class SensorsBoolLiarTests(_SensorsCacheSandbox):
    """The ex-500s on GET /api/system/sensors."""

    def test_nested_bool_liar_drops_and_the_sibling_survives(self):
        self._plant({"x": _LyingBool(), "y": 2})
        body = self._get("/api/system/sensors")
        self.assertIsNone(body["cpu"]["x"])
        self.assertEqual(body["cpu"]["y"], 2)

    def test_nested_bool_liar_on_the_light_tick(self):
        self._plant({"x": _LyingBool(), "y": 2})
        body = self._get("/api/system/sensors?light=true")
        self.assertIsNone(body["cpu"]["x"])
        self.assertEqual(body["cpu"]["y"], 2)

    def test_peek_sensors_scrubs_the_nested_bool_liar(self):
        self._plant({"x": _LyingBool(), "y": 2})
        out = sensors_svc.peek_sensors()
        self.assertIsInstance(out, dict)
        _starlette(out)

    def test_real_bools_still_render_exactly(self):
        # The exact-type tightening must not cost a legitimate flag.
        self._plant({"flag_on": True, "flag_off": False})
        body = self._get("/api/system/sensors")
        self.assertIs(body["cpu"]["flag_on"], True)
        self.assertIs(body["cpu"]["flag_off"], False)
        self.assertIs(body["light"], False)

    def test_the_other_scalar_liars_drop_the_same_way(self):
        self._plant({
            "i": _LyingInt(), "f": _LyingFloat(), "y": 2,
        })
        body = self._get("/api/system/sensors")
        self.assertIsNone(body["cpu"]["i"])
        self.assertIsNone(body["cpu"]["f"])
        self.assertEqual(body["cpu"]["y"], 2)

    def test_a_str_liar_renders_as_text_not_a_500(self):
        self._plant({"s": _LyingStr(), "y": 2})
        body = self._get("/api/system/sensors")
        self.assertIsInstance(body["cpu"]["s"], str)
        self.assertEqual(body["cpu"]["y"], 2)


# ---------------------------------------------------------------------------
# status: the bool-liar through the snapshot cache and the SMART cache
# ---------------------------------------------------------------------------


class _StatusCacheSandbox(unittest.TestCase):
    def setUp(self):
        self._cache = dict(status_mod._status_cache)
        self.addCleanup(status_mod.invalidate_status)
        self.addCleanup(
            lambda: status_mod._status_cache.update(self._cache))
        self.client = _client()


class StatusCacheBoolLiarTests(_StatusCacheSandbox):
    """The ex-500s on cache-hit GET /api/status."""

    def test_nested_bool_liar_keeps_the_sane_snapshot_fields(self):
        status_mod._status_cache.update(
            t=time.time(),
            v={"counts": {"ok": 1}, "groups": [], "junk": _LyingBool()},
        )
        resp = self.client.get("/api/status")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIsNone(body["junk"])
        self.assertEqual(body["counts"]["ok"], 1)

    def test_whole_cache_bool_liar_no_longer_500s_the_cache_hit(self):
        status_mod._status_cache.update(t=time.time(), v=_LyingBool())
        resp = self.client.get("/api/status")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _starlette(resp.json())

    def test_real_bool_engine_up_still_renders_exactly(self):
        status_mod._status_cache.update(
            t=time.time(),
            v={"counts": {"ok": 1}, "groups": [], "engine_up": False},
        )
        resp = self.client.get("/api/status")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertIs(resp.json()["engine_up"], False)

    def test_bool_liar_in_a_quick_links_row_costs_only_its_field(self):
        """The liar is a *leaf*: resolve_value passes it untouched (no
        junk-raise, per the bookmarks5 / docker9 contract) and the payload
        sweep is what drops it now — the row and the route survive."""
        with mock.patch.object(
            status_mod, "cfg",
            lambda: {"settings": {"adaptive": False},
                     "quick_links": [
                         {"name": "a", "url": "http://a.lan",
                          "flag": _LyingBool()}]},
        ):
            status_mod.invalidate_status()
            resp = self.client.get("/api/status?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertEqual(len(body["links"]), 1)
        self.assertEqual(body["links"][0]["url"], "http://a.lan")
        self.assertIsNone(body["links"][0]["flag"])


class SmartCacheBoolLiarTests(unittest.TestCase):
    """The ex-500 riding collect_system into GET /api/status?force."""

    def setUp(self):
        self._smart = dict(system._smart_cache)
        self.addCleanup(lambda: system._smart_cache.update(self._smart))
        self.addCleanup(status_mod.invalidate_status)
        self.client = _client()

    def test_nested_bool_liar_keeps_the_tile_and_the_wear_sibling(self):
        system._smart_cache.update(
            t=time.time(), v={"temp": _LyingBool(), "wear": "3%"})
        out = system.collect_system()
        self.assertIsInstance(out, dict)
        self.assertIsNone((out.get("smart") or {}).get("temp"))
        self.assertEqual((out.get("smart") or {}).get("wear"), "3%")
        _starlette(out)
        status_mod.invalidate_status()
        resp = self.client.get("/api/status?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        sysobj = body.get("system")
        self.assertIsInstance(sysobj, dict)
        self.assertIn("uptime_hours", sysobj)
        self.assertEqual((sysobj.get("smart") or {}).get("wear"), "3%")


# ---------------------------------------------------------------------------
# status: the collector-list seams of a cold build
# ---------------------------------------------------------------------------


class ColdBuildListSeamTests(_StatusCacheSandbox):
    """The ex-500s on cold GET /api/status?force=true."""

    def _cold_get(self) -> dict:
        status_mod.invalidate_status()
        status_mod._status_cache.update(t=0.0, v=None)
        resp = self.client.get("/api/status?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        return body

    def test_liar_list_collector_no_longer_500s_the_concat(self):
        with mock.patch.object(
            status_mod, "collect_apps", return_value=_LyingList()
        ):
            body = self._cold_get()
        self.assertIsInstance(body["groups"], list)

    def test_add_bomb_list_subclass_keeps_its_real_rows(self):
        rows = _AddBombList([{"id": "a", "name": "a", "state": "ok"}])
        with mock.patch.object(
            status_mod, "collect_apps", return_value=rows
        ):
            body = self._cold_get()
        ids = [
            svc.get("id")
            for grp in body["groups"]
            for svc in grp.get("services", [])
        ]
        self.assertIn("a", ids)
        self.assertGreaterEqual(body["counts"]["ok"], 1)

    def test_iter_bomb_list_subclass_costs_only_its_collector(self):
        rows = _IterBombList([{"id": "b", "name": "b", "state": "ok"}])
        with mock.patch.object(
            status_mod, "collect_apps", return_value=rows
        ):
            body = self._cold_get()
        self.assertIsInstance(body["groups"], list)

    def test_liar_list_launchd_collector_keeps_the_route(self):
        with mock.patch.object(
            status_mod, "discover_launchd", return_value=_LyingList()
        ):
            body = self._cold_get()
        self.assertIsInstance(body["groups"], list)

    def test_orphan_scan_class_bomb_no_longer_500s_the_gate(self):
        with mock.patch.object(
            status_mod, "discover_orphan_listeners",
            return_value=_ClassBomb(),
        ):
            body = self._cold_get()
        self.assertIsInstance(body["groups"], list)

    def test_orphan_scan_liar_list_no_longer_500s_the_iter(self):
        with mock.patch.object(
            status_mod, "discover_orphan_listeners",
            return_value=_LyingList(),
        ):
            body = self._cold_get()
        self.assertIsInstance(body["groups"], list)

    def test_rows_keeps_real_lists_and_subclass_rows(self):
        plain = [1, 2]
        self.assertIs(status_mod._rows(plain), plain)
        self.assertEqual(status_mod._rows(_AddBombList(["x"])), ["x"])
        self.assertEqual(status_mod._rows(_LyingList()), [])
        self.assertEqual(status_mod._rows(_ClassBomb()), [])


# ---------------------------------------------------------------------------
# stays-immune pins
# ---------------------------------------------------------------------------


class StaysImmuneTests(_StatusCacheSandbox):
    """Vectors that were already immune — pinned so a gate reorder cannot
    reopen them, and so the resolve_value contract stays exactly where the
    bookmarks5 / docker9 pins put it."""

    def test_health_stays_200_under_the_nested_bool_liar(self):
        status_mod._status_cache.update(
            t=time.time(),
            v={"counts": {"ok": 1}, "groups": [], "junk": _LyingBool()},
        )
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _starlette(resp.json())

    def test_health_stays_200_under_the_whole_cache_bool_liar(self):
        status_mod._status_cache.update(t=time.time(), v=_LyingBool())
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _starlette(resp.json())

    def test_resolve_value_still_raises_a_junk_container(self):
        """The raise-on-junk contract is untouched: a bomb *container*
        (here: a mapping whose keys detonate the walk) still raises so
        the callers' try/except junk-drop keeps working."""
        with self.assertRaises(RuntimeError):
            host_address.resolve_value({"u": "x", "junk": _ClassBomb()})

    def test_resolve_value_passes_the_bool_liar_leaf_untouched(self):
        """A non-container, non-str leaf is not junk to the walker: it
        passes through identically (no raise, no laundering) and the
        payload sweep downstream is what drops it."""
        bomb = _LyingBool()
        out = host_address.resolve_value({"u": "x", "flag": bomb})
        self.assertIs(out["flag"], bomb)
        self.assertEqual(out["u"], "x")

    def test_sensors_whole_cache_bool_liar_degrades_to_empty(self):
        saved = dict(sensors_svc._cache)
        self.addCleanup(lambda: sensors_svc._cache.update(saved))
        sensors_svc._cache.update(t=time.time(), v=_LyingBool())
        resp = self.client.get("/api/system/sensors")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertIsInstance(resp.json(), dict)
        self.assertIsNone(sensors_svc.peek_sensors())

    def test_host_route_stays_200_under_a_bool_liar_detect_cache(self):
        saved = dict(host_address._detect_cache)
        self.addCleanup(host_address.invalidate_routing)
        self.addCleanup(lambda: host_address._detect_cache.update(saved))
        with mock.patch.object(
            host_address, "configured_host", return_value="auto"
        ):
            host_address._detect_cache.update(
                t=time.time(), value=_LyingBool())
            resp = self.client.get("/api/system/host?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIsInstance(body["host_ip"], str)

    def test_jsonable_drops_the_bool_liar_in_every_module(self):
        for scrub in (
            status_mod._jsonable, sensors_svc._jsonable, system._jsonable,
        ):
            self.assertIsNone(scrub(_LyingBool()))
            self.assertIs(scrub(True), True)
            self.assertIs(scrub(False), False)
            self.assertIsNone(scrub(None))


if __name__ == "__main__":
    unittest.main()
