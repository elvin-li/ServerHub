"""Ninth leftover-500s sweep of the Dashboard: ``__class__``-property,
``__bool__`` and rc-``__eq__`` bombs in the host_address / sensors / top /
SMART / status caches, over the real mounted app.

dash8 sealed the host-identity *encode* bombs; re-running the zoo with the
health9 bomb classes surfaced a fresh family of live leftovers, because
``isinstance`` consults ``value.__class__`` whenever the exact-type check
misses — so a leftover whose ``__class__`` is a *raising property*
detonated the sanitizer gates themselves, one step ahead of every scrub:

* ``host_address._as_text``'s bytes gate blew straight out of ``host_ip()``
  and 500'd GET /api/system/host; a ``__bool__`` bomb planted in the
  LAN-detection cache blew ``_cached_detection``'s truthiness probe the
  same way.  An rc-subclass ``__ne__`` bomb from a patched/odd ``sh``
  detonated ``_default_route_fields``'s bare ``rc != 0`` — the same route,
  a third way.  **Three live 500s.**
* ``sensors_svc._jsonable``'s rank gates blew on the bomb as a nested
  value, as a mapping key and as the whole planted cache — 500ing
  GET /api/system/sensors on the cache hit and the light peek — and a bomb
  riding the top cache blew the *cold* collect's final sweep.  Lying
  ``__class__`` impostors (claim dict / list / bytes, are not) passed the
  bare gates and TypeError'd the unbound ``dict.items`` /
  ``base.__iter__`` / decode calls: **three more 500s.**  A whole-cache
  bomb in the top cache detonated ``_cpu_and_mem_from_top_cached``'s
  isinstance and silently wiped the top leg (PhysMem, load) for a TTL.
* ``system._jsonable`` raised out of ``collect_system`` and the status
  build's fallback silently wiped the whole ``system`` tile from
  GET /api/status; rc-``__eq__`` bombs on the boottime / smartctl probes
  in ``collect_system``'s main body wiped it too.
* ``status._stamp_locale``'s entry isinstance blew every cache-hit
  GET /api/status on a whole-cache bomb; ``_jsonable`` blew the nested
  one; ``_cfg_value``'s root gate and ``_status_quick_links``'s bare
  ``isinstance(raw, list)`` (only the read sat in its try) each blew a
  cold build.  **Four more live 500s.**

The fix is the docker_cli / nas8 convention: ``_isa`` (isinstance inside
try) on every rank gate, try-wrapped unbound base calls for the lying
impostors, guarded truthiness for the ``__bool__`` bombs, and
``_rc_int`` (``int.__index__`` salvage) for the rc probes — the bomb costs
only its own field and every sane sibling survives.

Stays-immune pins ride along: GET /api/health under both bomb shapes, the
pool-guarded sensors rc probes, the torn-IPv6 ``urlsplit`` in
``normalize_local_url``, and the plain default-``__str__`` subclass CPython
itself neutralizes.
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


class _ClassBomb:
    """A leftover that cannot answer what it is: ``isinstance`` itself raises."""

    @property
    def __class__(self):
        raise RuntimeError("class bomb")


class _BoolBomb:
    """A leftover whose truthiness probe raises."""

    def __bool__(self):
        raise RuntimeError("bool bomb")


class _LyingDict:
    """Claims to be a dict; is not — unbound ``dict.items`` TypeErrors."""

    @property
    def __class__(self):
        return dict


class _LyingList:
    @property
    def __class__(self):
        return list


class _LyingBytes:
    @property
    def __class__(self):
        return bytes


class _EqBombInt(int):
    """An rc whose comparison raises — ``rc == 0`` / ``rc != 0`` detonate."""

    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    def __ne__(self, other):
        raise RuntimeError("ne bomb")

    __hash__ = int.__hash__


class _PlainStrSub(str):
    """Default ``__str__``: CPython copies to exact str before any scrub."""


# ---------------------------------------------------------------------------
# host_address: the LAN-detection cache and the route reads under host_ip()
# ---------------------------------------------------------------------------


class _DetectCacheSandbox(unittest.TestCase):
    """Save/restore the LAN-detection cache; force the ``auto`` host path."""

    def setUp(self):
        self._cache = dict(host_address._detect_cache)
        self.addCleanup(host_address.invalidate_routing)
        self.addCleanup(lambda: host_address._detect_cache.update(self._cache))
        p = mock.patch.object(host_address, "configured_host", return_value="auto")
        p.start()
        self.addCleanup(p.stop)
        self.client = _client()

    def _plant(self, value) -> None:
        host_address._detect_cache.update(t=time.time(), value=value)

    def _get_host(self) -> dict:
        resp = self.client.get("/api/system/host?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        return body


class HostIdentityClassBombTests(_DetectCacheSandbox):
    """The ex-500s on GET /api/system/host."""

    def test_class_bomb_in_the_detect_cache_keeps_the_route(self):
        self._plant(_ClassBomb())
        body = self._get_host()
        # The bomb costs only its own value: it renders as junk text
        # instead of costing the route.
        self.assertIsInstance(body["host_ip"], str)

    def test_bool_bomb_in_the_detect_cache_reads_as_a_miss(self):
        self._plant(_BoolBomb())
        body = self._get_host()
        # A value that cannot answer truthiness is junk: the cache misses
        # and the address is re-detected instead of 500ing.
        self.assertIsInstance(body["host_ip"], str)

    def test_host_ip_no_longer_raises_either_bomb(self):
        self._plant(_ClassBomb())
        self.assertIsInstance(host_address.host_ip(), str)
        self._plant(_BoolBomb())
        self.assertIsInstance(host_address.host_ip(), str)

    def test_as_text_absorbs_the_class_bomb_and_the_lying_impostor(self):
        self.assertIsInstance(host_address._as_text(_ClassBomb()), str)
        # A lying ``__class__`` (claims bytes, is not) TypeErrors the
        # unbound decode and renders like any junk object instead.
        self.assertIsInstance(host_address._as_text(_LyingBytes()), str)

    def test_rc_eq_bomb_on_the_route_reads_no_longer_raises(self):
        """An rc-subclass ``__ne__`` bomb from a patched/odd ``sh`` used to
        detonate ``_default_route_fields``'s bare ``rc != 0`` straight out
        of host_ip() — 500ing GET /api/system/host."""
        host_address.invalidate_routing()
        with mock.patch.object(
            host_address, "sh",
            return_value=(_EqBombInt(0), "interface: en0\n", ""),
        ):
            self.assertIsInstance(host_address.host_ip(), str)
            body = self._get_host()
            self.assertIsInstance(body["host_ip"], str)


class HostAddressSanitizerContractTests(unittest.TestCase):
    """The walker/template contracts underneath the routes.

    ``resolve_value`` stays raise-on-junk on purpose: containers overrides,
    bookmarks quick_links and ``_status_quick_links`` all wrap the walk in
    a try and treat a raise as "the value is junk" (the bookmarks5 /
    docker9 pins) — dash9 must not launder those bombs through.
    """

    def test_resolve_value_still_raises_a_nested_class_bomb(self):
        with self.assertRaises(RuntimeError):
            host_address.resolve_value({"u": "x", "junk": _ClassBomb()})

    def test_template_variables_keeps_siblings_past_a_bomb_entry(self):
        with mock.patch.object(
            host_address, "host_ip", return_value="10.0.0.9"
        ), mock.patch(
            "hub.config.cfg",
            return_value={"settings": {"address_book": {
                "nas": "192.168.1.20", "junk": _ClassBomb(),
            }}},
        ):
            values = host_address.template_variables()
        # The sane sibling survives; the blanket except no longer wipes it.
        self.assertEqual(values["nas"], "192.168.1.20")
        self.assertEqual(values["host"], "10.0.0.9")

    def test_normalize_local_url_absorbs_a_class_bomb(self):
        self.assertIsInstance(
            host_address.normalize_local_url(_ClassBomb()), str)


# ---------------------------------------------------------------------------
# sensors: the sensors cache and the top cache
# ---------------------------------------------------------------------------


class _SensorsCacheSandbox(unittest.TestCase):
    """Save/restore the sensors + top caches around each planted bomb."""

    def setUp(self):
        self._cache = dict(sensors_svc._cache)
        self._top = dict(sensors_svc._top_cache)
        self.addCleanup(lambda: sensors_svc._cache.update(self._cache))
        self.addCleanup(lambda: sensors_svc._top_cache.update(self._top))
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


class SensorsClassBombTests(_SensorsCacheSandbox):
    """The ex-500s on GET /api/system/sensors."""

    def test_nested_class_bomb_value_keeps_its_siblings(self):
        self._plant({"x": _ClassBomb(), "y": 2})
        body = self._get("/api/system/sensors")
        self.assertEqual(body["cpu"]["y"], 2)

    def test_nested_class_bomb_on_the_light_tick(self):
        self._plant({"x": _ClassBomb(), "y": 2})
        body = self._get("/api/system/sensors?light=true")
        self.assertEqual(body["cpu"]["y"], 2)

    def test_class_bomb_key_keeps_the_sibling_entries(self):
        self._plant({_ClassBomb(): 1, "y": 2})
        body = self._get("/api/system/sensors")
        self.assertEqual(body["cpu"]["y"], 2)
        # The bombed key renders through str() and keeps its value.
        self.assertIn(1, body["cpu"].values())

    def test_whole_cache_class_bomb_degrades_to_an_empty_sample(self):
        sensors_svc._cache.update(t=time.time(), v=_ClassBomb())
        resp = self.client.get("/api/system/sensors")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertIsInstance(resp.json(), dict)

    def test_peek_sensors_no_longer_raises_the_whole_cache_bomb(self):
        sensors_svc._cache.update(t=time.time(), v=_ClassBomb())
        self.assertIsNone(sensors_svc.peek_sensors())

    def test_lying_impostors_drop_and_siblings_survive(self):
        for impostor in (_LyingDict(), _LyingList(), _LyingBytes()):
            self._plant({"x": impostor, "y": 2})
            body = self._get("/api/system/sensors")
            self.assertIsNone(body["cpu"]["x"])
            self.assertEqual(body["cpu"]["y"], 2)


class TopCacheClassBombTests(_SensorsCacheSandbox):
    """The top-cache leg: one ex-500 and one silent top-leg wipe."""

    def test_nested_bomb_in_the_top_cache_cannot_500_the_cold_collect(self):
        sensors_svc._cache.update(t=0.0, v=None)
        sensors_svc._top_cache.update(
            t=time.time(), v={"physmem_raw": _ClassBomb()})
        body = self._get("/api/system/sensors")
        self.assertIn("cpu", body)

    def test_whole_cache_bomb_recollects_instead_of_raising(self):
        """``_cpu_and_mem_from_top_cached`` used to detonate its own
        isinstance gate on the poisoned hit (the pool swallowed it and
        silently wiped PhysMem / load for a TTL)."""
        sensors_svc._top_cache.update(t=time.time(), v=_ClassBomb())
        out = sensors_svc._cpu_and_mem_from_top_cached()
        self.assertIsInstance(out, dict)


# ---------------------------------------------------------------------------
# system: the SMART cache feeding the /api/status system tile
# ---------------------------------------------------------------------------


class SmartCacheClassBombTests(unittest.TestCase):
    """A SMART-cache bomb silently wiped the whole system tile."""

    def setUp(self):
        self._smart = dict(system._smart_cache)
        self.addCleanup(lambda: system._smart_cache.update(self._smart))
        self.addCleanup(status_mod.invalidate_status)
        self.client = _client()

    def _status_system(self) -> dict:
        status_mod.invalidate_status()
        resp = self.client.get("/api/status?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        sysobj = body.get("system")
        self.assertIsInstance(sysobj, dict)
        self.assertTrue(sysobj, "system tile wiped by the smart-cache bomb")
        self.assertIn("uptime_hours", sysobj)
        return sysobj

    def test_nested_class_bomb_keeps_the_tile_and_the_wear_sibling(self):
        system._smart_cache.update(
            t=time.time(), v={"temp": _ClassBomb(), "wear": "3%"})
        out = system.collect_system()
        self.assertIsInstance(out, dict)
        self.assertEqual((out.get("smart") or {}).get("wear"), "3%")
        sysobj = self._status_system()
        self.assertEqual((sysobj.get("smart") or {}).get("wear"), "3%")

    def test_whole_cache_class_bomb_degrades_the_smart_field_alone(self):
        system._smart_cache.update(t=time.time(), v=_ClassBomb())
        out = system.collect_system()
        self.assertIsInstance(out, dict)
        self.assertIn("uptime_hours", out)
        self._status_system()

    def test_rc_eq_bomb_keeps_the_tile(self):
        """rc-``__eq__`` bombs on the boottime / smartctl probes sit in
        ``collect_system``'s main body: one used to wipe the whole tile."""
        system._smart_cache.update(t=0.0, v=None)  # force the smartctl leg
        with mock.patch.object(
            system, "sh", return_value=(_EqBombInt(0), "", "")
        ):
            out = system.collect_system()
        self.assertIsInstance(out, dict)
        self.assertIn("uptime_hours", out)


# ---------------------------------------------------------------------------
# status: the cached snapshot and the config reads of a cold build
# ---------------------------------------------------------------------------


class _StatusCacheSandbox(unittest.TestCase):
    def setUp(self):
        self._cache = dict(status_mod._status_cache)
        self.addCleanup(status_mod.invalidate_status)
        self.addCleanup(
            lambda: status_mod._status_cache.update(self._cache))
        self.client = _client()


class StatusCacheClassBombTests(_StatusCacheSandbox):
    """The ex-500s on cache-hit GET /api/status."""

    def test_whole_cache_class_bomb_no_longer_500s_the_cache_hit(self):
        status_mod._status_cache.update(t=time.time(), v=_ClassBomb())
        resp = self.client.get("/api/status")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _starlette(resp.json())

    def test_nested_class_bomb_keeps_the_sane_snapshot_fields(self):
        status_mod._status_cache.update(
            t=time.time(),
            v={"counts": {"ok": 1}, "groups": [], "system": _ClassBomb()},
        )
        resp = self.client.get("/api/status")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["counts"]["ok"], 1)

    def test_cfg_root_class_bomb_no_longer_500s_a_cold_build(self):
        bomb = _ClassBomb()
        with mock.patch.object(status_mod, "cfg", lambda: bomb):
            status_mod.invalidate_status()
            resp = self.client.get("/api/status?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _starlette(resp.json())

    def test_quick_links_class_bomb_no_longer_500s_a_cold_build(self):
        with mock.patch.object(
            status_mod, "cfg",
            lambda: {"settings": {"adaptive": False},
                     "quick_links": _ClassBomb()},
        ):
            status_mod.invalidate_status()
            resp = self.client.get("/api/status?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["links"], [])

    def test_bool_bomb_adaptive_setting_reads_as_off(self):
        with mock.patch.object(
            status_mod, "cfg",
            lambda: {"settings": {"adaptive": _BoolBomb()}},
        ):
            status_mod.invalidate_status()
            resp = self.client.get("/api/status?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json().get("adaptive"), {})


class StaysImmuneTests(_StatusCacheSandbox):
    """Vectors that were already immune — pinned so a probe reorder cannot
    start relying on the raise dash9 just removed elsewhere."""

    def test_health_stays_200_under_the_whole_cache_bomb(self):
        status_mod._status_cache.update(t=time.time(), v=_ClassBomb())
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _starlette(resp.json())

    def test_health_stays_200_under_the_nested_bomb(self):
        status_mod._status_cache.update(
            t=time.time(),
            v={"counts": {"ok": 1}, "groups": [], "system": _ClassBomb()},
        )
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _starlette(resp.json())

    def test_sensors_rc_eq_bomb_stays_200(self):
        """The per-leg pool guards already isolate an rc bomb in the
        sensors collectors: the bomb costs its own leg, never the route."""
        saved = dict(sensors_svc._cache)
        saved_top = dict(sensors_svc._top_cache)
        self.addCleanup(lambda: sensors_svc._cache.update(saved))
        self.addCleanup(lambda: sensors_svc._top_cache.update(saved_top))
        sensors_svc._cache.update(t=0.0, v=None)
        sensors_svc._top_cache.update(t=0.0, v=None)
        with mock.patch.object(
            sensors_svc, "sh", return_value=(_EqBombInt(0), "", "")
        ):
            resp = self.client.get("/api/system/sensors")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _starlette(resp.json())

    def test_nested_quick_link_bomb_is_contained_by_the_route(self):
        """A bomb nested *inside* a quick_links row raises out of
        resolve_value (by contract) and the route's catch keeps a 200."""
        with mock.patch.object(
            status_mod, "cfg",
            lambda: {"settings": {"adaptive": False},
                     "quick_links": [
                         {"name": _ClassBomb(), "url": "http://a.lan"}]},
        ):
            status_mod.invalidate_status()
            resp = self.client.get("/api/status?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["links"], [])

    def test_torn_ipv6_url_stays_unsplit_not_raised(self):
        """``urlsplit`` ValueErrors a torn IPv6 netloc; the existing catch
        keeps the raw URL rather than raising out of the URL writers."""
        raw = "http://[::1:8080/x"
        self.assertEqual(host_address.normalize_local_url(raw), raw)

    def test_plain_str_subclass_stays_immune_in_every_scrub(self):
        # CPython copies a default-``__str__`` subclass to exact str before
        # the scrubs; pin all three module conventions either way.
        self.assertEqual(host_address._as_text(_PlainStrSub("a")), "a")
        self.assertEqual(sensors_svc._utf8_text(_PlainStrSub("b")), "b")
        self.assertEqual(system._as_text(_PlainStrSub("c")), "c")
        self.assertEqual(status_mod._utf8_text(_PlainStrSub("d")), "d")


if __name__ == "__main__":
    unittest.main()
