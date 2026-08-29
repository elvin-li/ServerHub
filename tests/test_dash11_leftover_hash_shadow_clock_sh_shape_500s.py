"""Eleventh leftover-500s sweep of the Dashboard: hash-shadowing mapping
keys, clock-slot bombs and ``sh()`` answer-shape bombs, over the real
mounted app.

dash10 sealed the lying-``__class__`` impostors and the collector-list
seams.  Re-running the zoo with the health11 *hash-shadow* key shape and
the docker11 *answer-shape* bombs surfaced live leftovers on every
dashboard route:

* a str-subclass key whose hash shadows a real key and whose ``__eq__``
  raises — even a plain-dict lookup runs the *stored* keys' compare during
  the hash probe — detonated the bare ``_status_cache["v"]`` /
  ``_status_cache["t"]`` subscripts in ``full_status`` (a raw 500 on every
  GET /api/status), a shadowed ``locale`` in the cached snapshot blew
  ``_stamp_locale``'s bound ``.get`` and its ``status["locale"] = …``
  insert compare on every cache hit, and a shadowed ``adaptive`` key
  survived ``_build_status``'s plain-dict copy and blew the very first
  read of a cold build;
* the same shadow shape planted in ``sensors_svc._cache`` 500'd
  GET /api/system/sensors from ``peek_sensors`` / ``collect_sensors`` and
  from the final ``_cache.update`` insert compare at the end of a
  *successful* collection; in ``system._smart_cache`` it raised out of
  ``collect_system`` and silently wiped the whole system tile;
* a *clock bomb* planted in any ``t`` slot (``__float__`` / ``__rsub__``
  / comparison raising) blew the bare ``now - cache["t"]`` age arithmetic
  the same way — GET /api/status and GET /api/system/sensors alike;
* an ``sh()`` *answer-shape* bomb (2-tuple, scalar, tuple subclass whose
  ``__iter__`` raises, lying-``__class__`` tuple impostor) detonated the
  bare ``rc, out, _ = …`` unpacks in ``host_address`` and
  ``system_extra._host_snapshot`` — a raw 500 on GET /api/system/host —
  and in ``sensors_svc._memory_base``, which runs on the request thread
  of the light GET /api/system/sensors tick (plus an uncaught
  ``rc != 0`` probe one line past ``macos_sysctl.sysctl_int``'s guard);
* on GET /api/bookmarks, ``resolve_value``'s all-or-nothing fallback
  keeps the whole ``quick_links`` list raw when one sibling row bombs,
  and ``_plain_dict``'s C-level copy preserves a raw row's keys — so a
  hash-shadowing ``url`` key then detonated every bound ``link.get``
  downstream, after every probe had already succeeded.

Conflict policy is pinned, not re-claimed: ``resolve_value`` stays
raise-on-junk (the bookmarks5 / docker9 pin — a junk *container* raises,
a leaf passes untouched), ``_isa`` stays fail-closed, the dash10
type-is-bool gates and guarded decodes are untouched, and junk rc /
shapes read ``-255`` — never a success status.  Product version stays
3.9.3.
"""
from __future__ import annotations

import json
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from fastapi.testclient import TestClient  # noqa: E402

from hub import bookmarks_svc, host_address, macos_sysctl, sensors_svc, system  # noqa: E402
import hub.routers.system_extra as system_extra  # noqa: E402
import hub.status as status_mod  # noqa: E402
from hub.auth import require_auth  # noqa: E402

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


def _shadow_key(target: str):
    """A str-subclass key whose hash shadows *target* and whose ``__eq__``
    raises: inserting it downgrades the dict off the unicode fast path, and
    any later C-level probe for *target* lands on its slot and detonates
    the compare.  The health11 / vms / terminal hash-shadow zoo shape."""

    class Shadow(str):
        __hash__ = lambda self: hash(target)  # noqa: E731

        def __eq__(self, other):
            raise RuntimeError("shadow eq bomb")

        __ne__ = __eq__

    return Shadow("junk-" + target)


class _ClockBomb:
    """A leftover in a ``t`` slot that no arithmetic can read."""

    def __sub__(self, other):
        raise RuntimeError("clock bomb")

    def __rsub__(self, other):
        raise RuntimeError("clock bomb")

    def __float__(self):
        raise RuntimeError("clock bomb")


class _IterBombTuple(tuple):
    """A real tuple subclass whose bound iteration raises."""

    def __iter__(self):
        raise RuntimeError("iter bomb")


class _TupleLiar:
    """Claims to be a tuple; has no real sequence storage."""

    @property
    def __class__(self):
        return tuple


def _sh_shape(answer):
    """A patched ``sh`` that always answers *answer*."""

    def fake(cmd, timeout=10, **kwargs):
        return answer

    return fake


def _sh_raises(cmd, timeout=10, **kwargs):
    raise RuntimeError("sh spawn bomb")


_SANE_SH = (1, "", "")


# ---------------------------------------------------------------------------
# status: the module cache itself
# ---------------------------------------------------------------------------


class _StatusCacheSandbox(unittest.TestCase):
    def setUp(self):
        saved = dict(status_mod._status_cache)

        def _restore():
            status_mod._status_cache.clear()
            status_mod._status_cache.update(saved)

        self.addCleanup(status_mod.invalidate_status)
        self.addCleanup(_restore)
        self.client = _client()


class StatusCacheShadowKeyTests(_StatusCacheSandbox):
    """The ex-500s from shadow keys planted in ``_status_cache``."""

    def test_shadowed_v_slot_rebuilds_instead_of_500(self):
        status_mod._status_cache.clear()
        status_mod._status_cache[_shadow_key("v")] = 1
        resp = self.client.get("/api/status")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIn("counts", body)

    def test_shadowed_t_slot_survives_the_cache_write(self):
        # Pre-fix: the build succeeded and the final _cache_publish insert
        # compare detonated — a 500 at the end of a healthy cold build.
        status_mod._status_cache.clear()
        status_mod._status_cache["v"] = None
        status_mod._status_cache[_shadow_key("t")] = 1
        resp = self.client.get("/api/status")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _starlette(resp.json())

    def test_clock_bomb_t_slot_reads_as_expired_not_500(self):
        status_mod._status_cache.clear()
        status_mod._status_cache.update(
            t=_ClockBomb(), v={"counts": {"ok": 1}, "groups": []})
        resp = self.client.get("/api/status")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _starlette(resp.json())

    def test_invalidate_status_survives_a_shadowed_t(self):
        status_mod._status_cache.clear()
        status_mod._status_cache["v"] = {"counts": {}, "groups": []}
        status_mod._status_cache[_shadow_key("t")] = 1
        status_mod.invalidate_status()  # pre-fix: raised out of ["t"] = 0
        # The snapshot /api/health serves must survive the eviction.
        self.assertIsInstance(status_mod.cached_status(), dict)

    def test_cached_status_reads_through_a_shadowed_v(self):
        status_mod._status_cache.clear()
        status_mod._status_cache[_shadow_key("v")] = 1
        self.assertIsNone(status_mod.cached_status())
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200, resp.text[:300])


class StampLocaleShadowTests(_StatusCacheSandbox):
    """The ex-500s on every cache-hit GET /api/status."""

    def _plant(self, snap: dict) -> None:
        status_mod._status_cache.clear()
        status_mod._status_cache.update(t=time.time(), v=snap)

    def test_shadowed_locale_key_keeps_the_cache_hit(self):
        snap = {"counts": {"ok": 1}, "groups": []}
        snap[_shadow_key("locale")] = 1
        self._plant(snap)
        resp = self.client.get("/api/status")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["counts"]["ok"], 1)
        # The laundered copy still carries a current locale stamp.
        self.assertIsInstance(body.get("locale"), str)
        self.assertTrue(body["locale"])

    def test_locale_still_restamps_on_an_ordinary_hit(self):
        self._plant({"counts": {"ok": 1}, "groups": [], "locale": "stale"})
        resp = self.client.get("/api/status")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertNotEqual(resp.json().get("locale"), "stale")

    def test_str_subclass_locale_answer_is_laundered_not_compared(self):
        class NeBomb(str):
            def __ne__(self, other):
                raise RuntimeError("ne bomb")

            __eq__ = __ne__

        self._plant({"counts": {"ok": 1}, "groups": [], "locale": "zh-CN"})
        with mock.patch.object(
            status_mod, "panel_locale", return_value=NeBomb("zh-CN")
        ):
            resp = self.client.get("/api/status")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json().get("locale"), "zh-CN")


class ColdBuildShadowTests(_StatusCacheSandbox):
    """The ex-500 on the first read of a cold GET /api/status."""

    def _cold_get(self, cfg_map: dict):
        with mock.patch.object(status_mod, "cfg", lambda: cfg_map):
            status_mod.invalidate_status()
            status_mod._status_cache.clear()
            status_mod._status_cache.update(t=0.0, v=None)
            return self.client.get("/api/status?force=true")

    def test_shadowed_adaptive_key_degrades_to_the_default_alone(self):
        settings = {}
        settings[_shadow_key("adaptive")] = 1
        resp = self._cold_get({"settings": settings, "quick_links": []})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIn("counts", body)

    def test_shadowed_adaptive_cache_key_keeps_the_cold_build(self):
        saved = dict(status_mod._adaptive_cache)

        def _restore():
            status_mod._adaptive_cache.clear()
            status_mod._adaptive_cache.update(saved)

        self.addCleanup(_restore)
        status_mod._adaptive_cache.clear()
        status_mod._adaptive_cache[_shadow_key("compose")] = 1
        status_mod._adaptive_cache["t"] = 0.0
        resp = self._cold_get(
            {"settings": {"adaptive": True}, "quick_links": []})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _starlette(resp.json())


# ---------------------------------------------------------------------------
# sensors: cache shadow keys, clock bombs and the light-tick sh shape
# ---------------------------------------------------------------------------


class _SensorsCacheSandbox(unittest.TestCase):
    def setUp(self):
        saved = dict(sensors_svc._cache)

        def _restore():
            sensors_svc._cache.clear()
            sensors_svc._cache.update(saved)

        self.addCleanup(_restore)
        self.client = _client()

    def _get_ok(self, path: str) -> dict:
        resp = self.client.get(path)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        return body


class SensorsCacheShadowTests(_SensorsCacheSandbox):
    """The ex-500s on GET /api/system/sensors."""

    def test_shadowed_v_slot_recollects_instead_of_500(self):
        sensors_svc._cache.clear()
        sensors_svc._cache[_shadow_key("v")] = 1
        sensors_svc._cache["t"] = 0.0
        body = self._get_ok("/api/system/sensors")
        self.assertIsInstance(body, dict)

    def test_clock_bomb_t_slot_reads_as_expired_not_500(self):
        sensors_svc._cache.clear()
        sensors_svc._cache.update(t=_ClockBomb(), v={"cpu": {"y": 2}})
        body = self._get_ok("/api/system/sensors")
        self.assertIsInstance(body, dict)

    def test_shadowed_t_slot_survives_the_final_cache_write(self):
        # Pre-fix: the collection succeeded and the final ``_cache.update``
        # insert compare detonated — a 500 at the end of a healthy collect.
        sensors_svc._cache.clear()
        sensors_svc._cache["v"] = None
        sensors_svc._cache[_shadow_key("t")] = 1
        body = self._get_ok("/api/system/sensors?force=true")
        self.assertIsInstance(body, dict)
        # clear+rewrite evicted the poison: the next hit is an ordinary one.
        self.assertEqual(
            [type(k) for k in sensors_svc._cache.keys()], [str, str])

    def test_peek_sensors_reads_through_the_shadow(self):
        sensors_svc._cache.clear()
        sensors_svc._cache[_shadow_key("v")] = 1
        sensors_svc._cache["t"] = time.time()
        self.assertIsNone(sensors_svc.peek_sensors())

    def test_sane_cache_hit_still_serves(self):
        sensors_svc._cache.clear()
        sensors_svc._cache.update(t=time.time(), v={"cpu": {"y": 2}})
        body = self._get_ok("/api/system/sensors")
        self.assertEqual(body["cpu"]["y"], 2)


class SensorsShShapeTests(_SensorsCacheSandbox):
    """The ex-500s on the light GET /api/system/sensors tick."""

    def _light_get(self, sh_impl) -> dict:
        sensors_svc._cache.clear()
        sensors_svc._cache.update(t=0.0, v=None)
        saved_static = dict(sensors_svc._static)

        def _restore():
            sensors_svc._static.clear()
            sensors_svc._static.update(saved_static)

        self.addCleanup(_restore)
        sensors_svc._static.update(t=0.0, ncpu=None, mem_gb=None)
        with mock.patch.object(sensors_svc, "sh", sh_impl), \
                mock.patch("hub.resource_mode.is_high", lambda: False):
            return self._get_ok("/api/system/sensors?light=true")

    def test_two_tuple_sh_answer_degrades_the_leg_not_the_route(self):
        body = self._light_get(_sh_shape((1, "")))
        self.assertIs(body.get("light"), True)

    def test_scalar_sh_answer_degrades_the_leg_not_the_route(self):
        body = self._light_get(_sh_shape(object()))
        self.assertIs(body.get("light"), True)

    def test_iter_bomb_tuple_subclass_degrades_the_leg(self):
        body = self._light_get(_sh_shape(_IterBombTuple((0, "x", ""))))
        self.assertIs(body.get("light"), True)

    def test_tuple_liar_degrades_the_leg(self):
        body = self._light_get(_sh_shape(_TupleLiar()))
        self.assertIs(body.get("light"), True)

    def test_raising_sh_degrades_the_leg_not_the_route(self):
        body = self._light_get(_sh_raises)
        self.assertIs(body.get("light"), True)

    def test_rc_ne_bomb_through_sysctl_int_stays_a_none(self):
        class RcBomb(int):
            def __ne__(self, other):
                raise RuntimeError("rc ne bomb")

            __eq__ = __ne__

        with mock.patch.object(
            macos_sysctl, "sysctlbyname_int", lambda name: None
        ):
            self.assertIsNone(
                macos_sysctl.sysctl_int(
                    "hw.ncpu", timeout=1, sh=_sh_shape((RcBomb(0), "8", "")))
            )

    def test_sh_run_keeps_a_real_answer_exactly(self):
        with mock.patch.object(
            sensors_svc, "sh", _sh_shape((0, "out", "err"))
        ):
            self.assertEqual(
                sensors_svc._sh_run(["/bin/echo"], timeout=1),
                (0, "out", "err"),
            )
        # A real tuple subclass with honest storage survives the unwrap.
        class TupleWrap(tuple):
            pass

        with mock.patch.object(
            sensors_svc, "sh", _sh_shape(TupleWrap((0, "o", "e")))
        ):
            self.assertEqual(
                tuple(sensors_svc._sh_run(["/bin/echo"], timeout=1)),
                (0, "o", "e"),
            )


# ---------------------------------------------------------------------------
# system tile: the SMART cache shapes ride collect_system into /api/status
# ---------------------------------------------------------------------------


class SmartCacheShadowTests(unittest.TestCase):
    def setUp(self):
        saved = dict(system._smart_cache)

        def _restore():
            system._smart_cache.clear()
            system._smart_cache.update(saved)

        self.addCleanup(_restore)

    def test_clock_bomb_t_slot_keeps_the_tile(self):
        system._smart_cache.clear()
        system._smart_cache.update(t=_ClockBomb(), v=None)
        out = system.collect_system()
        self.assertIsInstance(out, dict)
        self.assertIn("uptime_hours", out)
        _starlette(out)

    def test_shadowed_v_slot_keeps_the_tile(self):
        system._smart_cache.clear()
        system._smart_cache["t"] = time.time()
        system._smart_cache[_shadow_key("v")] = 1
        out = system.collect_system()
        self.assertIsInstance(out, dict)
        self.assertIn("load", out)
        _starlette(out)

    def test_sh_shape_bomb_keeps_load_and_disk(self):
        system._smart_cache.clear()
        system._smart_cache.update(t=0.0, v=None)
        with mock.patch.object(system, "sh", _sh_shape((1, ""))):
            out = system.collect_system()
        self.assertIsInstance(out, dict)
        self.assertIn("disk_pct", out)
        _starlette(out)

    def test_sh3_junk_shapes_read_as_failure(self):
        for junk in ((1, ""), object(), _TupleLiar()):
            self.assertEqual(system._sh3(junk), (-255, "", ""))
        self.assertEqual(system._sh3((0, "o", "e")), (0, "o", "e"))
        # A real subclass with honest 3-tuple storage is salvaged through
        # the unbound read (the nginx rule), bypassing its bound bomb.
        self.assertEqual(
            tuple(system._sh3(_IterBombTuple((0, "x", "")))), (0, "x", ""))


# ---------------------------------------------------------------------------
# host: sh answer-shape through host_address and the host snapshot
# ---------------------------------------------------------------------------


class HostShShapeTests(unittest.TestCase):
    def setUp(self):
        host_address.invalidate_routing()
        self.addCleanup(host_address.invalidate_routing)
        try:
            system_extra._host_snapshot.invalidate()
            self.addCleanup(system_extra._host_snapshot.invalidate)
        except Exception:
            pass
        self.client = _client()

    def _host_ok(self) -> dict:
        resp = self.client.get("/api/system/host?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        return body

    def test_two_tuple_sh_no_longer_500s_the_host_route(self):
        with mock.patch.object(system_extra, "sh", _sh_shape((1, ""))), \
                mock.patch.object(host_address, "sh", _sh_shape((1, ""))):
            body = self._host_ok()
        self.assertIsInstance(body.get("host_ip"), str)
        self.assertIsInstance(body.get("hostname"), str)

    def test_scalar_sh_answer_via_host_address_alone(self):
        with mock.patch.object(host_address, "sh", _sh_shape(None)):
            body = self._host_ok()
        self.assertIsInstance(body.get("host_ip"), str)

    def test_iter_bomb_tuple_subclass_keeps_the_route(self):
        bomb = _IterBombTuple((0, "gateway: 1.2.3.4", ""))
        with mock.patch.object(system_extra, "sh", _sh_shape(bomb)), \
                mock.patch.object(host_address, "sh", _sh_shape(bomb)):
            body = self._host_ok()
        self.assertIsInstance(body.get("interfaces"), list)

    def test_raising_sh_keeps_the_route(self):
        with mock.patch.object(host_address, "sh", _sh_raises):
            body = self._host_ok()
        self.assertIsInstance(body.get("host_ip"), str)

    def test_default_route_fields_answer_real_subclass_storage(self):
        class TupleWrap(tuple):
            pass

        answer = TupleWrap((0, "gateway: 1.2.3.4\ninterface: en0", ""))
        with mock.patch.object(host_address, "sh", _sh_shape(answer)):
            host_address.invalidate_routing()
            fields = dict(host_address._default_route_fields())
        self.assertEqual(fields.get("interface"), "en0")


# ---------------------------------------------------------------------------
# bookmarks: raw-kept shadow-key rows after resolve_value's fallback
# ---------------------------------------------------------------------------


class _ItemsBombRow(dict):
    """A junk container: resolve_value raises on it (the bookmarks5 pin),
    which flips list_bookmarks into its all-or-nothing raw fallback."""

    def items(self):
        raise RuntimeError("items bomb")


_PROBE_OK = {"ok": True, "status": 200, "ms": 1, "error": None}


class BookmarksShadowRowTests(unittest.TestCase):
    def setUp(self):
        bookmarks_svc.list_bookmarks.invalidate()
        self.addCleanup(bookmarks_svc.list_bookmarks.invalidate)
        self.client = _client()

    def _get(self, quick_links, overrides=None) -> dict:
        with mock.patch.object(
            bookmarks_svc, "cfg",
            lambda: {"quick_links": quick_links,
                     "overrides": overrides or {}},
        ), mock.patch.object(
            bookmarks_svc, "_backend_index", lambda: {}
        ), mock.patch.object(
            bookmarks_svc, "_probe",
            lambda url, timeout=3.0: dict(_PROBE_OK),
        ):
            resp = self.client.get("/api/bookmarks?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        return body

    def test_shadow_url_row_costs_only_itself(self):
        shadow_row = {}
        shadow_row[_shadow_key("url")] = "http://x.lan"
        body = self._get([
            _ItemsBombRow({"name": "junk"}),
            shadow_row,
            {"name": "a", "url": "http://a.lan"},
        ])
        urls = [row.get("url") for row in body["bookmarks"]]
        self.assertEqual(urls, ["http://a.lan"])
        self.assertEqual(body["up"], 1)

    def test_shadow_name_key_keeps_the_row_and_its_url(self):
        row = {"url": "http://b.lan"}
        row[_shadow_key("name")] = 1
        body = self._get([_ItemsBombRow({"name": "junk"}), row])
        urls = [r.get("url") for r in body["bookmarks"]]
        self.assertIn("http://b.lan", urls)

    def test_shadow_service_key_keeps_the_backend_resolution(self):
        row = {"url": "http://c.lan"}
        row[_shadow_key("service")] = 1
        body = self._get([_ItemsBombRow({"name": "junk"}), row])
        self.assertEqual(len(body["bookmarks"]), 1)
        self.assertEqual(body["bookmarks"][0]["health"], "ok")

    def test_mapping_get_degrades_only_the_shadowed_field(self):
        d = {"keep": 2}
        d[_shadow_key("gone")] = 1
        self.assertIsNone(bookmarks_svc._mapping_get(d, "gone"))
        self.assertEqual(bookmarks_svc._mapping_get(d, "keep"), 2)
        self.assertEqual(bookmarks_svc._mapping_get(object(), "k", "d"), "d")


# ---------------------------------------------------------------------------
# stays-immune pins
# ---------------------------------------------------------------------------


class _ClassBomb:
    """A leftover that cannot answer what it is: ``isinstance`` raises."""

    @property
    def __class__(self):
        raise RuntimeError("class bomb")


class _LyingBool:
    @property
    def __class__(self):
        return bool


class StaysImmuneTests(unittest.TestCase):
    """Union guards from prior sweeps stay exactly where their pins put
    them; the new guards must not have weakened any of them."""

    def test_resolve_value_still_raises_a_junk_container(self):
        """The bookmarks5 / docker9 raise-on-junk pin is untouched: a bomb
        *container* still raises out of the walk so callers' try/except
        junk-drop keeps working."""
        with self.assertRaises(RuntimeError):
            host_address.resolve_value({"u": "x", "junk": _ClassBomb()})
        with self.assertRaises(RuntimeError):
            host_address.resolve_value(
                [_ItemsBombRow({"name": "j"}), {"u": "x"}])

    def test_resolve_value_passes_a_leaf_untouched(self):
        bomb = _LyingBool()
        out = host_address.resolve_value({"u": "x", "flag": bomb})
        self.assertIs(out["flag"], bomb)
        self.assertEqual(out["u"], "x")

    def test_resolve_value_launders_shadow_keys_to_exact_strs(self):
        """A shadow key in a *well-behaved* row never reaches the raw
        fallback: the walker rebuilds mappings with exact-str keys."""
        row = {"url": "http://a.lan"}
        row[_shadow_key("name")] = "x"
        out = host_address.resolve_value([row])
        self.assertEqual([type(k) for k in out[0]], [str, str])

    def test_jsonable_bool_gates_stay_exact_type(self):
        for scrub in (
            status_mod._jsonable, sensors_svc._jsonable, system._jsonable,
        ):
            self.assertIsNone(scrub(_LyingBool()))
            self.assertIs(scrub(True), True)
            self.assertIs(scrub(False), False)

    def test_rc_int_junk_still_reads_minus_255(self):
        class RcBomb:
            def __index__(self):
                raise RuntimeError("boom")

        for mod in (host_address, system, sensors_svc, system_extra):
            self.assertEqual(mod._rc_int(RcBomb()), -255)
            self.assertEqual(mod._rc_int(0), 0)
            self.assertEqual(mod._rc_int(True), 1)

    def test_health_still_serves_through_a_poisoned_status_cache(self):
        saved = dict(status_mod._status_cache)

        def _restore():
            status_mod._status_cache.clear()
            status_mod._status_cache.update(saved)

        self.addCleanup(_restore)
        status_mod._status_cache.clear()
        status_mod._status_cache.update(
            t=time.time(), v={"counts": {"ok": 1}, "groups": []})
        resp = _client().get("/api/health")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _starlette(resp.json())

    def test_version_stays_pinned(self):
        from hub import __version__

        self.assertEqual(__version__, "3.9.5")


if __name__ == "__main__":
    unittest.main()
