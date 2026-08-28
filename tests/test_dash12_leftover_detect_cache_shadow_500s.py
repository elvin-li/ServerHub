"""Twelfth leftover-500s sweep of the Dashboard: the LAN-detection cache.

dash11 sealed the hash-shadowing mapping keys, clock-slot bombs and
``sh()`` answer-shape bombs across the status / sensors / system / host
surfaces — but it hardened only the *module* caches those sweeps had
already named: ``status._status_cache`` / ``_adaptive_cache``,
``sensors_svc._cache`` / ``_static`` / ``_top_cache`` / ``_net_prev`` and
``system._smart_cache``.  Re-running the health11 *hash-shadow* key shape
against the one dashboard cache those pins never reached — the
``host_address._detect_cache`` that backs ``host_ip()`` — surfaced a live
leftover on GET /api/system/host:

* a str-subclass key whose hash shadows ``value`` and whose ``__eq__``
  raises detonated the bare ``_detect_cache["value"]`` read in
  ``_cached_detection`` — even a plain-dict lookup runs the *stored* key's
  compare during the hash probe — a raw 500 on GET /api/system/host
  through ``host_ip()`` → ``detect_lan_ip()`` (the ``t`` sibling was
  already inside a try, so only ``value`` blew the read);
* the same shadow shape planted over ``t`` survived the guarded read but
  detonated the ``_detect_cache.update(t=…, value=…)`` insert compare at
  the very end of a *successful* detection in ``_detect_lan_ip_uncached``
  — a 500 on the cold GET /api/system/host — and blew the identical
  ``_detect_cache.update(t=0.0, value=None)`` in ``invalidate_routing``,
  which ``network_svc._bust()`` reaches on every address / DNS / order /
  alias change.

The fix is the health11 / dash11 rule the sibling caches already carry:
``_mapping_get`` on the read (the shadowed slot degrades to its default
and re-detects) and ``_cache_publish`` on the writes (``clear()`` never
compares keys, so evicting the poison and rewriting always lands).

Conflict policy is pinned, not re-claimed: ``resolve_value`` stays
raise-on-junk (the bookmarks5 / docker9 pin), ``_isa`` stays fail-closed,
``_sh_run`` / ``_rc_int`` keep laundering answer-shape and rc bombs, the
guarded unbound decode stays, and the dash11 ``_mapping_get`` / ``_cache_age``
pins on the status / sensors caches are untouched.  Product version stays
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

from hub import host_address, sensors_svc, system  # noqa: E402
import hub.status as status_mod  # noqa: E402
import hub.routers.system_extra as system_extra  # noqa: E402
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
    the compare.  The health11 / dash11 hash-shadow zoo shape."""

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


# ---------------------------------------------------------------------------
# host: the LAN-detection cache behind host_ip()
# ---------------------------------------------------------------------------


class _DetectCacheSandbox(unittest.TestCase):
    def setUp(self):
        saved = dict(host_address._detect_cache)

        def _restore():
            host_address._detect_cache.clear()
            host_address._detect_cache.update(saved)

        self.addCleanup(host_address.invalidate_routing)
        self.addCleanup(_restore)
        # host_ip() only reaches the detection cache when the advertised
        # host is "auto"; pin it so the route exercises the seam regardless
        # of the runner's SERVERHUB_HOST / cfg host_ip.
        p = mock.patch.object(host_address, "configured_host", lambda: "auto")
        p.start()
        self.addCleanup(p.stop)
        try:
            system_extra._host_snapshot.invalidate()
            self.addCleanup(system_extra._host_snapshot.invalidate)
        except Exception:
            pass
        self.client = _client()

    def _plant(self, **fields):
        host_address._detect_cache.clear()
        host_address._detect_cache.update(fields)

    def _host_ok(self) -> dict:
        resp = self.client.get("/api/system/host?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        return body


class DetectCacheShadowKeyTests(_DetectCacheSandbox):
    """The ex-500s from shadow keys planted in ``_detect_cache``."""

    def test_shadowed_value_slot_redetects_instead_of_500(self):
        # Pre-fix: the bare ``_detect_cache["value"]`` read ran the stored
        # poison key's ``__eq__`` during the probe — a raw 500 on the route.
        self._plant()
        host_address._detect_cache["t"] = time.time()
        host_address._detect_cache[_shadow_key("value")] = "1.2.3.4"
        body = self._host_ok()
        self.assertIsInstance(body.get("host_ip"), str)

    def test_shadowed_t_slot_survives_the_detection_write(self):
        # Pre-fix: the guarded read fell through to a re-detect whose final
        # ``_detect_cache.update`` insert compare detonated — a 500 at the
        # end of a healthy cold detection.
        self._plant()
        host_address._detect_cache["value"] = "1.2.3.4"
        host_address._detect_cache[_shadow_key("t")] = 1
        body = self._host_ok()
        self.assertIsInstance(body.get("host_ip"), str)
        # clear+rewrite evicted the poison: the cache now holds only strs.
        self.assertEqual(
            sorted(type(k).__name__ for k in host_address._detect_cache),
            ["str", "str"],
        )

    def test_clock_bomb_t_slot_reads_as_expired_not_500(self):
        # Already handled (the read sits in a try); pinned so the new guards
        # did not regress it.
        self._plant(value="1.2.3.4", t=_ClockBomb())
        body = self._host_ok()
        self.assertIsInstance(body.get("host_ip"), str)

    def test_invalidate_routing_survives_a_shadowed_key(self):
        # network_svc._bust() reaches invalidate_routing() on every address
        # change; pre-fix its ``_detect_cache.update`` raised on the poison.
        self._plant()
        host_address._detect_cache["value"] = "1.2.3.4"
        host_address._detect_cache[_shadow_key("t")] = 1
        host_address.invalidate_routing()  # pre-fix: raised out of update
        self.assertEqual(
            [type(k).__name__ for k in host_address._detect_cache], ["str", "str"]
        )


class DetectCacheHelperTests(_DetectCacheSandbox):
    """The guards themselves, at the unit boundary."""

    def test_cached_detection_reads_through_a_shadowed_value(self):
        self._plant()
        host_address._detect_cache["t"] = time.time()
        host_address._detect_cache[_shadow_key("value")] = "1.2.3.4"
        # No real ``value`` key survives the shadow, so the slot degrades to
        # None and the read reports a miss rather than raising.
        self.assertEqual(host_address._cached_detection(time.time()), "")

    def test_mapping_get_degrades_only_the_shadowed_field(self):
        d = {"keep": "2"}
        d[_shadow_key("gone")] = 1
        self.assertIsNone(host_address._mapping_get(d, "gone"))
        self.assertEqual(host_address._mapping_get(d, "keep"), "2")
        self.assertEqual(host_address._mapping_get(object(), "k", "d"), "d")

    def test_cache_publish_evicts_a_shadow_key_and_rewrites(self):
        host_address._detect_cache.clear()
        host_address._detect_cache[_shadow_key("t")] = 1
        host_address._cache_publish(host_address._detect_cache, t=0.0, value=None)
        self.assertEqual(
            sorted(type(k).__name__ for k in host_address._detect_cache),
            ["str", "str"],
        )
        self.assertIsNone(host_address._mapping_get(host_address._detect_cache, "value"))

    def test_sane_detection_cache_hit_is_still_served(self):
        # Laundering must not break the happy path: a live, fresh cache is
        # returned verbatim without re-detecting.
        self._plant(t=time.time(), value="10.0.0.5")
        with mock.patch.object(
            host_address, "_detect_lan_ip_uncached",
            side_effect=AssertionError("must not re-detect on a fresh hit"),
        ):
            self.assertEqual(host_address.detect_lan_ip(), "10.0.0.5")


# ---------------------------------------------------------------------------
# stays-immune pins
# ---------------------------------------------------------------------------


class _ClassBomb:
    """A leftover that cannot answer what it is: ``isinstance`` raises."""

    @property
    def __class__(self):
        raise RuntimeError("class bomb")


class _ItemsBombRow(dict):
    def items(self):
        raise RuntimeError("items bomb")


class _IterBombTuple(tuple):
    def __iter__(self):
        raise RuntimeError("iter bomb")


class StaysImmuneTests(unittest.TestCase):
    """Union guards from prior sweeps stay where their pins put them; the
    new host guards must not have weakened any of them."""

    def test_host_mapping_get_is_fail_closed_like_its_siblings(self):
        for mod in (host_address, status_mod, sensors_svc, system):
            self.assertEqual(mod._mapping_get(object(), "k", "d"), "d")
            self.assertEqual(mod._mapping_get({"k": 1}, "k"), 1)

    def test_resolve_value_still_raises_a_junk_container(self):
        """The bookmarks5 / docker9 raise-on-junk pin is untouched: a bomb
        *container* still raises out of the walk so callers' junk-drop keeps
        working."""
        with self.assertRaises(RuntimeError):
            host_address.resolve_value({"u": "x", "junk": _ClassBomb()})
        with self.assertRaises(RuntimeError):
            host_address.resolve_value([_ItemsBombRow({"name": "j"}), {"u": "x"}])

    def test_resolve_value_passes_a_leaf_untouched(self):
        out = host_address.resolve_value({"u": "x", "n": 7})
        self.assertEqual(out, {"u": "x", "n": 7})

    def test_isa_stays_fail_closed(self):
        self.assertFalse(host_address._isa(_ClassBomb(), dict))
        self.assertTrue(host_address._isa({}, dict))

    def test_sh_run_and_rc_int_still_launder_shape_and_rc_bombs(self):
        class _TupleLiar:
            @property
            def __class__(self):
                return tuple

        for junk in ((1, ""), object(), _TupleLiar()):
            with mock.patch.object(host_address, "sh", lambda *a, **k: junk):
                self.assertEqual(
                    host_address._sh_run(["/bin/echo"], timeout=1), (-255, "", "")
                )
        with mock.patch.object(host_address, "sh", lambda *a, **k: (0, "o", "e")):
            self.assertEqual(
                host_address._sh_run(["/bin/echo"], timeout=1), (0, "o", "e")
            )
        # A real tuple subclass with honest 3-tuple storage is salvaged
        # through the unbound base iterator (the dash11 _sh3 pin), bypassing
        # its bound __iter__ bomb.
        with mock.patch.object(
            host_address, "sh", lambda *a, **k: _IterBombTuple((0, "x", ""))
        ):
            self.assertEqual(
                tuple(host_address._sh_run(["/bin/echo"], timeout=1)), (0, "x", "")
            )

        class RcBomb:
            def __index__(self):
                raise RuntimeError("boom")

        self.assertEqual(host_address._rc_int(RcBomb()), -255)
        self.assertEqual(host_address._rc_int(0), 0)
        self.assertEqual(host_address._rc_int(True), 1)

    def test_sibling_status_and_sensors_caches_stay_immune(self):
        saved_s = dict(status_mod._status_cache)
        saved_c = dict(sensors_svc._cache)

        def _restore():
            status_mod._status_cache.clear()
            status_mod._status_cache.update(saved_s)
            sensors_svc._cache.clear()
            sensors_svc._cache.update(saved_c)

        self.addCleanup(status_mod.invalidate_status)
        self.addCleanup(_restore)
        client = _client()

        status_mod._status_cache.clear()
        status_mod._status_cache["t"] = time.time()
        status_mod._status_cache[_shadow_key("v")] = {"counts": {}, "groups": []}
        self.assertEqual(client.get("/api/status").status_code, 200)

        sensors_svc._cache.clear()
        sensors_svc._cache["t"] = time.time()
        sensors_svc._cache[_shadow_key("v")] = {"cpu": {}}
        self.assertEqual(
            client.get("/api/system/sensors").status_code, 200
        )

    def test_version_stays_pinned(self):
        from hub import __version__

        self.assertEqual(__version__, "3.9.3")


if __name__ == "__main__":
    unittest.main()
