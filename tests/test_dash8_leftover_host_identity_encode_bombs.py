"""Eighth leftover-500s sweep of the Dashboard: a self-``__str__`` encode
bomb in the LAN-address detection cache, over the real mounted app.

dash6/dash7 sealed the sensors / top / SMART caches and the ``status`` build
against the whole subclass-bomb family, including the text bomb CPython does
*not* neutralize: a ``str`` subclass whose ``__str__`` answers **self** skips
the exact-str copy a ``str(value)`` probe relies on, so a scrub's *bound*
``value.encode("utf-8", "replace")`` then dispatches into the subclass's
``encode`` override.

``host_address._as_text`` is the sanitizer every ``host_ip()`` answer passes
through, and it still used that bound ``encode``.  A bomb planted in the
LAN-address detection cache (``_detect_cache``, which normally only ever holds
the exact-str address ``_detect_lan_ip_uncached`` writes) rode straight out of
``host_ip()`` — and its one *unguarded* dashboard/system consumer,
``GET /api/system/host``, calls ``host_ip()`` directly and returns the snapshot
without the ``_jsonable`` sweep its siblings (``/api/status``,
``/api/system/sensors``, ``/api/system/power``) all have.  **One live 500.**

The fix is the status.py convention: unbound ``str.encode(text, "utf-8",
"replace")`` reads the C-level storage underneath the override, so the poisoned
address keeps its real text (and its lone surrogates still scrub) instead of
costing the route.  Stays-immune pins ride along for the sibling surfaces that
already wrap ``host_ip()`` in a ``try`` — a probe reorder there must not start
depending on the raise never happening.
"""
from __future__ import annotations

import json
import time
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import host_address
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


class _DetectCacheSandbox(unittest.TestCase):
    """Save/restore the LAN-detection cache; force the ``auto`` host path."""

    def setUp(self):
        self._cache = dict(host_address._detect_cache)
        self.addCleanup(host_address.invalidate_routing)
        self.addCleanup(lambda: host_address._detect_cache.update(self._cache))
        # host_ip() consults detect_lan_ip() only when the advertised host is
        # "auto"; pin that so the test does not depend on the harness env.
        p = mock.patch.object(host_address, "configured_host", return_value="auto")
        p.start()
        self.addCleanup(p.stop)
        self.client = _client()

    def _plant(self, value) -> None:
        host_address._detect_cache.update(t=time.time(), value=value)


class HostRouteEncodeBombTests(_DetectCacheSandbox):
    """The ex-500 on GET /api/system/host."""

    def _get_host(self) -> dict:
        resp = self.client.get("/api/system/host?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        return body

    def test_self_str_encode_bomb_keeps_the_address_text(self):
        self._plant(_SelfStrEncodeBomb("10.0.0.9"))
        body = self._get_host()
        self.assertEqual(body["host_ip"], "10.0.0.9")
        self.assertEqual(body["lan_ip"], "10.0.0.9")

    def test_str_returning_the_bomb_subclass_keeps_the_text(self):
        self._plant(_StrReturnsBomb())
        body = self._get_host()
        self.assertEqual(body["host_ip"], "made by __str__")

    def test_surrogate_riding_the_bomb_subclass_still_scrubs(self):
        """The unbound encode keeps doing the scrub's original job: a lone
        surrogate in the poisoned address is replaced (encode-side
        ``replace`` yields ``?``), not served raw to Starlette's UTF-8."""
        self._plant(_SelfStrEncodeBomb("a\ud800b"))
        body = self._get_host()
        self.assertEqual(body["host_ip"], "a?b")


class HostIdentitySanitizerTests(_DetectCacheSandbox):
    """The sanitizer contract underneath the route: host_ip() must not raise."""

    def test_host_ip_no_longer_raises_the_encode_bomb(self):
        self._plant(_SelfStrEncodeBomb("192.168.1.5"))
        self.assertEqual(host_address.host_ip(), "192.168.1.5")

    def test_as_text_absorbs_the_self_str_encode_bomb(self):
        self.assertEqual(host_address._as_text(_SelfStrEncodeBomb("ok")), "ok")

    def test_as_text_absorbs_a_bytes_subclass_decode_bomb(self):
        class _DecodeBomb(bytes):
            def decode(self, *args, **kwargs):
                raise RuntimeError("decode bomb")

        self.assertEqual(host_address._as_text(_DecodeBomb(b"1.2.3.4")), "1.2.3.4")


class StaysImmuneTests(_DetectCacheSandbox):
    """The sibling surfaces already wrap ``host_ip()`` in a ``try`` — pinned so
    a refactor cannot start relying on the raise that dash8 just removed."""

    def test_plain_encode_bomb_subclass_stays_immune(self):
        # CPython copies a default-``__str__`` subclass to exact str before the
        # scrub, so this vector was never live; pin it either way.
        self._plant(_PlainEncodeBomb("172.16.0.2"))
        resp = self.client.get("/api/system/host?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["host_ip"], "172.16.0.2")

    def test_power_overview_stays_200_under_the_bomb(self):
        self._plant(_SelfStrEncodeBomb("10.0.0.9"))
        resp = self.client.get("/api/system/power")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _starlette(resp.json())

    def test_screensharing_stays_200_under_the_bomb(self):
        self._plant(_SelfStrEncodeBomb("10.0.0.9"))
        resp = self.client.get("/api/system/screensharing")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _starlette(resp.json())


if __name__ == "__main__":
    unittest.main()
