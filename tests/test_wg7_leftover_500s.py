"""WireGuard leftover-500 sweep #7: subclass bombs in the JSON read funnels.

All reproduced over ``create_app()`` + ``TestClient(raise_server_exceptions=
False)`` before the fixes; each answered ``500 Internal Server Error`` with a
traceback, never a coded JSON body.  Wave wg6 sealed the lock/write 503s;
these are the value-laundering leftovers.

The live leftovers
==================
* **``_as_text`` bound-method bombs, in all three wg modules.**  The
  launderer called ``value.decode(...)`` on bytes and ``value.encode(...)``
  on the result of ``str(value)`` — so a bytes-subclass whose ``.decode``
  raises, or a str-subclass whose ``__str__`` returns *itself* and whose
  ``.encode`` raises, detonated the very function that exists to absorb
  poisoned values.  One such ``sh`` stream 500'd GET /api/wireguard
  (``_dump_all``), GET /api/wireguard/readiness (``forwarding_enabled``
  under ``fan_out``, which re-raises) and POST /api/wireguard/ping
  (``_ping_once``'s latency parse sits outside its try).  Fixed with the
  brew_svc/docker_cli convention: unbound ``bytes.decode`` /
  ``bytearray.decode`` / ``str.encode`` through the base types.
* **``settings()`` probing stored values before type-gating them.**  The
  merge loop ran ``value in (None, "")`` (a reflected ``__eq__`` call),
  ``_nonfinite`` (``!=`` on a float subclass), a bound ``bytes.decode``, and
  a bare ``int(...)`` whose ``__int__``/``__index__`` a numeric subclass
  controls — each a raw 500 out of GET /api/wireguard, GET
  /api/wireguard/settings, /readiness and the PUT's echo of the saved
  settings, on values the range/type checks would have rejected anyway.
  The loop is now gated per expected type before anything calls into the
  value, strings are laundered through ``_as_text`` at merge time, and the
  numeric pass coerces through ``_plain_int`` (``int.__index__`` /
  ``float.__float__`` / text via ``_as_text``), so over-cap digit runs and
  every subclass bomb degrade to the default instead of the page.

What stays pinned besides the fixes
===================================
* Surrogates in a stored endpoint keep answering 200, replaced not raised.
* A 4300+-digit ``listen_port`` (already-int and digit-string forms) keeps
  the default rather than reaching Starlette's encoder.
* No new error codes: nothing here needs a locale key.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import wireguard_net_svc, wireguard_svc, wireguard_wstunnel  # noqa: E402

PUB = "A" * 42 + "b="

INSTALL = {
    "installed": True, "conf_exists": True, "conf_path": "", "conf_dir": "",
    "wg": "wg", "wg_quick": "wg-quick", "wireguard_go": "",
    "tools_version": "v1", "userspace_version": "", "probe_failed": False,
}


def _no_surrogates(payload) -> None:
    """What Starlette's JSONResponse does to the body (allow_nan=False)."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class EncodeBombStr(str):
    """``str(x)`` returns self, so the bound ``.encode`` used to fire."""

    def __str__(self):
        return self

    def encode(self, *a, **k):
        raise RuntimeError("encode bomb")


class DecodeBombBytes(bytes):
    def decode(self, *a, **k):
        raise RuntimeError("decode bomb")


class DecodeBombBytearray(bytearray):
    def decode(self, *a, **k):
        raise RuntimeError("decode bomb")


class IndexBombInt(int):
    def __index__(self):
        raise RuntimeError("index bomb")

    def __int__(self):
        raise RuntimeError("int bomb")


class EqBomb:
    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    __hash__ = None


class NeBombFloat(float):
    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    def __ne__(self, other):
        raise RuntimeError("ne bomb")

    __hash__ = float.__hash__


class AsTextUnitTests(unittest.TestCase):
    """The launderer itself must absorb the bombs, in all three modules."""

    MODULES = (wireguard_svc, wireguard_net_svc, wireguard_wstunnel)

    def test_encode_bomb_str_subclass_is_laundered_not_raised(self):
        # str.encode's "replace" substitutes "?" for the lone surrogate.
        for module in self.MODULES:
            with self.subTest(module=module.__name__):
                text = module._as_text(EncodeBombStr("utun9\ud800"))
                self.assertEqual(text, "utun9?")
                self.assertIs(type(text), str)

    def test_decode_bomb_bytes_and_bytearray_subclasses_are_laundered(self):
        for module in self.MODULES:
            for bomb in (DecodeBombBytes(b"wg0"), DecodeBombBytearray(b"wg0")):
                with self.subTest(module=module.__name__, kind=type(bomb)):
                    text = module._as_text(bomb)
                    self.assertEqual(text, "wg0")
                    self.assertIs(type(text), str)


class PlainIntUnitTests(unittest.TestCase):
    def test_subclass_index_bomb_is_recovered_as_an_exact_int(self):
        # The unbound base call reads the C-level value, dodging the override:
        # the number survives, the bomb never fires.
        recovered = wireguard_svc._plain_int(IndexBombInt(51825))
        self.assertEqual(recovered, 51825)
        self.assertIs(type(recovered), int)

    def test_over_cap_digit_string_degrades_to_none(self):
        self.assertIsNone(wireguard_svc._plain_int("1" * 5000))

    def test_nonfinite_float_degrades_to_none(self):
        for value in (float("inf"), float("-inf"), float("nan")):
            self.assertIsNone(wireguard_svc._plain_int(value))

    def test_plain_values_still_convert(self):
        self.assertEqual(wireguard_svc._plain_int("51820"), 51820)
        self.assertEqual(wireguard_svc._plain_int(1400.0), 1400)
        self.assertEqual(wireguard_svc._plain_int(True), 1)

    def test_nonfinite_survives_an_eq_bomb_float(self):
        # float.__float__ recovers the exact value, so the finite bomb reads
        # finite and the infinite one non-finite — neither raises.
        self.assertFalse(wireguard_svc._nonfinite(NeBombFloat(1.0)))
        self.assertTrue(wireguard_svc._nonfinite(NeBombFloat(float("inf"))))


class _MountedRouteTests(unittest.TestCase):
    """Real app, auth overridden, admin guard and installation patched."""

    def setUp(self):
        from fastapi.testclient import TestClient

        from hub.app_factory import create_app
        from hub.auth import require_auth
        from hub.routers import wireguard_api

        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        app = create_app()
        app.dependency_overrides[require_auth] = lambda: True
        self.addCleanup(app.dependency_overrides.clear)
        self.client = TestClient(app, raise_server_exceptions=False)
        self.stack.enter_context(mock.patch.object(
            wireguard_api, "require_admin_browser", lambda request: "admin"
        ))
        self.stack.enter_context(mock.patch.object(
            wireguard_svc, "installation", lambda: dict(INSTALL)
        ))


class ShStreamBombTests(_MountedRouteTests):
    """A poisoned ``wg`` stdout costs only the value, never the page."""

    def _patch_sh(self, out):
        return mock.patch.object(
            wireguard_svc, "sh", lambda cmd, timeout=10, **k: (0, out, "")
        )

    def test_encode_bomb_stdout_keeps_status_200(self):
        # The live leftover: _dump_all's ``_as_text(out)`` detonated the
        # str-subclass bomb — a raw 500 on every GET /api/wireguard poll.
        with self._patch_sh(EncodeBombStr("utun9\tstuff")):
            resp = self.client.get("/api/wireguard")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _no_surrogates(resp.json())

    def test_decode_bomb_bytes_stdout_keeps_status_200(self):
        with self._patch_sh(DecodeBombBytes(b"utun9\tstuff")):
            resp = self.client.get("/api/wireguard")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _no_surrogates(resp.json())

    def test_encode_bomb_stdout_keeps_ping_200_and_parses_latency(self):
        # _ping_once's latency parse sits outside its try; the bomb used to
        # escape through fan_out and 500 POST /api/wireguard/ping.
        tmp = tempfile.TemporaryDirectory(prefix="wg7-conf-")
        self.addCleanup(tmp.cleanup)
        conf = Path(tmp.name) / "wg0.conf"
        conf.write_text(
            "[Interface]\nPrivateKey = X\nAddress = 10.10.0.1/24\n\n"
            f"[Peer]\nPublicKey = {PUB}\nAllowedIPs = 10.10.0.2/32\n",
            encoding="utf-8",
        )
        self.stack.enter_context(mock.patch.object(
            wireguard_svc, "conf_path", lambda interface=None: conf
        ))
        with self._patch_sh(EncodeBombStr("64 bytes: time=1.2 ms")):
            resp = self.client.post("/api/wireguard/ping")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        self.assertEqual(body["results"][0]["latency_ms"], 1.2)

    def test_encode_bomb_sh_keeps_readiness_200(self):
        # forwarding_enabled runs under fan_out, which re-raises — one
        # poisoned sysctl stream used to 500 the whole readiness page.
        for target, value in (
            ("sh", lambda cmd, timeout=10, **k: (0, EncodeBombStr("1"), "")),
            ("sudo_capture", lambda cmd, timeout=10, **k: (1, "", "")),
        ):
            self.stack.enter_context(
                mock.patch.object(wireguard_net_svc, target, value)
            )
        for target in ("sh", "sudo_capture"):
            self.stack.enter_context(mock.patch.object(
                wireguard_svc, target, lambda cmd, timeout=10, **k: (1, "", "")
            ))
        resp = self.client.get("/api/wireguard/readiness")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _no_surrogates(resp.json())


class StoredSettingsBombTests(_MountedRouteTests):
    """Stored subclass bombs cost only their key, never the settings read."""

    def _with_section(self, payload: dict):
        # settings_section always returns an exact dict (its dict() launder),
        # but the *values* are whatever leftovers the config holds — that is
        # the honest seam these bombs ride in on.
        return mock.patch.object(
            wireguard_svc, "settings_section", lambda name: dict(payload)
        )

    def _get_settings(self):
        resp = self.client.get("/api/wireguard/settings")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        return body["settings"]

    def test_index_bomb_listen_port_is_recovered_not_500(self):
        # A non-default value proves the number itself survives the launder.
        with self._with_section({"listen_port": IndexBombInt(51825)}):
            self.assertEqual(self._get_settings()["listen_port"], 51825)

    def test_eq_bomb_endpoint_keeps_the_default(self):
        # The old ``value in (None, "")`` blank probe invoked the reflected
        # __eq__ before any type gate ran.
        with self._with_section({"endpoint": EqBomb()}):
            self.assertEqual(self._get_settings()["endpoint"], "")

    def test_encode_bomb_endpoint_is_laundered_to_an_exact_str(self):
        with self._with_section({"endpoint": EncodeBombStr("vpn.example.com:51820")}):
            self.assertEqual(
                self._get_settings()["endpoint"], "vpn.example.com:51820"
            )

    def test_decode_bomb_dns_bytes_are_laundered(self):
        with self._with_section({"dns": DecodeBombBytes(b"1.1.1.1")}):
            self.assertEqual(self._get_settings()["dns"], "1.1.1.1")

    def test_ne_bomb_float_mtu_still_converts(self):
        with self._with_section({"mtu": NeBombFloat(1400.0)}):
            self.assertEqual(self._get_settings()["mtu"], 1400)

    def test_encode_bomb_subnet_survives_the_network_check(self):
        with self._with_section({"subnet": EncodeBombStr("10.9.0.0/24")}):
            self.assertEqual(self._get_settings()["subnet"], "10.9.0.0/24")

    def test_over_cap_listen_port_keeps_the_default(self):
        # Already-int (YAML hex loads uncapped) and digit-string forms both:
        # neither may reach Starlette's json.dumps and its digit-cap ValueError.
        for leftover in (10 ** 5000, "1" * 5000):
            with self.subTest(kind=type(leftover).__name__):
                with self._with_section({"listen_port": leftover}):
                    self.assertEqual(self._get_settings()["listen_port"], 51820)

    def test_surrogate_endpoint_stays_200_with_replacement(self):
        with self._with_section({"endpoint": "vpn\ud800.example.com"}):
            self.assertEqual(
                self._get_settings()["endpoint"], "vpn?.example.com"
            )

    def test_put_settings_echo_survives_a_stored_index_bomb(self):
        # save_settings returns settings() — the bombed stored value used to
        # 500 the echo of a save that had already landed.
        with self._with_section({"listen_port": IndexBombInt(51820)}):
            resp = self.client.put(
                "/api/wireguard/settings", json={"dns": "9.9.9.9"}
            )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        self.assertTrue(body["ok"])

    def test_bomb_settings_keep_the_status_page_200(self):
        # GET /api/wireguard reads settings() too (status + wstunnel snapshot).
        with self._with_section({
            "endpoint": EqBomb(),
            "listen_port": IndexBombInt(51820),
            "dns": DecodeBombBytes(b"1.1.1.1"),
        }):
            resp = self.client.get("/api/wireguard")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _no_surrogates(resp.json())

    def test_stored_false_wstunnel_enabled_is_still_a_real_value(self):
        # The blank-skip rewrite must not start dropping stored False.
        with self._with_section({"wstunnel_enabled": False}):
            self.assertIs(self._get_settings()["wstunnel_enabled"], False)


if __name__ == "__main__":
    unittest.main()
