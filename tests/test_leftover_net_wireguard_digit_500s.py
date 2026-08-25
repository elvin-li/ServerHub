"""Leftover >4300-digit numbers in the network / WireGuard / wstunnel parsers.

Prior passes guarded the SMART/top/pmset, sysctl/journal and share-ACL digit
parsers against CPython's 4300-digit str->int ValueError.  The hunt across the
remaining network, wireguard, wstunnel, status and gateway parsers found five
live leftovers:

* ``network_svc._interfaces_uncached`` called bare ``int()`` on the unbounded
  ``mtu\\s+(\\d+)`` ifconfig capture — an over-cap mtu column 500'd
  GET /api/system/network/addresses and GET /api/system/network/alias/auto
  (the overview page merely lost its interfaces leg to the pool guard).
* ``network_svc._network_service_order_uncached`` called bare ``int()`` on the
  unbounded ``\\((\\d+)\\)`` networksetup index and 500'd
  GET /api/system/network/services.
* ``wireguard_svc._valid_endpoint`` ran ``int(port)`` behind ``isdigit()``,
  which bounds neither length nor the digit class (``²`` passes isdigit but
  not int); the ValueError is not WireGuardError — the only exception the
  router catches — so it 500'd PUT /api/wireguard/settings.
* ``wireguard_wstunnel.valid_restrict_to`` had the same isdigit/int pair on a
  port split out of the raw value, 500ing PUT /api/wireguard/settings and
  POST /api/wireguard/remediate (install reads the stored restrict-to).
* ``wireguard_svc._ping_once`` — documented "never raises" — parsed latency
  with a bare ``float()`` on ``[\\d.]+``, which matches ``1.2.3`` (ValueError
  through fan_out) and parses a >308-digit run to inf (refused by Starlette's
  allow_nan=False encoder); both 500'd POST /api/wireguard/ping.
  ``wireguard_export._mtu`` shared the isdigit/int shape at the module
  boundary and now degrades to DEFAULT_MTU.

The battery also pins hunted paths that already survive this class:

* the gateway parse (``_service_gateway_for_device`` via ``_valid_ip``) and
  the failover ``_coerce_int`` settings reads;
* ``wireguard_wstunnel.listen_parts`` / ``valid_listen_url``, whose port
  capture is bounded at ``\\d{1,5}`` so an over-cap listen URL is refused
  whole (and ``status`` reports port 0 instead of raising);
* ``status._remember_port``, which drops an over-cap known-port instead of
  500ing GET /api/status (the detail scan beside it is bounded at 5 digits).
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from hub import network_svc, status, wireguard_export, wireguard_svc
from hub import wireguard_wstunnel as wst

#: Past CPython's default 4300-digit str<->int conversion limit.
_HUGE_DIGITS = "9" * 5000


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


#: ``ifconfig -a`` whose first interface carries an over-cap mtu.
_POISONED_IFCONFIG = (
    f"en0: flags=8863<UP,BROADCAST,SMART,RUNNING> mtu {_HUGE_DIGITS}\n"
    "\tinet 192.0.2.10 netmask 0xffffff00 broadcast 192.0.2.255\n"
    "en1: flags=8863<UP,BROADCAST,SMART,RUNNING> mtu 1500\n"
    "\tinet 192.0.2.11 netmask 0xffffff00 broadcast 192.0.2.255\n"
)

#: ``networksetup -listnetworkserviceorder`` with one over-cap index.
_POISONED_ORDER = (
    "An asterisk (*) denotes that a network service is disabled.\n"
    f"({_HUGE_DIGITS}) Thunderbolt Bridge\n"
    "(Hardware Port: Thunderbolt Bridge, Device: bridge0)\n"
    "\n"
    "(2) Wi-Fi\n"
    "(Hardware Port: Wi-Fi, Device: en1)\n"
)


class InterfacesMtuDigitLimitTests(unittest.TestCase):
    """GET /api/system/network/addresses used to 500 on an over-cap mtu."""

    def test_huge_mtu_degrades_to_none_not_500(self):
        with (
            mock.patch.object(
                network_svc, "_sh", return_value=(0, _POISONED_IFCONFIG, "")
            ),
            mock.patch.object(
                network_svc, "_network_service_order_entries", return_value=[]
            ),
            mock.patch.object(network_svc, "hardware_ports", return_value=[]),
        ):
            items = network_svc._interfaces_uncached()
        by_name = {i["name"]: i for i in items}
        self.assertIn("en0", by_name)
        self.assertIsNone(by_name["en0"]["mtu"])
        self.assertEqual(by_name["en0"]["ipv4"][0]["ip"], "192.0.2.10")
        self.assertEqual(by_name["en1"]["mtu"], 1500)
        _starlette(items)


class ServiceOrderDigitLimitTests(unittest.TestCase):
    """GET /api/system/network/services used to 500 on an over-cap index."""

    def test_huge_order_skips_the_block_not_the_listing(self):
        with mock.patch.object(
            network_svc, "_sh", return_value=(0, _POISONED_ORDER, "")
        ):
            entries = network_svc._network_service_order_uncached()
        self.assertEqual([e["order"] for e in entries], [2])
        self.assertEqual(entries[0]["name"], "Wi-Fi")
        self.assertEqual(entries[0]["device"], "en1")
        _starlette(entries)


class WireGuardEndpointPortDigitTests(unittest.TestCase):
    """PUT /api/wireguard/settings used to 500 on an over-cap endpoint port."""

    def test_huge_port_is_invalid_not_a_500(self):
        self.assertFalse(
            wireguard_svc._valid_endpoint(f"vpn.example.com:{_HUGE_DIGITS}")
        )
        self.assertFalse(wireguard_svc._valid_endpoint(f"[2001:db8::1]:{_HUGE_DIGITS}"))

    def test_superscript_port_is_invalid_not_a_500(self):
        # "²" passes isdigit() but int() refuses it.
        self.assertFalse(wireguard_svc._valid_endpoint("vpn.example.com:\u00b2\u00b2"))

    def test_sane_endpoints_still_validate(self):
        self.assertTrue(wireguard_svc._valid_endpoint("vpn.example.com:51820"))
        self.assertTrue(wireguard_svc._valid_endpoint("[2001:db8::1]:51821"))

    def test_save_settings_answers_coded_not_500(self):
        with (
            mock.patch.object(
                wireguard_svc, "cfg",
                return_value={"settings": {"wireguard": {}}},
            ),
            mock.patch.object(wireguard_svc, "update_settings"),
        ):
            with self.assertRaises(wireguard_svc.WireGuardError) as ctx:
                wireguard_svc.save_settings(
                    {"endpoint": f"vpn.example.com:{_HUGE_DIGITS}"}
                )
            self.assertEqual(ctx.exception.code, "wg.bad_endpoint")

            with self.assertRaises(wireguard_svc.WireGuardError) as ctx:
                wireguard_svc.save_settings(
                    {"wstunnel_restrict_to": f"127.0.0.1:{_HUGE_DIGITS}"}
                )
            self.assertEqual(ctx.exception.code, "wg.bad_wstunnel_target")


class WstunnelRestrictToDigitTests(unittest.TestCase):
    """POST /api/wireguard/remediate reads the stored restrict-to through this."""

    def test_huge_port_is_invalid_not_a_500(self):
        self.assertFalse(wst.valid_restrict_to(f"127.0.0.1:{_HUGE_DIGITS}"))
        self.assertFalse(wst.valid_restrict_to(f"[::1]:{_HUGE_DIGITS}"))
        self.assertFalse(wst.valid_restrict_to("127.0.0.1:\u00b2\u00b2"))

    def test_sane_restrict_to_still_validates(self):
        self.assertTrue(wst.valid_restrict_to("127.0.0.1:51820"))
        self.assertTrue(wst.valid_restrict_to("[::1]:51820"))


class WireGuardPingLatencyTests(unittest.TestCase):
    """POST /api/wireguard/ping used to 500 on a garbled or over-range latency."""

    _PEER = [{"public_key": "p", "name": "n", "ip": "10.10.0.2/32"}]

    def _ping(self, out: str) -> dict:
        with (
            mock.patch.object(wireguard_svc, "peer_records", return_value=self._PEER),
            mock.patch.object(wireguard_svc, "sh", return_value=(0, out, "")),
        ):
            return wireguard_svc.ping_peers(200)

    def test_huge_latency_is_none_not_inf(self):
        # float() has no digit cap: a >308-digit run parses to inf, which
        # Starlette's allow_nan=False encoder refused with a 500.
        result = self._ping(f"64 bytes time={_HUGE_DIGITS} ms\n")
        self.assertTrue(result["results"][0]["reachable"])
        self.assertIsNone(result["results"][0]["latency_ms"])
        _starlette(result)

    def test_multi_dot_latency_is_none_not_valueerror(self):
        # ``[\d.]+`` happily captures "1.2.3"; the ValueError escaped fan_out.
        result = self._ping("64 bytes time=1.2.3 ms\n")
        self.assertIsNone(result["results"][0]["latency_ms"])
        _starlette(result)

    def test_sane_latency_still_parses(self):
        result = self._ping("64 bytes time=1.2 ms\n")
        self.assertEqual(result["results"][0]["latency_ms"], 1.2)


class WireGuardExportMtuDigitTests(unittest.TestCase):
    def test_huge_mtu_falls_back_to_default(self):
        self.assertEqual(
            wireguard_export._mtu({"MTU": _HUGE_DIGITS}),
            wireguard_export.DEFAULT_MTU,
        )
        self.assertEqual(wireguard_export._mtu({"MTU": "1420"}), 1420)

    def test_clash_render_survives_a_poisoned_conf(self):
        conf = (
            "[Interface]\n"
            "PrivateKey = k\n"
            "Address = 10.10.0.2/32\n"
            f"MTU = {_HUGE_DIGITS}\n"
            "\n"
            "[Peer]\n"
            "PublicKey = p\n"
            "Endpoint = vpn.example.com:51820\n"
            "AllowedIPs = 0.0.0.0/0\n"
        )
        rendered = wireguard_export.to_clash_proxy(conf, "peer")
        self.assertIn(f"mtu: {wireguard_export.DEFAULT_MTU}", rendered)
        self.assertNotIn(_HUGE_DIGITS, rendered)


class HuntedGatewayDigitPinTests(unittest.TestCase):
    """The gateway parse already refuses over-cap octets; pin it."""

    _ENTRIES = [
        {"device": "en0", "name": "Ethernet", "disabled": False, "port": "Ethernet"}
    ]

    def _gateway(self, router_line: str) -> dict:
        with (
            mock.patch.object(
                network_svc,
                "_network_service_order_entries",
                return_value=self._ENTRIES,
            ),
            mock.patch.object(
                network_svc, "_sh", return_value=(0, router_line, "")
            ),
        ):
            return network_svc._service_gateway_for_device("en0")

    def test_huge_octet_gateway_is_none_not_500(self):
        result = self._gateway(f"Router: {_HUGE_DIGITS}.0.0.1\n")
        self.assertEqual(result, {"service": "Ethernet", "gateway": None})
        _starlette(result)

    def test_sane_gateway_still_parses(self):
        result = self._gateway("Router: 192.0.2.1\n")
        self.assertEqual(result["gateway"], "192.0.2.1")

    def test_failover_settings_coerce_huge_digits_to_defaults(self):
        self.assertEqual(network_svc._coerce_int(_HUGE_DIGITS, 15), 15)


class HuntedWstunnelListenDigitPinTests(unittest.TestCase):
    """The listen-URL port capture is bounded at 5 digits; pin the refusal."""

    def test_huge_listen_port_is_refused_whole(self):
        self.assertFalse(wst.valid_listen_url(f"ws://0.0.0.0:{_HUGE_DIGITS}"))
        self.assertEqual(
            wst.listen_parts(f"ws://0.0.0.0:{_HUGE_DIGITS}"), ("", "", "")
        )

    def test_status_reports_port_zero_for_an_over_cap_listen(self):
        with (
            mock.patch.object(
                wst,
                "live",
                return_value={
                    "listen": "",
                    "restrict_to": "",
                    "pid": 0,
                    "running": False,
                    "binary": "",
                    "plist": "",
                },
            ),
            mock.patch.object(wst, "local_ipv4s", return_value=frozenset()),
        ):
            snap = wst.status({
                "listen_port": 0,
                "wstunnel_listen": f"ws://0.0.0.0:{_HUGE_DIGITS}",
            })
        self.assertEqual(snap["port"], 0)
        self.assertEqual(snap["local_port"], 0)
        json.dumps(snap, allow_nan=False)


class HuntedStatusPortDigitPinTests(unittest.TestCase):
    """GET /api/status drops an over-cap known-port instead of 500ing."""

    def test_huge_port_is_dropped_not_500(self):
        ports: set = set()
        status._remember_port(ports, _HUGE_DIGITS)
        self.assertEqual(ports, set())
        status._remember_port(ports, "8086")
        self.assertEqual(ports, {8086})


if __name__ == "__main__":
    unittest.main()
