"""Leftover type 500s on network overview, WireGuard readiness, host templates.

Bytes/None ifconfig and route payloads, a non-list ``ipv4`` leftover,
YAML ``.inf`` autobind intervals, leftover resolution/peer rows, and a
list ``extra=`` each used to raise on the request path.

Follow-up: YAML leftover ``netmask: 2026-08-19`` AttributeError'd
``_valid_ip`` on GET /api/system/network and GET /api/system/network/alias/auto.
"""
from __future__ import annotations

import datetime
import json
import unittest
from unittest import mock

from hub import host_address, network_svc
from hub import wireguard_net_svc as net


def _json(payload) -> None:
    json.dumps(payload, allow_nan=False)


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class NetworkSvcBytesPayloadTests(unittest.TestCase):
    def test_ifconfig_bytes_none_int_do_not_500(self):
        payload = (
            b"en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
            b"\tether aa:bb:cc:dd:ee:ff\n"
            b"\tinet 192.0.2.10 netmask 0xffffff00 broadcast 192.0.2.255\n"
        )
        with mock.patch.object(network_svc, "sh", return_value=(0, payload, "")):
            items = network_svc._interfaces_uncached()
        by_name = {i["name"]: i for i in items}
        self.assertEqual(by_name["en0"]["ipv4"][0]["ip"], "192.0.2.10")
        self.assertEqual(by_name["en0"]["mac"], "aa:bb:cc:dd:ee:ff")
        for junk in (None, 12):
            with mock.patch.object(network_svc, "sh", return_value=(0, junk, "")):
                self.assertEqual(network_svc._interfaces_uncached(), [])

    def test_hardware_ports_and_service_order_bytes_do_not_500(self):
        ports = (
            b"Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff\n"
        )
        with mock.patch.object(network_svc, "sh", return_value=(0, ports, "")):
            items = network_svc._hardware_ports_uncached()
        self.assertEqual(items[0]["device"], "en0")
        order = b"(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n"
        with mock.patch.object(network_svc, "sh", return_value=(0, order, "")):
            entries = network_svc._network_service_order_uncached()
        self.assertEqual(entries[0]["name"], "Wi-Fi")
        self.assertEqual(entries[0]["device"], "en0")
        with mock.patch.object(network_svc, "sh", return_value=(0, None, "")):
            self.assertEqual(network_svc._hardware_ports_uncached(), [])
            self.assertEqual(network_svc._network_service_order_uncached(), [])

    def test_service_info_and_alias_route_bytes_do_not_500(self):
        info = b"DHCP Configuration\nIP Address: 192.0.2.10\nRouter: 192.0.2.1\n"
        dns = b"1.1.1.1\n"
        search = b"lan\n"

        def fake_sh(argv, **kwargs):
            if argv[1] == "-getinfo":
                return 0, info, ""
            if argv[1] == "-getdnsservers":
                return 0, dns, ""
            if argv[1] == "-getsearchdomains":
                return 0, search, ""
            return 0, b"", ""

        with mock.patch.object(network_svc, "sh", side_effect=fake_sh):
            got = network_svc.service_info("Wi-Fi")
        self.assertEqual(got["mode"], "dhcp")
        self.assertEqual(got["ip"], "192.0.2.10")
        self.assertEqual(got["dns"], ["1.1.1.1"])
        _json(got)

        route = b"  interface: lo0\n      flags: <UP,HOST,DONE,LOCAL>\n"
        with mock.patch.object(network_svc, "sh", return_value=(0, route, "")):
            state = network_svc._alias_local_route("192.0.2.204")
        self.assertTrue(state["ok"])
        self.assertEqual(state["interface"], "lo0")
        for junk in (None, 12):
            with mock.patch.object(network_svc, "sh", return_value=(0, junk, "")):
                self.assertFalse(network_svc._alias_local_route("192.0.2.204")["ok"])

    def test_listen_routes_dns_and_wifi_bytes_do_not_500(self):
        lsof = (
            b"COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
            b"node 1 me 1u IPv4 0 0t0 TCP *:8080 (LISTEN)\n"
        )
        with mock.patch.object(network_svc, "sh", return_value=(0, lsof, "")):
            rows = network_svc.listening_ports()
        self.assertEqual(rows[0]["port"], "8080")
        netstat = b"Destination Gateway Flags Netif\ndefault 192.0.2.1 UGSc en0\n"
        with mock.patch.object(network_svc, "sh", return_value=(0, netstat, "")):
            routes = network_svc.routes()
        self.assertEqual(routes[0]["netif"], "en0")
        with mock.patch.object(
            network_svc, "sh", return_value=(0, b"ip_address: 1.2.3.4\n", "")
        ):
            ans = network_svc.dns_resolve("example.com")
        self.assertEqual(ans["answers"], ["1.2.3.4"])
        _json(ans)
        with mock.patch.object(network_svc, "_wifi_devices", return_value=["en0"]):
            with mock.patch.object(
                network_svc, "sh", return_value=(0, b"Wi-Fi Power (en0): On\n", "")
            ):
                wifi = network_svc.wifi_power_status()
        self.assertTrue(wifi["on"])
        _json(wifi)
        for junk in (None, 12):
            with mock.patch.object(network_svc, "sh", return_value=(0, junk, "")):
                self.assertEqual(network_svc.listening_ports(), [])
                self.assertEqual(network_svc.routes(), [])
                self.assertFalse(network_svc.dns_resolve("example.com")["ok"])


class NetworkSvcJunkRowTests(unittest.TestCase):
    def test_interface_addresses_junk_ipv4_and_ifaces_do_not_500(self):
        ifaces = [
            "oops",
            {"name": None, "up": True, "ipv4": [{"ip": "192.0.2.1"}]},
            {
                "name": "en0",
                "up": True,
                "mac": None,
                "status": "active",
                "ipv4": 5,
            },
            {
                "name": "en7",
                "up": True,
                "mac": "aa:bb:cc:dd:ee:ff",
                "status": "active",
                "ipv4": [
                    "not-a-row",
                    {"ip": "192.0.2.20", "netmask": "255.255.255.0"},
                ],
            },
        ]
        with mock.patch.object(network_svc, "interfaces", return_value=ifaces):
            rows = network_svc.interface_addresses()
        self.assertEqual(len(rows), 2)
        by_dev = {r["device"]: r for r in rows}
        self.assertEqual(by_dev["en0"]["addresses"], [])
        self.assertEqual(by_dev["en7"]["addresses"][0]["ip"], "192.0.2.20")

    def test_preferred_and_wifi_ports_skip_junk_rows(self):
        with mock.patch.object(
            network_svc, "hardware_ports", return_value=["oops", {"port": 1}]
        ):
            self.assertEqual(network_svc._wifi_devices(), [])
            self.assertEqual(network_svc._wired_devices(), [])
        with (
            mock.patch.object(
                network_svc, "_network_service_order_entries", return_value=["oops"]
            ),
            mock.patch.object(network_svc, "interfaces", return_value=["oops"]),
        ):
            self.assertIsNone(network_svc.preferred_active_device())


class NetworkSvcInfSettingsTests(unittest.TestCase):
    def test_inf_interval_does_not_500_alias_or_failover(self):
        self.assertEqual(network_svc._coerce_int(float("inf"), 60), 60)
        self.assertEqual(network_svc._coerce_int(float("-inf"), 15), 15)
        with mock.patch(
            "hub.config.settings_section",
            return_value={"interval": float("inf"), "ips": ["192.0.2.10"]},
        ):
            alias = network_svc._alias_settings()
            fail = network_svc._failover_settings()
        self.assertEqual(alias["interval"], 60)
        self.assertEqual(fail["interval"], 15)
        _json(alias)
        _json(fail)

    def test_yaml_date_netmask_does_not_500_alias(self):
        """YAML ``netmask: 2026-08-19`` used to 500 GET /api/system/network."""
        leftover = datetime.date(2026, 8, 19)
        with mock.patch(
            "hub.config.settings_section",
            return_value={
                "netmask": leftover,
                "ips": [leftover, "192.0.2.10"],
                "interval": leftover,
            },
        ):
            alias = network_svc._alias_settings()
        _json(alias)
        self.assertEqual(alias["netmask"], "255.255.255.255")
        self.assertEqual(alias["ips"], ["192.0.2.10"])
        self.assertEqual(alias["interval"], 60)
        self.assertFalse(network_svc._valid_ip(leftover))
        self.assertTrue(network_svc._valid_ip(b"192.0.2.10"))

    def test_inf_update_interval_is_clamped_not_500(self):
        with (
            mock.patch(
                "hub.config.settings_section", return_value={"ips": [], "auto_bind": True}
            ),
            mock.patch("hub.config.update_settings"),
            mock.patch.object(
                network_svc, "alias_auto_status", return_value={"ok": True}
            ),
        ):
            out = network_svc.update_alias_auto_config(interval=float("inf"))
        self.assertEqual(out["ok"], True)

    def test_unicode_digit_octet_does_not_500_alias(self):
        """``'²'.isdigit()`` is True; leftover ``int()`` 500'd GET /api/system/network."""
        self.assertFalse(network_svc._valid_ip("1.2.3.\u00b2"))
        self.assertFalse(network_svc._valid_ip("1.2.3.\u0661"))
        with mock.patch(
            "hub.config.settings_section",
            return_value={"ips": ["1.2.3.\u00b2", "192.0.2.10"], "netmask": "255.255.255.0"},
        ):
            alias = network_svc._alias_settings()
        _json(alias)
        self.assertEqual(alias["ips"], ["192.0.2.10"])

    def test_inf_probe_timeout_does_not_500_wired(self):
        """YAML leftover ``probe_timeout_ms: .inf`` used to ``int(inf)`` the ping."""
        with (
            mock.patch.object(
                network_svc, "_primary_ipv4_for_device", return_value="192.0.2.10"
            ),
            mock.patch.object(
                network_svc,
                "_service_gateway_for_device",
                return_value={"service": "Ethernet", "gateway": "192.0.2.1"},
            ),
            mock.patch.object(network_svc, "_sh", return_value=(0, "ok", "")) as sh,
        ):
            out = network_svc._probe_wired_device("en0", float("inf"))
        self.assertTrue(out["ok"])
        self.assertGreaterEqual(sh.call_args.kwargs["timeout"], 3)


class WireGuardNetTypingTests(unittest.TestCase):
    def test_bytes_forwarding_ifconfig_and_nat_do_not_500(self):
        with mock.patch.object(net, "sh", return_value=(0, b"1\n", "")):
            self.assertTrue(net.forwarding_enabled())
        for junk in (None, 12):
            with mock.patch.object(net, "sh", return_value=(0, junk, "")):
                self.assertFalse(net.forwarding_enabled())
                self.assertEqual(net._local_address_lines(), [])
        addrs = (
            b"\tinet 192.0.2.10 netmask 0xffffff00 broadcast 192.0.2.255\n"
            b"\tinet6 2001:db8::1 prefixlen 64\n"
        )
        with mock.patch.object(net, "sh", return_value=(0, addrs, "")):
            found = net._local_address_lines()
        self.assertEqual(
            {addr for addr, _ in found},
            {"192.0.2.10", "2001:db8::1"},
        )
        with mock.patch.object(
            net, "sudo_capture",
            return_value=(0, b"nat on en0 inet from 10.10.0.0/24 to any -> (en0)\n", ""),
        ):
            self.assertTrue(net.nat_active())

    def test_daemon_defects_bytes_do_not_500(self):
        self.assertEqual(net._daemon_defects(None), [])
        self.assertEqual(net._daemon_defects(1), ["unreadable"])
        self.assertIn("unreadable", net._daemon_defects(b"not a plist"))

    def test_resolution_detail_junk_does_not_500(self):
        self.assertIsInstance(net._resolution_detail({}), str)
        self.assertEqual(net._resolution_detail("oops"), "")
        self.assertIsInstance(
            net._resolution_detail({
                "reason": "not_this_host",
                "endpoint": "vpn.example",
                "unreachable": 5,
                "resolved": None,
                "suggest": 9,
            }),
            str,
        )
        detail = net._resolution_detail({
            "reason": "not_this_host",
            "endpoint": "vpn.example",
            "unreachable": ["2001:db8::9"],
            "suggest": "2001:db8::1",
        })
        self.assertIn("2001:db8::1", detail)
        self.assertEqual(net._nat_detail({}, "en0"), f"{net.PF_ANCHOR_PATH} missing")

    def test_daemon_detail_junk_does_not_500(self):
        self.assertEqual(net._daemon_detail({}), "")
        self.assertEqual(net._daemon_detail(None), "")
        self.assertEqual(net._daemon_detail("oops"), "")
        self.assertIn("restarts wg-quick", net._daemon_detail({
            "installed": True,
            "plist_path": "/Library/LaunchDaemons/com.wireguard.wg0.plist",
            "defects": ["respawn_loop"],
            "managed": False,
        }))

    def test_peer_origin_junk_records_do_not_500(self):
        with mock.patch.object(
            net.wireguard_svc, "peer_records",
            return_value=["oops", None, {"known": False, "reissuable": False, "public_key": "abcd" * 8}],
        ):
            got = net.peer_origin_conflict()
        self.assertTrue(got["conflict"])
        self.assertEqual(got["total"], 1)
        self.assertEqual(got["foreign"], 1)
        _json(got)
        with mock.patch.object(net.wireguard_svc, "peer_records", return_value="oops"):
            empty = net.peer_origin_conflict()
        self.assertFalse(empty["conflict"])
        self.assertEqual(empty["reason"], "no_peers")


class HostAddressExtraTests(unittest.TestCase):
    def test_list_extra_does_not_500(self):
        with mock.patch.object(host_address, "host_ip", return_value="192.0.2.40"):
            self.assertEqual(
                host_address.template_variables(["oops"])["host"],
                "192.0.2.40",
            )


class NetworkInfClockStrftimeLeftoverTests(unittest.TestCase):
    def test_overflow_strftime_does_not_500_failover_ts(self):
        """Leftover inf clock OverflowError'd GET failover ``last_check_at``."""
        with (
            mock.patch("hub.util.time.strftime", side_effect=OverflowError),
            mock.patch.object(
                network_svc, "_failover_settings",
                return_value={"enabled": False},
            ),
        ):
            result = network_svc.network_failover_tick(force=True)
        _starlette(result)
        status = network_svc.network_failover_status()
        _starlette(status)
        self.assertEqual(status["state"].get("last_check_at"), "")


class LeftoverSurrogateAndRecursionTests(unittest.TestCase):
    def test_ifconfig_surrogate_does_not_500(self):
        """Leftover ``\\ud800`` in ifconfig used to UTF-8 500 GET /api/system/network."""
        payload = (
            "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
            "\tether aa:bb:cc:dd:ee:ff\n"
            "\tinet 192.0.2.10 netmask 0xffffff00 broadcast 192.0.2.255\n"
            "en1\ud800: flags=8863<UP> mtu 1500\n"
        )
        with mock.patch.object(network_svc, "sh", return_value=(0, payload, "")):
            items = network_svc._interfaces_uncached()
        _starlette(items)
        self.assertTrue(any(i.get("name") == "en0" for i in items))

    def test_address_book_surrogate_does_not_500(self):
        leftover = "ok\ud800"
        with (
            mock.patch.object(host_address, "host_ip", return_value="192.0.2.40"),
            mock.patch(
                "hub.config.cfg",
                return_value={"settings": {"address_book": {leftover: leftover}}},
            ),
        ):
            values = host_address.template_variables({leftover: leftover})
            expanded = host_address.resolve_template("http://{host}:8086/" + leftover)
        _starlette(values)
        _starlette({"url": expanded})
        self.assertNotIn("\ud800", "".join(values.keys()) + "".join(values.values()))
        self.assertNotIn("\ud800", expanded)

    def test_configured_host_surrogate_does_not_500(self):
        with mock.patch(
            "hub.config.cfg",
            return_value={"settings": {"host_ip": "192.0.2.40\ud800"}},
        ), mock.patch.dict("os.environ", {"SERVERHUB_HOST_IP": "", "SERVERHUB_HOST": ""}, clear=False):
            host = host_address.configured_host()
        _starlette({"host": host})
        self.assertNotIn("\ud800", host)

    def test_route_surrogate_does_not_500(self):
        host_address.invalidate_routing()
        with mock.patch.object(
            host_address,
            "sh",
            return_value=(0, "gateway: 192.0.2.1\ud800\ninterface: en0\n", ""),
        ):
            route = host_address.default_route()
        _starlette(route)
        self.assertEqual(route["interface"], "en0")
        self.assertNotIn("\ud800", route["gateway"] or "")

    def test_getaddrinfo_surrogate_does_not_500_detect_lan(self):
        host_address.invalidate_routing()
        with (
            mock.patch.object(host_address, "default_interface", return_value=""),
            mock.patch(
                "hub.host_address.socket.gethostname", return_value="box\ud800"
            ),
            mock.patch(
                "hub.host_address.socket.getaddrinfo",
                side_effect=UnicodeError("surrogate"),
            ),
        ):
            value = host_address.detect_lan_ip(force=True)
        _starlette({"host": value})
        self.assertNotIn("\ud800", value)
        self.assertTrue(value)

    def test_nested_resolve_value_does_not_500(self):
        """Leftover deeply-nested YAML used to RecursionError host templates."""
        nested: dict = {"url": "http://{host}:1"}
        cur = nested
        for _ in range(40):
            nxt: dict = {"k": "x"}
            cur["child"] = nxt
            cur = nxt
        with mock.patch.object(host_address, "host_ip", return_value="192.0.2.40"):
            out = host_address.resolve_value(nested)
        _starlette(out)
        self.assertEqual(out["url"], "http://192.0.2.40:1")

    def test_recursing_services_error_does_not_500_overview(self):
        """``str(e)`` RecursionError used to 500 GET /api/system/network."""
        class Recursing(Exception):
            def __str__(self):
                raise RecursionError("nested")

        with (
            mock.patch.object(network_svc, "network_services", side_effect=Recursing()),
            mock.patch.object(network_svc, "interfaces", return_value=[]),
            mock.patch.object(network_svc, "hardware_ports", return_value=[]),
            mock.patch.object(network_svc, "interface_addresses", return_value=[]),
            mock.patch.object(network_svc, "listening_ports", return_value=[]),
            mock.patch.object(network_svc, "routes", return_value=[]),
            mock.patch.object(network_svc, "default_route", return_value={}),
            mock.patch.object(network_svc, "docker_published_ports", return_value=[]),
            mock.patch.object(network_svc, "docker_networks_detail", return_value=[]),
            mock.patch.object(network_svc, "alias_auto_status", return_value=None),
            mock.patch.object(network_svc, "network_failover_status", return_value=None),
            mock.patch.object(network_svc, "engine_up", return_value=False),
            mock.patch.object(network_svc, "_wstunnel_snapshot", return_value=None),
        ):
            v = network_svc._build_overview()
        _starlette(v)
        self.assertEqual(v["services"], [])
        self.assertEqual(v["services_error"], "Recursing")

    def test_surrogate_exception_message_does_not_500_overview(self):
        class Surrogate(Exception):
            def __str__(self):
                return "svc\ud800"

        with (
            mock.patch.object(network_svc, "network_services", side_effect=Surrogate()),
            mock.patch.object(network_svc, "interfaces", return_value=[]),
            mock.patch.object(network_svc, "hardware_ports", return_value=[]),
            mock.patch.object(network_svc, "interface_addresses", return_value=[]),
            mock.patch.object(network_svc, "listening_ports", return_value=[]),
            mock.patch.object(network_svc, "routes", return_value=[]),
            mock.patch.object(network_svc, "default_route", return_value={}),
            mock.patch.object(network_svc, "docker_published_ports", return_value=[]),
            mock.patch.object(network_svc, "docker_networks_detail", return_value=[]),
            mock.patch.object(network_svc, "alias_auto_status", return_value=None),
            mock.patch.object(network_svc, "network_failover_status", return_value=None),
            mock.patch.object(network_svc, "engine_up", return_value=False),
            mock.patch.object(network_svc, "_wstunnel_snapshot", return_value=None),
        ):
            v = network_svc._build_overview()
        _starlette(v)
        self.assertNotIn("\ud800", v["services_error"] or "")

    def test_forwarding_surrogate_does_not_500(self):
        with mock.patch.object(net, "sh", return_value=(0, "1\ud800\n", "")):
            self.assertFalse(net.forwarding_enabled())
        with mock.patch.object(
            net.wireguard_svc,
            "settings",
            return_value={**net.wireguard_svc.DEFAULTS, "endpoint": "vpn\ud800.example"},
        ):
            result = net.endpoint_resolution()
        _starlette(result)
        self.assertNotIn("\ud800", result.get("endpoint") or "")

    def test_peer_origin_missing_pubkey_does_not_500(self):
        with mock.patch.object(
            net.wireguard_svc,
            "peer_records",
            return_value=[
                {"known": False, "reissuable": False},
                {"known": False, "reissuable": False, "public_key": 12},
            ],
        ):
            got = net.peer_origin_conflict()
        _starlette(got)
        self.assertTrue(got["conflict"])
        self.assertEqual(got["foreign"], 2)


class WireGuardNetAsTextRecursionLeftoverTests(unittest.TestCase):
    def test_as_text_recursing_does_not_500(self):
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(net._as_text(Recursing()), "Recursing")
        _starlette({"message": net._as_text(Recursing())})


class NetworkAsTextRecursionLeftoverTests(unittest.TestCase):
    def test_as_text_and_netmask_recursing_do_not_500(self):
        """leftover ``str()`` RecursionError used to 500 GET /api/system/network."""
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(network_svc._as_text(Recursing()), "Recursing")
        _starlette({"message": network_svc._as_text(Recursing())})
        dotted = network_svc._hex_netmask_to_dotted(Recursing())
        _starlette({"mask": dotted})
        self.assertEqual(dotted, "Recursing")

    def test_alias_route_recursing_exc_does_not_500(self):
        """``fan_out`` re-raises; leftover ``{exc}`` RecursionError 500'd GET /api/network."""
        class Recursing(Exception):
            def __str__(self):
                raise RecursionError("nested")

        conf = {"ips": ["192.0.2.10"], "device": "en0"}
        with (
            mock.patch.object(network_svc, "_alias_settings", lambda: conf),
            mock.patch.object(network_svc, "preferred_active_device", lambda: None),
            mock.patch.object(network_svc, "interface_addresses", lambda: []),
            mock.patch.object(
                network_svc, "_alias_local_route", side_effect=Recursing(),
            ),
            mock.patch.object(
                network_svc, "find_ip_locations",
                lambda ip, addresses=None: [],
            ),
        ):
            data = network_svc.alias_auto_status()
        _starlette(data)
        self.assertFalse(data["ips"][0]["local_route"]["ok"])
        self.assertIn("Recursing", data["ips"][0]["local_route"]["reason"])

    def test_alias_route_surrogate_exc_does_not_500(self):
        """overview is not ``_jsonable``; leftover ``\\ud800`` in ``{exc}`` UTF-8 500'd."""
        conf = {"ips": ["192.0.2.10"], "device": "en0"}
        with (
            mock.patch.object(network_svc, "_alias_settings", lambda: conf),
            mock.patch.object(network_svc, "preferred_active_device", lambda: None),
            mock.patch.object(network_svc, "interface_addresses", lambda: []),
            mock.patch.object(
                network_svc, "_alias_local_route",
                side_effect=OSError("no route\ud800"),
            ),
            mock.patch.object(
                network_svc, "find_ip_locations",
                lambda ip, addresses=None: [],
            ),
        ):
            data = network_svc.alias_auto_status()
        _starlette(data)
        self.assertNotIn("\ud800", data["ips"][0]["local_route"]["reason"])


class WireGuardDaemonArgvLeftoverTests(unittest.TestCase):
    def test_recursing_program_argument_does_not_500(self):
        """leftover ``str(argv-item)`` RecursionError used to 500 GET /api/wireguard."""
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        with mock.patch.object(
            net.plistlib, "loads",
            return_value={
                "KeepAlive": True,
                "RunAtLoad": True,
                "ProgramArguments": [Recursing(), "sleep", "infinity"],
            },
        ):
            defects = net._daemon_defects("<plist/>")
        _starlette({"defects": defects})
        self.assertIsInstance(defects, list)

    def test_surrogate_program_argument_does_not_500(self):
        with mock.patch.object(
            net.plistlib, "loads",
            return_value={
                "KeepAlive": True,
                "RunAtLoad": True,
                "ProgramArguments": ["bash", "-c", "sleep 30\ud800"],
            },
        ):
            defects = net._daemon_defects("<plist/>")
        _starlette({"defects": defects})
        self.assertTrue(all("\ud800" not in d for d in defects))


if __name__ == "__main__":
    unittest.main()
