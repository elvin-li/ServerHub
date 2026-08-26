"""Fifth leftover-500s sweep of the Network surfaces, over the mounted app.

The hunted classes (lone UTF-8 surrogates in keys AND values, the CPython
4300-digit int cap — including the already-int YAML hex form — numeric YAML
ids via the str() probe, huge-number JSON bodies, vanished-CLI /
engine-down 503-vs-500, torn IPv6, option-shaped argv values) were re-driven
through ``create_app()`` + ``TestClient(raise_server_exceptions=False)``
against every Network surface, including angles the net/net2/net3/net4
batteries never pinned:

* the *success* half of every mutation route under the full hostile zoo —
  net4 pinned the coded refusals (bad profile, bad device, bad DNS server),
  but never drove dhcp/manual/dns/enabled/wifi/order/profile/alias/failover
  end-to-end with poisoned subprocess output and poisoned stored settings
  behind them, where the handler *succeeds* and the junk has to render;
* hostile path parameters: a percent-encoded lone surrogate and an over-cap
  service name in the ``{service_name}`` slot, a surrogate ``{state}`` on
  the wifi route and a surrogate ``{container}`` on the docker-ports
  recreate route;
* PUT /api/system/network/alias/auto with a *partial* body over a poisoned
  stored section: the handler copies the stored dict — already-int over-cap
  hex ints, a ``!!binary`` netmask, junk keys — back through the real
  ``update_settings`` → ``mutate`` → ``yaml.safe_dump`` cycle, where the
  unrenderable nodes must be dropped by the retry rather than 500ing (or
  wedging every later save);
* the ``/api/tools`` network tools (ports / net/ping / net/dns /
  net/flush-dns), which sit on the same lsof/ping/dig/dscacheutil parsers
  but were never driven through HTTP with hostile output;
* the recreate gate on POST /api/system/network/docker/ports/{container}:
  junk-typed inspect fields (an int RestartPolicy.Name) must answer the
  coded 400 *before* the destructive stop/rm, not after;
* torn-IPv6 and huge-numeric dns-lookup targets.

No live leak was found: every probe answered a 2xx/4xx/503 with a
strictly-decodable UTF-8 body.  These pins hold that line.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import docker_cli, host_address, network_svc, tools_svc
from hub.auth import require_auth

#: Past CPython's default 4300-digit int<->str conversion limit.
_HUGE_DIGITS = "9" * 5000
#: The already-int leftover: YAML/plist hex parses uncapped (base 16 is
#: exempt), so the value arrives as an int that only fails at render time.
_HEX_HUGE_INT = int("f" * 4400, 16)

_APP = None


def _client() -> TestClient:
    global _APP
    if _APP is None:
        from hub.app_factory import create_app

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


# ── the hostile zoo, injected at the boundaries the wrappers scrub ──────────
#
# ``hub.util.sh`` decodes subprocess output with errors="replace", so real
# spawn output cannot carry surrogates; the stubs poison *the boundary the
# wrappers scrub* (network_svc/tools_svc read through ``_sh``/``_as_text``),
# which is the leftover-stub convention the earlier net suites pin.

_POISON_IFCONFIG = (
    f"en0: flags=8863<UP,BROADCAST,SMART,RUNNING> mtu {_HUGE_DIGITS}\n"
    "\tether aa:bb:cc:dd:ee:ff\n"
    "\tinet 192.0.2.10 netmask 0xffffff00 broadcast 192.0.2.255\n"
    "\tstatus: active\n"
    "en5: flags=8863<UP> mtu 1500\n"
    "\tether \n"
    f"\tinet 192.0.2.11 netmask 0x{'f' * 5000} broadcast 192.0.2.255\n"
    "\tstatus: active\n"
)
_POISON_ORDER = (
    "An asterisk (*) denotes that a network service is disabled.\n"
    f"({_HUGE_DIGITS}) Thunderbolt Bridge\n"
    "(Hardware Port: Thunderbolt Bridge, Device: bridge0)\n"
    "\n"
    "(1) Wi-Fi\ud800\n"
    "(Hardware Port: Wi-Fi, Device: en0)\n"
    "(2) USB LAN\n"
    "(Hardware Port: USB 10/100/1000 LAN, Device: en5)\n"
)
_POISON_HW = (
    "Hardware Port: Wi-Fi\ud800\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff\n"
    "\n"
    "Hardware Port: USB 10/100/1000 LAN\nDevice: en5\n"
    "Ethernet Address: ff:ee:dd:cc:bb:aa\n"
)
_POISON_LSOF = (
    "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
    f"node\ud800 {_HUGE_DIGITS} me 1u IPv4 0 0t0 TCP *:8080 (LISTEN)\n"
    "app 2 me 1u IPv4 0 0t0 TCP 127.0.0.1:9090 (LISTEN)\n"
)
_POISON_GETINFO = (
    "DHCP Configuration\nIP Address: 192.0.2.10\ud800\n"
    f"Subnet mask: {_HUGE_DIGITS}.255.255.0\nRouter: 192.0.2.1\n"
)


def _fake_network_sh(argv, timeout=10, **kwargs):
    prog = argv[0]
    if prog == "/sbin/ifconfig":
        if len(argv) > 2 and argv[1] in ("en0", "en5"):
            return 0, "", ""  # alias add/remove mutations succeed
        return 0, _POISON_IFCONFIG, ""
    if prog == "/usr/sbin/networksetup":
        sub = argv[1]
        return {
            "-listnetworkserviceorder": (0, _POISON_ORDER, ""),
            "-listallhardwareports": (0, _POISON_HW, ""),
            "-getinfo": (0, _POISON_GETINFO, ""),
            "-getdnsservers": (0, "1.1.1.1\ud800\n", ""),
            "-getsearchdomains": (0, "lan\ud800\n", ""),
            "-getairportpower": (0, "Wi-Fi Power (en0): On\ud800\n", ""),
            "-listallnetworkservices": (0, "An asterisk…\nWi-Fi\nUSB LAN\n", ""),
        }.get(sub, (0, "", ""))  # every mutation subcommand succeeds
    if prog == "/usr/sbin/lsof":
        return 0, _POISON_LSOF, ""
    if prog == "/usr/sbin/netstat":
        return 0, (
            "Destination Gateway Flags Netif\n"
            "default 192.0.2.1\ud800 UGSc en0\n"
            f"{_HUGE_DIGITS}.0/24 192.0.2.1 UGSc en0\n"
        ), ""
    if prog == "/sbin/route":
        return 0, "  interface: lo0\n      flags: <UP,HOST,DONE,LOCAL\ud800>\n", ""
    if prog == "/usr/bin/dscacheutil":
        return 0, f"ip_address: 1.2.3.4\ud800\nip_address: {_HUGE_DIGITS}\n", ""
    if prog == "/usr/bin/dig":
        return 0, "1.2.3.4\ud800\n", ""
    if prog == "/sbin/ping":
        return 0, f"1 packets\ud800 {_HUGE_DIGITS}\n", ""
    if prog == "/usr/bin/killall":
        return 0, "", ""
    if prog == "/usr/bin/sudo":
        return 1, "", "sudo: a password is required"
    return 1, "", "not run"


def _fake_route_lookup_sh(argv, timeout=10, **kwargs):
    return 0, "gateway: 192.0.2.1\ud800\ninterface: en0\n", ""


def _fake_docker_sh(argv, timeout=30, **kwargs):
    args = tuple(argv[1:])
    if args[:1] == ("info",):
        return 0, "engine ok", ""
    if args[:2] == ("network", "ls"):
        return 0, "aaa111\tneta\tbridge\tlocal\n", ""
    if args[:2] == ("network", "inspect"):
        return 0, '[{"Name": "neta"}]', ""
    if args[:1] == ("ps",):
        return 0, "web-1\tabcdef123456\tUp 3 days\t0.0.0.0:8080->80/tcp\n", ""
    if args[:2] in (("network", "connect"), ("network", "disconnect")):
        return 0, "", ""
    return 1, "", "unexpected docker call"


#: services.yaml leftovers behind the alias / failover settings readers.
_POISON_SETTINGS = {
    "ip_aliases": {
        "ips": [_HEX_HUGE_INT, "192.0.2.10\ud800", "192.0.2.44", 8080],
        "netmask": b"255.255.255.0",
        "interval": _HEX_HUGE_INT,
        "auto_bind": True,
    },
    "network_failover": {
        "enabled": True,
        "power_save_wifi": True,
        "interval": _HEX_HUGE_INT,
        "fail_threshold": float("inf"),
        "probe_timeout_ms": _HUGE_DIGITS,
    },
}


def _poisoned_section(name):
    return _POISON_SETTINGS.get(name, {})


class _NetworkZooSandbox(unittest.TestCase):
    """Poisoned subprocess output and stored settings behind every boundary."""

    def setUp(self):
        for patched in (
            mock.patch.object(network_svc, "sh", side_effect=_fake_network_sh),
            mock.patch.object(tools_svc, "sh", side_effect=_fake_network_sh),
            mock.patch.object(docker_cli, "sh", side_effect=_fake_docker_sh),
            mock.patch.object(
                host_address, "sh", side_effect=_fake_route_lookup_sh
            ),
            mock.patch("hub.config.settings_section", side_effect=_poisoned_section),
            mock.patch("hub.config.update_settings", return_value={}),
            mock.patch.object(network_svc, "_wstunnel_snapshot", return_value=None),
        ):
            patched.start()
            self.addCleanup(patched.stop)
        self._reset_caches()
        self.addCleanup(self._reset_caches)

    @staticmethod
    def _reset_caches():
        network_svc._bust()
        host_address.invalidate_routing()
        docker_cli.invalidate_engine_state()

    def request_ok(self, method, path, body=None, want=200):
        resp = _client().request(method, path, json=body)
        # The body must already be valid UTF-8 — decode strictly on purpose.
        text = resp.content.decode("utf-8")
        self.assertEqual(resp.status_code, want, f"{path}: {text[:300]}")
        self.assertNotIn("\ud800", text, path)
        return json.loads(text)


class NetworkMutationSuccessUnderTheZooTests(_NetworkZooSandbox):
    """The *success* half of every mutation renders the zoo as 200."""

    def test_per_service_mutations_succeed_and_render_strictly(self):
        for path, body in (
            ("/api/system/network/services/USB LAN/dhcp", {}),
            (
                "/api/system/network/services/USB LAN/manual",
                {"ip": "192.0.2.20", "subnet": "255.255.255.0",
                 "router": "192.0.2.1"},
            ),
            ("/api/system/network/services/USB LAN/dns",
             {"servers": ["1.1.1.1"]}),
            ("/api/system/network/services/USB LAN/enabled",
             {"enabled": True}),
        ):
            payload = self.request_ok("POST", path, body)
            self.assertTrue(payload["ok"], path)

    def test_wifi_power_toggles_render_the_surrogate_status_scrubbed(self):
        for state in ("on", "off"):
            payload = self.request_ok(
                "POST", f"/api/system/network/wifi/{state}", {}
            )
            self.assertTrue(payload["ok"], state)
            self.assertEqual(payload["device"], "en0")

    def test_order_succeeds_with_the_scrubbed_sibling_name_appended(self):
        payload = self.request_ok(
            "POST", "/api/system/network/order", {"services": ["USB LAN"]}
        )
        self.assertTrue(payload["ok"])
        # The over-cap ({9...}) block was skipped at parse; the surrogate
        # sibling arrives scrubbed and is appended to complete the set.
        self.assertEqual(payload["order"][0], "USB LAN")
        self.assertEqual(len(payload["order"]), 2)
        self.assertNotIn("\ud800", payload["order"][1])

    def test_every_profile_switch_runs_end_to_end_as_200(self):
        # net4 pinned only the bad_profile refusal; the success path walks
        # set_service_enabled + set_wifi_power + set_service_order +
        # ensure_aliases_on_preferred over the same poisoned listings.
        with mock.patch.object(network_svc.time, "sleep", lambda *_: None):
            for profile in ("wifi", "ethernet", "wifi_only", "ethernet_only"):
                payload = self.request_ok(
                    "POST", "/api/system/network/profile", {"profile": profile}
                )
                self.assertEqual(payload["profile"], profile)
                self.assertEqual(payload["ethernet_services"], ["USB LAN"])
                self.assertTrue(payload["order"], profile)

    def test_alias_add_and_remove_succeed_under_the_zoo(self):
        added = self.request_ok(
            "POST", "/api/system/network/alias/add",
            {"device": "en0", "ip": "192.0.2.44"},
        )
        self.assertTrue(added["ok"])
        removed = self.request_ok(
            "POST", "/api/system/network/alias/remove",
            {"device": "en0", "ip": "192.0.2.44"},
        )
        self.assertTrue(removed["ok"])

    def test_alias_auto_run_renders_the_poisoned_config_as_200(self):
        payload = self.request_ok(
            "POST", "/api/system/network/alias/auto/run", {}
        )
        # Only the renderable, valid ip survives the stored zoo.
        self.assertEqual(payload["managed_ips"], ["192.0.2.44"])
        self.assertEqual(payload["preferred"]["device"], "en0")

    def test_failover_run_coerces_the_unrenderable_settings_as_200(self):
        payload = self.request_ok(
            "POST", "/api/system/network/failover/run", {}
        )
        self.assertTrue(payload["enabled"])
        # The already-int hex-huge interval and inf threshold degrade to
        # defaults instead of ValueError/OverflowError-ing the tick.
        self.assertIn("wired_probes", payload)
        self.assertEqual(
            [probe["device"] for probe in payload["wired_probes"]], ["en5"]
        )


class HostilePathParamTests(_NetworkZooSandbox):
    """Junk in path slots answers coded errors with scrubbed echoes."""

    def test_surrogate_service_name_is_the_coded_404_scrubbed(self):
        payload = self.request_ok(
            "POST", "/api/system/network/services/%ED%A0%80svc/dhcp", {},
            want=404,
        )
        self.assertEqual(payload["detail"]["code"], "network.service_not_found")
        self.assertNotIn("\ud800", payload["detail"]["params"]["service"])

    def test_over_cap_service_name_is_the_coded_400(self):
        payload = self.request_ok(
            "POST",
            "/api/system/network/services/" + "x" * 300 + "/dhcp",
            {},
            want=400,
        )
        self.assertEqual(
            payload["detail"]["code"], "network.invalid_service_name"
        )

    def test_surrogate_wifi_state_is_the_coded_400(self):
        payload = self.request_ok(
            "POST", "/api/system/network/wifi/%ED%A0%80", {}, want=400
        )
        self.assertEqual(payload["detail"]["code"], "network.bad_wifi_state")

    def test_surrogate_container_slot_is_the_coded_400(self):
        payload = self.request_ok(
            "POST", "/api/system/network/docker/ports/%ED%A0%80web",
            {"ports": []},
            want=400,
        )
        self.assertEqual(payload["detail"]["code"], "cli.invalid_value")


class NetToolsUnderTheZooTests(_NetworkZooSandbox):
    """The /api/tools network tools share the parsers; pin them through HTTP."""

    def test_ports_listing_scrubs_the_surrogate_lsof_rows(self):
        payload = self.request_ok("GET", "/api/tools/ports?limit=50")
        self.assertTrue(payload["ok"])
        self.assertTrue(
            any(row["port"] == 9090 for row in payload["ports"])
        )

    def test_ping_scrubs_the_surrogate_and_huge_output(self):
        payload = self.request_ok(
            "POST", "/api/tools/net/ping", {"host": "example.com", "count": 3}
        )
        self.assertTrue(payload["ok"])
        self.assertNotIn("\ud800", payload["output"])

    def test_option_shaped_ping_host_is_the_coded_soft_fail(self):
        payload = self.request_ok(
            "POST", "/api/tools/net/ping", {"host": "-f"}
        )
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["code"], "tools.bad_host")

    def test_dns_lookup_scrubs_the_surrogate_dig_answer(self):
        payload = self.request_ok(
            "POST", "/api/tools/net/dns", {"name": "localhost"}
        )
        self.assertTrue(payload["ok"])

    def test_option_shaped_dns_name_is_the_coded_soft_fail(self):
        payload = self.request_ok(
            "POST", "/api/tools/net/dns", {"name": "-f-"}
        )
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["code"], "tools.bad_host")

    def test_flush_dns_renders_the_surrogate_detail_scrubbed(self):
        payload = self.request_ok("POST", "/api/tools/net/flush-dns", {})
        self.assertTrue(payload["ok"])
        self.assertTrue(
            all("\ud800" not in line for line in payload["detail"])
        )


class DnsLookupEdgeTests(_NetworkZooSandbox):
    """Torn-IPv6 and huge-numeric lookup targets stay coded / handled."""

    def test_torn_ipv6_literal_is_the_coded_400(self):
        payload = self.request_ok(
            "GET", "/api/system/network/dns-lookup?host=%5B%3A%3A1", want=400
        )
        self.assertEqual(payload["detail"]["code"], "network.invalid_hostname")

    def test_bare_ipv6_literal_is_accepted(self):
        payload = self.request_ok(
            "GET", "/api/system/network/dns-lookup?host=::1"
        )
        self.assertEqual(payload["host"], "::1")

    def test_huge_numeric_host_renders_the_huge_answer_as_a_string(self):
        payload = self.request_ok(
            "GET", "/api/system/network/dns-lookup?host=" + "9" * 200
        )
        # The >4300-digit dscacheutil answer is a *string* in the JSON body,
        # so the int->str render cap never applies.
        self.assertTrue(any(len(a) > 4300 for a in payload["answers"]))


class DockerPortsRecreateGateTests(unittest.TestCase):
    """Junk-typed inspect answers the coded 400 before the destructive rm."""

    #: RestartPolicy.Name arrives as an int; every other field is junk-typed
    #: too, so the gates must coerce or refuse — never TypeError.
    _JUNK_INSPECT = json.dumps([{
        "Config": {"Image": 123456, "Env": {"k": "v"}, "Cmd": 7},
        "HostConfig": {
            "Binds": "notalist",
            "NetworkMode": 42,
            "RestartPolicy": {"Name": 5},
            "Privileged": "yes",
        },
    }])

    def test_junk_restart_policy_is_the_coded_400_and_nothing_is_destroyed(self):
        calls = []

        def fake_docker(*args, timeout=30, **kwargs):
            calls.append(args)
            if args[:1] == ("inspect",):
                return 0, self._JUNK_INSPECT, ""
            return 0, "", ""

        with (
            mock.patch.object(network_svc, "docker", side_effect=fake_docker),
            mock.patch.object(network_svc, "engine_up", return_value=True),
        ):
            resp = _client().post(
                "/api/system/network/docker/ports/web-1",
                json={"ports": ["8080:80"]},
            )
        text = resp.content.decode("utf-8")
        self.assertEqual(resp.status_code, 400, text[:300])
        self.assertEqual(
            json.loads(text)["detail"]["code"], "container.bad_policy"
        )
        # The gate must fire before the destructive stop/rm.
        destructive = [c for c in calls if c[:1] in (("stop",), ("rm",))]
        self.assertEqual(destructive, [])


class AliasAutoPartialPutThroughTheRealDumpTests(unittest.TestCase):
    """A partial PUT copies the poisoned stored section back through
    ``update_settings`` → ``mutate`` → ``yaml.safe_dump``; the unrenderable
    already-int hex leftovers must be dropped by the dump retry, never 500
    the request or wedge later saves."""

    def setUp(self):
        from hub import config

        # Leave the suite's shared services.yaml as we found it.
        def scrub():
            def apply(data):
                settings = data.get("settings")
                if isinstance(settings, dict):
                    settings.pop("ip_aliases", None)

            config.mutate(apply)

        self.addCleanup(scrub)

    def test_partial_put_over_the_poisoned_section_stays_200(self):
        from hub import config

        stored = {
            "ips": [_HEX_HUGE_INT, "192.0.2.44"],
            "netmask": b"255.255.255.0",
            "interval": _HEX_HUGE_INT,
            "junk": _HEX_HUGE_INT,
            "auto_bind": True,
        }
        with mock.patch(
            "hub.config.settings_section", return_value=stored
        ):
            resp = _client().put(
                "/api/system/network/alias/auto", json={"auto_bind": False}
            )
        text = resp.content.decode("utf-8")
        self.assertEqual(resp.status_code, 200, text[:300])
        self.assertNotIn("\ud800", text)
        payload = json.loads(text)
        # The response re-reads the (still-poisoned) section: only the
        # renderable valid ip survives and the interval coerces to default.
        self.assertEqual(payload["config"]["ips"], ["192.0.2.44"])
        self.assertEqual(payload["config"]["interval"], 60)
        # The dump retry dropped the over-cap ints: the stored file must be
        # loadable and free of them, so later saves are not wedged.
        written = config.YAML_PATH.read_text(encoding="utf-8")
        self.assertNotIn("f" * 100, written)
        self.assertNotIn("9" * 100, written)
        section = (config.reload_cfg().get("settings") or {}).get("ip_aliases")
        self.assertIsInstance(section, dict)
        self.assertEqual(section.get("ips"), ["192.0.2.44"])
        self.assertIs(section.get("auto_bind"), False)


if __name__ == "__main__":
    unittest.main()
