"""Fourth leftover-500s sweep of the Network page, over the real mounted app.

The hunted classes (lone UTF-8 surrogates in keys AND values, the CPython
4300-digit int cap — including the uncapped YAML hex/octal form that arrives
*already-int* — numeric YAML ids, huge-number JSON documents, vanished-CLI /
engine-down 503-vs-500) were re-driven against every route the Network page
mounts:

    GET  /api/system/network             GET  /api/system/network/services
    GET  /api/system/network/addresses   GET  /api/system/network/alias/auto
    GET  /api/system/network/failover    GET  /api/system/network/docker-ports
    GET  /api/system/network/dns-lookup  PUT  /api/system/network/alias/auto
    POST /api/system/network/order       POST /api/system/network/services/{s}/dns
    POST /api/system/network/alias/add   POST /api/system/network/alias/remove
    POST /api/system/network/wifi/{s}    POST /api/system/network/profile
    POST /api/system/network/docker/connect

No live leak was found: net3's service-layer probes (``_as_text`` str()
probes on alias settings, ``_coerce_int``'s render probe, the bounded mtu /
service-order ``int()`` guards, ``parse_int_capped`` + ``_jsonable`` under
docker inspect, ``_networksetup_missing``'s failure-path disk confirm) hold
at every boundary hostile bytes can actually enter — ``hub.util.sh`` decodes
subprocess output with ``errors="replace"``, so the service parsers only ever
meet surrogates through hand-edited YAML, JSON escapes, or request bodies,
and all three are scrubbed before Starlette's strict UTF-8 render.

None of those pins exercises request routing, Pydantic body parsing,
app_factory's sanitizing handlers, or the strict UTF-8 encode of the final
body, so this battery pins the whole cycle through ``create_app()``:

* the full hostile zoo behind one GET /api/system/network — over-cap mtu and
  service-order index, hex-huge netmask, surrogate ``lsof``/``netstat``/
  ``airportpower`` stub output, an already-int hex-huge alias ip + interval,
  a ``!!binary`` netmask, a surrogate ip and a numeric id — renders 200 and
  strictly-decodable UTF-8 with the junk dropped, never a 500;
* a >4300-digit integer literal in a request body: ``json.loads`` raises
  ValueError (NOT JSONDecodeError) for the whole document, and FastAPI's
  body-parse guard answers 400, never a 500;
* a JSON ``\\ud800`` escape mints a *real* lone surrogate through
  ``request.json()``; coded refusals that echo it back in params
  (network.invalid_dns / unknown_service / invalid_device) must scrub it
  before the strict encode — and a stored one must never resurface via
  PUT /api/system/network/alias/auto's 200 body;
* one huge JSON number inside ``docker network inspect`` degrades that
  network's row only, never the docker-ports listing (the ValueError-not-
  JSONDecodeError journal rule), and an escaped surrogate container name is
  scrubbed;
* the vanished docker CLI answers the coded 503 on the mounted
  connect/disconnect routes only after the *forced fresh probe* confirms the
  engine is unreachable; a timeout with the engine up keeps the plain
  ``ok: false`` 200 shape (the disk-confirm-on-the-failure-path convention —
  the networksetup twin is pinned in
  test_network_profile_networksetup_missing_503).
"""
from __future__ import annotations

import asyncio
import json
import unittest
from unittest import mock

from hub import docker_cli, host_address, network_svc
from hub.app_factory import create_app
from hub.auth import require_auth

#: Past CPython's default 4300-digit int<->str conversion limit.
_HUGE_DIGITS = "9" * 5000
#: The already-int leftover: YAML/plist hex parses uncapped (base 16 is
#: exempt), so the value arrives as an int that only fails at render time.
_HEX_HUGE_INT = int("f" * 4400, 16)

_app = None


def _the_app():
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return _app


async def _asgi_request(method, path, *, body=None, raw_body=None, query=b""):
    """Drive the full panel app (middleware + handlers) through one cycle."""
    app = _the_app()
    payload = raw_body if raw_body is not None else (
        b"{}" if body is None else json.dumps(body).encode("utf-8")
    )
    sent = False
    messages: list[dict] = []

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": payload, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1", "method": method, "scheme": "http",
        "path": path, "raw_path": path.encode(), "query_string": query,
        "root_path": "",
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
            (b"host", b"localhost:8086"),
        ],
        "server": ("localhost", 8086), "client": ("127.0.0.1", 1), "state": {},
    }
    await app(scope, receive, send)
    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    raw = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    # The body must already be valid UTF-8 — decode strictly on purpose.
    return status, raw.decode("utf-8")


def request(method, path, *, body=None, raw_body=None, query=b""):
    return asyncio.run(
        _asgi_request(method, path, body=body, raw_body=raw_body, query=query)
    )


# ── hostile subprocess outputs, injected at the real boundaries ─────────────
#
# ``hub.util.sh`` decodes with errors="replace", so real spawn output cannot
# carry surrogates; tests stub *the boundary the wrappers scrub* — network_svc
# reads through ``_sh``/``_as_text``, docker through ``docker()``'s
# ``_as_text``, host_address through its own scrubbers — which is exactly the
# leftover-stub convention the service-layer suites already pin.

_POISON_IFCONFIG = (
    f"en0: flags=8863<UP,BROADCAST,SMART,RUNNING> mtu {_HUGE_DIGITS}\n"
    "\tether aa:bb:cc:dd:ee:ff\n"
    "\tinet 192.0.2.10 netmask 0xffffff00 broadcast 192.0.2.255\n"
    "\tstatus: active\n"
    "en1\ud800: flags=8863<UP> mtu 1500\n"
    "\tether \n"
    f"\tinet 192.0.2.11 netmask 0x{'f' * 5000} broadcast 192.0.2.255\n"
)
_POISON_ORDER = (
    "An asterisk (*) denotes that a network service is disabled.\n"
    f"({_HUGE_DIGITS}) Thunderbolt Bridge\n"
    "(Hardware Port: Thunderbolt Bridge, Device: bridge0)\n"
    "\n"
    "(2) Wi-Fi\ud800\n"
    "(Hardware Port: Wi-Fi, Device: en0)\n"
)
_POISON_HW_PORTS = (
    "Hardware Port: Wi-Fi\ud800\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff\n"
)
_POISON_LSOF = (
    "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
    f"node\ud800 {_HUGE_DIGITS} me 1u IPv4 0 0t0 TCP *:8080 (LISTEN)\n"
    "app 2 me 1u IPv4 0 0t0 TCP 127.0.0.1:9090 (LISTEN)\n"
)
_POISON_NETSTAT = (
    "Destination Gateway Flags Netif\n"
    "default 192.0.2.1\ud800 UGSc en0\n"
    f"{_HUGE_DIGITS}.0/24 192.0.2.1 UGSc en0\n"
)
_POISON_GETINFO = (
    "DHCP Configuration\nIP Address: 192.0.2.10\ud800\n"
    f"Subnet mask: {_HUGE_DIGITS}.255.255.0\nRouter: 192.0.2.1\n"
)


def _fake_network_sh(argv, timeout=10, **kwargs):
    prog = argv[0]
    if prog == "/sbin/ifconfig":
        return 0, _POISON_IFCONFIG, ""
    if prog == "/usr/sbin/networksetup":
        sub = argv[1]
        if sub == "-listnetworkserviceorder":
            return 0, _POISON_ORDER, ""
        if sub == "-listallhardwareports":
            return 0, _POISON_HW_PORTS, ""
        if sub == "-getinfo":
            return 0, _POISON_GETINFO, ""
        if sub == "-getdnsservers":
            return 0, "1.1.1.1\ud800\n", ""
        if sub == "-getsearchdomains":
            return 0, "lan\ud800\n", ""
        if sub == "-getairportpower":
            return 0, "Wi-Fi Power (en0): On\ud800\n", ""
        if sub == "-listallnetworkservices":
            return 0, "An asterisk…\nWi-Fi\n", ""
        return 0, "", ""
    if prog == "/usr/sbin/lsof":
        return 0, _POISON_LSOF, ""
    if prog == "/usr/sbin/netstat":
        return 0, _POISON_NETSTAT, ""
    if prog == "/sbin/route":
        return 0, "  interface: lo0\n      flags: <UP,HOST,DONE,LOCAL\ud800>\n", ""
    if prog == "/usr/bin/dscacheutil":
        return 0, f"ip_address: 1.2.3.4\ud800\nip_address: {_HUGE_DIGITS}\n", ""
    if prog == "/usr/bin/dig":
        return 0, "1.2.3.4\ud800\n", ""
    return 1, "", "not run"


def _fake_route_lookup_sh(argv, timeout=10, **kwargs):
    """host_address's default-route read; its parsers scrub the surrogate."""
    return 0, "gateway: 192.0.2.1\ud800\ninterface: en0\n", ""


_DOCKER_NET_LS = "aaa111\tneta\tbridge\tlocal\nbbb222\tnetb\tbridge\tlocal\n"
#: >4300-digit decimal in otherwise valid JSON: ``json.loads`` raises plain
#: ValueError (the int parse cap), not JSONDecodeError.
_DOCKER_HUGE_JSON = '[{"Name": "neta", "IPAM": ' + "1" * 4400 + "}]"
#: json.loads('"\\ud800"') emits a real lone surrogate from ASCII input.
_DOCKER_SURROGATE_JSON = (
    '[{"Name": "netb", '
    '"IPAM": {"Config": [{"Subnet": "10.9.0.0/24", "Gateway": "10.9.0.1"}]}, '
    '"Containers": {"abcdef123456": '
    '{"Name": "/web\\ud800", "IPv4Address": "10.9.0.2/24"}}}]'
)
_DOCKER_PS = (
    "web-1\tabcdef123456\tUp 3 days\t"
    f"0.0.0.0:{_HUGE_DIGITS}->80/tcp, :::8080->80\ud800/tcp\n"
)


def _fake_docker_sh(argv, timeout=30, **kwargs):
    args = tuple(argv[1:])
    if args[:1] == ("info",):
        return 0, "engine ok", ""
    if args[:2] == ("network", "ls"):
        return 0, _DOCKER_NET_LS, ""
    if args[:2] == ("network", "inspect"):
        out = _DOCKER_HUGE_JSON if args[2] == "neta" else _DOCKER_SURROGATE_JSON
        return 0, out, ""
    if args[:1] == ("ps",):
        return 0, _DOCKER_PS, ""
    return 1, "", "unexpected docker call"


#: services.yaml leftovers behind the alias / failover settings readers: the
#: already-int hex-huge (str() raises), a surrogate ip, a numeric id, a
#: ``!!binary`` netmask and an unrenderable interval.
_POISON_SETTINGS = {
    "ip_aliases": {
        "ips": [_HEX_HUGE_INT, "192.0.2.10\ud800", "192.0.2.44", 8080],
        "netmask": b"255.255.255.0",
        "interval": _HEX_HUGE_INT,
        "auto_bind": True,
    },
    "network_failover": {
        "enabled": True,
        "interval": _HEX_HUGE_INT,
        "fail_threshold": float("inf"),
        "probe_timeout_ms": _HUGE_DIGITS,
    },
}


def _poisoned_section(name):
    return _POISON_SETTINGS.get(name, {})


#: A clean wstunnel snapshot (wt.status caps the port and scrubs text); the
#: merge into the listening rows is the one overview leg outside ``_safe``.
_WSTUNNEL_SNAPSHOT = {
    "configured": True, "running": True, "pid": 12, "port": 8444,
    "listen": "wss://0.0.0.0:8444", "restrict_to": "127.0.0.1:51820",
}


class _NetworkHttpSandbox(unittest.TestCase):
    """The hostile zoo behind every subprocess/settings boundary."""

    def setUp(self):
        for patched in (
            mock.patch.object(network_svc, "sh", side_effect=_fake_network_sh),
            mock.patch.object(docker_cli, "sh", side_effect=_fake_docker_sh),
            mock.patch.object(host_address, "sh", side_effect=_fake_route_lookup_sh),
            mock.patch("hub.config.settings_section", side_effect=_poisoned_section),
            mock.patch.object(
                network_svc, "_wstunnel_snapshot",
                return_value=dict(_WSTUNNEL_SNAPSHOT),
            ),
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


class NetworkOverviewHostileHttpTests(_NetworkHttpSandbox):
    """GET /api/system/network with the whole zoo renders 200, scrubbed."""

    def test_overview_renders_the_zoo_as_200(self):
        status, text = request(
            "GET", "/api/system/network", query=b"force=true"
        )
        self.assertEqual(status, 200, text[:300])
        self.assertNotIn("\ud800", text)
        payload = json.loads(text)
        by_name = {
            i.get("name"): i
            for i in payload["interfaces"]
            if isinstance(i, dict)
        }
        # The over-cap mtu degrades to None; the interface itself survives.
        self.assertIn("en0", by_name)
        self.assertIsNone(by_name["en0"]["mtu"])
        self.assertEqual(by_name["en0"]["ipv4"][0]["ip"], "192.0.2.10")
        # The over-cap service-order block is skipped, its sane sibling kept.
        self.assertEqual([s["order"] for s in payload["services"]], [2])
        self.assertEqual(payload["services"][0]["device"], "en0")
        # The alias config keeps only the renderable, valid ip.
        self.assertEqual(payload["alias_auto"]["config"]["ips"], ["192.0.2.44"])
        self.assertEqual(
            payload["alias_auto"]["config"]["netmask"], "255.255.255.0"
        )
        self.assertEqual(payload["alias_auto"]["config"]["interval"], 60)

    def test_overview_merges_the_wstunnel_listener_outside_safe(self):
        """`_with_wstunnel_listener` is the one collector leg not under
        ``_safe``; the clean snapshot must merge as a listening row."""
        status, text = request(
            "GET", "/api/system/network", query=b"force=true"
        )
        self.assertEqual(status, 200, text[:300])
        rows = json.loads(text)["listening"]
        wstunnel = [r for r in rows if r.get("process") == "wstunnel"]
        self.assertEqual(len(wstunnel), 1)
        self.assertEqual(wstunnel[0]["port"], "8444")
        # The surrogate lsof rows still listed, scrubbed.
        self.assertTrue(any(r.get("port") == "9090" for r in rows))


class NetworkReadRoutesHostileHttpTests(_NetworkHttpSandbox):
    """Every sibling GET renders the same zoo as 200 strict UTF-8."""

    def test_services_route_skips_the_over_cap_block(self):
        status, text = request("GET", "/api/system/network/services")
        self.assertEqual(status, 200, text[:300])
        self.assertNotIn("\ud800", text)
        services = json.loads(text)["services"]
        self.assertEqual([s["order"] for s in services], [2])

    def test_addresses_route_renders_the_hex_huge_netmask(self):
        status, text = request("GET", "/api/system/network/addresses")
        self.assertEqual(status, 200, text[:300])
        self.assertNotIn("\ud800", text)
        rows = json.loads(text)["interfaces"]
        by_dev = {r["device"]: r for r in rows}
        self.assertIn("en0", by_dev)
        self.assertEqual(by_dev["en0"]["addresses"][0]["ip"], "192.0.2.10")

    def test_alias_auto_route_drops_only_the_junk_ips(self):
        status, text = request("GET", "/api/system/network/alias/auto")
        self.assertEqual(status, 200, text[:300])
        self.assertNotIn("\ud800", text)
        payload = json.loads(text)
        self.assertEqual(payload["config"]["ips"], ["192.0.2.44"])
        self.assertEqual([row["ip"] for row in payload["ips"]], ["192.0.2.44"])

    def test_failover_route_coerces_the_unrenderable_settings(self):
        status, text = request("GET", "/api/system/network/failover")
        self.assertEqual(status, 200, text[:300])
        config = json.loads(text)["config"]
        self.assertEqual(config["interval"], 15)
        self.assertEqual(config["fail_threshold"], 2)
        self.assertEqual(config["probe_timeout_ms"], 1200)

    def test_docker_ports_route_degrades_one_network_not_the_listing(self):
        status, text = request("GET", "/api/system/network/docker-ports")
        self.assertEqual(status, 200, text[:300])
        self.assertNotIn("\ud800", text)
        payload = json.loads(text)
        by_name = {n["name"]: n for n in payload["networks"]}
        self.assertEqual(set(by_name), {"neta", "netb"})
        # The huge JSON number empties that network's detail only …
        self.assertEqual(by_name["neta"]["subnet"], "")
        self.assertEqual(by_name["netb"]["subnet"], "10.9.0.0/24")
        # … and the escaped surrogate container name arrives scrubbed.
        self.assertEqual(len(by_name["netb"]["containers"]), 1)
        # The huge published host port renders as the string it is.
        ports = payload["ports"]
        self.assertTrue(any(p["container"] == "web-1" for p in ports))

    def test_dns_lookup_scrubs_surrogate_answers(self):
        status, text = request(
            "GET", "/api/system/network/dns-lookup", query=b"host=example.com"
        )
        self.assertEqual(status, 200, text[:300])
        self.assertNotIn("\ud800", text)
        self.assertTrue(json.loads(text)["ok"])

    def test_dns_lookup_refuses_an_option_shaped_host(self):
        status, text = request(
            "GET", "/api/system/network/dns-lookup", query=b"host=--help"
        )
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(
            json.loads(text)["detail"]["code"], "network.invalid_hostname"
        )


class NetworkBodyParseGuardHttpTests(_NetworkHttpSandbox):
    """Hostile request bodies through Pydantic and the body-parse guard."""

    def test_huge_int_body_is_the_parse_400_never_a_500(self):
        # json.loads raises ValueError — not JSONDecodeError — on the
        # >4300-digit literal; FastAPI's generic body guard answers 400.
        status, text = request(
            "PUT", "/api/system/network/alias/auto",
            raw_body=b'{"interval": ' + _HUGE_DIGITS.encode() + b"}",
        )
        self.assertEqual(status, 400, text[:300])
        self.assertIn("error parsing the body", text)

    def test_escaped_surrogate_ip_never_resurfaces_in_the_200_body(self):
        # request.json() mints a real lone surrogate from the ASCII escape;
        # the write path's str() probe drops it and the response re-reads
        # the (poisoned) stored config — the body must stay strictly UTF-8.
        with mock.patch("hub.config.update_settings", return_value={}):
            status, text = request(
                "PUT", "/api/system/network/alias/auto",
                raw_body=b'{"ips": ["192.0.2.10", "\\ud800bad"]}',
            )
        self.assertEqual(status, 200, text[:300])
        self.assertNotIn("\ud800", text)
        self.assertEqual(json.loads(text)["config"]["ips"], ["192.0.2.44"])

    def test_over_cap_service_name_is_the_coded_400(self):
        with mock.patch.object(
            network_svc, "network_services", return_value=[{"name": "Wi-Fi"}]
        ):
            status, text = request(
                "POST", "/api/system/network/order",
                body={"services": ["Nope" + _HUGE_DIGITS]},
            )
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(
            json.loads(text)["detail"]["code"], "network.unknown_service"
        )


class NetworkCodedErrorParamHttpTests(_NetworkHttpSandbox):
    """Coded refusals that echo caller values must render strictly."""

    def test_option_shaped_dns_server_is_the_coded_400(self):
        with mock.patch.object(
            network_svc, "network_services", return_value=[{"name": "Wi-Fi"}]
        ):
            status, text = request(
                "POST", "/api/system/network/services/Wi-Fi/dns",
                body={"servers": ["-getinfo"]},
            )
        self.assertEqual(status, 400, text[:300])
        detail = json.loads(text)["detail"]
        self.assertEqual(detail["code"], "network.invalid_dns")
        self.assertEqual(detail["params"]["server"], "-getinfo")

    def test_surrogate_dns_server_is_scrubbed_in_the_echo(self):
        with mock.patch.object(
            network_svc, "network_services", return_value=[{"name": "Wi-Fi"}]
        ):
            status, text = request(
                "POST", "/api/system/network/services/Wi-Fi/dns",
                raw_body=b'{"servers": ["\\ud800dns"]}',
            )
        self.assertEqual(status, 400, text[:300])
        self.assertNotIn("\ud800", text)
        self.assertEqual(
            json.loads(text)["detail"]["code"], "network.invalid_dns"
        )

    def test_option_shaped_alias_device_is_the_coded_400(self):
        status, text = request(
            "POST", "/api/system/network/alias/add",
            body={"device": "-x", "ip": "192.0.2.99"},
        )
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(
            json.loads(text)["detail"]["code"], "network.invalid_device"
        )

    def test_unknown_alias_device_is_the_coded_404(self):
        status, text = request(
            "POST", "/api/system/network/alias/add",
            body={"device": "en99", "ip": "192.0.2.99"},
        )
        self.assertEqual(status, 404, text[:300])
        self.assertEqual(
            json.loads(text)["detail"]["code"], "network.device_not_found"
        )

    def test_signed_and_over_cap_octets_are_the_coded_400(self):
        # int() accepts a sign, so "-0.0.0.0" once validated; the huge octet
        # once ValueError'd — both must stay the coded invalid_ip.
        for ip in ("-0.0.0.0", _HUGE_DIGITS + ".1.1.1"):
            status, text = request(
                "POST", "/api/system/network/alias/remove",
                body={"device": "en0", "ip": ip},
            )
            self.assertEqual(status, 400, text[:300])
            self.assertEqual(
                json.loads(text)["detail"]["code"], "network.invalid_ip"
            )

    def test_bad_wifi_state_and_surrogate_profile_stay_coded(self):
        status, text = request("POST", "/api/system/network/wifi/sideways")
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(
            json.loads(text)["detail"]["code"], "network.bad_wifi_state"
        )
        status, text = request(
            "POST", "/api/system/network/profile",
            raw_body=b'{"profile": "\\ud800"}',
        )
        self.assertEqual(status, 400, text[:300])
        self.assertNotIn("\ud800", text)
        self.assertEqual(
            json.loads(text)["detail"]["code"], "network.bad_profile"
        )

    def test_option_shaped_docker_network_is_the_coded_400(self):
        status, text = request(
            "POST", "/api/system/network/docker/connect",
            body={"network": "--net", "container": "web"},
        )
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(
            json.loads(text)["detail"]["code"], "cli.invalid_value"
        )


class DockerVanishedCliHttpTests(unittest.TestCase):
    """Vanished CLI is the coded 503 through the mounted mutation routes."""

    SENTINEL = (-1, "", "not found")

    def setUp(self):
        docker_cli.invalidate_engine_state()
        self.addCleanup(docker_cli.invalidate_engine_state)

    def test_vanished_cli_answers_503_via_the_fresh_probe(self):
        # Both the mutation and the forced ``docker info`` probe hit the
        # spawn sentinel, so the fresh probe confirms "down" on the failure
        # path only — never a raw stderr message, never a 500.
        for route in (
            "/api/system/network/docker/connect",
            "/api/system/network/docker/disconnect",
        ):
            with (
                mock.patch.object(
                    network_svc, "docker", return_value=self.SENTINEL
                ),
                mock.patch.object(
                    docker_cli, "docker", return_value=self.SENTINEL
                ),
            ):
                status, text = request(
                    "POST", route,
                    body={"network": "mynet", "container": "web-1"},
                )
            self.assertEqual(status, 503, text[:300])
            self.assertEqual(
                json.loads(text)["detail"]["code"], "container.engine_down"
            )
            docker_cli.invalidate_engine_state()

    def test_timeout_with_the_engine_up_keeps_the_ok_false_shape(self):
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(
                network_svc, "docker", return_value=(-1, "", "timeout")
            ),
            mock.patch.object(network_svc, "engine_up", probe),
        ):
            status, text = request(
                "POST", "/api/system/network/docker/connect",
                body={"network": "mynet", "container": "web-1"},
            )
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "timeout")
        probe.assert_called_once_with(force=True)


if __name__ == "__main__":
    unittest.main()
