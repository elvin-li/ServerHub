"""Seventh leftover-500s sweep of the Network surfaces, over the mounted app.

net6 sealed the YAML-cycle deep_merge 500s over the real on-disk file; this
wave hunts what net5/net6 never drove: *subclass* leftovers nested INSIDE
the values the settings readers and the ``_sh`` text scrub coerce.
``settings_section`` launders the section itself to an exact dict, but the
nested values are whatever an in-process caller last stored, and
``hub.util.sh`` is stubbed by callers/tests with leftover subclass output —
both boundaries ran the poison's own dunders through bound methods.

Live leftovers found and fixed (each 500'd on the pre-fix tree):

* ``ips`` wearing a list-subclass ``__iter__`` bomb or a ``__bool__`` bomb,
  or a str-subclass ``replace`` bomb — GET/PUT /alias/auto, POST
  /alias/auto/run raised out of ``_alias_settings``;
* ``auto_bind`` / ``prefer_wired`` / failover ``enabled`` /
  ``power_save_wifi`` flags whose ``__bool__`` raises — the ``bool(...)``
  and ``x or default`` truth tests detonated on the same routes plus
  GET /failover and POST /failover/run;
* ``interval`` / thresholds whose ``__int__`` raises a non-ValueError —
  ``_coerce_int``'s (TypeError, ValueError, OverflowError) net let it out;
* a bytes-subclass ``decode`` bomb or a str-subclass self-``__str__``
  ``encode`` bomb as the netmask (through ``_as_text``) or as ``_sh``
  output (through every parser: services, addresses, wifi, dns-lookup);
* the same self-``__str__`` encode bomb riding an exception message into
  ``_as_text(exc)`` in the alias status row collector.

The fixes are the modules5/cf7 unbound-base convention: ``list.__iter__`` /
``str.replace`` / ``str.split`` / ``str.strip`` / ``bytes.decode`` /
``str.encode`` views read the real content underneath the override, so the
poison scrubs field-level — the real ips still render and only the truly
unrenderable degrades to its default.  Huge-int JSON bodies (``json.loads``
raising the digit-cap ValueError, not JSONDecodeError) ride along as
stays-immune pins on the alias mutation routes.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import docker_cli, host_address, network_svc

#: Past CPython's default 4300-digit int<->str conversion limit.
_HUGE_DIGITS = "9" * 5000

_APP = None


def _client() -> TestClient:
    global _APP
    if _APP is None:
        from hub.app_factory import create_app
        from hub.auth import require_auth

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


# ── the subclass-bomb zoo ────────────────────────────────────────────────────


class _BoolBomb:
    def __bool__(self):
        raise RuntimeError("bool bomb")


class _IntBomb:
    """Truthy (default __bool__) so it reaches int(); __int__ then bombs."""

    def __int__(self):
        raise RuntimeError("int bomb")


class _IterBombList(list):
    def __iter__(self):
        raise RuntimeError("iter bomb")


class _BoolBombList(list):
    def __bool__(self):
        raise RuntimeError("bool bomb")


class _ReplaceBombStr(str):
    def replace(self, *args, **kwargs):
        raise RuntimeError("replace bomb")


class _EncodeBombStr(str):
    """``__str__`` answers *self*, so the bound ``encode`` bomb survives
    ``str()`` — the exact shape that used to ride ``_as_text`` into a 500."""

    def __str__(self):
        return self

    def encode(self, *args, **kwargs):
        raise RuntimeError("encode bomb")


class _DecodeBombBytes(bytes):
    def decode(self, *args, **kwargs):
        raise RuntimeError("decode bomb")


class _StripBombStr(str):
    def strip(self, *args, **kwargs):
        raise RuntimeError("strip bomb")


# ── sane subprocess stubs (the settings values are the hostile boundary) ────

_SANE_IFCONFIG = (
    "en0: flags=8863<UP,BROADCAST,SMART,RUNNING> mtu 1500\n"
    "\tether aa:bb:cc:dd:ee:ff\n"
    "\tinet 192.0.2.10 netmask 0xffffff00 broadcast 192.0.2.255\n"
    "\tstatus: active\n"
)
_SANE_ORDER = (
    "An asterisk (*) denotes that a network service is disabled.\n"
    "(1) Wi-Fi\n"
    "(Hardware Port: Wi-Fi, Device: en0)\n"
    "(2) USB LAN\n"
    "(Hardware Port: USB 10/100/1000 LAN, Device: en5)\n"
)
_SANE_HW = (
    "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff\n"
    "\n"
    "Hardware Port: USB 10/100/1000 LAN\nDevice: en5\n"
    "Ethernet Address: ff:ee:dd:cc:bb:aa\n"
)


def _fake_network_sh(argv, timeout=10, **kwargs):
    prog = argv[0]
    if prog == "/sbin/ifconfig":
        if len(argv) > 2 and argv[1].startswith("en"):
            return 0, "", ""  # alias add/remove mutations succeed
        return 0, _SANE_IFCONFIG, ""
    if prog == "/usr/sbin/networksetup":
        return {
            "-listnetworkserviceorder": (0, _SANE_ORDER, ""),
            "-listallhardwareports": (0, _SANE_HW, ""),
            "-getinfo": (
                0,
                "DHCP Configuration\nIP Address: 192.0.2.10\nRouter: 192.0.2.1\n",
                "",
            ),
            "-getdnsservers": (0, "1.1.1.1\n", ""),
            "-getsearchdomains": (0, "lan\n", ""),
            "-getairportpower": (0, "Wi-Fi Power (en0): On\n", ""),
            "-listallnetworkservices": (0, "An asterisk\nWi-Fi\nUSB LAN\n", ""),
        }.get(argv[1], (0, "", ""))
    if prog == "/sbin/route":
        return 0, "  interface: lo0\n      flags: <UP,HOST,DONE,LOCAL>\n", ""
    if prog == "/usr/sbin/lsof":
        return 0, (
            "COMMAND PID USER FD TYPE DEVICE SIZE NODE NAME\n"
            "app 2 me 1u IPv4 0 0t0 TCP 127.0.0.1:9090 (LISTEN)\n"
        ), ""
    if prog == "/usr/sbin/netstat":
        return 0, "default 192.0.2.1 UGSc en0\n", ""
    if prog == "/sbin/ping":
        return 0, "1 packets\n", ""
    if prog == "/usr/bin/dscacheutil":
        return 0, "ip_address: 1.2.3.4\n", ""
    if prog == "/usr/bin/dig":
        return 0, "1.2.3.4\n", ""
    if prog == "/usr/bin/sudo":
        return 1, "", "sudo: a password is required"
    return 1, "", "not run"


def _fake_docker_sh(argv, timeout=30, **kwargs):
    return 1, "", "Cannot connect to the Docker daemon"


class _NetworkSandbox(unittest.TestCase):
    """Sane subprocess stubs; per-class hostile settings behind them."""

    #: Overridden per subclass: what ``settings_section(name)`` answers.
    SETTINGS: dict = {}

    def setUp(self):
        for patched in (
            mock.patch.object(network_svc, "sh", side_effect=self.network_sh),
            mock.patch.object(host_address, "sh", side_effect=_fake_network_sh),
            mock.patch.object(docker_cli, "sh", side_effect=_fake_docker_sh),
            mock.patch.object(network_svc, "_wstunnel_snapshot", return_value=None),
            mock.patch(
                "hub.config.settings_section",
                side_effect=lambda name: self.SETTINGS.get(name, {}),
            ),
            mock.patch("hub.config.update_settings", return_value={}),
        ):
            patched.start()
            self.addCleanup(patched.stop)
        self._reset_caches()
        self.addCleanup(self._reset_caches)

    #: Overridden by the ``_sh``-boundary class to poison the output shape.
    network_sh = staticmethod(_fake_network_sh)

    @staticmethod
    def _reset_caches():
        network_svc._bust()
        host_address.invalidate_routing()
        docker_cli.invalidate_engine_state()

    def request_ok(self, method, path, body=None, want=200, raw=None):
        if raw is not None:
            resp = _client().request(
                method, path, content=raw,
                headers={"content-type": "application/json"},
            )
        else:
            resp = _client().request(method, path, json=body)
        # The body must already be valid UTF-8 — decode strictly on purpose.
        text = resp.content.decode("utf-8")
        self.assertEqual(resp.status_code, want, f"{path}: {text[:300]}")
        self.assertNotIn("\ud800", text, path)
        return json.loads(text)


class AliasSettingsSubclassBombTests(_NetworkSandbox):
    """Nested bombs inside settings.ip_aliases scrub field-level, never 500."""

    SETTINGS = {
        "ip_aliases": {
            # Real content underneath the bombed __iter__: the unbound view
            # must still read it, so the valid ip SURVIVES the poison.
            "ips": _IterBombList(["192.0.2.44", 8080]),
            "netmask": _DecodeBombBytes(b"255.255.255.0"),
            "interval": _IntBomb(),
            "auto_bind": _BoolBomb(),
            "prefer_wired": _BoolBomb(),
        },
        "network_failover": {"enabled": False},
    }

    def test_alias_status_renders_the_real_ips_under_the_bombs(self):
        payload = self.request_ok("GET", "/api/system/network/alias/auto")
        conf = payload["config"]
        self.assertEqual(conf["ips"], ["192.0.2.44"])
        self.assertEqual(conf["netmask"], "255.255.255.0")
        self.assertEqual(conf["interval"], 60)
        # A bomb flag is junk, not consent to rebind — fails closed.
        self.assertIs(conf["auto_bind"], False)
        self.assertIs(conf["prefer_wired"], False)

    def test_alias_auto_run_stays_200_under_the_bombs(self):
        payload = self.request_ok("POST", "/api/system/network/alias/auto/run")
        self.assertEqual(payload["managed_ips"], ["192.0.2.44"])

    def test_alias_put_stays_200_under_the_bombs(self):
        payload = self.request_ok(
            "PUT", "/api/system/network/alias/auto", {"interval": 90}
        )
        self.assertEqual(payload["config"]["ips"], ["192.0.2.44"])

    def test_overview_keeps_the_alias_panel_rich(self):
        # Pre-fix the _safe wrapper ate the raise and the panel went dark
        # (alias_auto: null); the field-level scrub keeps it rendered.
        payload = self.request_ok("GET", "/api/system/network")
        self.assertIsNotNone(payload["alias_auto"])
        self.assertEqual(
            payload["alias_auto"]["config"]["ips"], ["192.0.2.44"]
        )


class AliasBoolAndStrBombVariantsTests(_NetworkSandbox):
    """The __bool__-bombed list and replace-bombed str forms of ``ips``."""

    SETTINGS = {
        "ip_aliases": {
            "ips": _BoolBombList(["192.0.2.44"]),
            "netmask": _EncodeBombStr("255.255.255.0"),
            "interval": _BoolBomb(),
            "auto_bind": True,
        },
        "network_failover": {"enabled": False},
    }

    def test_bool_bombed_list_and_encode_bombed_netmask_stay_200(self):
        payload = self.request_ok("GET", "/api/system/network/alias/auto")
        conf = payload["config"]
        self.assertEqual(conf["ips"], ["192.0.2.44"])
        self.assertEqual(conf["netmask"], "255.255.255.0")
        self.assertEqual(conf["interval"], 60)

    def test_replace_bombed_str_ips_still_split(self):
        section = dict(self.SETTINGS["ip_aliases"])
        section["ips"] = _ReplaceBombStr("192.0.2.44, 192.0.2.45")
        with mock.patch(
            "hub.config.settings_section",
            side_effect=lambda name: {"ip_aliases": section}.get(name, {}),
        ):
            payload = self.request_ok("GET", "/api/system/network/alias/auto")
        # The unbound str.replace/str.split read the real text underneath.
        self.assertEqual(
            payload["config"]["ips"], ["192.0.2.44", "192.0.2.45"]
        )


class FailoverSettingsSubclassBombTests(_NetworkSandbox):
    """Nested bombs inside settings.network_failover coerce to defaults."""

    SETTINGS = {
        "ip_aliases": {"auto_bind": False, "ips": []},
        "network_failover": {
            "enabled": _BoolBomb(),
            "power_save_wifi": _BoolBomb(),
            "interval": _IntBomb(),
            "fail_threshold": _BoolBomb(),
            "recover_threshold": _IntBomb(),
            "probe_timeout_ms": _BoolBomb(),
        },
    }

    def test_failover_status_coerces_every_bombed_field(self):
        payload = self.request_ok("GET", "/api/system/network/failover")
        conf = payload["config"]
        self.assertIs(conf["enabled"], False)
        self.assertIs(conf["power_save_wifi"], False)
        self.assertEqual(conf["interval"], 15)
        self.assertEqual(conf["fail_threshold"], 2)
        self.assertEqual(conf["recover_threshold"], 2)
        self.assertEqual(conf["probe_timeout_ms"], 1200)

    def test_failover_run_answers_disabled_not_500(self):
        payload = self.request_ok("POST", "/api/system/network/failover/run")
        # The bombed enabled flag is junk, not consent to toggle the radio.
        self.assertEqual(payload["mode"], "disabled")

    def test_enabled_tick_with_bombed_knobs_stays_200(self):
        section = dict(self.SETTINGS["network_failover"])
        section["enabled"] = True
        with mock.patch(
            "hub.config.settings_section",
            side_effect=lambda name: {
                "ip_aliases": {"auto_bind": False, "ips": []},
                "network_failover": section,
            }.get(name, {}),
        ):
            payload = self.request_ok(
                "POST", "/api/system/network/failover/run"
            )
        self.assertTrue(payload["enabled"])
        self.assertIn("wifi", payload)


class ShOutputSubclassBombTests(_NetworkSandbox):
    """``sh`` stubbed with subclass output: every parser reads through the
    ``_as_text`` scrub, whose bound decode/encode used to run the bomb."""

    SETTINGS = {
        "ip_aliases": {"auto_bind": True, "ips": ["192.0.2.44"]},
        "network_failover": {"enabled": False},
    }

    #: Set per test: wraps every stdout/stderr the sane stub answers.
    _WRAP = staticmethod(lambda text: text)

    @classmethod
    def network_sh(cls, argv, timeout=10, **kwargs):
        rc, out, err = _fake_network_sh(argv, timeout=timeout, **kwargs)
        return rc, cls._WRAP(out), cls._WRAP(err)

    def _drive_the_readers(self):
        services = self.request_ok("GET", "/api/system/network/services")
        self.assertEqual(
            [s["name"] for s in services["services"]], ["Wi-Fi", "USB LAN"]
        )
        addresses = self.request_ok("GET", "/api/system/network/addresses")
        self.assertEqual(addresses["interfaces"][0]["device"], "en0")
        wifi = self.request_ok("POST", "/api/system/network/wifi/on")
        self.assertEqual(wifi["device"], "en0")
        lookup = self.request_ok(
            "GET", "/api/system/network/dns-lookup?host=example.com"
        )
        self.assertEqual(lookup["answers"], ["1.2.3.4"])

    def test_decode_bombed_bytes_output_parses_field_level(self):
        type(self)._WRAP = staticmethod(
            lambda text: _DecodeBombBytes(text.encode("utf-8"))
        )
        try:
            self._drive_the_readers()
        finally:
            type(self)._WRAP = staticmethod(lambda text: text)

    def test_encode_bombed_selfstr_output_parses_field_level(self):
        type(self)._WRAP = staticmethod(_EncodeBombStr)
        try:
            self._drive_the_readers()
        finally:
            type(self)._WRAP = staticmethod(lambda text: text)

    def test_encode_bombed_exception_message_stays_in_the_row(self):
        # The alias status row collector catches and renders exceptions via
        # ``_as_text(exc)``; a self-__str__ encode bomb riding the message
        # used to raise out of the except handler itself.
        with mock.patch.object(
            network_svc,
            "_alias_local_route",
            side_effect=RuntimeError(_EncodeBombStr("route boom")),
        ):
            payload = self.request_ok("GET", "/api/system/network/alias/auto")
        row = payload["ips"][0]
        self.assertEqual(row["ip"], "192.0.2.44")
        self.assertIn("route lookup failed", row["local_route"]["reason"])


class ValidatorSubclassBombUnitTests(unittest.TestCase):
    """The coercers themselves: unbound views, never a raise."""

    def test_valid_ip_survives_strip_and_decode_bombs(self):
        self.assertTrue(network_svc._valid_ip(_StripBombStr(" 192.0.2.44 ")))
        self.assertFalse(network_svc._valid_ip(_DecodeBombBytes(b"junk")))
        self.assertTrue(network_svc._valid_ip(_DecodeBombBytes(b"192.0.2.44")))

    def test_hex_netmask_survives_a_startswith_bomb(self):
        class _StartswithBombStr(str):
            def startswith(self, *args, **kwargs):
                raise RuntimeError("startswith bomb")

        self.assertEqual(
            network_svc._hex_netmask_to_dotted(_StartswithBombStr("0xffffff00")),
            "255.255.255.0",
        )

    def test_coerce_int_swallows_non_valueerror_int_bombs(self):
        self.assertEqual(network_svc._coerce_int(_IntBomb(), 60), 60)

    def test_as_text_survives_the_bomb_shapes(self):
        self.assertEqual(network_svc._as_text(_DecodeBombBytes(b"ok")), "ok")
        self.assertEqual(network_svc._as_text(_EncodeBombStr("ok")), "ok")
        # Lone surrogates still launder through the unbound encode.
        self.assertEqual(
            network_svc._as_text(_EncodeBombStr("a\ud800b")), "a?b"
        )


class HugeIntBodyStaysImmuneTests(_NetworkSandbox):
    """json.loads of a >4300-digit number raises ValueError, NOT
    JSONDecodeError; the body-parse guard answers 400 on the alias routes."""

    SETTINGS = {
        "ip_aliases": {"auto_bind": True, "ips": []},
        "network_failover": {"enabled": False},
    }

    def test_over_cap_int_bodies_are_400_not_500(self):
        for method, path in (
            ("POST", "/api/system/network/alias/add"),
            ("POST", "/api/system/network/alias/remove"),
            ("PUT", "/api/system/network/alias/auto"),
        ):
            self.request_ok(
                method, path,
                raw=('{"ip": ' + _HUGE_DIGITS + "}").encode(),
                want=400,
            )


if __name__ == "__main__":
    unittest.main()
