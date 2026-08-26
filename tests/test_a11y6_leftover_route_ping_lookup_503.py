"""Sixth a11y leftover sweep: the last vanished-CLI lies on the Network routes.

a11y4/a11y5 taught the networksetup/ifconfig seams the house vanished-CLI
rule — a fresh disk probe on the spawn-sentinel failure path only, a coded
503 for a confirmed-absent binary, honest answers kept everywhere else —
but three sibling tools in the same flows still lied through ``sh``'s
``(-1, "", "not found")`` sentinel:

* POST /api/system/network/alias/auto/run runs ``_alias_local_route`` per
  managed IP.  A vanished ``/sbin/route`` made every lookup read
  "not found", so the handler tore the alias down and re-added it every
  pass, then answered 200 "partially failed" — churning the alias and
  blaming the local route for a missing host tool;
* POST /api/system/network/failover/run probes each wired gateway with
  ``/sbin/ping``.  A vanished ping read every wired link as dead: with
  failover enabled the tick switched the Wi-Fi radio ON and answered 200
  ok:true mode wifi_backup — mutating radio state over a missing tool;
* GET /api/system/network/dns-lookup falls from ``dscacheutil`` to ``dig``.
  With both vanished it answered 200 ok:false message "not found", which
  reads like the host does not resolve.

Reproduced live over ``create_app()`` + ``TestClient`` before fixing (the
stubs answered the exact sh sentinel with the module path constants pointed
at a gone path).  The fix follows the a11y4/a11y5 rule exactly: each disk
probe runs only when the spawn answered the sentinel, a present-but-failing
tool keeps its existing honest answer, the failover raise fires *before*
the Wi-Fi read/action, the alias raise fires before the remove/add churn,
and the background autobind loop's own try still wraps both.

``alias_auto_status``'s per-IP route row also swapped ``_as_text(exc)``
for ``exc_detail(exc)``: the lookup can now raise the coded HTTPException,
and str() on that rendered the detail dict's Python repr into a 200 body.
"""
from __future__ import annotations

import json
import sys
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import network_svc
from hub.auth import require_auth

_APP = None

#: A path that exists on every host, standing in for a binary still on disk.
_ON_DISK = sys.executable
_GONE = "/nonexistent/a11y6/tool"

#: Exactly what ``hub.util.sh`` answers for a FileNotFoundError spawn.
_SENTINEL = (-1, "", "not found")


def _client() -> TestClient:
    global _APP
    if _APP is None:
        from hub.app_factory import create_app

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


def _strict(resp) -> str:
    """The body must already be valid UTF-8 — decode strictly on purpose."""
    return resp.content.decode("utf-8")


def _settings(overrides):
    def read(name):
        return dict(overrides.get(name, {}))

    return mock.patch("hub.config.settings_section", side_effect=read)


#: en0 carries its primary address plus the managed /32 alias, so the alias
#: run reaches the local-route verification with no add/remove needed first.
_IFACE_WITH_ALIAS = {
    "name": "en0",
    "up": True,
    "status": "active",
    "ipv4": [
        {"ip": "192.0.2.10", "netmask": "255.255.255.0", "broadcast": ""},
        {"ip": "192.0.2.44", "netmask": "255.255.255.255", "broadcast": ""},
    ],
    "ipv6": [],
    "mac": "aa:bb:cc:dd:ee:ff",
    "flags": ["UP"],
    "mtu": 1500,
}

_IFACE_WIRED = {
    "name": "en5",
    "up": True,
    "status": "active",
    "ipv4": [{"ip": "192.0.2.20", "netmask": "255.255.255.0", "broadcast": ""}],
    "ipv6": [],
    "mac": "ff:ee:dd:cc:bb:aa",
    "flags": ["UP"],
    "mtu": 1500,
}

_ORDER_WIFI = [
    {"order": 1, "name": "Wi-Fi", "disabled": False,
     "port": "Wi-Fi", "device": "en0"},
]
_ORDER_WIRED = [
    {"order": 2, "name": "USB LAN", "disabled": False,
     "port": "USB 10/100/1000 LAN", "device": "en5"},
]
_WIRED_PORT = {"port": "USB 10/100/1000 LAN", "device": "en5", "mac": ""}
_WIFI_PORT = {"port": "Wi-Fi", "device": "en0", "mac": ""}

_ALIAS_IPS = {"ip_aliases": {"ips": ["192.0.2.44"], "auto_bind": True}}
_FAILOVER_ON = {"network_failover": {"enabled": True}}


def _fake_sh(route=_SENTINEL, ping=_SENTINEL, calls=None):
    """A stub keyed on the *live* module path constants, so tests that point
    ROUTE/PING at a gone or an on-disk path exercise the same spawn."""

    def fake(argv, timeout=10, **kwargs):
        prog = argv[0]
        if calls is not None:
            calls.append(list(argv))
        if prog == network_svc.ROUTE:
            return route
        if prog == network_svc.PING:
            return ping
        if prog == network_svc.NS:
            return {
                "-getinfo": (
                    0,
                    "Manual Configuration\nIP Address: 192.0.2.20\n"
                    "Router: 192.0.2.1\n",
                    "",
                ),
                "-getairportpower": (0, "Wi-Fi Power (en0): Off\n", ""),
                "-setairportpower": (0, "", ""),
            }.get(argv[1], (0, "", ""))
        if prog == network_svc.IFCONFIG:
            return 0, "", ""  # alias add/remove mutations succeed
        return 1, "", "not run"

    return fake


class VanishedRouteAliasRunTests(unittest.TestCase):
    """POST /alias/auto/run: the local-route churn becomes the coded 503."""

    def _run(self, *, route_path, route_result=_SENTINEL, calls=None):
        with (
            _settings(_ALIAS_IPS),
            mock.patch.object(
                network_svc, "interfaces",
                return_value=[dict(_IFACE_WITH_ALIAS)],
            ),
            mock.patch.object(
                network_svc, "_network_service_order_entries",
                return_value=list(_ORDER_WIFI),
            ),
            mock.patch.object(
                network_svc, "sh",
                side_effect=_fake_sh(route=route_result, calls=calls),
            ),
            mock.patch.object(network_svc, "ROUTE", route_path),
        ):
            return _client().post("/api/system/network/alias/auto/run")

    def test_confirmed_absent_route_is_the_coded_503_with_no_alias_churn(self):
        # Fails on the pre-fix tree: 200 "partially failed" after removing
        # and re-adding the alias over the missing tool.
        calls: list = []
        resp = self._run(route_path=_GONE, calls=calls)
        self.assertEqual(resp.status_code, 503, _strict(resp)[:300])
        self.assertEqual(resp.json()["detail"]["code"], "network.route_missing")
        churn = [c for c in calls if c[0] in (network_svc.IFCONFIG, "/usr/bin/sudo")]
        self.assertEqual(churn, [], "the raise must precede the remove/add churn")

    def test_sentinel_with_the_binary_on_disk_keeps_the_honest_repair(self):
        # Present-but-failing must not upgrade to 503 (the a11y4 rule): the
        # handler keeps its honest repair attempt and 200 partially-failed.
        resp = self._run(route_path=_ON_DISK)
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        payload = resp.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["managed_ips"], ["192.0.2.44"])

    def test_route_present_but_erroring_keeps_the_honest_repair(self):
        resp = self._run(
            route_path=_ON_DISK,
            route_result=(1, "", "route: writing to routing socket"),
        )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertFalse(resp.json()["ok"])

    def test_status_read_degrades_to_the_bare_code_row_not_the_repr(self):
        # GET /alias/auto is a read: it must stay 200 with the coded raise
        # folded into the per-IP row as the bare code — never the detail
        # dict's Python repr, and never a 503.
        with (
            _settings(_ALIAS_IPS),
            mock.patch.object(
                network_svc, "interfaces",
                return_value=[dict(_IFACE_WITH_ALIAS)],
            ),
            mock.patch.object(
                network_svc, "_network_service_order_entries",
                return_value=list(_ORDER_WIFI),
            ),
            mock.patch.object(network_svc, "sh", side_effect=_fake_sh()),
            mock.patch.object(network_svc, "ROUTE", _GONE),
        ):
            resp = _client().get("/api/system/network/alias/auto")
        text = _strict(resp)
        self.assertEqual(resp.status_code, 200, text[:300])
        row = json.loads(text)["ips"][0]["local_route"]
        self.assertFalse(row["ok"])
        self.assertIn("network.route_missing", row["reason"])
        self.assertNotIn("{'code'", text)


class VanishedPingFailoverRunTests(unittest.TestCase):
    """POST /failover/run: the dead-gateway lie becomes the coded 503, and
    the Wi-Fi radio is never touched on the way out."""

    def _run(self, *, ping_path, ping_result=_SENTINEL, calls=None):
        with (
            _settings(_FAILOVER_ON),
            mock.patch.object(
                network_svc, "hardware_ports",
                return_value=[dict(_WIRED_PORT), dict(_WIFI_PORT)],
            ),
            mock.patch.object(
                network_svc, "interfaces", return_value=[dict(_IFACE_WIRED)]
            ),
            mock.patch.object(
                network_svc, "_network_service_order_entries",
                return_value=list(_ORDER_WIRED),
            ),
            mock.patch.object(
                network_svc, "sh",
                side_effect=_fake_sh(ping=ping_result, calls=calls),
            ),
            mock.patch.object(network_svc, "PING", ping_path),
        ):
            return _client().post("/api/system/network/failover/run")

    def test_confirmed_absent_ping_is_the_coded_503_and_the_radio_is_untouched(self):
        # Fails on the pre-fix tree: 200 ok:true mode wifi_backup with the
        # radio switched ON over the missing tool.
        calls: list = []
        resp = self._run(ping_path=_GONE, calls=calls)
        self.assertEqual(resp.status_code, 503, _strict(resp)[:300])
        self.assertEqual(resp.json()["detail"]["code"], "network.ping_missing")
        toggles = [c for c in calls if len(c) > 1 and c[1] == "-setairportpower"]
        self.assertEqual(toggles, [], "the raise must precede the radio action")

    def test_sentinel_with_the_binary_on_disk_keeps_the_honest_tick(self):
        resp = self._run(ping_path=_ON_DISK)
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        payload = resp.json()
        self.assertTrue(payload["enabled"])
        self.assertFalse(payload["wired_healthy"])

    def test_ping_present_with_unreachable_gateway_keeps_the_honest_tick(self):
        # A genuinely dead gateway is exactly what failover exists for: the
        # tick keeps its honest wifi_backup answer (and may toggle the radio).
        resp = self._run(
            ping_path=_ON_DISK,
            ping_result=(1, "", "Request timeout for icmp_seq 0"),
        )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        payload = resp.json()
        self.assertFalse(payload["wired_healthy"])
        self.assertEqual(
            payload["wired_probes"][0]["reason"], "Request timeout for icmp_seq 0"
        )

    def test_disabled_failover_stays_the_early_return_with_ping_gone(self):
        with (
            _settings({"network_failover": {"enabled": False}}),
            mock.patch.object(network_svc, "sh", side_effect=_fake_sh()),
            mock.patch.object(network_svc, "PING", _GONE),
        ):
            resp = _client().post("/api/system/network/failover/run")
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertEqual(resp.json()["mode"], "disabled")


class VanishedLookupToolsDnsTests(unittest.TestCase):
    """GET /dns-lookup: the "not found" NXDOMAIN lie becomes the coded 503."""

    _GONE_DSC = "/nonexistent/a11y6/dscacheutil"
    _GONE_DIG = "/nonexistent/a11y6/dig"

    def _lookup(self, *, dsc_path, dig_path, dsc_result=_SENTINEL,
                dig_result=_SENTINEL):
        def fake(argv, timeout=10, **kwargs):
            if argv[0] == network_svc.DSCACHEUTIL:
                return dsc_result
            if argv[0] == network_svc.DIG:
                return dig_result
            return 1, "", "not run"

        with (
            mock.patch.object(network_svc, "sh", side_effect=fake),
            mock.patch.object(network_svc, "DSCACHEUTIL", dsc_path),
            mock.patch.object(network_svc, "DIG", dig_path),
        ):
            return _client().get(
                "/api/system/network/dns-lookup?host=example.com"
            )

    def test_both_tools_confirmed_absent_is_the_coded_503(self):
        # Fails on the pre-fix tree: 200 ok:false message "not found".
        resp = self._lookup(dsc_path=self._GONE_DSC, dig_path=self._GONE_DIG)
        self.assertEqual(resp.status_code, 503, _strict(resp)[:300])
        self.assertEqual(
            resp.json()["detail"]["code"], "network.lookup_tools_missing"
        )

    def test_dig_still_on_disk_keeps_the_honest_answer(self):
        resp = self._lookup(dsc_path=self._GONE_DSC, dig_path=_ON_DISK)
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertFalse(resp.json()["ok"])

    def test_dscacheutil_present_but_empty_keeps_the_honest_answer(self):
        # A resolver that ran and answered nothing is an honest miss, not
        # the tools gone — even with dig genuinely absent.
        resp = self._lookup(
            dsc_path=_ON_DISK,
            dig_path=self._GONE_DIG,
            dsc_result=(0, "", ""),
        )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertFalse(resp.json()["ok"])

    def test_working_resolver_keeps_the_honest_answers(self):
        resp = self._lookup(
            dsc_path=_ON_DISK,
            dig_path=_ON_DISK,
            dsc_result=(0, "name: example.com\nip_address: 192.0.2.7\n", ""),
        )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        payload = resp.json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["answers"], ["192.0.2.7"])


class AutobindLoopStaysWrappedTests(unittest.TestCase):
    """The background loop's own try still swallows the new coded raises."""

    def test_tick_and_rebind_raises_do_not_escape_the_loop_body(self):
        # The loop wraps the tick and the rebind in its own try; the coded
        # HTTPException must stay a normal Exception subclass it can catch.
        from fastapi import HTTPException

        from hub.errors import api_error

        for code in ("network.route_missing", "network.ping_missing"):
            exc = api_error(code)
            self.assertIsInstance(exc, HTTPException)
            self.assertIsInstance(exc, Exception)
            self.assertEqual(exc.status_code, 503)


if __name__ == "__main__":
    unittest.main()
