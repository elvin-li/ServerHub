"""Fifth a11y leftover sweep: vanished-CLI lies on the last Network mutations.

a11y4 (test_network_vanished_cli_service_device_503) taught the per-service
mutation validators the house vanished-CLI rule — disk-confirm on the
empty-listing failure path only, coded 503 for a confirmed-absent binary —
but three sibling mutation routes kept lying through a different empty
listing:

* POST /api/system/network/wifi/{state} runs ``set_wifi_power``, whose
  ``_wifi_devices`` reads the ``networksetup -listallhardwareports``
  listing.  A vanished networksetup emptied it and the route answered
  200 ``{"ok": false, "message": "No Wi-Fi adapter found"}`` — blaming
  the adapter for a missing host tool;
* POST /api/system/network/alias/auto/run runs
  ``ensure_aliases_on_preferred``: with managed IPs configured, a vanished
  ``/sbin/ifconfig`` (empty ``interfaces()``) or vanished networksetup
  (empty service order) both left ``preferred_active_device()`` at None
  and the route answered 200 "No usable preferred network (check the
  Ethernet cable / Wi-Fi)" — blaming the cable;
* POST /api/system/network/failover/run runs ``network_failover_tick``:
  a vanished networksetup emptied ``_wired_devices`` and the route
  answered 200 ok:false with the nested "No Wi-Fi adapter found" lie; a
  vanished ifconfig with networksetup intact left every wired probe at
  "link or IPv4 not ready" — blaming the link.

Reproduced live over ``create_app()`` + ``TestClient`` before fixing (Linux
CI verbatim, networksetup not on disk): wifi/on and wifi/off answered the
200 adapter lie, alias/auto/run the 200 cable lie, failover/run the 200
nested lie.  The fix follows the a11y4 rule exactly — each disk probe runs
on its empty-listing failure path only, present-but-empty listings and
honest no-adapter states keep their existing answers, and the coded raise
never reaches the background autobind loop (its own try already wraps the
tick and the rebind).

``switch_profile``'s non-critical rebind record also swapped ``str(e)``
for ``exc_detail(e)``: the rebind can now raise the coded HTTPException,
and str() on that rendered the detail dict's Python repr into a 200 body.

The tail pins hold the surrounding hostile-body line (surrogate order
names, over-cap ints, iterbombs, torn UTF-8) at not-500 with strictly
UTF-8-decodable bodies.
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
_GONE = "/nonexistent/a11y5/tool"

#: Past CPython's default 4300-digit int<->str conversion limit.
_HUGE_DIGITS = "9" * 5000


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


_USABLE_IFACE = {
    "name": "en0",
    "up": True,
    "status": "active",
    "ipv4": [{"ip": "192.0.2.10", "netmask": "255.255.255.0", "broadcast": ""}],
    "ipv6": [],
    "mac": "aa:bb:cc:dd:ee:ff",
    "flags": ["UP"],
    "mtu": 1500,
}

_WIRED_PORT = {"port": "USB 10/100/1000 LAN", "device": "en5", "mac": ""}


def _settings(overrides):
    def read(name):
        return overrides.get(name, {})

    return mock.patch("hub.config.settings_section", side_effect=read)


class VanishedNetworksetupWifiRouteTests(unittest.TestCase):
    """POST /wifi/{state}: adapter lie becomes the coded 503."""

    def test_confirmed_absent_networksetup_is_the_coded_503(self):
        # Fails on the pre-fix tree: 200 {"ok": false, "message": "No Wi-Fi
        # adapter found"} for a missing host tool.
        client = _client()
        for state in ("on", "off"):
            with (
                mock.patch.object(network_svc, "hardware_ports", return_value=[]),
                mock.patch.object(network_svc, "NS", _GONE),
            ):
                resp = client.post(f"/api/system/network/wifi/{state}")
            self.assertEqual(resp.status_code, 503, _strict(resp)[:300])
            self.assertEqual(
                resp.json()["detail"]["code"], "network.networksetup_missing", state
            )

    def test_listed_ports_without_wifi_keep_the_honest_answer(self):
        # A readable listing that simply has no Wi-Fi port is not the tool
        # gone — even with the binary off disk, the honest answer stays.
        with (
            mock.patch.object(
                network_svc, "hardware_ports", return_value=[dict(_WIRED_PORT)]
            ),
            mock.patch.object(network_svc, "NS", _GONE),
        ):
            resp = _client().post("/api/system/network/wifi/on")
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        payload = resp.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "No Wi-Fi adapter found")

    def test_empty_listing_with_the_binary_on_disk_keeps_the_honest_answer(self):
        # Present-but-empty must not upgrade to 503 (the a11y4 rule).
        with (
            mock.patch.object(network_svc, "hardware_ports", return_value=[]),
            mock.patch.object(network_svc, "NS", _ON_DISK),
        ):
            resp = _client().post("/api/system/network/wifi/off")
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertFalse(resp.json()["ok"])


class VanishedCliAliasAutoRunTests(unittest.TestCase):
    """POST /alias/auto/run: cable lie becomes the tool-specific coded 503."""

    _IPS = {"ip_aliases": {"ips": ["192.0.2.44"], "auto_bind": True}}

    def test_vanished_ifconfig_is_the_coded_503_not_the_cable_lie(self):
        # Fails on the pre-fix tree: 200 "No usable preferred network
        # (check the Ethernet cable / Wi-Fi)".
        with (
            _settings(self._IPS),
            mock.patch.object(network_svc, "interfaces", return_value=[]),
            mock.patch.object(
                network_svc,
                "_network_service_order_entries",
                return_value=[{"order": 1, "name": "Wi-Fi", "disabled": False,
                               "port": "Wi-Fi", "device": "en0"}],
            ),
            mock.patch.object(network_svc, "IFCONFIG", _GONE),
        ):
            resp = _client().post("/api/system/network/alias/auto/run")
        self.assertEqual(resp.status_code, 503, _strict(resp)[:300])
        self.assertEqual(resp.json()["detail"]["code"], "network.ifconfig_missing")

    def test_vanished_networksetup_is_its_own_coded_503(self):
        # ifconfig fine (usable interface listed), service order emptied by
        # the vanished networksetup: the 503 must name the right tool.
        with (
            _settings(self._IPS),
            mock.patch.object(
                network_svc, "interfaces", return_value=[dict(_USABLE_IFACE)]
            ),
            mock.patch.object(
                network_svc, "_network_service_order_entries", return_value=[]
            ),
            mock.patch.object(network_svc, "IFCONFIG", _ON_DISK),
            mock.patch.object(network_svc, "NS", _GONE),
        ):
            resp = _client().post("/api/system/network/alias/auto/run")
        self.assertEqual(resp.status_code, 503, _strict(resp)[:300])
        self.assertEqual(
            resp.json()["detail"]["code"], "network.networksetup_missing"
        )

    def test_tools_on_disk_keep_the_honest_cable_answer(self):
        # Both binaries present, genuinely no usable candidate: the honest
        # 200 stays (an unplugged cable is not a vanished tool).
        with (
            _settings(self._IPS),
            mock.patch.object(network_svc, "interfaces", return_value=[]),
            mock.patch.object(
                network_svc, "_network_service_order_entries", return_value=[]
            ),
            mock.patch.object(network_svc, "IFCONFIG", _ON_DISK),
            mock.patch.object(network_svc, "NS", _ON_DISK),
        ):
            resp = _client().post("/api/system/network/alias/auto/run")
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        payload = resp.json()
        self.assertFalse(payload["ok"])
        self.assertIn("No usable preferred network", payload["message"])

    def test_no_managed_ips_keeps_the_early_honest_return(self):
        # With nothing configured the handler exits before the preferred
        # check — the tools' absence must not turn that into a 503.
        with (
            _settings({"ip_aliases": {"ips": [], "auto_bind": True}}),
            mock.patch.object(network_svc, "interfaces", return_value=[]),
            mock.patch.object(
                network_svc, "_network_service_order_entries", return_value=[]
            ),
            mock.patch.object(network_svc, "IFCONFIG", _GONE),
            mock.patch.object(network_svc, "NS", _GONE),
        ):
            resp = _client().post("/api/system/network/alias/auto/run")
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertIn("No managed IPs configured", resp.json()["message"])


class VanishedCliFailoverRunTests(unittest.TestCase):
    """POST /failover/run: the nested adapter/link lies become coded 503s."""

    _ENABLED = {"network_failover": {"enabled": True}}

    def test_vanished_networksetup_is_the_coded_503(self):
        # Fails on the pre-fix tree: 200 ok:false, mode wifi_backup, with
        # the nested "No Wi-Fi adapter found" message.
        with (
            _settings(self._ENABLED),
            mock.patch.object(network_svc, "hardware_ports", return_value=[]),
            mock.patch.object(network_svc, "interfaces", return_value=[]),
            mock.patch.object(network_svc, "NS", _GONE),
        ):
            resp = _client().post("/api/system/network/failover/run")
        self.assertEqual(resp.status_code, 503, _strict(resp)[:300])
        self.assertEqual(
            resp.json()["detail"]["code"], "network.networksetup_missing"
        )

    def test_vanished_ifconfig_behind_listed_wired_adapters_is_the_coded_503(self):
        # networksetup still names a wired adapter, but the interface table
        # is empty because ifconfig vanished — every probe read "link or
        # IPv4 not ready", blaming the link.
        with (
            _settings(self._ENABLED),
            mock.patch.object(
                network_svc, "hardware_ports", return_value=[dict(_WIRED_PORT)]
            ),
            mock.patch.object(network_svc, "interfaces", return_value=[]),
            mock.patch.object(network_svc, "NS", _ON_DISK),
            mock.patch.object(network_svc, "IFCONFIG", _GONE),
        ):
            resp = _client().post("/api/system/network/failover/run")
        self.assertEqual(resp.status_code, 503, _strict(resp)[:300])
        self.assertEqual(resp.json()["detail"]["code"], "network.ifconfig_missing")

    def test_empty_listing_with_the_binary_on_disk_keeps_the_honest_tick(self):
        # A Mac with no wired adapters and the tool present is the honest
        # ok:false tick, not a 503.
        with (
            _settings(self._ENABLED),
            mock.patch.object(network_svc, "hardware_ports", return_value=[]),
            mock.patch.object(network_svc, "interfaces", return_value=[]),
            mock.patch.object(network_svc, "NS", _ON_DISK),
            mock.patch.object(network_svc, "IFCONFIG", _ON_DISK),
        ):
            resp = _client().post("/api/system/network/failover/run")
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        payload = resp.json()
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["enabled"])

    def test_disabled_failover_stays_the_early_return_with_tools_gone(self):
        with (
            _settings({"network_failover": {"enabled": False}}),
            mock.patch.object(network_svc, "hardware_ports", return_value=[]),
            mock.patch.object(network_svc, "NS", _GONE),
        ):
            resp = _client().post("/api/system/network/failover/run")
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertEqual(resp.json()["mode"], "disabled")


class ProfileRebindMessageTests(unittest.TestCase):
    """switch_profile's non-critical rebind step renders a coded raise as
    the bare code, never the detail dict's Python repr."""

    def test_coded_rebind_raise_stays_a_bare_code_in_the_200_body(self):
        from hub.errors import api_error

        with (
            mock.patch.object(
                network_svc,
                "network_services",
                return_value=[{"name": "Wi-Fi", "hardware_port": "Wi-Fi",
                               "device": "en0", "disabled": False}],
            ),
            mock.patch.object(
                network_svc, "set_service_enabled",
                return_value={"ok": True, "message": "enabled"},
            ),
            mock.patch.object(
                network_svc, "set_wifi_power",
                return_value={"ok": True, "on": True, "device": "en0",
                              "message": "Wi-Fi on"},
            ),
            mock.patch.object(
                network_svc, "set_service_order",
                return_value={"ok": True, "order": ["Wi-Fi"], "message": "ok"},
            ),
            mock.patch.object(
                network_svc, "ensure_aliases_on_preferred",
                side_effect=api_error("network.ifconfig_missing"),
            ),
            mock.patch.object(network_svc.time, "sleep", lambda *_: None),
        ):
            resp = _client().post(
                "/api/system/network/profile", json={"profile": "wifi"}
            )
        text = _strict(resp)
        self.assertEqual(resp.status_code, 200, text[:300])
        payload = json.loads(text)
        self.assertEqual(
            payload["alias_rebind"],
            {"ok": False, "message": "network.ifconfig_missing"},
        )
        # The detail dict's Python repr must not leak anywhere in the body.
        self.assertNotIn("{'code'", text)


class HostileBodyStaysImmuneTests(unittest.TestCase):
    """The surrounding hostile-body line holds: never a raw 500, always a
    strictly UTF-8-decodable body."""

    def _post_raw(self, path, raw: bytes):
        return _client().post(
            path, content=raw, headers={"content-type": "application/json"}
        )

    def test_surrogate_order_name_is_the_coded_400_scrubbed(self):
        with mock.patch.object(
            network_svc, "network_services", return_value=[{"name": "Wi-Fi"}]
        ):
            resp = self._post_raw(
                "/api/system/network/order", b'{"services": ["\\ud800bad"]}'
            )
        text = _strict(resp)
        self.assertEqual(resp.status_code, 400, text[:300])
        self.assertEqual(
            json.loads(text)["detail"]["code"], "network.unknown_service"
        )
        self.assertNotIn("\ud800", text)

    def test_over_cap_int_bodies_are_parse_refusals_not_500(self):
        for path, raw in (
            (
                "/api/system/network/order",
                ('{"services": [' + _HUGE_DIGITS + "]}").encode(),
            ),
            (
                "/api/system/network/alias/add",
                (
                    '{"device": "en0", "ip": "1.2.3.4", "netmask": '
                    + _HUGE_DIGITS + "}"
                ).encode(),
            ),
            (
                "/api/system/network/alias/auto",
                ('{"interval": ' + _HUGE_DIGITS + "}").encode(),
            ),
        ):
            if path.endswith("auto"):
                resp = _client().put(
                    path, content=raw,
                    headers={"content-type": "application/json"},
                )
            else:
                resp = self._post_raw(path, raw)
            text = _strict(resp)
            self.assertLess(resp.status_code, 500, f"{path}: {text[:300]}")
            self.assertGreaterEqual(resp.status_code, 400, path)

    def test_iterbomb_order_body_is_a_coded_refusal(self):
        deep = "[" * 3000 + "]" * 3000
        resp = self._post_raw(
            "/api/system/network/order", ('{"services": ' + deep + "}").encode()
        )
        text = _strict(resp)
        self.assertIn(resp.status_code, (400, 422), text[:300])

    def test_torn_utf8_body_on_a_bodyless_route_is_ignored(self):
        # alias/auto/run takes no body model; torn bytes must not 500 it.
        with (
            _settings({"ip_aliases": {"ips": [], "auto_bind": True}}),
            mock.patch.object(network_svc, "interfaces", return_value=[]),
            mock.patch.object(
                network_svc, "_network_service_order_entries", return_value=[]
            ),
        ):
            resp = self._post_raw(
                "/api/system/network/alias/auto/run", b'{"x": "\xed\xa0\x80"}'
            )
        text = _strict(resp)
        self.assertEqual(resp.status_code, 200, text[:300])


if __name__ == "__main__":
    unittest.main()
