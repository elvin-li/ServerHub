"""Leftover Network-page vanished-CLI misclassifications on the sibling routes.

test_network_profile_networksetup_missing_503 pinned the profile route: an
empty ``network_services()`` with ``/usr/sbin/networksetup`` confirmed absent
answers the coded 503 ``network.networksetup_missing``.  The same vanished
binary reached every *sibling* mutation route through a different validator
and kept blaming the caller:

* POST /api/system/network/services/{s}/dhcp | manual | dns | enabled run
  ``_validate_service``, whose fallback ``networksetup
  -listallnetworkservices`` answers the spawn sentinel, so the routes
  answered the 404 ``network.service_not_found`` — "network service not
  found: Wi-Fi" for a missing host tool;
* POST /api/system/network/order validates against the same empty listing
  and answered the 400 ``network.unknown_service`` for the first name;
* POST /api/system/network/alias/add | remove run ``_validate_device``, and
  a vanished ``/sbin/ifconfig`` empties ``interfaces()`` the same way, so
  both answered the 404 ``network.device_not_found`` — "no such interface:
  en0".

Reproduced live against the mounted routes before fixing (Linux CI verbatim,
neither binary on disk): all six answered 404/400 blaming the request.  The
fix follows the house vanished-CLI rule — the disk is probed *on the
empty-listing failure path only* (a listing that names services, or a typo
against a readable listing, never pays the stat), and only a confirmed-absent
binary answers the coded 503; present-but-empty keeps the honest 404/400,
and a stat the probe cannot perform must not upgrade the failure.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import network_svc
from hub.auth import require_auth

_APP = None


def _client() -> TestClient:
    global _APP
    if _APP is None:
        from hub.app_factory import create_app

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


#: Every per-service mutation the Network page posts through _validate_service.
_SERVICE_ROUTES = (
    ("/api/system/network/services/Wi-Fi/dhcp", {}),
    (
        "/api/system/network/services/Wi-Fi/manual",
        {"ip": "192.0.2.5", "subnet": "255.255.255.0", "router": "192.0.2.1"},
    ),
    ("/api/system/network/services/Wi-Fi/dns", {"servers": ["1.1.1.1"]}),
    ("/api/system/network/services/Wi-Fi/enabled", {"enabled": True}),
)


class VanishedNetworksetupServiceRoutesTests(unittest.TestCase):
    """dhcp/manual/dns/enabled/order with the binary confirmed absent."""

    def test_confirmed_absent_networksetup_is_the_coded_503_not_a_404(self):
        # Fails on the pre-fix tree with 404 network.service_not_found.
        client = _client()
        for path, body in _SERVICE_ROUTES:
            with (
                mock.patch.object(network_svc, "network_services", return_value=[]),
                mock.patch.object(network_svc, "NS", "/nonexistent/networksetup"),
            ):
                resp = client.post(path, json=body)
            self.assertEqual(resp.status_code, 503, f"{path}: {resp.text[:200]}")
            self.assertEqual(
                resp.json()["detail"]["code"],
                "network.networksetup_missing",
                path,
            )

    def test_order_route_answers_the_coded_503_not_unknown_service(self):
        # Fails on the pre-fix tree with 400 network.unknown_service.
        with (
            mock.patch.object(network_svc, "network_services", return_value=[]),
            mock.patch.object(network_svc, "NS", "/nonexistent/networksetup"),
        ):
            resp = _client().post(
                "/api/system/network/order", json={"services": ["Wi-Fi"]}
            )
        self.assertEqual(resp.status_code, 503, resp.text[:200])
        self.assertEqual(
            resp.json()["detail"]["code"], "network.networksetup_missing"
        )

    def test_present_but_empty_listing_keeps_the_honest_404_and_400(self):
        # networksetup on disk answering nothing is not the tool-absent case.
        with tempfile.NamedTemporaryFile(prefix="networksetup-") as ns:
            with (
                mock.patch.object(network_svc, "network_services", return_value=[]),
                mock.patch.object(network_svc, "NS", ns.name),
            ):
                resp = _client().post(
                    "/api/system/network/services/Wi-Fi/dhcp", json={}
                )
                order = _client().post(
                    "/api/system/network/order", json={"services": ["Wi-Fi"]}
                )
        self.assertEqual(resp.status_code, 404, resp.text[:200])
        self.assertEqual(
            resp.json()["detail"]["code"], "network.service_not_found"
        )
        self.assertEqual(order.status_code, 400, order.text[:200])
        self.assertEqual(
            order.json()["detail"]["code"], "network.unknown_service"
        )

    def test_a_typo_against_a_readable_listing_never_pays_the_stat(self):
        # The fallback listing names other services: the honest 404, and the
        # disk probe must not run (the failure-path-only rule).
        calls = []

        class _Probe(type(Path())):
            def is_file(self):  # pragma: no cover - must never run
                calls.append(str(self))
                return super().is_file()

        with (
            mock.patch.object(network_svc, "network_services", return_value=[]),
            mock.patch.object(
                network_svc,
                "_sh",
                return_value=(0, "An asterisk (*)…\nWi-Fi\nEthernet\n", ""),
            ),
            mock.patch.object(network_svc, "Path", _Probe),
        ):
            resp = _client().post(
                "/api/system/network/services/Nope/dhcp", json={}
            )
        self.assertEqual(resp.status_code, 404, resp.text[:200])
        self.assertEqual(
            resp.json()["detail"]["code"], "network.service_not_found"
        )
        self.assertEqual(calls, [])

    def test_unstatable_probe_must_not_upgrade_to_503(self):
        class _Unstatable(type(Path())):
            def is_file(self):
                raise OSError("stat refused")

        with (
            mock.patch.object(network_svc, "network_services", return_value=[]),
            mock.patch.object(network_svc, "NS", "/nonexistent/networksetup"),
            mock.patch.object(network_svc, "Path", _Unstatable),
        ):
            resp = _client().post(
                "/api/system/network/services/Wi-Fi/dhcp", json={}
            )
        self.assertEqual(resp.status_code, 404, resp.text[:200])
        self.assertEqual(
            resp.json()["detail"]["code"], "network.service_not_found"
        )


class VanishedIfconfigAliasRoutesTests(unittest.TestCase):
    """alias/add and alias/remove with /sbin/ifconfig confirmed absent."""

    def test_confirmed_absent_ifconfig_is_the_coded_503_not_a_404(self):
        # Fails on the pre-fix tree with 404 network.device_not_found.
        client = _client()
        for path in (
            "/api/system/network/alias/add",
            "/api/system/network/alias/remove",
        ):
            with (
                mock.patch.object(network_svc, "interfaces", return_value=[]),
                mock.patch.object(network_svc, "IFCONFIG", "/nonexistent/ifconfig"),
            ):
                resp = client.post(
                    path, json={"device": "en0", "ip": "192.0.2.99"}
                )
            self.assertEqual(resp.status_code, 503, f"{path}: {resp.text[:200]}")
            self.assertEqual(
                resp.json()["detail"]["code"], "network.ifconfig_missing", path
            )

    def test_present_but_empty_interface_listing_keeps_the_honest_404(self):
        with tempfile.NamedTemporaryFile(prefix="ifconfig-") as fake:
            with (
                mock.patch.object(network_svc, "interfaces", return_value=[]),
                mock.patch.object(network_svc, "IFCONFIG", fake.name),
            ):
                resp = _client().post(
                    "/api/system/network/alias/add",
                    json={"device": "en0", "ip": "192.0.2.99"},
                )
        self.assertEqual(resp.status_code, 404, resp.text[:200])
        self.assertEqual(
            resp.json()["detail"]["code"], "network.device_not_found"
        )

    def test_a_typo_against_a_readable_listing_never_pays_the_stat(self):
        calls = []

        class _Probe(type(Path())):
            def is_file(self):  # pragma: no cover - must never run
                calls.append(str(self))
                return super().is_file()

        with (
            mock.patch.object(
                network_svc, "interfaces", return_value=[{"name": "en0"}]
            ),
            mock.patch.object(network_svc, "Path", _Probe),
        ):
            resp = _client().post(
                "/api/system/network/alias/add",
                json={"device": "en99", "ip": "192.0.2.99"},
            )
        self.assertEqual(resp.status_code, 404, resp.text[:200])
        self.assertEqual(
            resp.json()["detail"]["code"], "network.device_not_found"
        )
        self.assertEqual(calls, [])

    def test_unstatable_probe_must_not_upgrade_to_503(self):
        class _Unstatable(type(Path())):
            def is_file(self):
                raise OSError("stat refused")

        with (
            mock.patch.object(network_svc, "interfaces", return_value=[]),
            mock.patch.object(network_svc, "IFCONFIG", "/nonexistent/ifconfig"),
            mock.patch.object(network_svc, "Path", _Unstatable),
        ):
            resp = _client().post(
                "/api/system/network/alias/remove",
                json={"device": "en0", "ip": "192.0.2.99"},
            )
        self.assertEqual(resp.status_code, 404, resp.text[:200])
        self.assertEqual(
            resp.json()["detail"]["code"], "network.device_not_found"
        )


class LocaleContractTests(unittest.TestCase):
    """The SPA translates coded errors via ``err.<code>`` in all locales."""

    def test_all_three_locales_name_the_new_code(self):
        web = Path(__file__).resolve().parent.parent / "web" / "src" / "i18n"
        for name in ("en.js", "ja.js", "zh-CN.js"):
            text = (web / name).read_text(encoding="utf-8")
            self.assertIn("ifconfig_missing", text, name)


if __name__ == "__main__":
    unittest.main()
