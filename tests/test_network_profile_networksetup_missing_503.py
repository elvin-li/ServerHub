"""Leftover Network-page 500: a vanished networksetup blamed the server.

The Network page's quick-switch buttons post ``/api/system/network/profile``.
``switch_profile`` starts from ``network_services()``, and an empty listing
flattens two very different failures: ``/usr/sbin/networksetup`` gone from
disk (``sh`` answers its spawn sentinel, the parser returns ``[]``) and a
readable-but-empty listing.  Both used to raise the coded *500*
``network.services_unreadable`` — a server fault toast for a missing host
tool, unlike every sibling tool-absent state (``identity.scutil_missing``,
``raid.diskutil_missing``, ``vms.utm_unavailable``), which are coded 503s.

Reproduced live against the mounted route before fixing: on a host without
networksetup (Linux CI verbatim), ``POST /api/system/network/profile`` with a
valid body answered HTTP 500.  The fix follows the house vanished-CLI rule —
the disk is probed *on the empty-listing failure path only* (a successful
listing never pays the stat), and only a confirmed-absent binary answers the
new coded 503 ``network.networksetup_missing``; a present-but-unreadable
listing keeps the ``services_unreadable`` shape, and a stat the probe cannot
perform must not upgrade the failure to a 503.
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


def _post_profile(client: TestClient):
    return client.post("/api/system/network/profile", json={"profile": "wifi"})


class VanishedNetworksetupRouteTests(unittest.TestCase):
    """POST /api/system/network/profile with the binary confirmed absent."""

    def test_confirmed_absent_networksetup_is_the_coded_503_not_a_500(self):
        # Fails on the pre-fix tree with HTTP 500 network.services_unreadable.
        with (
            mock.patch.object(network_svc, "network_services", return_value=[]),
            mock.patch.object(network_svc, "NS", "/nonexistent/networksetup"),
        ):
            resp = _post_profile(_client())
        self.assertEqual(resp.status_code, 503, resp.text[:200])
        self.assertEqual(
            resp.json()["detail"]["code"], "network.networksetup_missing"
        )

    def test_present_but_empty_listing_keeps_the_services_unreadable_shape(self):
        # networksetup on disk answering nothing is not the tool-absent case:
        # the classification must not flip to 503 without the disk confirm.
        with tempfile.NamedTemporaryFile(prefix="networksetup-") as ns:
            with (
                mock.patch.object(
                    network_svc, "network_services", return_value=[]
                ),
                mock.patch.object(network_svc, "NS", ns.name),
            ):
                resp = _post_profile(_client())
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        self.assertEqual(
            resp.json()["detail"]["code"], "network.services_unreadable"
        )

    def test_unstatable_probe_must_not_upgrade_to_503(self):
        # ``Path.is_file()`` swallows most stat failures itself, but a probe
        # that *raises* (an exotic Path subclass, a future pathlib) must keep
        # the unreadable classification, not invent a tool-absent 503.
        class _Unstatable(type(Path())):
            def is_file(self):
                raise OSError("stat refused")

        with (
            mock.patch.object(network_svc, "network_services", return_value=[]),
            mock.patch.object(network_svc, "Path", _Unstatable),
        ):
            resp = _post_profile(_client())
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        self.assertEqual(
            resp.json()["detail"]["code"], "network.services_unreadable"
        )

    def test_a_readable_listing_never_pays_the_stat(self):
        # The disk probe runs on the failure path only (the identity
        # _scutil_missing / docker cli_on_disk rule).
        svcs = [
            {"name": "Wi-Fi", "hardware_port": "Wi-Fi", "device": "en0"},
        ]
        calls = []

        class _Probe(type(Path())):
            def is_file(self):  # pragma: no cover - must never run
                calls.append(str(self))
                return super().is_file()

        with (
            mock.patch.object(network_svc, "network_services", return_value=svcs),
            mock.patch.object(network_svc, "Path", _Probe),
            mock.patch.object(
                network_svc,
                "set_service_enabled",
                return_value={"ok": True, "message": "enabled"},
            ),
            mock.patch.object(
                network_svc,
                "set_wifi_power",
                return_value={"ok": True, "on": True, "device": "en0", "message": ""},
            ),
            mock.patch.object(
                network_svc,
                "set_service_order",
                return_value={"ok": True, "order": ["Wi-Fi"], "message": "ok"},
            ),
            mock.patch.object(
                network_svc,
                "ensure_aliases_on_preferred",
                return_value={"ok": True, "message": ""},
            ),
            mock.patch.object(network_svc.time, "sleep"),
        ):
            resp = _post_profile(_client())
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertTrue(resp.json()["ok"])
        self.assertEqual(calls, [])


class LocaleContractTests(unittest.TestCase):
    """The SPA translates coded errors via ``err.<code>`` in all three locales."""

    def test_all_three_locales_name_the_new_code(self):
        web = Path(__file__).resolve().parent.parent / "web" / "src" / "i18n"
        for name in ("en.js", "ja.js", "zh-CN.js"):
            text = (web / name).read_text(encoding="utf-8")
            self.assertIn("networksetup_missing", text, name)


if __name__ == "__main__":
    unittest.main()
