"""Responses carrying key material must be marked uncacheable, over real HTTP.

Four WireGuard endpoints return a private key: a peer's config in three formats,
the bulk export, and the server config with the key revealed.  Authorization keeps
the wrong people out; ``Cache-Control: no-store`` keeps the key from coming to rest
in the browser's disk cache or an intermediary long after that session is gone.
The two are independent, and the second only matters if it actually reaches the
client.

That is why this goes through the app rather than calling the handlers.  Three of
these set the header by mutating an *injected* ``Response`` object, which is a
framework behaviour: whether the mutation survives into the real response is not
observable from the handler, and a version bump that changed it would break the
protection with every test still passing.  The fourth returns its own
``PlainTextResponse`` and takes an entirely different code path to the same
guarantee, so it has to be checked separately rather than assumed.

Authorization is stubbed here on purpose; it has its own tests, which
deliberately avoid TestClient so a missing check cannot run the handler.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

PEER_KEY = "P" * 43 + "="
PEER_CONF = (
    "[Interface]\n"
    f"PrivateKey = {PEER_KEY}\n"
    "Address = 10.10.0.2/32\n"
    "[Peer]\n"
    f"PublicKey = {'S' * 43}=\n"
    "AllowedIPs = 10.10.0.0/24\n"
    "Endpoint = vpn.example:51820\n"
)


class SecretHeaderTests(unittest.TestCase):
    """Every endpoint that can emit a private key says no-store."""

    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient

        from hub.app_factory import create_app
        from hub.auth import require_auth
        from hub.routers import wireguard_api

        # The session check is a router *dependency*, bound when the app is built,
        # so patching the module attribute afterwards has no effect -- FastAPI's
        # own override hook is the only thing that reaches it.
        cls.app = create_app()
        cls.app.dependency_overrides[require_auth] = lambda: True
        cls._patches = [
            patch.object(wireguard_api, "require_admin_browser", lambda request: "admin"),
            patch.object(
                wireguard_api.wireguard_svc, "installation",
                return_value={"installed": True},
            ),
        ]
        for item in cls._patches:
            item.start()
        cls.client = TestClient(cls.app)

    @classmethod
    def tearDownClass(cls):
        for item in cls._patches:
            item.stop()
        cls.app.dependency_overrides.clear()

    def _assert_no_store(self, response, where: str):
        self.assertEqual(response.status_code, 200, f"{where}: {response.text[:200]}")
        cache = response.headers.get("cache-control", "")
        self.assertIn(
            "no-store", cache.lower(),
            f"{where} can return a private key with Cache-Control={cache!r}",
        )

    def test_peer_config_is_no_store(self):
        from hub.routers import wireguard_api

        payload = {
            "ok": True, "name": "phone", "format": "wg",
            "filename": "phone.conf", "content": PEER_CONF,
        }
        with patch.object(wireguard_api.wireguard_svc, "peer_conf", return_value=payload):
            response = self.client.get(
                "/api/wireguard/peers/config", params={"pubkey": "K" * 43 + "="}
            )
        self._assert_no_store(response, "GET /peers/config")
        self.assertIn(PEER_KEY, response.text, "the test would pass on an empty body")

    def test_peer_download_is_no_store(self):
        """A different code path to the same guarantee: its own response object."""
        from hub.routers import wireguard_api

        payload = {
            "ok": True, "name": "phone", "format": "wg",
            "filename": "phone.conf", "content": PEER_CONF,
        }
        with patch.object(wireguard_api.wireguard_svc, "peer_conf", return_value=payload):
            response = self.client.get(
                "/api/wireguard/peers/download", params={"pubkey": "K" * 43 + "="}
            )
        self._assert_no_store(response, "GET /peers/download")
        self.assertIn(PEER_KEY, response.text)
        self.assertIn("attachment", response.headers.get("content-disposition", ""))

    def test_bulk_export_is_no_store(self):
        from hub.routers import wireguard_api

        with patch.object(
            wireguard_api.wireguard_svc, "export_all",
            return_value={"ok": True, "format": "wg", "items": [], "skipped": []},
        ):
            response = self.client.get("/api/wireguard/export")
        self._assert_no_store(response, "GET /export")

    def test_revealed_server_config_is_no_store(self):
        from hub.routers import wireguard_api

        with patch.object(
            wireguard_api.wireguard_svc, "view_conf",
            return_value={"ok": True, "conf": PEER_CONF, "redacted": False},
        ):
            response = self.client.get("/api/wireguard/conf", params={"reveal": "true"})
        self._assert_no_store(response, "GET /conf?reveal=true")
        self.assertIn(PEER_KEY, response.text)

    def test_the_redacted_config_is_also_no_store(self):
        """It is the same endpoint; the header must not depend on the query."""
        from hub.routers import wireguard_api

        with patch.object(
            wireguard_api.wireguard_svc, "view_conf",
            return_value={"ok": True, "conf": "[Interface]\n", "redacted": True},
        ):
            response = self.client.get("/api/wireguard/conf")
        self._assert_no_store(response, "GET /conf")


class ReadinessShapeTests(unittest.TestCase):
    """What the page receives has to be free of duplicates and internal markers."""

    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient

        from hub.app_factory import create_app
        from hub.auth import require_auth

        cls.app = create_app()
        cls.app.dependency_overrides[require_auth] = lambda: True
        cls.client = TestClient(cls.app)

    @classmethod
    def tearDownClass(cls):
        cls.app.dependency_overrides.clear()

    def test_readiness_serialises_without_duplicates_or_internals(self):
        response = self.client.get("/api/wireguard/readiness")
        self.assertEqual(response.status_code, 200, response.text[:200])
        checks = response.json()["checks"]
        ids = [c["id"] for c in checks]
        self.assertEqual(len(ids), len(set(ids)), f"duplicate rows on the page: {ids}")
        for check in checks:
            self.assertNotIn(
                "superseded_by", check,
                "an internal suppression marker reached the API",
            )
            self.assertEqual(
                set(check) - {"id", "ok", "level", "detail"}, set(),
                f"unexpected field in a check: {check}",
            )

    def test_status_never_carries_a_private_key(self):
        """The status endpoint is the one read a non-admin session could reach."""
        import re

        response = self.client.get("/api/wireguard")
        self.assertEqual(response.status_code, 200, response.text[:200])
        body = response.json()
        keyish = set(re.findall(r"[A-Za-z0-9+/]{42}[A-Za-z0-9+/=]=", response.text))
        public = {body.get("public_key") or ""} | {
            p["pubkey"] for p in body.get("peers") or []
        }
        self.assertEqual(
            keyish - public, set(),
            "a key that is not a known public key appeared in the status payload",
        )


if __name__ == "__main__":
    unittest.main()
