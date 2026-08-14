"""Pins the commercial-grade hardening that is easy to regress.

These are the properties a paying operator actually hits: first-run claim
through a tunnel, a cheap liveness probe, request correlation, and compose
secrets that must never be born world-readable.
"""
from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException, Request, Response
from fastapi.testclient import TestClient

from hub import __version__, auth
from hub.app_factory import create_app
from hub.routers import auth_api
from hub.routers.api import api_health


def request(
    *,
    client="127.0.0.1",
    method="GET",
    path="/api/auth/status",
    scheme="http",
    headers: list[tuple[bytes, bytes]] | None = None,
) -> Request:
    return Request({
        "type": "http",
        "method": method,
        "path": path,
        "headers": headers or [],
        "scheme": scheme,
        "server": ("localhost", 8086),
        "client": (client, 12345),
    })


class SetupTokenDisclosureTests(unittest.TestCase):
    def test_a_proxied_loopback_client_cannot_read_the_token(self):
        with (
            patch.object(auth, "setup_required", return_value=True),
            patch.object(auth, "setup_token", return_value="T" * 43),
        ):
            req = request(
                path="/api/auth/setup-token",
                headers=[
                    (b"host", b"localhost:8086"),
                    (b"x-forwarded-for", b"203.0.113.9"),
                ],
            )
            with self.assertRaises(HTTPException) as caught:
                auth_api.auth_setup_token(req, Response())
            self.assertEqual(caught.exception.status_code, 403)
            self.assertEqual(
                caught.exception.detail["code"], "auth.setup_token_localhost_only"
            )

    def test_a_direct_localhost_browser_can_read_the_token(self):
        with (
            patch.object(auth, "setup_required", return_value=True),
            patch.object(auth, "setup_token", return_value="T" * 43),
        ):
            req = request(
                path="/api/auth/setup-token",
                headers=[(b"host", b"localhost:8086")],
            )
            body = auth_api.auth_setup_token(req, Response())
            self.assertEqual(body["setup_token"], "T" * 43)


class HealthLivenessTests(unittest.TestCase):
    def test_health_does_not_run_discovery(self):
        req = request(path="/api/health")
        with (
            patch("hub.routers.api.cached_status", return_value=None) as cached,
            patch("hub.routers.api.full_status") as full,
        ):
            body = api_health(req)
        full.assert_not_called()
        cached.assert_called_once()
        self.assertTrue(body["ok"])
        self.assertEqual(body["version"], __version__)
        self.assertNotIn("counts", body)

    def test_health_includes_cached_counts_without_rebuilding(self):
        req = request(path="/api/health")
        snapshot = {"counts": {"ok": 3}, "engine_up": True, "ts": 1}
        with (
            patch("hub.routers.api.cached_status", return_value=snapshot),
            patch("hub.routers.api.full_status") as full,
            patch("hub.routers.api.auth.request_username", return_value=""),
        ):
            body = api_health(req)
        full.assert_not_called()
        self.assertEqual(body["counts"], {"ok": 3})
        self.assertTrue(body["engine_up"])


class RequestIdTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(create_app())

    def test_every_response_carries_a_request_id(self):
        resp = self.client.get("/api/auth/status")
        rid = resp.headers.get("x-request-id")
        self.assertTrue(rid)
        self.assertLessEqual(len(rid), 128)

    def test_a_well_formed_incoming_id_is_echoed(self):
        resp = self.client.get(
            "/api/auth/status", headers={"X-Request-ID": "op-trace-42"}
        )
        self.assertEqual(resp.headers.get("x-request-id"), "op-trace-42")

    def test_a_hostile_incoming_id_is_replaced(self):
        hostile = "not a valid id\nX-Injected: 1"
        resp = self.client.get("/api/auth/status", headers={"X-Request-ID": hostile})
        self.assertNotEqual(resp.headers.get("x-request-id"), hostile)


class ProxyClientIdentityTests(unittest.TestCase):
    def test_a_trusted_proxy_uses_the_forwarded_client(self):
        req = request(
            client="127.0.0.1",
            headers=[(b"x-forwarded-for", b"203.0.113.9, 127.0.0.1")],
        )
        self.assertEqual(auth.request_client_id(req), "203.0.113.9")

    def test_cf_connecting_ip_is_preferred(self):
        req = request(
            client="127.0.0.1",
            headers=[
                (b"cf-connecting-ip", b"198.51.100.4"),
                (b"x-forwarded-for", b"203.0.113.9"),
            ],
        )
        self.assertEqual(auth.request_client_id(req), "198.51.100.4")

    def test_a_non_proxy_peer_cannot_spoof_forwarded_headers(self):
        req = request(
            client="192.168.1.50",
            headers=[(b"x-forwarded-for", b"203.0.113.9")],
        )
        self.assertEqual(auth.request_client_id(req), "192.168.1.50")

    def test_login_rate_limit_keys_on_the_forwarded_client(self):
        req = request(
            client="127.0.0.1",
            path="/api/auth/login",
            method="POST",
            headers=[(b"x-forwarded-for", b"203.0.113.77")],
        )
        with (
            patch.object(auth, "setup_required", return_value=False),
            patch.object(auth, "login_allowed", return_value=(False, 42)) as allowed,
            patch.object(auth_api.audit, "record"),
        ):
            with self.assertRaises(HTTPException) as raised:
                auth_api.auth_login(
                    auth_api.LoginBody(username="admin", password="x"),
                    req,
                    Response(),
                )
        self.assertEqual(raised.exception.status_code, 429)
        allowed.assert_called_once_with("203.0.113.77")


class ReadyProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(create_app())

    def test_ready_is_unauthenticated_and_tiny(self):
        resp = self.client.get("/ready")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["version"], __version__)
        self.assertNotIn("counts", body)
        self.assertNotIn("engine_up", body)


class CatalogSecretWriteTests(unittest.TestCase):
    def test_install_writes_compose_through_secure_io(self):
        src = (Path(__file__).resolve().parent.parent / "hub" / "catalog.py").read_text()
        self.assertIn("secure_io.write_secret_text(dest, rendered)", src)
        self.assertNotIn("dest.write_text(rendered)", src)
        self.assertNotIn("vars_file.write_text", src)


class FilesRootFilterTests(unittest.TestCase):
    def test_custom_roots_drop_paths_that_are_not_directories(self):
        from hub import files_svc

        missing = "/tmp/serverhub-no-such-root-dir"
        with patch.object(
            files_svc, "_settings", return_value={"roots": [missing]}
        ):
            self.assertEqual(files_svc.default_roots(), [])


if __name__ == "__main__":
    unittest.main()
