"""Login rate-limit buckets behind a local reverse proxy.

``login_allowed`` buckets by client address.  Published through cloudflared or
nginx, every visitor used to arrive as 127.0.0.1 and share one global bucket —
one flaky client's five failures locked the whole family out for five minutes.

The fix (auth.request_client) trusts the *last* hop of ``X-Forwarded-For``
only when the direct peer is loopback, i.e. the trusted local proxy itself.
A remote direct peer keeps its socket address whatever headers it sends, so
the forwarded header cannot be used to mint fresh buckets and bypass the
limiter; and it is a reporting/bucketing identity only — the loopback checks
guarding setup-token disclosure and the menu-bar token still read the socket.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi import Request
from fastapi.testclient import TestClient

from hub import api_keys, audit, auth, config, twofa_svc
from hub.app_factory import create_app

ADMIN_PASSWORD = "correct-horse-battery"

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
    return _APP


def request(*, client: str | None = "203.0.113.9", xff: str | None = None) -> Request:
    headers = []
    if xff is not None:
        headers.append((b"x-forwarded-for", xff.encode()))
    return Request({
        "type": "http",
        "method": "POST",
        "path": "/api/auth/login",
        "headers": headers,
        "scheme": "http",
        "server": ("localhost", 8086),
        "client": (client, 12345) if client else None,
    })


class RequestClientTests(unittest.TestCase):
    def test_a_remote_peer_is_its_own_bucket(self):
        self.assertEqual(auth.request_client(request(client="203.0.113.9")), "203.0.113.9")

    def test_a_remote_peer_cannot_spoof_via_forwarded_headers(self):
        # Attacker-controlled text: honouring it would hand out a fresh bucket
        # per request and neuter the limiter entirely.
        req = request(client="203.0.113.9", xff="10.0.0.1, 10.0.0.2")
        self.assertEqual(auth.request_client(req), "203.0.113.9")

    def test_a_loopback_peer_uses_the_proxys_last_hop(self):
        for loop in ("127.0.0.1", "::1"):
            with self.subTest(loop=loop):
                req = request(client=loop, xff="198.51.100.7")
                self.assertEqual(auth.request_client(req), "198.51.100.7")

    def test_only_the_last_hop_is_believed(self):
        # Earlier elements are whatever the visitor sent to the proxy; the
        # last one is what the trusted local proxy appended itself.
        req = request(client="127.0.0.1", xff="6.6.6.6, 198.51.100.7")
        self.assertEqual(auth.request_client(req), "198.51.100.7")

    def test_loopback_without_forwarding_stays_loopback(self):
        self.assertEqual(auth.request_client(request(client="127.0.0.1")), "127.0.0.1")
        self.assertEqual(
            auth.request_client(request(client="127.0.0.1", xff="  ")), "127.0.0.1"
        )

    def test_missing_client_is_unknown(self):
        self.assertEqual(auth.request_client(request(client=None)), "unknown")

    def test_forwarded_value_is_length_bounded(self):
        req = request(client="127.0.0.1", xff="x" * 500)
        self.assertEqual(len(auth.request_client(req)), 64)

    def test_buckets_are_independent_per_forwarded_client(self):
        auth._login_attempts.clear()
        self.addCleanup(auth._login_attempts.clear)
        flaky = auth.request_client(request(client="127.0.0.1", xff="198.51.100.7"))
        healthy = auth.request_client(request(client="127.0.0.1", xff="198.51.100.8"))
        for _ in range(5):
            auth.record_login_failure(flaky)
        self.assertFalse(auth.login_allowed(flaky)[0])
        self.assertTrue(auth.login_allowed(healthy)[0])


class _PanelSandbox(unittest.TestCase):
    """Scratch config/data so the full login route can run."""

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        data = root / "data"
        data.mkdir()
        self.audit_path = data / "auth-audit.jsonl"
        for target, attr, value in (
            (config, "YAML_PATH", root / "services.yaml"),
            (config, "DATA_DIR", data),
            (config, "BASE", root),
            (config, "_LOCK_PATH", data / ".services.yaml.lock"),
            (auth, "SECRET_FILE", data / ".session-secret"),
            (auth, "SETUP_TOKEN_FILE", data / ".setup-token"),
            (auth, "LOCAL_TOKEN_FILE", data / ".local-client-token"),
            (twofa_svc, "STORE_FILE", data / "twofa.json"),
            (api_keys, "STORE_FILE", data / "api-keys.json"),
            (audit, "AUDIT_PATH", self.audit_path),
        ):
            patcher = mock.patch.object(target, attr, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(config.reload_cfg)
        config.reload_cfg()
        auth._login_attempts.clear()
        self.addCleanup(auth._login_attempts.clear)
        auth.set_password(ADMIN_PASSWORD, "admin")
        self.client = TestClient(app())

    def bad_login(self, xff: str | None = None):
        headers = {"x-forwarded-for": xff} if xff else {}
        return self.client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "wrong-password"},
            headers=headers,
        )

    def code(self, response) -> str:
        return response.json()["detail"]["code"]


class DirectPeerSpoofTests(_PanelSandbox):
    def test_rotating_forwarded_headers_do_not_mint_fresh_buckets(self):
        # TestClient's peer is "testclient" — not loopback — so the forwarded
        # header must be ignored and all failures land in one bucket.
        for i in range(5):
            response = self.bad_login(xff=f"198.51.100.{i}")
            self.assertEqual(self.code(response), "auth.bad_credentials")
        response = self.bad_login(xff="198.51.100.250")
        self.assertEqual(response.status_code, 429)
        self.assertEqual(self.code(response), "auth.rate_limited")


class LoopbackProxyTests(_PanelSandbox):
    def setUp(self):
        super().setUp()
        # Make the test transport's peer count as loopback, standing in for
        # the local cloudflared/nginx hop in front of the panel.
        patcher = mock.patch.object(
            auth, "LOOPBACK_HOSTS", ("127.0.0.1", "::1", "testclient")
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        # Login rate-limits now key on request_client_id (trusted-proxy CIDRs),
        # not LOOPBACK_HOSTS. Treat the TestClient peer as the local proxy hop.
        proxy = mock.patch.object(auth, "_peer_in_trusted_proxy", return_value=True)
        proxy.start()
        self.addCleanup(proxy.stop)

    def test_forwarded_clients_get_independent_buckets(self):
        for _ in range(5):
            response = self.bad_login(xff="198.51.100.7")
            self.assertEqual(self.code(response), "auth.bad_credentials")
        # The flaky client is now blocked...
        blocked = self.bad_login(xff="198.51.100.7")
        self.assertEqual(blocked.status_code, 429)
        # ...while the rest of the family keeps its own budget.
        other = self.bad_login(xff="198.51.100.8")
        self.assertEqual(self.code(other), "auth.bad_credentials")

    def test_audit_lines_name_the_forwarded_client(self):
        self.bad_login(xff="198.51.100.7")
        records = [
            json.loads(line)
            for line in self.audit_path.read_text().splitlines()
            if line.strip()
        ]
        failures = [r for r in records if r.get("event") == audit.LOGIN_FAILED]
        self.assertTrue(failures)
        self.assertEqual(failures[-1]["client"], "198.51.100.7")


if __name__ == "__main__":
    unittest.main()
