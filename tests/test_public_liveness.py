from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from hub.app_factory import create_app


class PublicLivenessTests(unittest.TestCase):
    def test_liveness_is_unauthenticated(self):
        """Watchdog / install.sh probe this without a session."""
        client = TestClient(create_app())
        r = client.get("/api/health")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertIs(body.get("ok"), True)
        self.assertIsInstance(body.get("ts"), int)
