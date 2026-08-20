from __future__ import annotations

import json
import unittest
from unittest import mock

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

    def test_liveness_infinite_clock_does_not_500(self):
        """int(time.time()) OverflowError on leftover inf used to 500 the watchdog probe."""
        from hub.app_factory import _health_ts

        with mock.patch("hub.app_factory.time.time", return_value=float("inf")):
            ts = _health_ts()
        self.assertEqual(ts, 0)
        json.dumps({"ok": True, "ts": ts}, allow_nan=False)
