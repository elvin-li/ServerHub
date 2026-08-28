"""Leftover sweep of health _as_text, actions, and launcher launderers."""
from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from hub import actions, health_svc, launcher_svc
from hub.app_factory import create_app
from hub.auth import require_auth

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return _APP


class _LyingBytesStr(str):
    @property
    def __class__(self):  # noqa: A003
        return bytes


class HealthActionsLauncherLeftoverTests(unittest.TestCase):
    def test_text_does_not_leak_a_heap_address(self):
        self.assertEqual(health_svc._as_text(object()), "")
        self.assertEqual(actions._as_text(object()), "")
        self.assertEqual(launcher_svc._as_text(object()), "")

    def test_text_recovers_str_storage_lying_bytes(self):
        self.assertEqual(health_svc._as_text(_LyingBytesStr("ok")), "ok")
        self.assertEqual(actions._as_text(_LyingBytesStr("ok")), "ok")
        self.assertEqual(launcher_svc._as_text(_LyingBytesStr("ok")), "ok")

    def test_get_health_checks_does_not_500(self):
        client = TestClient(app(), raise_server_exceptions=False)
        response = client.get("/api/health/checks")
        self.assertNotEqual(response.status_code, 500, response.text[:400])
        self.assertNotIn(" at 0x", response.text)

    def test_control_flow_still_propagates_from_text(self):
        class _Ki:
            def __str__(self):
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            health_svc._as_text(_Ki())
        with self.assertRaises(KeyboardInterrupt):
            actions._as_text(_Ki())
        with self.assertRaises(KeyboardInterrupt):
            launcher_svc._as_text(_Ki())


if __name__ == "__main__":
    unittest.main()
