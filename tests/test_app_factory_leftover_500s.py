"""Leftover sweep of app_factory startup nets."""
from __future__ import annotations

import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import app_factory
from hub.app_factory import create_app
from hub.auth import require_auth

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return _APP


class LeftoverWatchdogTimeout(BaseException):
    pass


class AppFactoryLeftoverTests(unittest.TestCase):
    def test_warm_hotpath_swallows_a_baseexception_brew_bomb(self):
        def _boom():
            raise LeftoverWatchdogTimeout("brew bomb")

        with mock.patch.dict("sys.modules", {}):
            with mock.patch(
                "hub.brew_cache.brew_services", _boom, create=True
            ):
                app_factory._warm_hotpath()

    def test_warm_hotpath_control_flow_still_propagates(self):
        def _ki():
            raise KeyboardInterrupt

        with mock.patch("hub.brew_cache.brew_services", _ki):
            with self.assertRaises(KeyboardInterrupt):
                app_factory._warm_hotpath()

    def test_get_health_does_not_500(self):
        client = TestClient(app(), raise_server_exceptions=False)
        response = client.get("/api/health")
        self.assertNotEqual(response.status_code, 500, response.text[:400])
        self.assertNotIn(" at 0x", response.text)


if __name__ == "__main__":
    unittest.main()
