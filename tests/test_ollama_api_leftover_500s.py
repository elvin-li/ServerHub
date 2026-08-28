"""Leftover sweep of the Ollama status route."""
from __future__ import annotations

import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub.app_factory import create_app
from hub.auth import require_auth
from hub.routers import ollama_api


_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return _APP


class LeftoverWatchdogTimeout(BaseException):
    pass


class OllamaApiLeftoverTests(unittest.TestCase):
    def test_status_baseexception_is_coded_not_raw_500(self):
        def _boom(*, force=False):
            raise LeftoverWatchdogTimeout("status bomb")

        with mock.patch.object(ollama_api.ollama_svc, "status", _boom):
            client = TestClient(app(), raise_server_exceptions=False)
            response = client.get("/api/ollama/status")
        self.assertIn("ollama.status_failed", response.text)
        self.assertNotIn(" at 0x", response.text)

    def test_status_control_flow_still_propagates(self):
        def _ki(*, force=False):
            raise KeyboardInterrupt

        with mock.patch.object(ollama_api.ollama_svc, "status", _ki):
            with self.assertRaises(KeyboardInterrupt):
                ollama_api.get_status()

    def test_get_status_does_not_500(self):
        client = TestClient(app(), raise_server_exceptions=False)
        response = client.get("/api/ollama/status")
        self.assertNotEqual(response.status_code, 500, response.text[:400])
        self.assertNotIn(" at 0x", response.text)


if __name__ == "__main__":
    unittest.main()
