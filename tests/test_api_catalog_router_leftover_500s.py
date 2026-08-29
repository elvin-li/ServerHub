"""Leftover sweep of routers.api and catalog router text launderers."""
from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from hub.app_factory import create_app
from hub.auth import require_auth
from hub.routers import api, catalog

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return _APP


class LeftoverWatchdogTimeout(BaseException):
    pass


class _ClassBaseBomb:
    @property
    def __class__(self):  # noqa: A003
        raise LeftoverWatchdogTimeout("class base-exc bomb")


class _LyingBytesStr(str):
    @property
    def __class__(self):  # noqa: A003
        return bytes


class ApiCatalogRouterLeftoverTests(unittest.TestCase):
    def test_isa_swallows_a_baseexception_class_bomb(self):
        self.assertFalse(catalog._isinst(_ClassBaseBomb(), str))

    def test_text_does_not_leak_a_heap_address(self):
        self.assertEqual(api._message_text(object()), "")
        self.assertEqual(catalog._as_text(object()), "")

    def test_text_recovers_str_storage_lying_bytes(self):
        self.assertEqual(api._message_text(_LyingBytesStr("ok")), "ok")
        self.assertEqual(catalog._as_text(_LyingBytesStr("ok")), "ok")

    def test_int_is_not_rendered_as_float(self):
        self.assertEqual(api._message_text(5), "5")

    def test_nan_float_is_dropped(self):
        self.assertEqual(api._message_text(float("nan")), "")
        self.assertEqual(catalog._as_text(float("inf")), "")

    def test_get_health_does_not_500(self):
        client = TestClient(app(), raise_server_exceptions=False)
        response = client.get("/api/health")
        self.assertNotEqual(response.status_code, 500, response.text[:400])
        self.assertNotIn(" at 0x", response.text)

    def test_control_flow_still_propagates_from_isa(self):
        class _Ki:
            @property
            def __class__(self):  # noqa: A003
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            catalog._isinst(_Ki(), dict)


if __name__ == "__main__":
    unittest.main()
