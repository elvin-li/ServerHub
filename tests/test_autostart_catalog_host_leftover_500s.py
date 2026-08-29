"""Leftover sweep of autostart, catalog_remote, and host_address helpers."""
from __future__ import annotations

import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import autostart_svc, catalog_remote, host_address, adaptive
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


class _ClassBaseBomb:
    @property
    def __class__(self):  # noqa: A003
        raise LeftoverWatchdogTimeout("class base-exc bomb")


class _LyingBytesStr(str):
    @property
    def __class__(self):  # noqa: A003
        return bytes


class AutostartCatalogHostLeftoverTests(unittest.TestCase):
    def test_isa_swallows_a_baseexception_class_bomb(self):
        self.assertFalse(autostart_svc._isinstance(_ClassBaseBomb(), str))
        self.assertFalse(catalog_remote._isinst(_ClassBaseBomb(), str))
        self.assertFalse(host_address._isa(_ClassBaseBomb(), str))

    def test_text_does_not_leak_a_heap_address(self):
        self.assertEqual(autostart_svc._as_text(object()), "")
        self.assertEqual(catalog_remote._as_text(object()), "")
        self.assertEqual(host_address._as_text(object()), "")

    def test_text_recovers_str_storage_lying_bytes(self):
        self.assertEqual(autostart_svc._as_text(_LyingBytesStr("ok")), "ok")
        self.assertEqual(catalog_remote._as_text(_LyingBytesStr("ok")), "ok")
        self.assertEqual(host_address._as_text(_LyingBytesStr("ok")), "ok")

    def test_plain_rc_bool_is_exact_type(self):
        self.assertEqual(autostart_svc._plain_rc(True), 1)
        self.assertIsNone(autostart_svc._plain_rc(_ClassBaseBomb()))

    def test_get_host_does_not_500(self):
        client = TestClient(app(), raise_server_exceptions=False)
        response = client.get("/api/system/host")
        self.assertNotEqual(response.status_code, 500, response.text[:400])
        self.assertNotIn(" at 0x", response.text)

    def test_control_flow_still_propagates_from_isa(self):
        class _Ki:
            @property
            def __class__(self):  # noqa: A003
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            autostart_svc._isinstance(_Ki(), dict)
        with self.assertRaises(KeyboardInterrupt):
            catalog_remote._isinst(_Ki(), dict)
        with self.assertRaises(KeyboardInterrupt):
            host_address._isa(_Ki(), dict)

    def test_template_variables_swallows_cfg_baseexception(self):
        def boom():
            raise LeftoverWatchdogTimeout("cfg watchdog")

        with mock.patch("hub.config.cfg", boom):
            values = host_address.template_variables()
        self.assertIn("host", values)

    def test_adaptive_utf8_does_not_leak_a_heap_address(self):
        self.assertEqual(adaptive._utf8_text(object()), "")


if __name__ == "__main__":
    unittest.main()
