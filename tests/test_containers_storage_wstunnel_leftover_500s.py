"""Leftover sweep of containers/storage routers and wstunnel helpers."""
from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from hub import wireguard_wstunnel
from hub.app_factory import create_app
from hub.auth import require_auth
from hub.routers import containers, storage

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


class ContainersStorageWstunnelLeftoverTests(unittest.TestCase):
    def test_isa_swallows_a_baseexception_class_bomb(self):
        self.assertFalse(storage._isa(_ClassBaseBomb(), str))
        self.assertFalse(wireguard_wstunnel._isa(_ClassBaseBomb(), str))

    def test_text_does_not_leak_a_heap_address(self):
        self.assertEqual(containers._as_text(object()), "")
        self.assertEqual(storage._as_text(object()), "")
        self.assertEqual(wireguard_wstunnel._as_text(object()), "")

    def test_text_recovers_str_storage_lying_bytes(self):
        self.assertEqual(containers._as_text(_LyingBytesStr("ok")), "ok")
        self.assertEqual(storage._as_text(_LyingBytesStr("ok")), "ok")
        self.assertEqual(wireguard_wstunnel._as_text(_LyingBytesStr("ok")), "ok")

    def test_rc_int_junk_is_minus_255(self):
        self.assertEqual(wireguard_wstunnel._rc_int(_ClassBaseBomb()), -255)

    def test_get_storage_does_not_500(self):
        client = TestClient(app(), raise_server_exceptions=False)
        response = client.get("/api/storage")
        self.assertNotEqual(response.status_code, 500, response.text[:400])
        self.assertNotIn(" at 0x", response.text)

    def test_control_flow_still_propagates_from_isa(self):
        class _Ki:
            @property
            def __class__(self):  # noqa: A003
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            storage._isa(_Ki(), dict)
        with self.assertRaises(KeyboardInterrupt):
            wireguard_wstunnel._isa(_Ki(), dict)

    def test_read_plist_swallows_load_baseexception(self):
        def boom(*_a, **_k):
            raise LeftoverWatchdogTimeout("plist watchdog")

        from unittest import mock

        with mock.patch.object(wireguard_wstunnel, "read_bytes_capped", boom):
            self.assertEqual(
                wireguard_wstunnel.read_plist(),
                {"listen": "", "restrict_to": ""},
            )


if __name__ == "__main__":
    unittest.main()
