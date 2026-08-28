"""Leftover sweep of service_signatures and users_svc text launderers."""
from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from hub import service_signatures, users_svc
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


class SignaturesUsersLeftoverTests(unittest.TestCase):
    def test_isa_swallows_a_baseexception_class_bomb(self):
        self.assertFalse(users_svc._isa(_ClassBaseBomb(), str))

    def test_text_does_not_leak_a_heap_address(self):
        self.assertEqual(service_signatures._utf8_text(object()), "")
        self.assertEqual(users_svc._pwd_text(object()), "")
        self.assertEqual(service_signatures.unescape_proc_name(object()), "")

    def test_text_recovers_str_storage_lying_bytes(self):
        self.assertEqual(service_signatures._utf8_text(_LyingBytesStr("ok")), "ok")
        self.assertEqual(users_svc._pwd_text(_LyingBytesStr("ok")), "ok")

    def test_get_users_does_not_500(self):
        client = TestClient(app(), raise_server_exceptions=False)
        response = client.get("/api/users")
        self.assertNotEqual(response.status_code, 500, response.text[:400])
        self.assertNotIn(" at 0x", response.text)

    def test_control_flow_still_propagates_from_isa(self):
        class _Ki:
            @property
            def __class__(self):  # noqa: A003
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            users_svc._isa(_Ki(), dict)


if __name__ == "__main__":
    unittest.main()
