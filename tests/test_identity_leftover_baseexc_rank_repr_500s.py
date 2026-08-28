"""Leftover sweep of identity sanitizer helpers.

``_isa`` / ``_as_text`` still stopped at ``except Exception``, trusted a
claimed decode base, and coerced default object ``__repr__`` heap
addresses into JSON.
"""
from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from hub import identity_svc
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


class IdentityLeftoverTests(unittest.TestCase):
    def test_isa_swallows_a_baseexception_class_bomb(self):
        self.assertFalse(identity_svc._isa(_ClassBaseBomb(), str))

    def test_as_text_does_not_leak_a_heap_address(self):
        self.assertEqual(identity_svc._as_text(object()), "")

    def test_as_text_recovers_str_storage_lying_bytes(self):
        self.assertEqual(identity_svc._as_text(_LyingBytesStr("ok")), "ok")

    def test_get_identity_does_not_500(self):
        client = TestClient(app(), raise_server_exceptions=False)
        response = client.get("/api/identity")
        self.assertNotEqual(response.status_code, 500, response.text[:400])
        self.assertNotIn(" at 0x", response.text)

    def test_control_flow_still_propagates_from_isa(self):
        class _Ki:
            @property
            def __class__(self):  # noqa: A003
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            identity_svc._isa(_Ki(), dict)


if __name__ == "__main__":
    unittest.main()
