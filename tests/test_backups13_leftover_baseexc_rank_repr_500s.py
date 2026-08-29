"""Thirteenth leftover sweep of backup sanitizer helpers.

backups12 sealed cfg/home seams.  ``_isa`` / ``_as_text`` still stopped at
``except Exception``, trusted a claimed decode base, and coerced default
object ``__repr__`` heap addresses into JSON.
"""
from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from hub import backups
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


class Backups13LeftoverTests(unittest.TestCase):
    def test_isa_swallows_a_baseexception_class_bomb(self):
        self.assertFalse(backups._isa(_ClassBaseBomb(), str))

    def test_as_text_does_not_leak_a_heap_address(self):
        self.assertEqual(backups._as_text(object()), "")
        self.assertEqual(backups._utf8_text(object()), "")

    def test_as_text_recovers_str_storage_lying_bytes(self):
        self.assertEqual(backups._as_text(_LyingBytesStr("ok")), "ok")

    def test_get_backups_does_not_500(self):
        client = TestClient(app(), raise_server_exceptions=False)
        response = client.get("/api/backups")
        self.assertNotEqual(response.status_code, 500, response.text[:400])
        self.assertNotIn(" at 0x", response.text)

    def test_control_flow_still_propagates_from_isa(self):
        class _Ki:
            @property
            def __class__(self):  # noqa: A003
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            backups._isa(_Ki(), dict)

    def test_jsonable_swallows_isoformat_getattr_baseexception(self):
        class _IsoBomb:
            @property
            def isoformat(self):
                raise LeftoverWatchdogTimeout("backups isoformat watchdog")

        self.assertEqual(backups._jsonable(_IsoBomb()), "")


if __name__ == "__main__":
    unittest.main()
