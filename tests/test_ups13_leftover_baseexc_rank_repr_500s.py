"""Thirteenth leftover sweep of UPS sanitizer helpers.

ups12 sealed isoformat dunder bombs.  ``_isa`` / ``_as_text`` still
stopped at ``except Exception``, trusted a claimed decode base, and
coerced default object ``__repr__`` heap addresses into JSON.
"""
from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from hub import ups_policy, ups_svc
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


class Ups13LeftoverTests(unittest.TestCase):
    def test_isa_swallows_a_baseexception_class_bomb(self):
        self.assertFalse(ups_svc._isa(_ClassBaseBomb(), str))

    def test_as_text_does_not_leak_a_heap_address(self):
        self.assertEqual(ups_svc._as_text(object()), "")

    def test_as_text_recovers_str_storage_lying_bytes(self):
        self.assertEqual(ups_svc._as_text(_LyingBytesStr("ok")), "ok")

    def test_get_ups_does_not_500(self):
        client = TestClient(app(), raise_server_exceptions=False)
        response = client.get("/api/ups")
        self.assertNotEqual(response.status_code, 500, response.text[:400])
        self.assertNotIn(" at 0x", response.text)

    def test_control_flow_still_propagates_from_isa(self):
        class _Ki:
            @property
            def __class__(self):  # noqa: A003
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            ups_svc._isa(_Ki(), dict)

    def test_policy_jsonable_swallows_list_iter_baseexception(self):
        class _IterBomb(list):
            def __iter__(self):
                raise LeftoverWatchdogTimeout("ups policy jsonable watchdog")

        self.assertIsNone(ups_policy._jsonable(_IterBomb([1])))


if __name__ == "__main__":
    unittest.main()
