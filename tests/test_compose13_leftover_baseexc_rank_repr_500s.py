"""Thirteenth leftover sweep of the Compose YAML helpers.

compose12 sealed home/stack-row seams.  ``_utf8_text`` still stopped at
``except Exception``, trusted a claimed decode base, and coerced
default-render objects through ``str()``.
"""
from __future__ import annotations

import unittest
from unittest import mock

from hub import compose_svc


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


class Compose13LeftoverTests(unittest.TestCase):
    def test_utf8_text_does_not_leak_a_heap_address(self):
        self.assertEqual(compose_svc._utf8_text(object()), "")

    def test_utf8_text_recovers_str_storage_lying_bytes(self):
        self.assertEqual(compose_svc._utf8_text(_LyingBytesStr("ok")), "ok")

    def test_utf8_text_none_is_empty(self):
        self.assertEqual(compose_svc._utf8_text(None), "")

    def test_finite_mtime_swallows_a_baseexception_coercion(self):
        class _Bomb:
            def __int__(self):
                raise LeftoverWatchdogTimeout("mtime watchdog")

        self.assertEqual(compose_svc._finite_mtime(_Bomb()), 0)

    def test_control_flow_still_propagates_from_finite_mtime(self):
        class _Ki:
            def __int__(self):
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            compose_svc._finite_mtime(_Ki())

    def test_row_get_swallows_eq_baseexception(self):
        class _Key(str):
            def __eq__(self, other):
                raise LeftoverWatchdogTimeout("eq watchdog")

            def __hash__(self):
                return hash("id")

        self.assertIsNone(compose_svc._row_get({_Key("id"): "x"}, "id"))

    def test_home_path_swallows_provider_baseexception(self):
        def boom():
            raise LeftoverWatchdogTimeout("home watchdog")

        with mock.patch.object(compose_svc, "user_home", boom):
            self.assertIsNone(compose_svc._home_path())


if __name__ == "__main__":
    unittest.main()
