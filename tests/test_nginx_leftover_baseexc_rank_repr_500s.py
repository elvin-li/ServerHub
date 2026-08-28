"""Leftover sweep of the nginx reverse-proxy helpers.

``_user_home`` / ``_isinst`` / ``_as_text`` still stopped at
``except Exception``, trusted a claimed decode base, and coerced
default-render objects through ``str()``.
"""
from __future__ import annotations

import unittest
from unittest import mock

from hub import nginx_svc


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


class NginxLeftoverTests(unittest.TestCase):
    def test_isinst_swallows_a_baseexception_class_bomb(self):
        self.assertFalse(nginx_svc._isinst(_ClassBaseBomb(), str))

    def test_as_text_does_not_leak_a_heap_address(self):
        self.assertEqual(nginx_svc._as_text(object()), "")

    def test_as_text_recovers_str_storage_lying_bytes(self):
        self.assertEqual(nginx_svc._as_text(_LyingBytesStr("ok")), "ok")

    def test_user_home_degrades_a_baseexception_provider(self):
        def boom():
            raise LeftoverWatchdogTimeout("home watchdog")

        with mock.patch.object(nginx_svc, "user_home", boom):
            self.assertIsNone(nginx_svc._user_home())

    def test_nginx_present_swallows_fspath_baseexception(self):
        class _PathBomb:
            def __fspath__(self):
                raise LeftoverWatchdogTimeout("nginx path watchdog")

        with mock.patch.object(nginx_svc, "NGINX_BIN", _PathBomb()):
            self.assertTrue(nginx_svc._nginx_present())

    def test_control_flow_still_propagates_from_isinst(self):
        class _Ki:
            @property
            def __class__(self):  # noqa: A003
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            nginx_svc._isinst(_Ki(), dict)


if __name__ == "__main__":
    unittest.main()
