"""Thirteenth leftover sweep of the Docker CLI sanitizer helpers.

docker12 sealed memo-store 500s.  ``_isa`` / ``_utf8_text`` / ``_as_text``
still stopped at ``except Exception``, trusted a claimed decode base, and
coerced default-render objects through ``str()``.
"""
from __future__ import annotations

import unittest

from hub import docker_cli


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


class Docker13LeftoverTests(unittest.TestCase):
    def test_isa_swallows_a_baseexception_class_bomb(self):
        self.assertFalse(docker_cli._isa(_ClassBaseBomb(), str))

    def test_utf8_text_does_not_leak_a_heap_address(self):
        self.assertEqual(docker_cli._utf8_text(object()), "")

    def test_utf8_text_recovers_str_storage_lying_bytes(self):
        self.assertEqual(docker_cli._utf8_text(_LyingBytesStr("ok")), "ok")

    def test_as_text_does_not_leak_a_heap_address(self):
        self.assertEqual(docker_cli._as_text(object()), "")

    def test_control_flow_still_propagates_from_isa(self):
        class _Ki:
            @property
            def __class__(self):  # noqa: A003
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            docker_cli._isa(_Ki(), dict)

    def test_jsonable_swallows_list_iter_baseexception(self):
        class _IterBomb(list):
            def __iter__(self):
                raise LeftoverWatchdogTimeout("jsonable iter watchdog")

        self.assertIsNone(docker_cli._jsonable(_IterBomb([1])))

    def test_jsonable_still_propagates_keyboardinterrupt_from_iter(self):
        class _Ki(list):
            def __iter__(self):
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            docker_cli._jsonable(_Ki([1]))


if __name__ == "__main__":
    unittest.main()
