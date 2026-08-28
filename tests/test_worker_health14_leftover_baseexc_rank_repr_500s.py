"""Fourteenth leftover sweep of the worker-health registry helpers.

health13 sealed sort-bomb names on this surface.  ``_isa`` / ``_utf8_text``
still stopped at ``except Exception``, trusted a claimed decode base, and
coerced default-render objects through ``str()``.
"""
from __future__ import annotations

import unittest

from hub import worker_health


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


class WorkerHealth14LeftoverTests(unittest.TestCase):
    def test_isa_swallows_a_baseexception_class_bomb(self):
        self.assertFalse(worker_health._isa(_ClassBaseBomb(), str))

    def test_utf8_text_does_not_leak_a_heap_address(self):
        self.assertEqual(worker_health._utf8_text(object()), "")

    def test_utf8_text_recovers_str_storage_lying_bytes(self):
        self.assertEqual(worker_health._utf8_text(_LyingBytesStr("ok")), "ok")

    def test_truthy_swallows_a_baseexception_bool(self):
        class _Bomb:
            def __bool__(self):
                raise LeftoverWatchdogTimeout("bool watchdog")

        self.assertFalse(worker_health._truthy(_Bomb()))

    def test_control_flow_still_propagates_from_isa(self):
        class _Ki:
            @property
            def __class__(self):  # noqa: A003
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            worker_health._isa(_Ki(), dict)


if __name__ == "__main__":
    unittest.main()
