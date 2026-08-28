"""Thirteenth leftover sweep of host-address helpers.

host12 sealed identity/settings readers.  ``_isa`` / ``_as_text`` /
``_sh_run`` still stopped at ``except Exception``, trusted a claimed decode
base, and coerced default-render objects through ``str()``.
"""
from __future__ import annotations

import unittest

from hub import host_address


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


class Host13LeftoverTests(unittest.TestCase):
    def test_isa_swallows_a_baseexception_class_bomb(self):
        self.assertFalse(host_address._isa(_ClassBaseBomb(), str))

    def test_as_text_does_not_leak_a_heap_address(self):
        self.assertEqual(host_address._as_text(object()), "")

    def test_as_text_recovers_str_storage_lying_bytes(self):
        self.assertEqual(host_address._as_text(_LyingBytesStr("ok")), "ok")

    def test_sh_run_degrades_a_baseexception_runner(self):
        def boom(*a, **k):
            raise LeftoverWatchdogTimeout("sh watchdog")

        orig = host_address.sh
        host_address.sh = boom
        try:
            self.assertEqual(host_address._sh_run(["true"], 1), (-255, "", ""))
        finally:
            host_address.sh = orig

    def test_control_flow_still_propagates_from_isa(self):
        class _Ki:
            @property
            def __class__(self):  # noqa: A003
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            host_address._isa(_Ki(), dict)


if __name__ == "__main__":
    unittest.main()
