"""Leftover sweep of hub.util._exc_text and utf8_env."""
from __future__ import annotations

import unittest

from hub import util


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


class UtilLeftoverTests(unittest.TestCase):
    def test_exc_text_does_not_leak_a_heap_address(self):
        self.assertEqual(util._exc_text(object()), "error")

    def test_exc_text_recovers_str_storage_lying_bytes(self):
        self.assertEqual(util._exc_text(_LyingBytesStr("boom")), "boom")

    def test_utf8_env_swallows_items_bomb(self):
        class _ItemsBomb(dict):
            def items(self):
                raise LeftoverWatchdogTimeout("items bomb")

            def keys(self):
                raise LeftoverWatchdogTimeout("keys bomb")

        self.assertEqual(util.utf8_env(_ItemsBomb(A="1")), {})

    def test_control_flow_still_propagates_from_exc_text(self):
        class _Ki:
            def __str__(self):
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            util._exc_text(_Ki())


if __name__ == "__main__":
    unittest.main()
