"""Leftover sweep of http_guard and cli_args helpers."""
from __future__ import annotations

import unittest

from hub import cli_args, http_guard


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


class HttpGuardCliArgsLeftoverTests(unittest.TestCase):
    def test_isa_swallows_a_baseexception_class_bomb(self):
        self.assertFalse(http_guard._isa(_ClassBaseBomb(), str))

    def test_coerce_does_not_leak_a_heap_address(self):
        self.assertIsNone(http_guard._coerce_text(object()))

    def test_coerce_recovers_str_storage_lying_bytes(self):
        self.assertEqual(http_guard._coerce_text(_LyingBytesStr("ok")), "ok")

    def test_as_argv_refuses_bytes_and_bombs(self):
        self.assertIsNone(cli_args.as_argv([b"--all"]))
        self.assertIsNone(cli_args.as_argv(_ClassBaseBomb()))
        self.assertEqual(cli_args.as_argv(["disk0"]), ["disk0"])

    def test_normalise_swallows_a_baseexception_class_bomb(self):
        self.assertIsNone(cli_args._normalise(_ClassBaseBomb()))

    def test_control_flow_still_propagates(self):
        class _Ki:
            @property
            def __class__(self):  # noqa: A003
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            http_guard._isa(_Ki(), dict)
        with self.assertRaises(KeyboardInterrupt):
            cli_args.as_argv(_Ki())


if __name__ == "__main__":
    unittest.main()
