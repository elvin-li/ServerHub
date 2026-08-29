"""Leftover sweep of launchd discovery probes and terminal PTY helpers."""
from __future__ import annotations

import unittest
from unittest import mock

from hub.discovery import launchd, vms
from hub import terminal_pty


class LeftoverWatchdogTimeout(BaseException):
    pass


class _LyingBytesStr(str):
    @property
    def __class__(self):  # noqa: A003
        return bytes


class LaunchdTerminalLeftoverTests(unittest.TestCase):
    def test_tls_alive_swallows_a_baseexception_port_bomb(self):
        class _Port:
            def __int__(self):
                raise LeftoverWatchdogTimeout("port bomb")

        self.assertFalse(launchd._tls_alive(_Port()))

    def test_http_alive_inf_port_is_dead(self):
        self.assertFalse(launchd._http_alive(float("inf")))

    def test_probe_port_swallows_port_open_bomb(self):
        def _boom(_port):
            raise LeftoverWatchdogTimeout("port_open bomb")

        with mock.patch.object(launchd, "port_open", _boom):
            self.assertFalse(launchd._probe_port(80))

    def test_discover_vms_swallows_a_baseexception(self):
        def _boom():
            raise LeftoverWatchdogTimeout("vms bomb")

        with mock.patch("hub.vms_svc.discover_vms", _boom):
            self.assertEqual(vms.discover_vms(), [])

    def test_safe_arg_does_not_leak_a_heap_address(self):
        self.assertEqual(terminal_pty._safe_arg(object()), "")

    def test_safe_arg_recovers_str_storage_lying_bytes(self):
        self.assertEqual(terminal_pty._safe_arg(_LyingBytesStr("ok")), "ok")

    def test_bounded_int_inf_is_default(self):
        self.assertEqual(terminal_pty._bounded_int(float("inf"), 80, 1, 500), 80)

    def test_control_flow_still_propagates_from_probe(self):
        def _ki(_port):
            raise KeyboardInterrupt

        with mock.patch.object(launchd, "port_open", _ki):
            with self.assertRaises(KeyboardInterrupt):
                launchd._probe_port(80)


if __name__ == "__main__":
    unittest.main()
