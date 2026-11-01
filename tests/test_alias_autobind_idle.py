"""The IP-alias autobind loop does no host probing when there is nothing to bind.

``ip_aliases.auto_bind`` defaults on, so the loop runs on every install.  Its
alias pass finds the preferred NIC (``ifconfig -a`` plus two ``networksetup``
listings) before it looks at the managed IP list, so an install that never
configured an alias paid three spawns a minute for a "No managed IPs
configured" answer.
"""
from __future__ import annotations

import threading
import types
import unittest
from unittest import mock

from hub import network_svc


class _StopAfter:
    """``threading.Event`` stand-in: ``wait`` returns at once, records the
    timeout and reports "stopped" after *rounds* waits."""

    def __init__(self, rounds: int) -> None:
        self.rounds = rounds
        self.waits: list[float] = []
        self._set = False

    def wait(self, timeout=None):
        self.waits.append(timeout)
        if len(self.waits) >= self.rounds:
            self._set = True
        return self._set

    def is_set(self):
        return self._set

    def set(self):
        self._set = True


class _InlineThread:
    """``threading.Thread`` stand-in that runs the loop on the test's thread."""

    def __init__(self, target, daemon=None, name=None):
        self._target = target

    def start(self):
        self._target()

    def is_alive(self):
        return False


class AutobindIdleTests(unittest.TestCase):
    def _run_loop(self, ips, rounds=6):
        event = _StopAfter(rounds)
        fake_threading = types.SimpleNamespace(
            Event=lambda: event,
            Thread=_InlineThread,
            current_thread=threading.current_thread,
        )
        sections = {
            "ip_aliases": {"auto_bind": True, "ips": list(ips), "interval": 60},
            "network_failover": {"enabled": False},
        }
        alias_pass = mock.MagicMock(return_value={"ok": True})
        probe = mock.MagicMock(side_effect=AssertionError("NIC probed"))
        with (
            mock.patch.object(network_svc, "threading", fake_threading),
            mock.patch.object(network_svc, "_alias_thread", None),
            mock.patch.object(network_svc, "_alias_stop", None),
            mock.patch(
                "hub.config.settings_section",
                side_effect=lambda name: dict(sections.get(name, {})),
            ),
            mock.patch.object(network_svc, "ensure_aliases_on_preferred", alias_pass),
            mock.patch.object(network_svc, "preferred_active_device", probe),
        ):
            network_svc.start_alias_autobind()
        return alias_pass, probe, event.waits

    def test_no_managed_ips_means_no_alias_pass(self):
        alias_pass, probe, waits = self._run_loop(ips=[])
        alias_pass.assert_not_called()
        probe.assert_not_called()
        # The 8 s boot settle, then the normal interval: skipping the pass must
        # not leave a past deadline that spins the loop once a second.
        self.assertEqual(waits[0], 8)
        self.assertTrue(all(w > 50 for w in waits[1:]), waits)

    def test_managed_ips_still_get_one_pass_per_interval(self):
        alias_pass, _probe, waits = self._run_loop(ips=["192.0.2.10"])
        alias_pass.assert_called_once_with(force=False)
        self.assertEqual(waits[0], 8)
        self.assertTrue(all(w > 50 for w in waits[1:]), waits)


if __name__ == "__main__":
    unittest.main()
