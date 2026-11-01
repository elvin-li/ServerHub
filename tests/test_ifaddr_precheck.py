"""No ``ipconfig getifaddr`` spawn for an interface that holds no IPv4 address.

The host page's interface sweep asks ``ipconfig getifaddr`` about the default
interface plus en0, en1, bridge0 and utun0, every time its 100 s snapshot
expires.  On this host three of those have no IPv4 address at all, and ipconfig
can only answer empty for them.  ``host_address._lacks_ipv4`` tells that from
one ``SIOCGIFADDR`` ioctl and skips the spawn.  An interface with an address
still asks ipconfig, because its answer is then not simply the kernel's first
address (a failover alias comes first on this host).
"""
from __future__ import annotations

import errno
import os
import socket
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import host_address  # noqa: E402

_ON_MAC = sys.platform == "darwin" and os.path.exists("/usr/sbin/ipconfig")


class _CheckOn(unittest.TestCase):
    def setUp(self):
        self.enterContext(mock.patch.dict(os.environ))
        os.environ.pop("SERVERHUB_NO_NATIVE_IFADDR", None)
        host_address.invalidate_routing()
        self.addCleanup(host_address.invalidate_routing)
        self.spawns = []

    def _sh(self, cmd, *args, **kwargs):
        self.spawns.append(list(cmd))
        return 0, "192.0.2.7", ""


@unittest.skipUnless(_ON_MAC, "needs macOS ipconfig")
class SameAnswerAsIpconfigTests(_CheckOn):
    def test_every_interface_without_ipv4_gets_an_empty_ipconfig_answer(self):
        names = [name for _index, name in socket.if_nameindex()] + ["zz9"]
        skipped = [name for name in names if host_address._lacks_ipv4(name)]
        self.assertIn("zz9", skipped)
        for name in skipped:
            with self.subTest(name=name):
                answer = subprocess.run(
                    ["/usr/sbin/ipconfig", "getifaddr", name],
                    capture_output=True, text=True, timeout=10, check=False,
                )
                self.assertNotEqual(answer.returncode, 0)
                self.assertEqual(answer.stdout.strip(), "")

    def test_loopback_has_an_address_so_ipconfig_is_still_asked(self):
        self.assertFalse(host_address._lacks_ipv4("lo0"))


@unittest.skipUnless(sys.platform == "darwin", "the check is macOS-only")
class SpawnTests(_CheckOn):
    def _address(self, interface, ioctl=None):
        patches = [mock.patch.object(host_address, "sh", side_effect=self._sh)]
        if ioctl is not None:
            patches.append(mock.patch.object(host_address.fcntl, "ioctl", side_effect=ioctl))
        for patch in patches:
            self.enterContext(patch)
        return host_address.interface_address(interface, force=True)

    def test_no_address_means_no_spawn(self):
        for code in (errno.EADDRNOTAVAIL, errno.ENXIO):
            with self.subTest(errno=code):
                self.spawns.clear()
                got = self._address("en7", ioctl=OSError(code, os.strerror(code)))
                self.assertEqual((got, self.spawns), ("", []))

    def test_an_address_or_another_error_still_asks_ipconfig(self):
        for ioctl in (lambda *a: b"", OSError(errno.EPERM, "nope"), ValueError("odd")):
            with self.subTest(ioctl=ioctl):
                self.spawns.clear()
                got = self._address("en7", ioctl=ioctl)
                self.assertEqual(got, "192.0.2.7")
                self.assertEqual(self.spawns, [["/usr/sbin/ipconfig", "getifaddr", "en7"]])

    def test_names_the_kernel_cannot_take_still_ask_ipconfig(self):
        for name in ("x" * 16, "caf\u00e9", "en0.1"):
            with self.subTest(name=name):
                self.assertFalse(host_address._lacks_ipv4(name))

    def test_the_env_flag_turns_the_check_off(self):
        os.environ["SERVERHUB_NO_NATIVE_IFADDR"] = "1"
        got = self._address("zz9")
        self.assertEqual(got, "192.0.2.7")
        self.assertEqual(len(self.spawns), 1)


if __name__ == "__main__":
    unittest.main()
