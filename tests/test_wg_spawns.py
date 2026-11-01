"""WireGuard status reads spend no spawn on answers they already have.

Every health check and every ``/api/wireguard/*`` request read the live tunnel
and the tool versions.  That cost four spawns on this host:

* ``wg --version`` and ``wireguard-go --version``.  The answer is a function of
  the binary file, so a successful one is now kept until that file changes;
  a failure is never kept, so a one-off timeout still clears on the next call.
* ``wg show <device> dump`` without root, then again through sudo.  wg-quick
  creates the UAPI socket mode 0700 root and connecting needs write access, so
  the unprivileged try can only fail; it is skipped when the socket refuses
  this account.  A missing socket or a writable one keeps it.
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import wireguard_svc  # noqa: E402

DUMP = "priv\tpub\t51820\toff\npeerpub\t(none)\t1.2.3.4:5\t10.0.0.2/32\t0\t1\t2\toff\n"
ALL_DUMP = "".join(f"utun9\t{line}\n" for line in DUMP.splitlines())


class _Calls:
    """Records argv for the unprivileged runner and the sudo runner."""

    def __init__(self, sudo_rc=0):
        self.sh, self.sudo = [], []
        self.sudo_rc = sudo_rc

    def run_sh(self, cmd, *args, **kwargs):
        self.sh.append(list(cmd))
        if cmd[1:2] == ["show"]:
            return 0, ALL_DUMP if "all" in cmd else DUMP, ""
        return 0, "", ""

    def run_sudo(self, cmd, *args, **kwargs):
        self.sudo.append(list(cmd))
        if self.sudo_rc:
            return self.sudo_rc, "", "sudo: a password is required"
        return 0, ALL_DUMP if "all" in cmd else DUMP, ""


@unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root may open any socket")
class UnprivilegedShowTests(unittest.TestCase):
    def setUp(self):
        self.run_dir = Path(self.enterContext(TemporaryDirectory()))
        self.enterContext(mock.patch.object(wireguard_svc, "WG_RUN_DIR", self.run_dir))
        self.calls = _Calls()
        self.enterContext(mock.patch.object(wireguard_svc, "sh", side_effect=self.calls.run_sh))
        self.enterContext(mock.patch.object(
            wireguard_svc, "sudo_capture", side_effect=self.calls.run_sudo,
        ))

    def _socket(self, name, mode):
        path = self.run_dir / f"{name}.sock"
        path.unlink(missing_ok=True)
        path.write_text("")
        path.chmod(mode)
        return path

    def _shows(self, calls):
        return [argv for argv in calls if argv[1:2] == ["show"]]

    def test_a_socket_that_refuses_us_goes_straight_to_sudo(self):
        self._socket("utun9", 0o500)
        device, rows, error = wireguard_svc.live_interface("wg9")
        self.assertEqual((device, error), ("utun9", ""))
        self.assertEqual(rows[0][1], "pub")
        self.assertEqual(self._shows(self.calls.sh), [])
        self.assertEqual(len(self.calls.sudo), 1)

    def test_a_socket_we_may_open_is_tried_first(self):
        self._socket("utun9", 0o600)
        device, _rows, error = wireguard_svc.live_interface("wg9")
        self.assertEqual((device, error), ("utun9", ""))
        self.assertEqual(len(self._shows(self.calls.sh)), 1)
        self.assertEqual(self.calls.sudo, [])

    def test_no_socket_file_keeps_the_unprivileged_try(self):
        with mock.patch.object(wireguard_svc, "real_interface", return_value="wg9"):
            wireguard_svc.live_interface("wg9")
        self.assertEqual(len(self._shows(self.calls.sh)), 1)

    def test_a_failed_sudo_still_reports_like_before(self):
        self._socket("utun9", 0o500)
        self.calls.sudo_rc = 1
        device, rows, error = wireguard_svc.live_interface("wg9")
        self.assertEqual((device, rows), ("", []))
        self.assertTrue(error)
        # Both dumps went to sudo; only `wg show interfaces` ran unprivileged.
        self.assertEqual(self._shows(self.calls.sh), [[wireguard_svc.WG, "show", "interfaces"]])
        self.assertEqual(len(self.calls.sudo), 2)

    def test_the_all_dump_skips_only_when_every_socket_refuses_us(self):
        cases = {"all refuse": (0o500, 0o500), "one open": (0o500, 0o600)}
        for label, (first, second) in cases.items():
            with self.subTest(label):
                self.calls.sh.clear()
                self.calls.sudo.clear()
                self._socket("utun8", first)
                self._socket("utun9", second)
                grouped, error = wireguard_svc._dump_all()
                self.assertEqual(error, "")
                self.assertIn("utun9", grouped)
                tried = len(self._shows(self.calls.sh))
                self.assertEqual(tried, 0 if label == "all refuse" else 1)

    def test_no_sockets_keeps_the_unprivileged_all_dump(self):
        wireguard_svc._dump_all()
        self.assertEqual(len(self._shows(self.calls.sh)), 1)


class VersionMemoTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(mock.patch.dict(os.environ))
        os.environ.pop("SERVERHUB_NO_VERSION_MEMO", None)
        self.dir = Path(self.enterContext(TemporaryDirectory()))
        self.wg = self.dir / "wg"
        self.go = self.dir / "wireguard-go"
        self.quick = self.dir / "wg-quick"
        for path in (self.wg, self.go, self.quick):
            path.write_text("#!/bin/sh\n")
        for name, path in (("WG", self.wg), ("WIREGUARD_GO", self.go), ("WG_QUICK", self.quick)):
            self.enterContext(mock.patch.object(wireguard_svc, name, str(path)))
        self.enterContext(mock.patch.dict(wireguard_svc._version_memo, clear=True))
        self.spawns = []
        self.answer = {}
        self.enterContext(mock.patch.object(wireguard_svc, "sh", side_effect=self._sh))

    def _sh(self, cmd, *args, **kwargs):
        self.spawns.append(os.path.basename(cmd[0]))
        rc, text = self.answer.get(os.path.basename(cmd[0]), (0, f"{cmd[0]} v1"))
        return rc, text, ""

    def _versions(self):
        got = wireguard_svc.installation()
        return got["tools_version"], got["userspace_version"], got["probe_failed"]

    def test_an_unchanged_binary_is_asked_once(self):
        first = self._versions()
        second = self._versions()
        self.assertEqual(first, second)
        self.assertEqual(first[2], False)
        self.assertEqual(sorted(self.spawns), ["wg", "wireguard-go"])

    def _replace(self):
        new = self.dir / "new"
        new.write_text("#!/bin/sh\n")  # same size, new inode
        os.replace(new, self.wg)

    def test_a_changed_binary_is_asked_again(self):
        changes = {
            "touched": lambda: os.utime(self.wg, ns=(0, os.stat(self.wg).st_mtime_ns + 10**9)),
            "rewritten": lambda: self.wg.write_text("#!/bin/sh\n# 2\n"),
            "replaced": self._replace,
            "chmod": lambda: self.wg.chmod(0o700),
        }
        for label, change in changes.items():
            with self.subTest(label):
                wireguard_svc._version_memo.clear()
                self._versions()
                self.spawns.clear()
                change()
                self._versions()
                self.assertEqual(self.spawns, ["wg"])

    def test_a_repointed_symlink_is_asked_again(self):
        target_a, target_b = self.dir / "wg-a", self.dir / "wg-b"
        target_a.write_text("a")
        target_b.write_text("b")
        self.wg.unlink()
        self.wg.symlink_to(target_a)
        self._versions()
        self.spawns.clear()
        self.wg.unlink()
        self.wg.symlink_to(target_b)
        self._versions()
        self.assertEqual(self.spawns, ["wg"])

    def test_a_failure_is_never_kept(self):
        self.answer["wg"] = (1, "")
        self.assertEqual(self._versions()[0], "")
        self.assertTrue(self._versions()[2])
        del self.answer["wg"]
        self.assertTrue(self._versions()[0].endswith("wg v1"))
        self.assertEqual(self.spawns.count("wg"), 3)

    def test_a_binary_changed_while_it_answered_is_asked_again(self):
        def sh_then_touch(cmd, *args, **kwargs):
            self.spawns.append(os.path.basename(cmd[0]))
            if cmd[0] == str(self.wg):
                self.wg.write_text("#!/bin/sh\n# upgraded mid-run\n")
            return 0, f"{cmd[0]} v1", ""

        with mock.patch.object(wireguard_svc, "sh", side_effect=sh_then_touch):
            self._versions()
        self.spawns.clear()
        self._versions()
        self.assertEqual(self.spawns, ["wg"])

    def test_the_env_flag_turns_the_memo_off(self):
        os.environ["SERVERHUB_NO_VERSION_MEMO"] = "1"
        self._versions()
        self._versions()
        self.assertEqual(sorted(self.spawns), ["wg", "wg", "wireguard-go", "wireguard-go"])


if __name__ == "__main__":
    unittest.main()
