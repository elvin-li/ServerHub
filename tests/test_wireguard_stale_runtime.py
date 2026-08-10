"""A half-finished wg-quick run must not leave the tunnel permanently unstartable.

Observed on the real host: `wg-quick up` created utun8, failed later in setup, and
left `/var/run/wireguard/wg0.name` behind pointing at it. utun8 no longer existed,
so from then on every start aborted with

    wg-quick: `wg0' already exists as `utun8'

and every stop failed too, because the device the record names is gone. The panel
reported "not running", which was true, next to a start button that could never
work again -- and the error blamed the interface rather than the leftover record.

wg-quick does not clean up after itself here, so the panel has to. The dangerous
mistake would be clearing the record while a tunnel is genuinely live, which would
orphan a running interface; these tests pin that boundary.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import wireguard_svc  # noqa: E402


class RuntimeStateTests(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.run_dir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        patcher = patch.object(wireguard_svc, "WG_RUN_DIR", self.run_dir)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_name_file_with_no_socket_is_stale(self):
        (self.run_dir / "wg0.name").write_text("utun8\n")
        state = wireguard_svc.runtime_state("wg0")
        self.assertTrue(state["stale"])
        self.assertTrue(state["name_file_present"])
        self.assertEqual(state["sockets"], [])

    def test_a_name_file_with_a_live_socket_is_not_stale(self):
        """Something is serving the interface; the record is correct."""
        (self.run_dir / "wg0.name").write_text("utun8\n")
        (self.run_dir / "utun8.sock").write_text("")
        self.assertFalse(wireguard_svc.runtime_state("wg0")["stale"])

    def test_no_name_file_is_not_stale(self):
        self.assertFalse(wireguard_svc.runtime_state("wg0")["stale"])

    def test_a_missing_run_directory_is_not_stale(self):
        with patch.object(wireguard_svc, "WG_RUN_DIR", self.run_dir / "absent"):
            self.assertFalse(wireguard_svc.runtime_state("wg0")["stale"])

    def test_detection_does_not_need_to_read_the_record(self):
        """The file is mode 0400 root, so only its presence is observable."""
        target = self.run_dir / "wg0.name"
        target.write_text("utun8\n")
        target.chmod(0o400)
        self.assertTrue(wireguard_svc.runtime_state("wg0")["stale"])


class SelfHealTests(unittest.TestCase):
    """`up` clears a stale claim first; `down` and a live tunnel are left alone."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.run_dir = Path(self._tmp.name)
        self.conf = self.run_dir / "wg0.conf"
        self.conf.write_text("[Interface]\nPrivateKey = x\n")
        self.addCleanup(self._tmp.cleanup)
        for attr, value in (("WG_RUN_DIR", self.run_dir),):
            p = patch.object(wireguard_svc, attr, value)
            p.start()
            self.addCleanup(p.stop)

    def _run(self, action: str, stale: bool):
        if stale:
            (self.run_dir / "wg0.name").write_text("utun8\n")
        issued: list[list[str]] = []

        def fake_sh(argv, **kwargs):
            issued.append([str(a) for a in argv])
            return (0, "", "")

        with (
            patch.object(wireguard_svc, "conf_path", return_value=self.conf),
            patch.object(wireguard_svc, "sh", side_effect=fake_sh),
            patch.object(wireguard_svc, "run_admin_sequence", return_value={"ok": True}),
        ):
            wireguard_svc.interface_action(action)
        return issued

    def _removals(self, issued):
        return [a for a in issued if "rm" in a[2] if len(a) > 2] if issued else []

    def test_up_clears_a_stale_claim_first(self):
        issued = self._run("up", stale=True)
        flat = [" ".join(a) for a in issued]
        removal = [c for c in flat if "/bin/rm" in c]
        self.assertTrue(removal, f"no cleanup was attempted: {flat}")
        self.assertIn("wg0.name", removal[0])
        # Order matters: clearing after the failed `up` would not help.
        self.assertLess(
            flat.index(removal[0]),
            next(i for i, c in enumerate(flat) if "wg-quick" in c),
            "the claim must be cleared before wg-quick runs",
        )

    def test_up_does_not_touch_a_consistent_state(self):
        issued = self._run("up", stale=False)
        flat = [" ".join(a) for a in issued]
        self.assertFalse(
            [c for c in flat if "/bin/rm" in c],
            "removed a record that was not stale",
        )

    def test_up_does_not_touch_a_live_tunnel(self):
        (self.run_dir / "wg0.name").write_text("utun8\n")
        (self.run_dir / "utun8.sock").write_text("")
        issued = self._run("up", stale=False)
        flat = [" ".join(a) for a in issued]
        self.assertFalse(
            [c for c in flat if "/bin/rm" in c],
            "clearing the record of a running interface would orphan it",
        )

    def test_down_does_not_clear_the_claim(self):
        """`down` is how an operator resolves a genuinely live interface."""
        issued = self._run("down", stale=True)
        flat = [" ".join(a) for a in issued]
        self.assertFalse([c for c in flat if "/bin/rm" in c])


class SudoersCoverageTests(unittest.TestCase):
    def test_the_cleanup_command_is_granted_and_path_pinned(self):
        template = (BASE / "deploy" / "sudoers.d" / "serverhub").read_text()
        self.assertIn("/bin/rm -f /var/run/wireguard/wg0.name", template)
        # A wildcard here would be a grant to delete any file as root.
        self.assertNotIn("/bin/rm -f /var/run/wireguard/*", template)
        self.assertNotIn("/bin/rm -rf", template)


if __name__ == "__main__":
    unittest.main()
