from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import call, patch

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hub import macos_admin, shares_svc


class MacOSAdminTests(unittest.TestCase):
    def test_single_command_uses_passwordless_sudo_when_allowed(self):
        with patch("hub.macos_admin.sh", return_value=(0, "", "")) as run:
            result = macos_admin.run_admin([
                "/usr/sbin/sharing", "-a", "/Users/example/Shared folder", "-n", "A; touch /tmp/no",
            ])

        self.assertEqual(result, {"ok": True})
        argv = run.call_args.args[0]
        self.assertEqual(argv[:2], ["/usr/bin/sudo", "-n"])
        # Arguments are passed as separate argv elements, so shell
        # metacharacters in a value can never split into extra commands.
        self.assertIn("/Users/example/Shared folder", argv)
        self.assertIn("A; touch /tmp/no", argv)

    def test_no_password_asks_the_web_ui_for_one(self):
        with patch("hub.macos_admin.sh", return_value=(1, "", "a password is required")):
            self.assertEqual(
                macos_admin.run_admin(["/usr/bin/true"]),
                {"ok": False, "error": "password_required"},
            )

    def test_web_password_runs_sudo_with_password_on_stdin(self):
        completed = type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        with patch("hub.macos_admin.subprocess.run", return_value=completed) as run:
            with macos_admin.use_admin_password("s3cret"):
                result = macos_admin.run_admin_sequence([
                    ["/bin/echo", "one"],
                    ["/bin/echo", "two"],
                ])

        self.assertEqual(result, {"ok": True})
        argv = run.call_args.args[0]
        self.assertEqual(argv[:4], ["/usr/bin/sudo", "-S", "-p", ""])
        self.assertEqual(argv[4:6], ["/bin/sh", "-c"])
        # sudo scrubs PATH, so the sequence re-adds the Homebrew prefixes before
        # the validated commands run (env-shebang scripts otherwise hit bash 3.2).
        self.assertTrue(argv[6].startswith("PATH=\"/opt/homebrew/bin:"), argv[6])
        self.assertTrue(argv[6].endswith("/bin/echo one; /bin/echo two"), argv[6])
        # The password travels on stdin, never on the command line.
        self.assertEqual(run.call_args.kwargs.get("input"), "s3cret\n")
        self.assertNotIn("s3cret", " ".join(argv))

    def test_wrong_web_password_is_structured(self):
        completed = type("R", (), {
            "returncode": 1, "stdout": "", "stderr": "sudo: Sorry, try again.",
        })()
        with patch("hub.macos_admin.subprocess.run", return_value=completed):
            with macos_admin.use_admin_password("wrong"):
                self.assertEqual(
                    macos_admin.run_admin(["/usr/bin/true"]),
                    {"ok": False, "error": "password_incorrect"},
                )

    def test_password_does_not_leak_between_requests(self):
        with macos_admin.use_admin_password("s3cret"):
            pass
        self.assertFalse(macos_admin.admin_password_supplied())

    def test_invalid_admin_sequence_is_rejected_without_spawning(self):
        with patch("hub.macos_admin.sh") as run:
            result = macos_admin.run_admin_sequence([["/usr/bin/true", "bad\x00arg"]])
        self.assertEqual(result, {"ok": False, "error": "invalid_command"})
        run.assert_not_called()


class SharesServiceTests(unittest.TestCase):
    def test_json_share_parser_normalizes_flags(self):
        payload = json.dumps({
            "Archive": {
                "path": "/Users/example/Archive",
                "smb_name": "Archive SMB",
                "smb_shared": "1",
                "smb_guest_access": 0,
                "smb_read_only": "false",
                "smb_sealed": True,
            }
        })
        with (
            patch("hub.shares_svc.sh", return_value=(0, payload, "")) as run,
            patch("hub.shares_svc.host_ip", return_value="192.0.2.20"),
        ):
            result = shares_svc.list_smb_shares(include_sizes=False)

        self.assertEqual(run.call_args.args[0], ["/usr/sbin/sharing", "-l", "-f", "json"])
        self.assertEqual(result, [{
            "record_name": "Archive",
            "name": "Archive",
            "path": "/Users/example/Archive",
            "smb_name": "Archive SMB",
            "shared": True,
            "guest": False,
            "readonly": False,
            "encrypted": True,
            "size_mb": None,
            "url": "smb://192.0.2.20/Archive SMB",
        }])

    def test_invalid_json_falls_back_to_legacy_output(self):
        legacy = """name: Public\npath: /Users/example/Public\nsmb:\n  name: Public\n  shared: 1\n  guest access: 1\n  read-only: 0\n}\n"""
        with (
            patch("hub.shares_svc.sh", side_effect=[(0, "{bad", ""), (0, legacy, "")]) as run,
            patch("hub.shares_svc.host_ip", return_value="host.local"),
        ):
            result = shares_svc.list_smb_shares(include_sizes=False)

        self.assertEqual(run.call_args_list, [
            call(["/usr/sbin/sharing", "-l", "-f", "json"], timeout=8),
            call(["/usr/sbin/sharing", "-l"], timeout=8),
        ])
        self.assertEqual(result[0]["record_name"], "Public")
        self.assertTrue(result[0]["guest"])

    def test_share_path_must_exist_and_rejects_runtime_and_system_roots(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            allowed = Path(temporary) / "Media"
            allowed.mkdir()
            self.assertEqual(shares_svc.validate_share_path(str(allowed)), allowed.resolve())
            with self.assertRaisesRegex(shares_svc.ShareValidationError, "shares.bad_path"):
                shares_svc.validate_share_path("relative/path")
            with self.assertRaisesRegex(shares_svc.ShareValidationError, "shares.protected_path"):
                shares_svc.validate_share_path(str(shares_svc.BASE))
            with self.assertRaisesRegex(shares_svc.ShareValidationError, "shares.protected_path"):
                shares_svc.validate_share_path(str(shares_svc.BASE.parent))
            with self.assertRaisesRegex(shares_svc.ShareValidationError, "shares.protected_path"):
                shares_svc.validate_share_path("/System")

    def test_share_names_reject_slashes_controls_and_empty_values(self):
        for value in ("", "a/b", "a\\b", "bad\nname", "x" * 65):
            with self.subTest(value=value), self.assertRaises(shares_svc.ShareValidationError):
                shares_svc._validate_name(value)

    def test_create_share_uses_fixed_argv_and_verifies_result(self):
        actual = {
            "record_name": "Media", "smb_name": "Media SMB", "shared": True,
            "guest": False, "readonly": True, "encrypted": True,
        }
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            folder = Path(temporary) / "Media"
            folder.mkdir()
            with (
                patch("hub.shares_svc._find_share", side_effect=[None, actual]),
                patch("hub.shares_svc.run_admin", return_value={"ok": True}) as admin,
            ):
                result = shares_svc.create_smb_share(
                    path=str(folder), name="Media", smb_name="Media SMB",
                    guest=False, readonly=True, encrypted=True,
                )

        self.assertTrue(result["ok"])
        self.assertEqual(admin.call_args.args[0], [
            "/usr/sbin/sharing", "-a", str(folder.resolve()), "-n", "Media",
            "-S", "Media SMB", "-s", "001", "-g", "000", "-R", "1", "-E", "1",
        ])

    def test_create_share_fails_when_system_state_does_not_match(self):
        actual = {
            "record_name": "Media", "smb_name": "Wrong", "shared": True,
            "guest": False, "readonly": False, "encrypted": False,
        }
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            folder = Path(temporary) / "Media"
            folder.mkdir()
            with (
                patch("hub.shares_svc._find_share", side_effect=[None, actual]),
                patch("hub.shares_svc.run_admin", return_value={"ok": True}),
            ):
                result = shares_svc.create_smb_share(
                    path=str(folder), name="Media", smb_name="Media",
                    guest=False, readonly=False, encrypted=False,
                )
        self.assertEqual(result["error"], "verification_failed")

    def test_remove_share_never_deletes_the_directory(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            marker = Path(temporary) / "keep.txt"
            marker.write_text("keep", encoding="utf-8")
            with (
                patch("hub.shares_svc._find_share", side_effect=[{"record_name": "Media"}, None]),
                patch("hub.shares_svc.run_admin", return_value={"ok": True}) as admin,
            ):
                result = shares_svc.remove_smb_share("Media")
            self.assertTrue(marker.exists())
        self.assertEqual(result, {"ok": True})
        admin.assert_called_once_with(["/usr/sbin/sharing", "-r", "Media"])

    def test_system_service_noop_skips_admin_prompt(self):
        current = {"id": "remote_login", "enabled": True}
        with (
            patch("hub.shares_svc.system_services", return_value=[current]),
            patch("hub.shares_svc.run_admin_sequence") as admin,
        ):
            result = shares_svc.set_system_service("remote_login", True)
        self.assertEqual(result, {"ok": True, "service": current})
        admin.assert_not_called()

    def test_system_service_command_is_allowlisted_and_verified(self):
        before = {"id": "remote_login", "enabled": False}
        after = {"id": "remote_login", "enabled": True}
        with (
            patch("hub.shares_svc.system_services", side_effect=[[before], [after]]),
            patch("hub.shares_svc.run_admin_sequence", return_value={"ok": True}) as admin,
        ):
            result = shares_svc.set_system_service("remote_login", True)
        self.assertTrue(result["ok"])
        admin.assert_called_once_with([[
            "/usr/sbin/systemsetup", "-setremotelogin", "on",
        ]])

    def test_admin_error_is_replaced_by_successful_state_verification(self):
        before = {"id": "screen_sharing", "enabled": False}
        after = {"id": "screen_sharing", "enabled": True}
        with (
            patch("hub.shares_svc.system_services", side_effect=[[before], [after]]),
            patch("hub.shares_svc.run_admin_sequence", return_value={"ok": False, "error": "failed"}),
        ):
            result = shares_svc.set_system_service("screen_sharing", True)
        self.assertEqual(result, {"ok": True, "service": after})

    def test_unknown_system_service_never_prompts(self):
        with patch("hub.shares_svc.run_admin_sequence") as admin:
            result = shares_svc.set_system_service("internet_sharing", True)
        self.assertEqual(result, {"ok": False, "error": "unknown_service"})
        admin.assert_not_called()

    def test_unknown_state_remains_unknown(self):
        with patch("hub.shares_svc.sh", return_value=(1, "", "permission denied")):
            enabled, detail = shares_svc._systemsetup_state("-getremotelogin", "com.openssh.sshd")
        self.assertIsNone(enabled)
        self.assertTrue(detail)


if __name__ == "__main__":
    unittest.main()
