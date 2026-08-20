"""hub/twofa_svc.py: enrollment lifecycle, replay defence, recovery codes.

Everything runs against a scratch store file; nothing touches data/twofa.json.
"""
from __future__ import annotations

import json
import os
import stat
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from hub import totp, twofa_svc

NOW = 1_700_000_000


def code_at(secret: str, timestamp: int) -> str:
    return totp.totp_at(secret, timestamp)


class _Sandbox(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = Path(tmp.name) / "twofa.json"
        patcher = mock.patch.object(twofa_svc, "STORE_FILE", self.store)
        patcher.start()
        self.addCleanup(patcher.stop)

    def enroll(self, username="admin", timestamp=NOW):
        enrollment = twofa_svc.begin_enrollment(username)
        secret = enrollment["secret"]
        codes = twofa_svc.confirm_enrollment(
            username, code_at(secret, timestamp), timestamp=timestamp
        )
        return secret, codes


class EnrollmentTests(_Sandbox):
    def test_non_list_recovery_does_not_500_status(self):
        self.store.write_text(json.dumps({
            "admin": {"enabled": True, "recovery": 3},
        }))
        self.assertEqual(twofa_svc.status("admin")["recovery_remaining"], 0)

    def test_non_object_user_row_does_not_500_status(self):
        self.store.write_text(json.dumps({"admin": ["not", "a", "mapping"]}))
        self.assertFalse(twofa_svc.enabled("admin"))
        self.assertEqual(twofa_svc.status("admin")["enabled"], False)
        # Enrollment must replace the garbage row, not ``dict([...])``.
        twofa_svc.begin_enrollment("admin")
        self.assertTrue(twofa_svc.status("admin")["pending"])

    def test_pending_enrollment_enforces_nothing(self):
        twofa_svc.begin_enrollment("admin")
        self.assertFalse(twofa_svc.enabled("admin"))
        status = twofa_svc.status("admin")
        self.assertTrue(status["pending"])
        self.assertFalse(status["enabled"])

    def test_wrong_confirmation_code_does_not_enable(self):
        twofa_svc.begin_enrollment("admin")
        self.assertIsNone(
            twofa_svc.confirm_enrollment("admin", "000000", timestamp=NOW)
        )
        self.assertFalse(twofa_svc.enabled("admin"))

    def test_valid_confirmation_enables_and_mints_recovery_codes(self):
        secret, codes = self.enroll()
        self.assertTrue(twofa_svc.enabled("admin"))
        self.assertEqual(len(codes), twofa_svc.RECOVERY_CODES)
        self.assertEqual(len(set(codes)), len(codes))
        status = twofa_svc.status("admin")
        self.assertEqual(status["recovery_remaining"], len(codes))
        self.assertFalse(status["pending"])

    def test_confirm_without_enrollment_raises(self):
        with self.assertRaises(twofa_svc.NotPending):
            twofa_svc.confirm_enrollment("admin", "123456", timestamp=NOW)

    def test_enroll_while_enabled_raises(self):
        self.enroll()
        with self.assertRaises(twofa_svc.AlreadyEnabled):
            twofa_svc.begin_enrollment("admin")

    def test_reenrollment_replaces_the_pending_secret(self):
        first = twofa_svc.begin_enrollment("admin")["secret"]
        second = twofa_svc.begin_enrollment("admin")["secret"]
        self.assertNotEqual(first, second)
        # Only the latest pending secret confirms.
        self.assertIsNone(
            twofa_svc.confirm_enrollment("admin", code_at(first, NOW), timestamp=NOW)
        )
        self.assertIsNotNone(
            twofa_svc.confirm_enrollment("admin", code_at(second, NOW), timestamp=NOW)
        )

    def test_store_file_is_owner_only(self):
        self.enroll()
        mode = stat.S_IMODE(os.stat(self.store).st_mode)
        self.assertEqual(mode, 0o600)

    def test_status_and_store_shape(self):
        secret, _codes = self.enroll()
        # The status view (what the API returns) never carries the secret.
        self.assertNotIn("secret", twofa_svc.status("admin"))
        # The store itself must keep it (TOTP needs the reversible secret).
        stored = json.loads(self.store.read_text())
        self.assertEqual(stored["admin"]["secret"], secret)


class ReplayTests(_Sandbox):
    def test_a_code_is_single_use_within_its_window(self):
        secret, _ = self.enroll(timestamp=NOW)
        code = code_at(secret, NOW + 60)
        self.assertTrue(twofa_svc.verify_totp_code("admin", code, timestamp=NOW + 60))
        # Same code, same window: replay refused.
        self.assertFalse(twofa_svc.verify_totp_code("admin", code, timestamp=NOW + 60))

    def test_confirmation_code_itself_cannot_be_replayed_for_login(self):
        secret, _ = self.enroll(timestamp=NOW)
        self.assertFalse(
            twofa_svc.verify_totp_code("admin", code_at(secret, NOW), timestamp=NOW)
        )

    def test_older_window_is_refused_after_a_newer_acceptance(self):
        secret, _ = self.enroll(timestamp=NOW)
        newer = code_at(secret, NOW + 90)
        self.assertTrue(twofa_svc.verify_totp_code("admin", newer, timestamp=NOW + 90))
        older = code_at(secret, NOW + 60)
        self.assertFalse(twofa_svc.verify_totp_code("admin", older, timestamp=NOW + 90))

    def test_drift_window_still_verifies_a_neighbouring_code(self):
        secret, _ = self.enroll(timestamp=NOW)
        # Phone 30s behind the server.
        behind = code_at(secret, NOW + 570)
        self.assertTrue(twofa_svc.verify_totp_code("admin", behind, timestamp=NOW + 600))

    def test_disabled_account_never_verifies(self):
        self.assertFalse(twofa_svc.verify_totp_code("admin", "123456", timestamp=NOW))


class RecoveryCodeTests(_Sandbox):
    def test_recovery_codes_are_one_time(self):
        _, codes = self.enroll()
        code = codes[0]
        self.assertTrue(twofa_svc.use_recovery_code("admin", code))
        self.assertFalse(twofa_svc.use_recovery_code("admin", code))
        self.assertEqual(
            twofa_svc.status("admin")["recovery_remaining"], len(codes) - 1
        )

    def test_recovery_codes_are_stored_hashed(self):
        _, codes = self.enroll()
        raw = self.store.read_text()
        for code in codes:
            self.assertNotIn(code, raw)
            self.assertNotIn(code.replace("-", ""), raw)

    def test_recovery_input_is_case_and_dash_insensitive(self):
        _, codes = self.enroll()
        sloppy = codes[0].lower().replace("-", " ")
        self.assertTrue(twofa_svc.use_recovery_code("admin", sloppy))

    def test_unknown_recovery_code_is_refused(self):
        self.enroll()
        self.assertFalse(twofa_svc.use_recovery_code("admin", "AAAAA-AAAAA"))

    def test_typed_wrong_secret_and_codes_do_not_500_login(self):
        """A leftover list secret or plaintext recovery used to raise on login."""
        self.store.write_text(json.dumps({
            "admin": {
                "enabled": True,
                "secret": ["not", "a", "string"],
                "recovery": ["PLAIN-CODE", 3, {"h": 1}, "cafe" + "é"],
                "last_counter": "oops",
            },
        }))
        self.assertFalse(twofa_svc.verify_totp_code("admin", "123456", timestamp=NOW))
        self.assertFalse(twofa_svc.use_recovery_code("admin", "AAAAA-AAAAA"))
        self.assertIsNone(twofa_svc.verify_second_factor("admin", "123456"))

    def test_json_1e309_last_counter_and_confirmed_at_do_not_500(self):
        """JSON ``1e309`` is inf; ``int(inf)`` 500'd TOTP login, and
        confirmed_at inf 500'd GET /api/auth/totp (allow_nan=False)."""
        secret, codes = self.enroll(timestamp=NOW)
        raw = json.loads(self.store.read_text())
        huge = json.loads("1e309")
        raw["admin"]["last_counter"] = huge
        raw["admin"]["confirmed_at"] = huge
        self.store.write_text(json.dumps(raw))
        status = twofa_svc.status("admin")
        json.dumps(status, allow_nan=False)
        self.assertIsNone(status["confirmed_at"])
        code = code_at(secret, NOW + 60)
        self.assertTrue(twofa_svc.verify_totp_code("admin", code, timestamp=NOW + 60))
        # A successful verify must not rewrite Infinity and poison the store.
        stored = json.loads(self.store.read_text())
        self.assertIsInstance(stored["admin"]["last_counter"], int)
        self.assertNotEqual(stored["admin"]["confirmed_at"], huge)

    def test_lone_surrogate_recovery_code_does_not_500(self):
        self.enroll()
        self.assertFalse(twofa_svc.use_recovery_code("admin", "\ud800"))
        self.assertIsNone(twofa_svc.verify_second_factor("admin", "\ud800"))

    def test_save_dumps_recursion_does_not_500(self):
        """json.dumps RecursionError is not OSError; enroll used to 500."""
        with mock.patch.object(twofa_svc.json, "dumps", side_effect=RecursionError):
            twofa_svc._save({"admin": {"enabled": True, "secret": "A"}})
        self.assertFalse(self.store.exists())

    def test_regeneration_invalidates_every_old_code(self):
        _, old = self.enroll()
        new = twofa_svc.regenerate_recovery("admin")
        self.assertEqual(len(new), twofa_svc.RECOVERY_CODES)
        self.assertFalse(twofa_svc.use_recovery_code("admin", old[0]))
        self.assertTrue(twofa_svc.use_recovery_code("admin", new[0]))

    def test_regeneration_requires_enabled(self):
        with self.assertRaises(twofa_svc.NotEnabled):
            twofa_svc.regenerate_recovery("admin")

    def test_second_factor_accepts_either_kind(self):
        secret, codes = self.enroll(timestamp=NOW)
        self.assertEqual(
            twofa_svc.verify_second_factor(
                "admin", code_at(secret, NOW + 60), timestamp=NOW + 60
            ),
            "totp",
        )
        self.assertEqual(twofa_svc.verify_second_factor("admin", codes[0]), "recovery")
        self.assertIsNone(twofa_svc.verify_second_factor("admin", "000000"))


class DisableTests(_Sandbox):
    def test_disable_clears_all_state(self):
        self.enroll()
        self.assertTrue(twofa_svc.disable("admin"))
        self.assertFalse(twofa_svc.enabled("admin"))
        self.assertEqual(twofa_svc.status("admin")["recovery_remaining"], 0)
        self.assertNotIn("admin", json.loads(self.store.read_text()))

    def test_disable_reports_whether_anything_was_enabled(self):
        self.assertFalse(twofa_svc.disable("admin"))
        twofa_svc.begin_enrollment("admin")
        # Pending-only state is dropped too, but it was never enabled.
        self.assertFalse(twofa_svc.disable("admin"))

    def test_accounts_are_independent(self):
        self.enroll("admin")
        secret_b, _ = self.enroll("kid")
        twofa_svc.disable("admin")
        self.assertTrue(twofa_svc.enabled("kid"))
        self.assertTrue(
            twofa_svc.verify_totp_code("kid", code_at(secret_b, NOW + 60), timestamp=NOW + 60)
        )


if __name__ == "__main__":
    unittest.main()
