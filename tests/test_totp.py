"""hub/totp.py against the published RFC vectors and its own contract.

The implementation is hand-rolled on hmac/struct/base64 (no dependency), so
the RFC 4226 Appendix D and RFC 6238 Appendix B tables are pinned here: any
change that still passes these is interoperable with every authenticator app,
and any change that breaks them is caught before it locks an operator out.
"""
from __future__ import annotations

import base64
import unittest

from hub import totp

#: RFC 4226/6238 shared test key: ASCII "12345678901234567890".
RFC_KEY_BYTES = b"12345678901234567890"
RFC_KEY_B32 = base64.b32encode(RFC_KEY_BYTES).decode()

#: RFC 4226 Appendix D — 6-digit HOTP values for counters 0-9.
HOTP_VECTORS = [
    "755224", "287082", "359152", "969429", "338314",
    "254676", "287922", "162583", "399871", "520489",
]

#: RFC 6238 Appendix B — SHA-1 rows (the mode this module implements), which
#: are specified with 8 digits.
TOTP_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


class HotpVectorTests(unittest.TestCase):
    def test_rfc4226_appendix_d(self):
        for counter, expected in enumerate(HOTP_VECTORS):
            with self.subTest(counter=counter):
                self.assertEqual(totp.hotp(RFC_KEY_BYTES, counter), expected)


class TotpVectorTests(unittest.TestCase):
    def test_rfc6238_appendix_b_sha1(self):
        for timestamp, expected in TOTP_VECTORS:
            with self.subTest(t=timestamp):
                self.assertEqual(
                    totp.totp_at(RFC_KEY_B32, timestamp, digits=8), expected
                )

    def test_verify_accepts_the_current_window(self):
        code = totp.totp_at(RFC_KEY_B32, 1111111111)
        matched = totp.verify(RFC_KEY_B32, code, timestamp=1111111111)
        self.assertEqual(matched, 1111111111 // 30)


class DriftWindowTests(unittest.TestCase):
    NOW = 1_700_000_000

    def test_one_step_of_drift_is_tolerated_each_way(self):
        for skew in (-30, 0, 30):
            with self.subTest(skew=skew):
                code = totp.totp_at(RFC_KEY_B32, self.NOW + skew)
                self.assertIsNotNone(
                    totp.verify(RFC_KEY_B32, code, timestamp=self.NOW)
                )

    def test_two_steps_of_drift_are_refused(self):
        for skew in (-60, 60):
            with self.subTest(skew=skew):
                code = totp.totp_at(RFC_KEY_B32, self.NOW + skew)
                self.assertIsNone(
                    totp.verify(RFC_KEY_B32, code, timestamp=self.NOW)
                )

    def test_verify_reports_the_matched_counter_not_the_current_one(self):
        code = totp.totp_at(RFC_KEY_B32, self.NOW - 30)
        self.assertEqual(
            totp.verify(RFC_KEY_B32, code, timestamp=self.NOW),
            (self.NOW - 30) // 30,
        )


class VerifyInputTests(unittest.TestCase):
    NOW = 1_700_000_000

    def test_malformed_codes_are_refused_without_raising(self):
        for bad in ("", "12345", "1234567", "abcdef", "12 34 5", None, "①②③④⑤⑥"):
            with self.subTest(code=bad):
                self.assertIsNone(totp.verify(RFC_KEY_B32, bad, timestamp=self.NOW))

    def test_spaces_inside_a_code_are_cosmetic(self):
        code = totp.totp_at(RFC_KEY_B32, self.NOW)
        spaced = f"{code[:3]} {code[3:]}"
        self.assertIsNotNone(totp.verify(RFC_KEY_B32, spaced, timestamp=self.NOW))

    def test_garbage_secret_is_a_refusal_not_a_crash(self):
        self.assertIsNone(totp.verify("not-base32!!!", "123456", timestamp=self.NOW))
        with self.assertRaises(ValueError):
            totp.decode_secret("")

    def test_leftover_inf_timestamp_does_not_500_verify(self):
        """``int(inf)`` OverflowError used to 500 TOTP confirm / login."""
        self.assertIsNone(totp.verify(RFC_KEY_B32, "000000", timestamp=float("inf")))
        self.assertIsNone(totp.verify(RFC_KEY_B32, "000000", timestamp=float("nan")))
        self.assertIsNone(totp.verify(RFC_KEY_B32, "000000", timestamp=1e20))
        self.assertIsNone(totp.verify(RFC_KEY_B32, "000000", timestamp=True))
        with self.assertRaises(ValueError):
            totp.totp_at(RFC_KEY_B32, float("inf"))


class SecretHandlingTests(unittest.TestCase):
    def test_generated_secret_is_160_bit_base32(self):
        secret = totp.generate_secret()
        self.assertEqual(len(secret), 32)
        self.assertEqual(len(totp.decode_secret(secret)), totp.SECRET_BYTES)

    def test_decode_tolerates_human_formatting(self):
        canonical = totp.decode_secret(RFC_KEY_B32)
        grouped = totp.manual_entry_groups(RFC_KEY_B32)
        for variant in (RFC_KEY_B32.lower(), grouped, grouped.replace(" ", "-")):
            with self.subTest(variant=variant):
                self.assertEqual(totp.decode_secret(variant), canonical)

    def test_otpauth_uri_carries_the_pairing_parameters(self):
        uri = totp.otpauth_uri("ABC234", "family admin", issuer="ServerHub")
        self.assertTrue(uri.startswith("otpauth://totp/ServerHub%3Afamily%20admin?"))
        self.assertIn("secret=ABC234", uri)
        self.assertIn("issuer=ServerHub", uri)
        self.assertIn("digits=6", uri)
        self.assertIn("period=30", uri)
        self.assertIn("algorithm=SHA1", uri)


if __name__ == "__main__":
    unittest.main()
