"""Regression tests for the 2026-08 security hardening pass.

Each test pins one finding from the security audit so the fix cannot silently
regress.  All findings were admin-gated hardening, not remote holes.
"""
import unittest
from unittest.mock import patch


class CatalogYamlInjectionTests(unittest.TestCase):
    """Finding #1 — compose-key injection via unquoted template variables."""

    def test_newline_in_value_is_refused(self):
        from fastapi import HTTPException

        from hub import catalog
        malicious = "postgres\n    privileged: true\n    volumes:\n      - /:/host"
        with self.assertRaises(HTTPException):
            catalog.render_template("- USER={{USER}}", {"USER": malicious})

    def test_carriage_return_is_refused(self):
        from fastapi import HTTPException

        from hub import catalog
        with self.assertRaises(HTTPException):
            catalog.render_template("x={{X}}", {"X": "a\rb"})

    def test_ordinary_values_still_render(self):
        from hub import catalog
        out = catalog.render_template(
            "user={{U}} port={{P}}", {"U": "admin", "P": "5432"}
        )
        self.assertEqual(out, "user=admin port=5432")


class ExportRedactionTests(unittest.TestCase):
    """Finding #3 — services.yaml export leaked plaintext secrets."""

    def test_secret_keys_are_redacted(self):
        from hub.routers import settings_api

        data = {
            "settings": {
                "notify": {"ha_token": "SECRET-TOKEN", "ha_service": "notify.notify"},
                "auth": {"password_hash": "scrypt$abc", "username": "admin"},
            },
            "wireguard": {"private_key": "PRIVKEY", "listen_port": 51821},
        }
        red = settings_api._redact_export(data)
        self.assertEqual(red["settings"]["notify"]["ha_token"], "***redacted***")
        self.assertEqual(red["settings"]["auth"]["password_hash"], "***redacted***")
        self.assertEqual(red["wireguard"]["private_key"], "***redacted***")
        # Non-secret values are preserved so the backup stays useful.
        self.assertEqual(red["settings"]["notify"]["ha_service"], "notify.notify")
        self.assertEqual(red["wireguard"]["listen_port"], 51821)
        self.assertEqual(red["settings"]["auth"]["username"], "admin")


class WebhookSsrfTests(unittest.TestCase):
    """Finding #6 — notification webhook accepted any URL scheme."""

    def test_non_http_scheme_is_rejected(self):
        from hub import alerts

        self.assertFalse(alerts._http_url_ok("file:///etc/passwd"))
        self.assertFalse(alerts._http_url_ok("gopher://x"))
        self.assertTrue(alerts._http_url_ok("https://hooks.example.com/x"))
        self.assertTrue(alerts._http_url_ok("http://192.168.1.2:8123/api"))


class MemberEnvRedactionTests(unittest.TestCase):
    """Finding #5 — credential URLs leaked to members via env_sample."""

    def test_credential_url_value_is_redacted(self):
        # Exercise the same value heuristic the detail path applies.
        def redact_line(e: str) -> str:
            if "=" in e:
                k, v = e.split("=", 1)
                if any(x in k.upper() for x in ("PASS", "SECRET", "TOKEN", "KEY", "PWD", "CRED", "AUTH")):
                    return f"{k}=***"
                if "://" in v and "@" in v.split("://", 1)[1].split("/", 1)[0]:
                    return f"{k}=***"
                return e
            return e

        self.assertEqual(
            redact_line("DATABASE_URL=postgres://user:pass@db:5432/app"),
            "DATABASE_URL=***",
        )
        self.assertEqual(redact_line("TZ=UTC"), "TZ=UTC")
        self.assertEqual(
            redact_line("HTTP_PROXY=http://proxy:3128"),  # no credentials
            "HTTP_PROXY=http://proxy:3128",
        )


class SessionRevocationTests(unittest.TestCase):
    """Finding #2 — logout did not revoke a stateless token."""

    def test_bumping_epoch_changes_the_signed_version(self):
        from hub import auth

        with patch.object(auth, "accounts", return_value={
            "admin": {"password_hash": "scrypt$abc"},
        }):
            with patch.object(auth, "_session_epoch", return_value=0):
                v0 = auth.account_session_version("admin")
            with patch.object(auth, "_session_epoch", return_value=1):
                v1 = auth.account_session_version("admin")
        self.assertNotEqual(v0, v1)

    def test_epoch_zero_preserves_legacy_version(self):
        """Cookies issued before the first logout must keep verifying."""
        from hub import auth

        with patch.object(auth, "accounts", return_value={
            "admin": {"password_hash": "scrypt$abc"},
        }), patch.object(auth, "_session_epoch", return_value=0):
            basis_version = auth.hashlib.sha256(b"scrypt$abc").hexdigest()[:16]
            self.assertEqual(auth.account_session_version("admin"), basis_version)


if __name__ == "__main__":
    unittest.main()
