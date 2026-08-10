"""Audit records for authentication events.

Today only command execution (terminal, VM console) is audited.  Sign-in,
sign-out, failed sign-in, the first-run setup claim and password rotation leave
no trace at all, so "who got into this panel, and when" is unanswerable -- which
is exactly the question a second household account creates.

Two properties matter more than the record's shape and are pinned first:

  1. **A password must never reach the log.**  These handlers receive plaintext
     passwords and a setup token in the request body.  An audit record built
     from "the request" rather than from named fields would persist them to a
     file that is kept forever.

  2. **Logging must never break the request.**  A full disk or a bad permission
     must not turn a valid sign-in into a 500.

The assertions target observable behaviour -- an entry exists, it names the
account, it does not contain the secret -- rather than a byte layout, so the
record can gain fields later without rewriting these tests.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException, Request, Response

from hub import audit


PASSWORD = "test-password"
NEW_PASSWORD = "new-test-password"
SETUP_TOKEN = "setup-token-placeholder-0000000000"


def request(client: str = "192.0.2.10") -> Request:
    return Request({
        "type": "http",
        "method": "POST",
        "path": "/api/auth/login",
        "headers": [(b"user-agent", b"pytest-agent/1.0")],
        "scheme": "http",
        "server": ("localhost", 8086),
        "client": (client, 51234),
    })


class AuditSink:
    """Redirect the audit log into a temp file for one test."""

    def __enter__(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "auth-audit.jsonl"
        self._patch = patch.object(audit, "AUDIT_PATH", self.path)
        self._patch.start()
        return self

    def __exit__(self, *exc):
        self._patch.stop()
        self._tmp.cleanup()
        return False

    def entries(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [
            json.loads(line)
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def raw(self) -> str:
        return self.path.read_text(encoding="utf-8") if self.path.exists() else ""


class RedactionTests(unittest.TestCase):
    """The log must be safe to keep forever."""

    def test_a_password_never_reaches_the_log(self):
        with AuditSink() as sink:
            audit.record(
                "auth.login",
                username="admin",
                outcome="success",
                request=request(),
                password=PASSWORD,
                current_password=PASSWORD,
                new_password=NEW_PASSWORD,
                setup_token=SETUP_TOKEN,
            )
            blob = sink.raw()

        for secret in (PASSWORD, NEW_PASSWORD, SETUP_TOKEN):
            self.assertNotIn(
                secret,
                blob,
                "a credential supplied in the request body must never be "
                "persisted to the audit log",
            )

    def test_sensitive_keys_are_dropped_not_merely_masked_in_value(self):
        with AuditSink() as sink:
            audit.record("auth.login", username="admin", token="abc123secret")
            entry = sink.entries()[0]
        self.assertNotIn("token", entry)
        self.assertNotIn("abc123secret", json.dumps(entry))

    def test_non_sensitive_context_is_kept(self):
        with AuditSink() as sink:
            audit.record(
                "auth.login", username="mom", outcome="success", client="192.0.2.10"
            )
            entry = sink.entries()[0]
        self.assertEqual(entry["event"], "auth.login")
        self.assertEqual(entry["username"], "mom")
        self.assertEqual(entry["outcome"], "success")
        self.assertEqual(entry["client"], "192.0.2.10")


class DurabilityTests(unittest.TestCase):
    """Auditing is best-effort: it observes, it does not gate."""

    def test_an_unwritable_log_does_not_raise(self):
        with patch.object(audit, "AUDIT_PATH", Path("/proc/nonexistent/audit.jsonl")):
            # Must not raise: a failed write cannot turn a valid sign-in into 500.
            audit.record("auth.login", username="admin", outcome="success")

    def test_log_is_owner_only(self):
        with AuditSink() as sink:
            audit.record("auth.login", username="admin")
            mode = sink.path.stat().st_mode & 0o777
        self.assertEqual(
            mode,
            0o600,
            "the audit log names accounts and client addresses; it must not be "
            "world-readable",
        )

    def test_entries_append_rather_than_overwrite(self):
        with AuditSink() as sink:
            audit.record("auth.login", username="a")
            audit.record("auth.logout", username="a")
            self.assertEqual([e["event"] for e in sink.entries()],
                             ["auth.login", "auth.logout"])

    def test_every_entry_carries_a_timestamp(self):
        with AuditSink() as sink:
            audit.record("auth.login", username="admin")
            entry = sink.entries()[0]
        self.assertIn("ts", entry)
        self.assertRegex(str(entry["ts"]), r"^\d{4}-\d{2}-\d{2}T")


class AuthEventCoverageTests(unittest.TestCase):
    """Each auth route must leave a record."""

    def _auth_cfg(self):
        return {
            "enabled": True,
            "username": "admin",
            "password_hash": "scrypt$fake",
        }

    def test_successful_login_is_recorded(self):
        from hub.routers import auth_api

        with AuditSink() as sink:
            with (
                patch("hub.auth.setup_required", return_value=False),
                patch("hub.auth.login_allowed", return_value=(True, 0)),
                patch("hub.auth.verify_password", return_value=True),
                patch("hub.auth.clear_login_failures"),
                patch("hub.auth.create_session", return_value="tok"),
                patch.object(auth_api.auth, "_auth_cfg", self._auth_cfg),
            ):
                auth_api.auth_login(
                    auth_api.LoginBody(username="admin", password=PASSWORD),
                    request(),
                    Response(),
                )
            events = [e["event"] for e in sink.entries()]
            blob = sink.raw()

        self.assertIn(audit.LOGIN_OK, events)
        self.assertNotIn(PASSWORD, blob)

    def test_failed_login_is_recorded_with_the_attempted_name(self):
        from hub.routers import auth_api

        with AuditSink() as sink:
            with (
                patch("hub.auth.setup_required", return_value=False),
                patch("hub.auth.login_allowed", return_value=(True, 0)),
                patch("hub.auth.verify_password", return_value=False),
                patch("hub.auth.record_login_failure"),
                patch.object(auth_api.auth, "_auth_cfg", self._auth_cfg),
            ):
                with self.assertRaises(HTTPException):
                    auth_api.auth_login(
                        auth_api.LoginBody(username="admin", password="wrong-password"),
                        request(),
                        Response(),
                    )
            entries = sink.entries()
            blob = sink.raw()

        failures = [e for e in entries if e.get("outcome") == "failure"]
        self.assertTrue(
            failures,
            "a rejected sign-in is the event most worth recording; brute force "
            "is invisible without it",
        )
        self.assertNotIn("wrong-password", blob)

    def test_rate_limited_login_is_recorded(self):
        from hub.routers import auth_api

        with AuditSink() as sink:
            with (
                patch("hub.auth.setup_required", return_value=False),
                patch("hub.auth.login_allowed", return_value=(False, 42)),
                patch.object(auth_api.auth, "_auth_cfg", self._auth_cfg),
            ):
                with self.assertRaises(HTTPException):
                    auth_api.auth_login(
                        auth_api.LoginBody(username="admin", password=PASSWORD),
                        request(),
                        Response(),
                    )
            events = [e["event"] for e in sink.entries()]

        self.assertIn(audit.LOGIN_RATE_LIMITED, events)

    def test_logout_is_recorded(self):
        from hub.routers import auth_api

        with AuditSink() as sink:
            auth_api.auth_logout(request(), Response())
            events = [e["event"] for e in sink.entries()]
        self.assertIn(audit.LOGOUT, events)

    def test_password_change_is_recorded_without_either_password(self):
        from hub.routers import auth_api

        with AuditSink() as sink:
            with (
                patch("hub.auth.setup_required", return_value=False),
                patch("hub.auth.browser_authenticated", return_value=True),
                patch("hub.auth.request_username", return_value="admin"),
                patch("hub.auth.is_admin", return_value=True),
                patch("hub.auth.login_allowed", return_value=(True, 0)),
                patch(
                    "hub.auth.verify_password",
                    side_effect=lambda pw: pw == PASSWORD,
                ),
                patch("hub.auth.set_password"),
                patch("hub.auth.clear_login_failures"),
                patch("hub.auth.create_session", return_value="tok"),
                patch.object(auth_api.auth, "_auth_cfg", self._auth_cfg),
            ):
                auth_api.auth_change_password(
                    auth_api.ChangePasswordBody(
                        username="admin",
                        current_password=PASSWORD,
                        new_password=NEW_PASSWORD,
                    ),
                    request(),
                    Response(),
                )
            events = [e["event"] for e in sink.entries()]
            blob = sink.raw()

        self.assertIn(audit.PASSWORD_CHANGED, events)
        self.assertNotIn(PASSWORD, blob)
        self.assertNotIn(NEW_PASSWORD, blob)

    def test_setup_claim_is_recorded_without_the_token(self):
        from hub.routers import auth_api

        with AuditSink() as sink:
            with (
                patch("hub.auth.setup_required", return_value=True),
                patch("hub.auth.complete_setup", return_value=True),
                patch("hub.auth.create_session", return_value="tok"),
            ):
                auth_api.auth_setup(
                    auth_api.SetupBody(
                        username="admin",
                        password=PASSWORD,
                        setup_token=SETUP_TOKEN,
                    ),
                    request(),
                    Response(),
                )
            events = [e["event"] for e in sink.entries()]
            blob = sink.raw()

        self.assertIn(audit.SETUP_CLAIMED, events)
        self.assertNotIn(SETUP_TOKEN, blob)
        self.assertNotIn(PASSWORD, blob)


class AuditReaderTests(unittest.TestCase):
    """Reading the log back is what makes it useful."""

    def test_recent_returns_newest_last_and_respects_the_limit(self):
        with AuditSink():
            for i in range(5):
                audit.record("auth.login", username=f"u{i}")
            got = audit.recent(limit=3)
        self.assertEqual([e["username"] for e in got], ["u2", "u3", "u4"])

    def test_recent_survives_a_corrupt_line(self):
        with AuditSink() as sink:
            audit.record("auth.login", username="good")
            with sink.path.open("a", encoding="utf-8") as fh:
                fh.write("{not json\n")
            audit.record("auth.logout", username="also-good")
            got = audit.recent()
        self.assertEqual([e["username"] for e in got], ["good", "also-good"])

    def test_recent_on_a_missing_log_is_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(audit, "AUDIT_PATH", Path(tmp) / "nope.jsonl"):
                self.assertEqual(audit.recent(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
