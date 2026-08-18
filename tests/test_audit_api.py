"""Contract for the read-only auth-audit endpoint.

Writing the trail is only half of it: a log nobody can read is a log nobody
checks.  This pins the reader endpoint's behaviour.

The property that matters most is negative.  ``hub/audit.py`` drops secret-looking
fields on the way *in*, but a reader that re-derives entries from somewhere else,
or that grows a "raw" passthrough mode later, could still surface them.  So the
tests below assert against the response body of the real route, not against
``audit.record``'s return value -- the two are only the same thing as long as
nothing sits in between, and that is exactly what is being guarded.

Deliberately *not* asserted here: any change in who may call this. The endpoint
rides the same ``require_auth`` dependency as every other protected route, the
same way ``/api/terminal/history`` already exposes the command trail. Making the
audit reader admin-only is a change in authorisation semantics and is left for a
separate, deliberate decision.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import audit  # noqa: E402
from hub.routers import audit_api  # noqa: E402

PASSWORD = "sup3r-secret-pw"
SETUP_TOKEN = "t0ken-" + "x" * 40


class AuditSink:
    """Point the audit log at a scratch file for the duration of a block."""

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


class AuditReadEndpointTests(unittest.TestCase):
    def test_returns_recorded_entries_newest_last(self):
        with AuditSink():
            audit.record(audit.LOGIN_OK, username="admin", outcome="success")
            audit.record(audit.LOGOUT, username="admin", outcome="success")
            body = audit_api.auth_audit(limit=50)

        events = [e["event"] for e in body["entries"]]
        self.assertEqual(events, [audit.LOGIN_OK, audit.LOGOUT])

    def test_empty_log_returns_an_empty_list_not_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(audit, "AUDIT_PATH", Path(tmp) / "absent.jsonl"):
                body = audit_api.auth_audit(limit=50)
        self.assertEqual(body["entries"], [])

    def test_limit_bounds_the_response(self):
        with AuditSink():
            for i in range(10):
                audit.record(audit.LOGIN_OK, username=f"u{i}", outcome="success")
            body = audit_api.auth_audit(limit=3)

        got = [e["username"] for e in body["entries"]]
        self.assertEqual(got, ["u7", "u8", "u9"], "must return the newest window")

    def test_a_corrupt_line_does_not_break_the_reader(self):
        with AuditSink() as sink:
            audit.record(audit.LOGIN_OK, username="good", outcome="success")
            with sink.path.open("a", encoding="utf-8") as fh:
                fh.write("{ this is not json\n")
            audit.record(audit.LOGOUT, username="also-good", outcome="success")
            body = audit_api.auth_audit(limit=50)

        names = [e["username"] for e in body["entries"]]
        self.assertEqual(names, ["good", "also-good"])

    def test_a_json_array_line_does_not_break_the_reader(self):
        with AuditSink() as sink:
            audit.record(audit.LOGIN_OK, username="good", outcome="success")
            with sink.path.open("a", encoding="utf-8") as fh:
                fh.write("[]\n")
            body = audit_api.auth_audit(limit=50)

        names = [e["username"] for e in body["entries"]]
        self.assertEqual(names, ["good"])


class AuditReadRedactionTests(unittest.TestCase):
    """No secret may reach the client through this endpoint."""

    def test_password_and_token_are_absent_from_the_response(self):
        with AuditSink():
            # Exactly the shape the auth routes pass: the field names that carry
            # secrets are the ones redaction keys off.
            audit.record(
                audit.PASSWORD_CHANGED,
                username="admin",
                outcome="success",
                current_password=PASSWORD,
                new_password=PASSWORD + "-new",
                setup_token=SETUP_TOKEN,
            )
            body = audit_api.auth_audit(limit=50)

        blob = json.dumps(body, ensure_ascii=False)
        self.assertNotIn(PASSWORD, blob, "a password reached the audit API response")
        self.assertNotIn(SETUP_TOKEN, blob, "a setup token reached the audit API response")
        # The key itself is gone, not merely blanked: its presence would still
        # disclose that a secret was involved.
        entry = body["entries"][0]
        for key in ("current_password", "new_password", "setup_token"):
            self.assertNotIn(key, entry)
        # ...while the useful context survives.
        self.assertEqual(entry["username"], "admin")
        self.assertEqual(entry["event"], audit.PASSWORD_CHANGED)

    def test_a_secret_smuggled_onto_disk_is_still_withheld(self):
        """Defence in depth: the reader must not trust the file's contents.

        ``record`` is not the only way bytes can land in that file -- an operator
        edit, a future writer, or a partially-written line from an older build
        could all put a raw field there.  The reader is the last chance to stop
        it reaching a browser.
        """
        with AuditSink() as sink:
            with sink.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "ts": "2026-07-27T20:00:00+0800",
                    "event": audit.LOGIN_OK,
                    "username": "admin",
                    "password": PASSWORD,
                }, ensure_ascii=False) + "\n")
            body = audit_api.auth_audit(limit=50)

        blob = json.dumps(body, ensure_ascii=False)
        self.assertNotIn(
            PASSWORD,
            blob,
            "the reader must re-apply redaction, not assume the file is clean",
        )


class AuditRouteWiringTests(unittest.TestCase):
    """The endpoint has to actually be mounted, and stay read-only.

    Both tests read the OpenAPI schema rather than walking ``router.routes``.
    In this FastAPI version ``include_router`` stores an opaque
    ``_IncludedRouter`` node that carries no ``.path``, at every nesting level,
    so a scan for ``.path`` finds ``None`` for every entry and would pass or
    fail for reasons unrelated to whether the route exists.  The schema is the
    registry the app actually serves, which is the thing worth asserting on.
    """

    @staticmethod
    def _schema_paths() -> dict:
        from hub.app_factory import create_app

        return create_app().openapi().get("paths") or {}

    def test_route_is_registered_on_the_app(self):
        self.assertIn(
            "/api/audit/auth",
            self._schema_paths(),
            "the audit reader is not mounted, so nothing can call it",
        )

    def test_endpoint_exposes_no_mutating_method(self):
        entry = self._schema_paths().get("/api/audit/auth")
        self.assertIsNotNone(entry, "route not found")
        methods = {m.upper() for m in entry}
        self.assertEqual(
            methods - {"GET", "HEAD"},
            set(),
            "an audit trail that can be written or cleared over HTTP is not a trail",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
