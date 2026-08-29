"""Audit listing leftover sweep: hostile lists/mappings on GET /api/audit/auth.

hub/audit.py already fail-closes record()/recent() shaping.  The read-only
route still did ``[redact(e) for e in recent(limit)]`` with no net, so a
leftover mapping (list-comp walks keys), a list subclass whose iterator
bombs, or a redact() raise on one row 500'd the whole page.  The route now
fail-closes those shapes and keeps honest sibling rows.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import audit
from hub.app_factory import create_app
from hub.auth import require_auth
from hub.routers import audit_api

_APP = None


def _client() -> TestClient:
    global _APP
    if _APP is None:
        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _Watchdog(BaseException):
    """BaseException-shaped leftover that is not Exception."""


class _IterBomb(list):
    def __iter__(self):
        raise RuntimeError("iter-bomb")


class AuditListingLeftoverTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="audit15-listing-"))
        self.path = self.dir / "auth-audit.jsonl"
        patched = mock.patch.object(audit, "AUDIT_PATH", self.path)
        patched.start()
        self.addCleanup(patched.stop)
        self.addCleanup(shutil.rmtree, self.dir, True)

    def test_mapping_from_recent_is_empty_page_not_500(self):
        with mock.patch.object(audit, "recent", return_value={"0": {"event": "x"}}):
            body = audit_api.auth_audit(limit=50)
        self.assertEqual(body["entries"], [])
        self.assertEqual(body["count"], 0)
        _starlette(body)
        r = _client().get("/api/audit/auth")
        self.assertNotEqual(r.status_code, 500)

    def test_recent_raise_is_empty_page_not_500(self):
        def _boom(_limit=100):
            raise RuntimeError("recent-bomb")

        with mock.patch.object(audit, "recent", side_effect=_boom):
            body = audit_api.auth_audit(limit=50)
        self.assertEqual(body["entries"], [])
        _starlette(body)

    def test_iter_bomb_list_is_empty_page_not_500(self):
        with mock.patch.object(audit, "recent", return_value=_IterBomb([{"event": "x"}])):
            body = audit_api.auth_audit(limit=50)
        self.assertEqual(body["entries"], [])
        _starlette(body)

    def test_non_mapping_rows_drop_honest_sibling_stays(self):
        honest = {
            "ts": "2026-08-19T12:00:00+0000",
            "event": "panel.event",
            "username": "alice",
            "outcome": "success",
        }
        with mock.patch.object(
            audit,
            "recent",
            return_value=[None, "nope", ["nested"], honest],
        ):
            body = audit_api.auth_audit(limit=50)
        self.assertEqual(len(body["entries"]), 1)
        self.assertEqual(body["entries"][0]["username"], "alice")
        _starlette(body)

    def test_redact_bomb_row_drops_honest_sibling_stays(self):
        honest = {
            "ts": "2026-08-19T12:00:00+0000",
            "event": "panel.event",
            "username": "bob",
            "outcome": "success",
        }
        real = audit.redact

        def _redact(value, _depth=0):
            if isinstance(value, dict) and value.get("event") == "bomb":
                raise _Watchdog("redact-bomb")
            return real(value, _depth)

        with mock.patch.object(audit, "redact", side_effect=_redact), mock.patch.object(
            audit,
            "recent",
            return_value=[{"event": "bomb"}, honest],
        ):
            body = audit_api.auth_audit(limit=50)
        names = [e.get("username") for e in body["entries"]]
        self.assertIn("bob", names)
        self.assertNotIn("bomb", [e.get("event") for e in body["entries"]])
        _starlette(body)

    def test_honest_disk_rows_still_list(self):
        audit.record("panel.event", username="carol", outcome="success")
        body = audit_api.auth_audit(limit=50)
        self.assertEqual(body["entries"][0]["username"], "carol")
        self.assertEqual(body["count"], 1)
        _starlette(body)
        r = _client().get("/api/audit/auth?limit=50")
        self.assertEqual(r.status_code, 200)
        _starlette(r.json())
