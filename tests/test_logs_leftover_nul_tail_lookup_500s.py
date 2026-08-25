"""Leftover Logs tail 500s / silently-untailable sources.

Two classes reproduced on the real routes before this sweep:

* **NUL-path tail 500.**  A hand-edited ``log_sources`` path carrying an
  embedded NUL listed fine in GET /api/logs (``exists: false`` — pathlib's
  ``is_file`` swallows the ValueError), but GET /api/logs/{id} mapped the
  ``Path.resolve()`` ValueError to the coded-500 ``logs.read_failed``
  although no read was ever attempted.  Such a path can never name an
  on-disk file, so the tail now gives the same answer the listing gives:
  the 200 ``exists: false`` / "(file does not exist)" payload.

* **Listed-but-untailable ids.**  ``tail_log`` gated its id through
  ``cli_args.require_positional`` — an argv-injection guard — although a
  source id is only ever a dict key (the tail is a plain ``os.open``, no
  subprocess).  A configured ``id: 日志`` (the panel defaults to zh-CN) or
  ``id: my log`` was listed by GET /api/logs yet 400'd its own tail, on
  the Logs page and in the Services script-log fallback that feeds
  ``log_sources`` ids straight back into ``tail_log``.  The gate is now a
  lookup-shaped one: scrub through ``_utf8_text`` *before* the dict-key
  compare (leftover lone surrogates must match the replace-encoded key
  they were listed under), coerce non-str via the ``_config_text``
  ``str()`` probe (int ``42`` matches the ``"42"`` the listing publishes
  for ``id: 0x2A``; bool and >4300-digit leftovers match nothing), and
  answer anything unmatched — including option-like junk — with the
  honest 404.

Stays-immune pins ride along for the vectors this sweep probed and found
already guarded: protected paths still refuse the tail after the gate
loosened, traversal-shaped ids cannot match a listing key, an over-cap
digit ``lines`` query is pydantic's 422 (never a digit-cap 500), and
invalid-UTF-8 log *content* re-encodes through the real route.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from fastapi import HTTPException  # noqa: E402

from hub import logs_svc  # noqa: E402

#: Built arithmetically: int("9" * 5000) itself trips the parse cap.
_HUGE_INT = 10 ** 5000


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does to the body."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from hub.routers.logs import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


def _code(exc: HTTPException) -> str:
    detail = exc.detail
    return detail.get("code") if isinstance(detail, dict) else detail


class LogsTailBase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="logs-tail-pin-")
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.log_path = self.dir / "pin.log"
        self.log_path.write_text("alpha\nbeta\n", encoding="utf-8")

    def _with_sources(self, sources):
        return mock.patch.object(
            logs_svc, "cfg", lambda: {"log_sources": sources},
        )


class NulPathTailTests(LogsTailBase):
    """A NUL-path source answers its tail like its listing: exists false."""

    def test_nul_path_lists_missing_and_tails_200_not_500(self):
        with self._with_sources([
            {"id": "nul", "name": "NUL", "path": "/tmp/leftover\x00junk.log"},
            {"id": "ok", "name": "OK", "path": str(self.log_path)},
        ]):
            listing = _client().get("/api/logs")
            tail = _client().get("/api/logs/nul")
        self.assertEqual(listing.status_code, 200)
        by_id = {r["id"]: r for r in listing.json()["sources"]}
        self.assertFalse(by_id["nul"]["exists"])
        # The reproduced leftover: this was a coded 500 (logs.read_failed)
        # although no read was ever attempted.
        self.assertEqual(tail.status_code, 200)
        body = tail.json()
        self.assertFalse(body["exists"])
        self.assertEqual(body["log"], "(file does not exist)")
        self.assertEqual(body["lines"], 0)
        _starlette(body)

    def test_nul_path_sibling_still_tails(self):
        with self._with_sources([
            {"id": "nul", "name": "NUL", "path": "/tmp/leftover\x00junk.log"},
            {"id": "ok", "name": "OK", "path": str(self.log_path)},
        ]):
            tail = _client().get("/api/logs/ok")
        self.assertEqual(tail.status_code, 200)
        self.assertIn("beta", tail.json()["log"])


class ListedIdStaysTailableTests(LogsTailBase):
    """Every id GET /api/logs publishes must be acceptable to its tail."""

    def test_unicode_id_listed_by_the_panel_tails_through_the_route(self):
        with self._with_sources([
            {"id": "日志", "name": "面板", "path": str(self.log_path)},
        ]):
            listing = _client().get("/api/logs")
            tail = _client().get("/api/logs/" + urllib.parse.quote("日志"))
        self.assertEqual([r["id"] for r in listing.json()["sources"]], ["日志"])
        # The reproduced leftover: the argv gate 400'd (cli.invalid_value)
        # an id the listing had just published.
        self.assertEqual(tail.status_code, 200)
        self.assertIn("alpha", tail.json()["log"])
        _starlette(tail.json())

    def test_spaced_id_listed_by_the_panel_tails_through_the_route(self):
        with self._with_sources([
            {"id": "my log", "name": "Spaced", "path": str(self.log_path)},
        ]):
            tail = _client().get("/api/logs/" + urllib.parse.quote("my log"))
        self.assertEqual(tail.status_code, 200)
        self.assertIn("alpha", tail.json()["log"])

    def test_surrogate_id_is_scrubbed_before_the_dict_key_compare(self):
        """The listing publishes the replace-encoded key; a raw leftover
        ``\\ud800`` id must scrub to that key, not miss (or 400) on it."""
        with self._with_sources([
            {"id": "app\ud800", "name": "App", "path": str(self.log_path)},
        ]):
            listed = logs_svc.log_sources()[0]["id"]
            out = logs_svc.tail_log("app\ud800")
        self.assertEqual(out["id"], listed)
        self.assertNotIn("\ud800", json.dumps(out, ensure_ascii=False))
        _starlette(out)

    def test_int_id_coerces_like_the_listing_did(self):
        """``id: 0x2A`` lists as "42"; a direct int caller follows the same
        str() probe instead of being refused as non-str."""
        with self._with_sources([
            {"id": 42, "name": "Answer", "path": str(self.log_path)},
        ]):
            out = logs_svc.tail_log(42)
        self.assertEqual(out["id"], "42")
        self.assertIn("alpha", out["log"])

    def test_bool_id_matches_nothing_not_the_string_true(self):
        """bool passes isinstance(int); True must not tail an id "True"."""
        with self._with_sources([
            {"id": "True", "name": "Trap", "path": str(self.log_path)},
        ]):
            with self.assertRaises(HTTPException) as raised:
                logs_svc.tail_log(True)
        self.assertEqual(_code(raised.exception), "logs.unknown_source")
        self.assertEqual(raised.exception.status_code, 404)

    def test_over_cap_int_id_is_a_404_not_a_digit_cap_error(self):
        """The str() probe absorbs the >4300-digit ValueError; the huge
        leftover simply matches nothing."""
        with self._with_sources([
            {"id": "ok", "name": "OK", "path": str(self.log_path)},
        ]):
            with self.assertRaises(HTTPException) as raised:
                logs_svc.tail_log(_HUGE_INT)
        self.assertEqual(_code(raised.exception), "logs.unknown_source")

    def test_option_like_id_is_an_honest_404(self):
        """No argv exists to inject into, so ``--all`` is just unknown."""
        with self._with_sources([
            {"id": "ok", "name": "OK", "path": str(self.log_path)},
        ]):
            resp = _client().get("/api/logs/--all")
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(resp.json()["detail"]["code"], "logs.unknown_source")


class StaysImmuneTests(LogsTailBase):
    """Vectors this sweep probed and found already guarded — pinned so."""

    def test_protected_path_still_refuses_the_tail_after_the_gate_change(self):
        from hub import files_svc
        from hub.paths import BASE as HUB_BASE

        secret = HUB_BASE / "data" / ".session-secret"
        self.assertTrue(files_svc.is_protected(secret))
        with mock.patch.object(logs_svc, "log_sources", return_value=[{
            "id": "secret", "name": "secret", "path": str(secret),
            "exists": True, "size": 1,
        }]):
            with self.assertRaises(HTTPException) as raised:
                logs_svc.tail_log("secret")
        self.assertEqual(_code(raised.exception), "logs.protected")

    def test_traversal_shaped_id_cannot_match_a_listing_key(self):
        """Ids are lookup keys into what the listing published; a path-shaped
        id never names a file directly."""
        with self._with_sources([
            {"id": "ok", "name": "OK", "path": str(self.log_path)},
        ]):
            with self.assertRaises(HTTPException) as raised:
                logs_svc.tail_log("../../etc/passwd")
        self.assertEqual(_code(raised.exception), "logs.unknown_source")

    def test_over_cap_digit_lines_query_is_a_422_not_a_500(self):
        """A 5000-digit ``lines`` never reaches int(str) digit-cap territory:
        pydantic refuses it as validation, not a crash."""
        with self._with_sources([
            {"id": "ok", "name": "OK", "path": str(self.log_path)},
        ]):
            resp = _client().get("/api/logs/ok", params={"lines": "9" * 5000})
        self.assertEqual(resp.status_code, 422)

    def test_invalid_utf8_log_content_reencodes_through_the_route(self):
        """CESU-8 surrogate bytes in the file body decode replaced, and the
        whole payload survives Starlette's strict UTF-8 encode."""
        bad = self.dir / "bad.log"
        bad.write_bytes(b"line-\xed\xa0\x80-cesu\nplain\n")
        with self._with_sources([
            {"id": "bad", "name": "Bad", "path": str(bad)},
        ]):
            resp = _client().get("/api/logs/bad")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("plain", resp.json()["log"])
        _starlette(resp.json())


if __name__ == "__main__":
    unittest.main(verbosity=2)
