"""Leftover sweep: one fat trail line wiped every sibling row from the reader.

``audit.recent`` tailed the file with ``tail_file_lines``' default 256 KB
window, but ``audit._trim`` legitimately keeps up to ``MAX_LINES * 1024``
(5 MB): the reader's window was smaller than what the writer maintains.
Three consequences, all reproduced over the real mounted app before fixing:

* **fixed** — a single fat (> 256 KB) line at the *tail* of the trail put the
  window's seek mid-line, and the torn-first-row prefix-drop then discarded
  every complete row in the window.  GET /api/audit/auth answered
  ``entries: []`` while intact sign-in rows sat on disk right before the fat
  line — the page whose whole job is proving events were recorded showed
  "no audit records".  ``recent()`` now reads the same byte window ``_trim``
  keeps, so anything the writer retains, the reader can see.

* **fixed** — the same undersizing quietly under-filled honest requests:
  ``limit=500`` over ~1 KB rows needs ~500 KB, so the endpoint returned
  roughly half of what it advertised, with no error and no hint.

* **fixed** — ``record()`` put no bound on field text, so a caller auditing
  an unbounded payload (a 300 KB shell-job command) wrote the fat line in
  the first place.  Worse than the wipe: a line wider than ``_trim``'s own
  window makes the trim's tail-read hold no complete line, and ``_trim``
  (correctly) refuses to rewrite — the trail turns append-only forever and
  grows without limit on the one file that must stay bounded unattended.
  ``_utf8_text`` now clips one field at 64 KB with util.py's marker shape,
  on write *and* on read, so a leftover fat field already on disk is also
  bounded on its way to the browser.

Stays-immune pins (probed over the mounted app, came back clean):

* a >4300-digit ``limit`` is pydantic's 422, not a digit-cap 500;
* a leftover FIFO occupying the trail answers 200/empty, not a hang.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import audit  # noqa: E402
from hub.routers import audit_api  # noqa: E402

GOOD1 = json.dumps(
    {"ts": "2026-08-01T00:00:00+0000", "event": "auth.login.ok", "username": "amy"}
)
GOOD2 = json.dumps(
    {"ts": "2026-08-02T00:00:00+0000", "event": "auth.logout", "username": "amy"}
)
#: Wider than tail_file_lines' 256 KB default window, well inside _trim's.
FAT = json.dumps(
    {"ts": "x", "event": "scheduler.job.run_now", "command": "A" * 300_000}
)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: this raising is the 500."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _TrailCase(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="audit-fatline-pin-"))
        self.path = self.dir / "auth-audit.jsonl"
        patched = mock.patch.object(audit, "AUDIT_PATH", self.path)
        patched.start()
        self.addCleanup(patched.stop)
        # rmtree: record() takes secure_io.file_lock, which leaves a .lock
        # sibling beside the trail.
        self.addCleanup(shutil.rmtree, self.dir, True)


class FatTailLineWipeTests(_TrailCase):
    """A fat line must cost (at most) itself — never the sibling rows."""

    def test_fat_tail_line_does_not_wipe_the_recent_list(self):
        # Pre-fix: the 256 KB window seeked into the middle of the fat line,
        # the prefix-drop ate everything up to its trailing newline, and
        # recent() returned [] with two intact rows on disk.
        self.path.write_text(GOOD1 + "\n" + GOOD2 + "\n" + FAT + "\n", encoding="utf-8")
        rows = audit.recent(100)
        events = [r["event"] for r in rows]
        self.assertIn("auth.login.ok", events)
        self.assertIn("auth.logout", events)
        # The fat line itself is inside the widened window, so it is a row
        # too — with its field clipped on the way out, not shipped whole.
        self.assertIn("scheduler.job.run_now", events)
        fat_row = rows[events.index("scheduler.job.run_now")]
        self.assertLessEqual(len(fat_row["command"]), audit._STR_CAP + 32)
        _starlette(rows)

    def test_fat_middle_line_does_not_hide_the_rows_before_it(self):
        self.path.write_text(GOOD1 + "\n" + FAT + "\n" + GOOD2 + "\n", encoding="utf-8")
        events = [r["event"] for r in audit.recent(100)]
        self.assertEqual(
            events, ["auth.login.ok", "scheduler.job.run_now", "auth.logout"]
        )

    def test_limit_500_of_1kb_rows_is_filled_not_quietly_halved(self):
        # Pre-fix: 500 rows of ~1 KB need ~500 KB; the 256 KB window returned
        # ~250 entries for limit=500 with no error and no hint.
        self.path.write_text(
            "".join(
                json.dumps({"ts": i, "event": f"e{i}", "pad": "x" * 900}) + "\n"
                for i in range(600)
            ),
            encoding="utf-8",
        )
        self.assertEqual(len(audit.recent(500)), 500)

    def test_reader_window_matches_what_trim_keeps(self):
        # The invariant behind both fixes: anything _trim retains, recent()
        # can read.  Build a trail just past the trim trigger, trim it, and
        # require the reader to see exactly the kept tail.
        line = json.dumps({"ts": "x", "event": "auth.login.ok", "pad": "n" * 400})
        n_lines = audit._TRIM_SOFT_BYTES // len(line) + 8
        self.path.write_text((line + "\n") * n_lines, encoding="utf-8")
        audit._trim(self.path)
        kept = len(self.path.read_text(encoding="utf-8").splitlines())
        self.assertEqual(len(audit.recent(1000)), min(kept, 1000))


class UnboundedFieldClipTests(_TrailCase):
    """record() must bound field text so the fat line never exists at all."""

    def test_recorded_runaway_field_is_clipped_and_stays_visible(self):
        # Pre-fix: the 300 KB note was written verbatim; the event then hid
        # itself and every older sibling from the reader's window.
        entry = audit.record(
            "auth.login.failed", username="bob", note="B" * 300_000
        )
        self.assertLessEqual(len(entry["note"]), audit._STR_CAP + 32)
        self.assertTrue(entry["note"].endswith("…[truncated]"))
        self.assertEqual(entry["username"], "bob")
        audit.record("auth.login.ok", username="amy")
        events = [r["event"] for r in audit.recent(100)]
        self.assertEqual(events, ["auth.login.failed", "auth.login.ok"])
        # The on-disk line is bounded far under every tail window, so _trim's
        # tail-read always holds complete lines and the trail stays trimmable.
        widest = max(
            len(ln) for ln in self.path.read_text(encoding="utf-8").splitlines()
        )
        self.assertLess(widest, 2 * audit._STR_CAP)

    def test_runaway_bytes_and_keys_are_clipped_too(self):
        entry = audit.record(
            "auth.login.failed",
            blob=b"C" * 300_000,
            detail={"k" * 300_000: "v"},
        )
        self.assertLessEqual(len(entry["blob"]), audit._STR_CAP + 32)
        for key in entry["detail"]:
            self.assertLessEqual(len(key), audit._STR_CAP + 32)
        _starlette(entry)

    def test_ordinary_fields_round_trip_verbatim(self):
        # The clip must not touch anything a caller legitimately records —
        # including the >4300-digit *string* the hexint pins round-trip.
        big_text = "9" * 4400
        entry = audit.record(
            "auth.login.ok", username="amy", note=big_text, attempts=3
        )
        self.assertEqual(entry["note"], big_text)
        self.assertEqual(entry["username"], "amy")
        rows = audit.recent(10)
        self.assertEqual(rows[0]["note"], big_text)


class MountedRouteTests(unittest.TestCase):
    """The wipe as the operator saw it, plus stays-immune HTTP pins."""

    def setUp(self):
        from fastapi.testclient import TestClient

        from hub.app_factory import create_app
        from hub.auth import require_auth

        app = create_app()
        app.dependency_overrides[require_auth] = lambda: True
        self.addCleanup(app.dependency_overrides.clear)
        self.client = TestClient(app, raise_server_exceptions=False)
        self.dir = Path(tempfile.mkdtemp(prefix="audit-fatline-http-"))
        self.path = self.dir / "auth-audit.jsonl"
        patched = mock.patch.object(audit, "AUDIT_PATH", self.path)
        patched.start()
        self.addCleanup(patched.stop)
        self.addCleanup(shutil.rmtree, self.dir, True)

    def test_fat_tail_line_does_not_answer_an_empty_trail(self):
        # Pre-fix: 200 with "entries": [] — the Audit page rendered its
        # "no audit records" placeholder over a populated trail.
        self.path.write_text(GOOD1 + "\n" + GOOD2 + "\n" + FAT + "\n", encoding="utf-8")
        resp = self.client.get("/api/audit/auth?limit=100")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        events = [e["event"] for e in body["entries"]]
        self.assertIn("auth.login.ok", events)
        self.assertIn("auth.logout", events)
        _starlette(body)

    def test_over_cap_and_huge_digit_limits_stay_422_not_500(self):
        for query in ("9" * 5000, str(audit_api.MAX_LIMIT + 1), "0", "nan", "1e3"):
            resp = self.client.get(f"/api/audit/auth?limit={query}")
            self.assertEqual(resp.status_code, 422, f"limit={query[:40]}")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFOs")
    def test_leftover_fifo_trail_answers_empty_not_a_hang(self):
        os.mkfifo(self.path)
        resp = self.client.get("/api/audit/auth?limit=100")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["entries"], [])


if __name__ == "__main__":
    unittest.main()
