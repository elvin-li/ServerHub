"""Audit leftover sweep #8: the terminal command trail's fat-line trio.

audit4..7 sealed the *auth* trail (hub/audit.py) against fat lines: the
reader's byte window was widened to match what ``_trim`` keeps, ``record()``
grew a 64 KB per-field clip so the fat line never exists, and ``_trim``
refuses a rewrite whose tail window holds no complete line.  This sweep
re-hunted the *other* audit trail — ``terminal_svc``'s command log, the only
record of what an operator typed into a root-capable shell — over the real
mounted app (create_app + TestClient, raise_server_exceptions=False) and
found the same shape entirely unfixed there:

* **fixed, wipe** — ``_audit``'s inline trim rewrote the file with
  ``"\\n".join(lines) + ("\\n" if lines else "")``: when a leftover torn fat
  tail (another writer crashed mid-line, a restored backup) glued the
  appended entry into one >512 KB line, the 512 KB tail window held no
  complete row, ``lines`` came back empty, and the rewrite emptied the
  **entire command history** — including the command just audited.  The
  trim now refuses the empty rewrite, the same guard ``audit._trim`` has.

* **fixed, hide** — ``recent_audit`` tailed with ``tail_file_lines``' 256 KB
  default window while the trim legitimately keeps up to 512 KB.  One
  leftover fat (>256 KB) line at the tail put the seek mid-line and the
  torn-row prefix-drop discarded every complete row in the window:
  GET /api/terminal/history answered an empty pane over a populated trail.
  The same undersizing quietly under-filled honest requests — ``limit=500``
  over ~1 KB rows returned ~280.  The reader now uses the trim's window.

* **fixed, source** — ``_audit`` put no bound on field text (the auth
  trail's ``_STR_CAP`` had no analogue here), so a leftover runaway field
  wrote the fat line in the first place.  Audit payload strings are now
  clipped at 64 KB with util.py's marker shape, on write *and* on read —
  while ``_response`` still carries run output up to MAX_OUTPUT untouched.

Stays-immune pins ride along for terminal-history disk shapes probed fresh
this sweep and found already dead: NaN/Infinity constants, a huge-exponent
float, an over-cap digit run under a key, non-dict rows and a fat event
string all answer 200 with an allow_nan=False-encodable body.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import terminal_svc
from hub.app_factory import create_app
from hub.auth import require_auth

_APP = None


def _client() -> TestClient:
    global _APP
    if _APP is None:
        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: this raising is the 500."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


GOOD1 = json.dumps(
    {"ts": 1, "target": "host", "who": "amy", "command": "ls", "rc": 0}
)
GOOD2 = json.dumps(
    {"ts": 2, "target": "host", "who": "amy", "command": "pwd", "rc": 0}
)
#: Wider than tail_file_lines' 256 KB default window, inside the trim's 512 KB.
FAT = json.dumps({"ts": 3, "target": "host", "command": "A" * 300_000, "rc": 0})


class _TrailCase(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="audit8-term-"))
        self.path = self.dir / "terminal-audit.jsonl"
        patched = mock.patch.object(terminal_svc, "AUDIT_PATH", self.path)
        patched.start()
        self.addCleanup(patched.stop)
        # rmtree: _audit takes secure_io.file_lock, which leaves a .lock
        # sibling beside the trail.
        self.addCleanup(shutil.rmtree, self.dir, True)

    def _history(self, limit="100") -> dict:
        resp = _client().get(f"/api/terminal/history?limit={limit}")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        return body


class TrimWipeTests(_TrailCase):
    """Appending one command must never erase the command history."""

    def test_append_onto_a_torn_fat_tail_does_not_wipe_the_trail(self):
        # Pre-fix: the glued >512 KB line left the trim's tail window with
        # no complete row, ``lines`` came back empty, and the rewrite
        # emptied the whole file — history *and* the entry just appended.
        self.path.write_text(
            GOOD1 + "\n" + GOOD2 + "\n" + "B" * 600_000, encoding="utf-8"
        )
        terminal_svc._audit(
            {"ts": 4, "target": "host", "who": "amy", "command": "echo hi", "rc": 0}
        )
        body = self.path.read_text(encoding="utf-8")
        self.assertGreater(
            self.path.stat().st_size,
            0,
            "one audited command truncated the entire command history",
        )
        self.assertIn('"command": "ls"', body)
        self.assertIn('"command": "echo hi"', body)

    def test_ordinary_trim_still_bounds_the_trail(self):
        # The guard must not turn the trim off: a trail of small rows past
        # the byte cap is still cut back to the keep window.
        line = GOOD1 + "\n"
        n = terminal_svc._AUDIT_MAX_BYTES // len(line) + 50
        self.path.write_text(line * n, encoding="utf-8")
        terminal_svc._audit(
            {"ts": 5, "target": "host", "who": "amy", "command": "pwd", "rc": 0}
        )
        kept = self.path.read_text(encoding="utf-8").splitlines()
        self.assertLessEqual(len(kept), terminal_svc._AUDIT_KEEP_LINES)
        self.assertIn('"command": "pwd"', kept[-1])


class FatTailLineHideTests(_TrailCase):
    """A fat line must cost (at most) itself — never the sibling rows."""

    def test_fat_tail_line_does_not_hide_the_history(self):
        # Pre-fix: the 256 KB window seeked into the middle of the fat line,
        # the prefix-drop ate everything up to its trailing newline, and the
        # history pane showed nothing over a populated trail.
        self.path.write_text(
            GOOD1 + "\n" + GOOD2 + "\n" + FAT + "\n", encoding="utf-8"
        )
        rows = terminal_svc.recent_audit(100)
        _starlette(rows)
        commands = [r.get("command") for r in rows]
        self.assertIn("ls", commands)
        self.assertIn("pwd", commands)
        # The fat row itself is inside the widened window — with its field
        # clipped on the way out, not shipped whole to the browser.
        fat_rows = [c for c in commands if c and c.startswith("AAA")]
        self.assertEqual(len(fat_rows), 1)
        self.assertLessEqual(
            len(fat_rows[0]), terminal_svc._AUDIT_STR_CAP + 32
        )

    def test_http_history_lists_the_rows_behind_a_fat_tail_line(self):
        self.path.write_text(
            GOOD1 + "\n" + GOOD2 + "\n" + FAT + "\n", encoding="utf-8"
        )
        body = self._history()
        commands = [e.get("command") for e in body["entries"]]
        self.assertIn("ls", commands)
        self.assertIn("pwd", commands)

    def test_limit_500_of_1kb_rows_is_filled_not_quietly_halved(self):
        # Pre-fix: 500 rows of ~1 KB need ~500 KB; the 256 KB window
        # returned ~280 entries for limit=500 with no error and no hint.
        self.path.write_text(
            "".join(
                json.dumps({"ts": i, "command": "x" * 900, "rc": 0}) + "\n"
                for i in range(600)
            ),
            encoding="utf-8",
        )
        self.assertEqual(len(terminal_svc.recent_audit(500)), 500)


class AuditFieldClipTests(_TrailCase):
    """_audit must bound field text so the fat line never exists at all."""

    def test_runaway_field_is_clipped_on_write(self):
        # Pre-fix: the 300 KB field was written verbatim; the line then hid
        # itself and every older sibling from the reader's window, and a
        # >512 KB one primed the trim wipe.
        terminal_svc._audit({"ts": 6, "command": "D" * 300_000, "rc": 0})
        widest = max(
            len(ln)
            for ln in self.path.read_text(encoding="utf-8").splitlines()
        )
        self.assertLess(widest, 2 * terminal_svc._AUDIT_STR_CAP)
        rows = terminal_svc.recent_audit(10)
        self.assertTrue(rows[0]["command"].endswith("…[truncated]"))

    def test_leftover_fat_field_on_disk_is_clipped_on_read(self):
        # A fat field written by an older build must be bounded on its way
        # to the browser even though the line itself fits the window.
        self.path.write_text(
            json.dumps({"ts": 7, "command": "E" * 100_000, "rc": 0}) + "\n",
            encoding="utf-8",
        )
        rows = terminal_svc.recent_audit(10)
        _starlette(rows)
        self.assertLessEqual(
            len(rows[0]["command"]), terminal_svc._AUDIT_STR_CAP + 32
        )

    def test_ordinary_rows_round_trip_verbatim(self):
        # The clip must not touch anything legitimately recorded: the widest
        # honest field (MAX_COMMAND_LEN) survives untouched, as does a
        # >4300-digit *string* like the hexint pins round-trip.
        cmd = "c" * terminal_svc.MAX_COMMAND_LEN
        terminal_svc._audit(
            {"ts": 8, "who": "amy", "command": cmd, "note": "9" * 4400, "rc": 0}
        )
        rows = terminal_svc.recent_audit(10)
        self.assertEqual(rows[0]["command"], cmd)
        self.assertEqual(rows[0]["note"], "9" * 4400)
        self.assertEqual(rows[0]["who"], "amy")

    def test_run_response_output_is_not_clipped_by_the_audit_cap(self):
        # The cap belongs to the trail only: _response still carries run
        # output far wider than _AUDIT_STR_CAP (MAX_OUTPUT is 200 KB).
        wide = "o" * (terminal_svc._AUDIT_STR_CAP + 10_000)
        out = terminal_svc._response({"rc": 0, "stdout": wide, "stderr": ""})
        self.assertEqual(len(out["stdout"]), len(wide))


class HistoryStaysImmuneTests(_TrailCase):
    """Disk shapes probed fresh this sweep and found already dead."""

    def test_nan_and_infinity_constants_null_not_500(self):
        self.path.write_text(
            '{"command":"x","f":NaN,"g":Infinity,"h":-Infinity}\n',
            encoding="utf-8",
        )
        entry = self._history()["entries"][0]
        self.assertIsNone(entry["f"])
        self.assertIsNone(entry["g"])
        self.assertIsNone(entry["h"])

    def test_huge_digit_float_and_huge_exponent_answer_200(self):
        self.path.write_text(
            '{"command":"a","n":' + "9" * 5000 + ".5}\n"
            '{"command":"b","n":9E999999999}\n',
            encoding="utf-8",
        )
        body = self._history()
        self.assertEqual(
            [e["command"] for e in body["entries"]], ["a", "b"]
        )

    def test_overcap_int_costs_its_field_not_the_row(self):
        self.path.write_text(
            '{"command":"whoami","rc":' + "9" * 5000 + "}\n", encoding="utf-8"
        )
        body = self._history()
        self.assertEqual(body["entries"][0]["command"], "whoami")
        self.assertIsNone(body["entries"][0]["rc"])

    def test_non_dict_rows_cost_only_themselves(self):
        self.path.write_text(
            '[1,2,3]\n"just a string"\n42\n{"command":"ok"}\n',
            encoding="utf-8",
        )
        body = self._history()
        self.assertEqual([e["command"] for e in body["entries"]], ["ok"])

    def test_fat_event_string_row_answers_200_and_is_bounded(self):
        self.path.write_text(
            json.dumps({"command": "f" * 200_000, "rc": 0}) + "\n",
            encoding="utf-8",
        )
        body = self._history()
        self.assertLessEqual(
            len(body["entries"][0]["command"]),
            terminal_svc._AUDIT_STR_CAP + 32,
        )


if __name__ == "__main__":
    unittest.main()
