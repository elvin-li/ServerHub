"""Stays-immune pins: leftover journal/state nodes on the mounted alerts routes.

This sweep re-probed GET /api/alerts, POST /api/alerts/check and
POST /api/alerts/test through the *real* app (create_app + TestClient, so
Starlette's ensure_ascii=False / allow_nan=False / UTF-8 encode and FastAPI's
query-param parsing are part of what is under test) with every leftover class
planted on disk, and found them all already sealed by the prior alerts /
metrics / notify sweeps.  What was missing is the HTTP-layer pin: the prior
suites assert at the ``alerts.list_alerts`` / ``alerts.check_once`` function
boundary, so a regression that reintroduced a raise *between* that boundary
and the response encoder (or that narrowed an except clause the route relies
on) would ship green.  Each test here fails on the pre-hardening tree.

Pinned classes, all via mounted routes:

* a leftover FIFO occupying alerts.jsonl (the class metrics3 hardened in
  tail_file_lines / append_text: O_NONBLOCK + regular-file check) answers
  200, never parks the request waiting for a writer and never 500s;
* leftover directory / symlink-to-directory / dangling-symlink nodes
  occupying alerts.jsonl or alert_state.json answer 200;
* ``json.loads`` of a leftover >4300-digit number raises CPython's digit-cap
  *ValueError* (not JSONDecodeError): the poisoned line is skipped, the
  sibling row still renders, and the journal bytes on disk stay untouched —
  a read must never wipe the journal;
* lone UTF-8 surrogates in journal/state keys AND values scrub before
  Starlette's UTF-8 encode;
* leftover Infinity / NaN / 1e400 ``t`` stamps render as null, never 500;
* an over-cap ``limit`` query is FastAPI's 422, never a 500, and
  ``limit=0`` / negative never slurp the whole journal;
* a planted ``alert_state.json.{pid}.tmp`` symlink surfaces as
  FileExistsError out of replace_bytes (never a silent redirect of the
  write), which POST /api/alerts/check absorbs — 200, and the symlink
  target is never created;
* a leftover FIFO occupying the sibling ``alerts.jsonl.lock`` runs the
  request unlocked instead of wedging or raising.
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

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import alerts  # noqa: E402

#: Past CPython's default 4300-digit str<->int conversion limit.
_HUGE_DIGITS = "9" * 5000


class _AlertsRouteSandbox(unittest.TestCase):
    """Scratch journal + state file, and the real app's TestClient."""

    def setUp(self):
        root = Path(tempfile.mkdtemp(prefix="serverhub-alerts3-http-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        self.root = root
        self.journal = root / "alerts.jsonl"
        self.state = root / "alert_state.json"
        for name, value in (
            ("ALERTS_FILE", self.journal),
            ("STATE_FILE", self.state),
        ):
            patched = mock.patch.object(alerts, name, value)
            patched.start()
            self.addCleanup(patched.stop)

    def client(self):
        from fastapi.testclient import TestClient
        from hub.app_factory import create_app
        from hub.auth import require_auth

        app = create_app()
        app.dependency_overrides[require_auth] = lambda: True
        self.addCleanup(app.dependency_overrides.clear)
        return TestClient(app, raise_server_exceptions=False)


class FifoJournalRoutePins(_AlertsRouteSandbox):
    """Leftover FIFO nodes: the class the metrics sweep hardened, pinned at
    the alerts routes so a revert of the O_NONBLOCK + S_ISREG guards in
    tail_file_lines / read_text_capped / append_text cannot ship green."""

    def test_fifo_journal_get_alerts_answers_200(self):
        """A FIFO at alerts.jsonl used to park os.open until a writer
        appeared — GET /api/alerts hung forever instead of 500ing."""
        os.mkfifo(self.journal)
        r = self.client().get("/api/alerts")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["alerts"], [])

    def test_fifo_journal_check_answers_200(self):
        os.mkfifo(self.journal)
        r = self.client().post("/api/alerts/check")
        self.assertEqual(r.status_code, 200)
        self.assertIn("emitted", r.json())

    def test_fifo_state_check_answers_200(self):
        """A FIFO at alert_state.json used to wedge _load_state's open."""
        os.mkfifo(self.state)
        r = self.client().post("/api/alerts/check")
        self.assertEqual(r.status_code, 200)

    def test_fifo_lock_sibling_runs_unlocked_not_500(self):
        """A FIFO occupying alerts.jsonl.lock must not raise out of
        file_lock (the context runs unlocked instead)."""
        os.mkfifo(self.journal.with_name(self.journal.name + ".lock"))
        c = self.client()
        self.assertEqual(c.post("/api/alerts/check").status_code, 200)
        self.assertEqual(c.get("/api/alerts").status_code, 200)


class NonfileNodeRoutePins(_AlertsRouteSandbox):
    def test_directory_journal_answers_200(self):
        """IsADirectoryError out of the journal read used to 500 GET /api/alerts."""
        self.journal.mkdir()
        c = self.client()
        r = c.get("/api/alerts")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["alerts"], [])
        self.assertEqual(c.post("/api/alerts/check").status_code, 200)

    def test_directory_state_check_answers_200(self):
        self.state.mkdir()
        self.assertEqual(self.client().post("/api/alerts/check").status_code, 200)

    def test_symlink_to_directory_journal_answers_200(self):
        self.journal.symlink_to(self.root)
        self.assertEqual(self.client().get("/api/alerts").status_code, 200)

    def test_dangling_symlink_journal_answers_200(self):
        self.journal.symlink_to(self.root / "vanished-target")
        r = self.client().get("/api/alerts")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["alerts"], [])


class JournalContentRoutePins(_AlertsRouteSandbox):
    def test_over_cap_digit_line_skips_line_never_wipes_journal(self):
        """``json.loads`` of a >4300-digit number is the digit-cap ValueError,
        not JSONDecodeError.  The poisoned line is skipped, the sibling row
        still renders — and the journal on disk is byte-identical after the
        read: a GET must never rewrite (or wipe) the journal."""
        payload = (
            '{"t": 1, "id": "bad", "n": ' + _HUGE_DIGITS + "}\n"
            + json.dumps({"t": 1, "id": "good", "name": "disk"}) + "\n"
        )
        self.journal.write_text(payload)
        r = self.client().get("/api/alerts")
        self.assertEqual(r.status_code, 200)
        self.assertEqual([a["id"] for a in r.json()["alerts"]], ["good"])
        self.assertEqual(self.journal.read_text(), payload)

    def test_deeply_nested_line_skips_line_not_route(self):
        """json.loads RecursionError is not ValueError; the route used to 500."""
        self.journal.write_text(
            '{"k":' * 12000 + "1" + "}" * 12000 + "\n"
            + json.dumps({"t": 1, "id": "good"}) + "\n"
        )
        r = self.client().get("/api/alerts")
        self.assertEqual(r.status_code, 200)
        self.assertEqual([a["id"] for a in r.json()["alerts"]], ["good"])

    def test_surrogate_key_and_value_scrub_through_the_encoder(self):
        """Leftover lone surrogates in keys AND values used to 500
        Starlette's UTF-8 encode of GET /api/alerts."""
        self.journal.write_text(json.dumps({
            "t": 1, "id": "s", "name": "disk\ud800", "\udfffkey": "v\ud800",
        }) + "\n")
        r = self.client().get("/api/alerts")
        self.assertEqual(r.status_code, 200)
        rows = r.json()["alerts"]
        self.assertEqual(len(rows), 1)
        body = json.dumps(rows, ensure_ascii=False)
        self.assertNotIn("\ud800", body)
        self.assertNotIn("\udfff", body)

    def test_inf_nan_huge_float_t_render_null_not_500(self):
        """Leftover Infinity / NaN / 1e400 stamps used to 500 the
        allow_nan=False encoder (or render Invalid Date)."""
        self.journal.write_text(
            '{"t": 1e400, "id": "f"}\n'
            '{"t": Infinity, "id": "i", "v": NaN}\n'
            + json.dumps({"t": 2, "id": "ok"}) + "\n"
        )
        r = self.client().get("/api/alerts")
        self.assertEqual(r.status_code, 200)
        by_id = {a["id"]: a for a in r.json()["alerts"]}
        self.assertIsNone(by_id["f"]["t"])
        self.assertIsNone(by_id["i"]["t"])
        self.assertIsNone(by_id["i"]["v"])
        self.assertEqual(by_id["ok"]["t"], 2)

    def test_binary_garbage_line_skipped_not_500(self):
        """A torn binary write used to UnicodeDecodeError past the guards."""
        self.journal.write_bytes(
            b"\xff\xfe\x00garbage\n" + json.dumps({"t": 1, "id": "g"}).encode() + b"\n"
        )
        r = self.client().get("/api/alerts")
        self.assertEqual(r.status_code, 200)
        self.assertEqual([a["id"] for a in r.json()["alerts"]], ["g"])


class StateContentRoutePins(_AlertsRouteSandbox):
    def test_surrogate_state_keys_and_values_check_answers_200(self):
        """Escaped ``"\\ud800…"`` in alert_state.json produces lone-surrogate
        keys from json.loads; the check used to 500 (and the state rewrote
        on every sweep)."""
        self.state.write_text('{"\\ud800svc": "down", "svc": "warn\\ud800"}')
        self.assertEqual(self.client().post("/api/alerts/check").status_code, 200)

    def test_over_cap_digit_state_value_check_answers_200(self):
        """A >4300-digit cooldown stamp used to ValueError json.loads and
        wipe the whole state (re-announce storm); the parse_int hook drops
        just the number and the route answers 200."""
        self.state.write_text('{"cooldown": ' + _HUGE_DIGITS + ', "svc": "ok"}')
        self.assertEqual(self.client().post("/api/alerts/check").status_code, 200)

    def test_deeply_nested_state_check_answers_200(self):
        self.state.write_text('{"k":' * 12000 + "1" + "}" * 12000)
        self.assertEqual(self.client().post("/api/alerts/check").status_code, 200)

    def test_oversize_state_check_answers_200(self):
        """A leftover multi-hundred-KB alert_state.json trips the read cap
        (OSError EFBIG), never an OOM or a 500."""
        self.state.write_text('{"pad": "' + "x" * 300000 + '"}')
        self.assertEqual(self.client().post("/api/alerts/check").status_code, 200)

    def test_list_state_from_torn_write_check_answers_200(self):
        self.state.write_text('["torn"]')
        self.assertEqual(self.client().post("/api/alerts/check").status_code, 200)

    def test_planted_state_tmp_symlink_is_never_followed(self):
        """replace_bytes opens the tmp with O_EXCL|O_NOFOLLOW: a planted
        ``alert_state.json.{pid}.tmp`` symlink raises FileExistsError instead
        of redirecting the write.  The check absorbs it (200) and the symlink
        target must never be created."""
        target = self.root / "evil-target"
        tmp = self.state.with_name(f"{self.state.name}.{os.getpid()}.tmp")
        tmp.symlink_to(target)
        # Non-empty prior state forces new_state != prev, so _save_state runs.
        self.state.write_text('{"stale-service": "warn"}')
        r = self.client().post("/api/alerts/check")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(target.exists())


class LimitParamRoutePins(_AlertsRouteSandbox):
    def test_over_cap_limit_is_422_not_500(self):
        """FastAPI's int parse of a >4300-digit query is a coded 422; a
        regression to a bare int(...) in the handler would be a 500."""
        r = self.client().get("/api/alerts?limit=" + _HUGE_DIGITS)
        self.assertEqual(r.status_code, 422)

    def test_inf_limit_is_422_not_500(self):
        c = self.client()
        self.assertEqual(c.get("/api/alerts?limit=inf").status_code, 422)
        self.assertEqual(c.get("/api/alerts?limit=1e309").status_code, 422)

    def test_zero_and_negative_limit_never_slurp_the_journal(self):
        """``lines[-0:]`` is the whole file: limit=0 used to return every
        row.  Both clamp to one row now."""
        self.journal.write_text("".join(
            json.dumps({"t": i, "id": f"a{i}"}) + "\n" for i in range(5)
        ))
        c = self.client()
        for q in ("0", "-5"):
            r = c.get("/api/alerts?limit=" + q)
            self.assertEqual(r.status_code, 200)
            self.assertEqual(len(r.json()["alerts"]), 1)


if __name__ == "__main__":
    unittest.main()
