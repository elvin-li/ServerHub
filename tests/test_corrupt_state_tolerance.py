"""A truncated or garbage state file must degrade to empty state, not raise.

Every reader under data/ is exercised against the same three corpses: a
truncated JSON fragment, plain-text garbage, and raw bytes that are not valid
UTF-8 (a torn write after power loss produces exactly that).  A reader that
raises here takes an API endpoint to 500 at best, and at worst kills the
background thread that called it — the alert engine reads several of these
files every sweep.

The non-UTF-8 case is the one that actually caught bugs: ``read_text()``
raises ``UnicodeDecodeError`` (a ValueError, not an OSError), which sailed
past ``except OSError`` guards in the alerts journal and the metrics ring
buffer — the reader raised and, worse, both files' trim passes stayed
disabled forever after one corrupt byte.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import (  # noqa: E402
    alerts, api_keys, metrics, notify_channels, scheduler_svc, smart_test_svc,
    twofa_svc, ups_policy,
)

#: (label, bytes) — every reader is tried against each.
CORPSES = (
    ("truncated-json", b'{"keys": [{"id": "a", "na'),
    ("text-garbage", b"this is not json at all\n<<<>>>\n"),
    ("binary-junk", b"\x00\xff\xfe{" + b"\x80" * 32),
)


class _Corpses(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="serverhub-corrupt-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))

    def corpse(self, label: str, payload: bytes) -> Path:
        path = self.tmp / f"{label}.state"
        path.write_bytes(payload)
        return path

    def check_all(self, module, attr, reader, expect):
        """Patch *module.attr* to each corpse and assert *reader* degrades."""
        for label, payload in CORPSES:
            with self.subTest(corpse=label):
                with mock.patch.object(module, attr, self.corpse(label, payload)):
                    self.assertEqual(reader(), expect)


class StateReaderTolerance(_Corpses):
    def test_alert_state(self):
        self.check_all(alerts, "STATE_FILE", alerts._load_state, {})

    def test_alerts_journal(self):
        self.check_all(alerts, "ALERTS_FILE", alerts.list_alerts, [])

    def test_alerts_journal_mixed_corruption_keeps_good_lines(self):
        """One mangled line must cost that line, not the whole journal."""
        path = self.tmp / "alerts.jsonl"
        path.write_bytes(
            b'{"t": 1, "id": "ok-1"}\n'
            b"\xff\xfe not a line\n"
            b'{"t": 2, "id": "ok-2"}\n'
        )
        with mock.patch.object(alerts, "ALERTS_FILE", path):
            got = [a["id"] for a in alerts.list_alerts()]
        self.assertEqual(got, ["ok-2", "ok-1"], "newest first, corrupt line skipped")

    def test_alerts_trim_survives_binary_junk(self):
        """The count-gated trim must keep working after a torn write."""
        path = self.tmp / "alerts.jsonl"
        path.write_bytes(b"\xff\xfe broken\n" * 10)
        with mock.patch.object(alerts, "ALERTS_FILE", path), \
             mock.patch.object(alerts, "_appends_since_trim", alerts._TRIM_EVERY - 1):
            alerts._append_alert({"t": 1, "id": "x"})  # crosses the trim gate
        self.assertIn(b'"id": "x"', path.read_bytes())

    def test_metrics_history_and_latest(self):
        for label, payload in CORPSES:
            with self.subTest(corpse=label):
                with mock.patch.object(metrics, "METRICS_FILE",
                                       self.corpse(label, payload)), \
                     mock.patch.object(metrics, "_last_sample", None):
                    self.assertEqual(metrics.history(60), [])
                    self.assertIsNone(metrics.latest_sample())

    def test_metrics_trim_survives_binary_junk(self):
        path = self.tmp / "metrics.jsonl"
        path.write_bytes(b"\xff\xfe broken\n" * 10)
        # _last_trim/_last_flush are patched so this test's flush cannot
        # shift the time gates other tests observe.
        with mock.patch.object(metrics, "METRICS_FILE", path), \
             mock.patch.object(metrics, "_last_trim", 0.0), \
             mock.patch.object(metrics, "_last_flush", 0.0):
            with metrics._lock:
                metrics._write_buf.append('{"t": 1}\n')
                metrics._flush_buf_locked(force_trim=True)
        self.assertIn(b'{"t": 1}', path.read_bytes())

    def test_schedule_runs_journal(self):
        self.check_all(scheduler_svc, "RUNS_PATH", scheduler_svc.runs, [])
        self.check_all(scheduler_svc, "RUNS_PATH", scheduler_svc.last_runs_by_job, {})

    def test_ups_policy_state(self):
        self.check_all(ups_policy, "STATE_FILE", ups_policy._load_state, {})

    def test_api_keys_store(self):
        self.check_all(api_keys, "STORE_FILE", api_keys._load, [])

    def test_twofa_store(self):
        self.check_all(twofa_svc, "STORE_FILE", twofa_svc._load, {})

    def test_notify_secrets(self):
        self.check_all(notify_channels, "SECRETS_FILE",
                       notify_channels._load_secrets, {})

    def test_smart_test_history(self):
        self.check_all(smart_test_svc, "HISTORY_PATH",
                       smart_test_svc._load_history, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
