"""Leftover YAML/JSON 500s on alerts, notify channels, and metrics range.

``id: [foo]`` / ``kind: .inf`` used to 500 POST /api/alerts/check,
``port: .inf`` / ``name: 2026-08-19`` used to 500 GET /api/alerts/channels,
and a 400-digit leftover ``t`` / ``n`` OverflowError'd GET /api/metrics?range=.

Follow-up: leftover JSON ``\\ud800`` in a metrics/alerts/audit field or key
still 500'd Starlette's ``ensure_ascii=False`` + UTF-8 encode.

Follow-up 2: leftover Infinity in notify-credentials.json used to rewrite
onto disk from PUT /api/alerts/channels (and 500 under allow_nan=False).

Follow-up 3: a leftover directory occupying notify-credentials.json used to
IsADirectoryError PUT /api/alerts/channels.

Follow-up 4: CPython's 4300-digit str<->int cap.  ``json.loads`` of a leftover
>4300-digit number raises the digit-cap *ValueError* (not JSONDecodeError),
which used to 500 GET /api/alerts, GET /api/metrics and GET /api/metrics?range=
past the ``(json.JSONDecodeError, RecursionError)`` guards; and an over-cap
``int`` passed the sanitizers untouched, so Starlette's ``json.dumps`` itself
raised out of POST /api/alerts/check and GET /api/alerts/channels.
"""
from __future__ import annotations

import datetime
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from hub import alerts, metrics, metrics_rollup, notify_channels
from hub.routers import settings_api

#: Past CPython's default 4300-digit str<->int conversion limit.
_HUGE_DIGITS = "9" * 5000
#: The same class as an already-parsed int (5001 digits).
_HUGE_INT = 10 ** 5000


def _json(payload) -> None:
    json.dumps(payload, allow_nan=False)


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class NotifyPublicChannelLeftoverTests(unittest.TestCase):
    def _view(self, ch: dict) -> dict:
        with mock.patch.object(notify_channels, "channel_secrets", return_value={}):
            return notify_channels.public_channel(ch)

    def test_leftover_inf_port_does_not_500(self):
        """YAML ``port: .inf`` used to leak Infinity into GET /api/alerts/channels."""
        out = self._view({
            "id": "mail", "type": "email",
            "host": "smtp.example.com", "to": "a@b.com",
            "port": float("inf"),
        })
        _json(out)
        self.assertIsNone(out["config"].get("port"))

    def test_leftover_yaml_date_and_set_do_not_500(self):
        out = self._view({
            "id": "n1", "type": "ntfy",
            "name": datetime.date(2026, 8, 19),
            "topic": {"alerts"},
            "server": b"https://ntfy.sh",
        })
        _json(out)
        self.assertEqual(out["name"], "2026-08-19")
        self.assertEqual(out["config"]["topic"], ["alerts"])
        self.assertEqual(out["config"]["server"], "https://ntfy.sh")

    def test_leftover_inf_name_does_not_500(self):
        out = self._view({
            "id": "n1", "type": "ntfy", "name": float("nan"), "topic": "t",
        })
        _json(out)
        self.assertEqual(out["name"], "n1")

    def test_leftover_inf_email_port_does_not_raise(self):
        """YAML ``port: .inf`` used to OverflowError ``int(inf)`` in the sender."""
        with mock.patch.object(notify_channels, "_smtp_connect", side_effect=AssertionError("dial")):
            res = notify_channels._send_email(
                {"host": "127.0.0.1", "to": "a@b.com", "port": float("inf")},
                {}, "T", "M",
            )
        self.assertIsInstance(res, dict)
        self.assertIn("ok", res)

    def test_leftover_surrogate_name_does_not_500(self):
        """YAML ``name: "\\ud800"`` used to 500 GET /api/alerts/channels."""
        out = self._view({
            "id": "n1", "type": "ntfy", "name": "bot\ud800",
            "topic": "t\udfff", "min_level": "warn\ud800",
        })
        _starlette(out)
        self.assertNotIn("\ud800", out["name"])
        self.assertNotIn("\udfff", out["config"]["topic"])
        self.assertNotIn("\ud800", out["min_level"])

    def test_leftover_surrogate_nested_key_does_not_500(self):
        out = self._view({
            "id": "mail", "type": "email",
            "host": "smtp.example.com", "to": {"\ud800": "a@b.com"},
        })
        _starlette(out)
        self.assertTrue(out["config"].get("to"))
        self.assertNotIn("\ud800", json.dumps(out))

    def test_leftover_over_cap_port_does_not_500(self):
        """A >4300-digit ``port`` is unrenderable: CPython's int->str digit
        cap makes ``json.dumps`` itself ValueError; GET /api/alerts/channels
        used to 500 on it."""
        out = self._view({
            "id": "mail", "type": "email",
            "host": "smtp.example.com", "to": "a@b.com",
            "port": _HUGE_INT,
        })
        _json(out)
        self.assertIsNone(out["config"].get("port"))


class AlertsCheckOnceLeftoverTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for name, value in (
            ("ALERTS_FILE", root / "alerts.jsonl"),
            ("STATE_FILE", root / "alert_state.json"),
        ):
            patched = mock.patch.object(alerts, name, value)
            patched.start()
            self.addCleanup(patched.stop)

    def _check(self, status, prev):
        with (
            mock.patch.object(alerts, "full_status", return_value=status),
            mock.patch.object(alerts, "_load_state", return_value=prev),
            mock.patch.object(alerts, "notify_settings", return_value={"enabled": False}),
            mock.patch.object(alerts, "_check_resource_thresholds", return_value=[]),
            mock.patch.object(alerts, "_check_smart_health", return_value=[]),
            mock.patch.object(alerts, "_check_ups", return_value=[]),
            mock.patch("hub.ups_policy.sweep", return_value=[]),
            mock.patch("hub.freshness_svc.check_freshness", return_value=[]),
            mock.patch("hub.stale_runtime.remediate", return_value=[]),
        ):
            return alerts.check_once()

    def test_unhashable_service_id_does_not_500(self):
        """Leftover ``id: [foo]`` TypeError'd ``services[s['id']]``."""
        status = {"groups": [{"group": "Core", "services": [
            {"id": ["bad"], "name": "x", "state": "down", "kind": "launchd"},
            {"id": "ok", "name": "ok", "state": "down", "kind": "launchd",
             "detail": "exit 1"},
        ]}]}
        emitted = self._check(status, {"ok": "ok"})
        _json({"emitted": emitted})
        self.assertTrue(all(a.get("id") != ["bad"] for a in emitted))

    def test_leftover_inf_service_fields_do_not_500(self):
        """Starlette allow_nan=False: leftover ``kind: .inf`` used to 500 the check."""
        status = {"groups": [{"group": "Core", "services": [
            {"id": "svc", "name": float("inf"), "state": "down",
             "kind": float("inf"), "group": float("nan"), "detail": "x"},
        ]}]}
        emitted = self._check(status, {"svc": "warn"})
        _json({"emitted": emitted})
        self.assertEqual(len(emitted), 1)
        self.assertIsNone(emitted[0]["name"])
        self.assertIsNone(emitted[0]["kind"])

    def test_leftover_surrogate_service_fields_do_not_500(self):
        """YAML/JSON ``name: "\\ud800"`` used to 500 POST /api/alerts/check."""
        status = {"groups": [{"group": "Core", "services": [
            {"id": "svc", "name": "bad\ud800", "state": "down",
             "kind": "launchd", "group": "Core", "detail": "x\udfff"},
        ]}]}
        emitted = self._check(status, {"svc": "warn"})
        _starlette({"emitted": emitted})
        self.assertEqual(len(emitted), 1)
        self.assertNotIn("\ud800", emitted[0]["name"])
        self.assertNotIn("\udfff", emitted[0]["detail"])

    def test_infinite_now_does_not_500(self):
        """``int(time.time())`` OverflowError on leftover inf used to 500 the check."""
        with (
            mock.patch.object(alerts.time, "time", return_value=float("inf")),
            mock.patch.object(alerts, "notify_settings", return_value={"enabled": False}),
        ):
            emitted = self._check({"groups": []}, {})
            alert = alerts.emit_alert(
                kind="schedule", level="warn",
                alert_id="schedule:x", message="failed",
            )
        _json({"emitted": emitted})
        _starlette(alert)
        self.assertEqual(alert["t"], 0)

    def test_smart_num_leftover_inf_and_huge_int_do_not_raise(self):
        """Leftover ``10**400`` OverflowError'd ``float(int)``; inf used to leak into alerts."""
        self.assertIsNone(alerts._smart_num(float("inf")))
        self.assertIsNone(alerts._smart_num(10 ** 400))
        self.assertEqual(alerts._smart_num(12), 12.0)

    def test_leftover_non_dict_emitted_does_not_500(self):
        """A helper returning inf / a date / !!binary / !!set used to skip sanitization."""
        with (
            mock.patch.object(alerts, "full_status", return_value={"groups": []}),
            mock.patch.object(alerts, "_load_state", return_value={}),
            mock.patch.object(alerts, "notify_settings", return_value={"enabled": False}),
            mock.patch.object(alerts, "_check_resource_thresholds", return_value=[
                float("inf"), datetime.date(2026, 8, 19), b"x", {"alerts"},
                {"ok": float("nan")},
            ]),
            mock.patch.object(alerts, "_check_smart_health", return_value=[]),
            mock.patch.object(alerts, "_check_ups", return_value=[]),
            mock.patch("hub.ups_policy.sweep", return_value=[]),
            mock.patch("hub.freshness_svc.check_freshness", return_value=[]),
            mock.patch("hub.stale_runtime.remediate", return_value=[]),
        ):
            emitted = alerts.check_once()
        _starlette({"emitted": emitted})
        self.assertIsNone(emitted[0])
        self.assertEqual(emitted[1], "2026-08-19")
        self.assertEqual(emitted[2], "x")
        self.assertEqual(emitted[3], ["alerts"])
        self.assertIsNone(emitted[4]["ok"])

    def test_leftover_over_cap_helper_int_does_not_500(self):
        """A helper returning a >4300-digit int used to 500 POST
        /api/alerts/check: the sanitizer passed it through and Starlette's
        ``json.dumps`` raised the digit-cap ValueError itself."""
        with (
            mock.patch.object(alerts, "full_status", return_value={"groups": []}),
            mock.patch.object(alerts, "_load_state", return_value={}),
            mock.patch.object(alerts, "notify_settings", return_value={"enabled": False}),
            mock.patch.object(alerts, "_check_resource_thresholds", return_value=[
                {"id": "r", "n": _HUGE_INT}, _HUGE_INT,
            ]),
            mock.patch.object(alerts, "_check_smart_health", return_value=[]),
            mock.patch.object(alerts, "_check_ups", return_value=[]),
            mock.patch("hub.ups_policy.sweep", return_value=[]),
            mock.patch("hub.freshness_svc.check_freshness", return_value=[]),
            mock.patch("hub.stale_runtime.remediate", return_value=[]),
        ):
            emitted = alerts.check_once()
        _starlette({"emitted": emitted})
        self.assertIsNone(emitted[0]["n"])
        self.assertEqual(emitted[0]["id"], "r")
        self.assertIsNone(emitted[1])


class AlertsListLeftoverTests(unittest.TestCase):
    def test_leftover_surrogate_field_and_key_do_not_500(self):
        """Leftover ``\\ud800`` in alerts.jsonl used to 500 GET /api/alerts."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "alerts.jsonl"
        path.write_text(json.dumps({
            "t": 1, "id": "a", "name": "disk\ud800", "\ud800": "x",
        }) + "\n")
        with mock.patch.object(alerts, "ALERTS_FILE", path):
            rows = alerts.list_alerts(50)
        _starlette(rows)
        self.assertEqual(len(rows), 1)
        self.assertNotIn("\ud800", rows[0]["name"])
        self.assertNotIn("\ud800", rows[0])

    def test_leftover_t_date_and_inf_do_not_render(self):
        """YAML ``t: 2026-08-19`` / ``.inf`` used to stringify into GET /api/alerts."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "alerts.jsonl"
        path.write_text("\n".join([
            json.dumps({"t": "2026-08-19", "id": "a", "name": "x"}),
            json.dumps({"t": None, "id": "b", "name": "y"}),
            json.dumps({"t": 1_800_000_000, "id": "c", "name": "z"}),
        ]) + "\n")
        with mock.patch.object(alerts, "ALERTS_FILE", path):
            rows = alerts.list_alerts(50)
        _starlette(rows)
        by_id = {r["id"]: r["t"] for r in rows}
        self.assertIsNone(by_id["a"])
        self.assertIsNone(by_id["b"])
        self.assertEqual(by_id["c"], 1_800_000_000)

    def test_append_drops_leftover_t(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "alerts.jsonl"
        with mock.patch.object(alerts, "ALERTS_FILE", path):
            alerts._append_alert({"t": datetime.date(2026, 8, 19), "id": "a", "name": "x"})
            alerts._append_alert({"t": float("inf"), "id": "b", "name": "y"})
        rows = [
            json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()
        ]
        self.assertIsNone(rows[0]["t"])
        self.assertIsNone(rows[1]["t"])

    def test_over_cap_digit_alert_line_does_not_500(self):
        """``json.loads`` of a >4300-digit number is the digit-cap ValueError,
        not JSONDecodeError; GET /api/alerts used to 500 on the leftover line."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "alerts.jsonl"
        good = json.dumps({"t": 1, "id": "a", "name": "disk"})
        path.write_text('{"t": 1, "id": "bad", "n": ' + _HUGE_DIGITS + "}\n" + good + "\n")
        with mock.patch.object(alerts, "ALERTS_FILE", path):
            rows = alerts.list_alerts(50)
        _starlette(rows)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], "a")

    def test_deeply_nested_alert_line_does_not_500(self):
        """``json.loads`` RecursionError is not ValueError; GET /api/alerts used to 500."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "alerts.jsonl"
        good = json.dumps({"t": 1, "id": "a", "name": "disk"})
        path.write_text('{"k":' * 12000 + "1" + "}" * 12000 + "\n" + good + "\n")
        with mock.patch.object(alerts, "ALERTS_FILE", path):
            rows = alerts.list_alerts(50)
        _starlette(rows)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], "a")

    def test_save_state_dumps_recursion_does_not_500(self):
        """json.dumps RecursionError is not OSError; POST /api/alerts/check used to 500."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "alert_state.json"
        with (
            mock.patch.object(alerts, "STATE_FILE", path),
            mock.patch.object(alerts.json, "dumps", side_effect=RecursionError),
        ):
            alerts._save_state({"resource:cpu": "warn"})
        self.assertFalse(path.exists())

    def test_append_dumps_recursion_does_not_500(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "alerts.jsonl"
        with (
            mock.patch.object(alerts, "ALERTS_FILE", path),
            mock.patch.object(alerts.json, "dumps", side_effect=RecursionError),
        ):
            alerts._append_alert({"t": 1, "id": "a", "name": "x"})
        self.assertFalse(path.exists() and path.read_text().strip())


class MetricsHugeIntLeftoverTests(unittest.TestCase):
    def test_sample_ts_rejects_a_digit_string_that_overflows_float(self):
        huge = 10 ** 400
        self.assertIsNone(metrics.sample_ts(huge))
        self.assertIsNone(metrics_rollup._sample_ts(huge))
        self.assertIsNone(metrics_rollup._finite_num(huge))

    def test_query_range_huge_window_does_not_500(self):
        out = metrics_rollup.query_range(10 ** 400, 10 ** 400 + 100)
        self.assertEqual(out["points"], [])
        _json(out)

    def test_decimate_leftover_huge_n_does_not_500(self):
        rows = [
            {"t": 1_700_000_000 + i * 90, "n": 10 ** 400, "cpu_used_pct": 10.0}
            for i in range(20)
        ]
        out = metrics_rollup._decimate(rows, 1_700_000_000, 1_700_002_000, 5)
        _json(out)
        self.assertTrue(out)
        self.assertNotEqual(out[0].get("n"), 10 ** 400)

    def test_history_leftover_surrogate_does_not_500(self):
        """Leftover ``note: "\\ud800"`` used to 500 GET /api/metrics."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "metrics.jsonl"
        now = int(time.time())
        path.write_text(json.dumps({
            "t": now - 30, "cpu_used_pct": 1.0, "note": "ok\ud800", "\ud800": 2,
        }) + "\n")
        with mock.patch.object(metrics, "METRICS_FILE", path), mock.patch.object(
            metrics, "_write_buf", [],
        ):
            rows = metrics.history(60)
        _starlette(rows)
        self.assertEqual(len(rows), 1)
        self.assertNotIn("\ud800", rows[0]["note"])
        self.assertNotIn("\ud800", rows[0])

    def test_deeply_nested_history_line_does_not_500(self):
        """``json.loads`` RecursionError is not ValueError; GET /api/metrics used to 500."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "metrics.jsonl"
        now = int(time.time())
        good = json.dumps({"t": now - 30, "cpu_used_pct": 1.0})
        path.write_text('{"k":' * 12000 + "1" + "}" * 12000 + "\n" + good + "\n")
        with mock.patch.object(metrics, "METRICS_FILE", path), mock.patch.object(
            metrics, "_write_buf", [],
        ):
            rows = metrics.history(60)
        _starlette(rows)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["cpu_used_pct"], 1.0)

    def test_over_cap_digit_history_line_does_not_500(self):
        """``json.loads`` digit-cap ValueError is not JSONDecodeError;
        GET /api/metrics used to 500 on the leftover line."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "metrics.jsonl"
        now = int(time.time())
        good = json.dumps({"t": now - 30, "cpu_used_pct": 1.0})
        path.write_text(
            '{"t": ' + str(now - 30) + ', "n": ' + _HUGE_DIGITS + "}\n" + good + "\n"
        )
        with mock.patch.object(metrics, "METRICS_FILE", path), mock.patch.object(
            metrics, "_write_buf", ['{"t": ' + str(now - 20) + ', "n": ' + _HUGE_DIGITS + "}\n"],
        ):
            rows = metrics.history(60)
        _starlette(rows)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["cpu_used_pct"], 1.0)

    def test_over_cap_digit_rollup_lines_do_not_500(self):
        """A >4300-digit head/tail line used to raise the digit-cap ValueError
        out of ``_rows_since`` / ``_first_row_ts`` / ``_last_row_ts`` and 500
        GET /api/metrics?range= (and abort the rollup pass)."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "metrics-5m.jsonl"
        huge = '{"t": 1700000000, "n": ' + _HUGE_DIGITS + "}"
        good = json.dumps({"t": 1_700_000_000, "n": 5, "cpu_used_pct": 1.0})
        path.write_text(huge + "\n" + good + "\n" + huge + "\n")
        rows = metrics_rollup._rows_since(path, 1_700_000_000 - 10)
        _starlette(rows)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["n"], 5)
        self.assertEqual(metrics_rollup._first_row_ts(path), 1_700_000_000)
        self.assertEqual(metrics_rollup._last_row_ts(path), 1_700_000_000)

    def test_metrics_range_router_over_cap_head_line_does_not_500(self):
        """GET /api/metrics?range= probes file heads to pick the tier; a
        leftover >4300-digit first line used to 500 the route there."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        now = int(time.time())
        huge = '{"t": ' + str(now - 60) + ', "n": ' + _HUGE_DIGITS + "}"
        good = json.dumps({"t": now - 30, "cpu_used_pct": 1.0})
        (root / "metrics.jsonl").write_text(huge + "\n" + good + "\n")
        with (
            mock.patch.object(metrics, "METRICS_FILE", root / "metrics.jsonl"),
            mock.patch.object(metrics, "_write_buf", []),
            mock.patch.object(metrics_rollup, "FILE_5M", root / "5m.jsonl"),
            mock.patch.object(metrics_rollup, "FILE_1H", root / "1h.jsonl"),
            mock.patch.object(metrics_rollup, "STATE_FILE", root / "state.json"),
        ):
            out = settings_api.get_metrics(range_="1h")
        _starlette(out)
        self.assertIn("points", out)
        self.assertEqual(len(out["points"]), 1)

    def test_parse_range_over_cap_digits_are_rejected_not_500(self):
        """The router turns parse_range's ValueError into metrics.bad_range;
        pin that the digit-cap raise stays a ValueError, not a 500."""
        with self.assertRaises(ValueError):
            metrics_rollup.parse_range(_HUGE_DIGITS + "h")

    def test_rollup_row_leftover_surrogate_does_not_500(self):
        """Leftover ``\\ud800`` in metrics-5m.jsonl used to 500 GET /api/metrics?range=."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "metrics-5m.jsonl"
        path.write_text(json.dumps({
            "t": 1_700_000_000, "n": 5, "cpu_used_pct": 1.0, "note": "ok\ud800",
        }) + "\n")
        rows = metrics_rollup._rows_since(path, 1_700_000_000 - 10)
        _starlette(rows)
        self.assertEqual(len(rows), 1)
        self.assertNotIn("\ud800", rows[0]["note"])

    def test_deeply_nested_rollup_line_does_not_500(self):
        """``json.loads`` RecursionError is not ValueError; GET /api/metrics?range= used to 500."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "metrics-5m.jsonl"
        good = json.dumps({"t": 1_700_000_000, "n": 5, "cpu_used_pct": 1.0})
        path.write_text('{"k":' * 12000 + "1" + "}" * 12000 + "\n" + good + "\n")
        rows = metrics_rollup._rows_since(path, 1_700_000_000 - 10)
        _starlette(rows)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["n"], 5)

    def test_deeply_nested_rollup_state_does_not_500(self):
        """``json.loads`` RecursionError is not ValueError; leftover nested
        metrics-rollup-state.json used to raise out of maybe_rollup."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        state = root / "state.json"
        state.write_text('{"k":' * 12000 + "1" + "}" * 12000)
        with (
            mock.patch.object(metrics, "METRICS_FILE", root / "metrics.jsonl"),
            mock.patch.object(metrics_rollup, "FILE_5M", root / "5m.jsonl"),
            mock.patch.object(metrics_rollup, "FILE_1H", root / "1h.jsonl"),
            mock.patch.object(metrics_rollup, "STATE_FILE", state),
            mock.patch.object(metrics_rollup, "_state", {"w5": 0, "w1h": 0}),
            mock.patch.object(metrics_rollup, "_state_loaded", False),
            mock.patch.object(metrics_rollup, "_last_trim", {"5m": 0.0, "1h": 0.0}),
        ):
            done = metrics_rollup.maybe_rollup(now=1_700_000_000)
        self.assertIn("w5", done)
        self.assertIn("w1h", done)

    def test_metrics_range_router_infinite_clock_does_not_500(self):
        """``int(time.time())`` OverflowError on leftover inf used to 500 GET /api/metrics?range=."""
        from hub.routers import settings_api

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        with (
            mock.patch.object(metrics, "METRICS_FILE", root / "metrics.jsonl"),
            mock.patch.object(metrics, "_write_buf", []),
            mock.patch.object(metrics_rollup, "FILE_5M", root / "5m.jsonl"),
            mock.patch.object(metrics_rollup, "FILE_1H", root / "1h.jsonl"),
            mock.patch.object(metrics_rollup, "STATE_FILE", root / "state.json"),
            mock.patch.object(metrics_rollup, "_state", {"w5": 0, "w1h": 0}),
            mock.patch.object(metrics_rollup, "_state_loaded", False),
            mock.patch("hub.routers.settings_api.time.time", return_value=float("inf")),
        ):
            out = settings_api.get_metrics(range_="1h")
        _starlette(out)
        self.assertIn("points", out)

    def test_history_infinite_now_does_not_500(self):
        """``int(time.time())`` OverflowError on leftover inf used to 500 GET /api/metrics."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "metrics.jsonl"
        path.write_text(json.dumps({"t": 1_700_000_000, "cpu_used_pct": 1.0}) + "\n")
        with (
            mock.patch.object(metrics, "METRICS_FILE", path),
            mock.patch.object(metrics, "_write_buf", []),
            mock.patch.object(metrics.time, "time", return_value=float("inf")),
        ):
            rows = metrics.history(60)
        _starlette(rows)

    def test_ncpu_leftover_inf_cache_does_not_raise(self):
        """Leftover planted ``n: .inf`` OverflowError'd ``int(inf)`` in ``_ncpu``."""
        with mock.patch.object(metrics, "_ncpu_cache", {"t": time.time(), "n": float("inf")}):
            n = metrics._ncpu()
        self.assertIsInstance(n, int)
        self.assertGreater(n, 0)

    def test_query_range_infinite_now_does_not_500(self):
        """``int((time.time() - since) // 60)`` OverflowError'd GET /api/metrics?range=."""
        with (
            mock.patch.object(metrics.time, "time", return_value=float("inf")),
            mock.patch.object(metrics_rollup.time, "time", return_value=float("inf")),
        ):
            out = metrics_rollup.query_range(1_700_000_000, 1_700_000_060)
        _starlette(out)
        self.assertEqual(out["points"], out.get("points", []))

    def test_router_infinite_since_until_does_not_500(self):
        with mock.patch.object(settings_api.time, "time", return_value=1_700_000_000):
            out = settings_api.get_metrics(since=float("inf"), until=float("inf"))
        _starlette(out)
        self.assertIn("points", out)

    def test_leftover_huge_rollup_file_is_capped(self):
        """Unbounded ``_rows_since`` of leftover multi-MB jsonl used to OOM GET /api/metrics?range=."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "metrics-5m.jsonl"
        rows = [
            {"t": 1_700_000_000 + i * 300, "n": 1, "cpu_used_pct": 1.0}
            for i in range(400)
        ]
        path.write_text("".join(json.dumps(r) + "\n" for r in rows))
        with mock.patch.object(metrics_rollup, "_ROWS_CAP", 2048):
            got = metrics_rollup._rows_since(path, 1_700_000_000)
        _starlette(got)
        self.assertTrue(got)
        self.assertLess(len(got), 400)
        self.assertGreaterEqual(got[0]["t"], 1_700_000_000)

    def test_deeply_nested_rollup_trim_line_does_not_raise(self):
        """A leftover nested aggregate line used to RecursionError the trim."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "5m.jsonl"
        now = 1_800_000_000
        old = now - metrics_rollup.RETAIN_5M - metrics_rollup._TRIM_SLACK["5m"] - 10
        keep = now - 60
        path.write_text(
            json.dumps({"t": old, "n": 1}) + "\n"
            + '{"k":' * 12000 + "1" + "}" * 12000 + "\n"
            + json.dumps({"t": keep, "n": 2}) + "\n"
        )
        with mock.patch.object(metrics_rollup, "_last_trim", {"5m": 0.0, "1h": 0.0}):
            metrics_rollup._maybe_trim_locked("5m", path, now=now)
        rows = [
            json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()
        ]
        self.assertEqual([r["n"] for r in rows], [2])

    def test_over_cap_digit_rollup_trim_line_does_not_raise(self):
        """A leftover >4300-digit aggregate line used to raise the digit-cap
        ValueError out of the trim and abort it."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "5m.jsonl"
        now = 1_800_000_000
        old = now - metrics_rollup.RETAIN_5M - metrics_rollup._TRIM_SLACK["5m"] - 10
        keep = now - 60
        path.write_text(
            json.dumps({"t": old, "n": 1}) + "\n"
            + '{"t": ' + str(keep) + ', "n": ' + _HUGE_DIGITS + "}\n"
            + json.dumps({"t": keep, "n": 2}) + "\n"
        )
        with mock.patch.object(metrics_rollup, "_last_trim", {"5m": 0.0, "1h": 0.0}):
            metrics_rollup._maybe_trim_locked("5m", path, now=now)
        rows = [
            json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()
        ]
        self.assertEqual([r["n"] for r in rows], [2])


class NotifyDispatchLeftoverTests(unittest.TestCase):
    def test_leftover_surrogate_channel_id_does_not_500_dispatch(self):
        """YAML ``id: "\\ud800ok"`` used to 500 POST /api/alerts/test."""
        raw = {"channels": [{"id": "\ud800ok", "type": "slack"}]}
        with mock.patch.object(notify_channels, "_raw_notify_cfg", lambda: raw), mock.patch.dict(
            notify_channels._SENDERS, {"slack": lambda *a, **k: {"ok": True, "message": "sent"}},
        ):
            res = notify_channels.dispatch("T", "M", level="down")
        _starlette(res)
        self.assertTrue(res["ok"], res)
        self.assertNotIn("\ud800", res["results"][0]["id"])

    def test_leftover_surrogate_id_timeout_does_not_500(self):
        """Timeout/exception rows skipped ``_json_safe``; leftover ``\\ud800`` 500'd the test send."""
        raw = {"channels": [{"id": "\ud800ok", "type": "slack"}]}
        fut = mock.Mock()
        fut.done.return_value = False
        pool = mock.MagicMock()
        pool.submit.return_value = fut
        with mock.patch.object(notify_channels, "_raw_notify_cfg", lambda: raw), mock.patch(
            "hub.notify_channels.ThreadPoolExecutor", return_value=pool,
        ), mock.patch("hub.notify_channels.futures_wait"):
            res = notify_channels.dispatch("T", "M", level="down")
        _starlette(res)
        self.assertFalse(res["ok"])
        self.assertEqual(len(res["results"]), 1)
        self.assertNotIn("\ud800", res["results"][0]["id"])
        self.assertNotIn("\ud800", res.get("message") or "")

    def test_leftover_surrogate_id_future_exception_does_not_500(self):
        raw = {"channels": [{"id": "\ud800ok", "type": "slack"}]}
        fut = mock.Mock()
        fut.done.return_value = True
        fut.result.side_effect = RuntimeError("boom\ud800")
        pool = mock.MagicMock()
        pool.submit.return_value = fut
        with mock.patch.object(notify_channels, "_raw_notify_cfg", lambda: raw), mock.patch(
            "hub.notify_channels.ThreadPoolExecutor", return_value=pool,
        ), mock.patch("hub.notify_channels.futures_wait"):
            res = notify_channels.dispatch("T", "M", level="down")
        _starlette(res)
        self.assertFalse(res["ok"])
        self.assertNotIn("\ud800", json.dumps(res, ensure_ascii=False))

    def test_pathological_exc_str_does_not_500_dispatch(self):
        """``str(exc)`` RecursionError used to 500 POST /api/alerts/test."""

        class Boom(Exception):
            def __str__(self):
                raise RecursionError("loop")

        raw = {"channels": [{"id": "slack", "type": "slack"}]}
        with mock.patch.object(notify_channels, "_raw_notify_cfg", lambda: raw), mock.patch.dict(
            notify_channels._SENDERS, {"slack": lambda *a, **k: (_ for _ in ()).throw(Boom())},
        ):
            res = notify_channels.dispatch("T", "M", level="down")
        _starlette(res)
        self.assertFalse(res["ok"])
        self.assertTrue(res["results"])

    def test_leftover_sender_message_types_do_not_500(self):
        ch = {"id": "c1", "type": "slack"}
        for leftover in (float("inf"), float("nan"), datetime.date(2026, 8, 19), b"fail", {"x"}):
            out = notify_channels._send_via(
                lambda *a, **k: {"ok": False, "message": leftover},
                ch, {}, "T", "M", level="down", event=None,
            )
            _starlette(out)
            self.assertFalse(out["ok"])

    def test_leftover_date_and_inf_payload_do_not_raise_post(self):
        """``level: 2026-08-19`` / ``.inf`` used to raise ``json.dumps`` in ``_post``."""
        with mock.patch.object(notify_channels, "notify_connect_peer", return_value="203.0.113.10") as peer, \
             mock.patch.object(notify_channels, "_open_request", side_effect=AssertionError("net")):
            dated = notify_channels._post(
                "https://hooks.example.com/x",
                {"level": datetime.date(2026, 8, 19)},
            )
            inf = notify_channels._post(
                "https://hooks.example.com/x", {"level": float("inf")},
            )
        self.assertFalse(dated["ok"])
        self.assertIn("net", dated["message"])
        peer.assert_called()
        self.assertFalse(inf["ok"])
        # ``_json_safe`` drops leftover inf before dumps, so the post proceeds
        # to the socket instead of raising / sending Infinity.
        self.assertIn("net", inf["message"])
        _starlette(dated)
        _starlette(inf)


class NotifySecretsDumpLeftoverTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "notify-credentials.json"
        patched = mock.patch.object(notify_channels, "SECRETS_FILE", self.path)
        patched.start()
        self.addCleanup(patched.stop)

    def test_leftover_inf_sibling_does_not_500_set(self):
        """``json.dumps`` without allow_nan=False used to rewrite Infinity onto disk."""
        self.path.write_text('{"other": {"token": Infinity, "n": NaN}}\n')
        notify_channels.set_channel_secrets("c1", {"token": "new"})
        raw = json.loads(self.path.read_text())
        json.dumps(raw, allow_nan=False)
        self.assertEqual(raw["c1"]["token"], "new")
        self.assertIsNone(raw["other"]["token"])
        self.assertIsNone(raw["other"]["n"])

    def test_leftover_inf_sibling_does_not_500_drop(self):
        self.path.write_text(
            '{"gone": {"url": "https://x"}, "other": {"token": Infinity}}\n'
        )
        notify_channels.drop_channel_secrets("gone")
        raw = json.loads(self.path.read_text())
        json.dumps(raw, allow_nan=False)
        self.assertNotIn("gone", raw)
        self.assertIsNone(raw["other"]["token"])

    def test_leftover_directory_occupying_secrets_does_not_500_set(self):
        """Empty leftover dir named notify-credentials.json used to 500 PUT channels."""
        self.path.mkdir()
        notify_channels.set_channel_secrets("c1", {"token": "new"})
        raw = json.loads(self.path.read_text())
        json.dumps(raw, allow_nan=False)
        self.assertEqual(raw["c1"]["token"], "new")

    def test_leftover_nonempty_secrets_directory_does_not_500_set(self):
        self.path.mkdir()
        (self.path / "stuck").write_text("x", encoding="utf-8")
        notify_channels.set_channel_secrets("c1", {"token": "new"})
        self.assertTrue(self.path.is_dir())

    def test_write_secrets_dumps_recursion_does_not_500(self):
        """json.dumps RecursionError is not OSError; PUT /api/alerts/channels used to 500."""
        with mock.patch.object(notify_channels.json, "dumps", side_effect=RecursionError):
            notify_channels._write_secrets({"c1": {"token": "x"}})
        self.assertFalse(self.path.exists() and self.path.is_file() and self.path.read_text().strip())


class AlertsJsonableKeepsFiniteFloats(unittest.TestCase):
    def test_finite_float_is_not_stringified(self):
        out = alerts._jsonable_alert({"cpu": 12.5, "ok": True})
        self.assertEqual(out["cpu"], 12.5)
        self.assertIs(out["ok"], True)
        _json(out)

    def test_format_alert_recursing_and_surrogate_do_not_500(self):
        """``str.format`` RecursionError used to abort the SMART pass."""
        class Recursing:
            def __format__(self, spec):
                raise RecursionError("nested")
            def __str__(self):
                raise RecursionError("nested")

        text = alerts._format_alert("Disk {label}", label=Recursing())
        _starlette({"m": text})
        self.assertEqual(text, "Disk Recursing")
        text = alerts._format_alert("Disk {label}", label="SSD\ud800")
        _starlette({"m": text})
        self.assertNotIn("\ud800", text)


class MetricsRecordSampleDumpsLeftoverTests(unittest.TestCase):
    def test_record_sample_dumps_recursion_does_not_raise(self):
        """json.dumps RecursionError used to kill the metrics sampler thread."""
        with (
            mock.patch.object(metrics, "_write_buf", []),
            mock.patch.object(metrics.json, "dumps", side_effect=RecursionError),
        ):
            sample = metrics.record_sample({"t": 1, "cpu_used_pct": 1.0})
        self.assertIsInstance(sample, dict)
        _json(sample)


class AlertsInfClockStrftimeLeftoverTests(unittest.TestCase):
    def test_overflow_strftime_does_not_500_test_notify(self):
        """Leftover inf clock OverflowError'd POST /api/alerts/test message ts."""
        captured = {}

        def _send(title, message, **kwargs):
            captured["message"] = message
            return {"ok": True, "title": title, "message": message}

        with (
            mock.patch("hub.util.time.strftime", side_effect=OverflowError),
            mock.patch.object(alerts, "send_ha_notify", side_effect=_send),
        ):
            out = alerts.test_notify()
        _starlette(out)
        self.assertEqual(captured["message"], "Notification channel test ")

    def test_overflow_strftime_does_not_500_channel_test(self):
        """Leftover inf clock OverflowError'd POST /api/alerts/channels/{id}/test."""
        from hub.routers import notify_api

        captured = {}

        def _dispatch(title, message, **kwargs):
            captured["message"] = message
            return {"ok": True}

        with (
            mock.patch("hub.util.time.strftime", side_effect=OverflowError),
            mock.patch.object(notify_channels, "valid_channel_id", return_value=True),
            mock.patch.object(
                notify_channels, "get_channel",
                return_value={"id": "c1", "type": "ntfy", "name": "n"},
            ),
            mock.patch.object(notify_channels, "dispatch", side_effect=_dispatch),
            mock.patch.object(notify_api.audit, "record"),
            mock.patch.object(notify_api, "request_username", return_value="op"),
        ):
            out = notify_api.test_channel("c1", request=mock.Mock())
        _starlette(out)
        self.assertEqual(captured["message"], "Notification channel test ")


class MetricsRollupUtf8TextRecursionLeftoverTests(unittest.TestCase):
    def test_utf8_text_recursing_does_not_500(self):
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(metrics_rollup._utf8_text(Recursing()), "Recursing")
        _starlette({"k": metrics_rollup._utf8_text(Recursing())})


class AlertsMetricsNotifyJsonableLeftoverTests(unittest.TestCase):
    def test_isoformat_inf_date_bytes_set_do_not_500(self):
        """A leftover ``isoformat()`` returning inf used to 500 alerts/metrics/notify JSON."""
        class _Stamp:
            def isoformat(self):
                return float("inf")

        self.assertIsNone(alerts._jsonable_alert(_Stamp()))
        self.assertIsNone(metrics._jsonable(_Stamp()))
        self.assertIsNone(metrics_rollup._jsonable(_Stamp()))
        self.assertIsNone(notify_channels._json_safe(_Stamp()))
        for fn in (
            alerts._jsonable_alert, metrics._jsonable,
            metrics_rollup._jsonable, notify_channels._json_safe,
        ):
            out = fn({
                "when": _Stamp(),
                "name": datetime.date(2026, 8, 19),
                "blob": b"ok",
                "tags": {"cpu"},
                "n": float("inf"),
            })
            _starlette(out)
            self.assertIsNone(out["when"])
            self.assertEqual(out["name"], "2026-08-19")
            self.assertEqual(out["blob"], "ok")
            self.assertEqual(out["tags"], ["cpu"])
            self.assertIsNone(out["n"])

    def test_over_cap_int_is_dropped_not_500(self):
        """A >4300-digit int passed the sanitizers untouched, and Starlette's
        ``json.dumps`` then raised CPython's int->str digit-cap ValueError."""
        for fn in (
            alerts._jsonable_alert, metrics._jsonable,
            metrics_rollup._jsonable, notify_channels._json_safe,
        ):
            self.assertIsNone(fn(_HUGE_INT))
            out = fn({"n": _HUGE_INT, "ok": 7, "f": 1.5, "b": True})
            _starlette(out)
            self.assertIsNone(out["n"])
            self.assertEqual(out["ok"], 7)
            self.assertEqual(out["f"], 1.5)
            self.assertIs(out["b"], True)


if __name__ == "__main__":
    unittest.main()
