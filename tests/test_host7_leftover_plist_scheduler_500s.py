"""Host7 leftover sweep: launchd/plist and system-diagnostics raw-500s over the real app.

A hostile re-sweep of the host/diagnostics surfaces over ``create_app()`` +
``TestClient(raise_server_exceptions=False)``, after host6 sealed the
disk/scheduler/diagnostics sanitizers, found three clusters still answering
raw 500s:

* **GET /api/system/scheduler never sanitized at all.**  It handed
  ``launchd_timers()`` rows straight to Starlette while *both* scheduler
  siblings (GET /api/scheduler, GET /api/settings/scheduler) scrubbed the
  same data — a leftover ``\\ud800`` label, an over-cap interval, an
  items()-bomb row or an ``__iter__``-bomb timers list each 500'd here and
  answered 200 one alias over.  A non-list answer also leaked through as
  ``{"timers": {...}}``, a shape no consumer of this route ever renders.

* **The launchd plist readers trusted the parser answer wholesale.**
  ``launchd_timers`` and ``launchd_agents_summary`` gated on
  ``isinstance(pl, dict)`` then read with the *bound* ``.get`` — a
  dict-subclass parser answer with a bombing ``.get`` raised straight out —
  and the Label fallback rode a bare ``or`` that dispatched into a leftover
  value's own ``__bool__``.  ``bool(RunAtLoad/KeepAlive/Disabled/calendar)``
  detonated the same way, and a ProgramArguments list subclass whose
  ``__iter__`` bombs blew the display join.  Inside ``_plist_jsonable``
  every coercion was bound (``value.items()``, iteration, ``value.decode``,
  the ValueError-only ``str()`` digit-cap probe), so a calendar carrying an
  items()-bomb dict, an ``__iter__``-bomb list, a decode()-bomb bytes or an
  ``__index__``/``__str__``-bomb int 500'd GET /api/system/scheduler while
  its plain-typed siblings rendered fine.  The unbound base reads now
  salvage the real C-level content instead of dropping or raising.

* **GET /api/system/diagnostics: one unguarded cross-module read.**
  ``tools_svc.diagnostics`` guarded every probe through its fan-out, then
  read ``len(metrics.history(60))`` bare in the return dict — a leftover
  history table that refuses ``len()`` (a list-subclass ``__len__`` bomb)
  cost the whole bundle after every probe had already answered.
"""
from __future__ import annotations

import json
import plistlib
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import metrics, tools_svc
from hub.app_factory import create_app
from hub.auth import require_auth


class GetBomb(dict):
    """Passes ``isinstance(x, dict)``; the bound ``.get`` raises."""

    def get(self, *a, **k):
        raise RuntimeError("get bomb")


class ItemsBomb(dict):
    """Passes ``isinstance(x, dict)``; the bound ``items()`` raises."""

    def items(self):
        raise RuntimeError("items bomb")


class IterBombList(list):
    """Passes ``isinstance(x, list)``; bound iteration raises."""

    def __iter__(self):
        raise RuntimeError("iter bomb")


class LenBombList(list):
    """Passes ``isinstance(x, list)``; ``len()`` raises."""

    def __len__(self):
        raise RuntimeError("len bomb")


class BoolBomb:
    def __bool__(self):
        raise RuntimeError("bool bomb")


class DecodeBombBytes(bytes):
    def decode(self, *a, **k):
        raise RuntimeError("decode bomb")


class IndexStrBombInt(int):
    """An int whose bound ``__index__``/``__str__`` both raise."""

    def __index__(self):
        raise RuntimeError("index bomb")

    def __str__(self):
        raise RuntimeError("str bomb")


#: An already-parsed over-cap int: XML plists load ``<integer>0x…</integer>``
#: uncapped through ``int(raw, 16)``, so ``str()`` of it raises the 4300-digit
#: ValueError and json.dumps cannot render it at all.
OVER_CAP_INT = 1 << 20000
SURROGATE = "\ud800leftover"


class _HttpPin(unittest.TestCase):
    def _client(self) -> TestClient:
        app = create_app()
        app.dependency_overrides[require_auth] = lambda: None
        self.addCleanup(app.dependency_overrides.clear)
        return TestClient(app, raise_server_exceptions=False)

    def _ok_body(self, resp) -> dict:
        self.assertEqual(resp.status_code, 200, resp.text[:400])
        body = resp.json()
        # The body Starlette encoded must be re-encodable under the same
        # allow_nan=False / UTF-8 contract it used.
        json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        return body


class SystemSchedulerRoutePins(_HttpPin):
    """GET /api/system/scheduler sanitizes like its two scheduler siblings."""

    def _get(self, timers):
        client = self._client()
        with mock.patch.object(tools_svc, "launchd_timers", return_value=timers):
            return client.get("/api/system/scheduler")

    def test_surrogate_label_is_scrubbed_not_500(self):
        body = self._ok_body(self._get([
            {"label": SURROGATE, "interval_sec": 300},
        ]))
        self.assertIn("leftover", body["timers"][0]["label"])
        self.assertEqual(body["timers"][0]["interval_sec"], 300)

    def test_over_cap_interval_drops_like_inf(self):
        body = self._ok_body(self._get([
            {"label": "com.example.huge", "interval_sec": OVER_CAP_INT},
        ]))
        self.assertIsNone(body["timers"][0]["interval_sec"])
        self.assertEqual(body["timers"][0]["label"], "com.example.huge")

    def test_items_bomb_row_drops_alone_not_500(self):
        body = self._ok_body(self._get([
            ItemsBomb({"label": "x"}),
            {"label": "com.example.ok", "interval_sec": 60},
        ]))
        self.assertIsNone(body["timers"][0])
        self.assertEqual(body["timers"][1]["label"], "com.example.ok")

    def test_iter_bomb_timers_list_degrades_to_empty(self):
        body = self._ok_body(self._get(IterBombList([{"label": "x"}])))
        self.assertEqual(body["timers"], [])

    def test_non_list_timers_degrade_to_empty(self):
        body = self._ok_body(self._get({"not": "a list"}))
        self.assertEqual(body["timers"], [])


class _PlistReaderPin(_HttpPin):
    """Drive both launchd plist readers over a leftover parser answer."""

    def _timers(self, pl):
        client = self._client()
        with (
            mock.patch.object(plistlib, "loads", return_value=pl),
            mock.patch.object(tools_svc, "read_bytes_capped", return_value=b"x"),
            mock.patch.object(
                tools_svc.glob, "glob", return_value=["/tmp/leftover.plist"],
            ),
        ):
            return self._ok_body(client.get("/api/system/scheduler"))["timers"]

    def _agents(self, pl):
        client = self._client()
        with (
            mock.patch.object(plistlib, "loads", return_value=pl),
            mock.patch.object(tools_svc, "read_bytes_capped", return_value=b"x"),
            mock.patch.object(
                Path, "glob", return_value=[Path("/tmp/leftover.plist")],
            ),
        ):
            return self._ok_body(client.get("/api/tools/agents"))["agents"]


class LaunchdPlistSubclassBombPins(_PlistReaderPin):
    """Dict-subclass / ``__bool__`` / iter bombs in the parsed plist."""

    def test_get_bomb_plist_is_laundered_not_500(self):
        pl = GetBomb({"Label": "com.example.job", "StartInterval": 5})
        rows = self._timers(pl)
        # dict(...) laundering keeps the values the bomb was holding.
        self.assertEqual(rows[0]["label"], "com.example.job")
        self.assertEqual(rows[0]["interval_sec"], 5)
        agents = self._agents(pl)
        self.assertEqual(agents[0]["label"], "com.example.job")
        self.assertEqual(agents[0]["interval_sec"], 5)

    def test_bool_bomb_label_falls_to_the_stem(self):
        pl = {"Label": BoolBomb(), "StartInterval": 5}
        rows = self._timers(pl)
        # The bombing value reads as "not a name"; the filename answers.
        self.assertEqual(rows[0]["label"], "leftover")
        agents = self._agents(pl)
        self.assertEqual(agents[0]["label"], "leftover")

    def test_bool_bomb_calendar_reads_as_absent_not_500(self):
        pl = {"Label": "com.example.job", "StartCalendarInterval": BoolBomb()}
        # No interval and a calendar that refuses truth: not a timer.
        self.assertEqual(self._timers(pl), [])
        agents = self._agents(pl)
        self.assertIs(agents[0]["calendar"], False)

    def test_bool_bomb_flags_degrade_to_false_not_500(self):
        pl = {
            "Label": "com.example.job",
            "RunAtLoad": BoolBomb(),
            "KeepAlive": BoolBomb(),
            "Disabled": BoolBomb(),
        }
        agents = self._agents(pl)
        self.assertIs(agents[0]["run_at_load"], False)
        self.assertIs(agents[0]["keep_alive"], False)
        self.assertIs(agents[0]["disabled"], False)

    def test_iter_bomb_program_arguments_salvage_content(self):
        pl = {
            "Label": "com.example.job",
            "StartInterval": 5,
            "ProgramArguments": IterBombList(["/bin/echo", "hi"]),
        }
        # Base-storage copy: the real argv survives the bound-iter bomb.
        rows = self._timers(pl)
        self.assertEqual(rows[0]["program"], "/bin/echo hi")
        agents = self._agents(pl)
        self.assertEqual(agents[0]["program"], "/bin/echo hi")


class PlistJsonableCoercionPins(_PlistReaderPin):
    """Nested unbound coercions inside the calendar sanitizer."""

    def test_items_bomb_calendar_salvages_the_keys(self):
        rows = self._timers({
            "Label": "x", "StartCalendarInterval": ItemsBomb({"Minute": 5}),
        })
        self.assertEqual(rows[0]["calendar"], {"Minute": 5})

    def test_iter_bomb_calendar_list_salvages_entries(self):
        rows = self._timers({
            "Label": "x",
            "StartCalendarInterval": IterBombList([{"Minute": 5}]),
        })
        self.assertEqual(rows[0]["calendar"], [{"Minute": 5}])

    def test_decode_bomb_bytes_are_base_decoded(self):
        rows = self._timers({
            "Label": "x",
            "StartCalendarInterval": {"raw": DecodeBombBytes(b"ok")},
        })
        self.assertEqual(rows[0]["calendar"]["raw"], "ok")

    def test_index_str_bomb_int_salvages_the_value(self):
        rows = self._timers({
            "Label": "x",
            "StartCalendarInterval": {"Minute": IndexStrBombInt(5)},
        })
        self.assertEqual(rows[0]["calendar"]["Minute"], 5)

    def test_over_cap_calendar_int_drops_like_inf(self):
        rows = self._timers({
            "Label": "x",
            "StartCalendarInterval": {"Minute": OVER_CAP_INT, "Hour": 3},
        })
        self.assertIsNone(rows[0]["calendar"]["Minute"])
        self.assertEqual(rows[0]["calendar"]["Hour"], 3)

    def test_index_str_bomb_start_interval_salvages(self):
        rows = self._timers({"Label": "x", "StartInterval": IndexStrBombInt(7)})
        self.assertEqual(rows[0]["interval_sec"], 7)

    def test_surrogate_calendar_value_is_scrubbed(self):
        rows = self._timers({
            "Label": "x", "StartCalendarInterval": {"Note": SURROGATE},
        })
        self.assertIn("leftover", rows[0]["calendar"]["Note"])


class SystemDiagnosticsMetricsPins(_HttpPin):
    """GET /api/system/diagnostics: the one unguarded cross-module read."""

    def _get(self, history):
        client = self._client()
        with mock.patch.object(metrics, "history", return_value=history):
            return client.get("/api/system/diagnostics")

    def test_len_bomb_history_costs_one_field_not_the_bundle(self):
        body = self._ok_body(self._get(LenBombList([{"cpu": 1}])))
        self.assertEqual(body["metrics_points"], 0)
        # Every sibling section still answers.
        for field in ("hostname", "platform", "load", "root_disk_pct", "version"):
            self.assertIn(field, body)

    def test_unsized_history_degrades_the_count_only(self):
        body = self._ok_body(self._get(None))
        self.assertEqual(body["metrics_points"], 0)
        self.assertIn("hostname", body)


if __name__ == "__main__":
    unittest.main()
