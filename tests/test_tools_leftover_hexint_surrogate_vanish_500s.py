"""Leftover Tools 500s: hex-plist over-cap ints, surrogate CLI paths in the
diagnostics/about payloads, and the vanished-docker df/prune answers.

The launchd battery (test_files_logs_tools_leftover_500s) pinned inf floats,
surrogate labels and multi-MB plists.  This sweep covers the shapes those pins
dodge, on the Tools page's own endpoints:

* XML plists route ``<integer>0x…</integer>`` through ``int(raw, 16)``, which
  CPython's 4300-digit conversion limit does not apply to — so a leftover hex
  ``StartInterval`` / ``StartCalendarInterval`` arrived *already-int*, passed
  ``_plist_int``'s bare ``int(raw)`` and ``_plist_jsonable``'s bare
  ``isinstance(value, int)`` branch untouched, and Starlette's ``json.dumps``
  itself raised the int->str digit-cap ValueError — 500ing
  GET /api/system/scheduler, GET /api/scheduler and GET /api/tools/agents;
* ``diagnostics()`` returns ``hub.paths.DOCKER`` / ``ORB`` raw.  Both are
  resolved via ``shutil.which`` over a surrogateescape-decoded PATH, so a
  leftover non-UTF-8 byte there surfaces as a lone surrogate in the resolved
  path and 500'd GET /api/system/diagnostics at Starlette's UTF-8 encode —
  the exact sibling of the ``_host_snapshot`` fix, one module over, where
  every other field already goes through ``_as_text``.  ``about_info()``'s
  ``base`` (``str(BASE)``, derived from ``__file__``) 500'd
  GET /api/tools/about the same way;
* a docker CLI that vanished inside ``engine_up()``'s 5s memo made
  GET /api/docker/df answer ``{"engine_up": true, "raw": "not found"}`` — a
  payload that tells the operator the engine is up while quoting the spawn
  sentinel — and POST /api/tools/docker/prune answer an uncoded
  ``{"ok": false, "message": "not found"}`` instead of the coded 503-state
  ``container.engine_down`` the daemon-socket branch right next to it already
  returns.  Classification requires the disk confirm (the docker_cli
  ``looks_cli_vanished`` contract: pattern-match, then confirm), run only on
  the failure path, so a still-present CLI whose output merely reads
  ``not found`` — or a genuinely running engine — keeps its raw result.

No os.kill/ctypes pid surface exists on this page (flush-dns kills by name,
the process table only renders pids), so the pid-overflow class has nothing
to pin here.
"""
from __future__ import annotations

import json
import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import tools_svc

#: Built arithmetically: int("9" * 5000) itself trips the digit cap.
_HUGE_INT = 16 ** 5000


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class HexPlistVectorTest(unittest.TestCase):
    def test_hex_plist_integer_loads_past_the_digit_cap(self):
        """The vector this file guards: plistlib routes 0x text through
        int(raw, 16), which the conversion limit does not apply to."""
        xml = (
            b'<?xml version="1.0" encoding="UTF-8"?><plist version="1.0">'
            b"<dict><key>StartInterval</key><integer>0x" + b"f" * 5000
            + b"</integer></dict></plist>"
        )
        loaded = plistlib.loads(xml)
        self.assertIsInstance(loaded["StartInterval"], int)
        with self.assertRaises(ValueError):
            str(loaded["StartInterval"])


class LaunchdOverCapIntTests(unittest.TestCase):
    """GET /api/system/scheduler and /api/tools/agents must drop what
    json.dumps cannot render."""

    def _agents_dir(self, payload: dict) -> tempfile.TemporaryDirectory:
        tmp = tempfile.TemporaryDirectory()
        (Path(tmp.name) / "x.plist").write_bytes(plistlib.dumps({
            "Label": "job", "ProgramArguments": ["true"], **payload,
        }))
        return tmp

    def _timers(self, agents: Path, leftover: dict | None = None) -> list:
        patches = [
            mock.patch.object(tools_svc.os.path, "expanduser", return_value=str(agents)),
            mock.patch.object(
                tools_svc.glob, "glob", return_value=[str(agents / "x.plist")],
            ),
        ]
        if leftover is not None:
            patches.append(mock.patch.object(plistlib, "loads", return_value=leftover))
        for p in patches:
            p.start()
        try:
            return tools_svc.launchd_timers()
        finally:
            for p in patches:
                p.stop()

    def test_plist_int_drops_over_cap_interval(self):
        self.assertIsNone(tools_svc._plist_int(_HUGE_INT))
        self.assertEqual(tools_svc._plist_int(60), 60)

    def test_plist_jsonable_drops_over_cap_calendar_value(self):
        cleaned = tools_svc._plist_jsonable({"Minute": _HUGE_INT, "Hour": 3})
        _starlette(cleaned)
        self.assertIsNone(cleaned["Minute"])
        self.assertEqual(cleaned["Hour"], 3)

    def test_plist_jsonable_replaces_surrogate_keys_and_values(self):
        """Keys AND values: a leftover ``\\ud800`` in either must be
        replace-encoded, not served raw to the UTF-8 encoder."""
        cleaned = tools_svc._plist_jsonable({"Min\ud800ute": "a\ud800b"})
        _starlette(cleaned)
        blob = json.dumps(cleaned, ensure_ascii=False)
        self.assertNotIn("\ud800", blob)

    def test_hex_interval_does_not_500_launchd_timers(self):
        """A leftover hex StartInterval used to 500 GET /api/system/scheduler.

        An unrenderable interval with no calendar leaves nothing to show, so
        the entry is skipped — same as the existing inf-StartInterval pin.
        """
        # plistlib.dumps rejects over-cap ints on write, so the leftover is
        # injected the way it arrives in production: already parsed.
        with self._agents_dir({"StartInterval": 60}) as tmp:
            timers = self._timers(Path(tmp), {
                "Label": "job",
                "StartInterval": _HUGE_INT,
                "ProgramArguments": ["true"],
            })
        _starlette(timers)
        self.assertEqual(timers, [])

    def test_hex_calendar_minute_does_not_500_launchd_timers(self):
        """The calendar dict travels ``_plist_jsonable``; an over-cap minute
        used to ValueError Starlette's own json.dumps."""
        with self._agents_dir({}) as tmp:
            timers = self._timers(Path(tmp), {
                "Label": "job",
                "StartCalendarInterval": {"Minute": _HUGE_INT, "Hour": 3},
                "ProgramArguments": ["true"],
            })
        _starlette(timers)
        self.assertEqual(len(timers), 1)
        self.assertIsNone(timers[0]["calendar"]["Minute"])
        self.assertEqual(timers[0]["calendar"]["Hour"], 3)

    def test_hex_interval_does_not_500_agents_summary(self):
        """GET /api/tools/agents lists every agent; the row must survive with
        its unrenderable interval dropped rather than costing the payload."""
        with self._agents_dir({}) as tmp:
            agents = Path(tmp)
            leftover = {
                "Label": "job",
                "StartInterval": _HUGE_INT,
                "RunAtLoad": True,
                "ProgramArguments": ["true"],
            }
            with (
                mock.patch.object(tools_svc.os.path, "expanduser", return_value=str(agents)),
                mock.patch.object(plistlib, "loads", return_value=leftover),
            ):
                summary = tools_svc.launchd_agents_summary()
        _starlette(summary)
        self.assertEqual(len(summary["agents"]), 1)
        self.assertIsNone(summary["agents"][0]["interval_sec"])
        self.assertTrue(summary["agents"][0]["run_at_load"])

    def test_finite_interval_still_passes(self):
        with self._agents_dir({"StartInterval": 60}) as tmp:
            agents = Path(tmp)
            timers = self._timers(agents)
            with mock.patch.object(
                tools_svc.os.path, "expanduser", return_value=str(agents),
            ):
                summary = tools_svc.launchd_agents_summary()
        self.assertEqual(timers[0]["interval_sec"], 60)
        self.assertEqual(summary["agents"][0]["interval_sec"], 60)


class DiagnosticsSurrogateCliTests(unittest.TestCase):
    """GET /api/system/diagnostics and /api/tools/about must survive surrogate
    CLI / checkout paths, like /api/system/host already does."""

    def _diag(self):
        from collections import namedtuple
        du = namedtuple("DU", "total used free")(1, 0, 1)
        with (
            mock.patch.object(tools_svc, "DOCKER", "/usr/local/bin/d\ud800ocker"),
            mock.patch.object(tools_svc, "ORB", "/opt/homebrew/bin/o\ud800rb"),
            mock.patch.object(tools_svc.shutil, "disk_usage", return_value=du),
            mock.patch.object(
                tools_svc, "fan_out",
                return_value=("h", "m", 1, 1.0, 1, (False, {}), "p", ""),
            ),
            mock.patch.object(tools_svc.os, "getloadavg", return_value=(0.0, 0.0, 0.0)),
            mock.patch.object(tools_svc.metrics, "history", return_value=[]),
        ):
            return tools_svc.diagnostics()

    def test_surrogate_docker_cli_does_not_500_diagnostics(self):
        snap = self._diag()
        _starlette(snap)
        self.assertNotIn("\ud800", snap["docker_cli"])
        self.assertNotIn("\ud800", snap["orb_cli"])

    def test_clean_cli_paths_pass_through(self):
        from collections import namedtuple
        du = namedtuple("DU", "total used free")(1, 0, 1)
        with (
            mock.patch.object(tools_svc, "DOCKER", "/usr/local/bin/docker"),
            mock.patch.object(tools_svc, "ORB", "/usr/local/bin/orb"),
            mock.patch.object(tools_svc.shutil, "disk_usage", return_value=du),
            mock.patch.object(
                tools_svc, "fan_out",
                return_value=("h", "m", 1, 1.0, 1, (False, {}), "p", ""),
            ),
            mock.patch.object(tools_svc.os, "getloadavg", return_value=(0.0, 0.0, 0.0)),
            mock.patch.object(tools_svc.metrics, "history", return_value=[]),
        ):
            snap = tools_svc.diagnostics()
        self.assertEqual(snap["docker_cli"], "/usr/local/bin/docker")
        self.assertEqual(snap["orb_cli"], "/usr/local/bin/orb")

    def test_surrogate_base_does_not_500_about(self):
        with (
            mock.patch.object(tools_svc, "BASE", "/srv/hu\ud800b"),
            mock.patch.object(tools_svc, "fan_out", return_value=("", "macOS")),
            mock.patch.object(tools_svc, "github_update_status", return_value={}),
        ):
            about = tools_svc.about_info()
        _starlette(about)
        self.assertNotIn("\ud800", about["base"])


class VanishedDockerCliTests(unittest.TestCase):
    """GET /api/docker/df and POST /api/tools/docker/prune: a vanished CLI is
    the same operator-facing state as a stopped engine."""

    def setUp(self):
        tools_svc.docker_disk_usage.invalidate()
        self.addCleanup(tools_svc.docker_disk_usage.invalidate)

    def _df(self, docker_result, *, on_disk: bool, engine_forced: bool = False):
        def fake_engine_up(force: bool = False):
            return engine_forced if force else True

        with (
            mock.patch.object(tools_svc, "engine_up", fake_engine_up),
            mock.patch.object(tools_svc, "docker", return_value=docker_result),
            mock.patch.object(tools_svc, "cli_on_disk", return_value=on_disk),
        ):
            return tools_svc.docker_disk_usage()

    def _prune(self, docker_result, *, on_disk: bool, engine_forced: bool = False):
        def fake_engine_up(force: bool = False):
            return engine_forced if force else True

        with (
            mock.patch.object(tools_svc, "engine_up", fake_engine_up),
            mock.patch.object(tools_svc, "docker", return_value=docker_result),
            mock.patch.object(tools_svc, "cli_on_disk", return_value=on_disk),
        ):
            return tools_svc.docker_prune("dangling", True)

    def test_vanished_cli_df_reports_engine_down_not_up(self):
        """rc -1 + the two-word sentinel + the CLI gone from disk used to
        answer engine_up: true with the raw sentinel as `raw`."""
        df = self._df((-1, "", "not found"), on_disk=False)
        _starlette(df)
        self.assertFalse(df["engine_up"])
        self.assertEqual(df["raw"], "")
        self.assertEqual(df["lines"], [])

    def test_vanished_cli_prune_is_coded_engine_down(self):
        """The same coded soft-fail the daemon-socket branch next to it
        returns, instead of an uncoded raw "not found"."""
        out = self._prune((-1, "", "not found"), on_disk=False)
        _starlette(out)
        self.assertFalse(out["ok"])
        self.assertEqual(out["code"], "container.engine_down")
        self.assertEqual(out["what"], "dangling")
        self.assertIsNone(out["df"])

    def test_sentinel_with_cli_on_disk_keeps_raw_result(self):
        """rc -1 with the CLI still present (a cwd that vanished raises the
        same FileNotFoundError) must not be blamed on the engine."""
        out = self._prune((-1, "", "not found"), on_disk=True, engine_forced=True)
        self.assertFalse(out["ok"])
        self.assertNotIn("code", out)
        self.assertEqual(out["message"], "not found")

    def test_real_exit_saying_not_found_keeps_raw_result(self):
        """A genuine docker exit whose stderr merely reads "not found" while
        the engine answers up is that command's own truth."""
        out = self._prune((1, "", "not found"), on_disk=False, engine_forced=True)
        self.assertFalse(out["ok"])
        self.assertNotIn("code", out)
        self.assertEqual(out["message"], "not found")

    def test_running_engine_never_reports_engine_down(self):
        """The forced probe stays the final arbiter, matching the
        daemon-socket branch."""
        df = self._df((-1, "", "not found"), on_disk=False, engine_forced=True)
        self.assertTrue(df["engine_up"])
        self.assertEqual(df["raw"], "not found")

    def test_disk_probe_runs_only_on_the_failure_path(self):
        """A healthy `docker system df` must not pay for a disk stat."""
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(tools_svc, "engine_up", return_value=True),
            mock.patch.object(
                tools_svc, "docker",
                return_value=(0, "TYPE\nImages 1 1 10MB 5MB (50%)\n", ""),
            ),
            mock.patch.object(tools_svc, "cli_on_disk", probe),
        ):
            df = tools_svc.docker_disk_usage()
        self.assertTrue(df["engine_up"])
        probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
