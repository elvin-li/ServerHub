"""Apps managed-inventory leftovers: launchd log paths, surrogates, hex ints.

Continues test_apps_leftover_wipe_and_brew_503s (persistence/action paths) and
test_apps_launchd_inventory across the *read* paths of the managed tab:

* **fixed** — ``apps_manage_svc._launchd_logs`` classified an unusable
  ``StandardOutPath`` / ``StandardErrorPath`` with ``Path(str(logp))`` and
  caught the ValueError — but the except handler re-formatted the same value
  with ``f"{logp!s}"``.  plistlib resolves a hex ``<integer>0x…</integer>``
  through ``int(raw, 16)``, which CPython's 4300-digit int(str) cap does not
  police, so a LaunchAgent whose log path was an over-cap hex integer raised
  the digit-cap ValueError *inside* the handler and 500'd
  GET /api/apps/managed/logs?id=launchd:… instead of reporting the bad path;
* **stays immune** — the same hostile plist (over-cap Label /
  ProgramArguments / WorkingDirectory / KeepAlive) keeps one inventory row
  and a Starlette-encodable detail payload (``_as_text`` probes, never bare
  ``str()``);
* **stays immune** — ``_safe_payload`` scrubs lone-surrogate KEYS as well as
  values, and drops already-int over-cap leftovers via a ``str()`` probe
  (``json.dumps(allow_nan=False)`` then encodes clean);
* **stays immune** — ``_field_text`` coerces numeric YAML/plist scalars with
  a ``str()`` probe, not an isinstance gate: ``8080`` renders as ``"8080"``
  while an over-cap int falls back instead of raising;
* **stays immune** — ``_compose_cmd`` answers the coded
  ``container.engine_down`` soft-fail only for run_capped's exact
  ``(-1, "not found")`` vanished-CLI sentinel confirmed by a *forced* engine
  probe on the failure path; timeouts and real CLI exits keep their original
  uncoded shape and never consult the probe.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import apps_manage_svc  # noqa: E402

#: Hex spelling dodges CPython's int(str) parse cap, so plistlib really can
#: mint an int whose str() raises the 4300-digit ValueError.
_HEX_HUGE = "0x" + "f" * 4000

_POISON_PLIST = f"""<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>Label</key><integer>{_HEX_HUGE}</integer>
  <key>ProgramArguments</key><array><integer>{_HEX_HUGE}</integer></array>
  <key>WorkingDirectory</key><integer>{_HEX_HUGE}</integer>
  <key>KeepAlive</key><integer>{_HEX_HUGE}</integer>
  <key>StandardOutPath</key><integer>{_HEX_HUGE}</integer>
  <key>StandardErrorPath</key><string>/tmp/serverhub-test-nope.log</string>
</dict></plist>
""".encode()


def _starlette(payload) -> None:
    """Exactly what Starlette's JSONResponse does: dumps then UTF-8 encode."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _AgentsSandbox(unittest.TestCase):
    """One poisoned LaunchAgent plist under a private AGENTS_DIR."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.agents = Path(self._tmp.name)
        (self.agents / "local.poison.plist").write_bytes(_POISON_PLIST)
        # services_uninstall_svc copies AGENTS_DIR at import time, so patch
        # both bindings — otherwise the detail test depends on import order.
        for target in ("hub.paths.AGENTS_DIR", "hub.services_uninstall_svc.AGENTS_DIR"):
            patched = mock.patch(target, str(self.agents))
            patched.start()
            self.addCleanup(patched.stop)


class LaunchdLogsOverCapPathTests(_AgentsSandbox):
    """GET /api/apps/managed/logs?id=launchd:… — the fixed 500."""

    def test_over_cap_hex_log_path_reports_instead_of_raising(self):
        # Pre-fix: the digit-cap ValueError escaped the except handler's own
        # f-string and 500'd the endpoint.
        r = apps_manage_svc._launchd_logs("local.poison")
        self.assertTrue(r["ok"])
        self.assertIn("(invalid path)", r["log"])

    def test_the_sibling_string_path_still_contributes_its_chunk(self):
        # One bad key must not cost the other key's section.
        r = apps_manage_svc._launchd_logs("local.poison")
        self.assertIn("serverhub-test-nope.log", r["log"])

    def test_public_logs_entry_encodes_for_starlette(self):
        _starlette(apps_manage_svc.logs("launchd:local.poison"))

    def test_a_sane_agent_still_tails_its_log(self):
        log = self.agents / "out.log"
        log.write_text("line one\nline two\n")
        (self.agents / "local.sane.plist").write_bytes(
            f"""<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>Label</key><string>local.sane</string>
  <key>StandardOutPath</key><string>{log}</string>
</dict></plist>
""".encode()
        )
        r = apps_manage_svc._launchd_logs("local.sane")
        self.assertTrue(r["ok"])
        self.assertIn("line two", r["log"])


class LaunchdInventoryStaysImmuneTests(_AgentsSandbox):
    """The hostile plist costs fields, never the row, never the section."""

    def _apps(self):
        # launchctl is absent on the test host; force the empty-listing branch
        # deterministically rather than depending on a failed spawn.
        with mock.patch(
            "hub.launchd_cache.listing", side_effect=RuntimeError("no launchd")
        ):
            return apps_manage_svc._launchd_apps()

    def test_poisoned_plist_keeps_its_inventory_row(self):
        rows = self._apps()
        self.assertEqual([r["source_id"] for r in rows], ["local.poison"])

    def test_the_row_survives_the_starlette_encode(self):
        _starlette(apps_manage_svc._safe_payload({"items": self._apps()}))

    def test_detail_payload_encodes_for_starlette(self):
        with mock.patch(
            "hub.launchd_cache.listing", side_effect=RuntimeError("no launchd")
        ):
            d = apps_manage_svc._launchd_detail("local.poison")
        _starlette(apps_manage_svc._safe_payload(d))


class SafePayloadSurrogateAndHugeIntTests(unittest.TestCase):
    """_safe_payload: keys AND values are scrubbed before Starlette."""

    def test_surrogate_keys_and_values_encode_clean(self):
        payload = apps_manage_svc._safe_payload({
            "items": [{"name": "bad\ud800name", "\udfffkey": "v"}],
            "\ud800top": "x",
        })
        _starlette(payload)
        flat = json.dumps(payload, ensure_ascii=False)
        self.assertFalse(any("\ud800" <= ch <= "\udfff" for ch in flat))

    def test_already_int_over_cap_value_is_dropped_not_a_500(self):
        huge = int("f" * 4000, 16)
        payload = apps_manage_svc._safe_payload({"counts": {"total": huge}})
        self.assertIsNone(payload["counts"]["total"])
        _starlette(payload)

    def test_sane_numbers_pass_through_untouched(self):
        payload = apps_manage_svc._safe_payload({"counts": {"total": 7}})
        self.assertEqual(payload["counts"]["total"], 7)


class FieldTextStrProbeTests(unittest.TestCase):
    """str() probe, not isinstance gate: numeric YAML/plist scalars render."""

    def test_numeric_scalar_coerces_to_its_string(self):
        self.assertEqual(apps_manage_svc._field_text(8080, ""), "8080")

    def test_over_cap_int_falls_back_instead_of_raising(self):
        huge = int("f" * 4000, 16)
        self.assertEqual(apps_manage_svc._field_text(huge, "fallback"), "fallback")

    def test_bools_and_none_keep_the_fallback(self):
        self.assertEqual(apps_manage_svc._field_text(True, "fb"), "fb")
        self.assertEqual(apps_manage_svc._field_text(None, "fb"), "fb")


class ComposeCmdVanishedCliTests(unittest.TestCase):
    """The failure-path probe convention for compose actions stays pinned."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.compose = Path(self._tmp.name) / "docker-compose.yml"
        self.compose.write_text("services: {}\n")
        # The up-front presence gate must pass: point DOCKER at a real file.
        patched = mock.patch.object(apps_manage_svc, "DOCKER", sys.executable)
        patched.start()
        self.addCleanup(patched.stop)
        # cli_on_disk stubbed: the sentinel only classifies once the binary
        # is confirmed gone from disk (the compose_svc convention), and the
        # verdict must not depend on the suite machine's own docker binary.
        patched = mock.patch.object(
            apps_manage_svc, "cli_on_disk", return_value=False
        )
        patched.start()
        self.addCleanup(patched.stop)

    def _cmd(self, rc, msg, engine_up_answer):
        probe = mock.Mock(return_value=engine_up_answer)
        with (
            mock.patch.object(
                apps_manage_svc, "run_capped", return_value=(rc, msg)
            ),
            mock.patch.object(apps_manage_svc, "engine_up", probe),
        ):
            r = apps_manage_svc._compose_cmd(str(self.compose), "stop")
        return r, probe

    def test_sentinel_with_the_binary_still_on_disk_stays_raw(self):
        """The vanished-cwd twin of the sentinel: CLI still on disk means
        the coded 503 would point the operator at the wrong remedy."""
        probe = mock.Mock(return_value=False)
        with (
            mock.patch.object(
                apps_manage_svc, "run_capped", return_value=(-1, "not found")
            ),
            mock.patch.object(apps_manage_svc, "engine_up", probe),
            mock.patch.object(apps_manage_svc, "cli_on_disk", return_value=True),
        ):
            r = apps_manage_svc._compose_cmd(str(self.compose), "stop")
        self.assertNotIn("code", r)
        self.assertEqual(r["message"], "not found")
        probe.assert_not_called()

    def test_vanished_cli_sentinel_becomes_the_coded_soft_fail(self):
        r, probe = self._cmd(-1, "not found", engine_up_answer=False)
        self.assertEqual(r["code"], "container.engine_down")
        self.assertFalse(r["ok"])
        probe.assert_called_once_with(force=True)

    def test_a_timeout_keeps_its_original_shape(self):
        r, probe = self._cmd(124, "command timed out after 180s", True)
        self.assertNotIn("code", r)
        self.assertIn("timed out", r["message"])
        probe.assert_not_called()

    def test_a_real_cli_exit_keeps_its_output(self):
        r, probe = self._cmd(1, "unauthorized: incorrect credentials", True)
        self.assertNotIn("code", r)
        self.assertIn("unauthorized", r["message"])
        probe.assert_not_called()

    def test_sentinel_while_the_engine_answers_up_stays_raw(self):
        # A stack log that merely reads "not found" while the engine is fine
        # must not flip into engine_down.
        r, _ = self._cmd(-1, "not found", engine_up_answer=True)
        self.assertNotIn("code", r)

    def test_missing_compose_file_is_the_coded_404_soft_fail(self):
        with mock.patch.object(apps_manage_svc, "run_capped") as spawn:
            r = apps_manage_svc._compose_cmd(
                str(self.compose.parent / "absent.yml"), "stop"
            )
        self.assertEqual(r["code"], "compose.file_missing")
        spawn.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
