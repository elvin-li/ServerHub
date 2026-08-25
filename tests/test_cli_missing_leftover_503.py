"""CLI-missing leftovers: VM / brew / WireGuard actions carry the coded 503.

``sh()`` / ``run_capped()`` report a FileNotFoundError spawn with the exact
sentinel ``"not found"`` and rc -1 — never a real CLI exit.  Every route in
this sweep checks binary presence up front and answers with a coded 503 when
the tool is absent, but a binary that vanished *between* that check and the
spawn (an uninstall mid-request, a dying mount) used to fall through:

* ``vms_svc._utm_action`` / ``_orb_action`` / ``create_orb_machine``
  (POST /api/vms/{id}/action, /api/vms/create) answered an uncoded
  ``{ok: false, message: "not found"}`` the SPA cannot translate
* ``brew_svc.service_action`` (POST /api/brew/services/{name}/action) did the
  same — and its broad ``except`` would even have swallowed a coded raise
  back into that shape
* ``wireguard_svc.generate_keypair`` / ``generate_psk`` (peer create / batch /
  PSK toggle) raised ``wg.keygen_failed`` — a 500 — when the truthful answer
  is the same ``wg.not_installed`` 503 the route guard raises

Deliberately narrow, pinned by the negative cases below: only the exact
``(-1, "not found")`` sentinel classifies.  A timeout keeps its own sentinel
(a slow CLI is not a missing one) and a genuine non-zero CLI exit keeps its
raw stderr — that message is then the truth.

UPS and maintenance were audited in the same sweep and found already safe;
their behavior is pinned rather than changed: a missing ``pmset`` reads as
"no UPS present" (200), and a maintenance job whose command is gone records
the failure in the job log instead of turning the run/log routes into 500s.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi import HTTPException

from hub import brew_svc, jobs, ups_svc, vms_svc, wireguard_svc
from hub.errors import CODES

#: What hub.util.sh / run_capped return when the binary is gone (sentinel).
MISSING = (-1, "", "not found")


def _detail(ctx) -> dict:
    detail = ctx.exception.detail
    return detail if isinstance(detail, dict) else {"code": str(detail)}


class CodeStatusPins(unittest.TestCase):
    """The codes this sweep maps to must stay 503 — a demotion would silently
    turn "install the tool" answers back into generic failures."""

    def test_unavailable_codes_are_503(self):
        for code in (
            "vms.utm_unavailable",
            "vms.orb_unavailable",
            "brew.not_found",
            "wg.not_installed",
        ):
            with self.subTest(code=code):
                self.assertEqual(CODES[code][0], 503)


class UtmCliMissingTests(unittest.TestCase):
    """Every utmctl action answers a vanished binary with the coded 503."""

    def _run(self, action: str, sh_result=MISSING, **kwargs):
        with (
            mock.patch.object(vms_svc, "_utm_available", return_value=True),
            mock.patch.object(vms_svc, "sh", return_value=sh_result),
            mock.patch.object(vms_svc, "_invalidate"),
        ):
            return vms_svc._utm_action("Ubuntu", action, **kwargs)

    def test_actions_carry_the_code(self):
        for action, kwargs in (
            ("start", {}),
            ("stop", {}),
            ("kill", {}),
            ("suspend", {}),
            ("delete", {}),
            ("clone", {"name": "copy"}),
            ("ip", {}),
        ):
            with self.subTest(action=action):
                with self.assertRaises(HTTPException) as ctx:
                    self._run(action, **kwargs)
                self.assertEqual(ctx.exception.status_code, 503)
                self.assertEqual(_detail(ctx)["code"], "vms.utm_unavailable")

    def test_timeout_sentinel_is_not_classified(self):
        """A slow utmctl is not a missing one: the ok:false shape survives."""
        result = self._run("start", sh_result=(-1, "", "timeout"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["message"], "timeout")

    def test_real_cli_failure_keeps_its_stderr(self):
        result = self._run("start", sh_result=(1, "", "Error: no such VM"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["message"], "Error: no such VM")

    def test_upfront_absence_still_raises_the_same_code(self):
        with mock.patch.object(vms_svc, "_utm_available", return_value=False):
            with self.assertRaises(HTTPException) as ctx:
                vms_svc._utm_action("Ubuntu", "start")
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_detail(ctx)["code"], "vms.utm_unavailable")


class OrbCliMissingTests(unittest.TestCase):
    """Every orbctl action answers a vanished binary with the coded 503."""

    def _run(self, action: str, sh_result=MISSING, **kwargs):
        with (
            mock.patch.object(vms_svc, "_orb_available", return_value=True),
            mock.patch.object(vms_svc, "sh", return_value=sh_result),
            mock.patch.object(vms_svc, "_invalidate"),
        ):
            return vms_svc._orb_action("web", action, **kwargs)

    def test_actions_carry_the_code(self):
        for action, kwargs in (
            ("start", {}),
            ("stop", {}),
            ("restart", {}),
            ("delete", {}),
            ("clone", {"name": "copy"}),
            ("info", {}),
        ):
            with self.subTest(action=action):
                with self.assertRaises(HTTPException) as ctx:
                    self._run(action, **kwargs)
                self.assertEqual(ctx.exception.status_code, 503)
                self.assertEqual(_detail(ctx)["code"], "vms.orb_unavailable")

    def test_create_machine_carries_the_code(self):
        with (
            mock.patch.object(vms_svc, "_orb_available", return_value=True),
            mock.patch.object(vms_svc, "sh", return_value=MISSING),
            mock.patch.object(vms_svc, "_invalidate"),
        ):
            with self.assertRaises(HTTPException) as ctx:
                vms_svc.create_orb_machine("ubuntu", "box")
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_detail(ctx)["code"], "vms.orb_unavailable")

    def test_vm_action_route_shape_carries_the_code(self):
        """Through vm_action, the entry POST /api/vms/{id}/action uses."""
        with (
            mock.patch.object(vms_svc, "_orb_available", return_value=True),
            mock.patch.object(vms_svc, "sh", return_value=MISSING),
            mock.patch.object(vms_svc, "_invalidate"),
        ):
            with self.assertRaises(HTTPException) as ctx:
                vms_svc.vm_action("orb:web", "start")
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_detail(ctx)["code"], "vms.orb_unavailable")

    def test_timeout_sentinel_is_not_classified(self):
        result = self._run("start", sh_result=(-1, "", "timeout"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["message"], "timeout")

    def test_real_cli_failure_keeps_its_stderr(self):
        result = self._run("start", sh_result=(1, "", "machine not running"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["message"], "machine not running")


class BrewCliMissingTests(unittest.TestCase):
    def test_vanished_brew_carries_the_code(self):
        """The raise must survive the broad except that used to swallow it."""
        # The up-front gate passes, then the confirmation finds brew gone —
        # the same two-look shape set_brew_autostart pins.
        gate = mock.Mock(side_effect=[True, False])
        with (
            mock.patch.object(brew_svc, "_brew_present", gate),
            mock.patch.object(
                brew_svc, "run_capped", return_value=(-1, "not found"),
            ),
        ):
            with self.assertRaises(HTTPException) as ctx:
                brew_svc.service_action("redis", "start")
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_detail(ctx)["code"], "brew.not_found")
        self.assertEqual(gate.call_count, 2)

    def test_sentinel_while_brew_is_still_present_keeps_the_dict(self):
        """The filesystem confirmation rules, mirroring set_brew_autostart: a
        signal-killed brew is also rc -1, so a brew that is really there must
        keep its raw result instead of a false "Homebrew is not installed"."""
        gate = mock.Mock(side_effect=[True, True])
        invalidate = mock.Mock()
        with (
            mock.patch.object(brew_svc, "_brew_present", gate),
            mock.patch.object(
                brew_svc, "run_capped", return_value=(-1, "not found"),
            ),
            mock.patch.object(brew_svc, "invalidate_brew_services", invalidate),
            mock.patch.object(brew_svc, "invalidate_status"),
        ):
            result = brew_svc.service_action("redis", "start")
        self.assertEqual(result, {"ok": False, "message": "not found"})
        self.assertEqual(gate.call_count, 2)
        invalidate.assert_called_once_with()

    def test_timeout_sentinel_is_not_classified(self):
        """rc -1 with empty output is run_capped's timeout, not the spawn
        sentinel: no second filesystem look, the exit fallback message."""
        gate = mock.Mock(return_value=True)
        with (
            mock.patch.object(brew_svc, "_brew_present", gate),
            mock.patch.object(brew_svc, "run_capped", return_value=(-1, "")),
            mock.patch.object(brew_svc, "invalidate_brew_services"),
            mock.patch.object(brew_svc, "invalidate_status"),
        ):
            result = brew_svc.service_action("redis", "start")
        self.assertEqual(result, {"ok": False, "message": "exit -1"})
        gate.assert_called_once()

    def test_a_real_brew_exit_reading_not_found_stays_raw(self):
        """``rc == -1`` is part of the gate: a genuine brew exit whose output
        happens to read "not found" keeps its own shape."""
        gate = mock.Mock(return_value=True)
        with (
            mock.patch.object(brew_svc, "_brew_present", gate),
            mock.patch.object(brew_svc, "run_capped", return_value=(1, "not found")),
            mock.patch.object(brew_svc, "invalidate_brew_services"),
            mock.patch.object(brew_svc, "invalidate_status"),
        ):
            result = brew_svc.service_action("redis", "start")
        self.assertEqual(result, {"ok": False, "message": "not found"})
        gate.assert_called_once()

    def test_real_brew_failure_keeps_its_output(self):
        invalidations = []
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(
                brew_svc, "run_capped",
                return_value=(1, "Error: Formula not installed"),
            ),
            mock.patch.object(
                brew_svc, "invalidate_brew_services",
                side_effect=lambda: invalidations.append("brew"),
            ),
            mock.patch.object(
                brew_svc, "invalidate_status",
                side_effect=lambda: invalidations.append("status"),
            ),
        ):
            result = brew_svc.service_action("redis", "start")
        self.assertEqual(result, {"ok": False, "message": "Error: Formula not installed"})
        # A real run still busts the caches so the next list is truthful.
        self.assertEqual(invalidations, ["brew", "status"])

    def test_ok_path_never_probes_or_raises(self):
        with (
            mock.patch.object(brew_svc, "_brew_present", return_value=True),
            mock.patch.object(
                brew_svc, "run_capped", return_value=(0, "started redis"),
            ),
            mock.patch.object(brew_svc, "invalidate_brew_services"),
            mock.patch.object(brew_svc, "invalidate_status"),
        ):
            result = brew_svc.service_action("redis", "start")
        self.assertEqual(result, {"ok": True, "message": "started redis"})

    def test_upfront_absence_still_raises_the_same_code(self):
        with mock.patch.object(brew_svc, "_brew_present", return_value=False):
            with self.assertRaises(HTTPException) as ctx:
                brew_svc.service_action("redis", "start")
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_detail(ctx)["code"], "brew.not_found")


class WireGuardCliMissingTests(unittest.TestCase):
    def test_genkey_missing_wg_maps_to_not_installed(self):
        with mock.patch.object(wireguard_svc, "sh", return_value=MISSING):
            with self.assertRaises(wireguard_svc.WireGuardError) as ctx:
                wireguard_svc.generate_keypair()
        self.assertEqual(ctx.exception.code, "wg.not_installed")

    def test_genpsk_missing_wg_maps_to_not_installed(self):
        with mock.patch.object(wireguard_svc, "sh", return_value=MISSING):
            with self.assertRaises(wireguard_svc.WireGuardError) as ctx:
                wireguard_svc.generate_psk()
        self.assertEqual(ctx.exception.code, "wg.not_installed")

    def test_router_translation_yields_the_coded_503(self):
        """_call is what every /api/wireguard mutation funnels through."""
        from hub.routers import wireguard_api

        with mock.patch.object(wireguard_svc, "sh", return_value=MISSING):
            with self.assertRaises(HTTPException) as ctx:
                wireguard_api._call(wireguard_svc.generate_keypair)
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_detail(ctx)["code"], "wg.not_installed")

    def test_garbage_keygen_output_stays_keygen_failed(self):
        """wg answered and produced junk: that is a keygen failure, not an
        installation problem — and keygen_failed stays a 500."""
        with mock.patch.object(
            wireguard_svc, "sh", return_value=(1, "not-a-key", "boom"),
        ):
            with self.assertRaises(wireguard_svc.WireGuardError) as ctx:
                wireguard_svc.generate_keypair()
        self.assertEqual(ctx.exception.code, "wg.keygen_failed")
        self.assertEqual(CODES["wg.keygen_failed"][0], 500)

    def test_timeout_sentinel_stays_keygen_failed(self):
        with mock.patch.object(
            wireguard_svc, "sh", return_value=(-1, "", "timeout"),
        ):
            with self.assertRaises(wireguard_svc.WireGuardError) as ctx:
                wireguard_svc.generate_keypair()
        self.assertEqual(ctx.exception.code, "wg.keygen_failed")


class UpsAlreadySafePins(unittest.TestCase):
    """UPS was audited in this sweep and is already safe: a missing pmset is
    "no UPS present", a 200 — never an error.  Pinned so it stays that way."""

    def test_missing_pmset_reads_as_not_present(self):
        with mock.patch.object(ups_svc, "sh", return_value=MISSING):
            snapshot = ups_svc.ups_snapshot(force=True)
        self.assertFalse(snapshot["present"])
        self.assertIsNone(snapshot["halt_levels"])
        # The merged /api/ups payload must survive Starlette's encoder.
        with mock.patch.object(ups_svc, "sh", return_value=MISSING):
            payload = ups_svc.ups_status(force=True)
        json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertFalse(payload["present"])


class MaintenanceAlreadySafePins(unittest.TestCase):
    """Maintenance jobs were audited in this sweep and are already safe: a
    missing command is a job *result* (logged, rc reported), never an HTTP
    error from the run/log routes.  Pinned so it stays that way."""

    def test_missing_binary_is_a_logged_job_failure(self):
        log: list[str] = []
        rc = jobs.run_watchdog(
            ["/definitely/not/a/real/cli-xyz"], timeout=5, log=log,
        )
        self.assertEqual(rc, -1)
        self.assertTrue(any(line.startswith("!! error") for line in log))

    def test_job_log_payload_for_a_failed_job_never_raises(self):
        jobs._jobs["cli-missing-pin"] = {
            "running": False, "rc": 127,
            "log": ["$ definitely-not-a-cli-xyz", "bash: definitely-not-a-cli-xyz: command not found"],
            "started": "00:00:00", "finished": "00:00:01",
        }
        self.addCleanup(jobs._jobs.pop, "cli-missing-pin", None)
        payload = jobs.job_log("cli-missing-pin")
        self.assertEqual(payload["rc"], 127)
        self.assertIn("command not found", payload["log"])
        json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


if __name__ == "__main__":
    unittest.main()
