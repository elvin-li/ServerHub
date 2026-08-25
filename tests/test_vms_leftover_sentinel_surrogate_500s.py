"""Leftover VMs-domain 500s/mis-503s: sentinel misclassification, surrogate ids.

Second sweep over the VM action paths, continuing
test_cli_missing_leftover_503 (vanished CLI) and test_leftover_vm_500s
(listing/console leftovers):

* ``_cli_missing`` classified the ``(-1, "not found")`` spawn sentinel on its
  shape alone.  rc -1 is also what a signal-killed run reports, so a
  *still-present* utmctl/orbctl that printed exactly ``not found`` and died
  mid-request was answered with the vanished-binary 503 instead of its raw
  result.  Classification now confirms the binary is gone on disk — and only
  probes the disk on that failure path, never after a successful spawn (the
  same "defer to a fresh probe" rule the docker paths follow via
  ``engine_up``).

* ``_argv_name`` let a lone surrogate through (it only refused control
  characters), so ``vm_action("orb:web\\ud800", "shell"|"start"|…)`` — the id
  shape hub/actions.py builds from services.yaml metadata — echoed the
  surrogate back in ``id`` and the ``orb -m {name}`` hint, and Starlette's
  UTF-8 response encode raised a bare 500.  A clone with a surrogate target
  name answered the uncoded ``{ok: false, message: "invalid argv"}`` argv
  sentinel instead of the coded 400 its non-str siblings already get.

* ``util.port_open`` guarded ``int(port)`` — which does not catch an
  *already-int* over-cap value.  A YAML hex/octal override (``port: 0xfff…``
  dodges CPython's int(str) digit cap) reached ``create_connection``, whose
  digit-capped str conversion raised ValueError past the OSError guard.
  ``fan_out`` re-raises, so only vms_svc._probe_port's blanket except kept
  GET /api/vms alive; the helper itself now honours its own never-raises
  contract.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi import HTTPException

from hub import util, vms_svc

#: What hub.util.sh returns when the binary is gone at spawn time (sentinel).
MISSING = (-1, "", "not found")


def _detail(ctx) -> dict:
    detail = ctx.exception.detail
    return detail if isinstance(detail, dict) else {"code": str(detail)}


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class StillPresentCliSentinelTests(unittest.TestCase):
    """A CLI that is still on disk keeps its raw rc -1 result."""

    def test_utm_present_cli_keeps_raw_result(self):
        with (
            mock.patch.object(vms_svc, "_bin_present", return_value=True),
            mock.patch.object(vms_svc, "sh", return_value=MISSING),
            mock.patch.object(vms_svc, "_invalidate"),
        ):
            result = vms_svc._utm_action("Ubuntu", "start")
        self.assertFalse(result["ok"])
        self.assertEqual(result["message"], "not found")
        _starlette(result)

    def test_utm_ip_present_cli_keeps_raw_result(self):
        with (
            mock.patch.object(vms_svc, "_bin_present", return_value=True),
            mock.patch.object(vms_svc, "sh", return_value=MISSING),
            mock.patch.object(vms_svc, "_invalidate"),
        ):
            result = vms_svc._utm_action("Ubuntu", "ip")
        self.assertFalse(result["ok"])
        self.assertEqual(result["ips"], [])

    def test_orb_present_cli_keeps_raw_result(self):
        for action in ("start", "info"):
            with self.subTest(action=action):
                with (
                    mock.patch.object(vms_svc, "_bin_present", return_value=True),
                    mock.patch.object(vms_svc, "sh", return_value=MISSING),
                    mock.patch.object(vms_svc, "_invalidate"),
                ):
                    result = vms_svc._orb_action("web", action)
                self.assertFalse(result["ok"])
                self.assertEqual(result["message"], "not found")

    def test_orb_create_present_cli_keeps_raw_result(self):
        with (
            mock.patch.object(vms_svc, "_bin_present", return_value=True),
            mock.patch.object(vms_svc, "sh", return_value=MISSING),
            mock.patch.object(vms_svc, "_invalidate"),
        ):
            result = vms_svc.create_orb_machine("ubuntu", "box")
        self.assertFalse(result["ok"])
        self.assertEqual(result["message"], "not found")

    def test_vm_action_route_shape_keeps_raw_result(self):
        """Through vm_action, the entry POST /api/vms/{id}/action uses."""
        with (
            mock.patch.object(vms_svc, "_bin_present", return_value=True),
            mock.patch.object(vms_svc, "sh", return_value=MISSING),
            mock.patch.object(vms_svc, "_invalidate"),
        ):
            result = vms_svc.vm_action("orb:web", "start")
        self.assertFalse(result["ok"])
        self.assertEqual(result["message"], "not found")

    def test_vanished_on_disk_still_raises_the_coded_503(self):
        """The uninstall-mid-request case must keep its coded answer."""
        with (
            mock.patch.object(vms_svc, "_utm_available", return_value=True),
            mock.patch.object(vms_svc, "_bin_present", return_value=False),
            mock.patch.object(vms_svc, "sh", return_value=MISSING),
            mock.patch.object(vms_svc, "_invalidate"),
        ):
            with self.assertRaises(HTTPException) as ctx:
                vms_svc._utm_action("Ubuntu", "start")
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_detail(ctx)["code"], "vms.utm_unavailable")
        with (
            mock.patch.object(vms_svc, "_orb_available", return_value=True),
            mock.patch.object(vms_svc, "_bin_present", return_value=False),
            mock.patch.object(vms_svc, "sh", return_value=MISSING),
            mock.patch.object(vms_svc, "_invalidate"),
        ):
            with self.assertRaises(HTTPException) as ctx:
                vms_svc._orb_action("web", "start")
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_detail(ctx)["code"], "vms.orb_unavailable")

    def test_success_path_never_stats_the_disk(self):
        """The gone-on-disk probe belongs to the failure path only."""
        probe = mock.Mock(return_value=True)
        with (
            mock.patch.object(vms_svc, "_utm_available", return_value=True),
            mock.patch.object(vms_svc, "_bin_present", probe),
            mock.patch.object(vms_svc, "sh", return_value=(0, "started", "")),
            mock.patch.object(vms_svc, "_invalidate"),
        ):
            result = vms_svc._utm_action("Ubuntu", "start")
        self.assertTrue(result["ok"])
        probe.assert_not_called()

    def test_real_rc_minus_one_with_other_stderr_never_probes(self):
        """A timeout / signal kill with real stderr is not the sentinel."""
        probe = mock.Mock(return_value=False)
        with (
            mock.patch.object(vms_svc, "_utm_available", return_value=True),
            mock.patch.object(vms_svc, "_bin_present", probe),
            mock.patch.object(vms_svc, "sh", return_value=(-1, "", "timeout")),
            mock.patch.object(vms_svc, "_invalidate"),
        ):
            result = vms_svc._utm_action("Ubuntu", "start")
        self.assertFalse(result["ok"])
        self.assertEqual(result["message"], "timeout")
        probe.assert_not_called()


class SurrogateIdLeftoverTests(unittest.TestCase):
    """A lone surrogate can never name a listed machine; refuse it coded."""

    def _vm_action(self, vm_id: str, action: str):
        with (
            mock.patch.object(vms_svc, "list_orb_machines", return_value=[]),
            mock.patch.object(vms_svc, "_orb_available", return_value=True),
            mock.patch.object(vms_svc, "_utm_available", return_value=True),
            mock.patch.object(vms_svc, "sh") as sh,
            mock.patch.object(vms_svc, "_invalidate"),
        ):
            try:
                out = vms_svc.vm_action(vm_id, action)
            finally:
                sh.assert_not_called()
        return out

    def test_orb_surrogate_id_is_coded_not_500(self):
        """``orb:web\\ud800`` used to echo the surrogate in ``id`` and the
        ``orb -m {name}`` shell hint — a bare 500 at Starlette's UTF-8 encode."""
        for action in ("shell", "start", "info"):
            with self.subTest(action=action):
                with self.assertRaises(HTTPException) as ctx:
                    self._vm_action("orb:web\ud800", action)
                self.assertEqual(ctx.exception.status_code, 400)
                self.assertEqual(_detail(ctx)["code"], "vms.bad_id")
                _starlette(ctx.exception.detail)

    def test_utm_surrogate_id_is_coded_not_500(self):
        with self.assertRaises(HTTPException) as ctx:
            self._vm_action("Ubuntu\ud800", "start")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(_detail(ctx)["code"], "vms.bad_id")

    def test_surrogate_clone_name_is_coded_not_uncoded_argv_sentinel(self):
        """Used to answer ``{ok: false, message: "invalid argv"}`` — the
        as_argv sentinel — where every non-str sibling already gets 400."""
        with (
            mock.patch.object(vms_svc, "_utm_available", return_value=True),
            mock.patch.object(vms_svc, "sh") as sh,
        ):
            with self.assertRaises(HTTPException) as ctx:
                vms_svc._utm_action("Ubuntu", "clone", name="copy\ud800")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(_detail(ctx)["code"], "vms.bad_machine_name")
        sh.assert_not_called()
        with (
            mock.patch.object(vms_svc, "_orb_available", return_value=True),
            mock.patch.object(vms_svc, "sh") as sh,
        ):
            with self.assertRaises(HTTPException) as ctx:
                vms_svc._orb_action("web", "clone", name="copy\ud800")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(_detail(ctx)["code"], "vms.bad_machine_name")
        sh.assert_not_called()

    def test_spaced_utm_names_still_pass(self):
        """UTM display names carry spaces; the surrogate guard must not
        tighten the accepted alphabet."""
        self.assertEqual(vms_svc._argv_name("Windows 11"), "Windows 11")
        self.assertEqual(vms_svc._argv_name("Ubuntu · 中文"), "Ubuntu · 中文")


class PortOpenOvercapIntTests(unittest.TestCase):
    """port_open honours its never-raises contract for already-int over-caps."""

    def test_overcap_int_port_is_false_not_valueerror(self):
        """``int()`` accepts an already-int over-cap unchanged; the digit-capped
        str conversion inside create_connection used to ValueError out."""
        self.assertFalse(util.port_open(10 ** 5000))

    def test_out_of_range_ports_are_false(self):
        for port in (70000, -3, 65536):
            with self.subTest(port=port):
                self.assertFalse(util.port_open(port))

    def test_vm_port_probe_still_reports_warn_not_500(self):
        """End to end: a YAML hex over-cap ``port:`` override on a started VM
        reads as unreachable ("warn"), and the row still serialises."""
        listing = (
            "UUID                                 Status   Name\n"
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee started  Ubuntu\n"
        )
        with (
            mock.patch.object(vms_svc, "_utm_available", return_value=True),
            mock.patch.object(vms_svc, "sh", return_value=(0, listing, "")),
            mock.patch.object(vms_svc, "override", return_value={"port": 10 ** 5000}),
        ):
            items = vms_svc._list_utm_vms_uncached()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["state"], "warn")
        _starlette(items)


if __name__ == "__main__":
    unittest.main()
