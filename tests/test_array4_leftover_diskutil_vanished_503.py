"""Fourth leftover sweep of the Main Array page's backend: vanished diskutil.

The hunted class — engine-down / vanished CLI answered with a coded 503 only
after a fresh disk probe confirms the binary is gone, and only on the failure
path — was re-reproduced over the real mounted app (``create_app()``,
``TestClient`` with ``raise_server_exceptions=False``) against every mutation
the Main Array page performs.  Every NAS sibling of these routes already
follows the rule (raid.diskutil_missing, smart.smartctl_missing,
snapshot.tmutil_missing, nfs.nfsd_missing, usage.mdutil_missing); the two
services behind the page's own manage/power buttons were skipped.  Each of
these was live on the pre-fix tree:

* ``disk_manage_svc.disk_action`` (POST /api/storage/manage/{id}): a
  diskutil that vanished between the eligibility checks and the spawn
  surfaced as HTTP 200 ``{"ok": false, "message": "not found"}`` for mount,
  unmount, rename, eject and even eraseVolume/eraseDisk — a body that reads
  like a missing *disk* and misdirects the operator at the hardware.
* ``disk_power_svc.sleep_disk`` / ``wake_disk``
  (POST /api/storage/disks/{id}/power): the same bare "not found" rode out
  of the unmount / eject / mountDisk legs.
* ``disk_power_svc.sleep_disk`` with the listing *emptied* by the vanished
  binary (diskutil lists at least disk0 on any healthy Mac) answered the
  404 ``disk not found: diskN`` — sending the operator to check a cable
  that was never the problem.
* ``disk_power_svc._power_state`` read sh()'s vanished-binary sentinel
  (``rc == -1``, the exact "not found" body) through the timeout branch and
  reported every unmounted disk on a smartctl-less host as ``spun_down`` —
  a spin state the disk was never asked about.

The 503 keeps the sibling discipline: a message-pattern gate first (diskutil's
own genuine failures can contain "not found" too), then the fresh
``_diskutil_on_disk`` probe, run only on the failure path.  With the binary
still on disk the raw failure keeps its own message, and a success never pays
for the probe.
"""
from __future__ import annotations

import json
import unittest
from contextlib import ExitStack
from unittest import mock

from hub import disk_manage_svc, disk_power_svc

#: What hub.util.sh returns when the spawned binary is FileNotFoundError.
_VANISHED = (-1, "", "not found")


def _vanished_sh(argv, timeout=10, **kw):
    return _VANISHED


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


_APP = None


def _client():
    global _APP
    from fastapi.testclient import TestClient

    if _APP is None:
        from hub.app_factory import create_app
        from hub.auth import require_auth

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


class ManageVanishedDiskutilTests(unittest.TestCase):
    """POST /api/storage/manage/{id} over the real mounted app."""

    def _post(self, body, *, sh=_vanished_sh, on_disk):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(disk_manage_svc, "sh", sh))
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "_diskutil_info",
                return_value={"VolumeName": "Vault", "MountPoint": ""}))
            stack.enter_context(mock.patch.object(
                disk_manage_svc, "root_devices", return_value=frozenset()))
            probe = stack.enter_context(mock.patch.object(
                disk_manage_svc, "_diskutil_on_disk", return_value=on_disk))
            resp = _client().post("/api/storage/manage/disk4s1", json=body)
        return resp, probe

    def test_vanished_mount_is_the_coded_503(self):
        """Pre-fix: HTTP 200 ``{"ok": false, "message": "not found"}``."""
        resp, _ = self._post({"action": "mount"}, on_disk=False)
        self.assertEqual(resp.status_code, 503, resp.text[:200])
        detail = resp.json()["detail"]
        self.assertEqual(detail["code"], "disk.diskutil_missing")
        _starlette(detail)

    def test_vanished_unmount_is_the_coded_503(self):
        resp, _ = self._post({"action": "unmount"}, on_disk=False)
        self.assertEqual(resp.status_code, 503, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "disk.diskutil_missing")

    def test_vanished_erase_is_the_coded_503(self):
        """The most destructive action must not report "not found" either."""
        resp, _ = self._post(
            {"action": "eraseVolume", "fs": "APFS", "name": "X",
             "confirm": True, "confirm_name": "Vault"},
            on_disk=False,
        )
        self.assertEqual(resp.status_code, 503, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "disk.diskutil_missing")

    def test_binary_still_on_disk_keeps_the_raw_failure(self):
        """The pattern gate alone must never classify: diskutil's genuine
        failures can read vanished-looking ("Volume … was not found"), so a
        failing spawn with the binary confirmed present keeps its own body."""
        def genuine(argv, timeout=10, **kw):
            return 1, "", "Volume disk4s1 was not found"

        resp, _ = self._post({"action": "mount"}, sh=genuine, on_disk=True)
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertIs(body["ok"], False)
        self.assertIn("was not found", body["message"])

    def test_genuine_failure_never_pays_for_the_probe(self):
        """A failure without a vanish marker keeps its message and never
        stats the disk — the "failure path only" half of the rule."""
        def busy(argv, timeout=10, **kw):
            return 1, "", "Unmount failed: volume is in use by a process"

        resp, probe = self._post({"action": "unmount"}, sh=busy, on_disk=False)
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIs(resp.json()["ok"], False)
        probe.assert_not_called()

    def test_success_never_pays_for_the_probe(self):
        def ok(argv, timeout=10, **kw):
            return 0, "mounted", ""

        resp, probe = self._post({"action": "mount"}, sh=ok, on_disk=False)
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIs(resp.json()["ok"], True)
        probe.assert_not_called()


#: A sleepable, non-system disk row as list_power_disks reports it.
_POWER_DISK = {"id": "disk4", "device": "/dev/disk4", "system": False,
               "can_sleep": True, "volumes": []}


class PowerVanishedDiskutilTests(unittest.TestCase):
    """POST /api/storage/disks/{id}/power over the real mounted app."""

    def _post(self, action, *, sh=_vanished_sh, on_disk, disks=None,
              dev_exists=None):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(disk_power_svc, "sh", sh))
            stack.enter_context(mock.patch.object(
                disk_power_svc, "list_power_disks",
                return_value=[dict(_POWER_DISK)] if disks is None else disks))
            stack.enter_context(mock.patch.object(
                disk_power_svc, "invalidate_disk_info", lambda: None))
            stack.enter_context(mock.patch.object(
                disk_power_svc, "invalidate_power_disks", lambda: None))
            if dev_exists is not None:
                stack.enter_context(mock.patch.object(
                    disk_power_svc, "_dev_exists", return_value=dev_exists))
            stack.enter_context(mock.patch.object(
                disk_power_svc.time, "sleep", lambda *_: None))
            probe = stack.enter_context(mock.patch.object(
                disk_power_svc, "_diskutil_on_disk", return_value=on_disk))
            resp = _client().post(
                "/api/storage/disks/disk4/power", json={"action": action})
        return resp, probe

    def test_vanished_sleep_is_the_coded_503(self):
        """Pre-fix: HTTP 200 ``{"ok": false, "message": "not found"}``."""
        resp, _ = self._post("sleep", on_disk=False)
        self.assertEqual(resp.status_code, 503, resp.text[:200])
        detail = resp.json()["detail"]
        self.assertEqual(detail["code"], "disk_power.diskutil_missing")
        _starlette(detail)

    def test_vanished_eject_leg_is_the_coded_503(self):
        """diskutil vanishing *between* the unmount and the eject."""
        def eject_vanishes(argv, timeout=10, **kw):
            if "eject" in argv:
                return _VANISHED
            return 0, "unmounted", ""

        resp, _ = self._post("eject", sh=eject_vanishes, on_disk=False)
        self.assertEqual(resp.status_code, 503, resp.text[:200])
        self.assertEqual(
            resp.json()["detail"]["code"], "disk_power.diskutil_missing")

    def test_vanished_wake_is_the_coded_503(self):
        resp, _ = self._post("wake", on_disk=False, dev_exists=True)
        self.assertEqual(resp.status_code, 503, resp.text[:200])
        self.assertEqual(
            resp.json()["detail"]["code"], "disk_power.diskutil_missing")

    def test_emptied_listing_is_the_coded_503_not_the_404(self):
        """A vanished diskutil empties the listing (a healthy Mac always
        lists at least disk0); the pre-fix 404 "disk not found: disk4" sent
        the operator to check a cable that was never the problem."""
        resp, _ = self._post("sleep", disks=[], on_disk=False)
        self.assertEqual(resp.status_code, 503, resp.text[:200])
        self.assertEqual(
            resp.json()["detail"]["code"], "disk_power.diskutil_missing")

    def test_emptied_listing_with_the_binary_present_stays_the_404(self):
        """No disks and diskutil alive is a real (if odd) answer: 404."""
        resp, _ = self._post("sleep", disks=[], on_disk=True)
        self.assertEqual(resp.status_code, 404, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "disk_power.not_found")

    def test_a_genuine_miss_in_a_live_listing_never_probes(self):
        """The listing answered, so diskutil is alive: the miss is the
        disk's own absence and the disk probe must not even be consulted."""
        other = dict(_POWER_DISK, id="disk7", device="/dev/disk7")
        resp, probe = self._post("sleep", disks=[other], on_disk=False)
        self.assertEqual(resp.status_code, 404, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "disk_power.not_found")
        probe.assert_not_called()

    def test_genuine_unmount_failure_keeps_its_own_message(self):
        def busy(argv, timeout=10, **kw):
            return 1, "", "Unmount failed: volume is in use by a process"

        resp, probe = self._post("sleep", sh=busy, on_disk=False)
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertIs(body["ok"], False)
        self.assertIn("in use", body["message"])
        probe.assert_not_called()


class PowerStateSentinelTests(unittest.TestCase):
    """The read path never 503s; it must just stop inventing a spin state."""

    def _state(self, sh):
        with (
            mock.patch.object(disk_power_svc, "sh", sh),
            mock.patch.object(disk_power_svc, "_dev_exists", return_value=True),
        ):
            return disk_power_svc._power_state("disk4", [], {"Ejectable": True})

    def test_vanished_smartctl_reads_idle_not_spun_down(self):
        """Pre-fix the sentinel rode the timeout branch: every unmounted
        disk on a host without smartctl showed as parked."""
        self.assertEqual(self._state(_vanished_sh), "idle")

    def test_probe_timeout_still_reads_spun_down(self):
        """The timeout reading is real: a spun-down disk behind a USB
        bridge refuses to answer, and the listing must not hang on it."""
        self.assertEqual(
            self._state(lambda *a, **k: (-1, "", "timeout")), "spun_down")

    def test_a_standby_answer_still_reads_spun_down(self):
        self.assertEqual(
            self._state(lambda *a, **k: (2, "Device is in STANDBY mode", "")),
            "spun_down",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
