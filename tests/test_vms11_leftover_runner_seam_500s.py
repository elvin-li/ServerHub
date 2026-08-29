"""Eleventh leftover-500s sweep of the VMs surfaces, over the real app.

vms10 sealed the lying-``__class__`` impostors, the bool-liars, the
``sh()`` *answer-shape* bombs (``_sh3``) and the junk-rc forgery of the
vanished-CLI 503 (``_rc_int`` → -255, never the ``-1`` sentinel).  This
sweep hunted the seam those guards all stand *behind*: the runner call
itself.  ``hub.util.sh`` never raises — every failure is a return code —
but ``vms_svc`` does not own it (tests and tooling patch it, the very
seam ``_sh3`` exists for), and every spawning path called it bare.  A
leftover runner that **raises** instead of answering reproduced as a live
500 against ``create_app()`` with ``raise_server_exceptions=False`` on:

* **POST /api/vms/{id}/action** — every spawning UTM action (start,
  stop, kill, suspend, clone, ip, status, delete) and every spawning
  OrbStack action (start, stop, restart, delete, clone, info), all
  outside the listing catches.
* **POST /api/vms/create** — the ``orbctl create`` spawn.
* **POST /api/vms/{console_id}/console/session** — the mint's liveness
  re-check runs ``_utm_status`` *outside* the try that guards the listing
  read in ``utm_vm_running``, so the raise escaped the route.
* **The delete action's fire-and-forget ``stop --force``** — the one
  spawn whose answer is discarded, one line past the guarded status
  probe.  The restart worker thread had the same two bare spawns; a raise
  there crashed the worker between the stop and the start, abandoning the
  restart halfway with the VM left stopped.

The fix is one guarded seam, :func:`vms_svc._spawn`: every spawn now
funnels through it, a raising runner reads as ``(-255, "", "")`` —
nonzero (a runner that cannot answer is not consent to claim success)
and never the ``-1`` spawn *sentinel*, so a raising runner cannot forge
the vanished-CLI 503 any more than junk rc could (the ``_rc_int`` rule,
pinned here so it cannot be weakened).  The real sentinel still answers
the coded 503, still only after the disk confirm.

Re-probed and found already immune (union guards kept, not weakened):
flickering ``__class__`` claims (a different builtin per access) and
second-access ``__class__`` bombs as row values, mapping keys and ``sh``
answer slots — every unbound follow-up sits inside its own try; a
keys/iter-bomb dict-subclass override (``_override``'s laundering copy);
and a raising runner under GET /api/vms, which the ``_listing_rows``
catch already degraded to an empty inventory.
"""
from __future__ import annotations

import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import audit, auth, vm_console, vms_svc
from hub.app_factory import create_app
from hub.auth import require_auth

_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
UTM_LISTING = (
    "UUID                                 Status   Name\n"
    f"{_UUID} started  Ubuntu\n"
)

_app = None


def _client() -> TestClient:
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return TestClient(_app, raise_server_exceptions=False)


def _raising_runner(*args, **kwargs):
    raise RuntimeError("leftover runner bomb")


class UtmActionRunnerSeamTests(unittest.TestCase):
    """POST /api/vms/{id}/action (UTM): a raising runner answers a plain
    coded failure, never a raw 500."""

    def setUp(self):
        self.client = _client()
        vms_svc.invalidate_vm_lists()
        self.addCleanup(vms_svc.invalidate_vm_lists)

    def _act(self, action, **body):
        with mock.patch.object(vms_svc, "_utm_available", return_value=True), \
             mock.patch.object(vms_svc, "list_orb_machines", return_value=[]), \
             mock.patch.object(vms_svc, "sh", side_effect=_raising_runner), \
             mock.patch.object(vms_svc.time, "sleep"), \
             mock.patch.object(audit, "record"):
            return self.client.post("/api/vms/Ubuntu/action",
                                    json={"action": action, **body})

    def test_spawning_actions_answer_a_plain_failure(self):
        # Pre-fix every one of these was a raw 500: the bare sh() call sat
        # ahead of _sh3, outside every listing catch.
        for action in ("start", "stop", "kill", "suspend", "clone", "ip"):
            with self.subTest(action=action):
                resp = self._act(action)
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                body = resp.json()
                self.assertIs(body["ok"], False)
                resp.content.decode("utf-8")

    def test_status_action_reads_unknown_instead_of_500ing(self):
        resp = self._act("status")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertIs(body["ok"], True)
        self.assertEqual(body["status"], "unknown")

    def test_delete_survives_a_raise_from_the_discarded_stop_spawn(self):
        # The status probe answers "started" through the guarded path, then
        # the fire-and-forget ``stop --force`` — whose answer is discarded —
        # raises.  Pre-fix that one bare call 500'd the delete mid-action.
        def _sh(cmd, **kw):
            cmd = [str(c) for c in cmd]
            if "status" in cmd:
                return (0, "started", "")
            raise RuntimeError("leftover runner bomb")

        with mock.patch.object(vms_svc, "_utm_available", return_value=True), \
             mock.patch.object(vms_svc, "list_orb_machines", return_value=[]), \
             mock.patch.object(vms_svc, "sh", side_effect=_sh), \
             mock.patch.object(vms_svc.time, "sleep"), \
             mock.patch.object(audit, "record"):
            resp = self.client.post("/api/vms/Ubuntu/action",
                                    json={"action": "delete"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIs(resp.json()["ok"], False)

    def test_restart_worker_survives_a_raising_runner(self):
        # The worker's stop/status/start spawns all raise; pre-fix the first
        # bare one crashed the thread between the stop and the start.  Run
        # the job inline so the raise (if any) surfaces in the test.
        jobs = []

        class _InlineThread:
            def __init__(self, target=None, daemon=None):
                jobs.append(target)

            def start(self):
                pass

        with mock.patch.object(vms_svc, "_utm_available", return_value=True), \
             mock.patch.object(vms_svc, "list_orb_machines", return_value=[]), \
             mock.patch.object(vms_svc.threading, "Thread", _InlineThread), \
             mock.patch.object(audit, "record"):
            resp = self.client.post("/api/vms/Ubuntu/action",
                                    json={"action": "restart"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIs(resp.json()["ok"], True)
        self.assertEqual(len(jobs), 1)
        with mock.patch.object(vms_svc, "sh", side_effect=_raising_runner), \
             mock.patch.object(vms_svc.time, "sleep"):
            jobs[0]()  # must not raise


class OrbActionAndCreateRunnerSeamTests(unittest.TestCase):
    """The OrbStack action and create routes take the same degrade."""

    def setUp(self):
        self.client = _client()
        vms_svc.invalidate_vm_lists()
        self.addCleanup(vms_svc.invalidate_vm_lists)

    def test_spawning_orb_actions_answer_a_plain_failure(self):
        for action in ("start", "stop", "restart", "delete", "clone", "info"):
            with self.subTest(action=action):
                with mock.patch.object(vms_svc, "_orb_available",
                                       return_value=True), \
                     mock.patch.object(vms_svc, "list_orb_machines",
                                       return_value=[]), \
                     mock.patch.object(vms_svc, "sh",
                                       side_effect=_raising_runner), \
                     mock.patch.object(audit, "record"):
                    resp = self.client.post("/api/vms/orb:ubuntu/action",
                                            json={"action": action})
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                self.assertIs(resp.json()["ok"], False)

    def test_create_answers_a_plain_failure(self):
        with mock.patch.object(vms_svc, "_orb_available", return_value=True), \
             mock.patch.object(vms_svc, "sh", side_effect=_raising_runner), \
             mock.patch.object(audit, "record"):
            resp = self.client.post("/api/vms/create",
                                    json={"distro": "ubuntu"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertIs(body["ok"], False)
        self.assertEqual(body["action"], "create")

    def test_parse_id_listing_raise_degrades_to_the_utm_branch(self):
        # The orb-listing raise inside _parse_id degrades to an empty
        # machine walk; the action then answers through the UTM branch as a
        # plain failure instead of a raw 500.
        with mock.patch.object(vms_svc, "_orb_available", return_value=True), \
             mock.patch.object(vms_svc, "_utm_available", return_value=True), \
             mock.patch.object(vms_svc, "sh", side_effect=_raising_runner), \
             mock.patch.object(audit, "record"):
            resp = self.client.post("/api/vms/somevm/action",
                                    json={"action": "start"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIs(resp.json()["ok"], False)


class ConsoleMintRunnerSeamTests(unittest.TestCase):
    """The console-session mint's liveness re-check spawns outside the
    listing try; a raising runner used to 500 the mint."""

    _SECTION = {"allowlist": {_UUID: {"enabled": True, "port": 5900,
                                      "host": "127.0.0.1",
                                      "protocol": "vnc"}}}

    def test_raising_runner_answers_the_coded_404(self):
        client = _client()
        rows = [{"uuid": _UUID, "id": "Ubuntu"}]
        with mock.patch.object(auth, "browser_authenticated",
                               return_value=True), \
             mock.patch.object(vm_console, "settings_section",
                               lambda n: dict(self._SECTION)), \
             mock.patch.object(vms_svc, "_utm_available", return_value=True), \
             mock.patch.object(vms_svc, "list_utm_vms", return_value=rows), \
             mock.patch.object(vms_svc, "sh", side_effect=_raising_runner):
            resp = client.post(f"/api/vms/utm:{_UUID}/console/session",
                               json={})
        self.assertEqual(resp.status_code, 404, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"],
                         "vm_console.unavailable")

    def test_utm_vm_running_reads_false_over_a_raising_runner(self):
        rows = [{"uuid": _UUID, "id": "Ubuntu"}]
        with mock.patch.object(vms_svc, "_utm_available", return_value=True), \
             mock.patch.object(vms_svc, "list_utm_vms", return_value=rows), \
             mock.patch.object(vms_svc, "sh", side_effect=_raising_runner):
            self.assertFalse(vms_svc.utm_vm_running(_UUID))


class VanishedCli503ForgeryPins(unittest.TestCase):
    """A raising runner cannot mint the vanished-CLI 503; the real spawn
    sentinel still can, still only after the disk confirm (union guards
    pinned, not weakened)."""

    def setUp(self):
        self.client = _client()
        vms_svc.invalidate_vm_lists()
        self.addCleanup(vms_svc.invalidate_vm_lists)

    def _act(self, sh_answer=None, sh_effect=None):
        sh_patch = mock.patch.object(vms_svc, "sh", side_effect=sh_effect) \
            if sh_effect else mock.patch.object(vms_svc, "sh",
                                                return_value=sh_answer)
        with mock.patch.object(vms_svc, "_utm_available", return_value=True), \
             mock.patch.object(vms_svc, "list_orb_machines",
                               return_value=[]), \
             sh_patch, mock.patch.object(audit, "record"):
            return self.client.post("/api/vms/Ubuntu/action",
                                    json={"action": "start"})

    def test_raising_runner_beside_a_vanished_binary_stays_a_plain_failure(self):
        # A raising runner has no stderr to say "not found" and its rc reads
        # -255, so the classifier never fires even with the binary gone.
        with mock.patch.object(vms_svc, "_bin_present", return_value=False):
            resp = self._act(sh_effect=_raising_runner)
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIs(resp.json()["ok"], False)

    def test_real_sentinel_still_answers_the_coded_503_through_spawn(self):
        with mock.patch.object(vms_svc, "_bin_present", return_value=False):
            resp = self._act(sh_answer=(-1, "", "not found"))
        self.assertEqual(resp.status_code, 503, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"],
                         "vms.utm_unavailable")

    def test_sentinel_with_the_binary_still_on_disk_stays_a_plain_failure(self):
        with mock.patch.object(vms_svc, "_bin_present", return_value=True):
            resp = self._act(sh_answer=(-1, "", "not found"))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIs(resp.json()["ok"], False)


class ListingRunnerSeamTests(unittest.TestCase):
    """GET /api/vms over a raising runner: empty inventories, never a 500."""

    def setUp(self):
        self.client = _client()
        vms_svc.invalidate_vm_lists()
        self.addCleanup(vms_svc.invalidate_vm_lists)

    def test_raising_runner_empties_both_inventories(self):
        with mock.patch.object(vms_svc, "_utm_available", return_value=True), \
             mock.patch.object(vms_svc, "_orb_available", return_value=True), \
             mock.patch.object(vms_svc, "sh", side_effect=_raising_runner), \
             mock.patch.object(audit, "record"):
            resp = self.client.get("/api/vms")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertEqual(body["vms"], [])
        self.assertEqual(body["utm_count"], 0)
        self.assertEqual(body["orb_count"], 0)

    def test_a_runner_that_raises_only_for_orbctl_keeps_the_utm_rows(self):
        def _sh(cmd, **kw):
            cmd = [str(c) for c in cmd]
            if "orbctl" in cmd[0]:
                raise RuntimeError("leftover runner bomb")
            if cmd[1:2] == ["list"]:
                return (0, UTM_LISTING, "")
            return (0, "", "")

        with mock.patch.object(vms_svc, "_utm_available", return_value=True), \
             mock.patch.object(vms_svc, "_orb_available", return_value=True), \
             mock.patch.object(vms_svc, "UTMCTL", "/usr/local/bin/utmctl"), \
             mock.patch.object(vms_svc, "ORBCTL", "/usr/local/bin/orbctl"), \
             mock.patch.object(vms_svc, "sh", side_effect=_sh), \
             mock.patch.object(audit, "record"):
            resp = self.client.get("/api/vms")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertEqual(body["utm_count"], 1)
        self.assertEqual(body["orb_count"], 0)
        self.assertIn("Ubuntu", [v["name"] for v in body["vms"]])


class SpawnHelperUnitPins(unittest.TestCase):
    """Direct pins for the _spawn seam and the guards it composes."""

    def test_spawn_degrades_a_raising_runner_to_the_junk_triple(self):
        with mock.patch.object(vms_svc, "sh", side_effect=_raising_runner):
            self.assertEqual(vms_svc._spawn(["x"], 5), (-255, "", ""))

    def test_spawn_never_answers_the_minus_one_sentinel_for_a_raise(self):
        # -1 is the spawn-failure sentinel _cli_missing keys on; a raising
        # runner must not be able to mint it.
        with mock.patch.object(vms_svc, "sh", side_effect=_raising_runner):
            rc, _, err = vms_svc._spawn(["x"], 5)
        self.assertNotEqual(vms_svc._rc_int(rc), -1)
        self.assertNotEqual(err, "not found")

    def test_spawn_passes_honest_answers_and_the_sentinel_through(self):
        with mock.patch.object(vms_svc, "sh", return_value=(0, "out", "err")):
            self.assertEqual(vms_svc._spawn(["x"], 5), (0, "out", "err"))
        with mock.patch.object(vms_svc, "sh",
                               return_value=(-1, "", "not found")):
            self.assertEqual(vms_svc._spawn(["x"], 5), (-1, "", "not found"))

    def test_spawn_still_launders_the_answer_shape(self):
        # The _sh3 union guard rides along: junk shapes degrade, they do
        # not unpack-bomb the caller.
        with mock.patch.object(vms_svc, "sh", return_value="junk"):
            self.assertEqual(vms_svc._spawn(["x"], 5), (-255, "", ""))
        with mock.patch.object(vms_svc, "sh", return_value=(0, "only-two")):
            self.assertEqual(vms_svc._spawn(["x"], 5), (-255, "", ""))

    def test_rc_int_junk_rule_stays_pinned(self):
        # Do-not-weaken pins for the guards _spawn composes with.
        self.assertEqual(vms_svc._rc_int("junk"), -255)
        self.assertEqual(vms_svc._rc_int(10 ** 5000), -255)
        self.assertEqual(vms_svc._rc_int(-1), -1)
        with mock.patch.object(vms_svc, "_bin_present", return_value=False):
            self.assertFalse(vms_svc._cli_missing("junk", "not found", "/x"))
            self.assertTrue(vms_svc._cli_missing(-1, "not found", "/x"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
