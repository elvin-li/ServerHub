"""VMs leftover sweep #6: the Apps-page suspend dispatch leftover.

``apps_manage_svc._vm_actions`` offers ``suspend`` for every running UTM VM,
but the action dispatch used to rewrite ``suspend`` into ``"pause"`` — an
action no VM backend has ever had (``vms_svc._utm_action`` speaks
``suspend``; there is no ``pause`` branch anywhere).  Every click of the
Apps-page suspend button on a running UTM VM therefore answered the coded
400 ``vms.utm_unsupported_action`` instead of suspending the machine.

The mapping now runs the right way: ``pause`` is accepted as an alias for
``suspend`` and ``suspend`` passes through to ``utmctl suspend``.  OrbStack
machines still answer their coded unsupported-action 400 for both verbs —
they have no suspend, and the Apps page never offers them one.
"""
from __future__ import annotations

import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import audit, vms_svc
from hub.app_factory import create_app
from hub.auth import require_auth

_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
UTM_LISTING = (
    "UUID                                 Status   Name\n"
    f"{_UUID} started  Ubuntu\n"
)
ORB_JSON = '[{"name":"web","state":"running","id":"mid"}]'


class AppsVmSuspendDispatchTests(unittest.TestCase):
    def setUp(self):
        app = create_app()
        app.dependency_overrides[require_auth] = lambda: True
        self.client = TestClient(app, raise_server_exceptions=False)
        self.calls: list[list[str]] = []

    def _fake_sh(self, cmd, **kw):
        cmd = [str(c) for c in cmd]
        self.calls.append(cmd)
        if "utmctl" in cmd[0]:
            if cmd[1:2] == ["list"]:
                return (0, UTM_LISTING, "")
            if cmd[1:2] == ["status"]:
                return (0, "started", "")
            return (0, "done", "")
        if "orbctl" in cmd[0]:
            if "-f" in cmd:
                return (0, ORB_JSON, "")
            if cmd[1:2] == ["list"]:
                return (0, "NAME  STATE\nweb  running\n", "")
            return (0, "done", "")
        return (0, "", "")

    def _patched(self):
        return (
            mock.patch.object(vms_svc, "_utm_available", return_value=True),
            mock.patch.object(vms_svc, "_orb_available", return_value=True),
            mock.patch.object(vms_svc, "UTMCTL", "/usr/local/bin/utmctl"),
            mock.patch.object(vms_svc, "ORBCTL", "/usr/local/bin/orbctl"),
            mock.patch.object(vms_svc, "sh", side_effect=self._fake_sh),
            mock.patch.object(audit, "record"),
        )

    def _post(self, body):
        vms_svc.invalidate_vm_lists()
        self.calls.clear()
        p = self._patched()
        with p[0], p[1], p[2], p[3], p[4], p[5]:
            return self.client.post("/api/apps/managed/action", json=body)

    def test_apps_page_offers_suspend_for_the_running_utm_vm(self):
        vms_svc.invalidate_vm_lists()
        p = self._patched()
        with p[0], p[1], p[2], p[3], p[4], p[5]:
            resp = self.client.get("/api/apps/managed?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        items = resp.json().get("items") or []
        row = next(v for v in items if v.get("id") == "vm:Ubuntu")
        self.assertIn("suspend", row["actions"])

    def test_suspend_reaches_utmctl_suspend(self):
        resp = self._post({"id": "vm:Ubuntu", "action": "suspend"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertTrue(body["ok"], body)
        self.assertEqual(body["action"], "suspend")
        self.assertIn(
            ["/usr/local/bin/utmctl", "suspend", "Ubuntu"], self.calls,
        )

    def test_pause_is_an_alias_for_suspend(self):
        resp = self._post({"id": "vm:Ubuntu", "action": "pause"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertTrue(resp.json()["ok"], resp.text[:200])
        self.assertIn(
            ["/usr/local/bin/utmctl", "suspend", "Ubuntu"], self.calls,
        )

    def test_orb_machine_suspend_stays_the_coded_400(self):
        for verb in ("suspend", "pause"):
            with self.subTest(verb=verb):
                resp = self._post({"id": "vm:orb:web", "action": verb})
                self.assertEqual(resp.status_code, 400, resp.text[:200])
                self.assertEqual(
                    resp.json()["detail"]["code"], "vms.orb_unsupported_action",
                )


if __name__ == "__main__":
    unittest.main()
