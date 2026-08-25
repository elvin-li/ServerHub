"""Power actions must hit the audit trail before the machine goes away.

POST /api/system/power/action schedules shutdown / restart / sleep of the
whole host and used to record nothing — the one event where "who did this"
can no longer be asked afterwards.  Wake-on-LAN decides whether the box can
be brought back remotely, and the /api/system/screensharing/* pair toggles
remote-desktop access while its twin under /api/system/services/… already
recorded the equivalent change.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from fastapi import HTTPException  # noqa: E402

from hub import audit  # noqa: E402
from hub.routers import power  # noqa: E402


class _AuditSandbox(unittest.TestCase):
    def setUp(self):
        self.calls: list = []

        def _record(event, **fields):
            self.calls.append((event, fields))

        for patched in (
            mock.patch.object(power.audit, "record", _record),
            mock.patch.object(power.auth, "request_username", lambda r: "admin"),
            mock.patch.object(power.auth, "request_client_id", lambda r: "10.0.0.9"),
        ):
            patched.start()
            self.addCleanup(patched.stop)


class PowerActionAuditTests(_AuditSandbox):
    def test_confirmed_shutdown_is_recorded_with_operator_and_client(self):
        with mock.patch.object(power.power_svc, "power_action",
                               return_value={"ok": True, "action": "shutdown"}):
            power.power_action(power.PowerBody(action="shutdown", confirm=True),
                               request=mock.Mock())
        self.assertEqual(len(self.calls), 1, self.calls)
        event, fields = self.calls[0]
        self.assertEqual(event, audit.POWER_ACTION)
        self.assertEqual(fields["username"], "admin")
        self.assertEqual(fields["client"], "10.0.0.9")
        self.assertEqual(fields["action"], "shutdown")

    def test_a_rejected_action_leaves_no_record(self):
        """power_svc raises before scheduling on missing confirm — nothing ran,
        so nothing is written (rejections are visible as the 4xx itself)."""
        def _raise(action, confirm=False):
            raise HTTPException(status_code=400, detail={"code": "power.confirm_required"})

        with mock.patch.object(power.power_svc, "power_action", _raise):
            with self.assertRaises(HTTPException):
                power.power_action(power.PowerBody(action="sleep", confirm=False),
                                   request=mock.Mock())
        self.assertEqual(self.calls, [])


class WolAuditTests(_AuditSandbox):
    def test_wol_toggle_records_outcome(self):
        with mock.patch.object(power.power_svc, "set_wol",
                               return_value={"ok": False, "enabled": True}):
            power.set_wol(power.WolBody(enabled=False), request=mock.Mock())
        event, fields = self.calls[0]
        self.assertEqual(event, audit.POWER_WOL_CHANGED)
        self.assertEqual(fields["action"], "disable")
        self.assertEqual(fields["outcome"], "failure")


class ScreenSharingAuditTests(_AuditSandbox):
    def setUp(self):
        super().setUp()
        for patched in (
            mock.patch.object(power.auth, "browser_authenticated", lambda r: True),
            mock.patch.object(power.auth, "is_admin", lambda u: True),
        ):
            patched.start()
            self.addCleanup(patched.stop)

    def test_enable_records_the_same_event_the_shares_router_uses(self):
        with mock.patch.object(power.shares_svc, "set_system_service",
                               return_value={"ok": True, "service": {}}):
            power.screensharing_enable(request=mock.Mock())
        event, fields = self.calls[0]
        self.assertEqual(event, audit.SYSTEM_SHARING_CHANGED)
        self.assertEqual(fields["service"], "screen_sharing")
        self.assertEqual(fields["action"], "enable")
        self.assertEqual(fields["outcome"], "success")

    def test_a_failed_disable_is_recorded_before_the_error_is_raised(self):
        with mock.patch.object(power.shares_svc, "set_system_service",
                               return_value={"ok": False, "error": "cancelled"}):
            with self.assertRaises(HTTPException):
                power.screensharing_disable(request=mock.Mock())
        event, fields = self.calls[0]
        self.assertEqual(event, audit.SYSTEM_SHARING_CHANGED)
        self.assertEqual(fields["action"], "disable")
        self.assertEqual(fields["outcome"], "failure")


if __name__ == "__main__":
    unittest.main()
