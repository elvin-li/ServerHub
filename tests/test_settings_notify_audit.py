"""PUT /api/settings edits the legacy Home Assistant notify config — token
included — yet used to leave no audit record, while the equivalent edit
through the channels API did.  A credential swap must leave the same trail
either way.

Only the changed field *names* are recorded (record() redaction would drop
token-shaped values regardless), and a cosmetic UI patch stays out of the
trail: it is capped and evicts oldest-first, so noise pushes real security
events out.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import audit  # noqa: E402
from hub.routers import settings_api  # noqa: E402


class NotifySettingsAuditTests(unittest.TestCase):
    def _put(self, body: settings_api.SettingsPatch) -> list:
        calls: list = []

        def _record(event, **fields):
            calls.append((event, fields))

        with (
            mock.patch.object(settings_api, "update_settings"),
            mock.patch.object(settings_api.audit, "record", _record),
            mock.patch.object(settings_api, "request_username", lambda r: "admin"),
            mock.patch.object(settings_api, "request_client_id", lambda r: "10.0.0.9"),
            mock.patch.object(settings_api, "settings_section", lambda name: {}),
            mock.patch.object(settings_api, "_public_settings", lambda: {}),
        ):
            settings_api.put_settings(body, request=mock.Mock())
        return calls

    def test_notify_patch_records_operator_client_and_field_names(self):
        calls = self._put(settings_api.SettingsPatch(
            notify={"enabled": True, "ha_token": "secret-token", "ha_url": "http://ha.local"},
        ))
        self.assertEqual(len(calls), 1, calls)
        event, fields = calls[0]
        self.assertEqual(event, audit.NOTIFY_SETTINGS_CHANGED)
        self.assertEqual(fields["username"], "admin")
        self.assertEqual(fields["client"], "10.0.0.9")
        # Field names only, sorted; never the values.
        self.assertEqual(fields["fields"], "enabled,ha_token,ha_url")
        self.assertNotIn("secret-token", str(fields))

    def test_cosmetic_ui_patch_stays_out_of_the_audit_trail(self):
        calls = self._put(settings_api.SettingsPatch(ui={"theme": "macos"}))
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
