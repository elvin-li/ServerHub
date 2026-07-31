from __future__ import annotations

import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hub.discovery import launchd


class LaunchdDiscoveryTests(unittest.TestCase):
    def _discover(self, arguments: list[str], table_value: tuple[str, str], **extra):
        with tempfile.TemporaryDirectory() as tmp:
            label = "com.example.service"
            payload = {
                "Label": label,
                "ProgramArguments": arguments,
                "RunAtLoad": True,
                **extra,
            }
            path = Path(tmp) / f"{label}.plist"
            path.write_bytes(plistlib.dumps(payload))
            with (
                patch.object(launchd, "AGENTS_DIR", tmp),
                patch.object(launchd, "launchctl_table", return_value={label: table_value}),
                patch.object(launchd, "override", return_value={}),
                patch.object(launchd, "friendly_name", return_value="Example"),
                patch.object(launchd, "guess_group", return_value="Native"),
                patch.object(launchd, "ports_from_plist", return_value=[]),
                patch.object(launchd, "url_from_plist", return_value=None),
                patch.object(launchd, "resolve_template", side_effect=lambda value: value),
                patch.object(launchd, "enrich_service", side_effect=lambda item, **_: item),
            ):
                return launchd.discover_launchd()[0]

    def test_launchservices_login_item_success_is_healthy_without_pid(self):
        item = self._discover(
            ["/usr/bin/open", "-gj", "/Applications/ServerHub.app"],
            ("-", "0"),
        )
        self.assertEqual(item["state"], "ok")
        self.assertEqual(item["detail"], "loaded · opens app at login")
        self.assertIn("run", item["actions"])

    def test_launchservices_login_item_failure_is_warning(self):
        item = self._discover(
            ["/usr/bin/open", "-gj", "/Applications/ServerHub.app"],
            ("-", "7"),
        )
        self.assertEqual(item["state"], "warn")
        self.assertIn("exit 7", item["detail"])

    def test_non_launchservices_job_without_pid_remains_down(self):
        item = self._discover(
            ["/usr/bin/python3", "/tmp/service.py"],
            ("-", "0"),
            KeepAlive=True,
        )
        self.assertEqual(item["state"], "down")
        self.assertEqual(item["detail"], "已加载未运行")


if __name__ == "__main__":
    unittest.main()
