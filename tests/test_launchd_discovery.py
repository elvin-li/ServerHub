from __future__ import annotations

import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hub.discovery import launchd


class LaunchdDiscoveryTests(unittest.TestCase):
    def _discover(
        self,
        arguments: list[str],
        table_value: tuple[str, str] | None,
        hide: bool = False,
        group: str = "Native",
        override: dict | None = None,
        **extra,
    ):
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
            table = {} if table_value is None else {label: table_value}
            ov = {"hide": True} if hide else dict(override or {})
            with (
                patch.object(launchd, "AGENTS_DIR", tmp),
                patch.object(launchd, "launchctl_table", return_value=table),
                patch.object(launchd, "override", return_value=ov),
                patch.object(launchd, "friendly_name", return_value="Example"),
                patch.object(launchd, "guess_group", return_value=group),
                patch.object(launchd, "ports_from_plist", return_value=[]),
                patch.object(launchd, "ports_for_pid", return_value=[]),
                patch.object(launchd, "configured_signatures", return_value=[]),
                patch.object(launchd, "url_from_plist", return_value=None),
                patch.object(launchd, "resolve_template", side_effect=lambda value: value),
                patch.object(launchd, "enrich_service", side_effect=lambda item, **_: item),
            ):
                items = launchd.discover_launchd()
                return items[0] if items else None

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
        self.assertEqual(item["detail"], "Loaded but not running")

    def test_interval_job_last_exit_nonzero_is_ok(self):
        item = self._discover(
            ["/bin/zsh", "/tmp/nightly.sh"],
            ("-", "1"),
            StartCalendarInterval={"Hour": 3, "Minute": 30},
        )
        self.assertEqual(item["state"], "ok")
        self.assertIn("last exit code 1", item["detail"])

    def test_disabled_interval_job_not_loaded_is_stopped(self):
        item = self._discover(
            ["/bin/zsh", "/tmp/refresh.sh"],
            None,
            Disabled=True,
            StartInterval=7200,
        )
        self.assertEqual(item["state"], "stopped")
        self.assertEqual(item["detail"], "Disabled")
        self.assertIn("start", item["actions"])

    def test_disabled_keepalive_job_not_running_is_stopped(self):
        item = self._discover(
            ["/opt/homebrew/opt/redis/bin/redis-server"],
            ("-", "1"),
            Disabled=True,
            KeepAlive=True,
        )
        self.assertEqual(item["state"], "stopped")
        self.assertEqual(item["detail"], "Disabled")

    def test_hidden_override_is_omitted(self):
        item = self._discover(
            ["/opt/homebrew/opt/redis/bin/redis-server"],
            ("-", "1"),
            KeepAlive=True,
            hide=True,
        )
        self.assertIsNone(item)

    def test_recognised_binary_uses_signature_name_and_category(self):
        item = self._discover(
            ["/opt/homebrew/opt/redis/bin/redis-server"],
            ("1234", "0"),
            group="Native Services",
            KeepAlive=True,
        )
        self.assertEqual(item["name"], "Redis")
        self.assertEqual(item["group"], "Databases")
        self.assertEqual(item["signature"]["slug"], "redis")
        self.assertEqual(item["signature"]["confidence"], "high")

    def test_name_override_wins_over_signature(self):
        item = self._discover(
            ["/opt/homebrew/opt/redis/bin/redis-server"],
            ("1234", "0"),
            group="Native Services",
            override={"name": "Cache", "group": "Infra"},
            KeepAlive=True,
        )
        self.assertEqual(item["name"], "Cache")
        self.assertEqual(item["group"], "Infra")
        self.assertEqual(item["signature"]["slug"], "redis")

    def test_unknown_binary_keeps_friendly_name(self):
        item = self._discover(
            ["/usr/local/bin/mysteryd"],
            ("1234", "0"),
            KeepAlive=True,
        )
        self.assertEqual(item["name"], "Example")
        self.assertNotIn("signature", item)


if __name__ == "__main__":
    unittest.main()
