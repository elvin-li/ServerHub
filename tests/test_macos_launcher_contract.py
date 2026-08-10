from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "macos" / "ServerHubLauncher.swift"


class MacOSLauncherContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_text(encoding="utf-8")
        cls.temporary = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.temporary.name) / "ServerHubLauncher"
        cls.compile_result = subprocess.run(
            [
                "swiftc",
                "-parse-as-library",
                "-warnings-as-errors",
                "-target",
                f"{os.uname().machine}-apple-macosx13.0",
                "-framework",
                "AppKit",
                "-framework",
                "Foundation",
                str(SOURCE),
                "-o",
                str(cls.binary),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def localization_snapshot(
        self,
        language: str | None = None,
        *,
        apple_language: str | None = None,
    ) -> str:
        self.assertEqual(
            self.compile_result.returncode,
            0,
            self.compile_result.stdout + self.compile_result.stderr,
        )
        environment = os.environ.copy()
        environment.pop("SERVERHUB_LANGUAGE", None)
        if language is not None:
            environment["SERVERHUB_LANGUAGE"] = language
        arguments = [str(self.binary)]
        if apple_language is not None:
            arguments.extend(["-AppleLanguages", f"({apple_language})"])
        arguments.append("--dump-localization")
        result = subprocess.run(
            arguments,
            capture_output=True,
            text=True,
            env=environment,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def test_python_launch_is_isolated_and_keeps_bundle_immutable(self):
        self.assertNotIn('"PYTHONPATH": root.path', self.source)
        self.assertIn('"PYTHONDONTWRITEBYTECODE": "1"', self.source)
        self.assertIn('sys.path.insert(0, \\(String(reflecting: root.path)))', self.source)
        self.assertIn('["-I", "-B", "-c", script]', self.source)
        self.assertIn('<string>-I</string><string>-B</string><string>-c</string>', self.source)
        self.assertIn('environment: runtimeEnvironment', self.source)

    def test_stopped_is_neutral_but_down_is_failure(self):
        self.assertIn('case "stopped": return "⚪️"', self.source)
        self.assertIn('case "down": return "🔴"', self.source)
        warning = re.search(r"let warning = ([^\n]+)", self.source)
        self.assertIsNotNone(warning)
        self.assertIn("counts?.down", warning.group(1))
        self.assertNotIn("counts?.stopped", warning.group(1))

    def test_summary_distinguishes_failure_from_stopped(self):
        self.assertIn('故障 · \\(counts?.stopped ?? 0) 已停止', self.source)
        self.assertIn('down · \\(counts?.stopped ?? 0) stopped', self.source)

    def test_fully_stopped_group_avoids_zero_over_zero_running(self):
        self.assertIn("if active.isEmpty {", self.source)
        self.assertIn('"\\(dot) \\(name)（\\(stopped) 已停止）"', self.source)
        self.assertIn('"\\(dot) \\(name) (\\(stopped) stopped)"', self.source)
        self.assertNotIn("（0/0 运行", self.source)

    def test_service_logs_open_panel_instead_of_action_api(self):
        self.assertIn('action.id == "logs"', self.source)
        self.assertIn("#selector(openPanelLogs)", self.source)
        self.assertIn('panelURL.appendingPathComponent("logs")', self.source)
        self.assertIn('localized("📄 查看日志", "📄 View Logs")', self.source)
        self.assertNotIn(
            'ServiceActionPayload(\n                    target: target,\n                    action: "logs"',
            self.source,
        )

    def test_disruptive_actions_require_confirmation(self):
        for action in ("stop", "restart", "pause", "suspend"):
            self.assertRegex(
                self.source,
                rf'case "{action}":\s*return localized\(',
                f"{action} must have a localized confirmation message",
            )
        self.assertIn("serviceConfirmation(action: payload.action, name: payload.name)", self.source)
        self.assertIn('localized("确认操作", "Confirm Action")', self.source)

    def test_menu_signature_tracks_service_and_quick_links(self):
        self.assertIn("service.links ?? []", self.source)
        self.assertIn("status.links ?? []", self.source)
        self.assertIn('"quick:', self.source)

    def test_forced_refresh_is_replayed_after_inflight_poll(self):
        self.assertIn("private var forceRefreshPending = false", self.source)
        self.assertIn("if forceMenu { forceRefreshPending = true }", self.source)
        self.assertIn("let rerunForced = self.forceRefreshPending", self.source)
        self.assertIn("self.refreshStatus(forceMenu: true)", self.source)

    def test_action_response_must_be_valid_json(self):
        self.assertRegex(
            self.source,
            r"let decoded = try\? JSONDecoder\(\)\.decode\(ServiceActionResponse\.self, from: data\)",
        )
        self.assertIn("guard let decoded, let ok = decoded.ok else", self.source)
        self.assertIn("APIRequestError.invalidResponse", self.source)
        self.assertNotIn(
            "decoded ?? ServiceActionResponse(ok: true, message: nil)",
            self.source,
        )

    def test_only_duplicate_service_action_is_disabled_and_rechecked(self):
        self.assertIn("menu.autoenablesItems = false", self.source)
        self.assertIn("private func managedSubmenu() -> NSMenu", self.source)
        self.assertIn("result.autoenablesItems = false", self.source)
        self.assertIn("result.delegate = self", self.source)
        self.assertIn("func menuWillOpen(_ menu: NSMenu)", self.source)
        self.assertIn("updateMenuAvailability(menu)", self.source)
        self.assertIn("menuItem.isEnabled = menuItem.action != nil", self.source)
        self.assertEqual(
            self.source.count("let submenu = managedSubmenu()"),
            3,
            "every dynamic submenu must opt out of AppKit automatic validation",
        )
        self.assertNotIn("let submenu = NSMenu()", self.source)
        self.assertIn("private var serviceActionsInFlight = Set<String>()", self.source)
        self.assertIn("guard !serviceActionsInFlight.contains(actionKey) else", self.source)
        self.assertIn("serviceActionsInFlight.insert(actionKey)", self.source)
        self.assertIn("self.serviceActionsInFlight.remove(actionKey)", self.source)
        self.assertRegex(
            self.source,
            r"actionItem\.isEnabled = !serviceActionsInFlight\.contains\(",
        )
        self.assertNotIn("serviceActionInFlight", self.source)
        self.assertRegex(self.source, r"asyncAfter\(deadline: \.now\(\) \+ 2(?:\.0)?\)")

    def test_snapshot_lists_the_same_visible_actions(self):
        self.assertGreaterEqual(self.source.count("visibleActions(service)"), 2)
        self.assertIn('print("ACTION\\t', self.source)
        self.assertIn('localized("📄 查看日志", "📄 View Logs")', self.source)

    def test_external_links_are_limited_to_http_and_https(self):
        self.assertIn('scheme == "http" || scheme == "https"', self.source)
        self.assertIn("url.host != nil", self.source)
        self.assertRegex(
            self.source,
            r"private func linkItem[\s\S]*?guard let safeURL = safeWebURL\(url\)",
        )
        self.assertRegex(
            self.source,
            r"openRepresentedURL[\s\S]*?let url = safeWebURL\(raw\)",
        )
        self.assertEqual(self.source.count("private func inferredPort("), 1)

    def test_first_launch_waits_for_health_and_shows_setup_token_locally(self):
        self.assertIn("let started = self.manager.startPanel()", self.source)
        self.assertIn("guard self.manager.waitUntilHealthy() else", self.source)
        self.assertIn("let setupToken = self.manager.setupToken()", self.source)
        self.assertIn("NSPasteboard.general", self.source)
        self.assertIn("pasteboard.setString(setupToken, forType: .string)", self.source)
        self.assertIn('manager.panelURL.appendingPathComponent("settings")', self.source)

    def test_setup_token_never_enters_url_or_command_output(self):
        self.assertNotRegex(self.source, r"URL\(string:[^\n]*setupToken")
        self.assertNotRegex(self.source, r"panelURL[^\n]*setupToken")
        self.assertNotRegex(self.source, r"print\([^\n]*setupToken")
        self.assertNotRegex(self.source, r"NSLog\([^\n]*setupToken")
        self.assertNotRegex(self.source, r"arguments:[^\n]*setupToken")

    def test_launch_failures_are_actionable(self):
        self.assertIn("private func showLaunchFailure(_ result: CommandResult)", self.source)
        self.assertIn('localized("打开日志", "Open Logs")', self.source)
        self.assertIn('manager.home.appendingPathComponent("Library/Logs")', self.source)
        self.assertIn("String(detail.prefix(2_000))", self.source)

    def test_simplified_chinese_localization_snapshot(self):
        snapshot = self.localization_snapshot("zh-Hans")

        self.assertIn("LANG\tzh-Hans", snapshot)
        self.assertIn("SUMMARY\t2 正常 · 1 警告 · 1 故障 · 1 已停止", snapshot)
        self.assertIn("GROUP\t⚪️ 样例服务（1 已停止）", snapshot)
        self.assertIn("ACTION\trestart\t🔄 重启", snapshot)
        self.assertIn("ACTION\tlogs\t📄 查看日志", snapshot)
        self.assertIn("MENU\t打开 ServerHub 面板", snapshot)
        self.assertIn("CONFIRM\t重启 Sample？服务会短暂中断。", snapshot)

    def test_english_localization_snapshot(self):
        snapshot = self.localization_snapshot("en-US")

        self.assertIn("LANG\ten", snapshot)
        self.assertIn("SUMMARY\t2 OK · 1 warnings · 1 down · 1 stopped", snapshot)
        self.assertIn("GROUP\t⚪️ Sample Services (1 stopped)", snapshot)
        self.assertIn("ACTION\trestart\t🔄 Restart", snapshot)
        self.assertIn("ACTION\tlogs\t📄 View Logs", snapshot)
        self.assertIn("MENU\tOpen ServerHub Panel", snapshot)
        self.assertIn(
            "CONFIRM\tRestart Sample? The service will be briefly unavailable.",
            snapshot,
        )
        self.assertIsNone(
            re.search(r"[㐀-䶿一-鿿]", snapshot),
            "English menu snapshots must not contain Chinese text",
        )

    def test_non_chinese_locale_falls_back_to_english(self):
        snapshot = self.localization_snapshot("ja-JP")

        self.assertIn("LANG\ten", snapshot)
        self.assertIn("MENU\tOpen ServerHub Panel", snapshot)
        self.assertIn("ACTION\tlogs\t📄 View Logs", snapshot)
        self.assertIsNone(re.search(r"[㐀-䶿一-鿿]", snapshot))

    def test_traditional_chinese_locale_uses_chinese_menu(self):
        snapshot = self.localization_snapshot("zh-Hant-TW")

        self.assertIn("LANG\tzh-Hans", snapshot)
        self.assertIn("MENU\t打开 ServerHub 面板", snapshot)
        self.assertIn("SUMMARY\t2 正常 · 1 警告 · 1 故障 · 1 已停止", snapshot)

    def test_apple_languages_selects_simplified_chinese_without_override(self):
        snapshot = self.localization_snapshot(apple_language="zh-Hans")

        self.assertIn("LANG\tzh-Hans", snapshot)
        self.assertIn("MENU\t打开 ServerHub 面板", snapshot)
        self.assertIn("ACTION\tlogs\t📄 查看日志", snapshot)

    def test_apple_languages_selects_english_without_override(self):
        snapshot = self.localization_snapshot(apple_language="en-US")

        self.assertIn("LANG\ten", snapshot)
        self.assertIn("MENU\tOpen ServerHub Panel", snapshot)
        self.assertIn("ACTION\tlogs\t📄 View Logs", snapshot)
        self.assertIsNone(re.search(r"[㐀-䶿一-鿿]", snapshot))

    def test_empty_override_falls_back_to_preferred_language(self):
        snapshot = self.localization_snapshot("", apple_language="zh-Hans")

        self.assertIn("LANG\tzh-Hans", snapshot)
        self.assertIn("MENU\t打开 ServerHub 面板", snapshot)

    def test_override_ignores_surrounding_whitespace_and_case(self):
        snapshot = self.localization_snapshot("  ZH-hant-TW  ")

        self.assertIn("LANG\tzh-Hans", snapshot)
        self.assertIn("ACTION\tlogs\t📄 查看日志", snapshot)


if __name__ == "__main__":
    unittest.main()
