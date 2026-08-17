"""The menu-bar client follows the panel locale saved in settings.ui."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from hub import config, status


class PanelLocaleTests(unittest.TestCase):
    def test_defaults_to_zh_cn_like_settings_api(self):
        with patch.object(config, "cfg", return_value={"settings": {}}):
            self.assertEqual(config.panel_locale(), "zh-CN")

    def test_reads_saved_ui_locale(self):
        with patch.object(
            config, "cfg", return_value={"settings": {"ui": {"locale": "ja"}}}
        ):
            self.assertEqual(config.panel_locale(), "ja")

    def test_normalizes_bcp47_tags(self):
        with patch.object(
            config, "cfg",
            return_value={"settings": {"ui": {"locale": "zh-Hans-CN"}}},
        ):
            self.assertEqual(config.panel_locale(), "zh-CN")
        with patch.object(
            config, "cfg",
            return_value={"settings": {"ui": {"locale": "ja-JP"}}},
        ):
            self.assertEqual(config.panel_locale(), "ja")

    def test_unknown_locale_stays_on_the_panel_default(self):
        with patch.object(
            config, "cfg",
            return_value={"settings": {"ui": {"locale": "de-DE"}}},
        ):
            self.assertEqual(config.panel_locale(), "zh-CN")

    def test_status_snapshot_carries_locale(self):
        with patch.object(status, "_build_status", return_value={"groups": []}), \
             patch.object(status, "panel_locale", return_value="ja"), \
             patch.object(status, "_status_cache", {"t": 0.0, "v": None}), \
             patch.object(status, "_status_ttl", return_value=35.0):
            snapshot = status.full_status(force=True)
        self.assertEqual(snapshot["locale"], "ja")

    def test_member_filter_keeps_locale(self):
        filtered = status.filter_status_for_resources(
            {
                "locale": "en",
                "groups": [{
                    "group": "Media",
                    "services": [{"id": "jellyfin", "state": "ok", "actions": ["open"]}],
                }],
            },
            ["jellyfin"],
        )
        self.assertEqual(filtered["locale"], "en")
