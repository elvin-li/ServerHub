"""Rumps menu chrome must follow panel locale; leftover Chinese cannot leak."""
from __future__ import annotations

import ast
import importlib
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
MENUBAR = ROOT / "menubar.py"
CJK = re.compile(r"[一-鿿]")
PLACEHOLDER = re.compile(r"\{(\w+)\}")

#: Keys extracted from leftover Chinese call sites in menubar.py.
EXTRACTED_KEYS = (
    "notify_done",
    "notify_fail",
    "confirm_maint",
    "alert_ok",
    "alert_cancel",
    "maint_started",
    "maint_start_fail",
    "docker_start_all",
    "docker_stop_all",
    "docker_restart_all",
    "confirm_docker",
    "docker_error",
    "docker_page",
    "storage_array",
    "docker_shortcuts",
    "start_all",
    "stop_all",
    "restart_all",
    "maintenance",
    "group_counts",
)

EXISTING_KEYS = (
    "open_panel",
    "needs_attention",
    "summary",
    "backend_down",
    "start_panel",
    "quit",
    "open_url",
    "restart",
    "stop",
    "start",
    "run",
)

# Distinctive leftover Chinese from the old call sites — must not appear in en/ja.
LEFTOVER_ZH = (
    "完成",
    "失败",
    "确定执行",
    "启动全部容器",
    "停止全部容器",
    "重启全部容器",
    "Docker 页",
    "存储阵列",
    "Docker 快捷",
    "全部启动",
    "全部停止",
    "全部重启",
    "维护与更新",
    "已开始，日志在面板查看",
    "启动失败",
    "确定",
)


def _load_menubar():
    try:
        import menubar
        return menubar
    except ModuleNotFoundError as exc:
        if exc.name != "rumps":
            raise
    fake = mock.MagicMock()
    sys.modules.setdefault("rumps", fake)
    sys.modules.setdefault("rumps.rumps", fake)
    if "menubar" in sys.modules:
        del sys.modules["menubar"]
    return importlib.import_module("menubar")


def _source_outside_menu(src: str) -> str:
    tree = ast.parse(src)
    start = end = None
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "_MENU":
                start, end = node.lineno, node.end_lineno
    if start is None or end is None:
        raise AssertionError("menubar.py has no top-level _MENU assignment")
    lines = src.splitlines()
    return "\n".join(lines[: start - 1] + lines[end:])


def _render(mb, locale, key):
    template = mb._MENU[locale][key]
    params = {name: "x" for name in PLACEHOLDER.findall(template)}
    return mb._t(locale, key, **params)


class MenuBarI18nTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = MENUBAR.read_text(encoding="utf-8")
        cls.mb = _load_menubar()

    def test_no_hardcoded_cjk_outside_menu_tables(self):
        outside = _source_outside_menu(self.src)
        match = CJK.search(outside)
        self.assertIsNone(
            match,
            f"hardcoded CJK outside _MENU: {match.group()!r} in {outside[match.start()-40:match.end()+40]!r}"
            if match else None,
        )
        self.assertNotIn("（", outside)
        self.assertNotIn("）", outside)

    def test_existing_keys_still_present(self):
        for loc in ("zh-CN", "en", "ja"):
            for key in EXISTING_KEYS:
                self.assertIn(key, self.mb._MENU[loc])

    def test_extracted_keys_present_in_all_locales(self):
        for loc in ("zh-CN", "en", "ja"):
            for key in EXTRACTED_KEYS:
                self.assertIn(key, self.mb._MENU[loc], f"{loc} missing {key}")

    def test_en_keys_have_no_cjk(self):
        for key in self.mb._MENU["en"]:
            text = _render(self.mb, "en", key)
            self.assertIsNone(
                CJK.search(text),
                f'_t("en", {key!r}) still has CJK: {text!r}',
            )

    def test_ja_extracted_keys_are_not_leftover_chinese(self):
        for key in EXTRACTED_KEYS:
            zh = self.mb._MENU["zh-CN"][key]
            ja = self.mb._MENU["ja"][key]
            if CJK.search(zh):
                self.assertNotEqual(ja, zh, f"ja.{key} copies zh-CN")
            for phrase in LEFTOVER_ZH:
                self.assertNotIn(phrase, ja, f"ja.{key} still contains {phrase!r}")
            text = _render(self.mb, "ja", key)
            for phrase in LEFTOVER_ZH:
                self.assertNotIn(phrase, text)

    def test_en_group_counts_use_ascii_parens(self):
        en = self.mb._t(
            "en", "group_counts", head="🟢", group="Core", ok=1, total=2,
        )
        zh = self.mb._t(
            "zh-CN", "group_counts", head="🟢", group="Core", ok=1, total=2,
        )
        ja = self.mb._t(
            "ja", "group_counts", head="🟢", group="Core", ok=1, total=2,
        )
        self.assertEqual(en, "🟢 Core (1/2)")
        self.assertNotIn("（", en)
        self.assertEqual(zh, "🟢 Core（1/2）")
        self.assertEqual(ja, "🟢 Core（1/2）")


if __name__ == "__main__":
    unittest.main()
