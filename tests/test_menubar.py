import copy
import importlib
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

_MENUBAR = Path(__file__).resolve().parent.parent / "menubar.py"


def _load_menubar():
    try:
        import menubar
    except ModuleNotFoundError as exc:
        if exc.name != "rumps":
            raise
        menubar = None
    else:
        bar_cls = getattr(menubar, "ServerHubBar", None)
        tick = getattr(bar_cls, "tick", None) if isinstance(bar_cls, type) else None
        if callable(tick) and not isinstance(tick, mock.Mock):
            return menubar

    # Linux CI has no rumps. MagicMock() as rumps.App makes ServerHubBar
    # unusable (not a type, no tick); give App a real base so the class
    # statement in menubar.py still defines tick.
    class _FakeApp:
        def __init__(self, *args, **kwargs):
            self.menu = {}
            self.title = ""

    fake = mock.MagicMock()
    fake.App = _FakeApp
    sys.modules["rumps"] = fake
    sys.modules["rumps.rumps"] = fake
    if "menubar" in sys.modules:
        del sys.modules["menubar"]
    return importlib.import_module("menubar")


_mb = _load_menubar()
_kickstart_panel = _mb._kickstart_panel
_menu_signature = _mb._menu_signature


class MenuBarSignatureTests(unittest.TestCase):
    def _status(self):
        return {
            "counts": {"ok": 1, "warn": 0, "down": 0},
            "system": {"load1": 1.5},
            "groups": [{
                "group": "Core",
                "services": [{
                    "id": "panel",
                    "name": "Panel",
                    "state": "ok",
                    "url": "http://localhost:8086",
                    "actions": ["restart"],
                    "links": [],
                }],
            }],
            "problems": [],
            "links": [],
        }

    def test_load_change_does_not_rebuild_native_menu(self):
        before = self._status()
        after = copy.deepcopy(before)
        after["system"]["load1"] = 9.9
        self.assertEqual(_menu_signature(before, []), _menu_signature(after, []))

    def test_service_state_change_rebuilds_native_menu(self):
        before = self._status()
        after = copy.deepcopy(before)
        after["groups"][0]["services"][0]["state"] = "down"
        after["counts"] = {"ok": 0, "warn": 0, "down": 1}
        self.assertNotEqual(_menu_signature(before, []), _menu_signature(after, []))

    def test_locale_change_rebuilds_native_menu(self):
        before = self._status()
        after = copy.deepcopy(before)
        after["locale"] = "en"
        self.assertNotEqual(_menu_signature(before, []), _menu_signature(after, []))


class MenuBarKickstartCapTests(unittest.TestCase):
    def test_kickstart_does_not_capture_unbounded_output(self):
        src = _MENUBAR.read_text(encoding="utf-8")
        self.assertNotIn("capture_output=True", src)
        kick = src[src.index("def _kickstart_panel"): src.index("def _menu_signature")]
        self.assertIn("DEVNULL", kick)
        self.assertIn("timeout=10", kick)

    def test_kickstart_discards_child_pipes(self):
        completed = subprocess.CompletedProcess(
            args=["/bin/launchctl"], returncode=0, stdout=b"", stderr=b"",
        )
        with mock.patch("menubar.subprocess.run", return_value=completed) as run:
            _kickstart_panel()
        kwargs = run.call_args.kwargs
        self.assertIs(kwargs["stdout"], subprocess.DEVNULL)
        self.assertIs(kwargs["stderr"], subprocess.DEVNULL)
        self.assertIs(kwargs["stdin"], subprocess.DEVNULL)
        self.assertNotIn("capture_output", kwargs)


if __name__ == "__main__":
    unittest.main()
