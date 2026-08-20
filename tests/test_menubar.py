import copy
import subprocess
import unittest
from pathlib import Path
from unittest import mock

_MENUBAR = Path(__file__).resolve().parent.parent / "menubar.py"

try:
    from menubar import _kickstart_panel, _menu_signature
except ModuleNotFoundError as exc:
    if exc.name != "rumps":
        raise
    _kickstart_panel = None
    _menu_signature = None


class MenuBarSignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if _menu_signature is None:
            raise unittest.SkipTest(
                "rumps is macOS-only and is not installed on this host"
            )
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
        if _kickstart_panel is None:
            raise unittest.SkipTest(
                "rumps is macOS-only and is not installed on this host"
            )
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
