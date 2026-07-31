import copy
import unittest

from menubar import _menu_signature


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


if __name__ == "__main__":
    unittest.main()
