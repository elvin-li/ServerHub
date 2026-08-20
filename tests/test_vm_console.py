"""Leftover allowlist/port leftovers on the VM console resolver."""
from __future__ import annotations

import json
import unittest
from unittest import mock

from hub import vm_console

_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


class VmConsolePortTests(unittest.TestCase):
    def _allow(self, **entry):
        payload = {"enabled": True, "host": "127.0.0.1", "port": 5900}
        payload.update(entry)
        return {_UUID: payload}

    def test_infinite_port_does_not_500(self):
        with mock.patch.object(
            vm_console, "_allowlist", return_value=self._allow(port=float("inf")),
        ):
            self.assertIsNone(vm_console.resolve_target(f"utm:{_UUID}"))
            cap = vm_console.capability(backend="utm", vm_uuid=_UUID, running=True)
        self.assertFalse(cap["available"])
        self.assertEqual(cap["reason"], "vm_console.not_configured")

    def test_json_overflow_port_does_not_500(self):
        port = json.loads("1e309")
        with mock.patch.object(
            vm_console, "_allowlist", return_value=self._allow(port=port),
        ):
            self.assertIsNone(vm_console.resolve_target(f"utm:{_UUID}"))

    def test_bool_port_is_not_port_one(self):
        with mock.patch.object(
            vm_console, "_allowlist", return_value=self._allow(port=True),
        ):
            self.assertIsNone(vm_console.resolve_target(f"utm:{_UUID}"))

    def test_valid_loopback_port_still_resolves(self):
        with mock.patch.object(
            vm_console, "_allowlist", return_value=self._allow(),
        ):
            target = vm_console.resolve_target(f"utm:{_UUID}")
        self.assertIsNotNone(target)
        self.assertEqual(target.port, 5900)
        self.assertEqual(target.host, "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
