"""Leftover sweep of util spawn nets, resource_mode, and secure_io cleanup."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import resource_mode, secure_io, util


class LeftoverWatchdogTimeout(BaseException):
    pass


class UtilResourceSecureLeftoverTests(unittest.TestCase):
    def test_resource_mode_swallows_a_baseexception_cfg_bomb(self):
        def _boom():
            raise LeftoverWatchdogTimeout("cfg bomb")

        with mock.patch.object(resource_mode, "cfg", _boom):
            self.assertEqual(resource_mode.resource_mode(), resource_mode.DEFAULT)

    def test_resource_mode_control_flow_still_propagates(self):
        def _ki():
            raise KeyboardInterrupt

        with mock.patch.object(resource_mode, "cfg", _ki):
            with self.assertRaises(KeyboardInterrupt):
                resource_mode.resource_mode()

    def test_resource_mode_class_bomb_settings_is_default_not_a_raise(self):
        class ClassBomb:
            @property
            def __class__(self):
                raise RuntimeError("class bomb")

        with mock.patch.object(resource_mode, "cfg", return_value={"settings": ClassBomb()}):
            self.assertEqual(resource_mode.resource_mode(), resource_mode.DEFAULT)
            self.assertFalse(resource_mode.is_high())

    def test_resource_mode_class_bomb_value_is_default_not_a_raise(self):
        class ClassBomb:
            @property
            def __class__(self):
                raise RuntimeError("class bomb")

        with mock.patch.object(
            resource_mode, "cfg", return_value={"settings": {"resource_mode": ClassBomb()}},
        ):
            self.assertEqual(resource_mode.resource_mode(), resource_mode.DEFAULT)

    def test_spawn_record_swallows_a_baseexception_key_bomb(self):
        def _boom(*_a, **_k):
            raise LeftoverWatchdogTimeout("spawn key bomb")

        with mock.patch.object(util, "spawn_key", _boom):
            util.spawn_counts.record(["/bin/true"])

    def test_spawn_record_control_flow_still_propagates(self):
        def _ki(*_a, **_k):
            raise KeyboardInterrupt

        with mock.patch.object(util, "spawn_key", _ki):
            with self.assertRaises(KeyboardInterrupt):
                util.spawn_counts.record(["/bin/true"])

    def test_replace_bytes_unlinks_tmp_on_baseexception(self):
        with tempfile.TemporaryDirectory() as raw:
            target = Path(raw) / "blob.bin"

            def _open_bomb(*_a, **_k):
                raise LeftoverWatchdogTimeout("open bomb")

            with mock.patch("os.open", _open_bomb):
                with self.assertRaises(LeftoverWatchdogTimeout):
                    secure_io.replace_bytes(target, b"abc")
            leftovers = list(Path(raw).glob("*.tmp"))
            self.assertEqual(leftovers, [])


if __name__ == "__main__":
    unittest.main()
