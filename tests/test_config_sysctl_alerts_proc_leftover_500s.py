"""Leftover sweep of config, sysctl, alerts, and proc_utils helpers.

``_isa`` / text launderers still stopped at ``except Exception`` and coerced
default object ``__repr__`` heap addresses into JSON.
"""
from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from hub import alerts, config, macos_sysctl, proc_utils
from hub.app_factory import create_app
from hub.auth import require_auth

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return _APP


class LeftoverWatchdogTimeout(BaseException):
    pass


class _ClassBaseBomb:
    @property
    def __class__(self):  # noqa: A003
        raise LeftoverWatchdogTimeout("class base-exc bomb")


class _LyingBytesStr(str):
    @property
    def __class__(self):  # noqa: A003
        return bytes


class ConfigSysctlAlertsProcLeftoverTests(unittest.TestCase):
    def test_isa_swallows_a_baseexception_class_bomb(self):
        self.assertFalse(config._isa(_ClassBaseBomb(), str))
        self.assertFalse(alerts._isa(_ClassBaseBomb(), str))

    def test_text_does_not_leak_a_heap_address(self):
        self.assertEqual(proc_utils._as_text(object()), "")
        self.assertEqual(alerts._utf8_text(object()), "")

    def test_text_recovers_str_storage_lying_bytes(self):
        self.assertEqual(proc_utils._as_text(_LyingBytesStr("ok")), "ok")
        self.assertEqual(alerts._utf8_text(_LyingBytesStr("ok")), "ok")

    def test_parse_int_recovers_lying_bytes_digits(self):
        self.assertEqual(macos_sysctl.parse_int(_LyingBytesStr("8")), 8)

    def test_get_alerts_does_not_500(self):
        client = TestClient(app(), raise_server_exceptions=False)
        response = client.get("/api/alerts")
        self.assertNotEqual(response.status_code, 500, response.text[:400])
        self.assertNotIn(" at 0x", response.text)

    def test_control_flow_still_propagates_from_isa(self):
        class _Ki:
            @property
            def __class__(self):  # noqa: A003
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            config._isa(_Ki(), dict)
        with self.assertRaises(KeyboardInterrupt):
            alerts._isa(_Ki(), dict)

    def test_alerts_jsonable_swallows_isoformat_getattr_baseexception(self):
        class _IsoBomb:
            @property
            def isoformat(self):
                raise LeftoverWatchdogTimeout("alerts isoformat watchdog")

        self.assertEqual(alerts._jsonable_alert(_IsoBomb()), "")

    def test_alerts_truthy_swallows_a_bool_baseexception(self):
        class _BoolBomb:
            def __bool__(self):
                raise LeftoverWatchdogTimeout("alerts bool watchdog")

        self.assertFalse(alerts._truthy(_BoolBomb()))


if __name__ == "__main__":
    unittest.main()
