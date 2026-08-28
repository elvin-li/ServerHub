"""Thirteenth leftover sweep of the dashboard sensors/system helpers.

dash12 sealed the LAN-detection cache.  ``_isa`` / ``_as_text`` /
``_sh_run`` still stopped at ``except Exception``, trusted a claimed decode
base, and coerced default-render objects through ``str()``.
"""
from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from hub import sensors_svc, system
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


class Dash13LeftoverTests(unittest.TestCase):
    def test_isa_swallows_a_baseexception_class_bomb(self):
        self.assertFalse(sensors_svc._isa(_ClassBaseBomb(), str))
        self.assertFalse(system._isa(_ClassBaseBomb(), str))

    def test_as_text_does_not_leak_a_heap_address(self):
        self.assertEqual(sensors_svc._as_text(object()), "")
        self.assertEqual(system._as_text(object()), "")

    def test_as_text_recovers_str_storage_lying_bytes(self):
        self.assertEqual(sensors_svc._as_text(_LyingBytesStr("ok")), "ok")
        self.assertEqual(system._as_text(_LyingBytesStr("ok")), "ok")

    def test_sh_run_degrades_a_baseexception_runner(self):
        def boom(*a, **k):
            raise LeftoverWatchdogTimeout("sh watchdog")

        orig = sensors_svc.sh
        sensors_svc.sh = boom
        try:
            self.assertEqual(sensors_svc._sh_run(["true"], 1), (-255, "", ""))
        finally:
            sensors_svc.sh = orig

    def test_get_sensors_does_not_leak_a_heap_address(self):
        client = TestClient(app(), raise_server_exceptions=False)
        response = client.get("/api/system/sensors?light=1")
        self.assertNotEqual(response.status_code, 500, response.text[:400])
        self.assertNotIn(" at 0x", response.text)

    def test_control_flow_still_propagates_from_isa(self):
        class _Ki:
            @property
            def __class__(self):  # noqa: A003
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            sensors_svc._isa(_Ki(), dict)
        with self.assertRaises(KeyboardInterrupt):
            system._isa(_Ki(), dict)


if __name__ == "__main__":
    unittest.main()
