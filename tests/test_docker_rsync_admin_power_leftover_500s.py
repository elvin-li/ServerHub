"""Leftover sweep of docker_info, rsync, macos_admin, and power text launderers."""
from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from hub import docker_info_svc, macos_admin, power_svc, rsync_svc
from hub.app_factory import create_app
from hub.auth import require_auth

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return _APP


class _LyingBytesStr(str):
    @property
    def __class__(self):  # noqa: A003
        return bytes


class DockerRsyncAdminPowerLeftoverTests(unittest.TestCase):
    def test_text_does_not_leak_a_heap_address(self):
        self.assertEqual(docker_info_svc._as_text(object()), "")
        self.assertEqual(rsync_svc._as_text(object()), "")
        self.assertEqual(macos_admin._as_text(object()), "")
        self.assertEqual(power_svc._as_text(object()), "")

    def test_text_recovers_str_storage_lying_bytes(self):
        self.assertEqual(docker_info_svc._as_text(_LyingBytesStr("ok")), "ok")
        self.assertEqual(rsync_svc._as_text(_LyingBytesStr("ok")), "ok")
        self.assertEqual(macos_admin._as_text(_LyingBytesStr("ok")), "ok")
        self.assertEqual(power_svc._as_text(_LyingBytesStr("ok")), "ok")

    def test_get_power_does_not_500(self):
        client = TestClient(app(), raise_server_exceptions=False)
        response = client.get("/api/system/power")
        self.assertNotEqual(response.status_code, 500, response.text[:400])
        self.assertNotIn(" at 0x", response.text)

    def test_control_flow_still_propagates_from_text(self):
        class _Ki:
            def __str__(self):
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            docker_info_svc._as_text(_Ki())
        with self.assertRaises(KeyboardInterrupt):
            rsync_svc._as_text(_Ki())

    def test_power_jsonable_swallows_isoformat_getattr_baseexception(self):
        class LeftoverWatchdogTimeout(BaseException):
            pass

        class _IsoBomb:
            @property
            def isoformat(self):
                raise LeftoverWatchdogTimeout("power isoformat watchdog")

        self.assertEqual(power_svc._jsonable(_IsoBomb()), "")


if __name__ == "__main__":
    unittest.main()
