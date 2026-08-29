"""Leftover sweep of nas_storage walks and discovery apps ids."""
from __future__ import annotations

import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub.app_factory import create_app
from hub.auth import require_auth
from hub.discovery import apps
from hub.routers import nas_storage

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return _APP


class LeftoverWatchdogTimeout(BaseException):
    pass


class _LyingBytesStr(str):
    @property
    def __class__(self):  # noqa: A003
        return bytes


class NasStorageAppsLeftoverTests(unittest.TestCase):
    def test_entry_id_does_not_leak_a_heap_address(self):
        self.assertEqual(apps._entry_id(object()), "")

    def test_entry_id_recovers_str_storage_lying_bytes(self):
        self.assertEqual(apps._entry_id(_LyingBytesStr("ok")), "ok")

    def test_entry_id_int_coerces_and_bool_drops(self):
        self.assertEqual(apps._entry_id(8080), "8080")
        self.assertEqual(apps._entry_id(True), "")

    def test_probe_port_swallows_a_baseexception(self):
        def _boom(_port):
            raise LeftoverWatchdogTimeout("port bomb")

        with mock.patch.object(apps, "port_open", _boom):
            self.assertFalse(apps._probe_port(80))

    def test_known_mount_boot_volume_survives_listing_bomb(self):
        def _boom():
            raise LeftoverWatchdogTimeout("mounts bomb")

        with mock.patch("hub.snapshots_svc.snapshot_mounts", _boom):
            self.assertEqual(nas_storage._known_mount("/"), "/")

    def test_get_nfs_preview_does_not_500(self):
        client = TestClient(app(), raise_server_exceptions=False)
        response = client.get("/api/nfs/exports/preview")
        self.assertNotEqual(response.status_code, 500, response.text[:400])
        self.assertNotIn(" at 0x", response.text)

    def test_control_flow_still_propagates_from_probe(self):
        def _ki(_port):
            raise KeyboardInterrupt

        with mock.patch.object(apps, "port_open", _ki):
            with self.assertRaises(KeyboardInterrupt):
                apps._probe_port(80)


if __name__ == "__main__":
    unittest.main()
