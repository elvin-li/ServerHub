"""Seventh leftover-500s sweep of the Apps managed-detail surfaces.

apps6 sealed the *returned* junk shapes (subclass ``.get``/``items``/
``__bool__`` bombs, surrogates, >4300-digit ints) at the list_containers /
list_all_vms / list_native_apps / uninstall-preview boundaries.  What was
still live on the pre-fix tree, driven through ``create_app()`` +
``TestClient(raise_server_exceptions=False)``:

* the same collaborators *raising* instead of returning junk.
  ``list_containers`` genuinely raises on a hostile cached row (its own
  aggregation KeyErrors) — ``_docker_stacks`` absorbs that call but
  ``_docker_detail`` / ``_docker_logs`` / the action autostart branch did
  not, so GET /api/apps/managed/detail?id=docker:*, the logs fallback and
  POST action were raw 500s.  Same for ``list_all_vms`` (vm detail),
  ``list_native_apps(force=True)`` (native detail),
  ``services_uninstall_svc.preview`` (launchd detail),
  ``cloudflared_svc.logs`` (native logs) and ``actions.run_action``
  (launchd start/stop/restart);
* POST /api/apps/managed/action returned most branch results verbatim —
  the single-container autostart fallback, the launchd/brew autostart
  toggles and ``vms_svc.vm_action`` — so a lone surrogate, a >4300-digit
  int or raw bytes in another module's payload 500'd Starlette's encoder
  *after* the action had already run.  ``action()`` now launders its
  result through ``_safe_payload`` exactly like ``detail()`` and
  ``logs()``.

Also pinned: a non-bool leftover from the engine probe used to be
stringified into GET /api/apps/managed as an object repr
(``"engine_up": "<_BoolBomb object at …>"``); the flag now reads as a
plain bool, and a value that cannot answer ``__bool__`` reads as down.

No new error codes: the locales are untouched.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import apps_manage_svc
from hub.app_factory import create_app
from hub.auth import require_auth
from hub.errors import api_error

_app = None


def _client() -> TestClient:
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return TestClient(_app, raise_server_exceptions=False)


def _strict_utf8(resp) -> str:
    """The body must already be valid UTF-8 — decode strictly on purpose."""
    return resp.content.decode("utf-8")


class _BoolBomb:
    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")


class _DictGetBomb(dict):
    def get(self, *a, **k):
        raise RuntimeError("leftover .get bomb")


#: Hex spelling dodges CPython's int(str) parse cap, so a payload really can
#: carry an int whose str() raises the 4300-digit ValueError.
_HEX_HUGE = int("0x" + "f" * 4400, 16)


class _AppsSandbox(unittest.TestCase):
    """Temp SERVICES_ROOT, collaborators stubbed per test."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.services = Path(self._tmp.name) / "services"
        self.services.mkdir()
        apps_manage_svc.inventory.invalidate()
        self.addCleanup(apps_manage_svc.inventory.invalidate)
        patched = mock.patch.object(apps_manage_svc, "SERVICES_ROOT", self.services)
        patched.start()
        self.addCleanup(patched.stop)

    def _mount(self, **kwargs):
        defaults = {
            "hub.containers_svc.list_containers":
                {"return_value": {"containers": []}},
            "hub.containers_svc.list_stacks": {"return_value": []},
            "hub.vms_svc.list_all_vms": {"return_value": {"vms": []}},
            "hub.native_catalog.list_native_apps": {"return_value": []},
            "hub.apps_manage_svc.engine_up": {"return_value": False},
            # No real docker/inspect spawns during these tests.
            "hub.apps_manage_svc._inspect": {"return_value": (1, "")},
        }
        defaults.update(kwargs)
        for target, kw in defaults.items():
            patched = mock.patch(target, **kw)
            patched.start()
            self.addCleanup(patched.stop)


class RaisingCollaboratorDetailHttpTests(_AppsSandbox):
    """A collaborator that raises must cost its section, never the route."""

    def test_docker_detail_survives_a_raising_list_containers(self):
        self._mount(**{"hub.containers_svc.list_containers":
                       {"side_effect": RuntimeError("torn row")}})
        resp = _client().get("/api/apps/managed/detail", params={"id": "docker:web"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["source_id"], "web")
        self.assertEqual(payload["containers"], [])

    def test_docker_logs_fallback_survives_a_raising_list_containers(self):
        self._mount(**{"hub.containers_svc.list_containers":
                       {"side_effect": RuntimeError("torn row")}})
        resp = _client().get("/api/apps/managed/logs", params={"id": "docker:web"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["log"], "no logs")

    def test_vm_detail_answers_the_coded_404_for_a_raising_list_all_vms(self):
        # Same answer an unusable payload already gives (apps6): with no
        # readable rows the VM is not findable, and the coded 404 is what
        # the SPA translates.
        self._mount(**{"hub.vms_svc.list_all_vms":
                       {"side_effect": RuntimeError("utmctl torn")}})
        resp = _client().get("/api/apps/managed/detail", params={"id": "vm:u1"})
        self.assertEqual(resp.status_code, 404, resp.text[:300])
        detail = json.loads(_strict_utf8(resp))["detail"]
        self.assertEqual(detail["code"], "apps.vm_not_found")

    def test_native_detail_falls_back_to_the_catalog_entry(self):
        from hub import native_catalog
        native_id = native_catalog.NATIVE_APPS[0]["id"]
        self._mount(**{
            "hub.native_catalog.list_native_apps":
                {"side_effect": RuntimeError("brew torn")},
            "hub.tools_svc.listening_ports": {"return_value": {"ports": []}},
        })
        resp = _client().get(
            "/api/apps/managed/detail", params={"id": f"native:{native_id}"}
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(json.loads(_strict_utf8(resp))["source_id"], native_id)


class LaunchdDetailPreviewRaiseHttpTests(unittest.TestCase):
    """GET detail?id=launchd:*: a raising preview costs its fields only."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        agents = Path(self._tmp.name) / "agents"
        agents.mkdir()
        (agents / "local.sane.plist").write_bytes(
            b"""<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>Label</key><string>local.sane</string>
</dict></plist>
"""
        )
        apps_manage_svc.inventory.invalidate()
        self.addCleanup(apps_manage_svc.inventory.invalidate)
        for target, kwargs in (
            ("hub.paths.AGENTS_DIR", {"new": str(agents)}),
            ("hub.services_uninstall_svc.AGENTS_DIR", {"new": str(agents)}),
            ("hub.launchd_cache.listing",
             {"side_effect": RuntimeError("no launchd")}),
        ):
            patched = mock.patch(target, **kwargs)
            patched.start()
            self.addCleanup(patched.stop)

    def test_a_raising_preview_keeps_the_listing_fields(self):
        with mock.patch(
            "hub.services_uninstall_svc.preview",
            side_effect=RuntimeError("torn reader"),
        ):
            resp = _client().get(
                "/api/apps/managed/detail", params={"id": "launchd:local.sane"}
            )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["source_id"], "local.sane")
        self.assertEqual(payload["program"], "")
        self.assertEqual(payload["data_paths"], [])


class ManagedActionResultLaunderHttpTests(_AppsSandbox):
    """POST action results are laundered like detail() and logs()."""

    def _post(self, body):
        return _client().post("/api/apps/managed/action", json=body)

    def test_docker_autostart_fallback_surrogate_and_huge_int_encode_clean(self):
        # No related containers → the toggle result is returned as-is; a
        # surrogate / >4300-digit int in it used to 500 after the toggle ran.
        self._mount(**{"hub.autostart_svc.set_docker_autostart": {
            "return_value": {"ok": True, "message": "ok\ud800!", "pid": _HEX_HUGE},
        }})
        resp = self._post({"id": "docker:web", "action": "autostart_on"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = _strict_utf8(resp)
        self.assertNotIn("\ud800", body)
        payload = json.loads(body)
        self.assertTrue(payload["ok"])
        # The unrenderable int is dropped, not the response.
        self.assertIsNone(payload["pid"])

    def test_docker_autostart_survives_a_raising_list_containers(self):
        toggle = mock.Mock(return_value={"ok": True, "message": "done"})
        self._mount(**{
            "hub.containers_svc.list_containers":
                {"side_effect": RuntimeError("torn row")},
            "hub.autostart_svc.set_docker_autostart": {"side_effect": toggle},
        })
        resp = self._post({"id": "docker:web", "action": "autostart_on"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertTrue(json.loads(_strict_utf8(resp))["ok"])
        toggle.assert_called_once_with("web", True)

    def test_launchd_autostart_surrogate_result_encodes_clean(self):
        self._mount(**{"hub.autostart_svc.set_launchd_autostart": {
            "return_value": {"ok": True, "message": "loaded\ud800"},
        }})
        resp = self._post({"id": "launchd:local.x", "action": "autostart_on"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = _strict_utf8(resp)
        self.assertNotIn("\ud800", body)
        self.assertTrue(json.loads(body)["ok"])

    def test_vm_action_surrogate_huge_int_and_bytes_encode_clean(self):
        self._mount(**{"hub.vms_svc.vm_action": {"return_value": {
            "ok": True, "message": "up\ud800", "pid": _HEX_HUGE,
            "raw": bytes([0xFF, 0xFE]),
        }}})
        resp = self._post({"id": "vm:u1", "action": "start"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = _strict_utf8(resp)
        self.assertNotIn("\ud800", body)
        payload = json.loads(body)
        self.assertTrue(payload["ok"])
        self.assertIsNone(payload["pid"])

    def test_launchd_start_reports_a_raising_run_action_as_ok_false(self):
        self._mount(**{"hub.actions.run_action":
                       {"side_effect": RuntimeError("torn registry row")}})
        resp = self._post({"id": "launchd:local.x", "action": "start"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "torn registry row")

    def test_launchd_start_keeps_the_coded_error_from_run_action(self):
        self._mount(**{"hub.actions.run_action": {
            "side_effect": api_error("actions.unknown_target", target="local.x"),
        }})
        resp = self._post({"id": "launchd:local.x", "action": "start"})
        self.assertEqual(resp.status_code, 404, resp.text[:300])
        detail = json.loads(_strict_utf8(resp))["detail"]
        self.assertEqual(detail["code"], "actions.unknown_target")


class CloudflaredLogsRaiseHttpTests(_AppsSandbox):
    """GET logs?id=native:native-cloudflared over a raising backend."""

    def test_a_raising_logs_reader_is_ok_false_not_a_500(self):
        self._mount(**{"hub.cloudflared_svc.logs":
                       {"side_effect": RuntimeError("boom\ud800")}})
        resp = _client().get(
            "/api/apps/managed/logs", params={"id": "native:native-cloudflared"}
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = _strict_utf8(resp)
        self.assertNotIn("\ud800", body)
        payload = json.loads(body)
        self.assertFalse(payload["ok"])
        self.assertIn("boom", payload["log"])


class InventoryEngineFlagTests(_AppsSandbox):
    """GET /api/apps/managed: engine_up is a bool, never an object echo."""

    def test_a_bool_bomb_engine_flag_reads_as_down(self):
        self._mount(**{"hub.apps_manage_svc.engine_up":
                       {"return_value": _BoolBomb()}})
        resp = _client().get("/api/apps/managed", params={"force": "true"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = _strict_utf8(resp)
        self.assertNotIn("_BoolBomb", body)
        self.assertIs(json.loads(body)["engine_up"], False)

    def test_a_get_bomb_engine_payload_reads_as_a_bool(self):
        # A truthy non-bool leftover must still read as a plain bool.
        self._mount(**{"hub.apps_manage_svc.engine_up":
                       {"return_value": _DictGetBomb(up=1)}})
        resp = _client().get("/api/apps/managed", params={"force": "true"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertIs(json.loads(_strict_utf8(resp))["engine_up"], True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
