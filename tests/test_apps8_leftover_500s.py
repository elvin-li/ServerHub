"""Eighth leftover-500s sweep of the Apps managed action/detail surfaces.

apps7 laundered the *returned* junk shapes at the POST /api/apps/managed/action
boundary (surrogates, >4300-digit ints, raw bytes, subclass ``.get`` bombs in
another module's payload) and absorbed a raising ``list_containers`` /
``run_action``.  What was still live on the pre-fix tree, driven through
``create_app()`` + ``TestClient(raise_server_exceptions=False)``: nearly every
*other* collaborator the action branches call could still raise raw out of the
route.

* POST /api/apps/managed/action — a raising ``set_docker_autostart`` (the
  single-container fallback *and* the per-container loop),
  ``set_launchd_autostart``, ``set_brew_autostart``, ``vms_svc.vm_action``,
  ``catalog.uninstall_template``, ``services_uninstall_svc.uninstall``,
  ``native_catalog.uninstall_native``, ``install_native`` /
  ``_launchctl_unload`` (the LaunchAgent-backed native start/stop),
  ``cloudflared_svc.stop`` (autostart_off) and ``native_catalog._run`` (brew
  start) were all raw 500s.  ``action()`` now owns the seam: coded
  HTTPExceptions stay coded for the SPA to translate, everything else answers
  ``ok: false`` with the failure text (exc_detail, so a leftover ``\\ud800``
  in the message costs the message, never the response).  The per-container
  autostart loop keeps its own inner seam so one raising toggle costs its own
  line, not the lines of containers already toggled.
* GET /api/apps/managed/detail?id=launchd:* — ``config.override`` raising
  (a torn services.yaml read) or returning a dict-subclass ``.get`` bomb
  raised out of ``_launchd_apps`` and 500'd the detail route; the same tear
  silently emptied the whole launchd section of GET /api/apps/managed via
  ``_collect``'s fallback.  The override is cosmetics (name, group, port,
  url): losing it now costs those fields only.

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


class _DictGetBomb(dict):
    def get(self, *a, **k):
        raise RuntimeError("leftover .get bomb")


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

    def _post(self, body):
        return _client().post("/api/apps/managed/action", json=body)


class RaisingAutostartToggleHttpTests(_AppsSandbox):
    """POST action autostart: a raising toggle answers ok:false, never 500."""

    def test_docker_single_container_fallback_toggle_raises(self):
        # No related containers → source_id is treated as a container name
        # and the toggle result is returned directly; the toggle *raising*
        # used to be a raw 500 where returned junk no longer was (apps7).
        self._mount(**{"hub.autostart_svc.set_docker_autostart":
                       {"side_effect": RuntimeError("torn toggle")}})
        resp = self._post({"id": "docker:web", "action": "autostart_on"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])
        self.assertIn("torn toggle", payload["message"])

    def test_docker_loop_keeps_lines_of_containers_already_toggled(self):
        # One container's raising toggle must cost its own line — not the
        # route, and not the report of the toggle that already ran.
        def toggle(ident, enabled):
            if ident == "web-2":
                raise RuntimeError("torn toggle")
            return {"ok": True, "message": "restart policy set"}

        self._mount(**{
            "hub.containers_svc.list_containers": {"return_value": {"containers": [
                {"id": "web-1", "project": "web"},
                {"id": "web-2", "project": "web"},
            ]}},
            "hub.autostart_svc.set_docker_autostart": {"side_effect": toggle},
        })
        resp = self._post({"id": "docker:web", "action": "autostart_on"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])
        self.assertIn("web-1: restart policy set", payload["message"])
        self.assertIn("web-2: torn toggle", payload["message"])

    def test_launchd_toggle_raises_with_a_surrogate_in_the_message(self):
        # exc_detail: the failure text is reported, the lone surrogate is not.
        self._mount(**{"hub.autostart_svc.set_launchd_autostart":
                       {"side_effect": RuntimeError("boom\ud800")}})
        resp = self._post({"id": "launchd:local.x", "action": "autostart_on"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = _strict_utf8(resp)
        self.assertNotIn("\ud800", body)
        payload = json.loads(body)
        self.assertFalse(payload["ok"])
        self.assertIn("boom", payload["message"])

    def test_native_brew_toggle_raises(self):
        self._mount(**{"hub.autostart_svc.set_brew_autostart":
                       {"side_effect": RuntimeError("brew torn")}})
        resp = self._post({"id": "native:native-ollama", "action": "autostart_on"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])
        self.assertIn("brew torn", payload["message"])

    def test_cloudflared_autostart_off_stop_raises(self):
        self._mount(**{"hub.cloudflared_svc.stop":
                       {"side_effect": RuntimeError("agent torn")}})
        resp = self._post(
            {"id": "native:native-cloudflared", "action": "autostart_off"}
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])
        self.assertIn("agent torn", payload["message"])


class RaisingActionBackendHttpTests(_AppsSandbox):
    """POST action start/stop/uninstall: raising backends answer ok:false."""

    def test_vm_action_raises(self):
        self._mount(**{"hub.vms_svc.vm_action":
                       {"side_effect": RuntimeError("utmctl torn")}})
        resp = self._post({"id": "vm:u1", "action": "start"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])
        self.assertIn("utmctl torn", payload["message"])

    def test_vm_action_keeps_its_coded_error(self):
        # The seam in action() must not over-absorb: a coded HTTPException
        # is the answer the SPA translates (the apps7 run_action pin).
        self._mount(**{"hub.vms_svc.vm_action":
                       {"side_effect": api_error("apps.vm_not_found")}})
        resp = self._post({"id": "vm:u1", "action": "start"})
        self.assertEqual(resp.status_code, 404, resp.text[:300])
        detail = json.loads(_strict_utf8(resp))["detail"]
        self.assertEqual(detail["code"], "apps.vm_not_found")

    def test_docker_uninstall_backend_raises(self):
        self._mount(**{
            "hub.catalog.uninstall_template":
                {"side_effect": RuntimeError("compose reader torn")},
            "hub.auth.browser_authenticated": {"return_value": True},
        })
        resp = self._post({"id": "docker:web", "action": "uninstall"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])
        self.assertIn("compose reader torn", payload["message"])

    def test_launchd_uninstall_backend_raises(self):
        self._mount(**{
            "hub.services_uninstall_svc.uninstall":
                {"side_effect": RuntimeError("plist reader torn")},
            "hub.auth.browser_authenticated": {"return_value": True},
        })
        resp = self._post({"id": "launchd:local.x", "action": "uninstall"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])
        self.assertIn("plist reader torn", payload["message"])

    def test_native_uninstall_backend_raises(self):
        self._mount(**{
            "hub.native_catalog.uninstall_native":
                {"side_effect": RuntimeError("brew torn")},
            "hub.auth.browser_authenticated": {"return_value": True},
        })
        resp = self._post({"id": "native:native-ollama", "action": "uninstall"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])
        self.assertIn("brew torn", payload["message"])

    def test_native_launchd_label_start_reinstall_raises(self):
        # filebrowser start with no plist on disk re-runs install_native;
        # that raising used to 500 the action.
        agents = Path(self._tmp.name) / "agents"
        agents.mkdir()
        self._mount(**{
            "hub.native_catalog.install_native":
                {"side_effect": RuntimeError("installer torn")},
            "hub.paths.AGENTS_DIR": {"new": str(agents)},
        })
        resp = self._post({"id": "native:native-filebrowser", "action": "start"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])
        self.assertIn("installer torn", payload["message"])

    def test_native_launchd_label_stop_unload_raises(self):
        agents = Path(self._tmp.name) / "agents"
        agents.mkdir()
        self._mount(**{
            "hub.native_catalog._launchctl_unload":
                {"side_effect": RuntimeError("launchctl torn")},
            "hub.paths.AGENTS_DIR": {"new": str(agents)},
        })
        resp = self._post({"id": "native:native-filebrowser", "action": "stop"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])
        self.assertIn("launchctl torn", payload["message"])

    def test_brew_formula_start_run_raises(self):
        self._mount(**{
            "hub.native_catalog._run":
                {"side_effect": RuntimeError("spawn torn")},
            "hub.native_catalog.ollama_api_already_served":
                {"return_value": False},
        })
        resp = self._post({"id": "native:native-ollama", "action": "start"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])
        self.assertIn("spawn torn", payload["message"])


class LaunchdOverrideSeamHttpTests(unittest.TestCase):
    """config.override junk costs its cosmetic fields, never the route."""

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
            ("hub.services_uninstall_svc.preview", {"return_value": {}}),
            ("hub.containers_svc.list_containers",
             {"return_value": {"containers": []}}),
            ("hub.containers_svc.list_stacks", {"return_value": []}),
            ("hub.vms_svc.list_all_vms", {"return_value": {"vms": []}}),
            ("hub.native_catalog.list_native_apps", {"return_value": []}),
            ("hub.apps_manage_svc.engine_up", {"return_value": False}),
        ):
            patched = mock.patch(target, **kwargs)
            patched.start()
            self.addCleanup(patched.stop)

    def test_a_raising_override_keeps_the_detail_route(self):
        with mock.patch(
            "hub.config.override", side_effect=RuntimeError("torn yaml"),
        ):
            resp = _client().get(
                "/api/apps/managed/detail", params={"id": "launchd:local.sane"}
            )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["source_id"], "local.sane")
        # Cosmetic fields fall back, the agent itself stays.
        self.assertEqual(payload["name"], "local.sane")
        self.assertEqual(payload["category"], "other")

    def test_a_get_bomb_override_keeps_the_detail_route(self):
        # dict.get reads the real storage underneath the poisoned method.
        with mock.patch(
            "hub.config.override",
            return_value=_DictGetBomb(name="Example Worker"),
        ):
            resp = _client().get(
                "/api/apps/managed/detail", params={"id": "launchd:local.sane"}
            )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["source_id"], "local.sane")
        self.assertEqual(payload["name"], "Example Worker")

    def test_a_raising_override_keeps_the_inventory_item(self):
        # The same tear used to empty the whole launchd section of
        # GET /api/apps/managed via _collect's fallback.
        with mock.patch(
            "hub.config.override", side_effect=RuntimeError("torn yaml"),
        ):
            resp = _client().get("/api/apps/managed", params={"force": "true"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        ids = [item["id"] for item in payload["items"]]
        self.assertIn("launchd:local.sane", ids)
        self.assertEqual(payload["counts"]["launchd"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
