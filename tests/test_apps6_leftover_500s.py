"""Sixth leftover-500s sweep of the Apps / catalog surfaces, over the real app.

The find: the Apps detail/logs/action readers and the store overview never got
the subclass-bomb hardening the rest of the tree standardized on (the modules5
unbound convention: ``hub.ups_svc._mapping_get``, ``hub.jobs._truthy``,
``hub.docker_cli._jsonable``'s unbound ``dict``/``list.__iter__`` copies).
Driven through ``create_app()`` + ``TestClient(raise_server_exceptions=False)``,
these junk shapes were live raw HTTP 500s on the pre-fix tree:

* GET /api/apps/managed/detail?id=docker:* — a dict-subclass ``.get`` bomb as
  the whole ``list_containers()`` payload, a list-subclass ``__iter__`` bomb
  as ``containers``, a subclass ``.get`` bomb row, and a ``__bool__`` bomb
  behind ``if c.get("ports"):``;
* GET /api/apps/managed/logs?id=docker:* — the same payload/row bombs raised
  out of the fallback matcher;
* POST /api/apps/managed/action (autostart_on/off, docker kind) — the same
  payload/row bombs, plus a subclass ``.get`` bomb as the *result* of one
  ``set_docker_autostart`` toggle, raised after toggles had already run;
* GET /api/apps/managed/detail?id=vm:* — a dict-subclass ``.get`` bomb as the
  ``list_all_vms()`` payload, per-row ``.get``/``__eq__`` bombs, an ``ips``
  list-subclass ``__iter__`` bomb, and a ``__bool__`` bomb behind
  ``v.get("state") or ""`` in ``_vm_actions``;
* GET /api/apps/managed/detail?id=native:* — a subclass ``.get``/``__eq__``
  bomb row in ``list_native_apps()``, and a ``__bool__`` bomb behind
  ``listed.get("running")``;
* GET /api/catalog — a subclass ``.get`` bomb row raised out of the installed
  filter, ``__bool__``/``__str__`` bombs out of the sort key, and — past the
  handler — a lone-surrogate name, a >4300-digit int and raw bytes in a
  native row 500'd Starlette's encoder because ``catalog_overview()`` merged
  the native listing into the response verbatim.

Fixes, all the established conventions: ``_mapping_get`` (ups_svc) +
``_clean_rows`` (``_jsonable`` row laundering, docker_cli) at the
``list_containers`` / ``list_all_vms`` / ``list_native_apps`` /
``list_stacks`` / uninstall-preview boundaries in hub/apps_manage_svc.py, the
same ``_jsonable`` laundering for the native half of ``catalog_overview()``,
``_truthy`` (jobs) for the toggle-result reads, and the unbound base encode in
``catalog._plain_str``.  Section resilience follows for free: one hostile row
used to cost the whole native/docker/vm section of GET /api/apps/managed via
``_collect``'s fallback, and unhashable ``package`` / ``launchd_label`` junk
TypeError'd the brew-autostart index the same way.

Also pinned here: the vanished-CLI sentinel in ``_compose_cmd`` /
``install_template`` / ``uninstall_template`` now classifies as
``container.engine_down`` only after ``cli_on_disk()`` confirms the binary
actually left the disk (the compose_svc / actions convention) — a stack
directory that vanished mid-request raises the same FileNotFoundError and,
with the CLI still present, the coded 503 pointed the operator at the wrong
remedy.  No new error codes: the locales are untouched.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import apps_manage_svc, catalog
from hub.app_factory import create_app
from hub.auth import require_auth

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


class _DictItemsBomb(dict):
    def items(self):
        raise RuntimeError("leftover .items bomb")


class _ListIterBomb(list):
    def __iter__(self):
        raise RuntimeError("leftover __iter__ bomb")


class _StrEqBomb(str):
    def __eq__(self, other):
        raise RuntimeError("leftover __eq__ bomb")

    __ne__ = __eq__
    __hash__ = str.__hash__


class _IntStrBomb(int):
    def __str__(self):
        raise RuntimeError("leftover __str__ bomb")


#: Hex spelling dodges CPython's int(str) parse cap, so a listing really can
#: carry an int whose str() raises the 4300-digit ValueError.
_HEX_HUGE = int("0x" + "f" * 4400, 16)

#: What hub.util.run_capped returns when a spawn raises FileNotFoundError.
_MISSING = (-1, "not found")


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


class DockerDetailRowBombHttpTests(_AppsSandbox):
    """GET detail/logs?id=docker:* over hostile list_containers payloads."""

    def test_payload_get_bomb_is_a_200_detail(self):
        self._mount(**{"hub.containers_svc.list_containers":
                       {"return_value": _DictGetBomb(containers=[])}})
        resp = _client().get("/api/apps/managed/detail", params={"id": "docker:web"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(json.loads(_strict_utf8(resp))["source_id"], "web")

    def test_containers_iter_bomb_keeps_its_real_rows(self):
        # list.__iter__ walks the real storage underneath the override, so
        # the sane row still attaches to the stack (the backups6 convention).
        self._mount(**{"hub.containers_svc.list_containers": {"return_value": {
            "containers": _ListIterBomb([
                {"id": "web", "project": "web", "state": "ok"},
            ]),
        }}})
        resp = _client().get("/api/apps/managed/detail", params={"id": "docker:web"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual([c["name"] for c in payload["containers"]], ["web"])
        self.assertEqual(payload["state"], "ok")

    def test_row_get_bomb_keeps_its_real_data(self):
        # dict.get / the _jsonable dict() copy read the storage underneath
        # the poisoned method, so the bomb row keeps its sane fields.
        self._mount(**{"hub.containers_svc.list_containers": {"return_value": {
            "containers": [_DictGetBomb(id="web", project="web", state="ok")],
        }}})
        resp = _client().get("/api/apps/managed/detail", params={"id": "docker:web"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["state"], "ok")
        self.assertEqual([c["name"] for c in payload["containers"]], ["web"])

    def test_bool_bomb_ports_and_eq_bomb_id_render(self):
        self._mount(**{"hub.containers_svc.list_containers": {"return_value": {
            "containers": [
                {"id": "web", "project": "web", "ports": _BoolBomb(), "state": "ok"},
                {"id": _StrEqBomb("web"), "project": "web"},
                {"id": "web-sane", "project": "web",
                 "ports": "0.0.0.0:8080->80/tcp", "state": "ok"},
            ],
        }}})
        resp = _client().get("/api/apps/managed/detail", params={"id": "docker:web"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        names = [c["name"] for c in payload["containers"]]
        self.assertIn("web-sane", names, "the sane sibling must survive")
        self.assertEqual(payload["url"], "http://" + payload["host_ip"] + ":8080")

    def test_logs_fallback_survives_the_same_rows(self):
        self._mount(**{
            "hub.containers_svc.list_containers": {"return_value": {
                "containers": [
                    _DictGetBomb(id="web", project="web"),
                    {"id": "web2", "project": "web", "labels": _DictItemsBomb()},
                ],
            }},
            "hub.apps_manage_svc.docker": {"return_value": (0, "line1", "")},
        })
        resp = _client().get("/api/apps/managed/logs", params={"id": "docker:web"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertIn("===== web =====", payload["log"])
        self.assertIn("===== web2 =====", payload["log"])

    def test_huge_int_and_surrogate_fields_encode_clean(self):
        self._mount(**{"hub.containers_svc.list_containers": {"return_value": {
            "containers": [{
                "id": "web", "project": "web", "state": "ok",
                "created": _HEX_HUGE, "image": "img\ud800name",
            }],
        }}})
        resp = _client().get("/api/apps/managed/detail", params={"id": "docker:web"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertNotIn("\ud800", _strict_utf8(resp))


class ManagedActionAutostartBombHttpTests(_AppsSandbox):
    """POST /api/apps/managed/action, autostart branch, docker kind."""

    def _post(self, body):
        return _client().post("/api/apps/managed/action", json=body)

    def test_payload_get_bomb_falls_back_to_the_single_container_toggle(self):
        toggle = mock.Mock(return_value={"ok": True, "message": "done"})
        self._mount(**{
            "hub.containers_svc.list_containers":
                {"return_value": _DictGetBomb(containers=[])},
            "hub.autostart_svc.set_docker_autostart": {"side_effect": toggle},
        })
        resp = self._post({"id": "docker:web", "action": "autostart_on"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertTrue(json.loads(_strict_utf8(resp))["ok"])
        toggle.assert_called_once_with("web", True)

    def test_row_get_bomb_still_toggles_its_real_container(self):
        toggle = mock.Mock(return_value={"ok": True, "message": "done"})
        self._mount(**{
            "hub.containers_svc.list_containers": {"return_value": {
                "containers": [_DictGetBomb(id="web", project="web")],
            }},
            "hub.autostart_svc.set_docker_autostart": {"side_effect": toggle},
        })
        resp = self._post({"id": "docker:web", "action": "autostart_on"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["autostart"])
        toggle.assert_called_once_with("web", True)

    def test_a_toggle_result_get_bomb_cannot_500_after_the_toggle_ran(self):
        # The result is another module's payload: dict.get reads the sane
        # storage underneath the poisoned method.
        self._mount(**{
            "hub.containers_svc.list_containers": {"return_value": {
                "containers": [{"id": "web", "project": "web"}],
            }},
            "hub.autostart_svc.set_docker_autostart":
                {"return_value": _DictGetBomb(ok=True, message="ok\ud800!")},
        })
        resp = self._post({"id": "docker:web", "action": "autostart_on"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertTrue(payload["ok"])
        self.assertIn("web: ok", payload["message"])
        self.assertNotIn("\ud800", _strict_utf8(resp))

    def test_a_bool_bomb_ok_field_reads_as_failure_not_a_500(self):
        self._mount(**{
            "hub.containers_svc.list_containers": {"return_value": {
                "containers": [{"id": "web", "project": "web"}],
            }},
            "hub.autostart_svc.set_docker_autostart":
                {"return_value": {"ok": _BoolBomb(), "message": "?"}},
        })
        resp = self._post({"id": "docker:web", "action": "autostart_off"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertFalse(json.loads(_strict_utf8(resp))["ok"])


class VmDetailRowBombHttpTests(_AppsSandbox):
    """GET detail?id=vm:* over hostile list_all_vms payloads."""

    def test_payload_get_bomb_is_the_coded_404_not_a_500(self):
        self._mount(**{"hub.vms_svc.list_all_vms":
                       {"return_value": _DictGetBomb(vms=[])}})
        resp = _client().get("/api/apps/managed/detail", params={"id": "vm:u1"})
        self.assertEqual(resp.status_code, 404, resp.text[:300])
        detail = json.loads(_strict_utf8(resp))["detail"]
        self.assertEqual(detail["code"], "apps.vm_not_found")

    def test_row_get_bomb_keeps_its_real_data(self):
        self._mount(**{"hub.vms_svc.list_all_vms": {"return_value": {
            "vms": [_DictGetBomb(id="u1", state="running", backend="utm")],
        }}})
        resp = _client().get("/api/apps/managed/detail", params={"id": "vm:u1"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["backend"], "utm")
        self.assertIn("stop", payload["actions"])

    def test_iter_bomb_ips_and_bool_bomb_state_render(self):
        self._mount(**{"hub.vms_svc.list_all_vms": {"return_value": {
            "vms": [
                {"id": "u1", "state": _BoolBomb(), "ips": _ListIterBomb(["10.0.0.9"]),
                 "actions": _ListIterBomb(["clone"]), "url": _BoolBomb()},
            ],
        }}})
        resp = _client().get("/api/apps/managed/detail", params={"id": "vm:u1"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        # A nested list subclass whose own __iter__ bombs is unreadable:
        # _jsonable drops that field (its value cannot be trusted), costing
        # the ips column only — never the detail page.
        self.assertEqual(payload["ips"], [])
        self.assertIn("start", payload["actions"])
        self.assertNotIn("clone", payload["actions"])

    def test_eq_bomb_sibling_does_not_cost_the_looked_up_row(self):
        self._mount(**{"hub.vms_svc.list_all_vms": {"return_value": {
            "vms": [
                {"id": _StrEqBomb("uX"), "state": "running"},
                {"id": "u1", "state": "stopped"},
            ],
        }}})
        resp = _client().get("/api/apps/managed/detail", params={"id": "vm:u1"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertIn("start", json.loads(_strict_utf8(resp))["actions"])


class NativeDetailRowBombHttpTests(_AppsSandbox):
    """GET detail?id=native:* over hostile list_native_apps rows."""

    def setUp(self):
        super().setUp()
        from hub import native_catalog
        self.native_id = native_catalog.NATIVE_APPS[0]["id"]
        patched = mock.patch(
            "hub.tools_svc.listening_ports", return_value={"ports": []}
        )
        patched.start()
        self.addCleanup(patched.stop)

    def _detail(self, rows):
        self._mount(**{"hub.native_catalog.list_native_apps":
                       {"return_value": rows}})
        return _client().get(
            "/api/apps/managed/detail", params={"id": f"native:{self.native_id}"}
        )

    def test_row_get_bomb_keeps_its_real_data(self):
        resp = self._detail([_DictGetBomb(id=self.native_id, running=True)])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(json.loads(_strict_utf8(resp))["state"], "ok")

    def test_bool_bomb_running_and_iter_bomb_actions_render(self):
        resp = self._detail([{
            "id": self.native_id, "installed": True,
            "running": _BoolBomb(), "actions": _ListIterBomb(["detail"]),
        }])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["source_id"], self.native_id)

    def test_eq_bomb_id_row_falls_back_to_the_catalog_entry(self):
        resp = self._detail([{"id": _StrEqBomb(self.native_id)}])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(
            json.loads(_strict_utf8(resp))["source_id"], self.native_id
        )


class InventorySectionResilienceTests(_AppsSandbox):
    """One hostile row must cost itself, never its section of the page."""

    def test_hostile_native_row_keeps_the_sane_sibling(self):
        self._mount(**{"hub.native_catalog.list_native_apps": {"return_value": [
            {"id": "native-junk", "installed": True, "running": _BoolBomb(),
             "package": {"not": "hashable"}, "method": "brew_formula",
             "name": "x\ud800y", "ports": _ListIterBomb([_HEX_HUGE])},
            {"id": "native-sane", "installed": True, "running": True,
             "name": "Sane", "category": "dev"},
        ]}})
        resp = _client().get("/api/apps/managed", params={"force": "true"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = _strict_utf8(resp)
        self.assertNotIn("\ud800", body)
        ids = {r["source_id"] for r in json.loads(body)["items"]
               if r["kind"] == "native"}
        self.assertEqual(ids, {"native-junk", "native-sane"})

    def test_hostile_vm_row_keeps_the_sane_sibling(self):
        self._mount(**{"hub.vms_svc.list_all_vms": {"return_value": {
            "vms": [
                _DictGetBomb(id="junk", state=_BoolBomb()),
                {"id": "sane", "name": "sane", "state": "running"},
            ],
        }}})
        resp = _client().get("/api/apps/managed", params={"force": "true"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        ids = {r["source_id"] for r in json.loads(_strict_utf8(resp))["items"]
               if r["kind"] == "vm"}
        self.assertEqual(ids, {"junk", "sane"})

    def test_hostile_stack_row_keeps_the_sane_sibling(self):
        self._mount(**{"hub.containers_svc.list_stacks": {"return_value": [
            _DictGetBomb(id="junkstack", status=_BoolBomb()),
            {"id": "sanestack", "name": "sane", "running_containers": []},
        ]}})
        resp = _client().get("/api/apps/managed", params={"force": "true"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        ids = {r["source_id"] for r in json.loads(_strict_utf8(resp))["items"]
               if r["kind"] == "docker"}
        self.assertEqual(ids, {"junkstack", "sanestack"})


class CatalogOverviewNativeBombHttpTests(unittest.TestCase):
    """GET /api/catalog with hostile native rows merged into the store."""

    def _get(self, rows):
        with (
            mock.patch("hub.native_catalog.list_native_apps", return_value=rows),
            mock.patch.object(catalog, "list_templates", return_value=[]),
        ):
            return _client().get("/api/catalog")

    def test_row_get_bomb_keeps_its_real_data(self):
        resp = self._get([
            _DictGetBomb(id="native-a", installed=True, kind="native", name="A"),
            {"id": "native-b", "installed": False, "kind": "native", "name": "B"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        names = [t.get("name") for t in payload["templates"]]
        self.assertEqual(names, ["A", "B"])
        self.assertEqual(payload["installed"], 1)

    def test_bool_eq_str_bombs_in_the_sort_key_render(self):
        resp = self._get([
            {"id": _StrEqBomb("native-y"), "installed": _BoolBomb(),
             "kind": "native", "category": _ListIterBomb(),
             "featured": _BoolBomb(), "name": _IntStrBomb(3)},
            {"id": "native-sane", "installed": True, "kind": "native",
             "name": "Sane", "category": "dev"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertIn("Sane", [t.get("name") for t in payload["templates"]])
        self.assertEqual(payload["counts"].get("dev"), 1)

    def test_surrogate_huge_int_and_bytes_encode_clean(self):
        # These three passed every python-level gate and 500'd Starlette's
        # UTF-8 / json.dumps encode on the pre-fix tree.
        resp = self._get([
            {"id": "native-z", "installed": True, "kind": "native",
             "name": "a\ud800b"},
            {"id": "native-h", "installed": True, "kind": "native",
             "name": "h", "ports": [_HEX_HUGE]},
            {"id": "native-b", "installed": True, "kind": "native",
             "name": "b", "running": bytes([0xFF, 0xFE])},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = _strict_utf8(resp)
        self.assertNotIn("\ud800", body)
        payload = json.loads(body)
        self.assertEqual(len(payload["templates"]), 3)
        huge = next(t for t in payload["templates"] if t["id"] == "native-h")
        # The unrenderable int is dropped, not the row.
        self.assertEqual(huge["ports"], [None])


class LaunchdDetailPreviewBombHttpTests(unittest.TestCase):
    """GET detail?id=launchd:* launders the uninstall preview it merges."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        agents = Path(self._tmp.name) / "agents"
        agents.mkdir()
        (agents / "local.sane.plist").write_bytes(
            b"""<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>Label</key><string>local.sane</string>
  <key>RunAtLoad</key><true/>
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

    def test_preview_get_bomb_keeps_its_real_fields(self):
        preview = _DictGetBomb(
            program="/usr/local/bin/kirogo", workdir="/srv", plist="p",
            can_remove_data=_BoolBomb(), remove_data_path="",
        )
        with mock.patch("hub.services_uninstall_svc.preview", return_value=preview):
            resp = _client().get(
                "/api/apps/managed/detail", params={"id": "launchd:local.sane"}
            )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["program"], "/usr/local/bin/kirogo")
        self.assertEqual(payload["workdir"], "/srv")


class ComposeCwdVanishedDiskConfirmHttpTests(_AppsSandbox):
    """POST action / install / uninstall: the vanished-CLI 503 only after the
    disk confirm; a vanished cwd (same sentinel, CLI on disk) stays raw."""

    def setUp(self):
        super().setUp()
        import sys
        stack = self.services / "mystack"
        stack.mkdir()
        (stack / "docker-compose.yml").write_text("services: {}\n")
        patched = mock.patch.object(apps_manage_svc, "DOCKER", sys.executable)
        patched.start()
        self.addCleanup(patched.stop)

    def _stop(self, on_disk):
        probe = mock.Mock(return_value=False)
        with (
            mock.patch.object(apps_manage_svc, "run_capped", return_value=_MISSING),
            mock.patch.object(apps_manage_svc, "engine_up", probe),
            mock.patch.object(
                apps_manage_svc, "cli_on_disk", return_value=on_disk
            ),
        ):
            resp = _client().post(
                "/api/apps/managed/action",
                json={"id": "docker:mystack", "action": "stop"},
            )
        return resp, probe

    def test_cli_confirmed_gone_is_the_coded_soft_fail(self):
        resp, probe = self._stop(on_disk=False)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["code"], "container.engine_down")
        probe.assert_called_once_with(force=True)

    def test_cli_still_on_disk_keeps_the_raw_message(self):
        resp, probe = self._stop(on_disk=True)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])
        self.assertNotIn("code", payload)
        self.assertEqual(payload["message"], "not found")
        # The message-pattern gate fails first, so no probe is spawned.
        probe.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
