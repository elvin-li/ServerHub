"""Ninth leftover-500s sweep of the Apps managed action/detail surfaces.

apps8 sealed the *raising* collaborators behind ``action()``'s seam and the
raising / ``.get``-bomb ``config.override`` behind ``_launchd_apps``.  What
was still live on the pre-fix tree, driven through ``create_app()`` +
``TestClient(raise_server_exceptions=False)``: the module had no fail-closed
``_isa`` helper, so every bare ``isinstance`` gate was itself a detonation
point for a leftover whose ``__class__`` is a *raising property* — and a
*lying* ``__class__`` could walk through the gates the bombs could not.

* POST /api/apps/managed/action — a collaborator that *returned* junk
  instead of raising it rode past the apps8 seam (the try only covers a
  raising call): a ``__class__``-property bomb or a lying dict impostor
  from ``set_docker_autostart`` / ``set_launchd_autostart`` /
  ``set_brew_autostart`` / ``vm_action`` detonated ``_safe_payload``'s bare
  dict gate (or came back verbatim into Starlette's encoder) — a raw 500
  after the action had already run.  A bool-liar ``ok`` flag inside an
  otherwise sane result 500'd the encoder the same way.  In the
  per-container loop, one bomb *result* raised out of the result formatting
  and folded the lines of containers already toggled into one bare
  ``ok: false``.
* GET /api/apps/managed/detail?id=launchd:* — junk *inside* a sane override
  dict raised out of ``_launchd_apps`` one line past the apps8 seams: a
  ``__class__``-property-bomb value, a hash-shadowing str-subclass key
  whose ``__eq__`` fires during ``dict.get``'s probe, a float-subclass
  ``__eq__`` bomb port, an int-subclass ``__str__`` bomb port, and a
  bytes-subclass ``.decode`` bomb name were all raw 500s — and each one
  silently emptied the whole launchd section of GET /api/apps/managed via
  ``_collect``'s fallback.  An override whose ``__class__`` is itself a
  raising property detonated the post-seam dict gate the same way.
* GET /api/apps/managed — ``engine_up`` returning a ``__class__``-property
  bomb detonated the bare bool gate in ``inventory()``; a bool-liar rode
  through it verbatim into Starlette's encoder.  Both raw 500s.  One
  ``__class__``-property-bomb row in ``list_stacks`` / ``list_all_vms``
  detonated ``_clean_rows``' bare row gate and wiped the row's whole
  section, the exact row-wipe the launderer exists to stop.
* GET /api/apps/managed/logs?id=native:native-cloudflared — the one logs
  branch that hands another module's payload back verbatim: a bomb or
  impostor return from ``cloudflared_svc.logs`` 500'd where a *raising*
  backend already answered ``ok: false``.

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


class _ClassBomb:
    """``__class__`` is a raising property: every bare isinstance detonates."""

    @property
    def __class__(self):
        raise RuntimeError("leftover __class__ bomb")


class _DictLiar:
    """Lies about being a dict; carries none of a dict's machinery."""

    @property
    def __class__(self):
        return dict


class _BoolLiar:
    """Lies about being a bool; bool is final, so only a liar can claim it."""

    @property
    def __class__(self):
        return bool


class _HashWarKey(str):
    """A stored key whose hash shadows a real field and whose ``__eq__`` fires."""

    def __new__(cls, shadow):
        obj = str.__new__(cls, "\x00hash-war")
        obj._shadow = shadow
        return obj

    def __hash__(self):
        return hash(self._shadow)

    def __eq__(self, other):
        raise RuntimeError("leftover key __eq__ bomb")

    __ne__ = __eq__


class _EqBombFloat(float):
    def __eq__(self, other):
        raise RuntimeError("leftover float __eq__ bomb")

    __ne__ = __eq__
    __hash__ = float.__hash__


class _EqBombInt(int):
    def __eq__(self, other):
        raise RuntimeError("leftover rc __eq__ bomb")

    __ne__ = __eq__
    __hash__ = int.__hash__


class _StrBombInt(int):
    def __str__(self):
        raise RuntimeError("leftover int __str__ bomb")


class _DecodeBombBytes(bytes):
    def decode(self, *a, **k):
        raise RuntimeError("leftover .decode bomb")


class _AppsSandbox(unittest.TestCase):
    """Temp SERVICES_ROOT, collaborators stubbed per test (the apps8 rig)."""

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


class ReturnedJunkActionResultHttpTests(_AppsSandbox):
    """POST action: a collaborator *returning* junk answers ok:false, not 500."""

    def test_docker_single_toggle_returns_a_class_bomb(self):
        # apps8 pinned the *raising* toggle; the toggle handing back a
        # ``__class__``-property bomb detonated _safe_payload's dict gate
        # one line past that seam — a raw 500 after the action had run.
        self._mount(**{"hub.autostart_svc.set_docker_autostart":
                       {"return_value": _ClassBomb()}})
        resp = self._post({"id": "docker:web", "action": "autostart_on"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])

    def test_docker_single_toggle_returns_a_dict_impostor(self):
        # A lying ``__class__`` passed the gate and came back verbatim —
        # an unencodable object straight into Starlette (raw 500).
        self._mount(**{"hub.autostart_svc.set_docker_autostart":
                       {"return_value": _DictLiar()}})
        resp = self._post({"id": "docker:web", "action": "autostart_on"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])

    def test_toggle_result_with_a_bool_liar_ok_flag(self):
        # The sane message must survive; the liar flag is junk, not consent.
        self._mount(**{"hub.autostart_svc.set_docker_autostart":
                       {"return_value": {"ok": _BoolLiar(), "message": "toggled"}}})
        resp = self._post({"id": "docker:web", "action": "autostart_on"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertIsNot(payload["ok"], True)
        self.assertIn("toggled", payload["message"])

    def test_docker_loop_bomb_result_keeps_lines_already_toggled(self):
        # apps8 pinned a *raising* toggle costing its own line; a toggle
        # *returning* a bomb raised out of the result formatting instead and
        # folded web-1's finished line into one bare ok:false.
        def toggle(ident, enabled):
            if ident == "web-2":
                return _ClassBomb()
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

    def test_launchd_toggle_returns_a_class_bomb(self):
        self._mount(**{"hub.autostart_svc.set_launchd_autostart":
                       {"return_value": _ClassBomb()}})
        resp = self._post({"id": "launchd:local.x", "action": "autostart_on"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])

    def test_brew_toggle_returns_a_class_bomb(self):
        self._mount(**{"hub.autostart_svc.set_brew_autostart":
                       {"return_value": _ClassBomb()}})
        resp = self._post({"id": "native:native-ollama", "action": "autostart_on"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])

    def test_vm_action_returns_a_class_bomb(self):
        self._mount(**{"hub.vms_svc.vm_action": {"return_value": _ClassBomb()}})
        resp = self._post({"id": "vm:u1", "action": "start"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])

    def test_launchd_run_action_rc_eq_bomb_keeps_the_output_text(self):
        # The bare ``rc == 0`` probe used to detonate on an rc-subclass
        # ``__eq__`` bomb; the seam absorbed it but the action's own output
        # was folded into a bare ok:false with it.  An rc that really is 0
        # keeps its success and its text.
        self._mount(**{"hub.actions.run_action":
                       {"return_value": (_EqBombInt(0), "started", "")}})
        resp = self._post({"id": "launchd:local.x", "action": "start"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertTrue(payload["ok"])
        self.assertIn("started", payload["message"])


class LaunchdOverrideJunkHttpTests(unittest.TestCase):
    """Junk inside (or instead of) config.override costs cosmetic fields only."""

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

    def _detail(self, override):
        with mock.patch("hub.config.override", return_value=override):
            return _client().get(
                "/api/apps/managed/detail", params={"id": "launchd:local.sane"}
            )

    def _inventory(self, override):
        with mock.patch("hub.config.override", return_value=override):
            return _client().get("/api/apps/managed", params={"force": "true"})

    def test_a_class_bomb_override_keeps_the_detail_route(self):
        # apps8 pinned the raising and ``.get``-bomb overrides; an override
        # whose ``__class__`` is itself a raising property detonated the
        # post-seam dict gate the same way (500 + a wiped launchd section).
        resp = self._detail(_ClassBomb())
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["source_id"], "local.sane")
        self.assertEqual(payload["name"], "local.sane")

    def test_a_class_bomb_name_value_keeps_the_detail_route(self):
        resp = self._detail({"name": _ClassBomb()})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["source_id"], "local.sane")
        self.assertIsInstance(payload["name"], str)

    def test_a_hash_shadowing_key_costs_the_shadowed_field_only(self):
        # Even the unbound ``dict.get`` runs the *stored keys'* ``__eq__``
        # during the hash probe: a str-subclass key shadowing "name" used
        # to raise out of _launchd_apps and 500 the detail route.
        resp = self._detail({_HashWarKey("name"): "Shadowed"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["source_id"], "local.sane")
        self.assertEqual(payload["name"], "local.sane")

    def test_a_float_eq_bomb_port_keeps_the_detail_route(self):
        resp = self._detail({"port": _EqBombFloat(8080.0)})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["source_id"], "local.sane")
        # A real float underneath the bombed methods keeps its value.
        self.assertEqual(payload["ports_summary"], "8080.0")

    def test_an_int_str_bomb_port_keeps_the_detail_route(self):
        resp = self._detail({"port": _StrBombInt(8080)})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["source_id"], "local.sane")
        # int.__index__ reads the real value underneath the bombed __str__.
        self.assertEqual(payload["ports_summary"], "8080")

    def test_a_decode_bomb_bytes_name_keeps_the_detail_route(self):
        resp = self._detail({"name": _DecodeBombBytes(b"Example Worker")})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["source_id"], "local.sane")
        # The unbound decode reads the real bytes under the bombed method.
        self.assertEqual(payload["name"], "Example Worker")

    def test_a_class_bomb_override_keeps_the_inventory_item(self):
        # The same bomb used to silently empty the whole launchd section of
        # GET /api/apps/managed via _collect's fallback (the row-wipe twin).
        resp = self._inventory(_ClassBomb())
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        ids = [item["id"] for item in payload["items"]]
        self.assertIn("launchd:local.sane", ids)
        self.assertEqual(payload["counts"]["launchd"], 1)

    def test_a_hash_war_override_keeps_the_inventory_item(self):
        resp = self._inventory({_HashWarKey("name"): "Shadowed"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["counts"]["launchd"], 1)


class InventoryJunkHttpTests(_AppsSandbox):
    """GET /api/apps/managed: probe/row junk costs its field or row, not 500."""

    def _get(self):
        return _client().get("/api/apps/managed", params={"force": "true"})

    def test_engine_probe_returns_a_class_bomb(self):
        # The bare bool gate in inventory() detonated on the bomb itself.
        self._mount(**{"hub.apps_manage_svc.engine_up":
                       {"return_value": _ClassBomb()}})
        resp = self._get()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertIsInstance(payload["engine_up"], bool)

    def test_engine_probe_returns_a_bool_liar(self):
        # A lying ``__class__`` rode through the old isinstance gate
        # verbatim into Starlette's encoder — a raw 500 on the Apps page.
        self._mount(**{"hub.apps_manage_svc.engine_up":
                       {"return_value": _BoolLiar()}})
        resp = self._get()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertIsInstance(payload["engine_up"], bool)

    def test_a_class_bomb_stack_row_costs_itself_not_the_section(self):
        # One bomb row used to detonate _clean_rows' bare row gate and wipe
        # the whole docker section via _collect's fallback.
        self._mount(**{"hub.containers_svc.list_stacks": {"return_value": [
            _ClassBomb(),
            {"id": "web", "path": str(self.services / "web"), "status": "ok"},
        ]}})
        resp = self._get()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        ids = [item["id"] for item in payload["items"]]
        self.assertIn("docker:web", ids)
        self.assertEqual(payload["counts"]["docker"], 1)

    def test_a_class_bomb_vm_row_costs_itself_not_the_section(self):
        self._mount(**{"hub.vms_svc.list_all_vms": {"return_value": {"vms": [
            _ClassBomb(),
            {"id": "u1", "name": "u1", "state": "stopped"},
        ]}}})
        resp = self._get()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        ids = [item["id"] for item in payload["items"]]
        self.assertIn("vm:u1", ids)
        self.assertEqual(payload["counts"]["vm"], 1)


class CloudflaredLogsJunkHttpTests(_AppsSandbox):
    """GET logs?id=native:native-cloudflared: junk payloads answer ok:false."""

    def _get(self):
        return _client().get(
            "/api/apps/managed/logs", params={"id": "native:native-cloudflared"}
        )

    def test_a_class_bomb_log_payload(self):
        self._mount(**{"hub.cloudflared_svc.logs":
                       {"return_value": _ClassBomb()}})
        resp = self._get()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])

    def test_a_dict_impostor_log_payload(self):
        self._mount(**{"hub.cloudflared_svc.logs":
                       {"return_value": _DictLiar()}})
        resp = self._get()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])

    def test_a_sane_log_payload_stays_intact(self):
        # The new gate must not over-absorb: a real backend answer passes.
        self._mount(**{"hub.cloudflared_svc.logs":
                       {"return_value": {"ok": True, "log": "tunnel up"}}})
        resp = self._get()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["log"], "tunnel up")


if __name__ == "__main__":
    unittest.main(verbosity=2)
