"""Leftover Dashboard silent-loss + 500s: numeric YAML ids and str() probes.

The dash sweep (test_dashboard_leftover_hexint_surrogate_vanish_500s) pinned
the encoder legs — over-cap ints and surrogates travelling *out* through
``status._jsonable``.  This battery covers the id plumbing the dashboard's
Attention tile and member view stand on:

* ``actions.registry()`` gated ids on ``isinstance(sid, str)``, so a numeric
  YAML id (``id: 8080`` loads as int) was silently dropped from the action
  registry while ``collect_apps`` / ``collect_scripts`` still rendered the
  row with start/stop buttons — POST /api/action answered
  ``actions.unknown_target`` for a service the dashboard itself offered.
  The fix is the ``jobs._task_id`` rule: a ``str()`` probe that coerces a
  renderable int, drops an over-cap hex leftover (its ``str()`` raises the
  same digit-cap ValueError ``json.dumps`` would), and refuses bool.
* the discovery rows emitted ``id`` raw, so a leftover ``\\ud800`` id row
  never matched its scrubbed registry key, and an over-cap hex id rendered
  a ghost row whose id nulls out in JSON and can never be acted on.
* ``status._build_status`` filtered ``groups_order`` on ``isinstance(g,
  str)``, so a numeric YAML group name (``groups_order: [2024, Media]``)
  silently lost its configured position.
* ``status.filter_status_for_resources`` called bare ``str()`` on resource
  ids and service states; an over-cap int in either raised the digit-cap
  ValueError and 500'd the member GET /api/status it exists to serve.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi import HTTPException

from hub import actions, status
from hub.discovery import apps as apps_mod

#: Built arithmetically: int("9" * 5000) itself trips the digit cap.
_HUGE_INT = 10 ** 5000


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _registry_with_cfg(cfg_data):
    with mock.patch.object(actions, "cfg", return_value=cfg_data), \
         mock.patch.object(actions, "sh", return_value=(1, "", "")), \
         mock.patch.object(actions, "AGENTS_DIR", "/nonexistent-agents-dir"), \
         mock.patch("hub.vms_svc.list_orb_machines", return_value=[]):
        return actions.registry()


class NumericYamlIdRegistryTests(unittest.TestCase):
    """actions.registry(): str() probe, not an isinstance(str) gate."""

    def test_numeric_app_id_is_registered(self):
        reg = _registry_with_cfg(
            {"apps": [{"id": 8080, "name": "Web", "process": "webproc"}]}
        )
        self.assertIn("8080", reg)
        self.assertEqual(reg["8080"][0], "app")

    def test_numeric_script_id_is_registered(self):
        reg = _registry_with_cfg(
            {"scripts": [{"id": 3001, "name": "Bot", "start": "echo hi"}]}
        )
        self.assertIn("3001", reg)
        self.assertEqual(reg["3001"][0], "script")

    def test_over_cap_hex_id_drops_only_its_entry(self):
        """A >4300-digit YAML hex id cannot be rendered or targeted at all —
        it drops, and must not take registry() (or its neighbours) with it."""
        reg = _registry_with_cfg({
            "apps": [
                {"id": _HUGE_INT, "process": "ghost"},
                {"id": "plex", "process": "plexproc"},
            ],
        })
        self.assertIn("plex", reg)
        self.assertEqual(len([k for k in reg if k not in ("plex",)]), 0)

    def test_bool_id_never_becomes_the_string_true(self):
        reg = _registry_with_cfg({"apps": [{"id": True, "process": "p"}]})
        self.assertNotIn("True", reg)
        self.assertNotIn(True, reg)

    def test_run_action_reaches_a_numeric_id_app(self):
        """The dashboard Attention tile offers stop on this row; the action
        must reach the app branch instead of falling through to the VM
        fallback and answering actions.unknown_target."""
        cfg_data = {"apps": [{"id": 8080, "name": "Web", "process": "webproc"}]}
        calls = []

        def fake_sh(argv, **kw):
            calls.append(argv)
            return 0, "", ""

        with mock.patch.object(actions, "cfg", return_value=cfg_data), \
             mock.patch.object(actions, "sh", fake_sh), \
             mock.patch.object(actions, "AGENTS_DIR", "/nonexistent-agents-dir"), \
             mock.patch("hub.vms_svc.list_orb_machines", return_value=[]), \
             mock.patch("hub.vms_svc.vm_action",
                        side_effect=AssertionError("fell through to VM fallback")):
            try:
                rc, out, err = actions.run_action("8080", "stop")
            except HTTPException as exc:  # pragma: no cover - pre-fix shape
                self.fail(f"numeric-id app answered a coded error: {exc.detail}")
        self.assertEqual((rc, out, err), (0, "stopped", ""))
        self.assertTrue(
            any("osascript" in str(argv[0]) for argv in calls if argv),
            f"expected the app quit branch to run, saw {calls}",
        )


class DiscoveryRowIdTests(unittest.TestCase):
    """collect_apps / collect_scripts emit the id text the registry keys."""

    def _apps(self, cfg_data, engine_up=False):
        with mock.patch.object(apps_mod, "cfg", return_value=cfg_data), \
             mock.patch.object(apps_mod, "sh", return_value=(1, "", "")), \
             mock.patch.object(apps_mod, "port_open", return_value=False), \
             mock.patch.object(apps_mod, "configured_group_rules", return_value=[]):
            return apps_mod.collect_apps(engine_up)

    def _scripts(self, cfg_data):
        with mock.patch.object(apps_mod, "cfg", return_value=cfg_data), \
             mock.patch.object(apps_mod, "port_open", return_value=False), \
             mock.patch.object(apps_mod, "configured_group_rules", return_value=[]):
            return apps_mod.collect_scripts()

    def test_numeric_app_row_id_matches_its_registry_key(self):
        cfg_data = {"apps": [{"id": 8080, "name": "Web", "process": "webproc"}]}
        rows = self._apps(cfg_data)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], "8080")
        self.assertIn(rows[0]["id"], _registry_with_cfg(cfg_data))

    def test_numeric_script_row_id_matches_its_registry_key(self):
        cfg_data = {"scripts": [{"id": 3001, "start": "echo hi"}]}
        rows = self._scripts(cfg_data)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], "3001")
        self.assertEqual(rows[0]["name"], "3001")
        self.assertIn(rows[0]["id"], _registry_with_cfg(cfg_data))

    def test_surrogate_app_id_row_matches_its_scrubbed_registry_key(self):
        """The registry scrubs \\ud800 (actions._as_text); the row used to
        carry it raw, so the id the dashboard serves — scrubbed again by
        status._jsonable at encode time — named a key that does not exist."""
        cfg_data = {"apps": [{"id": "j\ud800f", "process": "jf"}]}
        rows = self._apps(cfg_data)
        self.assertEqual(len(rows), 1)
        self.assertNotIn("\ud800", rows[0]["id"])
        _starlette(rows[0]["id"])
        reg = _registry_with_cfg(cfg_data)
        self.assertIn(rows[0]["id"], reg)

    def test_over_cap_app_id_row_is_skipped_not_rendered_as_a_ghost(self):
        rows = self._apps({
            "apps": [
                {"id": _HUGE_INT, "process": "ghost"},
                {"id": "plex", "process": "plexproc"},
            ],
        })
        self.assertEqual([r["id"] for r in rows], ["plex"])

    def test_over_cap_script_id_row_is_skipped(self):
        rows = self._scripts({
            "scripts": [
                {"id": _HUGE_INT, "start": "x"},
                {"id": "bot", "start": "y"},
            ],
        })
        self.assertEqual([r["id"] for r in rows], ["bot"])

    def test_engine_row_numeric_id_matches_its_registry_key(self):
        cfg_data = {"apps": [{"id": 42, "container_engine": True}]}
        rows = self._apps(cfg_data, engine_up=True)
        self.assertEqual(rows[0]["id"], "42")
        reg = _registry_with_cfg(cfg_data)
        self.assertEqual(reg.get("42", (None,))[0], "app-engine")


class GroupsOrderNumericTests(unittest.TestCase):
    """status._build_status: groups_order keeps numeric YAML group names."""

    def _build(self, cfg_data, rows):
        patches = [
            mock.patch.object(status, "cfg", lambda: cfg_data),
            mock.patch.object(status, "discover_launchd", lambda: []),
            mock.patch.object(status, "discover_containers", lambda: ([], True)),
            mock.patch.object(status, "discover_vms", lambda: []),
            mock.patch.object(status, "collect_system", lambda: {}),
            mock.patch.object(status, "collect_scripts", lambda: []),
            mock.patch.object(status, "collect_apps", lambda up: rows),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        return status._build_status()

    _ROWS = [
        {"id": "a", "name": "a", "state": "ok", "group": "2024"},
        {"id": "b", "name": "b", "state": "ok", "group": "Media"},
    ]

    def test_numeric_groups_order_entry_keeps_its_position(self):
        payload = self._build(
            {"settings": {"adaptive": False}, "groups_order": [2024, "Media"]},
            self._ROWS,
        )
        _starlette(payload)
        self.assertEqual(
            [g["group"] for g in payload["groups"]], ["2024", "Media"]
        )

    def test_over_cap_groups_order_entry_does_not_500_status(self):
        payload = self._build(
            {"settings": {"adaptive": False}, "groups_order": [_HUGE_INT, "Media"]},
            self._ROWS,
        )
        _starlette(payload)
        self.assertEqual(
            [g["group"] for g in payload["groups"]], ["Media", "2024"]
        )


class MemberFilterProbeTests(unittest.TestCase):
    """filter_status_for_resources: str() probes, never a bare str() 500."""

    _SNAP = {"groups": [{"group": "G", "services": [
        {"id": "svc", "name": "svc", "state": "ok", "actions": ["open"]},
    ]}]}

    def test_over_cap_resource_id_does_not_500_member_status(self):
        got = status.filter_status_for_resources(self._SNAP, [_HUGE_INT, "svc"])
        _starlette(got)
        self.assertEqual(got["service_total"], 1)

    def test_planted_over_cap_state_counts_as_unknown_not_500(self):
        snap = {"groups": [{"group": "G", "services": [
            {"id": "svc", "name": "svc", "state": _HUGE_INT, "actions": []},
        ]}]}
        got = status.filter_status_for_resources(snap, ["svc"])
        _starlette(got)
        self.assertEqual(got["counts"]["unknown"], 1)

    def test_numeric_resource_id_still_matches_a_numeric_row(self):
        """Stays-allowed: a numeric YAML resources entry names the numeric-id
        row the discovery layer now serves as its text form."""
        snap = {"groups": [{"group": "G", "services": [
            {"id": "8080", "name": "web", "state": "ok", "actions": ["open"]},
        ]}]}
        got = status.filter_status_for_resources(snap, [8080])
        _starlette(got)
        self.assertEqual(got["service_total"], 1)
        self.assertEqual(got["groups"][0]["services"][0]["id"], "8080")


if __name__ == "__main__":
    unittest.main()
