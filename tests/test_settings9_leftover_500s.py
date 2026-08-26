"""Settings9 leftover sweep: the two 500s a hostile re-probe still found.

settings8 sealed the scalar/subclass bombs inside the section reads, but a
fresh battery over the real ``create_app()`` + TestClient
(raise_server_exceptions=False) — every settings route x every bomb shape x
every top-level and nested slot — still detonated in two places:

* **``config.settings_section`` called ``cfg()`` unguarded.**  Its dict
  laundering (``dict.get`` / ``dict(...)``) already survives every subclass
  bomb *inside* the snapshot, but a snapshot provider that raises escaped
  the helper itself.  GET /api/settings answered 200 over the very same
  failure (its reads go through the guarded ``_cfg_map`` /
  ``_settings_map`` siblings), while GET /api/settings/other and
  /api/settings/thresholds — whose first read is ``settings_section`` —
  were raw 500s.  Guarded to the same rule: an unanswerable snapshot reads
  as an empty section and the routes render defaults.

* **``_public_settings`` probed ``data.get("stacks") or []``.**  The ``or``
  reflects into the stored value's own ``__bool__``/``__len__``, so a
  leftover bomb riding ``stacks`` / ``log_sources`` / ``groups_order`` — a
  non-list ``__bool__`` bomb, a list *subclass* whose ``__len__`` raises
  (``bool(list_subclass)`` dispatches there), or a dict-subclass
  ``__bool__`` bomb — 500'd GET /api/settings (and the PUT response render)
  before ``_json_list``'s isinstance gate ever saw the value.  ``_json_list``
  already answers ``[]`` for None and non-list leftovers, so the probe
  bought nothing.

The disk-mutate battery (torn / unparseable / oversize / FIFO / directory
services.yaml under PUT), the redacted export, and every http_guard gate
came back sealed; the config-unreadable pins here keep the 503-plus-intact-
file contract from regressing alongside the new fixes.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import config, system_settings_svc
from hub.app_factory import create_app
from hub.auth import require_auth
from hub.routers import settings_api


class BoolBomb:
    """Not a list: ``bool(x)`` raises before any isinstance gate."""

    def __bool__(self):
        raise RuntimeError("bool bomb")


class LenBombList(list):
    """Passes ``isinstance(x, list)``; ``bool(x)`` dispatches into ``__len__``."""

    def __len__(self):
        raise RuntimeError("len bomb")


class BoolBombDict(dict):
    def __bool__(self):
        raise RuntimeError("bool bomb dict")


def _base(**top) -> dict:
    return {
        "settings": {"host_ip": "10.0.0.9"},
        "stacks": [{"name": "s1", "port": 80}],
        "log_sources": [],
        "groups_order": ["a"],
        **top,
    }


class _SettingsHttpPin(unittest.TestCase):
    def _client(self) -> TestClient:
        app = create_app()
        app.dependency_overrides[require_auth] = lambda: None
        self.addCleanup(app.dependency_overrides.clear)
        return TestClient(app, raise_server_exceptions=False)

    def _patched(self, **kwargs):
        # cfg was imported by name into each consumer, so every seam the
        # routes read through gets the same poisoned snapshot / failure.
        return (
            mock.patch.object(config, "cfg", **kwargs),
            mock.patch.object(system_settings_svc, "cfg", **kwargs),
            mock.patch.object(settings_api, "cfg", **kwargs),
        )

    def _ok_body(self, path: str, **kwargs) -> dict:
        client = self._client()
        p1, p2, p3 = self._patched(**kwargs)
        with p1, p2, p3:
            resp = client.get(path)
        self.assertEqual(resp.status_code, 200, resp.text[:400])
        body = resp.json()
        # The body Starlette encoded must be re-encodable under the same
        # allow_nan=False / UTF-8 contract it used.
        json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        return body


class SettingsSectionCfgRaisesPins(_SettingsHttpPin):
    """A raising snapshot provider degrades to defaults, never a raw 500."""

    @staticmethod
    def _boom():
        raise RuntimeError("cfg bomb")

    def test_settings_section_answers_empty_not_raise(self):
        with mock.patch.object(config, "cfg", side_effect=self._boom):
            self.assertEqual(config.settings_section("thresholds"), {})
            self.assertEqual(config.settings_section("ip_aliases"), {})

    def test_other_route_renders_defaults(self):
        body = self._ok_body("/api/settings/other", side_effect=self._boom)
        self.assertEqual(body["resource_mode"], "low")
        self.assertEqual(body["metrics_interval"], 90)
        self.assertEqual(body["ip_aliases"]["ips"], [])

    def test_thresholds_route_renders_defaults(self):
        body = self._ok_body("/api/settings/thresholds", side_effect=self._boom)
        self.assertEqual(body["cpu_pct"], 90)
        self.assertTrue(body["enabled"])

    def test_get_settings_still_answers_beside_them(self):
        # The already-guarded sibling must keep its answer over the same
        # failure — pinned so the three routes stay in lockstep.
        body = self._ok_body("/api/settings", side_effect=self._boom)
        self.assertEqual(body["resource_mode"], "low")


class TopLevelListBombPins(_SettingsHttpPin):
    """GET /api/settings over ``stacks``/``log_sources``/``groups_order`` bombs."""

    BOMBS = (
        ("non-list __bool__", lambda: BoolBomb()),
        ("list-subclass __len__", lambda: LenBombList([{"name": "s1"}])),
        ("dict-subclass __bool__", lambda: BoolBombDict({"a": 1})),
    )

    def test_each_key_each_bomb_degrades_to_empty(self):
        for key in ("stacks", "log_sources", "groups_order"):
            for label, make in self.BOMBS:
                with self.subTest(key=key, shape=label):
                    snap = _base(**{key: make()})
                    body = self._ok_body("/api/settings", return_value=snap)
                    self.assertEqual(body[key], [])
                    # Healthy siblings around the bomb are untouched.
                    self.assertEqual(body["host_ip"], "10.0.0.9")
                    others = {"stacks", "log_sources", "groups_order"} - {key}
                    for other in others:
                        self.assertIsInstance(body[other], list)

    def test_healthy_lists_still_pass_through(self):
        body = self._ok_body("/api/settings", return_value=_base())
        self.assertEqual(body["stacks"], [{"name": "s1", "port": 80}])
        self.assertEqual(body["groups_order"], ["a"])
        self.assertEqual(body["log_sources"], [])

    def test_put_response_render_survives_the_bombs(self):
        # PUT mutates the on-disk file (untouched here) and then renders
        # _public_settings() off the poisoned snapshot: the response render
        # used to inherit the same ``or []`` 500.
        snap = _base(stacks=BoolBomb(), groups_order=LenBombList(["a"]))
        client = self._client()
        p1, p2, p3 = self._patched(return_value=snap)
        with p1, p2, p3:
            resp = client.put("/api/settings", json={"ui": {"theme": "nord"}})
        self.assertEqual(resp.status_code, 200, resp.text[:400])
        body = resp.json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["settings"]["stacks"], [])
        self.assertEqual(body["settings"]["groups_order"], [])
        json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")


class ConfigUnreadableStaysPinned(unittest.TestCase):
    """The mutate refusal contract the fixes above must not disturb.

    services.yaml torn to non-UTF-8 answers the coded 503
    ``settings.config_unreadable`` and stays byte-identical on disk —
    never a 200 that persisted a wipe, never a raw 500.
    """

    def test_torn_config_is_refused_and_intact(self):
        app = create_app()
        app.dependency_overrides[require_auth] = lambda: None
        self.addCleanup(app.dependency_overrides.clear)
        client = TestClient(app, raise_server_exceptions=False)

        torn = b"settings:\n  host_ip: \xff\xfe\n"
        path = config.YAML_PATH
        original = path.read_bytes() if path.is_file() else None
        path.write_bytes(torn)
        try:
            config.reload_cfg()
            resp = client.put("/api/settings", json={"ui": {"theme": "nord"}})
            self.assertEqual(resp.status_code, 503, resp.text[:400])
            self.assertEqual(
                resp.json()["detail"]["code"], "settings.config_unreadable",
            )
            self.assertEqual(path.read_bytes(), torn)
        finally:
            if original is None:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(original)
            config.reload_cfg()


if __name__ == "__main__":
    unittest.main()
