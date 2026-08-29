"""JSON sweep #5: dict-subclass / __iter__ bombs in the settings render.

Four prior JSON passes (json_dumps, json_recursion, config_unreadable,
config_yaml_hugeint) sealed ``hub/config.py``'s mutate path and its
YAML/JSON loaders against oversize / torn / over-cap / surrogate leftovers,
and the notify/pool sweeps degraded flock and retention-glob EIO.  What none
of them ran against the *settings render* is the row-bomb class that
bookmarks5 / audit5 / usage5 / metrics5 already fixed elsewhere: objects that
pass the ``isinstance(x, dict)`` / ``isinstance(x, list)`` gates and then
raise from an overridden ``.get()`` / ``.items()`` / ``__iter__``.

Driven over the real mounted app (``create_app()`` + TestClient with
``raise_server_exceptions=False``), each of these ``cfg()`` shapes turned
GET /api/settings into a raw 500 before the fix in
``hub/routers/settings_api.py``:

* a settings *section* (``auth`` / ``ui`` / ``notify`` / ``thresholds`` /
  ``ollama``) that is a dict **subclass** whose ``.get`` raises — read
  directly by ``auth.get("username")`` and its siblings;
* the whole ``settings`` map, or the top-level config, a ``.get`` bomb —
  ``cfg().get("settings")`` was the first unguarded read;
* an ``ip_aliases`` map whose ``items()`` raises — it reaches
  ``_jsonable``'s dict branch, whose bare ``value.items()`` raised at encode
  time;
* a ``stacks`` / ``groups_order`` **list subclass** whose ``__iter__``
  raises — ``_json_list`` fed it straight into ``_jsonable``'s list
  comprehension;
* a bomb riding a scalar *value* (``ui.locale`` = an ``items()`` bomb)
  reached ``_jsonable`` a level deeper.

The fix laments each section through ``dict(...)`` (the C-level copy bypasses
the overridden methods) and drops an un-iterable node to ``null`` in
``_jsonable`` — so a bomb degrades alone and every healthy sibling still
renders, and the body stays UTF-8 / allow_nan=False encodable.  A raw 500 is
the leftover; the coded 200 whose good siblings survive is the pass.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import config
from hub.app_factory import create_app
from hub.auth import require_auth
from hub.routers import settings_api


class GetBomb(dict):
    """Passes ``isinstance(x, dict)``; ``.get`` raises.  ``dict(x)`` still
    copies the underlying storage, so laundering neutralises it."""

    def get(self, *a, **k):
        raise RuntimeError("get bomb")


class ItemsBomb(dict):
    def items(self):
        raise RuntimeError("items bomb")


class IterBombList(list):
    def __iter__(self):
        raise RuntimeError("iter bomb")


class BoolBomb:
    def __bool__(self):
        raise RuntimeError("bool bomb")


class Unhashable:
    __hash__ = None


def _base(**settings_extra) -> dict:
    return {
        "settings": {"host_ip": "10.0.0.9", **settings_extra},
        "stacks": [],
        "log_sources": [],
        "groups_order": [],
    }


class _SettingsHttpPin(unittest.TestCase):
    """Shared client that drives the real GET /api/settings route."""

    def _client(self) -> TestClient:
        app = create_app()
        app.dependency_overrides[require_auth] = lambda: None
        self.addCleanup(app.dependency_overrides.clear)
        return TestClient(app, raise_server_exceptions=False)

    def _get(self, cfg_value: dict):
        client = self._client()
        with mock.patch.object(settings_api, "cfg", return_value=cfg_value):
            return client.get("/api/settings")

    def _ok_body(self, cfg_value: dict) -> dict:
        resp = self._get(cfg_value)
        self.assertEqual(resp.status_code, 200, resp.text[:400])
        body = resp.json()
        # The whole point: the body Starlette encoded must be re-encodable
        # under the same allow_nan=False / UTF-8 contract it used.
        json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        return body


class SectionGetBombPins(_SettingsHttpPin):
    """A settings section that is a dict subclass with a bombing ``.get``."""

    def test_each_section_get_bomb_answers_200(self):
        for section in ("auth", "notify", "ui", "thresholds", "ollama"):
            with self.subTest(section=section):
                body = self._ok_body(_base(**{section: GetBomb()}))
                self.assertIn(section, body)

    def test_bombing_section_keeps_its_laundered_values(self):
        """``dict(GetBomb(username="keep"))`` still carries the row, so the
        laundering does not cost the data — it only defuses the method."""
        body = self._ok_body(_base(auth=GetBomb(username="keep-admin")))
        self.assertEqual(body["auth"]["username"], "keep-admin")


class TopLevelGetBombPins(_SettingsHttpPin):
    """The first reads: ``cfg().get("settings")`` and ``settings.get(...)``."""

    def test_top_level_cfg_get_bomb_answers_200(self):
        body = self._ok_body(GetBomb(settings={"host_ip": "1.2.3.4"},
                                     stacks=[], log_sources=[],
                                     groups_order=[]))
        # ``cfg().get("settings")`` was the first unguarded read; the win is
        # a rendered body at all (host_ip_config resolves through a separate
        # configured_host() path, so its value is not asserted here).
        self.assertIn("ui", body)

    def test_settings_map_get_bomb_answers_200(self):
        body = self._ok_body({"settings": GetBomb(host_ip="5.6.7.8"),
                              "stacks": [], "log_sources": [],
                              "groups_order": []})
        self.assertIn("ui", body)


class JsonableItemsAndIterBombPins(_SettingsHttpPin):
    """``items()`` / ``__iter__`` bombs that reach ``_jsonable``."""

    def test_ip_aliases_items_bomb_answers_200_empty(self):
        body = self._ok_body(_base(ip_aliases=ItemsBomb()))
        self.assertEqual(body["ip_aliases"], {})

    def test_stacks_iter_bomb_drops_to_empty_list(self):
        cfg_value = {"settings": {"host_ip": "x"}, "log_sources": [],
                     "groups_order": [], "stacks": IterBombList([{"id": "a"}])}
        body = self._ok_body(cfg_value)
        self.assertEqual(body["stacks"], [])

    def test_groups_order_iter_bomb_drops_to_empty_list(self):
        cfg_value = {"settings": {"host_ip": "x"}, "log_sources": [],
                     "stacks": [], "groups_order": IterBombList(["g"])}
        body = self._ok_body(cfg_value)
        self.assertEqual(body["groups_order"], [])

    def test_nested_value_items_bomb_drops_alone(self):
        """A bomb riding ``ui.locale`` reaches ``_jsonable`` one level in;
        the locale falls back to the default rather than 500ing."""
        body = self._ok_body(_base(ui={"locale": ItemsBomb(), "theme": "nord"}))
        self.assertEqual(body["ui"]["locale"], "zh-CN")
        self.assertEqual(body["ui"]["theme"], "nord")


class ScalarBombPins(_SettingsHttpPin):
    """__bool__ / unhashable scalars already coerced — pinned so they stay."""

    def test_bool_bomb_adaptive_answers_200(self):
        body = self._ok_body(_base(adaptive=BoolBomb()))
        self.assertIn("adaptive", body)

    def test_unhashable_scalars_answer_200(self):
        body = self._ok_body(_base(metrics_interval=Unhashable(),
                                   resource_mode=Unhashable()))
        self.assertEqual(body["metrics_interval"], 90)
        self.assertEqual(body["resource_mode"], "low")


class HealthySiblingsSurvivePins(_SettingsHttpPin):
    """One bombing section must not blank the rest of the render."""

    def test_good_siblings_render_beside_a_bomb_section(self):
        cfg_value = {
            "settings": {
                "host_ip": "9.9.9.9",
                "auth": GetBomb(username="keep"),
                "ui": {"locale": "ja", "theme": "nord"},
                "metrics_interval": 120,
            },
            "stacks": [{"id": "keepstack"}],
            "log_sources": [],
            "groups_order": ["Grp"],
        }
        body = self._ok_body(cfg_value)
        self.assertEqual(body["ui"]["locale"], "ja")
        self.assertEqual(body["ui"]["theme"], "nord")
        self.assertEqual(body["metrics_interval"], 120)
        self.assertEqual(body["stacks"], [{"id": "keepstack"}])
        self.assertEqual(body["groups_order"], ["Grp"])


class JsonableUnitPins(unittest.TestCase):
    """The scrub itself: bombs drop alone, siblings stay encodable."""

    def test_items_bomb_mapping_drops_alone(self):
        out = settings_api._jsonable({"bomb": ItemsBomb(a=1), "ok": 1})
        self.assertEqual(out, {"bomb": None, "ok": 1})
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_iter_bomb_sequence_drops_alone(self):
        out = settings_api._jsonable({"bomb": IterBombList([1]), "ok": 1})
        self.assertEqual(out, {"bomb": None, "ok": 1})
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_as_map_launders_a_get_bomb(self):
        laundered = settings_api._as_map(GetBomb(a=1, b=2))
        self.assertEqual(laundered, {"a": 1, "b": 2})
        self.assertEqual(laundered.get("a"), 1)


class ConfigReaderBombPins(unittest.TestCase):
    """``hub.config``'s cfg()-readers: a dict-subclass bomb at the root or a
    section holder used to raise straight out of the hot helpers, and any
    route that did not happen to wrap the call inherited the 500 (found live
    on GET /api/system/network/alias/auto through ``settings_section``)."""

    def _with_cfg(self, value):
        return mock.patch.object(config, "cfg", return_value=value)

    def test_settings_section_survives_root_and_section_get_bombs(self):
        for value in (GetBomb(settings={}), {"settings": GetBomb()}):
            with self.subTest(value=type(value).__name__), self._with_cfg(value):
                self.assertEqual(config.settings_section("ip_aliases"), {})

    def test_settings_section_launders_the_returned_section(self):
        with self._with_cfg({"settings": {"ip_aliases": GetBomb(ips=["1"])}}):
            section = config.settings_section("ip_aliases")
        self.assertEqual(section.get("ips"), ["1"])

    def test_settings_section_healthy_passthrough(self):
        with self._with_cfg({"settings": {"ui": {"locale": "ja"}}}):
            self.assertEqual(config.settings_section("ui"), {"locale": "ja"})

    def test_override_survives_root_and_section_get_bombs(self):
        for value in (GetBomb(overrides={}), {"overrides": GetBomb()}):
            with self.subTest(value=type(value).__name__), self._with_cfg(value):
                self.assertEqual(config.override("sid"), {})

    def test_override_launders_and_passes_through(self):
        with self._with_cfg({"overrides": {"s1": GetBomb(name="keep")}}):
            self.assertEqual(config.override("s1").get("name"), "keep")

    def test_panel_locale_survives_bombs_and_reads_the_real_locale(self):
        for value in (GetBomb(settings={}), {"settings": GetBomb()}):
            with self.subTest(value=type(value).__name__), self._with_cfg(value):
                self.assertEqual(config.panel_locale(), "zh-CN")
        with self._with_cfg({"settings": {"ui": {"locale": "ja"}}}):
            self.assertEqual(config.panel_locale(), "ja")


class AliasAutoStatusHttpPin(unittest.TestCase):
    """The live HTTP surface where the ``settings_section`` bomb escaped."""

    def test_get_alias_auto_survives_a_cfg_root_get_bomb(self):
        app = create_app()
        app.dependency_overrides[require_auth] = lambda: None
        self.addCleanup(app.dependency_overrides.clear)
        client = TestClient(app, raise_server_exceptions=False)
        with mock.patch.object(config, "cfg",
                               return_value=GetBomb(settings={})):
            resp = client.get("/api/system/network/alias/auto")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        json.dumps(resp.json(), ensure_ascii=False,
                   allow_nan=False).encode("utf-8")


if __name__ == "__main__":
    unittest.main()
