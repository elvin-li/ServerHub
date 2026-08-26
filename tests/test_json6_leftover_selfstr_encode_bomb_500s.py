"""JSON sweep #6: self-``__str__`` encode bombs past the json5/settings8 seals.

json5 laundered the settings sections through ``dict(...)`` and settings8
added the unbound base coercions (``int.__index__`` / ``float.__float__`` /
``bytes(...)``) — but both left the *final* step of the shared text
sanitizers bound: ``_utf8_text`` did ``str(value)`` and then
``text.encode("utf-8", "replace")``.  ``str(x)`` of a str subclass with the
default ``__str__`` launders to an exact str, so the settings8 bombs never
reached the encode — but a subclass whose ``__str__`` returns *itself* (the
jobs6 class, sealed in the jobs/terminal sanitizers with unbound
``str.encode``) keeps the subclass, and the bound ``.encode`` dispatched
into the leftover override.

Driven over the real mounted app (``create_app()`` + TestClient with
``raise_server_exceptions=False``), each of these turned a settings read
into a raw 500 before the fix:

* a stack ``name`` riding GET /api/settings through ``_jsonable`` →
  ``settings_api._utf8_text``;
* a stored ``resource_mode`` riding GET /api/settings/other through
  ``system_settings_svc._as_text`` → ``_utf8_text``;
* a thresholds mapping *key* riding GET /api/settings/thresholds through
  ``get_thresholds``'s key scrub.

``hub.config.panel_locale`` carried the same class one layer down: its
catch was ValueError-only (the digit-cap probe), so a leftover ``__bool__``
bomb in ``ui.locale`` raised out of the ``_locale_raw or …`` read, a
non-ValueError ``__str__`` bomb raised out of the coercion, and a
self-``__str__`` subclass kept its overridden ``.strip()`` / ``in`` /
``.lower()`` in play — each escaping the menu-bar locale probe that
GET /api/status reads on a cold cache.

The fix is the established convention: unbound ``str.encode(text, …)`` in
both ``_utf8_text`` helpers, and in ``panel_locale`` a generic catch plus an
exact-str launder (``str.__str__``) before the bound string ops.  The pass
is the coded 200 with the stored value *recovered* — the subclass carries
real text, so laundering keeps the data and only defuses the methods.
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


class SelfStr(str):
    """``str(x)`` keeps the subclass (``__str__`` returns self); the bound
    ``.encode`` then dispatches into the bomb."""

    def __str__(self):
        return self

    def encode(self, *a, **k):
        raise RuntimeError("encode bomb")


class SelfStrStrip(SelfStr):
    """Same, with the bound ``.strip()`` bombing too (panel_locale's ops)."""

    def strip(self, *a, **k):
        raise RuntimeError("strip bomb")


class BoolBomb:
    def __bool__(self):
        raise RuntimeError("bool bomb")


class StrBomb:
    """A non-ValueError ``__str__`` bomb — past panel_locale's old catch."""

    def __str__(self):
        raise RuntimeError("str bomb")


def _base(**settings_extra) -> dict:
    return {
        "settings": {"host_ip": "10.0.0.9", **settings_extra},
        "stacks": [],
        "log_sources": [],
        "groups_order": [],
    }


class _SettingsHttpPin(unittest.TestCase):
    """Drives the real mounted routes with a poisoned cfg() snapshot."""

    def _client(self) -> TestClient:
        app = create_app()
        app.dependency_overrides[require_auth] = lambda: None
        self.addCleanup(app.dependency_overrides.clear)
        return TestClient(app, raise_server_exceptions=False)

    def _ok_body(self, path: str, cfg_value) -> dict:
        client = self._client()
        # cfg was imported by name into each consumer, so every seam the
        # route reads through gets the same poisoned snapshot.
        with (
            mock.patch.object(config, "cfg", return_value=cfg_value),
            mock.patch.object(system_settings_svc, "cfg", return_value=cfg_value),
            mock.patch.object(settings_api, "cfg", return_value=cfg_value),
        ):
            resp = client.get(path)
        self.assertEqual(resp.status_code, 200, resp.text[:400])
        body = resp.json()
        # The body Starlette encoded must be re-encodable under the same
        # allow_nan=False / UTF-8 contract it used.
        json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        return body


class PublicSettingsEncodeBombPins(_SettingsHttpPin):
    """GET /api/settings: the bomb rode ``_jsonable`` → ``_utf8_text``."""

    def test_stack_name_self_str_encode_bomb_answers_200(self):
        snap = {
            "settings": {"host_ip": "10.0.0.9"},
            "stacks": [{"name": SelfStr("keep-stack")}],
            "log_sources": [],
            "groups_order": [],
        }
        body = self._ok_body("/api/settings", snap)
        # The subclass carries real text; the unbound encode keeps it.
        self.assertEqual(body["stacks"], [{"name": "keep-stack"}])

    def test_scalar_setting_self_str_encode_bomb_answers_200(self):
        body = self._ok_body("/api/settings", _base(
            resource_mode=SelfStr("high"),
            ui={"locale": SelfStr("ja"), "theme": "nord"},
        ))
        self.assertEqual(body["resource_mode"], "high")
        self.assertEqual(body["ui"]["locale"], "ja")
        self.assertEqual(body["ui"]["theme"], "nord")


class OtherAndThresholdsEncodeBombPins(_SettingsHttpPin):
    """The sibling routes through ``system_settings_svc._utf8_text``."""

    def test_other_resource_mode_self_str_encode_bomb_answers_200(self):
        body = self._ok_body("/api/settings/other", _base(resource_mode=SelfStr("high")))
        self.assertEqual(body["resource_mode"], "high")

    def test_other_alias_ip_self_str_encode_bomb_answers_200(self):
        body = self._ok_body("/api/settings/other", _base(
            ip_aliases={"ips": [SelfStr("10.0.0.5")], "netmask": "255.255.255.0"},
        ))
        self.assertEqual(body["ip_aliases"]["ips"], ["10.0.0.5"])
        self.assertEqual(body["ip_aliases"]["netmask"], "255.255.255.0")

    def test_thresholds_key_self_str_encode_bomb_answers_200(self):
        body = self._ok_body("/api/settings/thresholds", _base(
            thresholds={SelfStr("cpu_pct"): 91, "disk_pct": 85},
        ))
        # The bombing key is laundered, not dropped: the value lands.
        self.assertEqual(body["cpu_pct"], 91)
        self.assertEqual(body["disk_pct"], 85)


class UtfTextUnitPins(unittest.TestCase):
    """The sanitizers themselves: bombs launder, healthy text is untouched."""

    HELPERS = (settings_api._utf8_text, system_settings_svc._utf8_text)

    def test_self_str_encode_bomb_launders_to_exact_str(self):
        for fn in self.HELPERS:
            with self.subTest(helper=fn.__module__):
                out = fn(SelfStr("keep"))
                self.assertEqual(out, "keep")
                self.assertIs(type(out), str)

    def test_surrogates_still_scrubbed(self):
        for fn in self.HELPERS:
            with self.subTest(helper=fn.__module__):
                out = fn("a\ud800b")
                # encode-side "replace" substitutes "?": the lone surrogate
                # is gone and the result is strictly UTF-8 encodable.
                self.assertEqual(out, "a?b")
                out.encode("utf-8")


class PanelLocaleBombPins(unittest.TestCase):
    """panel_locale: every leftover shape degrades to a locale, never raises."""

    def _locale_for(self, leftover) -> str:
        snap = {"settings": {"ui": {"locale": leftover}}}
        with mock.patch.object(config, "cfg", return_value=snap):
            return config.panel_locale()

    def test_bool_bomb_defaults(self):
        # The old ``_locale_raw or …`` reflected into the bomb's __bool__.
        self.assertEqual(self._locale_for(BoolBomb()), "zh-CN")

    def test_non_valueerror_str_bomb_defaults(self):
        # The old catch was ValueError-only (the digit-cap probe).
        self.assertEqual(self._locale_for(StrBomb()), "zh-CN")

    def test_self_str_subclass_keeps_its_real_locale(self):
        # Laundered to an exact str, the carried text still answers.
        self.assertEqual(self._locale_for(SelfStr("ja")), "ja")
        self.assertEqual(self._locale_for(SelfStrStrip("ja")), "ja")

    def test_over_cap_hex_int_still_defaults(self):
        # The digit-cap leftover the old catch was written for must keep
        # its answer: str() of an over-cap int is ValueError.
        self.assertEqual(self._locale_for(1 << 20000), "zh-CN")

    def test_numeric_and_falsy_locales_keep_their_defaults(self):
        for leftover in (2023, 0, "", False, None):
            with self.subTest(leftover=repr(leftover)):
                self.assertEqual(self._locale_for(leftover), "zh-CN")

    def test_healthy_locales_untouched(self):
        for stored, want in (("ja", "ja"), ("en-US", "en"), ("zh-Hans", "zh-CN")):
            with self.subTest(stored=stored):
                self.assertEqual(self._locale_for(stored), want)


if __name__ == "__main__":
    unittest.main()
