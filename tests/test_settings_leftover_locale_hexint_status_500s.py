"""Leftover over-cap ``settings.ui.locale`` vs GET /api/status.

YAML hex (``locale: 0xF…``) loads through ``int(x, 16)``, which CPython's
4300-digit str<->int cap does not bound, so a hand-edited over-cap locale
parsed fine and then the bare ``str()`` inside ``config.panel_locale()``
raised ValueError.  Every read sanitizer downstream (status._jsonable,
settings _text) already dropped the value at the edge — but panel_locale
runs *before* any of them:

* GET /api/status 500'd forever on a cold cache: ``_build_status`` raised at
  the ``"locale"`` field, and on first boot there is no last-good snapshot
  for ``full_status`` to fall back to, so the dashboard, the sidebar and the
  menu-bar client all got 500 until services.yaml was hand-edited;
* member GET /api/status and the member services filter raised the same way
  inside ``filter_status_for_resources`` whenever the snapshot carried no
  ``locale`` of its own.

Fixed with a guarded ``str()`` in ``panel_locale`` (a str() probe, NOT an
``isinstance(x, str)`` gate: a hand-edited numeric ``locale: 2023`` must
still coerce and fall through to the default rather than raise).

Also pinned (stays-immune classes, against the real app):

* GET /api/settings answers 200 with the locale defaulted, not the poison;
* PUT /api/settings (theme) still unsticks and persists — the _dump retry
  drops only the unrenderable locale node;
* a lone-surrogate locale never raises and never leaks out of the
  whitelist.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import yaml
from fastapi.testclient import TestClient

from hub import auth, config, status
from hub.app_factory import create_app

PASSWORD = "correct-horse-battery"
#: What a leftover ``0xF…`` (5000 hex digits) in services.yaml loads as.
HUGE_HEX = "0x" + "F" * 5000
HUGE_INT = int("F" * 5000, 16)

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
    return _APP


def _poisoned_yaml(password_hash: str) -> str:
    """A claimed config whose ui.locale is an already-parsed over-cap int."""
    return (
        "settings:\n"
        "  auth:\n"
        "    enabled: true\n"
        "    username: admin\n"
        f'    password_hash: "{password_hash}"\n'
        "  ui:\n"
        f"    locale: {HUGE_HEX}\n"
        "    theme: omv\n"
    )


class PanelLocaleScrubUnitTests(unittest.TestCase):
    """panel_locale() must probe with str(), never raise the digit cap."""

    def _with_locale(self, value):
        with mock.patch.object(
            config, "cfg", return_value={"settings": {"ui": {"locale": value}}}
        ):
            return config.panel_locale()

    def test_overcap_hex_locale_defaults_instead_of_valueerror(self):
        """The bare str() used to raise CPython's 4300-digit ValueError."""
        self.assertEqual(self._with_locale(HUGE_INT), config.DEFAULT_UI_LOCALE)

    def test_numeric_locale_still_coerces_via_str_probe(self):
        """A str() probe, not isinstance: ``locale: 2023`` must not raise."""
        self.assertEqual(self._with_locale(2023), config.DEFAULT_UI_LOCALE)

    def test_surrogate_locale_never_leaks_out_of_the_whitelist(self):
        out = self._with_locale("\ud800zh")
        self.assertIn(out, config.UI_LOCALES)
        json.dumps(out, ensure_ascii=False).encode("utf-8")

    def test_normal_locales_untouched(self):
        self.assertEqual(self._with_locale("ja"), "ja")
        self.assertEqual(self._with_locale("zh-Hans-CN"), "zh-CN")
        self.assertEqual(self._with_locale(None), config.DEFAULT_UI_LOCALE)


class MemberFilterLocaleTests(unittest.TestCase):
    """filter_status_for_resources falls back to panel_locale() when the
    snapshot has none; the poisoned locale used to 500 the member routes."""

    def test_member_filter_survives_overcap_locale(self):
        with mock.patch.object(
            config, "cfg",
            return_value={"settings": {"ui": {"locale": HUGE_INT}}},
        ):
            out = status.filter_status_for_resources(
                {"groups": [], "counts": {}}, []
            )
        self.assertEqual(out["locale"], config.DEFAULT_UI_LOCALE)
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _AppSandbox(unittest.TestCase):
    """Scratch services.yaml + data dir; a fresh authenticated client per test."""

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        data = self.root / "data"
        data.mkdir()
        self.yaml_path = self.root / "services.yaml"
        for target, attr, value in (
            (config, "YAML_PATH", self.yaml_path),
            (config, "DATA_DIR", data),
            (config, "BASE", self.root),
            (config, "_LOCK_PATH", data / ".services.yaml.lock"),
            (auth, "SECRET_FILE", data / ".session-secret"),
            (auth, "SETUP_TOKEN_FILE", data / ".setup-token"),
            (auth, "LOCAL_TOKEN_FILE", data / ".local-client-token"),
        ):
            patcher = mock.patch.object(target, attr, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(config.reload_cfg)
        auth._secret_cache = None
        auth._login_attempts.clear()
        self.yaml_path.write_text(_poisoned_yaml(auth.hash_password(PASSWORD)))
        config.reload_cfg()
        self.client = TestClient(app(), raise_server_exceptions=False)
        response = self.client.post(
            "/api/auth/login", json={"username": "admin", "password": PASSWORD}
        )
        assert response.status_code == 200, response.text

    def stored(self) -> dict:
        return yaml.safe_load(self.yaml_path.read_text())


class ColdCacheStatusTests(_AppSandbox):
    def test_get_status_is_200_on_a_cold_cache(self):
        """First boot has no last-good snapshot: _build_status raised at the
        ``locale`` field and every GET /api/status answered 500 forever."""
        saved = dict(status._status_cache)
        status._status_cache.clear()
        status._status_cache.update(t=0.0, v=None)

        def restore():
            status._status_cache.clear()
            status._status_cache.update(saved)

        self.addCleanup(restore)
        response = self.client.get("/api/status")
        self.assertEqual(response.status_code, 200, response.text[:200])
        body = response.json()
        json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertEqual(body["locale"], config.DEFAULT_UI_LOCALE)


class StaysImmuneSettingsTests(_AppSandbox):
    """The poisoned locale never 500s the Settings page reads or writes."""

    def test_get_settings_defaults_the_locale(self):
        response = self.client.get("/api/settings")
        self.assertEqual(response.status_code, 200, response.text[:200])
        body = response.json()
        json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertEqual(body["ui"]["locale"], "zh-CN")
        self.assertEqual(body["ui"]["theme"], "omv")

    def test_put_settings_theme_unsticks_and_persists(self):
        """The _dump retry drops only the unrenderable locale node; the
        theme change must land and every sibling key must survive."""
        response = self.client.put("/api/settings", json={"ui": {"theme": "nord"}})
        self.assertEqual(response.status_code, 200, response.text[:200])
        self.assertEqual(response.json()["settings"]["ui"]["theme"], "nord")
        on_disk = self.stored()
        self.assertEqual(on_disk["settings"]["ui"]["theme"], "nord")
        self.assertNotIn("locale", on_disk["settings"]["ui"])
        self.assertEqual(on_disk["settings"]["auth"]["username"], "admin")

    def test_put_settings_locale_replaces_the_poison(self):
        response = self.client.put("/api/settings", json={"ui": {"locale": "ja"}})
        self.assertEqual(response.status_code, 200, response.text[:200])
        self.assertEqual(self.stored()["settings"]["ui"]["locale"], "ja")
        self.assertEqual(config.panel_locale(), "ja")


if __name__ == "__main__":
    unittest.main()
