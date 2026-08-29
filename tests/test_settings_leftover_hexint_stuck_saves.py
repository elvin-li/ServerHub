"""Leftover over-cap ints outside the auth block vs every settings save.

YAML hex (``0x…``) loads through ``int(x, 16)``, which CPython's 4300-digit
str<->int cap does not bound, so a leftover huge int *anywhere* in
services.yaml (a stray hand-edited settings key, an explicit ``? 0x…``
mapping key, a stack port) parsed fine and then ValueError'd
``yaml.safe_dump`` inside every ``config.mutate()``.  ``config._dump``
degraded that to a coded 503 — which meant the whole write side of the
Settings page was permanently stuck until services.yaml was hand-edited:

* PUT /api/settings (theme, locale, thresholds, host_ip, notify, aliases)
  always answered 503 while GET /api/settings kept answering 200, so the
  page looked healthy and every save silently went nowhere;
* PUT /api/identity (comment / host_ip) 503'd the same way;
* GET /api/export/services-yaml refused the backup outright even though the
  parse and the secret redaction had both already succeeded.

The auth sweep un-stuck only its own writes by scrubbing ``settings.auth``
before saving; a leftover *outside* that block rode through untouched.

Fixed with a ``str()``-probe scrub (NOT an ``isinstance(x, str)`` gate — the
poison is an already-parsed int, and numeric YAML ids must survive as ints):
``_dump`` retries once with only the unrenderable nodes dropped, and the
export streams the rest of the backup with the same node dropped.

Also pinned (stays-immune classes, against the real app):

* a >4300-digit number literal in a PUT /api/settings body is 400, not 500
  (``json.loads`` raises plain ValueError there, not JSONDecodeError);
* lone-surrogate leftovers in settings keys AND values (the YAML
  ``"\\uD800"`` escape loads back into a real surrogate) never 500 the
  GET/PUT round trip, and a surrogate PUT through the API round-trips the
  save without wedging it;
* the poisoned config never 500s the Settings-page reads
  (/api/settings, /api/settings/system, /api/settings/thresholds,
  /api/settings/other, /api/diagnostics).
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import yaml
from fastapi.testclient import TestClient

from hub import auth, config, system_settings_svc
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
    """A claimed config carrying over-cap ints outside the auth block:
    a stray settings value, an explicit mapping key, and a stack port."""
    return (
        "settings:\n"
        "  auth:\n"
        "    enabled: true\n"
        "    username: admin\n"
        f'    password_hash: "{password_hash}"\n'
        f"  legacy_junk: {HUGE_HEX}\n"
        "  thresholds:\n"
        "    cpu_pct: 90\n"
        f"    stray: {HUGE_HEX}\n"
        f"  ? {HUGE_HEX}\n"
        "  : keyed\n"
        '  note: "\\uD800"\n'
        '  "\\uDFFF": junk-key\n'
        "stacks:\n"
        "  - id: s1\n"
        "    name: media\n"
        f"    port: {HUGE_HEX}\n"
    )


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
        system_settings_svc.unraid_settings_bundle.invalidate()
        self.addCleanup(system_settings_svc.unraid_settings_bundle.invalidate)
        self.yaml_path.write_text(_poisoned_yaml(auth.hash_password(PASSWORD)))
        config.reload_cfg()
        self.client = TestClient(app(), raise_server_exceptions=False)
        response = self.client.post(
            "/api/auth/login", json={"username": "admin", "password": PASSWORD}
        )
        assert response.status_code == 200, response.text

    def stored(self) -> dict:
        return yaml.safe_load(self.yaml_path.read_text())


class HugeLeftoverStuckSaveTests(_AppSandbox):
    def test_put_settings_theme_unsticks_despite_huge_leftovers(self):
        """PUT /api/settings answered 503 forever while GET stayed 200: the
        theme/locale change was silently lost until services.yaml was fixed
        by hand."""
        response = self.client.put("/api/settings", json={"ui": {"theme": "nord"}})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["settings"]["ui"]["theme"], "nord")
        on_disk = self.stored()
        self.assertEqual(on_disk["settings"]["ui"]["theme"], "nord")
        # Only the unrenderable nodes were dropped; siblings survive.
        self.assertEqual(on_disk["settings"]["thresholds"]["cpu_pct"], 90)
        self.assertNotIn("legacy_junk", on_disk["settings"])
        self.assertNotIn("stray", on_disk["settings"]["thresholds"])
        self.assertNotIn(HUGE_INT, on_disk["settings"])
        self.assertEqual(on_disk["stacks"][0]["id"], "s1")
        self.assertEqual(on_disk["stacks"][0]["name"], "media")
        self.assertNotIn("port", on_disk["stacks"][0])

    def test_put_settings_thresholds_unsticks_and_persists(self):
        response = self.client.put(
            "/api/settings", json={"thresholds": {"cpu_pct": 85}}
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.stored()["settings"]["thresholds"]["cpu_pct"], 85)

    def test_put_identity_comment_unsticks(self):
        """PUT /api/identity rode the same mutate() and 503'd the same way."""
        response = self.client.put("/api/identity", json={"comment": "rack 2"})
        self.assertEqual(response.status_code, 200, response.text)

    def test_export_streams_backup_with_only_the_poison_dropped(self):
        """GET /api/export/services-yaml refused the whole backup for one
        unrenderable leftover after parse and redaction had both succeeded."""
        import hub.paths as paths

        with mock.patch.object(paths, "CONFIG_FILE", self.yaml_path):
            response = self.client.get("/api/export/services-yaml")
        self.assertEqual(response.status_code, 200, response.text)
        exported = yaml.safe_load(response.text)
        self.assertNotIn("legacy_junk", exported["settings"])
        self.assertEqual(exported["settings"]["thresholds"]["cpu_pct"], 90)
        self.assertEqual(exported["stacks"][0]["id"], "s1")
        # Redaction still applies on the surviving nodes.
        self.assertEqual(
            exported["settings"]["auth"]["password_hash"], "***redacted***"
        )


class RenderableScrubUnitTests(unittest.TestCase):
    def test_dump_retry_drops_only_unrenderable_nodes(self):
        text = config._dump({
            "settings": {
                "keep": 1,
                "legacy": HUGE_INT,
                HUGE_INT: "keyed",
                "tags": {"a", HUGE_INT},
                "rows": [1, HUGE_INT, "x"],
            },
        })
        data = yaml.safe_load(text)
        self.assertEqual(data["settings"]["keep"], 1)
        self.assertNotIn("legacy", data["settings"])
        self.assertNotIn(HUGE_INT, data["settings"])
        self.assertEqual(sorted(data["settings"]["tags"]), ["a"])
        self.assertEqual(data["settings"]["rows"], [1, "x"])

    def test_scrub_uses_str_probe_not_isinstance_gates(self):
        """Numeric YAML ids must survive as ints; only over-cap ints drop."""
        tree = config._renderable_tree({
            "id": 123,
            "flag": True,
            "name": "adm\ud800in",
            "port": HUGE_INT,
        })
        self.assertEqual(tree["id"], 123)
        self.assertIsInstance(tree["id"], int)
        self.assertIs(tree["flag"], True)
        self.assertEqual(tree["name"], "adm\ud800in")
        self.assertNotIn("port", tree)

    def test_clean_config_is_unchanged(self):
        data = {"settings": {"a": 1, "ui": {"theme": "nord"}}, "stacks": []}
        self.assertEqual(yaml.safe_load(config._dump(data)), data)


class StaysImmuneSettingsReadTests(_AppSandbox):
    """The poisoned config never 500s the Settings-page reads."""

    def _get_json(self, path: str) -> dict:
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200, f"{path}: {response.text[:200]}")
        body = response.json()
        # Starlette's exact encode: ensure_ascii=False then UTF-8.
        json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        return body

    def test_settings_reads_stay_200_and_encodable(self):
        for path in (
            "/api/settings",
            "/api/settings/system",
            "/api/settings/thresholds",
            "/api/settings/other",
            "/api/diagnostics",
        ):
            with self.subTest(path=path):
                self._get_json(path)

    def test_get_settings_scrubs_the_poison(self):
        body = self._get_json("/api/settings")
        self.assertEqual(body["thresholds"]["cpu_pct"], 90)
        dumped = json.dumps(body, ensure_ascii=False)
        self.assertNotIn("\ud800", dumped)
        self.assertNotIn("F" * 100, dumped)


class StaysImmuneSettingsWriteBodyTests(_AppSandbox):
    def test_huge_number_literal_in_put_body_is_400_not_500(self):
        """``json.loads`` of a >4300-digit literal raises plain ValueError,
        not JSONDecodeError; the body parse must still answer 400."""
        response = self.client.put(
            "/api/settings",
            content='{"metrics_interval": ' + "9" * 4400 + "}",
            headers={"content-type": "application/json"},
        )
        self.assertEqual(response.status_code, 400)

    def test_surrogate_host_ip_put_round_trips_without_wedging(self):
        """The YAML ``"\\uD800"`` escape survives the dump/load round trip;
        the PUT must save and every later read must stay UTF-8-encodable."""
        response = self.client.put(
            "/api/settings",
            content='{"host_ip": "\\ud800nas"}',
            headers={"content-type": "application/json"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertNotIn("\ud800", json.dumps(body, ensure_ascii=False))
        # The stored value keeps the surrogate (reads scrub at the edge).
        self.assertEqual(self.stored()["settings"]["host_ip"], "\ud800nas")
        follow_up = self.client.get("/api/settings")
        self.assertEqual(follow_up.status_code, 200)
        json.dumps(
            follow_up.json(), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")


if __name__ == "__main__":
    unittest.main()
