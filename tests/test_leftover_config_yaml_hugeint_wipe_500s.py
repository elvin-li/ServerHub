"""A >4300-digit decimal int in services.yaml wiped the whole config.

PyYAML builds decimal ints with ``int(str)``, so one over-cap scalar raises
*bare ValueError* — not YAMLError — out of ``yaml.safe_load``.  Three live
consequences on the mounted routes:

* ``config.cfg()`` / ``_read_disk()`` answered ``{}`` for the WHOLE file:
  GET /api/settings served factory defaults (admin username gone,
  has_password false, locale reset) while the real config sat on disk.
* Any ``config.mutate()`` — PUT /api/settings, a notify/override/bookmark
  save — merged its patch into that ``{}`` snapshot and *persisted the
  wipe*: the admin account, apps and stacks were rewritten out of
  services.yaml (the JSON-journal "one poisoned entry wipes every sibling"
  bug, in YAML form).
* GET /api/export/services-yaml refused the backup with the coded 500
  ``system_settings.export_failed`` — while the *hex* spelling of the very
  same leftover exported fine (``int(x, 16)`` is uncapped and
  ``_renderable_tree`` drops it at re-dump).

``config.load_yaml_int_capped`` now retries the digit-cap ValueError with a
SafeLoader whose int constructor drops the unrenderable scalar to None (the
``docker_cli.parse_int_capped`` drop), so siblings survive.  Genuinely
unparseable documents (``!!timestamp .inf``, ``2026-13-01``, ``!!bool 2``,
12k-deep nests) keep their corrupt-document ``{}`` fallback.

The JSON side of the same contract (``json.loads`` of a huge literal is
ValueError, not JSONDecodeError; ``parse_int_capped`` keeps journal
siblings) was found immune and is pinned here so a stdlib change cannot
silently reopen it.
"""
from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml
from fastapi import FastAPI

from hub import config
from hub.docker_cli import parse_int_capped
from hub.routers import settings_api
from hub.util import safe_json_loads

#: 5000 decimal digits — past CPython's default 4300-digit int(str) cap.
_HUGE_DIGITS = "9" * 5000

#: A real config an operator would mind losing, with the poison in a value
#: position (the YAML scanner caps implicit block *keys* at 1024 chars;
#: values are unbounded).
POISONED_YAML = (
    "settings:\n"
    "  host_ip: 10.0.0.9\n"
    "  adaptive: true\n"
    "  auth:\n"
    "    enabled: true\n"
    "    username: keep-admin\n"
    "    password_hash: pbkdf2-keep-hash\n"
    "  ui: {locale: ja}\n"
    "  port: " + _HUGE_DIGITS + "\n"
    "apps:\n"
    "  - {id: keep-app, name: Keep App}\n"
    "stacks:\n"
    "  - {id: keep-stack}\n"
)


async def _asgi_request(method, path, *, body=None):
    """Drive hub/routers/settings_api.py through a real ASGI cycle."""
    app = FastAPI()
    app.include_router(settings_api.router)
    payload = b"" if body is None else json.dumps(body).encode("utf-8")
    sent = False
    messages: list[dict] = []

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": payload, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1", "method": method, "scheme": "http",
        "path": path, "raw_path": path.encode(),
        "query_string": b"", "root_path": "",
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
        ],
        "server": ("localhost", 8086), "client": ("127.0.0.1", 1), "state": {},
    }
    await app(scope, receive, send)
    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    raw = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    headers = dict(next(
        m for m in messages if m["type"] == "http.response.start"
    ).get("headers") or [])
    # The body must already be valid UTF-8 — decode strictly on purpose.
    text = raw.decode("utf-8")
    ctype = headers.get(b"content-type", b"").decode("latin-1")
    parsed = json.loads(text) if "json" in ctype and text else None
    return status, parsed, text


def request(method, path, *, body=None):
    return asyncio.run(_asgi_request(method, path, body=body))


class CappedYamlLoaderUnitTests(unittest.TestCase):
    """load_yaml_int_capped: only the digit-cap scalar degrades, to None."""

    def test_value_key_and_list_positions_drop_only_the_scalar(self):
        doc = config.load_yaml_int_capped(
            "keep: yes\n"
            "big: " + _HUGE_DIGITS + "\n"
            "rows:\n"
            "  - 7\n"
            "  - " + _HUGE_DIGITS + "\n"
            "? " + _HUGE_DIGITS + "\n"
            ": from-huge-key\n"
        )
        self.assertIs(doc["keep"], True)
        self.assertIsNone(doc["big"])
        self.assertEqual(doc["rows"], [7, None])
        # the over-cap mapping key collapses to the None key
        self.assertEqual(doc[None], "from-huge-key")

    def test_hex_spelling_still_loads_as_a_real_int(self):
        """``int(x, 16)`` is exempt from the cap — that path must not change:
        the dump-side ``_renderable_tree`` drop is what handles it."""
        doc = config.load_yaml_int_capped("v: 0x" + "F" * 4400 + "\n")
        self.assertIsInstance(doc["v"], int)
        with self.assertRaises(ValueError):
            str(doc["v"])

    def test_other_corruption_keeps_the_corrupt_document_fallback(self):
        for text in (
            "when: 2026-13-01\n",            # date ValueError, not digit cap
            "when: !!timestamp .inf\n",       # AttributeError
            "flag: !!bool 2\n",               # KeyError
        ):
            with self.subTest(text=text):
                with self.assertRaises((ValueError, AttributeError, KeyError)):
                    config.load_yaml_int_capped(text)


class ConfigWipeOnDiskTests(unittest.TestCase):
    """mutate() on the poisoned file must not rewrite siblings away."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.yaml = self.dir / "services.yaml"
        for target, value in (
            ("YAML_PATH", self.yaml),
            ("DATA_DIR", self.dir),
            ("_LOCK_PATH", self.dir / ".services.yaml.lock"),
            ("_cfg", {"mtime": None, "data": {}}),
        ):
            patched = mock.patch.object(config, target, value)
            patched.start()
            self.addCleanup(patched.stop)
        self.addCleanup(config.reload_cfg)
        self.yaml.write_text(POISONED_YAML)

    def test_cfg_serves_siblings_not_an_empty_mapping(self):
        data = config.cfg()
        self.assertEqual(data["settings"]["auth"]["username"], "keep-admin")
        self.assertEqual([a["id"] for a in data["apps"]], ["keep-app"])
        self.assertIsNone(data["settings"]["port"])

    def test_update_settings_does_not_wipe_the_admin_account(self):
        """update_settings → mutate → _read_disk: the {} snapshot used to be
        written back, deleting auth/apps/stacks from services.yaml."""
        config.update_settings({"host_ip": "10.9.9.9"})
        raw = self.yaml.read_text(encoding="utf-8")
        self.assertIn("keep-admin", raw)
        self.assertIn("pbkdf2-keep-hash", raw)
        self.assertIn("keep-app", raw)
        self.assertIn("keep-stack", raw)
        self.assertIn("10.9.9.9", raw)
        self.assertNotIn(_HUGE_DIGITS, raw)
        # the rewritten file parses clean — the poison is gone for good
        reloaded = yaml.safe_load(raw)
        self.assertEqual(reloaded["settings"]["auth"]["username"], "keep-admin")
        self.assertIsNone(reloaded["settings"]["port"])


class SettingsRoutesPoisonedConfigPins(unittest.TestCase):
    """The mounted routes, over a real ASGI cycle, with the poison on disk."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.yaml = self.dir / "services.yaml"
        for target, value in (
            ("YAML_PATH", self.yaml),
            ("DATA_DIR", self.dir),
            ("_LOCK_PATH", self.dir / ".services.yaml.lock"),
            ("_cfg", {"mtime": None, "data": {}}),
        ):
            patched = mock.patch.object(config, target, value)
            patched.start()
            self.addCleanup(patched.stop)
        # the export route resolves the file through hub.paths.CONFIG_FILE
        patched = mock.patch("hub.paths.CONFIG_FILE", self.yaml)
        patched.start()
        self.addCleanup(patched.stop)
        self.addCleanup(config.reload_cfg)
        self.yaml.write_text(POISONED_YAML)

    def test_get_settings_serves_the_real_config_not_defaults(self):
        status, body, _ = request("GET", "/api/settings")
        self.assertEqual(status, 200)
        # pre-fix these read "admin" / False / "zh-CN": the factory defaults
        # of an empty config, served while the real one sat on disk
        self.assertEqual(body["auth"]["username"], "keep-admin")
        self.assertIs(body["auth"]["has_password"], True)
        self.assertEqual(body["ui"]["locale"], "ja")

    def test_put_settings_is_200_and_keeps_every_sibling_on_disk(self):
        with mock.patch.object(settings_api.audit, "record", lambda *a, **k: {}):
            status, _, _ = request("PUT", "/api/settings", body={"adaptive": False})
        self.assertEqual(status, 200)
        raw = self.yaml.read_text(encoding="utf-8")
        self.assertIn("keep-admin", raw)
        self.assertIn("keep-app", raw)
        self.assertIn("keep-stack", raw)
        self.assertNotIn(_HUGE_DIGITS, raw)
        self.assertIs(config.cfg()["settings"]["adaptive"], False)

    def test_export_is_200_with_the_poison_dropped_and_secrets_redacted(self):
        """The decimal spelling used to be the coded 500
        system_settings.export_failed; hex already exported fine."""
        status, _, text = request("GET", "/api/export/services-yaml")
        self.assertEqual(status, 200)
        self.assertIn("keep-admin", text)
        self.assertIn("***redacted***", text)
        self.assertNotIn("pbkdf2-keep-hash", text)
        self.assertNotIn(_HUGE_DIGITS, text)
        # the download itself must round-trip as YAML
        parsed = yaml.safe_load(text)
        self.assertEqual(parsed["settings"]["auth"]["username"], "keep-admin")


class JsonJournalContractStaysImmunePins(unittest.TestCase):
    """The JSON side was found immune — pin the stdlib contract it rests on."""

    def test_huge_json_literal_is_valueerror_not_jsondecodeerror(self):
        """Callers that catch only JSONDecodeError would 500; every hub
        journal read catches ValueError.  Pin the exception type so a
        CPython change cannot silently reclassify it."""
        with self.assertRaises(ValueError) as ctx:
            json.loads('{"n": ' + _HUGE_DIGITS + "}")
        self.assertNotIsInstance(ctx.exception, json.JSONDecodeError)

    def test_parse_int_capped_keeps_journal_siblings(self):
        self.assertIsNone(parse_int_capped(_HUGE_DIGITS))
        doc = safe_json_loads(
            '{"big": ' + _HUGE_DIGITS + ', "keep": 2}',
            parse_int=parse_int_capped,
        )
        self.assertEqual(doc, {"big": None, "keep": 2})

    def test_over_cap_int_cannot_be_dumped_either(self):
        """The str() probe rationale: no encoder can render it, so drop-to-
        None is the only shape that keeps the document."""
        with self.assertRaises(ValueError):
            json.dumps(10 ** 5000)


if __name__ == "__main__":
    unittest.main()
