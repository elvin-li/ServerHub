"""An unreadable-but-present services.yaml let every mutation persist a wipe.

The JSON3 sweep fixed the >4300-digit decimal int (``load_yaml_int_capped``
drops the one scalar, siblings survive) and the notify sweep capped what the
panel itself will *write* (``_save_full_locked`` refuses a dump larger than
its own 1MB read cap).  What was still live is the read side of
:func:`hub.config.mutate`: a services.yaml that got into an unusable state by
another road answered every mutating route with **HTTP 200 while rewriting
the file from the ``{}`` corrupt-document fallback** — the admin account,
apps, stacks and bookmarks all replaced by the patch alone.

Reproduced over the real mounted app (``create_app()``, TestClient with
``raise_server_exceptions=False``) before the fix, each of these on-disk
states turned PUT /api/settings, POST /api/alerts/channels and
PUT /api/services/group-rules into a silent full wipe:

* **oversize but perfectly valid YAML** (grown past the 1MB cap by a hand
  edit or a restored ``services.yaml.bak.*``): ``read_text_capped`` raises
  EFBIG, ``_read_disk`` answered ``{}`` — and because the pre-save backup
  copy is capped too (its OSError deliberately swallowed), this wipe left
  **no pre-image at all** to recover from;
* **torn non-UTF-8 bytes** after power loss (UnicodeDecodeError, which is a
  ValueError, not an OSError);
* **scanner-corrupt text** (an unclosed flow list);
* **an over-deep nest** (RecursionError, which is not YAMLError);
* **a whole-document paste** that parses to a list rather than a mapping.

``mutate()`` now reads through ``_read_disk_for_mutate``, which refuses those
states with the coded 503 ``settings.config_unreadable`` and leaves the file
byte-identical, while keeping every flow that must write:

* a *missing* file (first-run setup) still creates the config;
* an empty / comments-only file still accepts the save;
* the JSON3 contract stays: a >4300-digit decimal poison parses through the
  capped loader, the save lands, and every sibling survives on disk;
* a leftover empty directory squatting services.yaml still saves (it holds
  no YAML to lose; ``_save_full_locked`` clears it) — the pre-existing
  leniency this sweep must not regress.

Reads are deliberately untouched: ``cfg()`` / ``_read_disk`` keep their
``{}`` fallback so GET routes render defaults instead of 500ing.
"""
from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi import HTTPException
from fastapi.testclient import TestClient

from hub import config
from hub.app_factory import create_app
from hub.auth import require_auth

#: 5000 decimal digits — past CPython's default 4300-digit int(str) cap.
_HUGE_DEC = "9" * 5000

#: A populated config an operator would mind losing.
POPULATED = """\
settings:
  host_ip: 10.0.0.9
  adaptive: true
  auth:
    enabled: true
    username: keep-admin
    password_hash: pbkdf2-keep-hash
  ui: {locale: ja}
apps:
  - {id: keep-app, name: Keep App}
stacks:
  - {id: keep-stack}
quick_links:
  - {name: keep-link, url: "http://x", port: 8080}
"""

#: Valid YAML, just larger than config._YAML_CAP: read_text_capped EFBIG.
OVERSIZE_VALID = POPULATED + 'pad_key: "' + "x" * (config._YAML_CAP + 4096) + '"\n'

#: Torn write: bytes no UTF-8 decode accepts (UnicodeDecodeError path).
TORN_BYTES = POPULATED.encode("utf-8")[: len(POPULATED) // 2] + b"\x00\xff\xfe\x80" * 8

#: ScannerError: an unclosed flow sequence after the real content.
SCANNER_CORRUPT = POPULATED + "\t\tbroken: [unclosed\n"

#: RecursionError on Python 3.12's constructor — not YAMLError.
DEEP_NEST = POPULATED + "deep: " + "[" * 5000 + "1" + "]" * 5000 + "\n"

#: A stray whole-document paste that parses to a list, not a mapping.
NON_MAPPING = "- just\n- a\n- list\n"

#: JSON3 leftover: parses through load_yaml_int_capped, must still save.
DECIMAL_POISON = POPULATED.replace(
    "  adaptive: true", "  adaptive: true\n  port: " + _HUGE_DEC
)

_app = None


def _the_app():
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return _app


def _client() -> TestClient:
    # raise_server_exceptions=False: a real 500 must arrive as HTTP 500, not
    # as a re-raised exception that would mask which route crashed.
    return TestClient(_the_app(), raise_server_exceptions=False)


#: One mutating request per service that funnels into config.mutate().
MUTATIONS = (
    ("PUT", "/api/settings", {"adaptive": False}),
    ("POST", "/api/alerts/channels",
     {"id": "pin-ch", "type": "ntfy", "name": "Pin", "min_level": "info",
      "config": {"topic": "pin-topic"}}),
    ("PUT", "/api/services/group-rules",
     {"id": "pin-rule", "group": "PinGroup", "id_prefix": ["pin"]}),
)


class _Sandbox(unittest.TestCase):
    """Scratch services.yaml so no test touches a real install."""

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.yaml = self.dir / "services.yaml"
        for target, value in (
            ("YAML_PATH", self.yaml),
            ("DATA_DIR", self.dir),
            ("BASE", self.dir),
            ("_LOCK_PATH", self.dir / ".services.yaml.lock"),
            ("_cfg", {"mtime": None, "data": {}}),
        ):
            patched = mock.patch.object(config, target, value)
            patched.start()
            self.addCleanup(patched.stop)
        self.addCleanup(config.reload_cfg)

    def write(self, doc, *, raw: bytes | None = None) -> None:
        if raw is not None:
            self.yaml.write_bytes(raw)
        else:
            self.yaml.write_text(doc, encoding="utf-8")
        config.reload_cfg()

    def on_disk(self) -> bytes:
        return self.yaml.read_bytes()


class UnreadableConfigRefusesEveryMutationTests(_Sandbox):
    """Present-but-unusable services.yaml: coded 503, file byte-identical."""

    #: (name, text-or-None, raw-bytes-or-None)
    STATES = (
        ("oversize_valid", OVERSIZE_VALID, None),
        ("torn_bytes", None, TORN_BYTES),
        ("scanner_corrupt", SCANNER_CORRUPT, None),
        ("deep_nest", DEEP_NEST, None),
        ("non_mapping", NON_MAPPING, None),
    )

    def test_mutating_routes_answer_the_coded_503_and_keep_the_file(self):
        client = _client()
        for name, text, raw in self.STATES:
            for method, path, body in MUTATIONS:
                with self.subTest(state=name, route=f"{method} {path}"):
                    self.write(text, raw=raw)
                    before = self.on_disk()
                    r = client.request(method, path, json=body)
                    self.assertEqual(r.status_code, 503, r.text[:300])
                    self.assertEqual(
                        r.json()["detail"]["code"], "settings.config_unreadable",
                    )
                    self.assertEqual(
                        self.on_disk(), before,
                        "the refused save must leave the on-disk file intact",
                    )

    def test_read_routes_keep_their_defaults_fallback(self):
        """GET must not start 500ing: readers keep the {} degrade."""
        client = _client()
        for name, text, raw in self.STATES:
            with self.subTest(state=name):
                self.write(text, raw=raw)
                r = client.get("/api/settings")
                self.assertEqual(r.status_code, 200, r.text[:300])

    def test_oversize_wipe_would_have_had_no_backup_preimage(self):
        """Why refusal (not wipe-with-backup) is the only safe shape here:
        the pre-save copy reads capped, so the oversize original is exactly
        the file the backup step cannot preserve."""
        self.write(OVERSIZE_VALID)
        with self.assertRaises(OSError):
            from hub import secure_io
            secure_io.copy_secret_file(
                self.yaml, self.dir / "bak", max_bytes=config._YAML_CAP,
            )

    def test_mutate_raises_the_coded_error_in_process(self):
        self.write(OVERSIZE_VALID)
        before = self.on_disk()
        with self.assertRaises(HTTPException) as ctx:
            config.mutate(lambda d: d.setdefault("settings", {}).update(x=1))
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(ctx.exception.detail["code"], "settings.config_unreadable")
        self.assertEqual(self.on_disk(), before)

    def test_update_settings_background_callers_get_the_same_refusal(self):
        """The alias/SMART timers call update_settings off-request; their
        loops guard broadly, so the coded exception is safe — and the file
        must survive them too."""
        self.write(SCANNER_CORRUPT)
        before = self.on_disk()
        with self.assertRaises(HTTPException):
            config.update_settings({"host_ip": "10.9.9.9"})
        self.assertEqual(self.on_disk(), before)


class WritableStatesKeepWorkingTests(_Sandbox):
    """The refusal must not creep into states that hold nothing to lose."""

    def test_missing_file_still_accepts_the_first_save(self):
        """First-run setup writes the admin account through mutate()."""
        config.reload_cfg()
        client = _client()
        r = client.put("/api/settings", json={"adaptive": False})
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertTrue(self.yaml.is_file(), "the first save must create the file")
        self.assertIn("adaptive: false", self.yaml.read_text(encoding="utf-8"))

    def test_empty_and_comments_only_files_still_accept_saves(self):
        client = _client()
        for doc in ("", "# nothing here yet\n"):
            with self.subTest(doc=repr(doc)):
                self.write(doc)
                r = client.put("/api/settings", json={"adaptive": False})
                self.assertEqual(r.status_code, 200, r.text[:300])

    def test_leftover_empty_directory_still_saves(self):
        """Pre-existing leniency: a squatting non-file node holds no YAML."""
        self.yaml.mkdir()
        config.reload_cfg()
        client = _client()
        r = client.put("/api/settings", json={"adaptive": False})
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertTrue(self.yaml.is_file())

    def test_decimal_poison_still_parses_and_keeps_every_sibling(self):
        """JSON3 contract: the capped loader path must not regress into the
        refusal — the document IS readable once the one scalar drops."""
        self.write(DECIMAL_POISON)
        client = _client()
        r = client.put("/api/settings", json={"adaptive": False})
        self.assertEqual(r.status_code, 200, r.text[:300])
        raw = self.yaml.read_text(encoding="utf-8")
        for token in ("keep-admin", "pbkdf2-keep-hash", "keep-app", "keep-stack"):
            self.assertIn(token, raw)
        self.assertNotIn(_HUGE_DEC, raw)

    def test_junk_sections_inside_a_mapping_still_save(self):
        """_as_config coercions (settings: [] etc.) are readable configs."""
        self.write(POPULATED + "log_sources: nope\noverrides: [oops]\n")
        client = _client()
        r = client.put("/api/settings", json={"adaptive": False})
        self.assertEqual(r.status_code, 200, r.text[:300])
        raw = self.yaml.read_text(encoding="utf-8")
        self.assertIn("keep-admin", raw)


if __name__ == "__main__":
    unittest.main()
