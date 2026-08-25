"""Leftover over-digit-cap ints and surrogate filenames on the remote catalog.

Prior sweeps hardened the listing (``catalog._plain_ports``) and the summary
encoder (``catalog_remote._jsonable``) against ints CPython's 4300-digit
str<->int cap cannot render.  This hunt covered the remote catalog's
survivors — all reproduced on the pre-fix tree:

* **fixed** — ``_validate_template_text`` ran bare ``str()`` on the
  front-matter ``name`` / ``desc`` / ``id``.  YAML's hex int form dodges the
  decimal digit cap, so a remote template with ``name: 0xfff…`` (4000 hex
  digits) passed the YAML try/except and then ValueError'd *outside* it —
  500ing the whole POST /api/catalog/remote/check instead of rejecting the
  one template.  The replacement is a str() probe (``_as_text``), not an
  ``isinstance(str)`` gate: a template with a sane numeric name still lands.
* **fixed** — ``scan_compose_directives`` ran bare ``str()`` on
  ``network_mode`` and each volume entry.  A hex-huge value there fired
  *after* ingest validation had accepted the template, 500ing the sync on
  its very last step.
* **fixed** — ``status()`` returned override ids as raw filename stems and
  the source URL as a raw settings string.  A leftover override file named
  with surrogateescape bytes (or a hand-edited services.yaml url carrying a
  lone ``\\ud800``) UnicodeEncodeError'd Starlette's UTF-8 encode and 500'd
  GET /api/catalog/remote.
* **fixed** — ``_load_state`` had no ``parse_int`` hook: ``json.loads`` of a
  >4300-digit *decimal* number is ValueError (not JSONDecodeError) for the
  whole document, so one poisoned number silently wiped every synced
  override's version, warnings and the last-check stamp — and the same
  number inside one manifest entry failed the entire sync as
  ``bad_manifest`` instead of that entry.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import audit, catalog, catalog_remote  # noqa: E402

#: Past CPython's default 4300-digit str<->int conversion limit; hex is the
#: reachable YAML spelling (decimal literals already fail to parse).
_HEX_HUGE = "0x" + "f" * 4000
#: The decimal JSON spelling: valid JSON, but int() of it is ValueError.
_DEC_HUGE = "1" * 4400

INDEX_URL = "https://catalog.example.com/dir/index.json"

VALID_TEMPLATE = """---
name: Remote Demo
desc: A demo application delivered by the remote catalog
---
services:
  demo:
    image: example/demo:1.2.3
"""


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does; raises exactly where a 500 would."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def entry(tid: str, text: str, **over) -> dict:
    e = {"id": tid, "version": "1.0.0", "path": f"{tid}.yml", "sha256": sha(text)}
    e.update(over)
    return e


class RemoteSandbox(unittest.TestCase):
    """Temp REMOTE_DIR / TEMPLATES / audit and a fake ``_fetch``; no network."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="catalog-remote-digit-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

        remote_dir = self.tmp / "catalog-remote"
        templates_dir = self.tmp / "templates"
        templates_dir.mkdir()

        for target, attr, value in (
            (catalog_remote, "REMOTE_DIR", remote_dir),
            (catalog_remote, "STATE_PATH", remote_dir / "state.json"),
            (catalog, "TEMPLATES", templates_dir),
            (audit, "AUDIT_PATH", self.tmp / "audit.jsonl"),
        ):
            p = patch.object(target, attr, value)
            p.start()
            self.addCleanup(p.stop)

        self.remote_dir = remote_dir
        self.responses: dict[str, bytes] = {}

        def fake_fetch(url: str, max_bytes: int) -> bytes:
            if url not in self.responses:
                raise catalog_remote._FetchError(f"no response for {url}")
            return self.responses[url]

        fp = patch.object(catalog_remote, "_fetch", fake_fetch)
        fp.start()
        self.addCleanup(fp.stop)

        catalog.invalidate_listing()
        self.addCleanup(catalog.invalidate_listing)

    def serve_manifest_raw(self, body: str) -> None:
        self.responses[INDEX_URL] = body.encode()

    def serve_manifest(self, entries: list[dict]) -> None:
        self.serve_manifest_raw(
            json.dumps({"version": 1, "signature": "", "templates": entries})
        )

    def serve_template(self, tid: str, text: str) -> None:
        self.responses[f"https://catalog.example.com/dir/{tid}.yml"] = text.encode()

    def sync(self) -> dict:
        return catalog_remote.check_updates(url=INDEX_URL, operator="tester")


class ValidateTemplateTextDigitPinTests(unittest.TestCase):
    """Front-matter fields go through a str() probe, never a bare str()."""

    def test_hex_huge_name_is_a_reason_not_a_raise(self):
        text = f"---\nname: {_HEX_HUGE}\ndesc: d\n---\nservices:\n  a:\n    image: x\n"
        self.assertEqual(
            catalog_remote._validate_template_text(text), "front matter lacks a name"
        )

    def test_hex_huge_desc_is_a_reason_not_a_raise(self):
        text = f"---\nname: n\ndesc: {_HEX_HUGE}\n---\nservices:\n  a:\n    image: x\n"
        self.assertEqual(
            catalog_remote._validate_template_text(text), "front matter lacks a desc"
        )

    def test_hex_huge_id_is_a_mismatch_not_a_raise(self):
        text = (
            f"---\nname: n\ndesc: d\nid: {_HEX_HUGE}\n---\n"
            "services:\n  a:\n    image: x\n"
        )
        self.assertEqual(
            catalog_remote._validate_template_text(text, expected_id="demo"),
            "front matter id does not match the manifest id",
        )

    def test_numeric_name_and_desc_still_pass_the_probe(self):
        # str() probe, not isinstance(str): YAML mints ints from bare numeric
        # scalars and those templates were always accepted.
        text = "---\nname: 8080\ndesc: 42\n---\nservices:\n  a:\n    image: x\n"
        self.assertEqual(catalog_remote._validate_template_text(text), "")


class ScanDirectivesDigitPinTests(unittest.TestCase):
    """The directive scan renders untrusted scalars with the same probe."""

    def test_hex_huge_network_mode_scans_clean_not_a_raise(self):
        body = (
            f"---\nname: n\ndesc: d\n---\n"
            f"services:\n  a:\n    image: x\n    network_mode: {_HEX_HUGE}\n"
        )
        self.assertEqual(catalog_remote.scan_compose_directives(body), [])

    def test_hex_huge_volume_entry_scans_clean_not_a_raise(self):
        body = (
            f"---\nname: n\ndesc: d\n---\n"
            f"services:\n  a:\n    image: x\n    volumes:\n      - {_HEX_HUGE}\n"
        )
        self.assertEqual(catalog_remote.scan_compose_directives(body), [])

    def test_real_directives_are_still_detected(self):
        body = (
            "---\nname: n\ndesc: d\n---\n"
            "services:\n  a:\n    image: x\n    network_mode: host\n"
            "    volumes:\n      - /var/run/docker.sock:/s\n"
        )
        self.assertEqual(
            catalog_remote.scan_compose_directives(body),
            ["docker_socket", "host_network"],
        )


class CheckUpdatesDigitPinTests(RemoteSandbox):
    """POST /api/catalog/remote/check end to end with poisoned inputs."""

    def test_hex_huge_name_rejects_one_template_not_the_sync(self):
        poison = (
            f"---\nname: {_HEX_HUGE}\ndesc: d\n---\nservices:\n  a:\n    image: x\n"
        )
        self.serve_manifest([entry("poison", poison), entry("demo", VALID_TEMPLATE)])
        self.serve_template("poison", poison)
        self.serve_template("demo", VALID_TEMPLATE)

        summary = self.sync()

        self.assertEqual(summary["added"], ["demo"])
        rejected = {r["id"]: r["reason"] for r in summary["rejected"]}
        self.assertEqual(rejected, {"poison": catalog_remote.REJECT_PARSE_FAILED})
        _starlette(summary)

    def test_hex_huge_network_mode_syncs_and_records_no_bogus_warning(self):
        # Validation accepts the template (network_mode is not gated), and the
        # directive scan on the very last ingest step must not blow the sync.
        tricky = (
            f"---\nname: Tricky\ndesc: d\n---\n"
            f"services:\n  a:\n    image: x\n    network_mode: {_HEX_HUGE}\n"
        )
        self.serve_manifest([entry("tricky", tricky)])
        self.serve_template("tricky", tricky)

        summary = self.sync()

        self.assertEqual(summary["added"], ["tricky"])
        self.assertEqual(summary["rejected"], [])
        self.assertEqual(catalog_remote.remote_warnings().get("tricky"), [])
        _starlette(summary)

    def test_decimal_huge_number_in_one_entry_no_longer_fails_the_manifest(self):
        # json.loads of a >4300-digit number is ValueError, not
        # JSONDecodeError; it used to 422 the whole sync as bad_manifest.
        poisoned_entry = (
            json.dumps(entry("demo", VALID_TEMPLATE))[:-1] + f', "size": {_DEC_HUGE}}}'
        )
        self.serve_manifest_raw(f'{{"version": 1, "templates": [{poisoned_entry}]}}')
        self.serve_template("demo", VALID_TEMPLATE)

        summary = self.sync()

        self.assertEqual(summary["added"], ["demo"])
        self.assertEqual(summary["rejected"], [])
        _starlette(summary)


class StateDigitPinTests(RemoteSandbox):
    """A poisoned number in state.json must lose only itself."""

    def _write_state(self, body: str) -> None:
        self.remote_dir.mkdir(parents=True, exist_ok=True)
        (self.remote_dir / "state.json").write_text(body, encoding="utf-8")

    def test_decimal_huge_number_keeps_the_rest_of_the_state(self):
        self._write_state(
            '{"last_check": "2026-01-01T00:00:00", "templates": {"demo": '
            '{"version": "1.0", "sha256": "ab", "warnings": ["privileged"], '
            f'"size": {_DEC_HUGE}}}}}}}'
        )
        state = catalog_remote._load_state()
        self.assertEqual(state.get("last_check"), "2026-01-01T00:00:00")
        self.assertEqual(catalog_remote.remote_versions(), {"demo": "1.0"})
        self.assertEqual(catalog_remote.remote_warnings(), {"demo": ["privileged"]})
        # The unrenderable number itself is dropped, not preserved.
        self.assertIsNone(state["templates"]["demo"]["size"])

    def test_sane_state_still_loads_intact(self):
        self._write_state(
            '{"last_check": "2026-01-01T00:00:00", "templates": {"demo": '
            '{"version": "2.0", "sha256": "cd", "warnings": [], "size": 1234}}}'
        )
        state = catalog_remote._load_state()
        self.assertEqual(state["templates"]["demo"]["size"], 1234)
        self.assertEqual(catalog_remote.remote_versions(), {"demo": "2.0"})

    def test_status_still_reports_last_check_past_the_poison(self):
        self._write_state(
            f'{{"last_check": "2026-01-01T00:00:00", "size": {_DEC_HUGE}}}'
        )
        status = catalog_remote.status()
        self.assertEqual(status["last_check"], "2026-01-01T00:00:00")
        _starlette(status)


class StatusSurrogatePinTests(RemoteSandbox):
    """GET /api/catalog/remote with leftovers only bytes can spell."""

    def test_surrogate_override_filename_does_not_500_status(self):
        # surrogateescape is how a leftover file with undecodable bytes in
        # its name reaches Python; the stem lands in the override id.
        self.remote_dir.mkdir(parents=True, exist_ok=True)
        name = b"bad\xff.yml".decode("utf-8", "surrogateescape")
        (self.remote_dir / name).write_text("services: {}\n", errors="replace")

        status = catalog_remote.status()

        self.assertEqual(status["count"], 1)
        _starlette(status)

    def test_surrogate_source_url_does_not_500_status(self):
        with patch.object(catalog_remote, "source_url", return_value="\udc80url"):
            status = catalog_remote.status()
            self.assertTrue(status["configured"])
            _starlette(status)

    def test_sane_override_is_still_reported_with_its_version(self):
        self.serve_manifest([entry("demo", VALID_TEMPLATE)])
        self.serve_template("demo", VALID_TEMPLATE)
        self.sync()

        status = catalog_remote.status()

        self.assertEqual(status["count"], 1)
        self.assertEqual(status["overrides"][0]["id"], "demo")
        self.assertEqual(status["overrides"][0]["version"], "1.0.0")
        _starlette(status)


if __name__ == "__main__":
    unittest.main()
