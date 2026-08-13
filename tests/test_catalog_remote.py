"""Remote template catalog: validation chain, atomicity, merge and restore.

Every test runs against a temp REMOTE_DIR and a fake ``_fetch`` — nothing here
touches the network, the real data/catalog-remote/ directory, services.yaml or
the real audit trail.

What is pinned down:

* URL vetting: only plain ``https://`` sources are accepted, because the
  transport is half of the integrity story (no signature dependency exists in
  requirements.txt, so the manifest is trusted via TLS + per-file sha256).
* The per-template validation chain: sha256 mismatch, oversize, unparseable
  and impersonating templates are rejected with machine-readable reasons, and
  a rejection never blocks the other manifest entries.
* Atomic swap: accepted templates appear whole, rejected ones not at all, and
  no staging litter survives a sync.
* Merge priority: a remote override shadows the built-in with the same id in
  the listing and in install resolution; restore-builtin removes exactly that
  override and falls back to the shipped file.
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

from fastapi import HTTPException

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import audit, catalog, catalog_remote  # noqa: E402

VALID_TEMPLATE = """---
name: Remote Demo
desc: A demo application delivered by the remote catalog
category: other
ports: ["18080"]
vars:
  - name: HOST_PORT
    label: Port
    default: "18080"
---
services:
  demo:
    image: example/demo:1.2.3
    restart: unless-stopped
    ports:
      - "{{HOST_PORT}}:80"
"""

SECOND_TEMPLATE = """---
name: Remote Second
desc: Another demo application from the remote catalog
category: other
ports: ["18081"]
vars:
  - name: HOST_PORT
    label: Port
    default: "18081"
---
services:
  second:
    image: example/second:2.0.0
    ports:
      - "{{HOST_PORT}}:80"
"""

BUILTIN_TEMPLATE = """---
name: Builtin Demo
desc: The shipped copy of the demo application
category: other
ports: ["18080"]
vars:
  - name: HOST_PORT
    label: Port
    default: "18080"
---
services:
  demo:
    image: example/demo:1.0.0
    ports:
      - "{{HOST_PORT}}:80"
"""

INDEX_URL = "https://catalog.example.com/dir/index.json"


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def entry(tid: str, text: str, **over) -> dict:
    e = {"id": tid, "version": "1.0.0", "path": f"{tid}.yml", "sha256": sha(text)}
    e.update(over)
    return e


class RemoteCatalogCase(unittest.TestCase):
    """Shared fixture: temp dirs for REMOTE_DIR / TEMPLATES / audit, fake fetch."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="catalog-remote-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

        remote_dir = self.tmp / "catalog-remote"
        templates_dir = self.tmp / "templates"
        templates_dir.mkdir()
        (templates_dir / "demo.yml").write_text(BUILTIN_TEMPLATE)

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
        self.templates_dir = templates_dir

        self.responses: dict[str, bytes] = {}
        self.fetch_log: list[str] = []

        def fake_fetch(url: str, max_bytes: int) -> bytes:
            self.fetch_log.append(url)
            if url not in self.responses:
                raise catalog_remote._FetchError(f"no response for {url}")
            data = self.responses[url]
            if len(data) > max_bytes:
                raise catalog_remote._TooLargeError(
                    f"response exceeds {max_bytes} bytes"
                )
            return data

        fp = patch.object(catalog_remote, "_fetch", fake_fetch)
        fp.start()
        self.addCleanup(fp.stop)

        # The listing cache is process-global; drop it so template merges from
        # a previous test (or the real catalog) never leak in.
        catalog._list_cache["t"] = 0
        catalog._list_cache["items"] = None
        self.addCleanup(lambda: catalog._list_cache.update(t=0, items=None))

    # ── helpers ───────────────────────────────────────────────────────────────

    def serve_manifest(self, entries: list[dict]) -> None:
        manifest = {"version": 1, "signature": "", "templates": entries}
        self.responses[INDEX_URL] = json.dumps(manifest).encode()

    def serve_template(self, tid: str, text: str) -> None:
        self.responses[f"https://catalog.example.com/dir/{tid}.yml"] = text.encode()

    def sync(self) -> dict:
        return catalog_remote.check_updates(url=INDEX_URL, operator="tester")

    def api_code(self, ctx) -> str:
        detail = ctx.exception.detail
        return detail["code"] if isinstance(detail, dict) else str(detail)


class UrlValidation(RemoteCatalogCase):
    def test_https_url_is_accepted(self):
        self.assertEqual(
            catalog_remote.validate_source_url("https://example.com/index.json"),
            "https://example.com/index.json",
        )

    def test_empty_url_clears_the_source(self):
        self.assertEqual(catalog_remote.validate_source_url("  "), "")

    def test_non_https_schemes_are_refused(self):
        for url in (
            "http://example.com/index.json",
            "ftp://example.com/index.json",
            "file:///etc/passwd",
            "example.com/index.json",
        ):
            with self.subTest(url=url):
                with self.assertRaises(HTTPException) as ctx:
                    catalog_remote.validate_source_url(url)
                self.assertEqual(self.api_code(ctx), "catalog_remote.bad_url")

    def test_embedded_credentials_are_refused(self):
        # The URL is persisted in services.yaml and echoed by the status API,
        # so a user:pass@ form would store a secret in plain sight.
        with self.assertRaises(HTTPException) as ctx:
            catalog_remote.validate_source_url("https://user:pw@example.com/i.json")
        self.assertEqual(self.api_code(ctx), "catalog_remote.bad_url")

    def test_check_without_a_configured_source_is_a_clean_error(self):
        with patch.object(catalog_remote, "source_url", lambda: ""):
            with self.assertRaises(HTTPException) as ctx:
                catalog_remote.check_updates()
            self.assertEqual(self.api_code(ctx), "catalog_remote.not_configured")


class ManifestValidation(RemoteCatalogCase):
    def test_unfetchable_manifest_is_fetch_failed(self):
        with self.assertRaises(HTTPException) as ctx:
            self.sync()
        self.assertEqual(self.api_code(ctx), "catalog_remote.fetch_failed")

    def test_non_json_manifest_is_bad_manifest(self):
        self.responses[INDEX_URL] = b"<html>not a manifest</html>"
        with self.assertRaises(HTTPException) as ctx:
            self.sync()
        self.assertEqual(self.api_code(ctx), "catalog_remote.bad_manifest")

    def test_manifest_without_templates_list_is_bad_manifest(self):
        self.responses[INDEX_URL] = json.dumps({"version": 1}).encode()
        with self.assertRaises(HTTPException) as ctx:
            self.sync()
        self.assertEqual(self.api_code(ctx), "catalog_remote.bad_manifest")

    def test_manifest_over_the_entry_cap_is_refused_whole(self):
        entries = [entry(f"app-{i}", VALID_TEMPLATE) for i in range(3)]
        self.serve_manifest(entries)
        with patch.object(catalog_remote, "MAX_TEMPLATES", 2):
            with self.assertRaises(HTTPException) as ctx:
                self.sync()
        self.assertEqual(self.api_code(ctx), "catalog_remote.too_many_templates")
        self.assertEqual(catalog_remote.remote_template_files(), [])


class TemplateValidationChain(RemoteCatalogCase):
    def test_valid_templates_are_added(self):
        self.serve_manifest([
            entry("app-one", VALID_TEMPLATE),
            entry("app-two", SECOND_TEMPLATE),
        ])
        self.serve_template("app-one", VALID_TEMPLATE)
        self.serve_template("app-two", SECOND_TEMPLATE)

        result = self.sync()
        self.assertEqual(result["added"], ["app-one", "app-two"])
        self.assertEqual(result["rejected"], [])
        self.assertEqual(
            (self.remote_dir / "app-one.yml").read_text(), VALID_TEMPLATE
        )
        self.assertEqual(
            catalog_remote.remote_versions(),
            {"app-one": "1.0.0", "app-two": "1.0.0"},
        )

    def test_sha256_mismatch_is_rejected_and_others_still_land(self):
        self.serve_manifest([
            entry("app-bad", VALID_TEMPLATE, sha256="0" * 64),
            entry("app-good", SECOND_TEMPLATE),
        ])
        self.serve_template("app-bad", VALID_TEMPLATE)
        self.serve_template("app-good", SECOND_TEMPLATE)

        result = self.sync()
        self.assertEqual(result["added"], ["app-good"])
        reasons = {r["id"]: r["reason"] for r in result["rejected"]}
        self.assertEqual(reasons, {"app-bad": "sha256_mismatch"})
        self.assertFalse((self.remote_dir / "app-bad.yml").exists())
        self.assertTrue((self.remote_dir / "app-good.yml").exists())

    def test_oversize_template_is_rejected(self):
        big = VALID_TEMPLATE + "#" + "x" * catalog_remote.MAX_TEMPLATE_BYTES
        self.serve_manifest([entry("app-big", big)])
        self.serve_template("app-big", big)

        result = self.sync()
        self.assertEqual(result["added"], [])
        self.assertEqual(result["rejected"][0]["reason"], "too_large")
        self.assertFalse((self.remote_dir / "app-big.yml").exists())

    def test_unparseable_template_is_rejected(self):
        no_front_matter = "services:\n  x:\n    image: a:1\n"
        bad_yaml_default = VALID_TEMPLATE.replace('default: "18080"', "default: {{SERVICES}}/x")
        no_services = "---\nname: X\ndesc: Y\n---\nnothing: here\n"
        for i, text in enumerate((no_front_matter, bad_yaml_default, no_services)):
            tid = f"app-parse-{i}"
            with self.subTest(tid=tid):
                self.serve_manifest([entry(tid, text)])
                self.serve_template(tid, text)
                result = self.sync()
                self.assertEqual(result["rejected"][0]["reason"], "parse_failed")
                self.assertFalse((self.remote_dir / f"{tid}.yml").exists())

    def test_template_claiming_another_id_is_rejected(self):
        # front-matter `id:` overrides the filename in _parse_template(), so a
        # template claiming a different id would impersonate another entry.
        impersonator = VALID_TEMPLATE.replace(
            "name: Remote Demo", "id: vaultwarden\nname: Remote Demo"
        )
        self.serve_manifest([entry("app-fake", impersonator)])
        self.serve_template("app-fake", impersonator)
        result = self.sync()
        self.assertEqual(result["rejected"][0]["reason"], "parse_failed")

    def test_bad_ids_and_duplicates_are_rejected(self):
        self.serve_manifest([
            entry("../escape", VALID_TEMPLATE),
            entry("UPPER", VALID_TEMPLATE),
            entry("app-dup", VALID_TEMPLATE),
            entry("app-dup", VALID_TEMPLATE),
        ])
        self.serve_template("app-dup", VALID_TEMPLATE)
        result = self.sync()
        reasons = [r["reason"] for r in result["rejected"]]
        self.assertEqual(reasons.count("bad_id"), 2)
        self.assertEqual(reasons.count("duplicate_id"), 1)
        self.assertEqual(result["added"], ["app-dup"])
        # Nothing escaped the remote dir.
        self.assertEqual(
            {p.name for p in self.remote_dir.glob("*.yml")}, {"app-dup.yml"}
        )

    def test_file_url_outside_the_manifest_origin_is_rejected(self):
        self.serve_manifest([
            entry("app-elsewhere", VALID_TEMPLATE, path="https://evil.example.net/x.yml"),
        ])
        self.responses["https://evil.example.net/x.yml"] = VALID_TEMPLATE.encode()
        result = self.sync()
        self.assertEqual(result["rejected"][0]["reason"], "bad_url")
        self.assertNotIn("https://evil.example.net/x.yml", self.fetch_log)

    def test_unreachable_template_is_rejected_and_others_still_land(self):
        self.serve_manifest([
            entry("app-offline", VALID_TEMPLATE),
            entry("app-online", SECOND_TEMPLATE),
        ])
        self.serve_template("app-online", SECOND_TEMPLATE)
        result = self.sync()
        reasons = {r["id"]: r["reason"] for r in result["rejected"]}
        self.assertEqual(reasons, {"app-offline": "fetch_failed"})
        self.assertEqual(result["added"], ["app-online"])


class Atomicity(RemoteCatalogCase):
    def test_no_staging_litter_survives_a_sync(self):
        self.serve_manifest([
            entry("app-ok", VALID_TEMPLATE),
            entry("app-bad", SECOND_TEMPLATE, sha256="f" * 64),
        ])
        self.serve_template("app-ok", VALID_TEMPLATE)
        self.serve_template("app-bad", SECOND_TEMPLATE)
        self.sync()
        leftovers = [p.name for p in self.remote_dir.iterdir() if p.name.startswith(".staging")]
        self.assertEqual(leftovers, [])

    def test_accepted_files_are_complete_and_private(self):
        self.serve_manifest([entry("app-one", VALID_TEMPLATE)])
        self.serve_template("app-one", VALID_TEMPLATE)
        self.sync()
        final = self.remote_dir / "app-one.yml"
        self.assertEqual(final.read_text(), VALID_TEMPLATE)
        self.assertEqual(final.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.remote_dir.stat().st_mode & 0o777, 0o700)

    def test_second_sync_skips_unchanged_templates(self):
        self.serve_manifest([entry("app-one", VALID_TEMPLATE)])
        self.serve_template("app-one", VALID_TEMPLATE)
        self.sync()
        self.fetch_log.clear()

        result = self.sync()
        self.assertEqual(result["added"], [])
        self.assertEqual(result["unchanged"], 1)
        # Only the manifest was re-fetched; the template body was not.
        self.assertEqual(self.fetch_log, [INDEX_URL])

    def test_changed_template_is_updated_in_place(self):
        self.serve_manifest([entry("app-one", VALID_TEMPLATE)])
        self.serve_template("app-one", VALID_TEMPLATE)
        self.sync()

        changed = VALID_TEMPLATE.replace("1.2.3", "1.3.0")
        self.serve_manifest([entry("app-one", changed, version="1.3.0")])
        self.serve_template("app-one", changed)
        result = self.sync()
        self.assertEqual(result["updated"], ["app-one"])
        self.assertIn("1.3.0", (self.remote_dir / "app-one.yml").read_text())
        self.assertEqual(catalog_remote.remote_versions()["app-one"], "1.3.0")


DANGEROUS_TEMPLATE = """---
name: Remote Danger
desc: A demo using every elevated-access compose directive at once
category: other
---
services:
  danger:
    image: example/danger:1.0.0
    privileged: true
    network_mode: host
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/ttyUSB0:/dev/ttyUSB0
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./data:/data
"""


class ElevatedAccessScan(RemoteCatalogCase):
    """Dangerous compose directives are recorded at ingest, never rejected.

    Defence in depth for the "remote override looks exactly like the built-in"
    problem: the admin's source choice stays the trust root, but privileged /
    cap_add / docker.sock / host networking / devices are surfaced as template
    metadata so the install dialog can warn before anything runs.
    """

    def test_scanner_reports_each_directive_once(self):
        self.assertEqual(
            catalog_remote.scan_compose_directives(DANGEROUS_TEMPLATE),
            ["cap_add", "devices", "docker_socket", "host_network", "privileged"],
        )

    def test_scanner_reports_nothing_for_a_clean_template(self):
        self.assertEqual(catalog_remote.scan_compose_directives(VALID_TEMPLATE), [])

    def test_scanner_sees_long_form_volume_mounts(self):
        text = (
            "---\nname: X\ndesc: Y\n---\n"
            "services:\n  x:\n    image: a:1\n    volumes:\n"
            "      - type: bind\n        source: /var/run/docker.sock\n"
            "        target: /var/run/docker.sock\n"
        )
        self.assertEqual(
            catalog_remote.scan_compose_directives(text), ["docker_socket"]
        )

    def test_dangerous_template_is_accepted_and_its_hits_are_recorded(self):
        self.serve_manifest([entry("app-danger", DANGEROUS_TEMPLATE)])
        self.serve_template("app-danger", DANGEROUS_TEMPLATE)
        result = self.sync()
        self.assertEqual(result["added"], ["app-danger"])
        self.assertEqual(result["rejected"], [])
        self.assertEqual(
            catalog_remote.remote_warnings()["app-danger"],
            ["cap_add", "devices", "docker_socket", "host_network", "privileged"],
        )
        with patch.object(catalog_remote, "source_url", lambda: INDEX_URL):
            status = catalog_remote.status()
        self.assertEqual(
            status["overrides"][0]["warnings"],
            ["cap_add", "devices", "docker_socket", "host_network", "privileged"],
        )

    def test_clean_sync_records_an_empty_warning_list(self):
        self.serve_manifest([entry("app-one", VALID_TEMPLATE)])
        self.serve_template("app-one", VALID_TEMPLATE)
        self.sync()
        self.assertEqual(catalog_remote.remote_warnings()["app-one"], [])

    def test_listing_carries_compose_warnings_for_remote_overrides(self):
        dangerous_demo = DANGEROUS_TEMPLATE.replace(
            "name: Remote Danger", "name: Remote Demo"
        )
        self.serve_manifest([entry("demo", dangerous_demo, version="6.6.6")])
        self.serve_template("demo", dangerous_demo)
        self.sync()
        items = {t["id"]: t for t in catalog.list_templates(force=True)}
        self.assertEqual(
            items["demo"]["compose_warnings"],
            ["cap_add", "devices", "docker_socket", "host_network", "privileged"],
        )
        # Built-in templates never carry sync-time warnings.
        for tid, item in items.items():
            if item["source"] == "builtin":
                self.assertEqual(item["compose_warnings"], [], tid)


class MergeAndRestore(RemoteCatalogCase):
    def install_override(self, tid: str = "demo", text: str | None = None) -> None:
        body = text if text is not None else VALID_TEMPLATE
        self.serve_manifest([entry(tid, body, version="9.9.9")])
        self.serve_template(tid, body)
        self.sync()

    def test_remote_override_shadows_the_builtin_listing(self):
        items = {t["id"]: t for t in catalog.list_templates(force=True)}
        self.assertEqual(items["demo"]["name"], "Builtin Demo")
        self.assertEqual(items["demo"]["source"], "builtin")

        self.install_override()
        items = {t["id"]: t for t in catalog.list_templates(force=True)}
        self.assertEqual(items["demo"]["name"], "Remote Demo")
        self.assertEqual(items["demo"]["source"], "remote")
        self.assertEqual(items["demo"]["remote_version"], "9.9.9")
        self.assertTrue(items["demo"]["builtin_available"])
        # No duplicate card for the shadowed built-in.
        self.assertEqual(
            sum(1 for t in catalog.list_templates(force=True) if t["id"] == "demo"), 1
        )

    def test_remote_only_template_is_listed_without_builtin_fallback(self):
        self.install_override("app-new")
        items = {t["id"]: t for t in catalog.list_templates(force=True)}
        self.assertEqual(items["app-new"]["source"], "remote")
        self.assertFalse(items["app-new"]["builtin_available"])

    def test_install_resolution_prefers_the_remote_file(self):
        self.assertEqual(
            catalog.template_file("demo"), self.templates_dir / "demo.yml"
        )
        self.install_override()
        self.assertEqual(
            catalog.template_file("demo"), self.remote_dir / "demo.yml"
        )

    def test_restore_builtin_removes_exactly_the_override(self):
        self.install_override()
        self.install_override("app-new")

        result = catalog_remote.restore_builtin("demo", operator="tester")
        self.assertTrue(result["ok"])
        self.assertTrue(result["builtin_available"])
        self.assertFalse((self.remote_dir / "demo.yml").exists())
        self.assertTrue((self.remote_dir / "app-new.yml").exists())
        self.assertNotIn("demo", catalog_remote.remote_versions())

        items = {t["id"]: t for t in catalog.list_templates(force=True)}
        self.assertEqual(items["demo"]["name"], "Builtin Demo")
        self.assertEqual(items["demo"]["source"], "builtin")

    def test_restoring_a_template_with_no_override_is_a_404(self):
        with self.assertRaises(HTTPException) as ctx:
            catalog_remote.restore_builtin("demo")
        self.assertEqual(self.api_code(ctx), "catalog_remote.not_remote")

    def test_status_reports_overrides_and_capability(self):
        self.install_override()
        with patch.object(catalog_remote, "source_url", lambda: INDEX_URL):
            status = catalog_remote.status()
        self.assertTrue(status["configured"])
        self.assertEqual(status["count"], 1)
        self.assertEqual(status["overrides"][0]["id"], "demo")
        self.assertEqual(status["overrides"][0]["version"], "9.9.9")
        self.assertTrue(status["overrides"][0]["builtin_available"])
        # Honest about the integrity model: no signature verification without
        # an asymmetric-crypto dependency.
        self.assertFalse(status["signature_verified"])
        self.assertIsNotNone(status["last_result"])


if __name__ == "__main__":
    unittest.main()
