"""Fourth leftover-500s sweep of the Apps catalog surface, over the real app.

The hunted classes (lone UTF-8 surrogates in keys AND values, the CPython
4300-digit int cap — including the uncapped YAML/plist hex form that arrives
already-int — numeric YAML ids, huge-number JSON journals, vanished-CLI /
engine-down 503-vs-500) were re-reproduced against every route the Apps
catalog tab mounts:

    GET  /api/catalog                GET  /api/catalog/templates
    GET  /api/catalog/remote         PUT  /api/catalog/remote
    POST /api/catalog/remote/check   POST /api/catalog/remote/restore
    POST /api/catalog/{id}/install   POST /api/catalog/{id}/uninstall

One live leak was found and fixed: ``bootstrap_files`` is the only block of
template front matter ``_parse_template`` leaves raw, and its consumer in
``install_template`` ran bare ``str()`` on ``path``/``content``.  A leftover
hex-huge YAML int there (``0xfff…`` dodges the parse-time digit cap and
arrives already-int) made ``str()`` raise the digit-cap ValueError — outside
the loop's OSError guard — and a lone ``"\\ud800"`` UnicodeEncodeError'd the
write the same way.  Either failed the *whole* install through the broad
rollback: the operator's filled-in variables and minted passwords were
discarded over one junk entry, and the response carried CPython's raw
``Exceeds the limit (4300 digits)`` prose.  Junk entries are now dropped and
the install proceeds (:class:`BootstrapJunkEntryHttpTests` fails on the
pre-fix tree).

Everything else was already immune at the service level (catalog3's
``_plain_str`` / ``_plain_ports`` / ``_sig_int`` probes, catalog_remote's
``_jsonable`` + ``_capped_json_int`` hook, the vanished-CLI classifiers) —
but none of those pins exercises request routing, Pydantic body parsing,
app_factory's sanitizing RequestValidationError handler, or Starlette's
strict UTF-8 render of the final body.  This battery pins the whole cycle
through ``create_app()``:

* a >4300-digit integer literal anywhere in a request body: ``json.loads``
  raises ValueError (NOT JSONDecodeError) for the whole document, and
  FastAPI's body-parse guard answers 400, never a 500;
* a JSON ``\\ud800`` escape in a typed str field is refused by Pydantic
  (``string_unicode``) and the 422 body — which echoes the input — must
  survive the strict UTF-8 encode (app_factory's handler scrubs it; the
  stock FastAPI handler 500s, so this pin guards the custom handler);
* the hostile-template zoo renders GET /api/catalog(/templates) as 200;
* a poisoned remote state.json loses only the unrenderable number, never
  the whole journal (versions of sane siblings survive);
* one poisoned manifest entry costs that entry, not the sync;
* engine-down / vanished-CLI on install and uninstall keep their coded
  shapes (soft-fail dict / HTTP 503) through the mounted routes, and the
  timeout sentinel stays unclassified.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import catalog, catalog_remote, native_catalog
from hub.app_factory import create_app
from hub.auth import require_auth
from hub.routers import catalog as catalog_router

#: Parsed from real plist bytes: plistlib's ``<integer>`` handler runs
#: ``int(x, 16)`` for the ``0x`` form, which CPython's 4300-digit str->int
#: parse cap does not bound, so the leftover arrives *already-int* and only
#: fails at render time (``str()`` / ``json.dumps``).
_HUGE_INT = plistlib.loads(
    b'<?xml version="1.0"?><plist version="1.0"><dict>'
    b"<key>v</key><integer>0x" + b"F" * 4400 + b"</integer>"
    b"</dict></plist>"
)["v"]

#: The YAML spelling of the same leftover (hex is exempt from the digit cap).
_HEX_HUGE = "0x" + "f" * 4400

_app = None


def _the_app():
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return _app


async def _asgi_request(method, path, *, body=None, raw_body=None):
    """Drive the full panel app (middleware + handlers) through one cycle."""
    app = _the_app()
    payload = raw_body if raw_body is not None else (
        b"{}" if body is None else json.dumps(body).encode("utf-8")
    )
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
        "path": path, "raw_path": path.encode(), "query_string": b"",
        "root_path": "",
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
            (b"host", b"localhost:8086"),
        ],
        "server": ("localhost", 8086), "client": ("127.0.0.1", 1), "state": {},
    }
    await app(scope, receive, send)
    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    raw = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    # The body must already be valid UTF-8 — decode strictly on purpose.
    return status, raw.decode("utf-8")


def request(method, path, *, body=None, raw_body=None):
    return asyncio.run(_asgi_request(method, path, body=body, raw_body=raw_body))


def _admin_browser():
    """An administrator browser session, as the catalog router resolves one."""
    return (
        mock.patch.object(catalog_router.auth, "browser_authenticated", return_value=True),
        mock.patch.object(catalog_router.auth, "request_username", return_value="admin"),
        mock.patch.object(catalog_router.auth, "is_admin", return_value=True),
        mock.patch.object(catalog_router.auth, "request_client_id", return_value="127.0.0.1"),
    )


class _CatalogSandbox(unittest.TestCase):
    """Template dir + services root + remote dir in a per-test temp tree."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        tmp = Path(self._tmp.name)
        self.templates = tmp / "templates"
        self.templates.mkdir()
        self.services = tmp / "services"
        self.services.mkdir()
        self.remote_dir = tmp / "catalog-remote"
        self.remote_dir.mkdir()
        catalog.invalidate_listing()
        self.addCleanup(catalog.invalidate_listing)
        for module, name, value in (
            (catalog, "TEMPLATES", self.templates),
            (catalog, "SERVICES_ROOT", self.services),
            (catalog_remote, "REMOTE_DIR", self.remote_dir),
            (catalog_remote, "STATE_PATH", self.remote_dir / "state.json"),
        ):
            patched = mock.patch.object(module, name, value)
            patched.start()
            self.addCleanup(patched.stop)
        for patched in _admin_browser():
            patched.start()
            self.addCleanup(patched.stop)


class CatalogListingHostileHttpTests(_CatalogSandbox):
    """GET /api/catalog(/templates) with the full leftover zoo on disk."""

    def setUp(self):
        super().setUp()
        # Every front-matter field carries the already-int hex leftover.
        (self.templates / "hexall.yml").write_text(
            f"---\nid: {_HEX_HUGE}\nname: {_HEX_HUGE}\ndesc: {_HEX_HUGE}\n"
            f"category: {_HEX_HUGE}\nnotes: {_HEX_HUGE}\nurl_template: {_HEX_HUGE}\n"
            f"first_run_credentials: {_HEX_HUGE}\nfeatured: {_HEX_HUGE}\n"
            f"tags: [{_HEX_HUGE}]\nports: [{_HEX_HUGE}, \"8080\"]\n"
            f"vars:\n  - name: {_HEX_HUGE}\n    default: {_HEX_HUGE}\n"
            f"    label: {_HEX_HUGE}\n    help: {_HEX_HUGE}\n---\n"
            "services:\n  a:\n    image: example/a\n"
        )
        # Lone surrogates in keys AND values (YAML's \ud800 escape mints the
        # str a strict UTF-8 encode refuses).
        (self.templates / "surr.yml").write_text(
            '---\nid: "s\\ud800x"\nname: "n\\ud800"\ndesc: "d\\udc80"\n'
            '"\\ud800key": poisoned-key\n'
            'notes: "x\\ud800"\ntags: ["t\\ud800"]\nports: ["80\\ud800"]\n'
            'vars:\n  - name: "V\\ud800"\n    default: "dv\\ud800"\n'
            '    label: "l\\ud800"\n    help: "h\\ud800"\n---\n'
            "services:\n  a:\n    image: example/a\n"
        )
        # Numeric YAML id must read as its quoted twin, not the filename.
        (self.templates / "numid.yml").write_text(
            "---\nid: 8080\nname: NumId\ndesc: d\n---\n"
            "services:\n  a:\n    image: example/a\n"
        )
        # A sane neighbour that must keep its ports and url hint.
        (self.templates / "sane.yml").write_text(
            '---\nname: Sane\ndesc: d\nports: ["9090"]\n---\n'
            "services:\n  a:\n    image: example/a\n"
        )

    def test_templates_route_renders_the_whole_zoo(self):
        status, text = request("GET", "/api/catalog/templates")
        self.assertEqual(status, 200, text[:300])
        rows = json.loads(text)["templates"]
        self.assertEqual(len(rows), 4)
        by_id = {}
        for row in rows:
            by_id[row["file"]] = row
        # Hex-huge fields degrade to fallbacks, never fail the listing.
        hexall = by_id["hexall.yml"]
        self.assertEqual(hexall["id"], "hexall")
        self.assertEqual(hexall["ports"], ["8080"])
        self.assertEqual(hexall["category"], "other")
        # Numeric id reads as its string form.
        self.assertEqual(by_id["numid.yml"]["id"], "8080")
        # The sane sibling is untouched.
        self.assertEqual(by_id["sane.yml"]["ports"], ["9090"])
        self.assertNotIn("\ud800", text)

    def test_store_overview_keeps_the_docker_half(self):
        with mock.patch.object(
            native_catalog, "list_native_apps", return_value=[]
        ):
            status, text = request("GET", "/api/catalog")
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        self.assertEqual(payload["docker_count"], 4)


class CatalogRemoteStateJournalHttpTests(_CatalogSandbox):
    """GET /api/catalog/remote with a poisoned state.json journal."""

    def test_huge_number_loses_the_number_not_the_journal(self):
        # One >4300-digit decimal makes json.loads raise ValueError (not
        # JSONDecodeError) for the whole document; without the parse_int
        # hook the load returned {} and every synced override's version
        # vanished.  The sane sibling's version must survive.
        (self.remote_dir / "state.json").write_text(
            '{"templates": {'
            '"jellyfin": {"version": "1.2.0", "synced": ' + "9" * 5000 + '},'
            '"navi\\ud800drome": {"version": "2.0", "warnings": ["w\\ud800"]}'
            '}, "last_check": "2026-08-01T00:00:00+0000"}'
        )
        (self.remote_dir / "jellyfin.yml").write_text(
            "---\nname: J\ndesc: d\n---\nservices:\n  a:\n    image: e/a\n"
        )
        status, text = request("GET", "/api/catalog/remote")
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        overrides = {o["id"]: o for o in payload["overrides"]}
        self.assertEqual(overrides["jellyfin"]["version"], "1.2.0")
        self.assertEqual(payload["last_check"], "2026-08-01T00:00:00+0000")
        self.assertNotIn("\ud800", text)


class CatalogRemoteCheckPartialHttpTests(_CatalogSandbox):
    """POST /api/catalog/remote/check: one bad entry costs that entry only."""

    def test_poisoned_entries_never_block_a_valid_neighbour(self):
        good = (
            "---\nname: Good\ndesc: fine\n---\n"
            "services:\n  a:\n    image: example/a\n"
        ).encode("utf-8")
        manifest = json.dumps({
            "version": 1,
            "templates": [
                {"id": "good-app", "version": "1.0",
                 "sha256": hashlib.sha256(good).hexdigest(),
                 "path": "good-app.yml", "size": None},
                {"id": "s\\ud800x", "version": "1", "sha256": "0" * 64},
            ],
        }).encode("utf-8")
        # Splice a >4300-digit size into the raw JSON: without the parse_int
        # hook the whole sync failed as bad_manifest.
        manifest = manifest.replace(b'"size": null', b'"size": ' + b"9" * 5000)

        def fetch(url, max_bytes):
            if url.endswith("index.json"):
                return manifest
            return good

        with mock.patch.object(catalog_remote, "_fetch", fetch), \
                mock.patch.object(
                    catalog_remote, "source_url",
                    return_value="https://example.invalid/index.json"), \
                mock.patch.object(
                    catalog_remote, "validate_source_url",
                    side_effect=lambda u: u):
            status, text = request("POST", "/api/catalog/remote/check")
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        self.assertEqual(payload["added"], ["good-app"])
        reasons = {r["reason"] for r in payload["rejected"]}
        self.assertIn("bad_id", reasons)
        self.assertTrue((self.remote_dir / "good-app.yml").is_file())
        self.assertNotIn("\ud800", text)


class BodyParseGuardHttpTests(_CatalogSandbox):
    """Hostile request bodies through the real app's parse + 422 handler."""

    def test_huge_int_literal_in_a_body_is_400_not_500(self):
        # json.loads raises the digit-cap ValueError, not JSONDecodeError;
        # FastAPI's body-parse guard must map it to 400.
        status, text = request(
            "POST", "/api/catalog/x/install",
            raw_body=b'{"variables": {"V": ' + b"9" * 5000 + b"}}",
        )
        self.assertEqual(status, 400, text[:300])

    def test_surrogate_escape_in_a_str_field_is_422_with_a_clean_body(self):
        # Pydantic refuses the lone surrogate (string_unicode) and the 422
        # body echoes the input; the stock FastAPI handler 500s on the UTF-8
        # encode — app_factory's sanitizing handler must keep scrubbing it.
        status, text = request(
            "POST", "/api/catalog/remote/restore",
            raw_body=b'{"id": "a\\ud800b"}',
        )
        self.assertEqual(status, 422, text[:300])
        self.assertNotIn("\ud800", text)

    def test_bad_restore_id_is_the_coded_400(self):
        status, text = request(
            "POST", "/api/catalog/remote/restore", body={"id": "no/slash"}
        )
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(
            json.loads(text)["detail"]["code"], "catalog_remote.bad_id"
        )


class InstallSurrogateVariablesHttpTests(_CatalogSandbox):
    """POST install with surrogate escapes in the untyped variables dict."""

    def test_surrogate_values_are_scrubbed_end_to_end(self):
        (self.templates / "app.yml").write_text(
            "---\nname: App\ndesc: d\nvars:\n  - name: V\n    default: dv\n"
            "---\nservices:\n  a:\n    image: e/a\n    environment:\n"
            "      - V={{V}}\n"
        )
        # dict[str, Any] values skip Pydantic's str validation, so the lone
        # surrogate reaches the handler; the install must scrub it before
        # the compose write and the response render.
        status, text = request(
            "POST", "/api/catalog/app/install",
            raw_body=b'{"variables": {"V": "x\\ud800y", "\\ud800k": 1}}',
        )
        self.assertEqual(status, 200, text[:300])
        self.assertNotIn("\ud800", text)
        compose = self.services / "app" / "docker-compose.yml"
        self.assertTrue(compose.is_file())
        self.assertNotIn("\ud800", compose.read_text())


class BootstrapJunkEntryHttpTests(_CatalogSandbox):
    """The fixed leak: junk bootstrap_files entries are dropped, not fatal.

    Fails on the pre-fix tree: bare ``str()`` on the hex-huge path raised
    the digit-cap ValueError, the broad rollback removed the compose file,
    and the body carried CPython's raw ``Exceeds the limit`` prose.
    """

    def setUp(self):
        super().setUp()
        (self.templates / "boot.yml").write_text(
            f"---\nname: Boot\ndesc: d\nbootstrap_files:\n"
            f"  - path: {_HEX_HUGE}\n    content: {_HEX_HUGE}\n"
            f'  - path: "s\\ud800.txt"\n    content: "c\\ud800"\n'
            f"  - path: cfg/app.ini\n    content: \"k={{{{V}}}}\"\n"
            "vars:\n  - name: V\n    default: dv\n---\n"
            "services:\n  a:\n    image: e/a\n"
        )

    def test_unrenderable_entries_cost_themselves_not_the_install(self):
        status, text = request("POST", "/api/catalog/boot/install")
        self.assertEqual(status, 200, text[:300])
        self.assertNotIn("Exceeds the limit", text)
        self.assertNotIn("\ud800", text)
        # The install proceeded: compose written, the sane bootstrap file
        # rendered with its substituted variable.
        dest = self.services / "boot"
        self.assertTrue((dest / "docker-compose.yml").is_file())
        self.assertEqual((dest / "cfg" / "app.ini").read_text(), "k=dv")

    def test_a_leftover_file_blocking_one_parent_dir_is_skipped(self):
        dest = self.services / "boot"
        dest.mkdir()
        # A *file* where the bootstrap entry needs a directory: mkdir raises
        # OSError, which used to escape to the broad rollback.
        (dest / "cfg").write_text("i am a file")
        status, text = request("POST", "/api/catalog/boot/install")
        self.assertEqual(status, 200, text[:300])
        self.assertTrue((dest / "docker-compose.yml").is_file())
        # The blocked entry was skipped; the blocking file is untouched.
        self.assertEqual((dest / "cfg").read_text(), "i am a file")


class EngineDownHttpTests(_CatalogSandbox):
    """Vanished-CLI / engine-down keep their coded shapes on the routes."""

    def setUp(self):
        super().setUp()
        (self.templates / "app.yml").write_text(
            "---\nname: App\ndesc: d\n---\nservices:\n  a:\n    image: e/a\n"
        )
        fake_docker = Path(self._tmp.name) / "docker"
        fake_docker.write_text("#!/bin/sh\n")
        patched = mock.patch.object(catalog, "DOCKER", str(fake_docker))
        patched.start()
        self.addCleanup(patched.stop)

    def _install(self, rc, msg, engine_up):
        with mock.patch.object(catalog, "run_capped", return_value=(rc, msg)), \
                mock.patch.object(
                    catalog, "engine_up", return_value=engine_up
                ) as probe:
            status, text = request("POST", "/api/catalog/app/install")
        return status, text, probe

    def test_install_engine_down_is_the_coded_soft_fail(self):
        status, text, probe = self._install(
            1, "Cannot connect to the Docker daemon", engine_up=False
        )
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["code"], "container.engine_down")
        # The probe is forced: a stale memoised "up" must not reclassify.
        probe.assert_called_once_with(force=True)
        # The compose file is kept for "Apps -> Managed", never rolled back.
        self.assertTrue(
            (self.services / "app" / "docker-compose.yml").is_file()
        )

    def test_install_vanished_cli_sentinel_is_the_same_coded_shape(self):
        status, text, _ = self._install(-1, "not found", engine_up=False)
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["code"], "container.engine_down")

    def test_install_timeout_sentinel_stays_unclassified(self):
        status, text, _ = self._install(-1, "command timed out", engine_up=False)
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        self.assertFalse(payload["ok"])
        self.assertNotIn("code", payload)

    def _installed_stack(self):
        dest = self.services / "app"
        dest.mkdir(exist_ok=True)
        (dest / "docker-compose.yml").write_text("services: {}\n")

    def test_uninstall_engine_down_refuses_with_503(self):
        self._installed_stack()
        with mock.patch.object(
                catalog, "run_capped",
                return_value=(1, "Cannot connect to the Docker daemon")), \
                mock.patch.object(catalog, "engine_up", return_value=False):
            status, text = request(
                "POST", "/api/catalog/app/uninstall", body={"confirm": True}
            )
        self.assertEqual(status, 503, text[:300])
        self.assertEqual(
            json.loads(text)["detail"]["code"], "container.engine_down"
        )
        # Nothing destructive happened: the tree survives for the retry.
        self.assertTrue(
            (self.services / "app" / "docker-compose.yml").is_file()
        )

    def test_uninstall_vanished_cli_refuses_with_503(self):
        self._installed_stack()
        with mock.patch.object(
                catalog, "run_capped", return_value=(-1, "not found")), \
                mock.patch.object(catalog, "engine_up", return_value=False):
            status, text = request(
                "POST", "/api/catalog/app/uninstall", body={"confirm": True}
            )
        self.assertEqual(status, 503, text[:300])
        self.assertEqual(
            json.loads(text)["detail"]["code"], "container.engine_down"
        )


class NativeRouteHttpTests(_CatalogSandbox):
    """native-* ids through the same install route keep their coded errors."""

    def test_unknown_native_app_is_404(self):
        status, text = request("POST", "/api/catalog/native-zzz/install")
        self.assertEqual(status, 404, text[:300])
        self.assertEqual(
            json.loads(text)["detail"]["code"], "catalog.unknown_app"
        )

    def test_missing_brew_is_the_coded_503(self):
        missing = str(Path(self._tmp.name) / "no-such-brew")
        with mock.patch.object(native_catalog, "BREW", missing):
            status, text = request("POST", "/api/catalog/native-htop/install")
        self.assertEqual(status, 503, text[:300])
        self.assertEqual(
            json.loads(text)["detail"]["code"], "catalog.brew_missing"
        )


if __name__ == "__main__":
    unittest.main()
