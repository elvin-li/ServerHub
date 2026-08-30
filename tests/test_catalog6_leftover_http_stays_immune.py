"""Sixth leftover sweep, part two: catalog surfaces that stayed immune.

Everything here already answers the coded shape on the current tree — these
pins keep it that way.  The classes re-probed (all through the mounted app):

* leftover FIFOs occupying catalog paths must neither hang nor 500: a FIFO
  named ``*.yml`` in templates/ (the listing glob has no ``is_file`` gate,
  so ``_parse_template`` reads it — ``read_text_capped``'s O_NONBLOCK +
  S_ISREG probe is what answers EINVAL instead of parking the request until
  a writer appears), a FIFO override in the remote dir, a FIFO at
  state.json, and a FIFO where an installed stack's docker-compose.yml
  should be;
* an oversize (>64 KB) or unreadable template file costs itself, never the
  listing;
* a leftover *file* occupying ~/Services (the services root) degrades
  install to the ok:false dict and uninstall to the coded 404;
* a leftover directory named ``<id>.yml`` in the remote dir is "no such
  override" for restore (Linux raises IsADirectoryError where macOS says
  EPERM — both are the OSError branch) and never lists as an override;
* hostile install ``variables`` values the typed model cannot refuse
  (lists, dicts, huge floats) degrade to their str() forms instead of
  failing the install.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import catalog, catalog_remote, native_catalog
from hub.app_factory import create_app
from hub.auth import require_auth
from hub.routers import catalog as catalog_router

_app = None


def _the_app():
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return _app


async def _asgi_request(method, path, *, body=None):
    """Drive the full panel app (middleware + handlers) through one cycle."""
    app = _the_app()
    payload = b"{}" if body is None else json.dumps(body).encode("utf-8")
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


def request(method, path, *, body=None):
    return asyncio.run(_asgi_request(method, path, body=body))


_SANE = "---\nname: Sane\ndesc: d\n---\nservices:\n  a:\n    image: e/a\n"


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
        patched = mock.patch.object(catalog, "DOCKER", "")
        patched.start()
        self.addCleanup(patched.stop)
        patched = mock.patch.object(catalog.shutil, "which", return_value=None)
        patched.start()
        self.addCleanup(patched.stop)
        for patched in (
            mock.patch.object(catalog_router.auth, "browser_authenticated", return_value=True),
            mock.patch.object(catalog_router.auth, "request_username", return_value="admin"),
            mock.patch.object(catalog_router.auth, "is_admin", return_value=True),
            mock.patch.object(catalog_router.auth, "request_client_id", return_value="127.0.0.1"),
        ):
            patched.start()
            self.addCleanup(patched.stop)


class FifoInCatalogTreesHttpTests(_CatalogSandbox):
    """Leftover FIFOs on every catalog path: no hang, no 500."""

    def setUp(self):
        super().setUp()
        os.mkfifo(self.templates / "fifo.yml")
        (self.templates / "sane.yml").write_text(_SANE)
        os.mkfifo(self.remote_dir / "fifor.yml")
        catalog.invalidate_listing()

    def test_listing_skips_the_fifo_and_keeps_the_sibling(self):
        # No writer is ever attached to the FIFO: a plain open() would park
        # this request forever, so returning at all is half the assertion.
        status, text = request("GET", "/api/catalog/templates")
        self.assertEqual(status, 200, text[:300])
        rows = json.loads(text)["templates"]
        self.assertEqual([r["file"] for r in rows], ["sane.yml"])

    def test_store_overview_keeps_the_docker_half(self):
        with mock.patch.object(
            native_catalog, "list_native_apps", return_value=[]
        ):
            status, text = request("GET", "/api/catalog")
        self.assertEqual(status, 200, text[:300])
        self.assertEqual(json.loads(text)["docker_count"], 1)

    def test_remote_status_never_lists_the_fifo_override(self):
        status, text = request("GET", "/api/catalog/remote")
        self.assertEqual(status, 200, text[:300])
        self.assertEqual(json.loads(text)["overrides"], [])

    def test_fifo_state_json_reads_as_empty_state(self):
        os.mkfifo(self.remote_dir / "state.json.f")
        os.replace(self.remote_dir / "state.json.f", self.remote_dir / "state.json")
        status, text = request("GET", "/api/catalog/remote")
        self.assertEqual(status, 200, text[:300])
        self.assertEqual(json.loads(text)["last_check"], "")

    def test_install_of_the_fifo_template_is_the_coded_404(self):
        status, text = request("POST", "/api/catalog/fifo/install")
        self.assertEqual(status, 404, text[:300])
        self.assertEqual(
            json.loads(text)["detail"]["code"], "catalog.unknown_template"
        )

    def test_uninstall_with_a_fifo_compose_file_never_hangs(self):
        dest = self.services / "sane"
        dest.mkdir()
        os.mkfifo(dest / "docker-compose.yml")
        with mock.patch.object(catalog, "run_capped", return_value=(0, "down ok")), \
                mock.patch.object(catalog, "engine_up", return_value=True):
            status, text = request(
                "POST", "/api/catalog/sane/uninstall", body={"confirm": True}
            )
        self.assertEqual(status, 200, text[:300])
        self.assertTrue(json.loads(text)["ok"])
        self.assertFalse(dest.exists())


class JunkTemplateFilesHttpTests(_CatalogSandbox):
    """Oversize / unreadable template files cost themselves, not the listing."""

    def setUp(self):
        super().setUp()
        (self.templates / "sane.yml").write_text(_SANE)

    def test_oversize_template_is_skipped(self):
        (self.templates / "big.yml").write_text("#" + "x" * (70 * 1024))
        catalog.invalidate_listing()
        status, text = request("GET", "/api/catalog/templates")
        self.assertEqual(status, 200, text[:300])
        rows = json.loads(text)["templates"]
        self.assertEqual([r["file"] for r in rows], ["sane.yml"])

    @unittest.skipIf(os.geteuid() == 0, "chmod 0 does not bind root")
    def test_unreadable_template_is_skipped(self):
        p = self.templates / "noperm.yml"
        p.write_text(_SANE)
        os.chmod(p, 0)
        self.addCleanup(os.chmod, p, 0o644)
        catalog.invalidate_listing()
        status, text = request("GET", "/api/catalog/templates")
        self.assertEqual(status, 200, text[:300])
        rows = json.loads(text)["templates"]
        self.assertEqual([r["file"] for r in rows], ["sane.yml"])


class ServicesRootBlockedHttpTests(_CatalogSandbox):
    """A leftover *file* occupying ~/Services keeps the coded shapes."""

    def setUp(self):
        super().setUp()
        (self.templates / "sane.yml").write_text(_SANE)
        blocked = Path(self._tmp.name) / "services-file"
        blocked.write_text("i am a file")
        patched = mock.patch.object(catalog, "SERVICES_ROOT", blocked)
        patched.start()
        self.addCleanup(patched.stop)
        self.blocked = blocked
        catalog.invalidate_listing()

    def test_listing_still_renders(self):
        status, text = request("GET", "/api/catalog/templates")
        self.assertEqual(status, 200, text[:300])
        rows = json.loads(text)["templates"]
        self.assertEqual([r["installed"] for r in rows], [False])

    def test_install_degrades_to_the_ok_false_dict(self):
        status, text = request("POST", "/api/catalog/sane/install")
        self.assertEqual(status, 200, text[:300])
        self.assertFalse(json.loads(text)["ok"])
        # The blocking file is never deleted on the panel's behalf.
        self.assertEqual(self.blocked.read_text(), "i am a file")

    def test_uninstall_is_the_coded_404(self):
        status, text = request(
            "POST", "/api/catalog/sane/uninstall", body={"confirm": True}
        )
        self.assertEqual(status, 404, text[:300])
        self.assertEqual(
            json.loads(text)["detail"]["code"], "catalog.not_installed"
        )


class DirectoryOverrideHttpTests(_CatalogSandbox):
    """A leftover directory named <id>.yml is not an override."""

    def setUp(self):
        super().setUp()
        (self.remote_dir / "dirov.yml").mkdir()

    def test_restore_is_the_coded_404(self):
        # Linux raises IsADirectoryError where macOS raises EPERM; both must
        # land in the OSError branch, never a raw 500.
        status, text = request(
            "POST", "/api/catalog/remote/restore", body={"id": "dirov"}
        )
        self.assertEqual(status, 404, text[:300])
        self.assertEqual(
            json.loads(text)["detail"]["code"], "catalog_remote.not_remote"
        )
        self.assertTrue((self.remote_dir / "dirov.yml").is_dir())

    def test_status_never_lists_the_directory(self):
        status, text = request("GET", "/api/catalog/remote")
        self.assertEqual(status, 200, text[:300])
        self.assertEqual(json.loads(text)["overrides"], [])


class HostileInstallVariablesHttpTests(_CatalogSandbox):
    """Untyped ``variables`` values Pydantic cannot refuse degrade, not 500."""

    def setUp(self):
        super().setUp()
        (self.templates / "vars.yml").write_text(
            "---\nname: V\ndesc: d\nvars:\n  - name: V\n    default: dv\n"
            "---\nservices:\n  a:\n    image: e/a\n    environment:\n"
            "      - V={{V}}\n"
        )
        catalog.invalidate_listing()

    def _install(self, variables):
        status, text = request(
            "POST", "/api/catalog/vars/install", body={"variables": variables}
        )
        self.addCleanup(
            shutil.rmtree, self.services / "vars", ignore_errors=True
        )
        return status, text

    def test_container_values_degrade_to_their_str_forms(self):
        for label, variables in (
            ("list", {"V": ["a", "b"]}),
            ("dict", {"V": {"a": 1}}),
            ("hugefloat", {"V": 1e308}),
        ):
            with self.subTest(label=label):
                status, text = self._install(variables)
                self.assertEqual(status, 200, f"{label}: {text[:300]}")
                self.assertTrue(
                    (self.services / "vars" / "docker-compose.yml").is_file()
                )
                shutil.rmtree(self.services / "vars", ignore_errors=True)
                catalog.invalidate_listing()

    def test_newline_value_is_the_coded_injection_refusal(self):
        status, text = self._install({"V": "a\nprivileged: true"})
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(
            json.loads(text)["detail"]["code"], "catalog.bad_var_value"
        )


if __name__ == "__main__":
    unittest.main()
