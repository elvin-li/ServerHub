"""Fifth leftover-500s sweep of the Apps catalog surface, over the real app.

One live leak was found and fixed: ``urllib.parse.urlsplit`` (and ``urljoin``,
which calls it) raises ``ValueError: Invalid IPv6 URL`` whenever a ``[``
lands in the netloc without a matching bracket — ``https://[boo``,
``https://x@[`` — and ``catalog_remote`` called both unguarded:

* ``validate_source_url`` split the operator's URL before any vetting, so a
  pasted ``https://[boo`` escaped PUT /api/catalog/remote as a raw 500
  instead of the coded ``catalog_remote.bad_url`` 400 every other junk URL
  earns, and a hand-edited services.yaml carrying the same string 500'd
  POST /api/catalog/remote/check before the fetch even started;
* ``_entry_url`` joined each manifest entry's ``path`` against the index URL,
  so one hostile entry (``"path": "//[boo/x.yml"``) failed the *whole* sync —
  the documented contract is that a bad entry costs only itself, as the
  per-entry ``bad_url`` rejection.

Every test here drives the full mounted app (``create_app()``), so request
routing, the security middleware, the sanitizing handlers and Starlette's
strict UTF-8 render are all on the hook.  With the fix stashed, the PUT and
check tests raise the ValueError instead of answering the coded shapes.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import catalog, catalog_remote
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
        for patched in (
            mock.patch.object(catalog_router.auth, "browser_authenticated", return_value=True),
            mock.patch.object(catalog_router.auth, "request_username", return_value="admin"),
            mock.patch.object(catalog_router.auth, "is_admin", return_value=True),
            mock.patch.object(catalog_router.auth, "request_client_id", return_value="127.0.0.1"),
        ):
            patched.start()
            self.addCleanup(patched.stop)


class SourceUrlUnsplittableHttpTests(_CatalogSandbox):
    """PUT /api/catalog/remote: an unsplittable URL is the coded 400."""

    def test_lone_bracket_host_is_the_coded_bad_url(self):
        # urlsplit raises "Invalid IPv6 URL" before any vetting ran; the
        # route used to escape it as a raw 500.
        with mock.patch("hub.config.update_settings") as save:
            status, text = request(
                "PUT", "/api/catalog/remote", body={"url": "https://[boo"}
            )
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(
            json.loads(text)["detail"]["code"], "catalog_remote.bad_url"
        )
        # The refusal happened before anything was persisted.
        save.assert_not_called()

    def test_credentialed_bracket_host_is_the_same_coded_400(self):
        status, text = request(
            "PUT", "/api/catalog/remote", body={"url": "https://x@["}
        )
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(
            json.loads(text)["detail"]["code"], "catalog_remote.bad_url"
        )

    def test_a_sane_url_still_validates_unchanged(self):
        # Service-level round trip so the sandbox config is not persisted.
        url = "https://example.com/catalog/index.json"
        self.assertEqual(catalog_remote.validate_source_url(url), url)


class CheckWithStoredJunkUrlHttpTests(_CatalogSandbox):
    """POST /api/catalog/remote/check: a hand-edited stored URL cannot 500."""

    def test_stored_unsplittable_url_is_the_coded_400(self):
        # services.yaml is hand-editable; the stored URL is re-validated on
        # every check and used to raise the same ValueError before _fetch.
        with mock.patch.object(
            catalog_remote, "source_url",
            return_value="https://[boo/index.json",
        ):
            status, text = request("POST", "/api/catalog/remote/check")
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(
            json.loads(text)["detail"]["code"], "catalog_remote.bad_url"
        )


class ManifestEntryUnjoinableHttpTests(_CatalogSandbox):
    """One unjoinable manifest entry costs that entry, never the sync."""

    def test_bracket_path_entry_is_rejected_not_fatal(self):
        good = (
            "---\nname: Good\ndesc: fine\n---\n"
            "services:\n  a:\n    image: example/a\n"
        ).encode("utf-8")
        manifest = json.dumps({
            "version": 1,
            "templates": [
                {"id": "evil", "version": "1", "sha256": "0" * 64,
                 "path": "//[boo/x.yml"},
                {"id": "good-app", "version": "1.0",
                 "sha256": hashlib.sha256(good).hexdigest(),
                 "path": "good-app.yml"},
            ],
        }).encode("utf-8")

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
        # The sane neighbour synced; the hostile entry earned the per-entry
        # bad_url rejection instead of failing the whole sync.
        self.assertEqual(payload["added"], ["good-app"])
        rejected = {r["id"]: r["reason"] for r in payload["rejected"]}
        self.assertEqual(rejected.get("evil"), catalog_remote.REJECT_BAD_URL)
        self.assertTrue((self.remote_dir / "good-app.yml").is_file())
        self.assertFalse((self.remote_dir / "evil.yml").exists())


class EntryUrlSeamTests(unittest.TestCase):
    """The seam itself: _entry_url answers "" for what urlsplit refuses."""

    def test_unjoinable_rel_is_empty(self):
        self.assertEqual(
            catalog_remote._entry_url(
                "https://example.com/index.json", {"path": "//[boo/x.yml"}
            ),
            "",
        )

    def test_sane_rel_still_resolves_on_origin(self):
        self.assertEqual(
            catalog_remote._entry_url(
                "https://example.com/cat/index.json", {"path": "jellyfin.yml"}
            ),
            "https://example.com/cat/jellyfin.yml",
        )


if __name__ == "__main__":
    unittest.main()
