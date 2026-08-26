"""Sixth leftover-500s sweep of the Apps catalog surface, over the real app.

One live leak class was found and fixed: ``http.client.InvalidURL`` is a
subclass of ``http.client.HTTPException`` — which is **neither OSError nor
ValueError** — so it escaped ``catalog_remote._fetch``'s catch tuple
(``URLError, OSError, ValueError``) and surfaced as a raw 500:

* ``validate_source_url`` never re-parsed the port and never vetted the
  hostname's charset, so PUT /api/catalog/remote happily persisted
  ``https://[::1]:x`` (nonnumeric port), ``https://exa mple.com/x`` (space
  in the host) and ``https://example.com%00/x`` (urllib.request *unquotes*
  the host before connecting, smuggling the NUL past urlsplit) — and every
  POST /api/catalog/remote/check after that raised InvalidURL out of
  ``urlopen`` as a raw 500, repeatedly, until the operator somehow guessed
  to clear the stored source;
* the same class applied per manifest entry: an entry ``path`` carrying a
  space resolved to a file URL the per-entry ``_fetch`` raised InvalidURL
  on, failing the *whole* sync instead of costing only itself as the
  documented per-entry ``fetch_failed`` rejection (the exact contract
  catalog5 pinned for the torn-IPv6 ``urljoin`` sibling).

Also aligned in the same sweep: ``catalog_remote.write_failed`` was a coded
*500*; a blocked remote-catalog directory is a dependency state, so it is
now the 503 every sibling could-not-write-the-disk code uses
(settings.save_failed, compose.save_failed, cloudflared.plist_write_failed).

Every HTTP test drives the full mounted app (``create_app()``), so request
routing, the security middleware, the sanitizing handlers and Starlette's
strict UTF-8 render are all on the hook.  With the fix stashed, the check
tests raise InvalidURL instead of answering the coded shapes.
"""
from __future__ import annotations

import asyncio
import hashlib
import http.client
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import catalog, catalog_remote
from hub.app_factory import create_app
from hub.auth import require_auth
from hub.errors import CODES
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


#: URLs urlsplit accepts but http.client's InvalidURL refuses at fetch time.
_INVALIDURL_SOURCES = (
    "https://[::1]:x/index.json",       # nonnumeric port
    "https://exa mple.com/index.json",  # space in the host
    "https://example.com%00/x",         # %00 the opener unquotes into the host
    "https://example.com:-1/x",         # out-of-range port
    "https://example.com:99999999999999999999/x",  # over-65535 port
)


class SourceUrlInvalidUrlHttpTests(_CatalogSandbox):
    """PUT /api/catalog/remote: what InvalidURL would choke on is a coded 400."""

    def test_hostile_sources_are_the_coded_400_and_never_persist(self):
        for url in _INVALIDURL_SOURCES:
            with self.subTest(url=url), \
                    mock.patch("hub.config.update_settings") as save:
                status, text = request(
                    "PUT", "/api/catalog/remote", body={"url": url}
                )
                self.assertEqual(status, 400, f"{url}: {text[:300]}")
                self.assertEqual(
                    json.loads(text)["detail"]["code"], "catalog_remote.bad_url"
                )
                # The refusal happened before anything was persisted: the
                # pre-fix tree stored the URL and every later check 500'd.
                save.assert_not_called()

    def test_sane_urls_with_ports_still_validate_unchanged(self):
        # Service-level round trip so the sandbox config is not persisted.
        for url in (
            "https://example.com/catalog/index.json",
            "https://example.com:8443/index.json",
            "https://[2001:db8::1]:8443/index.json",
        ):
            self.assertEqual(catalog_remote.validate_source_url(url), url)


class CheckWithStoredHostileUrlHttpTests(_CatalogSandbox):
    """POST /api/catalog/remote/check: a hand-edited stored URL cannot 500."""

    def test_stored_hostile_urls_are_the_coded_400(self):
        # services.yaml is hand-editable; the stored URL is re-validated on
        # every check and used to raise InvalidURL out of the live fetch.
        for url in _INVALIDURL_SOURCES:
            with self.subTest(url=url), mock.patch.object(
                catalog_remote, "source_url", return_value=url
            ):
                status, text = request("POST", "/api/catalog/remote/check")
                self.assertEqual(status, 400, f"{url}: {text[:300]}")
                self.assertEqual(
                    json.loads(text)["detail"]["code"], "catalog_remote.bad_url"
                )


class _Resp(io.BytesIO):
    """Minimal urlopen response: context manager + capped read."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _InvalidUrlOpener:
    """Serve the manifest; raise InvalidURL for any URL carrying a space."""

    def __init__(self, manifest: bytes, blob: bytes):
        self.manifest = manifest
        self.blob = blob

    def open(self, req, timeout=None):
        url = req.full_url
        if url.endswith("index.json"):
            return _Resp(self.manifest)
        if " " in url:
            # What http.client's putrequest/_validate_host raise for control
            # bytes in the request target — before any packet is sent.
            raise http.client.InvalidURL(
                f"URL can't contain control characters. {url!r}"
            )
        return _Resp(self.blob)


class FetchInvalidUrlSeamHttpTests(_CatalogSandbox):
    """InvalidURL raised inside the *real* ``_fetch`` keeps the coded shapes."""

    def test_invalidurl_is_not_oserror_or_valueerror(self):
        # The assumption the fix rests on: without the explicit
        # http.client.HTTPException catch, nothing else in the tuple takes it.
        self.assertFalse(issubclass(http.client.InvalidURL, OSError))
        self.assertFalse(issubclass(http.client.InvalidURL, ValueError))

    def test_manifest_fetch_invalidurl_is_the_coded_502(self):
        class Boom:
            def open(self, req, timeout=None):
                raise http.client.InvalidURL("nonnumeric port: 'x'")

        with mock.patch.object(catalog_remote, "_opener", Boom()), \
                mock.patch.object(
                    catalog_remote, "source_url",
                    return_value="https://example.invalid/index.json"), \
                mock.patch.object(
                    catalog_remote, "validate_source_url",
                    side_effect=lambda u: u):
            status, text = request("POST", "/api/catalog/remote/check")
        self.assertEqual(status, 502, text[:300])
        payload = json.loads(text)["detail"]
        self.assertEqual(payload["code"], "catalog_remote.fetch_failed")
        self.assertIn("nonnumeric port", payload["message"])

    def test_entry_path_invalidurl_costs_that_entry_not_the_sync(self):
        good = (
            "---\nname: Good\ndesc: fine\n---\n"
            "services:\n  a:\n    image: example/a\n"
        ).encode("utf-8")
        manifest = json.dumps({
            "version": 1,
            "templates": [
                {"id": "evil", "version": "1", "sha256": "0" * 64,
                 "path": "x y.yml"},
                {"id": "good-app", "version": "1.0",
                 "sha256": hashlib.sha256(good).hexdigest(),
                 "path": "good-app.yml"},
            ],
        }).encode("utf-8")

        with mock.patch.object(
                catalog_remote, "_opener", _InvalidUrlOpener(manifest, good)), \
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
        # fetch_failed rejection instead of failing the whole sync.
        self.assertEqual(payload["added"], ["good-app"])
        rejected = {r["id"]: r["reason"] for r in payload["rejected"]}
        self.assertEqual(
            rejected.get("evil"), catalog_remote.REJECT_FETCH_FAILED
        )
        self.assertTrue((self.remote_dir / "good-app.yml").is_file())
        self.assertFalse((self.remote_dir / "evil.yml").exists())


class WriteFailedIsDependency503Tests(_CatalogSandbox):
    """A blocked remote-catalog dir is the 503 dependency shape, not a 500."""

    def test_code_registration_matches_the_sibling_convention(self):
        self.assertEqual(CODES["catalog_remote.write_failed"][0], 503)
        # The siblings it is aligned with.
        self.assertEqual(CODES["settings.save_failed"][0], 503)
        self.assertEqual(CODES["compose.save_failed"][0], 503)
        self.assertEqual(CODES["cloudflared.plist_write_failed"][0], 503)

    def test_leftover_file_as_remote_dir_is_503_on_the_route(self):
        blocked = Path(self._tmp.name) / "blocked-remote"
        blocked.write_text("i am a file")

        def fetch(url, max_bytes):
            return json.dumps({"version": 1, "templates": []}).encode()

        with mock.patch.object(catalog_remote, "REMOTE_DIR", blocked), \
                mock.patch.object(
                    catalog_remote, "STATE_PATH", blocked / "state.json"), \
                mock.patch.object(catalog_remote, "_fetch", fetch), \
                mock.patch.object(
                    catalog_remote, "source_url",
                    return_value="https://example.invalid/index.json"), \
                mock.patch.object(
                    catalog_remote, "validate_source_url",
                    side_effect=lambda u: u):
            status, text = request("POST", "/api/catalog/remote/check")
        self.assertEqual(status, 503, text[:300])
        self.assertEqual(
            json.loads(text)["detail"]["code"], "catalog_remote.write_failed"
        )
        # The blocking file survives untouched for the operator to inspect.
        self.assertEqual(blocked.read_text(), "i am a file")


if __name__ == "__main__":
    unittest.main()
