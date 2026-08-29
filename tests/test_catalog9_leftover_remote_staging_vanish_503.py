"""Ninth leftover-500s sweep of the Apps catalog surface: one live 500.

The live leftover
=================
``catalog_remote.check_updates`` creates its staging directory with a bare
``tempfile.mkdtemp(prefix=".staging-", dir=REMOTE_DIR)`` — the one write in
the module with no OSError guard.  ``_ensure_dir()`` answers fine one call
earlier, but the staging mkdtemp is a *second* write into REMOTE_DIR: a
remote dir that vanishes in between (a concurrent cleanup, an operator's
``rm -rf`` of data/, a dying FUSE/SMB mount answering EIO) used to raise the
raw OSError out of POST /api/catalog/remote/check as an uncoded HTTP 500 —
reproduced over ``create_app()`` + ``TestClient(raise_server_exceptions=
False)`` — while every neighbouring write in the module (``_ensure_dir``,
``_save_state``, the per-template ``replace_secret_text``) already degrades
to the coded 503 ``catalog_remote.write_failed`` that names the dependency.

The fix wraps the mkdtemp in the same coded 503.  Nothing was fetched into
place and state.json was not rewritten, so the operator retries once the
directory is back — the settings.save_failed / compose.save_failed shape.

The control test keeps the sunny day pinned: with the directory present the
same sync still lands the override on disk and answers ``ok: true``.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import catalog, catalog_remote, config  # noqa: E402
from hub.routers import catalog as catalog_router  # noqa: E402

_app = None
_client = None


def _the_client():
    """One app for the module: create_app() is expensive and stateless here."""
    global _app, _client
    if _client is None:
        from fastapi.testclient import TestClient

        from hub.app_factory import create_app
        from hub.auth import require_auth

        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
        _client = TestClient(_app, raise_server_exceptions=False)
    return _client


_GOOD_TPL = "---\nname: R\ndesc: d\n---\nservices:\n  a:\n    image: x\n"
_GOOD_SHA = hashlib.sha256(_GOOD_TPL.encode("utf-8")).hexdigest()
_MANIFEST = json.dumps(
    {"templates": [{"id": "zt", "sha256": _GOOD_SHA, "version": "1"}]}
).encode("utf-8")


def _fake_fetch(url, max_bytes):
    return _MANIFEST if "index" in url else _GOOD_TPL.encode("utf-8")


class _CatalogSandbox(unittest.TestCase):
    """Template dir + services root + remote dir in a per-test temp tree,
    with services.yaml saved/restored so the stored source URL is per-test."""

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
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
            self.stack.enter_context(mock.patch.object(module, name, value))
        for name, value in (
            ("browser_authenticated", lambda request: True),
            ("request_username", lambda request: "admin"),
            ("is_admin", lambda username: True),
            ("request_client_id", lambda request: "127.0.0.1"),
        ):
            self.stack.enter_context(
                mock.patch.object(catalog_router.auth, name, value)
            )
        yaml_path = config.YAML_PATH
        saved = yaml_path.read_bytes() if yaml_path.is_file() else None

        def restore():
            if saved is None:
                try:
                    yaml_path.unlink()
                except OSError:
                    pass
            else:
                yaml_path.write_bytes(saved)
            config.reload_cfg()

        self.addCleanup(restore)
        self.client = _the_client()
        resp = self.client.put(
            "/api/catalog/remote", json={"url": "https://example.com/index.json"}
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])


class RemoteStagingVanishTests(_CatalogSandbox):
    """The staging mkdtemp answers the coded 503, never the raw OSError 500."""

    def test_vanished_remote_dir_is_coded_503(self):
        # The dir vanishes while the manifest is being processed: the state
        # read sits between _ensure_dir() and the staging mkdtemp, so a
        # side-effecting wrapper plays the concurrent cleanup deterministically.
        real_load = catalog_remote._load_state

        def racing_load_state():
            out = real_load()
            shutil.rmtree(self.remote_dir, ignore_errors=True)
            return out

        with mock.patch.object(catalog_remote, "_fetch", _fake_fetch), \
                mock.patch.object(catalog_remote, "_load_state", racing_load_state):
            resp = self.client.post("/api/catalog/remote/check")
        self.assertEqual(resp.status_code, 503, resp.text[:300])
        self.assertEqual(
            resp.json()["detail"]["code"], "catalog_remote.write_failed"
        )
        # Nothing half-landed: no override file, no rewritten state.json.
        self.assertFalse(self.remote_dir.exists())

    def test_dying_mount_eio_is_the_same_coded_503(self):
        def eio_mkdtemp(*a, **k):
            raise OSError(5, "Input/output error")

        with mock.patch.object(catalog_remote, "_fetch", _fake_fetch), \
                mock.patch.object(
                    catalog_remote.tempfile, "mkdtemp", eio_mkdtemp
                ):
            resp = self.client.post("/api/catalog/remote/check")
        self.assertEqual(resp.status_code, 503, resp.text[:300])
        self.assertEqual(
            resp.json()["detail"]["code"], "catalog_remote.write_failed"
        )

    def test_control_clean_sync_still_lands_the_override(self):
        with mock.patch.object(catalog_remote, "_fetch", _fake_fetch):
            resp = self.client.post("/api/catalog/remote/check")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["added"], ["zt"])
        self.assertTrue((self.remote_dir / "zt.yml").is_file())
        # No staging litter left behind either way.
        self.assertEqual(list(self.remote_dir.glob(".staging-*")), [])


if __name__ == "__main__":
    unittest.main()
