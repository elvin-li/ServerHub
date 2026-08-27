"""Tenth leftover sweep, part two: catalog_remote corners that stayed immune.

Beyond the one live 500 this sweep found (the ``__class__``-property-bomb
native row at the store-overview merge gate, fixed and pinned in
``test_catalog10_leftover_native_row_class_bomb_500``), the ``catalog_remote``
check / staging / ``state.json`` surfaces were replayed over the real mounted
app — ``create_app()`` + ``TestClient(raise_server_exceptions=False)`` — and
held.  These pins cover the ``state.json`` corners no prior wave pinned:

* **``state.json`` occupied by a FIFO** — the read side is ``read_text_capped``
  (O_NONBLOCK, refuse non-regular), so ``_load_state`` degrades to ``{}``
  instead of parking on the ``open`` until a writer appears; the write side is
  ``replace_secret_text`` (tmp + ``os.replace``), which never opens the
  squatting node and atomically swaps it out.  A sync over a FIFO ``state.json``
  answers ``ok: true`` promptly (watchdogged against a hang) and leaves a real
  file behind.  GET /api/catalog/remote reads the empty state as 200.
* **``state.json`` occupied by a non-empty directory** — the same read degrades
  to ``{}`` (200 status), and the write's ``os.replace`` onto a directory is
  the coded 503 ``catalog_remote.write_failed`` that every other blocked write
  in the module already reports — never a raw ``IsADirectoryError`` 500.

The sunny-day control is kept alongside so the pins cannot pass by accident.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import threading
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import catalog, catalog_remote  # noqa: E402
from hub.routers import catalog as catalog_router  # noqa: E402

_WATCHDOG_SECS = 15.0

_app = None
_client = None


def _the_client():
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
        self.state_path = self.remote_dir / "state.json"
        catalog.invalidate_listing()
        self.addCleanup(catalog.invalidate_listing)
        for module, name, value in (
            (catalog, "TEMPLATES", self.templates),
            (catalog, "SERVICES_ROOT", self.services),
            (catalog_remote, "REMOTE_DIR", self.remote_dir),
            (catalog_remote, "STATE_PATH", self.state_path),
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
        self.stack.enter_context(
            mock.patch.object(
                catalog_remote, "source_url",
                lambda: "https://example.com/index.json",
            )
        )
        self.client = _the_client()

    def request_watchdogged(self, method: str, url: str, **kw):
        result: dict = {}

        def run():
            result["r"] = self.client.request(method, url, **kw)

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        worker.join(timeout=_WATCHDOG_SECS)
        if worker.is_alive():
            self.fail(f"{method} {url} parked past the watchdog")
        return result["r"]


class StateJsonSquatterTests(_CatalogSandbox):
    """A leftover node occupying state.json never 500s or hangs the surface."""

    def test_fifo_state_json_syncs_promptly_and_is_swapped_out(self):
        os.mkfifo(self.state_path)
        with mock.patch.object(catalog_remote, "_fetch", _fake_fetch):
            status = self.request_watchdogged("GET", "/api/catalog/remote")
            self.assertEqual(status.status_code, 200, status.text[:300])
            status.content.decode("utf-8")
            check = self.request_watchdogged("POST", "/api/catalog/remote/check")
        self.assertEqual(check.status_code, 200, check.text[:300])
        self.assertTrue(check.json()["ok"])
        # The tmp+os.replace write swapped the FIFO out for a real file.
        self.assertTrue(self.state_path.is_file())
        json.loads(self.state_path.read_text(encoding="utf-8"))

    def test_directory_state_json_is_the_coded_503(self):
        self.state_path.mkdir()
        (self.state_path / "keep").write_text("x", encoding="utf-8")
        with mock.patch.object(catalog_remote, "_fetch", _fake_fetch):
            status = self.client.get("/api/catalog/remote")
            self.assertEqual(status.status_code, 200, status.text[:300])
            check = self.client.post("/api/catalog/remote/check")
        self.assertEqual(check.status_code, 503, check.text[:300])
        self.assertEqual(
            check.json()["detail"]["code"], "catalog_remote.write_failed"
        )
        # The squatting directory is untouched: nothing half-landed.
        self.assertTrue(self.state_path.is_dir())

    def test_control_clean_state_json_sync(self):
        with mock.patch.object(catalog_remote, "_fetch", _fake_fetch):
            check = self.client.post("/api/catalog/remote/check")
        self.assertEqual(check.status_code, 200, check.text[:300])
        self.assertTrue(check.json()["ok"])
        self.assertTrue(self.state_path.is_file())


if __name__ == "__main__":
    unittest.main()
