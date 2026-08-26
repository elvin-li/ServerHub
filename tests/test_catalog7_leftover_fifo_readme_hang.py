"""Seventh leftover-500s sweep of the Apps catalog surface: one live hang.

The live leftover
=================
``install_template`` never removes a pre-existing ``~/Services/<id>/`` (it
may hold user data), so a **leftover FIFO occupying README.serverhub.md** in
a pre-seeded install directory survived up to the README step — which was a
bare ``Path.write_text``.  A plain ``open(..., "w")`` of a FIFO parks until a
reader appears, so POST /api/catalog/{id}/install hung *forever* after the
compose file, the data dirs, ``.serverhub-vars.json`` and the stack
registration had already landed: no response, no timeout, one worker gone.
Reproduced over ``create_app()`` + ``TestClient(raise_server_exceptions=
False)`` — the request thread stayed parked past any deadline until a reader
opened the FIFO's other end.

The fix routes the README through ``secure_io.replace_bytes`` (tmp file +
``os.replace``), which never opens the squatting node and atomically swaps
the FIFO out for the real README.  A leftover non-empty *directory* by that
name still refuses ``os.replace`` — that OSError now costs only the advisory
README (the same convention as the ``bootstrap_files`` loop), never the
install the operator's filled-in variables and minted passwords are riding
on.

What stays pinned besides the fix
=================================
* A clean install still writes the same README: title, redacted-variables
  block, 0644-class regular file.
* The FIFO case answers within the watchdog window and the response carries
  the normal missing-CLI shape (``stack_id`` set, compose path written) —
  the hang, not the payload, was the defect.
"""
from __future__ import annotations

import json
import os
import shutil
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

#: Generous versus the fixed path (<1s here) and far below the forever the
#: pre-fix open() parked for.
_WATCHDOG_SECS = 15.0


class _CatalogSandbox(unittest.TestCase):
    """Real app over TestClient; template/services/remote dirs in a temp tree."""

    def setUp(self):
        from fastapi.testclient import TestClient

        from hub.app_factory import create_app
        from hub.auth import require_auth

        self.stack = ExitStack()
        self.addCleanup(self.stack.close)

        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        tmp = Path(self._tmp.name)
        self.templates = tmp / "templates"
        self.templates.mkdir()
        self.services = tmp / "services"
        self.services.mkdir()
        remote = tmp / "catalog-remote"
        remote.mkdir()

        catalog.invalidate_listing()
        self.addCleanup(catalog.invalidate_listing)
        for module, name, value in (
            (catalog, "TEMPLATES", self.templates),
            (catalog, "SERVICES_ROOT", self.services),
            (catalog_remote, "REMOTE_DIR", remote),
            (catalog_remote, "STATE_PATH", remote / "state.json"),
            # Deterministic missing-CLI outcome on any host: the README is
            # written before the docker spawn either way.
            (catalog, "DOCKER", ""),
        ):
            self.stack.enter_context(mock.patch.object(module, name, value))
        self.stack.enter_context(
            mock.patch.object(catalog.shutil, "which", lambda *_a, **_k: None)
        )
        # Keep the shared per-run services.yaml free of sandbox stack rows.
        self.stack.enter_context(
            mock.patch.object(catalog, "_register_stack", lambda *a, **k: None)
        )
        self.stack.enter_context(
            mock.patch.object(catalog, "_unregister_stack", lambda *a, **k: None)
        )

        app = create_app()
        app.dependency_overrides[require_auth] = lambda: None
        self.addCleanup(app.dependency_overrides.clear)
        self.client = TestClient(app, raise_server_exceptions=False)

        (self.templates / "app.yml").write_text(
            "---\nname: App\ndesc: demo\n---\n"
            "services:\n  a:\n    image: example/app\n",
            encoding="utf-8",
        )

    def _install_with_watchdog(self, fifo: Path | None = None):
        """POST install; fail (instead of wedging the suite) if it parks."""
        result: dict = {}

        def run():
            result["r"] = self.client.post(
                "/api/catalog/app/install", json={"variables": {}}
            )

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        worker.join(timeout=_WATCHDOG_SECS)
        if worker.is_alive():
            if fifo is not None:
                # Release the parked writer so the suite does not leak a
                # wedged thread: opening the read end un-blocks open(..., "w").
                try:
                    rd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
                    os.close(rd)
                except OSError:
                    pass
                worker.join(timeout=5)
            self.fail(
                "POST /api/catalog/app/install parked past the watchdog — "
                "the leftover FIFO at README.serverhub.md is hanging installs"
            )
        return result["r"]


class FifoReadmeHangTests(_CatalogSandbox):
    """A FIFO squatting README.serverhub.md must not park the install."""

    def test_install_with_fifo_readme_answers_promptly(self):
        dest = self.services / "app"
        dest.mkdir()
        fifo = dest / "README.serverhub.md"
        os.mkfifo(fifo)

        resp = self._install_with_watchdog(fifo=fifo)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = resp.json()
        # Normal missing-CLI shape: files on disk, stack startable later.
        self.assertEqual(payload.get("stack_id"), "app")
        self.assertTrue((dest / "docker-compose.yml").is_file())
        # The squatting FIFO was atomically swapped for the real README.
        self.assertTrue(fifo.is_file())
        text = fifo.read_text(encoding="utf-8")
        self.assertIn("# App", text)
        self.assertIn("Variables (secrets redacted)", text)

    def test_leftover_readme_directory_costs_only_the_readme(self):
        dest = self.services / "app"
        dest.mkdir()
        squatter = dest / "README.serverhub.md"
        squatter.mkdir()
        (squatter / "occupant").write_text("keep me", encoding="utf-8")

        resp = self._install_with_watchdog()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = resp.json()
        # The install itself landed — no rollback over advisory documentation.
        self.assertEqual(payload.get("stack_id"), "app")
        self.assertTrue((dest / "docker-compose.yml").is_file())
        self.assertTrue((dest / ".serverhub-vars.json").is_file())
        # The operator's leftover directory survives untouched.
        self.assertTrue(squatter.is_dir())
        self.assertEqual(
            (squatter / "occupant").read_text(encoding="utf-8"), "keep me"
        )
        # No orphaned staging file left beside it.
        leftovers = [p.name for p in dest.iterdir() if p.name.endswith(".tmp")]
        self.assertEqual(leftovers, [])

    def test_clean_install_still_writes_the_readme(self):
        resp = self._install_with_watchdog()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        readme = self.services / "app" / "README.serverhub.md"
        self.assertTrue(readme.is_file())
        text = readme.read_text(encoding="utf-8")
        self.assertIn("# App", text)
        self.assertIn("demo", text)
        self.assertIn("## Variables (secrets redacted)", text)
        # Valid JSON travels inside the fenced block.
        block = text.split("```json", 1)[1].split("```", 1)[0]
        self.assertIsInstance(json.loads(block), dict)

    def tearDown(self):
        shutil.rmtree(self.services, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
