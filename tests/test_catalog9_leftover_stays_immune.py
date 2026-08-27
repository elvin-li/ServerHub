"""Ninth leftover sweep, part two: catalog surfaces that stayed immune.

Beyond the one live 500 this sweep found (the vanished-remote-dir staging
mkdtemp, fixed and pinned in ``test_catalog9_leftover_remote_staging_vanish_
503``), the remaining leftover zoo was replayed over the real mounted app —
``create_app()`` + ``TestClient(raise_server_exceptions=False)`` — and the
catalog / install / README surfaces held.  These pins cover the corners no
prior wave pinned:

* **Pre-seeded install squatter zoo** — install never removes a pre-existing
  ``~/Services/<id>/``, so leftovers survive to every write the install
  makes.  The catalog7 FIFO-README hang is pinned elsewhere; its siblings
  are pinned here: the dest path occupied by a *file*, ``data/`` occupied by
  a file, ``.serverhub-vars.json`` occupied by a FIFO (the tmp+os.replace
  write swaps it out without opening it — no parked worker) or by a
  non-empty directory, and ``docker-compose.yml`` squatted by a FIFO or a
  directory (both read as installed → the coded 409, never an IsADirectory /
  parked open).
* **Filesystem-exotic template nodes** — a builtin template file whose *name*
  carries surrogateescape bytes (the override twin is pinned in the digit
  sweep; the builtin listing was not), and a self-referencing symlink named
  ``*.yml`` — both listings stay 200 with a strictly-UTF-8 body.
* **Manifest entry-shape zoo** — entries that are scalars/null, ``id`` as a
  mapping or list, ``version`` as a list, ``Infinity``/``NaN`` versions
  (json.loads accepts both), and a lone-surrogate id via a ``\\ud800`` JSON
  escape: each entry costs only itself as a ``rejected`` row and the summary
  body is strictly UTF-8.  A manifest whose ``templates`` is a mapping, a
  bare number, or a 3000-deep array bomb is the coded 422 ``bad_manifest``.
* **Ingest template body zoo** — a synced template carrying a recursive YAML
  anchor in its front matter, a 5000-deep nested compose body, a
  lone-surrogate service key, or a hex-huge ``network_mode``/volume entry:
  the sync answers 200 (accepting or rejecting per entry, never raising) and
  the store listing stays 200 afterwards.
* **Native store spawn-output zoo** — brew/launchctl outputs that are raw
  bytes, lone surrogates, a str subclass whose ``__str__`` returns itself
  (keeping a bound ``.encode`` bomb live), a bytes subclass with a
  ``.decode`` bomb, and the vanished-CLI sentinel while brew is still on
  disk (kept as the raw result, not misclassified) — install and uninstall
  answer their dict shape, never a raw 500.
"""
from __future__ import annotations

import hashlib
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

from hub import catalog, catalog_remote, native_catalog  # noqa: E402
from hub.routers import catalog as catalog_router  # noqa: E402

_WATCHDOG_SECS = 15.0

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


class _CatalogSandbox(unittest.TestCase):
    """Template dir + services root + remote dir in a per-test temp tree."""

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
        self.client = _the_client()

    def request_watchdogged(self, method: str, url: str, **kw):
        """Drive one request; fail rather than wedge the suite on a hang."""
        result: dict = {}

        def run():
            result["r"] = self.client.request(method, url, **kw)

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        worker.join(timeout=_WATCHDOG_SECS)
        if worker.is_alive():
            self.fail(f"{method} {url} parked past the watchdog")
        return result["r"]

    def assert_never_500(self, resp, label: str):
        self.assertLess(resp.status_code, 500, f"{label}: {resp.text[:300]}")
        # What Starlette must have already guaranteed: a strictly valid body.
        resp.content.decode("utf-8")

    def assert_utf8_200(self, resp, label: str):
        self.assertEqual(resp.status_code, 200, f"{label}: {resp.text[:300]}")
        resp.content.decode("utf-8")


# ── pre-seeded install squatter zoo ──────────────────────────────────────────

_APP_TPL = (
    "---\nname: App\ndesc: d\nvars:\n  - name: FOO\n    default: bar\n---\n"
    "services:\n  a:\n    image: x\n    environment:\n      - FOO={{FOO}}\n"
)


class InstallSquatterZooTests(_CatalogSandbox):
    """Leftover nodes inside a pre-seeded ~/Services/<id>/ cost at most the
    node they squat, never the request (500) or the worker (hang)."""

    def setUp(self):
        super().setUp()
        (self.templates / "app.yml").write_text(_APP_TPL, encoding="utf-8")
        catalog.invalidate_listing()
        # Deterministic missing-CLI tail: the docker spawn is not this pin's
        # subject and the host may or may not carry a CLI.
        self.stack.enter_context(mock.patch.object(catalog, "DOCKER", ""))
        self.stack.enter_context(
            mock.patch.object(catalog.shutil, "which", lambda *_a, **_k: None)
        )
        self.stack.enter_context(
            mock.patch.object(catalog, "_register_stack", lambda *a, **k: None)
        )
        self.stack.enter_context(
            mock.patch.object(catalog, "_unregister_stack", lambda *a, **k: None)
        )

    def _install(self):
        return self.request_watchdogged(
            "POST", "/api/catalog/app/install", json={"variables": {}}
        )

    def test_dest_path_occupied_by_a_file(self):
        (self.services / "app").write_text("squatter", encoding="utf-8")
        resp = self._install()
        self.assert_never_500(resp, "dest-is-file")
        self.assertFalse(resp.json().get("ok"))
        # The squatting file is user data by contract: never deleted.
        self.assertEqual(
            (self.services / "app").read_text(encoding="utf-8"), "squatter"
        )

    def test_data_dir_occupied_by_a_file(self):
        dest = self.services / "app"
        dest.mkdir()
        (dest / "data").write_text("squatter", encoding="utf-8")
        resp = self._install()
        self.assert_never_500(resp, "data-is-file")
        self.assertFalse(resp.json().get("ok"))
        # A pre-existing directory is never rmtree'd by the rollback.
        self.assertEqual(
            (dest / "data").read_text(encoding="utf-8"), "squatter"
        )

    def test_vars_file_occupied_by_a_fifo_answers_promptly(self):
        dest = self.services / "app"
        dest.mkdir()
        os.mkfifo(dest / ".serverhub-vars.json")
        resp = self._install()
        self.assert_never_500(resp, "vars-fifo")
        body = resp.json()
        # The tmp+os.replace write swapped the FIFO out for the real dump.
        self.assertTrue((dest / ".serverhub-vars.json").is_file())
        self.assertTrue((dest / "docker-compose.yml").is_file())
        self.assertEqual(body.get("stack_id"), "app")

    def test_vars_file_occupied_by_a_nonempty_dir(self):
        dest = self.services / "app"
        dest.mkdir()
        (dest / ".serverhub-vars.json").mkdir()
        (dest / ".serverhub-vars.json" / "keep").write_text("x", encoding="utf-8")
        resp = self._install()
        self.assert_never_500(resp, "vars-dir")

    def test_readme_occupied_by_a_nonempty_dir_costs_only_the_readme(self):
        dest = self.services / "app"
        dest.mkdir()
        (dest / "README.serverhub.md").mkdir()
        (dest / "README.serverhub.md" / "keep").write_text("x", encoding="utf-8")
        resp = self._install()
        self.assert_never_500(resp, "readme-dir")
        body = resp.json()
        # The README is advisory: the install itself still landed.
        self.assertTrue((dest / "docker-compose.yml").is_file())
        self.assertEqual(body.get("stack_id"), "app")

    def test_compose_squatted_by_a_fifo_reads_as_installed(self):
        dest = self.services / "app"
        dest.mkdir()
        os.mkfifo(dest / "docker-compose.yml")
        resp = self._install()
        self.assertEqual(resp.status_code, 409, resp.text[:300])
        self.assertEqual(
            resp.json()["detail"]["code"], "catalog.already_installed"
        )

    def test_compose_squatted_by_a_dir_reads_as_installed(self):
        dest = self.services / "app"
        dest.mkdir()
        (dest / "docker-compose.yml").mkdir()
        resp = self._install()
        self.assertEqual(resp.status_code, 409, resp.text[:300])
        self.assertEqual(
            resp.json()["detail"]["code"], "catalog.already_installed"
        )

    def test_uninstall_over_squatted_compose_never_500s(self):
        for make in (
            lambda p: os.mkfifo(p),
            lambda p: p.mkdir(),
        ):
            dest = self.services / "app"
            shutil.rmtree(dest, ignore_errors=True)
            dest.mkdir()
            make(dest / "docker-compose.yml")
            resp = self.request_watchdogged(
                "POST", "/api/catalog/app/uninstall", json={"confirm": True}
            )
            self.assert_never_500(resp, "uninstall squatted compose")


# ── filesystem-exotic template nodes ─────────────────────────────────────────


class ExoticTemplateNodeTests(_CatalogSandbox):
    """Nodes only a filesystem can spell keep the listings at 200."""

    def test_surrogate_named_builtin_template(self):
        # surrogateescape is how a leftover file with undecodable bytes in
        # its name reaches Python; the stem then carries lone surrogates.
        name = b"bad\xff.yml".decode("utf-8", "surrogateescape")
        (self.templates / name).write_bytes(
            b"---\nname: B\ndesc: d\n---\nservices:\n  a:\n    image: x\n"
        )
        catalog.invalidate_listing()
        self.assert_utf8_200(
            self.client.get("/api/catalog/templates"), "surrogate builtin"
        )
        self.assert_utf8_200(self.client.get("/api/catalog"), "surrogate store")

    def test_symlink_loop_template(self):
        loop = self.templates / "loop.yml"
        loop.symlink_to(loop)
        catalog.invalidate_listing()
        self.assert_utf8_200(
            self.client.get("/api/catalog/templates"), "symlink loop"
        )


# ── manifest entry-shape zoo (through the _fetch seam) ───────────────────────

_GOOD_TPL = "---\nname: R\ndesc: d\n---\nservices:\n  a:\n    image: x\n"
_GOOD_SHA = hashlib.sha256(_GOOD_TPL.encode("utf-8")).hexdigest()


def _fetch_of(manifest_bytes: bytes, tpl_bytes: bytes = _GOOD_TPL.encode("utf-8")):
    def _fetch(url, max_bytes):
        return manifest_bytes if "index" in url else tpl_bytes

    return _fetch


#: Each entry costs only itself as a rejected row; the summary stays 200.
_REJECTED_ENTRY_ZOO = {
    "scalar-entries": (b'{"templates": [5, "x", null]}', 3),
    "id-mapping": (
        b'{"templates": [{"id": {"a": 1}, "sha256": "%s"}]}' % _GOOD_SHA.encode(),
        1,
    ),
    "id-list": (
        b'{"templates": [{"id": [1], "sha256": "%s"}]}' % _GOOD_SHA.encode(),
        1,
    ),
    "surrogate-id": (
        b'{"templates": [{"id": "a\\ud800", "sha256": "%s"}]}' % _GOOD_SHA.encode(),
        1,
    ),
}

#: Junk *versions* pass validation through their str() forms — the pin is
#: that the sync stays coded and the stored version is laundered text, not
#: that they are refused (a sane numeric version is legitimate).
_LAUNDERED_VERSION_ZOO = {
    "version-list": (
        b'{"templates": [{"id": "a", "sha256": "%s", "version": [1, 2]}]}'
        % _GOOD_SHA.encode()
    ),
    "infinity-version": (
        b'{"templates": [{"id": "a", "sha256": "%s", "version": Infinity}]}'
        % _GOOD_SHA.encode()
    ),
    "nan-version": (
        b'{"templates": [{"id": "a", "sha256": "%s", "version": NaN}]}'
        % _GOOD_SHA.encode()
    ),
}

#: The whole document is junk: the coded 422, never a raw parse 500.
_MANIFEST_JUNK = {
    "templates-mapping": b'{"templates": {"a": 1}}',
    "top-level-number": b"9" * 5000,
    "deep-array-bomb": b'{"templates": ' + b"[" * 3000 + b"]" * 3000 + b"}",
}


class ManifestEntryZooTests(_CatalogSandbox):
    """POST /api/catalog/remote/check over hostile manifests stays coded."""

    def _check(self, manifest: bytes, tpl: bytes = _GOOD_TPL.encode("utf-8")):
        with mock.patch.object(
            catalog_remote, "source_url",
            lambda: "https://example.com/index.json",
        ), mock.patch.object(catalog_remote, "_fetch", _fetch_of(manifest, tpl)):
            return self.client.post("/api/catalog/remote/check")

    def test_bad_entries_cost_only_themselves(self):
        for name, (manifest, rejected) in _REJECTED_ENTRY_ZOO.items():
            with self.subTest(entry=name):
                resp = self._check(manifest)
                self.assert_utf8_200(resp, name)
                body = resp.json()
                self.assertTrue(body["ok"])
                self.assertEqual(len(body["rejected"]), rejected, body)

    def test_junk_versions_are_laundered_not_raised(self):
        for name, manifest in _LAUNDERED_VERSION_ZOO.items():
            with self.subTest(version=name):
                resp = self._check(manifest)
                self.assert_utf8_200(resp, name)
                body = resp.json()
                self.assertTrue(body["ok"])
                self.assertEqual(body["rejected"], [], body)
                # The status echo of the stored version must render too.
                self.assert_utf8_200(
                    self.client.get("/api/catalog/remote"), f"status {name}"
                )
                for p in self.remote_dir.glob("*.yml"):
                    p.unlink()
                try:
                    (self.remote_dir / "state.json").unlink()
                except OSError:
                    pass

    def test_junk_manifests_are_the_coded_422(self):
        for name, manifest in _MANIFEST_JUNK.items():
            with self.subTest(manifest=name):
                resp = self._check(manifest)
                self.assertEqual(resp.status_code, 422, resp.text[:300])
                self.assertEqual(
                    resp.json()["detail"]["code"], "catalog_remote.bad_manifest"
                )


#: Hostile template *bodies* at ingest: accepted or rejected per entry,
#: never a raised sync — and the store listing stays 200 afterwards.
_INGEST_BODY_ZOO = {
    "cycle-anchor-front-matter": (
        "---\nname: A\ndesc: d\nm: &a {s: *a}\n---\nservices:\n  a:\n    image: x\n"
    ),
    "deep-nested-body": "---\nname: A\ndesc: d\n---\n" + "a:\n " * 5000 + "x: 1\n",
    "surrogate-service-key": (
        '---\nname: A\ndesc: d\n---\nservices:\n  "a\\udcff":\n    image: x\n'
    ),
    "hexint-network-mode": (
        "---\nname: A\ndesc: d\n---\nservices:\n  a:\n    image: x\n"
        "    network_mode: 0x" + "f" * 4400 + "\n"
    ),
    "hexint-volume-source": (
        "---\nname: A\ndesc: d\n---\nservices:\n  a:\n    image: x\n"
        "    volumes:\n      - source: 0x" + "f" * 4400 + "\n"
    ),
}


class IngestBodyZooTests(_CatalogSandbox):
    """A poisoned synced template never raises the sync or the store."""

    def test_sync_and_listing_survive_hostile_bodies(self):
        for name, text in _INGEST_BODY_ZOO.items():
            with self.subTest(body=name):
                blob = text.encode("utf-8", "surrogatepass")
                sha = hashlib.sha256(blob).hexdigest()
                manifest = json.dumps(
                    {"templates": [{"id": "zt", "sha256": sha, "version": "1"}]}
                ).encode("utf-8")
                with mock.patch.object(
                    catalog_remote, "source_url",
                    lambda: "https://example.com/index.json",
                ), mock.patch.object(
                    catalog_remote, "_fetch", _fetch_of(manifest, blob)
                ):
                    resp = self.client.post("/api/catalog/remote/check")
                self.assert_utf8_200(resp, f"check {name}")
                self.assert_utf8_200(
                    self.client.get("/api/catalog"), f"store after {name}"
                )
                for p in self.remote_dir.glob("*.yml"):
                    p.unlink()
                try:
                    (self.remote_dir / "state.json").unlink()
                except OSError:
                    pass
                catalog.invalidate_listing()


# ── native store spawn-output zoo ────────────────────────────────────────────


class _SelfStr(str):
    """``str()`` keeps the subclass, so a bound ``.encode`` bomb stays live."""

    def __str__(self):
        return self

    def encode(self, *a, **k):  # noqa: A003
        raise RuntimeError("encode bomb")


class _BoomBytes(bytes):
    def decode(self, *a, **k):
        raise RuntimeError("decode bomb")


#: (rc, stdout, stderr) shapes a poisoned spawn seam can hand back.
_SPAWN_ZOO = {
    "raw-bytes": (1, b"\x80\x81junk", b""),
    "lone-surrogates": (1, "out\ud800put", "err\udcff"),
    "self-str-encode-bomb": (1, _SelfStr("s\ud800"), ""),
    "bytes-decode-bomb": (1, _BoomBytes(b"bb"), b""),
    "none-streams": (0, None, None),
}


class NativeSpawnZooTests(_CatalogSandbox):
    """Native install/uninstall answer their dict shape over poisoned spawns."""

    def setUp(self):
        super().setUp()
        # A real brew on disk so the up-front gate passes and the vanished-CLI
        # classifier has a binary to confirm against.
        fake_brew = Path(self._tmp.name) / "brew"
        fake_brew.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_brew.chmod(0o755)
        self.stack.enter_context(
            mock.patch.object(native_catalog, "BREW", str(fake_brew))
        )
        self.stack.enter_context(
            mock.patch.object(native_catalog, "_brew_list_installed", lambda: set())
        )
        self.addCleanup(native_catalog.list_native_apps.invalidate)

    def test_spawn_zoo_never_500s(self):
        for name, (rc, out, err) in _SPAWN_ZOO.items():
            with self.subTest(spawn=name):
                def fake_sh(cmd, timeout=None, **kw):
                    return (rc, out, err)

                def fake_run_capped(cmd, timeout=None, env=None, cap=None, **kw):
                    msg = out if isinstance(out, (str, bytes)) else (err or "")
                    return (rc, msg)

                with mock.patch.object(native_catalog, "sh", fake_sh), \
                        mock.patch.object(
                            native_catalog, "run_capped", fake_run_capped
                        ):
                    native_catalog.list_native_apps.invalidate()
                    for label, method, url, body in (
                        ("install formula", "POST",
                         "/api/catalog/native-rclone/install", {"variables": {}}),
                        ("install multi", "POST",
                         "/api/catalog/native-wireguard/install", {"variables": {}}),
                        ("install cask", "POST",
                         "/api/catalog/native-rustdesk/install", {"variables": {}}),
                        ("uninstall formula", "POST",
                         "/api/catalog/native-rclone/uninstall", {"confirm": True}),
                    ):
                        resp = self.request_watchdogged(method, url, json=body)
                        self.assert_never_500(resp, f"{name} {label}")
                    self.assert_utf8_200(
                        self.request_watchdogged("GET", "/api/catalog"),
                        f"{name} store",
                    )
                native_catalog.list_native_apps.invalidate()

    def test_sentinel_with_brew_on_disk_keeps_the_raw_result(self):
        # run_capped's vanished-CLI sentinel while brew is still on disk must
        # NOT be misclassified as catalog.brew_missing: the binary is there,
        # so the sentinel (a vanished cwd, an exec-format oddity) keeps its
        # honest raw shape — the confirm-against-the-disk convention.
        def fake_run_capped(cmd, timeout=None, env=None, cap=None, **kw):
            return (-1, "not found")

        with mock.patch.object(native_catalog, "run_capped", fake_run_capped):
            native_catalog.list_native_apps.invalidate()
            resp = self.request_watchdogged(
                "POST", "/api/catalog/native-rclone/install",
                json={"variables": {}},
            )
        self.assert_never_500(resp, "sentinel install")
        body = resp.json()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertFalse(body.get("ok"))
        native_catalog.list_native_apps.invalidate()


if __name__ == "__main__":
    unittest.main()
