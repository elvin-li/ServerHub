"""Seventh leftover-500s sweep of the Apps catalog surface: immunity pins.

Beyond the one live hang this sweep found (the FIFO-README install hang,
fixed and pinned in ``test_catalog7_leftover_fifo_readme_hang``), the whole
known leftover zoo was replayed over the real mounted app —
``create_app()`` + ``TestClient(raise_server_exceptions=False)`` — and the
catalog / remote-catalog surfaces held.  These pins keep them held:

* **Front-matter zoo** — YAML hex ints past CPython's int->str digit cap in
  ``ports`` / ``id`` / ``name`` / var ``default`` / ``label`` / ``tags`` /
  ``url_template`` / mapping *keys*; a numeric ``id`` keeping its quoted
  twin's identity (str() probe, not an isinstance gate); lone-surrogate
  strings; ``!!binary`` names; ``!!set`` vars; tuple/date/bool/None keys —
  GET /api/catalog/templates and GET /api/catalog stay 200 with a strictly
  UTF-8 body.
* **Install body zoo** — a >4300-digit JSON int (``json.loads``'s digit-cap
  ValueError is *not* JSONDecodeError), ``Infinity`` / ``NaN`` literals,
  lone-surrogate escapes in values, a 3000-deep array bomb — POST install
  never answers a raw 500.
* **Remote state zoo** — huge-int stamps, surrogate ids, deep nesting, and
  wrong-shaped rows in ``state.json`` keep GET /api/catalog/remote at 200.
* **FIFO squatters answer promptly** — a FIFO as a template ``*.yml``, a
  remote override, ``state.json``, or a *sibling* install's compose file
  (the port-claims scan) — every read is O_NONBLOCK-capped, so listings and
  installs answer instead of parking.
* **Config-mutate contract** — PUT /api/catalog/remote against a torn /
  oversize / whole-document-pasted services.yaml is the coded 503
  ``settings.config_unreadable`` and the file stays byte-identical on disk.
"""
from __future__ import annotations

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

from hub import catalog, catalog_remote, config  # noqa: E402
from hub.routers import catalog as catalog_router  # noqa: E402

#: YAML hex spelling dodges the int(str) digit cap at parse time, so this
#: arrives as an int str()/json.dumps cannot render.
_HUGE = "0x" + "f" * 4400
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

    def assert_utf8_200(self, resp, label: str):
        self.assertEqual(resp.status_code, 200, f"{label}: {resp.text[:300]}")
        # What Starlette must have already guaranteed: a strictly valid body.
        resp.content.decode("utf-8")


_FRONT_MATTER_ZOO = {
    "huge-hex-port": f"---\nname: A\nports: [{_HUGE}]\n---\nservices:\n  a:\n    image: x\n",
    "huge-hex-id": f"---\nid: {_HUGE}\nname: A\n---\nservices:\n  a:\n    image: x\n",
    "huge-hex-name": f"---\nname: {_HUGE}\n---\nservices:\n  a:\n    image: x\n",
    "huge-hex-var-default": (
        f"---\nname: A\nvars:\n  - name: FOO\n    default: {_HUGE}\n---\n"
        "services:\n  a:\n    image: x\n    environment:\n      - FOO={{FOO}}\n"
    ),
    "huge-hex-var-label": (
        f"---\nname: A\nvars:\n  - name: FOO\n    label: {_HUGE}\n    help: {_HUGE}\n---\n"
        "services:\n  a:\n    image: x\n    environment:\n      - FOO={{FOO}}\n"
    ),
    "huge-hex-tags": f"---\nname: A\ntags: [{_HUGE}]\n---\nservices:\n  a:\n    image: x\n",
    "huge-hex-url-template": (
        f"---\nname: A\nurl_template: {_HUGE}\n---\nservices:\n  a:\n    image: x\n"
    ),
    "huge-hex-url-port-var": (
        "---\nname: A\nurl_template: http://{{HOST_IP}}:{{WEB_PORT}}\n"
        f"vars:\n  - name: WEB_PORT\n    default: {_HUGE}\n---\n"
        "services:\n  a:\n    image: x\n    ports:\n      - \"{{WEB_PORT}}:80\"\n"
    ),
    "huge-hex-mapping-key": f"---\n{_HUGE}: x\nname: A\n---\nservices:\n  a:\n    image: x\n",
    "huge-hex-bootstrap": (
        f"---\nname: A\nbootstrap_files:\n  - path: {_HUGE}\n    content: {_HUGE}\n---\n"
        "services:\n  a:\n    image: x\n"
    ),
    "numeric-id": "---\nid: 8080\nname: A\n---\nservices:\n  a:\n    image: x\n",
    "surrogate-name": '---\nname: "\\ud800"\n---\nservices:\n  a:\n    image: x\n',
    "surrogate-id": '---\nid: "a\\ud800b"\n---\nservices:\n  a:\n    image: x\n',
    "binary-name": '---\nname: !!binary "gIGC"\n---\nservices:\n  a:\n    image: x\n',
    "set-vars": "---\nname: A\nvars: !!set {? x}\n---\nservices:\n  a:\n    image: x\n",
    "set-ports": "---\nname: A\nports: !!set {? 80}\n---\nservices:\n  a:\n    image: x\n",
    "dict-name": "---\nname: {a: b}\n---\nservices:\n  a:\n    image: x\n",
    "list-category": "---\nname: A\ncategory: [x]\n---\nservices:\n  a:\n    image: x\n",
    "tuple-key": "---\n? [a, b]\n: x\nname: A\n---\nservices:\n  a:\n    image: x\n",
    "date-key": "---\n2020-01-01: x\nname: A\n---\nservices:\n  a:\n    image: x\n",
    "none-key": "---\n~: x\nname: A\n---\nservices:\n  a:\n    image: x\n",
}


class FrontMatterZooTests(_CatalogSandbox):
    """Hostile shipped/remote front matter keeps both listings at 200."""

    def test_listings_survive_the_front_matter_zoo(self):
        for name, text in _FRONT_MATTER_ZOO.items():
            with self.subTest(template=name):
                catalog.invalidate_listing()
                (self.templates / "zoo.yml").write_text(text, encoding="utf-8")
                self.assert_utf8_200(
                    self.client.get("/api/catalog/templates"), f"templates {name}"
                )
                self.assert_utf8_200(
                    self.client.get("/api/catalog"), f"catalog {name}"
                )

    def test_numeric_id_keeps_its_quoted_twin_identity(self):
        (self.templates / "zoo.yml").write_text(
            "---\nid: 8080\nname: A\n---\nservices:\n  a:\n    image: x\n",
            encoding="utf-8",
        )
        catalog.invalidate_listing()
        resp = self.client.get("/api/catalog/templates")
        self.assertEqual(resp.status_code, 200)
        ids = [t["id"] for t in resp.json()["templates"]]
        self.assertIn("8080", ids)

    def test_over_cap_numeric_id_falls_back_to_the_stem(self):
        (self.templates / "zoo.yml").write_text(
            f"---\nid: {_HUGE}\nname: A\n---\nservices:\n  a:\n    image: x\n",
            encoding="utf-8",
        )
        catalog.invalidate_listing()
        resp = self.client.get("/api/catalog/templates")
        self.assertEqual(resp.status_code, 200)
        ids = [t["id"] for t in resp.json()["templates"]]
        self.assertIn("zoo", ids)


_INSTALL_BODY_ZOO = {
    "huge-int-value": b'{"variables": {"FOO": ' + b"9" * 5000 + b"}}",
    "huge-int-port-var": b'{"variables": {"FOO": "x", "WEB_PORT": ' + b"9" * 5000 + b"}}",
    "infinity-value": b'{"variables": {"FOO": Infinity}}',
    "nan-value": b'{"variables": {"FOO": NaN}}',
    "one-e-999": b'{"variables": {"FOO": 1e999}}',
    "surrogate-value": b'{"variables": {"FOO": "\\ud800"}}',
    "surrogate-key": b'{"variables": {"\\ud800": "x", "FOO": "y"}}',
    "nested-array-bomb": b'{"variables": {"FOO": ' + b"[" * 3000 + b"]" * 3000 + b"}}",
    "dict-value": b'{"variables": {"FOO": {"a": 1}}}',
}


class InstallBodyZooTests(_CatalogSandbox):
    """POST install with a hostile JSON body never answers a raw 500."""

    def test_install_bodies_never_500(self):
        for name, raw in _INSTALL_BODY_ZOO.items():
            with self.subTest(body=name):
                catalog.invalidate_listing()
                shutil.rmtree(self.services / "app", ignore_errors=True)
                (self.templates / "app.yml").write_text(
                    "---\nname: App\nvars:\n  - name: FOO\n    default: bar\n---\n"
                    "services:\n  a:\n    image: x\n"
                    "    environment:\n      - FOO={{FOO}}\n",
                    encoding="utf-8",
                )
                with mock.patch.object(
                    catalog, "_register_stack", lambda *a, **k: None
                ), mock.patch.object(
                    catalog, "_unregister_stack", lambda *a, **k: None
                ):
                    resp = self.client.post(
                        "/api/catalog/app/install",
                        content=raw,
                        headers={"content-type": "application/json"},
                    )
                self.assertLess(
                    resp.status_code, 500, f"{name}: {resp.text[:300]}"
                )
                resp.content.decode("utf-8")


_STATE_ZOO = {
    "huge-int-version": '{"templates": {"a": {"version": ' + "9" * 5000 + "}}}",
    "surrogate-id": '{"templates": {"a\\ud800": {"version": "1"}}}',
    "deep-nest": "[" * 3000 + "]" * 3000,
    "huge-last-check": '{"last_check": ' + "9" * 5000 + "}",
    "last-result-list": '{"last_result": [1,2]}',
    "templates-list": '{"templates": [1,2]}',
    "huge-warning": '{"templates": {"a": {"warnings": [' + "9" * 5000 + "]}}}",
    "version-dict": '{"templates": {"a": {"version": {"x": 1}}}}',
}


class RemoteStateZooTests(_CatalogSandbox):
    """Hostile state.json keeps GET /api/catalog/remote at 200."""

    def test_status_survives_the_state_zoo(self):
        for name, text in _STATE_ZOO.items():
            with self.subTest(state=name):
                (self.remote_dir / "state.json").write_text(text, encoding="utf-8")
                self.assert_utf8_200(
                    self.client.get("/api/catalog/remote"), f"state {name}"
                )
                (self.remote_dir / "state.json").unlink()


class FifoSquatterTests(_CatalogSandbox):
    """FIFOs on every read path answer promptly — no parked worker."""

    def test_fifo_template_file(self):
        os.mkfifo(self.templates / "fifo.yml")
        catalog.invalidate_listing()
        self.assert_utf8_200(
            self.request_watchdogged("GET", "/api/catalog/templates"),
            "fifo template",
        )

    def test_fifo_remote_override(self):
        os.mkfifo(self.remote_dir / "over.yml")
        catalog.invalidate_listing()
        self.assert_utf8_200(
            self.request_watchdogged("GET", "/api/catalog/templates"),
            "fifo override listing",
        )
        self.assert_utf8_200(
            self.request_watchdogged("GET", "/api/catalog/remote"),
            "fifo override status",
        )

    def test_fifo_state_json(self):
        os.mkfifo(self.remote_dir / "state.json")
        self.assert_utf8_200(
            self.request_watchdogged("GET", "/api/catalog/remote"),
            "fifo state.json",
        )

    def test_fifo_sibling_compose_in_port_scan(self):
        (self.templates / "papp.yml").write_text(
            "---\nname: P\nvars:\n  - name: WEB_PORT\n    default: \"18099\"\n---\n"
            "services:\n  a:\n    image: x\n"
            "    ports:\n      - \"{{WEB_PORT}}:80\"\n",
            encoding="utf-8",
        )
        (self.services / "other").mkdir()
        os.mkfifo(self.services / "other" / "docker-compose.yml")
        catalog.invalidate_listing()
        with mock.patch.object(
            catalog, "_register_stack", lambda *a, **k: None
        ), mock.patch.object(catalog, "DOCKER", ""), mock.patch.object(
            catalog.shutil, "which", lambda *_a, **_k: None
        ):
            resp = self.request_watchdogged(
                "POST", "/api/catalog/papp/install", json={"variables": {}}
            )
        self.assertEqual(resp.status_code, 200, resp.text[:300])


class ConfigMutateContractTests(_CatalogSandbox):
    """PUT /api/catalog/remote against an unreadable services.yaml: coded 503,
    the file stays byte-identical (never patched-{}-and-rewritten)."""

    _CONFIG_ZOO = {
        "torn-utf8": b"settings:\n  x: \xff\xfe\n",
        "oversize": b"# pad\n" + b"a" * (2 * 1024 * 1024),
        "whole-document-paste": b"- a\n- b\n",
    }

    def test_unreadable_config_is_503_and_intact(self):
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
        for name, blob in self._CONFIG_ZOO.items():
            with self.subTest(config=name):
                yaml_path.parent.mkdir(parents=True, exist_ok=True)
                yaml_path.write_bytes(blob)
                config.reload_cfg()
                resp = self.client.put(
                    "/api/catalog/remote",
                    json={"url": "https://example.com/index.json"},
                )
                self.assertEqual(resp.status_code, 503, resp.text[:300])
                self.assertEqual(
                    resp.json()["detail"]["code"], "settings.config_unreadable"
                )
                self.assertEqual(yaml_path.read_bytes(), blob)


if __name__ == "__main__":
    unittest.main()
