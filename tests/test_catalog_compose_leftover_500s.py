"""Leftover type 500s on the app store, remote catalog, compose, native install.

YAML ``.inf`` in template front matter, leftover Infinity in catalog-remote
state, a leftover file occupying a new stack path, leftover bytes from brew
or launchctl, and a leftover directory named like a LaunchAgent plist each
used to raise on the request path or fail Starlette's allow_nan=False encoder.
"""
from __future__ import annotations

import datetime
import errno
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from hub import catalog, catalog_remote, compose_svc, containers_svc, native_catalog, paths, service_credentials
from hub.routers import catalog as catalog_router


def _json(payload) -> None:
    json.dumps(payload, allow_nan=False)


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _code(exc: HTTPException) -> str:
    detail = exc.detail
    return detail["code"] if isinstance(detail, dict) else str(detail)


class CatalogYamlInfTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        catalog._list_cache.update(t=0.0, sig="", items=None)
        self.addCleanup(lambda: catalog._list_cache.update(t=0.0, sig="", items=None))

    def _list(self, text: str) -> list:
        (self.tmp / "infy.yml").write_text(text)
        with (
            mock.patch.object(catalog, "TEMPLATES", self.tmp),
            mock.patch.object(catalog, "SERVICES_ROOT", self.tmp / "Services"),
            mock.patch.object(catalog.catalog_remote, "remote_template_files", return_value=[]),
            mock.patch.object(catalog.catalog_remote, "remote_versions", return_value={}),
            mock.patch.object(catalog.catalog_remote, "remote_warnings", return_value={}),
        ):
            return catalog.list_templates(force=True)

    def test_leftover_inf_frontmatter_does_not_500_the_store(self):
        items = self._list(
            "---\n"
            "name: Infy\n"
            "desc: A demo\n"
            "url_template: .inf\n"
            "tags: [.inf, media]\n"
            "ports: [.inf, 8080]\n"
            "vars:\n"
            "  - name: HOST_PORT\n"
            "    label: .inf\n"
            "    help: .inf\n"
            "    default: .inf\n"
            "---\n"
            "services:\n  x:\n    image: a:1\n    ports:\n      - \"{{HOST_PORT}}:80\"\n"
        )
        item = items[0]
        _json(item)
        self.assertEqual(item["url_template"], "")
        self.assertEqual(item["tags"], ["media"])
        self.assertEqual(item["ports"], [8080])
        var = item["vars"][0]
        self.assertEqual(var["label"], "HOST_PORT")
        self.assertEqual(var["help"], "")
        self.assertEqual(var["default"], "")

    def test_scalar_inf_tags_do_not_500_the_store(self):
        items = self._list(
            "---\nname: Infy\ndesc: A demo\ntags: .inf\n---\n"
            "services:\n  x:\n    image: a:1\n"
        )
        _json(items[0])
        self.assertEqual(items[0]["tags"], [])

    def test_surrogate_frontmatter_does_not_500_the_store(self):
        """JSON ``\\ud800`` used to UnicodeEncodeError GET /api/catalog."""
        items = self._list(
            "---\n"
            'name: "Demo\\ud800"\n'
            'desc: "d\\ud800"\n'
            'notes: "n\\ud800"\n'
            'url_template: "http://x/\\ud800"\n'
            "---\n"
            "services:\n  x:\n    image: a:1\n"
        )
        item = items[0]
        _starlette(item)
        self.assertNotIn("\ud800", item["name"])
        self.assertNotIn("\ud800", item["desc"])
        self.assertNotIn("\ud800", item["notes"])
        self.assertNotIn("\ud800", item["url_template"])

    def test_surrogate_var_fields_do_not_500_the_store(self):
        """YAML ``"\\ud800"`` in var name/label/help/default is a str and used
        to skip ``_plain_str``, then UnicodeEncodeError GET /api/catalog."""
        items = self._list(
            "---\n"
            "name: Demo\n"
            "desc: d\n"
            "vars:\n"
            '  - name: "NOTE\\ud800"\n'
            '    label: "L\\ud800"\n'
            '    help: "H\\ud800"\n'
            '    default: "D\\ud800"\n'
            "---\n"
            "services:\n  x:\n    image: a:1\n"
        )
        item = items[0]
        _starlette(item)
        var = item["vars"][0]
        for key in ("name", "label", "help", "default"):
            self.assertNotIn("\ud800", var[key], key)
            self.assertTrue(var[key], key)

    def test_auto_var_home_runtimeerror_does_not_500(self):
        """``Path.home()`` RuntimeError used to 500 GET /api/catalog auto placeholders."""
        with mock.patch.object(Path, "home", side_effect=RuntimeError("HOME")):
            vals = catalog.auto_var_values()
        self.assertEqual(vals["HOME"], "")
        _starlette(vals)

    def test_leftover_surrogate_template_filename_does_not_500(self):
        """Leftover ``\\ud800`` in a template filename used to 500 GET /api/catalog."""
        (self.tmp / "ok.yml").write_text("---\nname: Ok\n---\nservices:\n  x:\n    image: a:1\n")
        real_name = Path.name.fget

        def fake_name(self):
            n = real_name(self)
            return "ok\ud800.yml" if n == "ok.yml" else n

        catalog._list_cache.update(t=0.0, sig="", items=None)
        with (
            mock.patch.object(catalog, "TEMPLATES", self.tmp),
            mock.patch.object(catalog, "SERVICES_ROOT", self.tmp / "Services"),
            mock.patch.object(catalog.catalog_remote, "remote_template_files", return_value=[]),
            mock.patch.object(catalog.catalog_remote, "remote_versions", return_value={}),
            mock.patch.object(catalog.catalog_remote, "remote_warnings", return_value={}),
            mock.patch.object(Path, "name", property(fake_name)),
        ):
            items = catalog.list_templates(force=True)
        item = items[0]
        _starlette(item)
        self.assertNotIn("\ud800", item["file"])
        self.assertNotIn("\ud800", item["id"])

    def test_templates_dir_eio_does_not_500_the_store(self):
        """Dying-mount ``Path.is_dir`` EIO used to 500 GET /api/catalog."""
        catalog._list_cache.update(t=0.0, sig="", items=None)
        with mock.patch.object(Path, "is_dir", side_effect=OSError(errno.EIO, "I/O error")):
            items = catalog.list_templates(force=True)
        _starlette(items)
        self.assertEqual(items, [])

    def test_dest_exists_eio_does_not_500_the_store(self):
        """Dying-mount ``dest.exists`` EIO used to 500 GET /api/catalog."""
        (self.tmp / "infy.yml").write_text("---\nname: Infy\n---\nservices:\n  x:\n    image: a:1\n")
        catalog._list_cache.update(t=0.0, sig="", items=None)
        real_exists = Path.exists

        def fake_exists(self, *a, **k):
            if self.name == "infy":
                raise OSError(errno.EIO, "I/O error")
            return real_exists(self, *a, **k)

        with (
            mock.patch.object(catalog, "TEMPLATES", self.tmp),
            mock.patch.object(catalog, "SERVICES_ROOT", self.tmp / "Services"),
            mock.patch.object(catalog.catalog_remote, "remote_template_files", return_value=[]),
            mock.patch.object(catalog.catalog_remote, "remote_versions", return_value={}),
            mock.patch.object(catalog.catalog_remote, "remote_warnings", return_value={}),
            mock.patch.object(Path, "exists", fake_exists),
        ):
            items = catalog.list_templates(force=True)
        _starlette(items)
        self.assertEqual(items[0]["name"], "Infy")
        self.assertIsNone(items[0]["path"])

    def test_inf_template_mtime_does_not_500_the_store(self):
        """FUSE ``st_mtime = inf`` used to OverflowError GET /api/catalog."""
        yml = self.tmp / "infy.yml"
        yml.write_text("---\nname: Infy\n---\nservices:\n  x:\n    image: a:1\n")
        real_stat = Path.stat

        def fake_stat(self, *a, **k):
            st = real_stat(self, *a, **k)
            if self.name == "infy.yml":
                return type("St", (), {
                    "st_mtime": float("inf"),
                    "st_size": st.st_size,
                    "st_mode": st.st_mode,
                })()
            return st

        catalog._list_cache.update(t=0.0, sig="", items=None)
        with (
            mock.patch.object(catalog, "TEMPLATES", self.tmp),
            mock.patch.object(catalog, "SERVICES_ROOT", self.tmp / "Services"),
            mock.patch.object(catalog.catalog_remote, "remote_template_files", return_value=[]),
            mock.patch.object(catalog.catalog_remote, "remote_versions", return_value={}),
            mock.patch.object(catalog.catalog_remote, "remote_warnings", return_value={}),
            mock.patch.object(Path, "stat", fake_stat),
        ):
            items = catalog.list_templates(force=True)
        _json(items)
        self.assertEqual(items[0]["name"], "Infy")


class CatalogRemoteStateLeftoverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        self.remote = self.tmp / "catalog-remote"
        self.remote.mkdir()
        self.patches = [
            mock.patch.object(catalog_remote, "REMOTE_DIR", self.remote),
            mock.patch.object(catalog_remote, "STATE_PATH", self.remote / "state.json"),
            mock.patch.object(catalog_remote, "source_url", return_value="https://x.example/index.json"),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def test_leftover_inf_state_does_not_500_status(self):
        (self.remote / "state.json").write_text(json.dumps({
            "last_check": float("inf"),
            "last_result": {"added": float("inf"), "at": float("nan")},
            "templates": {"demo": {"version": float("inf"), "warnings": [float("inf")]}},
        }))
        status = catalog_remote.status()
        _json(status)
        self.assertEqual(status["last_check"], "")
        self.assertIsInstance(status["last_result"], dict)
        self.assertIsNone(status["last_result"].get("added"))
        self.assertEqual(catalog_remote.remote_versions().get("demo"), "")

    def test_leftover_surrogate_state_does_not_500_status(self):
        """JSON ``\\ud800`` used to UnicodeEncodeError GET /api/catalog/remote."""
        (self.remote / "state.json").write_text(json.dumps({
            "last_check": "ok\ud800",
            "last_result": {"added": 1, "note": "x\ud800"},
            "templates": {"demo": {"version": "1\ud800"}},
        }))
        (self.remote / "demo.yml").write_text("x")
        status = catalog_remote.status()
        _starlette(status)
        self.assertNotIn("\ud800", status["last_check"])
        self.assertNotIn("\ud800", status["last_result"]["note"])
        self.assertNotIn("\ud800", catalog_remote.remote_versions().get("demo", ""))

    def test_deeply_nested_state_does_not_500_status(self):
        """``json.loads`` RecursionError is not ValueError; GET /api/catalog/remote used to 500."""
        (self.remote / "state.json").write_text(
            '{"k":' * 12000 + "1" + "}" * 12000, encoding="utf-8"
        )
        status = catalog_remote.status()
        _starlette(status)
        self.assertEqual(catalog_remote._load_state(), {})
        self.assertEqual(catalog_remote.remote_versions(), {})

    def test_huge_state_does_not_oom_status(self):
        """``read_text()`` of leftover multi-MB state used to OOM GET /api/catalog/remote."""
        (self.remote / "state.json").write_bytes(b"x" * (2 * 1024 * 1024))
        status = catalog_remote.status()
        _starlette(status)
        self.assertEqual(catalog_remote._load_state(), {})

    def test_is_file_eio_does_not_500_remote_path(self):
        """Dying-mount ``is_file`` EIO used to 500 catalog-remote lookups."""
        (self.remote / "demo.yml").write_text("x")
        with mock.patch.object(Path, "is_file", side_effect=OSError(errno.EIO, "I/O error")):
            self.assertIsNone(catalog_remote.remote_template_path("demo"))
            _starlette(catalog_remote.remote_template_files())

    def test_exists_eio_does_not_500_status(self):
        """Dying-mount ``exists`` EIO used to 500 GET /api/catalog/remote."""
        (self.remote / "demo.yml").write_text("x")
        with mock.patch.object(Path, "exists", side_effect=OSError(errno.EIO, "I/O error")):
            status = catalog_remote.status()
        _starlette(status)
        self.assertFalse(status["overrides"][0]["builtin_available"])

    def test_ensure_dir_eio_is_coded_not_500(self):
        """Dying-mount ``is_dir`` EIO used to 500 remote catalog writes."""
        with mock.patch("hub.secure_io.make_secret_dir"), mock.patch.object(
            Path, "is_dir", side_effect=OSError(errno.EIO, "I/O error")
        ):
            with self.assertRaises(HTTPException) as ctx:
                catalog_remote._ensure_dir()
        self.assertEqual(_code(ctx.exception), "catalog_remote.write_failed")

    def test_leftover_file_as_remote_dir_is_coded_not_500(self):
        blocked = self.tmp / "blocked-remote"
        blocked.write_text("i am a file")
        with (
            mock.patch.object(catalog_remote, "REMOTE_DIR", blocked),
            mock.patch.object(catalog_remote, "STATE_PATH", blocked / "state.json"),
        ):
            with self.assertRaises(HTTPException) as ctx:
                catalog_remote._ensure_dir()
        self.assertEqual(_code(ctx.exception), "catalog_remote.write_failed")

    def test_leftover_dir_named_state_json_is_coded_not_500(self):
        (self.remote / "state.json").mkdir()
        with self.assertRaises(HTTPException) as ctx:
            catalog_remote._save_state({"ok": True})
        self.assertEqual(_code(ctx.exception), "catalog_remote.write_failed")

    def test_save_state_dumps_recursion_is_coded_not_500(self):
        """json.dumps RecursionError is not OSError; POST catalog-remote used to 500."""
        with mock.patch.object(catalog_remote.json, "dumps", side_effect=RecursionError):
            with self.assertRaises(HTTPException) as ctx:
                catalog_remote._save_state({"ok": True})
        self.assertEqual(_code(ctx.exception), "catalog_remote.write_failed")

    def test_leftover_surrogate_rejected_id_does_not_500_check(self):
        """JSON ``\\ud800`` in a rejected manifest id used to 500 POST check."""
        raw = (
            b'{"templates":[{"id":"x\\ud800","sha256":"'
            + b"0" * 64
            + b'","version":"1","path":"x.yml"}]}'
        )
        with (
            mock.patch.object(
                catalog_remote, "validate_source_url",
                return_value="https://x.example/index.json",
            ),
            mock.patch.object(catalog_remote, "_fetch", return_value=raw),
        ):
            out = catalog_remote.check_updates()
        _starlette(out)
        self.assertEqual(out["checked"], 1)
        self.assertEqual(len(out["rejected"]), 1)
        self.assertNotIn("\ud800", out["rejected"][0]["id"])

    def test_recursing_fetch_reject_does_not_500_check(self):
        """``str(exc)`` RecursionError used to 500 POST /api/catalog/remote/check reject."""
        class Recursing(catalog_remote._FetchError):
            def __str__(self):
                raise RecursionError("nested")

        raw = (
            b'{"templates":[{"id":"demo","sha256":"'
            + b"0" * 64
            + b'","version":"1","path":"demo.yml"}]}'
        )

        def fake_fetch(url, max_bytes):
            if "index.json" in url:
                return raw
            raise Recursing("offline")

        with mock.patch.object(catalog_remote, "_fetch", fake_fetch):
            out = catalog_remote.check_updates()
        _starlette(out)
        self.assertEqual(out["rejected"][0]["reason"], "fetch_failed")
        self.assertEqual(out["rejected"][0]["detail"], "Recursing")

    def test_recursing_write_reject_does_not_500_check(self):
        """``str(exc)`` RecursionError used to 500 POST catalog-remote write reject."""
        class Recursing(OSError):
            def __str__(self):
                raise RecursionError("nested")

        text = (
            "---\nname: Demo\ndesc: A demo\n---\n"
            "services:\n  x:\n    image: a:1\n"
        )
        blob = text.encode()
        sha = hashlib.sha256(blob).hexdigest()
        raw = json.dumps({
            "templates": [{
                "id": "demo", "sha256": sha, "version": "1", "path": "demo.yml",
            }],
        }).encode()

        def fake_fetch(url, max_bytes):
            if "index.json" in url:
                return raw
            return blob

        real_replace = catalog_remote.secure_io.replace_secret_text

        def boom(path, content, **kwargs):
            if str(path).endswith(".yml"):
                raise Recursing(28, "No space left on device")
            return real_replace(path, content, **kwargs)

        with (
            mock.patch.object(catalog_remote, "_fetch", fake_fetch),
            mock.patch.object(
                catalog_remote.secure_io, "replace_secret_text", boom,
            ),
        ):
            out = catalog_remote.check_updates()
        _starlette(out)
        self.assertEqual(out["rejected"][0]["reason"], "write_failed")
        self.assertEqual(out["rejected"][0]["detail"], "Recursing")

    def test_recursing_save_state_oserror_is_coded_not_500(self):
        """``str(exc)`` RecursionError used to 500 POST catalog-remote state write."""
        class Recursing(OSError):
            def __str__(self):
                raise RecursionError("nested")

        with mock.patch.object(
            catalog_remote.secure_io, "replace_secret_text",
            side_effect=Recursing(28, "No space left on device"),
        ):
            with self.assertRaises(HTTPException) as ctx:
                catalog_remote._save_state({"ok": True})
        self.assertEqual(_code(ctx.exception), "catalog_remote.write_failed")
        _starlette(ctx.exception.detail)
        self.assertEqual(ctx.exception.detail["params"]["reason"], "Recursing")


class ComposeLeftoverTests(unittest.TestCase):
    def test_leftover_inf_name_does_not_500_get(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        compose = tmp / "docker-compose.yml"
        compose.write_text("services: {}\n")
        stack = {
            "id": "x",
            "name": float("inf"),
            "path": float("nan"),
            "compose_path": str(compose),
        }
        with mock.patch.object(compose_svc, "_find_stack", return_value=stack):
            data = compose_svc.get_compose("x")
        _json(data)
        self.assertEqual(data["name"], "x")
        self.assertIsNone(data["path"])

    def test_inf_mtime_does_not_500_get(self):
        """FUSE ``st_mtime = inf`` used to OverflowError GET /api/compose/{id}."""
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        compose = tmp / "docker-compose.yml"
        compose.write_text("services: {}\n")
        real_stat = Path.stat

        def fake_stat(self, *a, **k):
            st = real_stat(self, *a, **k)
            if self.name == "docker-compose.yml":
                return type("St", (), {
                    "st_mtime": float("inf"),
                    "st_size": st.st_size,
                    "st_mode": st.st_mode,
                })()
            return st

        stack = {"id": "x", "name": "x", "path": str(tmp), "compose_path": str(compose)}
        with (
            mock.patch.object(compose_svc, "_find_stack", return_value=stack),
            mock.patch.object(Path, "stat", fake_stat),
        ):
            data = compose_svc.get_compose("x")
        _json(data)
        self.assertEqual(data["content"], "services: {}\n")
        self.assertEqual(data["mtime"], 0)

    def test_leftover_file_at_stack_path_is_coded_not_500(self):
        home = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        (home / "Services").mkdir()
        (home / "Services" / "mystack").write_text("i am a file")
        with (
            mock.patch.object(Path, "home", return_value=home),
            mock.patch.object(
                compose_svc, "validate_compose_text", return_value={"ok": True}
            ),
        ):
            with self.assertRaises(HTTPException) as ctx:
                compose_svc.create_stack("mystack", "My", "services:\n  x:\n    image: a:1\n")
        self.assertEqual(_code(ctx.exception), "compose.exists")

    def test_leftover_file_at_data_does_not_500_create(self):
        home = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        root = home / "Services" / "s3"
        root.mkdir(parents=True)
        (root / "data").write_text("x")
        with (
            mock.patch.object(Path, "home", return_value=home),
            mock.patch.object(
                compose_svc, "validate_compose_text", return_value={"ok": True}
            ),
            mock.patch("hub.config.mutate", lambda fn: None),
            mock.patch.object(compose_svc, "inv"),
        ):
            out = compose_svc.create_stack("s3", "S3", "services:\n  x:\n    image: a:1\n")
        self.assertTrue(out["ok"])
        self.assertTrue((root / "docker-compose.yml").is_file())

    def test_leftover_bytes_content_does_not_500_validate(self):
        with mock.patch.object(compose_svc, "run_capped", return_value=(0, "valid")):
            out = compose_svc.validate_compose_text(b"services: {}\n", cwd="/tmp")
        self.assertTrue(out["ok"])
        self.assertIsInstance(out["message"], str)
        out = compose_svc.validate_compose_text(1, cwd="/tmp")
        self.assertFalse(out["ok"])

    def test_validate_home_runtimeerror_is_invalid_not_500(self):
        """``Path.home()`` RuntimeError used to 500 POST /api/compose/validate."""
        with mock.patch.object(Path, "home", side_effect=RuntimeError("HOME")):
            out = compose_svc.validate_compose_text("services: {}\n")
        self.assertFalse(out["ok"])
        self.assertIn("working directory", out["message"])
        _json(out)

    def test_validate_str_recursion_is_invalid_not_500(self):
        class Boom(Exception):
            def __str__(self):
                raise RecursionError("leftover")

        with mock.patch.object(compose_svc, "run_capped", side_effect=Boom()):
            out = compose_svc.validate_compose_text("services: {}\n", cwd="/tmp")
        self.assertFalse(out["ok"])
        self.assertIsInstance(out["message"], str)
        _json(out)

    def test_leftover_surrogate_content_does_not_500_save(self):
        """JSON ``\\ud800`` in compose content used to UnicodeEncodeError PUT save."""
        home = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        stack_dir = home / "Services" / "s"
        stack_dir.mkdir(parents=True)
        compose = stack_dir / "docker-compose.yml"
        compose.write_text("services: {}\n")
        stack = {
            "id": "s", "name": "s", "path": str(stack_dir),
            "compose_path": str(compose),
        }
        body = "services:\n  x:\n    image: a:1\n# \ud800\n"
        with (
            mock.patch.object(Path, "home", return_value=home),
            mock.patch.object(compose_svc, "_find_stack", return_value=stack),
            mock.patch.object(compose_svc, "inv"),
        ):
            out = compose_svc.save_compose("s", body, validate=False)
        self.assertTrue(out["ok"])
        raw = compose.read_text(encoding="utf-8")
        self.assertNotIn("\ud800", raw)
        _starlette(out)

    def test_leftover_surrogate_content_does_not_500_create(self):
        """JSON ``\\ud800`` in compose content used to UnicodeEncodeError POST create."""
        home = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        (home / "Services").mkdir()
        body = "services:\n  x:\n    image: a:1\n# \ud800\n"
        with (
            mock.patch.object(compose_svc, "user_home", return_value=home),
            mock.patch.object(
                compose_svc, "validate_compose_text", return_value={"ok": True}
            ),
            mock.patch("hub.config.mutate", lambda fn: None),
            mock.patch.object(compose_svc, "inv"),
        ):
            out = compose_svc.create_stack("s3", "S3", body)
        self.assertTrue(out["ok"])
        raw = (home / "Services" / "s3" / "docker-compose.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("\ud800", raw)
        _starlette(out)

    def test_huge_compose_does_not_oom_get(self):
        """``read_text()`` of leftover multi-MB compose used to OOM GET /api/compose."""
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        compose = tmp / "docker-compose.yml"
        compose.write_bytes(b"x" * (2 * 1024 * 1024))
        stack = {
            "id": "x", "name": "x", "path": str(tmp), "compose_path": str(compose),
        }
        with mock.patch.object(compose_svc, "_find_stack", return_value=stack):
            with self.assertRaises(HTTPException) as ctx:
                compose_svc.get_compose("x")
        self.assertEqual(_code(ctx.exception), "container.no_compose_file")

    def test_huge_compose_save_skips_backup_not_500(self):
        home = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        stack_dir = home / "Services" / "s"
        stack_dir.mkdir(parents=True)
        compose = stack_dir / "docker-compose.yml"
        compose.write_bytes(b"x" * (2 * 1024 * 1024))
        stack = {
            "id": "s", "name": "s", "path": str(stack_dir),
            "compose_path": str(compose),
        }
        body = "services:\n  x:\n    image: a:1\n"
        with (
            mock.patch.object(Path, "home", return_value=home),
            mock.patch.object(compose_svc, "_find_stack", return_value=stack),
            mock.patch.object(
                compose_svc, "validate_compose_text", return_value={"ok": True}
            ),
            mock.patch.object(compose_svc, "inv"),
        ):
            out = compose_svc.save_compose("s", body)
        self.assertTrue(out["ok"])
        self.assertEqual(compose.read_text(), body)


class NativeCatalogLeftoverTests(unittest.TestCase):
    def test_leftover_bytes_and_int_launchctl_do_not_500_screen_sharing(self):
        with mock.patch.object(
            native_catalog, "sh", return_value=(0, b"state = running\n", "")
        ):
            self.assertTrue(native_catalog._screen_sharing_on())
        for junk in (12, None, b"idle"):
            with mock.patch.object(native_catalog, "sh", return_value=(1, junk, "")):
                self.assertFalse(native_catalog._screen_sharing_on())

    def test_leftover_bytes_run_capped_does_not_500_join(self):
        with mock.patch.object(native_catalog, "run_capped", return_value=(0, b"ok")):
            out = native_catalog._run(["echo"])
        self.assertEqual(out["message"], "ok")
        "\n".join([out["message"]])
        with mock.patch.object(native_catalog, "run_capped", return_value=(1, 7)):
            out = native_catalog._run(["echo"])
        self.assertEqual(out["message"], "7")
        self.assertFalse(out["ok"])

    def test_leftover_plist_directory_is_coded_not_500(self):
        agents = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(agents, ignore_errors=True))
        (agents / "local.filebrowser.plist").mkdir()
        with mock.patch.object(paths, "AGENTS_DIR", agents):
            with self.assertRaises(HTTPException) as ctx:
                native_catalog._write_launchagent("local.filebrowser", ["/bin/true"])
        self.assertEqual(_code(ctx.exception), "catalog.plist_write_failed")
        self.assertTrue((agents / "local.filebrowser.plist").is_dir())

    def test_recursing_ensure_dir_oserror_is_coded_not_500(self):
        """``str(exc)`` RecursionError used to 500 native install mkdir."""
        class Recursing(OSError):
            def __str__(self):
                raise RecursionError("nested")

        with mock.patch.object(Path, "mkdir", side_effect=Recursing(5, "I/O error")):
            with self.assertRaises(HTTPException) as ctx:
                native_catalog._ensure_dir(Path("/tmp/serverhub-native-ensure"))
        self.assertEqual(_code(ctx.exception), "catalog.path_blocked")
        _starlette(ctx.exception.detail)
        self.assertEqual(ctx.exception.detail["params"]["detail"], "Recursing")

    def test_recursing_plist_write_oserror_is_coded_not_500(self):
        """``str(exc)`` RecursionError used to 500 native LaunchAgent write."""
        class Recursing(OSError):
            def __str__(self):
                raise RecursionError("nested")

        agents = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(agents, ignore_errors=True))
        with (
            mock.patch.object(paths, "AGENTS_DIR", agents),
            mock.patch(
                "hub.secure_io.replace_bytes",
                side_effect=Recursing(28, "No space left on device"),
            ),
        ):
            with self.assertRaises(HTTPException) as ctx:
                native_catalog._write_launchagent("local.filebrowser", ["/bin/true"])
        self.assertEqual(_code(ctx.exception), "catalog.plist_write_failed")
        _starlette(ctx.exception.detail)
        self.assertEqual(ctx.exception.detail["params"]["detail"], "Recursing")

    def test_app_exists_eio_does_not_500(self):
        """Dying-mount ``Path.exists`` EIO used to 500 native install checks."""
        with mock.patch.object(Path, "exists", side_effect=OSError(errno.EIO, "I/O error")):
            self.assertFalse(native_catalog._app_exists("WireGuard"))
            self.assertFalse(native_catalog._check_one("path:/tmp/x"))

    def test_tilde_path_home_runtimeerror_does_not_500(self):
        """``Path.home()`` RuntimeError used to 500 GET /api/apps ``path:~`` checks."""
        with mock.patch.object(Path, "home", side_effect=RuntimeError("HOME")):
            self.assertFalse(
                native_catalog._check_one("path:~/Services/filebrowser/filebrowser-bin")
            )

    def test_screen_sharing_exists_eio_does_not_500(self):
        """Dying-mount ``Path.exists`` EIO used to 500 Screen Sharing enable."""
        with (
            mock.patch.object(Path, "exists", side_effect=OSError(errno.EIO, "I/O error")),
            mock.patch.object(native_catalog, "_run", return_value={"ok": False, "message": "x"}),
            mock.patch.object(native_catalog, "_screen_sharing_on", return_value=False),
        ):
            out = native_catalog._enable_screen_sharing()
        self.assertIn("ok", out)
        _starlette(out)

    def test_which_eio_does_not_500(self):
        with mock.patch("shutil.which", side_effect=OSError(errno.EIO, "I/O error")):
            self.assertIsNone(native_catalog._which("no-such-serverhub-bin"))

    def test_copy2_eio_does_not_500_filebrowser(self):
        """Dying-mount ``shutil.copy2`` EIO used to 500 FileBrowser install."""
        home = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        brew_bin = home / "filebrowser"
        brew_bin.write_text("x")
        with (
            mock.patch.object(native_catalog, "SERVICES_ROOT", home / "Services"),
            mock.patch.object(native_catalog, "_which", return_value=str(brew_bin)),
            mock.patch.object(
                native_catalog, "_run",
                return_value={"ok": True, "message": "ok", "rc": 0},
            ),
            mock.patch.object(Path, "symlink_to", side_effect=OSError(errno.EIO, "I/O error")),
            mock.patch("shutil.copy2", side_effect=OSError(errno.EIO, "I/O error")),
        ):
            out = native_catalog._install_filebrowser({"notes": ""}, "native-filebrowser", [])
        self.assertIn("ok", out)
        _starlette(out)


class CatalogInstallLeftoverTests(unittest.TestCase):
    def test_leftover_bytes_compose_up_does_not_500_install(self):
        """``run_capped`` leftover bytes used to TypeError POST /api/catalog/install."""
        home = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        (home / "Services").mkdir()
        src = home / "ok.yml"
        src.write_text("---\nname: Ok\ndesc: d\n---\nservices:\n  x:\n    image: a:1\n")
        with (
            mock.patch.object(catalog, "SERVICES_ROOT", home / "Services"),
            mock.patch.object(catalog, "template_file", return_value=src),
            mock.patch.object(catalog, "DOCKER", "/usr/bin/true"),
            mock.patch.object(catalog, "run_capped", return_value=(0, b"Created")),
            mock.patch.object(catalog, "_check_ports_free"),
            mock.patch.object(catalog, "_register_stack"),
        ):
            out = catalog.install_template("ok", {})
        self.assertIsInstance(out["message"], str)
        _starlette(out)

    def test_leftover_inf_notes_on_failed_install_does_not_500(self):
        """YAML ``notes: .inf`` on the failure path used to 500 the encoder."""
        home = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        (home / "Services").mkdir()
        src = home / "ok.yml"
        src.write_text("---\nname: Ok\ndesc: d\nnotes: .inf\n---\nservices:\n  x:\n    image: a:1\n")
        with (
            mock.patch.object(catalog, "SERVICES_ROOT", home / "Services"),
            mock.patch.object(catalog, "template_file", return_value=src),
            mock.patch.object(catalog, "DOCKER", "/usr/bin/true"),
            mock.patch.object(catalog, "run_capped", side_effect=RuntimeError("boom")),
            mock.patch.object(catalog, "_check_ports_free"),
            mock.patch.object(catalog, "_register_stack"),
        ):
            out = catalog.install_template("ok", {})
        self.assertFalse(out["ok"])
        self.assertEqual(out["notes"], "")
        _starlette(out)

    def test_leftover_bytes_compose_down_does_not_500_uninstall(self):
        """``run_capped`` leftover bytes used to TypeError POST uninstall."""
        home = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        dest = home / "Services" / "ok"
        dest.mkdir(parents=True)
        (dest / "docker-compose.yml").write_text("services: {}\n")
        with (
            mock.patch.object(catalog, "SERVICES_ROOT", home / "Services"),
            mock.patch.object(catalog, "DOCKER", "/usr/bin/true"),
            mock.patch.object(catalog, "run_capped", return_value=(0, b"Removed")),
        ):
            out = catalog.uninstall_template("ok", confirm=True, remove_data=False)
        self.assertIsInstance(out["message"], str)
        _starlette(out)

    def test_leftover_surrogate_var_does_not_500_install(self):
        """json.dumps(ensure_ascii=False) of leftover ``\\ud800`` used to UnicodeEncodeError."""
        home = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        (home / "Services").mkdir()
        src = home / "ok.yml"
        src.write_text(
            "---\nname: Ok\ndesc: d\nvars:\n  - name: NOTE\n    required: false\n"
            "---\nservices:\n  x:\n    image: a:1\n"
        )
        with (
            mock.patch.object(catalog, "SERVICES_ROOT", home / "Services"),
            mock.patch.object(catalog, "template_file", return_value=src),
            mock.patch.object(catalog, "DOCKER", ""),
            mock.patch.object(catalog, "_check_ports_free"),
            mock.patch.object(catalog, "_register_stack"),
            mock.patch("shutil.which", return_value=""),
        ):
            out = catalog.install_template("ok", {"NOTE": "x\ud800y"})
        _starlette(out)
        dest = home / "Services" / "ok"
        raw = (dest / ".serverhub-vars.json").read_text(encoding="utf-8")
        self.assertNotIn("\ud800", raw)
        json.dumps(json.loads(raw), allow_nan=False)
        readme = (dest / "README.serverhub.md").read_text(encoding="utf-8")
        self.assertNotIn("\ud800", readme)

    def test_bootstrap_symlink_loop_does_not_500_install(self):
        """``Path.resolve`` RuntimeError on a leftover loop used to 500 install."""
        home = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        dest = home / "Services" / "ok"
        dest.mkdir(parents=True)
        loop = dest / "loop.yml"
        loop.symlink_to(loop)
        src = home / "boot.yml"
        src.write_text(
            "---\nname: Ok\ndesc: d\nbootstrap_files:\n  - path: loop.yml\n    content: hi\n"
            "---\nservices:\n  x:\n    image: a:1\n"
        )
        with (
            mock.patch.object(catalog, "SERVICES_ROOT", home / "Services"),
            mock.patch.object(catalog, "template_file", return_value=src),
            mock.patch.object(catalog, "DOCKER", ""),
            mock.patch.object(catalog, "_check_ports_free"),
            mock.patch.object(catalog, "_register_stack"),
            mock.patch("shutil.which", return_value=""),
        ):
            out = catalog.install_template("ok", {})
        _starlette(out)
        self.assertTrue((dest / "docker-compose.yml").is_file())


class CatalogHugeTemplateTests(unittest.TestCase):
    def test_huge_template_does_not_oom_the_store(self):
        """``read_text()`` of leftover multi-MB ``*.yml`` used to OOM GET /api/catalog."""
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        (tmp / "big.yml").write_bytes(b"x" * (2 * 1024 * 1024))
        catalog._list_cache.update(t=0.0, sig="", items=None)
        self.addCleanup(lambda: catalog._list_cache.update(t=0.0, sig="", items=None))
        with (
            mock.patch.object(catalog, "TEMPLATES", tmp),
            mock.patch.object(catalog, "SERVICES_ROOT", tmp / "Services"),
            mock.patch.object(catalog.catalog_remote, "remote_template_files", return_value=[]),
            mock.patch.object(catalog.catalog_remote, "remote_versions", return_value={}),
            mock.patch.object(catalog.catalog_remote, "remote_warnings", return_value={}),
        ):
            items = catalog.list_templates(force=True)
        _starlette(items)
        self.assertEqual(items, [])


class StackPathSurrogateLeftoverTests(unittest.TestCase):
    def test_leftover_surrogate_stack_path_does_not_500(self):
        """Leftover ``\\ud800`` in a compose path used to 500 GET /api/stacks."""
        with (
            mock.patch.object(
                containers_svc, "cfg",
                return_value={"stacks": [{
                    "id": "x", "name": "X", "path": "/tmp/ok\ud800",
                }]},
            ),
            mock.patch.object(Path, "exists", return_value=False),
            mock.patch.object(Path, "home", return_value=Path("/tmp")),
            mock.patch.object(Path, "is_dir", return_value=False),
        ):
            stacks = containers_svc._stack_paths()
        _starlette(stacks)
        self.assertTrue(any(s.get("id") == "x" for s in stacks))
        for s in stacks:
            self.assertNotIn("\ud800", s.get("path") or "")
            self.assertNotIn("\ud800", s.get("id") or "")
            self.assertNotIn("\ud800", s.get("name") or "")


class CatalogCredentialSaveLeftoverTests(unittest.TestCase):
    def _save(self, apply_result):
        body = catalog_router.CredentialSaveBody(
            service_id="jellyfin",
            username="admin",
            password="password1",
            apply_to_service=True,
        )
        with (
            mock.patch.object(
                catalog_router.auth, "browser_authenticated", return_value=True,
            ),
            mock.patch.object(
                catalog_router.service_credentials, "adapter_for",
                return_value="generic",
            ),
            mock.patch.object(
                catalog_router.service_credentials, "apply",
                return_value=apply_result,
            ),
            mock.patch.object(
                catalog_router.service_credentials, "store",
                return_value={"service_id": "jellyfin"},
            ),
        ):
            return catalog_router.save_app_credential(body, mock.Mock())

    def test_leftover_apply_message_does_not_500(self):
        """Leftover inf / ``\\ud800`` apply message used to 500 POST credentials."""
        for leftover in (float("inf"), "saved\ud800", b"saved", None):
            out = self._save({"ok": True, "message": leftover})
            _starlette(out)
            self.assertNotIn("\ud800", out["message"])

    def test_leftover_non_dict_apply_result_does_not_500(self):
        out = self._save(float("inf"))
        _starlette(out)
        self.assertTrue(out["ok"])


class CredentialSurrogateLeftoverTests(unittest.TestCase):
    def test_leftover_surrogate_display_name_does_not_500_get(self):
        """Leftover ``\\ud800`` in service-credentials.json used to 500 GET credentials."""
        item = service_credentials.public_item({
            "service_id": "jellyfin",
            "display_name": "JF\ud800",
            "username": "u\ud800",
            "url": "http://x/\ud800",
            "notes": "n\ud800",
            "adapter": "generic",
            "applied": False,
            "updated_at": 1,
        })
        _starlette(item)
        self.assertNotIn("\ud800", item["display_name"])
        self.assertNotIn("\ud800", item["username"])
        self.assertNotIn("\ud800", item["url"])
        self.assertNotIn("\ud800", item["notes"])

    def test_leftover_surrogate_password_is_coded_not_500(self):
        """Leftover ``\\ud800`` password UnicodeEncodeError'd PUT credentials."""
        rc, message = service_credentials._security(
            ["add-generic-password", "-w"],
            password_input="secret\ud800xx",
        )
        self.assertNotEqual(rc, 0)
        self.assertIsInstance(message, str)
        _starlette({"ok": False, "error": message})

    def test_run_with_input_oserror_is_not_500(self):
        with mock.patch.object(
            service_credentials.subprocess, "run",
            side_effect=OSError(5, "I/O error"),
        ):
            rc, out, err = service_credentials._run_with_input(
                ["/usr/bin/true"], None, timeout=1,
            )
        self.assertEqual(rc, -1)
        self.assertIn("I/O error", err)


class ImportTimeHomeLeftoverTests(unittest.TestCase):
    """``Path.home()`` at module import used to 500 every route that loads the module."""

    def test_native_catalog_services_root_falls_back(self):
        """``Path.home()`` leftover used to 500 import of native_catalog."""
        with mock.patch.object(native_catalog, "user_home", return_value=None):
            root = native_catalog._default_services_root()
        self.assertIsInstance(root, Path)
        self.assertTrue(str(root).endswith("serverhub-services"))

    def test_catalog_services_root_falls_back(self):
        with mock.patch.object(catalog, "user_home", return_value=None):
            root = catalog._default_services_root()
        self.assertIsInstance(root, Path)
        self.assertTrue(str(root).endswith("serverhub-services"))

    def test_catalog_global_prefs_falls_back(self):
        with mock.patch.object(catalog, "user_home", return_value=None):
            prefs = catalog._default_global_prefs()
        self.assertIsInstance(prefs, Path)
        self.assertTrue(str(prefs).endswith("serverhub-global-prefs"))
        with mock.patch.object(catalog, "_GLOBAL_PREFS", prefs):
            langs = catalog.host_languages()
        self.assertEqual(langs, ("en",))

    def test_credentials_home_falls_back(self):
        with mock.patch.object(service_credentials, "user_home", return_value=None):
            home = service_credentials._home_dir()
        self.assertIsInstance(home, Path)
        self.assertTrue(str(home).endswith("serverhub-credentials"))

    def test_apps_manage_services_root_falls_back(self):
        from hub import apps_manage_svc

        with mock.patch.object(apps_manage_svc, "user_home", return_value=None):
            root = apps_manage_svc._default_services_root()
        self.assertIsInstance(root, Path)
        self.assertTrue(str(root).endswith("serverhub-services"))

    def test_files_home_falls_back(self):
        from hub import files_svc

        with mock.patch.object(files_svc, "user_home", return_value=None):
            home = files_svc._default_home()
        self.assertIsInstance(home, Path)
        self.assertTrue(str(home).endswith("serverhub-files"))

    def test_photoshub_hub_falls_back(self):
        from hub import photoshub_svc

        with mock.patch.object(photoshub_svc, "user_home", return_value=None):
            hub = photoshub_svc._default_hub()
        self.assertIsInstance(hub, Path)
        self.assertTrue(str(hub).endswith("serverhub-photoshub"))

    def test_backups_home_falls_back(self):
        from hub import backups

        with mock.patch.object(backups, "user_home", return_value=None):
            home = backups._home_dir()
        self.assertIsInstance(home, Path)
        self.assertTrue(str(home).endswith("serverhub-backups"))

    def test_immich_home_falls_back(self):
        from hub import immich_svc

        with mock.patch.object(immich_svc, "user_home", return_value=None):
            home = immich_svc._home_dir()
        self.assertIsInstance(home, Path)
        self.assertTrue(str(home).endswith("serverhub-immich"))

    def test_uninstall_services_root_falls_back(self):
        from hub import services_uninstall_svc

        with mock.patch.object(services_uninstall_svc, "user_home", return_value=None):
            root = services_uninstall_svc._default_services_root()
        self.assertIsInstance(root, Path)
        self.assertTrue(str(root).endswith("serverhub-services"))

    def test_utmctl_candidates_skip_unresolvable_home(self):
        """``Path.home()`` leftover used to 500 import of hub.paths."""
        with mock.patch.object(paths, "user_home", return_value=None):
            cands = paths._utmctl_candidates()
        utm = [c for c in cands if c and c.endswith("UTM.app/Contents/MacOS/utmctl")]
        self.assertEqual(utm, ["/Applications/UTM.app/Contents/MacOS/utmctl"])

    def test_agents_dir_falls_back_when_unresolvable(self):
        """``os.path.expanduser`` leftover used to 500 import of hub.paths."""
        with mock.patch.object(paths, "user_home", return_value=None):
            agents = paths._default_agents_dir()
        self.assertIsInstance(agents, Path)
        self.assertTrue(str(agents).endswith("serverhub-launchagents"))

    def test_expand_root_runtimeerror_does_not_raise(self):
        """``Path.expanduser`` leftover used to 500 import of hub.paths."""
        with mock.patch.object(Path, "expanduser", side_effect=RuntimeError("no home")):
            root = paths._expand_root("~/serverhub")
        self.assertIsInstance(root, Path)

    def test_bin_exists_eio_is_false_not_raise(self):
        """Dying-mount ``Path.is_file`` EIO used to 500 import of hub.paths."""
        with mock.patch.object(Path, "is_file", side_effect=OSError(5, "I/O error")):
            self.assertFalse(paths._bin_exists("/opt/homebrew/bin/brew", as_file=True))
        with mock.patch.object(Path, "exists", side_effect=OSError(5, "I/O error")):
            self.assertFalse(paths._bin_exists("/Applications/UTM.app/Contents/MacOS/utmctl"))
        with mock.patch.object(Path, "is_file", side_effect=ValueError("embedded null")):
            self.assertFalse(paths._bin_exists("/tmp/\x00brew", as_file=True))


class CatalogRemoteJsonableLeftoverTests(unittest.TestCase):
    def test_isoformat_inf_date_bytes_set_do_not_500(self):
        """A leftover ``isoformat()`` returning inf used to 500 GET /api/catalog/remote."""
        class _Stamp:
            def isoformat(self):
                return float("inf")

        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(catalog_remote._as_text(Recursing()), "Recursing")
        self.assertIsNone(catalog_remote._jsonable(_Stamp()))
        out = catalog_remote._jsonable({
            "when": _Stamp(),
            "name": datetime.date(2026, 8, 19),
            "blob": b"tpl",
            "tags": {"remote"},
            "n": float("inf"),
        })
        _starlette(out)
        self.assertIsNone(out["when"])
        self.assertEqual(out["name"], "2026-08-19")
        self.assertEqual(out["blob"], "tpl")
        self.assertEqual(out["tags"], ["remote"])
        self.assertIsNone(out["n"])


if __name__ == "__main__":
    unittest.main()
