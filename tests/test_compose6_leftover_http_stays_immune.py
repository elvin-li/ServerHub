"""Compose leftover sweep #6: on-disk config + scan-name HTTP stays-immune pins.

A sixth adversarial pass over the Compose surfaces (GET/PUT /api/compose/{id},
POST /api/compose[/validate], POST /api/compose/{id}/validate, GET /api/stacks,
GET /api/adaptive/compose-scan) through the real ``create_app`` wiring with
``TestClient(raise_server_exceptions=False)`` found no live unhandled 500s.
These pins keep the corners that pass exercised — none of which the prior
compose/compose2/3/4/5 sweeps asserted at the HTTP layer — answering coded
2xx/4xx/503 with UTF-8-renderable bodies:

* hostile services.yaml *on disk*, parsed by the real ``cfg()`` load path
  (every prior compose sweep mocked ``containers_svc.cfg``, bypassing
  ``_as_config`` normalisation and the capped-int loader): huge uncapped hex
  ids/paths/compose_file, >4300-digit decimal scalars, ``\\ud800`` and NUL
  escapes, ``stacks:`` as a scalar / string / mapping, torn non-UTF-8 bytes,
  a bare-list document, and a 300-deep nest;
* POST /api/compose over a torn or oversize services.yaml: config.mutate's
  read-back refusal is the coded 503 ``settings.config_unreadable`` and the
  poisoned file stays byte-identical on disk — never a silent ``{}``-rewrite
  and never a raw 500;
* a healthy create with a fake CLI registers the stack row through mutate,
  and an id squatted by a plain file is the coded ``compose.exists``;
* every stack id the listing publishes for hostile *scanned* directory names
  (spaces, unicode, emoji, a leading dash, ``[::1]``, ``?``/``#``/``&``,
  newline, tab, 200-digit and hex-looking numerics, a surrogateescape byte)
  round-trips GET / validate / PUT as coded answers;
* the validate temp file ``.compose-check.<pid>.yml`` occupied by a leftover
  directory (soft refusal) or FIFO (recovered: squatter unlinked, check runs,
  temp cleaned) — never a hang, never a 500;
* hostile compose documents through POST /api/compose/validate at the HTTP
  layer: unhashable ``? [1,2]`` keys, ``!!python`` tags, ``!!timestamp .inf``,
  ``2026-13-01``, ``!!bool 2``, multi-doc streams, 400-deep nests, and
  >4300-digit decimal ints are soft refusals; uncapped hex ints and ``!!set``
  members still validate; PUT with ``check: true`` keeps the coded 400.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import adaptive, compose_svc, config, containers_svc  # noqa: E402

VALID_COMPOSE = "services:\n  web:\n    image: nginx:alpine\n"
#: YAML hex spellings load uncapped (``int(x, 16)`` is a power-of-two base),
#: so services.yaml can hand routes an already-int past CPython's str cap.
_HUGE_HEX = "0x" + "f" * 4400
_HUGE_DEC = "9" * 4400


class _Compose6Sandbox(unittest.TestCase):
    """Real app wiring + the real services.yaml on disk under a temp home."""

    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        from hub.app_factory import create_app
        from hub.auth import require_auth

        cls._app = create_app()
        cls._app.dependency_overrides[require_auth] = lambda: True
        cls.client = TestClient(cls._app, raise_server_exceptions=False)

    @classmethod
    def tearDownClass(cls):
        cls._app.dependency_overrides.clear()

    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="compose6-http-9a14-"))
        self.addCleanup(lambda: shutil.rmtree(self.home, ignore_errors=True))
        self.stack_dir = self.home / "Services" / "app-9a14"
        self.stack_dir.mkdir(parents=True)
        self.compose = self.stack_dir / "docker-compose.yml"
        self.compose.write_text(VALID_COMPOSE)
        # The point of this sweep is the real on-disk config parse, so cfg()
        # is NOT mocked; the suite-level SERVERHUB_STATE_DIR redirection makes
        # config.YAML_PATH hermetic, and the original bytes are restored so
        # sibling suites in the same process see their own config again.
        self._orig_cfg = None
        try:
            self._orig_cfg = config.YAML_PATH.read_bytes()
        except OSError:
            self._orig_cfg = None
        self.addCleanup(self._restore_config)
        for p in (
            mock.patch.object(containers_svc, "user_home", return_value=self.home),
            mock.patch.object(compose_svc, "user_home", return_value=self.home),
            mock.patch.object(adaptive, "user_home", return_value=self.home),
        ):
            p.start()
            self.addCleanup(p.stop)
        self._write_config(self._base_config())

    def _restore_config(self):
        try:
            if self._orig_cfg is None:
                config.YAML_PATH.unlink(missing_ok=True)
            else:
                config.YAML_PATH.write_bytes(self._orig_cfg)
        except OSError:
            pass
        config.reload_cfg()

    def _base_config(self) -> str:
        return (
            "settings: {}\nstacks:\n"
            f"  - id: app-9a14\n    name: App\n    path: {self.stack_dir}\n"
        )

    def _write_config(self, text) -> None:
        if isinstance(text, bytes):
            config.YAML_PATH.write_bytes(text)
        else:
            config.YAML_PATH.write_text(text, encoding="utf-8")
        # cfg() caches by mtime; same-second rewrites must still be seen.
        config.reload_cfg()

    def _fake_docker(self, script: str = "exit 0\n") -> str:
        fake = self.home / "docker-9a14"
        fake.write_text("#!/bin/sh\n" + script)
        fake.chmod(0o755)
        return str(fake)

    # ---- request helpers ----
    def _get(self, sid: str = "app-9a14"):
        return self.client.get(f"/api/compose/{sid}")

    def _validate_stack(self, sid: str = "app-9a14"):
        return self.client.post(f"/api/compose/{sid}/validate")

    def _save(self, sid: str = "app-9a14", content: str = VALID_COMPOSE + "# edited\n",
              check: bool = False):
        return self.client.put(
            f"/api/compose/{sid}",
            content=json.dumps({"content": content, "check": check}),
            headers={"Content-Type": "application/json"},
        )

    def _validate_text(self, content, cwd=None):
        body: dict = {"content": content}
        if cwd is not None:
            body["cwd"] = cwd
        return self.client.post(
            "/api/compose/validate",
            content=json.dumps(body),
            headers={"Content-Type": "application/json"},
        )

    def _create(self, sid: str, name=None, content: str = VALID_COMPOSE):
        body: dict = {"id": sid, "content": content}
        if name is not None:
            body["name"] = name
        return self.client.post(
            "/api/compose",
            content=json.dumps(body),
            headers={"Content-Type": "application/json"},
        )

    def _assert_renders(self, resp):
        """Body must be JSON that UTF-8-encodes without lone surrogates."""
        self.assertLess(resp.status_code, 500, resp.text)
        text = json.dumps(resp.json())
        self.assertNotIn("\ud800", text)
        return resp

    def _sweep(self, sid: str = "app-9a14"):
        for resp in (
            self.client.get("/api/stacks"),
            self._get(sid),
            self._validate_stack(sid),
            self._save(sid),
            self.client.get("/api/adaptive/compose-scan"),
        ):
            self._assert_renders(resp)


class HostileOnDiskConfigTests(_Compose6Sandbox):
    """Poisoned services.yaml parsed by the real cfg() keeps compose coded."""

    def test_hostile_stack_row_scalars_on_disk_never_500(self):
        zoo = {
            "hugehex-id": f"  - id: {_HUGE_HEX}\n    path: {self.stack_dir}\n",
            "hugedec-id": f"  - id: {_HUGE_DEC}\n    path: {self.stack_dir}\n",
            "numeric-id": f"  - id: 42\n    path: {self.stack_dir}\n",
            "surrogate-id": f'  - id: "\\ud800"\n    path: {self.stack_dir}\n',
            "nul-path": f'  - id: app-9a14\n    path: "{self.stack_dir}\\0x"\n',
            "hugehex-path": f"  - id: app-9a14\n    path: {_HUGE_HEX}\n",
            "inf-name": f"  - id: app-9a14\n    name: .inf\n    path: {self.stack_dir}\n",
            "date-name": f"  - id: app-9a14\n    name: 2026-08-19\n    path: {self.stack_dir}\n",
            "binary-name": f"  - id: app-9a14\n    name: !!binary aGk=\n    path: {self.stack_dir}\n",
            "set-compose-file": (
                f"  - id: app-9a14\n    path: {self.stack_dir}\n"
                "    compose_file: !!set {a: null}\n"
            ),
            "hugehex-compose-file": (
                f"  - id: app-9a14\n    path: {self.stack_dir}\n"
                f"    compose_file: {_HUGE_HEX}\n"
            ),
            "junk-containers": (
                f"  - id: app-9a14\n    path: {self.stack_dir}\n"
                f"    containers: [1, null, {{a: 1}}, ok, .inf, {_HUGE_HEX}]\n"
            ),
        }
        for label, row in zoo.items():
            with self.subTest(row=label):
                self._write_config("settings: {}\nstacks:\n" + row)
                self._sweep()

    def test_numeric_yaml_id_on_disk_renders_via_the_str_probe(self):
        self._write_config(
            f"settings: {{}}\nstacks:\n  - id: 42\n    path: {self.stack_dir}\n"
        )
        resp = self._assert_renders(self.client.get("/api/stacks"))
        ids = [s["id"] for s in resp.json()["stacks"]]
        self.assertIn("42", ids)
        # The rendered id names a working stack, end to end.
        self.assertEqual(self._get("42").status_code, 200)

    def test_huge_hex_id_on_disk_falls_back_to_the_directory_name(self):
        self._write_config(
            f"settings: {{}}\nstacks:\n  - id: {_HUGE_HEX}\n    path: {self.stack_dir}\n"
        )
        resp = self._assert_renders(self.client.get("/api/stacks"))
        ids = [s["id"] for s in resp.json()["stacks"]]
        # str() of the uncapped hex int is the digit-cap ValueError; the
        # probe eats it and the directory name keeps the stack usable.
        self.assertIn("app-9a14", ids)
        self.assertEqual(self._get("app-9a14").status_code, 200)

    def test_non_list_stacks_documents_on_disk_never_500(self):
        for label, doc in {
            "scalar": "settings: {}\nstacks: 42\n",
            "string": "settings: {}\nstacks: hello\n",
            "mapping": "settings: {}\nstacks: {a: 1}\n",
            "hugehex": f"settings: {{}}\nstacks: {_HUGE_HEX}\n",
            "list-of-scalars": "settings: {}\nstacks: [1, x, null]\n",
        }.items():
            with self.subTest(doc=label):
                self._write_config(doc)
                resp = self._assert_renders(self.client.get("/api/stacks"))
                # _as_config normalises; only the scan row remains.
                for row in resp.json()["stacks"]:
                    self.assertEqual(row["source"], "scan")
                self._sweep()

    def test_torn_and_unparseable_configs_on_disk_never_500(self):
        for label, doc in {
            "torn-utf8": b"settings: {}\nstacks:\n  - id: \xff\xfe\n",
            "bare-list": "- a\n- b\n",
            "deep-nest": "a:" + " {b:" * 300 + " 1" + "}" * 300 + "\n",
            "tab-lead": "\tstacks: []\n",
            "hugedec-scalar": f"settings: {{}}\nx: {_HUGE_DEC}\nstacks: []\n",
        }.items():
            with self.subTest(doc=label):
                self._write_config(doc)
                self._sweep()


class CreateOverPoisonedConfigTests(_Compose6Sandbox):
    """POST /api/compose meets config.mutate's read-back refusal, coded."""

    def test_create_over_a_torn_config_is_the_coded_503_and_the_file_survives(self):
        torn = b"settings: {}\nstacks:\n  - id: \xff\xfe torn\n"
        self._write_config(torn)
        with mock.patch.object(compose_svc, "DOCKER", self._fake_docker()):
            resp = self._create("newstack-9a14")
        self.assertEqual(resp.status_code, 503, resp.text)
        self.assertEqual(
            resp.json()["detail"]["code"], "settings.config_unreadable",
        )
        # The refusal is the whole point: the poisoned file is byte-identical,
        # not silently rewritten as {}-plus-stack with an HTTP 200.
        self.assertEqual(config.YAML_PATH.read_bytes(), torn)

    def test_create_over_an_oversize_config_is_the_same_coded_503(self):
        big = "settings: {}\n# " + "x" * (2 * 1024 * 1024) + "\n"
        self._write_config(big)
        with mock.patch.object(compose_svc, "DOCKER", self._fake_docker()):
            resp = self._create("newstack-9a14")
        self.assertEqual(resp.status_code, 503, resp.text)
        self.assertEqual(
            resp.json()["detail"]["code"], "settings.config_unreadable",
        )
        self.assertEqual(
            config.YAML_PATH.read_text(encoding="utf-8"), big,
        )

    def test_a_healthy_create_registers_the_stack_through_mutate(self):
        with mock.patch.object(compose_svc, "DOCKER", self._fake_docker()):
            resp = self._create("newstack-9a14", name="Fresh")
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertTrue(resp.json()["ok"])
        compose = self.home / "Services" / "newstack-9a14" / "docker-compose.yml"
        self.assertEqual(compose.read_text(encoding="utf-8"), VALID_COMPOSE)
        data = yaml.safe_load(config.YAML_PATH.read_text(encoding="utf-8"))
        rows = {s["id"]: s for s in data["stacks"]}
        self.assertIn("newstack-9a14", rows)
        self.assertEqual(rows["newstack-9a14"]["name"], "Fresh")
        # The pre-existing stack row survives the mutate.
        self.assertIn("app-9a14", rows)

    def test_an_id_squatted_by_a_plain_file_is_the_coded_conflict(self):
        (self.home / "Services" / "squat-9a14").write_text("file")
        with mock.patch.object(compose_svc, "DOCKER", self._fake_docker()):
            resp = self._create("squat-9a14")
        self.assertLess(resp.status_code, 500, resp.text)
        self.assertEqual(resp.json()["detail"]["code"], "compose.exists")


class ScannedHostileNameRoundTripTests(_Compose6Sandbox):
    """Every id the listing publishes for hostile scan names stays coded."""

    def test_hostile_scanned_directory_names_round_trip_coded(self):
        import urllib.parse

        names = [
            b"bad\xff-9a14".decode("utf-8", "surrogateescape"),
            "sp ace-9a14",
            "uni\u00e9-9a14",
            "emoji\U0001f600-9a14",
            "-dash-9a14",
            "..dots-9a14",
            "q?mark-9a14",
            "pct%20enc-9a14",
            "new\nline-9a14",
            "tab\tname-9a14",
            "[::1]-9a14",
            "9" * 200,
            "0x" + "f" * 100,
            "a#b-9a14",
            "a&b=c-9a14",
        ]
        for n in names:
            d = self.home / "Services" / n
            d.mkdir()
            (d / "docker-compose.yml").write_text(VALID_COMPOSE)
        listing = self._assert_renders(self.client.get("/api/stacks"))
        rows = listing.json()["stacks"]
        # The config row plus every scanned directory: nothing dropped.
        self.assertGreaterEqual(len(rows), len(names) + 1)
        for row in rows:
            sid = row["id"]
            q = urllib.parse.quote(sid, safe="")
            with self.subTest(sid=sid[:24]):
                self._assert_renders(self._get(q))
                self._assert_renders(self._validate_stack(q))
                self._assert_renders(self._save(q))

    def test_the_scrubbed_surrogate_id_still_reaches_its_compose(self):
        import urllib.parse

        raw = b"bad\xff-9a14".decode("utf-8", "surrogateescape")
        d = self.home / "Services" / raw
        d.mkdir()
        (d / "docker-compose.yml").write_text(VALID_COMPOSE)
        listing = self.client.get("/api/stacks").json()["stacks"]
        sid = next(s["id"] for s in listing if s["id"].startswith("bad"))
        # The published id is the ?-scrubbed twin; I/O rides the raw os name.
        self.assertNotIn("\udcff", sid)
        resp = self._get(urllib.parse.quote(sid, safe=""))
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json()["content"], VALID_COMPOSE)


class ValidateTempFileCollisionTests(_Compose6Sandbox):
    """Squatters on .compose-check.<pid>.yml are soft outcomes, never hangs."""

    def test_a_leftover_directory_at_the_temp_path_is_a_soft_refusal(self):
        work = self.home / "work-9a14"
        squatter = work / f".compose-check.{os.getpid()}.yml"
        squatter.mkdir(parents=True)
        with mock.patch.object(compose_svc, "DOCKER", self._fake_docker()):
            resp = self._validate_text(VALID_COMPOSE, cwd=str(work))
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertFalse(body["ok"])
        self.assertNotIn("Traceback", body["message"])
        # The squatter is untouched — validate refuses, it does not bulldoze.
        self.assertTrue(squatter.is_dir())

    def test_a_leftover_fifo_at_the_temp_path_is_recovered_not_a_hang(self):
        work = self.home / "work-9a14"
        work.mkdir()
        squatter = work / f".compose-check.{os.getpid()}.yml"
        os.mkfifo(squatter)
        with mock.patch.object(compose_svc, "DOCKER", self._fake_docker()):
            resp = self._validate_text(VALID_COMPOSE, cwd=str(work))
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertTrue(resp.json()["ok"], resp.text)
        # The FIFO was unlinked for the check and the temp cleaned after it.
        self.assertFalse(squatter.exists())


class HostileComposeDocumentValidateTests(_Compose6Sandbox):
    """Hostile YAML documents over POST /api/compose/validate stay soft."""

    def test_unloadable_documents_are_soft_refusals_not_500s(self):
        docs = {
            "unhashable-key": "? [1,2]\n: x\nservices: {}\n",
            "python-tag": "!!python/object/apply:os.system [id]\n",
            "timestamp-inf": "x: !!timestamp .inf\nservices: {}\n",
            "bad-date": "x: 2026-13-01\nservices: {}\n",
            "bool-2": "x: !!bool 2\nservices: {}\n",
            "multi-doc": "---\na: 1\n---\nb: 2\n",
            "hugedec-int": "x: " + _HUGE_DEC + "\nservices: {}\n",
            "bare-list": "- not: a mapping\n",
        }
        with mock.patch.object(compose_svc, "DOCKER", self._fake_docker()):
            for label, doc in docs.items():
                with self.subTest(doc=label):
                    resp = self._validate_text(doc)
                    self.assertEqual(resp.status_code, 200, resp.text)
                    body = resp.json()
                    self.assertFalse(body["ok"])
                    self.assertNotIn("Traceback", body["message"])
                    self.assertNotIn("\ud800", json.dumps(body))

    def test_loadable_oddities_still_validate_through_the_cli(self):
        docs = {
            # Hex spellings load uncapped into a plain (huge) int — the
            # document is still a mapping and must reach the CLI check.
            "hugehex-int": "x: " + _HUGE_HEX + "\nservices: {}\n",
            "set-member": "x: !!set {a: null}\nservices: {}\n",
        }
        with mock.patch.object(compose_svc, "DOCKER", self._fake_docker()):
            for label, doc in docs.items():
                with self.subTest(doc=label):
                    resp = self._validate_text(doc)
                    self.assertEqual(resp.status_code, 200, resp.text)
                    self.assertTrue(resp.json()["ok"], resp.text)

    def test_a_deeply_nested_document_is_a_soft_outcome_either_way(self):
        # Where the parse survives the depth (Python-version dependent) the
        # mapping validates; where it RecursionErrors, the coded refusal
        # answers.  Neither outcome may be a 500 or an unrenderable body.
        doc = "a:" + " {b:" * 400 + " 1" + "}" * 400 + "\n"
        with mock.patch.object(compose_svc, "DOCKER", self._fake_docker()):
            resp = self._validate_text(doc)
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertIsInstance(body["ok"], bool)
        self.assertNotIn("Traceback", body["message"])

    def test_put_with_check_keeps_the_coded_400_for_unloadable_yaml(self):
        with mock.patch.object(compose_svc, "DOCKER", self._fake_docker()):
            resp = self._save(content="? [1,2]\n: x\n", check=True)
        self.assertEqual(resp.status_code, 400, resp.text)
        self.assertEqual(resp.json()["detail"]["code"], "compose.invalid")
        # The refusal happened before the write: the compose is untouched.
        self.assertEqual(self.compose.read_text(encoding="utf-8"), VALID_COMPOSE)


if __name__ == "__main__":
    unittest.main()
