"""Install must be transactional: a failed `docker compose up` may not leave a
registered stack or an orphan ~/Services/<id>/ behind, or every retry 409s
forever on "already installed".

Everything runs against a temp SERVICES_ROOT with a fake docker binary, so no
container is ever created and the live system is untouched.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from hub import catalog


class _FakeProc:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


TEMPLATE = """---
name: Rollback Fixture
desc: fixture
category: other
ports: ["59731"]
url_template: "http://{{HOST_IP}}:{{HOST_PORT}}"
vars:
  - name: HOST_PORT
    label: port
    default: "59731"
---
services:
  fixture:
    image: example/fixture:latest
    container_name: rollback-fixture
    ports:
      - "{{HOST_PORT}}:80"
    volumes:
      - ./data:/data
"""


class CatalogRollbackTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        tmp = Path(self._tmp.name)
        self.services = tmp / "Services"
        self.services.mkdir()
        self.templates = tmp / "templates"
        self.templates.mkdir()
        self.tid = "rollback-fixture"
        (self.templates / f"{self.tid}.yml").write_text(TEMPLATE)

        # A fake docker binary that is never actually executed (subprocess.run
        # is patched) but must exist so install_template takes the "up" path.
        self.docker = tmp / "docker"
        self.docker.write_text("#!/bin/sh\nexit 0\n")
        self.docker.chmod(0o755)

        self.registered: list[dict] = []

        patches = [
            mock.patch.object(catalog, "SERVICES_ROOT", self.services),
            mock.patch.object(catalog, "TEMPLATES", self.templates),
            mock.patch.object(catalog, "DOCKER", str(self.docker)),
            # never touch the real services.yaml
            mock.patch.object(
                catalog, "_register_stack",
                lambda tid, name, dest: self.registered.append(
                    {"id": tid, "name": name, "path": str(dest)}
                ),
            ),
            mock.patch.object(
                catalog, "_unregister_stack",
                lambda tid, dest=None: self.registered.clear(),
            ),
            # the fixture port must look free regardless of what the host runs
            mock.patch.object(catalog, "_port_is_bound", lambda port: False),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(self._tmp.cleanup)

    @property
    def dest_dir(self) -> Path:
        return self.services / self.tid

    # ── failure rolls everything back ───────────────────────────────────────
    def test_failed_up_removes_dir_and_registration(self):
        with mock.patch.object(
            catalog.subprocess, "run",
            return_value=_FakeProc(1, stderr="Error: port is already allocated"),
        ):
            r = catalog.install_template(self.tid, {})

        self.assertFalse(r["ok"])
        self.assertIn("port is already allocated", r["message"])
        self.assertFalse(
            self.dest_dir.exists(),
            f"orphan directory left behind: {self.dest_dir}",
        )
        self.assertEqual(self.registered, [], "stack registration left behind")
        self.assertIsNone(r["stack_id"])

    def test_retry_after_failure_is_not_409(self):
        """The actual reported bug: second attempt used to fail forever."""
        with mock.patch.object(
            catalog.subprocess, "run", return_value=_FakeProc(1, stderr="boom")
        ):
            catalog.install_template(self.tid, {})
        # retry now succeeds instead of raising "already installed"
        with mock.patch.object(
            catalog.subprocess, "run", return_value=_FakeProc(0, stdout="Started")
        ):
            r2 = catalog.install_template(self.tid, {})
        self.assertTrue(r2["ok"], r2["message"])
        self.assertTrue((self.dest_dir / "docker-compose.yml").exists())

    def test_exception_during_up_also_rolls_back(self):
        with mock.patch.object(
            catalog.subprocess, "run",
            side_effect=catalog.subprocess.TimeoutExpired("docker", 600),
        ):
            r = catalog.install_template(self.tid, {})
        self.assertFalse(r["ok"])
        self.assertFalse(self.dest_dir.exists())
        self.assertEqual(self.registered, [])

    # ── never delete user data ──────────────────────────────────────────────
    def test_preexisting_dir_with_user_data_is_kept(self):
        self.dest_dir.mkdir()
        keeper = self.dest_dir / "data" / "important.db"
        keeper.parent.mkdir(parents=True)
        keeper.write_text("user data")

        with mock.patch.object(
            catalog.subprocess, "run", return_value=_FakeProc(1, stderr="boom")
        ):
            r = catalog.install_template(self.tid, {})

        self.assertFalse(r["ok"])
        self.assertTrue(self.dest_dir.exists(), "pre-existing dir must survive")
        self.assertEqual(keeper.read_text(), "user data")
        self.assertEqual(self.registered, [], "stack registration still removed")

    # ── success leaves things in place ──────────────────────────────────────
    def test_success_keeps_dir_and_registration(self):
        with mock.patch.object(
            catalog.subprocess, "run", return_value=_FakeProc(0, stdout="Started")
        ):
            r = catalog.install_template(self.tid, {})
        self.assertTrue(r["ok"], r["message"])
        self.assertTrue((self.dest_dir / "docker-compose.yml").exists())
        self.assertEqual(len(self.registered), 1)
        self.assertEqual(r["stack_id"], self.tid)

    def test_missing_docker_cli_is_not_a_rollback(self):
        """No docker CLI => files kept so the user can start it later."""
        with mock.patch.object(catalog, "DOCKER", str(self.services / "nope")), \
             mock.patch.object(catalog.shutil, "which", return_value=None):
            r = catalog.install_template(self.tid, {})
        self.assertFalse(r["ok"])
        self.assertTrue((self.dest_dir / "docker-compose.yml").exists())
        self.assertEqual(len(self.registered), 1)


class PortConflictTest(unittest.TestCase):
    """install_template() must fail fast, before writing anything."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        tmp = Path(self._tmp.name)
        self.services = tmp / "Services"
        self.services.mkdir()
        self.templates = tmp / "templates"
        self.templates.mkdir()
        self.tid = "rollback-fixture"
        (self.templates / f"{self.tid}.yml").write_text(TEMPLATE)
        patches = [
            mock.patch.object(catalog, "SERVICES_ROOT", self.services),
            mock.patch.object(catalog, "TEMPLATES", self.templates),
            mock.patch.object(catalog, "_register_stack", lambda *a, **k: None),
            mock.patch.object(catalog, "_unregister_stack", lambda *a, **k: None),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(self._tmp.cleanup)

    def test_port_bound_on_host_refuses_install(self):
        with mock.patch.object(catalog, "_port_is_bound", lambda port: True), \
             mock.patch.object(catalog.subprocess, "run") as run:
            with self.assertRaises(HTTPException) as ctx:
                catalog.install_template(self.tid, {})
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(ctx.exception.detail["code"], "catalog.port_in_use")
        self.assertEqual(ctx.exception.detail["params"]["port"], 59731)
        run.assert_not_called()
        self.assertFalse((self.services / self.tid).exists())

    def test_port_claimed_by_other_stack_refuses_install(self):
        other = self.services / "someone-else"
        other.mkdir()
        (other / "docker-compose.yml").write_text(
            'services:\n  x:\n    image: a\n    ports:\n      - "59731:80"\n'
        )
        with mock.patch.object(catalog, "_port_is_bound", lambda port: False), \
             mock.patch.object(catalog.subprocess, "run") as run:
            with self.assertRaises(HTTPException) as ctx:
                catalog.install_template(self.tid, {})
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(ctx.exception.detail["code"], "catalog.port_claimed")
        self.assertEqual(ctx.exception.detail["params"]["stack"], "someone-else")
        run.assert_not_called()
        self.assertFalse((self.services / self.tid).exists())

    def test_own_stack_does_not_count_as_claiming_its_port(self):
        """Reinstalling after rollback must not see itself as the conflict."""
        own = self.services / self.tid
        own.mkdir()
        (own / "docker-compose.yml").write_text(
            'services:\n  x:\n    image: a\n    ports:\n      - "59731:80"\n'
        )
        claimed = catalog._ports_claimed_by_stacks(exclude_id=self.tid)
        self.assertNotIn(59731, claimed)


class HostPortParsingTest(unittest.TestCase):
    def test_parses_list_inline_udp_and_ranges(self):
        body = """
services:
  a:
    image: x
    ports:
      - "8080:80"
      - "53:53/udp"
      - "127.0.0.1:9000:9000"
      - 7000:7000
    environment:
      - NOT_A_PORT=1234:5678
  b:
    image: y
    ports: ["6001:6001", "6002:6002"]
"""
        self.assertEqual(
            catalog._host_ports(body),
            [8080, 53, 9000, 7000, 6001, 6002],
        )

    def test_tcp_udp_pair_counted_once(self):
        body = (
            'services:\n  a:\n    image: x\n    ports:\n'
            '      - "22000:22000/tcp"\n      - "22000:22000/udp"\n'
        )
        self.assertEqual(catalog._host_ports(body), [22000])

    def test_container_only_port_is_not_a_host_port(self):
        body = 'services:\n  a:\n    image: x\n    ports:\n      - "80"\n'
        self.assertEqual(catalog._host_ports(body), [])


if __name__ == "__main__":
    unittest.main()
