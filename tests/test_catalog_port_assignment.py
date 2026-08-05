"""The app store must move a busy default port, not refuse the install.

Every shipped template hardcodes a conventional host port -- AdGuard 3000,
Uptime Kuma 3001, Postgres 5432, Redis 6379, Mosquitto 1883 -- and a host that
already runs a few services has most of them taken.  The installer used to fail
fast with "host port N is already in use", which is accurate and useless: a third
of the catalogue was uninstallable with no route forward from the UI, and two
templates (dockge, navidrome) declared ``HOST_PORT`` required with no default at
all, so they failed as a missing variable before any port was even considered.

Every host port in the shipped templates comes from a template variable, so moving
one is safe.  These tests pin that, and pin the boundary that keeps it safe: a port
the operator typed themselves is a requirement, not a hint, so a conflict there is
still refused rather than silently relocated.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from fastapi import HTTPException  # noqa: E402

from hub import catalog  # noqa: E402

SINGLE_PORT_TEMPLATE = """---
name: Porty
desc: test fixture
vars:
  - name: HOST_PORT
    default: "3001"
---
services:
  app:
    image: example/app
    ports:
      - "{{HOST_PORT}}:3001"
"""


class PortVarDetectionTests(unittest.TestCase):
    def test_recognises_the_names_templates_actually_use(self):
        for name in ("HOST_PORT", "WEB_PORT", "DNS_PORT", "MQTT_PORT",
                     "ADMIN_PORT", "HTTP_PORT", "HTTPS_PORT", "WS_PORT"):
            self.assertTrue(catalog._is_port_var(name), name)

    def test_does_not_claim_unrelated_variables(self):
        for name in ("PASSWORD", "MUSIC_PATH", "TZ", "STACKS_DIR", "WG_HOST"):
            self.assertFalse(catalog._is_port_var(name), name)


class NextFreePortTests(unittest.TestCase):
    def test_returns_the_preferred_port_when_free(self):
        with patch.object(catalog, "_port_is_bound", return_value=False):
            self.assertEqual(catalog._next_free_port(3001, {}, set()), 3001)

    def test_skips_a_port_bound_on_the_host(self):
        with patch.object(catalog, "_port_is_bound", side_effect=lambda p: p in (3001, 3002)):
            self.assertEqual(catalog._next_free_port(3001, {}, set()), 3003)

    def test_skips_a_port_claimed_by_an_installed_stack(self):
        with patch.object(catalog, "_port_is_bound", return_value=False):
            self.assertEqual(
                catalog._next_free_port(6379, {6379: "immich"}, set()), 6380
            )

    def test_does_not_hand_out_the_same_port_twice_in_one_install(self):
        """A template asking for three ports must get three distinct ones."""
        with patch.object(catalog, "_port_is_bound", return_value=False):
            reserved: set[int] = set()
            got = []
            for _ in range(3):
                port = catalog._next_free_port(8080, {}, reserved)
                reserved.add(port)
                got.append(port)
        self.assertEqual(got, [8080, 8081, 8082])
        self.assertEqual(len(set(got)), 3)

    def test_falls_back_to_a_sane_base_for_a_nonsense_preference(self):
        with patch.object(catalog, "_port_is_bound", return_value=False):
            self.assertEqual(catalog._next_free_port(0, {}, set()), 8000)
            self.assertEqual(catalog._next_free_port(99999, {}, set()), 8000)


TEMPLATE = """---
name: Porty
desc: test fixture
vars:
  - name: HOST_PORT
    default: "3001"
  - name: NO_DEFAULT_PORT
    required: true
---
services:
  app:
    image: example/app
    ports:
      - "{{HOST_PORT}}:3001"
      - "{{NO_DEFAULT_PORT}}:9000"
"""


class InstallPortResolutionTests(unittest.TestCase):
    """Drives install_template far enough to see the resolved variables.

    The install is stopped at the port check by making every port look busy for
    the *final* guard only, so no files are written and no container is started.
    """

    def setUp(self):
        # Real directories rather than a patched Path.exists: install_template
        # asks `exists()` about both the template source and the destination, and
        # a blanket patch answers True to both, tripping "already installed".
        self._tmp = TemporaryDirectory()
        root = Path(self._tmp.name)
        self.templates = root / "templates"
        self.templates.mkdir()
        (self.templates / "porty.yml").write_text(TEMPLATE)
        self.services = root / "services"
        self.services.mkdir()
        self.addCleanup(self._tmp.cleanup)
        for attr, value in (("TEMPLATES", self.templates), ("SERVICES_ROOT", self.services)):
            p = patch.object(catalog, attr, value)
            p.start()
            self.addCleanup(p.stop)

    def _resolve(self, supplied: dict, bound: set[int]) -> dict:
        captured: dict = {}

        def fake_check(rendered: str, template_id: str) -> None:
            captured["rendered"] = rendered
            raise RuntimeError("stop-before-write")

        with (
            patch.object(catalog, "_ports_claimed_by_stacks", return_value={}),
            patch.object(catalog, "_port_is_bound", side_effect=lambda p: p in bound),
            patch.object(catalog, "_check_ports_free", side_effect=fake_check),
        ):
            with self.assertRaises(RuntimeError):
                catalog.install_template("porty", supplied)
        return captured

    def _expect_refusal(self, template_body: str, supplied: dict,
                        claimed: dict, bound: set[int]) -> dict:
        (self.templates / "porty.yml").write_text(template_body)
        with (
            patch.object(catalog, "_ports_claimed_by_stacks", return_value=claimed),
            patch.object(catalog, "_port_is_bound", side_effect=lambda p: p in bound),
        ):
            with self.assertRaises(HTTPException) as ctx:
                catalog.install_template("porty", supplied)
        return ctx.exception.detail

    def test_busy_default_is_moved_to_the_next_free_port(self):
        captured = self._resolve({}, bound={3001, 3002})
        self.assertIn('"3003:3001"', captured["rendered"])

    def test_variable_with_no_default_still_gets_a_port(self):
        """This was a hard 'missing required variable' failure before."""
        captured = self._resolve({}, bound=set())
        self.assertIn('"3001:3001"', captured["rendered"])
        # 8000 is the fallback base for a port var the template left blank.
        self.assertIn('"8000:9000"', captured["rendered"])

    def test_an_explicitly_chosen_free_port_is_honoured_exactly(self):
        captured = self._resolve({"HOST_PORT": "9999"}, bound=set())
        self.assertIn('"9999:3001"', captured["rendered"])

    def test_an_explicitly_chosen_busy_port_is_refused_not_moved(self):
        """Silently relocating a port the operator picked would hide their intent."""
        detail = self._expect_refusal(
            SINGLE_PORT_TEMPLATE, {"HOST_PORT": "9999"}, claimed={}, bound={9999}
        )
        self.assertEqual(detail.get("code"), "catalog.port_in_use")

    def test_a_port_claimed_by_another_stack_names_that_stack(self):
        detail = self._expect_refusal(
            SINGLE_PORT_TEMPLATE, {"HOST_PORT": "6379"},
            claimed={6379: "immich"}, bound=set(),
        )
        self.assertEqual(detail.get("code"), "catalog.port_claimed")
        self.assertEqual(detail.get("params", {}).get("stack"), "immich")


if __name__ == "__main__":
    unittest.main()
