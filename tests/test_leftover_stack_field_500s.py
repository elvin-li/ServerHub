"""Leftover stack-registry fields that still 500'd the Compose/Containers API.

Prior passes hardened these paths against inf/NaN floats, ``!!binary``,
``!!set`` and lone surrogates, and gave ``docker_cli._jsonable`` the
int->str digit-cap drop.  This sweep covered three survivors:

* **fixed** — ``containers_svc._field_text`` returned ``str(value)`` for an
  int with no guard.  CPython's int->str conversion cap (4300 digits) makes
  that ``str()`` itself raise ValueError, and YAML loads hex / leading-zero
  octal ints *uncapped* (``int(x, 16)`` / ``int(x, 8)`` are power-of-two
  bases) — so a leftover ``name: 0xfff…`` in services.yaml stacks or
  container overrides raised out of ``_stack_paths`` / ``_friendly_container``
  and 500'd GET /api/stacks, GET /api/containers, and GET /api/compose/{id}
  (which walks every stack to find its target).

* **fixed** — the *containers-only* stack branch of ``_stack_paths`` handed
  ``id`` (and the ``name`` fallback) to the payload raw, unlike the path
  branch beside it.  YAML double quotes load ``id: "\\ud800"`` as a lone
  surrogate str, and Starlette's UTF-8 encode then 500'd GET /api/stacks.

* **fixed** — ``compose_svc.validate_compose_text`` classified run_capped's
  ``(-1, "not found")`` sentinel as a vanished docker CLI without checking
  the binary was actually gone from disk.  The sentinel is *any*
  FileNotFoundError spawn — a stack cwd deleted mid-request raises the same
  way — so with the CLI present and the engine merely off, a compose
  save/create failed as the coded 503 ``container.engine_down`` and pointed
  the operator at the wrong remedy.  ``docker_cli.cli_on_disk`` now gates
  the classification (tested here; the engine-probe half of the contract is
  pinned in test_catalog_cli_missing_leftover_503).
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

import yaml  # noqa: E402

from hub import compose_svc, containers_svc, docker_cli  # noqa: E402

#: Loads as an int past CPython's 4300-digit str<->int cap: hex conversion
#: is uncapped, so the value exists in memory and only str() explodes.
_HUGE_HEX_YAML = "0x" + "f" * 5000
#: PyYAML's YAML-1.1 octal (leading zero) resolves to int uncapped too.
_HUGE_OCTAL_YAML = "0" + "7" * 6000


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does to a payload."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _load_int(yaml_literal: str) -> int:
    value = yaml.safe_load(f"name: {yaml_literal}")["name"]
    assert isinstance(value, int)
    return value


class FieldTextDigitPinTests(unittest.TestCase):
    """_field_text is the one funnel for stack/override display fields."""

    def test_yaml_hex_int_past_the_digit_cap_falls_back(self):
        # str(huge) is the failing conversion; before the guard the
        # ValueError raised out of every _field_text caller.
        self.assertEqual(
            containers_svc._field_text(_load_int(_HUGE_HEX_YAML), "fb"), "fb"
        )

    def test_yaml_octal_int_past_the_digit_cap_falls_back(self):
        self.assertEqual(
            containers_svc._field_text(_load_int(_HUGE_OCTAL_YAML), "fb"), "fb"
        )

    def test_sane_int_still_renders(self):
        self.assertEqual(containers_svc._field_text(8080), "8080")

    def test_existing_junk_fallbacks_survive(self):
        for value in (float("inf"), float("nan"), None, True, {"a": 1}, [1]):
            with self.subTest(value=str(value)[:12]):
                self.assertEqual(containers_svc._field_text(value, "fb"), "fb")


class StackPathsDigitPinTests(unittest.TestCase):
    """GET /api/stacks and GET /api/compose/{id} walk every configured stack,
    so one poisoned neighbor used to 500 both."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="stack-field-pin-"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.good = self.tmp / "goodstack"
        self.good.mkdir()
        (self.good / "docker-compose.yml").write_text("services: {}\n")

    def _patched(self, config):
        return (
            mock.patch.object(containers_svc, "cfg", return_value=config),
            mock.patch.object(containers_svc, "user_home", return_value=None),
        )

    def test_stack_paths_render_with_a_huge_int_name(self):
        config = {"stacks": [
            {"id": "poisoned", "name": _load_int(_HUGE_HEX_YAML),
             "path": str(self.tmp / "missing")},
        ]}
        cfg_patch, home_patch = self._patched(config)
        with cfg_patch, home_patch:
            stacks = containers_svc._stack_paths()
        self.assertEqual(len(stacks), 1)
        # The unusable name falls back to the directory name.
        self.assertEqual(stacks[0]["name"], "missing")
        _starlette({"stacks": stacks})

    def test_get_compose_survives_a_poisoned_neighbor_stack(self):
        config = {"stacks": [
            {"id": "poisoned", "name": _load_int(_HUGE_HEX_YAML),
             "path": str(self.tmp / "missing")},
            {"id": "goodstack", "name": "Good", "path": str(self.good)},
        ]}
        cfg_patch, home_patch = self._patched(config)
        with cfg_patch, home_patch:
            data = compose_svc.get_compose("goodstack")
        self.assertEqual(data["id"], "goodstack")
        self.assertEqual(data["content"], "services: {}\n")
        _starlette(data)


class StackPathsSurrogatePinTests(unittest.TestCase):
    """The containers-only branch must clean id/name like the path branch."""

    def _stacks(self, entry):
        with (
            mock.patch.object(
                containers_svc, "cfg", return_value={"stacks": [entry]}
            ),
            mock.patch.object(containers_svc, "user_home", return_value=None),
        ):
            return containers_svc._stack_paths()

    def test_surrogate_id_on_a_containers_only_stack_encodes(self):
        # YAML double quotes load "\ud800" as a lone surrogate; the raw id
        # used to reach Starlette's UTF-8 encode and 500 GET /api/stacks.
        entry = yaml.safe_load(
            'id: "st\\ud800ack"\ncontainers: [db]\n'
        )
        stacks = self._stacks(entry)
        self.assertEqual(len(stacks), 1)
        _starlette({"stacks": stacks})
        self.assertEqual(stacks[0]["containers"], ["db"])

    def test_surrogate_name_fallback_encodes_too(self):
        entry = yaml.safe_load(
            'id: "st\\ud800ack"\nname: "\\ud800"\ncontainers: [db]\n'
        )
        stacks = self._stacks(entry)
        self.assertEqual(len(stacks), 1)
        _starlette({"stacks": stacks})

    def test_clean_containers_only_stack_keeps_its_id(self):
        stacks = self._stacks({"id": "media", "containers": ["plex"]})
        self.assertEqual(stacks[0]["id"], "media")
        self.assertEqual(stacks[0]["name"], "media")
        self.assertIsNone(stacks[0]["compose_path"])


class CliOnDiskPinTests(unittest.TestCase):
    """cli_on_disk distinguishes a vanished binary from a vanished cwd."""

    def test_present_binary_reads_on_disk(self):
        with tempfile.NamedTemporaryFile() as fh:
            with mock.patch.object(docker_cli, "DOCKER", fh.name):
                self.assertTrue(docker_cli.cli_on_disk())

    def test_missing_binary_reads_gone(self):
        with mock.patch.object(
            docker_cli, "DOCKER", "/definitely/not/a/real/docker-xyz"
        ):
            self.assertFalse(docker_cli.cli_on_disk())

    def test_dying_mount_counts_as_gone(self):
        # EIO out of exists() means the CLI is unreachable either way.
        with (
            mock.patch.object(docker_cli, "DOCKER", "/x/docker"),
            mock.patch.object(Path, "exists", side_effect=OSError(5, "EIO")),
        ):
            self.assertFalse(docker_cli.cli_on_disk())


if __name__ == "__main__":
    unittest.main()
