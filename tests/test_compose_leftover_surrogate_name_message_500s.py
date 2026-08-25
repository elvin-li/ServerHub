"""Leftover Compose-editor 500s: the unscrubbed validate message sink and
the raw ``name`` POST /api/compose persisted into services.yaml.

Prior sweeps sealed most of this surface: ``_stack_paths`` probes ids with
``_field_text`` (test_leftover_stack_field_500s), ``get_compose`` clamps a
>4300-digit ``st_mtime`` (test_leftover_compose_digit_500s), the vanished
docker CLI answers the coded 503 only after the fresh disk probe
(test_catalog_cli_missing_leftover_503), and engine-down classification is
pinned in test_engine_down_net_compose_503.  This hunt covered two
survivors and pins the rest of the surface as stays-immune:

* **fixed** — ``validate_compose_text`` built its ``message`` from
  ``run_capped`` output with a bare bytes-decode / ``str(text)`` and no
  surrogate scrub.  The dict returns to POST /api/compose/validate
  verbatim, so a lone ``\\ud800`` in the text 500'd Starlette's UTF-8
  encode *outside* the function's blanket except, and ``str()`` of an
  already-int leftover past CPython's 4300-digit cap is itself the
  ValueError.  The sink now funnels through ``_utf8_text``.

* **fixed** — ``create_stack`` persisted the request ``name`` into the
  services.yaml stacks registry raw.  ``json.loads`` accepts the
  ``"\\ud800"`` escape, so a browser POST could plant a lone surrogate
  every later reader had to re-scrub (the vms rename-echo class), and a
  leftover *already-int* name past the digit cap made ``config._dump``
  raise its coded 503 (settings.save_failed) *after* the stack directory
  and compose file were already created — a half-created stack reported
  as failure.  ``_field_text`` now probes the name (the str() probe, not
  an ``isinstance(str)`` gate: a numeric YAML/JSON name must render, not
  be silently dropped), with the stack id as fallback.

os.kill leftovers (the fourth sweep class) do not apply here: nothing in
hub/compose_svc.py or the compose part of hub/routers/modules_api.py
signals a pid.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml  # noqa: E402

from hub import compose_svc, config, containers_svc  # noqa: E402

#: Loads as an int past CPython's 4300-digit str<->int cap: hex conversion
#: is uncapped (a power-of-two base), so the value exists in memory and
#: only str() explodes.
_HUGE_INT = yaml.safe_load("v: 0x" + "f" * 5000)["v"]

#: A lone surrogate exactly as ``json.loads('"my \\ud800 app"')`` builds it.
_SUR_NAME = "my \ud800 app"


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does to a payload."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class ValidateMessageSinkTests(unittest.TestCase):
    """The ``message`` POST /api/compose/validate serves must always encode."""

    def setUp(self):
        self.tmp = Path(
            os.environ.get("TMPDIR", "/tmp")
        ) / f"compose-msg-{os.getpid()}-{id(self)}"
        self.tmp.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _validate(self, run_result):
        with mock.patch.object(
            compose_svc, "run_capped", return_value=run_result
        ):
            return compose_svc.validate_compose_text(
                "services: {}\n", cwd=str(self.tmp)
            )

    def test_surrogate_cli_text_is_scrubbed_not_a_500(self):
        # The blanket except cannot save this one: the dict left the
        # function fine and Starlette's UTF-8 encode raised in the router.
        v = self._validate((1, "bad \ud800 output"))
        self.assertFalse(v["ok"])
        self.assertNotIn("\ud800", v["message"])
        self.assertIn("bad", v["message"])
        _starlette(v)

    def test_already_int_text_past_the_digit_cap_falls_back(self):
        # ``str(text)`` was the conversion that raised; the junk drops.
        v = self._validate((1, _HUGE_INT))
        self.assertFalse(v["ok"])
        self.assertEqual(v["message"], "invalid")
        _starlette(v)

    def test_leftover_bytes_text_still_decodes(self):
        v = self._validate((1, b"oops \xff"))
        self.assertFalse(v["ok"])
        self.assertIn("oops", v["message"])
        _starlette(v)

    def test_a_genuine_yaml_error_message_is_untouched(self):
        v = self._validate((1, "services.web.ports must be a list"))
        self.assertFalse(v["ok"])
        self.assertEqual(v["message"], "services.web.ports must be a list")

    def test_the_valid_verdict_is_untouched(self):
        v = self._validate((0, ""))
        self.assertTrue(v["ok"])
        self.assertEqual(v["message"], "valid")


class _RegistrySandbox(unittest.TestCase):
    """A real services.yaml behind config.mutate, torn down completely."""

    def setUp(self):
        root = Path(os.environ.get("TMPDIR", "/tmp")) / (
            f"compose-name-{os.getpid()}-{id(self)}"
        )
        (root / "data").mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        for target, value in (
            ("YAML_PATH", root / "services.yaml"),
            ("DATA_DIR", root / "data"),
            ("BASE", root),
        ):
            patched = mock.patch.object(config, target, value)
            patched.start()
            self.addCleanup(patched.stop)
        self.addCleanup(config.reload_cfg)
        self.root = root
        self.yaml_path = root / "services.yaml"
        config.save_full({"stacks": []})

    def _create(self, stack_id: str, name):
        with (
            mock.patch.object(compose_svc, "user_home", return_value=self.root),
            mock.patch.object(
                compose_svc,
                "validate_compose_text",
                return_value={"ok": True, "message": "valid"},
            ),
        ):
            return compose_svc.create_stack(stack_id, name, "services: {}\n")

    def _registered(self, stack_id: str) -> dict:
        rows = config._read_disk().get("stacks") or []
        for row in rows:
            if isinstance(row, dict) and row.get("id") == stack_id:
                return row
        raise AssertionError(f"stack {stack_id!r} was not registered")


class CreateStackNameProbeTests(_RegistrySandbox):
    def test_surrogate_name_is_scrubbed_before_it_lands_on_disk(self):
        # json.loads accepts the "\ud800" escape, so a browser POST could
        # plant the raw surrogate into services.yaml for every later
        # reader to trip over (the vms rename-echo class).
        r = self._create("myapp", _SUR_NAME)
        self.assertTrue(r["ok"])
        row = self._registered("myapp")
        self.assertNotIn("\ud800", row["name"])
        # Still a real name, not dropped to the fallback.
        self.assertIn("my", row["name"])
        _starlette({"stacks": config._read_disk().get("stacks")})

    def test_already_int_name_past_the_digit_cap_creates_the_stack(self):
        # config._dump's ValueError guard answered the coded 503 — but only
        # after the stack directory and compose file were already created,
        # so the operator saw a failure for a create that half-happened.
        r = self._create("hugename", _HUGE_INT)
        self.assertTrue(r["ok"])
        row = self._registered("hugename")
        self.assertEqual(row["name"], "hugename")
        self.assertTrue(
            (self.root / "Services" / "hugename" / "docker-compose.yml").is_file()
        )

    def test_numeric_name_renders_instead_of_being_dropped(self):
        # The str() probe rule: a numeric name must keep rendering, not be
        # silently swallowed by an isinstance(str) gate (and not be stored
        # as a raw YAML int either).
        r = self._create("numname", 8080)
        self.assertTrue(r["ok"])
        self.assertEqual(self._registered("numname")["name"], "8080")

    def test_bool_name_falls_back_to_the_stack_id(self):
        # bool passes isinstance(int) and used to be stored as YAML `true`.
        r = self._create("boolname", True)
        self.assertTrue(r["ok"])
        self.assertEqual(self._registered("boolname")["name"], "boolname")

    def test_missing_name_keeps_the_stack_id_fallback(self):
        r = self._create("noname", None)
        self.assertTrue(r["ok"])
        self.assertEqual(self._registered("noname")["name"], "noname")

    def test_a_clean_name_is_stored_verbatim(self):
        r = self._create("cleanname", "My App")
        self.assertTrue(r["ok"])
        self.assertEqual(self._registered("cleanname")["name"], "My App")


class ComposeStaysImmunePins(unittest.TestCase):
    """The rest of the sweep surface, pinned as already immune."""

    def setUp(self):
        self.tmp = Path(
            os.environ.get("TMPDIR", "/tmp")
        ) / f"compose-pin-{os.getpid()}-{id(self)}"
        self.services = self.tmp / "Services"
        self.stackdir = self.services / "web"
        self.stackdir.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.compose = self.stackdir / "docker-compose.yml"
        self.compose.write_text("services: {}\n", encoding="utf-8")

    def _cfg_patches(self, stacks):
        return (
            mock.patch.object(
                containers_svc, "cfg", return_value={"stacks": stacks}
            ),
            mock.patch.object(containers_svc, "user_home", return_value=None),
        )

    def test_numeric_yaml_stack_id_still_reaches_its_compose(self):
        # YAML ``id: 42`` loads as an int; the _field_text probe renders
        # "42" so GET /api/compose/42 finds it — an isinstance(str) gate
        # here would silently rename the stack and 404 it.
        cfg_patch, home_patch = self._cfg_patches(
            [{"id": 42, "name": 42, "path": str(self.stackdir)}]
        )
        with cfg_patch, home_patch:
            data = compose_svc.get_compose("42")
            self.assertEqual(data["id"], "42")
            self.assertEqual(data["name"], "42")
            _starlette(data)
            with mock.patch.object(
                compose_svc, "user_home", return_value=self.tmp
            ):
                saved = compose_svc.save_compose(
                    "42", "services: {x: {image: a}}\n", validate=False
                )
        self.assertTrue(saved["ok"])

    def test_surrogate_id_and_name_on_the_path_branch_encode(self):
        entry = yaml.safe_load('id: "st\\ud800ack"\nname: "n\\ud800m"\n')
        entry["path"] = str(self.stackdir)
        cfg_patch, home_patch = self._cfg_patches([entry])
        with cfg_patch, home_patch:
            listed = containers_svc._stack_paths()
            data = compose_svc.get_compose(listed[0]["id"])
        self.assertNotIn("\ud800", data["id"])
        self.assertNotIn("\ud800", data["name"])
        _starlette(data)

    def test_surrogate_content_is_scrubbed_before_the_write(self):
        cfg_patch, home_patch = self._cfg_patches(
            [{"id": "web", "name": "web", "path": str(self.stackdir)}]
        )
        with cfg_patch, home_patch, mock.patch.object(
            compose_svc, "user_home", return_value=self.tmp
        ):
            r = compose_svc.save_compose(
                "web", "services: {}\n# x\ud800y\n", validate=False
            )
        self.assertTrue(r["ok"])
        on_disk = self.compose.read_text(encoding="utf-8")
        self.assertNotIn("\ud800", on_disk)
        _starlette(r)

    def test_surrogate_cwd_is_a_soft_failure_not_a_500(self):
        v = compose_svc.validate_compose_text(
            "services: {}\n", cwd=str(self.tmp / "x\ud800dir")
        )
        self.assertFalse(v["ok"])
        _starlette(v)

    def test_huge_plain_decimal_yaml_value_is_a_soft_failure(self):
        # Plain decimal hits the int(str) cap inside the YAML constructor;
        # ValueError is in the handled set, so the verdict is ok:false.
        v = compose_svc.validate_compose_text(
            "x: " + "9" * 5000 + "\nservices: {}\n", cwd=str(self.stackdir)
        )
        self.assertFalse(v["ok"])
        _starlette(v)

    def test_huge_hex_yaml_key_is_a_soft_failure_not_a_500(self):
        # A 5000-char plain scalar key exceeds YAML's 1024-char implicit-key
        # limit, so this is a syntax verdict; the point of the pin is that
        # neither the parse nor the message render raises out of the
        # handler, and the verdict still encodes.
        v = compose_svc.validate_compose_text(
            "0x" + "f" * 5000 + ": {}\nservices: {}\n",
            cwd=str(self.stackdir),
        )
        self.assertFalse(v["ok"])
        _starlette(v)

    def test_huge_hex_yaml_explicit_key_does_not_break_validation(self):
        # An *explicit* key (``? 0xfff…``) dodges the 1024-char implicit-key
        # limit, so the over-cap int really does become a dict key here;
        # validation only type-checks the document and must not render it.
        with mock.patch.object(
            compose_svc, "run_capped", return_value=(0, "")
        ):
            v = compose_svc.validate_compose_text(
                "? 0x" + "f" * 5000 + "\n: {}\nservices: {}\n",
                cwd=str(self.stackdir),
            )
        self.assertTrue(v["ok"])
        _starlette(v)


if __name__ == "__main__":
    unittest.main(verbosity=2)
