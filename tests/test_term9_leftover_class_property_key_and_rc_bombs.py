"""Terminal leftover sweep #9: __class__-property, hostile-key and rc bombs.

A fresh hunt over the terminal settings/listing JSON surfaces (GET
/api/terminal, POST /api/terminal/run, the terminal branch of GET/PUT
/api/settings, and the PTY handshake's config reads) replayed the leftover
zoo through the established in-process seams — poisoned
``settings_section("terminal")`` values/keys and poisoned ``_run`` receipts
— and found genuinely live raw 500s term 8 had not reached:

* **fixed** — a leftover ``settings.terminal`` value whose ``__class__`` is
  a *raising property* detonated ``_config_text``'s bare
  ``isinstance(value, str)`` gate itself (``isinstance`` consults
  ``value.__class__`` when the exact-type check misses): a raw 500 on GET
  /api/terminal and POST /api/terminal/run, one line ahead of the
  laundering built to absorb junk scalars.  A *lying* ``__class__`` (claims
  str, is not) rode through the gate and TypeError'd the unbound
  ``str.__str__`` copy the same way.  ``_isa`` (the storage_svc/vms_svc
  rule) plus a try around the unbound copy degrade both;

* **fixed** — a leftover str-subclass *key* whose hash shadows
  ``host_enabled``/``cwd``/``shell`` and whose ``__eq__`` raises detonated
  the plain-dict hash probes: ``host_enabled()`` / ``_cfg_value`` (a 500 on
  GET /api/terminal and POST /api/terminal/run), the ``_as_map(...).get``
  read in GET /api/settings' terminal render, and PUT /api/settings'
  ``cur_tm.update(tm)`` insert probe.  ``_mapping_get`` /
  ``_merged_section`` degrade the shadowed field to its default — for the
  host-shell RCE gate the safe default is *locked* (the coded 403);

* **fixed** — the same ``__class__``-property bomb riding a stored section
  back through PUT /api/settings escaped as a RuntimeError (not the
  YAMLError ``config._dump`` retried on) out of the dumper's own
  ``ignore_aliases`` isinstance, out of ``deep_merge``'s bare rank gate,
  and out of ``_renderable_tree``'s gates on the retry walk — a raw 500
  where every other unrenderable node already degraded.  The save now
  lands with the bomb node dropped and every sibling kept;

* **fixed** — ``run_container`` does not own ``_run``'s receipt (tests and
  tooling patch it), and an rc-*subclass* whose ``__eq__``/``__ne__``
  raises detonated the bare ``result["rc"] != 0`` probe, while a
  stdout/stderr subclass whose ``__bool__``/``__str__`` raises detonated
  the engine-down or-truthiness f-string — raw 500s *after* the command
  had already executed.  ``_rc_int`` + ``_config_text`` on the probe
  inputs degrade both.

Stays-immune pins: ``host_enabled`` value bombs (``_cfg_truthy`` was
already guarded), the PTY handshake's ``_argv`` over every poisoned
section shape, and the sanitizer unit contracts the fixes rely on.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import yaml
from fastapi.testclient import TestClient

from hub import config, terminal_pty, terminal_svc
from hub.auth import require_auth
from hub.routers import settings_api

JSON_HDR = {"Content-Type": "application/json"}

_APP = None


def _client() -> TestClient:
    global _APP
    if _APP is None:
        from hub.app_factory import create_app

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> str:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    text = json.dumps(payload, ensure_ascii=False, allow_nan=False)
    text.encode("utf-8")
    return text


class _ClassBomb:
    """``__class__`` is a raising property: every bare isinstance detonates."""

    @property
    def __class__(self):
        raise RuntimeError("leftover __class__ bomb")


class _LyingClassStr:
    """Claims to be a str; the unbound ``str.__str__`` copy TypeErrors."""

    @property
    def __class__(self):
        return str


class _LyingClassDict:
    """Claims to be a dict; the unbound ``dict.items`` view TypeErrors."""

    @property
    def __class__(self):
        return dict


class _EqBombKey(str):
    """Hash-shadows a real settings key; the lookup's ``__eq__`` raises."""

    __hash__ = str.__hash__

    def __eq__(self, other):
        raise RuntimeError("leftover key eq bomb")

    def __ne__(self, other):
        raise RuntimeError("leftover key ne bomb")


class _RcBomb(int):
    __hash__ = int.__hash__

    def __eq__(self, other):
        raise RuntimeError("leftover rc eq bomb")

    def __ne__(self, other):
        raise RuntimeError("leftover rc ne bomb")


class _BoolStrBomb(str):
    """Output subclass whose truthiness and rendering both raise."""

    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")

    def __str__(self):
        raise RuntimeError("leftover __str__ bomb")


class _TerminalSectionSandbox(unittest.TestCase):
    """Poisoned settings_section("terminal") + scratch audit path."""

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.audit = Path(tmp.name) / "terminal-audit.jsonl"
        patcher = mock.patch.object(terminal_svc, "AUDIT_PATH", self.audit)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client = _client()

    def _with_section(self, section: dict):
        return mock.patch.object(
            terminal_svc, "settings_section", return_value=section
        )

    def assert_coded_not_500(self, response, status: int) -> dict:
        self.assertEqual(response.status_code, status, response.text[:300])
        body = response.json()
        _starlette(body)
        return body


class TerminalStatusBombTests(_TerminalSectionSandbox):
    """GET /api/terminal over every poisoned-section shape: 200, encodable,
    every sibling field still present."""

    def test_class_bomb_values_render_200(self):
        for key in ("cwd", "shell"):
            with self.subTest(key=key):
                with self._with_section({key: _ClassBomb()}):
                    body = self.assert_coded_not_500(
                        self.client.get("/api/terminal"), 200
                    )
                # The bomb cannot 500 the listing; the healthy siblings and
                # the advertised limits all survive.
                self.assertIn("host_enabled", body)
                self.assertEqual(body["max_timeout"], terminal_svc.MAX_TIMEOUT)

    def test_lying_class_str_cwd_degrades_to_home(self):
        with self._with_section({"cwd": _LyingClassStr()}):
            body = self.assert_coded_not_500(self.client.get("/api/terminal"), 200)
        # Unreadable scalar: the fallback chain answers a real directory.
        self.assertTrue(body["cwd"])
        self.assertNotIn("_LyingClassStr", body["cwd"])

    def test_eq_bomb_key_shadowing_host_enabled_reads_locked(self):
        with self._with_section({_EqBombKey("host_enabled"): True}):
            body = self.assert_coded_not_500(self.client.get("/api/terminal"), 200)
        # The shadowed RCE gate degrades to its default — locked.
        self.assertIs(body["host_enabled"], False)

    def test_eq_bomb_key_shadowing_cwd_keeps_the_siblings(self):
        with self._with_section({"host_enabled": True, _EqBombKey("cwd"): "/tmp"}):
            body = self.assert_coded_not_500(self.client.get("/api/terminal"), 200)
        self.assertIs(body["host_enabled"], True)
        self.assertTrue(body["cwd"])


class TerminalRunBombTests(_TerminalSectionSandbox):
    """POST /api/terminal/run over the same poisoned sections: the command
    still executes and answers its 200 receipt (or the coded 403 when the
    shadowed gate degrades to locked) — never a raw 500."""

    def _run(self):
        return self.client.post(
            "/api/terminal/run", json={"command": "echo term9-ok", "target": "host"}
        )

    def test_run_executes_over_value_bombs(self):
        for label, section in (
            ("class-bomb cwd", {"host_enabled": True, "cwd": _ClassBomb()}),
            ("lying-str cwd", {"host_enabled": True, "cwd": _LyingClassStr()}),
            ("lying-str shell", {"host_enabled": True, "shell": _LyingClassStr()}),
            ("eq-bomb shell key", {"host_enabled": True, _EqBombKey("shell"): "/bin/sh"}),
        ):
            with self.subTest(label=label):
                with self._with_section(section):
                    body = self.assert_coded_not_500(self._run(), 200)
                self.assertIn("term9-ok", body["stdout"])
                self.assertEqual(body["rc"], 0)

    def test_eq_bomb_key_shadowing_the_gate_is_the_coded_403(self):
        with self._with_section({_EqBombKey("host_enabled"): True}):
            body = self.assert_coded_not_500(self._run(), 403)
        self.assertEqual(body["detail"]["code"], "terminal.host_disabled")

    def test_class_bomb_shell_is_a_receipt_not_a_500(self):
        # An unrenderable-typed shell still answers a run receipt (the spawn
        # fails rc-127) — the leftover degrades, the transport survives.
        with self._with_section({"host_enabled": True, "shell": _ClassBomb()}):
            body = self.assert_coded_not_500(self._run(), 200)
        self.assertEqual(body["rc"], 127)


class HostEnabledValueBombStaysImmuneTests(_TerminalSectionSandbox):
    """Stays-immune pins: a *value* bomb on the gate itself was already
    absorbed by ``_cfg_truthy`` (term 6); the __class__-property shape must
    keep riding the same guard."""

    def test_class_bomb_gate_value_never_500s_status(self):
        with self._with_section({"host_enabled": _ClassBomb()}):
            body = self.assert_coded_not_500(self.client.get("/api/terminal"), 200)
        # bool() reads the C-level slots, not __class__: a plain object is
        # truthy, and the flag stays a real bool either way.
        self.assertIsInstance(body["host_enabled"], bool)

    def test_bool_bomb_gate_value_still_reads_locked(self):
        class _BoolBomb:
            def __bool__(self):
                raise RuntimeError("leftover __bool__ bomb")

        with self._with_section({"host_enabled": _BoolBomb()}):
            body = self.assert_coded_not_500(self.client.get("/api/terminal"), 200)
        self.assertIs(body["host_enabled"], False)


class PtyHandshakeConfigBombTests(_TerminalSectionSandbox):
    """The PTY handshake's config reads (``_argv`` -> ``host_enabled`` /
    ``_resolve_cwd``) over the same poisoned sections: the coded refusal or
    a clean argv, never an unhandled exception."""

    def test_argv_survives_value_bombs(self):
        for label, section in (
            ("class-bomb cwd", {"host_enabled": True, "cwd": _ClassBomb()}),
            ("lying-str cwd", {"host_enabled": True, "cwd": _LyingClassStr()}),
            ("eq-bomb cwd key", {"host_enabled": True, _EqBombKey("cwd"): "/tmp"}),
        ):
            with self.subTest(label=label):
                with self._with_section(section):
                    argv, cwd = terminal_pty._argv("host", "", "")
                self.assertTrue(argv[0])
                self.assertTrue(cwd)

    def test_argv_refuses_coded_when_the_gate_key_is_shadowed(self):
        with self._with_section({_EqBombKey("host_enabled"): True}):
            with self.assertRaises(PermissionError):
                terminal_pty._argv("host", "", "")


class RunReceiptBombTests(_TerminalSectionSandbox):
    """Poisoned ``_run`` receipts through POST /api/terminal/run's container
    branch: the rc/engine-down probes degrade, never a raw 500 after the
    command already executed."""

    @staticmethod
    def _receipt(**kw) -> dict:
        base = {
            "ok": False, "rc": 1, "stdout": "x", "stderr": "y",
            "truncated": False, "duration_ms": 1,
        }
        base.update(kw)
        return base

    def _post(self, receipt: dict, engine_up: bool):
        with mock.patch.object(terminal_svc, "_run", return_value=receipt), \
                mock.patch.object(terminal_svc, "engine_up", return_value=engine_up):
            return self.client.post(
                "/api/terminal/run",
                json={"command": "echo hi", "target": "container", "container": "web"},
            )

    def test_rc_subclass_bomb_is_a_laundered_receipt(self):
        body = self.assert_coded_not_500(
            self._post(self._receipt(rc=_RcBomb(1)), engine_up=True), 200
        )
        # The unbound base read salvages the real exit status.
        self.assertEqual(body["rc"], 1)
        self.assertEqual(body["stdout"], "x")

    def test_stdout_bool_str_bomb_degrades_field_level(self):
        body = self.assert_coded_not_500(
            self._post(self._receipt(stdout=_BoolStrBomb("z")), engine_up=True), 200
        )
        # The unreadable field drops; the receipt and its siblings survive.
        self.assertEqual(body["stderr"], "y")
        self.assertEqual(body["rc"], 1)

    def test_stderr_bomb_quoting_engine_down_is_the_coded_503(self):
        receipt = self._receipt(
            stderr=_BoolStrBomb("cannot connect to the docker daemon")
        )
        body = self.assert_coded_not_500(self._post(receipt, engine_up=False), 503)
        self.assertEqual(body["detail"]["code"], "container.engine_down")


class _ConfigSandbox(unittest.TestCase):
    """Scratch services.yaml + data dir so PUT /api/settings runs a real
    mutate() against disk (the term 7 sandbox)."""

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        data = self.root / "data"
        data.mkdir()
        self.yaml_path = self.root / "services.yaml"
        for target, attr, value in (
            (config, "YAML_PATH", self.yaml_path),
            (config, "DATA_DIR", data),
            (config, "BASE", self.root),
            (config, "_LOCK_PATH", data / ".services.yaml.lock"),
        ):
            patcher = mock.patch.object(target, attr, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(config.reload_cfg)
        self.yaml_path.write_text(
            "settings:\n"
            "  auth:\n"
            "    enabled: true\n"
            "    username: admin\n"
            "    password_hash: sentinel-hash\n"
        )
        config.reload_cfg()
        self.client = _client()

    def stored(self) -> dict:
        return yaml.safe_load(self.yaml_path.read_text())


class SettingsListingTerminalBombTests(_ConfigSandbox):
    """GET /api/settings' terminal render over a poisoned stored section."""

    def _get(self, terminal_section: dict):
        poisoned = {"settings": {"terminal": terminal_section}}
        with mock.patch.object(settings_api, "cfg", return_value=poisoned):
            return self.client.get("/api/settings")

    def test_eq_bomb_key_degrades_the_gate_and_keeps_siblings(self):
        resp = self._get({_EqBombKey("host_enabled"): True})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        # The shadowed flag reads its safe default; every sibling section
        # around the terminal block still renders.
        self.assertIs(body["terminal"]["host_enabled"], False)
        self.assertIn("auth", body)
        self.assertIn("notify", body)

    def test_class_bomb_gate_value_stays_immune(self):
        resp = self._get({"host_enabled": _ClassBomb()})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        self.assertIsInstance(body["terminal"]["host_enabled"], bool)


class SettingsPutTerminalBombTests(_ConfigSandbox):
    """PUT /api/settings' terminal merge over a bombed stored section: the
    save lands, the bomb degrades, and every sibling key persists."""

    def _put(self, section: dict):
        with mock.patch.object(
            settings_api, "settings_section", return_value=section
        ):
            return self.client.put(
                "/api/settings", json={"terminal": {"host_enabled": False}}
            )

    def test_eq_bomb_stored_key_saves_200(self):
        # The update's insert probe used to run the hostile stored key's
        # __eq__ — a raw 500 out of put_settings before mutate() even ran.
        resp = self._put({_EqBombKey("host_enabled"): True, "cwd": "/tmp"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _starlette(resp.json())
        terminal = self.stored()["settings"]["terminal"]
        self.assertIs(terminal["host_enabled"], False)
        self.assertEqual(terminal["cwd"], "/tmp")
        self.assertEqual(
            self.stored()["settings"]["auth"]["password_hash"], "sentinel-hash"
        )

    def test_class_bomb_stored_value_saves_200_and_drops_the_node(self):
        # The bomb used to escape yaml's own ignore_aliases isinstance (a
        # RuntimeError, not the YAMLError _dump retried on) and deep_merge's
        # bare rank gate — a raw 500 out of mutate().
        resp = self._put({"cwd": _ClassBomb(), "keep": "/srv"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _starlette(resp.json())
        terminal = self.stored()["settings"]["terminal"]
        self.assertIs(terminal["host_enabled"], False)
        # The unrenderable node drops; its healthy sibling persists.
        self.assertNotIn("cwd", terminal)
        self.assertEqual(terminal["keep"], "/srv")
        self.assertEqual(
            self.stored()["settings"]["auth"]["password_hash"], "sentinel-hash"
        )

    def test_lying_class_stored_value_saves_200(self):
        resp = self._put({"cwd": _LyingClassStr(), "keep": "/srv"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        terminal = self.stored()["settings"]["terminal"]
        self.assertIs(terminal["host_enabled"], False)
        self.assertNotIn("cwd", terminal)
        self.assertEqual(terminal["keep"], "/srv")


class SanitizerUnitPinTests(unittest.TestCase):
    """The unit contracts the route fixes rely on."""

    def test_config_text_class_bomb_answers_an_exact_str(self):
        out = terminal_svc._config_text(_ClassBomb())
        self.assertIs(type(out), str)

    def test_config_text_lying_class_answers_empty(self):
        self.assertEqual(terminal_svc._config_text(_LyingClassStr()), "")

    def test_mapping_get_degrades_the_shadowed_field_only(self):
        section = {_EqBombKey("cwd"): "/x", "shell": "/bin/sh"}
        self.assertIsNone(terminal_svc._mapping_get(section, "cwd"))
        self.assertEqual(terminal_svc._mapping_get(section, "shell"), "/bin/sh")

    def test_rc_int_salvages_subclasses_and_degrades_bombs(self):
        self.assertEqual(terminal_svc._rc_int(_RcBomb(5)), 5)
        self.assertEqual(terminal_svc._rc_int(None), -255)
        self.assertEqual(terminal_svc._rc_int(True), -255)
        self.assertEqual(terminal_svc._rc_int(_ClassBomb()), -255)

    def test_jsonable_class_bomb_value_and_key_keep_siblings(self):
        out = terminal_svc._jsonable({"bomb": _ClassBomb(), "ok": 1})
        self.assertEqual(out["ok"], 1)
        self.assertIs(type(out["bomb"]), str)
        _starlette(out)
        keyed = terminal_svc._jsonable({_ClassBomb(): 1, "ok": 2})
        self.assertEqual(keyed["ok"], 2)
        _starlette(keyed)

    def test_jsonable_lying_class_shapes_degrade_not_raise(self):
        out = terminal_svc._jsonable({"d": _LyingClassDict(), "ok": 1})
        self.assertIsNone(out["d"])
        self.assertEqual(out["ok"], 1)
        _starlette(out)

    def test_renderable_tree_drops_the_class_bomb_and_keeps_siblings(self):
        out = config._renderable_tree({"bomb": _ClassBomb(), "ok": "/x"})
        self.assertEqual(out, {"ok": "/x"})

    def test_dump_survives_the_class_bomb_zoo(self):
        text = config._dump({
            "settings": {"terminal": {
                "cwd": _ClassBomb(),
                "lying": _LyingClassStr(),
                "keep": "/srv",
            }}
        })
        loaded = yaml.safe_load(text)
        self.assertEqual(loaded["settings"]["terminal"], {"keep": "/srv"})

    def test_deep_merge_survives_class_bomb_patch_values(self):
        merged = config.deep_merge(
            {"terminal": {"cwd": "/old"}},
            {"terminal": {"cwd": _ClassBomb(), "host_enabled": False}},
        )
        self.assertIs(merged["terminal"]["host_enabled"], False)


if __name__ == "__main__":
    unittest.main()
