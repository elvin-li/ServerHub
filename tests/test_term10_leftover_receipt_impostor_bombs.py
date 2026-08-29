"""Terminal leftover sweep #10: receipt impostors, bool-liars and shadow keys.

A fresh hunt over the terminal HTTP surfaces (GET /api/terminal, POST
/api/terminal/run host *and* container branches, GET /api/terminal/history)
replayed the leftover zoo through the established in-process seams —
poisoned ``settings_section("terminal")`` sections and poisoned ``_run``
receipts — and found genuinely live raw 500s term 9 had not reached:

* **fixed** — a *bool-liar* (an object whose ``__class__`` property returns
  ``bool``) passed ``_jsonable``'s ``_isa(value, bool)`` gate and escaped
  the launder raw: Starlette's encoder TypeError'd on it — a raw 500 on
  POST /api/terminal/run *after* the command had already executed.  bool
  cannot be subclassed, so the gate is now ``type(value) is bool`` and the
  impostor degrades to None through the int gate's unbound ``__index__``;

* **fixed** — ``run_host``/``run_container`` indexed and *mutated* the run
  receipt bare (``result["stdout"]``, ``result["target"] = ...``,
  ``result.get("rc")``): a dict-*subclass* receipt whose
  ``.get``/``__getitem__``/``__setitem__`` raises, a receipt missing a
  field, and a str-subclass *key* whose hash shadows ``rc``/``stderr`` and
  whose ``__eq__`` raises each detonated the reads — raw 500s after the
  command had executed.  ``_receipt_map`` launders the receipt into a plain
  dict (unbound ``dict.items``, per-insert guards, every transport field
  seeded; junk rc reads the ``-255`` sentinel, never ``-1``);

* **fixed** — a non-str receipt ``stdout`` (int), or a str subclass whose
  ``rfind``/``endswith`` raises, blew ``_split_cwd`` — the same after-the-
  command 500.  The stdout is now laundered through ``_config_text`` first;

* **fixed** — ``_clamp_timeout``/``recent_audit`` ran ``int()`` on a
  leftover int *subclass*, which executes the subclass's own ``__int__`` —
  a bomb there raises an arbitrary type past the numeric-trio catch; and
  their bare ``isinstance(..., bool)`` gates detonated on a
  ``__class__``-property bomb before the launder ran.

Stays-immune pins: the vanished-CLI 503 fires only after the disk confirm,
``_rc_int`` salvages ``__eq__``/``__float__``/``__index__``-bombing rc
subclasses through the unbound base read, over-cap digit ints degrade to
None (never a 500), nested dict-subclass ``items`` bombs, sequence-unwrap
through subclass ``__iter__`` bombs, self-recursive ``__str__``, and
isoformat property bombs.
"""
from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi.testclient import TestClient

from hub import terminal_svc
from hub.auth import require_auth

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


class _LyingBool:
    """Claims to be a bool; bool cannot be subclassed, so it is a pure liar."""

    @property
    def __class__(self):
        return bool


class _BombDict(dict):
    """Receipt whose every bound mapping hook raises."""

    def get(self, *a, **k):
        raise RuntimeError("leftover .get bomb")

    def __getitem__(self, *a):
        raise RuntimeError("leftover getitem bomb")

    def __setitem__(self, *a):
        raise RuntimeError("leftover setitem bomb")

    def __contains__(self, *a):
        raise RuntimeError("leftover contains bomb")

    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")


class _ItemsBombDict(dict):
    def items(self):
        raise RuntimeError("leftover items bomb")


class _EqBombKey(str):
    """Hash-shadows a real receipt field; the lookup's ``__eq__`` raises."""

    __hash__ = str.__hash__

    def __eq__(self, other):
        raise RuntimeError("leftover key eq bomb")

    def __ne__(self, other):
        raise RuntimeError("leftover key ne bomb")


class _RfindBombStr(str):
    def rfind(self, *a):
        raise RuntimeError("leftover rfind bomb")

    def endswith(self, *a):
        raise RuntimeError("leftover endswith bomb")


class _RcNumericBomb(int):
    """rc subclass whose every numeric/comparison dunder raises."""

    __hash__ = int.__hash__

    def __eq__(self, other):
        raise RuntimeError("leftover rc eq bomb")

    def __ne__(self, other):
        raise RuntimeError("leftover rc ne bomb")

    def __float__(self):
        raise RuntimeError("leftover rc float bomb")

    def __index__(self):
        raise RuntimeError("leftover rc index bomb")

    def __int__(self):
        raise RuntimeError("leftover rc int bomb")


class _IterBombList(list):
    def __iter__(self):
        raise RuntimeError("leftover __iter__ bomb")


class _SelfStr:
    def __str__(self):
        return str(self)


class _IsoPropertyBomb:
    @property
    def isoformat(self):
        raise RuntimeError("leftover isoformat property bomb")


class _IsoInf:
    def isoformat(self):
        return float("inf")


class _ClassBomb:
    @property
    def __class__(self):
        raise RuntimeError("leftover __class__ bomb")


def _receipt(**kw) -> dict:
    base = {
        "ok": False, "rc": 1, "stdout": "x", "stderr": "y",
        "truncated": False, "duration_ms": 1,
    }
    base.update(kw)
    return base


class _ReceiptSandbox(unittest.TestCase):
    """Poisoned ``_run`` receipts + scratch audit path, host_enabled on."""

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.audit = Path(tmp.name) / "terminal-audit.jsonl"
        patcher = mock.patch.object(terminal_svc, "AUDIT_PATH", self.audit)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client = _client()

    def _post(self, receipt, target="container", engine_up=True):
        body = {"command": "echo hi", "target": target}
        if target == "container":
            body["container"] = "web"
        with mock.patch.object(terminal_svc, "_run", return_value=receipt), \
                mock.patch.object(terminal_svc, "engine_up", return_value=engine_up), \
                mock.patch.object(
                    terminal_svc, "settings_section",
                    return_value={"host_enabled": True},
                ):
            return self.client.post("/api/terminal/run", json=body)

    def assert_coded_not_500(self, response, status: int) -> dict:
        self.assertEqual(response.status_code, status, response.text[:300])
        body = response.json()
        _starlette(body)
        return body


class BoolLiarReceiptTests(_ReceiptSandbox):
    """A lying ``__class__``-is-bool impostor in the receipt used to escape
    ``_jsonable`` raw and TypeError Starlette's encoder — a raw 500 after
    the command had already executed."""

    def test_bool_liar_rc_degrades_to_none_not_500(self):
        for target in ("container", "host"):
            with self.subTest(target=target):
                body = self.assert_coded_not_500(
                    self._post(_receipt(rc=_LyingBool()), target=target), 200
                )
                # The impostor drops; every honest sibling field survives.
                self.assertIsNone(body["rc"])
                self.assertEqual(body["stdout"], "x")

    def test_bool_liar_ok_degrades_field_level(self):
        body = self.assert_coded_not_500(
            self._post(_receipt(ok=_LyingBool())), 200
        )
        self.assertIsNone(body["ok"])
        self.assertEqual(body["rc"], 1)

    def test_exact_bools_still_pass_through(self):
        body = self.assert_coded_not_500(
            self._post(_receipt(ok=True, truncated=False)), 200
        )
        self.assertIs(body["ok"], True)
        self.assertIs(body["truncated"], False)


class ReceiptShapeBombTests(_ReceiptSandbox):
    """Dict-subclass receipts, missing fields and shadow keys used to
    detonate the bare ``result[...]`` reads/writes — the launder salvages
    the honest fields and degrades only the poisoned ones."""

    def test_dict_subclass_bomb_receipt_is_salvaged(self):
        for target in ("container", "host"):
            with self.subTest(target=target):
                body = self.assert_coded_not_500(
                    self._post(_BombDict(_receipt()), target=target), 200
                )
                # The unbound items view bypasses every bound-hook bomb.
                self.assertEqual(body["rc"], 1)
                self.assertEqual(body["stdout"], "x")

    def test_items_bomb_receipt_is_salvaged(self):
        body = self.assert_coded_not_500(
            self._post(_ItemsBombDict(_receipt())), 200
        )
        self.assertEqual(body["rc"], 1)

    def test_empty_receipt_reads_as_one_failed_command(self):
        for target in ("container", "host"):
            with self.subTest(target=target):
                body = self.assert_coded_not_500(self._post({}, target=target), 200)
                # The junk sentinel, never the honest-looking -1.
                self.assertEqual(body["rc"], -255)
                self.assertEqual(body["stdout"], "")

    def test_non_dict_receipt_reads_as_one_failed_command(self):
        body = self.assert_coded_not_500(self._post("junk"), 200)
        self.assertEqual(body["rc"], -255)

    def test_shadow_key_rc_degrades_to_the_junk_sentinel(self):
        receipt = dict(_receipt())
        del receipt["rc"]
        receipt[_EqBombKey("rc")] = 0
        body = self.assert_coded_not_500(self._post(receipt), 200)
        # The shadowed field drops to -255; its siblings survive intact.
        self.assertEqual(body["rc"], -255)
        self.assertEqual(body["stdout"], "x")

    def test_shadow_key_stderr_cannot_500_the_engine_probe(self):
        receipt = dict(_receipt())
        del receipt["stderr"]
        receipt[_EqBombKey("stderr")] = "cannot connect to the docker daemon"
        # Even with the engine probe answering "down", the shadowed stderr is
        # unreadable — the run stays a plain receipt, never a 500.
        body = self.assert_coded_not_500(self._post(receipt, engine_up=False), 200)
        self.assertEqual(body["rc"], 1)

    def test_int_stdout_is_rendered_not_a_500(self):
        body = self.assert_coded_not_500(self._post(_receipt(stdout=12345)), 200)
        self.assertEqual(body["stdout"], "12345")

    def test_rfind_bomb_stdout_is_laundered_before_split_cwd(self):
        body = self.assert_coded_not_500(
            self._post(_receipt(stdout=_RfindBombStr("x"))), 200
        )
        # The unbound base copy drops the method bombs; the content survives.
        self.assertEqual(body["stdout"], "x")

    def test_over_digit_cap_rc_degrades_to_none(self):
        body = self.assert_coded_not_500(self._post(_receipt(rc=10 ** 5000)), 200)
        # Past CPython's int->str digit cap the encoder cannot render the
        # number at all — the field drops, the receipt survives.
        self.assertIsNone(body["rc"])
        self.assertEqual(body["stdout"], "x")

    def test_rc_numeric_bomb_subclass_is_salvaged(self):
        body = self.assert_coded_not_500(self._post(_receipt(rc=_RcNumericBomb(3))), 200)
        # The unbound base read bypasses the __eq__/__float__/__index__ bombs.
        self.assertEqual(body["rc"], 3)

    def test_history_stays_encodable_after_a_bombed_run(self):
        self.assert_coded_not_500(self._post(_receipt(rc=_LyingBool())), 200)
        with mock.patch.object(
            terminal_svc, "settings_section", return_value={"host_enabled": True}
        ):
            resp = self.client.get("/api/terminal/history")
        body = self.assert_coded_not_500(resp, 200)
        self.assertIsInstance(body["entries"], list)


class VanishedCliDiskConfirmTests(_ReceiptSandbox):
    """The vanished-CLI 503 fires only after the on-disk confirm: the same
    rc-127 "not found" receipt with the CLI still present on disk stays the
    command's own receipt."""

    def _spawn_sentinel(self, docker_path: str, engine_up: bool):
        receipt = _receipt(rc=127, stdout="", stderr=f"not found: {docker_path}")
        with mock.patch.object(terminal_svc, "DOCKER", docker_path):
            return self._post(receipt, engine_up=engine_up)

    def test_cli_present_on_disk_keeps_the_receipt(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        cli = Path(tmp.name) / "docker"
        cli.write_text("#!/bin/sh\n")
        body = self.assert_coded_not_500(self._spawn_sentinel(str(cli), False), 200)
        # A container command that merely *prints* the sentinel words keeps
        # its own output verbatim while the binary is demonstrably there.
        self.assertEqual(body["rc"], 127)

    def test_cli_confirmed_gone_is_the_coded_503(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        gone = str(Path(tmp.name) / "docker")
        body = self.assert_coded_not_500(self._spawn_sentinel(gone, False), 503)
        self.assertEqual(body["detail"]["code"], "container.engine_down")


class SanitizerUnitPinTests(unittest.TestCase):
    """The unit contracts the route fixes rely on."""

    def test_jsonable_bool_liar_degrades_and_exact_bools_survive(self):
        out = terminal_svc._jsonable({"liar": _LyingBool(), "real": True, "off": False})
        self.assertIsNone(out["liar"])
        self.assertIs(out["real"], True)
        self.assertIs(out["off"], False)
        _starlette(out)

    def test_jsonable_nested_items_bomb_degrades_the_node_only(self):
        out = terminal_svc._jsonable({"nest": {"deep": _ItemsBombDict({"a": 1})}, "ok": 2})
        # The unbound base view still reads the nested subclass's real items.
        self.assertEqual(out["nest"]["deep"], {"a": 1})
        self.assertEqual(out["ok"], 2)
        _starlette(out)

    def test_jsonable_sequence_unwrap_survives_iter_bombs(self):
        out = terminal_svc._jsonable({"seq": _IterBombList([1, "two"]), "ok": 3})
        # Unbound list.__iter__ bypasses the subclass bomb: elements survive.
        self.assertEqual(out["seq"], [1, "two"])
        self.assertEqual(out["ok"], 3)
        _starlette(out)

    def test_jsonable_self_recursive_str_degrades(self):
        out = terminal_svc._jsonable({"v": _SelfStr(), "ok": 1})
        self.assertEqual(out["ok"], 1)
        _starlette(out)

    def test_jsonable_isoformat_bombs_degrade(self):
        out = terminal_svc._jsonable({
            "prop": _IsoPropertyBomb(),
            "inf": _IsoInf(),
            "ok": 1,
        })
        # The raising property cannot blow the getattr probe; an isoformat
        # that answers inf still rides the float sanitizer down to None.
        self.assertIsNone(out["inf"])
        self.assertEqual(out["ok"], 1)
        _starlette(out)

    def test_receipt_map_seeds_every_transport_field(self):
        out = terminal_svc._receipt_map({})
        for key, default in terminal_svc._RECEIPT_DEFAULTS.items():
            self.assertEqual(out[key], default)
        self.assertIs(type(out), dict)

    def test_receipt_map_lying_dict_reads_as_the_stub(self):
        class _LyingDict:
            @property
            def __class__(self):
                return dict

        out = terminal_svc._receipt_map(_LyingDict())
        self.assertEqual(out["rc"], -255)

    def test_receipt_map_drops_only_the_hostile_entries(self):
        receipt = {_EqBombKey("rc"): 0, "stdout": "kept"}
        out = terminal_svc._receipt_map(receipt)
        self.assertEqual(out["rc"], -255)
        self.assertEqual(out["stdout"], "kept")

    def test_receipt_map_stateful_hash_bomb_key_drops_cleanly(self):
        class _StatefulHashKey(str):
            """Hashes fine when first stored; every later re-hash raises."""

            armed = False

            def __hash__(self):
                if type(self).armed:
                    raise RuntimeError("leftover stateful hash bomb")
                return str.__hash__(self)

        key = _StatefulHashKey("weird")
        receipt = {key: "x", "stdout": "kept"}
        _StatefulHashKey.armed = True
        out = terminal_svc._receipt_map(receipt)
        # The re-insert re-hashes the hostile key; only its entry drops.
        self.assertNotIn("weird", out)
        self.assertEqual(out["stdout"], "kept")

    def test_rc_int_salvages_numeric_bombs_and_huge_ints(self):
        self.assertEqual(terminal_svc._rc_int(_RcNumericBomb(7)), 7)
        huge = 10 ** 5000
        self.assertEqual(terminal_svc._rc_int(huge), huge)
        self.assertEqual(terminal_svc._rc_int(_LyingBool()), -255)
        self.assertEqual(terminal_svc._rc_int(_ClassBomb()), -255)

    def test_clamp_timeout_survives_bombs(self):
        class _IntBomb(int):
            def __int__(self):
                raise RuntimeError("leftover __int__ bomb")

        self.assertEqual(
            terminal_svc._clamp_timeout(_IntBomb(5)), terminal_svc.DEFAULT_TIMEOUT
        )
        self.assertEqual(
            terminal_svc._clamp_timeout(_ClassBomb()), terminal_svc.DEFAULT_TIMEOUT
        )
        self.assertEqual(terminal_svc._clamp_timeout(10), 10)

    def test_recent_audit_limit_bombs_degrade_to_the_default(self):
        class _IntBomb(int):
            def __int__(self):
                raise RuntimeError("leftover __int__ bomb")

        with mock.patch.object(
            terminal_svc, "AUDIT_PATH", Path(os.devnull) / "missing"
        ):
            self.assertEqual(terminal_svc.recent_audit(_IntBomb(3)), [])
            self.assertEqual(terminal_svc.recent_audit(_ClassBomb()), [])

    def test_check_command_bombs_are_the_coded_400(self):
        from fastapi import HTTPException

        class _LyingStr:
            @property
            def __class__(self):
                return str

        for junk in (_ClassBomb(), _LyingStr(), None, 7):
            with self.subTest(junk=type(junk).__name__):
                with self.assertRaises(HTTPException) as ctx:
                    terminal_svc._check_command(junk)
                self.assertEqual(ctx.exception.status_code, 400)


if __name__ == "__main__":
    unittest.main()
