"""Terminal leftover sweep #7: settings-JSON seams terms 1-6 left open.

A fresh hunt over the terminal settings surfaces (GET/PUT /api/settings'
terminal branch, GET /api/terminal, GET /api/terminal/history) replayed the
leftover zoo against the mounted app and found two genuinely live gaps:

* **fixed** — PUT /api/settings with a terminal patch merges the *stored*
  ``settings.terminal`` section back into the write
  (``dict(settings_section("terminal"))`` + ``cur.update``), and
  ``yaml.safe_dump`` looks representers up by *exact* type.  A leftover
  str/int/float/dict/list *subclass* riding any stored value therefore
  raised ``RepresenterError`` — a YAMLError, **not** the ValueError
  ``config._dump`` retried on — straight out of ``mutate()``: a raw 500
  where the over-cap-hex-int sibling one line up already degraded.
  ``_dump`` now retries YAMLError too, and ``_renderable_tree`` launders
  subclass leftovers to their base type through unbound base calls
  (``str.__str__`` / ``int.__index__`` / ``float.__float__`` /
  ``dict.items`` / ``base.__iter__`` / ``bytes(...)``), so the value itself
  still persists and a subclass method bomb cannot blow the retry walk;

* **fixed** — one >4300-digit number in a single audit line made
  ``json.loads`` raise CPython's digit-cap ValueError (not JSONDecodeError)
  for the whole line, and ``recent_audit`` skipped the entire row: GET
  /api/terminal/history silently hid a command line from the only record of
  what was typed into a root-capable shell.  The sibling parse_int
  convention (smart_test/metrics/wireguard) now loads the huge literal as
  None and the rest of the row survives.

Surrogate / Infinity / deep-nest audit lines and the GET-side bomb shapes
were already sealed by terms 1-6; the pins here hold that line where this
sweep re-probed it.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import yaml
from fastapi import HTTPException
from fastapi.testclient import TestClient

from hub import config, terminal_svc
from hub.auth import require_auth
from hub.routers import settings_api

#: ``int(x, 16)`` is exempt from CPython's 4300-digit cap, so this is an
#: already-parsed int no JSON/YAML encoder can render.
HUGE_INT = int("F" * 5000, 16)

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


class _SelfStrEncodeBombStr(str):
    """``str(x)`` returns the subclass itself; its bound ``.encode`` bombs."""

    def __str__(self):
        return self

    def encode(self, *args, **kwargs):
        raise RuntimeError("leftover encode bomb")


class _ItemsBombDict(dict):
    def items(self):
        raise RuntimeError("leftover items bomb")


class _IterBombList(list):
    def __iter__(self):
        raise RuntimeError("leftover __iter__ bomb")


class _IterBombSet(set):
    def __iter__(self):
        raise RuntimeError("leftover __iter__ bomb")


class _IndexStrBombInt(int):
    def __index__(self):
        raise RuntimeError("leftover __index__ bomb")

    def __str__(self):
        raise RuntimeError("leftover __str__ bomb")


class _FloatBomb(float):
    __hash__ = float.__hash__

    def __eq__(self, other):
        raise RuntimeError("leftover __eq__ bomb")

    def __ne__(self, other):
        raise RuntimeError("leftover __ne__ bomb")


class _DecodeBombBytes(bytes):
    def decode(self, *args, **kwargs):
        raise RuntimeError("leftover decode bomb")


class _Unrepresentable:
    """No YAML representer, no laundering path: the save must refuse coded."""


class _ConfigSandbox(unittest.TestCase):
    """Scratch services.yaml + data dir so mutate() runs against a real file."""

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


#: Leftover subclass shapes riding the stored terminal section into the save,
#: with the exact base value each one must persist as (None = dropped).
_PUT_BOMB_SECTIONS = {
    "self-str encode-bomb str": (_SelfStrEncodeBombStr("/leftover"), "/leftover"),
    "items-bomb dict": (_ItemsBombDict({"a": 1}), {"a": 1}),
    "iter-bomb list": (_IterBombList(["/x"]), ["/x"]),
    "float eq-bomb": (_FloatBomb(1.5), 1.5),
    # The unbound ``int.__index__`` reads the C-level value, bypassing both
    # method bombs: the int itself is salvaged, not dropped.
    "index/str-bomb int": (_IndexStrBombInt(5), 5),
    "over-cap hex int": (HUGE_INT, None),
}


class PutTerminalSubclassBombPinTests(_ConfigSandbox):
    """PUT /api/settings' terminal merge over a bombed stored section: the
    save lands (200), the laundered base value persists, and services.yaml
    stays parseable with every sibling key intact."""

    def _put(self, section: dict):
        with mock.patch.object(
            settings_api, "settings_section", return_value=section
        ):
            return self.client.put(
                "/api/settings", json={"terminal": {"host_enabled": False}}
            )

    def test_every_subclass_bomb_shape_saves_200(self):
        for name, (value, expected) in _PUT_BOMB_SECTIONS.items():
            with self.subTest(name=name):
                resp = self._put({"cwd": value})
                # This used to raise RepresenterError out of mutate() — a raw
                # 500 — for every subclass shape here.
                self.assertEqual(resp.status_code, 200, resp.text[:300])
                _starlette(resp.json())
                on_disk = self.stored()
                terminal = on_disk["settings"]["terminal"]
                self.assertIs(terminal["host_enabled"], False)
                if expected is None:
                    self.assertNotIn("cwd", terminal)
                else:
                    self.assertEqual(terminal["cwd"], expected)
                # The sibling auth block must ride through untouched.
                self.assertEqual(
                    on_disk["settings"]["auth"]["password_hash"], "sentinel-hash"
                )

    def test_nested_zoo_salvages_the_healthy_entries(self):
        section = {
            "cwd": {
                "keep": _SelfStrEncodeBombStr("ok"),
                "num": _IndexStrBombInt(3),
                "drop": HUGE_INT,
                "seq": _IterBombList([1, 2]),
            }
        }
        resp = self._put(section)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        cwd = self.stored()["settings"]["terminal"]["cwd"]
        self.assertEqual(cwd, {"keep": "ok", "num": 3, "seq": [1, 2]})

    def test_decode_bomb_bytes_persists_as_binary(self):
        resp = self._put({"cwd": _DecodeBombBytes(b"/z")})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(self.stored()["settings"]["terminal"]["cwd"], b"/z")

    def test_unrepresentable_object_is_the_coded_503_and_file_intact(self):
        before = self.yaml_path.read_text()
        resp = self._put({"cwd": _Unrepresentable()})
        self.assertEqual(resp.status_code, 503, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "settings.save_failed")
        self.assertEqual(self.yaml_path.read_text(), before)


class RenderableTreeUnitPinTests(unittest.TestCase):
    """The unbound launder contract on config._renderable_tree."""

    def test_str_subclass_launders_to_the_exact_base_str(self):
        out = config._renderable_tree({"k": _SelfStrEncodeBombStr("/x")})
        self.assertEqual(out, {"k": "/x"})
        self.assertIs(type(out["k"]), str)

    def test_dict_items_bomb_still_walks_the_real_entries(self):
        out = config._renderable_tree({"k": _ItemsBombDict({"a": 1})})
        self.assertEqual(out, {"k": {"a": 1}})
        self.assertIs(type(out["k"]), dict)

    def test_sequence_and_set_iter_bombs_keep_the_real_elements(self):
        out = config._renderable_tree(
            {"l": _IterBombList([1, 2]), "s": _IterBombSet({3})}
        )
        self.assertEqual(out["l"], [1, 2])
        self.assertEqual(out["s"], {3})
        self.assertIs(type(out["l"]), list)
        self.assertIs(type(out["s"]), set)

    def test_int_bombs_salvage_and_over_cap_ints_drop_field_level(self):
        out = config._renderable_tree(
            {"bomb": _IndexStrBombInt(5), "huge": HUGE_INT, "ok": 7}
        )
        # The unbound base coercion bypasses the __index__/__str__ bombs and
        # keeps the real value; only the genuinely unrenderable int drops.
        self.assertEqual(out, {"bomb": 5, "ok": 7})
        self.assertIs(type(out["bomb"]), int)

    def test_float_subclass_launders_and_bytes_subclass_becomes_bytes(self):
        out = config._renderable_tree(
            {"f": _FloatBomb(1.5), "b": _DecodeBombBytes(b"\xffz")}
        )
        self.assertEqual(out["f"], 1.5)
        self.assertIs(type(out["f"]), float)
        self.assertEqual(out["b"], b"\xffz")
        self.assertIs(type(out["b"]), bytes)

    def test_subclass_keys_launder_too(self):
        out = config._renderable_tree({_SelfStrEncodeBombStr("k"): 1})
        self.assertEqual(out, {"k": 1})
        self.assertIs(type(next(iter(out))), str)

    def test_dump_survives_the_whole_zoo(self):
        text = config._dump({
            "settings": {"terminal": {
                "cwd": _SelfStrEncodeBombStr("/x"),
                "extra": _ItemsBombDict({"a": 1}),
                "seq": _IterBombList([1]),
            }}
        })
        loaded = yaml.safe_load(text)
        self.assertEqual(
            loaded["settings"]["terminal"],
            {"cwd": "/x", "extra": {"a": 1}, "seq": [1]},
        )

    def test_dump_refuses_a_truly_unrepresentable_node_coded(self):
        with self.assertRaises(HTTPException) as caught:
            config._dump({"settings": {"terminal": {"cwd": _Unrepresentable()}}})
        self.assertEqual(caught.exception.detail["code"], "settings.save_failed")


class _AuditSandbox(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.audit = Path(tmp.name) / "terminal-audit.jsonl"
        patcher = mock.patch.object(terminal_svc, "AUDIT_PATH", self.audit)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client = _client()


class HistoryDigitCapRowPinTests(_AuditSandbox):
    """GET /api/terminal/history: one over-cap number no longer erases the
    row it rides — and the already-sealed poison lines stay sealed."""

    def test_over_cap_number_keeps_the_row(self):
        self.audit.write_text(
            json.dumps({"ts": 1, "command": "before-row", "rc": 0}) + "\n"
            + '{"ts": ' + "9" * 4400 + ', "command": "bignum-row", "rc": 0}\n'
            + json.dumps({"ts": 2, "command": "after-row", "rc": 0}) + "\n"
        )
        resp = self.client.get("/api/terminal/history")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        entries = resp.json()["entries"]
        _starlette(entries)
        commands = [e.get("command") for e in entries]
        # bignum-row used to vanish: json.loads' digit-cap ValueError read
        # as a corrupt line and the whole audit row was hidden.
        self.assertEqual(commands, ["before-row", "bignum-row", "after-row"])
        by_command = {e.get("command"): e for e in entries}
        self.assertIsNone(by_command["bignum-row"]["ts"])
        self.assertEqual(by_command["bignum-row"]["rc"], 0)

    def test_over_cap_number_in_a_nested_field_keeps_the_row(self):
        self.audit.write_text(
            '{"ts": 3, "command": "nested-row", "extra": {"n": '
            + "9" * 4400 + "}}\n"
        )
        resp = self.client.get("/api/terminal/history")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        entries = resp.json()["entries"]
        _starlette(entries)
        self.assertEqual(entries[0]["command"], "nested-row")
        self.assertEqual(entries[0]["extra"], {"n": None})

    def test_already_sealed_poison_lines_stay_sealed(self):
        self.audit.write_text(
            '{"ts": Infinity, "command": "inf-row", "rc": 0}\n'
            + '{"ts": 2, "command": "\\ud800surrogate-row", "rc": 0}\n'
            + "[" * 6000 + "]" * 6000 + "\n"
            + json.dumps({"ts": 4, "command": "tail-row", "rc": 0}) + "\n"
        )
        resp = self.client.get("/api/terminal/history")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        entries = resp.json()["entries"]
        text = _starlette(entries)
        self.assertNotIn("\ud800", text)
        commands = [e.get("command") for e in entries]
        self.assertIn("tail-row", commands)
        self.assertIn("inf-row", commands)


if __name__ == "__main__":
    unittest.main()
