"""Seventh leftover-500s sweep of the Backups surfaces, over the real app.

backups6 sealed the ``backups:`` *cfg-readers* (``_mapping_get`` /
``_truthy`` / unbound ``list.__iter__``).  What it never touched: the
module's own text/JSON coercers — ``_as_text``, ``_utf8_text``,
``_cfg_text`` and the local ``_jsonable`` — which still called bound
subclass methods everywhere the tree-wide convention
(``hub.modules._jsonable``'s unbound ``dict.items`` / ``base.__iter__`` /
``int.__index__`` / ``float.__float__`` / base ``bytes.decode`` /
``str.encode``) uses base operations.  On the pre-fix tree:

* GET /api/backups — a status-store object that decodes to a dict subclass
  whose ``items()`` raises detonated in ``_json_object``'s ``_jsonable(raw)``
  call, which sits *outside* its load-time catch, and 500'd the whole page;
  so did a container whose ``__iter__`` raises, an int subclass whose
  ``__str__`` blows the digit-cap probe, a float subclass whose ``__eq__``
  blows the NaN/inf probes, a bytes subclass whose ``decode`` raises, a
  str subclass whose ``__str__`` answers *self* carrying a bound ``encode``
  bomb, and an ``isoformat`` probe on an object whose ``__getattr__``
  raises (getattr's default only swallows AttributeError);
* GET /api/backups — the same self-``__str__`` encode bomb as a
  ``backups.postgres`` field raised RuntimeError past ``_cfg_text``'s
  UnicodeEncodeError-only catch, 500ing the page on a function whose
  contract (backups6) is "drop the entry, keep the page";
* POST /api/backups/configs — a str-subclass ``agent_keywords`` /
  ``extra_paths`` entry passed ``isinstance(x, str)`` and its bound
  ``.strip()`` bomb raised out of ``agent_keywords()`` /
  ``config_archive_extra_paths()`` and 500'd the archive route;
* POST /api/backups/postgres and /configs — a 200 that lied *and* destroyed
  the artefact: ``_as_text`` ran the output's bound ``encode`` / ``decode``
  bomb inside the jobs' broad catches, so a dump/tar that had already
  written every byte was ``_discard``'ed and reported as its own failure.

Fixes, all in hub/backups.py, all the established conventions: base
``bytes.decode`` / ``str.encode`` in ``_as_text`` / ``_utf8_text`` /
``_cfg_text`` (which now also hands back an exact str so the ``.strip()`` /
``__eq__`` that follow cannot hit another override), the full modules5
unbound set in ``_jsonable`` plus a guarded ``isoformat`` getattr, and an
``_exact_str`` (surrogatepass — these values name real on-disk files) copy
in the two config string walks.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import backups
from hub.app_factory import create_app
from hub.auth import require_auth

_app = None


def _client() -> TestClient:
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return TestClient(_app, raise_server_exceptions=False)


def _strict_utf8(resp) -> str:
    """The body must already be valid UTF-8 — decode strictly on purpose."""
    return resp.content.decode("utf-8")


def _starlette(payload) -> str:
    """What Starlette's JSONResponse does: ensure_ascii=False then encode."""
    return json.dumps(payload, ensure_ascii=False, allow_nan=False).encode(
        "utf-8"
    ).decode("utf-8")


class _StrEncodeBomb(str):
    """``__str__`` answers *self*, so ``str()`` skips CPython's exact-str
    copy and the bound ``encode`` bomb stays live on the result."""

    def __str__(self):
        return self

    def encode(self, *a, **k):
        raise RuntimeError("leftover encode bomb")


class _StrStripBomb(str):
    def strip(self, *a, **k):
        raise RuntimeError("leftover strip bomb")


class _BytesDecodeBomb(bytes):
    def decode(self, *a, **k):
        raise RuntimeError("leftover decode bomb")


class _DictItemsBomb(dict):
    def items(self):
        raise RuntimeError("leftover items bomb")


class _ListIterBomb(list):
    def __iter__(self):
        raise RuntimeError("leftover __iter__ bomb")


class _TupleIterBomb(tuple):
    def __iter__(self):
        raise RuntimeError("leftover __iter__ bomb")


class _SetIterBomb(set):
    def __iter__(self):
        raise RuntimeError("leftover __iter__ bomb")


class _FrozenIterBomb(frozenset):
    def __iter__(self):
        raise RuntimeError("leftover __iter__ bomb")


class _IntStrBomb(int):
    def __str__(self):
        raise RuntimeError("leftover __str__ bomb")

    __repr__ = __str__


class _FloatEqBomb(float):
    def __eq__(self, other):
        raise RuntimeError("leftover __eq__ bomb")

    __ne__ = __eq__
    __hash__ = float.__hash__


class _IsoGetattrBomb:
    """getattr(value, "isoformat", None) only defaults AttributeError."""

    def __getattr__(self, name):
        raise RuntimeError("leftover __getattr__ bomb")


_ENTRY = {"id": "t1", "db": "db1"}


class JsonableZooTests(unittest.TestCase):
    """Every subclass bomb costs its value at most, never the document."""

    def test_dict_items_bomb_keeps_its_real_storage(self):
        out = backups._jsonable({"s": _DictItemsBomb({"a": 1})})
        self.assertEqual(out, {"s": {"a": 1}})
        _starlette(out)

    def test_container_iter_bombs_keep_their_real_elements(self):
        for bomb in (
            _ListIterBomb([1, "x"]),
            _TupleIterBomb((1, "x")),
            _SetIterBomb({1}),
            _FrozenIterBomb({1}),
        ):
            out = backups._jsonable({"v": bomb})
            self.assertTrue(out["v"], bomb)
            _starlette(out)

    def test_int_str_bomb_keeps_its_value_and_huge_one_drops(self):
        self.assertEqual(backups._jsonable(_IntStrBomb(7)), 7)
        # >4300 digits: the base coercion still hits the digit cap — the
        # same drop as the plain over-cap int, never a raise.
        self.assertIsNone(backups._jsonable(_IntStrBomb(10 ** 5000)))

    def test_float_eq_bomb_keeps_its_value_and_inf_drops(self):
        self.assertEqual(backups._jsonable(_FloatEqBomb(1.5)), 1.5)
        self.assertIsNone(backups._jsonable(_FloatEqBomb(float("inf"))))

    def test_bytes_decode_bomb_still_decodes_the_real_bytes(self):
        self.assertEqual(
            backups._jsonable(_BytesDecodeBomb(b"ok\xff")), "ok\ufffd"
        )

    def test_self_str_encode_bomb_is_scrubbed_not_raised(self):
        out = backups._jsonable(_StrEncodeBomb("a\ud800b"))
        self.assertEqual(out, "a?b")
        self.assertIs(type(out), str)

    def test_bombed_mapping_keys_cost_the_key_not_the_document(self):
        raw = {}
        dict.__setitem__(raw, _BytesDecodeBomb(b"k\xff"), 1)
        dict.__setitem__(raw, _IntStrBomb(5), 2)
        raw["fine"] = 3
        out = backups._jsonable(raw)
        self.assertEqual(out.get("k\ufffd"), 1)
        self.assertEqual(out.get("fine"), 3)
        self.assertEqual(len(out), 2)  # the __str__-bombed key is dropped
        _starlette(out)

    def test_getattr_bomb_object_is_rendered_not_raised(self):
        out = backups._jsonable(_IsoGetattrBomb())
        self.assertIsInstance(out, str)
        _starlette(out)


class TextCoercerZooTests(unittest.TestCase):
    def test_as_text_survives_decode_and_encode_bombs(self):
        self.assertEqual(backups._as_text(_BytesDecodeBomb(b"ok\xff")), "ok\ufffd")
        out = backups._as_text(_StrEncodeBomb("dump ok\ud800"))
        self.assertEqual(out, "dump ok?")
        self.assertIs(type(out), str)

    def test_cfg_text_keeps_the_real_name_and_hands_back_an_exact_str(self):
        out = backups._cfg_text(_StrEncodeBomb("db1"))
        self.assertEqual(out, "db1")
        self.assertIs(type(out), str)

    def test_cfg_text_still_rejects_surrogates_on_the_bombed_shape(self):
        self.assertIsNone(backups._cfg_text(_StrEncodeBomb("a\ud800")))


class BackupsPageEncodeBombCfgTests(unittest.TestCase):
    """GET /api/backups: a self-__str__ encode bomb costs nothing real."""

    def _get_backups(self, cfg_value):
        with mock.patch.object(backups, "cfg", lambda: cfg_value):
            resp = _client().get("/api/backups")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        return json.loads(_strict_utf8(resp))

    def test_encode_bomb_fields_keep_their_real_target(self):
        payload = self._get_backups({"backups": {"postgres": [
            dict(_ENTRY, id=_StrEncodeBomb("t1"), db=_StrEncodeBomb("db1")),
        ]}})
        self.assertEqual(
            [t["id"] for t in payload["postgres_targets"]], ["t1"])

    def test_surrogate_encode_bomb_field_costs_the_entry_not_the_page(self):
        payload = self._get_backups({"backups": {"postgres": [
            dict(_ENTRY, db=_StrEncodeBomb("d\ud800")),
            dict(_ENTRY),
        ]}})
        self.assertEqual(
            [t["id"] for t in payload["postgres_targets"]], ["t1"])


class BackupsPageStatusStoreBombTests(unittest.TestCase):
    """GET /api/backups: a bombed PhotosHub store costs values, not the page.

    ``_json_object``'s load-time catch cannot see these: they surface from
    the decode seam as live objects, and the ``_jsonable(raw)`` call that
    scrubs them sits outside that try.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.photos_dir = root / "photos"
        self.photos_dir.mkdir()
        cfg_file = root / "config.json"
        cfg_file.write_text("{}", encoding="utf-8")
        state_dir = root / "state"
        state_dir.mkdir()
        for name, value in (
            ("PHOTOSHUB_CFG", cfg_file),
            ("PHOTOSHUB_STATE", state_dir),
        ):
            patched = mock.patch.object(backups, name, value)
            patched.start()
            self.addCleanup(patched.stop)

    def test_subclass_bomb_zoo_in_the_store_keeps_the_page(self):
        bomb = _DictItemsBomb({
            "photos_library": str(self.photos_dir),
            "immich": {
                "media_location": _StrEncodeBomb("m\ud800"),
                "junk": [
                    _IntStrBomb(10 ** 5000),
                    _FloatEqBomb(float("inf")),
                    _BytesDecodeBomb(b"\xff"),
                    _ListIterBomb(["x"]),
                    _IsoGetattrBomb(),
                ],
            },
        })
        with mock.patch.object(backups, "safe_json_loads",
                               lambda *a, **k: bomb):
            resp = _client().get("/api/backups")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        layers = payload["immich"]["layers"]
        # dict.items read the real storage underneath the poisoned items().
        self.assertEqual(layers["originals"]["path"], str(self.photos_dir))
        self.assertTrue(layers["originals"]["present"])
        # The encode bomb's real characters survive, surrogate scrubbed.
        self.assertEqual(layers["generated"]["path"], "m?")


class _BackupsSandbox(unittest.TestCase):
    """Private BACKUP_ROOT / DATA_DIR / CONFIG_FILE per test."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.backup_root = root / "backups"
        self.backup_root.mkdir()
        self.data_dir = root / "data"
        self.data_dir.mkdir()
        self.cfg_file = root / "services.yaml"
        self.cfg_file.write_text("settings: {}\n", encoding="utf-8")
        for name, value in (
            ("BACKUP_ROOT", self.backup_root),
            ("DATA_DIR", self.data_dir),
            ("BACKUP_SECRETS_FILE", self.data_dir / "backup-credentials.json"),
            ("CONFIG_FILE", self.cfg_file),
        ):
            patched = mock.patch.object(backups, name, value)
            patched.start()
            self.addCleanup(patched.stop)

    def _post(self, path: str, cfg_value):
        with mock.patch.object(backups, "cfg", lambda: cfg_value):
            resp = _client().post(path)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        return json.loads(_strict_utf8(resp))


class PostgresDumpOutputBombTests(_BackupsSandbox):
    """POST /api/backups/postgres: a bombed output no longer destroys the
    artefact it is reporting on."""

    _CFG = {"backups": {"postgres": [dict(_ENTRY)]}}

    def _fake_run_capped(self, text):
        def fake(argv, timeout=None, env=None, **kwargs):
            # argv ends with ``-f <dest>``: produce the artefact the size
            # check judges success by.
            Path(argv[-1]).write_bytes(b"fake dump\n")
            return 0, text
        return fake

    def test_encode_bomb_output_keeps_the_successful_dump(self):
        fake = self._fake_run_capped(_StrEncodeBomb("dump ok\ud800"))
        with mock.patch.object(backups, "run_capped", fake):
            payload = self._post("/api/backups/postgres", self._CFG)
        # Pre-fix: the bound encode bomb raised inside the broad catch,
        # the already-written artefact was _discard'ed, and the 200 lied
        # ok:false with the bomb's text as the dump's failure.
        self.assertTrue(payload["ok"], payload)
        self.assertEqual(payload["message"], "dump ok?")
        dest = Path(payload["path"])
        self.assertTrue(dest.is_file(), dest)
        self.assertEqual(dest.read_bytes(), b"fake dump\n")

    def test_decode_bomb_output_keeps_the_successful_dump(self):
        fake = self._fake_run_capped(_BytesDecodeBomb(b"dump ok\xff"))
        with mock.patch.object(backups, "run_capped", fake):
            payload = self._post("/api/backups/postgres", self._CFG)
        self.assertTrue(payload["ok"], payload)
        self.assertEqual(payload["message"], "dump ok\ufffd")
        self.assertTrue(Path(payload["path"]).is_file())


class ConfigArchiveStrSubclassTests(_BackupsSandbox):
    """POST /api/backups/configs: str-subclass config entries still archive."""

    def test_strip_bomb_extra_path_still_archives_and_keeps_the_member(self):
        extra = Path(self._tmp.name) / "extra.conf"
        extra.write_text("k=v\n", encoding="utf-8")
        hostile_cfg = {
            "backups": {"config_archive": {
                "extra_paths": [_StrStripBomb(str(extra))]}},
        }
        payload = self._post("/api/backups/configs", hostile_cfg)
        self.assertTrue(payload["ok"], payload)
        with mock.patch.object(backups, "cfg", lambda: hostile_cfg):
            # The exact-str copy kept the real path underneath the bomb.
            self.assertIn(extra, backups.config_archive_extra_paths())

    def test_strip_bomb_agent_keyword_with_a_live_plist_still_archives(self):
        home = Path(self._tmp.name) / "home"
        agents = home / "Library" / "LaunchAgents"
        agents.mkdir(parents=True)
        (agents / "local.serverhub.plist").write_text(
            "<plist/>", encoding="utf-8")
        hostile_cfg = {
            "backups": {"config_archive": {
                "agent_keywords": [_StrStripBomb("extra-kw")]}},
        }
        with mock.patch.object(backups, "user_home", lambda: home):
            payload = self._post("/api/backups/configs", hostile_cfg)
        self.assertTrue(payload["ok"], payload)
        with mock.patch.object(backups, "cfg", lambda: hostile_cfg):
            self.assertIn("extra-kw", backups.agent_keywords())

    def test_encode_bomb_output_keeps_the_successful_archive(self):
        def fake(argv, timeout=None, env=None, **kwargs):
            # argv is ["/usr/bin/tar", "czf", dest, *members].
            Path(argv[2]).write_bytes(b"fake tar\n")
            return 0, _StrEncodeBomb("tar ok\ud800")
        with mock.patch.object(backups, "run_capped", fake):
            payload = self._post("/api/backups/configs", {})
        # Pre-fix: same as the postgres shape — the archive was discarded
        # and the 200 lied ok:false over its own report text.
        self.assertTrue(payload["ok"], payload)
        self.assertEqual(payload["message"], "tar ok?")
        self.assertTrue(Path(payload["path"]).is_file())


if __name__ == "__main__":
    unittest.main(verbosity=2)
