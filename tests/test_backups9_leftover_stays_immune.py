"""Ninth-sweep stays-immune pins for the Backups listing/jsonable sanitizers.

The hunt for the ``__class__``-property class (test_backups9_leftover_class
_bomb_500s) also re-checked the other listing/jsonable shapes the sweep
brief names.  Each below is *already* sealed by earlier sweeps; these pins
fail loudly if a future edit regresses one:

* the ``_jsonable`` ``isoformat`` probe (a leftover whose ``isoformat``
  raises drops to None rather than 500ing the encoder);
* the ``_jsonable`` bytes path (a ``bytes``-subclass ``.decode`` bomb rides
  the unbound base decode);
* the ``_capped_json_int`` parse hook (one >4300-digit number drops to None
  and the rest of the status document survives);
* the FIFO/``is_file`` gate in ``_json_object`` (a named pipe at a status
  path answers ``{}``, never parks the read — read_text_capped's O_NONBLOCK
  is the backstop);
* the ``_exit_code`` rc coercion from backups8 (an int-subclass whose
  comparison raises still unwraps to its real exit status).
"""
from __future__ import annotations

import json
import os
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


class JsonableStaysImmuneTests(unittest.TestCase):
    def test_isoformat_bomb_drops_to_none(self):
        class IsoBomb:
            def isoformat(self):
                raise RuntimeError("iso boom")

        out = backups._jsonable({"a": IsoBomb(), "b": 1})
        self.assertEqual(out, {"a": None, "b": 1})

    def test_bytes_subclass_decode_bomb_rides_the_unbound_base(self):
        class DecodeBomb(bytes):
            def decode(self, *a, **k):
                raise RuntimeError("decode boom")

        out = backups._jsonable({"k": DecodeBomb(b"hi"), "n": 2})
        self.assertEqual(out, {"k": "hi", "n": 2})

    def test_over_cap_int_drops_to_none(self):
        # Built by arithmetic: int("9"*5000) hits the same digit cap at
        # construction time.  str() of this is the ValueError _jsonable drops.
        big = 10 ** 5000
        self.assertIsNone(backups._jsonable(big))
        # inside a container the sibling survives.
        self.assertEqual(backups._jsonable({"big": big, "ok": 1}),
                         {"big": None, "ok": 1})

    def test_lone_surrogate_string_is_scrubbed(self):
        out = backups._jsonable({"reason": "x\ud800y"})
        # No lone surrogate survives to Starlette's UTF-8 encode.
        out["reason"].encode("utf-8")


class JsonObjectStaysImmuneTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def test_over_cap_json_number_keeps_the_document(self):
        p = self.dir / "backup_status.json"
        p.write_text(
            '{"ok": true, "counter": ' + "9" * 5000 + ', "reason": "x"}',
            encoding="utf-8",
        )
        out = backups._json_object(p)
        self.assertEqual(out, {"ok": True, "counter": None, "reason": "x"})

    def test_fifo_at_status_path_answers_empty_never_parks(self):
        fifo = self.dir / "panel_status.json"
        os.mkfifo(fifo)
        # is_file() is False for a FIFO, so the read never opens it; if it
        # ever did, read_text_capped's O_NONBLOCK raises EINVAL rather than
        # blocking for a writer.
        self.assertEqual(backups._json_object(fifo), {})


class ExitCodeStaysImmuneTests(unittest.TestCase):
    """backups8's rc coercion still reads the real status underneath a bomb."""

    def test_eq_bomb_unwraps_to_its_real_exit(self):
        class IntEqBomb(int):
            def __eq__(self, other):
                raise RuntimeError("eq boom")

            def __ne__(self, other):
                raise RuntimeError("ne boom")

            __hash__ = int.__hash__

        self.assertEqual(backups._exit_code(IntEqBomb(0)), 0)
        self.assertEqual(backups._exit_code(IntEqBomb(7)), 7)
        self.assertIsNone(backups._exit_code(object()))


class GetBackupsPoisonedStatusFilesTests(unittest.TestCase):
    """GET /api/backups stays 200 with poisoned PhotosHub status files."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.state = root / "state"
        self.state.mkdir()
        self.backup_root = root / "backups"
        self.backup_root.mkdir()
        for name, value in (
            ("BACKUP_ROOT", self.backup_root),
            ("PHOTOSHUB_STATE", self.state),
            ("PHOTOSHUB_CFG", root / "config.json"),
        ):
            patched = mock.patch.object(backups, name, value)
            patched.start()
            self.addCleanup(patched.stop)

    def _get(self):
        resp = _client().get("/api/backups")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        return json.loads(resp.content.decode("utf-8"))

    def test_over_cap_number_in_panel_status_stays_200(self):
        (self.state / "panel_status.json").write_text(
            '{"originals": {"local_original_pct": ' + "9" * 5000 + "}}",
            encoding="utf-8",
        )
        payload = self._get()
        self.assertIn("immich", payload)

    def test_fifo_backup_status_stays_200(self):
        os.mkfifo(self.state / "backup_status.json")
        payload = self._get()
        self.assertIn("immich", payload)


if __name__ == "__main__":
    unittest.main(verbosity=2)
