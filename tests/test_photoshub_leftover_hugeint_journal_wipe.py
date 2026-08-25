"""Leftover >4300-digit JSON literals wiped whole PhotosHub journals.

CPython's int<->str digit cap makes ``json.loads`` of a >4300-digit number
literal raise *bare ValueError* — the ``int()`` conversion inside the
decoder, not JSONDecodeError.  Every photoshub parse treated ValueError as
a corrupt document, so one over-cap counter written by an operator script:

* wiped a whole state journal to ``{}`` on GET /api/photoshub/status —
  ``gate_ready: true`` silently read back as False (re-freezing the delete
  channel) and every timestamp in the file was lost;
* blocked every PATCH /api/photoshub/config save with the coded
  ``photoshub.bad_config`` until the operator hand-edited config.json —
  and GET /api/photoshub/config rendered a blank settings page;
* 502'd the whole pending-delete listing (``photoshub.immich_response``)
  when any counter in an Immich response passed the cap.

Now the decoder's int hook (``_json_int``) nulls only the unrenderable
number — a ``str()``-probe-style guard, not an isinstance gate, so every
sane numeric id still parses as an int — and the rest of the document
survives.  The in-memory / already-int shapes were pinned earlier
(test_photoshub_leftover_ctl_surrogate_digit_500s.py); this battery covers
the on-disk literal path, plus stays-immune pins for surrogate escapes in
JSON keys *and* values loaded from disk.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from hub import photoshub_svc

#: A JSON number literal past CPython's 4300-digit int<->str conversion cap.
_HUGE_DIGITS = "9" * 5000


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: allow_nan=False, then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _PhotosHubTree(unittest.TestCase):
    """A real temp PhotosHub tree, photoctl installed."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="serverhub-photos3-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        self.hub = self.tmp / "PhotosHub"
        (self.hub / "config").mkdir(parents=True)
        (self.hub / "state").mkdir()
        (self.hub / "bin").mkdir()
        self.photoctl = self.hub / "bin" / "photoctl"
        self.photoctl.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.photoctl.chmod(0o755)
        for patched in (
            mock.patch.object(photoshub_svc, "HUB", self.hub),
            mock.patch.object(photoshub_svc, "CFG_PATH", self.hub / "config" / "config.json"),
            mock.patch.object(photoshub_svc, "STATE", self.hub / "state"),
            mock.patch.object(photoshub_svc, "BIN_PHOTOCTL", self.photoctl),
            mock.patch.object(photoshub_svc, "SCRIPTS", self.hub / "scripts"),
        ):
            patched.start()
            self.addCleanup(patched.stop)


class HugeIntStateJournalTests(_PhotosHubTree):
    """GET /api/photoshub/status must not lose a journal to one counter."""

    def test_over_cap_counter_keeps_the_rest_of_the_journal(self):
        (self.hub / "state" / "originals_status.json").write_text(
            '{"gate_ready": true, "last_success": "2026-08-25T10:00:00",'
            ' "n": ' + _HUGE_DIGITS + "}",
            encoding="utf-8",
        )
        snap = photoshub_svc.status()
        _starlette(snap)
        # The wipe read gate_ready:true back as False — a silently re-frozen
        # delete channel, not a 500, which is why it survived two sweeps.
        self.assertTrue(snap["gates"]["originals_ready"])
        self.assertEqual(snap["originals"]["last_success"], "2026-08-25T10:00:00")
        self.assertIsNone(snap["originals"]["n"])

    def test_sane_numeric_ids_still_parse_as_ints(self):
        # The guard is the decoder-level int probe, never an isinstance
        # gate: ordinary numeric ids/counters must stay ints, not None/str.
        (self.hub / "state" / "originals_status.json").write_text(
            '{"gate_ready": true, "originals_present": 812, "assets_active": 900}',
            encoding="utf-8",
        )
        snap = photoshub_svc.status()
        self.assertEqual(snap["originals"]["originals_present"], 812)
        self.assertEqual(snap["originals"]["assets_active"], 900)

    def test_structurally_broken_journal_still_falls_back_whole(self):
        (self.hub / "state" / "originals_status.json").write_text(
            "{torn", encoding="utf-8",
        )
        snap = photoshub_svc.status()
        _starlette(snap)
        self.assertFalse(snap["gates"]["originals_ready"])


class HugeIntConfigTests(_PhotosHubTree):
    """config.json with one over-cap literal is not a corrupt file."""

    def _write_cfg(self, text: str) -> Path:
        path = self.hub / "config" / "config.json"
        path.write_text(text, encoding="utf-8")
        return path

    def test_over_cap_literal_no_longer_blocks_every_save(self):
        path = self._write_cfg(
            '{"immich": {"album_yuanbao": "Kid A"}, "junk_counter": '
            + _HUGE_DIGITS + "}",
        )
        out = photoshub_svc.update_config({"people": {"yuanbao": {"name": "元宝"}}})
        _starlette(out)
        self.assertEqual(out["people"]["yuanbao"]["name"], "元宝")
        # The save merged; the fields next to the bad counter survived it.
        self.assertEqual(out["albums"]["yuanbao"], "Kid A")
        stored = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(stored["immich"]["album_yuanbao"], "Kid A")
        self.assertIsNone(stored["junk_counter"])

    def test_over_cap_literal_keeps_public_config_fields(self):
        self._write_cfg(
            '{"immich": {"album_erbao": "Kid B"}, "junk_counter": '
            + _HUGE_DIGITS + "}",
        )
        cfg = photoshub_svc.public_config()
        _starlette(cfg)
        self.assertEqual(cfg["albums"]["erbao"], "Kid B")

    def test_truly_corrupt_config_still_refuses_the_save(self):
        # The hook must not soften the real corruption guard: a torn file is
        # still never overwritten.
        path = self._write_cfg("{not-json")
        with self.assertRaises(HTTPException) as ctx:
            photoshub_svc.update_config({"panel": {"url": "http://127.0.0.1:8283/"}})
        self.assertEqual(ctx.exception.detail["code"], "photoshub.bad_config")
        self.assertEqual(path.read_text(encoding="utf-8"), "{not-json")


class _SeqResp:
    def __init__(self, body: bytes):
        self._body = body

    def read(self, n=-1):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class HugeIntImmichResponseTests(_PhotosHubTree):
    """One over-cap counter in an Immich reply must not 502 the listing."""

    ALBUM_ID = "0193b0d4-2f4c-7d31-a001-3f00aa11bb22"
    ASSET_ID = "0193b0d4-2f4c-7d31-a001-3f00aa11bb23"

    def setUp(self):
        super().setUp()
        (self.hub / "config" / "immich_api_key").write_text("k\n", encoding="utf-8")

    def test_over_cap_counter_in_album_json_still_lists_assets(self):
        albums = (
            '[{"id": "' + self.ALBUM_ID + '", "albumName": "Pending Delete",'
            ' "assetCount": ' + _HUGE_DIGITS + "}]"
        )
        detail = (
            '{"id": "' + self.ALBUM_ID + '", "someStat": ' + _HUGE_DIGITS + ","
            ' "assets": [{"id": "' + self.ASSET_ID + '",'
            ' "originalFileName": "IMG_0001.HEIC", "type": "IMAGE"}]}'
        )
        responses = [_SeqResp(albums.encode()), _SeqResp(detail.encode())]
        with mock.patch.object(
            photoshub_svc, "_immich_open", side_effect=lambda req, timeout: responses.pop(0),
        ):
            out = photoshub_svc.pending_delete_assets()
        _starlette(out)
        self.assertEqual(out["album_id"], self.ALBUM_ID)
        self.assertEqual(out["count"], 1)
        self.assertEqual(out["assets"][0]["id"], self.ASSET_ID)

    def test_non_json_immich_reply_is_still_the_coded_502(self):
        with mock.patch.object(
            photoshub_svc, "_immich_open", side_effect=lambda req, timeout: _SeqResp(b"<html>"),
        ):
            with self.assertRaises(HTTPException) as ctx:
                photoshub_svc.pending_delete_assets()
        self.assertEqual(ctx.exception.detail["code"], "photoshub.immich_response")


class SurrogateEscapeJsonPinTests(_PhotosHubTree):
    """Stays-immune pins: JSON ``"\\ud800"`` escapes in keys AND values.

    ``json.loads`` decodes the escape to a lone-surrogate str that
    Starlette's UTF-8 encode cannot render; ``_jsonable`` scrubs both
    positions after every disk parse (``str.encode(..., "replace")``
    substitutes ``?``), so these documents already degrade instead of
    500ing.
    """

    def test_surrogate_key_and_value_in_state_json_do_not_500(self):
        (self.hub / "state" / "originals_status.json").write_text(
            '{"gate_ready": true, "k\\ud800ey": "v\\ud800al"}',
            encoding="utf-8",
        )
        snap = photoshub_svc.status()
        _starlette(snap)
        self.assertTrue(snap["gates"]["originals_ready"])
        self.assertEqual(snap["originals"]["k?ey"], "v?al")

    def test_surrogate_person_name_in_config_json_does_not_500(self):
        (self.hub / "config" / "config.json").write_text(
            '{"people": {"yuanbao": {"name": "n\\ud800m"}}}',
            encoding="utf-8",
        )
        snap = photoshub_svc.status()
        _starlette(snap)
        self.assertEqual(snap["people"]["yuanbao"]["name"], "n?m")
        cfg = photoshub_svc.public_config()
        _starlette(cfg)
        self.assertEqual(cfg["people"]["yuanbao"]["name"], "n?m")


if __name__ == "__main__":
    unittest.main()
