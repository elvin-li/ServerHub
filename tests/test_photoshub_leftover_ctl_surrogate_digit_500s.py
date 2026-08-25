"""Leftover PhotosHub 500s: over-cap ints, surrogate names/paths, vanished photoctl.

A fresh hunt over hub/photoshub_svc.py and hub/immich_svc.py (the photos corner
already pinned once by test_leftover_photoshub_files_shares_digit_500s.py) found
three survivors, each reproduced before it was fixed:

* **Over-cap ints through ``_jsonable``.**  Both modules' sanitizers passed
  ``int`` values through untouched; past CPython's 4300-digit int<->str cap,
  ``json.dumps`` itself then raised ValueError — the exact 500 the sanitizer
  exists to prevent.  The JSON stores are parse-capped (a >4300-digit literal
  already fails ``json.loads`` and the whole file falls back to ``{}``), but
  hex/octal text loads *uncapped* (``int(x, 16)`` is a power-of-two base), so a
  YAML-fed or in-memory leftover reached Starlette whole.  backups.py and
  jobs.py fixed the same branch after their sweeps; these two lagged behind.

* **Surrogates in album / person names and log paths.**  JSON ``"\\ud800"`` in
  a PATCH body decodes to a lone-surrogate str that passed ``_NAME`` /
  ``_ALBUM`` (not a control character); accepted, ``_write_cfg``'s sanitizer
  stored a mangled ``?`` in place of the name — an album title that can never
  match Immich.  Now refused with the same coded 400 as any other bad value
  (the vms ``_argv_name`` precedent).  And a log file whose on-disk name holds
  undecodable bytes reaches ``recent_logs`` as surrogateescape'd text in the
  ``path`` field — the one field that skips ``_jsonable`` — and used to 500
  GET /api/photoshub/logs/{name} at Starlette's UTF-8 encode.

* **Vanished photoctl mid-request.**  ``run_action`` gates on ``installed()``
  up front, but a photoctl that vanished between that check and the spawn came
  back as HTTP 200 ``{ok: false, exit_code: -1}`` whose stderr leaked the raw
  spawn errno (home path included) — a shape the SPA cannot translate.  Now
  the coded 503 ``photoshub.ctl_missing`` — but only after the binary is
  confirmed gone from disk, because ``run_watchdog`` collapses *every* failed
  spawn into rc -1: a vanished cwd or a signal-killed child raises the same
  way, and with the binary still present the raw result is the truth (the
  docker ``cli_on_disk`` / vms ``_cli_missing`` rule).  A timeout keeps its
  own rc 124 and is deliberately never classified.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from hub import immich_svc, photoshub_svc
from hub.errors import CODES

#: Past CPython's 4300-digit int<->str conversion cap, built without tripping
#: the cap ourselves (a power of ten, and a hex parse — the YAML/leftover
#: shapes that dodge the int(str) digit limit).
_HUGE_INT = 10 ** 4999
_HEX_INT = int("f" * 5000, 16)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: allow_nan=False, then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _PhotosHubTree(unittest.TestCase):
    """A real temp PhotosHub tree, photoctl installed."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="serverhub-photos2-"))
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


class OverCapIntJsonableTests(unittest.TestCase):
    """Both photos sanitizers must drop what the encoder cannot render."""

    def test_photoshub_jsonable_drops_over_cap_and_hex_ints(self):
        out = photoshub_svc._jsonable({"n": _HUGE_INT, "hex": _HEX_INT, "list": [_HUGE_INT]})
        self.assertEqual(out, {"n": None, "hex": None, "list": [None]})
        _starlette(out)

    def test_immich_jsonable_drops_over_cap_and_hex_ints(self):
        out = immich_svc._jsonable({"n": _HUGE_INT, "hex": _HEX_INT})
        self.assertEqual(out, {"n": None, "hex": None})
        _starlette(out)

    def test_sane_ints_and_bools_still_pass_untouched(self):
        for mod in (photoshub_svc, immich_svc):
            with self.subTest(mod=mod.__name__):
                out = mod._jsonable({"n": 42, "big": 10 ** 100, "flag": True})
                self.assertEqual(out, {"n": 42, "big": 10 ** 100, "flag": True})

    def test_over_cap_int_key_is_still_skipped_not_a_500(self):
        # str(key) is the conversion that raises; the pair is dropped whole.
        out = photoshub_svc._jsonable({_HUGE_INT: "x", "keep": 1})
        self.assertEqual(out, {"keep": 1})
        _starlette(out)


class OverCapStateFilePinTests(_PhotosHubTree):
    """Survivor pin: the JSON stores are parse-capped, so a >4300-digit
    literal makes the whole file fall back to ``{}`` — degraded, never 500."""

    def test_huge_digit_state_file_does_not_500_status(self):
        (self.hub / "state" / "originals_status.json").write_text(
            '{"gate_ready": true, "n": ' + "9" * 5000 + "}", encoding="utf-8",
        )
        snap = photoshub_svc.status()
        _starlette(snap)
        self.assertFalse(snap["gates"]["originals_ready"])


class SurrogateLogPathTests(_PhotosHubTree):
    """GET /api/photoshub/logs/{name} returns ``path`` raw — no _jsonable."""

    def test_undecodable_log_filename_does_not_500_the_route(self):
        logs = self.hub / "logs"
        logs.mkdir()
        # An on-disk name with a raw 0xFF byte: os listing surrogateescapes it
        # to "bridge-\udcff.log", which glob still matches.
        raw = b"bridge-\xff.log"
        fd = os.open(bytes(logs) + b"/" + raw, os.O_CREAT | os.O_WRONLY, 0o600)
        os.write(fd, b"line one\n")
        os.close(fd)
        out = photoshub_svc.recent_logs("bridge")
        _starlette(out)
        self.assertEqual(out["lines"], ["line one"])
        # The path still names the file, with the byte replaced, not dropped.
        self.assertIn("bridge-", out["path"])

    def test_a_clean_log_path_is_returned_verbatim(self):
        logs = self.hub / "logs"
        logs.mkdir()
        (logs / "bridge-2026-08.log").write_text("ok\n", encoding="utf-8")
        out = photoshub_svc.recent_logs("bridge")
        self.assertEqual(out["path"], "logs/bridge-2026-08.log")
        self.assertEqual(out["lines"], ["ok"])


class SurrogateConfigPatchTests(_PhotosHubTree):
    """PATCH /api/photoshub/config: lone surrogates are refused, not mangled."""

    def test_surrogate_album_is_the_coded_400(self):
        with self.assertRaises(HTTPException) as ctx:
            photoshub_svc.update_config({"albums": {"yuanbao": "Album\ud800Name"}})
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail["code"], "photoshub.bad_album")
        _starlette(ctx.exception.detail)
        self.assertFalse(
            (self.hub / "config" / "config.json").exists(),
            "a refused patch must not write config.json",
        )

    def test_surrogate_person_name_is_the_coded_400(self):
        with self.assertRaises(HTTPException) as ctx:
            photoshub_svc.update_config({"people": {"yuanbao": {"name": "n\ud800m"}}})
        self.assertEqual(ctx.exception.detail["code"], "photoshub.bad_name")

    def test_cjk_names_and_albums_still_save(self):
        out = photoshub_svc.update_config({
            "people": {"yuanbao": {"name": "元宝"}},
            "albums": {"yuanbao": "元宝的相册"},
        })
        self.assertEqual(out["people"]["yuanbao"]["name"], "元宝")
        self.assertEqual(out["albums"]["yuanbao"], "元宝的相册")
        _starlette(out)


class VanishedPhotoctlTests(_PhotosHubTree):
    """POST /api/photoshub/action answers a vanished photoctl with a coded 503."""

    def test_ctl_missing_code_is_503(self):
        # A demotion would silently turn the "reinstall PhotosHub" answer
        # back into an untranslatable ok:false envelope.
        self.assertEqual(CODES["photoshub.ctl_missing"][0], 503)

    def test_vanished_photoctl_is_the_coded_503(self):
        """Mid-flight state, real spawn: the binary the installed() gate
        blessed is gone by the time run_watchdog execs it."""
        self.photoctl.unlink()
        with mock.patch.object(photoshub_svc, "installed", return_value=True):
            with self.assertRaises(HTTPException) as ctx:
                photoshub_svc.run_action("status", timeout=5)
        self.assertEqual(ctx.exception.status_code, 503)
        detail = ctx.exception.detail
        self.assertEqual(detail["code"], "photoshub.ctl_missing")
        self.assertEqual(detail["params"], {"tool": "photoctl"})
        # The coded body never leaks the spawn errno or the tree's path.
        self.assertNotIn(str(self.hub), json.dumps(detail))
        _starlette(detail)

    def test_rc_minus_one_with_the_binary_on_disk_keeps_the_raw_shape(self):
        """The disk re-check rules: a signal-killed run (or a vanished *cwd*
        with the binary still present) reports rc -1 the same way and must
        keep its uncoded ok:false result."""
        with (
            mock.patch.object(photoshub_svc, "run_watchdog", return_value=-1),
            mock.patch.object(photoshub_svc, "status", return_value={}),
        ):
            out = photoshub_svc.run_action("status", timeout=5)
        self.assertFalse(out["ok"])
        self.assertEqual(out["exit_code"], -1)

    def test_timeout_keeps_its_own_shape(self):
        """A slow photoctl is not a missing one — rc 124 is never classified."""
        self.photoctl.unlink()  # even with the binary gone
        with (
            mock.patch.object(photoshub_svc, "installed", return_value=True),
            mock.patch.object(photoshub_svc, "run_watchdog", return_value=124),
            mock.patch.object(photoshub_svc, "status", return_value={}),
        ):
            out = photoshub_svc.run_action("status", timeout=5)
        self.assertFalse(out["ok"])
        self.assertEqual(out["exit_code"], 124)

    def test_vanished_people_script_python_present_keeps_the_raw_shape(self):
        """configure-people spawns /usr/bin/python3: with the interpreter on
        disk, an rc -1 (the HUB cwd vanished mid-request) is not a missing
        CLI and keeps the uncoded result."""
        scripts = self.hub / "scripts"
        scripts.mkdir()
        (scripts / "configure_person_albums.py").write_text("", encoding="utf-8")
        with (
            mock.patch.object(photoshub_svc, "run_watchdog", return_value=-1),
            mock.patch.object(photoshub_svc, "status", return_value={}),
            mock.patch.object(photoshub_svc, "_ctl_on_disk", return_value=True) as on_disk,
        ):
            out = photoshub_svc.run_action("configure-people", timeout=5)
        self.assertFalse(out["ok"])
        on_disk.assert_called_once_with("/usr/bin/python3")

    def test_a_successful_run_never_re_stats_the_binary(self):
        """The disk re-check runs only on the rc -1 failure path."""
        with (
            mock.patch.object(photoshub_svc, "run_watchdog", return_value=0),
            mock.patch.object(photoshub_svc, "status", return_value={}),
            mock.patch.object(photoshub_svc, "_ctl_on_disk") as on_disk,
        ):
            out = photoshub_svc.run_action("status", timeout=5)
        self.assertTrue(out["ok"])
        on_disk.assert_not_called()


if __name__ == "__main__":
    unittest.main()
