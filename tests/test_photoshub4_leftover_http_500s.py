"""Leftover 500: a torn IPv6 URL 500'd every PhotosHub config/status route.

Reproduced live on the mounted routes before the fix: ``urlsplit`` raises
``ValueError: Invalid IPv6 URL`` on Python 3.12 for a torn bracket paste
(``http://[torn``).  hub/http_guard.py guards that inside ``_url_parts``
(the notify-save precedent), but PhotosHub's own ``_public_href`` called
``urlsplit`` bare, so:

* PATCH /api/photoshub/config with ``panel.url`` / ``immich.public_url`` =
  ``"http://[torn"`` answered the coded **500** ``photoshub.config_failed``
  instead of the coded 400 ``photoshub.bad_link_url`` — browser-suppliable
  through the Settings tab's plain text inputs;
* the same leftover already sitting in config.json (saved by an older build
  or hand-edited) 500'd **every** GET /api/photoshub/status and GET
  /api/photoshub/config until the operator hand-edited the file — the whole
  PhotosHub page rendered only its LoadFailure banner.

Now the torn URL degrades: reads answer an empty link, writes refuse with
the coded 400.

The rest of this module pins the PhotosHub page's other leftover classes
stays-immune at the HTTP layer, through the real ``create_app`` wiring
(prior passes fixed them at the service layer; nothing exercised the
mounted routes):

* a >4300-digit JSON literal in a state journal nulls only that number —
  ``gate_ready: true`` survives (``json.loads`` raises *bare ValueError*,
  not JSONDecodeError, so the corrupt-document fallback used to wipe the
  whole journal to ``{}``);
* UTF-8 lone surrogates in state/config JSON — keys AND values — are
  scrubbed, never a Starlette encode 500;
* an over-cap int literal in a raw PATCH body is a 4xx from the sanitizing
  validation handler, never a 500;
* a photoctl that vanished between the installed() gate and the spawn is
  the coded 503 ``photoshub.ctl_missing`` — only after the disk confirm on
  the failure path, so an rc -1 with the binary still present keeps its
  raw ok:false shape;
* a log file whose on-disk name holds undecodable bytes still answers 200.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import photoshub_svc  # noqa: E402

#: A JSON number literal past CPython's 4300-digit int<->str conversion cap.
_HUGE_DIGITS = "9" * 5000


class _PhotosHubHttpSandbox(unittest.TestCase):
    """Real app wiring + a real temp PhotosHub tree, photoctl installed."""

    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        from hub.app_factory import create_app
        from hub.auth import require_auth

        cls._app = create_app()
        cls._app.dependency_overrides[require_auth] = lambda: True
        cls.client = TestClient(cls._app, raise_server_exceptions=False)

    @classmethod
    def tearDownClass(cls):
        cls._app.dependency_overrides.clear()

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="photos4-http-1a5c-"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.hub = self.tmp / "PhotosHub"
        (self.hub / "config").mkdir(parents=True)
        (self.hub / "state").mkdir()
        (self.hub / "bin").mkdir()
        self.photoctl = self.hub / "bin" / "photoctl"
        self.photoctl.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.photoctl.chmod(0o755)
        self.cfg_path = self.hub / "config" / "config.json"
        for patched in (
            mock.patch.object(photoshub_svc, "HUB", self.hub),
            mock.patch.object(photoshub_svc, "CFG_PATH", self.cfg_path),
            mock.patch.object(photoshub_svc, "STATE", self.hub / "state"),
            mock.patch.object(photoshub_svc, "BIN_PHOTOCTL", self.photoctl),
            mock.patch.object(photoshub_svc, "SCRIPTS", self.hub / "scripts"),
        ):
            patched.start()
            self.addCleanup(patched.stop)


class TornIpv6UrlHttpTests(_PhotosHubHttpSandbox):
    """The reproduced leftover: urlsplit's Invalid IPv6 URL ValueError."""

    def test_patch_with_a_torn_panel_url_is_the_coded_400_not_a_500(self):
        resp = self.client.patch(
            "/api/photoshub/config", json={"panel": {"url": "http://[torn"}},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()["detail"]["code"], "photoshub.bad_link_url")
        self.assertFalse(
            self.cfg_path.exists(), "a refused patch must not write config.json",
        )

    def test_patch_with_a_torn_immich_public_url_is_the_coded_400(self):
        resp = self.client.patch(
            "/api/photoshub/config",
            json={"immich": {"public_url": "http://[::1"}},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()["detail"]["code"], "photoshub.bad_link_url")

    def test_leftover_torn_urls_in_config_json_do_not_500_status(self):
        # Saved by an older build or hand-edited: before the fix this 500'd
        # every GET until the operator hand-edited the file back out.
        self.cfg_path.write_text(
            '{"immich": {"public_url": "http://[torn"},'
            ' "panel": {"url": "http://[also"}}',
            encoding="utf-8",
        )
        resp = self.client.get("/api/photoshub/status")
        self.assertEqual(resp.status_code, 200)
        snap = resp.json()
        self.assertEqual(snap["links"]["immich"], "")
        self.assertEqual(snap["links"]["panel"], "")

    def test_leftover_torn_urls_in_config_json_do_not_500_get_config(self):
        self.cfg_path.write_text(
            '{"immich": {"public_url": "http://[torn"},'
            ' "panel": {"url": "http://[also"}}',
            encoding="utf-8",
        )
        resp = self.client.get("/api/photoshub/config")
        self.assertEqual(resp.status_code, 200)
        cfg = resp.json()
        self.assertEqual(cfg["immich"]["public_url"], "")
        self.assertEqual(cfg["panel"]["url"], "")

    def test_a_wellformed_link_still_saves_and_reads_back(self):
        resp = self.client.patch(
            "/api/photoshub/config",
            json={"panel": {"url": "https://panel.home.lan/"}},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["panel"]["url"], "https://panel.home.lan/")
        status = self.client.get("/api/photoshub/status")
        self.assertEqual(status.status_code, 200)
        self.assertEqual(status.json()["links"]["panel"], "https://panel.home.lan/")


class HugeIntJournalHttpPinTests(_PhotosHubHttpSandbox):
    """json.loads of a >4300-digit literal is bare ValueError, never a wipe."""

    def test_over_cap_counter_keeps_the_journal_through_the_route(self):
        (self.hub / "state" / "originals_status.json").write_text(
            '{"gate_ready": true, "last_success": "2026-08-25T10:00:00",'
            ' "n": ' + _HUGE_DIGITS + "}",
            encoding="utf-8",
        )
        resp = self.client.get("/api/photoshub/status")
        self.assertEqual(resp.status_code, 200)
        snap = resp.json()
        self.assertTrue(snap["gates"]["originals_ready"])
        self.assertEqual(snap["originals"]["last_success"], "2026-08-25T10:00:00")
        self.assertIsNone(snap["originals"]["n"])

    def test_over_cap_int_in_a_raw_patch_body_is_a_4xx_not_a_500(self):
        # json.loads raises plain ValueError (not JSONDecodeError) while
        # *parsing* these; the sanitizing handler registered by create_app
        # must keep answering 4xx.
        resp = self.client.patch(
            "/api/photoshub/config",
            content='{"panel": {"url": ' + _HUGE_DIGITS + "}}",
            headers={"Content-Type": "application/json"},
        )
        self.assertGreaterEqual(resp.status_code, 400)
        self.assertLess(resp.status_code, 500)
        resp.json()


class SurrogateJsonHttpPinTests(_PhotosHubHttpSandbox):
    """Lone-surrogate escapes in keys AND values stay scrubbed end to end."""

    def test_surrogate_key_and_value_in_state_json_do_not_500_status(self):
        (self.hub / "state" / "originals_status.json").write_text(
            '{"gate_ready": true, "k\\ud800ey": "v\\ud800al"}',
            encoding="utf-8",
        )
        resp = self.client.get("/api/photoshub/status")
        self.assertEqual(resp.status_code, 200)
        snap = resp.json()
        self.assertTrue(snap["gates"]["originals_ready"])
        self.assertEqual(snap["originals"]["k?ey"], "v?al")
        self.assertNotIn("\ud800", json.dumps(snap))

    def test_surrogate_album_in_a_patch_body_is_a_4xx_that_renders(self):
        # Pydantic's string_unicode check refuses the lone surrogate at the
        # validation layer (422) before photoshub.bad_album could; either
        # answer is fine — the pin is that the refusal renders (the echoed
        # ``input`` is scrubbed by the sanitizing handler) and nothing is
        # written.  The svc-layer coded 400 stays pinned in
        # test_photoshub_leftover_ctl_surrogate_digit_500s.py.
        resp = self.client.patch(
            "/api/photoshub/config",
            content='{"albums": {"yuanbao": "Album\\ud800Name"}}',
            headers={"Content-Type": "application/json"},
        )
        self.assertGreaterEqual(resp.status_code, 400)
        self.assertLess(resp.status_code, 500)
        self.assertNotIn("\ud800", json.dumps(resp.json()))
        self.assertFalse(
            self.cfg_path.exists(), "a refused patch must not write config.json",
        )


class VanishedPhotoctlHttpPinTests(_PhotosHubHttpSandbox):
    """POST /api/photoshub/action: 503 only after the disk confirm."""

    def test_vanished_photoctl_is_the_coded_503_through_the_route(self):
        self.photoctl.unlink()
        with mock.patch.object(photoshub_svc, "installed", return_value=True):
            resp = self.client.post(
                "/api/photoshub/action", json={"action": "status"},
            )
        self.assertEqual(resp.status_code, 503)
        detail = resp.json()["detail"]
        self.assertEqual(detail["code"], "photoshub.ctl_missing")
        self.assertEqual(detail["params"], {"tool": "photoctl"})
        # The coded body never leaks the spawn errno or the tree's path.
        self.assertNotIn(str(self.hub), json.dumps(detail))

    def test_rc_minus_one_with_the_binary_on_disk_keeps_the_raw_200(self):
        # A signal-killed child (or a vanished *cwd* with photoctl still
        # present) reports rc -1 identically; the disk confirm keeps that
        # from being misread as a missing CLI.
        with (
            mock.patch.object(photoshub_svc, "run_watchdog", return_value=-1),
            mock.patch.object(photoshub_svc, "status", return_value={}),
        ):
            resp = self.client.post(
                "/api/photoshub/action", json={"action": "status"},
            )
        self.assertEqual(resp.status_code, 200)
        out = resp.json()
        self.assertFalse(out["ok"])
        self.assertEqual(out["exit_code"], -1)


class UndecodableLogNameHttpPinTests(_PhotosHubHttpSandbox):
    """GET /api/photoshub/logs/{name}: a surrogateescape'd path stays 200."""

    def test_undecodable_log_filename_does_not_500_the_route(self):
        logs = self.hub / "logs"
        logs.mkdir()
        fd = os.open(
            bytes(logs) + b"/bridge-\xff.log", os.O_CREAT | os.O_WRONLY, 0o600,
        )
        os.write(fd, b"line one\n")
        os.close(fd)
        resp = self.client.get("/api/photoshub/logs/bridge")
        self.assertEqual(resp.status_code, 200)
        out = resp.json()
        self.assertEqual(out["lines"], ["line one"])
        self.assertIn("bridge-", out["path"])


if __name__ == "__main__":
    unittest.main()
