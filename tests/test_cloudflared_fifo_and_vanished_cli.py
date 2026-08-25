"""Leftover hang and misclassified 500s around the cloudflared panel.

A FIFO planted at ``login.url`` between the ``is_file`` check and the open
parked GET /api/cloudflared/status and GET /login/poll forever: ``open()`` of
a FIFO blocks until a writer appears, and ``read()`` blocks while the writer
stays silent, so one planted pipe stalled every status poll thread.

A cloudflared uninstalled mid-request (after ``_bin()`` probed but before the
spawn) surfaced ``sh``'s ``(-1, "", "not found")`` sentinel as a 400 blaming
the pasted token (POST /token) or as an uncoded ``{ok: false, message: "not
found"}`` (POST /create, /route-dns) instead of the coded 503 the up-front
probe raises.

An over-cap int leftover (beyond ``sys.get_int_max_str_digits``) passed
``_jsonable_state`` untouched, so ``json.dumps`` ValueError'd — which silently
dropped the whole ``_save_state`` write.
"""
from __future__ import annotations

import contextlib
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from hub import cloudflared_svc


@unittest.skipUnless(hasattr(os, "mkfifo"), "mkfifo required")
class FifoLoginUrlTests(unittest.TestCase):
    """status()/login_poll() must never block on a planted login.url FIFO."""

    #: Generous next to the ~0s expected runtime, tiny next to a real hang.
    JOIN_TIMEOUT = 5.0

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cf-fifo-")
        self.addCleanup(self.tmp.cleanup)
        self.fifo = Path(self.tmp.name) / "login.url"
        os.mkfifo(self.fifo)

    def _check_passed(self, path):
        # The is_file() probe saw a regular file; the path was swapped for a
        # FIFO before the open — the TOCTOU window the old code lost.
        return Path(path) == self.fifo

    def _run_with_watchdog(self, fn) -> dict:
        result: dict = {}

        def worker():
            result["value"] = fn()

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        t.join(self.JOIN_TIMEOUT)
        self.assertFalse(
            t.is_alive(),
            "blocked on the login.url FIFO instead of returning",
        )
        return result

    def test_status_does_not_hang_on_fifo_login_url(self):
        with contextlib.ExitStack() as stack:
            for name, value in (
                ("_ensure_dirs", mock.Mock()),
                ("_load_state", mock.Mock(return_value={})),
                ("_logged_in", mock.Mock(return_value=False)),
                ("_is_running", mock.Mock(return_value=False)),
                ("_bin", mock.Mock(side_effect=Exception("no"))),
                ("_login_process_pending", mock.Mock(return_value=False)),
                ("LOGIN_URL_FILE", self.fifo),
                ("_path_is_file", self._check_passed),
            ):
                stack.enter_context(mock.patch.object(cloudflared_svc, name, value))
            result = self._run_with_watchdog(cloudflared_svc.status)
        snap = result["value"]
        json.dumps(snap, allow_nan=False)
        self.assertIsNone(snap["login_url"])

    def test_login_poll_does_not_hang_on_fifo_login_url(self):
        with contextlib.ExitStack() as stack:
            for name, value in (
                ("_logged_in", mock.Mock(return_value=False)),
                ("_login_process_pending", mock.Mock(return_value=False)),
                ("LOGIN_URL_FILE", self.fifo),
                ("_path_is_file", self._check_passed),
            ):
                stack.enter_context(mock.patch.object(cloudflared_svc, name, value))
            result = self._run_with_watchdog(cloudflared_svc.login_poll)
        out = result["value"]
        json.dumps(out, allow_nan=False)
        self.assertIsNone(out["login_url"])
        self.assertFalse(out["logged_in"])


class ReadLoginUrlTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cf-url-")
        self.addCleanup(self.tmp.cleanup)
        self.url_file = Path(self.tmp.name) / "login.url"

    def _read(self):
        with mock.patch.object(cloudflared_svc, "LOGIN_URL_FILE", self.url_file):
            return cloudflared_svc._read_login_url()

    def test_regular_file_still_reads(self):
        self.url_file.write_text("https://dash.cloudflare.com/argotunnel\n")
        self.assertEqual(self._read(), "https://dash.cloudflare.com/argotunnel")

    def test_missing_and_empty_are_none(self):
        self.assertIsNone(self._read())
        self.url_file.write_text("  \n")
        self.assertIsNone(self._read())

    def test_undecodable_bytes_do_not_500(self):
        self.url_file.write_bytes(b"https://x\xff\xfe")
        url = self._read()
        json.dumps({"login_url": url}, allow_nan=False, ensure_ascii=False).encode("utf-8")
        self.assertTrue(url.startswith("https://x"))

    def test_huge_file_is_capped(self):
        self.url_file.write_text("h" * (10 * 1024 * 1024))
        url = self._read()
        self.assertLessEqual(len(url), cloudflared_svc._LOGIN_URL_CAP)

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "O_NOFOLLOW required")
    def test_planted_symlink_is_refused(self):
        victim = Path(self.tmp.name) / "victim"
        victim.write_text("https://evil.example/leak")
        self.url_file.symlink_to(victim)
        self.assertIsNone(self._read())


class VanishedCliTests(unittest.TestCase):
    """An uninstall between _bin() and the spawn must answer the coded 503."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cf-bin-")
        self.addCleanup(self.tmp.cleanup)
        self.missing = str(Path(self.tmp.name) / "cloudflared")

    def _patches(self):
        return (
            mock.patch.object(cloudflared_svc, "_logged_in", mock.Mock(return_value=True)),
            mock.patch.object(cloudflared_svc, "_bin", mock.Mock(return_value=self.missing)),
            mock.patch.object(cloudflared_svc, "sh", mock.Mock(return_value=(-1, "", "not found"))),
        )

    def _assert_not_installed(self, ctx):
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(ctx.exception.detail["code"], "cloudflared.not_installed")

    def test_fetch_token_is_coded_503_not_token_blame(self):
        with contextlib.ExitStack() as stack:
            for p in self._patches():
                stack.enter_context(p)
            with self.assertRaises(HTTPException) as ctx:
                cloudflared_svc.fetch_token("home")
        self._assert_not_installed(ctx)

    def test_create_tunnel_is_coded_503_not_uncoded_not_found(self):
        with contextlib.ExitStack() as stack:
            for p in self._patches():
                stack.enter_context(p)
            with self.assertRaises(HTTPException) as ctx:
                cloudflared_svc.create_tunnel("home")
        self._assert_not_installed(ctx)

    def test_route_dns_is_coded_503_not_uncoded_not_found(self):
        with contextlib.ExitStack() as stack:
            for p in self._patches():
                stack.enter_context(p)
            with self.assertRaises(HTTPException) as ctx:
                cloudflared_svc.route_dns("home", "ha.example.com")
        self._assert_not_installed(ctx)

    def test_still_present_cli_keeps_its_raw_result(self):
        # rc -1 is also what a signal-killed run reports; a binary that is
        # still on disk must not be classified as vanished.
        Path(self.missing).write_text("#!/bin/sh\n")
        with contextlib.ExitStack() as stack:
            for p in self._patches():
                stack.enter_context(p)
            with self.assertRaises(HTTPException) as ctx:
                cloudflared_svc.fetch_token("home")
        self.assertEqual(ctx.exception.detail["code"], "cloudflared.token_fetch_failed")

    def test_sentinel_shape_is_exact(self):
        self.assertFalse(cloudflared_svc._cli_vanished(1, "not found", self.missing))
        self.assertFalse(cloudflared_svc._cli_vanished(-1, "timeout", self.missing))
        self.assertFalse(cloudflared_svc._cli_vanished(-1, b"\xff", self.missing))
        self.assertTrue(cloudflared_svc._cli_vanished(-1, "not found", self.missing))
        self.assertTrue(cloudflared_svc._cli_vanished(-1, b"not found", self.missing))


class OverCapIntStateTests(unittest.TestCase):
    """Ints beyond the int→str digit cap must not ValueError json.dumps."""

    def test_jsonable_state_drops_over_cap_int(self):
        out = cloudflared_svc._jsonable_state({
            "tunnel_name": "home",
            "runs": 10 ** 5000,
            "nested": [10 ** 5000, 7],
        })
        json.dumps(out, allow_nan=False)
        self.assertIsNone(out["runs"])
        self.assertEqual(out["nested"], [None, 7])
        self.assertEqual(out["tunnel_name"], "home")

    def test_jsonable_state_keeps_normal_ints_and_bools(self):
        out = cloudflared_svc._jsonable_state({"runs": 12, "ok": True, "off": False})
        self.assertEqual(out["runs"], 12)
        self.assertIs(out["ok"], True)
        self.assertIs(out["off"], False)

    def test_save_state_keeps_the_rest_of_the_state(self):
        tmp = Path(tempfile.mkdtemp(prefix="cf-state-"))
        path = tmp / "serverhub-state.json"
        with (
            mock.patch.object(cloudflared_svc, "STATE_FILE", path),
            mock.patch.object(cloudflared_svc, "_ensure_dirs"),
        ):
            cloudflared_svc._save_state({
                "tunnel_name": "home",
                "updated": 10 ** 5000,
            })
        raw = json.loads(path.read_text())
        json.dumps(raw, allow_nan=False)
        self.assertEqual(raw["tunnel_name"], "home")
        self.assertIsNone(raw["updated"])


if __name__ == "__main__":
    unittest.main()
