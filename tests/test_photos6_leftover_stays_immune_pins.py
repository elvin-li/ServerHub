"""photos6 stays-immune pins: the rest of the sweep's battery, already coded.

The photos6 sweep re-drove the known leftover zoo through ``create_app()`` +
``TestClient(raise_server_exceptions=False)`` against every mounted PhotosHub
route — on-disk JSON zoo (NaN/Infinity literals, numeric/over-cap ids, huge
mantissas), non-file nodes occupying every path the handlers open (directory,
symlink cycle, FIFO on the ``.lock`` sibling, vanished config dir), spawn-path
leftovers (non-executable photoctl, lone-surrogate environ), and adversarial
Immich replies (NaN literals, float/bool ids, torn streams, HTTP errors).
Everything here answered coded already; these pins keep it that way.

None of these exact shapes were pinned by the photos/…/photos5 suites (those
cover FIFO-occupied stores, hugeint journals, torn-IPv6 URLs, surrogate JSON,
oversize/invalid-UTF-8/iterbomb Immich bodies and the vanished-CLI 503).
"""
from __future__ import annotations

import http.client
import json
import os
import shutil
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import photoshub_svc  # noqa: E402

#: A JSON number literal past CPython's 4300-digit int<->str conversion cap.
_HUGE_DIGITS = "9" * 5000

_APP = None


def _client():
    global _APP
    from fastapi.testclient import TestClient
    from hub.auth import require_auth

    if _APP is None:
        from hub.app_factory import create_app

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


class _PhotosHubHttpSandbox(unittest.TestCase):
    """Real app wiring + a real temp PhotosHub tree, photoctl installed."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="photos6-pins-2ab7-"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.hub = self.tmp / "PhotosHub"
        (self.hub / "config").mkdir(parents=True)
        (self.hub / "state").mkdir()
        (self.hub / "bin").mkdir()
        self.photoctl = self.hub / "bin" / "photoctl"
        self.photoctl.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.photoctl.chmod(0o755)
        self.cfg_path = self.hub / "config" / "config.json"
        self.key_path = self.hub / "config" / "immich_api_key"
        for patched in (
            mock.patch.object(photoshub_svc, "HUB", self.hub),
            mock.patch.object(photoshub_svc, "CFG_PATH", self.cfg_path),
            mock.patch.object(photoshub_svc, "STATE", self.hub / "state"),
            mock.patch.object(photoshub_svc, "BIN_PHOTOCTL", self.photoctl),
            mock.patch.object(photoshub_svc, "SCRIPTS", self.hub / "scripts"),
        ):
            patched.start()
            self.addCleanup(patched.stop)
        self.client = _client()


class NanInfinityJsonLiteralPinTests(_PhotosHubHttpSandbox):
    """``json.loads`` accepts bare NaN/Infinity literals; both must drop."""

    def test_nan_and_infinity_in_config_json_stay_coded(self):
        self.cfg_path.write_text(
            '{"gates": {"min_local_original_pct": NaN},'
            ' "immich": {"base_url": Infinity}}',
            encoding="utf-8",
        )
        cfg = self.client.get("/api/photoshub/config")
        self.assertEqual(cfg.status_code, 200)
        body = cfg.json()
        # NaN would 500 Starlette's allow_nan=False encoder; the pct falls
        # back to its default and the Infinity base_url reads empty.
        json.dumps(body, allow_nan=False)
        self.assertEqual(body["gates"]["min_local_original_pct"], 99.0)
        self.assertEqual(body["immich"]["base_url"], "")
        status = self.client.get("/api/photoshub/status")
        self.assertEqual(status.status_code, 200)
        json.dumps(status.json(), allow_nan=False)

    def test_nan_in_a_state_journal_drops_field_level(self):
        (self.hub / "state" / "originals_status.json").write_text(
            '{"gate_ready": true, "rate": NaN, "eta": Infinity}',
            encoding="utf-8",
        )
        resp = self.client.get("/api/photoshub/status")
        self.assertEqual(resp.status_code, 200)
        snap = resp.json()
        json.dumps(snap, allow_nan=False)
        self.assertTrue(snap["gates"]["originals_ready"])
        self.assertIsNone(snap["originals"]["rate"])
        self.assertIsNone(snap["originals"]["eta"])

    def test_huge_mantissa_float_min_pct_reads_as_the_default(self):
        # A >4300-digit mantissa parses as a float (inf) — no digit cap on
        # the float path — and must still fall back, never 500.
        self.cfg_path.write_text(
            '{"gates": {"min_local_original_pct": ' + _HUGE_DIGITS + ".5}}",
            encoding="utf-8",
        )
        resp = self.client.get("/api/photoshub/config")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["gates"]["min_local_original_pct"], 99.0)


class NumericBaseUrlPinTests(_PhotosHubHttpSandbox):
    """YAML/JSON numeric ids via the str() probe: a numeric base_url."""

    def setUp(self):
        super().setUp()
        self.key_path.write_text("testkey123\n", encoding="utf-8")

    def test_numeric_base_url_is_the_coded_400_on_pending_delete(self):
        self.cfg_path.write_text('{"immich": {"base_url": 2283}}')
        resp = self.client.get("/api/photoshub/pending-delete")
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(
            resp.json()["detail"]["code"], "photoshub.bad_immich_url",
        )

    def test_overcap_int_base_url_falls_back_to_the_default_origin(self):
        # parse_int nulls the unrenderable literal; ``or default`` then
        # restores the loopback origin instead of 500ing the str() render.
        self.cfg_path.write_text(
            '{"immich": {"base_url": ' + _HUGE_DIGITS + "}}",
        )
        resp = self.client.get("/api/photoshub/config")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["immich"]["base_url"], "")


class NonFileNodePinTests(_PhotosHubHttpSandbox):
    """Directories / symlink cycles occupying the files the handlers open."""

    def test_directory_config_json_reads_default_and_refuses_the_patch(self):
        self.cfg_path.mkdir()
        status = self.client.get("/api/photoshub/status")
        self.assertEqual(status.status_code, 200)
        patch = self.client.patch(
            "/api/photoshub/config", json={"panel": {"url": "https://p.lan/"}},
        )
        self.assertEqual(patch.status_code, 400)
        self.assertEqual(patch.json()["detail"]["code"], "photoshub.bad_config")
        # The refused write must not have destroyed the leftover node.
        self.assertTrue(self.cfg_path.is_dir())

    def test_symlink_cycle_config_json_reads_default_and_self_heals(self):
        os.symlink("loop2", self.cfg_path)
        os.symlink("config.json", self.hub / "config" / "loop2")
        status = self.client.get("/api/photoshub/status")
        self.assertEqual(status.status_code, 200)
        # ELOOP reads as missing config; the patch replaces the dangling
        # cycle with a real file (drop_leftover_nonfile + atomic replace).
        patch = self.client.patch(
            "/api/photoshub/config", json={"panel": {"url": "https://p.lan/"}},
        )
        self.assertEqual(patch.status_code, 200)
        self.assertEqual(patch.json()["panel"]["url"], "https://p.lan/")
        self.assertTrue(self.cfg_path.is_file())

    def test_directory_key_file_reads_as_missing_key(self):
        self.key_path.mkdir()
        resp = self.client.get("/api/photoshub/config")
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.json()["immich"]["has_api_key"])

    def test_directory_log_file_keeps_the_logs_route_200(self):
        (self.hub / "logs").mkdir()
        (self.hub / "logs" / "cleanup.log").mkdir()
        resp = self.client.get("/api/photoshub/logs/cleanup")
        self.assertEqual(resp.status_code, 200)
        resp.json()

    def test_logs_dir_occupied_by_a_file_keeps_the_logs_route_200(self):
        (self.hub / "logs").write_text("not a directory", encoding="utf-8")
        resp = self.client.get("/api/photoshub/logs/bridge")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["lines"], [])

    def test_fifo_on_the_lock_sibling_still_saves_the_patch(self):
        # file_lock's leftover-node fallback: the context runs unlocked.
        os.mkfifo(str(self.cfg_path) + ".lock")
        resp = self.client.patch(
            "/api/photoshub/config", json={"panel": {"url": "https://p.lan/"}},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["panel"]["url"], "https://p.lan/")
        self.assertTrue(self.cfg_path.is_file())

    def test_vanished_config_dir_is_recreated_by_the_patch(self):
        shutil.rmtree(self.hub / "config")
        resp = self.client.patch(
            "/api/photoshub/config", json={"panel": {"url": "https://p.lan/"}},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(self.cfg_path.is_file())


class SpawnPathPinTests(_PhotosHubHttpSandbox):
    """Failure-path truth on POST /api/photoshub/action (no invented lies)."""

    def test_non_executable_photoctl_keeps_the_raw_ok_false_shape(self):
        # EACCES at spawn is rc -1 with the binary still on disk: the disk
        # confirm must NOT translate that into the ctl_missing 503 lie.
        self.photoctl.chmod(0o644)
        resp = self.client.post(
            "/api/photoshub/action", json={"action": "status"},
        )
        self.assertEqual(resp.status_code, 200)
        out = resp.json()
        self.assertFalse(out["ok"])
        self.assertEqual(out["exit_code"], -1)

    def test_lone_surrogate_environ_value_does_not_break_the_spawn(self):
        # utf8_env drops the poisoned pair; the spawn still runs.
        with mock.patch.dict(os.environ, {"PHOTOS6_LEFTOVER": "x\udcffy"}):
            resp = self.client.post(
                "/api/photoshub/action", json={"action": "status"},
            )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["ok"])

    def test_photoctl_emitting_invalid_utf8_and_nul_stays_200(self):
        self.photoctl.write_bytes(
            b"#!/bin/sh\nprintf 'a\\xff\\xfeb\\x00c'\nexit 3\n",
        )
        self.photoctl.chmod(0o755)
        resp = self.client.post(
            "/api/photoshub/action", json={"action": "status"},
        )
        self.assertEqual(resp.status_code, 200)
        out = resp.json()
        json.dumps(out, allow_nan=False).encode("utf-8")
        self.assertFalse(out["ok"])
        self.assertEqual(out["exit_code"], 3)


class _FakeImmichResponse:
    def __init__(self, payload: bytes, ctype: str = "application/json"):
        self._payload = payload
        self.status = 200

        class _Headers:
            def get(_self, k, d=None):
                return {"Content-Type": ctype}.get(k, d)

        self.headers = _Headers()

    def read(self, n: int = -1) -> bytes:
        return self._payload[:n] if n >= 0 else self._payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class AdversarialImmichReplyPinTests(_PhotosHubHttpSandbox):
    """Immich reply shapes the photos5 battery did not cover."""

    def setUp(self):
        super().setUp()
        self.key_path.write_text("testkey123\n", encoding="utf-8")
        self.cfg_path.write_text(
            '{"immich": {"base_url": "http://127.0.0.1:2283",'
            ' "album_pending_delete": "PD"}}',
            encoding="utf-8",
        )

    def _with_body(self, payload: bytes):
        resp = _FakeImmichResponse(payload)
        return mock.patch.object(
            photoshub_svc, "_immich_open", lambda req, timeout: resp,
        )

    def test_nan_infinity_album_body_drops_field_level(self):
        with self._with_body(b'[{"albumName": NaN, "id": Infinity}]'):
            resp = self.client.get("/api/photoshub/pending-delete")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        json.dumps(body, allow_nan=False)
        self.assertIsNone(body["album_id"])

    def test_float_album_id_is_the_coded_400(self):
        # str(1.5e10) renders "15000000000.0" — the dot fails the hex-charset
        # id regex, so the probe refuses it coded instead of building a URL.
        with self._with_body(b'[{"albumName": "PD", "id": 1.5e10}]'):
            resp = self.client.get("/api/photoshub/pending-delete")
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()["detail"]["code"], "photoshub.bad_ids")

    def test_bool_album_id_is_the_coded_400(self):
        with self._with_body(b'[{"albumName": "PD", "id": true}]'):
            resp = self.client.get("/api/photoshub/pending-delete")
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()["detail"]["code"], "photoshub.bad_ids")

    def test_overcap_int_album_name_cannot_match_and_stays_200(self):
        body = ('[{"albumName": ' + _HUGE_DIGITS
                + ', "id": "aaaaaaaa-1111"}]').encode()
        with self._with_body(body):
            resp = self.client.get("/api/photoshub/pending-delete")
        self.assertEqual(resp.status_code, 200)
        self.assertIsNone(resp.json()["album_id"])

    def test_torn_stream_mid_body_is_the_coded_502(self):
        def _torn(req, timeout):
            raise http.client.IncompleteRead(b"[")

        with mock.patch.object(photoshub_svc, "_immich_open", _torn):
            resp = self.client.get("/api/photoshub/pending-delete")
        self.assertEqual(resp.status_code, 502)
        self.assertEqual(
            resp.json()["detail"]["code"], "photoshub.pending_failed",
        )

    def test_immich_http_401_is_the_coded_502_on_pending_delete(self):
        def _http_error(req, timeout):
            raise urllib.error.HTTPError(
                "http://127.0.0.1:2283/api/albums", 401, "unauthorized",
                {}, None,
            )

        with mock.patch.object(photoshub_svc, "_immich_open", _http_error):
            resp = self.client.get("/api/photoshub/pending-delete")
        self.assertEqual(resp.status_code, 502)
        self.assertEqual(
            resp.json()["detail"]["code"], "photoshub.pending_failed",
        )

    def test_torn_stream_on_a_thumb_is_the_coded_502(self):
        def _torn(req, timeout):
            raise http.client.IncompleteRead(b"")

        with mock.patch.object(photoshub_svc, "_immich_open", _torn):
            resp = self.client.get(
                "/api/photoshub/pending-delete/thumb/aaaaaaaa-1111",
            )
        self.assertEqual(resp.status_code, 502)
        self.assertEqual(
            resp.json()["detail"]["code"], "photoshub.thumb_failed",
        )


if __name__ == "__main__":
    unittest.main()
