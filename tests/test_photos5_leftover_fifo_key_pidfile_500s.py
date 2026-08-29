"""Leftover FIFOs wedged PhotosHub/Immich reads forever — plus photos5 HTTP pins.

Reproduced live on the mounted routes before the fix (thread-timeout probe):

* a leftover FIFO occupying ``PhotosHub/config/immich_api_key`` parked
  ``_immich_key``'s plain ``open()`` until a writer appeared — GET
  /api/photoshub/config (``has_api_key``) hung **forever**, and so would any
  pending-delete / thumbnail / remove call.  The same read also *truncated* a
  leftover multi-MB junk key to 4096 chars and answered ``has_api_key: true``
  for a key that could never authenticate.  Both now go through
  ``read_text_capped`` (O_NONBLOCK + regular-file check + EFBIG), so a FIFO
  and an oversize file are the missing-key path the handler already had.

* the same class in ``hub/immich_svc.py``: a leftover FIFO occupying
  ``~/.immich-accelerator/pids/worker.pid`` parked ``worker_pid``'s plain
  ``open()`` — wedging the Immich block of GET /api/health forever.

The rest of this module pins the photos5 sweep's stays-immune findings at the
HTTP layer through the real ``create_app`` wiring (none previously exercised
these exact shapes on the mounted routes):

* FIFOs occupying config.json / a state journal / an allowed log file answer
  coded responses, never a hang or a 500;
* adversarial Immich API bodies (invalid UTF-8, an unquoted-bracket iterbomb,
  an over-cap payload) are the coded 502 ``photoshub.immich_response``;
* a >4300-digit ``limit`` / ``lines`` query literal is a 422 that renders
  (pydantic's ``int_parsing_size``), never a digit-cap 500;
* leftover hugeint / Infinity / hex-text ``min_local_original_pct`` in
  config.json reads back as the 99.0 default, never a 500.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import immich_svc, photoshub_svc  # noqa: E402

#: A JSON number literal past CPython's 4300-digit int<->str conversion cap.
_HUGE_DIGITS = "9" * 5000


def _finishes(test: unittest.TestCase, fn, timeout: float = 10.0):
    """Run *fn* on a worker thread; fail (instead of wedging CI) on a hang.

    The bug being pinned was an ``open()`` of a FIFO that blocks until a
    writer appears — a plain call would hang the suite forever on regression.
    """
    box: dict = {}

    def target():
        try:
            box["value"] = fn()
        except BaseException as exc:  # surfaced below on the main thread
            box["exc"] = exc

    worker = threading.Thread(target=target, daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        test.fail(f"call wedged for >{timeout}s — the FIFO hang is back")
    if "exc" in box:
        raise box["exc"]
    return box["value"]


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
        self.tmp = Path(tempfile.mkdtemp(prefix="photos5-fifo-3e7b-"))
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


class FifoApiKeyHungForeverTests(_PhotosHubHttpSandbox):
    """The reproduced leftover: open() of a FIFO key file blocked forever."""

    def test_fifo_key_file_answers_the_config_read_instead_of_hanging(self):
        os.mkfifo(self.key_path)
        resp = _finishes(self, lambda: self.client.get("/api/photoshub/config"))
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.json()["immich"]["has_api_key"])

    def test_fifo_key_file_is_the_coded_key_missing_on_pending_delete(self):
        os.mkfifo(self.key_path)
        resp = _finishes(
            self, lambda: self.client.get("/api/photoshub/pending-delete"),
        )
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(resp.json()["detail"]["code"], "photoshub.key_missing")

    def test_oversize_junk_key_reads_as_missing_not_a_truthy_truncation(self):
        # The old read truncated a multi-MB junk file to its first 4096 chars
        # and answered has_api_key: true for a key that cannot authenticate.
        self.key_path.write_text("k" * (2 * 1024 * 1024), encoding="utf-8")
        resp = self.client.get("/api/photoshub/config")
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.json()["immich"]["has_api_key"])

    def test_invalid_utf8_key_stays_the_missing_key_path(self):
        self.key_path.write_bytes(b"\xff\xfe torn key")
        resp = self.client.get("/api/photoshub/config")
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.json()["immich"]["has_api_key"])

    def test_a_real_key_still_reads_back_configured(self):
        self.key_path.write_text("testkey-abc123\n", encoding="utf-8")
        resp = self.client.get("/api/photoshub/config")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["immich"]["has_api_key"])
        self.assertEqual(photoshub_svc._immich_key(), "testkey-abc123")


class FifoWorkerPidfileHungHealthTests(unittest.TestCase):
    """immich_svc.worker_pid: the same open()-of-a-FIFO hang, on GET /api/health."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="photos5-pid-3e7b-"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.pidfile = self.tmp / "worker.pid"

    def test_fifo_pidfile_answers_no_worker_instead_of_hanging(self):
        os.mkfifo(self.pidfile)
        with mock.patch.object(immich_svc, "WORKER_PID", self.pidfile):
            self.assertIsNone(_finishes(self, immich_svc.worker_pid))

    def test_oversize_pidfile_answers_no_worker(self):
        self.pidfile.write_text("9" * 4096, encoding="utf-8")
        with (
            mock.patch.object(immich_svc, "WORKER_PID", self.pidfile),
            mock.patch.object(immich_svc, "sh") as fake_sh,
        ):
            self.assertIsNone(immich_svc.worker_pid())
        fake_sh.assert_not_called()

    def test_a_sane_pidfile_still_resolves_the_worker(self):
        started = "Mon Aug  4 13:42:00 2025"
        self.pidfile.write_text(f"502\n{started}\n", encoding="utf-8")
        with (
            mock.patch.object(immich_svc, "WORKER_PID", self.pidfile),
            mock.patch.object(
                immich_svc, "sh", return_value=(0, f"{started} immich", ""),
            ),
        ):
            self.assertEqual(immich_svc.worker_pid(), 502)


class FifoOnDiskStoresHttpPinTests(_PhotosHubHttpSandbox):
    """FIFOs occupying the JSON stores / logs stay coded, never hang or 500."""

    def test_fifo_config_json_keeps_status_200_and_patch_the_coded_400(self):
        os.mkfifo(self.cfg_path)
        status = _finishes(self, lambda: self.client.get("/api/photoshub/status"))
        self.assertEqual(status.status_code, 200)
        patch = _finishes(self, lambda: self.client.patch(
            "/api/photoshub/config", json={"panel": {"url": "https://p.lan/"}},
        ))
        self.assertEqual(patch.status_code, 400)
        self.assertEqual(patch.json()["detail"]["code"], "photoshub.bad_config")

    def test_fifo_state_journal_keeps_status_200(self):
        os.mkfifo(self.hub / "state" / "originals_status.json")
        resp = _finishes(self, lambda: self.client.get("/api/photoshub/status"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["originals"], {})

    def test_fifo_log_file_keeps_the_logs_route_200(self):
        (self.hub / "logs").mkdir()
        os.mkfifo(self.hub / "logs" / "cleanup.log")
        resp = _finishes(
            self, lambda: self.client.get("/api/photoshub/logs/cleanup"),
        )
        self.assertEqual(resp.status_code, 200)
        resp.json()


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


class AdversarialImmichBodyHttpPinTests(_PhotosHubHttpSandbox):
    """Junk Immich replies are the coded 502, never a raw 500."""

    def setUp(self):
        super().setUp()
        self.key_path.write_text("testkey123\n", encoding="utf-8")
        self.cfg_path.write_text(
            '{"immich": {"base_url": "http://127.0.0.1:2283",'
            ' "album_pending_delete": "PD"}}',
            encoding="utf-8",
        )

    def _with_immich(self, payload: bytes, ctype: str = "application/json"):
        resp = _FakeImmichResponse(payload, ctype)
        return mock.patch.object(
            photoshub_svc, "_immich_open", lambda req, timeout: resp,
        )

    def test_invalid_utf8_album_body_is_the_coded_502(self):
        with self._with_immich(b"\xff\xfe not json"):
            resp = self.client.get("/api/photoshub/pending-delete")
        self.assertEqual(resp.status_code, 502)
        self.assertEqual(
            resp.json()["detail"]["code"], "photoshub.immich_response",
        )

    def test_iterbomb_album_body_is_the_coded_502(self):
        with self._with_immich(b"[" * 5000):
            resp = self.client.get("/api/photoshub/pending-delete")
        self.assertEqual(resp.status_code, 502)
        self.assertEqual(
            resp.json()["detail"]["code"], "photoshub.immich_response",
        )

    def test_oversize_album_body_is_the_coded_502(self):
        with self._with_immich(b"x" * (4 * 1024 * 1024 + 100)):
            resp = self.client.get("/api/photoshub/pending-delete")
        self.assertEqual(resp.status_code, 502)
        self.assertEqual(
            resp.json()["detail"]["params"]["detail"], "payload too large",
        )

    def test_hugeint_album_id_from_immich_is_a_coded_4xx_that_renders(self):
        # _json_int nulls the over-cap literal during the parse; the id probe
        # then refuses it with the coded 400, never a digit-cap 500.
        body = ('[{"albumName": "PD", "id": ' + _HUGE_DIGITS + "}]").encode()
        with self._with_immich(body):
            resp = self.client.get("/api/photoshub/pending-delete")
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()["detail"]["code"], "photoshub.bad_ids")

    def test_numeric_album_id_from_immich_still_lists_via_str_probe(self):
        # A YAML/JSON numeric id renders through str(); the hex-charset id
        # regex accepts its digits, so the listing stays 200.
        body = json.dumps([{"albumName": "PD", "id": 12345678}]).encode()
        with self._with_immich(body):
            resp = self.client.get("/api/photoshub/pending-delete")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["album_id"], "12345678")

    def test_surrogate_content_type_on_a_thumb_is_the_coded_502(self):
        with self._with_immich(b"x", ctype="image/jpeg\udcff"):
            resp = self.client.get(
                "/api/photoshub/pending-delete/thumb/aaaaaaaa-1111",
            )
        self.assertEqual(resp.status_code, 502)
        detail = resp.json()["detail"]
        self.assertEqual(detail["code"], "photoshub.thumb_failed")
        self.assertNotIn("\udcff", json.dumps(detail))

    def test_html_content_type_on_a_thumb_is_the_coded_502(self):
        with self._with_immich(b"<html>", ctype="text/html"):
            resp = self.client.get(
                "/api/photoshub/pending-delete/thumb/aaaaaaaa-1111",
            )
        self.assertEqual(resp.status_code, 502)
        self.assertEqual(resp.json()["detail"]["code"], "photoshub.thumb_failed")


class QueryDigitCapHttpPinTests(_PhotosHubHttpSandbox):
    """>4300-digit query literals stay a 422 that renders, never a 500."""

    def test_hugeint_limit_is_a_422_that_renders(self):
        resp = self.client.get(
            f"/api/photoshub/pending-delete?limit={_HUGE_DIGITS}",
        )
        self.assertEqual(resp.status_code, 422)
        resp.json()

    def test_hugeint_lines_is_a_422_that_renders(self):
        resp = self.client.get(
            f"/api/photoshub/logs/bridge?lines={_HUGE_DIGITS}",
        )
        self.assertEqual(resp.status_code, 422)
        resp.json()


class LeftoverMinPctHttpPinTests(_PhotosHubHttpSandbox):
    """Junk min_local_original_pct in config.json reads as the 99.0 default."""

    def _min_pct(self) -> float:
        resp = self.client.get("/api/photoshub/config")
        self.assertEqual(resp.status_code, 200)
        return resp.json()["gates"]["min_local_original_pct"]

    def test_hugeint_min_pct_reads_as_the_default(self):
        self.cfg_path.write_text(
            '{"gates": {"min_local_original_pct": ' + _HUGE_DIGITS + "}}",
            encoding="utf-8",
        )
        self.assertEqual(self._min_pct(), 99.0)

    def test_infinity_min_pct_reads_as_the_default(self):
        self.cfg_path.write_text(
            '{"gates": {"min_local_original_pct": 1e999}}', encoding="utf-8",
        )
        self.assertEqual(self._min_pct(), 99.0)

    def test_hex_text_min_pct_reads_as_the_default(self):
        # int(x, 16) has no digit cap: hex text dodges the parse limit, so
        # the float() conversion guard is what keeps this coded.
        self.cfg_path.write_text(
            '{"gates": {"min_local_original_pct": "0x' + "f" * 5000 + '"}}',
            encoding="utf-8",
        )
        self.assertEqual(self._min_pct(), 99.0)


if __name__ == "__main__":
    unittest.main()
