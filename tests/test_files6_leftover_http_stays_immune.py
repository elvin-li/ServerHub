"""Sixth leftover sweep of the Files page, over the real mounted app.

The hunted classes (lone UTF-8 surrogates in keys AND values, the CPython
4300-digit int cap — including the uncapped YAML/plist hex form that arrives
already-int — numeric YAML root ids, NUL/loop/traversal paths, vanished-CLI
503-vs-500) were re-reproduced against every route the Files page mounts:

    GET  /api/files                  GET  /api/files/list
    POST /api/files/mkdir            POST /api/files/delete
    POST /api/files/rename           GET  /api/files/download
    POST /api/files/upload           GET  /api/files/filebrowser
    POST /api/files/filebrowser/{ensure,stop,ondemand}

Two live leaks were found and fixed — both the same class the repo's own
``read_bytes_capped`` documents ("a plain open of a FIFO parks until a
writer appears"), which the files1-5 sweeps never reached because they only
ever planted regular files, symlinks and directories:

* ``download()`` opened the checked path with ``O_RDONLY | O_NOFOLLOW``
  only.  A leftover *named pipe* under a browsable root (mkfifo debris from
  a build script, a socket-activated tool's stale rendezvous file) made
  ``os.open`` block until a writer appeared — never, for a leftover — so
  GET /api/files/download parked its worker thread forever instead of
  answering anything at all.  ``O_NONBLOCK`` opens the FIFO immediately and
  the existing ``S_ISREG`` check then refuses it as the coded 400
  (:class:`FifoDownloadHttpTests` trips its watchdog on the pre-fix tree);
* ``ensure_filebrowser()`` opened its log path ``O_WRONLY | O_APPEND``
  the same way, so a FIFO planted at ``filebrowser-hub.log`` parked POST
  /api/files/filebrowser/ensure until a reader appeared.  With
  ``O_NONBLOCK`` the open fails ENXIO and the except arm maps it to the
  coded start failure (:class:`FifoLogEnsurePinTests`).

Everything else was already immune at the service level (``_as_text`` /
``_finite_int`` / ``_root_label`` / ``_try_resolve`` — see
test_files_leftover_fb_hex_surrogate_503s and
test_files_leftover_numeric_root_ids) — but none of those pins exercises
request routing, Pydantic body parsing, app_factory's sanitizing handlers,
or Starlette's strict UTF-8 render of the final body.  This battery pins the
whole cycle through ``create_app()``.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import quote

from fastapi import HTTPException

from hub import files_svc
from hub.app_factory import create_app
from hub.auth import require_auth

#: Loaded through a power-of-two base, so already an int past the digit cap.
_HUGE_HEX = int("F" * 4400, 16)

_app = None


def _the_app():
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return _app


async def _asgi_request(method, path, *, body=None, raw_body=None, query=""):
    """Drive the full panel app (middleware + handlers) through one cycle."""
    app = _the_app()
    payload = raw_body if raw_body is not None else (
        b"{}" if body is None else json.dumps(body).encode("utf-8")
    )
    sent = False
    messages: list[dict] = []

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": payload, "more_body": False}
        # Never send http.disconnect: StreamingResponse (the download route)
        # races its body against the disconnect listener and would abort.
        await asyncio.Event().wait()

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1", "method": method, "scheme": "http",
        "path": path, "raw_path": path.encode(),
        "query_string": query.encode() if isinstance(query, str) else query,
        "root_path": "",
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
            (b"host", b"localhost:8086"),
        ],
        "server": ("localhost", 8086), "client": ("127.0.0.1", 1), "state": {},
    }
    await app(scope, receive, send)
    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    raw = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    # The body must already be valid UTF-8 — decode strictly on purpose.
    return status, raw.decode("utf-8")


def request(method, path, **kw):
    return asyncio.run(_asgi_request(method, path, **kw))


class _FilesSandbox(unittest.TestCase):
    """One temp browsable root, patched in as the only configured root."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "root"
        self.root.mkdir()
        self._set_settings({"roots": [{"id": "r", "path": str(self.root)}]})

    def _set_settings(self, section: dict):
        patched = mock.patch.object(
            files_svc, "settings_section", return_value=section
        )
        patched.start()
        self.addCleanup(patched.stop)


@unittest.skipUnless(hasattr(os, "mkfifo"), "platform has no mkfifo")
class FifoDownloadHttpTests(_FilesSandbox):
    """The fixed leak: a leftover FIFO must answer, not park the worker.

    On the pre-fix tree the plain ``os.open`` blocks until a writer appears,
    so the request below never returns — the watchdog trips and the test
    fails fast instead of hanging the suite (cleanup opens a writer to
    release the leaked thread either way).
    """

    def setUp(self):
        super().setUp()
        self.fifo = self.root / "pipe.fifo"
        os.mkfifo(self.fifo)

    def _release_blocked_reader(self):
        # A blocked O_RDONLY open completes as soon as any writer opens.
        try:
            wfd = os.open(self.fifo, os.O_WRONLY | os.O_NONBLOCK)
        except OSError:
            return
        os.close(wfd)

    def test_download_of_a_fifo_is_the_coded_400_not_a_hang(self):
        done: dict = {}

        def go():
            done["result"] = request(
                "GET", "/api/files/download",
                query=f"path={quote(str(self.fifo))}&root_id=r",
            )

        worker = threading.Thread(target=go, daemon=True)
        worker.start()
        worker.join(10)
        if worker.is_alive():
            self._release_blocked_reader()
            worker.join(5)
            self.fail(
                "GET /api/files/download parked in os.open on the FIFO "
                "instead of answering"
            )
        status, text = done["result"]
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(json.loads(text)["detail"]["code"], "files.file_only")

    def test_a_regular_file_still_streams_with_its_length(self):
        target = self.root / "hello.txt"
        target.write_text("hello files6")
        status, text = request(
            "GET", "/api/files/download",
            query=f"path={quote(str(target))}&root_id=r",
        )
        self.assertEqual(status, 200, text[:300])
        self.assertEqual(text, "hello files6")

    def test_service_layer_refuses_the_fifo_promptly(self):
        done: dict = {}

        def go():
            try:
                files_svc.download(str(self.fifo), root_id="r")
            except HTTPException as exc:
                done["exc"] = exc

        worker = threading.Thread(target=go, daemon=True)
        worker.start()
        worker.join(10)
        if worker.is_alive():
            self._release_blocked_reader()
            worker.join(5)
            self.fail("files_svc.download parked in os.open on the FIFO")
        self.assertEqual(done["exc"].status_code, 400)
        self.assertEqual(done["exc"].detail["code"], "files.file_only")


@unittest.skipUnless(hasattr(os, "mkfifo"), "platform has no mkfifo")
class FifoLogEnsurePinTests(unittest.TestCase):
    """POST /api/files/filebrowser/ensure opens its log before the spawn.

    A FIFO planted at the log path parked the plain O_WRONLY open until a
    reader appeared; with O_NONBLOCK it fails ENXIO and the except arm keeps
    the coded start failure (binary still on disk, so never the 503).
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.bin = self.tmp / "filebrowser" / "filebrowser-bin"
        self.bin.parent.mkdir(parents=True)
        self.bin.write_text("#!/bin/sh\n")
        self.log = self.tmp / "logs" / "fb.log"
        self.log.parent.mkdir(parents=True)
        os.mkfifo(self.log)

    def _ensure(self):
        with (
            mock.patch.object(files_svc, "FB_BIN", self.bin),
            mock.patch.object(files_svc, "FB_PLIST", self.tmp / "absent.plist"),
            mock.patch.object(files_svc, "FB_DB", self.bin.parent / "filebrowser.db"),
            mock.patch.object(files_svc, "FB_ROOT_DEFAULT", self.tmp / "media"),
            mock.patch.object(files_svc, "FB_LOG", self.log),
            mock.patch.object(files_svc, "sh", return_value=(1, "", "")),
            mock.patch.object(files_svc, "host_ip", return_value="127.0.0.1"),
            mock.patch.object(files_svc.time, "sleep"),
            mock.patch.object(files_svc.subprocess, "Popen") as popen,
        ):
            try:
                files_svc.ensure_filebrowser()
            except HTTPException as exc:
                return exc, popen
            return None, popen

    def test_fifo_log_path_is_the_coded_start_failure_not_a_hang(self):
        done: dict = {}

        def go():
            done["exc"], done["popen"] = self._ensure()

        worker = threading.Thread(target=go, daemon=True)
        worker.start()
        worker.join(10)
        if worker.is_alive():
            # A blocked O_WRONLY open completes once any reader opens.
            try:
                rfd = os.open(self.log, os.O_RDONLY | os.O_NONBLOCK)
                os.close(rfd)
            except OSError:
                pass
            worker.join(5)
            self.fail("ensure_filebrowser parked in os.open on the FIFO log")
        exc = done["exc"]
        self.assertIsNotNone(exc, "expected the coded start failure")
        self.assertEqual(exc.status_code, 500)
        self.assertEqual(exc.detail["code"], "files.fb_start_failed")
        # The binary never left the disk, so the 503 vanish-shape is wrong here.
        self.assertTrue(self.bin.is_file())
        done["popen"].assert_not_called()


class ListHostileDiskHttpTests(_FilesSandbox):
    """GET /api/files(/list) with the leftover zoo on disk, over the app."""

    def setUp(self):
        super().setUp()
        (self.root / "sub").mkdir()
        (self.root / "plain.txt").write_text("x")
        # A name only surrogateescape can represent (undecodable disk bytes).
        raw = os.path.join(
            str(self.root), b"f\xff.bin".decode("utf-8", "surrogateescape")
        )
        Path(raw).write_text("x")
        (self.root / "loop").symlink_to(self.root / "loop")

    def test_listing_renders_the_zoo_and_scrubs_surrogates(self):
        status, text = request("GET", "/api/files/list", query="root_id=r")
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        names = {item["name"] for item in payload["items"]}
        self.assertIn("plain.txt", names)
        self.assertIn("f?.bin", names)  # encode-replace'd, never the surrogate
        self.assertNotIn("\udcff", text)

    def test_symlink_loop_target_is_the_coded_404(self):
        status, text = request(
            "GET", "/api/files/list",
            query=f"path={quote(str(self.root / 'loop'))}&root_id=r",
        )
        self.assertEqual(status, 404, text[:300])
        self.assertEqual(json.loads(text)["detail"]["code"], "files.not_found")

    def test_nul_byte_path_is_the_coded_404(self):
        status, text = request("GET", "/api/files/list", query="path=%00abc")
        self.assertEqual(status, 404, text[:300])

    def test_huge_digit_root_id_is_the_coded_400(self):
        status, text = request(
            "GET", "/api/files/list", query="root_id=" + "9" * 5000
        )
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(
            json.loads(text)["detail"]["code"], "files.unknown_root"
        )

    def test_traversal_outside_the_root_is_the_coded_403(self):
        status, text = request("GET", "/api/files/list", query="path=/etc")
        self.assertEqual(status, 403, text[:300])
        self.assertEqual(
            json.loads(text)["detail"]["code"], "files.path_outside_root"
        )


class HostileRootsConfigHttpTests(unittest.TestCase):
    """GET /api/files with leftover services.yaml root shapes, over the app."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "shared"
        self.root.mkdir()

    def _overview(self, roots):
        with mock.patch.object(
            files_svc, "settings_section", return_value={"roots": roots}
        ):
            return request("GET", "/api/files")

    def test_numeric_yaml_root_id_is_addressable_over_http(self):
        roots = [{"id": 2, "path": str(self.root)}]
        status, text = self._overview(roots)
        self.assertEqual(status, 200, text[:300])
        self.assertEqual(json.loads(text)["roots"][0]["id"], "2")
        with mock.patch.object(
            files_svc, "settings_section", return_value={"roots": roots}
        ):
            status, text = request("GET", "/api/files/list", query="root_id=2")
        self.assertEqual(status, 200, text[:300])

    def test_hex_huge_already_int_id_falls_back_not_500(self):
        status, text = self._overview([{"id": _HUGE_HEX, "path": str(self.root)}])
        self.assertEqual(status, 200, text[:300])
        # str() of the over-cap int raises the digit-cap ValueError; the
        # basename fallback must land instead of the 500.
        self.assertEqual(json.loads(text)["roots"][0]["id"], "shared")

    def test_surrogate_configured_path_renders_scrubbed(self):
        status, text = self._overview(
            [{"id": "s", "path": "/tmp/x\udcffnope"},
             {"id": "ok", "path": str(self.root)}]
        )
        self.assertEqual(status, 200, text[:300])
        self.assertNotIn("\udcff", text)

    def test_junk_root_entries_cost_themselves_only(self):
        status, text = self._overview(
            [None, 5, [], {"path": ""}, {"id": "ok", "path": str(self.root)}]
        )
        self.assertEqual(status, 200, text[:300])
        ids = [r["id"] for r in json.loads(text)["roots"]]
        self.assertEqual(ids, ["ok"])


class BodyParseGuardHttpTests(_FilesSandbox):
    """Hostile request bodies through the real app's parse + 422 handler."""

    def test_huge_int_literal_in_a_body_is_400_not_500(self):
        # json.loads raises the digit-cap ValueError, not JSONDecodeError;
        # the body-parse guard must map it to 400.
        status, text = request(
            "POST", "/api/files/mkdir",
            raw_body=b'{"path": "/x", "name": ' + b"9" * 5000 + b"}",
        )
        self.assertEqual(status, 400, text[:300])

    def test_surrogate_escape_name_is_the_coded_400_with_a_clean_body(self):
        # FastAPI parses the body with json.loads (which mints the lone
        # surrogate) and python-mode Pydantic lets it into the typed str
        # field, so the hostile name reaches the handler itself —
        # _clean_component must refuse it as the coded 400 and the error
        # body must survive Starlette's strict UTF-8 encode.
        raw = (
            '{"path": ' + json.dumps(str(self.root))
            + ', "root_id": "r", "name": "a\\ud800b"}'
        ).encode("ascii")
        status, text = request("POST", "/api/files/mkdir", raw_body=raw)
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(json.loads(text)["detail"]["code"], "files.bad_name")
        self.assertNotIn("\ud800", text)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_infinity_literal_in_a_str_field_is_422_with_a_clean_body(self):
        status, text = request(
            "POST", "/api/files/mkdir",
            raw_body=b'{"path": "/x", "name": 1e999}',
        )
        self.assertEqual(status, 422, text[:300])
        json.loads(text)  # renders under allow_nan=False

    def test_control_character_name_is_the_coded_400(self):
        status, text = request(
            "POST", "/api/files/mkdir",
            body={"path": str(self.root), "name": "a\tb", "root_id": "r"},
        )
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(json.loads(text)["detail"]["code"], "files.bad_name")

    def test_ondemand_huge_int_enabled_is_400_not_500(self):
        status, text = request(
            "POST", "/api/files/filebrowser/ondemand",
            raw_body=b'{"enabled": ' + b"9" * 5000 + b"}",
        )
        self.assertEqual(status, 400, text[:300])


class MutationShapesHttpTests(_FilesSandbox):
    """Delete/rename keep their coded refusals through the mounted routes."""

    def test_delete_of_the_root_is_the_coded_400(self):
        status, text = request(
            "POST", "/api/files/delete",
            body={"path": str(self.root), "root_id": "r"},
        )
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(
            json.loads(text)["detail"]["code"], "files.cannot_delete_root"
        )

    def test_rename_onto_an_existing_name_is_the_coded_400(self):
        (self.root / "a.txt").write_text("a")
        (self.root / "b.txt").write_text("b")
        status, text = request(
            "POST", "/api/files/rename",
            body={"path": str(self.root / "a.txt"), "new_name": "b.txt",
                  "root_id": "r"},
        )
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(
            json.loads(text)["detail"]["code"], "files.dest_exists"
        )
        self.assertEqual((self.root / "b.txt").read_text(), "b")

    def test_delete_of_a_vanished_path_is_the_coded_404(self):
        status, text = request(
            "POST", "/api/files/delete",
            body={"path": str(self.root / "gone.txt"), "root_id": "r"},
        )
        self.assertEqual(status, 404, text[:300])
        self.assertEqual(json.loads(text)["detail"]["code"], "files.not_found")


if __name__ == "__main__":
    unittest.main()
