"""Leftover Logs wrong-answers/500s: surrogate on-disk names, the
rotation race, and date/bytes config values.

Three classes reproduced over the real mounted app (``create_app()``)
before this sweep:

* **Surrogate on-disk name: listed alive, tailed "missing".**  One
  non-UTF-8 byte in a log's filename (surrogateescape from os.listdir /
  a pasted path) listed as ``exists: true`` with a real size — the
  listing stats the raw ``Path`` — but GET /api/logs/{id} re-derived its
  ``Path`` from the *published* row, whose text is scrubbed for
  Starlette's UTF-8 encode (``\\udcff`` → U+FFFD).  The scrubbed text
  names nothing, so the tail answered "(file does not exist)" for a file
  the listing had just stat'ed.  ``tail_log`` now reads through the raw
  ``Path`` the listing built (``_entries``); the *published* fields stay
  scrubbed.

* **Rotation race: vanished-under-read was a coded 500.**  A source that
  passed the ``is_file`` gate and was then rotated/unlinked before the
  ``os.open`` mapped the FileNotFoundError to ``logs.read_failed`` — an
  HTTP 500 blaming the server for logrotate doing its job, on a poller
  that refreshes every 6 seconds.  Per the vanished-CLI rule the
  downgrade needs a fresh disk probe *on the failure path*: confirmed
  gone answers the same missing-200 the listing gives; a bizarre ENOENT
  while the probe still sees the file keeps the coded 500.

* **Date / bytes config values silently vanished.**  The original panel
  published ``id``/``name`` verbatim through FastAPI's encoder — YAML
  ``id: 2024-01-01`` (a ``datetime.date``) rendered as its isoformat,
  bytes strict-decoded (and 500'd the whole listing on invalid UTF-8).
  The hardening sweep's str/int-only ``_config_text`` gate then silently
  hid such sources from GET /api/logs and 404'd their tails.  Dates now
  coerce to the same isoformat text the encoder used to publish, bytes
  replace-decode (never a 500), and a bytes *path* goes through
  ``os.fsdecode`` — its surrogateescape text names the real on-disk file
  instead of stringifying to the garbage relative name ``b'/…'``.

A FIFO stays-immune pin rides along: a leftover FIFO occupying a
configured log path lists ``exists: false`` and tails the missing-200
without ever opening it (the ``is_file`` gate), so the route cannot park
on a writer-less pipe.
"""
from __future__ import annotations

import datetime
import errno
import json
import os
import sys
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from fastapi.testclient import TestClient  # noqa: E402

from hub import auth, config, logs_svc  # noqa: E402
from hub.app_factory import create_app  # noqa: E402

PASSWORD = "correct-horse-battery"

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
    return _APP


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does to the body."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class LogsAppSandbox(unittest.TestCase):
    """Authenticated client over the real mounted app; sources per test."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="logs-leftover-pin-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        data = self.root / "data"
        data.mkdir(parents=True)
        self.yaml_path = self.root / "services.yaml"
        for target, attr, value in (
            (config, "YAML_PATH", self.yaml_path),
            (config, "DATA_DIR", data),
            (config, "BASE", self.root),
            (config, "_LOCK_PATH", data / ".services.yaml.lock"),
            (auth, "SECRET_FILE", data / ".session-secret"),
            (auth, "SETUP_TOKEN_FILE", data / ".setup-token"),
            (auth, "LOCAL_TOKEN_FILE", data / ".local-client-token"),
        ):
            patcher = mock.patch.object(target, attr, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(config.reload_cfg)
        auth._secret_cache = None
        auth._login_attempts.clear()
        self.yaml_path.write_text(
            "settings:\n"
            "  auth:\n"
            "    enabled: true\n"
            "    username: admin\n"
            f'    password_hash: "{auth.hash_password(PASSWORD)}"\n'
        )
        config.reload_cfg()
        self.client = TestClient(app(), raise_server_exceptions=False)
        response = self.client.post(
            "/api/auth/login", json={"username": "admin", "password": PASSWORD}
        )
        assert response.status_code == 200, response.text
        self.log_path = self.root / "pin.log"
        self.log_path.write_text("alpha\nbeta\n", encoding="utf-8")

    def _with_sources(self, sources):
        return mock.patch.object(
            logs_svc, "cfg", lambda: {"log_sources": sources},
        )


class SurrogateOnDiskNameTests(LogsAppSandbox):
    """A source the listing stats alive must tail its content, whatever
    bytes its on-disk name carries."""

    def _surrogate_log(self) -> str:
        raw = os.fsencode(str(self.root)) + b"/weird-\xff-name.log"
        try:
            with open(raw, "wb") as fh:
                fh.write(b"line1\nline2\n")
        except (OSError, ValueError):
            self.skipTest("this filesystem refuses non-UTF-8 filenames")
        return raw.decode("utf-8", "surrogateescape")

    def test_listed_alive_surrogate_name_tails_its_content(self):
        sur_path = self._surrogate_log()
        self.assertIn("\udcff", sur_path)
        with self._with_sources([
            {"id": "sur", "name": "Sur", "path": sur_path},
        ]):
            listing = self.client.get("/api/logs")
            tail = self.client.get("/api/logs/sur")
        self.assertEqual(listing.status_code, 200)
        row = listing.json()["sources"][0]
        self.assertTrue(row["exists"])
        self.assertGreater(row["size"], 0)
        # The reproduced leftover: this answered exists:false /
        # "(file does not exist)" for the file the listing just stat'ed,
        # because the tail re-derived its Path from the scrubbed row text.
        self.assertEqual(tail.status_code, 200)
        body = tail.json()
        self.assertTrue(body["exists"])
        self.assertEqual(body["lines"], 2)
        self.assertIn("line2", body["log"])
        # The published fields stay scrubbed for Starlette's UTF-8 encode.
        self.assertNotIn("\udcff", json.dumps(body, ensure_ascii=False))
        _starlette(listing.json())
        _starlette(body)

    def test_bytes_path_config_names_the_same_on_disk_file(self):
        """A bytes path (os.listdir(b"…") leftover) used to stringify to
        the garbage relative name ``b'/…'``; fsdecode keeps the
        surrogateescape text that names the real file."""
        sur_path = self._surrogate_log()
        with self._with_sources([
            {"id": "bin", "name": "Bin", "path": os.fsencode(sur_path)},
        ]):
            listing = self.client.get("/api/logs")
            tail = self.client.get("/api/logs/bin")
        self.assertEqual(listing.status_code, 200)
        self.assertTrue(listing.json()["sources"][0]["exists"])
        self.assertEqual(tail.status_code, 200)
        self.assertIn("line1", tail.json()["log"])


class RotationRaceTests(LogsAppSandbox):
    """Vanished between the is_file gate and the read: missing-200 after
    a fresh disk confirm, never a 500 for logrotate doing its job."""

    def test_confirmed_vanished_answers_the_missing_200(self):
        log_path = self.log_path

        def rotate_away(path, n):
            log_path.unlink(missing_ok=True)
            raise FileNotFoundError(
                errno.ENOENT, "No such file or directory", str(path))

        with self._with_sources([
            {"id": "ok", "name": "OK", "path": str(self.log_path)},
        ]):
            with mock.patch.object(
                logs_svc, "tail_file_lines", side_effect=rotate_away,
            ):
                resp = self.client.get("/api/logs/ok")
        # The reproduced leftover: this was the coded 500 logs.read_failed.
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertFalse(body["exists"])
        self.assertEqual(body["log"], "(file does not exist)")
        self.assertEqual(body["lines"], 0)
        _starlette(body)

    def test_enoent_with_the_file_still_on_disk_keeps_read_failed(self):
        """The downgrade is gated on the disk confirm: an ENOENT while a
        fresh probe still sees the file is a real read failure."""
        with self._with_sources([
            {"id": "ok", "name": "OK", "path": str(self.log_path)},
        ]):
            with mock.patch.object(
                logs_svc, "tail_file_lines",
                side_effect=FileNotFoundError(
                    errno.ENOENT, "ghost ENOENT", str(self.log_path)),
            ):
                resp = self.client.get("/api/logs/ok")
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(resp.json()["detail"]["code"], "logs.read_failed")
        self.assertTrue(self.log_path.is_file())


class DateBytesConfigValueTests(LogsAppSandbox):
    """Values the original panel published verbatim keep listing/tailing."""

    def test_yaml_date_id_lists_isoformat_and_tails(self):
        """``id: 2024-01-01`` loads as datetime.date; the encoder used to
        publish its isoformat before the str/int gate hid the source."""
        with self._with_sources([
            {"id": datetime.date(2024, 1, 1), "name": "Dated",
             "path": str(self.log_path)},
        ]):
            listing = self.client.get("/api/logs")
            tail = self.client.get("/api/logs/2024-01-01")
        self.assertEqual(
            [r["id"] for r in listing.json()["sources"]], ["2024-01-01"])
        self.assertEqual(tail.status_code, 200)
        self.assertIn("alpha", tail.json()["log"])
        _starlette(tail.json())

    def test_yaml_timestamp_id_lists_isoformat_and_tails(self):
        stamp = datetime.datetime(2024, 1, 1, 12, 30, 0)
        with self._with_sources([
            {"id": stamp, "name": "Stamped", "path": str(self.log_path)},
        ]):
            listing = self.client.get("/api/logs")
            tail = self.client.get(
                "/api/logs/" + urllib.parse.quote(stamp.isoformat()))
        self.assertEqual(
            [r["id"] for r in listing.json()["sources"]],
            ["2024-01-01T12:30:00"])
        self.assertEqual(tail.status_code, 200)
        self.assertIn("beta", tail.json()["log"])

    def test_binary_id_and_name_list_decoded_and_tail(self):
        """YAML ``!!binary`` id/name arrive as bytes; the original panel
        strict-decoded them in the encoder."""
        with self._with_sources([
            {"id": b"bin-id", "name": b"Bin", "path": str(self.log_path)},
        ]):
            listing = self.client.get("/api/logs")
            tail = self.client.get("/api/logs/bin-id")
        rows = listing.json()["sources"]
        self.assertEqual([(r["id"], r["name"]) for r in rows],
                         [("bin-id", "Bin")])
        self.assertEqual(tail.status_code, 200)
        self.assertIn("alpha", tail.json()["log"])

    def test_invalid_utf8_bytes_name_lists_scrubbed_not_500(self):
        """The original panel 500'd the whole listing here: FastAPI's
        encoder strict-decodes bytes and ``b"\\xff"`` is UnicodeDecodeError.
        Replace-decode keeps the row and the siblings."""
        with self._with_sources([
            {"id": "ok", "name": b"\xff\xfe-junk", "path": str(self.log_path)},
            {"id": "sib", "name": "Sibling", "path": str(self.log_path)},
        ]):
            listing = self.client.get("/api/logs")
        self.assertEqual(listing.status_code, 200)
        rows = listing.json()["sources"]
        self.assertEqual([r["id"] for r in rows], ["ok", "sib"])
        self.assertIn("\ufffd", rows[0]["name"])
        _starlette(rows)


class FifoStaysImmuneTests(LogsAppSandbox):
    """A FIFO occupying a log path lists dead and tails missing — the
    is_file gate answers before anything could open (and park on) it."""

    def test_fifo_lists_not_a_file_and_tails_missing_200(self):
        fifo = self.root / "trap.fifo"
        try:
            os.mkfifo(fifo)
        except (AttributeError, OSError):
            self.skipTest("mkfifo unavailable on this platform")
        with self._with_sources([
            {"id": "fifo", "name": "Trap", "path": str(fifo)},
        ]):
            listing = self.client.get("/api/logs")
            tail = self.client.get("/api/logs/fifo")
        row = listing.json()["sources"][0]
        self.assertFalse(row["exists"])
        self.assertEqual(tail.status_code, 200)
        self.assertFalse(tail.json()["exists"])
        self.assertEqual(tail.json()["log"], "(file does not exist)")


if __name__ == "__main__":
    unittest.main(verbosity=2)
