"""Leftover Logs coded-500s for states the listing already reports dead.

Two classes reproduced over the real mounted app (``create_app()`` +
``TestClient(raise_server_exceptions=False)``) before this sweep:

* **Symlink loop: listed dead, tailed a coded 500.**  A self-referencing
  symlink at a configured log path listed ``exists: false`` (``is_file``
  ignores ELOOP), but GET /api/logs/{id} raised ``RuntimeError("Symlink
  loop")`` out of ``Path.resolve()`` — which the handler mapped to the
  coded-500 ``logs.read_failed`` although no read was ever attempted.  A
  loop can never name a readable file, so per the NUL-path rule the tail
  now gives the same answer the listing gives: the 200 ``exists: false``
  / "(file does not exist)" payload.

* **Non-regular node swapped in under the read was a coded 500.**  The
  rotation-race fix downgraded *FileNotFoundError* (file unlinked between
  the ``is_file`` gate and the open) to the missing-200 after a fresh
  disk confirm — but the same race with the node *replaced* instead of
  removed kept the 500: a leftover FIFO, a directory, a device or socket
  swapped onto the name raises EINVAL/EISDIR/ENXIO out of
  ``tail_file_lines`` (which refuses non-regular files), and the handler
  blamed the server.  The downgrade is now any-OSError wide, still gated
  on the failure-path disk confirm: a probe that no longer sees a regular
  file answers like the listing; a probe that still sees one — ghost
  ENOENT, EACCES, or O_NOFOLLOW refusing a symlink swapped over the
  resolved name — keeps the coded ``logs.read_failed``.

Stays-immune pins ride along for vectors this sweep probed over *real
YAML on disk* (earlier pins mostly injected Python objects through a
mocked ``cfg``) and found already guarded: a YAML-escaped lone-surrogate
path or id (``"\\ud800"`` in a hand-edited double-quoted scalar) never
raw-500s and every id the listing publishes stays tailable; an over-cap
hex id parsed by the real loader drops only its entry — and the Settings
page surface (GET /api/settings ``log_sources``) stays renderable; an
oversize log tails capped; a socket at the path lists dead and tails
the missing-200; the Services script-log fallback that feeds listed ids
straight back into ``tail_log`` answers 200.
"""
from __future__ import annotations

import errno
import json
import os
import socket
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
        tmp = tempfile.TemporaryDirectory(prefix="logs5-leftover-pin-")
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
        self.auth_block = (
            "settings:\n"
            "  auth:\n"
            "    enabled: true\n"
            "    username: admin\n"
            f'    password_hash: "{auth.hash_password(PASSWORD)}"\n'
        )
        self.yaml_path.write_text(self.auth_block)
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

    def _write_yaml_sources(self, body: str) -> None:
        """Real services.yaml on disk, parsed by the real loader."""
        self.yaml_path.write_text(self.auth_block + body, encoding="utf-8")
        config.reload_cfg()


class SymlinkLoopTests(LogsAppSandbox):
    """A loop can never name a readable file: tail like the listing."""

    def _loop(self) -> Path:
        loop = self.root / "loop.log"
        try:
            loop.symlink_to(loop)
        except OSError:
            self.skipTest("this filesystem refuses symlinks")
        return loop

    def test_symlink_loop_lists_dead_and_tails_missing_200(self):
        loop = self._loop()
        with self._with_sources([
            {"id": "loop", "name": "Loop", "path": str(loop)},
        ]):
            listing = self.client.get("/api/logs")
            tail = self.client.get("/api/logs/loop")
        self.assertEqual(listing.status_code, 200)
        row = listing.json()["sources"][0]
        self.assertFalse(row["exists"])
        # The reproduced leftover: resolve()'s RuntimeError("Symlink loop")
        # answered the coded 500 logs.read_failed with no read attempted.
        self.assertEqual(tail.status_code, 200)
        body = tail.json()
        self.assertFalse(body["exists"])
        self.assertEqual(body["log"], "(file does not exist)")
        self.assertEqual(body["lines"], 0)
        _starlette(body)

    def test_symlink_loop_sibling_still_tails(self):
        loop = self._loop()
        with self._with_sources([
            {"id": "loop", "name": "Loop", "path": str(loop)},
            {"id": "ok", "name": "OK", "path": str(self.log_path)},
        ]):
            tail = self.client.get("/api/logs/ok")
        self.assertEqual(tail.status_code, 200)
        self.assertIn("beta", tail.json()["log"])


class NonRegularSwapRaceTests(LogsAppSandbox):
    """Passed the is_file gate, then the node changed under the open: the
    disk confirm decides, exactly like the rotation (unlink) race."""

    def _tail_with_swap(self, swap) -> "object":
        """GET the tail while *swap* replaces the file just before the read."""
        real_tail = logs_svc.tail_file_lines

        def swap_then_tail(path, n):
            swap()
            return real_tail(path, n)

        with self._with_sources([
            {"id": "race", "name": "Race", "path": str(self.log_path)},
        ]):
            with mock.patch.object(
                logs_svc, "tail_file_lines", swap_then_tail,
            ):
                return self.client.get("/api/logs/race")

    def test_fifo_swapped_in_answers_missing_200_without_hanging(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("mkfifo unavailable on this platform")

        def swap():
            self.log_path.unlink()
            os.mkfifo(self.log_path)

        # The real tail_file_lines runs against the FIFO: O_NONBLOCK keeps
        # the open from parking on a writer-less pipe, and its EINVAL
        # ("not a regular file") is the OSError under test.
        resp = self._tail_with_swap(swap)
        # The reproduced leftover: this was the coded 500 logs.read_failed.
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertFalse(body["exists"])
        self.assertEqual(body["log"], "(file does not exist)")
        self.assertEqual(body["lines"], 0)
        _starlette(body)

    def test_directory_swapped_in_answers_missing_200(self):
        def swap():
            self.log_path.unlink()
            self.log_path.mkdir()

        resp = self._tail_with_swap(swap)
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.json()["exists"])

    def test_socket_swapped_in_answers_missing_200(self):
        holder = socket.socket(socket.AF_UNIX)
        self.addCleanup(holder.close)

        def swap():
            self.log_path.unlink()
            try:
                holder.bind(str(self.log_path))
            except OSError:
                self.skipTest("cannot bind a unix socket here")

        resp = self._tail_with_swap(swap)
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.json()["exists"])

    def test_symlink_swap_to_a_real_file_keeps_read_failed(self):
        """O_NOFOLLOW refusing a swapped symlink is a security refusal: the
        probe still sees a regular file (through the link), so the
        downgrade must NOT turn the refusal into a quiet missing-200."""
        with self._with_sources([
            {"id": "race", "name": "Race", "path": str(self.log_path)},
        ]):
            with mock.patch.object(
                logs_svc, "tail_file_lines",
                side_effect=OSError(
                    errno.ELOOP, "Too many levels of symbolic links",
                    str(self.log_path)),
            ):
                resp = self.client.get("/api/logs/race")
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(resp.json()["detail"]["code"], "logs.read_failed")
        self.assertTrue(self.log_path.is_file())

    def test_eacces_with_the_file_still_on_disk_keeps_read_failed(self):
        """The widened OSError handler is confirm-gated: a permission error
        on a file the probe still sees is a real read failure."""
        with self._with_sources([
            {"id": "race", "name": "Race", "path": str(self.log_path)},
        ]):
            with mock.patch.object(
                logs_svc, "tail_file_lines",
                side_effect=PermissionError(
                    errno.EACCES, "Permission denied", str(self.log_path)),
            ):
                resp = self.client.get("/api/logs/race")
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(resp.json()["detail"]["code"], "logs.read_failed")


class RealYamlStaysImmuneTests(LogsAppSandbox):
    """Vectors probed through the real services.yaml loader (not a mocked
    cfg) and found already guarded — pinned so."""

    def test_yaml_escaped_surrogate_path_lists_dead_and_tails_missing(self):
        """A hand-edited double-quoted ``"\\ud800"`` escape survives the
        real loader as a lone surrogate.  os.stat on such a path is
        UnicodeEncodeError — a ValueError, not OSError — and both routes
        must answer coded/renderable, never a raw 500."""
        self._write_yaml_sources(
            'log_sources:\n'
            '  - {id: sur, name: Sur, path: "'
            + str(self.root) + '/x-\\ud800.log"}\n'
        )
        listing = self.client.get("/api/logs")
        tail = self.client.get("/api/logs/sur")
        self.assertEqual(listing.status_code, 200)
        row = listing.json()["sources"][0]
        self.assertFalse(row["exists"])
        self.assertEqual(tail.status_code, 200)
        self.assertEqual(tail.json()["log"], "(file does not exist)")
        _starlette(listing.json())
        _starlette(tail.json())

    def test_yaml_escaped_surrogate_id_round_trips_through_the_route(self):
        """Every id the listing publishes must be tailable: the scrubbed
        text of ``"s\\ud800id"`` is what the panel hands back."""
        self._write_yaml_sources(
            'log_sources:\n'
            '  - {id: "s\\ud800id", name: S, path: "'
            + str(self.log_path) + '"}\n'
        )
        listing = self.client.get("/api/logs")
        self.assertEqual(listing.status_code, 200)
        published = listing.json()["sources"][0]["id"]
        self.assertNotIn("\ud800", published)
        tail = self.client.get(
            "/api/logs/" + urllib.parse.quote(published))
        self.assertEqual(tail.status_code, 200)
        self.assertIn("alpha", tail.json()["log"])
        _starlette(tail.json())

    def test_real_yaml_over_cap_hex_id_drops_only_its_entry(self):
        """``id: 0xfff…`` (5000 hex digits) parses uncapped through the
        real loader; its str() is the digit-cap ValueError.  The listing
        keeps the sibling, and the Settings page surface that publishes
        raw ``log_sources`` (GET /api/settings) stays renderable."""
        self._write_yaml_sources(
            "log_sources:\n"
            f"  - {{id: 0x{'f' * 5000}, name: H, path: \"{self.log_path}\"}}\n"
            f'  - {{id: ok, name: OK, path: "{self.log_path}"}}\n'
        )
        listing = self.client.get("/api/logs")
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(
            [r["id"] for r in listing.json()["sources"]], ["ok"])
        tail = self.client.get("/api/logs/ok")
        self.assertEqual(tail.status_code, 200)
        settings = self.client.get("/api/settings")
        self.assertEqual(settings.status_code, 200)
        _starlette(settings.json())

    def test_oversize_log_tails_capped_not_oom(self):
        big = self.root / "big.log"
        with open(big, "wb") as fh:
            fh.write(b"a" * (300 * 1024))
            fh.write(b"\ntail-line\n")
        self._write_yaml_sources(
            f'log_sources:\n  - {{id: big, name: Big, path: "{big}"}}\n')
        resp = self.client.get("/api/logs/big")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("tail-line", body["log"])
        # 256 KiB read cap: the 300 KiB junk line before the tail line is
        # dropped with the torn prefix, never loaded whole.
        self.assertLessEqual(len(body["log"]), 256 * 1024)
        _starlette(body)

    def test_socket_at_the_path_lists_dead_and_tails_missing(self):
        sock_path = self.root / "s.sock"
        holder = socket.socket(socket.AF_UNIX)
        self.addCleanup(holder.close)
        try:
            holder.bind(str(sock_path))
        except OSError:
            self.skipTest("cannot bind a unix socket here")
        self._write_yaml_sources(
            f'log_sources:\n  - {{id: sk, name: Sock, path: "{sock_path}"}}\n')
        listing = self.client.get("/api/logs")
        tail = self.client.get("/api/logs/sk")
        self.assertFalse(listing.json()["sources"][0]["exists"])
        self.assertEqual(tail.status_code, 200)
        self.assertEqual(tail.json()["log"], "(file does not exist)")

    def test_script_log_fallback_feeds_listed_ids_back_to_tail(self):
        """The Services page script-log fallback pipes ``log_sources`` ids
        straight into ``tail_log``; it must answer 200 with the content."""
        self._write_yaml_sources(
            f'log_sources:\n  - {{id: myscript, name: My Script, path: "{self.log_path}"}}\n'
            'scripts:\n  - {id: myscript, name: My Script, cmd: "true"}\n'
        )
        resp = self.client.get("/api/services/myscript/logs")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("alpha", body.get("log", ""))
        _starlette(body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
