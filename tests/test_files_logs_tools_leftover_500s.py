"""Leftover 500s on logs, files, tools, and the one-shot terminal.

Junk ``lines`` / ``int(inf)``, dying-mount EIO before iterdir, Path.resolve()
RuntimeError on a symlink loop, mutation PermissionError, inf CPU in ``ps``,
and a 0-block root disk each used to escape as an unhandled exception.

Follow-up: rename dest.resolve()/exists(), is_protected on a looping deny-list
root, FileBrowser exists/mkdir/replace, syslog/brew/dig Path EIO, and inf
st_size / loadavg / StartCalendarInterval each used to 500 the JSON encoder.

Follow-up 2: leftover ``sh`` / ``docker`` / ``ps`` None/bytes/int used to
TypeError FileBrowser status, syslog, ping, DNS, ports, brew, diagnostics,
and container sizes (Starlette ``allow_nan=False``).

Follow-up 3: leftover ``\\ud800`` in a filename used to UnicodeEncodeError
GET /api/files/list and GET /api/files/download (``quote(p.name)``).

Follow-up 4: leftover ``\\ud800`` in a LaunchAgent Label / ProgramArguments
used to UnicodeEncodeError GET /api/system/scheduler and GET /api/tools/agents.
"""
from __future__ import annotations

import datetime
import json
import os
import stat
import tempfile
import unittest
from collections import namedtuple
from pathlib import Path
from unittest import mock
from urllib.parse import quote

from fastapi import HTTPException

from hub import files_svc, launchd_cache, logs_svc, proc_cache, secure_io, terminal_svc, tools_svc


def _code(exc: HTTPException) -> str:
    detail = exc.detail
    return detail["code"] if isinstance(detail, dict) else str(detail)


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _symlink_loop(directory: Path) -> Path:
    loop = directory / "loop"
    loop.symlink_to(loop)
    return loop


class LogsTailLeftoverTests(unittest.TestCase):
    def _tail(self, path: Path, lines):
        with mock.patch.object(
            logs_svc,
            "log_sources",
            return_value=[{
                "id": "app", "name": "app", "path": str(path),
                "exists": True, "size": 1,
            }],
        ):
            return logs_svc.tail_log("app", lines)

    def test_junk_lines_is_clamped_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.log"
            path.write_text("one\ntwo\n", encoding="utf-8")
            for junk in (float("inf"), float("nan"), ["50"], "nope", True):
                got = self._tail(path, junk)
                self.assertEqual(got["lines"], 2)
                json.dumps(got, allow_nan=False)

    def test_is_file_eio_is_coded_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.log"
            path.write_text("x\n", encoding="utf-8")
            with mock.patch.object(Path, "is_file", side_effect=OSError(5, "I/O error")):
                with self.assertRaises(HTTPException) as ctx:
                    self._tail(path, 10)
        self.assertEqual(_code(ctx.exception), "logs.read_failed")

    def test_nul_path_is_coded_not_500(self):
        with mock.patch.object(
            logs_svc,
            "log_sources",
            return_value=[{
                "id": "app", "name": "app", "path": "/tmp/foo\x00.log",
                "exists": True, "size": 1,
            }],
        ):
            try:
                got = logs_svc.tail_log("app", 10)
            except HTTPException as exc:
                self.assertEqual(_code(exc), "logs.read_failed")
                return
        self.assertFalse(got["exists"])
        json.dumps(got, allow_nan=False)

    def test_bytes_name_is_json_safe(self):
        # A bytes name decodes to its text (the original panel published it
        # through FastAPI's encoder) instead of silently falling back to the
        # id; the property this pin guards is that the row stays JSON-safe.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.log"
            path.write_text("x\n", encoding="utf-8")
            with mock.patch("hub.logs_svc.cfg", return_value={
                "log_sources": [{"id": "app", "name": b"bytes", "path": str(path)}],
            }):
                rows = logs_svc.log_sources()
        self.assertEqual(rows[0]["name"], "bytes")
        json.dumps(rows, allow_nan=False)

    def test_home_runtimeerror_does_not_500_default_sources(self):
        """``Path.home()`` RuntimeError used to 500 GET /api/logs with empty sources."""
        with (
            mock.patch("hub.logs_svc.cfg", return_value={}),
            mock.patch.object(Path, "home", side_effect=RuntimeError("HOME")),
        ):
            rows = logs_svc.log_sources()
        self.assertEqual(rows, [])
        _starlette(rows)

    def test_expanduser_runtimeerror_does_not_500_configured_sources(self):
        """``os.path.expanduser`` RuntimeError used to 500 GET /api/logs."""
        with (
            mock.patch("hub.logs_svc.cfg", return_value={
                "log_sources": [{"id": "app", "name": "app", "path": "~/app.log"}],
            }),
            mock.patch.object(logs_svc.os.path, "expanduser", side_effect=RuntimeError("no home")),
        ):
            rows = logs_svc.log_sources()
        self.assertEqual(rows, [])
        _starlette(rows)


class FilesResolveLoopTests(unittest.TestCase):
    def test_looping_path_is_coded_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            loop = _symlink_loop(parent)
            with mock.patch.object(
                files_svc, "default_roots",
                return_value=[{"id": "tmp", "name": "tmp", "path": str(parent)}],
            ):
                with self.assertRaises(HTTPException) as ctx:
                    files_svc._resolve_safe(str(loop), "tmp")
                self.assertEqual(_code(ctx.exception), "files.not_found")
                with self.assertRaises(HTTPException) as ctx:
                    files_svc.list_dir(str(loop), "tmp")
                self.assertEqual(_code(ctx.exception), "files.not_found")

    def test_looping_custom_root_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            loop = _symlink_loop(Path(tmp))
            with mock.patch.object(
                files_svc, "_settings", return_value={"roots": [str(loop)]},
            ):
                self.assertEqual(files_svc.default_roots(), [])


class FilesDyingMountTests(unittest.TestCase):
    def test_exists_eio_is_coded_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            target = parent / "dying"
            target.mkdir()
            with (
                mock.patch.object(
                    files_svc, "default_roots",
                    return_value=[{"id": "tmp", "name": "tmp", "path": str(parent)}],
                ),
                mock.patch.object(Path, "exists", side_effect=OSError(5, "I/O error")),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    files_svc.list_dir(str(target), "tmp")
        self.assertEqual(_code(ctx.exception), "files.permission_denied")

    def test_default_roots_is_dir_eio_does_not_500(self):
        with mock.patch.object(
            files_svc, "_settings",
            return_value={"roots": [str(Path.home() / "Downloads")]},
        ), mock.patch.object(Path, "is_dir", side_effect=OSError(5, "I/O error")):
            self.assertEqual(files_svc.default_roots(), [])

    def test_corrupt_mtime_does_not_500_a_listing_row(self):
        class _St:
            st_size = 1
            st_mode = 0o100644
            st_mtime = float("nan")

        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            path = parent / "f"
            path.write_text("x", encoding="utf-8")
            with mock.patch.object(Path, "lstat", return_value=_St()):
                row = files_svc._entry(path, parent)
        self.assertEqual(row["mtime"], 0)
        json.dumps(row, allow_nan=False)

    def test_infinite_mtime_does_not_500_a_listing_row(self):
        class _St:
            st_size = 1
            st_mode = 0o100644
            st_mtime = float("inf")

        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            path = parent / "f"
            path.write_text("x", encoding="utf-8")
            with mock.patch.object(Path, "lstat", return_value=_St()):
                row = files_svc._entry(path, parent)
        self.assertEqual(row["mtime"], 0)
        json.dumps(row, allow_nan=False)


class FilesSurrogateFilenameTests(unittest.TestCase):
    def test_leftover_surrogate_filename_does_not_500_listing(self):
        """FUSE/SMB leftover ``\\ud800`` in a name used to 500 GET /api/files/list."""

        class _P:
            name = "ok\ud800name"
            suffix = ".txt"

            def lstat(self):
                return os.stat_result((0o100644, 1, 1, 1, 0, 0, 1, 0, 0, 0))

            def is_symlink(self):
                return False

            def is_dir(self):
                return False

            def is_file(self):
                return True

            def relative_to(self, root):
                return Path("ok")

            def __str__(self):
                return "/tmp/ok\ud800name"

        row = files_svc._entry(_P(), Path("/tmp"))
        self.assertNotIn("\ud800", row["name"])
        self.assertNotIn("\ud800", row["path"])
        _starlette(row)

    def test_leftover_surrogate_filename_does_not_500_download_header(self):
        """``urllib.parse.quote`` UnicodeEncodeError used to 500 GET /api/files/download."""
        quoted = quote(files_svc._as_text("ok\ud800name"))
        self.assertNotIn("\ud800", quoted)
        json.dumps({"filename": quoted}, ensure_ascii=False).encode("utf-8")

    def test_recursing_filename_does_not_500_as_text(self):
        """leftover ``str()`` RecursionError used to 500 GET /api/files/list."""
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        text = files_svc._as_text(Recursing())
        self.assertEqual(text, "Recursing")
        _starlette({"name": text})

    def test_recursing_fold_does_not_500_protected(self):
        """leftover ``str()`` RecursionError used to 500 GET /api/files/list is_protected."""
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(files_svc._fold(Recursing()), "")

    def test_leftover_surrogate_lstat_does_not_500_a_listing_row(self):
        """``Path.lstat`` UnicodeEncodeError used to 500 GET /api/files/list.

        pathlib exists/is_dir swallow a leftover ``\\ud800`` name; lstat does not.
        """
        row = files_svc._entry(Path("/tmp/ok\ud800name"), Path("/tmp"))
        self.assertNotIn("\ud800", row["name"])
        self.assertIn("error", row)
        _starlette(row)

    def test_leftover_surrogate_name_is_bad_name_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            with mock.patch.object(
                files_svc, "default_roots",
                return_value=[{"id": "tmp", "name": "tmp", "path": str(parent)}],
            ):
                with self.assertRaises(HTTPException) as ctx:
                    files_svc.mkdir(str(parent), "ok\ud800name", "tmp")
        self.assertEqual(_code(ctx.exception), "files.bad_name")


class FilesMutationOsErrorTests(unittest.TestCase):
    def test_mkdir_permission_error_is_coded_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            with (
                mock.patch.object(
                    files_svc, "default_roots",
                    return_value=[{"id": "tmp", "name": "tmp", "path": str(parent)}],
                ),
                mock.patch.object(Path, "mkdir", side_effect=PermissionError(13, "denied")),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    files_svc.mkdir(str(parent), "new", "tmp")
        self.assertEqual(_code(ctx.exception), "files.permission_denied")

    def test_delete_permission_error_is_coded_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            target = parent / "x"
            target.write_text("x", encoding="utf-8")
            with (
                mock.patch.object(
                    files_svc, "default_roots",
                    return_value=[{"id": "tmp", "name": "tmp", "path": str(parent)}],
                ),
                mock.patch.object(Path, "unlink", side_effect=PermissionError(13, "denied")),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    files_svc.delete_path(str(target), "tmp")
        self.assertEqual(_code(ctx.exception), "files.permission_denied")

    def test_rename_eacces_is_coded_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            src = parent / "old"
            src.write_text("x", encoding="utf-8")
            with (
                mock.patch.object(
                    files_svc, "default_roots",
                    return_value=[{"id": "tmp", "name": "tmp", "path": str(parent)}],
                ),
                mock.patch.object(
                    files_svc.os, "link",
                    side_effect=OSError(13, "denied"),
                ),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    files_svc.rename_path(str(src), "new", "tmp")
        self.assertEqual(_code(ctx.exception), "files.permission_denied")

    def test_download_eacces_is_coded_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            path = parent / "a.txt"
            path.write_text("x", encoding="utf-8")
            with (
                mock.patch.object(
                    files_svc, "default_roots",
                    return_value=[{"id": "tmp", "name": "tmp", "path": str(parent)}],
                ),
                mock.patch.object(
                    files_svc.os, "open",
                    side_effect=OSError(13, "denied"),
                ),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    files_svc.download(str(path), "tmp")
        self.assertEqual(_code(ctx.exception), "files.permission_denied")

    def test_download_fstat_eio_is_coded_not_500(self):
        """Dying-mount ``fstat`` EIO after open used to 500 GET /api/files/download."""
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            path = parent / "a.txt"
            path.write_text("x", encoding="utf-8")
            with (
                mock.patch.object(
                    files_svc, "default_roots",
                    return_value=[{"id": "tmp", "name": "tmp", "path": str(parent)}],
                ),
                mock.patch.object(
                    files_svc.os, "fstat",
                    side_effect=OSError(5, "I/O error"),
                ),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    files_svc.download(str(path), "tmp")
        self.assertEqual(_code(ctx.exception), "files.permission_denied")

    def test_download_infinite_st_size_does_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            path = parent / "a.txt"
            path.write_text("x", encoding="utf-8")
            real_fstat = os.fstat

            def fake_fstat(fd):
                st = real_fstat(fd)
                return mock.Mock(
                    st_mode=st.st_mode, st_size=float("inf"),
                )

            with (
                mock.patch.object(
                    files_svc, "default_roots",
                    return_value=[{"id": "tmp", "name": "tmp", "path": str(parent)}],
                ),
                mock.patch.object(files_svc.os, "fstat", fake_fstat),
            ):
                resp = files_svc.download(str(path), "tmp")
        self.assertEqual(resp.headers["Content-Length"], "0")

    def test_list_name_is_bad_name_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            with mock.patch.object(
                files_svc, "default_roots",
                return_value=[{"id": "tmp", "name": "tmp", "path": str(parent)}],
            ):
                with self.assertRaises(HTTPException) as ctx:
                    files_svc.mkdir(str(parent), ["new"], "tmp")
        self.assertEqual(_code(ctx.exception), "files.bad_name")

    def test_infinite_upload_cap_does_not_500(self):
        import asyncio

        class _File:
            filename = "a.bin"

            async def read(self, n=-1):
                return b""

            async def close(self):
                pass

        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            with (
                mock.patch.object(
                    files_svc, "default_roots",
                    return_value=[{"id": "tmp", "name": "tmp", "path": str(parent)}],
                ),
                mock.patch.object(
                    files_svc, "_settings",
                    return_value={"max_upload_mb": float("inf")},
                ),
            ):
                out = asyncio.run(files_svc.upload(str(parent), _File(), "tmp"))
        self.assertTrue(out["ok"])
        json.dumps(out, allow_nan=False)


class ToolsLeftover500Tests(unittest.TestCase):
    def tearDown(self):
        tools_svc._proc_cache.update(t=0.0, v=None, limit=0)

    def test_infinite_cpu_does_not_500_json(self):
        with mock.patch.object(
            tools_svc, "ps_lines",
            return_value=["HDR", "u 1 inf 1.0 0 0 x S 0 0 cmd", "u 2 1.0 nan 0 0 x S 0 0 cmd"],
        ):
            tools_svc._proc_cache.update(t=0.0, v=None, limit=0)
            rows = tools_svc.top_processes(5)
        self.assertEqual(rows, [])
        json.dumps(rows, allow_nan=False)

    def test_zero_block_root_disk_does_not_500(self):
        du = namedtuple("DU", "total used free")(0, 0, 0)
        with (
            mock.patch.object(tools_svc.shutil, "disk_usage", return_value=du),
            mock.patch.object(
                tools_svc, "fan_out",
                return_value=("h", "m", 1, 1.0, 1, (False, {}), "p", ""),
            ),
            mock.patch.object(tools_svc.os, "getloadavg", return_value=(0.0, 0.0, 0.0)),
            mock.patch.object(tools_svc.metrics, "history", return_value=[]),
        ):
            snap = tools_svc.diagnostics()
        self.assertEqual(snap["root_disk_pct"], 0.0)
        json.dumps(snap, allow_nan=False)

    def test_huge_memsize_does_not_500_diagnostics(self):
        """``int('9'*400) / 2**30`` OverflowError'd GET /api/diagnostics."""
        du = namedtuple("DU", "total used free")(1, 0, 1)

        def fake_sh(argv, **kw):
            if "hw.memsize" in argv:
                return 0, "9" * 400, ""
            if "hw.ncpu" in argv:
                return 0, "8", ""
            return 0, "x", ""

        with (
            mock.patch.object(tools_svc, "_sh", fake_sh),
            mock.patch.object(tools_svc.shutil, "disk_usage", return_value=du),
            mock.patch.object(tools_svc, "engine_up", return_value=False),
            mock.patch.object(tools_svc.os, "getloadavg", return_value=(0.1, 0.1, 0.1)),
            mock.patch.object(tools_svc.metrics, "history", return_value=[]),
        ):
            snap = tools_svc.diagnostics()
        json.dumps(snap, allow_nan=False)
        self.assertIsNone(snap["mem_gb"])
        self.assertEqual(snap["ncpu"], 8)

    def test_infinite_clock_does_not_500_diagnostics_uptime(self):
        """int(time.time()) OverflowError on leftover inf used to 500 GET /api/diagnostics."""
        du = namedtuple("DU", "total used free")(1, 0, 1)

        def fake_sh(argv, **kw):
            if "kern.boottime" in argv:
                return 0, "{ sec = 1000, usec = 0 }", ""
            if "hw.ncpu" in argv:
                return 0, "8", ""
            if "hw.memsize" in argv:
                return 0, "8", ""
            return 0, "x", ""

        with (
            mock.patch.object(tools_svc, "_sh", fake_sh),
            mock.patch.object(tools_svc.time, "time", return_value=float("inf")),
            mock.patch.object(tools_svc.shutil, "disk_usage", return_value=du),
            mock.patch.object(tools_svc, "engine_up", return_value=False),
            mock.patch.object(tools_svc.os, "getloadavg", return_value=(0.1, 0.1, 0.1)),
            mock.patch.object(tools_svc.metrics, "history", return_value=[]),
        ):
            snap = tools_svc.diagnostics()
        json.dumps(snap, allow_nan=False)
        self.assertIsNone(snap["uptime_sec"])

    def test_huge_root_disk_does_not_500_diagnostics(self):
        du = namedtuple("DU", "total used free")(10 ** 400, 10 ** 400, 10 ** 400)
        with (
            mock.patch.object(tools_svc.shutil, "disk_usage", return_value=du),
            mock.patch.object(
                tools_svc, "fan_out",
                return_value=("h", "m", 8, 16.0, 1, (False, {}), "p", ""),
            ),
            mock.patch.object(tools_svc.os, "getloadavg", return_value=(0.0, 0.0, 0.0)),
            mock.patch.object(tools_svc.metrics, "history", return_value=[]),
        ):
            snap = tools_svc.diagnostics()
        json.dumps(snap, allow_nan=False)
        self.assertEqual(snap["root_disk_pct"], 0.0)
        self.assertEqual(snap["root_disk_free_gb"], 0.0)

    def test_hostname_fallback_surrogate_does_not_500_diagnostics(self):
        """``platform.node()`` leftover ``\\ud800`` used to 500 GET /api/diagnostics."""
        du = namedtuple("DU", "total used free")(1, 0, 1)

        def fake_sh(argv, **kw):
            if argv and argv[0].endswith("hostname"):
                return 1, "", "fail"
            if "hw.ncpu" in argv:
                return 0, "8", ""
            if "hw.memsize" in argv:
                return 0, "8", ""
            return 0, "x", ""

        with (
            mock.patch.object(tools_svc, "_sh", fake_sh),
            mock.patch.object(tools_svc.platform, "node", return_value="box\ud800"),
            mock.patch.object(tools_svc.platform, "machine", return_value="arm\ud800"),
            mock.patch.object(tools_svc.platform, "python_version", return_value="3\ud800"),
            mock.patch.object(tools_svc.shutil, "disk_usage", return_value=du),
            mock.patch.object(tools_svc, "engine_up", return_value=False),
            mock.patch.object(tools_svc.os, "getloadavg", return_value=(0.1, 0.1, 0.1)),
            mock.patch.object(tools_svc.metrics, "history", return_value=[]),
        ):
            snap = tools_svc.diagnostics()
        json.dumps(snap, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertNotIn("\ud800", snap["hostname"])
        self.assertNotIn("\ud800", snap["arch"])
        self.assertNotIn("\ud800", snap["python"])

    def test_infinite_uptime_does_not_500(self):
        self.assertEqual(tools_svc._fmt_uptime(float("inf")), "—")

    def test_syslog_infinite_minutes_is_clamped_not_500(self):
        with mock.patch.object(
            tools_svc, "_syslog_tail_uncached",
            return_value={"ok": True, "minutes": 60, "level": "error", "count": 0, "lines": []},
        ) as uncached:
            tools_svc._syslog_cache.clear()
            out = tools_svc.syslog_tail(minutes=float("inf"), limit=float("inf"), force=True)
        self.assertEqual(uncached.call_args.args[0], 60)
        self.assertEqual(uncached.call_args.args[1], 80)
        json.dumps(out, allow_nan=False)

    def test_net_ping_infinite_count_is_clamped_not_500(self):
        with mock.patch.object(tools_svc, "sh", return_value=(0, "ok", "")):
            out = tools_svc.net_ping("example.com", float("inf"))
        self.assertEqual(out["count"], 3)
        json.dumps(out, allow_nan=False)

    def test_docker_prune_list_what_is_coded_not_500(self):
        with mock.patch.object(tools_svc, "engine_up", return_value=True):
            out = tools_svc.docker_prune(["dangling"], True)
        self.assertFalse(out["ok"])
        self.assertEqual(out["code"], "tools.bad_prune")
        json.dumps(out, allow_nan=False)

    def test_net_dns_list_name_is_coded_not_500(self):
        out = tools_svc.net_dns_lookup(["example.com"])
        self.assertFalse(out["ok"])
        self.assertEqual(out["code"], "tools.empty_name")
        json.dumps(out, allow_nan=False)

    def test_launchd_glob_eio_does_not_500(self):
        with mock.patch.object(tools_svc.glob, "glob", side_effect=OSError(5, "I/O")):
            self.assertEqual(tools_svc.launchd_timers(), [])
        with mock.patch.object(Path, "glob", side_effect=OSError(5, "I/O")):
            out = tools_svc.launchd_agents_summary()
        self.assertEqual(out["agents"], [])
        json.dumps(out, allow_nan=False)

    def test_launchd_expanduser_runtimeerror_does_not_500(self):
        """``expanduser`` RuntimeError used to 500 GET /api/tools launchd views."""
        with mock.patch.object(
            tools_svc.os.path, "expanduser", side_effect=RuntimeError("no home"),
        ):
            timers = tools_svc.launchd_timers()
            summary = tools_svc.launchd_agents_summary()
        self.assertEqual(timers, [])
        self.assertEqual(summary["agents"], [])
        json.dumps(timers, allow_nan=False)
        json.dumps(summary, allow_nan=False)

    def test_leftover_surrogate_label_does_not_500_launchd_views(self):
        """Leftover ``\\ud800`` in a LaunchAgent Label used to 500 GET /api/system/scheduler."""
        import plistlib

        leftover = {
            "Label": "job\ud800",
            "StartInterval": 60,
            "ProgramArguments": ["true\ud800"],
        }
        with tempfile.TemporaryDirectory() as tmp:
            agents = Path(tmp)
            (agents / "x.plist").write_bytes(plistlib.dumps({
                "Label": "job",
                "StartInterval": 60,
                "ProgramArguments": ["true"],
            }))
            with (
                mock.patch.object(tools_svc.os.path, "expanduser", return_value=str(agents)),
                mock.patch.object(
                    tools_svc.glob, "glob", return_value=[str(agents / "x.plist")],
                ),
                mock.patch.object(plistlib, "loads", return_value=leftover),
            ):
                timers = tools_svc.launchd_timers()
                summary = tools_svc.launchd_agents_summary()
        self.assertEqual(len(timers), 1)
        self.assertNotIn("\ud800", timers[0]["label"])
        self.assertNotIn("\ud800", timers[0]["program"])
        self.assertNotIn("\ud800", summary["agents"][0]["label"])
        self.assertNotIn("\ud800", summary["agents"][0]["program"])
        _starlette(timers)
        _starlette(summary)

    def test_infinite_startinterval_does_not_500(self):
        import plistlib

        with tempfile.TemporaryDirectory() as tmp:
            agents = Path(tmp)
            (agents / "x.plist").write_bytes(plistlib.dumps({
                "Label": "x",
                "StartInterval": float("inf"),
                "ProgramArguments": ["true"],
            }))
            with (
                mock.patch.object(tools_svc.os.path, "expanduser", return_value=str(agents)),
                mock.patch.object(
                    tools_svc.glob, "glob", return_value=[str(agents / "x.plist")],
                ),
            ):
                items = tools_svc.launchd_timers()
        self.assertEqual(items, [])
        json.dumps(items, allow_nan=False)

    def test_huge_plist_does_not_oom_launchd_views(self):
        """``open(rb)`` of leftover multi-MB LaunchAgent used to OOM GET /api/tools."""
        import plistlib

        with tempfile.TemporaryDirectory() as tmp:
            agents = Path(tmp)
            (agents / "huge.plist").write_bytes(b"x" * (2 * 1024 * 1024))
            (agents / "ok.plist").write_bytes(plistlib.dumps({
                "Label": "ok",
                "StartInterval": 60,
                "ProgramArguments": ["true"],
            }))
            with (
                mock.patch.object(tools_svc.os.path, "expanduser", return_value=str(agents)),
                mock.patch.object(
                    tools_svc.glob, "glob",
                    return_value=[str(agents / "huge.plist"), str(agents / "ok.plist")],
                ),
            ):
                timers = tools_svc.launchd_timers()
                summary = tools_svc.launchd_agents_summary()
        json.dumps(timers, allow_nan=False)
        json.dumps(summary, allow_nan=False)
        self.assertEqual(len(timers), 1)
        self.assertEqual(timers[0]["label"], "ok")
        labels = {row["label"] for row in summary["agents"]}
        self.assertIn("ok", labels)
        self.assertIn("huge", labels)


class FilesRenameDestResolveTests(unittest.TestCase):
    def test_looping_dest_name_is_coded_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            src = parent / "old"
            src.write_text("x", encoding="utf-8")
            loop = parent / "loop"
            loop.symlink_to(loop)
            with mock.patch.object(
                files_svc, "default_roots",
                return_value=[{"id": "tmp", "name": "tmp", "path": str(parent)}],
            ):
                with self.assertRaises(HTTPException) as ctx:
                    files_svc.rename_path(str(src), "loop", "tmp")
        self.assertEqual(_code(ctx.exception), "files.bad_name")

    def test_dest_exists_eio_is_coded_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            src = parent / "old"
            src.write_text("x", encoding="utf-8")
            real_exists = Path.exists

            def exists_boom(self):
                if self.name == "new":
                    raise OSError(5, "I/O error")
                return real_exists(self)

            with (
                mock.patch.object(
                    files_svc, "default_roots",
                    return_value=[{"id": "tmp", "name": "tmp", "path": str(parent)}],
                ),
                mock.patch.object(Path, "exists", exists_boom),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    files_svc.rename_path(str(src), "new", "tmp")
        self.assertEqual(_code(ctx.exception), "files.permission_denied")


class FilesProtectedDirLoopTests(unittest.TestCase):
    def test_looping_deny_list_root_does_not_500_a_listing(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            (parent / "x").write_text("hi", encoding="utf-8")
            loop = _symlink_loop(parent)
            with (
                mock.patch.object(
                    files_svc, "default_roots",
                    return_value=[{"id": "tmp", "name": "tmp", "path": str(parent)}],
                ),
                mock.patch.object(files_svc, "PROTECTED_DIRS", (loop,)),
            ):
                out = files_svc.list_dir(str(parent), "tmp")
        self.assertGreaterEqual(out["count"], 1)
        json.dumps(out, allow_nan=False)

    def test_looping_deny_list_root_does_not_500_log_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.log"
            path.write_text("x\n", encoding="utf-8")
            loop = _symlink_loop(Path(tmp))
            with (
                mock.patch("hub.logs_svc.cfg", return_value={
                    "log_sources": [{"id": "app", "name": "app", "path": str(path)}],
                }),
                mock.patch.object(files_svc, "PROTECTED_DIRS", (loop,)),
            ):
                rows = logs_svc.log_sources()
        self.assertEqual(rows[0]["id"], "app")
        json.dumps(rows, allow_nan=False)


class FilesFilebrowserLeftoverTests(unittest.TestCase):
    def test_exists_eio_does_not_500_status(self):
        with mock.patch.object(Path, "exists", side_effect=OSError(5, "I/O error")):
            st = files_svc.filebrowser_status()
        self.assertFalse(st["installed"])
        json.dumps(st, allow_nan=False)

    def test_launchctl_bytes_none_int_do_not_500_status(self):
        running = b"state = running\n    pid = 42\n"
        for out in (running, None, 12, b""):
            with mock.patch.object(files_svc, "sh", return_value=(0, out, "")):
                st = files_svc.filebrowser_status()
            json.dumps(st, allow_nan=False)
        with mock.patch.object(files_svc, "sh", return_value=(0, running, "")):
            st = files_svc.filebrowser_status()
        self.assertTrue(st["running"])
        self.assertEqual(st["pid"], 42)

    def test_pgrep_none_does_not_500_status(self):
        def fake_sh(cmd, **kwargs):
            if cmd and cmd[0].endswith("pgrep"):
                return (0, None, "")
            return (1, "", "")

        with mock.patch.object(files_svc, "sh", side_effect=fake_sh):
            st = files_svc.filebrowser_status()
            ov = files_svc.overview()
        json.dumps(st, allow_nan=False)
        json.dumps(ov, allow_nan=False)

    def test_mkdir_permission_error_is_coded_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            bin_path = Path(tmp) / "filebrowser-bin"
            bin_path.write_text("x", encoding="utf-8")
            with (
                mock.patch.object(
                    files_svc, "filebrowser_status",
                    return_value={"running": False},
                ),
                mock.patch.object(files_svc, "FB_BIN", bin_path),
                mock.patch.object(files_svc, "FB_PLIST", Path(tmp) / "missing.plist"),
                mock.patch.object(files_svc, "FB_ROOT_DEFAULT", Path(tmp) / "root"),
                mock.patch.object(files_svc, "SERVICES_ROOT", Path(tmp)),
                mock.patch.object(
                    Path, "mkdir", side_effect=PermissionError(13, "denied"),
                ),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    files_svc.ensure_filebrowser()
        self.assertEqual(_code(ctx.exception), "files.fb_start_failed")

    def test_filebrowser_popen_valueerror_is_coded_not_500(self):
        """Leftover ``\\ud800`` env UnicodeEncodeError is ValueError, not OSError."""
        with tempfile.TemporaryDirectory() as tmp:
            bin_path = Path(tmp) / "filebrowser-bin"
            bin_path.write_text("x", encoding="utf-8")
            with (
                mock.patch.object(
                    files_svc, "filebrowser_status",
                    return_value={"running": False},
                ),
                mock.patch.object(files_svc, "FB_BIN", bin_path),
                mock.patch.object(files_svc, "FB_PLIST", Path(tmp) / "missing.plist"),
                mock.patch.object(files_svc, "FB_ROOT_DEFAULT", Path(tmp) / "root"),
                mock.patch.object(files_svc, "SERVICES_ROOT", Path(tmp)),
                mock.patch.object(files_svc, "FB_LOG", Path(tmp) / "fb.log"),
                mock.patch.object(
                    files_svc.subprocess, "Popen",
                    side_effect=UnicodeEncodeError(
                        "utf-8", "\ud800", 0, 1, "surrogates not allowed",
                    ),
                ),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    files_svc.ensure_filebrowser()
        self.assertEqual(_code(ctx.exception), "files.fb_start_failed")

    def test_filebrowser_popen_drops_leftover_surrogate_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            bin_path = Path(tmp) / "filebrowser-bin"
            bin_path.write_text("x", encoding="utf-8")
            proc = type("P", (), {"pid": 7})()
            leftover = {"PATH": "/bin", "BAD": "x\ud800"}
            status = {"running": False}

            def _status():
                return dict(status)

            with (
                mock.patch.object(files_svc, "filebrowser_status", side_effect=_status),
                mock.patch.object(files_svc, "FB_BIN", bin_path),
                mock.patch.object(files_svc, "FB_PLIST", Path(tmp) / "missing.plist"),
                mock.patch.object(files_svc, "FB_ROOT_DEFAULT", Path(tmp) / "root"),
                mock.patch.object(files_svc, "SERVICES_ROOT", Path(tmp)),
                mock.patch.object(files_svc, "FB_LOG", Path(tmp) / "fb.log"),
                mock.patch.object(files_svc.os, "environ", leftover),
                mock.patch.object(files_svc.time, "sleep"),
                mock.patch.object(files_svc.subprocess, "Popen", return_value=proc) as popen,
            ):
                status["running"] = False
                # After spawn, the wait loop sees it up.
                def _after(*_a, **_k):
                    status["running"] = True
                    return proc
                popen.side_effect = _after
                out = files_svc.ensure_filebrowser()
            env = popen.call_args.kwargs.get("env") or {}
            self.assertNotIn("BAD", env)
            self.assertTrue(out["ok"])
            json.dumps(out, allow_nan=False)

    def test_ondemand_replace_oserror_is_coded_not_500(self):
        import plistlib

        with tempfile.TemporaryDirectory() as tmp:
            plist = Path(tmp) / "fb.plist"
            plist.write_bytes(plistlib.dumps({
                "Label": "local.filebrowser",
                "RunAtLoad": True,
                "KeepAlive": True,
            }))
            with (
                mock.patch.object(files_svc, "FB_PLIST", plist),
                mock.patch.object(
                    secure_io, "replace_bytes",
                    side_effect=OSError(13, "denied"),
                ),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    files_svc.set_filebrowser_ondemand(True)
        self.assertEqual(_code(ctx.exception), "files.permission_denied")

    def test_huge_plist_does_not_oom_status(self):
        """``open(rb)`` of leftover multi-MB FileBrowser plist used to OOM GET /api/files."""
        with tempfile.TemporaryDirectory() as tmp:
            plist = Path(tmp) / "fb.plist"
            plist.write_bytes(b"x" * (2 * 1024 * 1024))
            with mock.patch.object(files_svc, "FB_PLIST", plist):
                st = files_svc.filebrowser_status()
            json.dumps(st, allow_nan=False)
            self.assertIsNone(st["keepalive"])

    def test_huge_plist_ondemand_is_coded_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            plist = Path(tmp) / "fb.plist"
            plist.write_bytes(b"x" * (2 * 1024 * 1024))
            with mock.patch.object(files_svc, "FB_PLIST", plist):
                with self.assertRaises(HTTPException) as ctx:
                    files_svc.set_filebrowser_ondemand(True)
        self.assertEqual(_code(ctx.exception), "files.fb_bad_plist")

    def test_nested_plist_ondemand_is_coded_not_500(self):
        """plistlib RecursionError is not ValueError; on-demand used to 500."""
        import plistlib

        with tempfile.TemporaryDirectory() as tmp:
            plist = Path(tmp) / "fb.plist"
            plist.write_bytes(plistlib.dumps({"Label": "local.filebrowser"}))
            with (
                mock.patch.object(files_svc, "FB_PLIST", plist),
                mock.patch("plistlib.loads", side_effect=RecursionError),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    files_svc.set_filebrowser_ondemand(True)
        self.assertEqual(_code(ctx.exception), "files.fb_bad_plist")


class FilesLogsToolsJsonInfTests(unittest.TestCase):
    def test_infinite_size_does_not_500_a_listing_row(self):
        class _St:
            st_size = float("inf")
            st_mode = 0o100644
            st_mtime = 1.0

        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            path = parent / "f"
            path.write_text("x", encoding="utf-8")
            with mock.patch.object(Path, "lstat", return_value=_St()):
                row = files_svc._entry(path, parent)
        self.assertEqual(row["size"], 0)
        json.dumps(row, allow_nan=False)

    def test_corrupt_mode_does_not_500_a_listing_row(self):
        class _St:
            st_size = 1
            st_mode = None
            st_mtime = 1.0

        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            path = parent / "f"
            path.write_text("x", encoding="utf-8")
            with mock.patch.object(Path, "lstat", return_value=_St()):
                row = files_svc._entry(path, parent)
        self.assertEqual(row.get("name"), "f")
        json.dumps(row, allow_nan=False)

    def test_infinite_log_size_does_not_500(self):
        class _St:
            st_size = float("inf")
            st_mode = stat.S_IFREG | 0o644

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.log"
            path.write_text("x\n", encoding="utf-8")
            with mock.patch("hub.logs_svc.cfg", return_value={
                "log_sources": [{"id": "app", "name": "app", "path": str(path)}],
            }), mock.patch.object(Path, "stat", return_value=_St()):
                rows = logs_svc.log_sources()
        self.assertEqual(rows[0]["size"], 0)
        json.dumps(rows, allow_nan=False)

    def test_infinite_loadavg_does_not_500(self):
        du = namedtuple("DU", "total used free")(1, 0, 1)
        with (
            mock.patch.object(tools_svc.shutil, "disk_usage", return_value=du),
            mock.patch.object(
                tools_svc, "fan_out",
                return_value=("h", "m", 1, 1.0, 1, (False, {}), "p", ""),
            ),
            mock.patch.object(
                tools_svc.os, "getloadavg",
                return_value=(float("inf"), float("nan"), 0.0),
            ),
            mock.patch.object(tools_svc.metrics, "history", return_value=[]),
        ):
            snap = tools_svc.diagnostics()
        self.assertEqual(snap["load"], [0.0, 0.0, 0.0])
        json.dumps(snap, allow_nan=False)

    def test_infinite_calendar_hour_does_not_500(self):
        import plistlib

        with tempfile.TemporaryDirectory() as tmp:
            agents = Path(tmp)
            (agents / "x.plist").write_bytes(plistlib.dumps({
                "Label": "x",
                "StartCalendarInterval": {"Hour": float("inf")},
                "ProgramArguments": ["true"],
            }))
            with (
                mock.patch.object(tools_svc.os.path, "expanduser", return_value=str(agents)),
                mock.patch.object(
                    tools_svc.glob, "glob", return_value=[str(agents / "x.plist")],
                ),
            ):
                items = tools_svc.launchd_timers()
        self.assertEqual(len(items), 1)
        json.dumps(items, allow_nan=False)


class ToolsPathEioTests(unittest.TestCase):
    def test_syslog_fallback_exists_eio_does_not_500(self):
        with mock.patch.object(tools_svc, "sh", return_value=(1, "", "fail")), \
             mock.patch.object(Path, "exists", side_effect=OSError(5, "I/O")):
            out = tools_svc._syslog_tail_uncached(60, 80, "error")
        self.assertFalse(out["ok"])
        json.dumps(out, allow_nan=False)

    def test_brew_exists_eio_does_not_500(self):
        with mock.patch.object(Path, "exists", side_effect=OSError(5, "I/O")):
            out = tools_svc._brew_outdated()
        self.assertFalse(out["ok"])
        json.dumps(out, allow_nan=False)

    def test_dig_is_file_eio_does_not_500(self):
        with mock.patch.object(Path, "is_file", side_effect=OSError(5, "I/O")), \
             mock.patch.object(tools_svc.socket, "getaddrinfo", return_value=[]):
            out = tools_svc.net_dns_lookup("example.com")
        self.assertTrue(out["ok"])
        json.dumps(out, allow_nan=False)

    def test_dig_which_eio_does_not_500(self):
        with mock.patch.object(Path, "is_file", return_value=False), \
             mock.patch.object(tools_svc.shutil, "which", side_effect=OSError(5, "I/O")), \
             mock.patch.object(tools_svc.socket, "getaddrinfo", return_value=[]):
            out = tools_svc.net_dns_lookup("example.com")
        self.assertTrue(out["ok"])
        json.dumps(out, allow_nan=False)


class ToolsShLeftoverTests(unittest.TestCase):
    def setUp(self):
        tools_svc._proc_cache.update(t=0.0, v=None, limit=0)
        tools_svc._hw_cache.update(t=0.0, v=None)
        tools_svc._updates_cache.update(t=0.0, v=None)
        tools_svc._syslog_cache.clear()
        tools_svc._brew_retry_at = 0.0
        tools_svc.docker_disk_usage.invalidate()

    def tearDown(self):
        self.setUp()

    def test_syslog_bytes_and_int_do_not_500(self):
        with mock.patch.object(
            tools_svc, "sh", return_value=(0, b"2020-01-01 error boom\n", ""),
        ):
            out = tools_svc._syslog_tail_uncached(60, 80, "error")
        self.assertEqual(out["lines"], ["2020-01-01 error boom"])
        json.dumps(out, allow_nan=False)
        with mock.patch.object(tools_svc, "sh", return_value=(0, 12, None)):
            out = tools_svc._syslog_tail_uncached(60, 80, "error")
        json.dumps(out, allow_nan=False)

    def test_listening_ports_none_and_int_do_not_500(self):
        row = (
            b"COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
            b"Python  1 u 6u IPv4 0x0 0t0 TCP 127.0.0.1:8086 (LISTEN)\n"
        )
        with mock.patch.object(tools_svc, "sh", return_value=(0, row, "")):
            out = tools_svc.listening_ports(5)
        self.assertEqual(out["count"], 1)
        json.dumps(out, allow_nan=False)
        for junk in (None, 12):
            with mock.patch.object(tools_svc, "sh", return_value=(0, junk, "")):
                out = tools_svc.listening_ports(5)
            self.assertEqual(out["ports"], [])
            json.dumps(out, allow_nan=False)

    def test_net_ping_and_dns_bytes_do_not_500_json(self):
        with mock.patch.object(tools_svc, "sh", return_value=(0, b"ok", 12)):
            ping = tools_svc.net_ping("example.com", 1)
        self.assertEqual(ping["output"], "ok")
        json.dumps(ping, allow_nan=False)
        with mock.patch.object(tools_svc, "sh", return_value=(0, 12, 13)):
            ping = tools_svc.net_ping("example.com", 1)
        json.dumps(ping, allow_nan=False)
        with (
            mock.patch.object(tools_svc.socket, "getaddrinfo", return_value=[]),
            mock.patch.object(Path, "is_file", return_value=True),
            mock.patch.object(tools_svc, "sh", return_value=(0, b"1.2.3.4\n", "")),
        ):
            dns = tools_svc.net_dns_lookup("example.com")
        self.assertEqual(dns["dig"], "1.2.3.4")
        json.dumps(dns, allow_nan=False)

    def test_brew_and_macos_bytes_do_not_500_json(self):
        with (
            mock.patch.object(Path, "exists", return_value=True),
            mock.patch.object(tools_svc, "_brew_busy", return_value=False),
            mock.patch.object(tools_svc, "sh", return_value=(0, b"wget 1.21\n", "")),
        ):
            brew = tools_svc._brew_outdated()
        self.assertEqual(brew["outdated"], ["wget 1.21"])
        json.dumps(brew, allow_nan=False)
        with mock.patch.object(tools_svc, "sh", return_value=(0, 12, None)):
            brew = tools_svc._brew_outdated()
        json.dumps(brew, allow_nan=False)
        with mock.patch.object(
            tools_svc, "sh", return_value=(0, b"Label: macOS\n", ""),
        ):
            mac = tools_svc._macos_updates()
        self.assertTrue(mac["has_updates"])
        json.dumps(mac, allow_nan=False)
        with mock.patch.object(tools_svc, "sh", return_value=(0, None, 12)):
            mac = tools_svc._macos_updates()
        json.dumps(mac, allow_nan=False)

    def test_hardware_and_diagnostics_bytes_do_not_500_json(self):
        with (
            mock.patch.object(tools_svc, "sh", return_value=(0, b"Model: X\n", "")),
            mock.patch("hub.disk_power_svc.list_power_disks", return_value=[]),
        ):
            hw = tools_svc.hardware_profile(force=True)
        self.assertEqual(hw["sections"]["hardware"]["text"], "Model: X")
        json.dumps(hw, allow_nan=False)
        with (
            mock.patch.object(tools_svc, "sh", return_value=(0, b"8", "")),
            mock.patch.object(tools_svc, "engine_up", return_value=False),
            mock.patch.object(tools_svc.metrics, "history", return_value=[]),
        ):
            snap = tools_svc.diagnostics()
        self.assertEqual(snap["ncpu"], 8)
        json.dumps(snap, allow_nan=False)
        with (
            mock.patch.object(tools_svc, "sh", return_value=(0, None, "")),
            mock.patch.object(tools_svc, "engine_up", return_value=False),
            mock.patch.object(tools_svc.metrics, "history", return_value=[]),
        ):
            snap = tools_svc.diagnostics()
        json.dumps(snap, allow_nan=False)

    def test_flush_dns_int_does_not_500(self):
        with mock.patch.object(tools_svc, "sh", return_value=(0, 12, 13)):
            out = tools_svc.flush_dns()
        json.dumps(out, allow_nan=False)

    def test_docker_and_ps_leftovers_do_not_500(self):
        with (
            mock.patch.object(tools_svc, "engine_up", return_value=True),
            mock.patch.object(
                tools_svc, "docker",
                return_value=(0, b"c1\t1B\timg\tUp\n", ""),
            ),
        ):
            rows = tools_svc.container_sizes()
        self.assertEqual(rows[0]["name"], "c1")
        json.dumps(rows, allow_nan=False)
        for junk in (None, 12):
            with (
                mock.patch.object(tools_svc, "engine_up", return_value=True),
                mock.patch.object(tools_svc, "docker", return_value=(0, junk, "")),
            ):
                self.assertEqual(tools_svc.container_sizes(), [])
        tools_svc.docker_disk_usage.invalidate()
        with (
            mock.patch.object(tools_svc, "engine_up", return_value=True),
            mock.patch.object(tools_svc, "docker", return_value=(0, None, 12)),
        ):
            df = tools_svc.docker_disk_usage()
        json.dumps(df, allow_nan=False)
        with mock.patch.object(
            tools_svc, "ps_lines",
            return_value=["HDR", b"u 1 1.0 1.0 0 0 x S 0 0 cmd", None, 12],
        ):
            rows = tools_svc.top_processes(5)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["command"], "cmd")
        json.dumps(rows, allow_nan=False)


class TerminalLeftover500Tests(unittest.TestCase):
    def test_list_target_is_coded_not_500(self):
        with self.assertRaises(HTTPException) as ctx:
            terminal_svc.execute(["host"], "echo hi")
        self.assertEqual(_code(ctx.exception), "terminal.bad_target")

    def test_list_container_is_coded_not_500(self):
        with self.assertRaises(HTTPException) as ctx:
            terminal_svc.run_container(["web"], "echo hi")
        self.assertEqual(_code(ctx.exception), "terminal.no_container")

    def test_infinite_timeout_does_not_500_run(self):
        result = terminal_svc._run(["/bin/echo", "hi"], float("inf"))
        self.assertEqual(result["rc"], 0)
        json.dumps(result, allow_nan=False)

    def test_list_audit_limit_does_not_500(self):
        entries = terminal_svc.recent_audit(["50"])
        self.assertIsInstance(entries, list)
        json.dumps(entries, allow_nan=False)

    def test_leftover_infinity_audit_line_does_not_500(self):
        """Python json.loads accepts Infinity; Starlette allow_nan=False does not."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "terminal-audit.jsonl"
            path.write_text(
                '{"ts": Infinity, "rc": NaN, "duration_ms": -Infinity, '
                '"who": "ops", "command": "ls"}\n',
                encoding="utf-8",
            )
            with mock.patch.object(terminal_svc, "AUDIT_PATH", path):
                entries = terminal_svc.recent_audit(10)
        self.assertEqual(len(entries), 1)
        self.assertIsNone(entries[0]["ts"])
        self.assertIsNone(entries[0]["rc"])
        self.assertIsNone(entries[0]["duration_ms"])
        json.dumps(entries, allow_nan=False)

    def test_deeply_nested_audit_line_does_not_500(self):
        """``json.loads`` RecursionError is not ValueError; leftover nested
        terminal-audit.jsonl used to 500 GET /api/terminal/history."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "terminal-audit.jsonl"
            good = json.dumps({"ts": 1, "who": "ops", "command": "ls", "rc": 0})
            path.write_text(
                '{"k":' * 12000 + "1" + "}" * 12000 + "\n" + good + "\n",
                encoding="utf-8",
            )
            with mock.patch.object(terminal_svc, "AUDIT_PATH", path):
                entries = terminal_svc.recent_audit(10)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["who"], "ops")
        json.dumps(entries, allow_nan=False)

    def test_surrogate_command_does_not_500_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "terminal-audit.jsonl"
            with mock.patch.object(terminal_svc, "AUDIT_PATH", path):
                terminal_svc._audit({
                    "ts": 1,
                    "who": b"ops",
                    "command": "echo \ud800",
                    "rc": float("inf"),
                })
                entries = terminal_svc.recent_audit(10)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["who"], "ops")
        self.assertIsNone(entries[0]["rc"])
        json.dumps(entries, allow_nan=False)

    def test_shell_exists_eio_does_not_500_status(self):
        with (
            mock.patch.object(terminal_svc, "_terminal_cfg", return_value={}),
            mock.patch.object(Path, "exists", side_effect=OSError(5, "I/O error")),
        ):
            st = terminal_svc.status()
        json.dumps(st, allow_nan=False)
        self.assertEqual(st["shell"], "/bin/sh")

    def test_surrogate_cwd_does_not_500_status(self):
        with mock.patch.object(
            terminal_svc, "_terminal_cfg",
            return_value={"cwd": "/tmp/\ud800", "shell": "\ud800"},
        ):
            st = terminal_svc.status()
        json.dumps(st, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertNotIn("\ud800", st["cwd"])
        self.assertNotIn("\ud800", st["shell"])

    def test_missing_home_does_not_500_status(self):
        with (
            mock.patch.object(terminal_svc, "_terminal_cfg", return_value={}),
            mock.patch.object(Path, "home", side_effect=RuntimeError("no home")),
        ):
            st = terminal_svc.status()
        json.dumps(st, allow_nan=False)
        self.assertIsInstance(st["cwd"], str)

    def test_expanduser_runtimeerror_does_not_500_cwd(self):
        with mock.patch.object(Path, "expanduser", side_effect=RuntimeError("no home")):
            cwd = terminal_svc._resolve_cwd("~/tmp")
        self.assertIsInstance(cwd, str)

    def test_popen_eio_does_not_500_run(self):
        with mock.patch.object(
            terminal_svc.subprocess, "Popen", side_effect=OSError(5, "I/O error")
        ):
            result = terminal_svc._run(["/bin/echo", "hi"], 2, cwd="/tmp")
        self.assertFalse(result["ok"])
        self.assertEqual(result["rc"], 127)
        json.dumps(result, allow_nan=False)

    def test_missing_home_does_not_500_execute(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "terminal-audit.jsonl"
            with (
                mock.patch.object(terminal_svc, "AUDIT_PATH", path),
                mock.patch.object(terminal_svc, "host_enabled", return_value=True),
                mock.patch.object(Path, "home", side_effect=RuntimeError("no home")),
                mock.patch.object(terminal_svc, "_run", return_value={
                    "ok": True, "rc": 0, "stdout": "", "stderr": "",
                    "truncated": False, "duration_ms": 1,
                }),
            ):
                result = terminal_svc.execute("host", "echo hi")
        json.dumps(result, allow_nan=False)
        self.assertEqual(result["rc"], 0)

    def test_surrogate_audit_key_does_not_500(self):
        """Values were scrubbed; leftover ``\\ud800`` keys still 500'd history."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "terminal-audit.jsonl"
            path.write_text(
                '{"ts": 1, "\\ud800": "x", "command": "ls\\ud800", "who": "ops"}\n',
                encoding="utf-8",
            )
            with mock.patch.object(terminal_svc, "AUDIT_PATH", path):
                entries = terminal_svc.recent_audit(10)
        self.assertEqual(len(entries), 1)
        _starlette(entries)
        blob = json.dumps(entries, ensure_ascii=False)
        self.assertNotIn("\ud800", blob)
        self.assertEqual(entries[0]["who"], "ops")

    def test_surrogate_cwd_does_not_500_container_run(self):
        """Container cwd is not host-validated; leftover ``\\ud800`` used to
        leak into POST /api/terminal/run when the cwd marker was missing."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "terminal-audit.jsonl"
            with (
                mock.patch.object(terminal_svc, "AUDIT_PATH", path),
                mock.patch.object(terminal_svc, "_run", return_value={
                    "ok": True, "rc": 0, "stdout": "", "stderr": "",
                    "truncated": False, "duration_ms": 1,
                }),
            ):
                result = terminal_svc.execute(
                    "container", "echo hi", container="web", cwd="ok\ud800",
                )
        _starlette(result)
        self.assertNotIn("\ud800", result["cwd"])
        self.assertEqual(result["rc"], 0)

    def test_audit_dumps_recursion_does_not_500_execute(self):
        """json.dumps RecursionError is not OSError; POST /api/terminal/run used to 500."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "terminal-audit.jsonl"
            with (
                mock.patch.object(terminal_svc, "AUDIT_PATH", path),
                mock.patch.object(terminal_svc, "host_enabled", return_value=True),
                mock.patch.object(terminal_svc, "_run", return_value={
                    "ok": True, "rc": 0, "stdout": "", "stderr": "",
                    "truncated": False, "duration_ms": 1,
                }),
                mock.patch.object(terminal_svc.json, "dumps", side_effect=RecursionError),
            ):
                result = terminal_svc.execute("host", "echo hi")
        json.dumps(result, allow_nan=False)
        self.assertEqual(result["rc"], 0)


class ToolsDnsLookupExcDetailTests(unittest.TestCase):
    def test_recursing_gaierror_does_not_500(self):
        """str(e) RecursionError used to 500 GET /api/tools/dns."""
        class Recursing(Exception):
            def __str__(self):
                raise RecursionError("nested")

        with mock.patch.object(tools_svc.socket, "getaddrinfo", side_effect=Recursing()):
            out = tools_svc.net_dns_lookup("example.com")
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertFalse(out["ok"])
        self.assertEqual(out["message"], "Recursing")

    def test_recursing_profiler_does_not_500(self):
        """``str(exc)`` RecursionError used to 500 GET /api/tools hardware."""
        class Recursing(Exception):
            def __str__(self):
                raise RecursionError("nested")

        with mock.patch.object(tools_svc, "_sh", side_effect=Recursing()):
            rc, text = tools_svc._profiler_report(("hardware", "SPHardwareDataType"))
        json.dumps({"rc": rc, "text": text}, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertEqual(rc, 1)
        self.assertEqual(text, "Recursing")

    def test_recursing_macos_updates_does_not_500(self):
        """``str(exc)`` RecursionError used to 500 GET /api/tools updates."""
        class Recursing(Exception):
            def __str__(self):
                raise RecursionError("nested")

        with mock.patch.object(tools_svc, "_sh", side_effect=Recursing()):
            out = tools_svc._macos_updates()
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertFalse(out["ok"])
        self.assertEqual(out["raw"], "Recursing")

    def test_recursing_brew_outdated_does_not_500(self):
        class Recursing(Exception):
            def __str__(self):
                raise RecursionError("nested")

        tools_svc._brew_retry_at = 0.0
        with (
            mock.patch.object(tools_svc, "BREW", "/bin/sh"),
            mock.patch.object(tools_svc, "_brew_busy", return_value=False),
            mock.patch.object(tools_svc, "_sh", side_effect=Recursing()),
        ):
            out = tools_svc._brew_outdated()
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertFalse(out["ok"])
        self.assertEqual(out["raw"], "Recursing")


class FilesAsTextRecursionLeftoverTests(unittest.TestCase):
    def test_files_as_text_recursing_does_not_500(self):
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(files_svc._as_text(Recursing()), "Recursing")
        _starlette({"message": files_svc._as_text(Recursing())})

    def test_proc_cache_as_text_recursing_does_not_500(self):
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(proc_cache._as_text(Recursing()), "Recursing")
        _starlette({"message": proc_cache._as_text(Recursing())})

    def test_launchd_cache_as_text_recursing_does_not_500(self):
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(launchd_cache._as_text(Recursing()), "Recursing")
        _starlette({"message": launchd_cache._as_text(Recursing())})


class ToolsPlistJsonableLeftoverTests(unittest.TestCase):
    def test_isoformat_inf_date_bytes_set_do_not_500(self):
        """Leftover plist dates / isoformat inf used to 500 GET /api/tools launchd."""
        class _Stamp:
            def isoformat(self):
                return float("inf")

        self.assertIsNone(tools_svc._plist_jsonable(_Stamp()))
        out = tools_svc._plist_jsonable({
            "when": _Stamp(),
            "name": datetime.date(2026, 8, 19),
            "blob": b"agent",
            "tags": {"KeepAlive"},
            "n": float("inf"),
        })
        _starlette(out)
        self.assertIsNone(out["when"])
        self.assertEqual(out["name"], "2026-08-19")
        self.assertEqual(out["blob"], "agent")
        self.assertEqual(out["tags"], ["KeepAlive"])
        self.assertIsNone(out["n"])


if __name__ == "__main__":
    unittest.main()
