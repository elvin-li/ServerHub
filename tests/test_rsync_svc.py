"""rsync service: binary detection, argv construction, injection, dry-run.

No test here ever runs a real rsync transfer: the probe and the preview are
exercised against mocked ``sh`` output, and the runner against a mocked
watchdog.  The one property that matters most is that no configured value can
reach the argv in a form rsync would read as an option.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import HTTPException  # noqa: E402

from hub import rsync_svc  # noqa: E402

RSYNC3 = {
    "available": True, "path": "/opt/homebrew/bin/rsync",
    "variant": "rsync3", "version": "3.4.1",
    "supports": {"itemize": True, "progress2": True, "compress": True, "bwlimit": True},
}
OPENRSYNC = {
    "available": True, "path": "/usr/bin/rsync",
    "variant": "openrsync", "version": "2.6.9",
    "supports": {"itemize": False, "progress2": False, "compress": False, "bwlimit": False},
}


def _code(ctx) -> str:
    detail = ctx.exception.detail
    return detail["code"] if isinstance(detail, dict) else str(detail)


class ProbeTests(unittest.TestCase):
    def _probe(self, existing: dict[str, str]):
        """existing: path -> --version stdout for paths that 'exist'."""
        def fake_is_file(self):
            return str(self) in existing

        def fake_sh(argv, timeout=10):
            return 0, existing[argv[0]], ""

        with mock.patch.object(Path, "is_file", fake_is_file), \
             mock.patch.object(rsync_svc, "sh", fake_sh):
            return rsync_svc.probe_rsync()

    def test_brew_rsync3_wins_and_reports_full_capabilities(self):
        info = self._probe({
            "/opt/homebrew/bin/rsync": "rsync  version 3.4.1  protocol version 32",
            "/usr/bin/rsync": "openrsync: protocol version 29",
        })
        self.assertEqual(info["variant"], "rsync3")
        self.assertEqual(info["path"], "/opt/homebrew/bin/rsync")
        self.assertEqual(info["version"], "3.4.1")
        self.assertTrue(all(info["supports"].values()))

    def test_openrsync_fallback_degrades_capabilities(self):
        info = self._probe({"/usr/bin/rsync": "openrsync: protocol version 29"})
        self.assertEqual(info["variant"], "openrsync")
        self.assertFalse(any(info["supports"].values()))

    def test_no_binary_at_all(self):
        info = self._probe({})
        self.assertFalse(info["available"])


class ArgvTests(unittest.TestCase):
    PARAMS = {
        "direction": "push",
        "src": "/Users/a0000/Services/photos",
        "dest": "/Volumes/Backup/photos",
        "delete": True,
        "compress": True,
        "bwlimit_kbps": 5000,
        "exclude": ["*.tmp", ".DS_Store"],
    }

    def test_full_argv_under_rsync3(self):
        argv = rsync_svc.build_argv(self.PARAMS, info=RSYNC3)
        self.assertEqual(argv, [
            "/opt/homebrew/bin/rsync", "-a", "--itemize-changes", "--delete",
            "-z", "--bwlimit=5000",
            "--exclude=*.tmp", "--exclude=.DS_Store",
            "/Users/a0000/Services/photos", "/Volumes/Backup/photos",
        ])

    def test_flags_degrade_under_openrsync(self):
        argv = rsync_svc.build_argv(self.PARAMS, info=OPENRSYNC)
        self.assertEqual(argv, [
            "/usr/bin/rsync", "-a", "-v", "--delete",
            "--exclude=*.tmp", "--exclude=.DS_Store",
            "/Users/a0000/Services/photos", "/Volumes/Backup/photos",
        ])
        self.assertNotIn("-z", argv)
        self.assertNotIn("--bwlimit=5000", argv)

    def test_dry_run_adds_n(self):
        argv = rsync_svc.build_argv(self.PARAMS, dry_run=True, info=RSYNC3)
        self.assertIn("-n", argv)

    def test_delete_stays_opt_in(self):
        params = {**self.PARAMS, "delete": False}
        argv = rsync_svc.build_argv(params, info=RSYNC3)
        self.assertNotIn("--delete", argv)

    def test_remote_dest_for_push(self):
        params = {**self.PARAMS, "dest": "backup@nas.local:/srv/photos"}
        argv = rsync_svc.build_argv(params, info=RSYNC3)
        self.assertEqual(argv[-1], "backup@nas.local:/srv/photos")

    def test_pull_from_remote(self):
        params = {"direction": "pull", "src": "backup@nas.local:/srv/photos",
                  "dest": "/Users/a0000/restore"}
        argv = rsync_svc.build_argv(params, info=RSYNC3)
        self.assertEqual(argv[-2:], ["backup@nas.local:/srv/photos", "/Users/a0000/restore"])

    def test_no_binary_raises_unavailable(self):
        with self.assertRaises(HTTPException) as ctx:
            rsync_svc.build_argv(self.PARAMS, info={"available": False})
        self.assertEqual(_code(ctx), "rsync.unavailable")


class InjectionRejectionTests(unittest.TestCase):
    BASE = {"direction": "push", "src": "/data", "dest": "/backup"}

    def _reject(self, expected_code: str, **overrides):
        params = {**self.BASE, **overrides}
        with self.assertRaises(HTTPException) as ctx:
            rsync_svc.validated(params)
        self.assertEqual(_code(ctx), expected_code)

    def test_option_like_src(self):
        self._reject("rsync.bad_path", src="--delete")

    def test_relative_src(self):
        self._reject("rsync.bad_path", src="photos")

    def test_src_with_control_chars(self):
        self._reject("rsync.bad_path", src="/data\n--delete")

    def test_src_with_surrounding_whitespace(self):
        self._reject("rsync.bad_path", src=" /data")

    def test_option_like_remote_user(self):
        # The remote spec must start with an alphanumeric, so an argv element
        # can never begin with "-".
        self._reject("rsync.bad_dest", dest="-oProxyCommand=evil@host:/x")

    def test_remote_path_starting_with_dash(self):
        self._reject("rsync.bad_dest", dest="user@host:-rf")

    def test_pull_dest_must_be_local(self):
        self._reject("rsync.bad_path",
                     direction="pull", src="user@host:/x", dest="user@host:/y")

    def test_option_like_exclude(self):
        self._reject("rsync.bad_exclude", exclude=["-rf"])

    def test_exclude_with_newline(self):
        self._reject("rsync.bad_exclude", exclude=["a\nb"])

    def test_bad_direction(self):
        self._reject("rsync.bad_direction", direction="sideways")

    def test_bad_bwlimit(self):
        self._reject("rsync.bad_params", bwlimit_kbps="fast")
        self._reject("rsync.bad_params", bwlimit_kbps=-5)
        self._reject("rsync.bad_params", bwlimit_kbps=float("inf"))

    def test_exclude_that_is_not_a_list_is_ignored(self):
        params = {**self.BASE, "exclude": 1}
        argv = rsync_svc.build_argv(params, info=RSYNC3)
        self.assertFalse(any(a.startswith("--exclude=") for a in argv))

    def test_params_that_are_not_a_dict_are_coded_not_500(self):
        """A YAML list leftover under params used to raise ``list.get``."""
        for junk in (["/data", "/backup"], "/data", 1):
            with self.subTest(junk=junk):
                with self.assertRaises(HTTPException) as ctx:
                    rsync_svc.validated(junk)
                self.assertEqual(_code(ctx), "rsync.bad_params")
        with self.assertRaises(HTTPException) as ctx:
            rsync_svc.validated(None)
        self.assertEqual(_code(ctx), "rsync.bad_path")

    def test_exclude_rides_in_a_single_token(self):
        """Even a hostile pattern cannot become its own argv element."""
        params = {**self.BASE, "exclude": ["weird pattern with spaces"]}
        argv = rsync_svc.build_argv(params, info=RSYNC3)
        self.assertIn("--exclude=weird pattern with spaces", argv)


ITEMIZED = """\
>f+++++++++ new/file.txt
cd+++++++++ new/
>f.st...... changed.txt
*deleting   gone.txt
.d..t...... touched-dir/
"""


class _FakeProc:
    """Stand-in for the streaming preview's Popen: iterable pipes, no fork.

    ``pid`` points at a nonexistent process so _kill_group's os.getpgid probe
    raises ProcessLookupError and returns, exactly like an already-dead child.
    """

    def __init__(self, out_lines, err_lines=(), rc=0):
        self.stdout = iter(list(out_lines))
        self.stderr = iter(list(err_lines))
        self.pid = 2 ** 22 + 1  # beyond macOS's pid range
        self.returncode = None
        self._rc = rc

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.returncode = self._rc
        return self.returncode

VERBOSE = """\
building file list ... done
photos/2026/a.jpg
photos/2026/b.jpg
deleting old/c.jpg

sent 123 bytes  received 45 bytes  336.00 bytes/sec
total size is 6789  speedup is 40.41
"""


class DryRunParseTests(unittest.TestCase):
    def test_itemized_output(self):
        summary = rsync_svc.parse_dry_run(ITEMIZED, itemize=True)
        self.assertEqual(summary["creates"], 2)
        self.assertEqual(summary["updates"], 1)
        self.assertEqual(summary["deletes"], 1)
        self.assertEqual(summary["total"], 4)

    def test_verbose_output(self):
        summary = rsync_svc.parse_dry_run(VERBOSE, itemize=False)
        self.assertEqual(summary["updates"], 2)
        self.assertEqual(summary["deletes"], 1)
        self.assertEqual(summary["creates"], 0)

    def test_preview_combines_run_and_parse(self):
        params = {"direction": "push", "src": "/data", "dest": "/backup"}
        with mock.patch.object(rsync_svc, "binary_info", lambda force=False: RSYNC3), \
             mock.patch.object(rsync_svc.subprocess, "Popen",
                               lambda *a, **kw: _FakeProc(ITEMIZED.splitlines(), rc=0)):
            summary = rsync_svc.preview(params)
        self.assertTrue(summary["ok"])
        self.assertEqual(summary["total"], 4)
        self.assertEqual(summary["binary"]["variant"], "rsync3")

    def test_preview_tolerates_non_object_supports(self):
        info = dict(RSYNC3)
        info["supports"] = ["itemize"]
        with mock.patch.object(rsync_svc, "binary_info", lambda force=False: info), \
             mock.patch.object(rsync_svc.subprocess, "Popen",
                               lambda *a, **kw: _FakeProc(VERBOSE.splitlines(), rc=0)):
            summary = rsync_svc.preview(
                {"direction": "push", "src": "/data", "dest": "/backup"}
            )
        self.assertTrue(summary["ok"])

    def test_preview_reports_failure(self):
        params = {"direction": "push", "src": "/data", "dest": "/backup"}
        with mock.patch.object(rsync_svc, "binary_info", lambda force=False: RSYNC3), \
             mock.patch.object(
                 rsync_svc.subprocess, "Popen",
                 lambda *a, **kw: _FakeProc([], err_lines=["permission denied"], rc=23)):
            summary = rsync_svc.preview(params)
        self.assertFalse(summary["ok"])
        self.assertEqual(summary["rc"], 23)
        self.assertIn("permission denied", summary["message"])


class PreviewStreamingTests(unittest.TestCase):
    """The preview is streamed, single-flight, and deadline-killed.

    The old implementation buffered the whole dry-run listing (hundreds of MB
    over a large tree) in panel memory, ran with a 600s request-thread hold,
    and let double-clicks stack concurrent full-tree scans.
    """

    PARAMS = {"direction": "push", "src": "/data", "dest": "/backup"}

    def setUp(self):
        # No test may inherit another's in-flight preview registration.
        with rsync_svc._preview_guard:
            rsync_svc._preview_running.clear()

    def test_leftover_inf_timeout_does_not_500_preview(self):
        with mock.patch.object(rsync_svc, "binary_info", lambda force=False: RSYNC3), \
             mock.patch.object(rsync_svc, "_run_preview") as run:
            run.return_value = {
                "creates": 0, "updates": 0, "deletes": 0, "total": 0,
                "samples": [], "ok": True, "rc": 0, "message": "",
            }
            summary = rsync_svc.preview(self.PARAMS, timeout=float("inf"))
        self.assertTrue(summary["ok"])
        self.assertEqual(run.call_args.kwargs["timeout"], rsync_svc.PREVIEW_TIMEOUT)
        json.dumps(summary, allow_nan=False)

    def test_huge_output_is_counted_but_only_samples_survive(self):
        lines = [f">f+++++++++ tree/file-{i}.bin" for i in range(50_000)]
        with mock.patch.object(rsync_svc, "binary_info", lambda force=False: RSYNC3), \
             mock.patch.object(rsync_svc.subprocess, "Popen",
                               lambda *a, **kw: _FakeProc(lines, rc=0)):
            summary = rsync_svc.preview(self.PARAMS)
        self.assertTrue(summary["ok"])
        self.assertEqual(summary["creates"], 50_000, "every line is counted")
        self.assertEqual(len(summary["samples"]), rsync_svc.PREVIEW_SAMPLES,
                         "everything past the sample cap is dropped, not kept")

    def test_second_concurrent_preview_of_the_same_job_is_refused(self):
        key = rsync_svc._preview_key(rsync_svc.validated(self.PARAMS))
        with rsync_svc._preview_guard:
            rsync_svc._preview_running.add(key)
        try:
            with mock.patch.object(rsync_svc, "binary_info", lambda force=False: RSYNC3), \
                 self.assertRaises(HTTPException) as ctx:
                rsync_svc.preview(self.PARAMS)
            self.assertEqual(_code(ctx), "rsync.preview_busy")
        finally:
            with rsync_svc._preview_guard:
                rsync_svc._preview_running.discard(key)
        # A *different* job is not blocked by the busy one.
        other = {**self.PARAMS, "dest": "/elsewhere"}
        with mock.patch.object(rsync_svc, "binary_info", lambda force=False: RSYNC3), \
             mock.patch.object(rsync_svc.subprocess, "Popen",
                               lambda *a, **kw: _FakeProc([], rc=0)):
            self.assertTrue(rsync_svc.preview(other)["ok"])

    def test_registration_is_released_even_when_the_run_fails(self):
        with mock.patch.object(rsync_svc, "binary_info", lambda force=False: RSYNC3), \
             mock.patch.object(rsync_svc.subprocess, "Popen",
                               side_effect=OSError("no rsync")):
            summary = rsync_svc.preview(self.PARAMS)
        self.assertFalse(summary["ok"])
        with rsync_svc._preview_guard:
            self.assertEqual(rsync_svc._preview_running, set(),
                             "a failed preview must not leave the job marked busy")

    def test_preview_popen_surrogate_does_not_500(self):
        """Leftover ``\\ud800`` env UnicodeEncodeError is ValueError; POST preview used to 500."""
        with mock.patch.object(rsync_svc, "binary_info", lambda force=False: RSYNC3), \
             mock.patch.object(
                 rsync_svc.subprocess, "Popen",
                 side_effect=UnicodeEncodeError(
                     "utf-8", "\ud800", 0, 1, "surrogates not allowed",
                 ),
             ):
            summary = rsync_svc.preview(self.PARAMS)
        self.assertFalse(summary["ok"])
        self.assertNotIn("\ud800", summary["message"])
        json.dumps(summary, allow_nan=False)

    def test_preview_str_recursion_does_not_500(self):
        """leftover ``str(e)`` RecursionError used to 500 POST /api/rsync/preview."""
        class Boom(OSError):
            def __str__(self):
                raise RecursionError

        with mock.patch.object(rsync_svc, "binary_info", lambda force=False: RSYNC3), \
             mock.patch.object(rsync_svc.subprocess, "Popen", side_effect=Boom()):
            summary = rsync_svc.preview(self.PARAMS)
        self.assertFalse(summary["ok"])
        json.dumps(summary, allow_nan=False)

    def test_timeout_kills_the_whole_process_group(self):
        import sys as _sys
        import time as _time

        # A stand-in rsync that spawns its own child (as rsync does for the
        # transfer), prints the child's pid, then hangs far past the deadline.
        script = (
            "import subprocess, sys, time\n"
            "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
            "print(child.pid, flush=True)\n"
            "time.sleep(60)\n"
        )
        argv = [_sys.executable, "-c", script]
        # OPENRSYNC → verbose (non-itemize) parsing, so the pid line lands in
        # the samples where the assertion below can read it back.
        with mock.patch.object(rsync_svc, "binary_info", lambda force=False: OPENRSYNC), \
             mock.patch.object(rsync_svc, "build_argv", lambda *a, **kw: argv):
            t0 = _time.monotonic()
            summary = rsync_svc.preview(self.PARAMS, timeout=1)
            elapsed = _time.monotonic() - t0
        self.assertEqual(summary["rc"], 124)
        self.assertFalse(summary["ok"])
        self.assertIn("timeout", summary["message"])
        self.assertLess(elapsed, 15, "the deadline must actually terminate the run")
        child_pid = int(summary["samples"][0])
        deadline = _time.monotonic() + 10
        while _time.monotonic() < deadline:
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                break  # the grandchild died with the group
            _time.sleep(0.2)
        else:
            os.kill(child_pid, 9)
            self.fail("the child rsync helper survived the group kill")


class RunJobTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        root = Path(tempfile.mkdtemp(prefix="serverhub-rsync-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        self.root = root
        logs = mock.patch.object(rsync_svc, "RUN_LOG_ROOT", root / "backup-runs")
        logs.start()
        self.addCleanup(logs.stop)

    def test_run_refuses_missing_local_source(self):
        log: list = []
        params = {"direction": "push", "src": str(self.root / "nope"), "dest": "/backup"}
        with mock.patch.object(rsync_svc, "binary_info", lambda force=False: RSYNC3):
            rc = rsync_svc.run_job(params, log=log, job_id="j1")
        self.assertEqual(rc, -1)
        self.assertTrue(any("does not exist" in ln for ln in log))

    def test_run_executes_argv_under_watchdog_and_writes_log(self):
        src = self.root / "data"
        src.mkdir()
        seen = {}

        def fake_watchdog(argv, *, timeout, log, env=None, cwd=None):
            seen["argv"] = argv
            seen["timeout"] = timeout
            log.append("fake transfer done")
            return 0

        params = {"direction": "push", "src": str(src), "dest": "/backup"}
        log: list = []
        with mock.patch.object(rsync_svc, "binary_info", lambda force=False: RSYNC3), \
             mock.patch.object(rsync_svc, "run_watchdog", fake_watchdog):
            rc = rsync_svc.run_job(params, log=log, timeout=120, job_id="j2")
        self.assertEqual(rc, 0)
        self.assertEqual(seen["argv"][0], RSYNC3["path"])
        self.assertEqual(seen["timeout"], 120)
        logs = list((self.root / "backup-runs" / "j2").glob("*.log"))
        self.assertEqual(len(logs), 1)
        self.assertIn("fake transfer done", logs[0].read_text())
        mode = os.stat(logs[0]).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_validation_error_becomes_log_line_not_exception(self):
        log: list = []
        with mock.patch.object(rsync_svc, "binary_info", lambda force=False: RSYNC3):
            rc = rsync_svc.run_job({"direction": "push", "src": "-rf", "dest": "/b"},
                                   log=log, job_id="j3")
        self.assertEqual(rc, -1)
        self.assertTrue(log and log[0].startswith("!!"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
