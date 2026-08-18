"""Cloudflared login helpers must reap the child process they terminate.

`cloudflared tunnel login` is started directly by ServerHub.  Sending SIGTERM
without waitpid leaves a zombie owned by the panel process.  These tests use
real child processes and assert that they are already reaped when the service
helper returns; checking only that the PID no longer accepts signals would miss
a zombie.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import cloudflared_svc


class LoginProcessTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        patches = (
            mock.patch.object(cloudflared_svc, "CERT", root / "cert.pem"),
            mock.patch.object(cloudflared_svc, "LOGIN_PID", root / "login.pid"),
            mock.patch.object(cloudflared_svc, "LOGIN_URL_FILE", root / "login.url"),
        )
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.children: list[subprocess.Popen] = []

    def tearDown(self):
        for proc in self.children:
            if proc.poll() is None:
                proc.kill()
            try:
                proc.wait(timeout=2)
            except (subprocess.TimeoutExpired, ChildProcessError):
                pass
            if proc.stdout is not None:
                proc.stdout.close()

    def child(self, code: str, *, stdout=None) -> subprocess.Popen:
        proc = subprocess.Popen([sys.executable, "-c", code], stdout=stdout, text=True)
        self.children.append(proc)
        cloudflared_svc.LOGIN_PID.write_text(str(proc.pid))
        return proc

    def assert_reaped(self, proc: subprocess.Popen) -> None:
        with self.assertRaises(
            ChildProcessError,
            msg="the terminated login child was left waitable (a zombie)",
        ):
            os.waitpid(proc.pid, os.WNOHANG)


class TestLoginPollReapsProcess(LoginProcessTestBase):
    def test_successful_login_terminates_and_reaps_waiter(self):
        proc = self.child("import time; time.sleep(60)")
        cloudflared_svc.CERT.write_text("x" * 32)

        result = cloudflared_svc.login_poll()

        self.assertTrue(result["logged_in"])
        self.assertFalse(cloudflared_svc.LOGIN_PID.exists())
        self.assert_reaped(proc)


class TestLoginTerminationEscalation(LoginProcessTestBase):
    def test_sigterm_resistant_child_is_killed_and_reaped(self):
        proc = self.child(
            "import signal,time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "print('ready', flush=True); time.sleep(60)",
            stdout=subprocess.PIPE,
        )
        self.assertEqual(proc.stdout.readline().strip(), "ready")

        stopped = cloudflared_svc._terminate_login_process(
            term_timeout=0.2,
            kill_timeout=1.0,
        )

        self.assertTrue(stopped)
        self.assertFalse(cloudflared_svc.LOGIN_PID.exists())
        # The helper owns only the PID, not this Popen instance.  Reaping via
        # os.waitpid therefore cannot update proc.returncode; ECHILD below is
        # the authoritative assertion that the SIGKILL escalation was reaped.
        self.assert_reaped(proc)


class LoginPipeClose(LoginProcessTestBase):
    def test_terminate_closes_the_held_stdout_wrapper(self):
        proc = self.child(
            "import time; time.sleep(60)",
            stdout=subprocess.PIPE,
        )
        cloudflared_svc._login_proc = proc
        self.addCleanup(lambda: setattr(cloudflared_svc, "_login_proc", None))

        self.assertTrue(cloudflared_svc._terminate_login_process(
            term_timeout=0.4,
            kill_timeout=1.0,
        ))
        self.assertIsNone(cloudflared_svc._login_proc)
        self.assertTrue(proc.stdout.closed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
