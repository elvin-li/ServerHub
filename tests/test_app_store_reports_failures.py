"""A failed install must not come back with a green tick.

The `brew_multi` branch of `install_native` computed its verdict as

    ok = ok and (_brew_install_ok(r["message"], r["rc"]) or True)

which is `ok = ok and True`.  It reported success for every outcome brew could
produce, and the line after it -- `ok = _is_installed(app) or ok` -- could not
undo that, because `or` on an already-true value never looks at the left side.

Two catalog entries use `brew_multi`, and one of them is `native-wireguard`, the
entry the WireGuard page depends on.  So a failing install of it showed "✅" in
the panel and left nothing installed, which is indistinguishable from the app
store being broken.

The other half of this file is about two operators (or two clicks) starting the
same install at once.  Homebrew answers the second one with "Another active
Homebrew process is already in progress" from somewhere deep in its own locking,
which arrives in the panel as an unexplained failure.
"""
from __future__ import annotations

import ast
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from fastapi import HTTPException  # noqa: E402

from hub import native_catalog  # noqa: E402

#: The real brew_multi entry, so the test tracks the catalog rather than a fixture.
MULTI_APP = "native-wireguard"
MULTI_PACKAGES = ("wireguard-tools", "wireguard-go")

SUDO_REFUSAL = "Error: Failure while executing; `/usr/bin/sudo -E -- /usr/sbin/installer` exited with 1.\nsudo: a password is required"


class _FakeProc:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class _Sealed:
    """Patches every path out of the process, then runs an installer.

    `sh`, `subprocess.run` and `_brew_list_installed` are the three ways this
    module reaches the host.  tests/test_tests_do_not_mutate_the_host.py fails
    the build if an installer is called without sealing them.  BREW is pointed at
    this interpreter so the "is Homebrew installed?" guard passes anywhere.
    """

    def __init__(self, run, installed=frozenset(), quiet=True):
        self.patches = [
            patch.object(native_catalog, "sh", return_value=(0, "", "")),
            patch.object(native_catalog, "BREW", sys.executable),
            patch.object(
                native_catalog, "_brew_list_installed", return_value=set(installed)
            ),
            patch.object(native_catalog.subprocess, "run", run),
        ]
        if quiet:
            # create_app() gives serverhub.* a real stderr handler, so every
            # simulated install below would print into the suite's output. A
            # noisy run is a run where a genuine warning goes unnoticed.
            # OutcomeIsLoggedTests passes quiet=False -- that is the one place
            # the records are the subject.
            self.patches.append(patch.object(native_catalog, "log"))

    def __enter__(self):
        for p in self.patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in reversed(self.patches):
            p.stop()
        return False


class BrewMultiVerdictTests(unittest.TestCase):
    def test_the_catalog_still_has_a_brew_multi_entry_to_test(self):
        app = next(a for a in native_catalog.NATIVE_APPS if a["id"] == MULTI_APP)
        self.assertEqual(app["method"], "brew_multi")
        self.assertEqual(tuple(app["packages"]), MULTI_PACKAGES)

    def test_a_failing_install_reports_failure(self):
        with _Sealed(lambda *a, **k: _FakeProc(1, stderr="Error: No such formula")):
            result = native_catalog.install_native(MULTI_APP)
        self.assertFalse(
            result["ok"],
            "brew failed for every package and the store still said it worked",
        )

    def test_the_failed_packages_are_named_in_the_first_line(self):
        # The toast shows only the first line of the message; the rest lives in
        # the install log.  If the first line is brew's own tail output, the
        # operator sees a truncated fragment of a stack of unrelated notices.
        with _Sealed(lambda *a, **k: _FakeProc(1, stderr="Error: No such formula")):
            result = native_catalog.install_native(MULTI_APP)
        first = result["message"].splitlines()[0]
        for pkg in MULTI_PACKAGES:
            self.assertIn(pkg, first)

    def test_a_successful_install_reports_success(self):
        with _Sealed(lambda *a, **k: _FakeProc(0, stdout="Pouring wireguard-tools")):
            result = native_catalog.install_native(MULTI_APP)
        self.assertTrue(result["ok"], result["message"])

    def test_a_nonzero_exit_that_left_the_package_installed_is_not_a_failure(self):
        # brew exits non-zero on states that leave the keg in place: a failed
        # post-install step, an already-linked formula.  Believing the exit code
        # over `brew list` would report failure for a working install.
        with _Sealed(
            lambda *a, **k: _FakeProc(1, stderr="Error: could not link"),
            installed=MULTI_PACKAGES,
        ):
            result = native_catalog.install_native(MULTI_APP)
        self.assertTrue(result["ok"], result["message"])

    def test_a_partial_failure_is_a_failure(self):
        calls: list[int] = []

        def _run(cmd, *a, **k):
            calls.append(1)
            # First package installs, second does not.
            if len(calls) == 1:
                return _FakeProc(0, stdout="Pouring")
            return _FakeProc(1, stderr="Error: download failed")

        with _Sealed(_run):
            result = native_catalog.install_native(MULTI_APP)
        self.assertFalse(result["ok"])
        self.assertIn(MULTI_PACKAGES[1], result["message"].splitlines()[0])
        self.assertNotIn(MULTI_PACKAGES[0], result["message"].splitlines()[0])

    def test_a_sudo_refusal_is_reported_as_password_required(self):
        # The frontend and the operator both need to tell "this needs a password
        # on the Mac itself" apart from "this package does not exist".
        with _Sealed(lambda *a, **k: _FakeProc(1, stderr=SUDO_REFUSAL)):
            result = native_catalog.install_native(MULTI_APP)
        self.assertFalse(result["ok"])
        self.assertEqual(result.get("error"), "password_required")


class NoTautologicalVerdictTests(unittest.TestCase):
    """`x or True` and `x and True` are how the original bug was written."""

    def test_no_boolean_in_the_catalog_is_hardcoded_true(self):
        source = (BASE / "hub" / "native_catalog.py").read_text(encoding="utf-8")
        offenders = []
        for node in ast.walk(ast.parse(source)):
            if not isinstance(node, ast.BoolOp):
                continue
            for value in node.values:
                if isinstance(value, ast.Constant) and value.value is True:
                    offenders.append(f"line {node.lineno}: {ast.unparse(node)}")
        self.assertEqual(
            offenders,
            [],
            "a boolean operand that is literally True makes the whole "
            "expression constant, which is how failed installs reported "
            "success:\n" + "\n".join(offenders),
        )


class OutcomeIsLoggedTests(unittest.TestCase):
    """The response body is the only record of an install, and it is transient.

    An operator reporting "the app store cannot install anything" leaves nothing
    behind to look at: the dialog is closed and the message is gone.  The panel's
    own log is the one place the reason can survive.
    """

    def test_a_failure_is_logged_at_warning_with_the_app_id(self):
        with _Sealed(
            lambda *a, **k: _FakeProc(1, stderr="Error: No such formula"), quiet=False
        ):
            with self.assertLogs("serverhub.appstore", level="WARNING") as captured:
                native_catalog.install_native(MULTI_APP)
        joined = "\n".join(captured.output)
        self.assertIn(MULTI_APP, joined)
        self.assertIn("No such formula", joined)

    def test_a_success_is_logged_at_info(self):
        with _Sealed(lambda *a, **k: _FakeProc(0, stdout="Pouring"), quiet=False):
            with self.assertLogs("serverhub.appstore", level="INFO") as captured:
                native_catalog.install_native(MULTI_APP)
        self.assertTrue(any(r.levelname == "INFO" for r in captured.records))
        self.assertFalse(
            any(r.levelname == "WARNING" for r in captured.records),
            "a successful install was logged as a problem",
        )

    def test_one_attempt_is_one_line(self):
        # brew output is many lines; a multi-line log record cannot be grepped
        # back to the app it belongs to.
        with _Sealed(
            lambda *a, **k: _FakeProc(1, stderr="Error: one\nError: two\nError: three"),
            quiet=False,
        ):
            with self.assertLogs("serverhub.appstore", level="WARNING") as captured:
                native_catalog.install_native(MULTI_APP)
        for record in captured.records:
            self.assertNotIn("\n", record.getMessage())


class LoggingIsActuallyConfiguredTests(unittest.TestCase):
    """Without a handler, every info-level record in this project is discarded.

    Nothing configured logging before, so Python's lastResort handler applied and
    it starts at WARNING -- which is why the one pre-existing logger in the
    codebase only ever logs warnings.  An install log nobody can read is not a
    log, so the wiring is pinned here rather than assumed.
    """

    def test_create_app_gives_the_serverhub_logger_a_handler_at_info(self):
        import logging

        from hub.app_factory import create_app

        create_app()
        logger = logging.getLogger("serverhub")
        self.assertTrue(logger.handlers, "serverhub.* records go nowhere")
        self.assertTrue(logger.isEnabledFor(logging.INFO))

    def test_it_does_not_add_a_handler_per_app(self):
        import logging

        from hub.app_factory import create_app

        create_app()
        before = len(logging.getLogger("serverhub").handlers)
        create_app()
        create_app()
        self.assertEqual(
            len(logging.getLogger("serverhub").handlers),
            before,
            "each create_app() added another handler, so every line would be "
            "printed once per app built in this process",
        )

    def test_records_do_not_also_propagate_to_the_root(self):
        # uvicorn configures the root logger; propagating would print each line
        # twice.
        import logging

        from hub.app_factory import create_app

        create_app()
        self.assertFalse(logging.getLogger("serverhub").propagate)


class SingleFlightTests(unittest.TestCase):
    def _install_in_thread(self, app_id: str) -> tuple[threading.Thread, list]:
        out: list = []

        def target():
            try:
                out.append(native_catalog.install_native(app_id))
            except BaseException as exc:  # noqa: BLE001 - reported to the test
                out.append(exc)

        thread = threading.Thread(target=target, daemon=True)
        return thread, out

    def test_a_second_install_of_the_same_app_is_refused_not_queued(self):
        reached_brew = threading.Event()
        release = threading.Event()

        def _blocking_run(*_a, **_k):
            reached_brew.set()
            release.wait(20)
            return _FakeProc(0, stdout="Pouring")

        with _Sealed(_blocking_run, installed=MULTI_PACKAGES):
            worker, out = self._install_in_thread(MULTI_APP)
            worker.start()
            try:
                self.assertTrue(
                    reached_brew.wait(20), "the first install never reached brew"
                )
                with self.assertRaises(HTTPException) as ctx:
                    native_catalog.install_native(MULTI_APP)
            finally:
                release.set()
                worker.join(30)

        self.assertEqual(ctx.exception.status_code, 409)
        self.assertIn(MULTI_APP, str(ctx.exception.detail))
        self.assertEqual(len(out), 1, "the first install did not finish")
        self.assertNotIsInstance(out[0], BaseException, out[0])
        self.assertTrue(out[0]["ok"], out[0])

    def test_the_lock_is_released_so_a_retry_works(self):
        with _Sealed(lambda *a, **k: _FakeProc(1, stderr="Error: nope")):
            first = native_catalog.install_native(MULTI_APP)
        self.assertFalse(first["ok"])
        # A failure that leaked the lock would make every later attempt answer
        # 409 until the panel restarted.
        with _Sealed(lambda *a, **k: _FakeProc(0, stdout="Pouring")):
            second = native_catalog.install_native(MULTI_APP)
        self.assertTrue(second["ok"], second["message"])

    def test_the_lock_is_released_when_the_installer_raises(self):
        unsupported = "native-screen-sharing"
        with _Sealed(lambda *a, **k: _FakeProc(0)):
            with patch.object(
                native_catalog, "_enable_screen_sharing", side_effect=RuntimeError("boom")
            ):
                with self.assertRaises(RuntimeError):
                    native_catalog.install_native(unsupported)
            # Still reachable: the guard has to be a try/finally, not a
            # release-on-success.
            with patch.object(
                native_catalog,
                "_enable_screen_sharing",
                return_value={"ok": True, "message": "on"},
            ):
                again = native_catalog.install_native(unsupported)
        self.assertTrue(again["ok"])

    def test_a_different_app_is_not_blocked(self):
        reached_brew = threading.Event()
        release = threading.Event()

        def _blocking_run(cmd, *_a, **_k):
            # Only the multi-package install blocks; the other app must not wait
            # for it.  A single global lock would deadlock this test's timeout.
            if any("wireguard" in str(part) for part in (cmd or [])):
                reached_brew.set()
                release.wait(20)
            return _FakeProc(0, stdout="Pouring")

        with _Sealed(_blocking_run, installed=MULTI_PACKAGES):
            worker, out = self._install_in_thread(MULTI_APP)
            worker.start()
            try:
                self.assertTrue(reached_brew.wait(20))
                other = native_catalog.install_native("native-smartmontools")
            finally:
                release.set()
                worker.join(30)
        self.assertTrue(other["ok"], other["message"])
        self.assertEqual(len(out), 1)
        self.assertNotIsInstance(out[0], BaseException, out[0])


if __name__ == "__main__":
    unittest.main()
