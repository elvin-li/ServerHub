from __future__ import annotations

import os
import signal
import subprocess
import tempfile
import textwrap
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
BUILD_SCRIPT = ROOT / "macos" / "build_app.sh"


class MacOSBuildRollbackTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.destination_parent = self.base / "install"
        self.destination_parent.mkdir()
        self.destination = self.destination_parent / "ServerHub.app"
        self.destination.mkdir()
        (self.destination / "old-version").write_text("known-good", encoding="utf-8")
        self.build_dir = self.base / "build"
        self.prebuilt = self.base / "prebuilt" / "ServerHub.app"
        prebuilt_macos = self.prebuilt / "Contents" / "MacOS"
        prebuilt_resources = self.prebuilt / "Contents" / "Resources"
        prebuilt_macos.mkdir(parents=True)
        prebuilt_resources.mkdir(parents=True)
        executable = prebuilt_macos / "ServerHub"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)
        (prebuilt_resources / "AppIcon.icns").write_text("icns", encoding="utf-8")
        (self.prebuilt / "Contents" / "Info.plist").write_text(
            "<plist><dict><key>CFBundleIdentifier</key>"
            "<string>local.serverhub.app</string></dict></plist>\n",
            encoding="utf-8",
        )
        self.tools = self.base / "tools"
        self.tools.mkdir()
        self._write_tools()

    def tearDown(self):
        self.temporary.cleanup()

    def _reap(self, process: subprocess.Popen, *, sig=signal.SIGKILL) -> None:
        """Kill leftover children and close the text pipes.

        ``wait()`` without ``communicate()`` left the stdout/stderr
        TextIOWrappers open and the suite warned about them.
        """
        if process.poll() is None:
            try:
                os.killpg(process.pid, sig)
            except (ProcessLookupError, PermissionError):
                pass
        try:
            process.communicate(timeout=5)
        except Exception:
            pass

    def test_bundle_versions_match_product_version(self):
        source = BUILD_SCRIPT.read_text(encoding="utf-8")
        product_version = (ROOT / "hub" / "__init__.py").read_text(encoding="utf-8")
        version = product_version.split('__version__ = "', 1)[1].split('"', 1)[0]

        self.assertIn(
            f"<key>CFBundleShortVersionString</key><string>{version}</string>",
            source,
        )
        self.assertIn(
            f"<key>CFBundleVersion</key><string>{version}</string>",
            source,
        )

    def _tool(self, name: str, source: str) -> Path:
        path = self.tools / name
        path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
        path.chmod(0o755)
        return path

    def _write_tools(self):
        self.swiftc = self._tool(
            "swiftc",
            """
            #!/bin/sh
            if [ -n "${SERVERHUB_TEST_SWIFTC_ARGS:-}" ]; then
              printf '%s\n' "$@" > "$SERVERHUB_TEST_SWIFTC_ARGS"
            fi
            while [ "$#" -gt 0 ]; do
              if [ "$1" = "-o" ]; then
                shift
                mkdir -p "$(dirname "$1")"
                printf '#!/bin/sh\nexit 0\n' > "$1"
                chmod +x "$1"
                exit 0
              fi
              shift
            done
            exit 2
            """,
        )
        self.sips = self._tool(
            "sips",
            """
            #!/bin/sh
            size="${2:-}"
            output=''
            while [ "$#" -gt 0 ]; do
              if [ "$1" = "--out" ]; then
                shift
                output="$1"
                break
              fi
              shift
            done
            [ -n "$output" ] || exit 2
            if [ -n "${SERVERHUB_TEST_ICON_BARRIER:-}" ]; then
              mkdir -p "$SERVERHUB_TEST_ICON_BARRIER"
              marker="$SERVERHUB_TEST_ICON_BARRIER/$(basename "$output").started"
              : > "$marker"
              attempts=0
              while [ "$(find "$SERVERHUB_TEST_ICON_BARRIER" -name '*.started' | wc -l | tr -d ' ')" -lt 9 ]; do
                attempts=$((attempts + 1))
                if [ "$attempts" -ge 200 ]; then
                  printf 'icon generation did not overlap\n' >&2
                  exit 6
                fi
                sleep 0.01
              done
            fi
            if [ -n "${SERVERHUB_TEST_FAIL_ICON_SIZE:-}" ] && [ "$size" = "$SERVERHUB_TEST_FAIL_ICON_SIZE" ]; then
              printf 'simulated icon resize failure for %s\n' "$size" >&2
              exit 10
            fi
            mkdir -p "$(dirname "$output")"
            printf icon > "$output"
            """,
        )
        self.iconutil = self._tool(
            "iconutil",
            """
            #!/bin/sh
            while [ "$#" -gt 0 ]; do
              if [ "$1" = "-o" ]; then
                shift
                mkdir -p "$(dirname "$1")"
                printf icns > "$1"
                exit 0
              fi
              shift
            done
            exit 2
            """,
        )
        self.plutil = self._tool(
            "plutil",
            """
            #!/bin/sh
            if [ "${1:-}" = "-extract" ]; then
              printf '%s\n' local.serverhub.app
            fi
            exit 0
            """,
        )
        self.ditto = self._tool(
            "ditto",
            """
            #!/bin/sh
            if [ "${SERVERHUB_TEST_FAIL_COPY:-0}" = "1" ]; then
              mkdir -p "$2"
              printf partial > "$2/partial-copy"
              printf 'simulated staged copy failure\n' >&2
              exit 8
            fi
            cp -R "$1" "$2"
            """,
        )
        self.codesign = self._tool(
            "codesign",
            """
            #!/bin/sh
            last=''
            for arg in "$@"; do last="$arg"; done
            case "$last" in
              */.ServerHub.app.install.*)
                if [ "${SERVERHUB_TEST_FAIL_STAGED:-0}" = "1" ]; then
                  printf 'simulated staged verification failure\n' >&2
                  exit 7
                fi
                ;;
            esac
            if [ "$last" = "${SERVERHUB_TEST_DEST:-}" ]; then
              if [ "${SERVERHUB_TEST_BLOCK_FINAL:-0}" = "1" ]; then
                : > "$SERVERHUB_TEST_FINAL_MARKER"
                trap 'exit 143' INT TERM
                while :; do sleep 1; done
              fi
              if [ "${SERVERHUB_TEST_FAIL_FINAL:-0}" = "1" ]; then
                printf 'simulated final verification failure\n' >&2
                exit 9
              fi
            fi
            exit 0
            """,
        )

    def _environment(
        self,
        *,
        fail_copy: bool = False,
        fail_staged: bool = False,
        fail_final: bool = False,
        block_final: bool = False,
        icon_barrier: bool = False,
        fail_icon_size: int | None = None,
        full_build: bool = False,
        prebuilt_app: Path | None = None,
    ) -> dict[str, str]:
        environment = os.environ.copy()
        environment.update({
            "SERVERHUB_BUILD_DIR": str(self.build_dir),
            "SERVERHUB_SWIFTC": str(self.swiftc),
            "SERVERHUB_TEST_SWIFTC_ARGS": str(self.base / "swiftc.args"),
            "SERVERHUB_SIPS": str(self.sips),
            "SERVERHUB_ICONUTIL": str(self.iconutil),
            "SERVERHUB_PLUTIL": str(self.plutil),
            # Most scenarios need only a successful signer. Avoid spawning the
            # slower shell fake unless a test must inject a staged/final failure
            # or synchronize an interrupt during final verification.
            "SERVERHUB_CODESIGN": str(self.codesign) if (
                fail_staged or fail_final or block_final
            ) else "/usr/bin/true",
            "SERVERHUB_DITTO": str(self.ditto),
            # build_app.sh canonicalizes the destination parent with pwd -P.
            # Match that physical path so the fake signer fails only for the
            # final, installed bundle verification.
            "SERVERHUB_TEST_DEST": str(self.destination_parent.resolve() / "ServerHub.app"),
            "SERVERHUB_TEST_FAIL_COPY": "1" if fail_copy else "0",
            "SERVERHUB_TEST_FAIL_STAGED": "1" if fail_staged else "0",
            "SERVERHUB_TEST_FAIL_FINAL": "1" if fail_final else "0",
            "SERVERHUB_TEST_BLOCK_FINAL": "1" if block_final else "0",
            "SERVERHUB_TEST_FINAL_MARKER": str(self.base / "final-verification.started"),
            "SERVERHUB_TEST_ICON_BARRIER": str(self.base / "icon-barrier") if icon_barrier else "",
            "SERVERHUB_TEST_FAIL_ICON_SIZE": "" if fail_icon_size is None else str(fail_icon_size),
            "SERVERHUB_PREBUILT_APP": "" if full_build else str(prebuilt_app or self.prebuilt),
        })
        return environment

    def _run_destination(
        self,
        destination: Path | str,
        *,
        fail_copy: bool = False,
        fail_staged: bool = False,
        fail_final: bool = False,
        icon_barrier: bool = False,
        fail_icon_size: int | None = None,
        full_build: bool = False,
        prebuilt_app: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/bin/bash", str(BUILD_SCRIPT), str(destination)],
            capture_output=True,
            text=True,
            env=self._environment(
                fail_copy=fail_copy,
                fail_staged=fail_staged,
                fail_final=fail_final,
                icon_barrier=icon_barrier,
                fail_icon_size=fail_icon_size,
                full_build=full_build,
                prebuilt_app=prebuilt_app,
            ),
            timeout=30,
        )

    def _run(
        self,
        *,
        fail_copy: bool = False,
        fail_staged: bool = False,
        fail_final: bool = False,
        icon_barrier: bool = False,
        fail_icon_size: int | None = None,
        full_build: bool = False,
        prebuilt_app: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return self._run_destination(
            self.destination,
            fail_copy=fail_copy,
            fail_staged=fail_staged,
            fail_final=fail_final,
            icon_barrier=icon_barrier,
            fail_icon_size=fail_icon_size,
            full_build=full_build,
            prebuilt_app=prebuilt_app,
        )

    def _residue(self) -> list[Path]:
        return list(self.destination_parent.glob(".ServerHub.app.*"))

    def test_invalid_bundle_name_is_rejected_before_building(self):
        bad_destination = self.destination_parent / "NotServerHub.app"

        result = self._run_destination(bad_destination)

        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("destination must end in /ServerHub.app", result.stderr)
        self.assertFalse(self.build_dir.exists())
        self.assertEqual(
            (self.destination / "old-version").read_text(encoding="utf-8"),
            "known-good",
        )

    def test_missing_destination_parent_is_rejected_before_building(self):
        missing_destination = self.base / "missing" / "ServerHub.app"

        result = self._run_destination(missing_destination)

        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("destination parent does not exist", result.stderr)
        self.assertFalse(self.build_dir.exists())
        self.assertFalse(missing_destination.exists())

    def test_filesystem_root_destination_is_rejected_before_building(self):
        result = self._run_destination(Path("/ServerHub.app"))

        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("refusing to install at filesystem root", result.stderr)
        self.assertFalse(self.build_dir.exists())
        self.assertEqual(
            (self.destination / "old-version").read_text(encoding="utf-8"),
            "known-good",
        )

    def test_missing_prebuilt_bundle_is_rejected_before_staging(self):
        missing = self.base / "missing-prebuilt" / "ServerHub.app"

        result = self._run(prebuilt_app=missing)

        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("prebuilt app does not exist", result.stderr)
        self.assertEqual(
            (self.destination / "old-version").read_text(encoding="utf-8"),
            "known-good",
        )
        self.assertEqual(self._residue(), [])

    def test_prebuilt_bundle_cannot_alias_destination(self):
        result = self._run(prebuilt_app=self.destination)

        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("prebuilt app cannot be the install destination", result.stderr)
        self.assertEqual(
            (self.destination / "old-version").read_text(encoding="utf-8"),
            "known-good",
        )
        self.assertFalse((self.destination / "Contents").exists())
        self.assertEqual(self._residue(), [])

    def test_prebuilt_bundle_cannot_live_inside_destination(self):
        nested = self.destination / "cache" / "ServerHub.app"
        nested.mkdir(parents=True)

        result = self._run(prebuilt_app=nested)

        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("prebuilt app cannot be inside the install destination", result.stderr)
        self.assertEqual(
            (self.destination / "old-version").read_text(encoding="utf-8"),
            "known-good",
        )
        self.assertTrue(nested.is_dir())
        self.assertEqual(self._residue(), [])

    def test_prebuilt_bundle_cannot_use_installer_reserved_path(self):
        reserved = self.destination_parent / ".ServerHub.app.backup.fixture"
        reserved.mkdir()

        result = self._run(prebuilt_app=reserved)

        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("prebuilt app uses a reserved installer path", result.stderr)
        self.assertEqual(
            (self.destination / "old-version").read_text(encoding="utf-8"),
            "known-good",
        )
        self.assertTrue(reserved.is_dir())
        self.assertEqual(self._residue(), [reserved])

    def test_stale_install_lock_is_recovered(self):
        lock = self.destination_parent / ".ServerHub.app.install.lock"
        lock.mkdir()
        (lock / "pid").write_text("99999999\n", encoding="utf-8")

        result = self._run()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(lock.exists())
        self.assertFalse((self.destination / "old-version").exists())
        self.assertEqual(self._residue(), [])

    def test_old_incomplete_install_lock_is_recovered(self):
        lock = self.destination_parent / ".ServerHub.app.install.lock"
        lock.mkdir()
        old = time.time() - 120
        os.utime(lock, (old, old))

        result = self._run()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(lock.exists())
        self.assertFalse((self.destination / "old-version").exists())
        self.assertEqual(self._residue(), [])

    def test_fresh_incomplete_install_lock_is_preserved(self):
        lock = self.destination_parent / ".ServerHub.app.install.lock"
        lock.mkdir()

        result = self._run()

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("install already in progress", result.stderr)
        self.assertTrue(lock.is_dir())
        self.assertFalse((lock / "pid").exists())
        self.assertEqual(
            (self.destination / "old-version").read_text(encoding="utf-8"),
            "known-good",
        )

    def test_old_malformed_install_lock_is_recovered(self):
        lock = self.destination_parent / ".ServerHub.app.install.lock"
        lock.mkdir()
        (lock / "pid").write_text("partial\n", encoding="utf-8")
        old = time.time() - 120
        os.utime(lock, (old, old))

        result = self._run()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(lock.exists())
        self.assertFalse((self.destination / "old-version").exists())
        self.assertEqual(self._residue(), [])

    def test_fresh_malformed_install_lock_is_preserved(self):
        lock = self.destination_parent / ".ServerHub.app.install.lock"
        lock.mkdir()
        (lock / "pid").write_text("partial\n", encoding="utf-8")

        result = self._run()

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("install already in progress", result.stderr)
        self.assertTrue(lock.is_dir())
        self.assertEqual((lock / "pid").read_text(encoding="utf-8"), "partial\n")
        self.assertEqual(
            (self.destination / "old-version").read_text(encoding="utf-8"),
            "known-good",
        )

    def test_active_install_lock_is_preserved(self):
        lock = self.destination_parent / ".ServerHub.app.install.lock"
        lock.mkdir()
        (lock / "pid").write_text(f"{os.getpid()}\n", encoding="utf-8")

        result = self._run()

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("install already in progress", result.stderr)
        self.assertEqual(
            (self.destination / "old-version").read_text(encoding="utf-8"),
            "known-good",
        )
        self.assertEqual((lock / "pid").read_text(encoding="utf-8"), f"{os.getpid()}\n")

    def test_full_build_pins_the_macos_13_deployment_target(self):
        result = self._run(full_build=True)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        swiftc_args = (self.base / "swiftc.args").read_text(encoding="utf-8").splitlines()
        self.assertIn("-target", swiftc_args)
        target_index = swiftc_args.index("-target")
        expected = f"{os.uname().machine}-apple-macosx13.0"
        self.assertEqual(swiftc_args[target_index + 1], expected)

    def test_icon_generation_runs_concurrently(self):
        result = self._run(icon_barrier=True, full_build=True)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        markers = list((self.base / "icon-barrier").glob("*.started"))
        self.assertEqual(len(markers), 9)
        self.assertFalse((self.destination / "old-version").exists())
        self.assertEqual(self._residue(), [])

    def test_icon_generation_failure_preserves_previous_bundle(self):
        result = self._run(fail_icon_size=128, full_build=True)

        self.assertEqual(result.returncode, 10, result.stdout + result.stderr)
        self.assertIn("simulated icon resize failure for 128", result.stderr)
        self.assertEqual(
            (self.destination / "old-version").read_text(encoding="utf-8"),
            "known-good",
        )
        self.assertFalse((self.destination / "Contents").exists())
        self.assertEqual(self._residue(), [])

    def test_staged_copy_failure_preserves_previous_bundle(self):
        result = self._run(fail_copy=True)

        self.assertEqual(result.returncode, 8, result.stdout + result.stderr)
        self.assertIn("simulated staged copy failure", result.stderr)
        self.assertEqual(
            (self.destination / "old-version").read_text(encoding="utf-8"),
            "known-good",
        )
        self.assertFalse((self.destination / "Contents").exists())
        self.assertEqual(self._residue(), [])

    def test_staged_verification_failure_preserves_previous_bundle(self):
        result = self._run(fail_staged=True)

        self.assertEqual(result.returncode, 7, result.stdout + result.stderr)
        self.assertIn("simulated staged verification failure", result.stderr)
        self.assertEqual(
            (self.destination / "old-version").read_text(encoding="utf-8"),
            "known-good",
        )
        self.assertFalse((self.destination / "Contents").exists())
        self.assertEqual(self._residue(), [])

    def test_final_verification_failure_restores_previous_bundle(self):
        result = self._run(fail_final=True)

        self.assertEqual(result.returncode, 9, result.stdout + result.stderr)
        self.assertEqual(
            (self.destination / "old-version").read_text(encoding="utf-8"),
            "known-good",
        )
        self.assertFalse((self.destination / "Contents").exists())
        self.assertEqual(self._residue(), [])

    def test_sigterm_during_final_verification_restores_previous_bundle(self):
        marker = self.base / "final-verification.started"
        process = subprocess.Popen(
            ["/bin/bash", str(BUILD_SCRIPT), str(self.destination)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=self._environment(block_final=True),
            start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 5
            while not marker.exists() and process.poll() is None:
                if time.monotonic() >= deadline:
                    self.fail("final verification did not start before timeout")
                time.sleep(0.01)
            self.assertIsNone(process.poll(), "installer exited before SIGTERM")
            self.assertTrue((self.destination / "Contents").is_dir())

            os.killpg(process.pid, signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=5)
        finally:
            self._reap(process)

        self.assertNotEqual(process.returncode, 0, stdout + stderr)
        self.assertEqual(
            (self.destination / "old-version").read_text(encoding="utf-8"),
            "known-good",
        )
        self.assertFalse((self.destination / "Contents").exists())
        self.assertEqual(self._residue(), [])

    def test_concurrent_install_is_rejected_before_touching_destination(self):
        marker = self.base / "final-verification.started"
        environment = self._environment(block_final=True)
        process = subprocess.Popen(
            ["/bin/bash", str(BUILD_SCRIPT), str(self.destination)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
            start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 5
            while not marker.exists():
                if process.poll() is not None:
                    stdout, stderr = process.communicate()
                    self.fail(f"installer exited before lock test: {stdout}{stderr}")
                if time.monotonic() >= deadline:
                    self.fail("final verification did not start before timeout")
                time.sleep(0.01)

            second = self._run()
            self.assertEqual(second.returncode, 3, second.stdout + second.stderr)
            self.assertIn("install already in progress", second.stderr)
            self.assertTrue((self.destination / "Contents").is_dir())

            os.killpg(process.pid, signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=5)
        finally:
            self._reap(process)

        self.assertNotEqual(process.returncode, 0, stdout + stderr)
        self.assertEqual(
            (self.destination / "old-version").read_text(encoding="utf-8"),
            "known-good",
        )
        self.assertFalse((self.destination / "Contents").exists())
        self.assertEqual(self._residue(), [])

    def test_failed_first_install_removes_unverified_bundle(self):
        for child in self.destination.iterdir():
            child.unlink()
        self.destination.rmdir()

        result = self._run(fail_final=True)

        self.assertEqual(result.returncode, 9, result.stdout + result.stderr)
        self.assertFalse(self.destination.exists())
        self.assertEqual(self._residue(), [])

    def test_failed_replacement_restores_dangling_symlink(self):
        for child in self.destination.iterdir():
            child.unlink()
        self.destination.rmdir()
        link_target = "missing/ServerHub.app"
        self.destination.symlink_to(link_target)

        result = self._run(fail_final=True)

        self.assertEqual(result.returncode, 9, result.stdout + result.stderr)
        self.assertTrue(self.destination.is_symlink())
        self.assertEqual(os.readlink(self.destination), link_target)
        self.assertEqual(self._residue(), [])

    def test_success_replaces_previous_bundle_and_removes_backup(self):
        result = self._run(fail_final=False)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        installed = self.destination_parent.resolve() / "ServerHub.app"
        self.assertIn(f"Installed {installed}", result.stdout)
        self.assertFalse((self.destination / "old-version").exists())
        self.assertTrue((self.destination / "Contents" / "MacOS" / "ServerHub").is_file())
        self.assertTrue((self.destination / "Contents" / "Resources" / "AppIcon.icns").is_file())
        self.assertEqual(self._residue(), [])


if __name__ == "__main__":
    unittest.main()
