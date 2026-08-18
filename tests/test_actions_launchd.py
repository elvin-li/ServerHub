"""launchd start must not surface 'already loaded' as a failure.

macOS `launchctl bootstrap` of a job that is already in the session returns
either 17 (EEXIST) or, on current releases, 5 (EIO) with the wording
"Bootstrap failed: 5: Input/output error".  The Ollama page's Start button
went through this path and toasted that string at the operator while the
daemon was already serving :11434.
"""
from __future__ import annotations

import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import actions, autostart_svc, services_manage_svc
from hub.paths import UID


class BootstrapAlreadyLoaded(unittest.TestCase):
    def test_eio_5_is_already_in_the_session(self):
        self.assertTrue(actions._bootstrap_ok_to_kickstart(
            5, "", "Bootstrap failed: 5: Input/output error",
        ))

    def test_eexist_17_is_already_in_the_session(self):
        self.assertTrue(actions._bootstrap_ok_to_kickstart(17, "", "already loaded"))

    def test_success_is_ok_to_kickstart(self):
        self.assertTrue(actions._bootstrap_ok_to_kickstart(0, "", ""))

    def test_already_wording_without_the_usual_exit_codes(self):
        self.assertTrue(actions._bootstrap_ok_to_kickstart(
            1, "service already bootstrapped", "",
        ))

    def test_a_real_bootstrap_failure_is_not_ok(self):
        self.assertFalse(actions._bootstrap_ok_to_kickstart(
            1, "", "Bootstrap failed: 125: Domain does not support specified action",
        ))


class PlistDisabled(unittest.TestCase):
    def test_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "job.plist")
            Path(path).write_bytes(plistlib.dumps({"Label": "job", "Disabled": True}))
            self.assertTrue(actions._plist_disabled(path))
            actions._set_plist_disabled(path, False)
            self.assertFalse(actions._plist_disabled(path))
            self.assertFalse(plistlib.loads(Path(path).read_bytes()).get("Disabled"))
            residue = [p.name for p in Path(tmp).iterdir() if p.suffix == ".tmp"]
            self.assertEqual(residue, [], "atomic write left a temp file")

    def test_non_dict_plist_is_left_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "job.plist")
            raw = plistlib.dumps(["not", "a", "dict"])
            Path(path).write_bytes(raw)
            self.assertFalse(actions._plist_disabled(path))
            actions._set_plist_disabled(path, True)
            self.assertEqual(Path(path).read_bytes(), raw)


class LaunchdStart(unittest.TestCase):
    TARGET = "com.kiro.ollama"
    PLIST = "/tmp/com.kiro.ollama.plist"

    def _run(self, launchctl):
        registry = {
            self.TARGET: ("launchd", {"label": self.TARGET, "path": self.PLIST}),
        }
        with (
            mock.patch.object(actions, "registry", return_value=registry),
            mock.patch.object(actions, "_launchctl", side_effect=launchctl) as mocked,
        ):
            rc, out, err = actions.run_action(self.TARGET, "start")
        return rc, out, err, mocked

    def test_already_loaded_eio_proceeds_to_kickstart(self):
        rc, out, err, mocked = self._run([
            (5, "", "Bootstrap failed: 5: Input/output error"),
            (0, "", ""),
        ])
        self.assertEqual((rc, out, err), (0, "", ""))
        self.assertEqual(
            mocked.call_args_list,
            [
                mock.call(["bootstrap", f"gui/{UID}", self.PLIST]),
                mock.call(["kickstart", f"gui/{UID}/{self.TARGET}"]),
            ],
        )

    def test_fresh_bootstrap_still_kickstarts(self):
        rc, _, _, mocked = self._run([(0, "", ""), (0, "", "")])
        self.assertEqual(rc, 0)
        self.assertEqual(mocked.call_count, 2)

    def test_real_bootstrap_failure_does_not_kickstart(self):
        rc, out, err, mocked = self._run([
            (1, "", "Bootstrap failed: 125: Domain does not support specified action"),
        ])
        self.assertEqual(rc, 1)
        self.assertIn("Domain does not support", err)
        mocked.assert_called_once_with(["bootstrap", f"gui/{UID}", self.PLIST])

    def test_start_enables_a_disabled_plist_before_bootstrap(self):
        with (
            mock.patch.object(actions, "_plist_disabled", return_value=True),
            mock.patch.object(actions, "_set_plist_disabled") as persist,
        ):
            rc, _, _, mocked = self._run([
                (0, "", ""),
                (0, "", ""),
                (0, "", ""),
            ])
        self.assertEqual(rc, 0)
        persist.assert_called_once_with(self.PLIST, False)
        self.assertEqual(
            mocked.call_args_list,
            [
                mock.call(["enable", f"gui/{UID}/{self.TARGET}"]),
                mock.call(["bootstrap", f"gui/{UID}", self.PLIST]),
                mock.call(["kickstart", f"gui/{UID}/{self.TARGET}"]),
            ],
        )

    def test_start_skips_enable_when_plist_is_active(self):
        with mock.patch.object(actions, "_plist_disabled", return_value=False):
            rc, _, _, mocked = self._run([(0, "", ""), (0, "", "")])
        self.assertEqual(rc, 0)
        self.assertEqual(
            mocked.call_args_list,
            [
                mock.call(["bootstrap", f"gui/{UID}", self.PLIST]),
                mock.call(["kickstart", f"gui/{UID}/{self.TARGET}"]),
            ],
        )


class PlistPathUsesLabel(unittest.TestCase):
    """Detail / logs must find a plist by Label when the file was renamed."""

    def test_renamed_plist_is_found_by_label(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "com.file.name.plist"
            path.write_bytes(plistlib.dumps({
                "Label": "com.real.job",
                "ProgramArguments": ["/usr/bin/true"],
                "StandardErrorPath": "/tmp/x.err",
            }))
            with mock.patch.object(services_manage_svc, "AGENTS_DIR", tmp):
                self.assertEqual(
                    services_manage_svc._plist_path("com.real.job"),
                    path,
                )
                self.assertIsNone(services_manage_svc._plist_path("com.file.name"))
                pl = services_manage_svc._load_plist("com.real.job")
        self.assertEqual(pl.get("StandardErrorPath"), "/tmp/x.err")

    def test_matching_filename_still_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "com.real.job.plist"
            path.write_bytes(plistlib.dumps({
                "Label": "com.real.job",
                "ProgramArguments": ["/usr/bin/true"],
            }))
            with mock.patch.object(services_manage_svc, "AGENTS_DIR", tmp):
                self.assertEqual(
                    services_manage_svc._plist_path("com.real.job"),
                    path,
                )

    def test_registry_keys_the_job_by_label(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "com.file.name.plist"
            path.write_bytes(plistlib.dumps({
                "Label": "com.real.job",
                "ProgramArguments": ["/usr/bin/true"],
            }))
            with (
                mock.patch.object(actions, "AGENTS_DIR", tmp),
                mock.patch.object(actions, "cfg", return_value={}),
                mock.patch.object(actions, "sh", return_value=(0, "", "")),
            ):
                reg = actions.registry()
        self.assertEqual(reg["com.real.job"][0], "launchd")
        self.assertEqual(reg["com.real.job"][1]["label"], "com.real.job")
        self.assertEqual(Path(reg["com.real.job"][1]["path"]), path)
        self.assertEqual(reg["com.file.name"][1]["label"], "com.real.job")

    def test_autostart_read_rejects_a_non_dict(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "job.plist"
            path.write_bytes(plistlib.dumps(["not", "a", "dict"]))
            self.assertEqual(autostart_svc._read_plist(path), {})

    def test_load_plist_rejects_a_non_dict(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "com.real.job.plist"
            path.write_bytes(plistlib.dumps(["not", "a", "dict"]))
            with mock.patch.object(services_manage_svc, "AGENTS_DIR", tmp):
                self.assertEqual(services_manage_svc._load_plist("com.real.job"), {})
