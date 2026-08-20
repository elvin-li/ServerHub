"""Compose-stack (appdata) backup: stop -> archive -> restart, always restart.

Every docker/tar invocation is routed through ``backups._run_argv`` precisely
so these tests can replace it: no container is ever stopped and no real tar
runs against user data.  The property this file exists to pin is the
try/finally one — once ``compose stop`` was issued, ``compose start`` runs no
matter how the archive step ends.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hub import backups  # noqa: E402


class _Harness(unittest.TestCase):
    def setUp(self):
        root = Path(tempfile.mkdtemp(prefix="serverhub-stackbak-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        self.root = root
        self.backup_root = root / "backups"
        self.backup_root.mkdir()
        patched = mock.patch.object(backups, "BACKUP_ROOT", self.backup_root)
        patched.start()
        self.addCleanup(patched.stop)
        self.data_dir = root / "data"
        self.data_dir.mkdir()
        data = mock.patch.object(backups, "DATA_DIR", self.data_dir)
        data.start()
        self.addCleanup(data.stop)

        # A stack with one real bind directory and one named volume.
        self.stack_dir = root / "photoprism"
        self.stack_dir.mkdir()
        self.compose_path = self.stack_dir / "docker-compose.yml"
        self.compose_path.write_text("services: {}\n")
        self.bind_dir = self.stack_dir / "data"
        self.bind_dir.mkdir()
        (self.bind_dir / "originals.txt").write_text("data")

        stack = {"id": "photoprism", "name": "PhotoPrism",
                 "path": str(self.stack_dir), "compose_path": str(self.compose_path)}
        find = mock.patch.object(
            backups, "_find_stack",
            lambda sid: dict(stack) if sid == "photoprism" else None,
        )
        find.start()
        self.addCleanup(find.stop)
        engine = mock.patch.object(backups, "_engine_up", lambda: True)
        engine.start()
        self.addCleanup(engine.stop)

        self.calls: list[list[str]] = []
        self.fail_tar = False
        self.fail_volume_export = False
        self.stop_rc = 0
        self.start_rc = 0

        def fake_run(argv, *, timeout, **_kwargs):
            self.calls.append(list(argv))
            joined = " ".join(argv)
            if "config" in argv and "--format" in argv:
                return 0, json.dumps(self._compose_config()), ""
            if argv[:2] == [argv[0], "compose"] and argv[-1] == "stop":
                return self.stop_rc, "", "" if self.stop_rc == 0 else "stop failed"
            if argv[:2] == [argv[0], "compose"] and argv[-1] == "start":
                return self.start_rc, "", "" if self.start_rc == 0 else "start failed"
            if argv[0].endswith("tar") and not joined.startswith("docker"):
                if self.fail_tar:
                    return 1, "", "tar: disk full"
                Path(argv[2]).write_bytes(b"x" * 2048)
                return 0, "", ""
            if "run" in argv and "alpine" in argv:
                return (1, "", "volume gone") if self.fail_volume_export else (0, "", "")
            return 0, "", ""

        runner = mock.patch.object(backups, "_run_argv", fake_run)
        runner.start()
        self.addCleanup(runner.stop)

    def _compose_config(self) -> dict:
        return {
            "name": "photoprism",
            "services": {
                "app": {
                    "volumes": [
                        {"type": "bind", "source": str(self.bind_dir), "target": "/data"},
                        # Nonexistent bind (docker.sock style wiring) is skipped.
                        {"type": "bind", "source": "/var/run/not-there.sock", "target": "/s"},
                        {"type": "volume", "source": "db-data", "target": "/db"},
                    ],
                },
            },
            "volumes": {"db-data": {"name": "photoprism_db-data"}},
        }

    # -- helpers ------------------------------------------------------------

    def _joined_calls(self) -> list[str]:
        return [" ".join(c) for c in self.calls]

    def _index_of(self, needle: str) -> int:
        for i, line in enumerate(self._joined_calls()):
            if needle in line:
                return i
        raise AssertionError(f"no call matching {needle!r} in {self._joined_calls()}")


class BackupStackTests(_Harness):
    def test_happy_path_stops_archives_restarts_in_order(self):
        log: list = []
        result = backups.backup_stack("photoprism", log=log)
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["stopped"])
        self.assertTrue(result["restarted"])
        self.assertEqual(result["binds"], 1)
        self.assertEqual(result["volumes"], 1)
        stop_i = self._index_of("compose")
        tar_i = self._index_of("tar czf")
        start_i = self._index_of("start")
        self.assertLess(self._index_of("stop"), tar_i, "stop must precede the archive")
        self.assertLess(tar_i, start_i, "the archive must precede the restart")
        # Product exists, is private, and records the bind + compose file.
        path = Path(result["path"])
        self.assertTrue(path.exists())
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        tar_argv = self.calls[tar_i]
        self.assertIn(str(self.bind_dir), tar_argv)
        self.assertIn(str(self.compose_path), tar_argv)
        del stop_i

    def test_volume_exported_via_throwaway_alpine(self):
        backups.backup_stack("photoprism")
        line = self._joined_calls()[self._index_of("alpine")]
        self.assertIn("photoprism_db-data:/src:ro", line)
        self.assertIn("--rm", line)

    def test_restart_runs_even_when_tar_fails(self):
        """The whole point of the try/finally: a failed archive never leaves
        the stack stopped."""
        self.fail_tar = True
        result = backups.backup_stack("photoprism")
        self.assertFalse(result["ok"])
        self.assertTrue(result["restarted"], "stack must restart after a tar failure")
        self.assertLess(self._index_of("tar czf"), self._index_of("start"))
        self.assertIsNone(result["path"])
        # The pre-created placeholder is discarded, not left as a fake backup.
        leftovers = list((self.backup_root / "appdata" / "photoprism").glob("*.tgz"))
        self.assertEqual(leftovers, [])

    def test_restart_runs_even_when_volume_export_fails(self):
        self.fail_volume_export = True
        result = backups.backup_stack("photoprism")
        self.assertFalse(result["ok"])
        self.assertTrue(result["restarted"])
        self.assertIn("volume export failed", result["message"])

    def test_failed_stop_still_restarts(self):
        """A non-zero stop may still have taken containers down, so the
        restart keys off "stop was attempted", not off its exit code."""
        self.stop_rc = 1
        result = backups.backup_stack("photoprism")
        self.assertTrue(result["stopped"])
        self.assertTrue(result["restarted"])

    def test_failed_restart_is_loud(self):
        self.start_rc = 1
        result = backups.backup_stack("photoprism")
        self.assertFalse(result["ok"], "a stack that did not come back is a failure")
        self.assertIs(result["restarted"], False)
        self.assertIn("DID NOT RESTART", result["message"])

    def test_engine_down_refuses_before_touching_anything(self):
        with mock.patch.object(backups, "_engine_up", lambda: False):
            result = backups.backup_stack("photoprism")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "engine_down")
        self.assertEqual(self.calls, [], "nothing may run when the engine is down")

    def test_unknown_stack(self):
        result = backups.backup_stack("ghost")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "stack_unknown")

    def test_no_stop_first_skips_stop_and_start(self):
        result = backups.backup_stack("photoprism", stop_first=False)
        self.assertTrue(result["ok"])
        self.assertFalse(result["stopped"])
        self.assertIsNone(result["restarted"])
        joined = self._joined_calls()
        self.assertFalse(any(line.endswith("stop") or line.endswith("start")
                             for line in joined))

    def test_retention_prunes_old_archives(self):
        dest_dir = self.backup_root / "appdata" / "photoprism"
        dest_dir.mkdir(parents=True)
        for i in range(4):
            (dest_dir / f"photoprism_2026010{i}_000000.tgz").write_bytes(b"old")
        result = backups.backup_stack("photoprism", retain=2)
        self.assertTrue(result["ok"])
        left = sorted(p.name for p in dest_dir.glob("*.tgz"))
        self.assertEqual(len(left), 2, left)
        self.assertIn(Path(result["path"]).name, left, "the newest survives")

    def test_second_concurrent_run_is_refused(self):
        from fastapi import HTTPException
        lock = backups._job_locks.setdefault("appdata:photoprism", __import__("threading").Lock())
        lock.acquire()
        try:
            with self.assertRaises(HTTPException) as ctx:
                backups.backup_stack("photoprism")
            self.assertEqual(ctx.exception.detail["code"], "backup.busy")
        finally:
            lock.release()


class InflightMarkerTests(_Harness):
    """The crash-recovery marker brackets the stop→start window exactly.

    The try/finally restart only covers Python exceptions; a SIGKILL between
    `compose stop` and the finally leaves the stack stopped with no record.
    The marker is the cross-process record: written before the stop is
    issued, removed once the in-process restart has run.
    """

    def _marker(self) -> Path:
        return backups._inflight_marker("photoprism")

    def test_marker_exists_while_stopped_and_is_cleared_after(self):
        seen = {"at_stop": None, "at_start": None}
        original = backups._run_argv

        def spying_run(argv, *, timeout, **kwargs):
            if argv[-1] == "stop":
                seen["at_stop"] = self._marker().exists()
            if argv[-1] == "start":
                seen["at_start"] = self._marker().exists()
            return original(argv, timeout=timeout, **kwargs)

        with mock.patch.object(backups, "_run_argv", spying_run):
            result = backups.backup_stack("photoprism")
        self.assertTrue(result["ok"], result)
        self.assertTrue(seen["at_stop"], "the marker must exist before compose stop runs")
        self.assertTrue(seen["at_start"], "the marker must survive until the restart")
        self.assertFalse(self._marker().exists(), "a finished backup leaves no marker")

    def test_marker_is_cleared_even_when_the_archive_fails(self):
        self.fail_tar = True
        backups.backup_stack("photoprism")
        self.assertFalse(self._marker().exists())

    def test_no_stop_first_writes_no_marker(self):
        backups.backup_stack("photoprism", stop_first=False)
        self.assertFalse(self._marker().exists())

    def test_write_inflight_leftover_inf_time_does_not_raise(self):
        """int(time.time()) OverflowError on leftover inf used to abort the backup."""
        with mock.patch("hub.backups.time.time", return_value=float("inf")):
            backups._write_inflight("photoprism", str(self.compose_path))
        rec = json.loads(self._marker().read_text())
        json.dumps(rec, allow_nan=False)
        self.assertEqual(rec["ts"], 0)
        self.assertEqual(rec["stack"], "photoprism")

    def test_marker_records_stack_and_compose_path(self):
        captured = {}
        original = backups._run_argv

        def spying_run(argv, *, timeout, **kwargs):
            if argv[-1] == "stop":
                captured.update(json.loads(self._marker().read_text()))
            return original(argv, timeout=timeout, **kwargs)

        with mock.patch.object(backups, "_run_argv", spying_run):
            backups.backup_stack("photoprism")
        self.assertEqual(captured["stack"], "photoprism")
        self.assertEqual(captured["compose_path"], str(self.compose_path))
        self.assertIn("ts", captured)


class StartupRecoveryTests(_Harness):
    """A leftover marker at startup means a backup died mid-flight: the
    stack gets a compose start, the operator gets an alert, the marker goes."""

    def test_leftover_marker_starts_the_stack_alerts_and_clears(self):
        backups._write_inflight("photoprism", str(self.compose_path))
        with mock.patch("hub.alerts.emit_alert") as emit:
            recovered = backups.recover_interrupted_stack_backups()
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0]["stack"], "photoprism")
        self.assertIs(recovered[0]["started"], True)
        started = [c for c in self._joined_calls() if c.endswith("start")]
        self.assertEqual(len(started), 1, self._joined_calls())
        self.assertIn(str(self.compose_path), started[0])
        emit.assert_called_once()
        kwargs = emit.call_args.kwargs
        self.assertEqual(kwargs["alert_id"], "backup:stack:photoprism")
        self.assertEqual(kwargs["level"], "warn")
        self.assertIn("photoprism", kwargs["message"])
        self.assertFalse(backups._inflight_marker("photoprism").exists(),
                         "recovery must not repeat on every future restart")

    def test_failed_start_is_still_alerted_and_marker_cleared(self):
        backups._write_inflight("photoprism", str(self.compose_path))
        self.start_rc = 1
        with mock.patch("hub.alerts.emit_alert") as emit:
            recovered = backups.recover_interrupted_stack_backups()
        self.assertIs(recovered[0]["started"], False)
        self.assertIn("compose start exit 1", recovered[0]["detail"])
        emit.assert_called_once()
        self.assertFalse(backups._inflight_marker("photoprism").exists())

    def test_unparsable_marker_falls_back_to_the_stack_lookup(self):
        backups._inflight_marker("photoprism").write_text("not json {")
        with mock.patch("hub.alerts.emit_alert"):
            recovered = backups.recover_interrupted_stack_backups()
        self.assertEqual(recovered[0]["stack"], "photoprism")
        self.assertIs(recovered[0]["started"], True,
                      "the compose path must come from the stack registry")

    def test_no_marker_no_work(self):
        with mock.patch("hub.alerts.emit_alert") as emit:
            self.assertEqual(backups.recover_interrupted_stack_backups(), [])
        emit.assert_not_called()
        self.assertEqual(self.calls, [])

    def test_broken_alert_pipeline_does_not_stop_recovery(self):
        backups._write_inflight("photoprism", str(self.compose_path))
        with mock.patch("hub.alerts.emit_alert", side_effect=RuntimeError("boom")):
            recovered = backups.recover_interrupted_stack_backups()
        self.assertIs(recovered[0]["started"], True)
        self.assertFalse(backups._inflight_marker("photoprism").exists())


class StackMountsJsonTests(unittest.TestCase):
    def test_a_json_array_is_not_an_object(self):
        with mock.patch.object(backups, "_run_argv", return_value=(0, "[1, 2]", "")):
            binds, volumes, err = backups._stack_mounts("compose.yml", None)
        self.assertEqual(binds, [])
        self.assertEqual(volumes, [])
        self.assertIn("not an object", err)

    def test_non_object_services_are_skipped(self):
        payload = json.dumps({
            "services": {
                "ok": {"volumes": [{"type": "bind", "source": "/tmp"}]},
                "bad": ["not", "a", "mapping"],
            },
            "volumes": {},
        })
        with (
            mock.patch.object(backups, "_run_argv", return_value=(0, payload, "")),
            mock.patch("hub.backups.Path.is_dir", return_value=True),
            mock.patch("hub.backups.Path.is_file", return_value=False),
            mock.patch("hub.backups.Path.is_socket", return_value=False),
        ):
            binds, volumes, err = backups._stack_mounts("compose.yml", None)
        self.assertEqual(err, "")
        self.assertEqual(binds, ["/tmp"])
        self.assertEqual(volumes, [])

    def test_nested_compose_json_does_not_500(self):
        """json.loads RecursionError is not ValueError; leftover nested
        ``compose config`` JSON used to 500 POST /api/backups/stack."""
        nested = '{"k":' * 12000 + "1" + "}" * 12000
        with mock.patch.object(backups, "_run_argv", return_value=(0, nested, "")):
            binds, volumes, err = backups._stack_mounts("compose.yml", None)
        self.assertEqual(binds, [])
        self.assertEqual(volumes, [])
        self.assertTrue(err)
        json.dumps({"err": err}, allow_nan=False)

    def test_compose_json_cap_covers_a_real_resolved_file(self):
        """``run_capped`` tails; a 4KB cap tore every real compose JSON."""
        seen = {}

        def fake_capped(cmd, timeout=10, env=None, cwd=None, cap=2048):
            seen["cap"] = cap
            return 0, json.dumps({"services": {}, "volumes": {}})

        with mock.patch.object(backups, "run_capped", fake_capped):
            _binds, _vols, err = backups._stack_mounts("/tmp/c.yml", None)
        self.assertGreaterEqual(seen["cap"], 64 * 1024)
        self.assertEqual(err, "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
