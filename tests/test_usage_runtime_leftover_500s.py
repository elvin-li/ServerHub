"""Leftover request-path 500s in usage / freshness / stale / worker / sudoers.

A 400-digit ``st_size`` OverflowError'd GET /api/storage/usage/tree (and
duplicates) at ``n / 2**30``; ``default_roots()`` returning None TypeError'd
GET /api/storage/usage; junk Spotlight rows / a None ``run_admin`` payload
AttributeError'd POST /api/storage/spotlight.

YAML ``max_age_hours: 1e400`` / ``.inf`` raised or leaked inf in freshness
parsing; ``int(inf)`` leftover pids leaked into ``scan()`` under
allow_nan=False; ``Path.resolve()`` RuntimeError on a symlink loop crashed
sudoers pinning; a ``-1e308`` beat + huge ``now`` rounded ``age_sec`` to inf.
"""
from __future__ import annotations

import datetime
import json
import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import (
    freshness_svc,
    resource_mode,
    stale_runtime,
    sudoers_policy,
    usage_svc,
    worker_health,
)
from hub.freshness_svc import Target, check_freshness, configured_targets


def _json(payload) -> None:
    json.dumps(payload, allow_nan=False)


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class UsageHugeSizeAndRootsTests(unittest.TestCase):
    def test_huge_st_size_does_not_500_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / "huge").write_text("x", encoding="utf-8")

            class _Entry:
                name = "huge"
                path = str(target / "huge")

                def is_symlink(self):
                    return False

                def is_dir(self, follow_symlinks=False):
                    return False

                def is_file(self, follow_symlinks=False):
                    return True

                def stat(self, follow_symlinks=False):
                    return mock.Mock(st_size=10 ** 400, st_mtime=1.0)

            class _Scan:
                def __enter__(self):
                    return [_Entry()]

                def __exit__(self, *exc):
                    return False

            with (
                mock.patch.object(usage_svc, "_resolve", return_value=target),
                mock.patch.object(
                    usage_svc, "scan_roots",
                    return_value=[{"id": "t", "name": "t", "path": str(target)}],
                ),
                mock.patch.object(usage_svc.os, "scandir", return_value=_Scan()),
            ):
                out = usage_svc.tree(str(target), None)
        _json(out)
        self.assertEqual(out["total_gb"], 0.0)

    def test_leftover_surrogate_entry_name_does_not_500_tree(self):
        """FUSE leftover ``\\ud800`` in a name used to 500 GET /api/storage/usage/tree."""
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / "ok").write_text("x", encoding="utf-8")

            class _Entry:
                name = "ok\ud800"
                path = str(target / "ok")

                def is_symlink(self):
                    return False

                def is_dir(self, follow_symlinks=False):
                    return False

                def is_file(self, follow_symlinks=False):
                    return True

                def stat(self, follow_symlinks=False):
                    return mock.Mock(st_size=1, st_mtime=1.0)

            class _Scan:
                def __enter__(self):
                    return [_Entry()]

                def __exit__(self, *exc):
                    return False

            with (
                mock.patch.object(usage_svc, "_resolve", return_value=target),
                mock.patch.object(
                    usage_svc, "scan_roots",
                    return_value=[{"id": "t", "name": "t", "path": str(target)}],
                ),
                mock.patch.object(usage_svc.os, "scandir", return_value=_Scan()),
            ):
                out = usage_svc.tree(str(target), None)
        _starlette(out)
        self.assertTrue(out["children"])
        self.assertNotIn("\ud800", out["children"][0]["name"])
        self.assertNotIn("\ud800", out["children"][0]["path"])

    def test_huge_duplicate_size_does_not_500(self):
        huge = 10 ** 400
        with (
            mock.patch.object(usage_svc, "_resolve", return_value=Path("/tmp")),
            mock.patch.object(
                usage_svc, "_walk_parallel",
                return_value=[{huge: ["/tmp/a", "/tmp/b"]}],
            ),
            mock.patch.object(
                usage_svc, "_hash_group",
                side_effect=lambda paths, budget, partial: ["abc"] * len(paths),
            ),
        ):
            out = usage_svc.duplicates("/", None, 1.0)
        _json(out)
        self.assertEqual(out["reclaimable_gb"], 0.0)
        self.assertEqual(out["groups"][0]["gb"], 0.0)

    def test_leftover_surrogate_duplicate_paths_do_not_500(self):
        """FUSE leftover ``\\ud800`` in duplicate paths used to 500 GET /api/storage/usage/duplicates."""
        with (
            mock.patch.object(usage_svc, "_resolve", return_value=Path("/tmp")),
            mock.patch.object(
                usage_svc, "_walk_parallel",
                return_value=[{1024 * 1024: ["/tmp/a\ud800", "/tmp/b\ud800"]}],
            ),
            mock.patch.object(
                usage_svc, "_hash_group",
                side_effect=lambda paths, budget, partial: ["abc"] * len(paths),
            ),
        ):
            out = usage_svc.duplicates("/", None, 1.0)
        _starlette(out)
        self.assertTrue(out["groups"])
        for path in out["groups"][0]["paths"]:
            self.assertNotIn("\ud800", path)
        self.assertNotIn("\ud800", out["path"])

    def test_leftover_surrogate_hash_path_does_not_500(self):
        """``open()`` of leftover ``\\ud800`` used to 500 GET /api/storage/usage/duplicates."""
        self.assertIsNone(usage_svc._hash_file(Path("/tmp/a\ud800"), partial=True))
        self.assertIsNone(usage_svc._hash_file(Path("/tmp/a\ud800"), partial=False))

    def test_leftover_surrogate_spotlight_volume_does_not_500(self):
        child = mock.Mock()
        child.__str__ = lambda self: "/Volumes/Data\ud800"
        child.is_dir.return_value = True
        child.is_symlink.return_value = False
        with (
            mock.patch.object(Path, "is_dir", autospec=True, return_value=True),
            mock.patch.object(Path, "iterdir", return_value=[child]),
            mock.patch.object(
                usage_svc, "fan_out",
                return_value=[(0, "Indexing enabled."), (0, "Indexing enabled.")],
            ),
        ):
            rows = usage_svc.spotlight_status()
        _starlette(rows)
        dumped = json.dumps(rows, ensure_ascii=False, allow_nan=False)
        self.assertNotIn("\ud800", dumped)

    def test_none_default_roots_do_not_500_scan_roots(self):
        with (
            mock.patch.object(usage_svc.files_svc, "default_roots", return_value=None),
            mock.patch("hub.shares_svc.list_smb_shares", return_value=[]),
        ):
            roots = usage_svc.scan_roots()
        _json(roots)

    def test_int_default_roots_do_not_500_scan_roots(self):
        with (
            mock.patch.object(usage_svc.files_svc, "default_roots", return_value=5),
            mock.patch("hub.shares_svc.list_smb_shares", return_value=[]),
        ):
            roots = usage_svc.scan_roots()
        _json(roots)

    def test_junk_spotlight_rows_do_not_500_set(self):
        with (
            mock.patch.object(
                usage_svc, "spotlight_status",
                return_value=["x", None, 5, {"volume": "/"}],
            ),
            mock.patch("hub.macos_admin.run_admin", return_value={"ok": True}),
        ):
            out = usage_svc.set_spotlight("/", True)
        _json(out)
        self.assertTrue(out["ok"])

    def test_none_run_admin_does_not_500_set(self):
        with (
            mock.patch.object(
                usage_svc, "spotlight_status",
                return_value=[{"volume": "/"}],
            ),
            mock.patch("hub.macos_admin.run_admin", return_value=None),
        ):
            out = usage_svc.set_spotlight("/", False)
        _json(out)
        self.assertFalse(out["ok"])


class FreshnessLeftoverTests(unittest.TestCase):
    def test_huge_and_nonfinite_max_age_are_skipped(self):
        parsed = configured_targets([
            {"id": "huge", "pattern": "/x/*.log", "max_age_hours": 10 ** 500},
            {"id": "inf", "pattern": "/x/*.log", "max_age_hours": float("inf")},
            {"id": "nan", "pattern": "/x/*.log", "max_age_hours": float("nan")},
            {"id": "good", "pattern": "/x/*.log", "max_age_hours": 25},
        ])
        self.assertEqual([t.id for t in parsed], ["good"])

    def test_bytes_date_and_set_entries_do_not_raise(self):
        parsed = configured_targets([
            {"a", "b"},
            {"id": b"good", "pattern": "/x/*.log", "max_age_hours": 25},
            {"id": "d", "pattern": datetime.date(2026, 8, 19), "max_age_hours": 25},
            {"id": "ok", "pattern": "/x/*.log", "max_age_hours": 26},
        ])
        self.assertEqual([t.id for t in parsed], ["good", "ok"])

    def _sweep(self, **kwargs):
        target = Target(
            id="t1", label="local.x", pattern="/no/such/*.tgz", max_age_hours=25,
        )
        with (
            mock.patch("hub.alerts.notify_settings", lambda: {"enabled": False}),
            mock.patch("hub.alerts._append_alert", lambda alert: None),
        ):
            return check_freshness(targets=(target,), **kwargs)

    def test_non_dict_prev_and_state_do_not_500(self):
        emitted = self._sweep(prev=None, new_state={}, now=1_800_000_000)
        _json(emitted)
        self.assertEqual(self._sweep(prev=[], new_state={}, now=1_800_000_000), emitted)
        self.assertEqual(self._sweep(prev={}, new_state=[], now=1_800_000_000), [])

    def test_infinite_now_does_not_500_json(self):
        emitted = self._sweep(prev={}, new_state={}, now=float("inf"))
        _json(emitted)
        emitted = self._sweep(prev={}, new_state={}, now=datetime.date(2026, 8, 19))
        _json(emitted)

    def test_date_mtime_does_not_500(self):
        with mock.patch.object(
            freshness_svc, "newest_mtime", return_value=datetime.date(2026, 8, 19),
        ):
            emitted = self._sweep(prev={}, new_state={}, now=1_800_000_000)
        _json(emitted)

    def test_expanduser_runtimeerror_does_not_500(self):
        """``Path.home`` / expanduser RuntimeError used to 500 POST /api/alerts/check."""
        with mock.patch.object(
            freshness_svc.os.path, "expanduser", side_effect=RuntimeError("no home"),
        ):
            parsed = configured_targets([
                {"id": "good", "pattern": "~/x/*.log", "max_age_hours": 25},
            ])
        self.assertEqual(parsed, ())

    def test_leftover_surrogate_label_does_not_500(self):
        parsed = configured_targets([
            {"id": "good", "label": "job\ud800", "pattern": "/x/*.log", "max_age_hours": 25},
        ])
        self.assertEqual(len(parsed), 1)
        self.assertNotIn("\ud800", parsed[0].label)
        _starlette({"label": parsed[0].label, "pattern": parsed[0].pattern})

        target = Target(
            id="t1", label="local.x\ud800", pattern="/no/such/*.tgz", max_age_hours=25,
        )
        with (
            mock.patch("hub.alerts.notify_settings", lambda: {"enabled": False}),
            mock.patch("hub.alerts._append_alert", lambda alert: None),
        ):
            emitted = check_freshness(
                prev={}, new_state={}, now=1_800_000_000, targets=(target,),
            )
        _starlette(emitted)
        self.assertTrue(emitted)
        self.assertNotIn("\ud800", emitted[0]["name"])
        self.assertNotIn("\ud800", emitted[0]["message"])

    def test_require_dir_leftover_does_not_500(self):
        parsed = configured_targets([
            {"id": "good", "pattern": "/x/*.log", "max_age_hours": 25,
             "require_dir": "/Volumes/X\ud800"},
        ])
        self.assertEqual(len(parsed), 1)
        self.assertTrue(parsed[0].require_dir)
        self.assertNotIn("\ud800", parsed[0].require_dir)
        _starlette({"require_dir": parsed[0].require_dir})

        def expand(path):
            text = str(path)
            if text.startswith("~"):
                raise RuntimeError("no home")
            return text

        with mock.patch.object(freshness_svc.os.path, "expanduser", side_effect=expand):
            parsed = configured_targets([
                {"id": "good", "pattern": "/x/*.log", "max_age_hours": 25,
                 "require_dir": "~/Volumes/X"},
            ])
        self.assertEqual(len(parsed), 1)
        self.assertIsNone(parsed[0].require_dir)


class StaleRuntimeInfPidTests(unittest.TestCase):
    def test_leftover_surrogate_label_does_not_500_health(self):
        """Leftover ``\\ud800`` in a plist Label used to 500 GET /api/health/checks."""
        with mock.patch.object(stale_runtime, "scan", return_value=[{
            "label": "local.x\ud800", "pid": 1, "exe": "/gone\ud800",
        }]):
            checks = stale_runtime.health_checks()
        _starlette(checks)
        self.assertNotIn("\ud800", checks[0]["detail"])
        self.assertNotIn("\ud800", checks[0]["fix"])

    def test_infinite_pid_does_not_500_scan_json(self):
        class _Listing:
            def pid_for(self, label):
                return float("inf")

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "local.x.plist"
            path.write_bytes(plistlib.dumps({"Label": "local.x"}))
            with (
                mock.patch.object(stale_runtime, "AGENTS_DIR", Path(tmp)),
                mock.patch.object(
                    stale_runtime, "launchd_listing", lambda: _Listing(),
                ),
                mock.patch.object(
                    stale_runtime, "pid_exe_path", lambda pid: "/gone",
                ),
            ):
                rows = stale_runtime.scan()
                checks = stale_runtime.health_checks()
        _json(rows)
        _json(checks)
        self.assertEqual(rows[0]["pid"], 0)

    def test_huge_plist_does_not_oom_scan(self):
        """``open(rb)`` of leftover multi-MB LaunchAgent used to OOM GET /api/health/checks."""
        class _Listing:
            def pid_for(self, label):
                return "4242"

        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "huge.plist").write_bytes(b"x" * (2 * 1024 * 1024))
            (Path(tmp) / "local.x.plist").write_bytes(plistlib.dumps({"Label": "local.x"}))
            with (
                mock.patch.object(stale_runtime, "AGENTS_DIR", Path(tmp)),
                mock.patch.object(
                    stale_runtime, "launchd_listing", lambda: _Listing(),
                ),
                mock.patch.object(
                    stale_runtime, "pid_exe_path", lambda pid: "/gone",
                ),
            ):
                rows = stale_runtime.scan()
        _json(rows)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["label"], "local.x")


class WorkerHealthAgeJsonTests(unittest.TestCase):
    def setUp(self):
        self._saved = dict(worker_health._workers)
        worker_health._workers.clear()
        self.addCleanup(self._restore)

    def _restore(self):
        worker_health._workers.clear()
        worker_health._workers.update(self._saved)

    def test_huge_negative_beat_does_not_500_json(self):
        worker_health.register("w", 10, thread=None)
        worker_health._workers["w"]["beat"] = -1e308
        snap = worker_health.snapshot(now=1e308)
        _json(snap)
        self.assertNotIn(snap[0]["age_sec"], (float("inf"), float("-inf")))
        self.assertNotIn(snap[0]["interval"], (float("inf"), float("-inf")))

    def test_leftover_surrogate_name_does_not_500(self):
        worker_health.register("w\ud800", 10, thread=None)
        snap = worker_health.snapshot()
        probs = worker_health.problems(rows=snap)
        _starlette(snap)
        _starlette(probs)
        self.assertNotIn("\ud800", snap[0]["name"])

    def test_dirty_row_surrogate_does_not_500_problems(self):
        """Leftover ``\\ud800`` planted in a snapshot row used to 500 health JSON."""
        probs = worker_health.problems(rows=[{
            "name": "w\ud800", "alive": False, "stale": True,
            "age_sec": float("inf"), "interval": float("inf"),
        }])
        _starlette(probs)
        self.assertTrue(probs)
        self.assertNotIn("\ud800", probs[0])

    def test_overflow_interval_is_clamped(self):
        worker_health.register("w", 1e308, thread=None)
        snap = worker_health.snapshot()
        _json(snap)
        self.assertEqual(snap[0]["interval"], 60.0)


class SudoersPathLeftoverTests(unittest.TestCase):
    def test_symlink_loop_does_not_raise(self):
        with tempfile.TemporaryDirectory() as tmp:
            loop = Path(tmp) / "loop"
            loop.symlink_to(loop)
            self.assertTrue(sudoers_policy.user_writable(str(loop)))

    def test_is_symlink_eio_does_not_raise(self):
        with tempfile.TemporaryDirectory() as tmp:
            tool = Path(tmp) / "tool"
            tool.write_text("x")
            with mock.patch.object(
                Path, "is_symlink", autospec=True,
                side_effect=OSError(5, "I/O error"),
            ):
                sudoers_policy.user_writable(str(tool))

    def test_exists_eio_does_not_raise(self):
        with tempfile.TemporaryDirectory() as tmp:
            tool = Path(tmp) / "tool"
            tool.write_text("x")
            with mock.patch.object(
                Path, "exists", autospec=True,
                side_effect=OSError(5, "I/O error"),
            ):
                sudoers_policy.user_writable(str(tool))

    def test_resolve_runtimeerror_does_not_raise(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp) / "real"
            real.write_text("x")
            link = Path(tmp) / "link"
            link.symlink_to(real)
            with mock.patch.object(
                Path, "resolve", autospec=True,
                side_effect=RuntimeError("symlink loop"),
            ):
                sudoers_policy.user_writable(str(link))

    def test_none_bytes_and_date_paths_do_not_raise(self):
        self.assertTrue(sudoers_policy.user_writable(None))
        self.assertTrue(sudoers_policy.user_writable(float("inf")))
        self.assertTrue(sudoers_policy.user_writable(datetime.date(2026, 8, 19)))
        self.assertTrue(sudoers_policy.user_writable(b"/usr/bin/pmset"))


class UsageInfClockStrftimeLeftoverTests(unittest.TestCase):
    def test_overflow_strftime_does_not_500_overview(self):
        """Leftover inf clock OverflowError'd GET /api/storage/usage ``ts``."""
        with (
            mock.patch("hub.util.time.strftime", side_effect=OverflowError),
            mock.patch.object(usage_svc, "scan_roots", return_value=[]),
            mock.patch.object(usage_svc, "spotlight_status", return_value={}),
        ):
            out = usage_svc.overview()
        _starlette(out)
        self.assertEqual(out["ts"], "")


class FreshnessWorkerUtf8TextRecursionLeftoverTests(unittest.TestCase):
    def test_utf8_text_recursing_does_not_500(self):
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(freshness_svc._utf8_text(Recursing()), "Recursing")
        self.assertEqual(worker_health._utf8_text(Recursing()), "Recursing")
        _starlette({"k": freshness_svc._utf8_text(Recursing())})
        _starlette({"k": worker_health._utf8_text(Recursing())})


class ResourceModeLeftoverTests(unittest.TestCase):
    def test_list_scalar_inf_bytes_date_and_set_do_not_500(self):
        leftovers = (
            {"settings": []},
            {"settings": None},
            {"settings": "high"},
            {"settings": {"resource_mode": float("inf")}},
            {"settings": {"resource_mode": float("nan")}},
            {"settings": {"resource_mode": b"high"}},
            {"settings": {"resource_mode": datetime.date(2026, 8, 19)}},
            {"settings": {"resource_mode": {"high"}}},
            [],
            None,
        )
        for cfg in leftovers:
            with self.subTest(cfg=cfg), mock.patch(
                "hub.resource_mode.cfg", return_value=cfg,
            ):
                self.assertEqual(resource_mode.resource_mode(), "low")
                self.assertFalse(resource_mode.is_high())


if __name__ == "__main__":
    unittest.main()
