"""The app lifespan actually starts the background workers it promises.

The SMART self-test scheduler existed for months with zero callers: the
schedule UI stored a plan, the scheduler page even displayed its next_run,
and no thread ever ran a test.  This file pins "declared in lifespan" to
"actually started", so a worker cannot silently fall out of startup again.

Every worker start is mocked — no sampler, alerter or cron engine thread is
really spawned by these tests.
"""
from __future__ import annotations

import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import (  # noqa: E402
    alerts, app_factory, backups, metrics, network_svc, scheduler_svc,
    smart_test_svc, tools_svc,
)
from hub.app_factory import create_app  # noqa: E402


class LifespanWorkerTests(unittest.TestCase):
    def _quiet_lifespan(self, **overrides):
        """Patch every worker start/stop to a no-op mock; return the mocks."""
        mocks = {}
        for module, names in (
            (metrics, ("start_sampler", "stop_sampler")),
            (alerts, ("start_alerter", "stop_alerter")),
            (scheduler_svc, ("start_scheduler", "stop_scheduler")),
            (smart_test_svc, ("start_scheduler", "stop_scheduler")),
            (tools_svc, ("start_updates_warmer", "stop_updates_warmer")),
            (network_svc, ("start_alias_autobind", "stop_alias_autobind")),
            (backups, ("recover_interrupted_stack_backups",)),
        ):
            for name in names:
                key = f"{module.__name__.rsplit('.', 1)[-1]}.{name}"
                patched = mock.patch.object(
                    module, name, overrides.get(key, mock.MagicMock()),
                )
                mocks[key] = patched.start()
                self.addCleanup(patched.stop)
        return mocks

    def test_lifespan_starts_and_stops_the_smart_test_scheduler(self):
        from fastapi.testclient import TestClient

        mocks = self._quiet_lifespan()
        with TestClient(create_app()):
            mocks["smart_test_svc.start_scheduler"].assert_called_once()
            mocks["smart_test_svc.stop_scheduler"].assert_not_called()
        mocks["smart_test_svc.stop_scheduler"].assert_called_once()

    def test_lifespan_scans_for_interrupted_stack_backups(self):
        from fastapi.testclient import TestClient

        ran = threading.Event()
        mocks = self._quiet_lifespan(
            **{"backups.recover_interrupted_stack_backups": lambda: ran.set()},
        )
        with TestClient(create_app()):
            # The scan runs on its own thread (a compose start can take
            # minutes and must not hold up startup), so wait for it briefly.
            self.assertTrue(ran.wait(timeout=5),
                            "the recovery scan never ran during startup")
        del mocks

    def test_lifespan_does_not_start_the_updates_warmer(self):
        from fastapi.testclient import TestClient

        mocks = self._quiet_lifespan()
        with TestClient(create_app()):
            mocks["tools_svc.start_updates_warmer"].assert_not_called()
        mocks["tools_svc.stop_updates_warmer"].assert_called_once()

    def test_inf_and_bool_intervals_do_not_crash_lifespan(self):
        """YAML ``metrics_interval: .inf`` used to OverflowError startup.

        ``true`` is a bool subclass of int and used to start the sampler at 1s.
        """
        from fastapi.testclient import TestClient

        mocks = self._quiet_lifespan()
        with mock.patch.object(
            app_factory, "cfg",
            return_value={"settings": {
                "metrics_interval": float("inf"),
                "alert_interval": True,
            }},
        ):
            with TestClient(create_app()):
                mocks["metrics.start_sampler"].assert_called_once_with(90)
                mocks["alerts.start_alerter"].assert_called_once_with(90)

    def test_smart_scheduler_start_is_idempotent(self):
        """Lifespan may run more than once per process (tests, reloads); a
        second start must reuse the live thread, not stack another."""
        stop = threading.Event()
        self.addCleanup(stop.set)
        fake_thread = threading.Thread(target=stop.wait, daemon=True)
        fake_thread.start()
        with mock.patch.object(smart_test_svc, "_scheduler_thread", fake_thread), \
             mock.patch.object(smart_test_svc, "_scheduler_stop", stop):
            smart_test_svc.start_scheduler()
            self.assertIs(
                smart_test_svc._scheduler_thread, fake_thread,
                "a live scheduler thread must be reused, not replaced",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
