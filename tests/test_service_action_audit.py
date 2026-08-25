"""Service lifecycle mutations must leave an audit record.

POST /api/action starts, stops or restarts a workload, POST
/api/services/bulk-action does it for many at once, POST
/api/services/{sid}/uninstall unregisters a launch agent, and POST
/api/maintenance/{tid}/run kicks a repo-defined script — the panel's
most-used privileged mutations, and until now the only ones that left no
trail at all.  The power, NFS/RAID, WireGuard, scheduler and notify routers
all record the operator and the caller's IP; these join them.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from fastapi import HTTPException  # noqa: E402

from hub import audit  # noqa: E402
from hub.routers import api as api_router  # noqa: E402
from hub.routers import services_api  # noqa: E402


class _AuditSandbox(unittest.TestCase):
    """Capture audit.record calls made through a router module."""

    module = None  # set by subclasses

    def setUp(self):
        self.calls: list = []

        def _record(event, **fields):
            self.calls.append((event, fields))

        for patched in (
            mock.patch.object(self.module.audit, "record", _record),
            mock.patch.object(self.module.auth, "request_username", lambda r: "admin"),
            mock.patch.object(self.module.auth, "request_client_id", lambda r: "10.0.0.9"),
        ):
            patched.start()
            self.addCleanup(patched.stop)


def _request():
    """A request whose auth kind is a browser session, not the local client."""
    req = mock.Mock()
    req.state = mock.Mock(spec=[])  # no serverhub_auth_kind attribute
    return req


class ApiActionAuditTests(_AuditSandbox):
    module = api_router

    def test_a_successful_action_records_operator_client_target_and_outcome(self):
        with mock.patch.object(api_router.actions, "run_action",
                               return_value=(0, "started", "")):
            api_router.api_action(
                api_router.Action(target="svc.immich", action="restart"),
                request=_request(),
            )
        self.assertEqual(len(self.calls), 1, self.calls)
        event, fields = self.calls[0]
        self.assertEqual(event, audit.SERVICE_ACTION)
        self.assertEqual(fields["username"], "admin")
        self.assertEqual(fields["client"], "10.0.0.9")
        self.assertEqual(fields["target"], "svc.immich")
        self.assertEqual(fields["action"], "restart")
        self.assertIs(fields["ok"], True)

    def test_a_failed_action_still_records_with_ok_false(self):
        """A stop that exited non-zero is still an operator acting on the host."""
        with mock.patch.object(api_router.actions, "run_action",
                               return_value=(1, "", "boom")):
            api_router.api_action(
                api_router.Action(target="svc.immich", action="stop"),
                request=_request(),
            )
        self.assertEqual(len(self.calls), 1, self.calls)
        _, fields = self.calls[0]
        self.assertIs(fields["ok"], False)

    def test_a_rejected_action_leaves_no_record(self):
        """run_action raises before touching anything on an unknown target."""
        def _raise(target, action):
            raise HTTPException(status_code=404,
                                detail={"code": "service.unknown"})

        with mock.patch.object(api_router.actions, "run_action", _raise):
            with self.assertRaises(HTTPException):
                api_router.api_action(
                    api_router.Action(target="nope", action="start"),
                    request=_request(),
                )
        self.assertEqual(self.calls, [])


class MaintenanceRunAuditTests(_AuditSandbox):
    module = api_router

    def test_a_started_task_is_recorded(self):
        task = {"id": "clean-logs", "cmd": ["true"]}
        with mock.patch.object(api_router.jobs, "maintenance_tasks",
                               return_value={"clean-logs": task}), \
             mock.patch.object(api_router.jobs, "start_job") as start:
            api_router.api_maintenance_run("clean-logs", request=_request())
        start.assert_called_once_with(task)
        self.assertEqual(len(self.calls), 1, self.calls)
        event, fields = self.calls[0]
        self.assertEqual(event, audit.MAINTENANCE_RUN)
        self.assertEqual(fields["username"], "admin")
        self.assertEqual(fields["client"], "10.0.0.9")
        self.assertEqual(fields["task"], "clean-logs")

    def test_an_unknown_task_leaves_no_record(self):
        with mock.patch.object(api_router.jobs, "maintenance_tasks",
                               return_value={}):
            with self.assertRaises(HTTPException):
                api_router.api_maintenance_run("nope", request=_request())
        self.assertEqual(self.calls, [])

    def test_callable_in_process_without_a_request(self):
        """FastAPI always injects `request`; the None default keeps direct
        in-process calls working, recording an empty operator."""
        task = {"id": "clean-logs", "cmd": ["true"]}
        with mock.patch.object(api_router.jobs, "maintenance_tasks",
                               return_value={"clean-logs": task}), \
             mock.patch.object(api_router.jobs, "start_job"):
            api_router.api_maintenance_run("clean-logs")
        self.assertEqual(len(self.calls), 1, self.calls)
        _, fields = self.calls[0]
        self.assertEqual(fields["username"], "")


class BulkActionAuditTests(_AuditSandbox):
    module = services_api

    def test_one_record_per_request_with_targets_and_counts(self):
        """One line per bulk call, not per id: the trail is capped and evicts
        oldest-first, so a forty-service stop must not push forty real
        security events out."""
        outcomes = {"a": (0, "ok", ""), "b": (1, "", "err")}
        with mock.patch.object(services_api.actions, "run_action",
                               side_effect=lambda sid, act: outcomes[sid]):
            services_api.services_bulk(
                services_api.BulkActionBody(ids=["a", "b"], action="stop"),
                request=_request(),
            )
        self.assertEqual(len(self.calls), 1, self.calls)
        event, fields = self.calls[0]
        self.assertEqual(event, audit.SERVICE_BULK_ACTION)
        self.assertEqual(fields["username"], "admin")
        self.assertEqual(fields["client"], "10.0.0.9")
        self.assertEqual(fields["action"], "stop")
        self.assertEqual(fields["targets"], "a,b")
        self.assertEqual(fields["ok_count"], 1)
        self.assertEqual(fields["fail_count"], 1)

    def test_a_bad_action_leaves_no_record(self):
        with self.assertRaises(HTTPException):
            services_api.services_bulk(
                services_api.BulkActionBody(ids=["a"], action="explode"),
                request=_request(),
            )
        self.assertEqual(self.calls, [])


class UninstallAuditTests(_AuditSandbox):
    module = services_api

    def test_a_completed_uninstall_is_recorded(self):
        with mock.patch.object(services_api.auth, "browser_authenticated",
                               return_value=True), \
             mock.patch.object(services_api.services_uninstall_svc, "uninstall",
                               return_value={"ok": True}) as svc:
            services_api.services_uninstall(
                "svc.immich", request=_request(),
                body=services_api.UninstallBody(remove_data=True),
            )
        svc.assert_called_once_with("svc.immich", remove_data=True)
        self.assertEqual(len(self.calls), 1, self.calls)
        event, fields = self.calls[0]
        self.assertEqual(event, audit.SERVICE_UNINSTALLED)
        self.assertEqual(fields["username"], "admin")
        self.assertEqual(fields["client"], "10.0.0.9")
        self.assertEqual(fields["target"], "svc.immich")
        self.assertIs(fields["remove_data"], True)

    def test_a_denied_uninstall_leaves_no_record(self):
        with mock.patch.object(services_api.auth, "browser_authenticated",
                               return_value=False):
            with self.assertRaises(HTTPException):
                services_api.services_uninstall("svc.immich", request=_request())
        self.assertEqual(self.calls, [])

    def test_a_failed_uninstall_leaves_no_record(self):
        """uninstall() raises on an unknown or protected service — nothing was
        unregistered, so nothing is written."""
        def _raise(sid, remove_data=False):
            raise HTTPException(status_code=404,
                                detail={"code": "services.unknown"})

        with mock.patch.object(services_api.auth, "browser_authenticated",
                               return_value=True), \
             mock.patch.object(services_api.services_uninstall_svc,
                               "uninstall", _raise):
            with self.assertRaises(HTTPException):
                services_api.services_uninstall("svc.immich", request=_request())
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
