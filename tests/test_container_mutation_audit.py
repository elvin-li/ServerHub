"""Container-engine mutations must leave an audit record.

Creating a container chooses its mounts and privilege level, exec runs an
arbitrary command inside one (the Terminal page's docker-exec twin has always
written the command it ran into its 0600 trail), and image/volume/network
removal and prune destroy data.  None of it recorded who did it.
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
from hub.routers import containers  # noqa: E402


class _AuditSandbox(unittest.TestCase):
    def setUp(self):
        self.calls: list = []

        def _record(event, **fields):
            self.calls.append((event, fields))

        for patched in (
            mock.patch.object(containers.audit, "record", _record),
            mock.patch.object(containers.auth, "request_username", lambda r: "admin"),
            mock.patch.object(containers.auth, "request_client_id", lambda r: "10.0.0.9"),
        ):
            patched.start()
            self.addCleanup(patched.stop)

    def only_call(self):
        self.assertEqual(len(self.calls), 1, self.calls)
        return self.calls[0]

    def assert_operator(self, fields):
        self.assertEqual(fields["username"], "admin")
        self.assertEqual(fields["client"], "10.0.0.9")


class RunAuditTests(_AuditSandbox):
    def test_records_image_mounts_and_privilege(self):
        body = containers.RunBody(
            image="nginx:latest", name="web",
            volumes=["/srv:/data", "/:/host"], privileged=True,
            env=["API_TOKEN=hunter2"],
        )
        with mock.patch.object(containers.svc, "create_run_container",
                               return_value={"ok": True}):
            containers.containers_run(body, request=mock.Mock())
        event, fields = self.only_call()
        self.assertEqual(event, audit.CONTAINER_RUN)
        self.assert_operator(fields)
        self.assertEqual(fields["image"], "nginx:latest")
        self.assertEqual(fields["volumes"], "/srv:/data,/:/host")
        self.assertIs(fields["privileged"], True)
        # env may carry secrets and is deliberately not recorded.
        self.assertNotIn("env", fields)

    def test_a_rejected_run_leaves_no_record(self):
        def _raise(spec):
            raise HTTPException(status_code=400,
                                detail={"code": "container.bad_image"})

        with mock.patch.object(containers.svc, "create_run_container", _raise):
            with self.assertRaises(HTTPException):
                containers.containers_run(
                    containers.RunBody(image="-bad"), request=mock.Mock())
        self.assertEqual(self.calls, [])


class ExecAuditTests(_AuditSandbox):
    def test_records_container_shell_command_and_outcome(self):
        with mock.patch.object(containers.svc, "exec_in_container",
                               return_value={"ok": True, "rc": 0, "output": ""}):
            containers.container_exec(
                "db", containers.ExecBody(command="ls /", shell="/bin/sh"),
                request=mock.Mock())
        event, fields = self.only_call()
        self.assertEqual(event, audit.CONTAINER_EXEC)
        self.assert_operator(fields)
        self.assertEqual(fields["container"], "db")
        self.assertEqual(fields["command"], "ls /")
        self.assertIs(fields["ok"], True)

    def test_the_recorded_command_is_capped(self):
        """One pasted script must not evict half the capped trail."""
        with mock.patch.object(containers.svc, "exec_in_container",
                               return_value={"ok": True, "rc": 0, "output": ""}):
            containers.container_exec(
                "db", containers.ExecBody(command="x" * 10_000),
                request=mock.Mock())
        _, fields = self.only_call()
        self.assertEqual(len(fields["command"]), 300)


class LifecycleAuditTests(_AuditSandbox):
    def test_batch_writes_one_line_with_all_targets(self):
        with mock.patch.object(containers.svc, "batch_action",
                               return_value={"ok": True}):
            containers.containers_batch(
                containers.BatchBody(action="stop", names=["a", "b", "c"]),
                request=mock.Mock())
        event, fields = self.only_call()
        self.assertEqual(event, audit.CONTAINER_ACTION)
        self.assert_operator(fields)
        self.assertEqual(fields["action"], "stop")
        self.assertEqual(fields["targets"], "a,b,c")

    def test_single_action_and_update_record_their_target(self):
        with mock.patch.object(containers.svc, "container_action",
                               return_value={"ok": True}):
            containers.container_action(
                "web", containers.CAction(action="restart"), request=mock.Mock())
        with mock.patch.object(containers.svc, "start_update_container_job",
                               return_value={"ok": True}):
            containers.container_update("web", request=mock.Mock())
        self.assertEqual(len(self.calls), 2, self.calls)
        self.assertEqual(self.calls[0][1]["targets"], "web")
        self.assertEqual(self.calls[0][1]["action"], "restart")
        self.assertEqual(self.calls[1][1]["action"], "update")

    def test_stack_run_names_the_stack(self):
        with mock.patch.object(containers.svc, "start_stack_job",
                               return_value={"job": "j1"}):
            containers.stack_run("media", containers.StackAction(action="up"),
                                 request=mock.Mock())
        _, fields = self.only_call()
        self.assertEqual(fields["targets"], "stack:media")


class ResourceAuditTests(_AuditSandbox):
    def test_image_volume_network_and_prune_are_recorded(self):
        with mock.patch.object(containers.svc, "remove_image",
                               return_value={"ok": True}):
            containers.images_remove(
                containers.ImageBody(image="old:1", force=True),
                request=mock.Mock())
        with mock.patch.object(containers.svc, "remove_volume",
                               return_value={"ok": True}):
            containers.volumes_remove(
                containers.NameBody(name="data"), request=mock.Mock())
        with mock.patch.object(containers.svc, "remove_network",
                               return_value={"ok": True}):
            containers.networks_remove(
                containers.NameBody(name="net0"), request=mock.Mock())
        with mock.patch.object(containers.svc, "prune",
                               return_value={"ok": True}):
            containers.prune(containers.PruneBody(kind="images"),
                             request=mock.Mock())
        events = [event for event, _ in self.calls]
        self.assertEqual(events, [
            audit.CONTAINER_IMAGE_CHANGED,
            audit.CONTAINER_VOLUME_CHANGED,
            audit.CONTAINER_NETWORK_CHANGED,
            audit.CONTAINER_PRUNED,
        ])
        for _, fields in self.calls:
            self.assert_operator(fields)

    def test_config_changes_record_field_and_value(self):
        with mock.patch.object(containers.svc, "rename_container",
                               return_value={"ok": True}):
            containers.container_rename(
                "web", containers.RenameBody(new_name="web2"),
                request=mock.Mock())
        _, fields = self.only_call()
        self.assertEqual(fields["field"], "name")
        self.assertEqual(fields["value"], "web2")


if __name__ == "__main__":
    unittest.main()
