"""Leftover type 500s on docker CLI, container lists, compose save, Apps logs.

None/bytes/int docker stdout, a compose tree that cannot be glob'd, a
``containers: 5`` leftover, non-str compose content, and ``lines=inf``
each used to raise on the request path instead of skipping or clamping.

Follow-up: YAML ``name: .inf`` / a date group, leftover Infinity in
docker-update-status.json and docker inspect/NDJSON, and leftover bytes
from ``docker compose config`` each 500'd Starlette's allow_nan=False encoder.

Follow-up 2: leftover ``run_capped`` bytes/None on container recreate
used to TypeError the job-log JSON.
"""
from __future__ import annotations

import asyncio
import datetime
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hub import apps_manage_svc, compose_svc, containers_svc, docker_cli


def _json(payload) -> None:
    json.dumps(payload, allow_nan=False)


PS_LINE = "abc123\tnginx\tnginx:latest\trunning\tUp\t\t\t\t\n"


class DockerJsonTypingTests(unittest.TestCase):
    def test_none_bytes_and_int_payloads_do_not_500(self):
        with mock.patch.object(docker_cli, "docker", return_value=(0, None, "")):
            data, rc, err = docker_cli.docker_json(
                ["images", "--format", "{{json .}}"]
            )
        self.assertEqual(rc, 0)
        self.assertEqual(data, [])

        with mock.patch.object(
            docker_cli, "docker",
            return_value=(0, b'{"Id":"x"}\n{"Id":"y"}', ""),
        ):
            data, rc, err = docker_cli.docker_json(
                ["images", "--format", "{{json .}}"]
            )
        self.assertEqual(data, [{"Id": "x"}, {"Id": "y"}])

        with mock.patch.object(docker_cli, "docker", return_value=(0, 42, "")):
            data, rc, err = docker_cli.docker_json(["images"])
        self.assertEqual(data, [])

    def test_infinity_size_does_not_500_json(self):
        """Python json.loads accepts Infinity; Starlette allow_nan=False does not."""
        with mock.patch.object(
            docker_cli, "docker",
            return_value=(0, '{"Id":"x","Size":Infinity,"SharedSize":NaN}\n', ""),
        ):
            data, rc, err = docker_cli.docker_json(
                ["images", "--format", "{{json .}}"]
            )
        self.assertEqual(rc, 0)
        self.assertEqual(data[0]["Id"], "x")
        self.assertIsNone(data[0]["Size"])
        self.assertIsNone(data[0]["SharedSize"])
        _json(data)


class ContainerListTypingTests(unittest.TestCase):
    def test_none_and_bytes_ps_do_not_500(self):
        def fake_docker(*args, **kwargs):
            if args and args[0] == "ps":
                return (0, b"" + PS_LINE.encode(), "")
            return (0, "[]", "")

        with mock.patch.object(containers_svc, "engine_up", return_value=True), \
             mock.patch.object(containers_svc, "docker", side_effect=fake_docker), \
             mock.patch.object(containers_svc, "override", return_value={}), \
             mock.patch.object(containers_svc, "resolve_value", side_effect=lambda x: x or {}), \
             mock.patch.object(containers_svc, "_load_update_status", return_value={}):
            ok, items = containers_svc._build_container_list()
        self.assertTrue(ok)
        self.assertEqual(items[0]["id"], "nginx")

        with mock.patch.object(containers_svc, "engine_up", return_value=True), \
             mock.patch.object(containers_svc, "docker", return_value=(0, None, "")), \
             mock.patch.object(containers_svc, "override", return_value={}), \
             mock.patch.object(containers_svc, "resolve_value", side_effect=lambda x: x or {}), \
             mock.patch.object(containers_svc, "_load_update_status", return_value={}):
            ok, items = containers_svc._build_container_list()
        self.assertTrue(ok)
        self.assertEqual(items, [])

    def test_non_dict_override_does_not_500(self):
        with mock.patch.object(containers_svc, "engine_up", return_value=True), \
             mock.patch.object(containers_svc, "docker", return_value=(0, PS_LINE, "")), \
             mock.patch.object(containers_svc, "override", return_value=["oops"]), \
             mock.patch.object(containers_svc, "resolve_value", side_effect=lambda x: x), \
             mock.patch.object(containers_svc, "_load_update_status", return_value={}):
            ok, items = containers_svc._build_container_list()
        self.assertTrue(ok)
        self.assertEqual(items[0]["id"], "nginx")


class VolumeNetworkTypingTests(unittest.TestCase):
    def test_none_bytes_and_int_listings_do_not_500(self):
        with mock.patch.object(containers_svc, "docker", return_value=(0, None, "")):
            self.assertEqual(containers_svc.list_volumes(), [])
            self.assertEqual(containers_svc.list_networks(), [])
        with mock.patch.object(containers_svc, "docker", return_value=(0, 42, "")):
            self.assertEqual(containers_svc.list_volumes(), [])
            self.assertEqual(containers_svc.list_networks(), [])
        with mock.patch.object(
            containers_svc, "docker",
            return_value=(0, b"vol\tlocal\t/x\n", ""),
        ):
            self.assertEqual(
                containers_svc.list_volumes(),
                [{"Name": "vol", "Driver": "local", "Mountpoint": "/x"}],
            )
        with mock.patch.object(
            containers_svc, "docker",
            return_value=(0, b"abc123def456\tbridge\tbridge\tlocal\n", ""),
        ):
            rows = containers_svc.list_networks()
        self.assertEqual(rows[0]["Name"], "bridge")
        self.assertEqual(rows[0]["Id"], "abc123def456"[:12])


class ActionAllTypingTests(unittest.TestCase):
    def test_scalar_and_junk_rows_do_not_500(self):
        with mock.patch.object(
            containers_svc, "list_containers", return_value={"containers": 5},
        ):
            out = containers_svc.action_all("start")
        self.assertEqual(out["done"], 0)
        self.assertEqual(out["total"], 0)

        payload = {
            "containers": [
                "nope",
                None,
                {"id": True, "raw_state": "exited"},
                {"id": "web", "raw_state": "exited"},
            ]
        }
        with mock.patch.object(containers_svc, "list_containers", return_value=payload), \
             mock.patch.object(
                 containers_svc, "container_action",
                 return_value={"ok": True, "message": "started"},
             ) as action:
            out = containers_svc.action_all("start")
        self.assertTrue(out["ok"])
        self.assertEqual(out["done"], 1)
        action.assert_called_once_with("web", "start")

    def test_list_stacks_scalar_containers_do_not_500(self):
        stack = {"id": "x", "path": None, "containers": []}
        with mock.patch.object(containers_svc, "_stack_paths", return_value=[stack]), \
             mock.patch.object(
                 containers_svc, "list_containers",
                 return_value={"containers": 5},
             ):
            stacks = containers_svc.list_stacks()
        self.assertEqual(stacks[0]["status"], "idle")
        self.assertEqual(stacks[0]["running_containers"], [])


class StackScanTypingTests(unittest.TestCase):
    def test_glob_oserror_does_not_500(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "Services").mkdir()

        def boom(self, pattern):
            raise PermissionError("nope")

        with mock.patch.object(Path, "home", return_value=tmp), \
             mock.patch.object(Path, "glob", boom), \
             mock.patch.object(containers_svc, "cfg", return_value={"stacks": []}):
            self.assertEqual(containers_svc._stack_paths(), [])


class ComposeSaveTypingTests(unittest.TestCase):
    def _code(self, ctx) -> str:
        detail = ctx.exception.detail
        return detail["code"] if isinstance(detail, dict) else str(detail)

    def test_non_str_content_is_coded_not_500(self):
        stack = {
            "id": "x", "name": "x", "path": "/tmp",
            "compose_path": "/tmp/x.yml",
        }
        with mock.patch.object(compose_svc, "_find_stack", return_value=stack):
            with self.assertRaises(HTTPException) as ctx:
                compose_svc.save_compose("x", ["services: {}"], validate=False)
        self.assertEqual(self._code(ctx), "compose.empty_content")
        with mock.patch.object(compose_svc, "_find_stack", return_value=stack):
            with self.assertRaises(HTTPException) as ctx:
                compose_svc.save_compose("x", 1, validate=False)
        self.assertEqual(self._code(ctx), "compose.empty_content")


class AppsLogsOverflowTests(unittest.TestCase):
    def test_infinite_lines_is_clamped_not_500(self):
        with mock.patch.object(
            apps_manage_svc, "_docker_logs", return_value={"ok": True, "log": ""}
        ) as logs:
            out = apps_manage_svc.logs("docker:web", lines=float("inf"))
        self.assertTrue(out["ok"])
        self.assertEqual(logs.call_args[0][1], 120)


class ExecPullTypingTests(unittest.TestCase):
    def test_bytes_and_int_output_do_not_500(self):
        with mock.patch.object(
            containers_svc, "docker", return_value=(0, b"hello", b""),
        ):
            out = containers_svc.exec_in_container("nginx", "ls")
        self.assertTrue(out["ok"])
        self.assertEqual(out["output"], "hello")

        with mock.patch.object(containers_svc, "docker", return_value=(0, 1, "")):
            out = containers_svc.pull_image("nginx")
        self.assertTrue(out["ok"])
        self.assertEqual(out["message"], "1")


class OverrideYamlLeftoverTests(unittest.TestCase):
    def test_inf_date_bytes_do_not_500_list(self):
        ov = {
            "name": float("inf"),
            "url": datetime.date(2026, 8, 19),
            "group": b"web",
        }
        with mock.patch.object(containers_svc, "engine_up", return_value=True), \
             mock.patch.object(containers_svc, "docker", return_value=(0, PS_LINE, "")), \
             mock.patch.object(containers_svc, "override", return_value=ov), \
             mock.patch.object(containers_svc, "resolve_value", side_effect=lambda x: x or {}), \
             mock.patch.object(containers_svc, "_load_update_status", return_value={}):
            ok, items = containers_svc._build_container_list()
        self.assertTrue(ok)
        self.assertEqual(items[0]["name"], "nginx")
        self.assertEqual(items[0]["url"], "2026-08-19")
        self.assertEqual(items[0]["group"], "web")
        _json(items)

    def test_set_nan_datetime_do_not_500_list(self):
        ov = {
            "name": {"guest"},
            "url": float("nan"),
            "group": datetime.datetime(2026, 1, 1),
        }
        with mock.patch.object(containers_svc, "engine_up", return_value=True), \
             mock.patch.object(containers_svc, "docker", return_value=(0, PS_LINE, "")), \
             mock.patch.object(containers_svc, "override", return_value=ov), \
             mock.patch.object(containers_svc, "resolve_value", side_effect=lambda x: x or {}), \
             mock.patch.object(containers_svc, "_load_update_status", return_value={}):
            ok, items = containers_svc._build_container_list()
        self.assertTrue(ok)
        self.assertEqual(items[0]["name"], "nginx")
        self.assertIsNone(items[0]["url"])
        self.assertEqual(items[0]["group"], "2026-01-01 00:00:00")
        _json(items)


class StackYamlLeftoverTests(unittest.TestCase):
    def test_inf_date_and_scalar_containers_do_not_500(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        (tmp / "Services").mkdir()
        cfg = {"stacks": [
            {
                "id": "a",
                "name": float("inf"),
                "path": str(tmp / "a"),
                "containers": [float("inf"), "web"],
            },
            {
                "id": "b",
                "name": datetime.date(2026, 8, 19),
                "containers": 5,
            },
        ]}
        with mock.patch.object(Path, "home", return_value=tmp), \
             mock.patch.object(containers_svc, "cfg", return_value=cfg):
            stacks = containers_svc._stack_paths()
        by = {s["id"]: s for s in stacks}
        self.assertEqual(by["a"]["name"], "a")
        self.assertEqual(by["a"]["containers"], ["web"])
        self.assertEqual(by["b"]["name"], "2026-08-19")
        self.assertEqual(by["b"]["containers"], [])
        _json(stacks)


class UpdateStatusLeftoverTests(unittest.TestCase):
    def test_infinity_checked_at_does_not_500(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        path = tmp / "docker-update-status.json"
        path.write_text(
            '{"_checked_at": Infinity, "nginx:latest":'
            ' {"status": "maybe", "update": NaN}}\n'
        )
        with mock.patch.object(containers_svc, "UPDATE_STATUS_PATH", path), \
             mock.patch.object(
                 containers_svc, "_container_list_cached",
                 return_value=(True, [{
                     "id": "nginx", "project": None, "raw_state": "running",
                 }]),
             ), \
             mock.patch.object(containers_svc, "_stats_cached", return_value={}):
            st = containers_svc._load_update_status()
            payload = containers_svc.list_containers(with_stats=False)
        self.assertIsNone(st.get("_checked_at"))
        self.assertIsNone(st["nginx:latest"]["update"])
        self.assertIsNone(payload.get("update_checked_at"))
        _json(st)
        _json(payload)


class InspectJsonLeftoverTests(unittest.TestCase):
    def test_infinity_fields_do_not_500_inspect(self):
        payload = (
            '{"Id":"abc123def456","Name":"/nginx","Created":Infinity,'
            '"Config":{"Image":"nginx","Labels":{"a":Infinity},"Env":[]},'
            '"HostConfig":{"Binds":["/a:/b",Infinity],'
            '"PortBindings":{"80/tcp":Infinity},'
            '"RestartPolicy":{"MaximumRetryCount":Infinity}},'
            '"State":{"ExitCode":Infinity},'
            '"Mounts":[{"Source":Infinity,"Destination":"/data","Type":"bind"}]}'
        )
        with mock.patch.object(containers_svc, "docker", return_value=(0, payload, "")):
            info = containers_svc.inspect_container("nginx")
        self.assertEqual(info["Id"], "abc123def456"[:12])
        self.assertIsNone(info["Created"])
        self.assertIsNone(info["Labels"]["a"])
        self.assertEqual(info["Binds"], ["/a:/b"])
        self.assertIsNone(info["State"]["ExitCode"])
        self.assertIsNone(info["Mounts"][0]["Source"])
        _json(info)

    def test_infinity_mounts_do_not_500_list(self):
        inspect = (
            '[{"Name":"/nginx","Created":"2024-01-01T00:00:00Z",'
            '"Config":{"Image":"nginx"},'
            '"HostConfig":{"NetworkMode":"bridge","RestartPolicy":{"Name":"no"}},'
            '"NetworkSettings":{"Networks":{}},'
            '"Mounts":[{"Source":Infinity,"Destination":NaN,"Type":"bind"}]}]'
        )

        def fake_docker(*args, **kwargs):
            if args and args[0] == "ps":
                return (0, PS_LINE, "")
            return (0, inspect, "")

        with mock.patch.object(containers_svc, "engine_up", return_value=True), \
             mock.patch.object(containers_svc, "docker", side_effect=fake_docker), \
             mock.patch.object(containers_svc, "override", return_value={}), \
             mock.patch.object(containers_svc, "resolve_value", side_effect=lambda x: x or {}), \
             mock.patch.object(containers_svc, "_load_update_status", return_value={}):
            ok, items = containers_svc._build_container_list()
        self.assertTrue(ok)
        self.assertEqual(items[0]["mounts"][0]["src"], "")
        self.assertEqual(items[0]["mounts"][0]["dst"], "")
        _json(items)


class ComposeValidateTypingTests(unittest.TestCase):
    def test_bytes_and_int_run_capped_do_not_500(self):
        with mock.patch.object(compose_svc, "run_capped", return_value=(0, b"valid")):
            out = compose_svc.validate_compose_text("services: {}\n", cwd="/tmp")
        self.assertTrue(out["ok"])
        self.assertEqual(out["message"], "valid")
        _json(out)
        with mock.patch.object(compose_svc, "run_capped", return_value=(1, 7)):
            out = compose_svc.validate_compose_text("services: {}\n", cwd="/tmp")
        self.assertFalse(out["ok"])
        self.assertEqual(out["message"], "7")
        _json(out)


class RecreateRunCappedLeftoverTests(unittest.TestCase):
    def test_bytes_and_none_run_capped_do_not_500(self):
        """Leftover ``run_capped`` bytes used to TypeError the recreate job JSON."""
        inspect = json.dumps({
            "HostConfig": {
                "RestartPolicy": {"Name": "no"},
                "NetworkMode": "bridge",
                "PortBindings": {},
                "Binds": [],
            },
            "Config": {"Env": [], "Cmd": None, "Image": "nginx:latest"},
        })
        job = {"log": []}
        with mock.patch.object(containers_svc, "docker", return_value=(0, inspect, "")), \
             mock.patch.object(containers_svc, "run_capped", return_value=(0, b"abc123")):
            ok = containers_svc._recreate_simple("nginx", "nginx:latest", job, {})
        self.assertTrue(ok)
        self.assertTrue(all(isinstance(line, str) for line in job["log"]))
        _json(job)
        job = {"log": []}
        with mock.patch.object(containers_svc, "docker", return_value=(0, inspect, "")), \
             mock.patch.object(containers_svc, "run_capped", return_value=(0, None)):
            ok = containers_svc._recreate_simple("nginx", "nginx:latest", job, {})
        self.assertTrue(ok)
        _json(job)


class ContainerLogsSseLeftoverTests(unittest.TestCase):
    def test_huge_log_line_does_not_500_sse(self):
        """asyncio StreamReader.readline ValueError used to 500 GET /logs."""
        from hub.routers import containers as containers_router

        class Stdout:
            def __init__(self):
                self.n = 0

            async def readline(self):
                self.n += 1
                if self.n == 1:
                    raise ValueError("Separator is found, but chunk exceed the limit")
                return b""

            async def read(self, _n):
                return b"\n"

        class Proc:
            stdout = Stdout()
            returncode = 0

            def kill(self):
                pass

            async def wait(self):
                return 0

        async def fake_exec(*_a, **_k):
            return Proc()

        async def collect():
            resp = await containers_router.logs_sse("web")
            chunks = []
            async for part in resp.body_iterator:
                chunks.append(part if isinstance(part, str) else part.decode())
            return "".join(chunks)

        with mock.patch.object(containers_router.asyncio, "create_subprocess_exec", fake_exec):
            body = asyncio.run(collect())
        self.assertIn("line truncated", body)


class ContainerUpdateStatusDumpsLeftoverTests(unittest.TestCase):
    def test_save_update_status_dumps_recursion_does_not_500(self):
        """json.dumps RecursionError used to 500 docker update-status writes."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "docker-update-status.json"
            with (
                mock.patch.object(containers_svc, "UPDATE_STATUS_PATH", path),
                mock.patch.object(containers_svc.json, "dumps", side_effect=RecursionError),
            ):
                containers_svc._save_update_status({"nginx": {"status": "ok"}})
            self.assertFalse(path.exists())


class ContainerActionAllExcDetailTests(unittest.TestCase):
    def test_recursing_action_error_does_not_500(self):
        """str(e) RecursionError used to 500 Start All."""
        class Recursing(Exception):
            def __str__(self):
                raise RecursionError("nested")

        with mock.patch.object(
            containers_svc, "container_action", side_effect=Recursing(),
        ):
            out = containers_svc.batch_action(["web"], "start")
        _json(out)
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertFalse(out["ok"])
        self.assertEqual(out["results"][0]["message"], "Recursing")


class ContainerJobEpochLeftoverTests(unittest.TestCase):
    def test_infinite_clock_does_not_raise(self):
        """int(time.time()) OverflowError on leftover inf used to 500 docker job ids."""
        with mock.patch.object(containers_svc.time, "time", return_value=float("inf")):
            self.assertEqual(containers_svc._job_epoch(), 0)

    def test_overflow_strftime_does_not_500_job_started(self):
        """Leftover inf clock OverflowError'd compose job ``started`` JSON."""
        containers_svc._cjobs.clear()
        with mock.patch("hub.util.time.strftime", side_effect=OverflowError):
            job = containers_svc._register_job("job-inf", stack_id="web", action="up")
        _json(job)
        json.dumps(job, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertEqual(job["started"], "")
        self.assertIsNone(job["finished"])
        containers_svc._cjobs.clear()


class StreamJobCommandPopenLeftoverTests(unittest.TestCase):
    def test_popen_oserror_is_logged_not_500(self):
        """``Popen`` leftover EIO used to 500 a compose/update job thread."""
        job = {"log": []}
        with mock.patch.object(
            containers_svc.subprocess, "Popen", side_effect=OSError(5, "I/O error"),
        ):
            rc = containers_svc._stream_job_command(["/bin/echo", "ok"], job)
        self.assertEqual(rc, -1)
        self.assertTrue(any("I/O error" in line for line in job["log"]))
        _json(job)

    def test_leftover_surrogate_argv_is_invalid_not_500(self):
        job = {"log": []}
        rc = containers_svc._stream_job_command(["/bin/echo", "ok\ud800"], job)
        self.assertEqual(rc, -1)
        self.assertTrue(any("invalid argv" in line for line in job["log"]))

    def test_leftover_surrogate_env_is_not_500(self):
        job = {"log": []}
        rc = containers_svc._stream_job_command(
            ["/bin/echo", "ok"],
            job,
            env={"PATH": "/bin:/usr/bin", "LEFTOVER": "x\ud800"},
        )
        self.assertEqual(rc, 0)
        self.assertTrue(any("ok" in line for line in job["log"]))


if __name__ == "__main__":
    unittest.main()
