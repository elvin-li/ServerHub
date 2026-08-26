"""Fifth leftover-500s sweep of the Docker / container surfaces: no live leftover.

Every probe in this battery ran over the real mounted app (``create_app()`` +
``TestClient(raise_server_exceptions=False)``) against the shapes the prior
docker/docker2/docker3/docker4 sweeps fixed — poisoned ``docker inspect`` /
``ps`` / ``{{json .}}`` output (lone-surrogate escapes in keys AND values,
>4300-digit ints, ``Infinity``/``NaN``, 300-deep nesting, torn JSON), adversarial
request bodies (surrogate names, option-shaped positionals, oversize fields),
leftover on-disk shapes (FIFO / oversize / invalid-UTF-8 / directory occupying a
compose path, poisoned docker-update-status.json), engine-down and
vanished-CLI failure paths, the SSE log stream, a real end-to-end stack job,
and the terminal docker-exec receipts.  None of them produced a raw HTTP 500 —
every answer was a 2xx or a coded 4xx/503 with a UTF-8-renderable body.

These tests pin that immunity so a refactor cannot quietly reopen any of it.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from fastapi.testclient import TestClient  # noqa: E402

import hub.docker_cli as docker_cli  # noqa: E402
import hub.routers.containers as containers_router  # noqa: E402
from hub import compose_svc, containers_svc, docker_info_svc, network_svc, terminal_svc, tools_svc  # noqa: E402
from hub.app_factory import create_app  # noqa: E402
from hub.auth import require_auth  # noqa: E402

_app = None


def _the_app():
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return _app


def _client() -> TestClient:
    # raise_server_exceptions=False: a real 500 must arrive as HTTP 500, not
    # as a re-raised exception that would mask which route crashed.
    return TestClient(_the_app(), raise_server_exceptions=False)


HUGE = "9" * 5000
DEEP = "[" * 300 + "]" * 300

#: ``docker inspect`` stdout families.  Raw text a real docker CLI could
#: print: ``\ud800`` rides as a JSON escape (json.loads turns it into a lone
#: surrogate), huge ints dodge json's decoder only via CPython's digit cap,
#: and ``Infinity``/``NaN`` are accepted by Python's decoder but refused by
#: Starlette's ``allow_nan=False`` encoder.
INSPECT_FAMILIES = {
    "surrogate_everywhere": (
        '[{"Id": "abc", "Name": "/web", "Created": "2024-01-01T00:00:00Z",'
        ' "Config": {"Image": "\\ud800img", "Env": ["A=\\ud800", "PASSWORD=x"],'
        ' "Cmd": ["\\ud800"], "Entrypoint": null,'
        ' "Labels": {"\\ud800k": "\\ud800v", "com.docker.compose.project": "\\ud800p"}},'
        ' "HostConfig": {"Binds": ["\\ud800:/x"], "NetworkMode": "\\ud800",'
        '   "RestartPolicy": {"Name": "\\ud800"}, "Privileged": true,'
        '   "PortBindings": {"\\ud800/tcp": [{"HostPort": "\\ud800", "HostIp": "\\ud800"}]}},'
        ' "State": {"Status": "\\ud800", "Health": {"Status": "\\ud800"}},'
        ' "NetworkSettings": {"Networks": {"\\ud800net": {"IPAddress": "\\ud800"}}},'
        ' "Mounts": [{"Source": "\\ud800", "Destination": "\\ud800", "Type": "\\ud800", "RW": true}]}]'
    ),
    "huge_ints": (
        '[{"Id": ' + HUGE + ', "Name": "/web", "Created": ' + HUGE + ','
        ' "Config": {"Image": "img", "Env": [' + HUGE + '], "Cmd": ' + HUGE + ','
        ' "Labels": {"a": ' + HUGE + '}},'
        ' "HostConfig": {"Binds": [' + HUGE + '], "NetworkMode": ' + HUGE + ','
        '   "RestartPolicy": {"Name": ' + HUGE + '}, "PortBindings": {"80/tcp": [{"HostPort": ' + HUGE + '}]}},'
        ' "State": {"ExitCode": ' + HUGE + '},'
        ' "NetworkSettings": {"Networks": {"bridge": {"IPAddress": ' + HUGE + '}}},'
        ' "Mounts": [{"Source": ' + HUGE + '}]}]'
    ),
    "inf_nan": (
        '[{"Id": "abc", "Name": "/web", "Created": Infinity,'
        ' "Config": {"Image": "img", "Env": NaN, "Cmd": -Infinity, "Labels": {"a": Infinity}},'
        ' "HostConfig": {"Binds": NaN, "NetworkMode": Infinity, "RestartPolicy": Infinity,'
        '   "PortBindings": {"80/tcp": [{"HostPort": Infinity}]}},'
        ' "State": {"ExitCode": NaN}, "NetworkSettings": {"Networks": {"b": {"IPAddress": Infinity}}},'
        ' "Mounts": [Infinity]}]'
    ),
    "deep_nesting": DEEP,
    "torn": '[{"Id": "abc", "Nam',
    "not_json": "plain text output\nno json here",
    "dict_not_list": '{"Name": 5, "Config": 7, "HostConfig": []}',
    "huge_number_top": HUGE,
}

PS_FAMILIES = {
    "short_lines": "abc\nabc\tweb\n",
    "extra_tabs": "id\tname\timg\trunning\tUp (unhealthy)\t0.0.0.0:80->80/tcp\tproj\tsvc\t12MB\textra\tmore",
    "empty_fields": "id\tweb\timg\t\t\t\t\t\t",
    "torn_ipv6_ports": "id\tweb\timg\trunning\tUp\t[::]:80->80/tcp, [::1:9->9/tcp, :::->/tcp\tp\ts\t1B",
}

GET_ROUTES = (
    "/api/containers",
    "/api/images",
    "/api/volumes",
    "/api/networks",
    "/api/stacks",
    "/api/stacks/jobs/nope",
    "/api/containers/web/inspect",
    "/api/docker/info",
    "/api/docker/df",
    "/api/docker/sizes",
    "/api/system/network/docker-ports",
)


def _fake_docker_factory(inspect_out: str, ps_out: str | None = None):
    """A docker() twin whose stdout is *inspect_out* for JSON-ish verbs."""
    ps = ps_out if ps_out is not None else (
        "id\tweb\timg\trunning\tUp 2 days\t0.0.0.0:80->80/tcp\tproj\tsvc\t12MB"
    )

    def fake(*args, timeout=None):
        a = list(args)
        if a and a[0] == "ps":
            return 0, ps, ""
        if a and a[0] == "stats":
            return 0, "web\t1%\t1MiB / 2MiB\t50%\t1B/2B\t3B/4B", ""
        if a and a[0] == "volume" and a[1] == "ls":
            return 0, "v1\tlocal\t/mnt", ""
        if a and a[0] == "network" and a[1] == "ls":
            return 0, "abc123\tbridge\tbridge\tlocal", ""
        return 0, inspect_out, ""

    return fake


class _DockerSurfaceBase(unittest.TestCase):
    """Shared fixtures: sandboxed update-status path + memo hygiene."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="docker5-pins-"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.upd = self.tmp / "docker-update-status.json"
        containers_svc.invalidate_container_lists()
        self.addCleanup(containers_svc.invalidate_container_lists)

    def _patched(self, fake, *, engine=True):
        """Patch the docker() twin + engine probe in every consuming module."""
        stacks_cfg = {"stacks": [{"id": "web", "name": "web", "containers": ["web"]}]}
        patches = [
            mock.patch.object(docker_cli, "docker", side_effect=fake),
            mock.patch.object(containers_svc, "docker", side_effect=fake),
            mock.patch.object(containers_svc, "engine_up", return_value=engine),
            mock.patch.object(network_svc, "docker", side_effect=fake),
            mock.patch.object(network_svc, "engine_up", return_value=engine),
            mock.patch.object(docker_info_svc, "docker", side_effect=fake),
            mock.patch.object(docker_info_svc, "engine_up", return_value=engine),
            mock.patch.object(tools_svc, "_docker", side_effect=fake),
            mock.patch.object(tools_svc, "engine_up", return_value=engine),
            mock.patch.object(containers_svc, "cfg", return_value=stacks_cfg),
            mock.patch.object(containers_svc, "UPDATE_STATUS_PATH", self.upd),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        containers_svc.invalidate_container_lists()

    def assert_never_raw_500(self, r, label):
        body = r.text
        if r.status_code >= 500:
            # A registered coded failure state (container.engine_down 503,
            # container.list_failed 500) is a contract answer, not a leftover.
            self.assertIn('"code"', body, f"{label}: raw {r.status_code}: {body[:300]}")
        # Whatever the status, the body must be UTF-8-renderable.
        body.encode("utf-8")


class PoisonedInspectListingPins(_DockerSurfaceBase):
    """Every inventory GET survives every poisoned docker stdout family."""

    def test_inspect_families_never_500_any_listing(self):
        for name, out in INSPECT_FAMILIES.items():
            with self.subTest(family=name):
                self.setUp()
                self._patched(_fake_docker_factory(out))
                c = _client()
                for url in GET_ROUTES:
                    r = c.get(url)
                    self.assert_never_raw_500(r, f"{name} {url}")

    def test_ps_families_never_500_container_listings(self):
        for name, ps in PS_FAMILIES.items():
            with self.subTest(family=name):
                self.setUp()
                self._patched(_fake_docker_factory(
                    '[{"Name": "/web", "Config": {"Image": "img"}}]', ps_out=ps,
                ))
                c = _client()
                for url in ("/api/containers", "/api/stacks",
                            "/api/docker/sizes", "/api/system/network/docker-ports"):
                    r = c.get(url)
                    self.assert_never_raw_500(r, f"{name} {url}")

    def test_surrogate_inspect_keeps_container_detail_route_clean(self):
        self._patched(_fake_docker_factory(INSPECT_FAMILIES["surrogate_everywhere"]))
        r = _client().get("/api/containers/web/inspect")
        self.assertEqual(r.status_code, 200, r.text)
        # The scrub must actually have happened, not merely not crashed.
        self.assertNotIn("\ud800", r.text)
        json.dumps(r.json(), ensure_ascii=False, allow_nan=False).encode("utf-8")


class AdversarialBodyPins(_DockerSurfaceBase):
    """Mutation routes answer coded 4xx (never raw 500) for hostile bodies.

    ``\\ud800`` rides the wire as a JSON escape — exactly what a real client
    can send — so bodies are serialized with ``ensure_ascii=True``.
    """

    SUR = "\ud800bad"

    def _post(self, c, url, body, method="POST"):
        return c.request(
            method, url,
            content=json.dumps(body, ensure_ascii=True).encode("ascii"),
            headers={"content-type": "application/json"},
        )

    def test_hostile_bodies_never_raw_500(self):
        sur = self.SUR
        targets = [
            ("POST", "/api/containers/run",
             {"image": sur, "name": sur, "ports": [sur], "volumes": [sur],
              "env": [sur], "network": sur, "command": sur}),
            ("POST", "/api/containers/run", {"image": "x" * 500, "restart": "sometimes"}),
            ("POST", "/api/containers/batch",
             {"action": sur, "names": [sur, "--all", "x" * 5000]}),
            ("POST", "/api/containers/batch", {"action": "stop", "names": []}),
            ("POST", "/api/containers/all", {"action": sur}),
            ("POST", "/api/images/pull", {"image": sur}),
            ("POST", "/api/images/remove", {"image": sur, "force": True}),
            ("POST", "/api/volumes/create", {"name": sur, "driver": sur}),
            ("POST", "/api/volumes/remove", {"name": sur}),
            ("POST", "/api/networks/create", {"name": sur, "driver": sur}),
            ("POST", "/api/networks/remove", {"name": sur}),
            ("POST", "/api/prune", {"kind": sur}),
            ("POST", "/api/stacks/web/run", {"action": sur}),
            ("POST", "/api/stacks/%ED%A0%80bad/run", {"action": "up"}),
            ("POST", "/api/containers/web/action", {"action": sur}),
            ("POST", "/api/containers/%ED%A0%80bad/action", {"action": "stop"}),
            ("POST", "/api/containers/web/exec", {"command": sur, "shell": sur}),
            ("POST", "/api/containers/web/exec", {"command": "", "shell": "/bin/sh"}),
            ("POST", "/api/containers/web/restart-policy", {"policy": sur}),
            ("POST", "/api/containers/web/rename", {"new_name": sur}),
            ("POST", "/api/system/network/docker/connect",
             {"network": sur, "container": sur}),
            ("POST", "/api/system/network/docker/disconnect",
             {"network": sur, "container": sur, "force": True}),
            ("POST", "/api/system/network/docker/ports/web", {"ports": [sur, "8080:80"]}),
            ("POST", "/api/compose/validate", {"content": sur, "cwd": sur}),
            ("POST", "/api/compose/validate",
             {"content": "name: 0x" + "f" * 5000, "cwd": None}),
            ("POST", "/api/compose", {"id": sur, "name": sur, "content": sur}),
            ("PUT", "/api/compose/web", {"content": sur, "check": False}),
        ]
        self._patched(_fake_docker_factory('[{"Name": "/web", "Config": {"Image": "img"}}]'))
        c = _client()
        for method, url, body in targets:
            with self.subTest(url=url, body=str(body)[:60]):
                r = self._post(c, url, body, method=method)
                self.assert_never_raw_500(r, url)

    def test_surrogate_batch_names_echo_back_scrubbed(self):
        self._patched(_fake_docker_factory("[]"))
        r = self._post(_client(), "/api/containers/batch",
                       {"action": "stop", "names": [self.SUR]})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertNotIn("\ud800", r.text)
        rows = r.json()["results"]
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]["ok"])


class WeirdStacksConfigPins(_DockerSurfaceBase):
    """services.yaml ``stacks:`` leftovers keep listings and jobs coded."""

    WEIRD = [
        {"stacks": [{"id": 10 ** 5000, "containers": ["a"]}]},
        {"stacks": [{"id": float("inf"), "name": float("nan"), "containers": ["a"]}]},
        {"stacks": [{"id": b"\xff\xfe", "name": b"\xff", "containers": [b"x"]}]},
        {"stacks": [{"id": {"n": 1}, "name": ["l"], "containers": "notalist"}]},
        {"stacks": [{"id": "ok", "path": 10 ** 5000}]},
        {"stacks": [{"id": "ok", "path": "\x00null"}]},
        {"stacks": [{"id": "ok", "path": "/nonexistent", "compose_file": 42}]},
        {"stacks": "notalist"},
        {"stacks": [None, 5, "str", []]},
        {"stacks": [{"id": "\ud800", "containers": ["\ud800"]}]},
    ]

    def test_weird_stacks_never_500_listing_or_run(self):
        fake = _fake_docker_factory('[{"Name": "/web", "Config": {"Image": "img"}}]')
        for i, cfg_val in enumerate(self.WEIRD):
            with self.subTest(idx=i):
                with (
                    mock.patch.object(containers_svc, "docker", side_effect=fake),
                    mock.patch.object(containers_svc, "engine_up", return_value=True),
                    mock.patch.object(containers_svc, "cfg", return_value=cfg_val),
                    mock.patch.object(containers_svc, "UPDATE_STATUS_PATH", self.upd),
                ):
                    containers_svc.invalidate_container_lists()
                    c = _client()
                    for url in ("/api/stacks", "/api/containers"):
                        self.assert_never_raw_500(c.get(url), f"cfg{i} {url}")
                    self.assert_never_raw_500(c.get("/api/compose/ok"), f"cfg{i} compose")
                    r = c.post("/api/stacks/ok/run", json={"action": "up"})
                    self.assert_never_raw_500(r, f"cfg{i} run")
                    containers_svc.invalidate_container_lists()


class UpdateStatusFilePins(_DockerSurfaceBase):
    """Leftover docker-update-status.json shapes never take down the listing."""

    FAMILIES = {
        "huge_int": '{"img": {"status": ' + HUGE + '}, "_checked_at": ' + HUGE + '}',
        "surrogate": '{"\\ud800": {"status": "\\ud800"}, "_checked_at": "\\ud800"}',
        "inf": '{"img": Infinity, "_checked_at": NaN}',
        "deep": DEEP,
        "list": "[1,2,3]",
    }

    def test_poisoned_update_status_keeps_containers_200(self):
        fake = _fake_docker_factory('[{"Name": "/web", "Config": {"Image": "img"}}]')
        for name, content in self.FAMILIES.items():
            with self.subTest(family=name):
                self.upd.write_text(content)
                self._patched(fake)
                r = _client().get("/api/containers")
                self.assertEqual(r.status_code, 200, f"{name}: {r.text[:300]}")
                self.assertNotIn("\ud800", r.text)
                self.upd.unlink(missing_ok=True)

    def test_invalid_utf8_update_status_keeps_containers_200(self):
        self.upd.write_bytes(b'\xff\xfe{"a": 1}')
        self._patched(_fake_docker_factory('[{"Name": "/web", "Config": {"Image": "img"}}]'))
        r = _client().get("/api/containers")
        self.assertEqual(r.status_code, 200, r.text[:300])

    def test_fifo_update_status_neither_hangs_nor_500s(self):
        os.mkfifo(self.upd)
        self._patched(_fake_docker_factory('[{"Name": "/web", "Config": {"Image": "img"}}]'))
        started = time.monotonic()
        r = _client().get("/api/containers")
        self.assertLess(time.monotonic() - started, 10,
                        "a leftover FIFO at docker-update-status.json wedged the read")
        self.assertEqual(r.status_code, 200, r.text[:300])


class OnDiskComposeShapePins(unittest.TestCase):
    """Leftover file shapes at a stack's compose path answer coded, never hang."""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="docker5-compose-"))
        self.addCleanup(lambda: shutil.rmtree(self.home, ignore_errors=True))
        services = self.home / "Services"
        services.mkdir()
        big = services / "big"
        big.mkdir()
        (big / "docker-compose.yml").write_text("x" * (2 * 1024 * 1024))
        badutf = services / "badutf"
        badutf.mkdir()
        (badutf / "docker-compose.yml").write_bytes(b"services:\n  a:\n    image: \xff\xfe\n")
        isdir = services / "isdir"
        isdir.mkdir()
        (isdir / "docker-compose.yml").mkdir()
        fifostack = services / "fifostack"
        fifostack.mkdir()
        os.mkfifo(fifostack / "docker-compose.yml")
        for p in (
            mock.patch.object(containers_svc, "cfg", return_value={"stacks": []}),
            mock.patch.object(containers_svc, "user_home", return_value=self.home),
            mock.patch.object(compose_svc, "user_home", return_value=self.home),
        ):
            p.start()
            self.addCleanup(p.stop)
        containers_svc.invalidate_container_lists()
        self.addCleanup(containers_svc.invalidate_container_lists)

    def test_every_leftover_shape_answers_coded_and_fast(self):
        with mock.patch.object(
            containers_svc, "list_containers",
            return_value={"engine_up": True, "containers": [], "stats": {}, "projects": []},
        ):
            c = _client()
            started = time.monotonic()
            r = c.get("/api/stacks")
            self.assertEqual(r.status_code, 200, r.text[:300])
            for sid in ("big", "badutf", "isdir", "fifostack"):
                with self.subTest(stack=sid):
                    r = c.get(f"/api/compose/{sid}")
                    if r.status_code >= 500:
                        self.fail(f"GET compose {sid}: raw {r.status_code}: {r.text[:200]}")
                    r.text.encode("utf-8")
                    r = c.put(
                        f"/api/compose/{sid}",
                        json={"content": "services: {}\n", "check": False},
                    )
                    if r.status_code >= 500:
                        self.fail(f"PUT compose {sid}: raw {r.status_code}: {r.text[:200]}")
            # The FIFO invariant: none of the reads above may park on open().
            self.assertLess(time.monotonic() - started, 15,
                            "a leftover FIFO at a compose path wedged the request")

    def test_create_over_leftover_file_is_coded_409(self):
        (self.home / "Services" / "occupied").write_text("i am a file")
        with mock.patch.object(
            compose_svc, "validate_compose_text",
            return_value={"ok": True, "message": "valid"},
        ):
            r = _client().post(
                "/api/compose",
                json={"id": "occupied", "name": None, "content": "services: {}\n"},
            )
        self.assertEqual(r.status_code, 409, r.text)
        self.assertIn("compose.exists", r.text)


class EngineDownClassificationPins(_DockerSurfaceBase):
    """Failure paths stay coded 503, and surrogate-bearing stderr stays clean."""

    def test_engine_down_failures_stay_coded_503(self):
        def fail(*args, timeout=None):
            return 1, "", "Cannot connect to the Docker daemon at unix:///var/run/docker.sock"

        self._patched(fail, engine=False)
        c = _client()
        for url in ("/api/images", "/api/volumes", "/api/networks",
                    "/api/containers/web/inspect"):
            with self.subTest(url=url):
                r = c.get(url)
                self.assertEqual(r.status_code, 503, f"{url}: {r.text[:200]}")
                self.assertIn("container.engine_down", r.text)

    def test_vanished_cli_sentinel_stays_coded_503(self):
        def fail(*args, timeout=None):
            return -1, "not found", ""

        self._patched(fail, engine=False)
        c = _client()
        for url in ("/api/images", "/api/volumes", "/api/networks"):
            with self.subTest(url=url):
                r = c.get(url)
                self.assertEqual(r.status_code, 503, f"{url}: {r.text[:200]}")
                self.assertIn("container.engine_down", r.text)

    def test_raw_failure_with_surrogate_escape_never_500s_mutations(self):
        # Engine answers "up", so the failure keeps its raw mapping — and the
        # \ud800-escape text a container could print must not poison the body.
        def fail(*args, timeout=None):
            return 125, "", "Error response from daemon: weird \\ud800 stuff"

        self._patched(fail, engine=True)
        c = _client()
        r = c.post("/api/volumes/remove", json={"name": "v1"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertFalse(r.json()["ok"])
        r.text.encode("utf-8")


class LogsSsePins(unittest.TestCase):
    """GET /api/containers/{name}/logs: oversize lines, junk bytes, gone CLI."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="docker5-sse-"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def _fake_docker(self, script_body: str) -> str:
        p = self.tmp / "fakedocker"
        p.write_text("#!/bin/sh\n" + script_body)
        p.chmod(0o755)
        return str(p)

    def test_oversize_line_and_junk_bytes_stream_clean_utf8(self):
        fake = self._fake_docker(
            "python3 -c \"import sys;"
            " sys.stdout.buffer.write(b'A'*200000);"
            " sys.stdout.buffer.write(b'\\xff\\xfe mid\\n')\"\n"
            "exit 0\n"
        )
        with mock.patch.object(containers_router, "DOCKER", fake):
            with _client().stream(
                "GET", "/api/containers/web/logs?follow=false&tail=50"
            ) as r:
                self.assertEqual(r.status_code, 200)
                body = b"".join(r.iter_bytes())
        text = body.decode("utf-8")  # must not raise
        self.assertIn("[line truncated]", text)

    def test_vanished_docker_binary_streams_coded_error_line(self):
        with mock.patch.object(containers_router, "DOCKER", str(self.tmp / "gone")):
            with _client().stream(
                "GET", "/api/containers/web/logs?follow=false"
            ) as r:
                self.assertEqual(r.status_code, 200)
                body = b"".join(r.iter_bytes())
        self.assertIn(b"could not start log stream", body)
        body.decode("utf-8")

    def test_option_shaped_name_is_coded_400_before_spawn(self):
        r = _client().get("/api/containers/--follow/logs")
        self.assertEqual(r.status_code, 400, r.text)
        self.assertIn("cli.invalid_value", r.text)


class StackJobEndToEndPins(unittest.TestCase):
    """A real stack job over an adversarial docker: log poll stays clean."""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="docker5-e2e-"))
        self.addCleanup(lambda: shutil.rmtree(self.home, ignore_errors=True))
        stack = self.home / "Services" / "realstack"
        stack.mkdir(parents=True)
        (stack / "docker-compose.yml").write_text("services: {}\n")
        self.fake = self.home / "fakedocker"
        self.fake.write_text(
            "#!/bin/sh\n"
            "printf 'line with \\\\ud800 escape\\n'\n"
            "python3 -c \"import sys;"
            " sys.stdout.write('9'*100000 + chr(10));"
            " sys.stdout.buffer.write(b'raw \\xff\\xfe bytes\\n')\"\n"
            "echo 'Cannot connect to the Docker daemon at unix:///x' >&2\n"
            "exit 1\n"
        )
        self.fake.chmod(0o755)

    def test_failing_job_classifies_engine_down_and_publishes_clean_log(self):
        with (
            mock.patch.object(containers_svc, "cfg", return_value={"stacks": []}),
            mock.patch.object(containers_svc, "user_home", return_value=self.home),
            mock.patch.object(compose_svc, "user_home", return_value=self.home),
            mock.patch.object(containers_svc, "DOCKER", str(self.fake)),
            mock.patch.object(containers_svc, "engine_up", return_value=False),
        ):
            containers_svc.invalidate_container_lists()
            self.addCleanup(containers_svc.invalidate_container_lists)
            c = _client()
            r = c.post("/api/stacks/realstack/run", json={"action": "up"})
            self.assertEqual(r.status_code, 200, r.text)
            tid = r.json()["job_id"]
            deadline = time.time() + 20
            while time.time() < deadline:
                j = containers_svc._cjobs.get(tid)
                if isinstance(j, dict) and j.get("running") is False:
                    break
                time.sleep(0.05)
            j = containers_svc._cjobs.get(tid)
            self.assertIsInstance(j, dict)
            self.assertFalse(j.get("running"), "job never finished")
            r = c.get(f"/api/stacks/jobs/{tid}")
            self.assertEqual(r.status_code, 200, r.text[:300])
            payload = r.json()
            # The daemon-unreachable output plus the down probe classifies
            # the failure; the poll body must carry the code and stay UTF-8.
            self.assertEqual(payload.get("code"), "container.engine_down", payload)
            self.assertIn("[line truncated]", payload["log"])
            r.text.encode("utf-8")
            self.assertNotIn("\ud800", r.text)
            r = c.get("/api/stacks")
            self.assertEqual(r.status_code, 200, r.text[:300])
            r.text.encode("utf-8")


class TerminalDockerReceiptPins(unittest.TestCase):
    """Terminal docker-exec receipts stay coded when docker is unreachable."""

    def _run_with(self, receipt):
        with (
            mock.patch.object(terminal_svc, "_run", return_value=dict(receipt)),
            mock.patch.object(terminal_svc, "engine_up", return_value=False),
            mock.patch.object(terminal_svc, "DOCKER", "/nonexistent/docker5-gone"),
        ):
            return _client().post(
                "/api/terminal/run",
                json={"target": "container", "container": "web",
                      "command": "ls", "shell": "/bin/sh"},
            )

    def test_vanished_cli_receipt_is_coded_503(self):
        r = self._run_with({
            "ok": False, "rc": 127, "stdout": "",
            "stderr": "not found: /nonexistent/docker5-gone",
            "truncated": False, "duration_ms": 1,
        })
        self.assertEqual(r.status_code, 503, r.text)
        self.assertIn("container.engine_down", r.text)

    def test_engine_down_stderr_receipt_is_coded_503(self):
        r = self._run_with({
            "ok": False, "rc": 1, "stdout": "partial",
            "stderr": "Cannot connect to the Docker daemon",
            "truncated": False, "duration_ms": 1,
        })
        self.assertEqual(r.status_code, 503, r.text)
        self.assertIn("container.engine_down", r.text)

    def test_plain_failure_receipt_keeps_its_own_output(self):
        r = self._run_with({
            "ok": False, "rc": 2, "stdout": "ls: /x: No such file",
            "stderr": "", "truncated": False, "duration_ms": 1,
        })
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["rc"], 2)


if __name__ == "__main__":
    unittest.main()
