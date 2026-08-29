"""Compose leftover sweep #5: HTTP stays-immune pins.

A fifth adversarial pass over the Compose surfaces (GET/PUT /api/compose/{id},
POST /api/compose[/validate], POST /api/compose/{id}/validate, GET /api/stacks,
POST /api/stacks/{id}/run, GET /api/stacks/jobs/{id}) through the real
``create_app`` wiring with ``TestClient(raise_server_exceptions=False)`` found
no live unhandled 500s.  These pins keep the corners that pass exercised —
none of which prior compose/compose2/3/4 sweeps asserted at the HTTP layer —
answering coded 2xx/4xx/503 with UTF-8-renderable bodies:

* filesystem shapes occupying docker-compose.yml: a FIFO (``open()`` of one
  used to park callers until a writer appeared), a directory, a symlink loop,
  a file past the 1MB read cap, and non-UTF-8 bytes in the content;
* hostile services.yaml stack rows: ``compose_file`` as a >4300-digit
  already-int (YAML hex loads uncapped), with an embedded NUL, or a
  ``../../`` traversal; a ``path`` with a NUL; a non-mapping stack entry;
  junk ``containers`` lists; a containers-only stack whose numeric YAML id
  renders via the str() probe while a huge hex id row is skipped, not 500'd;
* hostile path params on the compose routes: a torn IPv6 literal ``[::1``
  (urlsplit ValueError class), a percent-encoded lone surrogate, an embedded
  NUL and a 5000-digit id are coded 404s whose bodies render;
* the stack-job pipeline end to end with a real (fake) docker CLI binary:
  invalid-UTF-8 job output, a giant single output line (bounded by the
  per-line/total caps), a CLI that vanished before the spawn (coded
  ``container.engine_down`` stamped only after the failure-path probe), a
  non-executable CLI, engine-down-looking stderr, output that merely *quotes*
  the engine-down phrasing on a successful run (never classified, never
  probed), and the one-job-at-a-time mutex answering the coded 409;
* the update-container job's compose branch fed inspect JSON whose compose
  labels carry lone surrogates (JSON ``\\ud800`` escapes survive json.loads)
  — the poisoned job dict must not 500 later GET /api/stacks renders;
* POST /api/compose/validate ``cwd`` hostility: NUL / newline / DEL are the
  coded refusal, and a torn-IPv6 path segment never 500s.
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

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import compose_svc, containers_svc  # noqa: E402

VALID_COMPOSE = "services:\n  web:\n    image: nginx:alpine\n"
#: An already-int leftover past CPython's int->str digit cap (YAML hex/octal
#: spellings load uncapped, so config values arrive as ints this large).
_HUGE_INT = int("f" * 4400, 16)


class _Compose5Sandbox(unittest.TestCase):
    """Real app wiring + a real stack on disk under a temp home."""

    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        from hub.app_factory import create_app
        from hub.auth import require_auth

        cls._app = create_app()
        cls._app.dependency_overrides[require_auth] = lambda: True
        cls.client = TestClient(cls._app, raise_server_exceptions=False)

    @classmethod
    def tearDownClass(cls):
        cls._app.dependency_overrides.clear()

    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="compose5-http-148e-"))
        self.addCleanup(lambda: shutil.rmtree(self.home, ignore_errors=True))
        self.stack_dir = self.home / "Services" / "app-148e"
        self.stack_dir.mkdir(parents=True)
        self.compose = self.stack_dir / "docker-compose.yml"
        self.compose.write_text(VALID_COMPOSE)
        for p in (
            # Scan branch off (containers_svc user_home -> None); the config
            # branch serves the fixture stack.
            mock.patch.object(containers_svc, "user_home", return_value=None),
            mock.patch.object(
                containers_svc, "cfg",
                return_value={"stacks": [self._cfg_stack()]},
            ),
            mock.patch.object(compose_svc, "user_home", return_value=self.home),
        ):
            p.start()
            self.addCleanup(p.stop)

    def _cfg_stack(self) -> dict:
        return {"id": "app-148e", "name": "App", "path": str(self.stack_dir)}

    def _assert_coded_not_500(self, resp, *codes):
        self.assertLess(resp.status_code, 500, resp.text)
        detail = resp.json()["detail"]
        self.assertIn(detail["code"], codes)

    def _get(self):
        return self.client.get("/api/compose/app-148e")

    def _validate_stack(self):
        return self.client.post("/api/compose/app-148e/validate")

    def _save(self, content=VALID_COMPOSE + "# edited\n"):
        return self.client.put(
            "/api/compose/app-148e",
            content=json.dumps({"content": content, "check": False}),
            headers={"Content-Type": "application/json"},
        )


class ComposeFileShapeHttpTests(_Compose5Sandbox):
    """Leftover filesystem shapes at docker-compose.yml never 500 (or hang)."""

    def test_a_fifo_at_the_compose_path_is_the_coded_400_everywhere(self):
        # open() of a FIFO parks until a writer appears; read_text_capped's
        # O_NONBLOCK + S_ISREG gate turns it into the coded refusal instead.
        self.compose.unlink()
        os.mkfifo(self.compose)
        for resp in (self._get(), self._validate_stack(), self._save()):
            self._assert_coded_not_500(resp, "container.no_compose_file")

    def test_a_directory_occupying_the_compose_path_is_the_coded_400(self):
        self.compose.unlink()
        self.compose.mkdir()
        for resp in (self._get(), self._validate_stack(), self._save()):
            self._assert_coded_not_500(resp, "container.no_compose_file")

    def test_a_symlink_loop_at_the_compose_path_is_the_coded_400(self):
        self.compose.unlink()
        self.compose.symlink_to(self.compose)
        for resp in (self._get(), self._validate_stack(), self._save()):
            self._assert_coded_not_500(resp, "container.no_compose_file")

    def test_an_over_cap_compose_get_is_the_coded_400_not_an_oom_or_500(self):
        self.compose.write_text("#" + "x" * (2 * 1024 * 1024) + "\n" + VALID_COMPOSE)
        self._assert_coded_not_500(self._get(), "container.no_compose_file")

    def test_a_save_over_the_over_cap_leftover_still_succeeds(self):
        # The EFBIG backup handler: multi-MB junk is not worth backing up,
        # but the save over it must go through (and must not 500).
        self.compose.write_text("#" + "x" * (2 * 1024 * 1024) + "\n")
        resp = self._save(VALID_COMPOSE + "# rescued-148e\n")
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertTrue(resp.json()["ok"])
        self.assertIn("# rescued-148e", self.compose.read_text(encoding="utf-8"))

    def test_non_utf8_bytes_in_the_compose_render_replaced_not_a_500(self):
        self.compose.write_bytes(b"services:\n  w:\n    image: a:1 # \xff\xfe\n")
        resp = self._get()
        self.assertEqual(resp.status_code, 200, resp.text)
        content = resp.json()["content"]
        self.assertIn("image: a:1", content)
        self.assertNotIn("\udcff", content)


class HostileConfigStackHttpTests(_Compose5Sandbox):
    """Poisoned services.yaml stack rows keep every compose route coded."""

    def _with_stacks(self, stacks):
        return mock.patch.object(
            containers_svc, "cfg", return_value={"stacks": stacks},
        )

    def _sweep(self):
        for resp in (
            self.client.get("/api/stacks"),
            self._get(),
            self._validate_stack(),
            self._save(),
        ):
            self.assertLess(resp.status_code, 500, resp.text)
            resp.json()

    def test_huge_already_int_compose_file_falls_back_and_never_500s(self):
        # ``compose_file: 0xfff…`` loads as an over-cap int; the isinstance
        # gate must fall back to docker-compose.yml, so the stack stays fully
        # usable rather than raising str()'s digit-cap ValueError.
        with self._with_stacks(
            [{"id": "app-148e", "path": str(self.stack_dir), "compose_file": _HUGE_INT}]
        ):
            resp = self._get()
            self.assertEqual(resp.status_code, 200, resp.text)
            self.assertEqual(resp.json()["content"], VALID_COMPOSE)
            self._sweep()

    def test_nul_and_traversal_compose_file_values_stay_coded(self):
        for compose_file in ("a\x00b.yml", "../../../etc/hostname"):
            with self.subTest(compose_file=compose_file):
                with self._with_stacks(
                    [{"id": "app-148e", "path": str(self.stack_dir),
                      "compose_file": compose_file}]
                ):
                    self._sweep()

    def test_a_nul_in_the_stack_path_stays_coded(self):
        with self._with_stacks(
            [{"id": "app-148e", "path": str(self.stack_dir) + "\x00x"}]
        ):
            self._sweep()

    def test_a_non_mapping_stack_entry_is_skipped_not_a_500(self):
        with self._with_stacks(["not-a-dict", 42, None]):
            resp = self.client.get("/api/stacks")
            self.assertEqual(resp.status_code, 200, resp.text)
            self.assertEqual(resp.json()["stacks"], [])

    def test_junk_containers_entries_are_dropped_not_a_500(self):
        with self._with_stacks(
            [{"id": "app-148e", "path": str(self.stack_dir),
              "containers": [1, None, {"a": 1}, "ok", float("inf"), "\ud800"]}]
        ):
            resp = self.client.get("/api/stacks")
            self.assertEqual(resp.status_code, 200, resp.text)
            row = resp.json()["stacks"][0]
            # Non-str junk is dropped; the surrogate survives only in its
            # scrubbed ``?`` form so the row still UTF-8-encodes.
            self.assertEqual(row["containers"], ["ok", "?"])
            self.assertNotIn("\ud800", json.dumps(row))
            self._sweep()

    def test_containers_only_numeric_id_renders_and_huge_hex_id_is_skipped(self):
        with self._with_stacks(
            [{"id": 42, "containers": ["x"]},
             {"id": _HUGE_INT, "containers": ["y"]}]
        ):
            resp = self.client.get("/api/stacks")
            self.assertEqual(resp.status_code, 200, resp.text)
            ids = [s["id"] for s in resp.json()["stacks"]]
            self.assertEqual(ids, ["42"])


class HostilePathParamHttpTests(_Compose5Sandbox):
    """Torn IPv6 / surrogate / NUL / huge-digit ids are coded 404s that render."""

    def test_compose_routes_answer_coded_404s_for_hostile_stack_ids(self):
        for sid in ("[::1", "x%ED%A0%80", "a%00b", "9" * 5000):
            for url in (f"/api/compose/{sid}", f"/api/compose/{sid}/validate"):
                with self.subTest(url=url[:60]):
                    resp = (
                        self.client.get(url)
                        if url.endswith(sid) else self.client.post(url)
                    )
                    self.assertEqual(resp.status_code, 404, resp.text)
                    self.assertEqual(
                        resp.json()["detail"]["code"], "compose.unknown_stack",
                    )

    def test_job_log_lookups_render_for_hostile_job_ids(self):
        for jid in ("[::1", "j%ED%A0%80x", "a" * 4096):
            with self.subTest(jid=jid[:24]):
                resp = self.client.get(f"/api/stacks/jobs/{jid}")
                self.assertEqual(resp.status_code, 200, resp.text)
                body = resp.json()
                self.assertFalse(body["running"])
                self.assertNotIn("\ud800", json.dumps(body))


class _StackJobSandbox(_Compose5Sandbox):
    """Compose5 sandbox plus a controllable fake docker CLI binary."""

    def _fake_docker(self, script: str, mode: int = 0o755) -> str:
        fake = self.home / "docker"
        fake.write_text("#!/bin/sh\n" + script)
        fake.chmod(mode)
        return str(fake)

    def _run_stack_job(self, docker_path: str, action: str = "up"):
        with mock.patch.object(containers_svc, "DOCKER", docker_path):
            resp = self.client.post(
                "/api/stacks/app-148e/run",
                content=json.dumps({"action": action}),
                headers={"Content-Type": "application/json"},
            )
            self.assertEqual(resp.status_code, 200, resp.text)
            return self._wait_job(resp.json()["job_id"])

    def _wait_job(self, jid: str, timeout: float = 20.0) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            resp = self.client.get(f"/api/stacks/jobs/{jid}")
            self.assertEqual(resp.status_code, 200, resp.text)
            body = resp.json()
            if body.get("running") is False:
                return body
            time.sleep(0.05)
        self.fail(f"job {jid} did not finish within {timeout}s")


class StackJobHostileCliHttpTests(_StackJobSandbox):
    """The job pipeline survives hostile CLI binaries and hostile output."""

    def test_invalid_utf8_job_output_renders_replaced_not_a_500(self):
        job = self._run_stack_job(
            self._fake_docker("printf 'bad: \\377\\376 bytes\\n'; exit 0\n")
        )
        self.assertEqual(job["rc"], 0)
        self.assertIn("bad:", job["log"])
        # The whole /api/stacks render must survive the retained job dict.
        resp = self.client.get("/api/stacks")
        self.assertEqual(resp.status_code, 200, resp.text)

    def test_a_giant_single_output_line_is_bounded_not_an_oom(self):
        job = self._run_stack_job(
            self._fake_docker(
                "head -c 300000 /dev/zero | tr '\\0' 'x'; echo; exit 0\n"
            )
        )
        self.assertEqual(job["rc"], 0)
        # Per-line cap (4096 chars) + trailer, never the raw 300k line.
        self.assertLess(len(job["log"]), 20000)
        self.assertIn("[line truncated]", job["log"])

    def test_a_vanished_cli_job_is_stamped_engine_down_after_the_probe(self):
        probe = mock.Mock(return_value=False)
        with mock.patch.object(containers_svc, "engine_up", probe):
            job = self._run_stack_job("/nonexistent/docker-148e")
        self.assertEqual(job["rc"], -1)
        self.assertEqual(job["code"], "container.engine_down")
        probe.assert_called_once_with(force=True)

    def test_a_non_executable_cli_fails_coded_in_the_log_not_a_500(self):
        job = self._run_stack_job(
            self._fake_docker("exit 0\n", mode=0o644)
        )
        self.assertEqual(job["rc"], -1)
        self.assertIn("!! error:", job["log"])
        resp = self.client.get("/api/stacks")
        self.assertEqual(resp.status_code, 200, resp.text)

    def test_engine_down_stderr_is_classified_only_when_the_probe_confirms(self):
        script = (
            "echo 'Cannot connect to the Docker daemon at unix:///x."
            " Is the docker daemon running?' >&2; exit 1\n"
        )
        probe = mock.Mock(return_value=False)
        with mock.patch.object(containers_svc, "engine_up", probe):
            job = self._run_stack_job(self._fake_docker(script))
        self.assertEqual(job["code"], "container.engine_down")
        probe.assert_called_once_with(force=True)
        # Same output with a live engine keeps the raw failure, no code.
        probe = mock.Mock(return_value=True)
        with mock.patch.object(containers_svc, "engine_up", probe):
            job = self._run_stack_job(self._fake_docker(script))
        self.assertIsNone(job.get("code"))
        probe.assert_called_once_with(force=True)

    def test_quoting_engine_down_on_a_successful_run_never_classifies(self):
        # ``docker compose down`` output that merely *quotes* the phrasing
        # (a container's own log line) with rc 0 must not probe or stamp.
        probe = mock.Mock(return_value=False)
        with mock.patch.object(containers_svc, "engine_up", probe):
            job = self._run_stack_job(
                self._fake_docker("echo 'is the docker daemon running'; exit 0\n"),
                action="down",
            )
        self.assertEqual(job["rc"], 0)
        self.assertIsNone(job.get("code"))
        probe.assert_not_called()

    def test_the_job_mutex_answers_the_coded_409_while_a_job_runs(self):
        fake = self._fake_docker("sleep 1; exit 0\n")
        with mock.patch.object(containers_svc, "DOCKER", fake):
            first = self.client.post(
                "/api/stacks/app-148e/run",
                content=json.dumps({"action": "pull"}),
                headers={"Content-Type": "application/json"},
            )
            self.assertEqual(first.status_code, 200, first.text)
            second = self.client.post(
                "/api/stacks/app-148e/run",
                content=json.dumps({"action": "up"}),
                headers={"Content-Type": "application/json"},
            )
            self.assertEqual(second.status_code, 409, second.text)
            self.assertEqual(
                second.json()["detail"]["code"], "container.job_running",
            )
            self._wait_job(first.json()["job_id"])


class UpdateContainerComposeLabelHttpTests(_StackJobSandbox):
    """Surrogate compose labels in inspect JSON never poison later renders.

    ``docker inspect`` emits JSON; a ``\\ud800`` escape in a compose label
    survives json.loads as a lone surrogate.  The update job embeds those
    labels in its command line, its log, and its retained ``stack_id`` —
    every one of which outlives the request and feeds GET /api/stacks.
    """

    def test_surrogate_compose_labels_keep_every_job_render_coded(self):
        inspect_obj = {
            "Config": {
                "Image": "a:1",
                "Labels": {
                    "com.docker.compose.project": "p\ud800rj",
                    "com.docker.compose.project.working_dir": "/nonexistent\ud800dir",
                    "com.docker.compose.project.config_files":
                        "/nonexistent\ud800dir/docker-compose.yml",
                    "com.docker.compose.service": "web",
                },
            },
        }
        fake = self._fake_docker("exit 1\n")
        with (
            mock.patch.object(containers_svc, "DOCKER", fake),
            mock.patch.object(
                containers_svc, "docker",
                return_value=(0, json.dumps([inspect_obj]), ""),
            ),
            mock.patch.object(containers_svc, "engine_up", return_value=True),
        ):
            resp = self.client.post("/api/containers/ctr-148e/update")
            self.assertEqual(resp.status_code, 200, resp.text)
            job = self._wait_job(resp.json()["job_id"])
        self.assertNotIn("\ud800", json.dumps(job))
        stacks = self.client.get("/api/stacks")
        self.assertEqual(stacks.status_code, 200, stacks.text)
        self.assertNotIn("\ud800", json.dumps(stacks.json()))


class ValidateCwdHttpTests(_Compose5Sandbox):
    """POST /api/compose/validate cwd hostility stays a soft refusal."""

    def _validate(self, cwd):
        return self.client.post(
            "/api/compose/validate",
            content=json.dumps({"content": VALID_COMPOSE, "cwd": cwd}),
            headers={"Content-Type": "application/json"},
        )

    def test_control_characters_in_cwd_are_the_coded_refusal(self):
        for cwd in ("/tmp/x\x00y", "/tmp/a\nb", "/tmp/a\x7fb"):
            with self.subTest(cwd=repr(cwd)):
                resp = self._validate(cwd)
                self.assertEqual(resp.status_code, 200, resp.text)
                body = resp.json()
                self.assertFalse(body["ok"])
                self.assertEqual(body["message"], "invalid working directory")

    def test_a_torn_ipv6_cwd_segment_never_500s(self):
        # urlsplit of ``[::1`` raises ValueError; a cwd carrying the same
        # torn literal as a path segment must stay a plain soft outcome.
        cwd = str(self.home / "[::1")
        with mock.patch.object(
            compose_svc, "run_capped", return_value=(1, "boom"),
        ):
            resp = self._validate(cwd)
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertFalse(body["ok"])
        self.assertNotIn("Traceback", body["message"])


if __name__ == "__main__":
    unittest.main()
