"""Fourth leftover sweep of the Docker/container routes: two live leftovers.

Both were reproduced over the real mounted app (``create_app()`` +
``TestClient(raise_server_exceptions=False)``) and are fixed with this
battery:

* **fixed — "edit ports" destroyed the container.**
  ``network_svc.docker_update_ports`` ran ``docker stop`` + ``docker rm``
  and only *then* handed the rebuilt body to ``create_run_container``,
  whose validation gates (the panel's 64-char container-name form cap, the
  201-char image cap of ``re_match_image``) rejected it with a coded 400.
  Both caps are panel limits, not docker limits: a compose-generated or
  digest-pinned name/image that docker itself is perfectly happy with
  turned POST /api/system/network/docker/ports/{name} into "destroy the
  container" — the 400 arrived with the container already removed and
  nothing ever recreated (the sibling-wipe class, aimed at one row).
  The gates now run *before* the destructive stop/rm via the side-effect
  free ``containers_svc.build_run_args``.

* **fixed — surrogate-named scan stacks pointed I/O at the wrong path.**
  ``_stack_paths`` publishes ``path``/``compose_path`` scrubbed for
  Starlette's UTF-8 encode, so for a directory name carrying one non-UTF-8
  byte (``surrogateescape`` — routine on external volumes) the published
  ``?``-replacement text named a file that does not exist … or a *sibling*
  directory whose name really contains the ``?``.  Downstream I/O trusted
  that text: GET /api/compose/{id} answered 400 ``no_compose_file`` for a
  compose the scan had just globbed, POST /api/compose/{id}/validate
  ``mkdir()``'d a brand-new ``?``-named tree beside the real stack, a save
  would have written the new compose into it, and a stack job ran docker
  compose against it.  ``_stack_paths`` now keeps the raw os-level twins
  (``os_path``/``os_compose_path``) beside the scrubbed display fields;
  file I/O and job spawns read through the raw text, ``list_stacks`` strips
  the twins before rows are published, and ``validate_stack`` falls back to
  the clean ~/Services default when the raw name cannot ride in argv.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from fastapi.testclient import TestClient  # noqa: E402

from hub import compose_svc, containers_svc, network_svc  # noqa: E402
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


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does to a payload."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


_INSPECT = [{
    "Config": {"Image": "nginx:latest", "Env": ["PATH=/usr/bin", "TZ=UTC"],
               "Cmd": None},
    "HostConfig": {"Binds": ["/srv/data:/data"], "NetworkMode": "bridge",
                   "RestartPolicy": {"Name": "always"}, "Privileged": False},
}]


class UpdatePortsPreflightPinTests(unittest.TestCase):
    """The recreate gates must run before the destructive stop/rm."""

    #: Legal for docker (its limit is far higher), over the panel's 64-char
    #: form cap — the exact shape of a compose-generated name with a long
    #: project prefix.
    LONG_NAME = "a" * 70

    def _post_ports(self, name, inspect_payload=_INSPECT):
        calls = []

        def fake_docker(*args, timeout=None):
            calls.append(tuple(args))
            if args and args[0] == "inspect":
                return 0, json.dumps(inspect_payload), ""
            return 0, "", ""

        with (
            mock.patch.object(network_svc, "docker", side_effect=fake_docker),
            mock.patch.object(network_svc, "engine_up", return_value=True),
            mock.patch.object(containers_svc, "docker", side_effect=fake_docker),
            mock.patch.object(containers_svc, "engine_up", return_value=True),
        ):
            r = _client().post(
                f"/api/system/network/docker/ports/{name}",
                json={"ports": ["8080:80"]},
            )
        return r, calls

    def test_long_name_400s_before_any_stop_or_rm(self):
        r, calls = self._post_ports(self.LONG_NAME)
        self.assertEqual(r.status_code, 400, r.text)
        self.assertIn("container.bad_container_name", r.text)
        verbs = [c[0] for c in calls]
        # The whole point: the coded 400 used to arrive *after* stop+rm had
        # already destroyed the container, with nothing recreated.
        self.assertNotIn("stop", verbs, calls)
        self.assertNotIn("rm", verbs, calls)
        self.assertNotIn("run", verbs, calls)

    def test_over_cap_digest_image_400s_before_any_stop_or_rm(self):
        # A digest-pinned image reference from inspect past re_match_image's
        # 201-char cap — docker accepts it, the panel's recreate gate does not.
        long_image = "registry.example.com/" + "team/" * 36 + "app@sha256:" + "0" * 64
        payload = [{
            "Config": {"Image": long_image, "Env": [], "Cmd": None},
            "HostConfig": dict(_INSPECT[0]["HostConfig"]),
        }]
        r, calls = self._post_ports("webapp", inspect_payload=payload)
        self.assertEqual(r.status_code, 400, r.text)
        self.assertIn("container.image_required", r.text)
        verbs = [c[0] for c in calls]
        self.assertNotIn("stop", verbs, calls)
        self.assertNotIn("rm", verbs, calls)

    def test_clean_recreate_still_stops_removes_and_runs(self):
        r, calls = self._post_ports("webapp")
        self.assertEqual(r.status_code, 200, r.text)
        verbs = [c[0] for c in calls]
        self.assertIn("stop", verbs)
        self.assertIn("rm", verbs)
        self.assertIn("run", verbs)
        # Order still holds: validation, then stop, then rm, then run.
        self.assertLess(verbs.index("stop"), verbs.index("rm"))
        self.assertLess(verbs.index("rm"), verbs.index("run"))


class _SurrogateStackBase(unittest.TestCase):
    """A scan stack whose directory name carries one non-UTF-8 byte."""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="surrogate-stack-"))
        self.addCleanup(lambda: shutil.rmtree(self.home, ignore_errors=True))
        services = self.home / "Services"
        services.mkdir()
        raw = os.fsencode(str(services)) + b"/we\xffird"
        os.mkdir(raw)
        with open(raw + b"/docker-compose.yml", "wb") as fh:
            fh.write(b"services: {}\n")
        #: What the filesystem hands back: surrogateescape text.
        self.os_dir = os.fsdecode(raw)
        self.assertIn("\udcff", self.os_dir)
        #: What _field_text publishes: the ``?``-replacement twin.
        self.scrubbed_id = "we?ird"
        #: The ``?``-named sibling the scrubbed text used to point I/O at.
        self.sibling = services / "we?ird"
        self._patches = [
            mock.patch.object(containers_svc, "cfg", return_value={"stacks": []}),
            mock.patch.object(containers_svc, "user_home", return_value=self.home),
            mock.patch.object(compose_svc, "user_home", return_value=self.home),
        ]
        for p in self._patches:
            p.start()
            self.addCleanup(p.stop)


class SurrogateScanStackPinTests(_SurrogateStackBase):

    def test_scan_keeps_the_raw_twins_beside_the_scrubbed_fields(self):
        stacks = containers_svc._stack_paths()
        self.assertEqual(len(stacks), 1)
        s = stacks[0]
        self.assertEqual(s["id"], self.scrubbed_id)
        self.assertEqual(s["os_path"], self.os_dir)
        self.assertTrue(s["os_compose_path"].endswith("docker-compose.yml"))
        self.assertIn("\udcff", s["os_compose_path"])
        # The published display fields stay Starlette-encodable.
        _starlette({k: v for k, v in s.items()
                    if k not in ("os_path", "os_compose_path")})

    def test_get_compose_reads_the_file_the_scan_found(self):
        # Used to 400 ``no_compose_file``: the scrubbed compose_path named a
        # file that does not exist.
        data = compose_svc.get_compose(self.scrubbed_id)
        self.assertEqual(data["content"], "services: {}\n")
        _starlette(data)

    def test_http_get_compose_200s_with_the_content(self):
        with mock.patch.object(containers_svc, "list_containers", return_value=[]):
            quoted = urllib.parse.quote(self.scrubbed_id, safe="")
            r = _client().get(f"/api/compose/{quoted}")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["content"], "services: {}\n")
        self.assertNotIn("\udcff", r.text)

    def test_http_stacks_listing_strips_the_raw_twins(self):
        with mock.patch.object(containers_svc, "list_containers", return_value=[]):
            r = _client().get("/api/stacks")
        self.assertEqual(r.status_code, 200, r.text)
        rows = r.json()["stacks"]
        self.assertEqual(len(rows), 1)
        self.assertNotIn("os_path", rows[0])
        self.assertNotIn("os_compose_path", rows[0])
        self.assertEqual(rows[0]["id"], self.scrubbed_id)

    def test_validate_stack_never_mkdirs_the_question_mark_sibling(self):
        seen = {}

        def fake_run_capped(cmd, cwd=None, timeout=None, env=None, cap=None):
            seen["cwd"] = cwd
            return 0, ""

        with mock.patch.object(compose_svc, "run_capped", side_effect=fake_run_capped):
            v = compose_svc.validate_stack(self.scrubbed_id)
        self.assertTrue(v.get("ok"), v)
        # The raw name cannot ride in argv, so the check runs from the clean
        # ~/Services default — it used to mkdir() the scrubbed ``we?ird``
        # text and create a brand-new sibling tree on every validate click.
        self.assertEqual(seen["cwd"], str(self.home / "Services"))
        self.assertFalse(self.sibling.exists(),
                         "validate created the ?-named sibling directory")

    def test_save_compose_writes_through_the_raw_name(self):
        result = compose_svc.save_compose(
            self.scrubbed_id, "services: {redis: {image: redis}}\n",
            validate=False,
        )
        self.assertTrue(result["ok"], result)
        _starlette(result)
        on_disk = Path(self.os_dir, "docker-compose.yml").read_text()
        self.assertIn("redis", on_disk)
        self.assertFalse(self.sibling.exists(),
                         "save created the ?-named sibling directory")

    def test_stack_job_spawns_against_the_raw_paths(self):
        seen = {}

        def fake_stream(cmd, j, cwd=None, env=None, timeout=None):
            seen.setdefault("cmds", []).append(list(cmd))
            seen["cwd"] = cwd
            return 0

        with mock.patch.object(
            containers_svc, "_stream_job_command", side_effect=fake_stream
        ):
            out = containers_svc.start_stack_job(self.scrubbed_id, "up")
            tid = out["job_id"]
            deadline = time.time() + 10
            while time.time() < deadline:
                j = containers_svc._cjobs.get(tid)
                if isinstance(j, dict) and j.get("running") is False:
                    break
                time.sleep(0.02)
        j = containers_svc._cjobs.get(tid)
        self.assertIsInstance(j, dict)
        self.assertEqual(j.get("rc"), 0, j)
        # cwd and the -f argument carry the surrogateescape text that names
        # the real directory — not the scrubbed ``?`` twin that named the
        # (possibly existing!) sibling.
        self.assertEqual(seen["cwd"], self.os_dir)
        compose_args = [c for c in seen["cmds"][0] if "docker-compose" in str(c)]
        self.assertTrue(compose_args, seen["cmds"])
        self.assertIn("\udcff", compose_args[0])
        # The job log echoed those raw paths; the poll route must still
        # publish clean UTF-8.
        log = containers_svc.stack_job_log(tid)
        _starlette(log)
        self.assertNotIn("\udcff", log["log"])


if __name__ == "__main__":
    unittest.main()
