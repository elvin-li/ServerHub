"""Process-local ``sh`` / ``run_capped`` spawn counters and the admin peek."""
from __future__ import annotations

import json
import subprocess
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from fastapi.testclient import TestClient

from hub.app_factory import create_app
from hub.routers.api import debug_spawns
from hub.util import spawn_counts, spawn_key
from hub import auth, util


class _Req:
    pass


class SpawnKeyTests(unittest.TestCase):
    def test_basename_only_by_default(self):
        self.assertEqual(spawn_key(["/usr/bin/top", "-l", "1", "-n", "0"]), "top")
        self.assertEqual(spawn_key(["/usr/sbin/sysctl", "-n", "hw.ncpu"]), "sysctl")
        self.assertEqual(spawn_key(["/usr/bin/pgrep", "-x", "Python"]), "pgrep")

    def test_docker_brew_launchctl_take_first_subcommand_only(self):
        self.assertEqual(
            spawn_key(["/usr/local/bin/docker", "ps", "-a", "--format", "secret"]),
            "docker ps",
        )
        self.assertEqual(
            spawn_key(["/usr/local/bin/docker", "inspect", "immich_server"]),
            "docker inspect",
        )
        self.assertEqual(
            spawn_key(["docker", "stats", "--no-stream", "--format", "x"]),
            "docker stats",
        )
        self.assertEqual(
            spawn_key(["/opt/homebrew/bin/brew", "services", "list", "--json"]),
            "brew services",
        )
        self.assertEqual(spawn_key(["/bin/launchctl", "list"]), "launchctl list")

    def test_skips_leading_flags_for_subcommand(self):
        self.assertEqual(spawn_key(["docker", "--help"]), "docker")
        self.assertEqual(spawn_key(["docker", "-D", "ps"]), "docker ps")

    def test_empty_subcommand_is_basename_only(self):
        self.assertEqual(spawn_key(["/usr/local/bin/docker"]), "docker")
        self.assertEqual(spawn_key(["docker", "--help"]), "docker")

    def test_never_keeps_full_argv(self):
        key = spawn_key(["docker", "ps", "/secret/path", "token-value"])
        self.assertEqual(key, "docker ps")
        self.assertNotIn("secret", key)
        self.assertNotIn("token", key)


class SpawnCountsTests(unittest.TestCase):
    def setUp(self):
        spawn_counts.reset()

    def tearDown(self):
        spawn_counts.reset()

    def test_reset_isolates_cases(self):
        spawn_counts.record(["top"])
        spawn_counts.reset()
        snap = spawn_counts.snapshot()
        self.assertEqual(snap["total"], 0)
        self.assertEqual(snap["overflow"], 0)
        self.assertEqual(snap["by_key"], {})
        self.assertEqual(snap["window_s"], 60)
        json.dumps(snap, allow_nan=False)

    def test_sh_increments(self):
        done = subprocess.CompletedProcess(["/bin/echo"], 0)
        with patch.object(util.subprocess, "run", return_value=done):
            util.sh(["/bin/echo", "hi"], timeout=1)
        snap = spawn_counts.snapshot()
        self.assertEqual(snap["by_key"].get("echo"), 1)
        self.assertEqual(snap["total"], 1)

    def test_run_capped_increments(self):
        done = subprocess.CompletedProcess(["/bin/echo"], 0)
        with patch.object(util.subprocess, "run", return_value=done):
            util.run_capped(["/usr/local/bin/docker", "ps", "-a"], timeout=1)
        snap = spawn_counts.snapshot()
        self.assertEqual(snap["by_key"].get("docker ps"), 1)
        self.assertEqual(snap["total"], 1)

    def test_invalid_argv_does_not_count(self):
        util.sh([b"--all"], timeout=1)
        self.assertEqual(spawn_counts.snapshot()["total"], 0)

    def test_run_bytes_does_not_count(self):
        done = subprocess.CompletedProcess(["diskutil"], 0, stdout=b"x")
        with patch.object(util.subprocess, "run", return_value=done):
            util.run_bytes(["diskutil"], timeout=1, runner=lambda *a, **k: done)
        self.assertEqual(spawn_counts.snapshot()["total"], 0)

    def test_cardinality_cap_overflow(self):
        for i in range(70):
            spawn_counts.record([f"/usr/bin/tool{i}"])
        snap = spawn_counts.snapshot()
        self.assertEqual(len(snap["by_key"]), 64)
        self.assertEqual(snap["overflow"], 6)
        self.assertEqual(snap["total"], 70)

    def test_existing_key_still_increments_after_cap(self):
        spawn_counts.record(["top"])
        for i in range(64):
            spawn_counts.record([f"/usr/bin/tool{i}"])
        spawn_counts.record(["/usr/bin/top", "-l", "1"])
        snap = spawn_counts.snapshot()
        self.assertEqual(snap["by_key"]["top"], 2)
        self.assertEqual(len(snap["by_key"]), 64)
        self.assertEqual(snap["overflow"], 1)

    def test_tumbling_window_resets_at_60s(self):
        clock = {"t": 0.0}

        def mono():
            return clock["t"]

        with patch("hub.util.time.monotonic", mono):
            spawn_counts.reset()
            spawn_counts.record(["top"])
            clock["t"] = 59.9
            snap = spawn_counts.snapshot()
            self.assertEqual(snap["total"], 1)
            clock["t"] = 60.0
            snap = spawn_counts.snapshot()
            self.assertEqual(snap["total"], 0)
            self.assertEqual(snap["by_key"], {})


class SpawnPeekRouteTests(unittest.TestCase):
    def setUp(self):
        spawn_counts.reset()

    def tearDown(self):
        spawn_counts.reset()

    def test_unauthenticated_peek_is_401(self):
        client = TestClient(create_app())
        r = client.get("/api/debug/spawns")
        self.assertEqual(r.status_code, 401)

    def test_public_health_is_unchanged(self):
        client = TestClient(create_app())
        r = client.get("/api/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(set(r.json()), {"ok", "ts"})

    def test_member_cannot_peek(self):
        with (
            patch.object(auth, "request_username", return_value="mom"),
            patch.object(auth, "is_admin", return_value=False),
        ):
            with self.assertRaises(HTTPException) as ctx:
                debug_spawns(_Req())
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail["code"], "auth.admin_required")

    def test_admin_peek_shape(self):
        spawn_counts.record(["/usr/bin/top"])
        spawn_counts.record(["docker", "ps", "-a", "secret-token"])
        with (
            patch.object(auth, "request_username", return_value="admin"),
            patch.object(auth, "is_admin", return_value=True),
        ):
            body = debug_spawns(_Req())
        json.dumps(body, allow_nan=False)
        self.assertEqual(body["window_s"], 60)
        self.assertIn("age_s", body)
        self.assertEqual(body["total"], 2)
        self.assertEqual(body["overflow"], 0)
        self.assertEqual(body["by_key"]["top"], 1)
        self.assertEqual(body["by_key"]["docker ps"], 1)
        blob = json.dumps(body)
        self.assertNotIn("secret-token", blob)
