"""Regression tests for the third-wave audit's low-severity hardening findings.

Each class pins one finding so it cannot silently regress:

1. ``/api/launcher`` is no longer on the member read whitelist.
2. ``/api/auth/status`` does not hand the admin name to an unauthenticated caller.
3. the UPS-policy state file is cross-process safe (mirrors the 2FA/API-key fix).
4. pg-backup host/db/user reject libpq connection strings.
5. ``backup-credentials.json`` is tightened to 0600 on read.
6. a member cannot force the expensive status rebuild with ``?force=true``.
"""
from __future__ import annotations

import json
import multiprocessing
import os
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import mock

from hub import auth, backups, ups_policy
from tests.test_member_login import _MultiUserSandbox

_MP = multiprocessing.get_context("spawn")


def _req(method: str, path: str) -> SimpleNamespace:
    return SimpleNamespace(method=method, url=SimpleNamespace(path=path))


# ── 1. member whitelist ──────────────────────────────────────────────────────


class MemberWhitelistTests(unittest.TestCase):
    def test_launcher_is_no_longer_whitelisted(self):
        self.assertFalse(
            auth.member_request_authorized(_req("GET", "/api/launcher"), "mom")
        )

    def test_core_read_paths_stay_allowed(self):
        for path in ("/api/health", "/api/status", "/api/services"):
            self.assertTrue(
                auth.member_request_authorized(_req("GET", path), "mom"),
                f"{path} should stay on the member whitelist",
            )

    def test_writes_are_denied(self):
        self.assertFalse(
            auth.member_request_authorized(_req("POST", "/api/status"), "mom")
        )


# ── 2. unauthenticated status must not leak the admin name ───────────────────


class AuthStatusUsernameLeakTests(_MultiUserSandbox):
    def test_unauthenticated_status_hides_the_admin_username(self):
        body = self.client.get("/api/auth/status").json()
        self.assertFalse(body["authenticated"])
        self.assertFalse(body["setup_required"])
        self.assertEqual(body["username"], "")

    def test_member_status_still_names_the_member(self):
        body = self.member_session().get("/api/auth/status").json()
        self.assertEqual(body["username"], "mom")


# ── 3. UPS policy state file is cross-process atomic ─────────────────────────


def _race_ups_increment(state: str, lock: str, barrier, queue) -> None:
    """Child: read-modify-write the UPS state under a widened race window."""
    from hub import ups_policy as up

    real_load = up._load_state

    def slow_load():
        data = real_load()
        time.sleep(0.4)
        return data

    with mock.patch.object(up, "STATE_FILE", Path(state)), \
            mock.patch.object(up, "_LOCK_PATH", Path(lock)), \
            mock.patch.object(up, "_load_state", slow_load):
        barrier.wait(timeout=30)
        up._mutate(lambda s: s.update(n=(s.get("n") or 0) + 1))
    queue.put(True)


class UpsPolicyCrossProcessTests(unittest.TestCase):
    def test_two_processes_do_not_lose_an_update(self):
        with TemporaryDirectory() as d:
            state = str(Path(d) / "ups-policy-state.json")
            lock = str(Path(d) / "ups-policy-state.json.lock")
            barrier = _MP.Barrier(2)
            queue = _MP.Queue()
            procs = [
                _MP.Process(target=_race_ups_increment, args=(state, lock, barrier, queue))
                for _ in range(2)
            ]
            for p in procs:
                p.start()
            for p in procs:
                p.join(timeout=30)
            for p in procs:
                self.assertFalse(p.is_alive(), "child hung")
            # Both incremented one shared counter through a 0.4s read window;
            # without the fcntl lock both read 0 and the file ends at 1.
            final = json.loads(Path(state).read_text())
            self.assertEqual(final.get("n"), 2)

    def test_file_lock_is_reentrant_within_a_thread(self):
        # sweep holds the lock and then calls _mutate/_engage on the same
        # thread; a non-reentrant lock would self-deadlock on the second flock.
        with TemporaryDirectory() as d:
            with mock.patch.object(ups_policy, "STATE_FILE", Path(d) / "s.json"), \
                    mock.patch.object(ups_policy, "_LOCK_PATH", Path(d) / "s.json.lock"):
                with ups_policy._file_lock():
                    ups_policy._mutate(lambda s: s.update(k=1))
                    with ups_policy._file_lock():
                        ups_policy._mutate(lambda s: s.update(k=2))
                self.assertEqual(ups_policy._load_state().get("k"), 2)


class UpsWorkerBusyTests(unittest.TestCase):
    def test_no_owner_is_free(self):
        self.assertFalse(ups_policy._worker_busy({}))

    def test_live_foreign_pid_is_busy(self):
        st = {"worker_owner": {"pid": os.getpid(), "ts": int(time.time())}}
        # _worker_active is not set in this test, so only the persisted owner
        # can make it busy — proving the cross-process claim is honoured.
        self.assertFalse(ups_policy._worker_active.is_set())
        self.assertTrue(ups_policy._worker_busy(st))

    def test_dead_pid_reads_free_so_a_resumed_sweep_takes_over(self):
        st = {"worker_owner": {"pid": 999_999, "ts": int(time.time())}}
        self.assertFalse(ups_policy._worker_busy(st))

    def test_stale_claim_is_ignored(self):
        st = {"worker_owner": {"pid": os.getpid(), "ts": int(time.time()) - 90_000}}
        self.assertFalse(ups_policy._worker_busy(st))


# ── 4. pg-backup fields reject libpq connection strings ──────────────────────


class PgConninfoRejectionTests(unittest.TestCase):
    def test_connection_string_in_db_is_dropped(self):
        self.assertEqual(
            backups.pg_targets([{"id": "t", "db": "host=evil.tld dbname=x"}]), []
        )

    def test_connection_string_in_host_is_dropped(self):
        self.assertEqual(
            backups.pg_targets([{"id": "t", "db": "teslamate", "host": "h=1 y=2"}]), []
        )

    def test_whitespace_in_user_is_dropped(self):
        self.assertEqual(
            backups.pg_targets(
                [{"id": "t", "db": "teslamate", "user": "a b"}]
            ),
            [],
        )

    def test_clean_target_is_accepted(self):
        out = backups.pg_targets([{"id": "tesla", "db": "teslamate"}])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["db"], "teslamate")
        self.assertEqual(out[0]["user"], "teslamate")
        self.assertEqual(out[0]["host"], "localhost")

    def test_conninfo_char_helper(self):
        self.assertTrue(backups._pg_conninfo_chars("a=b"))
        self.assertTrue(backups._pg_conninfo_chars("a b"))
        self.assertTrue(backups._pg_conninfo_chars("a\tb"))
        self.assertFalse(backups._pg_conninfo_chars("teslamate-01.db_1"))


# ── 5. backup-credentials.json is tightened to 0600 on read ──────────────────


class BackupSecretModeTests(unittest.TestCase):
    def test_loose_mode_is_tightened_on_read(self):
        with TemporaryDirectory() as d:
            f = Path(d) / "backup-credentials.json"
            f.write_text(json.dumps({"tesla": {"password": "pw"}}))
            os.chmod(f, 0o644)
            with mock.patch.object(backups, "BACKUP_SECRETS_FILE", f):
                self.assertEqual(backups._pg_password("tesla"), "pw")
            self.assertEqual(f.stat().st_mode & 0o777, 0o600)

    def test_missing_file_is_silent(self):
        with TemporaryDirectory() as d:
            with mock.patch.object(backups, "BACKUP_SECRETS_FILE", Path(d) / "nope.json"):
                self.assertEqual(backups._pg_password("tesla"), "")


# ── 6. a member cannot force the status rebuild ──────────────────────────────


class MemberForceCacheTests(_MultiUserSandbox):
    def test_member_status_ignores_force(self):
        from hub.routers import api as api_router

        seen: list[bool] = []

        def spy(force=False):
            seen.append(force)
            return {"groups": []}

        with mock.patch.object(api_router, "full_status", spy):
            r = self.member_session().get("/api/status?force=true")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(seen)
        self.assertNotIn(True, seen)

    def test_admin_status_honours_force(self):
        from hub.routers import api as api_router

        seen: list[bool] = []

        def spy(force=False):
            seen.append(force)
            return {"groups": []}

        with mock.patch.object(api_router, "full_status", spy):
            self.admin_session().get("/api/status?force=true")
        self.assertIn(True, seen)

    def test_member_services_ignores_force(self):
        from hub.routers import services_api

        seen: list[bool] = []

        def spy(force=False):
            seen.append(force)
            return {"groups": []}

        with mock.patch.object(services_api.services_manage_svc, "list_manageable", spy):
            r = self.member_session().get("/api/services?force=true")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(seen)
        self.assertNotIn(True, seen)


if __name__ == "__main__":
    unittest.main(verbosity=2)
