"""Cross-process single-use guarantees for the 2FA and API-key stores.

The audit reproduced a real double-spend: two *processes* (not threads)
submitting the same TOTP code against one shared ``data/twofa.json`` were both
accepted, because the read→compare→write in hub/twofa_svc.py was guarded only
by a module-level ``threading.Lock`` — invisible to a second interpreter.
This deployment shape exists on the target machine (packaged ServerHub.app and
the LaunchAgent panel share ``data/``; hub/config.py grew its services.yaml
flock for exactly that reason).  hub/api_keys.py had the same defect: a
``verify()`` last_used write-back racing a ``revoke()`` in the other process
could rewrite the store from a stale snapshot and resurrect the revoked key.

These tests spawn two real interpreters (``multiprocessing`` spawn context, so
nothing is shared but the store file) and race them through the same window.
``_load`` is patched with a short sleep in the children to hold the
read-modify-write window open: without the fcntl file lock both processes read
the same pre-image and both succeed; with it the second blocks until the first
has written, then sees the spent state.
"""
from __future__ import annotations

import fcntl
import multiprocessing
import os
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from hub import api_keys, totp, twofa_svc

NOW = 1_700_000_000
_MP = multiprocessing.get_context("spawn")


def _slow_load(module, delay: float):
    """Patch *module*._load to sleep after reading, widening the race window."""
    real = module._load

    def slow():
        data = real()
        time.sleep(delay)
        return data

    return mock.patch.object(module, "_load", slow)


# ── child processes (top-level so the spawn context can import them) ─────────


def _race_totp(store: str, code: str, barrier, queue) -> None:
    from hub import twofa_svc as svc

    with mock.patch.object(svc, "STORE_FILE", Path(store)), _slow_load(svc, 0.4):
        barrier.wait(timeout=30)
        ok = svc.verify_totp_code("admin", code, timestamp=NOW + 60)
    queue.put(bool(ok))


def _race_recovery(store: str, code: str, barrier, queue) -> None:
    from hub import twofa_svc as svc

    with mock.patch.object(svc, "STORE_FILE", Path(store)), _slow_load(svc, 0.4):
        barrier.wait(timeout=30)
        ok = svc.use_recovery_code("admin", code)
    queue.put(bool(ok))


def _verify_key(store: str, token: str, barrier, queue) -> None:
    from hub import api_keys as keys

    # The longer sleep: without the file lock this write-back lands *after*
    # the other process's revoke and resurrects the key from a stale snapshot.
    with mock.patch.object(keys, "STORE_FILE", Path(store)), _slow_load(keys, 0.6):
        barrier.wait(timeout=30)
        record = keys.verify(token)
    queue.put(record is not None)


def _revoke_key(store: str, key_id: str, barrier, queue) -> None:
    from hub import api_keys as keys

    with mock.patch.object(keys, "STORE_FILE", Path(store)), _slow_load(keys, 0.1):
        barrier.wait(timeout=30)
        record = keys.revoke(key_id)
    queue.put(record is not None)


class _Sandbox(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def run_pair(self, target_a, args_a: tuple, target_b, args_b: tuple) -> list:
        """Run two children through a shared barrier; return their results."""
        barrier = _MP.Barrier(2)
        queue = _MP.Queue()
        procs = [
            _MP.Process(target=target_a, args=(*args_a, barrier, queue)),
            _MP.Process(target=target_b, args=(*args_b, barrier, queue)),
        ]
        for p in procs:
            p.start()
        results = [queue.get(timeout=60), queue.get(timeout=60)]
        for p in procs:
            p.join(timeout=60)
            self.assertEqual(p.exitcode, 0)
        return results


class TotpCrossProcessTests(_Sandbox):
    def setUp(self):
        super().setUp()
        self.store = self.dir / "twofa.json"
        patcher = mock.patch.object(twofa_svc, "STORE_FILE", self.store)
        patcher.start()
        self.addCleanup(patcher.stop)
        secret = twofa_svc.begin_enrollment("admin")["secret"]
        self.codes = twofa_svc.confirm_enrollment(
            "admin", totp.totp_at(secret, NOW), timestamp=NOW
        )
        self.secret = secret

    def test_the_same_totp_code_is_accepted_by_exactly_one_process(self):
        code = totp.totp_at(self.secret, NOW + 60)
        results = self.run_pair(
            _race_totp, (str(self.store), code),
            _race_totp, (str(self.store), code),
        )
        self.assertEqual(sorted(results), [False, True])

    def test_the_same_recovery_code_is_spent_by_exactly_one_process(self):
        code = self.codes[0]
        results = self.run_pair(
            _race_recovery, (str(self.store), code),
            _race_recovery, (str(self.store), code),
        )
        self.assertEqual(sorted(results), [False, True])
        # And it is gone afterwards, not merely refused once.
        self.assertFalse(twofa_svc.use_recovery_code("admin", code))

    def test_mutations_block_while_another_process_holds_the_file_lock(self):
        """flock semantics without multiprocessing: an exclusive lock held on
        the lock file stalls verify_totp_code until it is released."""
        lock_path = self.store.with_name(self.store.name + ".lock")
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)

        result: list = []
        code = totp.totp_at(self.secret, NOW + 60)
        worker = threading.Thread(
            target=lambda: result.append(
                twofa_svc.verify_totp_code("admin", code, timestamp=NOW + 60)
            )
        )
        worker.start()
        worker.join(timeout=0.3)
        self.assertTrue(worker.is_alive(), "verify must block on the file lock")

        fcntl.flock(fd, fcntl.LOCK_UN)
        worker.join(timeout=10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result, [True])


class ApiKeyCrossProcessTests(_Sandbox):
    def setUp(self):
        super().setUp()
        self.store = self.dir / "api-keys.json"
        patcher = mock.patch.object(api_keys, "STORE_FILE", self.store)
        patcher.start()
        self.addCleanup(patcher.stop)
        api_keys._last_seen.clear()

    def test_a_revoked_key_cannot_be_resurrected_by_a_concurrent_verify(self):
        record, token = api_keys.create("monitoring", "member")
        self.run_pair(
            _verify_key, (str(self.store), token),
            _revoke_key, (str(self.store), record["id"]),
        )
        # Whichever order the kernel serialised them in, the revocation is the
        # final word: the store holds no keys and the token no longer verifies.
        self.assertEqual(api_keys.list_public(), [])
        self.assertIsNone(api_keys.verify(token))

    def test_mutations_block_while_another_process_holds_the_file_lock(self):
        lock_path = self.store.with_name(self.store.name + ".lock")
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)

        done = threading.Event()
        worker = threading.Thread(
            target=lambda: (api_keys.create("blocked", "member"), done.set())
        )
        worker.start()
        worker.join(timeout=0.3)
        self.assertTrue(worker.is_alive(), "create must block on the file lock")

        fcntl.flock(fd, fcntl.LOCK_UN)
        worker.join(timeout=10)
        self.assertTrue(done.is_set())
        self.assertEqual(len(api_keys.list_public()), 1)


if __name__ == "__main__":
    unittest.main()
