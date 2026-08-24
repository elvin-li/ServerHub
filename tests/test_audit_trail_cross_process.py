"""Audit-trail appends must survive a trim in another panel process.

Both security trails — ``data/auth-audit.jsonl`` (hub/audit.py) and
``data/terminal-audit.jsonl`` (hub/terminal_svc.py) — serialise append + trim
with a ``threading.Lock``.  That lock is invisible to a second interpreter,
and the second interpreter is a documented deployment shape: the packaged
ServerHub.app and the LaunchAgent panel share one ``data/`` directory, which
is exactly why hub/config.py, hub/twofa_svc.py and hub/api_keys.py each grew a
kernel flock.  The trim is a read-tail-then-atomic-replace, so an O_APPEND
entry the *other* process lands on the pre-swap inode inside that window is
discarded with the swap — and what vanishes is a security event: a sign-in,
a privilege change, or the text of a command typed into a root-capable shell.

These tests spawn two real interpreters (spawn context, nothing shared but the
file), hold one process's trim window open by patching its ``tail_file_lines``
with a sleep, and land an append from the other process inside it.  Without
``secure_io.file_lock`` the appended event is gone; with it the append blocks
until the trim has swapped, then lands on the new inode.
"""
from __future__ import annotations

import fcntl
import json
import multiprocessing
import os
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from hub import audit, terminal_svc

_MP = multiprocessing.get_context("spawn")


def _slow_tail(module, delay: float):
    """Patch *module*.tail_file_lines to sleep after reading — the window
    between the trim's tail-read and its atomic replace."""
    real = module.tail_file_lines

    def slow(*args, **kwargs):
        lines = real(*args, **kwargs)
        time.sleep(delay)
        return lines

    return mock.patch.object(module, "tail_file_lines", slow)


# ── child processes (top-level so the spawn context can import them) ─────────


def _auth_trimmer(store: str, barrier, queue) -> None:
    from hub import audit as mod

    with mock.patch.object(mod, "AUDIT_PATH", Path(store)), _slow_tail(mod, 0.8):
        barrier.wait(timeout=30)
        mod.record("race.trimmer")
    queue.put("trimmer")


def _auth_appender(store: str, barrier, queue) -> None:
    from hub import audit as mod

    with mock.patch.object(mod, "AUDIT_PATH", Path(store)):
        barrier.wait(timeout=30)
        time.sleep(0.3)
        mod.record("race.victim")
    queue.put("appender")


def _terminal_trimmer(store: str, barrier, queue) -> None:
    from hub import terminal_svc as mod

    with mock.patch.object(mod, "AUDIT_PATH", Path(store)), _slow_tail(mod, 0.8):
        barrier.wait(timeout=30)
        mod._audit({"cmd": "race-trimmer", "who": "a"})
    queue.put("trimmer")


def _terminal_appender(store: str, barrier, queue) -> None:
    from hub import terminal_svc as mod

    with mock.patch.object(mod, "AUDIT_PATH", Path(store)):
        barrier.wait(timeout=30)
        time.sleep(0.3)
        mod._audit({"cmd": "race-victim", "who": "b"})
    queue.put("appender")


class _Sandbox(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def run_pair(self, target_a, args_a: tuple, target_b, args_b: tuple) -> list:
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

    @staticmethod
    def _grow(path: Path, *, line_bytes: int, total_bytes: int) -> None:
        """Fill *path* with valid jsonl well past the trim threshold."""
        filler = json.dumps({"event": "filler", "pad": "x" * line_bytes}) + "\n"
        with path.open("w", encoding="utf-8") as fh:
            for _ in range(total_bytes // len(filler) + 1):
                fh.write(filler)
        os.chmod(path, 0o600)

    @staticmethod
    def _events(path: Path) -> list:
        out = []
        for raw in path.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(raw)
            except ValueError:
                continue
            if isinstance(row, dict):
                out.append(row)
        return out


class AuthAuditCrossProcessTests(_Sandbox):
    def test_an_event_appended_during_another_processes_trim_survives(self):
        store = self.dir / "auth-audit.jsonl"
        self._grow(store, line_bytes=180,
                   total_bytes=audit._TRIM_SOFT_BYTES + 64 * 1024)
        self.run_pair(
            _auth_trimmer, (str(store),),
            _auth_appender, (str(store),),
        )
        events = {row.get("event") for row in self._events(store)}
        self.assertIn("race.victim",
                      events, "the other process's trim discarded the event")
        self.assertIn("race.trimmer", events)

    def test_record_blocks_while_another_process_holds_the_file_lock(self):
        store = self.dir / "auth-audit.jsonl"
        lock_path = store.with_name(store.name + ".lock")
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)

        done = threading.Event()
        with mock.patch.object(audit, "AUDIT_PATH", store):
            worker = threading.Thread(
                target=lambda: (audit.record("race.blocked"), done.set())
            )
            worker.start()
            worker.join(timeout=0.3)
            self.assertTrue(worker.is_alive(), "record must block on the file lock")

            fcntl.flock(fd, fcntl.LOCK_UN)
            worker.join(timeout=10)
        self.assertTrue(done.is_set())
        events = {row.get("event") for row in self._events(store)}
        self.assertIn("race.blocked", events)


class TerminalAuditCrossProcessTests(_Sandbox):
    def test_a_command_audited_during_another_processes_trim_survives(self):
        store = self.dir / "terminal-audit.jsonl"
        self._grow(store, line_bytes=400,
                   total_bytes=terminal_svc._AUDIT_MAX_BYTES + 64 * 1024)
        self.run_pair(
            _terminal_trimmer, (str(store),),
            _terminal_appender, (str(store),),
        )
        cmds = {row.get("cmd") for row in self._events(store)}
        self.assertIn("race-victim",
                      cmds, "the other process's trim discarded the command")
        self.assertIn("race-trimmer", cmds)


if __name__ == "__main__":
    unittest.main()
