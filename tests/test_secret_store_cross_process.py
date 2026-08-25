"""Secret-store edits must survive concurrent edits from the other process.

Sibling of test_cross_process_locking.py for three more shared stores:
``notify-credentials.json`` (hub/notify_channels.py),
``service-credentials.json`` (hub/service_credentials.py) and
``smart-tests.json`` (hub/smart_test_svc.py).  Each one is a whole-file
load → edit → atomic-replace guarded only by a ``threading.Lock``, which a
second interpreter never sees — and the second interpreter is the documented
deployment (packaged ServerHub.app + LaunchAgent panel sharing one ``data/``).
A write from a stale snapshot erased whatever the other process changed in
between; for the two credential stores the nastier direction is *resurrection*:
a save racing a delete in the other process wrote the deleted secret's entry
straight back to disk.

Same rig as the sibling files: two spawn-context interpreters, the writer with
a sleep patched into its load to hold the read→replace window open, the other
landing its edit inside it.  Only ``secure_io.file_lock`` keeps both edits.
"""
from __future__ import annotations

import json
import multiprocessing
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

_MP = multiprocessing.get_context("spawn")


def _slow(module, name: str, delay: float):
    real = getattr(module, name)

    def wrapper(*args, **kwargs):
        data = real(*args, **kwargs)
        time.sleep(delay)
        return data

    return mock.patch.object(module, name, wrapper)


# ── child processes (top-level so the spawn context can import them) ─────────


def _notify_setter(store: str, barrier, queue) -> None:
    from hub import notify_channels as mod

    with mock.patch.object(mod, "SECRETS_FILE", Path(store)), \
            _slow(mod, "_load_secrets", 0.6):
        barrier.wait(timeout=30)
        mod.set_channel_secrets("chan-b", {"token": "fresh-token"})
    queue.put("setter")


def _notify_dropper(store: str, barrier, queue) -> None:
    from hub import notify_channels as mod

    with mock.patch.object(mod, "SECRETS_FILE", Path(store)):
        barrier.wait(timeout=30)
        time.sleep(0.2)
        mod.drop_channel_secrets("chan-a")
    queue.put("dropper")


def _cred_storer(store: str, barrier, queue) -> None:
    from hub import service_credentials as mod

    with mock.patch.object(mod, "INDEX_FILE", Path(store)), \
            mock.patch.object(mod, "_security", lambda *a, **k: (0, "")), \
            mock.patch.object(mod, "_delete_keychain", lambda *a, **k: None), \
            _slow(mod, "_load", 0.6):
        barrier.wait(timeout=30)
        mod.store("svc2", display_name="Two", username="bob",
                  password="longenough")
    queue.put("storer")


def _cred_deleter(store: str, barrier, queue) -> None:
    from hub import service_credentials as mod

    with mock.patch.object(mod, "INDEX_FILE", Path(store)), \
            mock.patch.object(mod, "_security", lambda *a, **k: (0, "")), \
            mock.patch.object(mod, "_delete_keychain", lambda *a, **k: None):
        barrier.wait(timeout=30)
        time.sleep(0.2)
        mod.delete("svc1")
    queue.put("deleter")


def _smart_recorder(store: str, who: str, delay: float, barrier, queue) -> None:
    from hub import smart_test_svc as mod

    with mock.patch.object(mod, "HISTORY_PATH", Path(store)), \
            _slow(mod, "_load_history", delay):
        barrier.wait(timeout=30)
        if delay == 0:
            time.sleep(0.2)
        mod._append_history({"device": who, "status": "ok"})
    queue.put(who)


class _Sandbox(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def run_pair(self, target_a, args_a: tuple, target_b, args_b: tuple) -> None:
        barrier = _MP.Barrier(2)
        queue = _MP.Queue()
        procs = [
            _MP.Process(target=target_a, args=(*args_a, barrier, queue)),
            _MP.Process(target=target_b, args=(*args_b, barrier, queue)),
        ]
        for p in procs:
            p.start()
        for _ in procs:
            queue.get(timeout=60)
        for p in procs:
            p.join(timeout=60)
            self.assertEqual(p.exitcode, 0)


class NotifySecretsCrossProcessTests(_Sandbox):
    def test_a_dropped_channel_is_not_resurrected_by_a_concurrent_edit(self):
        store = self.dir / "notify-credentials.json"
        store.write_text(json.dumps({"chan-a": {"token": "doomed"}}),
                         encoding="utf-8")
        self.run_pair(
            _notify_setter, (str(store),),
            _notify_dropper, (str(store),),
        )
        data = json.loads(store.read_text(encoding="utf-8"))
        self.assertNotIn("chan-a", data,
                         "the deleted channel's secret came back from a stale snapshot")
        self.assertEqual(data.get("chan-b", {}).get("token"), "fresh-token",
                         "the concurrent edit was erased")


class ServiceCredentialsCrossProcessTests(_Sandbox):
    def test_a_deleted_credential_is_not_resurrected_by_a_concurrent_save(self):
        store = self.dir / "service-credentials.json"
        store.write_text(
            json.dumps({"svc1": {"service_id": "svc1", "username": "alice"}}),
            encoding="utf-8",
        )
        self.run_pair(
            _cred_storer, (str(store),),
            _cred_deleter, (str(store),),
        )
        data = json.loads(store.read_text(encoding="utf-8"))
        self.assertNotIn("svc1", data,
                         "the deleted credential came back from a stale snapshot")
        self.assertIn("svc2", data, "the concurrent save was erased")


class SmartHistoryCrossProcessTests(_Sandbox):
    def test_results_recorded_by_both_processes_both_survive(self):
        store = self.dir / "smart-tests.json"
        store.write_text("[]", encoding="utf-8")
        self.run_pair(
            _smart_recorder, (str(store), "disk-slow", 0.6),
            _smart_recorder, (str(store), "disk-fast", 0.0),
        )
        rows = json.loads(store.read_text(encoding="utf-8"))
        devices = {row.get("device") for row in rows if isinstance(row, dict)}
        self.assertEqual(devices, {"disk-slow", "disk-fast"},
                         "one process's result was dropped by the other's rewrite")


if __name__ == "__main__":
    unittest.main()
