"""hub.util.sh memoises constant and shared reads, and nothing else."""
import os
import threading
import time
import unittest
from unittest import mock

from hub import util


class ShMemoTest(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {"SERVERHUB_NO_SH_MEMO": ""})
        patcher.start()
        self.addCleanup(patcher.stop)
        util.sh_memo_clear()
        self.addCleanup(util.sh_memo_clear)

    def _spawn(self, answers):
        calls = []

        def fake(cmd, timeout=10, shell=False, env=None):
            calls.append(list(cmd) if isinstance(cmd, list) else cmd)
            return answers.pop(0) if answers else (0, "x", "")

        return calls, mock.patch.object(util, "_sh_spawn", side_effect=fake)

    def test_boottime_spawns_once(self):
        calls, p = self._spawn([(0, "{ sec = 1, usec = 0 }", "")])
        with p:
            a = util.sh(["/usr/sbin/sysctl", "-n", "kern.boottime"])
            b = util.sh(["/usr/sbin/sysctl", "-n", "kern.boottime"])
        self.assertEqual(a, b)
        self.assertEqual(len(calls), 1)

    def test_failed_read_is_not_kept(self):
        calls, p = self._spawn([(1, "", "boom"), (0, "ok", "")])
        with p:
            self.assertEqual(util.sh(["/usr/sbin/sysctl", "-n", "kern.boottime"])[0], 1)
            self.assertEqual(util.sh(["/usr/sbin/sysctl", "-n", "kern.boottime"])[1], "ok")
        self.assertEqual(len(calls), 2)

    def test_shared_read_expires(self):
        calls, p = self._spawn([(0, "50%", ""), (0, "40%", "")])
        with p, mock.patch.object(util, "_sh_now", side_effect=[100.0, 100.0, 106.0, 106.0]):
            util.sh(["/usr/bin/memory_pressure", "-Q"])
            util.sh(["/usr/bin/memory_pressure", "-Q"])
            self.assertEqual(util.sh(["/usr/bin/memory_pressure", "-Q"])[1], "40%")
        self.assertEqual(len(calls), 2)

    def test_concurrent_readers_share_one_spawn(self):
        calls = []
        started = threading.Event()
        release = threading.Event()

        def fake(cmd, timeout=10, shell=False, env=None):
            calls.append(cmd)
            started.set()
            release.wait(2)
            return 0, "50%", ""

        results = []
        guard = threading.Lock()

        def read():
            value = util.sh(["/usr/bin/memory_pressure", "-Q"])
            with guard:
                results.append(value)

        with mock.patch.object(util, "_sh_spawn", side_effect=fake):
            readers = [threading.Thread(target=read) for _ in range(8)]
            for reader in readers:
                reader.start()
            self.assertTrue(started.wait(1))
            time.sleep(0.02)
            release.set()
            for reader in readers:
                reader.join(2)
        self.assertFalse(any(reader.is_alive() for reader in readers))
        self.assertEqual(len(calls), 1)
        self.assertEqual(results, [(0, "50%", "")] * 8)
        self.assertFalse(util._sh_memo_flights)

    def test_a_caller_that_finds_a_spawn_running_shares_its_answer(self):
        # The waiter path, made deterministic: the spawn it found has already
        # timed out.  Waiters take that answer instead of queueing a spawn
        # each behind it, and the failure is not kept for the next caller.
        key = ("/usr/bin/memory_pressure", "-Q")
        flight = util._ShFlight()
        flight.result = (-1, "", "timeout")
        flight.done.set()
        util._sh_memo_flights[key] = flight
        self.addCleanup(util._sh_memo_flights.pop, key, None)
        calls, p = self._spawn([(0, "50%", "")])
        with p:
            self.assertEqual(util.sh(list(key)), (-1, "", "timeout"))
            self.assertEqual(calls, [])
            util._sh_memo_flights.pop(key, None)
            self.assertEqual(util.sh(list(key)), (0, "50%", ""))
        self.assertEqual(len(calls), 1)
        self.assertFalse(util._sh_memo_flights)

    def test_other_commands_always_spawn(self):
        calls, p = self._spawn([])
        with p:
            util.sh(["/bin/ps", "aux"])
            util.sh(["/bin/ps", "aux"])
            util.sh("sysctl -n kern.boottime", shell=True)
            util.sh(["/usr/sbin/sysctl", "-n", "kern.boottime"], env={"A": "1"})
        self.assertEqual(len(calls), 4)

    def test_off_switch(self):
        calls, p = self._spawn([])
        with p, mock.patch.dict(os.environ, {"SERVERHUB_NO_SH_MEMO": "1"}):
            util.sh(["/usr/sbin/sysctl", "-n", "kern.boottime"])
            util.sh(["/usr/sbin/sysctl", "-n", "kern.boottime"])
        self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
