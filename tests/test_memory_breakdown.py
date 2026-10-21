"""Activity-Monitor memory split on the dashboard card."""
import unittest
from unittest import mock

from hub import sensors_svc

VM_STAT = """Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free:                                     7976.
Pages active:                                 891455.
Pages inactive:                               892256.
Pages speculative:                              1032.
Pages wired down:                             163290.
Pages purgeable:                                9659.
File-backed pages:                            681833.
Anonymous pages:                             1102910.
Pages occupied by compressor:                  87252.
"""


class MemoryBreakdownTests(unittest.TestCase):
    def _bd(self):
        with mock.patch.object(sensors_svc, "_vm_counts_ctypes", return_value=None), \
             mock.patch.object(sensors_svc, "_sh_run", return_value=(0, VM_STAT, "")), \
             mock.patch.object(sensors_svc, "_swap_used_bytes", return_value=2655 * 2**20), \
             mock.patch.object(sensors_svc, "_local_model_memory", return_value=None):
            return sensors_svc._memory_breakdown(32.0, 16384)

    def test_split_matches_activity_monitor_formula(self):
        bd = self._bd()
        gib = lambda pages: round(pages * 16384 / 2**30, 2)  # noqa: E731
        self.assertEqual(bd["source"], "vm_stat")
        self.assertEqual(bd["app_gb"], gib(1102910 - 9659))
        self.assertEqual(bd["wired_gb"], gib(163290))
        self.assertEqual(bd["compressor_gb"], gib(87252))
        self.assertEqual(bd["cached_files_gb"], gib(681833 + 9659))
        self.assertAlmostEqual(bd["mem_used_gb"], gib(1102910 - 9659 + 163290 + 87252), places=2)
        self.assertAlmostEqual(bd["available_gb"], round(32.0 - bd["mem_used_gb"], 1), places=1)
        self.assertEqual(bd["swap_used_gb"], 2.59)

    def test_cache_no_longer_swallows_app_memory(self):
        payload = sensors_svc._apply_breakdown({}, self._bd())
        # old card: cache = PhysMem used - wired - compressor ~= 25 GB
        self.assertLess(payload["cache_gb"], 11)
        self.assertGreater(payload["used_gb"], 20)
        self.assertEqual(payload["available_gb"], payload["free_gb"])

    def test_missing_counts_leave_payload_alone(self):
        with mock.patch.object(sensors_svc, "_vm_counts_ctypes", return_value=None), \
             mock.patch.object(sensors_svc, "_sh_run", return_value=(1, "", "")):
            self.assertEqual(sensors_svc._safe_breakdown(32.0, 16384), {})
        self.assertEqual(sensors_svc._apply_breakdown({"x": 1}, {}), {"x": 1})


if __name__ == "__main__":
    unittest.main()
