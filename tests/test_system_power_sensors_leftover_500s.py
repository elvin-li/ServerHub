"""Leftover parse/typing 500s on identity, settings, power, and sensors.

Bytes/None scutil and pmset payloads, ``inf%`` memory_pressure, a zero-total
root volume, and non-finite ``top`` tokens each used to raise on the request
path or fail Starlette's ``allow_nan=False`` JSON encoder.

Follow-up: ``ps aux`` inf CPU / 400-digit RSS, a huge ``kern.boottime``,
huge netstat counters, huge ``hw.memsize``, and a dying root ``disk_usage``
each 500'd GET /api/system/sensors. YAML ``.inf`` / a date / ``!!binary``
username 500'd Settings. ``int(inf)`` 500'd POST /api/settings/power.
``get_identity()`` raising after a write 500'd PUT /api/identity. ``host_ip()``
raising 500'd GET /api/system/power.

Second follow-up: the same huge ``hw.memsize`` / root ``disk_usage`` /
``kern.boottime`` leftovers still OverflowError'd ``collect_system``
(GET /api/status). ``getloadavg`` OSError emptied the snapshot.

Third follow-up: leftover None/bytes from ``hostname`` / ``sysctl`` used to
AttributeError ``.isdigit`` or TypeError Starlette on GET /api/system/host.
"""
from __future__ import annotations

import collections
import datetime
import json
import time
import unittest
from unittest import mock

from hub import identity_svc, power_svc, sensors_svc, system, system_settings_svc
from hub.routers import system_extra


def _json(payload) -> None:
    json.dumps(payload, allow_nan=False)


class SensorsMemoryPressureTests(unittest.TestCase):
    def setUp(self):
        sensors_svc._static.update(t=0.0, ncpu=None, mem_gb=None, page_size=16384)
        self.addCleanup(
            sensors_svc._static.update,
            t=0.0, ncpu=None, mem_gb=None, page_size=16384,
        )

    def _sh(self, mem_out):
        def fake_sh(argv, **kwargs):
            last = argv[-1]
            if last == "hw.ncpu":
                return 0, 8, ""
            if last == "hw.memsize":
                return 0, 16 * 2**30, ""
            if last == "hw.pagesize":
                return 0, 16384, ""
            if argv[0].endswith("memory_pressure"):
                return 0, mem_out, ""
            return 1, "", ""
        return fake_sh

    def test_infinite_free_percentage_does_not_500_light(self):
        """``int(float('inf'))`` used to OverflowError collect_light."""
        with (
            mock.patch.object(sensors_svc, "sh", side_effect=self._sh("free percentage: inf%")),
            mock.patch.object(sensors_svc, "_cpu_from_ticks", return_value={"used_pct": 4}),
        ):
            mem = sensors_svc._memory_base()
            light = sensors_svc.collect_light()
        self.assertIsNone(mem["mem_free_pct"])
        self.assertIsNone(light["memory"]["free_pct"])
        _json(light)

    def test_huge_digit_free_percentage_does_not_500(self):
        with mock.patch.object(
            sensors_svc, "sh", side_effect=self._sh("free percentage: " + ("9" * 400) + "%")
        ):
            mem = sensors_svc._memory_base()
        self.assertIsNone(mem["mem_free_pct"])


class SensorsDiskTotalTests(unittest.TestCase):
    def test_zero_disk_total_does_not_500_light(self):
        DU = collections.namedtuple("Usage", "used total free")
        with (
            mock.patch.object(sensors_svc.shutil, "disk_usage", return_value=DU(0, 0, 0)),
            mock.patch.object(sensors_svc, "_memory_base", return_value={
                "ncpu": 8, "load1": 0.1, "load5": 0.1, "load15": 0.1,
            }),
            mock.patch.object(sensors_svc, "_cpu_from_ticks", return_value={"used_pct": 4}),
        ):
            disk = sensors_svc._disk()
            light = sensors_svc.collect_light()
        self.assertEqual(disk["root_pct"], 0)
        self.assertEqual(light["disk"]["root_pct"], 0)
        _json(light)


class SensorsTopNonfiniteTests(unittest.TestCase):
    def test_infinite_top_tokens_do_not_500_json(self):
        """Starlette allow_nan=False: leftover Infinity used to 500 /api/system/sensors."""
        top = (
            "CPU usage: inf% user, inf% sys, inf% idle\n"
            "Load Avg: inf, inf, inf\n"
            "PhysMem: " + ("9" * 400) + "G used, 1G unused.\n"
        )
        with mock.patch.object(sensors_svc, "sh", return_value=(0, top, "")):
            data = sensors_svc._cpu_and_mem_from_top()
        self.assertNotIn("user", data)
        self.assertNotIn("load1", data)
        self.assertIsNone(data.get("mem_used_gb"))
        self.assertEqual(data.get("mem_unused_gb"), 1.0)
        _json(data)
        self.assertIsNone(sensors_svc._parse_size_to_gb("9" * 400 + "G"))


class SensorsPsNetUptimeTests(unittest.TestCase):
    def setUp(self):
        sensors_svc._static.update(t=0.0, ncpu=None, mem_gb=None, page_size=16384)
        sensors_svc._net_prev = {"t": 0.0, "rx": 0, "tx": 0}
        self.addCleanup(
            sensors_svc._static.update,
            t=0.0, ncpu=None, mem_gb=None, page_size=16384,
        )

        def _reset_net():
            sensors_svc._net_prev = {"t": 0.0, "rx": 0, "tx": 0}

        self.addCleanup(_reset_net)

    def test_infinite_ps_cpu_does_not_500_json(self):
        """``float('inf')`` %CPU used to leak into GET /api/system/sensors."""
        table = [
            "USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND",
            "me 11 inf nan 100 2048 ?? S 1:00PM 0:01.00 /usr/bin/top",
            "me 12 1.0 0.5 100 512 ?? S 1:00PM 0:00.10 /usr/bin/idle",
        ]
        with mock.patch.object(sensors_svc, "ps_lines", return_value=table):
            rows = sensors_svc._top_processes(8)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["pid"], 12)
        _json(rows)

    def test_huge_rss_does_not_500(self):
        table = [
            "USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND",
            f"me 11 1.0 0.5 100 {'9' * 400} ?? S 1:00PM 0:01.00 /usr/bin/top",
        ]
        with mock.patch.object(sensors_svc, "ps_lines", return_value=table):
            rows = sensors_svc._top_processes(8)
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["rss_mb"])
        _json(rows)

    def test_huge_boottime_does_not_500(self):
        with mock.patch.object(
            sensors_svc, "sh",
            return_value=(0, "sec = " + ("9" * 400) + ", usec = 0", ""),
        ):
            data = sensors_svc._uptime()
        self.assertEqual(data["uptime_hours"], 0.0)
        _json(data)

    def test_huge_netstat_bytes_do_not_500_rates(self):
        huge = "9" * 400
        line = (
            f"en0 1500 <Link#14> aa:bb:cc:dd:ee:ff 1 0 {huge} 1 0 {huge} 0"
        )
        sensors_svc._net_prev = {"t": 1.0, "rx": 0, "tx": 0}
        with (
            mock.patch.object(sensors_svc.time, "time", return_value=10.0),
            mock.patch.object(sensors_svc, "sh", return_value=(0, "hdr\n" + line, "")),
        ):
            data = sensors_svc._network_rates()
        self.assertIsNone(data["rx_bps"])
        self.assertIsNone(data["tx_bps"])
        _json(data)

    def test_huge_memsize_does_not_500(self):
        def fake_sh(argv, **kwargs):
            last = argv[-1]
            if last == "hw.ncpu":
                return 0, "8", ""
            if last == "hw.memsize":
                return 0, "9" * 400, ""
            if last == "hw.pagesize":
                return 0, "16384", ""
            return 1, "", ""

        with mock.patch.object(sensors_svc, "sh", side_effect=fake_sh):
            hw = sensors_svc._static_hw()
        self.assertEqual(hw["ncpu"], 8)
        self.assertIsNone(hw["mem_total_gb"])
        _json(hw)

    def test_disk_eio_and_huge_total_do_not_500(self):
        DU = collections.namedtuple("Usage", "used total free")
        with mock.patch.object(
            sensors_svc.shutil, "disk_usage",
            side_effect=OSError(5, "I/O error"),
        ):
            dead = sensors_svc._disk()
        self.assertEqual(dead["root_pct"], 0)
        _json(dead)
        with mock.patch.object(
            sensors_svc.shutil, "disk_usage",
            return_value=DU(int("9" * 400), int("9" * 400), 0),
        ):
            huge = sensors_svc._disk()
        self.assertIsNone(huge["root_used_gb"])
        _json(huge)


class SensorsPeekLightLeftoverTests(unittest.TestCase):
    def tearDown(self):
        sensors_svc._cache.update(t=0.0, v=None)

    def test_peek_leftover_inf_bytes_surrogate_do_not_500(self):
        """Leftover inf / bytes / ``\\ud800`` in the peek cache used to 500 light."""
        sensors_svc._cache.update(t=time.time(), v={
            "cpu_used_pct": float("inf"),
            "note": b"ok",
            "name": "nginx\ud800",
            "\ud800": 1,
            "top_processes": [{"name": "ps\udfff", "cpu": float("nan")}],
        })
        hit = sensors_svc.peek_sensors()
        self.assertIsNotNone(hit)
        json.dumps(hit, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertIsNone(hit["cpu_used_pct"])
        self.assertEqual(hit["note"], "ok")
        self.assertNotIn("\ud800", hit["name"])
        self.assertNotIn("\ud800", hit)
        self.assertNotIn("\udfff", hit["top_processes"][0]["name"])
        self.assertIsNone(hit["top_processes"][0]["cpu"])

    def test_as_text_recursing_does_not_500(self):
        """leftover ``str(e)`` RecursionError used to 500 GET /api/sensors."""
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(sensors_svc._as_text(Recursing()), "Recursing")
        json.dumps({"n": sensors_svc._as_text(Recursing())}, ensure_ascii=False).encode("utf-8")

    def test_collect_sensors_cache_leftover_does_not_500(self):
        """Leftover inf / ``\\ud800`` in the full-sample cache used to 500 GET /api/system/sensors."""
        sensors_svc._cache.update(t=time.time(), v={
            "cpu_used_pct": float("inf"),
            "name": "nginx\ud800",
            "\ud800": 1,
        })
        hit = sensors_svc.collect_sensors()
        json.dumps(hit, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertIsNone(hit["cpu_used_pct"])
        self.assertNotIn("\ud800", hit["name"])
        self.assertNotIn("\ud800", hit)

    def test_collect_light_leftover_inf_ncpu_does_not_500(self):
        """YAML-ish leftover inf ncpu / load used to leak into the light payload."""
        with (
            mock.patch.object(sensors_svc, "_memory_base", return_value={
                "ncpu": float("inf"), "load1": float("nan"), "load5": 0.1,
                "load15": 0.1, "mem_free_pct": float("inf"),
                "mem_total_gb": float("-inf"),
            }),
            mock.patch.object(sensors_svc, "_cpu_from_ticks", return_value={
                "user": float("inf"), "sys": 1.0, "idle": 90.0, "used_pct": 4.0,
            }),
            mock.patch.object(sensors_svc, "_disk", return_value={
                "root_pct": 1, "root_used_gb": b"1",
            }),
        ):
            light = sensors_svc.collect_light()
        json.dumps(light, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertIsNone(light["cpu"]["ncpu"])
        self.assertIsNone(light["cpu"]["user"])
        self.assertIsNone(light["load1"])
        self.assertEqual(light["disk"]["root_used_gb"], "1")


class SystemCollectLeftoverTests(unittest.TestCase):
    def _collect(self, *, ncpu="8", memsize=None, boot="sec = 1,", mem_out="",
                 du=None, load=(0.1, 0.2, 0.3), load_exc=None, disk_exc=None):
        if memsize is None:
            memsize = str(16 * 2**30)
        DU = collections.namedtuple("Usage", "used total free")
        if du is None:
            du = DU(50 * 2**30, 100 * 2**30, 50 * 2**30)

        def fake_sh(argv, **kwargs):
            last = argv[-1]
            if last == "hw.ncpu":
                return 0, ncpu, ""
            if last == "hw.memsize":
                return 0, memsize, ""
            if last == "kern.boottime":
                return 0, boot, ""
            if argv[0].endswith("memory_pressure"):
                return 0, mem_out, ""
            return 1, "", ""

        load_patch = (
            mock.patch.object(system.os, "getloadavg", side_effect=load_exc)
            if load_exc is not None
            else mock.patch.object(system.os, "getloadavg", return_value=load)
        )
        disk_patch = (
            mock.patch.object(system.shutil, "disk_usage", side_effect=disk_exc)
            if disk_exc is not None
            else mock.patch.object(system.shutil, "disk_usage", return_value=du)
        )
        with (
            mock.patch.object(system, "sh", side_effect=fake_sh),
            mock.patch.object(system, "_smart_cache", {"t": 9e9, "v": None}),
            load_patch,
            disk_patch,
        ):
            return system.collect_system()

    def test_disk_eio_and_runtimeerror_do_not_500(self):
        for exc in (OSError(5, "I/O error"), RuntimeError("vfs")):
            snap = self._collect(disk_exc=exc)
            self.assertEqual(snap["disk_pct"], 0)
            self.assertIsNone(snap["disk_used_gb"])
            _json(snap)

    def test_getloadavg_oserror_does_not_500(self):
        snap = self._collect(load_exc=OSError("no load"))
        self.assertIsNone(snap["load1"])
        self.assertEqual(snap["load"], "")
        self.assertIsNone(snap["load_pct"])
        self.assertEqual(snap["ncpu"], 8)
        _json(snap)

    def test_huge_memsize_does_not_500(self):
        """``mem_n / 2**30`` OverflowError'd GET /api/status's system object."""
        snap = self._collect(memsize="9" * 400)
        self.assertEqual(snap["ncpu"], 8)
        self.assertIsNone(snap["mem_total_gb"])
        _json(snap)

    def test_huge_disk_does_not_500(self):
        DU = collections.namedtuple("Usage", "used total free")
        snap = self._collect(du=DU(int("9" * 400), int("9" * 400), 0))
        self.assertIsNone(snap["disk_used_gb"])
        self.assertIsNone(snap["disk_total_gb"])
        _json(snap)

    def test_huge_boottime_does_not_500(self):
        snap = self._collect(boot="sec = " + ("9" * 400) + ", usec = 0")
        self.assertEqual(snap["uptime_hours"], 0.0)
        _json(snap)

    def test_negative_huge_boottime_does_not_500(self):
        snap = self._collect(boot="sec = -" + ("9" * 400) + ", usec = 0")
        self.assertEqual(snap["uptime_hours"], 0.0)
        _json(snap)

    def test_leftover_smart_inf_and_surrogate_do_not_500(self):
        """Leftover SMART ``temp: \\ud800`` / ``wear: inf`` used to 500 collect_system."""
        snap = self._collect()
        snap["smart"] = {"temp": "42\ud800", "wear": float("inf"), "written": b"1 TB"}
        cleaned = system._jsonable(snap)
        json.dumps(cleaned, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertNotIn("\ud800", cleaned["smart"]["temp"])
        self.assertIsNone(cleaned["smart"]["wear"])
        self.assertEqual(cleaned["smart"]["written"], "1 TB")

        with (
            mock.patch.object(system, "sh", return_value=(0, "", "")),
            mock.patch.object(system.os, "getloadavg", return_value=(0.1, 0.2, 0.3)),
            mock.patch.object(
                system.shutil, "disk_usage",
                return_value=type("DU", (), {"used": 1, "total": 2, "free": 1})(),
            ),
            mock.patch.object(system, "_smart_cache", {
                "t": 9e9,
                "v": {"temp": "42\ud800", "wear": float("inf"), "written": b"1 TB"},
            }),
        ):
            planted = system.collect_system()
        json.dumps(planted, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertNotIn("\ud800", planted["smart"]["temp"])
        self.assertIsNone(planted["smart"]["wear"])
        self.assertEqual(planted["smart"]["written"], "1 TB")


class IdentityPayloadTests(unittest.TestCase):
    def setUp(self):
        identity_svc.time_zone.invalidate()
        identity_svc.platform_string.invalidate()
        self.addCleanup(identity_svc.time_zone.invalidate)
        self.addCleanup(identity_svc.platform_string.invalidate)

    def test_none_int_bytes_timezone_do_not_500(self):
        for payload in (None, 12, b".../zoneinfo/Asia/Shanghai"):
            identity_svc.time_zone.invalidate()
            with mock.patch.object(identity_svc, "sh", return_value=(0, payload, "")):
                zone = identity_svc.time_zone()
            self.assertIsInstance(zone, str)
        self.assertEqual(zone, "Asia/Shanghai")

    def test_bytes_identity_fields_do_not_500_json(self):
        with (
            mock.patch.object(identity_svc, "sh", return_value=(0, b"Studio", "")),
            mock.patch.object(identity_svc, "time_zone", return_value="UTC"),
            mock.patch.object(identity_svc, "platform_string", return_value="macOS"),
            mock.patch.object(identity_svc, "effective_host_ip", return_value="10.0.0.1"),
            mock.patch.object(identity_svc, "configured_host", return_value="auto"),
            mock.patch.object(
                identity_svc, "cfg",
                return_value={"settings": {"server_comment": b"lab"}},
            ),
        ):
            data = identity_svc.get_identity()
        self.assertEqual(data["hostname"], "Studio")
        self.assertEqual(data["computer_name"], "Studio")
        self.assertEqual(data["comment"], "lab")
        _json(data)

    def test_reread_raise_does_not_500_put(self):
        """A post-write ``get_identity()`` blow-up used to 500 PUT /api/identity."""
        with (
            mock.patch.object(identity_svc, "sh", return_value=(0, "", "")),
            mock.patch.object(
                identity_svc, "get_identity",
                side_effect=RuntimeError("scutil"),
            ),
        ):
            out = identity_svc.set_identity(computer_name="Studio")
        self.assertTrue(out["ok"])
        self.assertEqual(out["identity"], {})
        _json(out)

    def test_leftover_surrogate_host_ip_config_does_not_500(self):
        """YAML ``host_ip: "\\ud800"`` used to 500 GET /api/identity."""
        with (
            mock.patch.object(identity_svc, "cfg", return_value={"settings": {}}),
            mock.patch.object(identity_svc, "sh", return_value=(0, "host", "")),
            mock.patch.object(identity_svc, "time_zone", return_value="UTC"),
            mock.patch.object(identity_svc, "platform_string", return_value="mac"),
            mock.patch.object(identity_svc, "effective_host_ip", return_value="1.2.3.4"),
            mock.patch.object(identity_svc, "configured_host", return_value="ok\ud800"),
        ):
            ident = identity_svc.get_identity()
        json.dumps(ident, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertNotIn("\ud800", ident["host_ip_config"])

    def test_leftover_surrogate_platform_fallback_does_not_500(self):
        with (
            mock.patch.object(identity_svc, "cfg", return_value={"settings": {}}),
            mock.patch.object(identity_svc, "sh", return_value=(1, "", "")),
            mock.patch.object(identity_svc, "time_zone", return_value="UTC"),
            mock.patch.object(identity_svc, "platform_string", return_value="mac"),
            mock.patch.object(identity_svc.platform, "node", return_value="box\ud800"),
            mock.patch.object(identity_svc.platform, "machine", return_value="arm\ud800"),
            mock.patch.object(identity_svc, "effective_host_ip", return_value="1.2.3.4"),
            mock.patch.object(identity_svc, "configured_host", return_value="auto"),
        ):
            ident = identity_svc.get_identity()
        json.dumps(ident, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertNotIn("\ud800", ident["hostname"])
        self.assertNotIn("\ud800", ident["arch"])

    def test_platform_string_surrogate_does_not_500(self):
        """Leftover ``\\ud800`` in ``uname`` used to 500 GET /api/diagnostics."""
        identity_svc.platform_string.invalidate()
        with mock.patch.object(identity_svc.platform, "platform", return_value="macOS\ud800"):
            text = identity_svc.platform_string()
        json.dumps({"platform": text}, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertNotIn("\ud800", text)

    def test_leftover_surrogate_scutil_err_does_not_500_put(self):
        """Leftover ``\\ud800`` in scutil stderr used to 500 PUT /api/identity."""
        with (
            mock.patch.object(identity_svc, "sh", return_value=(1, "ok\ud800", "no\ud800")),
            mock.patch.object(identity_svc, "get_identity", return_value={}),
        ):
            out = identity_svc.set_identity(computer_name="Studio")
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertNotIn("\ud800", out["message"])


class HostSnapshotShLeftoverTests(unittest.TestCase):
    def setUp(self):
        system_extra._host_snapshot.invalidate()
        self.addCleanup(system_extra._host_snapshot.invalidate)

    def _snapshot(self, payload):
        def fake_sh(argv, timeout=3):
            return 0, payload, ""

        with (
            mock.patch.object(system_extra, "sh", side_effect=fake_sh),
            mock.patch.object(system_extra, "host_ip", return_value="10.0.0.1"),
            mock.patch.object(system_extra, "default_interface", return_value="en0"),
            mock.patch.object(system_extra, "is_high", return_value=False),
            mock.patch.object(system_extra, "peek_engine", return_value=False),
            mock.patch.object(system_extra, "_iface_addresses", return_value=[]),
        ):
            return system_extra._host_snapshot()

    def test_none_sysctl_does_not_500(self):
        """Leftover None from ``sysctl`` used to AttributeError ``.isdigit`` GET /api/system/host."""
        system_extra._host_snapshot.invalidate()
        data = self._snapshot(None)
        _json(data)
        self.assertIsInstance(data["hostname"], str)

    def test_bytes_hostname_and_sysctl_do_not_500(self):
        def fake_sh(argv, timeout=3):
            last = argv[-1] if argv else ""
            if argv and argv[0].endswith("hostname"):
                return 0, b"Studio", ""
            if last == "hw.ncpu":
                return 0, b"8", ""
            if last == "hw.memsize":
                return 0, b"17179869184", ""
            if "brand_string" in str(last):
                return 0, b"Apple M1", ""
            return 0, b"", ""

        system_extra._host_snapshot.invalidate()
        with (
            mock.patch.object(system_extra, "sh", side_effect=fake_sh),
            mock.patch.object(system_extra, "host_ip", return_value="10.0.0.1"),
            mock.patch.object(system_extra, "default_interface", return_value="en0"),
            mock.patch.object(system_extra, "is_high", return_value=False),
            mock.patch.object(system_extra, "peek_engine", return_value=False),
            mock.patch.object(system_extra, "_iface_addresses", return_value=[]),
        ):
            data = system_extra._host_snapshot()
        self.assertEqual(data["hostname"], "Studio")
        self.assertEqual(data["ncpu"], 8)
        self.assertIsInstance(data["cpu"], str)
        _json(data)

    def test_hostname_fallback_surrogate_does_not_500(self):
        """``platform.node()`` leftover ``\\ud800`` used to 500 GET /api/system/host."""
        def fake_sh(argv, timeout=3):
            last = argv[-1] if argv else ""
            if argv and argv[0].endswith("hostname"):
                return 1, "", "fail"
            if last == "hw.ncpu":
                return 0, "8", ""
            if last == "hw.memsize":
                return 0, "17179869184", ""
            if "brand_string" in str(last):
                return 0, "Apple M1", ""
            return 0, "", ""

        system_extra._host_snapshot.invalidate()
        with (
            mock.patch.object(system_extra, "sh", side_effect=fake_sh),
            mock.patch.object(system_extra.platform, "node", return_value="box\ud800"),
            mock.patch.object(system_extra.platform, "platform", return_value="mac\ud800"),
            mock.patch.object(system_extra.platform, "machine", return_value="arm\ud800"),
            mock.patch.object(system_extra.platform, "python_version", return_value="3\ud800"),
            mock.patch.object(system_extra, "host_ip", return_value="10.0.0.1"),
            mock.patch.object(system_extra, "default_interface", return_value="en0"),
            mock.patch.object(system_extra, "is_high", return_value=False),
            mock.patch.object(system_extra, "peek_engine", return_value=False),
            mock.patch.object(system_extra, "_iface_addresses", return_value=[]),
        ):
            data = system_extra._host_snapshot()
        json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertNotIn("\ud800", data["hostname"])
        self.assertNotIn("\ud800", data["platform"])
        self.assertNotIn("\ud800", data["arch"])
        self.assertNotIn("\ud800", data["python"])


class PowerPayloadTests(unittest.TestCase):
    def test_bytes_pmset_and_ifconfig_do_not_500(self):
        with mock.patch.object(power_svc, "sh", return_value=(0, b"womp 1\n", "")):
            self.assertTrue(power_svc._womp_enabled())
        with mock.patch.object(
            power_svc, "sh", return_value=(0, b"ether aa:bb:cc:dd:ee:ff", "")
        ):
            self.assertEqual(power_svc._iface_mac("en0"), "aa:bb:cc:dd:ee:ff")
        for payload in (None, 12):
            with mock.patch.object(power_svc, "sh", return_value=(0, payload, "")):
                self.assertIsNone(power_svc._womp_enabled())
                self.assertEqual(power_svc._iface_mac("en0"), "")

    def test_failed_wol_bytes_message_does_not_500(self):
        with mock.patch.object(power_svc, "sh", return_value=(1, b"denied", b"no")):
            out = power_svc.set_wol(True)
        self.assertFalse(out["ok"])
        self.assertIsInstance(out["message"], str)
        _json(out)

    def test_bytes_overview_still_reports_wol(self):
        def fake_sh(argv, **kwargs):
            if argv[0].endswith("ifconfig"):
                return 0, b"ether aa:bb:cc:dd:ee:ff", ""
            if argv[0].endswith("pmset"):
                return 0, b"womp 1\n", ""
            return 1, "", ""

        with (
            mock.patch.object(power_svc, "sh", side_effect=fake_sh),
            mock.patch.object(power_svc, "default_interface", return_value="en0"),
            mock.patch.object(power_svc, "host_ip", return_value="10.0.0.1"),
            mock.patch.object(power_svc, "port_open", return_value=False),
        ):
            data = power_svc.power_overview()
        self.assertEqual(data["wol"]["mac"], "aa:bb:cc:dd:ee:ff")
        self.assertTrue(data["wol"]["enabled"])
        _json(data)

    def test_host_ip_raise_does_not_500_overview(self):
        """``host_ip()`` raising used to 500 GET /api/system/power."""
        with (
            mock.patch.object(power_svc, "_nic", return_value=("en0", "aa:bb:cc:dd:ee:ff")),
            mock.patch.object(power_svc, "_womp_enabled", return_value=True),
            mock.patch.object(power_svc, "screensharing_status", return_value={}),
            mock.patch.object(power_svc, "host_ip", side_effect=RuntimeError("dns")),
        ):
            data = power_svc.power_overview()
        self.assertEqual(data["host_ip"], "")
        self.assertTrue(data["wol"]["enabled"])
        _json(data)

        with (
            mock.patch.object(power_svc, "port_open", return_value=True),
            mock.patch.object(power_svc, "host_ip", side_effect=RuntimeError("dns")),
        ):
            ss = power_svc.screensharing_status()
        self.assertEqual(ss["host"], "")
        _json(ss)

    def test_leftover_surrogate_host_does_not_500(self):
        """Leftover ``\\ud800`` in host_ip / MAC used to 500 GET /api/system/power."""
        with (
            mock.patch.object(power_svc, "_nic", return_value=("en0\ud800", "aa:bb\ud800")),
            mock.patch.object(power_svc, "_womp_enabled", return_value=True),
            mock.patch.object(
                power_svc, "screensharing_status",
                return_value={"host": "10.0.0.1\ud800", "vnc_url": "vnc://10.0.0.1\ud800:5900"},
            ),
            mock.patch.object(power_svc, "host_ip", return_value="10.0.0.1\ud800"),
        ):
            data = power_svc.power_overview()
        json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertNotIn("\ud800", data["host_ip"])
        self.assertNotIn("\ud800", data["wol"]["iface"])
        self.assertNotIn("\ud800", data["wol"]["mac"])

        with (
            mock.patch.object(power_svc, "port_open", return_value=True),
            mock.patch.object(power_svc, "host_ip", return_value="10.0.0.1\ud800"),
        ):
            ss = power_svc.screensharing_status()
        json.dumps(ss, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertNotIn("\ud800", ss["host"])
        self.assertNotIn("\ud800", ss["vnc_url"])

    def test_leftover_surrogate_wol_message_does_not_500(self):
        with mock.patch.object(power_svc, "sh", return_value=(1, "denied\ud800", "no\ud800")):
            out = power_svc.set_wol(True)
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertNotIn("\ud800", out["message"])

    def test_leftover_inf_screensharing_ok_does_not_500(self):
        """Leftover inf / ``\\ud800`` in set_system_service used to 500 enable."""
        from hub.routers import power as power_router

        with (
            mock.patch.object(power_router, "_require_admin_browser"),
            mock.patch.object(
                power_router.shares_svc, "set_system_service",
                return_value={"ok": True, "n": float("inf"), "name": "ok\ud800"},
            ),
        ):
            out = power_router._set_screen_sharing(mock.Mock(), True)
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertIsNone(out["n"])
        self.assertNotIn("\ud800", out["name"])

    def test_leftover_none_screensharing_is_coded_not_500(self):
        from hub.routers import power as power_router
        from fastapi import HTTPException

        with (
            mock.patch.object(power_router, "_require_admin_browser"),
            mock.patch.object(
                power_router.shares_svc, "set_system_service", return_value=None,
            ),
        ):
            with self.assertRaises(HTTPException) as ctx:
                power_router._set_screen_sharing(mock.Mock(), True)
        self.assertEqual(ctx.exception.detail["code"], "shares.operation_failed")


class SettingsPayloadTests(unittest.TestCase):
    def setUp(self):
        system_settings_svc.get_power_info.invalidate()
        self.addCleanup(system_settings_svc.get_power_info.invalidate)

    def test_bytes_clock_and_ntp_do_not_500_datetime(self):
        def fake_sh(argv, **kwargs):
            joined = " ".join(str(a) for a in argv)
            if argv[0].endswith("date") or "+%Y" in joined:
                return 0, b"2026-08-19 12:00:00 CST", ""
            if "getusingnetworktime" in joined:
                return 0, b"Network Time: On", ""
            if "getnetworktimeserver" in joined:
                return 0, b"Network Time Server: time.apple.com", ""
            return 1, "", ""

        with (
            mock.patch.object(system_settings_svc, "sh", side_effect=fake_sh),
            mock.patch("hub.identity_svc.time_zone", return_value="Asia/Shanghai"),
        ):
            info = system_settings_svc.get_datetime_info()
        self.assertEqual(info["now"], "2026-08-19 12:00:00 CST")
        self.assertTrue(info["ntp_enabled"])
        self.assertEqual(info["ntp_server"], "time.apple.com")
        _json(info)

    def test_infinite_unix_clock_does_not_500_datetime(self):
        """int(time.time()) OverflowError on leftover inf used to 500 GET /api/settings datetime."""
        def fake_sh(argv, **kwargs):
            joined = " ".join(str(a) for a in argv)
            if argv[0].endswith("date") or "+%Y" in joined:
                return 0, "2026-08-19 12:00:00 UTC", ""
            if "getusingnetworktime" in joined:
                return 0, "Network Time: On", ""
            if "getnetworktimeserver" in joined:
                return 0, "Network Time Server: time.apple.com", ""
            return 1, "", ""

        with (
            mock.patch.object(system_settings_svc, "sh", side_effect=fake_sh),
            mock.patch("hub.identity_svc.time_zone", return_value="UTC"),
            mock.patch.object(system_settings_svc.time, "time", return_value=float("inf")),
        ):
            info = system_settings_svc.get_datetime_info()
        self.assertEqual(info["unix"], 0)
        _json(info)

    def test_int_none_bytes_ntp_helpers_do_not_500(self):
        with mock.patch.object(system_settings_svc, "sh", return_value=(0, None, "")):
            self.assertIsNone(system_settings_svc._ntp_enabled())
            self.assertIsNone(system_settings_svc._ntp_server())
            self.assertEqual(system_settings_svc.get_ups_info()["source"], "unknown")
        with mock.patch.object(system_settings_svc, "sh", return_value=(0, 12, "")):
            self.assertIs(system_settings_svc._ntp_enabled(), False)
            self.assertIsNone(system_settings_svc._ntp_server())
            ups = system_settings_svc.get_ups_info()
        self.assertEqual(ups["source"], "unknown")
        _json(ups)

    def test_bytes_pmset_is_parsed_not_swallowed(self):
        def fake_sh(argv, **kwargs):
            if argv[-1] == "batt":
                return 0, b"Now drawing from 'AC Power'\n", ""
            if argv[-1] == "assertions":
                return 0, b"pid 1 named: caffeinate\n", ""
            return 0, b"System-wide power settings:\n sleep 0\n womp 1\n", ""

        with mock.patch.object(system_settings_svc, "sh", side_effect=fake_sh):
            info = system_settings_svc.get_power_info()
        self.assertEqual(info["sleep"], 0)
        self.assertEqual(info["womp"], 1)
        self.assertEqual(info["ups"]["source"], "ac")
        self.assertTrue(info["assertions"])
        _json(info)

    def test_failed_pref_bytes_message_does_not_500(self):
        with mock.patch.object(system_settings_svc, "sh", return_value=(1, b"denied", b"no")):
            out = system_settings_svc.set_power_pref("sleep", 0)
        self.assertFalse(out["ok"])
        self.assertIsInstance(out["message"], str)
        _json(out)

    def test_bytes_sharing_listing_does_not_500(self):
        def fake_sh(argv, **kwargs):
            if argv[0].endswith("sharing"):
                return 0, b"name: Media\nname: Time Machine\n", ""
            return 0, b"state = running\n", ""

        with mock.patch.object(system_settings_svc, "sh", side_effect=fake_sh):
            data = system_settings_svc.get_share_globals()
        self.assertEqual(data["share_count"], 2)
        self.assertTrue(data["smb_running"])
        _json(data)

    def test_non_dict_scheduler_rows_do_not_500(self):
        with mock.patch(
            "hub.tools_svc.launchd_timers",
            return_value=[{"label": "ok"}, "junk", None],
        ):
            data = system_settings_svc.get_scheduler_summary()
        self.assertEqual(data["count"], 3)
        self.assertEqual(len(data["timers"]), 1)
        _json(data)

    def test_scheduler_inf_fields_do_not_500(self):
        with mock.patch(
            "hub.tools_svc.launchd_timers",
            return_value=[{
                "label": float("inf"),
                "interval": float("inf"),
                "calendar": float("nan"),
                "path": b"/tmp/x.plist",
            }],
        ):
            data = system_settings_svc.get_scheduler_summary()
        self.assertIsNone(data["timers"][0]["label"])
        self.assertIsNone(data["timers"][0]["interval"])
        self.assertEqual(data["timers"][0]["path"], "/tmp/x.plist")
        _json(data)

    def test_yaml_inf_thresholds_do_not_500(self):
        with mock.patch.object(
            system_settings_svc, "settings_section",
            return_value={"cpu_pct": float("inf"), "mem_pct": float("nan"), "enabled": True},
        ):
            data = system_settings_svc.get_thresholds()
        self.assertEqual(data["cpu_pct"], 90)
        self.assertEqual(data["mem_pct"], 90)
        self.assertTrue(data["enabled"])
        _json(data)

    def test_yaml_inf_and_date_other_do_not_500(self):
        with (
            mock.patch.object(system_settings_svc, "cfg", return_value={"settings": {
                "metrics_interval": float("inf"),
                "alert_interval": datetime.date(2026, 8, 19),
                "adaptive": float("inf"),
                "resource_mode": "low",
            }}),
            mock.patch.object(
                system_settings_svc, "settings_section",
                return_value={"interval": float("inf"), "ips": [float("inf"), "10.0.0.1"]},
            ),
            mock.patch.object(
                system_settings_svc, "get_thresholds",
                return_value={"cpu_pct": 90},
            ),
        ):
            data = system_settings_svc.get_other_settings()
        self.assertEqual(data["metrics_interval"], 90)
        self.assertEqual(data["alert_interval"], 90)
        self.assertIs(data["adaptive"], True)
        self.assertEqual(data["ip_aliases"]["interval"], 60)
        self.assertEqual(data["ip_aliases"]["ips"], ["10.0.0.1"])
        _json(data)

    def test_bytes_username_does_not_500_management(self):
        with (
            mock.patch.object(system_settings_svc, "cfg", return_value={"settings": {}}),
            mock.patch.object(
                system_settings_svc, "settings_section",
                return_value={"enabled": True, "username": b"admin"},
            ),
            mock.patch.object(system_settings_svc, "host_ip", return_value="10.0.0.1"),
            mock.patch.object(system_settings_svc, "configured_host", return_value="auto"),
        ):
            data = system_settings_svc.get_management_access()
        self.assertEqual(data["username"], "admin")
        _json(data)

    def test_disk_settings_inf_size_does_not_500(self):
        with mock.patch.object(
            system_settings_svc, "fan_out",
            return_value=[
                {"disksleep": 0},
                ({}, []),
                [{"id": "disk4", "name": float("inf"), "power_state": "active",
                  "size_gb": float("inf")}],
            ],
        ):
            data = system_settings_svc.get_disk_settings()
        self.assertEqual(data["power_disks"][0]["id"], "disk4")
        self.assertIsNone(data["power_disks"][0]["size_gb"])
        _json(data)

    def test_vm_inf_name_does_not_500(self):
        with (
            mock.patch("hub.vms_svc.list_all_vms", return_value={
                "vms": [
                    None,
                    {"id": "ok", "name": float("inf"), "state": "running", "backend": "utm"},
                ],
            }),
            mock.patch("hub.vms_svc._utm_available", return_value=True),
            mock.patch("hub.vms_svc._orb_available", return_value=False),
        ):
            data = system_settings_svc.get_vm_settings()
        self.assertEqual(data["total"], 1)
        self.assertIsNone(data["items"][0]["name"])
        _json(data)

    def test_set_power_pref_inf_is_soft_fail(self):
        """YAML/JSON leftover ``value: .inf`` used to OverflowError ``int(inf)``."""
        out = system_settings_svc.set_power_pref("sleep", float("inf"))
        self.assertFalse(out["ok"])
        self.assertEqual(out["code"], "power.bad_value")
        _json(out)

    def test_diag_metrics_inf_does_not_500(self):
        with mock.patch("hub.metrics.history", return_value=[{"t": 1, "cpu": float("inf")}]):
            data = system_settings_svc._diag_metrics()
        self.assertIsNone(data["metrics_latest"]["cpu"])
        _json(data)


class PowerAsTextRecursionLeftoverTests(unittest.TestCase):
    def test_power_as_text_recursing_does_not_500(self):
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(power_svc._as_text(Recursing()), "Recursing")
        json.dumps(
            {"message": power_svc._as_text(Recursing())},
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")

    def test_system_extra_as_text_recursing_does_not_500(self):
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(system_extra._as_text(Recursing()), "Recursing")
        json.dumps(
            {"message": system_extra._as_text(Recursing())},
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")


class PowerSystemSensorsJsonableLeftoverTests(unittest.TestCase):
    def test_isoformat_inf_date_bytes_set_do_not_500(self):
        """A leftover ``isoformat()`` returning inf used to 500 power/system/sensors JSON."""
        class _Stamp:
            def isoformat(self):
                return float("inf")

        self.assertIsNone(power_svc._jsonable(_Stamp()))
        self.assertIsNone(system._jsonable(_Stamp()))
        self.assertIsNone(sensors_svc._jsonable(_Stamp()))
        for fn in (power_svc._jsonable, system._jsonable, sensors_svc._jsonable):
            out = fn({
                "when": _Stamp(),
                "name": datetime.date(2026, 8, 19),
                "blob": b"ok",
                "tags": {"ac"},
                "n": float("inf"),
            })
            _json(out)
            json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")
            self.assertIsNone(out["when"])
            self.assertEqual(out["name"], "2026-08-19")
            self.assertEqual(out["blob"], "ok")
            self.assertEqual(out["tags"], ["ac"])
            self.assertIsNone(out["n"])


if __name__ == "__main__":
    unittest.main()
