"""Tools-page leftover sweep #5: nested subclass bombs on the hardware tab.

Sweep #4 fixed the raw-copy leak on GET /api/tools/hardware: one poisoned
``list_power_disks`` row (lone surrogate, inf, bytes, over-cap int) used to
500 the route and poison ``_hw_cache`` for the full TTL.  Its fix scrubs per
field — but every scrub ran through *bound* calls on the row and its values.
A fresh hunt over the same mounted route (create_app + TestClient,
raise_server_exceptions=False) found six live 500s left behind:

* a dict-subclass row whose bound ``get()`` raises passes the isinstance
  gate, and the bomb escaped ``_power_disk_row`` into ``fan_out`` — which
  re-raises on iteration — wiping the four profiler sections alongside;
* a ``__bool__`` bomb on the ``ssd`` value blew ``bool(ssd)``, and one on
  the ``system`` value blew ``bool(d.get("system"))`` the same way;
* an int-subclass ``__str__`` bomb in ``size_gb`` blew ``_renderable_number``'s
  digit-cap ``str()`` probe (only ValueError was caught);
* a bytes-subclass ``decode`` bomb in ``power_state`` or ``name`` blew
  ``_as_text``'s byte scrub — the exact leftover class modules5 fixed one
  module over.

The fix routes the row reads through unbound base-type calls (``dict.get``,
``int.__index__``, ``float.__float__``, ``bytes``/``bytearray.decode``),
guards the two flags (``_safe_flag``), guards ``_as_text``'s final UTF-8
re-encode, and adds a last-ditch per-row try so a residual bomb costs its
own row, never the batch.  The real content survives the scrub: the
get-bomb row still lists its fields, the int keeps its number, the bombed
bytes still decode.

Stays-immune pins ride along for the vectors this sweep re-tested and found
already dead: a FIFO occupying a LaunchAgent plist (must not hang the
scheduler/agents routes — read_bytes_capped's O_NONBLOCK regular-file
check), torn-IPv6 ping/dns hosts (coded ``tools.bad_host``), an unhashable
leftover in the getaddrinfo sockaddr (the set-membership class, absorbed by
the coded failure), a list-subclass ``__iter__`` iterbomb around the rows
(neutralized by the ``[:12]`` base slice), a str-subclass ``__str__`` bomb
id (degrades to ""), and the huge-digit ports limit (parse 422).
"""
from __future__ import annotations

import json
import os
import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import tools_svc
from hub.app_factory import create_app
from hub.auth import require_auth

#: Built arithmetically: int("9" * 5000) itself trips the digit cap.
_HUGE_INT = 10 ** 5000

_APP = None


def _client() -> TestClient:
    global _APP
    if _APP is None:
        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: None
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _GetBombRow(dict):
    def get(self, *args, **kwargs):
        raise RuntimeError("get bomb")


class _BoolBomb:
    def __bool__(self):
        raise RuntimeError("bool bomb")


class _StrBombInt(int):
    def __str__(self):
        raise RuntimeError("int str bomb")

    __repr__ = __str__


class _DecodeBombBytes(bytes):
    def decode(self, *args, **kwargs):
        raise RuntimeError("bytes decode bomb")


class _DecodeBombBytearray(bytearray):
    def decode(self, *args, **kwargs):
        raise RuntimeError("bytearray decode bomb")


class _IterBombList(list):
    def __iter__(self):
        raise RuntimeError("list iter bomb")


class _StrBombStr(str):
    def __str__(self):
        raise RuntimeError("str bomb")


_CLEAN_ROW = {
    "id": "disk0", "name": "APPLE SSD", "size_gb": 494.4,
    "ssd": True, "power_state": "active", "system": True,
}


class _HardwareSandbox(unittest.TestCase):
    def setUp(self):
        tools_svc._hw_cache.update(t=0.0, v=None)
        self.addCleanup(tools_svc._hw_cache.update, t=0.0, v=None)

    def _get(self, rows):
        with (
            mock.patch.object(tools_svc, "sh", lambda *a, **k: (0, "Chip: M1", "")),
            mock.patch("hub.disk_power_svc.list_power_disks", lambda: rows),
        ):
            response = _client().get("/api/tools/hardware")
        self.assertEqual(response.status_code, 200, response.text[:300])
        body = response.json()
        _starlette(body)
        return body


class GetBombRowTests(_HardwareSandbox):
    """A dict-subclass row whose bound ``get()`` raises used to 500."""

    def test_get_bomb_row_lists_through_the_base_read(self):
        body = self._get([
            _GetBombRow(id="d1", name="usb", size_gb=1.0, ssd=True,
                        power_state="active", system=False),
            dict(_CLEAN_ROW),
        ])
        disks = body["disks"]
        self.assertEqual(len(disks), 2)
        # Unbound dict.get sees the real storage: the row's content survives.
        self.assertEqual(disks[0]["id"], "d1")
        self.assertEqual(disks[0]["name"], "usb")
        self.assertIs(disks[0]["ssd"], True)
        self.assertEqual(disks[1], dict(_CLEAN_ROW))

    def test_profiler_sections_survive_the_bomb_row(self):
        body = self._get([_GetBombRow(id="d1")])
        sections = body["sections"]
        self.assertEqual(sorted(sections), ["hardware", "memory", "power", "storage"])
        self.assertTrue(all(s["ok"] for s in sections.values()))


class BoolBombFlagTests(_HardwareSandbox):
    """``__bool__`` bombs on the two flags used to 500 the route."""

    def test_ssd_bool_bomb_costs_its_field_only(self):
        body = self._get([{**_CLEAN_ROW, "id": "d2", "ssd": _BoolBomb()},
                          dict(_CLEAN_ROW)])
        disks = body["disks"]
        self.assertIsNone(disks[0]["ssd"])
        self.assertEqual(disks[0]["name"], "APPLE SSD")
        self.assertEqual(disks[1], dict(_CLEAN_ROW))

    def test_system_bool_bomb_costs_its_field_only(self):
        body = self._get([{**_CLEAN_ROW, "id": "d3", "system": _BoolBomb()}])
        row = body["disks"][0]
        self.assertIs(row["system"], False)
        self.assertEqual(row["id"], "d3")

    def test_none_ssd_stays_the_tri_state_none(self):
        body = self._get([{**_CLEAN_ROW, "id": "d3b", "ssd": None}])
        self.assertIsNone(body["disks"][0]["ssd"])


class NumericSubclassBombTests(_HardwareSandbox):
    """Base coercion first, then the existing digit-cap / finite probes."""

    def test_int_subclass_str_bomb_keeps_its_number(self):
        body = self._get([{**_CLEAN_ROW, "id": "d4", "size_gb": _StrBombInt(5)}])
        self.assertEqual(body["disks"][0]["size_gb"], 5)

    def test_overcap_int_wearing_the_bomb_subclass_still_drops(self):
        body = self._get([{**_CLEAN_ROW, "id": "d5",
                           "size_gb": _StrBombInt(_HUGE_INT)}])
        self.assertIsNone(body["disks"][0]["size_gb"])

    def test_renderable_number_base_coercions(self):
        self.assertEqual(tools_svc._renderable_number(_StrBombInt(7)), 7)
        self.assertIsNone(tools_svc._renderable_number(_StrBombInt(_HUGE_INT)))
        self.assertIsNone(tools_svc._renderable_number(_HUGE_INT))
        self.assertIsNone(tools_svc._renderable_number(float("nan")))


class ByteDecodeBombTests(_HardwareSandbox):
    """Subclass ``decode`` bombs — the bytes still decode via the base."""

    def test_bytes_decode_bomb_power_state_still_decodes(self):
        body = self._get([{**_CLEAN_ROW, "id": "d6",
                           "power_state": _DecodeBombBytes(b"asleep")}])
        self.assertEqual(body["disks"][0]["power_state"], "asleep")

    def test_bytearray_decode_bomb_name_still_decodes_scrubbed(self):
        body = self._get([{**_CLEAN_ROW, "id": "d7",
                           "name": _DecodeBombBytearray(b"us\xffb")}])
        self.assertEqual(body["disks"][0]["name"], "us\ufffdb")


class CacheStaysCleanTests(_HardwareSandbox):
    """The cached payload after a bomb request is renderable for the TTL."""

    def test_cached_payload_after_a_bomb_row_is_renderable(self):
        self._get([
            _GetBombRow(id="d1"),
            {**_CLEAN_ROW, "id": "d2", "ssd": _BoolBomb(),
             "size_gb": _StrBombInt(_HUGE_INT),
             "power_state": _DecodeBombBytes(b"x")},
        ])
        _starlette(tools_svc._hw_cache["v"])

        def boom(*_a, **_k):
            raise AssertionError("a cache hit must not rebuild")

        with mock.patch("hub.disk_power_svc.list_power_disks", boom):
            second = _client().get("/api/tools/hardware")
        self.assertEqual(second.status_code, 200, second.text[:300])
        _starlette(second.json())


class StaysImmuneTests(unittest.TestCase):
    """Vectors this sweep re-tested and found already dead — pinned."""

    def setUp(self):
        tools_svc._hw_cache.update(t=0.0, v=None)
        self.addCleanup(tools_svc._hw_cache.update, t=0.0, v=None)

    def test_iterbomb_list_subclass_rows_are_neutralized_by_the_slice(self):
        rows = _IterBombList([dict(_CLEAN_ROW)])
        with (
            mock.patch.object(tools_svc, "sh", lambda *a, **k: (0, "x", "")),
            mock.patch("hub.disk_power_svc.list_power_disks", lambda: rows),
        ):
            response = _client().get("/api/tools/hardware")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["disks"], [dict(_CLEAN_ROW)])

    def test_str_subclass_str_bomb_id_degrades_to_empty_not_500(self):
        with (
            mock.patch.object(tools_svc, "sh", lambda *a, **k: (0, "x", "")),
            mock.patch("hub.disk_power_svc.list_power_disks",
                       lambda: [{**_CLEAN_ROW, "id": _StrBombStr("d9")}]),
        ):
            response = _client().get("/api/tools/hardware")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["disks"][0]["id"], "")

    def test_fifo_plist_neither_hangs_nor_500s_the_launchd_routes(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        os.mkfifo(Path(tmp.name) / "fifo.plist")
        (Path(tmp.name) / "good.plist").write_bytes(plistlib.dumps({
            "Label": "ok.job", "StartInterval": 60,
            "ProgramArguments": ["/usr/bin/true"],
        }))
        client = _client()
        with mock.patch.object(
            tools_svc.os.path, "expanduser", return_value=tmp.name,
        ):
            scheduler = client.get("/api/system/scheduler")
            agents = client.get("/api/tools/agents")
        self.assertEqual(scheduler.status_code, 200, scheduler.text[:300])
        self.assertEqual(agents.status_code, 200, agents.text[:300])
        self.assertEqual(
            [t["label"] for t in scheduler.json()["timers"]], ["ok.job"],
        )
        rows = {a["label"]: a for a in agents.json()["agents"]}
        self.assertEqual(rows["ok.job"]["interval_sec"], 60)
        # The FIFO surfaces as the parse-error row, never a hang or a 500.
        self.assertEqual(rows["fifo"]["error"], "parse")

    def test_torn_ipv6_hosts_are_the_coded_bad_host_soft_fail(self):
        for host in ("[::1", "::1]", "[fe80::1%25en0]"):
            for path, field in (("/api/tools/net/ping", "host"),
                                ("/api/tools/net/dns", "name")):
                response = _client().post(path, json={field: host})
                self.assertEqual(response.status_code, 200, response.text[:300])
                payload = response.json()
                self.assertFalse(payload["ok"])
                self.assertEqual(payload["code"], "tools.bad_host")

    def test_unhashable_sockaddr_is_the_coded_dns_failure(self):
        def fake_gai(name, port):
            return [(2, 1, 6, "", (["unhashable"], 0))]

        with mock.patch.object(tools_svc.socket, "getaddrinfo", fake_gai):
            response = _client().post(
                "/api/tools/net/dns", json={"name": "example.com"},
            )
        self.assertEqual(response.status_code, 200, response.text[:300])
        payload = response.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["results"], [])

    def test_huge_digit_ports_limit_is_the_parse_422_not_500(self):
        response = _client().get("/api/tools/ports?limit=" + "9" * 5000)
        self.assertEqual(response.status_code, 422, response.text[:300])


class SafeFlagUnitTests(unittest.TestCase):
    def test_safe_flag_shapes(self):
        self.assertIs(tools_svc._safe_flag(1), True)
        self.assertIs(tools_svc._safe_flag(0), False)
        self.assertIs(tools_svc._safe_flag(_BoolBomb()), False)
        self.assertIsNone(tools_svc._safe_flag(None, tri=True))
        self.assertIsNone(tools_svc._safe_flag(_BoolBomb(), tri=True))
        self.assertIs(tools_svc._safe_flag("x", tri=True), True)


if __name__ == "__main__":
    unittest.main()
