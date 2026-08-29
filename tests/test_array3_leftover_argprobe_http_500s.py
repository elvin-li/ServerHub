"""Third leftover-500s sweep of the Main Array page's backend.

The hunted classes (lone UTF-8 surrogates in keys AND values, the CPython
4300-digit int cap — including the uncapped YAML/plist hex form that arrives
*already-int* — and non-str in-process arguments) were re-reproduced against
every route the Main Array page calls: GET /api/storage (light and full),
GET /api/storage/manage, POST /api/storage/manage/{id},
POST /api/storage/disks/{id}/power, GET /api/raid, GET /api/smart and
POST /api/smart/test.

Live leaks found and fixed alongside this file — the exact class raid_svc /
storage_pool_svc already handle (their fix comments call it the
``_req_text`` / str()-probe convention), missed in the page's other three
services:

* ``smart_test_svc.start_test`` / ``abort_test`` stringified the device with
  a bare ``str(device or "")``: an over-cap already-int device raised the
  int->str digit-cap ValueError instead of the coded ``bad_device`` every
  other junk device gets.  A non-str *kind* (and ``set_schedule``'s
  interval/kind) AttributeError'd ``.strip()`` the same way.
* ``disk_power_svc.disk_power_action`` AttributeError'd ``.lower()`` on a
  non-str action, and ``sleep_disk`` / ``wake_disk`` TypeError'd
  ``DISK_RE.match`` on a non-str id, where the coded refusal is the contract.
* ``disk_manage_svc.disk_action`` AttributeError'd ``.strip()`` on a non-str
  action; ``_normalize_id`` and the erase branch gated on
  ``isinstance(..., str)`` so a finite numeric argument was refused instead
  of keeping its string form, and an over-cap int rode raw into the error
  params, where ``errors._jsonable_param`` drops it and the message's
  ``{device}`` / ``{fs}`` placeholder stayed unfilled.

Everything else in the blast radius was found immune, so the rest of this
file pins the stays-immune corners at the HTTP layer — request routing,
response rendering and the strict UTF-8 decode of the body — with hostile
plist hex ints, a garbled ``df`` table and over-cap smartctl fields riding
the real subprocess-parse pipeline.
"""
from __future__ import annotations

import asyncio
import json
import unittest
from unittest import mock
from urllib.parse import quote

from fastapi import FastAPI, HTTPException

from hub import (
    disk_manage_svc,
    disk_power_svc,
    disk_snapshot,
    raid_svc,
    smart_test_svc,
    storage_svc,
)
from hub.routers import storage as storage_router
from hub.routers import nas_storage

#: Past CPython's default 4300-digit int<->str conversion limit.  A valid
#: Python int — every ``isinstance(x, int)`` fast path accepts it — whose
#: ``str()`` raises the same ValueError ``json.dumps`` would.  Built from
#: hex like the YAML/plist loaders build theirs (``int(x, 16)`` is exempt
#: from the parse cap).
_HUGE_INT = int("f" * 4400, 16)

_SURROGATE = "\ud800junk"


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


# ── the fixed leaks: coded refusals, never the bare raise ────────────────────

class SmartTestArgProbeTests(unittest.TestCase):
    """start_test/abort_test used to raise the digit-cap ValueError."""

    def setUp(self):
        nodes = mock.patch.object(
            smart_test_svc, "_device_nodes", return_value=["/dev/disk0"]
        )
        nodes.start()
        self.addCleanup(nodes.stop)

    def test_huge_int_device_is_the_coded_refusal(self):
        """Pre-fix: ``str(10**...)`` ValueError'd POST /api/smart/test."""
        out = smart_test_svc.start_test(_HUGE_INT, "short")
        self.assertEqual(out, {"ok": False, "error": "bad_device"})
        _starlette(out)

    def test_huge_int_abort_device_is_the_coded_refusal(self):
        out = smart_test_svc.abort_test(_HUGE_INT)
        self.assertEqual(out, {"ok": False, "error": "bad_device"})

    def test_non_str_kind_is_the_coded_refusal(self):
        """Pre-fix: ``(kind or "").strip()`` AttributeError'd."""
        out = smart_test_svc.start_test("/dev/disk0", _HUGE_INT)
        self.assertEqual(out["error"], "bad_kind")

    def test_finite_numeric_device_keeps_its_string_form(self):
        """str() probe, not an isinstance gate: ``4`` behaves as ``"4"`` —
        the same coded refusal a junk string device earns."""
        out = smart_test_svc.start_test(4, "short")
        self.assertEqual(out["error"], "bad_device")

    def test_numeric_schedule_fields_are_coded_not_500(self):
        """Pre-fix both AttributeError'd out of PUT /api/smart/schedule."""
        with mock.patch.object(smart_test_svc, "update_settings") as upd:
            out = smart_test_svc.set_schedule(
                interval=123, kind="short", devices=[]
            )
            self.assertEqual(out, {"ok": False, "error": "bad_interval"})
            out = smart_test_svc.set_schedule(
                interval="off", kind=123, devices=[]
            )
            self.assertEqual(out, {"ok": False, "error": "bad_kind"})
            upd.assert_not_called()

    def test_over_cap_schedule_fields_save_the_defaults_not_500(self):
        """The unrenderable leftover coerces to "" and the caller's own
        defaults answer — the storage_pool save_pool(name=huge) convention."""
        with (
            mock.patch.object(smart_test_svc, "update_settings") as upd,
            mock.patch.object(smart_test_svc, "invalidate"),
            mock.patch.object(smart_test_svc, "_schedule_cfg", return_value={}),
        ):
            out = smart_test_svc.set_schedule(
                interval=_HUGE_INT, kind=_HUGE_INT, devices=[]
            )
        self.assertTrue(out["ok"])
        saved = upd.call_args.args[0]["smart_schedule"]
        self.assertEqual(saved["interval"], "off")
        self.assertEqual(saved["kind"], "short")


class DiskPowerArgProbeTests(unittest.TestCase):
    """disk_power_action/sleep/wake used to TypeError/AttributeError."""

    def test_non_str_action_is_the_coded_refusal(self):
        """Pre-fix: ``(action or "").lower()`` AttributeError'd the route."""
        with self.assertRaises(HTTPException) as ctx:
            disk_power_svc.disk_power_action("disk4", _HUGE_INT)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail["code"], "disk_power.unknown_action")
        _starlette(ctx.exception.detail)

    def test_non_str_disk_id_is_the_coded_refusal(self):
        """Pre-fix: ``DISK_RE.match(int)`` TypeError'd sleep and wake."""
        for fn in (
            lambda: disk_power_svc.disk_power_action(_HUGE_INT, "sleep"),
            lambda: disk_power_svc.sleep_disk(_HUGE_INT),
            lambda: disk_power_svc.wake_disk(_HUGE_INT),
        ):
            with self.assertRaises(HTTPException) as ctx:
                fn()
            self.assertEqual(ctx.exception.detail["code"], "disk_power.invalid_id")

    def test_finite_numeric_id_keeps_its_string_form(self):
        """``4`` reads as ``"4"``, which no whole-disk id matches — the same
        coded refusal a junk string id earns, never a TypeError."""
        with self.assertRaises(HTTPException) as ctx:
            disk_power_svc.disk_power_action(4, "wake")
        self.assertEqual(ctx.exception.detail["code"], "disk_power.invalid_id")

    def test_container_disk_id_never_unwraps(self):
        """``["disk4"]`` is junk, not disk4: the argument probe coerces a
        container to "" instead of unwrapping it into a real id the way the
        plist display sanitizer would."""
        with self.assertRaises(HTTPException) as ctx:
            disk_power_svc.disk_power_action(["disk4"], "wake")
        self.assertEqual(ctx.exception.detail["code"], "disk_power.invalid_id")

    def test_surrogate_action_param_is_scrubbed(self):
        with self.assertRaises(HTTPException) as ctx:
            disk_power_svc.disk_power_action("disk4", _SURROGATE)
        detail = ctx.exception.detail
        self.assertEqual(detail["code"], "disk_power.unknown_action")
        self.assertNotIn("\ud800", detail["params"]["action"])
        _starlette(detail)


class DiskManageArgProbeTests(unittest.TestCase):
    """disk_action's argument probes, matching raid_svc._req_text."""

    def setUp(self):
        info = mock.patch.object(
            disk_manage_svc, "_diskutil_info",
            return_value={"VolumeName": "Vault", "MountPoint": "/Volumes/Vault"},
        )
        info.start()
        self.addCleanup(info.stop)
        roots = mock.patch.object(
            disk_manage_svc, "root_devices", return_value=frozenset()
        )
        roots.start()
        self.addCleanup(roots.stop)

    def test_non_str_action_is_the_coded_refusal(self):
        """Pre-fix: ``(action or "").strip()`` AttributeError'd (a 500)."""
        with self.assertRaises(HTTPException) as ctx:
            disk_manage_svc.disk_action("disk4s1", _HUGE_INT)
        self.assertEqual(ctx.exception.detail["code"], "disk.unknown_action")

    def test_huge_int_device_fills_the_message_placeholder(self):
        """Pre-fix the raw int rode into the params, _jsonable_param dropped
        it, and the message kept a literal ``{device}`` placeholder."""
        with self.assertRaises(HTTPException) as ctx:
            disk_manage_svc.disk_action(_HUGE_INT, "mount")
        detail = ctx.exception.detail
        self.assertEqual(detail["code"], "disk.invalid_device")
        self.assertEqual(detail["params"]["device"], "")
        self.assertNotIn("{device}", detail["message"])

    def test_finite_numeric_device_keeps_its_string_form(self):
        with self.assertRaises(HTTPException) as ctx:
            disk_manage_svc.disk_action(4, "mount")
        self.assertEqual(ctx.exception.detail["params"]["device"], "4")

    def test_huge_int_fs_fills_the_message_placeholder(self):
        with self.assertRaises(HTTPException) as ctx:
            disk_manage_svc.disk_action(
                "disk4s1", "eraseVolume", fs=_HUGE_INT, name="X",
                confirm=True, confirm_name="Vault",
            )
        detail = ctx.exception.detail
        self.assertEqual(detail["code"], "disk.unsupported_fs")
        self.assertEqual(detail["params"]["fs"], "")
        self.assertNotIn("{fs}", detail["message"])

    def test_container_name_never_unwraps_into_a_label(self):
        """``["Backups"]`` must stay the coded ``name_required`` — the
        argument probe refuses containers instead of unwrapping them into a
        plausible rename label."""
        with self.assertRaises(HTTPException) as ctx:
            disk_manage_svc.disk_action("disk4s1", "rename", name=["Backups"])
        self.assertEqual(ctx.exception.detail["code"], "disk.name_required")

    def test_surrogate_rename_name_is_refused_not_scrubbed(self):
        """A lone-surrogate name earns ``name_required`` via _label_ok's
        strict encode; scrubbing it into a mangled-but-valid label would
        rename the volume to mojibake."""
        with self.assertRaises(HTTPException) as ctx:
            disk_manage_svc.disk_action("disk4s1", "rename", name="X\ud800")
        self.assertEqual(ctx.exception.detail["code"], "disk.name_required")

    def test_huge_int_rename_name_is_the_coded_refusal(self):
        with self.assertRaises(HTTPException) as ctx:
            disk_manage_svc.disk_action("disk4s1", "rename", name=_HUGE_INT)
        self.assertEqual(ctx.exception.detail["code"], "disk.name_required")

    def test_huge_int_confirm_name_mismatches_like_junk(self):
        with self.assertRaises(HTTPException) as ctx:
            disk_manage_svc.disk_action(
                "disk4s1", "eraseVolume", fs="APFS", name="X",
                confirm=True, confirm_name=_HUGE_INT,
            )
        self.assertEqual(
            ctx.exception.detail["code"], "disk.confirm_name_mismatch"
        )

    def test_finite_numeric_erase_label_keeps_its_string_form(self):
        """Pre-fix a numeric label was refused as name_required; the str()
        probe renders ``123`` as the label ``"123"`` like every other
        in-process caller's finite numeric argument."""
        calls = []

        def fake_sh(argv, timeout=10, **kw):
            calls.append(list(argv))
            return 0, "erased", ""

        with (
            mock.patch.object(disk_manage_svc, "sh", fake_sh),
            mock.patch.object(disk_manage_svc, "invalidate_disks"),
        ):
            out = disk_manage_svc.disk_action(
                "disk4s1", "eraseVolume", fs="APFS", name=123,
                confirm=True, confirm_name="Vault",
            )
        self.assertTrue(out["ok"])
        self.assertEqual(out["name"], "123")
        self.assertIn("123", calls[0])


# ── stays-immune pins at the HTTP layer ──────────────────────────────────────

#: Hostile ``diskutil info -plist`` output: plist hex ints load uncapped
#: through ``int(x, 16)``, so Size / MountPoint / BusProtocol arrive
#: *already-int* and only fail at render time.  VolumeName is invalid-UTF-8
#: ``<data>`` bytes.
_HOSTILE_INFO_PLIST = (
    '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict>'
    "<key>DeviceIdentifier</key><string>disk4</string>"
    "<key>TotalSize</key><integer>0x" + "F" * 4400 + "</integer>"
    "<key>Size</key><integer>0x" + "F" * 4400 + "</integer>"
    "<key>MountPoint</key><integer>0x" + "F" * 4400 + "</integer>"
    "<key>VolumeName</key><data>gA==</data>"
    "<key>MediaName</key><data>gA==</data>"
    "<key>BusProtocol</key><integer>0x" + "F" * 4400 + "</integer>"
    "<key>Internal</key><false/><key>SolidState</key><false/>"
    "<key>Ejectable</key><true/>"
    "</dict></plist>"
).encode()

_HOSTILE_LIST_PLIST = (
    '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict>'
    "<key>WholeDisks</key><array><string>disk4</string></array>"
    "<key>AllDisksAndPartitions</key><array><dict>"
    "<key>DeviceIdentifier</key><string>disk4</string>"
    "<key>Size</key><integer>0x" + "F" * 4400 + "</integer>"
    "<key>Content</key><integer>0x" + "F" * 4400 + "</integer>"
    "<key>Partitions</key><array><dict>"
    "<key>DeviceIdentifier</key><string>disk4s1</string>"
    "<key>Size</key><integer>0x" + "F" * 4400 + "</integer>"
    "<key>MountPoint</key><integer>0x" + "F" * 4400 + "</integer>"
    "</dict></array></dict></array></dict></plist>"
).encode()

_HOSTILE_RAID_PLIST = (
    '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict>'
    "<key>AppleRAIDSets</key><array><dict>"
    "<key>AppleRAIDSetUUID</key><string>abcd1234</string>"
    "<key>Name</key><string>Mirror</string>"
    "<key>Level</key><string>Mirror</string>"
    "<key>Status</key><string>Online</string>"
    "<key>Size</key><integer>0x" + "F" * 4400 + "</integer>"
    "<key>AppleRAIDMembers</key><array><dict>"
    "<key>AppleRAIDMemberUUID</key><string>m1</string>"
    "<key>MemberStatus</key><string>Online</string>"
    "<key>Size</key><integer>0x" + "F" * 4400 + "</integer>"
    "</dict></array></dict></array></dict></plist>"
)

#: ``df -P -k`` with one garbled over-cap/inf row and one healthy row.  The
#: poisoned row drops alone; its sibling must survive.
_HOSTILE_DF = (
    "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
    "/dev/disk3s1s1 100000000 50000000 50000000 50% /\n"
    "/dev/disk4s1 " + "9" * 5000 + " 1 1 inf% /Volumes/Junk\n"
    "/dev/disk4s1 10000000 5000000 5000000 50% /Volumes/Vault\n"
)

#: smartctl output with an over-cap attribute ID (row drops alone), an
#: over-cap raw counter (stays a digit *string*) and an over-cap model.
_HOSTILE_SMARTCTL = (
    "smartctl 7.5 2025-04-30 r5714\n"
    "=== START OF INFORMATION SECTION ===\n"
    "Model Number: Junk " + "9" * 4400 + "\n"
    "Serial Number: X\n"
    "SMART overall-health self-assessment test result: PASSED\n"
    "ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      "
    "UPDATED  WHEN_FAILED RAW_VALUE\n"
    "  " + "9" * 4400 + " Reallocated_Sector_Ct   0x0033   100   100   010"
    "    Pre-fail  Always       -       55\n"
    "  5 Reallocated_Sector_Ct   0x0033   100   100   010    Pre-fail"
    "  Always       -       " + "9" * 4400 + "\n"
)


def _fake_sh(argv, timeout=10, **kw):
    joined = " ".join(str(a) for a in argv)
    if "df" in str(argv[0]):
        return 0, _HOSTILE_DF, ""
    if "appleRAID" in joined:
        return 0, _HOSTILE_RAID_PLIST, ""
    if "diskutil" in joined and "list" in joined:
        return 0, "/dev/disk4 (external, physical):\n", ""
    if "diskutil" in joined and "info" in joined:
        return 0, (
            "   Device / Media Name: Junk\n"
            "   Disk Size: 1.0 TB (" + "9" * 4400 + " Bytes)\n"
            "   Protocol: USB\n"
        ), ""
    if "smartctl" in joined:
        return 0, _HOSTILE_SMARTCTL, ""
    return 1, "", ""


def _fake_run_bytes(cmd, timeout=10, cap=None, runner=None, **kw):
    joined = " ".join(str(c) for c in cmd)
    if "list" in joined:
        return 0, _HOSTILE_LIST_PLIST, b""
    return 0, _HOSTILE_INFO_PLIST, b""


async def _asgi_request(app, method, path, *, body=None, raw_body=None, query=b""):
    """Drive the routers through a real ASGI cycle."""
    if raw_body is not None:
        payload = raw_body
    else:
        payload = b"" if body is None else json.dumps(body).encode("utf-8")
    sent = False
    messages: list[dict] = []

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": payload, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1", "method": method, "scheme": "http",
        "path": path, "raw_path": quote(path, safe="/").encode(),
        "query_string": query, "root_path": "",
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
        ],
        "server": ("localhost", 8086), "client": ("127.0.0.1", 1), "state": {},
    }
    await app(scope, receive, send)
    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    raw = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    # The body must already be valid UTF-8 — decode strictly on purpose.
    return status, raw.decode("utf-8")


class MainArrayHttpStaysImmunePins(unittest.TestCase):
    """The page's read routes over real ASGI, with hostile plist hex ints, a
    garbled ``df`` table and over-cap smartctl fields riding the real
    subprocess-parse pipeline."""

    @classmethod
    def setUpClass(cls):
        cls.app = FastAPI()
        cls.app.include_router(storage_router.router)
        cls.app.include_router(nas_storage.router)

    def setUp(self):
        self._invalidate()
        self.addCleanup(self._invalidate)
        patches = [
            mock.patch.object(storage_svc, "sh", _fake_sh),
            mock.patch.object(disk_power_svc, "sh", _fake_sh),
            mock.patch.object(disk_manage_svc, "sh", _fake_sh),
            mock.patch.object(disk_snapshot, "sh", _fake_sh),
            mock.patch.object(smart_test_svc, "sh", _fake_sh),
            mock.patch.object(raid_svc, "sh", _fake_sh),
            mock.patch.object(disk_power_svc, "run_bytes", _fake_run_bytes),
            mock.patch.object(disk_manage_svc, "run_bytes", _fake_run_bytes),
            mock.patch.object(disk_snapshot, "run_bytes", _fake_run_bytes),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    @staticmethod
    def _invalidate():
        storage_svc.invalidate_smart()
        disk_manage_svc.invalidate_disk_info()
        disk_power_svc.invalidate_power_disks()
        raid_svc.invalidate()
        smart_test_svc.invalidate()

    def _request(self, method, path, **kw):
        return asyncio.run(_asgi_request(self.app, method, path, **kw))

    def test_storage_light_stays_http_200(self):
        status, raw = self._request("GET", "/api/storage", query=b"light=true")
        self.assertEqual(status, 200)
        body = json.loads(raw)
        mounts = [v["mount"] for v in body["volumes"]]
        # The healthy row survives; the over-cap/inf row drops alone.
        self.assertIn("/Volumes/Vault", mounts)
        self.assertNotIn("/Volumes/Junk", mounts)
        # The over-cap attribute ID row dropped; the over-cap raw counter is
        # a digit *string*, which renders fine and stays.
        attrs = body["disks"][0]["smart"]["attrs"]
        self.assertEqual([a["id"] for a in attrs], [5])
        self.assertEqual(attrs[0]["raw"], "9" * 4400)

    def test_storage_full_stays_http_200(self):
        status, raw = self._request("GET", "/api/storage")
        self.assertEqual(status, 200)
        body = json.loads(raw)
        # Power listing: the over-cap plist TotalSize loses only its GB figure.
        disk4 = next(d for d in body["power_disks"] if d["id"] == "disk4")
        self.assertIsNone(disk4["size_gb"])
        # Managed listing: over-cap Size drops to 0/None, int MountPoint to "".
        whole = next(v for v in body["managed"]["volumes"] if v["id"] == "disk4")
        self.assertEqual(whole["size_bytes"], 0)
        self.assertIsNone(whole["size_gb"])
        self.assertEqual(whole["mount"], "")

    def test_storage_manage_stays_http_200(self):
        status, raw = self._request("GET", "/api/storage/manage")
        self.assertEqual(status, 200)
        leaf = next(v for v in json.loads(raw)["volumes"] if v["id"] == "disk4s1")
        self.assertEqual(leaf["size_bytes"], 0)

    def test_raid_stays_http_200(self):
        status, raw = self._request("GET", "/api/raid")
        self.assertEqual(status, 200)
        body = json.loads(raw)
        self.assertEqual(body["sets"][0]["size_bytes"], None)
        self.assertEqual(body["sets"][0]["members"][0]["size_bytes"], None)

    def test_smart_stays_http_200(self):
        status, raw = self._request("GET", "/api/smart")
        self.assertEqual(status, 200)
        body = json.loads(raw)
        self.assertEqual(body["devices"][0]["id"], "disk4")

    def test_surrogate_manage_action_is_the_coded_400(self):
        """A ``\\ud800`` JSON escape is a lone surrogate by the time the
        service sees it; the coded error body scrubs it before the strict
        UTF-8 encode."""
        status, raw = self._request(
            "POST", "/api/storage/manage/disk4s1", body={"action": _SURROGATE}
        )
        self.assertEqual(status, 400)
        detail = json.loads(raw)["detail"]
        self.assertEqual(detail["code"], "disk.unknown_action")
        self.assertNotIn("\ud800", detail["params"]["action"])

    def test_surrogate_power_action_is_the_coded_400(self):
        status, raw = self._request(
            "POST", "/api/storage/disks/disk4/power", body={"action": _SURROGATE}
        )
        self.assertEqual(status, 400)
        self.assertEqual(
            json.loads(raw)["detail"]["code"], "disk_power.unknown_action"
        )

    def test_huge_int_body_literal_is_the_coded_400_not_500(self):
        """A >4300-digit integer literal in the request body: ``json.loads``
        raises ValueError, NOT JSONDecodeError, for the whole document.
        FastAPI's body-parse guard answers the coded 400 on this route too."""
        raw_body = b'{"action": "mount", "confirm": ' + b"9" * 5000 + b"}"
        status, raw = self._request(
            "POST", "/api/storage/manage/disk4s1", raw_body=raw_body
        )
        self.assertEqual(status, 400)
        self.assertIn("error parsing the body", raw)


if __name__ == "__main__":
    unittest.main()
