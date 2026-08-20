"""Leftover YAML/JSON 500s on GET /api/vms and the console resolver.

OrbStack ``id: Infinity`` / ``distro: NaN``, services.yaml override
``name: .inf`` / ``url: 2026-08-19``, a leftover allowlist host that
UnicodeError'd getaddrinfo, a non-list hypervisor listing, and a
non-dict orb row each used to 500 the request path.

Follow-up: YAML ``port: .inf`` / a 400-digit leftover int OverflowError'd
``int()`` and ``float()`` on the allowlist; ``!!binary`` host TypeError'd
``ord()`` in ``_is_loopback``; ``utmctl`` ``exists()`` EIO 500'd GET /api/vms
under Starlette's allow_nan=False encoder.

Follow-up 2: leftover ``\\ud800`` in a utmctl name / YAML override / orbctl
JSON name still 500'd GET /api/vms at UTF-8 encode time (``_jsonable``
returned strings as-is).
"""
from __future__ import annotations

import datetime
import json
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from hub import apps_manage_svc, vm_console, vms_svc, websocket_security

_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
UTM_LISTING = (
    "UUID                                 Status   Name\n"
    f"{_UUID} started  Ubuntu\n"
)


def _json(payload) -> None:
    json.dumps(payload, allow_nan=False)


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class OrbJsonLeftoverFieldTests(unittest.TestCase):
    def _list(self, payload: str):
        def fake_sh(cmd, **kw):
            if "-f" in cmd:
                return (0, payload, "")
            return (1, "", "no")

        with (
            mock.patch.object(vms_svc, "_orb_available", return_value=True),
            mock.patch.object(vms_svc, "sh", side_effect=fake_sh),
            mock.patch.object(vms_svc, "override", return_value={}),
        ):
            return vms_svc._list_orb_machines_uncached()

    def test_infinity_id_and_distro_do_not_500_json(self):
        """Python json.loads accepts Infinity; Starlette allow_nan=False does not."""
        items = self._list(
            '[{"name":"web","state":"running","id":Infinity,"distro":NaN}]'
        )
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["orb_name"], "web")
        self.assertEqual(items[0]["uuid"], "web")
        self.assertEqual(items[0]["distro"], "")
        _json(items)

    def test_nested_inf_id_object_does_not_500_json(self):
        items = self._list(
            '[{"name":"web","state":"running","id":{"k":Infinity},"distro":{"v":NaN}}]'
        )
        self.assertEqual(items[0]["uuid"], "web")
        self.assertEqual(items[0]["distro"], "")
        _json(items)


class OverrideLeftoverFieldTests(unittest.TestCase):
    def test_yaml_inf_date_bytes_do_not_500_utm_listing(self):
        ov = {
            "name": float("inf"),
            "url": datetime.date(2026, 8, 19),
            "group": b"UTM",
        }
        with (
            mock.patch.object(vms_svc, "_utm_available", return_value=True),
            mock.patch.object(vms_svc, "sh", return_value=(0, UTM_LISTING, "")),
            mock.patch.object(vms_svc, "override", return_value=ov),
            mock.patch.object(vms_svc, "port_open", return_value=True),
        ):
            items = vms_svc._list_utm_vms_uncached()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["name"], "Ubuntu")
        self.assertEqual(items[0]["url"], "2026-08-19")
        self.assertEqual(items[0]["group"], "UTM")
        _json(items)

    def test_yaml_set_and_nan_do_not_500_utm_listing(self):
        ov = {"name": {"guest"}, "url": float("nan"), "group": datetime.datetime(2026, 1, 1)}
        with (
            mock.patch.object(vms_svc, "_utm_available", return_value=True),
            mock.patch.object(vms_svc, "sh", return_value=(0, UTM_LISTING, "")),
            mock.patch.object(vms_svc, "override", return_value=ov),
            mock.patch.object(vms_svc, "port_open", return_value=True),
        ):
            items = vms_svc._list_utm_vms_uncached()
        self.assertEqual(items[0]["name"], "Ubuntu")
        self.assertIsNone(items[0]["url"])
        self.assertEqual(items[0]["group"], "2026-01-01 00:00:00")
        _json(items)

    def test_huge_int_override_does_not_500_utm_listing(self):
        """A 400-digit leftover YAML int used to OverflowError ``float()``."""
        ov = {"name": 10 ** 400, "url": 10 ** 400, "group": 10 ** 400}
        with (
            mock.patch.object(vms_svc, "_utm_available", return_value=True),
            mock.patch.object(vms_svc, "sh", return_value=(0, UTM_LISTING, "")),
            mock.patch.object(vms_svc, "override", return_value=ov),
            mock.patch.object(vms_svc, "port_open", return_value=True),
        ):
            items = vms_svc._list_utm_vms_uncached()
        self.assertEqual(items[0]["name"], "Ubuntu")
        self.assertIsNone(items[0]["url"])
        self.assertEqual(items[0]["group"], "UTM")
        _json(items)


class ConsoleHostLeftoverTests(unittest.TestCase):
    def _allow(self, **entry):
        payload = {"enabled": True, "host": "127.0.0.1", "port": 5900}
        payload.update(entry)
        return {_UUID: payload}

    def test_huge_host_does_not_500_listing(self):
        """Leftover 10k host used to UnicodeError getaddrinfo during capability()."""
        allow = self._allow(host="a" * 10000)
        with (
            mock.patch.object(vms_svc, "_utm_available", return_value=True),
            mock.patch.object(vms_svc, "sh", return_value=(0, UTM_LISTING, "")),
            mock.patch.object(vms_svc, "override", return_value={}),
            mock.patch.object(vms_svc, "port_open", return_value=True),
            mock.patch.object(vm_console, "_allowlist", return_value=allow),
        ):
            items = vms_svc._list_utm_vms_uncached()
        self.assertEqual(len(items), 1)
        self.assertFalse(items[0]["console"]["available"])
        _json(items)

    def test_surrogate_host_is_not_configured(self):
        with mock.patch.object(
            vm_console, "_allowlist", return_value=self._allow(host="\udcff"),
        ):
            self.assertIsNone(vm_console.resolve_target(f"utm:{_UUID}"))

    def test_nul_truncated_loopback_is_refused(self):
        """``getaddrinfo('127.0.0.1\\x00')`` used to resolve as 127.0.0.1."""
        with mock.patch.object(
            vm_console, "_allowlist",
            return_value=self._allow(host="127.0.0.1\x00evil"),
        ):
            self.assertIsNone(vm_console.resolve_target(f"utm:{_UUID}"))

    def test_valid_loopback_still_resolves(self):
        with mock.patch.object(
            vm_console, "_allowlist", return_value=self._allow(),
        ):
            target = vm_console.resolve_target(f"utm:{_UUID}")
        self.assertIsNotNone(target)
        self.assertEqual(target.host, "127.0.0.1")
        self.assertEqual(target.port, 5900)

    def test_inf_port_does_not_500_listing(self):
        """YAML ``port: .inf`` used to OverflowError ``int(inf)`` in capability()."""
        allow = self._allow(port=float("inf"))
        with (
            mock.patch.object(vms_svc, "_utm_available", return_value=True),
            mock.patch.object(vms_svc, "sh", return_value=(0, UTM_LISTING, "")),
            mock.patch.object(vms_svc, "override", return_value={}),
            mock.patch.object(vms_svc, "port_open", return_value=True),
            mock.patch.object(vm_console, "_allowlist", return_value=allow),
        ):
            items = vms_svc._list_utm_vms_uncached()
        self.assertFalse(items[0]["console"]["available"])
        _json(items)

    def test_huge_int_port_does_not_500_listing(self):
        allow = self._allow(port=10 ** 400)
        with (
            mock.patch.object(vms_svc, "_utm_available", return_value=True),
            mock.patch.object(vms_svc, "sh", return_value=(0, UTM_LISTING, "")),
            mock.patch.object(vms_svc, "override", return_value={}),
            mock.patch.object(vms_svc, "port_open", return_value=True),
            mock.patch.object(vm_console, "_allowlist", return_value=allow),
        ):
            items = vms_svc._list_utm_vms_uncached()
        self.assertFalse(items[0]["console"]["available"])
        _json(items)

    def test_bytes_loopback_host_still_resolves(self):
        """YAML ``!!binary`` of ``127.0.0.1`` used to TypeError ``ord()`` on bytes."""
        with mock.patch.object(
            vm_console, "_allowlist",
            return_value=self._allow(host=b"127.0.0.1"),
        ):
            target = vm_console.resolve_target(f"utm:{_UUID}")
        self.assertIsNotNone(target)
        self.assertEqual(target.host, "127.0.0.1")
        self.assertTrue(vm_console._is_loopback(b"127.0.0.1"))

    def test_bytes_junk_and_huge_int_host_do_not_500(self):
        for host in (b"\xff\xfe", bytearray(b"\xff\xfe"), 10 ** 400, float("inf")):
            with mock.patch.object(
                vm_console, "_allowlist", return_value=self._allow(host=host),
            ):
                self.assertIsNone(vm_console.resolve_target(f"utm:{_UUID}"))
            self.assertFalse(vm_console._is_loopback(host))

    def test_surrogate_ticket_does_not_500_digest(self):
        """Strict UTF-8 of leftover ``\\ud800`` used to 500 ticket mint/burn."""
        self.assertIsNone(vm_console.consume_ticket(
            "\ud800",
            console_id=f"utm:{_UUID}",
            user="admin",
            session_token="\ud800",
        ))
        with mock.patch.object(
            vm_console, "_allowlist", return_value=self._allow(),
        ):
            target = vm_console.resolve_target(f"utm:{_UUID}")
        issued = vm_console.issue_ticket(
            target, user="admin", session_token="tok\ud800",
        )
        _json(issued)
        self.assertIn("ticket", issued)
        self.assertEqual(issued["expires_in"], vm_console.TICKET_TTL_SECONDS)

    def test_leftover_inf_clock_does_not_500_ticket(self):
        """Leftover ``time.time() = inf`` used to poison ticket expiry math."""
        with mock.patch.object(
            vm_console, "_allowlist", return_value=self._allow(),
        ):
            target = vm_console.resolve_target(f"utm:{_UUID}")
        with mock.patch.object(vm_console.time, "time", return_value=float("inf")):
            issued = vm_console.issue_ticket(target, user="admin", session_token="tok")
            _json(issued)
            self.assertTrue(vm_console.allow_ticket_request("admin-inf"))
            burned = vm_console.consume_ticket(
                issued["ticket"],
                console_id=target.console_id,
                user="admin",
                session_token="tok",
            )
        self.assertIsNotNone(burned)


class WebsocketHostLeftoverTests(unittest.TestCase):
    def test_leftover_host_types_do_not_500(self):
        origin = "https://panel.example"
        for host in (b"panel.example", bytearray(b"panel.example"), 10 ** 400, float("inf"), None):
            self.assertFalse(websocket_security.origin_allowed(origin, host))


class SurrogateNameLeftoverTests(unittest.TestCase):
    def test_leftover_surrogate_utm_name_does_not_500(self):
        """Leftover ``\\ud800`` in utmctl Name used to 500 GET /api/vms UTF-8."""
        listing = (
            "UUID                                 Status   Name\n"
            f"{_UUID} started  Ubuntu\ud800\n"
        )
        with (
            mock.patch.object(vms_svc, "_utm_available", return_value=True),
            mock.patch.object(vms_svc, "sh", return_value=(0, listing, "")),
            mock.patch.object(vms_svc, "override", return_value={
                "name": "Box\ud800",
                "group": "UTM\ud800",
                "url": "http://x\ud800",
            }),
            mock.patch.object(vms_svc, "port_open", return_value=True),
        ):
            items = vms_svc._list_utm_vms_uncached()
        self.assertEqual(len(items), 1)
        for key in ("id", "name", "group", "url", "status", "detail"):
            self.assertNotIn("\ud800", items[0][key] or "")
        _starlette(items)
        _starlette(vms_svc._jsonable({"vms": items}))

    def test_leftover_surrogate_orb_name_does_not_500(self):
        """Leftover ``\\ud800`` in orbctl JSON used to 500 GET /api/vms UTF-8."""
        payload = '[{"name":"web\\ud800","state":"running","id":"abc","distro":"ubuntu\\ud800"}]'
        with (
            mock.patch.object(vms_svc, "_orb_available", return_value=True),
            mock.patch.object(vms_svc, "sh", return_value=(0, payload, "")),
            mock.patch.object(vms_svc, "override", return_value={}),
        ):
            items = vms_svc._list_orb_machines_uncached()
        self.assertEqual(len(items), 1)
        for key in ("id", "name", "orb_name", "distro", "detail"):
            self.assertNotIn("\ud800", items[0][key] or "")
        _starlette(items)
        wrapped = vms_svc._jsonable({"vms": items, "\ud800": 1})
        self.assertNotIn("\ud800", wrapped)
        _starlette(wrapped)


class ListAllVmsLeftoverTests(unittest.TestCase):
    def test_raising_utm_listing_does_not_drop_orb(self):
        with (
            mock.patch.object(vms_svc, "list_utm_vms", side_effect=RuntimeError("utmctl")),
            mock.patch.object(vms_svc, "list_orb_machines", return_value=[{"id": "orb:web"}]),
            mock.patch.object(vms_svc, "_utm_available", return_value=True),
            mock.patch.object(vms_svc, "_orb_available", return_value=True),
        ):
            data = vms_svc.list_all_vms()
        self.assertEqual([v["id"] for v in data["vms"]], ["orb:web"])
        _json(data)

    def test_none_listing_does_not_500(self):
        with (
            mock.patch.object(vms_svc, "list_utm_vms", return_value=None),
            mock.patch.object(vms_svc, "list_orb_machines", return_value=[{"id": "orb:web"}]),
            mock.patch.object(vms_svc, "_utm_available", return_value=True),
            mock.patch.object(vms_svc, "_orb_available", return_value=True),
        ):
            data = vms_svc.list_all_vms()
        self.assertEqual([v["id"] for v in data["vms"]], ["orb:web"])
        _json(data)

    def test_leftover_inf_row_does_not_500_json(self):
        """Starlette allow_nan=False: leftover Infinity in a listing row used to 500."""
        with (
            mock.patch.object(
                vms_svc, "list_utm_vms",
                return_value=[{"id": "Ubuntu", "name": float("inf"), "state": "ok"}],
            ),
            mock.patch.object(vms_svc, "list_orb_machines", return_value=[]),
            mock.patch.object(vms_svc, "_utm_available", return_value=True),
            mock.patch.object(vms_svc, "_orb_available", return_value=False),
        ):
            data = vms_svc.list_all_vms()
        _json(data)
        self.assertIsNone(data["vms"][0]["name"])

    def test_none_listing_does_not_500_discover(self):
        with (
            mock.patch.object(vms_svc, "list_utm_vms", return_value=None),
            mock.patch.object(
                vms_svc, "list_orb_machines",
                return_value=[{"id": "orb:web", "name": float("inf"), "state": "ok"}],
            ),
        ):
            items = vms_svc.discover_vms()
        _json(items)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["id"], "orb:web")
        self.assertIsNone(items[0]["name"])

    def test_exists_eio_does_not_500_list_all_vms(self):
        """Dying-mount ``Path.exists()`` EIO used to 500 GET /api/vms."""
        with (
            mock.patch.object(vms_svc, "list_utm_vms", return_value=[]),
            mock.patch.object(vms_svc, "list_orb_machines", return_value=[]),
            mock.patch.object(Path, "exists", side_effect=OSError(5, "I/O error")),
        ):
            data = vms_svc.list_all_vms()
        self.assertFalse(data["utm_available"])
        self.assertFalse(data["orb_available"])
        _json(data)

    def test_exists_eio_is_coded_not_500_on_utm_action(self):
        with mock.patch.object(Path, "exists", side_effect=OSError(5, "I/O error")):
            with self.assertRaises(HTTPException) as ctx:
                vms_svc._utm_action("Ubuntu", "start")
        self.assertEqual(ctx.exception.status_code, 503)
        detail = ctx.exception.detail
        self.assertEqual(
            detail["code"] if isinstance(detail, dict) else detail,
            "vms.utm_unavailable",
        )


class ParseIdLeftoverTests(unittest.TestCase):
    def test_non_dict_orb_rows_do_not_500_utm_action(self):
        rows = [None, "web", {"orb_name": "alpha", "id": "alpha"}]
        with mock.patch.object(vms_svc, "list_orb_machines", return_value=rows):
            backend, ident = vms_svc._parse_id("Ubuntu")
        self.assertEqual(backend, "utm")
        self.assertEqual(ident, "Ubuntu")

    def test_raising_orb_listing_does_not_500_utm_parse(self):
        with mock.patch.object(
            vms_svc, "list_orb_machines", side_effect=RuntimeError("orbctl"),
        ):
            backend, ident = vms_svc._parse_id("Ubuntu")
        self.assertEqual(backend, "utm")
        self.assertEqual(ident, "Ubuntu")


class ActionNameLeftoverTests(unittest.TestCase):
    def test_inf_clone_name_is_coded_not_500(self):
        with (
            mock.patch.object(vms_svc, "_utm_available", return_value=True),
            mock.patch.object(vms_svc, "sh") as sh,
        ):
            with self.assertRaises(HTTPException) as ctx:
                vms_svc._utm_action("Ubuntu", "clone", name=float("inf"))
        self.assertEqual(ctx.exception.status_code, 400)
        sh.assert_not_called()

    def test_inf_create_name_is_coded_not_500(self):
        with (
            mock.patch.object(vms_svc, "_orb_available", return_value=True),
            mock.patch.object(vms_svc, "sh") as sh,
        ):
            with self.assertRaises(HTTPException) as ctx:
                vms_svc.create_orb_machine("ubuntu", name=float("inf"))
        self.assertEqual(ctx.exception.status_code, 400)
        sh.assert_not_called()

    def test_bytes_create_name_is_coded_not_500(self):
        with (
            mock.patch.object(vms_svc, "_orb_available", return_value=True),
            mock.patch.object(vms_svc, "sh") as sh,
        ):
            with self.assertRaises(HTTPException) as ctx:
                vms_svc.create_orb_machine("ubuntu", name=b"web")
        self.assertEqual(ctx.exception.status_code, 400)
        sh.assert_not_called()


class VmLogsJsonDumpsLeftoverTests(unittest.TestCase):
    def test_leftover_inf_does_not_500_vm_logs(self):
        """json.dumps of leftover Infinity used to 500 GET /api/apps/.../logs."""
        with mock.patch.object(apps_manage_svc, "_vm_detail", return_value={
            "name": "box",
            "load": float("inf"),
            "blob": b"hello",
            "when": datetime.date(2026, 8, 19),
        }):
            out = apps_manage_svc._vm_logs("box")
        self.assertTrue(out["ok"])
        self.assertNotIn("Infinity", out["log"])
        parsed = json.loads(out["log"])
        _json(parsed)
        self.assertEqual(parsed["blob"], "hello")
        self.assertIsNone(parsed["load"])


class VmsJsonableLeftoverTests(unittest.TestCase):
    def test_isoformat_inf_and_recursing_do_not_500(self):
        """A leftover ``isoformat()`` returning inf used to 500 GET /api/vms."""
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        class _Stamp:
            def isoformat(self):
                return float("inf")

        self.assertEqual(vms_svc._as_text(Recursing()), "Recursing")
        self.assertIsNone(vms_svc._jsonable(_Stamp()))
        out = vms_svc._jsonable({
            "when": _Stamp(),
            "name": datetime.date(2026, 8, 19),
            "blob": b"vm",
            "tags": {"utm"},
            "n": float("inf"),
        })
        _json(out)
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertIsNone(out["when"])
        self.assertEqual(out["name"], "2026-08-19")
        self.assertEqual(out["blob"], "vm")
        self.assertEqual(out["tags"], ["utm"])
        self.assertIsNone(out["n"])


if __name__ == "__main__":
    unittest.main()
