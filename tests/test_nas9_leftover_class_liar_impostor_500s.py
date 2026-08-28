"""Ninth leftover-500s sweep of the NAS / shares-adjacent surfaces.

nas8 taught every NAS gate to survive a ``__class__`` that *raises*
(``_isa``).  This hunt found the impostor one step past that fix — the
modules9 / account9 class: a leftover whose ``__class__`` property *answers
the claimed type* while the real type is something else entirely.
``isinstance`` honours the lie, so the impostor sails through every
``_isa`` gate and then detonates the read the gate was guarding:

* the unbound base descriptors (``dict.items`` / ``dict.get`` /
  ``list.__iter__`` / ``bytes.decode``) are bound to the real C-level
  layout and reject the foreign operand with a TypeError outside any try;
* the bound reads (``.get`` / ``.decode`` / ``.encode``) do not even exist
  on the impostor and AttributeError the same way;
* a **bool-liar** needs no call at all: ``bool`` is final, so the old
  ``_isa(value, bool)`` arms returned it raw and Starlette's
  ``allow_nan=False`` encoder 500'd the response one layer down.

Each of these was a live raw HTTP 500 (traceback, no JSON body) on the
mounted app pre-fix:

* a liar nested in any NAS read payload blew ``nas_common._jsonable``
  (bool-liar at the encoder, dict-liar at ``dict.items``, bytes-liar at
  the unbound decode) — GET /api/nfs, /api/raid, /api/snapshots,
  /api/smart and /api/storage/usage at once, and every mutation ok body
  through the funnels;
* a bytes-liar error/message field blew ``_as_text`` in nfs / snapshots /
  usage / shares (bound ``.decode`` or the unbound descriptor) inside the
  very failure funnels built to answer coded;
* ``snapshots_svc.list_snapshots`` / ``time_machine_overview`` blew their
  bound ``.get`` reads and loop headers on liar plist shapes — a raw 500
  on GET /api/snapshots through fan_out;
* ``smart_test_svc._schedule_cfg``'s unbound ``dict.get`` blew on a
  dict-liar cfg (GET /api/smart, and the same raise escaped
  ``schedule_due()`` inside the scheduler tick), ``get_schedule`` /
  ``set_schedule`` blew ``list.__iter__`` on liar device tables, and
  ``start_test``'s message read blew after the operator had already typed
  the admin password;
* ``raid_svc``'s fresh enumerations (``list_sets`` / ``disk_topology`` /
  ``candidate_devices``) blew their bound ``.get`` reads on liar plist
  rows — raw 500s on every POST /api/raid/* through ``_resolve_set`` /
  ``_check_devices``, outside the ``_listing`` guard that protects the
  read page;
* ``usage_svc.set_spotlight`` blew ``base.__iter__`` on a list-liar
  status listing and ``dict.get`` on a dict-liar row, one line ahead of
  the coded ``bad_volume`` refusal;
* ``nfs_svc._validate_entry`` blew ``re.split`` on a str-liar client
  table past the router's NfsConfigError catch, and ``save_exports`` blew
  the unbound iterator selection on a list-liar table.

The fix is the modules9 rule applied across the NAS surfaces: every
unbound base call runs in a try (a raise means "not really this type", so
the impostor drops or falls through to the text probe), row walks launder
through plain-dict copies (``dict()`` reads the C-level storage, so a
genuine subclass keeps its salvageable rows), and the bool arms render
only ``type(value) is bool``.  The vanished-CLI 503s still fire only
after their fresh disk probes.
"""
from __future__ import annotations

import json
import sys
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import macos_admin, nfs_svc, raid_svc, smart_test_svc, snapshots_svc, usage_svc  # noqa: E402
from hub import shares_svc  # noqa: E402
from hub.routers import nas_common  # noqa: E402

_APP = None


def _client():
    global _APP
    from fastapi.testclient import TestClient

    if _APP is None:
        from hub.app_factory import create_app
        from hub.auth import require_auth

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _liar(kind):
    """A leftover whose ``__class__`` property *answers* ``kind``.

    The real type stays a plain object, so every ``isinstance`` gate
    matches through the lie while every base descriptor and bound method
    of ``kind`` rejects (or lacks) the operand — the exact shape the nas8
    raising-``__class__`` bombs could not reach.
    """

    class _Impostor:
        @property
        def __class__(self):
            return kind

    return _Impostor()


def _admin_browser(stack: ExitStack) -> None:
    """An administrator browser session, as the NAS routers resolve one."""
    stack.enter_context(mock.patch.object(
        nas_common.auth, "browser_authenticated", return_value=True))
    stack.enter_context(mock.patch.object(
        nas_common.auth, "request_username", return_value="admin"))
    stack.enter_context(mock.patch.object(
        nas_common.auth, "is_admin", return_value=True))
    stack.enter_context(mock.patch.object(
        nas_common.auth, "request_client_id", return_value="127.0.0.1"))


class ReadRoutesLiarTests(unittest.TestCase):
    """A liar nested in any NAS read payload must render degraded.

    Pre-fix the bool-liar rode ``_jsonable``'s first arm raw into the
    ``allow_nan=False`` encoder, the bytes-liar blew the unbound decode
    and the dict-liar blew ``dict.items`` — each a raw 500 on all five
    read pages while every sibling field was droppable collateral.
    """

    def test_liar_values_degrade_and_siblings_survive(self):
        for kind in (bool, bytes, dict, list):
            payload = {"server": {"detail": _liar(kind)}, "count": 3, "rows": ["ok"]}
            for label, module, route in (
                ("nfs", nfs_svc, "/api/nfs"),
                ("raid", raid_svc, "/api/raid"),
                ("snapshots", snapshots_svc, "/api/snapshots"),
                ("smart", smart_test_svc, "/api/smart"),
                ("usage", usage_svc, "/api/storage/usage"),
            ):
                with self.subTest(route=label, liar=kind.__name__):
                    with mock.patch.object(
                        module, "overview", lambda force=False, p=payload: p
                    ):
                        resp = _client().get(route)
                    self.assertEqual(resp.status_code, 200, resp.text[:200])
                    body = resp.json()
                    _starlette(body)
                    self.assertIsNone(body["server"]["detail"])
                    self.assertEqual(body["count"], 3)
                    self.assertEqual(body["rows"], ["ok"])

    def test_liar_element_in_a_list_keeps_its_siblings(self):
        # Pre-fix the sequence walk died mid-iteration on the impostor's
        # raise and silently dropped every element after it.
        cleaned = nas_common._jsonable({"entries": [_liar(bytes), "real"]})
        _starlette(cleaned)
        self.assertEqual(cleaned["entries"], [None, "real"])

    def test_liar_payload_at_top_rank_drops_whole(self):
        for kind in (bool, bytes, dict, list):
            with self.subTest(liar=kind.__name__):
                self.assertIsNone(nas_common._jsonable(_liar(kind)))

    def test_genuine_bool_and_subclass_rows_still_render(self):
        # The type-is-bool gate must not weaken the real arms: genuine
        # bools render, and a genuine dict subclass still walks through
        # the unbound items view.
        class _ItemsBombDict(dict):
            def items(self):
                raise ValueError("items bomb")

        cleaned = nas_common._jsonable(
            {"flag": True, "row": _ItemsBombDict({"keep": 1})}
        )
        _starlette(cleaned)
        self.assertIs(cleaned["flag"], True)
        self.assertEqual(cleaned["row"], {"keep": 1})

    def test_utf8_text_bytes_liar_falls_through_to_the_str_probe(self):
        # A *legible* impostor error string (one that carries its own
        # ``__str__``) still renders instead of costing the funnel that
        # carries it.  nas14 update (the maint14 address-belt rule): the
        # bare ``_liar(bytes)`` plain object used to pass this probe by
        # rendering its default ``object.__repr__`` — ``<X object at
        # 0x7f...>``, a raw heap address — verbatim into the funnel body;
        # that shape now scrubs to "" while real text keeps rendering.
        class _LegibleImpostor:
            @property
            def __class__(self):
                return bytes

            def __str__(self):
                return "still-renderable"

        text = nas_common._utf8_text(_LegibleImpostor())
        self.assertEqual(text, "still-renderable")
        scrubbed = nas_common._utf8_text(_liar(bytes))
        self.assertEqual(scrubbed, "")


class MutationFunnelLiarTests(unittest.TestCase):
    """Liar fields in privileged results answer coded, never raw."""

    def test_nfs_ok_body_bool_liar_degrades(self):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                nfs_svc, "server_action",
                return_value={"ok": True, "info": _liar(bool)}))
            resp = _client().post("/api/nfs/server", json={"action": "start"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertIs(payload["ok"], True)
        self.assertIsNone(payload["info"])

    def test_nfs_failed_body_bytes_liar_error_answers_coded(self):
        # Pre-fix the funnel's own _utf8_text read blew the unbound decode
        # while building the refusal.
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                nfs_svc, "server_action",
                return_value={"ok": False, "error": _liar(bytes)}))
            resp = _client().post("/api/nfs/server", json={"action": "start"})
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["detail"]["code"], "admin.failed")

    def test_timemachine_ok_body_dict_liar_degrades(self):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                snapshots_svc, "run_admin",
                return_value={"ok": True, "info": _liar(dict)}))
            resp = _client().post(
                "/api/timemachine/action", json={"action": "start"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertIs(payload["ok"], True)
        self.assertIsNone(payload["info"])

    def test_spotlight_liar_status_rows_keep_the_boot_volume_toggleable(self):
        # A dict-liar row (or a list-liar listing) used to 500 the route
        # one line ahead of the coded bad_volume refusal; "/" is pinned.
        for listing in ([_liar(dict)], _liar(list)):
            with self.subTest(listing=type(listing).__name__):
                with ExitStack() as stack:
                    _admin_browser(stack)
                    stack.enter_context(mock.patch.object(
                        usage_svc, "spotlight_status", return_value=listing))
                    stack.enter_context(mock.patch.object(
                        macos_admin, "run_admin", return_value={"ok": True}))
                    resp = _client().post(
                        "/api/storage/spotlight",
                        json={"volume": "/", "enabled": True})
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                payload = resp.json()
                _starlette(payload)
                self.assertIs(payload["ok"], True)

    def test_smart_test_dict_liar_admin_result_answers_coded(self):
        caps = {
            "readable": True, "available": True, "supported": ["short"],
            "reason": "", "device_type": "auto", "estimated_minutes": {},
            "detail": "",
        }
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_device_nodes", return_value=["/dev/disk0"]))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "device_type", return_value=()))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_capabilities", return_value=caps))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "sh", return_value=(1, "", "denied")))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "run_admin", return_value=_liar(dict)))
            resp = _client().post(
                "/api/smart/test", json={"device": "/dev/disk0", "kind": "short"})
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["detail"]["code"], "admin.failed")


class SnapshotsLiarTests(unittest.TestCase):
    def test_liar_snapshot_table_and_rows_drop_while_siblings_render(self):
        real_row = {
            "SnapshotName": "com.apple.TimeMachine.2026-08-03-160000.local",
            "SnapshotUUID": "u", "SnapshotXID": 5, "Purgeable": True,
        }
        for label, plist, expected in (
            ("list-liar table", {"Snapshots": _liar(list)}, 0),
            ("dict-liar plist", _liar(dict), 0),
            ("dict-liar row keeps sibling", {"Snapshots": [_liar(dict), real_row]}, 1),
        ):
            with self.subTest(shape=label):
                snapshots_svc.invalidate()
                try:
                    with ExitStack() as stack:
                        stack.enter_context(mock.patch.object(
                            snapshots_svc, "_plist", return_value=plist))
                        stack.enter_context(mock.patch.object(
                            snapshots_svc, "snapshot_mounts", return_value=["/"]))
                        stack.enter_context(mock.patch.object(
                            snapshots_svc, "_tm_latest_backup", return_value=""))
                        resp = _client().get("/api/snapshots?force=1")
                finally:
                    snapshots_svc.invalidate()
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                payload = resp.json()
                _starlette(payload)
                self.assertEqual(payload["volumes"][0]["mount"], "/")
                self.assertEqual(payload["volumes"][0]["count"], expected)

    def test_liar_time_machine_answers_render_unconfigured(self):
        snapshots_svc.invalidate()
        try:
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(
                    snapshots_svc, "_tm_destinations", return_value=_liar(dict)))
                stack.enter_context(mock.patch.object(
                    snapshots_svc, "_tm_status", return_value=_liar(dict)))
                stack.enter_context(mock.patch.object(
                    snapshots_svc, "_tm_latest_backup", return_value=""))
                stack.enter_context(mock.patch.object(
                    snapshots_svc, "snapshot_mounts", return_value=["/"]))
                stack.enter_context(mock.patch.object(
                    snapshots_svc, "list_snapshots", return_value=[]))
                resp = _client().get("/api/snapshots?force=1")
        finally:
            snapshots_svc.invalidate()
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertIs(payload["time_machine"]["configured"], False)

    def test_liar_destination_row_drops_and_real_sibling_survives(self):
        real = {"ID": "d1", "Name": "Backups", "Kind": "Network", "URL": ""}
        tm = snapshots_svc.time_machine_overview.__wrapped__ if hasattr(
            snapshots_svc.time_machine_overview, "__wrapped__"
        ) else snapshots_svc.time_machine_overview
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                snapshots_svc, "_tm_destinations",
                return_value={"Destinations": [_liar(dict), real]}))
            stack.enter_context(mock.patch.object(
                snapshots_svc, "_tm_status", return_value={}))
            stack.enter_context(mock.patch.object(
                snapshots_svc, "_tm_latest_backup", return_value=""))
            overview = tm()
        _starlette(overview)
        self.assertEqual(len(overview["destinations"]), 1)
        self.assertEqual(overview["destinations"][0]["name"], "Backups")

    def test_text_and_jsonable_contracts(self):
        self.assertIsInstance(snapshots_svc._as_text(_liar(bytes)), str)
        self.assertIsNone(snapshots_svc._jsonable(_liar(bool)))
        self.assertIsNone(snapshots_svc._jsonable(_liar(bytes)))
        # A genuine bool still renders through the type-is gate.
        self.assertIs(snapshots_svc._jsonable(True), True)


class SmartLiarTests(unittest.TestCase):
    def test_dict_liar_cfg_falls_back_to_the_default_schedule(self):
        smart_test_svc.invalidate()
        try:
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(
                    smart_test_svc, "cfg", return_value=_liar(dict)))
                stack.enter_context(mock.patch.object(
                    smart_test_svc, "_device_nodes", return_value=[]))
                stack.enter_context(mock.patch.object(
                    smart_test_svc, "passwordless_available", return_value=False))
                stack.enter_context(mock.patch.object(
                    smart_test_svc, "_load_history", return_value=[]))
                resp = _client().get("/api/smart?force=1")
        finally:
            smart_test_svc.invalidate()
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["schedule"]["interval"], "off")

    def test_list_liar_devices_read_as_none_scheduled(self):
        # The same raise used to escape schedule_due() inside the scheduler
        # tick, silently stopping every scheduled self-test.
        with mock.patch.object(
            smart_test_svc, "_schedule_cfg",
            return_value={"interval": "daily", "devices": _liar(list)},
        ):
            self.assertEqual(smart_test_svc.get_schedule()["devices"], [])
            self.assertIs(smart_test_svc.schedule_due(), False)

    def test_set_schedule_list_liar_devices_earn_the_empty_table(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_known_nodes", return_value={"/dev/disk0"}))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "update_settings"))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "_schedule_cfg", return_value={}))
            result = smart_test_svc.set_schedule(
                interval="daily", kind="short", devices=_liar(list))
        self.assertIs(result["ok"], True)
        self.assertEqual(result["schedule"]["devices"], [])

    def test_list_liar_history_document_reads_as_empty(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                smart_test_svc, "read_text_capped", return_value="[]"))
            stack.enter_context(mock.patch.object(
                smart_test_svc, "safe_json_loads", return_value=_liar(list)))
            resp = _client().get("/api/smart/history")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["history"], [])

    def test_text_contracts(self):
        self.assertIsInstance(smart_test_svc._as_text(_liar(bytes)), str)
        self.assertEqual(smart_test_svc._schedule_text(_liar(bytes)), "")
        self.assertIsNone(smart_test_svc._jsonable(_liar(bool)))
        self.assertIsNone(smart_test_svc._decode_bytes(_liar(bytes)))
        # A genuine bytes subclass still decodes through the base descriptor.
        class _DecodeBomb(bytes):
            def decode(self, *a, **k):
                raise ValueError("decode bomb")

        self.assertEqual(smart_test_svc._decode_bytes(_DecodeBomb(b"ok")), "ok")


class RaidLiarTests(unittest.TestCase):
    """Liar plist shapes on the mutation path answer coded, never raw."""

    _REAL_SET = {
        "AppleRAIDSetUUID": "AAAAAAAA-0000-1111-2222-333333333333",
        "Name": "Media",
        "Level": "Mirror",
        "Status": "Online",
        "AppleRAIDMembers": [],
        "Size": 1024,
        "AppleRAIDSetDeviceNode": "/dev/disk9",
    }

    def test_liar_plist_shapes_earn_the_coded_not_found(self):
        for label, plist in (
            ("dict-liar document", _liar(dict)),
            ("list-liar table", {"AppleRAIDSets": _liar(list)}),
            ("dict-liar row", {"AppleRAIDSets": [_liar(dict)]}),
        ):
            with self.subTest(shape=label):
                with ExitStack() as stack:
                    _admin_browser(stack)
                    stack.enter_context(mock.patch.object(
                        raid_svc, "_plist", return_value=plist))
                    resp = _client().post("/api/raid/delete", json={
                        "set_uuid": "0" * 12,
                        "confirm": True,
                        "confirm_phrase": "x",
                    })
                self.assertEqual(resp.status_code, 404, resp.text[:200])
                payload = resp.json()
                _starlette(payload)
                self.assertEqual(payload["detail"]["code"], "raid.set_not_found")

    def test_liar_row_drops_and_the_real_sibling_set_still_resolves(self):
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                raid_svc, "_plist",
                return_value={"AppleRAIDSets": [_liar(dict), dict(self._REAL_SET)]}))
            stack.enter_context(mock.patch.object(
                raid_svc, "run_admin", return_value={"ok": True}))
            resp = _client().post("/api/raid/delete", json={
                "set_uuid": self._REAL_SET["AppleRAIDSetUUID"],
                "confirm": True,
                "confirm_phrase": "Media",
            })
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertIs(payload["ok"], True)

    def test_launder_helpers_and_text_contracts(self):
        self.assertIsNone(raid_svc._plain_map(_liar(dict)))
        self.assertEqual(raid_svc._row_list(_liar(list)), [])
        self.assertEqual(raid_svc._ident(_liar(bytes)), "")
        self.assertEqual(raid_svc._ident(_liar(str)), "")
        self.assertIsNone(raid_svc._jsonable(_liar(bool)))
        self.assertIsNone(raid_svc._jsonable(_liar(dict)))
        self.assertIsNone(raid_svc._jsonable(_liar(bytes)))
        # _req_text keeps the str() probe: a legible impostor argument
        # still earns the coded refusal path instead of raising.
        self.assertIsInstance(raid_svc._req_text(_liar(bytes)), str)

    def test_genuine_subclass_rows_still_salvage(self):
        # dict() copies the C-level storage, so the row-bomb guards keep
        # their salvage semantics through the new laundering.
        class _GetBombDict(dict):
            def get(self, *a, **k):
                raise ValueError("get bomb")

        class _IterBombList(list):
            def __iter__(self):
                raise ValueError("iter bomb")

        self.assertEqual(
            raid_svc._plain_map(_GetBombDict({"ok": True})), {"ok": True})
        self.assertEqual(raid_svc._row_list(_IterBombList([1, 2])), [1, 2])


class NfsLiarTests(unittest.TestCase):
    def test_str_liar_client_table_earns_the_coded_refusal(self):
        # Pre-fix re.split's TypeError raised raw past the router's
        # NfsConfigError catch.
        entry = {"path": str(Path.home()), "clients": _liar(str)}
        with self.assertRaises(nfs_svc.NfsConfigError) as ctx:
            nfs_svc._validate_entry(entry)
        self.assertEqual(ctx.exception.code, "nfs.no_clients")

    def test_list_liar_export_table_validates_as_empty(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                nfs_svc, "run_admin_sequence", return_value={"ok": True}))
            stack.enter_context(mock.patch.object(
                nfs_svc, "check_exports", return_value={"ok": True, "detail": ""}))
            result = nfs_svc.save_exports(_liar(list))
        self.assertIs(result["ok"], True)
        self.assertEqual(result["count"], 0)

    def test_dict_liar_classify_input_answers_the_generic_failure(self):
        self.assertEqual(
            nfs_svc._classify_admin_failure(_liar(dict)),
            {"ok": False, "error": "failed"})

    def test_text_contract(self):
        self.assertIsInstance(nfs_svc._as_text(_liar(bytes)), str)


class SharesLiarTests(unittest.TestCase):
    def test_bytes_liar_failure_message_keeps_the_coded_refusal(self):
        # Pre-fix _admin_failure's message read blew shares_svc._as_text's
        # bound decode while building the coded refusal — a raw 500 on
        # PUT /api/shares/smb after the operator typed the password.
        existing = {"time_machine": False, "tm_quota_gb": None}
        with ExitStack() as stack:
            _admin_browser(stack)
            stack.enter_context(mock.patch.object(
                shares_svc, "_find_share", return_value=existing))
            stack.enter_context(mock.patch.object(
                shares_svc, "run_admin_sequence",
                return_value={"ok": False, "error": "failed", "message": _liar(bytes)}))
            resp = _client().put("/api/shares/smb/Media", json={"smb_name": "Media"})
        self.assertEqual(resp.status_code, 500, resp.text[:200])
        payload = resp.json()
        _starlette(payload)
        self.assertEqual(payload["detail"]["code"], "shares.authorization_failed")

    def test_liar_time_machine_records_cost_only_the_tm_columns(self):
        row = {
            "record_name": "Media", "name": "Media", "path": "/tmp",
            "smb_name": "Media", "shared": True, "guest": False,
            "readonly": False, "encrypted": False,
        }
        for label, records in (
            ("dict-liar table", _liar(dict)),
            ("dict-liar record", {"Media": _liar(dict)}),
        ):
            with self.subTest(shape=label):
                with ExitStack() as stack:
                    stack.enter_context(mock.patch.object(
                        shares_svc, "sh", return_value=(0, "{}", "")))
                    stack.enter_context(mock.patch.object(
                        shares_svc, "_json_shares", return_value=[dict(row)]))
                    stack.enter_context(mock.patch.object(
                        shares_svc, "time_machine_records", return_value=records))
                    shares = shares_svc.list_smb_shares(include_sizes=False)
                self.assertEqual(len(shares), 1)
                self.assertIs(shares[0]["time_machine"], False)
                self.assertIsNone(shares[0]["tm_quota_gb"])

    def test_text_contract(self):
        self.assertIsInstance(shares_svc._as_text(_liar(bytes)), str)


class VanishedCliPinsStayTests(unittest.TestCase):
    """The confirmed-vanish 503s still require their fresh disk probes."""

    def test_nfsd_vanish_still_answers_503_only_after_disk_confirm(self):
        failure = {
            "ok": False, "error": "failed",
            "message": "sh: /sbin/nfsd: command not found",
        }
        for on_disk, status, code in (
            (False, 503, "nfs.nfsd_missing"),
            (True, 500, "admin.failed"),
        ):
            with self.subTest(nfsd_on_disk=on_disk):
                with ExitStack() as stack:
                    _admin_browser(stack)
                    stack.enter_context(mock.patch.object(
                        nfs_svc, "run_admin_sequence", return_value=dict(failure)))
                    stack.enter_context(mock.patch.object(
                        nfs_svc, "_nfsd_on_disk", return_value=on_disk))
                    resp = _client().post(
                        "/api/nfs/server", json={"action": "stop"})
                self.assertEqual(resp.status_code, status, resp.text[:200])
                payload = resp.json()
                _starlette(payload)
                self.assertEqual(payload["detail"]["code"], code)

    def test_mdutil_vanish_classification_survives_the_new_walk_guards(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                usage_svc, "spotlight_status", return_value=[_liar(dict)]))
            stack.enter_context(mock.patch.object(
                macos_admin, "run_admin",
                return_value={"ok": False, "error": "failed",
                              "message": "mdutil: command not found"}))
            stack.enter_context(mock.patch.object(
                usage_svc, "_mdutil_on_disk", return_value=False))
            result = usage_svc.set_spotlight("/", True)
        self.assertEqual(result, {"ok": False, "error": "mdutil_missing"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
