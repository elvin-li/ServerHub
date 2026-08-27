"""Ninth leftover-500s sweep of the VMs surfaces, over the real app.

vms8 sealed ``resolve_target``'s per-*value* coercion of an allowlist entry
(``__bool__`` / ``__eq__`` / ``__int__`` subclass bombs).  This sweep hunted
two vectors that zoo never carried, and both reproduced as live 500s against
``create_app()`` with ``raise_server_exceptions=False``:

* **``__class__``-property bombs.**  ``isinstance`` consults
  ``value.__class__`` when the exact-type check misses, so a leftover whose
  ``__class__`` is a *raising property* detonated the bare type gates
  themselves — one line ahead of every scrub built to absorb junk shapes.
  Planted as the allowlist map, an allowlist key, an entry, or an entry's
  protocol/host/port value, it 500'd POST /api/vms/{id}/console/session;
  planted as a listing return it detonated ``_listing_rows``'s gate
  *outside* its try (re-raised through ``fan_out`` — GET /api/vms 500'd
  with both inventories); planted as a row value or mapping key it
  detonated the final ``_jsonable`` pass (also a GET /api/vms 500); and
  planted as the ``list_orb_machines`` / ``list_utm_vms`` return it 500'd
  the action route via ``_parse_id`` and the console mint via
  ``utm_vm_running``.  The sibling modules' ``_isa`` guard
  (storage_pool/system/status/usage_svc) is the fix these two never got.

* **Hash-shadowing mapping-key bombs.**  The unbound ``dict.get`` reads in
  ``_parse_id`` / ``utm_vm_running`` / ``discover_vms`` bypass a subclass
  ``.get`` override, but the hash probe still runs the *stored keys'* own
  ``__eq__`` — and ``_entry_for`` / ``config.override`` launder with a
  ``dict(...)`` copy that *keeps* hostile keys.  A leftover str-subclass
  key whose hash shadows ``enabled`` / ``port`` / ``host`` / ``protocol``
  / ``view_only`` (allowlist entry) or ``uuid`` / ``orb_name`` (rows)
  and whose ``__eq__`` raises 500'd the mint and the action route.
  ``_mapping_get`` (the ups_svc/storage_pool rule) degrades only the
  shadowed field.

Two more seams fell to the same sweep: ``vm_console._allowlist`` re-raised
a cfg snapshot provider bomb out of ``settings_section`` (its try covers
only the ``cfg()`` call), and an int-subclass ``sh()`` return code whose
``__eq__`` / ``__ne__`` raises detonated ``_cli_missing`` and the
``ok``/``message`` assembly of the action reply (``_rc_int`` now reads the
real value through ``int.__index__``).  A raising ``config.override`` (or
a shadowed-key override) also used to cost the *whole* UTM/Orb inventory
via the ``_listing_rows`` catch; ``_override`` / ``_mapping_get`` now lose
only the poisoned row's override.

Already immune (pinned so they stay that way): ``enabled`` / ``view_only``
class-bombs read through ``_flag``'s guarded ``bool()`` (a plain object is
simply truthy), and a hash-shadowing key bomb riding a row into
``_jsonable`` (the unbound ``dict.items`` walk never runs a key's
``__eq__``, and ``_as_text`` hands back an exact str before insertion).
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import audit, auth, vm_console, vms_svc
from hub.app_factory import create_app
from hub.auth import require_auth

_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
UTM_LISTING = (
    "UUID                                 Status   Name\n"
    f"{_UUID} started  Ubuntu\n"
)

_app = None


def _client() -> TestClient:
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return TestClient(_app, raise_server_exceptions=False)


class _ClassBomb:
    """A leftover whose ``__class__`` is a raising property: the bare
    ``isinstance`` gate itself detonates instead of taking a branch."""

    @property
    def __class__(self):
        raise RuntimeError("leftover __class__ property bomb")


class _KeyBomb(str):
    """str-subclass mapping key: ``__hash__`` shadows the real key's slot,
    ``__eq__`` raises — so the ``dict.get`` probe itself detonates."""

    def __new__(cls, target: str):
        self = str.__new__(cls, "leftover-" + target)
        self._shadow = str.__hash__(target)
        return self

    def __hash__(self):
        return self._shadow

    def __eq__(self, other):
        raise RuntimeError("leftover key __eq__ bomb")

    __ne__ = __eq__


class _RcBomb(int):
    """int-subclass return code whose comparisons raise."""

    def __eq__(self, other):
        raise RuntimeError("leftover rc __eq__ bomb")

    __ne__ = __eq__
    __hash__ = int.__hash__


def _shadowed(base: dict, target: str) -> dict:
    """*base* with *target*'s entry re-keyed onto a hash-shadowing bomb."""
    out = {k: v for k, v in base.items() if k != target}
    out[_KeyBomb(target)] = base.get(target)
    return out


_ENTRY = {"enabled": True, "port": 5900, "host": "127.0.0.1", "protocol": "vnc"}


def _entry(**over) -> dict:
    return {"allowlist": {_UUID: dict(_ENTRY, **over)}}


class ResolveTargetClassBombTests(unittest.TestCase):
    """A ``__class__``-property bomb anywhere in the allowlist refuses or
    resolves — it can no longer raise out of the resolver."""

    def _resolve(self, section):
        with mock.patch.object(
            vm_console, "settings_section", lambda name: section
        ):
            return vm_console.resolve_target(f"utm:{_UUID}")

    def test_bombed_allowlist_map_reads_as_not_configured(self):
        self.assertIsNone(self._resolve({"allowlist": _ClassBomb()}))

    def test_bombed_allowlist_key_keeps_the_healthy_sibling_entry(self):
        section = {"allowlist": {_ClassBomb(): dict(_ENTRY),
                                 _UUID: dict(_ENTRY)}}
        target = self._resolve(section)
        self.assertIsNotNone(target)
        self.assertEqual(target.port, 5900)

    def test_bombed_entry_reads_as_not_configured(self):
        self.assertIsNone(self._resolve({"allowlist": {_UUID: _ClassBomb()}}))

    def test_bombed_protocol_host_port_each_refuse_not_raise(self):
        for field in ("protocol", "host", "port"):
            with self.subTest(field=field):
                self.assertIsNone(
                    self._resolve(_entry(**{field: _ClassBomb()}))
                )

    def test_raising_settings_section_reads_as_not_configured(self):
        def boom(name):
            raise RuntimeError("leftover cfg snapshot provider bomb")

        with mock.patch.object(vm_console, "settings_section", boom):
            self.assertIsNone(vm_console.resolve_target(f"utm:{_UUID}"))


class ResolveTargetKeyBombTests(unittest.TestCase):
    """A hash-shadowing key inside the laundered entry degrades only the
    shadowed field instead of raising out of the plain-dict ``get`` probe."""

    def _resolve(self, entry):
        section = {"allowlist": {_UUID: entry}}
        with mock.patch.object(
            vm_console, "settings_section", lambda name: section
        ):
            return vm_console.resolve_target(f"utm:{_UUID}")

    def test_shadowed_required_fields_refuse_not_raise(self):
        for field in ("enabled", "port"):
            with self.subTest(field=field):
                self.assertIsNone(
                    self._resolve(_shadowed(dict(_ENTRY), field))
                )

    def test_shadowed_optional_fields_take_their_absent_defaults(self):
        # host and protocol degrade to their absent-field defaults
        # (loopback / vnc); the healthy sibling fields keep the entry
        # resolving.
        target = self._resolve(_shadowed(dict(_ENTRY), "host"))
        self.assertIsNotNone(target)
        self.assertEqual(target.host, "127.0.0.1")
        target = self._resolve(_shadowed(dict(_ENTRY), "protocol"))
        self.assertIsNotNone(target)
        self.assertEqual(target.protocol, "vnc")

    def test_shadowed_view_only_degrades_to_false_and_still_resolves(self):
        target = self._resolve(
            _shadowed(dict(_ENTRY, view_only=True), "view_only")
        )
        self.assertIsNotNone(target)
        self.assertFalse(target.view_only)


class ConsoleMintNoLonger500sTests(unittest.TestCase):
    """POST /api/vms/{id}/console/session answers the coded 404 over every
    bomb class instead of a bare 500."""

    def _mint(self, section):
        client = _client()
        with mock.patch.object(auth, "browser_authenticated", return_value=True), \
             mock.patch.object(vm_console, "settings_section", lambda n: section):
            return client.post(f"/api/vms/utm:{_UUID}/console/session", json={})

    def _assert_coded_404(self, resp):
        self.assertEqual(resp.status_code, 404, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "vm_console.unavailable")

    def test_class_bombed_allowlist_levels_answer_coded_404(self):
        for label, section in {
            "allowlist": {"allowlist": _ClassBomb()},
            "entry": {"allowlist": {_UUID: _ClassBomb()}},
            "protocol": _entry(protocol=_ClassBomb()),
            "host": _entry(host=_ClassBomb()),
            "port": _entry(port=_ClassBomb()),
        }.items():
            with self.subTest(level=label):
                self._assert_coded_404(self._mint(section))

    def test_key_bombed_entry_answers_coded_404(self):
        self._assert_coded_404(
            self._mint({"allowlist": {_UUID: _shadowed(dict(_ENTRY), "port")}})
        )

    def test_raising_settings_section_answers_coded_404(self):
        def boom(name):
            raise RuntimeError("leftover cfg snapshot provider bomb")

        client = _client()
        with mock.patch.object(auth, "browser_authenticated", return_value=True), \
             mock.patch.object(vm_console, "settings_section", boom):
            resp = client.post(f"/api/vms/utm:{_UUID}/console/session", json={})
        self._assert_coded_404(resp)

    def test_bombed_utm_listing_in_running_recheck_answers_coded_404(self):
        # resolve succeeds off a healthy entry; the ``utm_vm_running``
        # re-check then meets a bombed listing return and must read it as
        # "not running", not raise out of the mint.
        client = _client()
        section = _entry()
        with mock.patch.object(auth, "browser_authenticated", return_value=True), \
             mock.patch.object(vm_console, "settings_section", lambda n: section), \
             mock.patch.object(vms_svc, "_utm_available", return_value=True), \
             mock.patch.object(vms_svc, "list_utm_vms", return_value=_ClassBomb()):
            resp = client.post(f"/api/vms/utm:{_UUID}/console/session", json={})
        self._assert_coded_404(resp)


class UtmVmRunningBombTests(unittest.TestCase):
    """The console mint's liveness probe survives poisoned listing rows."""

    def test_key_bombed_row_is_skipped_and_the_healthy_sibling_answers(self):
        rows = [
            _shadowed({"uuid": _UUID, "id": "Ubuntu"}, "uuid"),
            {"uuid": _UUID, "id": "Ubuntu"},
        ]
        with mock.patch.object(vms_svc, "_utm_available", return_value=True), \
             mock.patch.object(vms_svc, "list_utm_vms", return_value=rows), \
             mock.patch.object(vms_svc, "_utm_status", return_value="started"):
            self.assertTrue(vms_svc.utm_vm_running(_UUID))

    def test_class_bombed_listing_reads_as_not_running(self):
        with mock.patch.object(vms_svc, "_utm_available", return_value=True), \
             mock.patch.object(vms_svc, "list_utm_vms", return_value=_ClassBomb()):
            self.assertFalse(vms_svc.utm_vm_running(_UUID))


class VmsListingNoLonger500sTests(unittest.TestCase):
    """GET /api/vms answers 200 with the healthy inventory kept over every
    bomb class that used to 500 (or silently empty) it."""

    ORB_ROW = {
        "id": "orb:ubuntu", "uuid": "ubuntu", "name": "ubuntu",
        "orb_name": "ubuntu", "backend": "orb", "status": "running",
        "state": "ok", "detail": "OrbStack · running", "url": None,
        "group": "OrbStack Linux", "actions": ["stop"], "distro": "ubuntu",
        "ips": [], "console_id": None,
        "console": {"available": False, "protocol": None,
                    "reason": "vm_console.no_graphical_console"},
    }

    def setUp(self):
        self.client = _client()
        vms_svc.invalidate_vm_lists()
        self.addCleanup(vms_svc.invalidate_vm_lists)

    def _get(self, utm_ret, orb_ret=None):
        with mock.patch.object(vms_svc, "list_utm_vms", return_value=utm_ret), \
             mock.patch.object(vms_svc, "list_orb_machines",
                               return_value=orb_ret if orb_ret is not None
                               else [dict(self.ORB_ROW)]):
            resp = self.client.get("/api/vms")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        # The body must already be valid UTF-8 — decode strictly on purpose.
        resp.content.decode("utf-8")
        return resp.json()

    def test_class_bombed_listing_return_keeps_the_sibling_inventory(self):
        # Pre-fix: ``_listing_rows``'s bare gate detonated outside its try,
        # re-raised through fan_out, and 500'd GET /api/vms whole.
        body = self._get(_ClassBomb())
        self.assertEqual(body["utm_count"], 0)
        self.assertEqual(body["orb_count"], 1)
        self.assertIn("ubuntu", [v["name"] for v in body["vms"]])

    def test_class_bombed_row_value_degrades_only_that_field(self):
        body = self._get([{"name": "Ubuntu", "poison": _ClassBomb()}])
        row = next(v for v in body["vms"] if v.get("name") == "Ubuntu")
        self.assertIsNone(row["poison"])
        json.dumps(row, allow_nan=False)
        self.assertIn("ubuntu", [v.get("name") for v in body["vms"]])

    def test_class_bombed_mapping_key_degrades_to_its_repr_text(self):
        body = self._get([{_ClassBomb(): 1, "name": "Ubuntu"}])
        self.assertIn("Ubuntu", [v.get("name") for v in body["vms"]])

    def test_raising_override_read_keeps_every_utm_row(self):
        # config.override reads cfg() bare; a snapshot provider bomb used to
        # raise out of the per-row loop and cost the whole UTM inventory.
        def _sh(cmd, **kw):
            cmd = [str(c) for c in cmd]
            if cmd[1:2] == ["list"] and "utmctl" in cmd[0]:
                return (0, UTM_LISTING, "")
            return (0, "", "")

        with mock.patch.object(vms_svc, "_utm_available", return_value=True), \
             mock.patch.object(vms_svc, "_orb_available", return_value=False), \
             mock.patch.object(vms_svc, "UTMCTL", "/usr/local/bin/utmctl"), \
             mock.patch.object(vms_svc, "sh", side_effect=_sh), \
             mock.patch.object(audit, "record"), \
             mock.patch.object(vms_svc, "override",
                               side_effect=RuntimeError("leftover cfg bomb")):
            resp = self.client.get("/api/vms")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertEqual(body["utm_count"], 1)
        self.assertIn("Ubuntu", [v["name"] for v in body["vms"]])

    def test_key_bombed_override_degrades_only_the_shadowed_field(self):
        # The laundered dict(...) copy keeps hostile keys: a shadowed
        # ``hide`` used to detonate the bound get and cost every row; now
        # only that field degrades and the healthy ``name`` still applies.
        def _sh(cmd, **kw):
            cmd = [str(c) for c in cmd]
            if cmd[1:2] == ["list"] and "utmctl" in cmd[0]:
                return (0, UTM_LISTING, "")
            return (0, "", "")

        poisoned = _shadowed({"hide": False, "name": "Renamed"}, "hide")
        with mock.patch.object(vms_svc, "_utm_available", return_value=True), \
             mock.patch.object(vms_svc, "_orb_available", return_value=False), \
             mock.patch.object(vms_svc, "UTMCTL", "/usr/local/bin/utmctl"), \
             mock.patch.object(vms_svc, "sh", side_effect=_sh), \
             mock.patch.object(audit, "record"), \
             mock.patch.object(vms_svc, "override", return_value=poisoned):
            resp = self.client.get("/api/vms")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertEqual(body["utm_count"], 1)
        self.assertIn("Renamed", [v["name"] for v in body["vms"]])


class VmActionNoLonger500sTests(unittest.TestCase):
    """POST /api/vms/{id}/action answers coded errors / honest results over
    poisoned orb listings and rc-subclass return codes."""

    def setUp(self):
        self.client = _client()
        vms_svc.invalidate_vm_lists()
        self.addCleanup(vms_svc.invalidate_vm_lists)

    def test_class_bombed_orb_listing_in_parse_id_answers_coded_error(self):
        with mock.patch.object(vms_svc, "list_orb_machines",
                               return_value=_ClassBomb()), \
             mock.patch.object(audit, "record"):
            resp = self.client.post("/api/vms/somevm/action",
                                    json={"action": "status"})
        self.assertNotEqual(resp.status_code, 500, resp.text[:200])
        self.assertIn("code", resp.json()["detail"])

    def test_key_bombed_orb_row_in_parse_id_answers_coded_error(self):
        rows = [_shadowed({"orb_name": "x", "id": "orb:x"}, "orb_name")]
        with mock.patch.object(vms_svc, "list_orb_machines",
                               return_value=rows), \
             mock.patch.object(audit, "record"):
            resp = self.client.post("/api/vms/somevm/action",
                                    json={"action": "status"})
        self.assertNotEqual(resp.status_code, 500, resp.text[:200])
        self.assertIn("code", resp.json()["detail"])

    def test_rc_subclass_eq_bomb_answers_the_honest_action_result(self):
        # ``rc != -1`` in _cli_missing and the ``ok``/``message`` assembly
        # both ran the subclass's own comparison; _rc_int reads the real 0.
        with mock.patch.object(vms_svc, "_utm_available", return_value=True), \
             mock.patch.object(vms_svc, "list_orb_machines", return_value=[]), \
             mock.patch.object(vms_svc, "sh",
                               return_value=(_RcBomb(0), "started", "")), \
             mock.patch.object(audit, "record"):
            resp = self.client.post("/api/vms/Ubuntu/action",
                                    json={"action": "start"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertIs(body["ok"], True)
        self.assertEqual(body["message"], "started")


class DiscoverVmsBombTests(unittest.TestCase):
    """The status-feed projection skips the poisoned row / field and keeps
    the healthy sibling instead of raising the whole feed away."""

    def test_class_bombed_row_is_skipped_and_the_sibling_kept(self):
        rows = [_ClassBomb(), {"id": "u", "name": "u", "state": "ok",
                               "detail": "d", "group": "g", "backend": "utm"}]
        with mock.patch.object(vms_svc, "list_utm_vms", return_value=rows), \
             mock.patch.object(vms_svc, "list_orb_machines", return_value=[]):
            out = vms_svc.discover_vms()
        self.assertEqual([v["name"] for v in out], ["u"])
        json.dumps(out, allow_nan=False)

    def test_key_bombed_state_degrades_only_that_field(self):
        rows = [
            _shadowed({"id": "a", "name": "a", "state": "ok"}, "state"),
            {"id": "b", "name": "b", "state": "ok"},
        ]
        with mock.patch.object(vms_svc, "list_utm_vms", return_value=rows), \
             mock.patch.object(vms_svc, "list_orb_machines", return_value=[]):
            out = vms_svc.discover_vms()
        self.assertEqual([v["name"] for v in out], ["a", "b"])
        by_name = {v["name"]: v for v in out}
        self.assertIsNone(by_name["a"]["state"])
        self.assertEqual(by_name["b"]["state"], "ok")
        json.dumps(out, allow_nan=False)


class StaysImmunePins(unittest.TestCase):
    """Seams this sweep re-probed and found already hardened: pinned so a
    regression cannot ship silently."""

    def _resolve(self, section):
        with mock.patch.object(
            vm_console, "settings_section", lambda name: section
        ):
            return vm_console.resolve_target(f"utm:{_UUID}")

    def test_flag_reads_a_class_bomb_as_plain_truthiness(self):
        # ``bool()`` never consults ``__class__``, and ``_flag`` guards the
        # call anyway: enabled/view_only class-bombs already resolved.
        target = self._resolve(_entry(enabled=_ClassBomb()))
        self.assertIsNotNone(target)
        self.assertEqual(target.port, 5900)
        target = self._resolve(_entry(view_only=_ClassBomb()))
        self.assertIsNotNone(target)

    def test_jsonable_key_bomb_row_stays_immune_over_http(self):
        # dict.items never runs a stored key's __eq__, and _as_text hands
        # back an exact str before insertion — this never 500'd.
        client = _client()
        vms_svc.invalidate_vm_lists()
        self.addCleanup(vms_svc.invalidate_vm_lists)
        rows = [_shadowed({"name": "Ubuntu"}, "name")]
        with mock.patch.object(vms_svc, "list_utm_vms", return_value=rows), \
             mock.patch.object(vms_svc, "list_orb_machines", return_value=[]):
            resp = client.get("/api/vms")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        resp.content.decode("utf-8")
        self.assertEqual(resp.json()["utm_count"], 1)


class HelperUnitPins(unittest.TestCase):
    """Direct pins for the new guards."""

    def test_isa_survives_a_class_property_bomb(self):
        self.assertIs(vms_svc._isa(_ClassBomb(), dict), False)
        self.assertIs(vms_svc._isa({}, dict), True)
        self.assertIs(vm_console._isa(_ClassBomb(), str), False)
        self.assertIs(vm_console._isa("x", str), True)

    def test_mapping_get_survives_both_bomb_classes(self):
        self.assertIsNone(vms_svc._mapping_get(_ClassBomb(), "x"))
        self.assertIsNone(
            vms_svc._mapping_get(_shadowed({"name": "u"}, "name"), "name")
        )
        self.assertEqual(vms_svc._mapping_get({"name": "u"}, "name"), "u")
        self.assertIsNone(
            vm_console._mapping_get(_shadowed(dict(_ENTRY), "port"), "port")
        )
        self.assertEqual(vm_console._mapping_get(dict(_ENTRY), "port"), 5900)

    def test_rc_int_reads_the_real_value_under_a_subclass_bomb(self):
        self.assertEqual(vms_svc._rc_int(_RcBomb(0)), 0)
        self.assertEqual(vms_svc._rc_int(_RcBomb(-1)), -1)
        self.assertEqual(vms_svc._rc_int(7), 7)
        # vms10 moved junk off the forgeable ``-1`` spawn sentinel: an
        # unreadable rc now degrades to -255 (still nonzero, still a
        # failure) so it can never satisfy the vanished-CLI classifier.
        self.assertEqual(vms_svc._rc_int("junk"), -255)
        self.assertEqual(vms_svc._rc_int(_ClassBomb()), -255)

    def test_cli_missing_still_requires_the_disk_confirm(self):
        # The vanished-CLI 503 stays gated on the disk re-check: a bombed
        # rc alone (or the sentinel with the binary still present) never
        # classifies as missing.
        self.assertFalse(vms_svc._cli_missing(_RcBomb(0), "not found", None))
        with mock.patch.object(vms_svc, "_bin_present", return_value=True):
            self.assertFalse(vms_svc._cli_missing(-1, "not found", "/x"))
        with mock.patch.object(vms_svc, "_bin_present", return_value=False):
            self.assertTrue(vms_svc._cli_missing(-1, "not found", "/x"))

    def test_override_guard_degrades_a_raising_read_to_empty(self):
        with mock.patch.object(vms_svc, "override",
                               side_effect=RuntimeError("boom")):
            self.assertEqual(vms_svc._override("x"), {})
        with mock.patch.object(vms_svc, "override",
                               return_value={"name": "n"}):
            self.assertEqual(vms_svc._override("x"), {"name": "n"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
