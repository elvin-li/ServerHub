"""Tenth leftover-500s sweep of the VMs surfaces, over the real app.

vms9 sealed the ``__class__``-*property* bombs (a gate that cannot answer
what it is) and the hash-shadowing mapping keys.  This sweep hunted the
wave-10 vectors the zoo never carried — objects that *lie* about their
class instead of refusing to answer — and each reproduced as a live 500
against ``create_app()`` with ``raise_server_exceptions=False``:

* **Lying ``__class__`` impostors.**  An object whose ``__class__``
  property answers a real builtin (bytes/str/dict/list/tuple/bool) passes
  every ``_isa`` gate, then detonates the *unbound* base descriptor that
  gate guards — a TypeError one line past the check, outside any try.
  A bytes-liar or str-liar in an ``sh`` slot blew ``_as_text``'s unbound
  decode/encode (raw 500 on POST /api/vms/{id}/action, a lost inventory
  on GET /api/vms); a dict-liar / list-liar / bytes-liar row value blew
  the final ``_jsonable`` pass (raw 500 on GET /api/vms); a str-liar
  ``uuid`` blew the console mint's liveness walk; a str-liar ``orb_name``
  beside a healthy matching ``id`` blew ``_parse_id`` on the action.

* **Bool-liars.**  ``bool`` admits no subclass, so ``_isa(value, bool)``
  can only pass for a *liar* — which ``_jsonable`` then returned raw into
  the response encoder: a raw 500 on GET /api/vms one layer past the
  scrub.  The gate is now ``type(value) is bool``.

* **Sequence-unwrap bombs.**  ``rc, out, err = sh(...)`` dispatched into
  the answer's own iteration: a list-subclass whose bound ``__iter__``
  raises — or a lying tuple impostor over no sequence storage — 500'd
  every spawning action and threw whole inventories away through the
  ``_listing_rows`` catch.  ``_sh3`` reads the real C-level storage
  (honest answers in subclass wrappers survive) and degrades junk to
  ``(-255, "", "")``.

* **rc forgery of the vanished-CLI 503.**  Junk rc used to read as ``-1``
  — exactly the ``sh`` spawn-failure *sentinel* — so a poisoned rc beside
  a leftover ``not found`` stderr and a vanished binary minted the coded
  503 out of a junk object.  ``_rc_int`` now degrades junk (and over-cap
  >4300-digit exact ints) to ``-255``, which no honest exit and no
  sentinel ever equals; the 503 still requires the real sentinel *and*
  the disk confirm.

Two degrade regressions fell to the same sweep: a leftover override
``port`` whose ``__bool__`` raises detonated inside the probe fan-out and
cost the whole UTM inventory (now one row's probe), and the rename action
still read ``config.override`` bare with bare truthiness — a cfg snapshot
provider bomb 500'd POST /api/vms/{id}/action rename (now the guarded
``_override``), while a raising ``set_override`` answered a raw 500
instead of the coded ``settings.save_failed`` 503.

Already immune (pinned): nested dict-subclass rows inside the final
``_jsonable`` pass (unbound reads recurse), ``isoformat`` property bombs,
>4300-digit JSON number literals in ``orbctl list -f json``
(``json.loads`` raises ValueError for the whole document past the digit
cap; the ``parse_int`` hook drops just the field), and self-``__str__``
str-subclass encode bombs.
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


class _Liar:
    """Lying ``__class__`` impostor: passes ``isinstance``/``_isa`` for the
    claimed builtin but carries none of its real storage, so the unbound
    base descriptor one line past the gate TypeErrors.  ``__slots__`` keeps
    the response encoder from quietly rendering it via ``vars()``."""

    __slots__ = ("_claim",)

    def __init__(self, claim):
        object.__setattr__(self, "_claim", claim)

    @property
    def __class__(self):
        return self._claim


class _IterBombList(list):
    """list-subclass ``sh`` answer whose bound ``__iter__`` raises: the bare
    3-slot unpack dispatched into it; the real storage is honest."""

    def __iter__(self):
        raise RuntimeError("leftover __iter__ bomb")


class _RcEqFloatBomb(int):
    """int-subclass return code whose comparisons and ``__float__`` raise."""

    def __eq__(self, other):
        raise RuntimeError("leftover rc __eq__ bomb")

    __ne__ = __eq__
    __hash__ = int.__hash__

    def __float__(self):
        raise RuntimeError("leftover rc __float__ bomb")


class _BoolBomb:
    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")


class _IsoPropertyBomb:
    @property
    def isoformat(self):
        raise RuntimeError("leftover isoformat property bomb")


class _ItemsBombDict(dict):
    def items(self):
        raise RuntimeError("leftover items bomb")


class _SelfStrEncodeBomb(str):
    """``str()`` answers *self*, so the subclass (and its bound ``encode``
    bomb) survives CPython's exact-str copy."""

    def __str__(self):
        return self

    def encode(self, *a, **kw):
        raise RuntimeError("leftover encode bomb")


class VmsListingLiarTests(unittest.TestCase):
    """GET /api/vms answers 200 valid UTF-8 with liars degraded field-level."""

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

    def test_lying_class_row_values_degrade_only_that_field(self):
        # Pre-fix: the bool-liar rode raw into the response encoder, and
        # each other claim TypeError'd _jsonable's unbound base read —
        # every one a raw 500 on GET /api/vms.
        for claim in (bool, dict, list, tuple, bytes, str, float, int):
            with self.subTest(claim=claim.__name__):
                body = self._get([{"name": "Ubuntu", "poison": _Liar(claim)}])
                row = next(v for v in body["vms"] if v.get("name") == "Ubuntu")
                self.assertIsInstance(row["poison"], (str, type(None)))
                json.dumps(row, allow_nan=False)
                self.assertIn("ubuntu", [v.get("name") for v in body["vms"]])

    def test_lying_class_mapping_keys_degrade_to_repr_text(self):
        # A str-liar key passed the key gate and blew _as_text's unbound
        # encode; a bytes-liar key blew the unbound decode.
        for claim in (str, bytes):
            with self.subTest(claim=claim.__name__):
                body = self._get([{_Liar(claim): 1, "name": "Ubuntu"}])
                self.assertIn("Ubuntu", [v.get("name") for v in body["vms"]])

    def test_iter_bomb_sh_answer_keeps_the_utm_inventory(self):
        # Pre-fix the bare unpack raised and _listing_rows swallowed the
        # whole inventory into [] — a silent empty list, not a 500.
        def _sh(cmd, **kw):
            cmd = [str(c) for c in cmd]
            if cmd[1:2] == ["list"] and "utmctl" in cmd[0]:
                return _IterBombList([0, UTM_LISTING, ""])
            return (0, "", "")

        with mock.patch.object(vms_svc, "_utm_available", return_value=True), \
             mock.patch.object(vms_svc, "_orb_available", return_value=False), \
             mock.patch.object(vms_svc, "UTMCTL", "/usr/local/bin/utmctl"), \
             mock.patch.object(vms_svc, "sh", side_effect=_sh), \
             mock.patch.object(audit, "record"):
            resp = self.client.get("/api/vms")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertEqual(body["utm_count"], 1)
        self.assertIn("Ubuntu", [v["name"] for v in body["vms"]])

    def test_bool_bomb_override_port_costs_one_probe_not_the_inventory(self):
        # The probe fan-out ran ``if port`` bare: one leftover override
        # port whose __bool__ raises re-raised on iteration and dropped
        # every UTM row through the _listing_rows catch.
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
                               return_value={"port": _BoolBomb()}):
            resp = self.client.get("/api/vms")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertEqual(body["utm_count"], 1)
        row = next(v for v in body["vms"] if v["name"] == "Ubuntu")
        self.assertEqual(row["state"], "ok")


class VmActionUnwrapAndForgeryTests(unittest.TestCase):
    """POST /api/vms/{id}/action answers 200/coded errors over poisoned
    ``sh`` answers; junk rc can no longer forge the vanished-CLI 503."""

    def setUp(self):
        self.client = _client()
        vms_svc.invalidate_vm_lists()
        self.addCleanup(vms_svc.invalidate_vm_lists)

    def _act(self, sh_answer, action="start", vm="Ubuntu"):
        with mock.patch.object(vms_svc, "_utm_available", return_value=True), \
             mock.patch.object(vms_svc, "list_orb_machines", return_value=[]), \
             mock.patch.object(vms_svc, "sh", return_value=sh_answer), \
             mock.patch.object(audit, "record"):
            return self.client.post(f"/api/vms/{vm}/action",
                                    json={"action": action})

    def test_lying_tuple_sh_answer_reads_as_a_plain_failure(self):
        # Pre-fix the 3-slot unpack TypeError'd on the impostor — a raw
        # 500 on the action route, outside every listing catch.
        resp = self._act(_Liar(tuple))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertIs(body["ok"], False)
        resp.content.decode("utf-8")

    def test_iter_bomb_sh_answer_still_reads_its_honest_storage(self):
        resp = self._act(_IterBombList([0, "started", ""]))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertIs(body["ok"], True)
        self.assertEqual(body["message"], "started")

    def test_wrong_arity_sh_answer_reads_as_a_plain_failure(self):
        resp = self._act((0, "only-two"))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIs(resp.json()["ok"], False)

    def test_bytes_liar_stdout_no_longer_500s_the_reply(self):
        # Pre-fix _as_text's unbound decode ran outside any try: the
        # impostor TypeError'd the message assembly itself.
        for claim in (bytes, str):
            with self.subTest(claim=claim.__name__):
                resp = self._act((0, _Liar(claim), ""))
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                self.assertIs(resp.json()["ok"], True)
                resp.content.decode("utf-8")

    def test_status_action_survives_a_lying_list_sh_answer(self):
        resp = self._act(_Liar(list), action="status")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertIs(body["ok"], True)
        self.assertEqual(body["status"], "unknown")

    def test_junk_rc_cannot_forge_the_vanished_cli_503(self):
        # Pre-fix junk rc read as -1 — the spawn sentinel — so beside a
        # leftover "not found" stderr and a vanished binary the action
        # answered the coded 503 minted out of a junk object.
        with mock.patch.object(vms_svc, "_bin_present", return_value=False):
            resp = self._act(("junk", "", "not found"))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIs(resp.json()["ok"], False)

    def test_real_spawn_sentinel_still_answers_the_coded_503(self):
        with mock.patch.object(vms_svc, "_bin_present", return_value=False):
            resp = self._act((-1, "", "not found"))
        self.assertEqual(resp.status_code, 503, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "vms.utm_unavailable")

    def test_over_cap_exact_int_rc_reads_as_a_plain_failure(self):
        resp = self._act((10 ** 5000, "", "boom"))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIs(resp.json()["ok"], False)

    def test_str_liar_orb_name_falls_back_to_the_request_text(self):
        # A liar orb_name beside a healthy matching id blew _parse_id's
        # _as_text pre-fix; the exact request text now names the machine.
        seen = []

        def _sh(cmd, **kw):
            seen.append([str(c) for c in cmd])
            return (0, "ok", "")

        rows = [{"orb_name": _Liar(str), "id": "somevm"}]
        with mock.patch.object(vms_svc, "_orb_available", return_value=True), \
             mock.patch.object(vms_svc, "list_orb_machines",
                               return_value=rows), \
             mock.patch.object(vms_svc, "sh", side_effect=_sh), \
             mock.patch.object(audit, "record"):
            resp = self.client.post("/api/vms/somevm/action",
                                    json={"action": "start"})
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIs(resp.json()["ok"], True)
        self.assertTrue(seen and seen[0][1:] == ["start", "somevm"], seen)


class RenameOverrideBombTests(unittest.TestCase):
    """The rename action's config seam degrades instead of 500ing."""

    def setUp(self):
        self.client = _client()
        vms_svc.invalidate_vm_lists()
        self.addCleanup(vms_svc.invalidate_vm_lists)

    def _rename(self, override_effect=None, set_override_effect=None):
        ov = mock.patch.object(
            vms_svc, "override",
            side_effect=override_effect) if override_effect else \
            mock.patch.object(vms_svc, "override", return_value={})
        so = mock.patch(
            "hub.config.set_override",
            side_effect=set_override_effect) if set_override_effect else \
            mock.patch("hub.config.set_override", return_value={})
        with mock.patch.object(vms_svc, "_orb_available", return_value=True), \
             ov, so, mock.patch.object(vms_svc, "_invalidate"), \
             mock.patch.object(audit, "record"):
            return self.client.post(
                "/api/vms/orb:ubuntu/action",
                json={"action": "rename", "name": "NewName"})

    def test_raising_override_read_still_renames(self):
        # Pre-fix the raw config.override call (and its bare truthiness)
        # raised out of rename_vm_display — a raw 500 on the action.
        resp = self._rename(
            override_effect=RuntimeError("leftover cfg snapshot bomb"))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertIs(body["ok"], True)
        self.assertEqual(body["name"], "NewName")

    def test_raising_set_override_answers_the_coded_save_failed_503(self):
        resp = self._rename(
            set_override_effect=RuntimeError("leftover persist bomb"))
        self.assertEqual(resp.status_code, 503, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "settings.save_failed")


class ConsoleMintLiarTests(unittest.TestCase):
    """The console-session mint's liveness walk skips liar rows instead of
    raising out of the route."""

    _ENTRY = {"enabled": True, "port": 5900,
              "host": "127.0.0.1", "protocol": "vnc"}

    def test_str_liar_uuid_row_answers_the_coded_404(self):
        client = _client()
        section = {"allowlist": {_UUID: dict(self._ENTRY)}}
        rows = [{"uuid": _Liar(str), "id": "Ubuntu"}]
        with mock.patch.object(auth, "browser_authenticated",
                               return_value=True), \
             mock.patch.object(vm_console, "settings_section",
                               lambda n: section), \
             mock.patch.object(vms_svc, "_utm_available", return_value=True), \
             mock.patch.object(vms_svc, "list_utm_vms", return_value=rows):
            resp = client.post(f"/api/vms/utm:{_UUID}/console/session",
                               json={})
        self.assertEqual(resp.status_code, 404, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"],
                         "vm_console.unavailable")

    def test_liar_row_is_skipped_and_the_healthy_sibling_answers(self):
        rows = [
            {"uuid": _Liar(str), "id": "Ubuntu"},
            {"uuid": _UUID, "id": "Ubuntu"},
        ]
        with mock.patch.object(vms_svc, "_utm_available", return_value=True), \
             mock.patch.object(vms_svc, "list_utm_vms", return_value=rows), \
             mock.patch.object(vms_svc, "_utm_status",
                               return_value="started"):
            self.assertTrue(vms_svc.utm_vm_running(_UUID))


class StaysImmunePins(unittest.TestCase):
    """Seams this sweep re-probed and found already hardened."""

    def setUp(self):
        self.client = _client()
        vms_svc.invalidate_vm_lists()
        self.addCleanup(vms_svc.invalidate_vm_lists)

    def test_nested_items_bomb_row_keeps_its_real_storage(self):
        # The unbound dict.items walk recurses, so a subclass bomb nested
        # inside a list inside a row still reads through.
        out = vms_svc._jsonable({"a": [_ItemsBombDict({"x": 1})]})
        self.assertEqual(out, {"a": [{"x": 1}]})

    def test_isoformat_property_bomb_row_value_degrades_to_none(self):
        with mock.patch.object(vms_svc, "list_utm_vms",
                               return_value=[{"name": "Ubuntu",
                                              "stamp": _IsoPropertyBomb()}]), \
             mock.patch.object(vms_svc, "list_orb_machines",
                               return_value=[]):
            resp = self.client.get("/api/vms")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        row = next(v for v in resp.json()["vms"] if v["name"] == "Ubuntu")
        self.assertIsNone(row["stamp"])

    def test_huge_json_number_in_orb_listing_loses_only_its_field(self):
        # json.loads of a >4300-digit literal is ValueError for the whole
        # document; the parse_int hook loads it as None instead.
        doc = json.dumps([{"name": "ubuntu", "state": "running"}])
        doc = doc.replace('"running"}', '"running", "weight": '
                          + "9" * 4400 + "}")

        def _sh(cmd, **kw):
            cmd = [str(c) for c in cmd]
            if cmd[1:2] == ["list"] and "orbctl" in cmd[0]:
                return (0, doc, "")
            return (1, "", "")

        with mock.patch.object(vms_svc, "_utm_available",
                               return_value=False), \
             mock.patch.object(vms_svc, "_orb_available", return_value=True), \
             mock.patch.object(vms_svc, "ORBCTL", "/usr/local/bin/orbctl"), \
             mock.patch.object(vms_svc, "sh", side_effect=_sh), \
             mock.patch.object(audit, "record"):
            resp = self.client.get("/api/vms")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertEqual(body["orb_count"], 1)
        self.assertIn("ubuntu", [v["name"] for v in body["vms"]])

    def test_self_str_encode_bomb_still_scrubs_through_unbound_encode(self):
        # encode(..., "replace") substitutes "?" for the lone surrogate.
        self.assertEqual(vms_svc._as_text(_SelfStrEncodeBomb("ok\ud800")),
                         "ok?")


class HelperUnitPins(unittest.TestCase):
    """Direct pins for the vms10 guards."""

    def test_rc_int_degrades_junk_to_minus_255_never_the_sentinel(self):
        self.assertEqual(vms_svc._rc_int("junk"), -255)
        self.assertEqual(vms_svc._rc_int(_Liar(int)), -255)
        self.assertEqual(vms_svc._rc_int(_Liar(bool)), -255)
        self.assertEqual(vms_svc._rc_int(10 ** 5000), -255)
        self.assertEqual(vms_svc._rc_int(_RcEqFloatBomb(3)), 3)
        self.assertEqual(vms_svc._rc_int(_RcEqFloatBomb(-1)), -1)
        self.assertEqual(vms_svc._rc_int(True), 1)
        self.assertEqual(vms_svc._rc_int(False), 0)
        self.assertEqual(vms_svc._rc_int(0), 0)

    def test_sh3_reads_honest_storage_and_degrades_junk(self):
        self.assertEqual(vms_svc._sh3((0, "a", "b")), (0, "a", "b"))
        self.assertEqual(vms_svc._sh3(_IterBombList([1, "o", "e"])),
                         (1, "o", "e"))
        self.assertEqual(vms_svc._sh3(_Liar(tuple)), (-255, "", ""))
        self.assertEqual(vms_svc._sh3(_Liar(list)), (-255, "", ""))
        self.assertEqual(vms_svc._sh3("junk"), (-255, "", ""))
        self.assertEqual(vms_svc._sh3((0, "only-two")), (-255, "", ""))
        self.assertEqual(vms_svc._sh3(None), (-255, "", ""))

    def test_cli_missing_rejects_junk_rc_and_keeps_the_disk_confirm(self):
        with mock.patch.object(vms_svc, "_bin_present", return_value=False):
            self.assertFalse(vms_svc._cli_missing("junk", "not found", "/x"))
            self.assertTrue(vms_svc._cli_missing(-1, "not found", "/x"))
        with mock.patch.object(vms_svc, "_bin_present", return_value=True):
            self.assertFalse(vms_svc._cli_missing(-1, "not found", "/x"))

    def test_decode_bytes_answers_none_for_a_lying_impostor(self):
        self.assertIsNone(vms_svc._decode_bytes(_Liar(bytes)))
        self.assertEqual(vms_svc._decode_bytes(b"ok\xff"), "ok\ufffd")

    def test_as_text_renders_liars_like_any_junk_object(self):
        for claim in (bytes, bytearray, str):
            with self.subTest(claim=claim.__name__):
                text = vms_svc._as_text(_Liar(claim))
                self.assertIsInstance(text, str)
                self.assertIn("_Liar", text)

    def test_display_and_id_text_take_the_fallback_for_liars(self):
        for claim in (str, bytes, bool, int, float):
            with self.subTest(claim=claim.__name__):
                self.assertEqual(vms_svc._display_text(_Liar(claim), "fb"),
                                 "fb")
        self.assertEqual(vms_svc._id_text(_Liar(str), "fb"), "fb")

    def test_jsonable_degrades_every_liar_claim(self):
        for claim in (bool, dict, list, tuple, set, frozenset, bytes,
                      bytearray, int, float):
            with self.subTest(claim=claim.__name__):
                self.assertIsNone(vms_svc._jsonable(_Liar(claim)))
        # A str-liar renders as its repr text — still an exact str.
        out = vms_svc._jsonable(_Liar(str))
        self.assertIsInstance(out, str)
        # Honest values keep passing through untouched.
        self.assertEqual(
            vms_svc._jsonable({"a": [1, 2.5, "x", True, None]}),
            {"a": [1, 2.5, "x", True, None]},
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
