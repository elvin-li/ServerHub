"""Eighth leftover-500s sweep of the VMs surfaces, over the real app.

vms7 sealed ``hub/vms_svc.py``'s own coercers and the listing/row walks, and
in ``hub/vm_console.py`` it made ``_entry_for`` launder the allowlist
*container* (unbound ``dict.items`` / a plain-dict copy of the entry) and the
*key* / *host* text probes (unbound base decode, exact-str copies).  What it
never reached is ``resolve_target``'s per-*value* coercion of the resolved
entry: the leftover convention was applied to the mapping and its keys, not to
the flag/number/host **values** those keys point at.  On the pre-fix tree a
leftover ``settings.vm_console.allowlist`` entry whose value is a subclass with
a bombing ``__bool__`` / ``__eq__`` / ``__int__`` detonated straight through
``resolve_target``:

* ``enabled`` — ``not entry.get("enabled")`` ran the value's ``__bool__``;
* ``protocol`` — ``entry.get("protocol") or "vnc"`` ran its ``__bool__``;
* ``host`` — ``raw_host in (None, "")`` ran its reflected ``__eq__``;
* ``port`` — ``int(raw_port or 0)`` ran its ``__bool__`` (and a leftover int
  subclass ``__int__``);
* ``view_only`` — ``bool(entry.get("view_only"))`` ran its ``__bool__``.

Both HTTP surfaces the resolver backs bombed with it: POST
/api/vms/{console_id}/console/session answered a bare 500, and — because
``capability()`` calls ``resolve_target`` per UTM row and ``_listing_rows``
catches the raise and answers ``[]`` — GET /api/vms silently threw away the
whole UTM inventory (the exact vms7 failure mode, one value deeper).

Fix in ``hub/vm_console.py``: a bomb-safe ``_flag`` truthiness and a
``_coerce_port`` that base-coerces via ``int.__index__`` / ``float.__float__``,
plus ``is None`` / exact-str host defaulting that never touches a subclass
``__eq__``.
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


class _StrBoolBomb(str):
    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")


class _IntBoolBomb(int):
    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")


class _IntIntBomb(int):
    """``or 0`` / ``int()`` both used to run this."""

    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")

    def __int__(self):
        raise RuntimeError("leftover __int__ bomb")

    def __index__(self):
        raise RuntimeError("leftover __index__ bomb")


class _StrEqBomb(str):
    """Reflected ``__eq__`` bomb: ``subclass in (None, "")`` calls this."""

    def __eq__(self, other):
        raise RuntimeError("leftover __eq__ bomb")

    __ne__ = __eq__
    __hash__ = str.__hash__


_ENTRY = {"enabled": True, "port": 5900, "host": "127.0.0.1", "protocol": "vnc"}


def _entry(**over) -> dict:
    return {"allowlist": {_UUID: dict(_ENTRY, **over)}}


class ResolveTargetValueBombTests(unittest.TestCase):
    """A leftover entry value cannot 500 the resolver; it resolves or refuses."""

    def _resolve(self, section):
        with mock.patch.object(
            vm_console, "settings_section", lambda name: section
        ):
            return vm_console.resolve_target(f"utm:{_UUID}")

    def test_enabled_bool_bomb_refuses_not_raises(self):
        # A bombing ``enabled`` cannot be read as truthy, so the console is
        # simply "not configured" — never a 500.
        self.assertIsNone(self._resolve(_entry(enabled=_StrBoolBomb("x"))))

    def test_protocol_bool_bomb_resolves_off_the_real_text(self):
        target = self._resolve(_entry(protocol=_StrBoolBomb("vnc")))
        self.assertIsNotNone(target)
        self.assertEqual(target.protocol, "vnc")

    def test_view_only_bool_bomb_resolves_and_defaults_false(self):
        target = self._resolve(_entry(view_only=_StrBoolBomb("x")))
        self.assertIsNotNone(target)
        self.assertFalse(target.view_only)

    def test_port_bool_and_int_bombs_resolve_off_the_real_value(self):
        for bomb in (_IntBoolBomb(5900), _IntIntBomb(5900)):
            with self.subTest(bomb=type(bomb).__name__):
                target = self._resolve(_entry(port=bomb))
                self.assertIsNotNone(target)
                self.assertEqual(target.port, 5900)

    def test_host_eq_bomb_resolves_off_the_real_host(self):
        target = self._resolve(_entry(host=_StrEqBomb("127.0.0.1")))
        self.assertIsNotNone(target)
        self.assertEqual(target.host, "127.0.0.1")

    def test_absent_and_blank_host_still_default_to_loopback(self):
        self.assertEqual(self._resolve(_entry(host=None)).host, "127.0.0.1")
        section = {"allowlist": {_UUID: {"enabled": True, "port": 5900}}}
        self.assertEqual(self._resolve(section).host, "127.0.0.1")
        self.assertEqual(self._resolve(_entry(host="")).host, "127.0.0.1")

    def test_present_but_unusable_host_is_refused_not_defaulted(self):
        # A non-loopback host is rejected, and a whitespace/undecodable host
        # must NOT be silently upgraded to the loopback default.
        self.assertIsNone(self._resolve(_entry(host="10.0.0.5")))
        self.assertIsNone(self._resolve(_entry(host="   ")))


class ConsoleSessionMintBombTests(unittest.TestCase):
    """POST /api/vms/{id}/console/session: a bombed entry cannot 500 the mint."""

    def test_enabled_bomb_answers_coded_unavailable_not_500(self):
        client = _client()
        section = _entry(enabled=_StrBoolBomb("x"))
        with mock.patch.object(auth, "browser_authenticated", return_value=True), \
             mock.patch.object(vm_console, "settings_section", lambda n: section):
            resp = client.post(f"/api/vms/utm:{_UUID}/console/session", json={})
        self.assertEqual(resp.status_code, 404, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "vm_console.unavailable")


class UtmListingSurvivesConsoleBombTests(unittest.TestCase):
    """GET /api/vms: a bombed allowlist value must not empty the UTM inventory."""

    def setUp(self):
        self.client = _client()
        self.addCleanup(vms_svc.invalidate_vm_lists)

    def _sh(self, cmd, **kw):
        cmd = [str(c) for c in cmd]
        if cmd[1:2] == ["list"] and "utmctl" in cmd[0]:
            return (0, UTM_LISTING, "")
        return (0, "", "")

    def test_listing_keeps_the_utm_machine_despite_the_bomb(self):
        section = _entry(enabled=_StrBoolBomb("x"))
        vms_svc.invalidate_vm_lists()
        with mock.patch.object(vms_svc, "_utm_available", return_value=True), \
             mock.patch.object(vms_svc, "_orb_available", return_value=False), \
             mock.patch.object(vms_svc, "UTMCTL", "/usr/local/bin/utmctl"), \
             mock.patch.object(vms_svc, "sh", side_effect=self._sh), \
             mock.patch.object(audit, "record"), \
             mock.patch.object(vm_console, "settings_section", lambda n: section):
            resp = self.client.get("/api/vms")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        names = {v["name"] for v in body["vms"]}
        # Pre-fix: capability() raised, _listing_rows swallowed it and the
        # whole UTM inventory answered [] (utm_count 0).
        self.assertIn("Ubuntu", names)
        self.assertEqual(body["utm_count"], 1)
        # The row's console capability degrades cleanly rather than raising.
        row = next(v for v in body["vms"] if v["name"] == "Ubuntu")
        json.dumps(row, allow_nan=False)
        self.assertIn("available", row["console"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
