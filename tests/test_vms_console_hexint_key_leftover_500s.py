"""Leftover VMs-domain 500s/silent losses: huge-int allowlist key/protocol.

Third sweep over the VM paths, continuing test_leftover_vm_500s and
test_vms_leftover_sentinel_surrogate_500s:

* ``vm_console._entry_for`` compared allowlist keys with a bare ``str(key)``.
  services.yaml keys are UUID strings, but a leftover YAML hex int key
  (``0x…`` dodges CPython's int(str) digit cap, so the *already-int* value
  blows ``str()`` at 4300+ digits) raised ValueError out of the comparison.
  That 500'd POST /api/vms/{console_id}/console/session and the console
  WebSocket resolve — and, because ``capability()`` runs per row inside the
  UTM listing, it silently wiped every UTM row from GET /api/vms
  (``_listing_rows`` absorbs the raise into ``[]``).

* ``resolve_target`` normalised the protocol with bare
  ``str(entry.get("protocol") or "vnc")`` — the same already-int blow-up for
  a leftover ``protocol: 0x…`` value, with the same blast radius.

Both now use a ``str()`` probe, not an ``isinstance(x, str)`` gate: a
numeric YAML key still compares as its decimal text instead of being
silently dropped.

Stays-immune pins (behaviour that was already correct and must not regress):

* an orbctl ``-f json`` payload whose id is a 4400-digit number literal is a
  ValueError from ``json.loads`` (not JSONDecodeError); the listing falls
  back to the text table instead of wiping the machines or 500ing.
* a lone-surrogate allowlist key cannot match and cannot 500 the resolve.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from hub import vm_console, vms_svc

_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
#: An already-int over the CPython 4300-digit str() cap, as a YAML hex
#: leftover produces it (int(str) never runs, so the cap is dodged on parse).
_HUGE = 0x10 ** 4000
_GOOD = {"enabled": True, "host": "127.0.0.1", "port": 5900}
UTM_LISTING = (
    "UUID                                 Status   Name\n"
    f"{_UUID} started  Ubuntu\n"
)


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _utm_listing(allowlist):
    with (
        mock.patch.object(vms_svc, "_utm_available", return_value=True),
        mock.patch.object(vms_svc, "sh", return_value=(0, UTM_LISTING, "")),
        mock.patch.object(vms_svc, "override", return_value={}),
        mock.patch.object(vms_svc, "port_open", return_value=True),
        mock.patch.object(vm_console, "_allowlist", return_value=allowlist),
    ):
        return vms_svc._list_utm_vms_uncached()


class HugeIntAllowlistKeyTests(unittest.TestCase):
    """A YAML hex int key used to ValueError bare ``str(key)`` mid-compare."""

    def test_hugeint_key_does_not_500_resolve(self):
        """The entry *after* the leftover key must still be found."""
        allow = {_HUGE: {"enabled": True}, _UUID: dict(_GOOD)}
        with mock.patch.object(vm_console, "_allowlist", return_value=allow):
            target = vm_console.resolve_target(f"utm:{_UUID}")
        self.assertIsNotNone(target)
        self.assertEqual(target.port, 5900)
        self.assertEqual(target.host, "127.0.0.1")

    def test_hugeint_key_does_not_wipe_utm_listing(self):
        """capability() runs per UTM row; the raise used to empty GET /api/vms."""
        allow = {_HUGE: {"enabled": True}, _UUID: dict(_GOOD)}
        items = _utm_listing(allow)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["name"], "Ubuntu")
        self.assertTrue(items[0]["console"]["available"])
        _starlette(items)

    def test_hugeint_key_capability_is_not_configured_when_alone(self):
        with mock.patch.object(
            vm_console, "_allowlist", return_value={_HUGE: {"enabled": True}},
        ):
            cap = vm_console.capability(backend="utm", vm_uuid=_UUID, running=True)
        self.assertFalse(cap["available"])
        self.assertEqual(cap["reason"], "vm_console.not_configured")
        _starlette(cap)

    def test_numeric_key_still_compares_as_text(self):
        """str() probe, not an isinstance-str gate: a numeric YAML key keeps
        matching by its decimal text instead of being silently dropped."""
        entry = {"enabled": True}
        with mock.patch.object(
            vm_console, "_allowlist", return_value={123: entry},
        ):
            self.assertIs(vm_console._entry_for("123"), entry)

    def test_bytes_key_still_compares_as_text(self):
        entry = {"enabled": True}
        with mock.patch.object(
            vm_console, "_allowlist", return_value={_UUID.encode(): entry},
        ):
            self.assertIs(vm_console._entry_for(_UUID), entry)


class HugeIntProtocolTests(unittest.TestCase):
    """``protocol: 0x…`` used to ValueError ``str()`` in resolve_target."""

    def test_hugeint_protocol_is_not_configured_not_500(self):
        allow = {_UUID: {**_GOOD, "protocol": _HUGE}}
        with mock.patch.object(vm_console, "_allowlist", return_value=allow):
            self.assertIsNone(vm_console.resolve_target(f"utm:{_UUID}"))
        items = _utm_listing(allow)
        self.assertEqual(len(items), 1)
        self.assertFalse(items[0]["console"]["available"])
        _starlette(items)

    def test_falsy_protocol_still_defaults_to_vnc(self):
        """The probe must not tighten the old ``or "vnc"`` default."""
        for falsy in (None, "", 0, False):
            with self.subTest(protocol=falsy):
                allow = {_UUID: {**_GOOD, "protocol": falsy}}
                with mock.patch.object(
                    vm_console, "_allowlist", return_value=allow,
                ):
                    target = vm_console.resolve_target(f"utm:{_UUID}")
                self.assertIsNotNone(target)
                self.assertEqual(target.protocol, "vnc")

    def test_non_vnc_protocol_still_refused(self):
        allow = {_UUID: {**_GOOD, "protocol": "spice"}}
        with mock.patch.object(vm_console, "_allowlist", return_value=allow):
            self.assertIsNone(vm_console.resolve_target(f"utm:{_UUID}"))


class StaysImmuneTests(unittest.TestCase):
    """Behaviour that was already correct on this sweep; pinned so it stays."""

    def test_surrogate_allowlist_key_does_not_500(self):
        allow = {"k\ud800": {"enabled": True}, _UUID: dict(_GOOD)}
        with mock.patch.object(vm_console, "_allowlist", return_value=allow):
            target = vm_console.resolve_target(f"utm:{_UUID}")
        self.assertIsNotNone(target)
        self.assertEqual(target.port, 5900)

    def test_orb_hugeint_json_id_falls_back_to_text_listing(self):
        """``json.loads`` of a 4400-digit number literal is ValueError, not
        JSONDecodeError; the machines must survive via the text table rather
        than the whole listing being wiped or the request 500ing."""
        def fake_sh(cmd, **kw):
            if "-f" in cmd:
                return (0, '[{"name":"web","state":"running","id":' + "9" * 4400 + "}]", "")
            return (0, "NAME  STATE\nweb  running\n", "")

        with (
            mock.patch.object(vms_svc, "_orb_available", return_value=True),
            mock.patch.object(vms_svc, "sh", side_effect=fake_sh),
            mock.patch.object(vms_svc, "override", return_value={}),
        ):
            items = vms_svc._list_orb_machines_uncached()
        self.assertEqual([m["orb_name"] for m in items], ["web"])
        self.assertEqual(items[0]["state"], "ok")
        _starlette(items)

    def test_hugeint_port_value_still_not_configured(self):
        """An already-int over-cap ``port:`` (hex leftover) stays refused
        without raising — ``int()`` of an int never re-runs the digit cap."""
        allow = {_UUID: {**_GOOD, "port": _HUGE}}
        with mock.patch.object(vm_console, "_allowlist", return_value=allow):
            self.assertIsNone(vm_console.resolve_target(f"utm:{_UUID}"))


if __name__ == "__main__":
    unittest.main()
