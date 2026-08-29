"""Leftover digit-cap ints in api-keys.json: whole-store wipe and encoder 500s.

``json.loads`` of a >4300-digit number literal raises CPython's str->int
digit-cap ValueError — a *plain* ValueError, not JSONDecodeError — so
``api_keys._load``'s corrupt-document fallback read the whole store as ``[]``:

* every Bearer-authenticated request 401'd (the key list looked empty), and
* the very next write — key create, revoke, or ``verify``'s throttled
  last_used persist — rewrote api-keys.json from that empty snapshot,
  silently wiping every sibling key for good.

The sibling stores (twofa.json, notify-credentials.json,
service-credentials.json, SMART history) each already carry a ``parse_int``
hook for exactly this; api-keys.json was the leftover without one.

Already-int leftovers past the cap (a plist/YAML hex import: ``int(x, 16)``
is exempt from the digit cap) hit the same ValueError later, at dump time:
``_save`` silently dropped the entire write, and ``public_view`` handed the
number to Starlette's encoder, which 500'd GET /api/api-keys.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from hub import api_keys
from hub.routers import api_keys_api

#: What a leftover ``0xF…`` (5000 hex digits) in a plist/YAML import loads as:
#: ``int(x, 16)`` is exempt from CPython's str<->int digit cap, so the value
#: exists fine as an int and only explodes at ``str()`` / ``json.dumps`` time.
HUGE_INT = int("F" * 5000, 16)
#: A 5000-digit number literal as JSON text: valid JSON, but the default
#: ``int(text)`` conversion inside ``json.loads`` raises the digit-cap
#: ValueError for the whole document.
HUGE_DIGITS = "9" * 5000


def _starlette_json(payload) -> bytes:
    """Starlette JSONResponse encoding: allow_nan=False + UTF-8."""
    return json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class ApiKeysHugeIntLiteralTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = Path(tmp.name) / "api-keys.json"
        patcher = mock.patch.object(api_keys, "STORE_FILE", self.store)
        patcher.start()
        self.addCleanup(patcher.stop)
        api_keys._last_seen.clear()

    def _poison(self, field: str, literal: str = HUGE_DIGITS) -> None:
        """Splice a raw huge number literal into the stored JSON."""
        raw = self.store.read_text()
        needle = f'"{field}": null'
        self.assertIn(needle, raw)
        self.store.write_text(raw.replace(needle, f'"{field}": {literal}'))

    def test_huge_int_literal_does_not_401_every_bearer(self):
        """One poisoned stamp made _load return [] — every key stopped verifying."""
        rec, token = api_keys.create("mon", "member")
        self._poison("last_used")
        hit = api_keys.verify(token)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["id"], rec["id"])
        _starlette_json(hit)

    def test_huge_int_literal_does_not_empty_the_listing(self):
        rec, _ = api_keys.create("mon", "member")
        self._poison("last_used")
        with mock.patch.object(
            api_keys_api, "require_admin_browser", return_value="admin"
        ):
            body = api_keys_api.api_keys_list(mock.Mock())
        _starlette_json(body)
        self.assertEqual([k["id"] for k in body["keys"]], [rec["id"]])

    def test_huge_int_literal_does_not_wipe_siblings_on_create(self):
        """The next write used to rewrite the store from the empty snapshot."""
        rec, token = api_keys.create("mon", "member")
        self._poison("last_used")
        api_keys.create("other", "member")
        stored = json.loads(self.store.read_text())
        names = sorted(k.get("name") for k in stored["keys"])
        self.assertEqual(names, ["mon", "other"])
        # The surviving original key still authenticates.
        self.assertIsNotNone(api_keys.verify(token))
        json.dumps(stored, allow_nan=False)

    def test_huge_int_literal_does_not_wipe_siblings_on_revoke(self):
        rec, token = api_keys.create("mon", "member")
        rec2, _ = api_keys.create("gone", "member")
        self._poison("last_used")
        self.assertIsNotNone(api_keys.revoke(rec2["id"]))
        stored = json.loads(self.store.read_text())
        self.assertEqual([k.get("name") for k in stored["keys"]], ["mon"])
        self.assertIsNotNone(api_keys.verify(token))

    def test_huge_expires_literal_fails_closed_not_open(self):
        """An unreadable expiry must read as expired, never as "no expiry"."""
        rec, token = api_keys.create("mon", "member", expires_days=7)
        raw = self.store.read_text()
        raw = raw.replace(f'"expires": {json.loads(raw)["keys"][0]["expires"]}',
                          f'"expires": {HUGE_DIGITS}')
        self.store.write_text(raw)
        self.assertIsNone(api_keys.verify(token))
        # The poisoned row persists as expired (0), not as expires: null.
        listed = api_keys.list_public()
        _starlette_json(listed)
        self.assertEqual(listed[0]["expires"], 0)

    def test_huge_created_literal_reads_as_unknown_not_500(self):
        rec, token = api_keys.create("mon", "member")
        raw = self.store.read_text()
        created = json.loads(raw)["keys"][0]["created"]
        self.store.write_text(raw.replace(f'"created": {created}', f'"created": {HUGE_DIGITS}'))
        listed = api_keys.list_public()
        _starlette_json(listed)
        self.assertIsNone(listed[0]["created"])
        self.assertIsNotNone(api_keys.verify(token))


class ApiKeysAlreadyIntLeftoverTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = Path(tmp.name) / "api-keys.json"
        patcher = mock.patch.object(api_keys, "STORE_FILE", self.store)
        patcher.start()
        self.addCleanup(patcher.stop)
        api_keys._last_seen.clear()

    def test_over_cap_int_field_does_not_drop_the_whole_save(self):
        """json.dumps of the already-int leftover ValueError'd _save into a
        silent no-op — the sibling row (and a revocation) never landed."""
        api_keys._save([
            {"id": "ak_x", "name": "mon", "role": "member", "digest": "d" * 64,
             "created": HUGE_INT, "expires": None, "last_used": None},
            {"id": "ak_y", "name": "sib", "role": "member", "digest": "e" * 64,
             "created": 1, "expires": None, "last_used": None},
        ])
        self.assertTrue(self.store.is_file())
        stored = json.loads(self.store.read_text())
        json.dumps(stored, ensure_ascii=False, allow_nan=False)
        self.assertEqual([k["name"] for k in stored["keys"]], ["mon", "sib"])

    def test_public_view_over_cap_created_is_dropped_not_500(self):
        view = api_keys.public_view({
            "id": "ak_x", "name": "mon", "role": "member",
            "created": HUGE_INT, "expires": None, "last_used": HUGE_INT,
        })
        _starlette_json(view)
        self.assertIsNone(view["created"])
        self.assertIsNone(view["last_used"])

    def test_over_cap_expires_fails_closed_in_verify(self):
        rec, token = api_keys.create("mon", "member")
        keys = api_keys._load()
        keys[0]["expires"] = HUGE_INT
        api_keys._save(keys)
        self.assertIsNone(api_keys.verify(token))

    def test_as_epoch_over_cap_int_reads_default(self):
        self.assertEqual(api_keys._as_epoch(HUGE_INT), 0)
        self.assertIsNone(api_keys._as_epoch(HUGE_INT, default=None))


if __name__ == "__main__":
    unittest.main()
