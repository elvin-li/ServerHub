"""Seventh leftover-500s sweep of the storage-pool routes, over the real app.

The zoo (dict-subclass protocol bombs, nested unbound coercions, surrogates,
over-digit-cap ints, huge JSON number literals) was re-reproduced against
``create_app()`` with ``raise_server_exceptions=False``.  Pool6 sealed the
oversize-name 400; what survived it lives one seam earlier, in
``storage_pool_svc._pool_config`` / ``_text`` — the one pool reader that
never got the modules5/cf7 unbound-base convention.  Each of these raised
out of the config read and 500'd all four pool routes at once (GET
/api/storage/pool, plan, save, and clear *after* its config write had
already landed):

* a config root / settings map / storage_pool block that is a dict
  *subclass* with a bombing ``.get`` or ``__bool__`` (the bound ``.get``
  chain and its ``or {}`` truth tests detonated);
* a list-subclass ``members`` whose ``__iter__`` raises;
* member/name values wearing subclass protocol bombs through ``_text``:
  an int-subclass ``__str__`` bomb (bare ``str()`` reflected into it and
  RuntimeError is not the digit-cap ValueError the probe expected), a
  str-subclass self-``__str__`` ``encode`` bomb (the bound encode
  dispatched into the override), a bytes-subclass ``__bytes__``/``decode``
  bomb, a float-subclass ``__eq__`` bomb (the nan/inf probes ran it), a
  bare ``__eq__`` bomb (the old ``raw in (None, False, True, "")`` tuple
  probe), an ``isoformat`` ``__getattr__`` bomb, and a list-subclass
  ``__bool__``/``__getitem__`` bomb;
* ``min_free_gb`` whose ``__bool__`` (the ``or 0``) or ``__float__``
  (``float()`` reflection) raises past the old (TypeError, ValueError,
  OverflowError) net;
* a ``cfg()`` snapshot provider that raises outright.

The fixes are the modules5/cf7 unbound-base convention: ``dict.get`` /
``list.__iter__`` / ``list.__getitem__`` / ``int.__index__`` /
``bytes.decode`` / ``str.encode`` views read the real content underneath
the override, so the poison scrubs field-level — the real name and members
still render and only the truly unrenderable degrades to its default.
Huge-int JSON bodies (``json.loads`` raising the digit-cap ValueError, not
JSONDecodeError, absorbed by FastAPI's generic body-parse 400) and the
surrogate laundering of the unbound encode ride along as stays-immune pins.
"""
from __future__ import annotations

import unittest
from unittest import mock

from hub import storage_pool_svc, storage_svc

_APP = None

#: Past CPython's default 4300-digit int<->str conversion limit.
_HUGE_DIGITS = "9" * 5000


def _client():
    global _APP
    from fastapi.testclient import TestClient

    if _APP is None:
        from hub.app_factory import create_app
        from hub.auth import require_auth

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


#: A complete, well-formed poolable volume row: the point of the pins is
#: that the healthy candidate keeps rendering next to the bombed config.
_VAULT = {
    "device": "/dev/disk6s1",
    "mount": "/Volumes/Vault",
    "kind": "external",
    "total_gb": 10.0,
    "used_gb": 1.0,
    "avail_gb": 9.0,
    "pct": 10,
    "disk_id": "disk6",
    "filesystem": "apfs",
}

#: A sane stored pool block; the bombs below replace one field at a time so
#: each pin isolates one seam.
_POOL = {
    "name": "media",
    "members": ["/Volumes/Vault"],
    "policy": "most-free",
    "min_free_gb": 0,
}


class _GetBombDict(dict):
    """Passes ``isinstance(x, dict)``; the bound ``.get`` raises."""

    def get(self, *args, **kwargs):
        raise RuntimeError("leftover get bomb")


class _BoolBombDict(dict):
    """Passes the isinstance gate; the ``or {}`` truth test used to raise."""

    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")


class _IterBombList(list):
    """Passes ``isinstance(x, list)``; bound iteration raises."""

    def __iter__(self):
        raise RuntimeError("leftover __iter__ bomb")


class _StrBombInt(int):
    def __str__(self):
        raise RuntimeError("leftover int __str__ bomb")


class _SelfStrEncodeBomb(str):
    """``str()`` answers *self* (skipping CPython's exact-str copy), so the
    bound ``encode`` bomb used to ride into the UTF-8 launder."""

    def __str__(self):
        return self

    def encode(self, *args, **kwargs):
        raise RuntimeError("leftover encode bomb")


class _DecodeBombBytes(bytes):
    def __bytes__(self):
        return self

    def decode(self, *args, **kwargs):
        raise RuntimeError("leftover decode bomb")


class _EqBomb:
    def __eq__(self, other):
        raise RuntimeError("leftover __eq__ bomb")

    __hash__ = None


class _GetattrBomb:
    def __getattr__(self, name):
        raise RuntimeError("leftover __getattr__ bomb")


class _FloatBoolBomb(float):
    def __float__(self):
        raise RuntimeError("leftover __float__ bomb")

    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")


class _GetItemBombList(list):
    def __getitem__(self, key):
        raise RuntimeError("leftover __getitem__ bomb")


class _PoolConfigSeam(unittest.TestCase):
    """Shared plumbing: a healthy candidate listing plus a bombed cfg tree."""

    def setUp(self):
        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)

    def overview(self, cfg_tree, **cfg_kwargs):
        with (
            mock.patch.object(storage_svc, "list_volumes",
                              return_value=[dict(_VAULT)]),
            mock.patch.object(storage_pool_svc, "cfg",
                              return_value=cfg_tree, **cfg_kwargs),
        ):
            resp = _client().get("/api/storage/pool?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        # The body must already be valid UTF-8 — decode strictly on purpose.
        resp.content.decode("utf-8")
        return resp.json()


class PoolConfigDictSubclassBombTests(_PoolConfigSeam):
    """Dict-subclass ``.get`` / ``__bool__`` bombs wrapping real storage.
    Pre-fix: all four pool routes 500'd; the unbound ``dict.get`` now reads
    the real pool block underneath the override, so the configured member
    still renders."""

    def test_root_get_bomb_renders_the_real_pool(self):
        body = self.overview(_GetBombDict(settings={"storage_pool": dict(_POOL)}))
        self.assertIs(body["configured"], True)
        self.assertEqual(body["name"], "media")
        self.assertEqual([m["mount"] for m in body["members"]],
                         ["/Volumes/Vault"])

    def test_settings_get_bomb_renders_the_real_pool(self):
        body = self.overview(
            {"settings": _GetBombDict(storage_pool=dict(_POOL))}
        )
        self.assertEqual([m["mount"] for m in body["members"]],
                         ["/Volumes/Vault"])

    def test_settings_bool_bomb_renders_the_real_pool(self):
        body = self.overview(
            {"settings": _BoolBombDict(storage_pool=dict(_POOL))}
        )
        self.assertEqual([m["mount"] for m in body["members"]],
                         ["/Volumes/Vault"])

    def test_pool_block_get_bomb_renders_the_real_pool(self):
        body = self.overview({"settings": {"storage_pool": _GetBombDict(_POOL)}})
        self.assertEqual(body["name"], "media")
        self.assertEqual([m["mount"] for m in body["members"]],
                         ["/Volumes/Vault"])

    def test_pool_block_bool_bomb_renders_the_real_pool(self):
        body = self.overview({"settings": {"storage_pool": _BoolBombDict(_POOL)}})
        self.assertEqual([m["mount"] for m in body["members"]],
                         ["/Volumes/Vault"])

    def test_cfg_raising_outright_degrades_to_defaults(self):
        with (
            mock.patch.object(storage_svc, "list_volumes",
                              return_value=[dict(_VAULT)]),
            mock.patch.object(storage_pool_svc, "cfg",
                              side_effect=RuntimeError("cfg boom")),
        ):
            resp = _client().get("/api/storage/pool?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertIs(body["configured"], False)
        self.assertIn("/Volumes/Vault",
                      [c["mount"] for c in body["unassigned"]])


class PoolMembersIterBombTests(_PoolConfigSeam):
    """A list-subclass ``members`` whose bound ``__iter__`` raises: the
    unbound ``list.__iter__`` reads the real items, so the configured
    member still resolves against the live candidate."""

    def test_iter_bomb_members_still_resolve(self):
        pool = dict(_POOL, members=_IterBombList(["/Volumes/Vault"]))
        body = self.overview({"settings": {"storage_pool": pool}})
        self.assertEqual([m["mount"] for m in body["members"]],
                         ["/Volumes/Vault"])
        self.assertEqual(body["missing_members"], [])


class PoolTextSubclassBombTests(_PoolConfigSeam):
    """Member/name values wearing subclass protocol bombs through ``_text``:
    the unbound-base views render the real content, and only the truly
    unrenderable (an over-digit-cap int) degrades to absent."""

    def test_int_str_bomb_member_renders_as_missing_digits(self):
        pool = dict(_POOL, members=[_StrBombInt(7), "/Volumes/Vault"])
        body = self.overview({"settings": {"storage_pool": pool}})
        self.assertEqual([m["mount"] for m in body["members"]],
                         ["/Volumes/Vault"])
        # int.__index__ launders the subclass; the real digits render as a
        # missing member instead of 500ing (or silently vanishing).
        self.assertEqual(body["missing_members"], ["7"])

    def test_over_cap_int_subclass_member_drops_alone(self):
        """10**5000 is arithmetic, so it exists uncapped; its str() is the
        digit-cap ValueError.  The unrenderable member drops, the sane
        sibling still resolves."""
        pool = dict(_POOL, members=[_StrBombInt(10 ** 5000), "/Volumes/Vault"])
        body = self.overview({"settings": {"storage_pool": pool}})
        self.assertEqual([m["mount"] for m in body["members"]],
                         ["/Volumes/Vault"])
        self.assertEqual(body["missing_members"], [])

    def test_selfstr_encode_bomb_member_still_matches_the_candidate(self):
        pool = dict(_POOL, members=[_SelfStrEncodeBomb("/Volumes/Vault")])
        body = self.overview({"settings": {"storage_pool": pool}})
        self.assertEqual([m["mount"] for m in body["members"]],
                         ["/Volumes/Vault"])

    def test_selfstr_encode_bomb_name_renders_the_real_text(self):
        pool = dict(_POOL, name=_SelfStrEncodeBomb("media"))
        body = self.overview({"settings": {"storage_pool": pool}})
        self.assertEqual(body["name"], "media")

    def test_decode_bomb_bytes_name_renders_the_real_text(self):
        pool = dict(_POOL, name=_DecodeBombBytes(b"media"))
        body = self.overview({"settings": {"storage_pool": pool}})
        self.assertEqual(body["name"], "media")

    def test_eq_bomb_name_degrades_to_the_default(self):
        pool = dict(_POOL, name=_EqBomb())
        body = self.overview({"settings": {"storage_pool": pool}})
        self.assertEqual(body["name"], "pool")

    def test_getattr_bomb_name_degrades_to_the_default(self):
        pool = dict(_POOL, name=_GetattrBomb())
        body = self.overview({"settings": {"storage_pool": pool}})
        self.assertEqual(body["name"], "pool")

    def test_getitem_bomb_list_name_renders_the_real_first_item(self):
        # The unbound ``list.__getitem__`` reads the real storage underneath
        # the override, so the first-item convention keeps working.
        pool = dict(_POOL, name=_GetItemBombList(["media"]))
        body = self.overview({"settings": {"storage_pool": pool}})
        self.assertEqual(body["name"], "media")

    def test_min_free_float_and_bool_bombs_degrade_to_zero(self):
        pool = dict(_POOL, min_free_gb=_FloatBoolBomb(1.0))
        body = self.overview({"settings": {"storage_pool": pool}})
        self.assertIs(body["configured"], True)


class PoolMutationsNextToBombedConfigTests(unittest.TestCase):
    """Save and clear re-read the config for the overview they answer with;
    a bombed stored block must not 500 the mutation *after* its write had
    already landed."""

    def setUp(self):
        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)
        self.settings = {"storage_pool": _GetBombDict(
            dict(_POOL, members=_IterBombList(["/Volumes/Vault"]),
                 name=_SelfStrEncodeBomb("media")),
        )}
        for patcher in (
            mock.patch.object(
                storage_pool_svc, "update_settings",
                side_effect=lambda p: self.settings.update(p) or self.settings,
            ),
            mock.patch.object(
                storage_pool_svc, "cfg",
                side_effect=lambda: {"settings": self.settings},
            ),
            mock.patch.object(
                storage_svc, "list_volumes", return_value=[dict(_VAULT)]
            ),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_save_over_a_bombed_block_lands_200(self):
        resp = _client().post(
            "/api/storage/pool/save",
            json={"mounts": ["/Volumes/Vault"], "policy": "most-free",
                  "name": "media"},
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIs(resp.json()["applied"], True)
        self.assertEqual(self.settings["storage_pool"]["members"],
                         ["/Volumes/Vault"])

    def test_clear_over_a_bombed_block_lands_200(self):
        resp = _client().post("/api/storage/pool/clear")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertIs(body["configured"], False)
        self.assertIs(body["applied"], True)
        self.assertEqual(self.settings["storage_pool"]["members"], [])


class PoolHugeIntBodyStaysImmuneTests(unittest.TestCase):
    """json.loads of a >4300-digit number literal raises ValueError, NOT
    JSONDecodeError; FastAPI's generic body-parse guard answers 400 on the
    pool mutation routes.  Pinned so a bespoke body reader cannot regress
    it to a 500."""

    def test_over_cap_int_bodies_are_400_not_500(self):
        client = _client()
        payload = ('{"mounts": ["/x"], "policy": ' + _HUGE_DIGITS + "}").encode()
        for path in ("/api/storage/pool/plan", "/api/storage/pool/save"):
            resp = client.post(
                path, content=payload,
                headers={"content-type": "application/json"},
            )
            self.assertEqual(resp.status_code, 400, resp.text[:200])
            resp.content.decode("utf-8")


class PoolTextUnitPins(unittest.TestCase):
    """Direct ``_text`` pins for the unbound-base scrub shapes."""

    def test_bomb_shapes_render_the_real_content(self):
        self.assertEqual(
            storage_pool_svc._text(_DecodeBombBytes(b"ok")), "ok")
        self.assertEqual(
            storage_pool_svc._text(_SelfStrEncodeBomb("ok")), "ok")
        self.assertEqual(storage_pool_svc._text(_StrBombInt(42)), "42")

    def test_surrogates_still_launder_through_the_unbound_encode(self):
        self.assertEqual(
            storage_pool_svc._text(_SelfStrEncodeBomb("a\ud800b")), "a?b")

    def test_truly_unrenderable_degrades_to_empty(self):
        self.assertEqual(storage_pool_svc._text(_StrBombInt(10 ** 5000)), "")
        self.assertEqual(storage_pool_svc._text(_EqBomb()), "")
        self.assertEqual(storage_pool_svc._text(_GetattrBomb()), "")
        self.assertEqual(storage_pool_svc._text(_FloatBoolBomb(3.5)), "")
        # The getitem-bomb list is *renderable*: the unbound view reads the
        # real first item.
        self.assertEqual(storage_pool_svc._text(_GetItemBombList(["x"])), "x")

    def test_isoformat_chain_recursion_degrades_to_empty(self):
        """A leftover isoformat *chain* (A stamps B, B stamps A) slips the
        ``stamped is raw`` identity probe and used to RecursionError out of
        the coercer."""
        class _A:
            def isoformat(self):
                return _B()

        class _B:
            def isoformat(self):
                return _A()

        self.assertEqual(storage_pool_svc._text(_A()), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
