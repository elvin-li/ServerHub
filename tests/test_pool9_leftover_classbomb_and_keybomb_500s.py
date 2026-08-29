"""Ninth leftover-500s sweep of the storage-pool routes, over the real app.

pool8 pinned the pool7-era hardening (exotic-type config values, hostile
``df`` rows, unreadable-config mutate refusals) and found no remaining bare
500s in that zoo.  This sweep hunted two vectors the zoo never carried, and
both reproduced as live 500s against ``create_app()`` with
``raise_server_exceptions=False``:

* **``__class__``-property bombs.**  ``isinstance`` consults
  ``value.__class__`` when the exact-type check misses, so a leftover whose
  ``__class__`` is a *raising property* detonated the bare rank gates
  themselves — one line ahead of every scrub built to absorb junk shapes.
  Planted as the cfg root, the ``settings`` map, the ``storage_pool``
  block, the ``members`` list, a member value, the ``name`` or ``policy``
  scalar (through ``_text``'s first gate), a ``list_volumes`` row, or the
  listing return whole, each 500'd all four pool routes at once (GET
  /api/storage/pool, plan, save, and clear *after* its config write had
  already landed).  The sibling modules' ``_isa`` guard
  (system/status/usage_svc/shares_svc…) is the fix this module never got.

* **Hash-shadowing mapping-key bombs.**  ``_pool_config`` already read
  through the *unbound* ``dict.get``, which bypasses a subclass ``.get``
  override — but the hash probe still runs the *stored keys'* own
  ``__eq__``.  A leftover str-subclass key whose ``__hash__`` shadows
  ``"settings"`` / ``"storage_pool"`` / ``"members"`` / ``"name"`` /
  ``"policy"`` and whose ``__eq__`` raises detonated the bare ``dict.get``
  and 500'd the same four routes.  ``_mapping_get`` (the ups_svc rule)
  degrades only the shadowed field to its default.

Both are field-level degrades now: the route answers 200 with a strictly
valid UTF-8 body and the healthy sibling member/candidate keeps rendering.

Already immune (pinned here so they stay that way): the ``min_free_gb``
read under its ``except Exception`` (both bomb classes), a key bomb inside
a ``list_volumes`` row (the per-row try), list-subclass ``__bool__`` /
``__iter__`` members (the unbound ``list.__iter__`` walk), and a leftover
FIFO squatting services.yaml — ``read_text_capped`` opens O_NONBLOCK and
refuses non-regular files as EINVAL, so the config read degrades to
defaults instead of parking the worker or 500ing.
"""
from __future__ import annotations

import os
import stat
import unittest
from unittest import mock

from hub import config, storage_pool_svc, storage_svc

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


#: A complete, well-formed poolable volume row: every case below asserts that
#: *this* healthy candidate keeps rendering next to the poison.
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

_POOL = {
    "name": "media",
    "members": ["/Volumes/Vault"],
    "policy": "most-free",
    "min_free_gb": 0,
}


class _ClassBomb:
    """A leftover whose ``__class__`` is a raising property: the bare
    ``isinstance`` gate itself detonates instead of taking a branch."""

    @property
    def __class__(self):
        raise RuntimeError("leftover __class__ property bomb")


class _KeyBomb(str):
    """str-subclass mapping key: ``__hash__`` shadows the real key's slot,
    ``__eq__`` raises — so the unbound ``dict.get`` probe itself detonates."""

    def __new__(cls, target: str):
        self = str.__new__(cls, "leftover-" + target)
        self._shadow = str.__hash__(target)
        return self

    def __hash__(self):
        return self._shadow

    def __eq__(self, other):
        raise RuntimeError("leftover key __eq__ bomb")

    __ne__ = __eq__


def _shadowed(base: dict, target: str) -> dict:
    """*base* with *target*'s entry re-keyed onto a hash-shadowing bomb."""
    out = {k: v for k, v in base.items() if k != target}
    out[_KeyBomb(target)] = base.get(target)
    return out


class _BoolBombList(list):
    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")


class _IterBombList(list):
    def __iter__(self):
        raise RuntimeError("leftover __iter__ bomb")


def _wrap(pool_block) -> dict:
    return {"settings": {"storage_pool": pool_block}}


class _PoolSeam(unittest.TestCase):
    def setUp(self):
        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)

    def _overview(self, cfg_ret, volumes=None):
        if volumes is None:
            volumes = [dict(_VAULT)]
        with (
            mock.patch.object(storage_svc, "list_volumes",
                              return_value=volumes),
            mock.patch.object(storage_pool_svc, "cfg",
                              return_value=cfg_ret),
        ):
            resp = _client().get("/api/storage/pool?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        # The body must already be valid UTF-8 — decode strictly on purpose.
        resp.content.decode("utf-8")
        return resp.json()


class PoolConfigClassBombNoLonger500sTests(_PoolSeam):
    """A ``__class__``-property bomb at every nesting level of the config
    read degrades field-level instead of 500ing all four pool routes."""

    def test_bombed_config_levels_degrade_to_defaults(self):
        for label, cfg_ret in {
            "root": _ClassBomb(),
            "settings": {"settings": _ClassBomb()},
            "storage_pool": _wrap(_ClassBomb()),
            "members": _wrap(dict(_POOL, members=_ClassBomb())),
        }.items():
            with self.subTest(level=label):
                body = self._overview(cfg_ret)
                self.assertIs(body["configured"], False)
                # The healthy candidate still renders as unassigned.
                self.assertIn("/Volumes/Vault",
                              [c["mount"] for c in body["unassigned"]])

    def test_bombed_member_value_keeps_the_healthy_sibling(self):
        body = self._overview(
            _wrap(dict(_POOL, members=[_ClassBomb(), "/Volumes/Vault"]))
        )
        self.assertIn("/Volumes/Vault",
                      [m["mount"] for m in body["members"]])

    def test_bombed_name_defaults_and_pool_still_renders(self):
        body = self._overview(_wrap(dict(_POOL, name=_ClassBomb())))
        self.assertEqual(body["name"], "pool")
        self.assertIn("/Volumes/Vault",
                      [m["mount"] for m in body["members"]])

    def test_bombed_policy_falls_back_to_a_valid_placement(self):
        body = self._overview(_wrap(dict(_POOL, policy=_ClassBomb())))
        self.assertIn(body["policy"], storage_pool_svc.PLACEMENT_POLICIES)
        self.assertIn("/Volumes/Vault",
                      [m["mount"] for m in body["members"]])

    def test_clear_after_write_answers_200_over_a_bombed_snapshot(self):
        """clear rebuilds the overview *after* its config write landed; the
        bombed snapshot used to turn that into a 500 with the write kept."""
        try:
            saved = config.YAML_PATH.read_bytes()
        except OSError:
            saved = None

        def restore():
            if saved is None:
                try:
                    config.YAML_PATH.unlink()
                except OSError:
                    pass
            else:
                config.YAML_PATH.write_bytes(saved)
            config.reload_cfg()

        self.addCleanup(restore)
        with (
            mock.patch.object(storage_svc, "list_volumes",
                              return_value=[dict(_VAULT)]),
            mock.patch.object(storage_pool_svc, "cfg",
                              return_value={"settings": _ClassBomb()}),
        ):
            resp = _client().post("/api/storage/pool/clear")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIs(resp.json()["applied"], True)


class PoolConfigKeyBombNoLonger500sTests(_PoolSeam):
    """A hash-shadowing key bomb in the config maps degrades only the
    shadowed field instead of 500ing all four pool routes."""

    def test_shadowed_map_keys_degrade_to_defaults(self):
        for label, cfg_ret in {
            "settings": _shadowed(_wrap(dict(_POOL)), "settings"),
            "storage_pool": {"settings": _shadowed(
                {"storage_pool": dict(_POOL)}, "storage_pool")},
            "members": _wrap(_shadowed(dict(_POOL), "members")),
        }.items():
            with self.subTest(key=label):
                body = self._overview(cfg_ret)
                self.assertIs(body["configured"], False)
                self.assertIn("/Volumes/Vault",
                              [c["mount"] for c in body["unassigned"]])

    def test_shadowed_name_defaults_and_siblings_keep_their_values(self):
        body = self._overview(_wrap(_shadowed(dict(_POOL), "name")))
        self.assertEqual(body["name"], "pool")
        self.assertIn("/Volumes/Vault",
                      [m["mount"] for m in body["members"]])

    def test_shadowed_policy_falls_back_to_a_valid_placement(self):
        body = self._overview(_wrap(_shadowed(dict(_POOL), "policy")))
        self.assertIn(body["policy"], storage_pool_svc.PLACEMENT_POLICIES)
        self.assertIn("/Volumes/Vault",
                      [m["mount"] for m in body["members"]])


class PoolListingClassBombNoLonger500sTests(_PoolSeam):
    """``__class__``-property bombs riding the volume listing drop the
    hostile row (or the whole unreadable listing) instead of 500ing."""

    def test_bombed_row_keeps_the_healthy_sibling_rendering(self):
        body = self._overview(_wrap(dict(_POOL)),
                              volumes=[_ClassBomb(), dict(_VAULT)])
        self.assertIn("/Volumes/Vault",
                      [m["mount"] for m in body["members"]])

    def test_bombed_listing_return_reads_members_as_missing(self):
        body = self._overview(_wrap(dict(_POOL)), volumes=_ClassBomb())
        self.assertEqual(body["members"], [])
        self.assertEqual(body["missing_members"], ["/Volumes/Vault"])


class PoolStaysImmunePins(_PoolSeam):
    """Seams the sweep re-probed and found already hardened: pinned so a
    regression cannot ship silently."""

    def test_min_free_bombs_stay_guarded(self):
        for label, cfg_ret in {
            "class_bomb": _wrap(dict(_POOL, min_free_gb=_ClassBomb())),
            "key_bomb": _wrap(_shadowed(dict(_POOL), "min_free_gb")),
        }.items():
            with self.subTest(kind=label):
                body = self._overview(cfg_ret)
                self.assertIs(body["configured"], True)
                self.assertIn("/Volumes/Vault",
                              [m["mount"] for m in body["members"]])

    def test_key_bomb_inside_a_volume_row_drops_only_that_row(self):
        body = self._overview(
            _wrap(dict(_POOL)),
            volumes=[_shadowed(dict(_VAULT, mount="/Volumes/Bad"), "kind"),
                     dict(_VAULT)],
        )
        self.assertIn("/Volumes/Vault",
                      [m["mount"] for m in body["members"]])
        self.assertNotIn("/Volumes/Bad",
                         [c["mount"] for c in body["unassigned"]])

    def test_list_subclass_member_bombs_stay_guarded(self):
        for label, members in {
            "bool_bomb": _BoolBombList(["/Volumes/Vault"]),
            "iter_bomb_unbound_walk": _IterBombList(["/Volumes/Vault"]),
        }.items():
            with self.subTest(kind=label):
                body = self._overview(_wrap(dict(_POOL, members=members)))
                self.assertIs(body["configured"], True)
                self.assertIn("/Volumes/Vault",
                              [m["mount"] for m in body["members"]])

    def test_fifo_squatting_services_yaml_degrades_the_config_read(self):
        """A leftover FIFO at services.yaml: ``read_text_capped`` opens
        O_NONBLOCK and refuses non-regular files, so the pool config read
        degrades to defaults — no worker parked on open(), no 500."""
        try:
            saved = config.YAML_PATH.read_bytes()
        except OSError:
            saved = None

        def restore():
            try:
                mode = os.lstat(config.YAML_PATH).st_mode
            except OSError:
                mode = None
            if mode is not None and not stat.S_ISREG(mode):
                os.unlink(config.YAML_PATH)
            if saved is None:
                try:
                    config.YAML_PATH.unlink()
                except OSError:
                    pass
            else:
                config.YAML_PATH.write_bytes(saved)
            config.reload_cfg()

        self.addCleanup(restore)
        try:
            config.YAML_PATH.unlink()
        except OSError:
            pass
        os.mkfifo(config.YAML_PATH)
        config.reload_cfg()
        with mock.patch.object(storage_svc, "list_volumes",
                               return_value=[dict(_VAULT)]):
            resp = _client().get("/api/storage/pool?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertIs(body["configured"], False)
        self.assertIn("/Volumes/Vault",
                      [c["mount"] for c in body["unassigned"]])


class PoolHelperUnitPins(unittest.TestCase):
    """Direct pins for the new guards."""

    def test_isa_survives_a_class_property_bomb(self):
        self.assertIs(storage_pool_svc._isa(_ClassBomb(), dict), False)
        self.assertIs(storage_pool_svc._isa({}, dict), True)

    def test_mapping_get_survives_both_bomb_classes(self):
        self.assertIsNone(storage_pool_svc._mapping_get(_ClassBomb(), "x"))
        self.assertIsNone(
            storage_pool_svc._mapping_get(
                _shadowed({"name": "media"}, "name"), "name")
        )
        self.assertEqual(
            storage_pool_svc._mapping_get({"name": "media"}, "name"), "media"
        )

    def test_text_degrades_a_class_property_bomb(self):
        self.assertEqual(storage_pool_svc._text(_ClassBomb()), "")

    def test_pool_config_defaults_over_a_bombed_snapshot(self):
        with mock.patch.object(storage_pool_svc, "cfg",
                               return_value=_ClassBomb()):
            conf = storage_pool_svc._pool_config()
        self.assertEqual(conf, {"name": "pool", "members": [],
                                "policy": storage_pool_svc.DEFAULT_POLICY,
                                "min_free_gb": 0.0})


if __name__ == "__main__":
    unittest.main(verbosity=2)
