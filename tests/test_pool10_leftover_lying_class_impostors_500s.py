"""Tenth leftover-500s sweep of the storage-pool routes, over the real app.

pool9 armoured the config read against *raising* ``__class__``-property
bombs (``_isa``) and hash-shadowing key bombs (``_mapping_get``).  This
sweep hunted the next class over — impostors that *pass* ``_isa`` — and
five vectors reproduced as live 500s against ``create_app()`` with
``raise_server_exceptions=False``:

* **Lying ``__class__`` impostors.**  A leftover whose ``__class__``
  property answers ``list`` without being one passes ``_isa`` cleanly,
  and the unbound ``list.__iter__(members_raw)`` walk in ``_pool_config``
  then TypeError'd *outside* every try ("descriptor '__iter__' requires a
  'list' object") — 500ing all four pool routes at once (GET
  /api/storage/pool, plan, save, and clear *after* its config write had
  already landed).  ``_sequence_rows`` keeps the descriptor's
  bypass-the-override property for real subclasses and takes the empty
  branch for impostors.

* **Flaky ``__class__`` bombs.**  A property that answers once and raises
  on the next look passed ``_isa``'s guarded probe and then detonated the
  *bare* ``isinstance`` one line later — ``_text``'s
  ``base = list if isinstance(raw, list) else tuple`` pick — through the
  ``members`` block, one member value, the ``name``, or the ``policy``.
  Every base pick in ``_text`` now goes through ``_isa``, and a mispicked
  base for an impostor just TypeErrors the unbound call inside its try.

In-process callers (the routes hand over Pydantic-exact shapes, so these
never rode HTTP): ``plan_pool``/``save_pool`` with a lying-list ``mounts``
raised the same descriptor TypeError instead of the coded
``storage_pool.no_members`` refusal, and a ``min_free_gb`` whose
``__bool__`` raises blew ``save_pool``'s ``or 0`` probe past its narrow
except tuple.

Field-level upgrades pinned alongside: ``_finite_float``/``_finite_int``
dropped the *whole healthy row* when one ``df`` field carried a subclass
``__eq__``/``__float__`` bomb (the ``raw in (None, "")`` probe / the
narrow except tuple); they now degrade only the field.  The bool gate is
``type(raw) is bool`` — ``type`` never reflects into a lying
``__class__``, and bool cannot be subclassed — so an int-subclass
*claiming* bool renders its digits instead of silently reading as ""/0.

Stays-immune pins: lying-dict impostors at every config nesting level
(the guarded unbound ``dict.get`` TypeErrors inside its try), a lying
volumes listing / volume row, and the huge-number JSON body on plan/save
(``json.loads`` raises the 4300-digit ValueError, *not* JSONDecodeError —
already answered 400, pinned so it stays that way).
"""
from __future__ import annotations

import unittest
from unittest import mock

from fastapi import HTTPException

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


class _LyingList:
    """Not a list, but claims to be: passes ``_isa`` and then blows the
    unbound ``list.__iter__`` descriptor with a TypeError."""

    @property
    def __class__(self):
        return list


class _LyingDict:
    @property
    def __class__(self):
        return dict


class _FlakyClass:
    """``__class__`` answers ``list`` once, then raises: passes ``_isa``'s
    guarded probe and detonates the next *bare* ``isinstance``."""

    def __init__(self):
        self._looks = 0

    @property
    def __class__(self):
        self._looks += 1
        if self._looks > 1:
            raise RuntimeError("leftover flaky __class__ bomb")
        return list


class _BoolLiarInt(int):
    """Real int subclass whose ``__class__`` lies as bool: ``type`` tells
    the truth, ``isinstance(x, bool)`` does not."""

    @property
    def __class__(self):
        return bool


class _EqBombFloat(float):
    def __eq__(self, other):
        raise RuntimeError("leftover __eq__ bomb")

    __ne__ = __eq__
    __hash__ = float.__hash__


class _FloatBomb(float):
    def __float__(self):
        raise RuntimeError("leftover __float__ bomb")


class _BoolBombFloat(float):
    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")


def _wrap(pool_block) -> dict:
    return {"settings": {"storage_pool": pool_block}}


class _PoolSeam(unittest.TestCase):
    def setUp(self):
        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)

    def _overview(self, cfg_ret, volumes=None):
        # force=true skips the outer cache read but the single-flight
        # double-check still serves a fresh snapshot; drop it so back-to-back
        # probes in one test each see their own poison.
        storage_pool_svc.invalidate_pool()
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

    def _restorable_yaml(self):
        """services.yaml snapshot/restore for cases that really write it."""
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


class PoolLyingImpostorNoLonger500sTests(_PoolSeam):
    """A lying ``__class__`` impostor as the members block passes ``_isa``
    and used to TypeError the unbound ``list.__iter__`` outside every try."""

    def test_lying_list_members_degrade_to_unconfigured(self):
        body = self._overview(_wrap(dict(_POOL, members=_LyingList())))
        self.assertIs(body["configured"], False)
        # The healthy candidate still renders as unassigned.
        self.assertIn("/Volumes/Vault",
                      [c["mount"] for c in body["unassigned"]])

    def test_clear_after_write_answers_200_over_lying_members(self):
        """clear rebuilds the overview *after* its config write landed; the
        impostor used to turn that into a 500 with the write kept."""
        self._restorable_yaml()
        with (
            mock.patch.object(storage_svc, "list_volumes",
                              return_value=[dict(_VAULT)]),
            mock.patch.object(storage_pool_svc, "cfg",
                              return_value=_wrap(dict(_POOL,
                                                      members=_LyingList()))),
        ):
            resp = _client().post("/api/storage/pool/clear")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIs(resp.json()["applied"], True)


class PoolFlakyClassBombNoLonger500sTests(_PoolSeam):
    """A flaky ``__class__`` (answers once, raises next) passed ``_isa`` and
    detonated ``_text``'s bare ``isinstance`` base pick one line later."""

    def test_flaky_members_block_degrades_to_unconfigured(self):
        body = self._overview(_wrap(dict(_POOL, members=_FlakyClass())))
        self.assertIs(body["configured"], False)
        self.assertIn("/Volumes/Vault",
                      [c["mount"] for c in body["unassigned"]])

    def test_flaky_member_value_keeps_the_healthy_sibling(self):
        body = self._overview(
            _wrap(dict(_POOL, members=[_FlakyClass(), "/Volumes/Vault"]))
        )
        self.assertIn("/Volumes/Vault",
                      [m["mount"] for m in body["members"]])

    def test_flaky_name_defaults_and_pool_still_renders(self):
        body = self._overview(_wrap(dict(_POOL, name=_FlakyClass())))
        self.assertEqual(body["name"], "pool")
        self.assertIn("/Volumes/Vault",
                      [m["mount"] for m in body["members"]])

    def test_flaky_policy_falls_back_to_a_valid_placement(self):
        body = self._overview(_wrap(dict(_POOL, policy=_FlakyClass())))
        self.assertIn(body["policy"], storage_pool_svc.PLACEMENT_POLICIES)
        self.assertIn("/Volumes/Vault",
                      [m["mount"] for m in body["members"]])


class PoolRowFieldBombsDegradeFieldLevelTests(_PoolSeam):
    """One poisoned ``df`` field used to throw the whole healthy row away
    through ``_candidates``' per-row try; it now degrades only the field."""

    def test_eq_bomb_total_keeps_the_row_and_its_real_value(self):
        body = self._overview(
            _wrap(dict(_POOL)),
            volumes=[dict(_VAULT, total_gb=_EqBombFloat(7.0))],
        )
        rows = {m["mount"]: m for m in body["members"]}
        self.assertIn("/Volumes/Vault", rows)
        # float() never consults __eq__, so the honest number survives.
        self.assertEqual(rows["/Volumes/Vault"]["total_gb"], 7.0)

    def test_float_bomb_avail_zeroes_the_field_only(self):
        body = self._overview(
            _wrap(dict(_POOL)),
            volumes=[dict(_VAULT, avail_gb=_FloatBomb(9.0))],
        )
        rows = {m["mount"]: m for m in body["members"]}
        self.assertIn("/Volumes/Vault", rows)
        self.assertEqual(rows["/Volumes/Vault"]["avail_gb"], 0.0)

    def test_bool_liar_int_field_renders_its_digits(self):
        """type(raw) is bool, not isinstance: an int-subclass lying as bool
        used to silently read as 0 through the bool gate."""
        body = self._overview(
            _wrap(dict(_POOL)),
            volumes=[dict(_VAULT, pct=_BoolLiarInt(42))],
        )
        rows = {m["mount"]: m for m in body["members"]}
        self.assertEqual(rows["/Volumes/Vault"]["pct"], 42)


class PoolStaysImmunePins(_PoolSeam):
    """Seams this sweep re-probed and found already hardened: pinned so a
    regression cannot ship silently."""

    def test_lying_dict_impostors_degrade_at_every_config_level(self):
        for label, cfg_ret in {
            "root": _LyingDict(),
            "settings": {"settings": _LyingDict()},
            "storage_pool": _wrap(_LyingDict()),
        }.items():
            with self.subTest(level=label):
                body = self._overview(cfg_ret)
                self.assertIs(body["configured"], False)
                self.assertIn("/Volumes/Vault",
                              [c["mount"] for c in body["unassigned"]])

    def test_lying_listing_and_row_degrade_without_500(self):
        body = self._overview(_wrap(dict(_POOL)), volumes=_LyingList())
        self.assertEqual(body["members"], [])
        self.assertEqual(body["missing_members"], ["/Volumes/Vault"])
        body = self._overview(_wrap(dict(_POOL)),
                              volumes=[_LyingDict(), dict(_VAULT)])
        self.assertIn("/Volumes/Vault",
                      [m["mount"] for m in body["members"]])

    def test_bool_liar_min_free_keeps_the_pool_configured(self):
        body = self._overview(_wrap(dict(_POOL,
                                         min_free_gb=_BoolLiarInt(3))))
        self.assertIs(body["configured"], True)
        self.assertIn("/Volumes/Vault",
                      [m["mount"] for m in body["members"]])

    def test_huge_number_json_body_is_a_400_not_a_500(self):
        """json.loads raises the 4300-digit ValueError, *not*
        JSONDecodeError; the body-parse guard must answer 4xx."""
        huge = "9" * 5000
        for path, body in (
            ("/api/storage/pool/plan",
             '{"mounts": ["/x"], "policy": ' + huge + "}"),
            ("/api/storage/pool/save",
             '{"mounts": ["/x"], "min_free_gb": ' + huge + "}"),
        ):
            with self.subTest(path=path):
                resp = _client().post(
                    path, content=body.encode(),
                    headers={"content-type": "application/json"},
                )
                self.assertGreaterEqual(resp.status_code, 400)
                self.assertLess(resp.status_code, 500, resp.text[:200])
                resp.content.decode("utf-8")


class PoolInProcessCallerPins(_PoolSeam):
    """The routes hand over Pydantic-exact shapes; these pin the service's
    own contract for in-process callers carrying leftovers."""

    def test_plan_pool_lying_mounts_earn_the_coded_refusal(self):
        for label, mounts in {
            "lying_list": _LyingList(),
            "flaky_class": _FlakyClass(),
        }.items():
            with self.subTest(kind=label):
                with mock.patch.object(storage_svc, "list_volumes",
                                       return_value=[dict(_VAULT)]):
                    with self.assertRaises(HTTPException) as caught:
                        storage_pool_svc.plan_pool(mounts)
                # Coded 4xx refusal, never the descriptor TypeError.
                self.assertLess(caught.exception.status_code, 500)

    def test_save_pool_bool_bomb_min_free_degrades_to_no_reservation(self):
        self._restorable_yaml()
        with mock.patch.object(storage_svc, "list_volumes",
                               return_value=[dict(_VAULT)]):
            out = storage_pool_svc.save_pool(
                ["/Volumes/Vault"], min_free_gb=_BoolBombFloat(1.0)
            )
        self.assertIs(out["applied"], True)
        conf = storage_pool_svc._pool_config()
        self.assertEqual(conf["min_free_gb"], 1.0)


class PoolHelperUnitPins(unittest.TestCase):
    """Direct pins for the new guards."""

    def test_sequence_rows_takes_the_empty_branch_for_impostors(self):
        self.assertEqual(storage_pool_svc._sequence_rows(_LyingList()), [])
        self.assertEqual(storage_pool_svc._sequence_rows(_FlakyClass()), [])
        self.assertEqual(storage_pool_svc._sequence_rows(None), [])
        self.assertEqual(storage_pool_svc._sequence_rows(["a"]), ["a"])
        self.assertEqual(storage_pool_svc._sequence_rows(("a",)), ["a"])

    def test_sequence_rows_still_bypasses_a_subclass_iter_override(self):
        class IterBomb(list):
            def __iter__(self):
                raise RuntimeError("leftover __iter__ bomb")

        self.assertEqual(
            storage_pool_svc._sequence_rows(IterBomb(["a"])), ["a"]
        )

    def test_text_degrades_flaky_and_lying_impostors(self):
        self.assertEqual(storage_pool_svc._text(_FlakyClass()), "")
        self.assertEqual(storage_pool_svc._text(_LyingList()), "")

    def test_finite_float_field_level_degrades(self):
        self.assertEqual(storage_pool_svc._finite_float(_EqBombFloat(7.0)),
                         7.0)
        self.assertEqual(storage_pool_svc._finite_float(_FloatBomb(9.0)),
                         0.0)
        self.assertEqual(storage_pool_svc._finite_float(_BoolLiarInt(5)),
                         5.0)
        self.assertEqual(storage_pool_svc._finite_float(True), 0.0)
        self.assertEqual(storage_pool_svc._finite_float(""), 0.0)
        self.assertEqual(storage_pool_svc._finite_float(None), 0.0)
        self.assertEqual(storage_pool_svc._finite_float(float("inf")), 0.0)

    def test_finite_int_field_level_degrades(self):
        self.assertEqual(storage_pool_svc._finite_int(_BoolLiarInt(5)), 5)
        self.assertEqual(storage_pool_svc._finite_int(_FloatBomb(9.0)), 0)
        self.assertEqual(storage_pool_svc._finite_int(True), 0)
        self.assertEqual(storage_pool_svc._finite_int("12"), 12)

    def test_pool_config_defaults_over_lying_members(self):
        with mock.patch.object(
            storage_pool_svc, "cfg",
            return_value=_wrap(dict(_POOL, members=_LyingList())),
        ):
            conf = storage_pool_svc._pool_config()
        self.assertEqual(conf["members"], [])
        self.assertEqual(conf["name"], "media")


if __name__ == "__main__":
    unittest.main(verbosity=2)
