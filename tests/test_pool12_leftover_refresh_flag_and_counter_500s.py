"""Twelfth leftover-500s sweep of the storage-pool routes, over the real app.

pool11 sealed the placement-policy ``__eq__`` bomb and canonicalized what
plan/save echo and persist.  This sweep hunted the coercions *after* that
gate — the parameters and helper answers the earlier sweeps never
laundered — and found two still live:

* **Refresh-flag ``__bool__`` bombs.**  ``pool_overview`` opened with
  ``if not force:``, and ``not`` reflects into the flag's own ``__bool__``
  (or ``__len__``) — the one public parameter left unlaundered after
  mounts / policy / name / min_free_gb were sealed.  The route hands over
  a FastAPI-exact ``bool``, but the overview is also called in-process,
  and a leftover flag whose ``__bool__`` raises detonated the reader
  itself with a RuntimeError one line ahead of every guard — the same
  reader ``save_pool`` / ``clear_pool`` re-enter after their config
  writes.  ``_wants_refresh`` answers the truth test under a try; a flag
  that cannot say whether it is truthy degrades to a *fresh* rebuild,
  because re-reading ``df`` can never lie while serving the cache to a
  caller of unknowable intent can.

* **Round-robin counter bombs.**  ``_pick_target`` stepped the rotation
  with ``counter % len(usable)``, which reflects into the counter's own
  ``__mod__`` — so the one leftover an advancing round-robin caller could
  hand it (an int-subclass whose arithmetic raises) detonated the
  placement pick.  The guarded unbound ``int.__index__`` reads the real
  number underneath a subclass override and degrades junk to step 0, the
  same answer a fresh counter gives.  The policy compares in the same
  helper now route through ``_match_policy``, so a str-subclass ``__eq__``
  bomb handed directly to the helper degrades to the most-free fallback
  it always had for unknown policies.

Stays-immune pins re-probed alongside (the do-not-weaken set): the
guarded ``cfg()`` read, the unbound config reads under a hostile
dict-subclass block, the ``type(raw) is bool`` gate in ``_text``, the
pool11 policy pins over HTTP, and the route-level exact-bool coercion.
"""
from __future__ import annotations

import unittest
from unittest import mock

from fastapi import HTTPException

from hub import storage_pool_svc, storage_svc

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

_ANNEX = dict(_VAULT, device="/dev/disk7s1", mount="/Volumes/Annex",
              disk_id="disk7", avail_gb=4.0, pct=60)

_POOL = {
    "name": "media",
    "members": ["/Volumes/Vault"],
    "policy": "most-free",
    "min_free_gb": 0,
}


class _BoolBombInt(int):
    """A real int subclass whose ``__bool__`` raises: ``not force`` used to
    dispatch straight into it."""

    def __bool__(self):
        raise RuntimeError("leftover force __bool__ bomb")


class _BoolBombObj:
    """A bare object whose ``__bool__`` raises — not even int-shaped."""

    def __bool__(self):
        raise RuntimeError("leftover force __bool__ bomb (obj)")


class _LenBombObj:
    """No ``__bool__`` at all: truth testing falls back to ``__len__``."""

    def __len__(self):
        raise RuntimeError("leftover force __len__ bomb")


class _CounterBomb(int):
    """An int subclass whose arithmetic raises: ``counter % len(usable)``
    reflected into ``__mod__`` before the guard existed."""

    def __mod__(self, other):
        raise RuntimeError("leftover counter __mod__ bomb")

    def __int__(self):
        raise RuntimeError("leftover counter __int__ bomb")


class _EqBombStr(str):
    """The pool11 policy bomb, re-aimed at ``_pick_target`` directly."""

    def __eq__(self, other):
        raise RuntimeError("leftover policy __eq__ bomb")

    __ne__ = __eq__
    __hash__ = str.__hash__


class _GetBombDict(dict):
    """A dict subclass whose bound ``.get`` raises; the unbound reads must
    keep bypassing it."""

    def get(self, *a, **k):
        raise RuntimeError("leftover .get bomb")


class _ClassBomb:
    """``__class__`` is a raising property: bare ``isinstance`` detonates."""

    @property
    def __class__(self):
        raise RuntimeError("leftover __class__ bomb")


def _wrap(pool_block) -> dict:
    return {"settings": {"storage_pool": pool_block}}


class _PoolSeam(unittest.TestCase):
    def setUp(self):
        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)

    def _overview_http(self, cfg_ret, volumes=None):
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


class RefreshFlagBoolBombNoLonger500sTests(_PoolSeam):
    """A leftover refresh flag whose truth test raises used to detonate
    ``pool_overview`` itself for in-process callers."""

    def test_bool_bomb_force_answers_the_healthy_view(self):
        for label, force in {
            "int_subclass": _BoolBombInt(1),
            "bare_object": _BoolBombObj(),
            "len_bomb": _LenBombObj(),
        }.items():
            with self.subTest(kind=label):
                storage_pool_svc.invalidate_pool()
                with (
                    mock.patch.object(storage_svc, "list_volumes",
                                      return_value=[dict(_VAULT)]),
                    mock.patch.object(storage_pool_svc, "cfg",
                                      return_value=_wrap(dict(_POOL))),
                ):
                    body = storage_pool_svc.pool_overview(force=force)
                self.assertIn("/Volumes/Vault",
                              [m["mount"] for m in body["members"]])
                self.assertIn(body["policy"],
                              storage_pool_svc.PLACEMENT_POLICIES)

    def test_bool_bomb_force_still_sees_a_changed_world_after_invalidate(self):
        """An unanswerable flag degrades to a refresh, so after an
        invalidate it rebuilds and reports the new volume set instead of
        raising out of the reader."""
        with mock.patch.object(storage_pool_svc, "cfg",
                               return_value=_wrap(dict(_POOL))):
            with mock.patch.object(storage_svc, "list_volumes",
                                   return_value=[dict(_VAULT)]):
                storage_pool_svc.pool_overview(force=True)  # seed the cache
            storage_pool_svc.invalidate_pool()
            with mock.patch.object(storage_svc, "list_volumes",
                                   return_value=[dict(_VAULT), dict(_ANNEX)]):
                body = storage_pool_svc.pool_overview(force=_BoolBombObj())
        self.assertIn("/Volumes/Annex",
                      [c["mount"] for c in body["unassigned"]])

    def test_exact_bools_keep_their_meaning(self):
        """The laundering must not turn the route's real ``False`` into a
        refresh: a cached view is still served for the plain read."""
        with mock.patch.object(storage_pool_svc, "cfg",
                               return_value=_wrap(dict(_POOL))):
            with mock.patch.object(storage_svc, "list_volumes",
                                   return_value=[dict(_VAULT)]):
                storage_pool_svc.pool_overview(force=True)
            # list_volumes now raises: only a rebuild would notice.
            with mock.patch.object(storage_svc, "list_volumes",
                                   side_effect=AssertionError("rebuilt")):
                body = storage_pool_svc.pool_overview(force=False)
        self.assertIn("/Volumes/Vault",
                      [m["mount"] for m in body["members"]])


class PickTargetCounterBombNoLonger500sTests(unittest.TestCase):
    """The round-robin step used to run the counter's own ``__mod__``."""

    _MEMBERS = [
        {"mount": "/Volumes/Vault", "avail_gb": 9.0, "pct": 10},
        {"mount": "/Volumes/Annex", "avail_gb": 4.0, "pct": 60},
    ]

    def test_counter_bomb_keeps_its_real_number(self):
        """The unbound ``int.__index__`` reads the real 1 underneath the
        ``__mod__`` / ``__int__`` overrides, so the rotation the caller
        meant is honoured instead of raising (the ``_text`` rule)."""
        picked = storage_pool_svc._pick_target(
            [dict(m) for m in self._MEMBERS], "round-robin",
            counter=_CounterBomb(1),
        )
        self.assertEqual(picked, "/Volumes/Annex")

    def test_junk_counters_degrade_instead_of_raising(self):
        for label, counter in {
            "none": None,
            "text": "3",
            "float": 1.5,
            "class_bomb": _ClassBomb(),
        }.items():
            with self.subTest(kind=label):
                picked = storage_pool_svc._pick_target(
                    [dict(m) for m in self._MEMBERS], "round-robin",
                    counter=counter,
                )
                self.assertEqual(picked, "/Volumes/Vault")

    def test_exact_counters_keep_rotating(self):
        for counter, expected in ((0, "/Volumes/Vault"),
                                  (1, "/Volumes/Annex"),
                                  (2, "/Volumes/Vault")):
            with self.subTest(counter=counter):
                picked = storage_pool_svc._pick_target(
                    [dict(m) for m in self._MEMBERS], "round-robin",
                    counter=counter,
                )
                self.assertEqual(picked, expected)

    def test_policy_eq_bomb_degrades_to_most_free(self):
        """Handed directly to the helper, a policy ``__eq__`` bomb takes the
        same most-free fallback every unknown policy always had."""
        picked = storage_pool_svc._pick_target(
            [dict(m) for m in self._MEMBERS], _EqBombStr("round-robin"),
        )
        self.assertEqual(picked, "/Volumes/Vault")  # most free, not a raise

    def test_known_policies_keep_their_answers(self):
        for policy, expected in (("most-free", "/Volumes/Vault"),
                                 ("least-used-pct", "/Volumes/Vault"),
                                 ("round-robin", "/Volumes/Vault")):
            with self.subTest(policy=policy):
                picked = storage_pool_svc._pick_target(
                    [dict(m) for m in self._MEMBERS], policy,
                )
                self.assertEqual(picked, expected)


class PoolStaysImmunePins(_PoolSeam):
    """Seams this sweep re-probed and found already sound: pinned so a
    regression cannot ship silently (the do-not-weaken set)."""

    def test_cfg_that_raises_still_answers_the_default_view(self):
        """Pins the try around ``cfg()`` in ``_pool_config``."""
        storage_pool_svc.invalidate_pool()
        with (
            mock.patch.object(storage_svc, "list_volumes",
                              return_value=[dict(_VAULT)]),
            mock.patch.object(storage_pool_svc, "cfg",
                              side_effect=RuntimeError("snapshot bomb")),
        ):
            resp = _client().get("/api/storage/pool?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertFalse(body["configured"])
        self.assertIn("/Volumes/Vault",
                      [c["mount"] for c in body["unassigned"]])

    def test_get_bomb_config_block_still_reads_through_unbound_get(self):
        """Pins ``_mapping_get``'s unbound ``dict.get`` under a subclass."""
        body = self._overview_http(
            {"settings": _GetBombDict(storage_pool=_GetBombDict(_POOL))}
        )
        self.assertIn("/Volumes/Vault",
                      [m["mount"] for m in body["members"]])

    def test_bool_config_scalars_stay_behind_the_exact_type_gate(self):
        """Pins ``type(raw) is bool`` in ``_text``: a YAML ``name: true``
        reads as the default, and a bool member drops, without a 500."""
        body = self._overview_http(
            _wrap({"name": True, "members": [True, "/Volumes/Vault"],
                   "policy": "most-free", "min_free_gb": 0})
        )
        self.assertEqual(body["name"], "pool")
        self.assertIn("/Volumes/Vault",
                      [m["mount"] for m in body["members"]])

    def test_plan_policy_eq_bomb_still_earns_the_coded_refusal(self):
        """Re-pins pool11: ``_match_policy`` absorbs the bomb in-process."""
        with mock.patch.object(storage_svc, "list_volumes",
                               return_value=[dict(_VAULT)]):
            with self.assertRaises(HTTPException) as caught:
                storage_pool_svc.plan_pool(["/Volumes/Vault"],
                                           policy=_EqBombStr("nope"))
        self.assertEqual(caught.exception.status_code, 400)
        self.assertEqual(caught.exception.detail["code"],
                         "storage_pool.bad_policy")

    def test_route_force_coercion_stays_a_4xx(self):
        """FastAPI's exact-bool query coercion refuses junk before the
        service ever runs — a 4xx, never a 500."""
        with mock.patch.object(storage_svc, "list_volumes",
                               return_value=[dict(_VAULT)]):
            resp = _client().get("/api/storage/pool?force=maybe")
        self.assertGreaterEqual(resp.status_code, 400)
        self.assertLess(resp.status_code, 500, resp.text[:200])
        resp.content.decode("utf-8")


class PoolHelperUnitPins(unittest.TestCase):
    """Direct pins for the new guards."""

    def test_wants_refresh_absorbs_truth_bombs(self):
        for bomb in (_BoolBombInt(1), _BoolBombObj(), _LenBombObj()):
            self.assertIs(storage_pool_svc._wants_refresh(bomb), True)

    def test_wants_refresh_keeps_exact_bools_and_plain_truthiness(self):
        self.assertIs(storage_pool_svc._wants_refresh(True), True)
        self.assertIs(storage_pool_svc._wants_refresh(False), False)
        self.assertIs(storage_pool_svc._wants_refresh(None), False)
        self.assertIs(storage_pool_svc._wants_refresh(1), True)
        self.assertIs(storage_pool_svc._wants_refresh(""), False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
