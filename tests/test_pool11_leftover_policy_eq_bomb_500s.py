"""Eleventh leftover-500s sweep of the storage-pool routes, over the real app.

pool10 sealed the *lying* ``__class__`` impostor class — values that pass
``_isa`` and then blow an unbound descriptor — across the config read and
the ``df`` row fields.  This sweep hunted the one coercion in the module
those guards never reached: the *placement policy* membership gate.

* **Policy ``__eq__`` bombs.**  ``_validate`` decided a policy with
  ``policy not in PLACEMENT_POLICIES``.  A tuple membership test compares
  each known entry against the caller's value, and the reflected compare
  dispatches into the caller value's ``__eq__`` first — so a leftover
  policy (a str-subclass whose ``__eq__`` raises, or a bare object that
  raises from ``__eq__``) detonated the gate with a RuntimeError one line
  *outside* every try.  The routes hand over a Pydantic-exact ``str`` so
  this never rode HTTP, but ``plan_pool`` / ``save_pool`` are also called
  in-process, and there the bomb 500'd the service where every other junk
  policy already earns the coded ``storage_pool.bad_policy`` refusal.
  ``_match_policy`` compares under a per-entry try, so the bomb degrades to
  that same coded refusal.

* **Lying-policy laundering.**  ``_match_policy`` hands back the *exact*
  known string, not the caller's value, so a genuine str-subclass that only
  *equals* a policy (its real content a lone surrogate, its ``__eq__`` a
  liar) is no longer echoed into the ``plan_pool`` response nor persisted
  into services.yaml by ``save_pool`` wearing its own ``__eq__`` / ``encode``
  overrides — either of which would have handed Starlette's UTF-8 encoder,
  or the YAML dumper, a value it could not render.

Stays-immune pins re-probed alongside: the GET overview's config-read
policy path (``_text`` hands ``_match_policy`` an exact str, so an
``__eq__``-bomb str-subclass stored as the policy degrades to a valid
placement without a 500), the route-level coded refusal for a plain unknown
policy string, and the huge-number JSON body that ``json.loads`` rejects
with the 4300-digit ValueError before Pydantic ever sees it.
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


class _EqBombStr(str):
    """A real str subclass whose ``__eq__`` raises: the reflected compare in
    ``policy not in PLACEMENT_POLICIES`` dispatched into it first."""

    def __eq__(self, other):
        raise RuntimeError("leftover policy __eq__ bomb")

    __ne__ = __eq__
    __hash__ = str.__hash__


class _EqBombObj:
    """A bare object whose ``__eq__`` raises — not even str-shaped."""

    def __eq__(self, other):
        raise RuntimeError("leftover policy __eq__ bomb (obj)")

    __ne__ = __eq__


class _PolicyLiar(str):
    """``__eq__`` answers True to everything while the real content is a lone
    surrogate: it *passes* the membership match but must never be echoed or
    persisted raw."""

    def __eq__(self, other):
        return True

    def __ne__(self, other):
        return False

    __hash__ = str.__hash__


def _wrap(pool_block) -> dict:
    return {"settings": {"storage_pool": pool_block}}


class _PoolSeam(unittest.TestCase):
    def setUp(self):
        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)

    def _overview(self, cfg_ret, volumes=None):
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


class PoolPolicyEqBombNoLonger500sTests(_PoolSeam):
    """A leftover policy whose ``__eq__`` raises used to detonate
    ``_validate``'s membership gate for in-process callers."""

    def test_plan_pool_eq_bomb_policy_earns_the_coded_refusal(self):
        for label, policy in {
            "str_subclass": _EqBombStr("nope"),
            "bare_object": _EqBombObj(),
        }.items():
            with self.subTest(kind=label):
                with mock.patch.object(storage_svc, "list_volumes",
                                       return_value=[dict(_VAULT)]):
                    with self.assertRaises(HTTPException) as caught:
                        storage_pool_svc.plan_pool(["/Volumes/Vault"],
                                                   policy=policy)
                # Coded 4xx refusal, never the bare RuntimeError.
                self.assertEqual(caught.exception.status_code, 400)
                self.assertEqual(caught.exception.detail["code"],
                                 "storage_pool.bad_policy")

    def test_save_pool_eq_bomb_policy_refuses_before_persisting(self):
        self._restorable_yaml()
        before = storage_pool_svc._pool_config()["members"]
        with mock.patch.object(storage_svc, "list_volumes",
                               return_value=[dict(_VAULT)]):
            with self.assertRaises(HTTPException) as caught:
                storage_pool_svc.save_pool(["/Volumes/Vault"],
                                           policy=_EqBombStr("nope"))
        self.assertEqual(caught.exception.detail["code"],
                         "storage_pool.bad_policy")
        # The rejection came from _validate, so nothing was written.
        self.assertEqual(storage_pool_svc._pool_config()["members"], before)

    def test_get_overview_survives_an_eq_bomb_config_policy(self):
        """The config-read path hands ``_match_policy`` an exact str via
        ``_text``, so an ``__eq__``-bomb policy stored in services.yaml
        degrades to a valid placement rather than 500ing GET."""
        body = self._overview(
            _wrap(dict(_POOL, policy=_EqBombStr("most-free")))
        )
        self.assertIn(body["policy"], storage_pool_svc.PLACEMENT_POLICIES)
        self.assertIn("/Volumes/Vault",
                      [m["mount"] for m in body["members"]])


class PoolPolicyCanonicalizationTests(_PoolSeam):
    """``_match_policy`` returns the exact known string, so a lying policy
    subclass is never echoed or persisted wearing its own overrides."""

    def test_plan_pool_echoes_the_canonical_exact_string(self):
        with mock.patch.object(storage_svc, "list_volumes",
                               return_value=[dict(_VAULT)]):
            out = storage_pool_svc.plan_pool(["/Volumes/Vault"],
                                             policy=_PolicyLiar("\ud800"))
        self.assertIs(type(out["policy"]), str)
        self.assertIn(out["policy"], storage_pool_svc.PLACEMENT_POLICIES)

    def test_save_pool_persists_the_canonical_exact_string(self):
        self._restorable_yaml()
        with mock.patch.object(storage_svc, "list_volumes",
                               return_value=[dict(_VAULT)]):
            out = storage_pool_svc.save_pool(["/Volumes/Vault"],
                                             policy=_PolicyLiar("\ud800"),
                                             name="media")
        self.assertIs(out["applied"], True)
        persisted = storage_pool_svc._pool_config()["policy"]
        self.assertIs(type(persisted), str)
        self.assertIn(persisted, storage_pool_svc.PLACEMENT_POLICIES)


class PoolStaysImmunePins(_PoolSeam):
    """Seams this sweep re-probed and found already sound: pinned so a
    regression cannot ship silently."""

    def test_valid_policies_round_trip_over_http(self):
        for policy in storage_pool_svc.PLACEMENT_POLICIES:
            with self.subTest(policy=policy):
                with mock.patch.object(storage_svc, "list_volumes",
                                       return_value=[dict(_VAULT)]):
                    resp = _client().post(
                        "/api/storage/pool/plan",
                        json={"mounts": ["/Volumes/Vault"], "policy": policy},
                    )
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                self.assertEqual(resp.json()["policy"], policy)

    def test_unknown_policy_string_is_a_coded_400_over_http(self):
        with mock.patch.object(storage_svc, "list_volumes",
                               return_value=[dict(_VAULT)]):
            resp = _client().post(
                "/api/storage/pool/plan",
                json={"mounts": ["/Volumes/Vault"], "policy": "raid5"},
            )
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"],
                         "storage_pool.bad_policy")

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


class PoolHelperUnitPins(unittest.TestCase):
    """Direct pins for the new guard."""

    def test_match_policy_absorbs_eq_bombs(self):
        self.assertIsNone(storage_pool_svc._match_policy(_EqBombStr("x")))
        self.assertIsNone(storage_pool_svc._match_policy(_EqBombObj()))

    def test_match_policy_returns_the_canonical_exact_string(self):
        for policy in storage_pool_svc.PLACEMENT_POLICIES:
            matched = storage_pool_svc._match_policy(policy)
            self.assertEqual(matched, policy)
            self.assertIs(type(matched), str)

    def test_match_policy_rejects_unknown_and_launders_a_liar(self):
        self.assertIsNone(storage_pool_svc._match_policy("nope"))
        self.assertIsNone(storage_pool_svc._match_policy(None))
        # A liar that equals everything takes the first canonical entry.
        liar = storage_pool_svc._match_policy(_PolicyLiar("\ud800"))
        self.assertIs(type(liar), str)
        self.assertIn(liar, storage_pool_svc.PLACEMENT_POLICIES)

    def test_pool_config_defaults_over_an_eq_bomb_policy(self):
        with mock.patch.object(
            storage_pool_svc, "cfg",
            return_value=_wrap(dict(_POOL, policy=_EqBombStr("bogus"))),
        ):
            conf = storage_pool_svc._pool_config()
        self.assertIn(conf["policy"], storage_pool_svc.PLACEMENT_POLICIES)
        self.assertEqual(conf["members"], ["/Volumes/Vault"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
