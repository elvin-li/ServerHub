"""Guards for persisting a storage-pool definition.

``save_pool`` is the one writing function in an otherwise read-only module, so
the boundary it must not cross is worth pinning down in tests:

1. Saving is *config only*.  It writes membership and policy into
   services.yaml.  It must never run a command that can change disk state, and
   dropping a member must never touch that disk's files.
2. Saving must not be a weaker gate than planning.  Both go through
   ``_validate``, so a system volume rejected by the preview cannot be
   persisted through the save endpoint instead.
3. The view handed back after a save must reflect what was saved, not the
   membership that was cached a moment earlier.
"""
from __future__ import annotations

import unittest
from unittest import mock

from fastapi import HTTPException

from hub import storage_pool_svc, storage_svc

from tests.test_storage_pool import POOL, VOLS


class SaveTestBase(unittest.TestCase):
    """Runs against an in-memory settings dict; services.yaml is never opened."""

    def setUp(self):
        vols = mock.patch.object(storage_svc, "list_volumes", return_value=list(VOLS))
        vols.start()
        self.addCleanup(vols.stop)

        # Stand-in for the on-disk config.  update_settings() merges into it the
        # way hub.config does, so save/clear round-trips are observable without
        # writing to the real file.
        self.settings: dict = {}

        def fake_update(patch: dict) -> dict:
            for k, v in patch.items():
                self.settings[k] = v
            return self.settings

        upd = mock.patch.object(storage_pool_svc, "update_settings", side_effect=fake_update)
        upd.start()
        self.addCleanup(upd.stop)

        cfgp = mock.patch.object(
            storage_pool_svc, "cfg", side_effect=lambda: {"settings": self.settings}
        )
        cfgp.start()
        self.addCleanup(cfgp.stop)

        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)

    def saved(self) -> dict:
        return self.settings.get("storage_pool") or {}


class TestSaveWritesConfigOnly(SaveTestBase):
    FORBIDDEN = ("diskutil", "mount", "umount", "newfs", "mergerfs", "mount_fusefs", "ln", "rm")

    def test_save_runs_no_state_changing_command(self):
        seen: list[str] = []

        def spy(cmd, *a, **kw):
            seen.append(" ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd))
            return (0, "", "")

        with mock.patch("hub.util.sh", side_effect=spy), \
             mock.patch("subprocess.run", side_effect=AssertionError("subprocess.run called")):
            storage_pool_svc.save_pool(POOL)

        offenders = [c for c in seen if any(f in c for f in self.FORBIDDEN)]
        self.assertEqual(offenders, [], f"save ran a state-changing command: {offenders}")

    def test_clear_runs_no_state_changing_command(self):
        storage_pool_svc.save_pool(POOL)
        seen: list[str] = []

        def spy(cmd, *a, **kw):
            seen.append(" ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd))
            return (0, "", "")

        with mock.patch("hub.util.sh", side_effect=spy), \
             mock.patch("subprocess.run", side_effect=AssertionError("subprocess.run called")):
            storage_pool_svc.clear_pool()

        offenders = [c for c in seen if any(f in c for f in self.FORBIDDEN)]
        self.assertEqual(offenders, [], f"clear ran a state-changing command: {offenders}")

    def test_save_persists_members_and_policy(self):
        storage_pool_svc.save_pool(POOL, policy="least-used-pct", name="media")
        self.assertEqual(self.saved()["members"], POOL)
        self.assertEqual(self.saved()["policy"], "least-used-pct")
        self.assertEqual(self.saved()["name"], "media")

    def test_save_touches_no_other_settings_key(self):
        self.settings["unrelated"] = {"keep": True}
        storage_pool_svc.save_pool(POOL)
        self.assertEqual(self.settings["unrelated"], {"keep": True})

    def test_clear_empties_membership_but_keeps_the_disks_listed(self):
        storage_pool_svc.save_pool(POOL)
        out = storage_pool_svc.clear_pool()
        self.assertEqual(self.saved()["members"], [])
        self.assertFalse(out["configured"])
        # The disks did not go anywhere: they are candidates again, not gone.
        self.assertEqual({c["mount"] for c in out["unassigned"]}, set(POOL))


class TestSaveIsNotAWeakerGateThanPlan(SaveTestBase):
    def test_a_system_volume_cannot_be_saved(self):
        with self.assertRaises(HTTPException) as ctx:
            storage_pool_svc.save_pool(["/", "/Volumes/PhotoVault"])
        self.assertEqual(ctx.exception.detail["code"], "storage_pool.not_poolable")
        self.assertEqual(self.saved(), {}, "a refused pool was still written to config")

    def test_an_unknown_policy_cannot_be_saved(self):
        with self.assertRaises(HTTPException) as ctx:
            storage_pool_svc.save_pool(POOL, policy="stripe")
        self.assertEqual(ctx.exception.detail["code"], "storage_pool.bad_policy")
        self.assertEqual(self.saved(), {})

    def test_an_empty_member_list_cannot_be_saved(self):
        with self.assertRaises(HTTPException) as ctx:
            storage_pool_svc.save_pool([])
        self.assertEqual(ctx.exception.detail["code"], "storage_pool.no_members")
        self.assertEqual(self.saved(), {})

    def test_a_duplicated_mount_is_stored_once(self):
        """Twice in the list would double-count capacity and understate the blast radius."""
        storage_pool_svc.save_pool(["/Volumes/Archive", "/Volumes/Archive"])
        self.assertEqual(self.saved()["members"], ["/Volumes/Archive"])

    def test_a_negative_reservation_is_clamped(self):
        storage_pool_svc.save_pool(POOL, min_free_gb=-50)
        self.assertEqual(self.saved()["min_free_gb"], 0.0)

    def test_a_non_numeric_reservation_falls_back_to_zero(self):
        storage_pool_svc.save_pool(POOL, min_free_gb="lots")  # type: ignore[arg-type]
        self.assertEqual(self.saved()["min_free_gb"], 0.0)

    def test_a_blank_name_falls_back_to_a_default(self):
        storage_pool_svc.save_pool(POOL, name="   ")
        self.assertEqual(self.saved()["name"], "pool")


class TestSaveReturnsTheSavedView(SaveTestBase):
    def test_the_returned_view_reflects_the_new_membership(self):
        # Warm the cache with the empty pool first, so a stale view would show
        # zero members and be caught here.
        storage_pool_svc.pool_overview(force=True)
        out = storage_pool_svc.save_pool(POOL)
        self.assertTrue(out["configured"])
        self.assertEqual({m["mount"] for m in out["members"]}, set(POOL))
        self.assertTrue(out["applied"])

    def test_a_later_overview_agrees_with_what_was_saved(self):
        storage_pool_svc.save_pool(POOL)
        again = storage_pool_svc.pool_overview(force=True)
        self.assertEqual({m["mount"] for m in again["members"]}, set(POOL))

    def test_saving_does_not_promise_a_single_mount_point(self):
        """Config is saved, but one merged path still needs a FUSE layer."""
        out = storage_pool_svc.save_pool(POOL)
        self.assertFalse(out["union"]["single_mount_supported"])
        self.assertEqual(out["union"]["reason"], "union_fs_missing")

    def test_the_saved_view_is_still_not_raid(self):
        out = storage_pool_svc.save_pool(POOL)
        self.assertFalse(out["raid"])
        self.assertFalse(out["parity"])

    def test_replacing_membership_drops_the_removed_member_from_the_view(self):
        storage_pool_svc.save_pool(POOL)
        out = storage_pool_svc.save_pool(["/Volumes/PhotoVault"])
        self.assertEqual([m["mount"] for m in out["members"]], ["/Volumes/PhotoVault"])
        # Removed from the pool, not from the host: it is selectable again.
        self.assertIn("/Volumes/Archive", {c["mount"] for c in out["unassigned"]})


if __name__ == "__main__":
    unittest.main(verbosity=2)
