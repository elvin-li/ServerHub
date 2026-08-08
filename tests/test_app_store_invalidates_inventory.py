"""Installing or uninstalling from the app store must stale the Apps inventory.

The Apps page serves `apps_manage_svc.inventory()` from an 8 second snapshot.
The store installs through `native_catalog`, which is a different route and does
not go through `apps_manage_svc.action()`, so it has to drop that snapshot itself.

Only the install path did.  Uninstalling left the inventory untouched, so an app
the operator had just removed went on being listed as installed until the TTL
expired -- which reads exactly like "the uninstall button did nothing".

The install path also reached in and assigned `apps_manage_svc._inv_cache["t"] = 0`
inside `except Exception: pass`.  Renaming that cache would have silently turned
invalidation off, so both paths now call a named function and these tests assert
they do.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import apps_manage_svc, native_catalog  # noqa: E402

#: A brew_formula app, so the code reaches the invalidation block. Which app does
#: not matter: invalidation happens before the method dispatch.
APP_ID = "native-syncthing"


class InvalidationOnStoreActionsTests(unittest.TestCase):
    def setUp(self):
        # Seal the execution boundary first.  Without this the test really does
        # reach `brew services stop syncthing` and `brew uninstall`: an earlier
        # version of this file spawned subprocesses against the host's Homebrew
        # and took 16s to run.  A test that can uninstall software is not a test.
        completed = mock.Mock(returncode=0, stdout="", stderr="")
        for name, kwargs in (
            ("sh", {"return_value": (0, "", "")}),
            ("invalidate_brew_services", {}),
            ("_brew_list_installed", {"return_value": set()}),
        ):
            patcher = mock.patch.object(native_catalog, name, **kwargs)
            patcher.start()
            self.addCleanup(patcher.stop)
        run_patcher = mock.patch.object(
            native_catalog.subprocess, "run", return_value=completed
        )
        run_patcher.start()
        self.addCleanup(run_patcher.stop)

        self.invalidate = mock.patch.object(
            apps_manage_svc, "invalidate_inventory"
        ).start()
        self.addCleanup(mock.patch.stopall)

    def _run_guarded(self, fn, *args, **kwargs):
        """Call *fn*, tolerating whatever the sealed-off tail of it reports.

        The assertions are about the invalidation that happens before the method
        dispatch; with every executor mocked out, the dispatch's own verdict does
        not matter here.
        """
        try:
            fn(*args, **kwargs)
        except Exception:
            pass

    def test_install_invalidates_the_apps_inventory(self):
        self._run_guarded(native_catalog.install_native, APP_ID)
        self.assertTrue(
            self.invalidate.called,
            "installing did not stale the Apps inventory, so the new app stays "
            "hidden from the Apps page for up to _INV_TTL",
        )

    def test_uninstall_invalidates_the_apps_inventory(self):
        self._run_guarded(native_catalog.uninstall_native, APP_ID)
        self.assertTrue(
            self.invalidate.called,
            "uninstalling did not stale the Apps inventory, so the removed app "
            "keeps showing as installed for up to _INV_TTL",
        )

    def test_both_paths_also_drop_the_store_list_cache(self):
        """The store's own list has to refresh too, not just the Apps page."""
        for fn in (native_catalog.install_native, native_catalog.uninstall_native):
            native_catalog._list_cache.update(t=9e9, v=[{"id": "stale"}])
            self._run_guarded(fn, APP_ID)
            with self.subTest(fn=fn.__name__):
                self.assertIsNone(
                    native_catalog._list_cache["v"],
                    f"{fn.__name__} left the store list cache in place",
                )


class InvalidateInventoryTests(unittest.TestCase):
    def test_it_clears_the_snapshot(self):
        apps_manage_svc._inv_cache.update(t=9e9, v={"apps": ["stale"]})
        apps_manage_svc.invalidate_inventory()
        self.assertIsNone(apps_manage_svc._inv_cache["v"])
        self.assertEqual(apps_manage_svc._inv_cache["t"], 0.0)

    def test_the_next_read_is_not_served_from_the_dropped_snapshot(self):
        apps_manage_svc._inv_cache.update(t=9e9, v={"apps": ["stale"]})
        apps_manage_svc.invalidate_inventory()
        with mock.patch.object(
            apps_manage_svc, "_docker_stacks", return_value=[]
        ), mock.patch.object(
            apps_manage_svc, "_native_apps", return_value=[]
        ), mock.patch.object(apps_manage_svc, "_vms", return_value=[]):
            result = apps_manage_svc.inventory()
        self.assertNotIn(
            "stale",
            str(result),
            "inventory() served the snapshot that had just been invalidated",
        )


class SourceShapeTests(unittest.TestCase):
    def test_no_module_pokes_the_inventory_cache_from_outside(self):
        """Private-state assignment across modules is how this broke silently."""
        offenders = []
        for path in (BASE / "hub").rglob("*.py"):
            if path.name in ("apps_manage_svc.py", "__init__.py"):
                continue
            if "_inv_cache" in path.read_text():
                offenders.append(path.relative_to(BASE).as_posix())
        self.assertEqual(
            offenders,
            [],
            "these modules reach into apps_manage_svc._inv_cache instead of "
            "calling invalidate_inventory():\n" + "\n".join(offenders),
        )


if __name__ == "__main__":
    unittest.main()
