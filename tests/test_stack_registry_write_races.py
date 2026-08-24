"""The app-store stack registry must not write stale config snapshots back.

``_register_stack`` / ``_unregister_stack`` used the shape
``save_full(deepcopy(cfg()))``: read the mtime-cached config outside the write
lock, edit the copy, rewrite the whole file.  ``config.save_full``'s own
docstring names that a lost update — a concurrent install (two app-store tabs),
an uninstall, or any settings save landing between the read and the write was
silently overwritten by whichever writer finished last.  Both helpers also
assumed every ``stacks:`` row is a mapping, so one hand-edited junk row made
registration raise into its blanket ``except`` and the installed stack was
never recorded at all.

These tests hand the stale path (the ``cfg()`` snapshot) a different answer
than the file on disk: only an implementation that re-reads under the config
write lock — :func:`hub.config.mutate` — leaves the concurrent change standing.
"""
from __future__ import annotations

import os
import shutil
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hub import catalog, config  # noqa: E402


class _Sandbox(unittest.TestCase):
    def setUp(self):
        root = Path(os.environ.get("TMPDIR", "/tmp")) / (
            f"serverhub-stackreg-{os.getpid()}-{id(self)}"
        )
        (root / "data").mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        for target, value in (
            ("YAML_PATH", root / "services.yaml"),
            ("DATA_DIR", root / "data"),
            ("BASE", root),
        ):
            patched = mock.patch.object(config, target, value)
            patched.start()
            self.addCleanup(patched.stop)
        self.addCleanup(config.reload_cfg)
        self.yaml_path = root / "services.yaml"

    def _seed(self, data: dict) -> None:
        config.save_full(data)

    def _stacks(self) -> list:
        rows = config._read_disk().get("stacks")
        return rows if isinstance(rows, list) else []

    def _stale(self, data: dict):
        """Patch the cached-config reader to answer with *data*, emulating the
        window where another process has already written a newer file."""
        return mock.patch.object(config, "cfg", lambda: data)


class RegisterStackTests(_Sandbox):
    def test_register_does_not_write_back_a_stale_snapshot(self):
        # On disk: a concurrent install already registered "other", and the
        # operator saved a bookmark.  The stale snapshot predates both.
        self._seed({
            "stacks": [{"id": "other", "name": "Other", "path": "/srv/other",
                        "compose_file": "docker-compose.yml"}],
            "quick_links": [{"name": "NAS", "url": "http://nas.local"}],
        })
        with self._stale({"stacks": []}):
            catalog._register_stack("immich", "Immich", Path("/srv/immich"))
        on_disk = config._read_disk()
        ids = sorted(s.get("id") for s in self._stacks())
        self.assertEqual(ids, ["immich", "other"],
                         "registration overwrote a concurrent install")
        self.assertEqual(on_disk.get("quick_links"),
                         [{"name": "NAS", "url": "http://nas.local"}],
                         "registration wiped a concurrent settings save")

    def test_register_is_idempotent_and_skips_the_rewrite(self):
        self._seed({"stacks": [{"id": "immich", "name": "Immich",
                                "path": "/srv/immich",
                                "compose_file": "docker-compose.yml"}]})
        before = self.yaml_path.read_bytes()
        catalog._register_stack("immich", "Immich", Path("/srv/immich"))
        self.assertEqual(self.yaml_path.read_bytes(), before,
                         "a no-op registration must not rewrite services.yaml")

    def test_a_junk_stacks_row_does_not_lose_the_registration(self):
        """_as_config drops non-dict rows from the parsed view, but the raw
        write path must tolerate them too: one junk row used to raise inside
        the helper's blanket except and the install left no stacks entry."""
        self._seed({"stacks": []})
        # Bypass save_full's normalisation to plant the junk row literally.
        self.yaml_path.write_text(
            "stacks:\n- junk-string\n- id: other\n  path: /srv/other\n",
            encoding="utf-8",
        )
        catalog._register_stack("immich", "Immich", Path("/srv/immich"))
        ids = [s.get("id") for s in self._stacks() if isinstance(s, dict)]
        self.assertIn("immich", ids, "junk row swallowed the registration")

    def test_stacks_of_the_wrong_type_is_replaced_not_fatal(self):
        self._seed({})
        self.yaml_path.write_text("stacks: not-a-list\n", encoding="utf-8")
        catalog._register_stack("immich", "Immich", Path("/srv/immich"))
        self.assertEqual([s.get("id") for s in self._stacks()], ["immich"])


class UnregisterStackTests(_Sandbox):
    def test_unregister_does_not_write_back_a_stale_snapshot(self):
        self._seed({
            "stacks": [
                {"id": "immich", "name": "Immich", "path": "/srv/immich",
                 "compose_file": "docker-compose.yml"},
                {"id": "fresh", "name": "Fresh", "path": "/srv/fresh",
                 "compose_file": "docker-compose.yml"},
            ],
        })
        # Stale snapshot from before "fresh" was installed.
        stale = {"stacks": [{"id": "immich", "name": "Immich",
                             "path": "/srv/immich",
                             "compose_file": "docker-compose.yml"}]}
        with self._stale(stale):
            catalog._unregister_stack("immich", Path("/srv/immich"))
        self.assertEqual([s.get("id") for s in self._stacks()], ["fresh"],
                         "uninstall erased a concurrently installed stack")

    def test_unregister_of_an_unknown_stack_skips_the_rewrite(self):
        self._seed({"stacks": [{"id": "other", "name": "Other",
                                "path": "/srv/other",
                                "compose_file": "docker-compose.yml"}]})
        before = self.yaml_path.read_bytes()
        catalog._unregister_stack("ghost", Path("/srv/ghost"))
        self.assertEqual(self.yaml_path.read_bytes(), before)

    def test_unregister_keeps_junk_rows_rather_than_failing(self):
        self._seed({"stacks": []})
        self.yaml_path.write_text(
            "stacks:\n- junk-string\n- id: immich\n  path: /srv/immich\n",
            encoding="utf-8",
        )
        catalog._unregister_stack("immich", Path("/srv/immich"))
        ids = [s.get("id") for s in self._stacks() if isinstance(s, dict)]
        self.assertEqual(ids, [], "the target row survived the unregister")


if __name__ == "__main__":
    unittest.main()
