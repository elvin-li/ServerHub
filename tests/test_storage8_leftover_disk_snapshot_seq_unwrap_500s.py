"""Eighth leftover-500s sweep of the Storage read family.

storage7 sealed the *self-``__str__`` encode bomb* across every text scrub in
the disk-read family and left the disk-manage / disk-power / ``_jsonable``
HTTP surfaces immune to it.  Re-reproducing the remaining bomb shapes against
``create_app()`` with ``raise_server_exceptions=False`` shows those routes now
degrade cleanly, but it also surfaced the one scrub storage7 half-hardened:
``hub.disk_snapshot`` — the shared read layer *beneath* both disk-manage and
disk-power — got the unbound ``str.encode`` tail added to ``_as_text`` and
``_disk_token``, yet the *list-unwrap at the head* of both was left bare.

Its guarded siblings (``disk_manage_svc._text``, ``disk_power_svc._text``)
already wrap ``value[0] if value else ""`` in ``try/except`` so a sequence
*subclass* whose ``__bool__`` / ``__getitem__`` raises (the storage4/pool4
iteration-bomb class) costs at most its own field.  ``disk_snapshot``'s two
scrubs did not, so such a leftover raised straight out of them.

The blast radius is the reason this matters past a single dropped field:
``_disk_token`` feeds ``_whole_id`` and ``root_whole_disks`` — the set of
whole disks the panel *refuses to spin down or eject*.  A raise there does not
drop one identifier, it collapses the entire plist arm of that safety union
(``from_plist`` answers an empty set), silently narrowing boot-disk
protection.  With the guard, ``ParentWholeDisk`` degrading to "" no longer
takes the ``APFSPhysicalStores`` disks down with it.

No ``json.loads`` seam exists on these routes (plists go through
``plistlib``), so the huge-number ValueError class from the sibling sweeps
does not apply here.
"""
from __future__ import annotations

import json
import unittest
from contextlib import ExitStack
from unittest import mock

from hub import disk_snapshot


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _BoolBombList(list):
    """Passes ``isinstance(x, list)``; raises on the truthiness probe the
    list-unwrap runs before indexing."""

    def __bool__(self):
        raise RuntimeError("list bool bomb")


class _GetItemBombTuple(tuple):
    """Passes ``isinstance(x, tuple)``; raises on the ``[0]`` index."""

    def __getitem__(self, item):
        raise RuntimeError("tuple getitem bomb")


class _GetItemBombList(list):
    def __getitem__(self, item):
        raise RuntimeError("list getitem bomb")


class ScrubNeverRaisesTests(unittest.TestCase):
    """The two disk_snapshot scrubs must launder a hostile sequence to ""
    exactly like their guarded siblings — pre-fix each raised."""

    def test_disk_token_bool_bomb_sequence(self):
        self.assertEqual(disk_snapshot._disk_token(_BoolBombList(["disk0"])), "")

    def test_disk_token_getitem_bomb_sequence(self):
        self.assertEqual(disk_snapshot._disk_token(_GetItemBombList(["disk0"])), "")
        self.assertEqual(disk_snapshot._disk_token(_GetItemBombTuple(("disk0",))), "")

    def test_as_text_bool_bomb_sequence(self):
        self.assertEqual(disk_snapshot._as_text(_BoolBombList(["/mnt"])), "")

    def test_as_text_getitem_bomb_sequence(self):
        self.assertEqual(disk_snapshot._as_text(_GetItemBombList(["/mnt"])), "")

    def test_whole_id_bomb_sequence_is_empty_not_raise(self):
        # _whole_id runs _disk_token then _WHOLE_RE.match; the raise used to
        # ride straight through it into from_plist.
        self.assertEqual(disk_snapshot._whole_id(_BoolBombList(["disk0s2"])), "")


class HealthyTokensUnchangedTests(unittest.TestCase):
    """The guard must be behaviour-preserving for the plain lists/strings a
    real ``plistlib`` parse produces."""

    def test_disk_token_unwraps_first_element(self):
        self.assertEqual(disk_snapshot._disk_token(["disk4", "disk5"]), "disk4")
        self.assertEqual(disk_snapshot._disk_token(("disk3",)), "disk3")

    def test_disk_token_empty_sequence(self):
        self.assertEqual(disk_snapshot._disk_token([]), "")
        self.assertEqual(disk_snapshot._disk_token(()), "")

    def test_disk_token_plain_string(self):
        self.assertEqual(disk_snapshot._disk_token("disk0"), "disk0")

    def test_as_text_unwraps_first_element(self):
        self.assertEqual(disk_snapshot._as_text(["/Volumes/Data"]), "/Volumes/Data")

    def test_whole_id_from_partition_token(self):
        self.assertEqual(disk_snapshot._whole_id("disk0s2"), "disk0")


class RootWholeDisksSafetyUnionTests(unittest.TestCase):
    """``root_whole_disks`` is the set the panel refuses to eject / spin down.

    A hostile ``ParentWholeDisk`` sequence used to collapse the whole plist
    arm of the union — pre-fix the boot disk vanished from protection; with
    the guard the ``APFSPhysicalStores`` disks still contribute.
    """

    def _root_whole_disks(self, root_info_value):
        disk_snapshot.invalidate_disks()
        self.addCleanup(disk_snapshot.invalidate_disks)
        with ExitStack() as stack:
            # Neutralise the other two union members so the assertion isolates
            # the plist arm: no diskutil / df on the Linux CI host anyway, but
            # pin it so the test cannot pass by accident through them.
            stack.enter_context(mock.patch.object(
                disk_snapshot, "sh", lambda *a, **k: (-1, "", "not found")))
            stack.enter_context(mock.patch.object(
                disk_snapshot, "df_lines", lambda *a, **k: ()))
            stack.enter_context(mock.patch.object(
                disk_snapshot, "root_info", lambda *a, **k: root_info_value))
            return disk_snapshot.root_whole_disks(force=True)

    def test_bomb_parent_still_salvages_physical_store_disk(self):
        got = self._root_whole_disks({
            "ParentWholeDisk": _BoolBombList(["disk3"]),
            "APFSPhysicalStores": [{"APFSPhysicalStore": "disk0s2"}],
        })
        # Pre-fix: from_plist raised on the parent and returned an empty set,
        # so disk0 was unprotected.  Post-fix the store still contributes it.
        self.assertIn("disk0", got)

    def test_healthy_plist_parent_and_store_both_contribute(self):
        got = self._root_whole_disks({
            "ParentWholeDisk": "disk3",
            "APFSPhysicalStores": [{"APFSPhysicalStore": "disk0s2"}],
        })
        self.assertIn("disk3", got)
        self.assertIn("disk0", got)
        _starlette(sorted(got))


if __name__ == "__main__":
    unittest.main(verbosity=2)
