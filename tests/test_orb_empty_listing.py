"""An empty `orbctl list -f json` answer is final: no text-listing respawn.

OrbStack answers ``[]`` when it has no Linux machines.  The OrbStack inventory
used to treat that like an unusable answer and spawn `orbctl list` as well,
which on such a host doubled the cost of every refresh (~95 ms of CPU each)
for the same empty result.  The text fallback stays for answers that are not
a usable JSON list.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import vms_svc  # noqa: E402

TEXT = "NAME  STATE\nweb  running\n"


class EmptyOrbListingTests(unittest.TestCase):
    def _list(self, json_out):
        calls = []

        def fake_sh(cmd, **kwargs):
            calls.append(list(cmd))
            if "-f" in cmd:
                return 0, json_out, ""
            return 0, TEXT, ""

        with (
            mock.patch.object(vms_svc, "_orb_available", return_value=True),
            mock.patch.object(vms_svc, "sh", side_effect=fake_sh),
            mock.patch.object(vms_svc, "override", return_value={}),
        ):
            return vms_svc._list_orb_machines_uncached(), calls

    def test_an_empty_json_list_spawns_once(self):
        for answer in ("[]", " [ ]\n", b"[]"):
            with self.subTest(answer=answer):
                items, calls = self._list(answer)
                self.assertEqual(items, [])
                self.assertEqual(len(calls), 1)
                self.assertIn("-f", calls[0])

    def test_other_unusable_answers_still_read_the_text_listing(self):
        for answer in (
            '{"machines": []}',
            '{"machines": 3}',
            "[null, 42]",
            '[{"name": 1, "state": "running"}]',
            "{not json",
        ):
            with self.subTest(answer=answer):
                items, calls = self._list(answer)
                self.assertEqual([i["orb_name"] for i in items], ["web"])
                self.assertEqual(len(calls), 2)

    def test_machines_in_the_json_answer_are_unchanged(self):
        answer = json.dumps([{"name": "web", "state": "running", "distro": "ubuntu"}])
        items, calls = self._list(answer)
        self.assertEqual([i["orb_name"] for i in items], ["web"])
        self.assertEqual(items[0]["distro"], "ubuntu")
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
