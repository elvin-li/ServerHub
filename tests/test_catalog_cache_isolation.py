"""The template cache must not hand out its own mutable objects.

``list_templates()`` memoises the parsed template list for a few seconds.
``catalog_overview()`` then *edits* what it gets back — it appends a "you
already have the native CLI" sentence to the cloudflared card's ``notes`` and
sorts the list.  Because both were operating on the cached objects, every
request re-appended the same sentence to the same dict: the note grew by ~81
characters per call and the store card eventually rendered a wall of repeated
prose.

The contract these tests pin down: a caller may freely mutate whatever the
cache returns, and the next caller must still see pristine data.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import catalog  # noqa: E402


class TestListTemplatesReturnsCopies(unittest.TestCase):
    def setUp(self):
        catalog.list_templates(force=True)

    def test_repeated_calls_do_not_share_the_list_object(self):
        a = catalog.list_templates()
        b = catalog.list_templates()
        self.assertIsNot(a, b, "the cached list itself is exposed to callers")

    def test_repeated_calls_do_not_share_item_dicts(self):
        a = catalog.list_templates()
        b = catalog.list_templates()
        if not a:
            self.skipTest("no templates on disk")
        self.assertIsNot(a[0], b[0], "cached item dicts are exposed to callers")

    def test_mutating_a_returned_item_does_not_leak_into_the_cache(self):
        first = catalog.list_templates()
        if not first:
            self.skipTest("no templates on disk")
        target = first[0]["id"]
        first[0]["notes"] = "MUTATED-BY-CALLER"
        first.append({"id": "injected"})

        second = catalog.list_templates()
        again = next((t for t in second if t.get("id") == target), None)
        self.assertIsNotNone(again)
        self.assertNotEqual(again.get("notes"), "MUTATED-BY-CALLER")
        self.assertNotIn("injected", [t.get("id") for t in second])

    def test_nested_values_are_copied_too(self):
        """``vars`` / ``ports`` are lists inside each item — shallow copy is not enough."""
        first = catalog.list_templates()
        victim = next((t for t in first if t.get("vars")), None)
        if victim is None:
            self.skipTest("no template declares vars")
        vid = victim["id"]
        victim["vars"].append({"name": "INJECTED"})

        second = catalog.list_templates()
        again = next(t for t in second if t["id"] == vid)
        self.assertNotIn("INJECTED", [v.get("name") for v in again["vars"]])


class TestCatalogOverviewIsIdempotent(unittest.TestCase):
    """The real symptom: notes must not grow with each request."""

    def test_notes_are_stable_across_calls(self):
        catalog.list_templates(force=True)
        lengths = []
        for _ in range(4):
            data = catalog.catalog_overview()
            notes = {t["id"]: len(t.get("notes") or "") for t in data["templates"]}
            lengths.append(notes)

        for tid, n in lengths[0].items():
            for later in lengths[1:]:
                self.assertEqual(
                    later.get(tid), n,
                    f"notes for {tid} changed length across identical requests",
                )

    def test_template_count_is_stable_across_calls(self):
        counts = {len(catalog.catalog_overview()["templates"]) for _ in range(3)}
        self.assertEqual(len(counts), 1, f"template count drifted: {counts}")

    def test_overview_does_not_duplicate_the_native_cli_hint(self):
        marker = "原生 cloudflared"
        for _ in range(3):
            data = catalog.catalog_overview()
        card = next((t for t in data["templates"] if t.get("id") == "cloudflared"), None)
        if card is None:
            self.skipTest("no cloudflared docker template")
        self.assertLessEqual(
            (card.get("notes") or "").count(marker), 1,
            "the native-CLI hint was appended more than once",
        )


if __name__ == "__main__":
    unittest.main()
