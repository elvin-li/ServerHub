"""Modules-page leftover sweep #4: the domain is already immune — HTTP pins.

A fresh hunt over the Modules page surface — GET /api/modules and the
router's never-pinned GET /api/adaptive/compose-scan — reproduced every
sweep class against the *mounted routes* (create_app + TestClient,
raise_server_exceptions=False) and found no remaining 500 and no
sibling-row wipe.  What it did find is vectors with no pin anywhere:

* whole junk rows in the registry (None, a str, an int, a >4300-digit
  int, bytes, a list, a bare object) are dropped one at a time by
  ``modules._module_row`` — prior sweeps pinned poisoned *fields* inside
  dict rows and one "not-a-module" string at the function level, but the
  route-level sibling-survival contract for whole-row junk was unpinned;
* the ``ModuleInfo`` *dataclass* arm of ``_module_row`` (``asdict`` +
  try/except) had no pin at all — every prior sweep appended plain dicts.
  A dataclass whose field recursion blows ``asdict`` (RecursionError is
  an Exception subclass) loses only its own row; a dataclass carrying a
  surrogate name, an already-int YAML-hex over-cap description, an
  over-cap category and inf ``enabled`` is scrubbed field-level like its
  dict siblings;
* a mapping key whose ``__str__`` raises drops only that entry (the
  ``except Exception: continue`` in ``_jsonable``'s dict arm), and a dict
  *subclass* whose ``items()`` raises is neutralized before iteration by
  the ``dict(m)`` copy in ``_module_row`` — both rows keep their sane
  fields;
* a finite numeric id (``id: 8080``) rides through unchanged — the
  over-cap drop is a str() probe, not an ``isinstance(id, str)`` gate
  (the union-wide numeric-id contract, previously pinned for bookmarks
  and the Gateway pid but not for registry rows);
* GET /api/adaptive/compose-scan had function-level pins only
  (test_leftover_parse_500s); at the HTTP layer an on-disk stack dir
  with a raw 0xFF byte (os surrogateescape mints a lone ``\\udcff``)
  stays 200 and encodable with the sane sibling still listed, a
  dangling-symlink compose file keeps its hint row (the scan is
  hint-only and never opens the file), and a vanished/poisoned HOME
  (Services occupied by a file, NUL ValueError, EIO OSError) answers the
  empty list, never a 500.

The remaining sweep classes do not apply: nothing on this surface spawns
a CLI (the Gateway's vanished-nginx 503 is pinned in
test_modules_gateway_leftover_stays_immune_500s), nothing signals a pid,
nothing parses JSON with ``json.loads``, and the registry is in-code with
no journal to corrupt.

Everything here passed on the tree it was written against; these are
stays-immune pins so a refactor cannot quietly reopen the routes.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml
from fastapi.testclient import TestClient

from hub import modules
from hub.auth import require_auth

#: Built arithmetically: int("9" * 5000) itself trips the digit cap.
_HUGE_INT = 10 ** 5000
#: What a leftover ``0xF…`` in hand-edited YAML loads as — already-int.
_HUGE_HEX_YAML = "0x" + "F" * 5000

_APP = None


def _client() -> TestClient:
    global _APP
    if _APP is None:
        from hub.app_factory import create_app

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _RegistrySandbox(unittest.TestCase):
    def setUp(self):
        self._saved = list(modules.MODULES)
        self.addCleanup(
            lambda: modules.MODULES.__setitem__(slice(None), self._saved)
        )
        self.client = _client()

    def _get_modules(self) -> dict:
        resp = self.client.get("/api/modules")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        return body


class ModulesRouteJunkRowTests(_RegistrySandbox):
    """Whole junk rows are dropped one at a time — never a 500, never a wipe."""

    def test_junk_rows_drop_without_taking_the_siblings(self):
        sane = len(modules.list_modules())
        modules.MODULES.extend([
            None, "junk", 7, _HUGE_INT, b"\xff\xfe", ["not", "a", "row"],
            object(),
        ])
        body = self._get_modules()
        self.assertEqual(len(body["modules"]), sane)
        # The category grouping keeps every sane row too — same count.
        grouped = sum(len(v) for v in body["by_category"].values())
        self.assertEqual(grouped, sane)
        self.assertIn(
            "dashboard", [r.get("id") for r in body["modules"]]
        )


class ModulesRouteDataclassPoisonTests(_RegistrySandbox):
    """The ``asdict`` arm of ``_module_row`` scrubs field-level, drops row-level."""

    def test_poisoned_dataclass_row_is_scrubbed_field_level(self):
        desc = yaml.safe_load("v: " + _HUGE_HEX_YAML)["v"]
        # The vector is real: the hex load bypasses the str->int cap.
        with self.assertRaises(ValueError):
            str(desc)
        modules.MODULES.append(modules.ModuleInfo(
            id="dc",
            name="n\ud800",
            description=desc,
            category=_HUGE_INT,
            apis=[_HUGE_INT, "\ud800", b"\xff", "/api/x"],
            ui_routes=["/x"],
            enabled=float("inf"),
        ))
        body = self._get_modules()
        self.assertNotIn("\ud800", json.dumps(body, ensure_ascii=False))
        row = next(r for r in body["modules"] if r.get("id") == "dc")
        # Field-level scrub, never whole-row loss: the sane fields survive.
        self.assertIsNone(row["description"])
        self.assertIn("/api/x", row["apis"])
        self.assertEqual(row["ui_routes"], ["/x"])
        # Non-str category regroups under "other"; non-bool enabled reads True.
        self.assertEqual(row["category"], "other")
        self.assertIs(row["enabled"], True)
        self.assertIn(
            "dc", [r.get("id") for r in body["by_category"].get("other", [])]
        )

    def test_recursive_dataclass_loses_only_its_own_row(self):
        """``asdict`` of a self-referential field is RecursionError — an
        Exception subclass, so the except in ``_module_row`` drops that row
        alone and the appended sane sibling survives."""
        loop: list = []
        loop.append(loop)
        sane = len(modules.list_modules())
        modules.MODULES.append(modules.ModuleInfo(
            id="rec", name="r", description="d", category="ops", apis=loop,
        ))
        modules.MODULES.append({
            "id": "sane", "name": "S", "description": "d", "category": "ops",
            "apis": [], "ui_routes": [],
        })
        body = self._get_modules()
        ids = [r.get("id") for r in body["modules"]]
        self.assertNotIn("rec", ids)
        self.assertIn("sane", ids)
        self.assertEqual(len(ids), sane + 1)


class ModulesRouteEntryDropTests(_RegistrySandbox):
    """Poison drops the entry (or is neutralized), never the row or a 500."""

    def test_raising_str_key_drops_the_entry_not_the_row(self):
        class BadStr:
            def __str__(self):
                raise RuntimeError("no str")

            __repr__ = __str__

        modules.MODULES.append({
            "id": "bs", "name": "n", "category": "ops",
            BadStr(): "keyed", "apis": [], "ui_routes": [],
        })
        body = self._get_modules()
        row = next(r for r in body["modules"] if r.get("id") == "bs")
        self.assertEqual(row["name"], "n")
        self.assertNotIn("keyed", row.values())

    def test_raising_items_subclass_is_neutralized_by_the_copy(self):
        """``dict(m)`` in ``_module_row`` copies through the C fast path, so
        a subclass whose ``items()`` raises never gets to raise inside
        ``_jsonable``'s iteration."""
        class EvilDict(dict):
            def items(self):
                raise RuntimeError("boom items")

        modules.MODULES.append(
            EvilDict(id="ed", name="n", category="ops", apis=[], ui_routes=[])
        )
        body = self._get_modules()
        row = next(r for r in body["modules"] if r.get("id") == "ed")
        self.assertEqual(row["name"], "n")

    def test_finite_numeric_id_rides_through_unchanged(self):
        """The over-cap drop must stay a str() probe, not an
        ``isinstance(id, str)`` gate: a numeric YAML ``id: 8080`` keeps its
        value (the SPA uses it as a render key)."""
        modules.MODULES.append({
            "id": 8080, "name": "numeric", "category": "ops",
            "apis": [], "ui_routes": [],
        })
        body = self._get_modules()
        row = next(r for r in body["modules"] if r.get("name") == "numeric")
        self.assertEqual(row["id"], 8080)


class ComposeScanRouteTests(unittest.TestCase):
    """GET /api/adaptive/compose-scan held at the HTTP layer for the first time."""

    def setUp(self):
        self.client = _client()
        self.home = Path(tempfile.mkdtemp(prefix="serverhub-modscan-"))

    def _scan(self) -> dict:
        with mock.patch("hub.adaptive.user_home", return_value=self.home):
            resp = self.client.get("/api/adaptive/compose-scan")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        return body

    def test_surrogateescape_stack_dir_keeps_the_sane_sibling(self):
        """An on-disk dir with a raw 0xFF byte lists as ``stack-\\udcff``
        (os surrogateescape); the route scrubs it before Starlette's UTF-8
        encode and the sane sibling project is still hinted."""
        services = self.home / "Services"
        services.mkdir()
        try:
            os.mkdir(os.fsencode(services) + b"/stack-\xff")
        except OSError:  # pragma: no cover - APFS refuses raw invalid bytes
            self.skipTest("filesystem refuses undecodable bytes in names")
        poisoned = next(p for p in services.iterdir() if p.name != "good")
        (poisoned / "docker-compose.yml").write_text("services: {}\n")
        good = services / "good"
        good.mkdir()
        (good / "compose.yaml").write_text("services: {}\n")
        body = self._scan()
        dumped = json.dumps(body, ensure_ascii=False)
        self.assertNotIn("\udcff", dumped)
        ids = [p["id"] for p in body["projects"]]
        self.assertIn("good", ids)
        # The poisoned dir still names itself, byte replaced — not dropped.
        self.assertTrue(any(i.startswith("stack-") for i in ids), ids)

    def test_dangling_symlink_compose_keeps_its_hint_row(self):
        """The scan is hint-only and never opens the file: a compose path
        whose target vanished still names the project instead of raising."""
        stack = self.home / "Services" / "dangling"
        stack.mkdir(parents=True)
        (stack / "docker-compose.yml").symlink_to(self.home / "gone.yml")
        body = self._scan()
        self.assertEqual([p["id"] for p in body["projects"]], ["dangling"])

    def test_services_occupied_by_a_file_answers_the_empty_list(self):
        (self.home / "Services").write_text("not a dir")
        self.assertEqual(self._scan(), {"projects": []})

    def test_poisoned_home_answers_the_empty_list_not_a_500(self):
        """A NUL in HOME is ValueError, a dying mount is OSError — both
        already classified in the service; this holds the route contract."""
        for exc in (ValueError("embedded null byte"), OSError(5, "eio")):
            with self.subTest(exc=type(exc).__name__):
                with mock.patch(
                    "hub.adaptive.user_home", side_effect=exc,
                ):
                    resp = self.client.get("/api/adaptive/compose-scan")
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                self.assertEqual(resp.json(), {"projects": []})


if __name__ == "__main__":
    unittest.main()
