"""Modules-page leftover sweep #6: the self-``__str__`` encode-bomb class.

Sweep #5 pinned that a plain str-subclass ``encode`` bomb never fires on
GET /api/modules because ``str()`` of a subclass returns an exact str —
which is true only for the *default* ``__str__``.  CPython's PyObject_Str
returns whatever ``__str__`` answers as long as it is a str instance, so a
subclass whose ``__str__`` returns *self* skips the exact-str copy entirely
(the class gateway6 found live in hub/nginx_svc.py).  ``modules._utf8_text``
wrapped only the ``str(value)`` call in its try; the final scrub line was a
*bound* ``text.encode(...)`` on whatever came back.  Confirmed against the
mounted route (create_app + TestClient, raise_server_exceptions=False) —
each of these was a raw HTTP 500 before the fix:

* the bomb subclass as a registry field *value* (``name``);
* nested inside a sequence field (``apis=[bomb]``) — the list arm routes
  elements straight back into the unguarded str arm;
* as a mapping *key* — ``out[_utf8_text(k)]`` in ``_jsonable``'s dict arm
  is outside any try, both for a key that is already the bomb subclass and
  for a non-str key whose ``__str__`` mints one;
* through the ``ModuleInfo`` dataclass arm — ``asdict``'s deepcopy keeps
  the subclass, so the poison rides the same scrub;
* as ``category`` — the value passes ``isinstance(cat, str)`` and became
  the ``by_category`` group key via the same ``_utf8_text``.

The fix is one line brought to the modules5/gateway6 unbound convention:
``str.encode(text, "utf-8", "replace")`` bypasses the override, so the
poison scrubs field-level (a lone surrogate riding the bomb still degrades
to ``?``) and every healthy sibling row survives.

Stays-immune pins ride along: an arbitrary object whose ``__str__``
returns the bomb subclass reaches ``_jsonable``'s fall-through, which was
already wrapped in a try (before the fix it degraded to None; now the text
survives), and a poisoned row never wipes the sane siblings or the
``by_category`` grouping.
"""
from __future__ import annotations

import json
import unittest

from fastapi.testclient import TestClient

from hub import modules
from hub.auth import require_auth

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


class SelfStr(str):
    """``str()`` answers *self* — no exact-str copy — and ``encode`` bombs."""

    def __str__(self):
        return self

    def encode(self, *args, **kwargs):
        raise RuntimeError("encode bomb")


class _RegistrySandbox(unittest.TestCase):
    def setUp(self):
        self._saved = list(modules.MODULES)
        self.addCleanup(
            lambda: modules.MODULES.__setitem__(slice(None), self._saved)
        )
        self.client = _client()

    def _row(self, **fields) -> dict:
        row = {"id": "x6", "name": "n", "category": "ops",
               "apis": [], "ui_routes": []}
        row.update(fields)
        modules.MODULES.append(row)
        body = self._get_modules()
        return next(r for r in body["modules"] if r.get("id") == "x6")

    def _get_modules(self) -> dict:
        resp = self.client.get("/api/modules")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        return body


class SelfStrEncodeBombTests(_RegistrySandbox):
    """Each rank was a live raw 500 before the unbound-encode fix."""

    def test_value_rank_scrubs_the_surrogate_and_keeps_the_text(self):
        row = self._row(name=SelfStr("pan\ud800el"))
        # Encode-side "replace" substitutes "?" for the lone surrogate.
        self.assertEqual(row["name"], "pan?el")

    def test_nested_sequence_rank_keeps_the_element(self):
        row = self._row(apis=[SelfStr("/api/x"), "/api/y"])
        self.assertEqual(row["apis"], ["/api/x", "/api/y"])

    def test_mapping_key_rank_keeps_the_entry(self):
        modules.MODULES.append({
            "id": "k6", "name": "n", "category": "ops",
            SelfStr("extra"): "kept", "apis": [], "ui_routes": [],
        })
        body = self._get_modules()
        row = next(r for r in body["modules"] if r.get("id") == "k6")
        self.assertEqual(row["extra"], "kept")

    def test_nonstr_key_whose_str_mints_the_bomb_keeps_the_entry(self):
        class KeyToBomb:
            def __str__(self):
                return SelfStr("minted")

        modules.MODULES.append({
            "id": "k7", "name": "n", "category": "ops",
            KeyToBomb(): "kept", "apis": [], "ui_routes": [],
        })
        body = self._get_modules()
        row = next(r for r in body["modules"] if r.get("id") == "k7")
        self.assertEqual(row["minted"], "kept")

    def test_dataclass_arm_rides_the_same_scrub(self):
        """``asdict``'s deepcopy keeps the subclass — the poison reaches
        ``_jsonable`` exactly like the dict-row ranks."""
        modules.MODULES.append(modules.ModuleInfo(
            id="dc6", name=SelfStr("pan\ud800el"), description="d",
            category="ops",
        ))
        body = self._get_modules()
        row = next(r for r in body["modules"] if r.get("id") == "dc6")
        self.assertEqual(row["name"], "pan?el")

    def test_category_rank_still_groups_under_its_real_name(self):
        """The bomb passes ``isinstance(cat, str)`` and used to 500 as the
        ``by_category`` group key; the scrubbed exact str groups normally."""
        modules.MODULES.append({
            "id": "c6", "name": "n", "category": SelfStr("ops"),
            "apis": [], "ui_routes": [],
        })
        body = self._get_modules()
        row = next(r for r in body["modules"] if r.get("id") == "c6")
        self.assertEqual(row["category"], "ops")
        self.assertIn(
            "c6", [r.get("id") for r in body["by_category"].get("ops", [])]
        )


class StaysImmuneTests(_RegistrySandbox):
    """Vectors the same hunt found guarded — pinned against regression."""

    def test_object_fallthrough_minting_the_bomb_keeps_its_text(self):
        """``_jsonable``'s fall-through ``_utf8_text`` was already inside a
        try; with the unbound scrub the text now survives instead of
        degrading to None."""
        class ObjToBomb:
            def __str__(self):
                return SelfStr("obj-text")

        row = self._row(apis=[ObjToBomb(), "/api/x"])
        self.assertEqual(row["apis"], ["obj-text", "/api/x"])

    def test_poisoned_rows_never_wipe_the_sane_siblings(self):
        sane = len(modules.list_modules())
        modules.MODULES.extend([
            {"id": "p1", "name": SelfStr("n\ud800"), "category": "ops",
             SelfStr("k"): SelfStr("v"), "apis": [SelfStr("/x")],
             "ui_routes": []},
            modules.ModuleInfo(
                id="p2", name=SelfStr("m"), description="d",
                category=SelfStr("ops"),
            ),
        ])
        body = self._get_modules()
        ids = [r.get("id") for r in body["modules"]]
        self.assertIn("dashboard", ids)
        self.assertIn("p1", ids)
        self.assertIn("p2", ids)
        self.assertEqual(len(ids), sane + 2)
        grouped = sum(len(v) for v in body["by_category"].values())
        self.assertEqual(grouped, sane + 2)
        self.assertNotIn("\ud800", json.dumps(body, ensure_ascii=False))


if __name__ == "__main__":
    unittest.main()
