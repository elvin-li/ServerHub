"""Modules-page leftover sweep #13: mid-walk mutation bombs and the
claimed-base sequence fidelity gap on GET /api/modules.

Sweep #12 reached every swallow site down to ``except BaseException``, so
a leftover can no longer 500 the route by *raising* out of its own hooks.
A fresh hunt over the same mounted route (create_app + TestClient,
raise_server_exceptions=False) found the next seam: the sanitizer's own
probes *run* leftover code — ``_isinst`` reads a value's ``__class__``
property, key coercion calls a key's ``__str__`` — and the dict arm
walked a **live** ``dict_items`` view while doing so.  A hook whose side
effect resizes its parent mapping made the very next step of the walk
raise ``RuntimeError: dictionary changed size during iteration`` —
outside every try, straight out of GET /api/modules as a raw 500.  Four
shapes were live:

* a dict-row value whose ``__class__`` property pops a sibling key;
* the same hook growing the mapping instead of shrinking it;
* a non-str mapping *key* whose ``__str__`` coercion pops a later entry;
* a set element whose ``__class__`` property discards a sibling —
  ``RuntimeError: Set changed size during iteration`` from the live set
  iterator in the sequence arm.

Exact dicts are as exposed as subclasses: the bomb is the *value's* hook,
not a mapping override, so no lying ``__class__`` or subclass registry is
needed to arm it.

The launder snapshots both walks off the real storage first —
``list(dict.items(...))`` and ``list(base.__iter__(...))`` copy pure C
entries without running any leftover code — so the walk is immune to
whatever the hooks later do to the original, and every entry captured at
snapshot time still renders.

The same hunt found the sequence arm degrading a rank too coarsely, the
mirror of the decode gap sweep #12 fixed: it picked the iteration base
off the *claimed* ``__class__``, so a genuine tuple whose ``__class__``
lied ``list`` was handed to ``list.__iter__``, rejected by the
descriptor, and its perfectly renderable elements vanished to ``None``.
Not a 500, but the wrong degrade rank.  Every base is now tried against
the real storage: the honest layout wins and the elements survive; a
total impostor (real type is none of the four) still fails every base
and drops exactly as before.

Control flow keeps its lane: a ``KeyboardInterrupt`` or ``SystemExit``
raised from a hook mid-walk still propagates — the snapshot moves *when*
the hooks run relative to the container walk, never whether genuine
control flow escapes.  Stays-immune pins ride along so a refactor trips
loudly.
"""
from __future__ import annotations

import json
import unittest

from fastapi.testclient import TestClient

from hub import modules

_APP = None


def _client() -> TestClient:
    global _APP
    if _APP is None:
        from hub.app_factory import create_app
        from hub.auth import require_auth

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _DelSiblingClassBomb:
    """``__class__`` probe pops a sibling key off the parent mapping.

    Idempotent (``pop`` with default): the route walks the registry twice
    (``modules`` then ``by_category``) and ``_isinst`` probes ``__class__``
    once per type gate, so the hook runs many times."""

    def __init__(self, parent: dict, victim: str):
        self._parent = parent
        self._victim = victim

    @property
    def __class__(self):  # type: ignore[override]
        self._parent.pop(self._victim, None)
        raise RuntimeError("mutating class bomb")


class _GrowClassBomb:
    """``__class__`` probe inserts a new key into the parent mapping."""

    def __init__(self, parent: dict):
        self._parent = parent

    @property
    def __class__(self):  # type: ignore[override]
        self._parent.setdefault("injected", "grown")
        raise RuntimeError("growing class bomb")


class _KeyMutBomb:
    """A mapping *key* whose ``__str__`` coercion pops a later entry."""

    def __init__(self):
        self.parent: dict | None = None

    def __str__(self):
        if self.parent is not None:
            self.parent.pop("later", None)
        return "kb13"

    def __hash__(self):
        return 13


class _SetDiscardBomb:
    """A set element whose ``__class__`` probe discards a sibling."""

    def __init__(self):
        self.parent: set | None = None

    @property
    def __class__(self):  # type: ignore[override]
        if self.parent is not None:
            self.parent.discard("/api/keep")
        raise RuntimeError("set mutation bomb")


class _TupleLyingList(tuple):
    """Genuine tuple storage; ``__class__`` claims ``list``."""

    @property
    def __class__(self):  # type: ignore[override]
        return list


class _SequenceImpostor:
    """Claims ``list`` while carrying none of the four sequence layouts."""

    @property
    def __class__(self):  # type: ignore[override]
        return list


class _RegistrySandbox(unittest.TestCase):
    def setUp(self):
        self._saved = modules.MODULES
        self.addCleanup(lambda: setattr(modules, "MODULES", self._saved))
        self.client = _client()

    def _get_modules(self) -> dict:
        resp = self.client.get("/api/modules")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        return body

    def _row(self, body: dict, row_id: str) -> dict:
        return next(r for r in body["modules"] if r.get("id") == row_id)


class MidWalkMutationBombTests(_RegistrySandbox):
    """Each vector was a live raw 500 (``RuntimeError: ... changed size
    during iteration``) before the walks snapshotted off real storage."""

    def test_value_class_bomb_shrinking_the_row_keeps_the_snapshot(self):
        row = {"id": "mut13a", "name": None, "category": "ops",
               "apis": [], "ui_routes": [], "extra": "keep"}
        row["name"] = _DelSiblingClassBomb(row, "extra")
        modules.MODULES = list(self._saved) + [row]
        body = self._get_modules()
        got = self._row(body, "mut13a")
        # Snapshot precedes any hook: the popped sibling still renders.
        self.assertEqual(got["extra"], "keep")
        # The bomb itself degrades through the text fallback, not a 500.
        self.assertIsInstance(got["name"], str)
        self.assertEqual(got["category"], "ops")
        ids = [r.get("id") for r in body["modules"]]
        self.assertIn("dashboard", ids)
        self.assertEqual(len(ids), len(self._saved) + 1)

    def test_value_class_bomb_growing_the_row_keeps_the_snapshot(self):
        row = {"id": "mut13b", "name": None, "category": "ops",
               "apis": [], "ui_routes": []}
        row["name"] = _GrowClassBomb(row)
        modules.MODULES = list(self._saved) + [row]
        body = self._get_modules()
        got = self._row(body, "mut13b")
        # The key injected mid-walk is not part of the snapshot.
        self.assertNotIn("injected", got)
        self.assertIsInstance(got["name"], str)

    def test_key_str_bomb_popping_a_later_entry_keeps_it(self):
        kb = _KeyMutBomb()
        row = {"id": "mut13c", "name": "n", "category": "ops",
               kb: "v", "later": "still-here", "apis": [], "ui_routes": []}
        kb.parent = row
        modules.MODULES = list(self._saved) + [row]
        body = self._get_modules()
        got = self._row(body, "mut13c")
        self.assertEqual(got["later"], "still-here")
        self.assertEqual(got["kb13"], "v")

    def test_set_element_bomb_discarding_a_sibling_keeps_both(self):
        el = _SetDiscardBomb()
        apis = {el, "/api/keep"}
        el.parent = apis
        modules.MODULES = list(self._saved) + [
            {"id": "mut13d", "name": "n", "category": "ops",
             "apis": apis, "ui_routes": []}]
        body = self._get_modules()
        got = self._row(body, "mut13d")
        self.assertEqual(len(got["apis"]), 2)
        self.assertIn("/api/keep", got["apis"])

    def test_nested_mapping_mutation_bomb_cannot_500_either(self):
        inner = {"safe": "v", "doomed": "keep"}
        inner["bomb"] = _DelSiblingClassBomb(inner, "doomed")
        modules.MODULES = list(self._saved) + [
            {"id": "mut13e", "name": "n", "category": "ops",
             "apis": [], "ui_routes": [], "meta": inner}]
        body = self._get_modules()
        got = self._row(body, "mut13e")
        self.assertEqual(got["meta"]["safe"], "v")
        self.assertEqual(got["meta"]["doomed"], "keep")


class SequenceFidelityTests(_RegistrySandbox):
    """The claimed-base iteration gap: real elements behind a lying
    ``__class__`` used to vanish; a total impostor still drops."""

    def test_tuple_lying_list_keeps_its_elements(self):
        modules.MODULES = list(self._saved) + [
            {"id": "fid13", "name": "n", "category": "ops",
             "apis": _TupleLyingList(("/api/a", "/api/b")),
             "ui_routes": []}]
        body = self._get_modules()
        got = self._row(body, "fid13")
        self.assertEqual(got["apis"], ["/api/a", "/api/b"])

    def test_total_sequence_impostor_still_drops_to_none(self):
        modules.MODULES = list(self._saved) + [
            {"id": "imp13", "name": "n", "category": "ops",
             "apis": _SequenceImpostor(), "ui_routes": []}]
        body = self._get_modules()
        got = self._row(body, "imp13")
        self.assertIsNone(got["apis"])


class ControlFlowStillPropagatesTests(_RegistrySandbox):
    """The snapshot changes when hooks run relative to the walk, never
    whether genuine control flow escapes them."""

    def test_keyboardinterrupt_from_dict_value_hook_propagates(self):
        class _KIBomb:
            @property
            def __class__(self):  # type: ignore[override]
                raise KeyboardInterrupt

        modules.MODULES = [
            {"id": "ki13", "name": _KIBomb(), "category": "ops"}]
        with self.assertRaises(KeyboardInterrupt):
            modules.list_modules()

    def test_systemexit_from_set_element_hook_propagates(self):
        class _SEBomb:
            @property
            def __class__(self):  # type: ignore[override]
                raise SystemExit(5)

        modules.MODULES = [
            {"id": "se13", "name": "n", "category": "ops",
             "apis": {_SEBomb()}}]
        with self.assertRaises(SystemExit):
            modules.list_modules()


class StaysImmuneTests(_RegistrySandbox):
    """Neighbours the same hunt confirmed already safe, pinned so a
    refactor trips loudly."""

    def test_list_shrunk_mid_walk_never_raised_and_still_does_not(self):
        # A list iterator tolerates resizing (it just stops early), so a
        # list-mutating hook was never a 500 — and with the snapshot the
        # sibling captured before the hook ran now renders too.
        class _ListShrinkBomb:
            def __init__(self):
                self.parent: list | None = None

            @property
            def __class__(self):  # type: ignore[override]
                if self.parent is not None and "/api/tail" in self.parent:
                    self.parent.remove("/api/tail")
                raise RuntimeError("list mutation bomb")

        el = _ListShrinkBomb()
        apis = [el, "/api/tail"]
        el.parent = apis
        modules.MODULES = list(self._saved) + [
            {"id": "ls13", "name": "n", "category": "ops",
             "apis": apis, "ui_routes": []}]
        body = self._get_modules()
        got = self._row(body, "ls13")
        self.assertEqual(len(got["apis"]), 2)
        self.assertIn("/api/tail", got["apis"])

    def test_exact_registry_renders_identically(self):
        body = self._get_modules()
        ids = [r.get("id") for r in body["modules"]]
        self.assertIn("dashboard", ids)
        self.assertEqual(len(ids), len(self._saved))
        grouped = sum(len(v) for v in body["by_category"].values())
        self.assertEqual(grouped, len(self._saved))

    def test_modules12_baseexception_class_bomb_stays_closed(self):
        # The widened walks must not reopen the sweep-#12 seal: a row
        # whose ``__class__`` raises a BaseException subclass still drops
        # alone.
        class _Watchdog(BaseException):
            pass

        class _ClassBaseBomb:
            @property
            def __class__(self):  # type: ignore[override]
                raise _Watchdog("class access bomb")

        modules.MODULES = list(self._saved) + [
            _ClassBaseBomb(),
            {"id": "sane13", "name": "S", "category": "ops",
             "apis": [], "ui_routes": []}]
        body = self._get_modules()
        ids = [r.get("id") for r in body["modules"]]
        self.assertIn("sane13", ids)
        self.assertEqual(len(ids), len(self._saved) + 1)

    def test_dict_items_override_stays_inert_via_unbound_snapshot(self):
        class _ItemsBomb(dict):
            def items(self):
                raise RuntimeError("items bomb")

        modules.MODULES = list(self._saved) + [
            _ItemsBomb({"id": "it13", "name": "n", "category": "ops",
                        "apis": [], "ui_routes": []})]
        body = self._get_modules()
        ids = [r.get("id") for r in body["modules"]]
        self.assertIn("it13", ids)


if __name__ == "__main__":
    unittest.main()
