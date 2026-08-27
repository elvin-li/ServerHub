"""Ninth leftover-500s sweep of the Logs surfaces, over the real app.

logs8 laundered the last *bound* coercion (`str(raw_path)`) through the
unbound ``str.__str__``, but every type gate in hub/logs_svc.py was still
a *bare* ``isinstance``.  CPython's ``isinstance`` consults the operand's
``__class__`` attribute whenever the exact-type fast check misses, so a
leftover whose ``__class__`` is a *raising property* detonated the gates
themselves — one line ahead of every scrub this module carries:

- planted as the cfg() root it blew ``_mapping_get``'s dict gate;
- planted as the ``log_sources`` value it blew ``_entries``' list gate;
- planted as an entry it blew ``_mapping_get`` again;
- planted as an entry's ``id`` / ``name`` it blew ``_config_text``'s str
  gate; planted as ``path`` it blew ``_entries``' bytes gate.

Each one 500'd GET /api/logs AND GET /api/logs/{id} together (the tail
re-lists through ``log_sources()``).  A *lying* ``__class__`` property
that returns ``list`` without being one passed the gate instead and blew
the bare ``list.__len__(sources)`` with the descriptor TypeError — the
same double 500.

The fix, in hub/logs_svc.py, is the module-local ``_isa`` fail-closed
helper every neighbouring service already carries (the ups_svc / vms_svc
/ smart_test_svc rule): a real subclass still matches through the C-level
type check, and only a value that cannot answer what it is takes the
non-matching branch.  Every bare gate routes through it, and ``_entries``
snapshots the sources through unbound ``list.__iter__`` under a broad
catch so the lying impostor degrades to the unconfigured defaults instead
of raising.

Stays-immune pins ride along for the neighbours that were already
absorbed: a ``__class__``-bomb *dict subclass* (matches through the
C-level check, keeps its sane fields), dict-subclass ``.get`` bombs,
hash-shadowing str-subclass mapping keys whose ``__eq__`` raises,
rc-subclass ``__eq__`` / ``__index__`` bombs as ids, and lying-``bool``
impostors that must drop rather than publish "True".
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
import urllib.parse
from unittest import mock

from fastapi.testclient import TestClient

from hub import logs_svc
from hub.app_factory import create_app
from hub.auth import require_auth

_app = None

DEFAULT_IDS = ["autostart", "serverhub", "ha"]


def _client() -> TestClient:
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return TestClient(_app, raise_server_exceptions=False)


def _strict_utf8(resp) -> str:
    """The body must already be valid UTF-8 — decode strictly on purpose."""
    return resp.content.decode("utf-8")


class ClassBomb:
    """``value.__class__`` is a raising property: bare ``isinstance``
    detonates before any laundering can run."""

    @property
    def __class__(self):
        raise RuntimeError("leftover __class__ property bomb")


class ClassBombDictSub(dict):
    """A *real* dict subclass with the same raising ``__class__``: the
    C-level type check must still match it, keeping its sane fields."""

    @property
    def __class__(self):
        raise RuntimeError("leftover __class__ property bomb (dict sub)")


class LyingListImpostor:
    """``__class__`` *returns* list without being one: passes the isa gate,
    then every unbound list read raises the descriptor TypeError."""

    @property
    def __class__(self):
        return list


class LyingDictImpostor:
    @property
    def __class__(self):
        return dict


class BoolLiar:
    """``__class__`` claims bool: must drop, never publish its repr."""

    @property
    def __class__(self):
        return bool


class EqShadowKey(str):
    """Hash-shadowing mapping key: hashes like its text (so it can be
    planted), but the bucket comparison ``__eq__`` raises on lookup."""

    def __hash__(self):
        return str.__hash__(self)

    def __eq__(self, other):
        raise RuntimeError("leftover key __eq__ bomb")


class DictGetBomb(dict):
    def get(self, *a, **k):
        raise RuntimeError("leftover .get bomb")

    def items(self):
        raise RuntimeError("leftover .items bomb")

    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")


class EqBombInt(int):
    def __hash__(self):
        return int.__hash__(self)

    def __eq__(self, other):
        raise RuntimeError("leftover int __eq__ bomb")


class IndexBombInt(int):
    def __index__(self):
        raise RuntimeError("leftover __index__ bomb")

    def __int__(self):
        raise RuntimeError("leftover __int__ bomb")


class _LogsSandbox(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.log_path = os.path.join(self._tmp.name, "sane.log")
        with open(self.log_path, "w", encoding="utf-8") as fh:
            fh.write("line-one\nline-two\n")

    def _list(self, cfg_value):
        with mock.patch.object(logs_svc, "cfg", lambda: cfg_value):
            resp = _client().get("/api/logs")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        return json.loads(_strict_utf8(resp))["sources"]

    def _tail(self, cfg_value, source_id="s1", expect=200):
        with mock.patch.object(logs_svc, "cfg", lambda: cfg_value):
            resp = _client().get(
                "/api/logs/" + urllib.parse.quote(str(source_id), safe=""))
        self.assertEqual(resp.status_code, expect, resp.text[:300])
        return json.loads(_strict_utf8(resp))


class ClassBombGateTests(_LogsSandbox):
    """The reproduced 500s: a raising-``__class__`` property at every seam
    the bare isinstance gates used to trust."""

    def test_class_bomb_cfg_root_degrades_to_defaults(self):
        rows = self._list(ClassBomb())
        self.assertEqual([r["id"] for r in rows], DEFAULT_IDS)
        # The tail of an unconfigured id is an honest 404, not a 500.
        self._tail(ClassBomb(), "s1", expect=404)

    def test_class_bomb_log_sources_degrades_to_defaults(self):
        cfg_value = {"log_sources": ClassBomb()}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], DEFAULT_IDS)
        self._tail(cfg_value, "s1", expect=404)

    def test_lying_list_impostor_degrades_to_defaults(self):
        cfg_value = {"log_sources": LyingListImpostor()}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], DEFAULT_IDS)
        self._tail(cfg_value, "s1", expect=404)

    def test_class_bomb_entry_drops_only_its_own_row(self):
        cfg_value = {"log_sources": [
            ClassBomb(),
            {"id": "sane", "path": self.log_path},
        ]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["sane"])
        self.assertEqual(self._tail(cfg_value, "sane")["lines"], 2)

    def test_class_bomb_id_drops_only_its_own_row(self):
        cfg_value = {"log_sources": [
            {"id": ClassBomb(), "path": self.log_path},
            {"id": "sane", "path": self.log_path},
        ]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["sane"])
        self.assertEqual(self._tail(cfg_value, "sane")["lines"], 2)

    def test_class_bomb_name_falls_back_to_the_id(self):
        cfg_value = {"log_sources": [
            {"id": "s1", "name": ClassBomb(), "path": self.log_path}]}
        rows = self._list(cfg_value)
        # The unrenderable name drops to the id; the source still tails.
        self.assertEqual([(r["id"], r["name"]) for r in rows], [("s1", "s1")])
        payload = self._tail(cfg_value, "s1")
        self.assertEqual(payload["log"], "line-one\nline-two")
        self.assertEqual(payload["lines"], 2)

    def test_class_bomb_path_drops_only_its_own_row(self):
        cfg_value = {"log_sources": [
            {"id": "junk", "path": ClassBomb()},
            {"id": "sane", "path": self.log_path},
        ]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["sane"])
        self.assertEqual(self._tail(cfg_value, "sane")["lines"], 2)
        # The dropped row's own tail is an honest 404.
        self._tail(cfg_value, "junk", expect=404)


class StaysImmuneTests(_LogsSandbox):
    """Neighbours of the reproduced bombs, pinned so they cannot regress."""

    def test_class_bomb_dict_subclass_keeps_its_sane_fields(self):
        # A *real* dict subclass matches through the C-level type check even
        # with the raising ``__class__``: its stored fields keep working.
        entry = ClassBombDictSub({"id": "s1", "path": self.log_path})
        cfg_value = ClassBombDictSub({"log_sources": [entry]})
        rows = self._list(cfg_value)
        self.assertEqual(
            [(r["id"], r["exists"], r["size"]) for r in rows],
            [("s1", True, 18)])
        self.assertEqual(self._tail(cfg_value, "s1")["lines"], 2)

    def test_lying_dict_cfg_root_degrades_to_defaults(self):
        rows = self._list(LyingDictImpostor())
        self.assertEqual([r["id"] for r in rows], DEFAULT_IDS)

    def test_dict_get_bomb_entry_keeps_its_sane_fields(self):
        cfg_value = {"log_sources": [
            DictGetBomb({"id": "s1", "path": self.log_path})]}
        rows = self._list(cfg_value)
        self.assertEqual(
            [(r["id"], r["exists"]) for r in rows], [("s1", True)])
        self.assertEqual(self._tail(cfg_value, "s1")["lines"], 2)

    def test_eq_shadow_cfg_key_degrades_to_defaults(self):
        # The poisoned key detonates inside dict.get's bucket comparison;
        # _mapping_get fails closed and the page shows the defaults.
        cfg_value = {EqShadowKey("log_sources"): [
            {"id": "s1", "path": self.log_path}]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], DEFAULT_IDS)

    def test_eq_shadow_entry_keys_drop_only_their_own_row(self):
        cfg_value = {"log_sources": [
            {EqShadowKey("id"): "s1", EqShadowKey("path"): self.log_path},
            {"id": "sane", "path": self.log_path},
        ]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["sane"])
        self.assertEqual(self._tail(cfg_value, "sane")["lines"], 2)

    def test_eq_bomb_int_id_still_lists_and_tails_as_text(self):
        cfg_value = {"log_sources": [
            {"id": EqBombInt(42), "path": self.log_path}]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["42"])
        self.assertEqual(self._tail(cfg_value, "42")["lines"], 2)

    def test_index_bomb_int_id_still_lists_and_tails_as_text(self):
        cfg_value = {"log_sources": [
            {"id": IndexBombInt(7), "path": self.log_path}]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["7"])
        self.assertEqual(self._tail(cfg_value, "7")["lines"], 2)

    def test_bool_liar_id_drops_and_never_publishes_its_repr(self):
        cfg_value = {"log_sources": [
            {"id": BoolLiar(), "path": self.log_path},
            {"id": "sane", "path": self.log_path},
        ]}
        rows = self._list(cfg_value)
        self.assertEqual([r["id"] for r in rows], ["sane"])
        for row in rows:
            for field in (row["id"], row["name"]):
                self.assertNotIn("BoolLiar", field)
                self.assertNotIn("True", field)


class SanitizerUnitPins(unittest.TestCase):
    """The helper itself: fail-closed on a raising ``__class__``, still
    matching a real subclass through the C-level type check."""

    def test_isa_fails_closed_on_a_class_property_bomb(self):
        self.assertFalse(logs_svc._isa(ClassBomb(), dict))
        self.assertFalse(logs_svc._isa(ClassBomb(), (str, bytes, int)))

    def test_isa_still_matches_a_real_subclass(self):
        self.assertTrue(logs_svc._isa(ClassBombDictSub(), dict))
        self.assertTrue(logs_svc._isa(EqShadowKey("x"), str))


if __name__ == "__main__":
    unittest.main(verbosity=2)
