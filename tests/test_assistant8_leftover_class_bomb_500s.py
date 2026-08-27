"""Assistant sweep #8: raising ``__class__`` properties past the sealed gates.

A fresh hunt over the mounted assistant routes (GET /api/assistant/catalog,
POST /api/assistant/ask) found one **remaining HTTP 500** the earlier sweeps
missed: ``isinstance`` consults ``value.__class__`` whenever the value's real
type does not already match, so a leftover object whose ``__class__`` is a
*raising property* blew up the type gate itself — outside every try.  The
found 500: a poisoned PANELS row (the row object, or its ``id`` cell) hit
``suggest_panels``' bare ``isinstance(panel, dict)`` / ``_panel_id``'s
``isinstance(raw, str)`` inside the router's own error fallback, where the
re-raise is a guaranteed 500 on POST /api/assistant/ask — every action
(find / brief / ask / page) at once.  A poisoned ``path`` / ``title`` cell on
any row the fallback *selects* (services/health/logs on a down count, ollama
when unreachable, dashboard on battery) 500'd the same way.

The same bomb anywhere else was a wipe, not a 500: a class bomb on the
status / ollama / ups wrappers (or one of their cells) raised out of
``build_snapshot``'s gates and dropped the *whole* snapshot to the minimal
brief; on the chat result it dropped the model's answer the call already
had; on a catalog row it wiped the whole Cmd+K catalog to ``[]``.

Fixed with ``_isa`` — the module-level isinstance that answers False when
the probe itself raises — at every gate fed by collaborator / catalog data,
so junk drops a cell or a row, never the turn, never the section.  ``_dget``
additionally grew an items-walk fallback for the sibling vector: a
str-subclass *stored key* whose ``__eq__`` raises shares the probe key's
hash, so even ``dict.get`` hit the poisoned comparison and silently dropped
the section whose sane value sat right there.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import assistant_svc
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


class _ClassBomb:
    """``isinstance(bomb, anything-but-its-own-type)`` raises out of the gate."""

    @property
    def __class__(self):
        raise RuntimeError("class bomb")


class _StrEqBombKey(str):
    """Stored-key bomb: shares the sane key's hash, raises on the compare."""

    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    __hash__ = str.__hash__


def _status() -> dict:
    return {
        "system": {
            "load": "0.10 / 0.20 / 0.30",
            "load_pct": 1.0,
            "mem_used_pct": 10,
            "disk_pct": 20,
            "disk_used_gb": 1,
            "disk_total_gb": 2,
            "uptime": "1.0 hours",
        },
        "engine_up": True,
        "counts": {"ok": 3, "warn": 0, "down": 0, "stopped": 0},
        "problems": [],
    }


_SANE = {"id": "dashboard", "path": "/", "title": {"en": "Dashboard"}, "aliases": ["home"]}
_DOCKER = {"id": "docker", "path": "/docker", "title": {"en": "Docker"}, "aliases": ["docker"]}
_HEALTH = {"id": "health", "path": "/health", "title": {"en": "Health"}}


class _QuietCollectors(unittest.TestCase):
    """Route tests with the status / ollama / ups collectors stubbed."""

    def setUp(self):
        self.client = _client()
        for target, kwargs in (
            ("hub.status.peek_status", {"return_value": _status()}),
            ("hub.status.full_status", {"return_value": {}}),
            ("hub.ollama_svc.status", {"return_value": {"reachable": False}}),
            ("hub.ups_svc.ups_snapshot", {"return_value": {"present": False}}),
        ):
            patcher = mock.patch(target, **kwargs)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _ask(self, **body):
        payload = {"query": "", "action": "brief", "locale": "en"}
        payload.update(body)
        return self.client.post("/api/assistant/ask", json=payload)

    def _ok(self, resp) -> dict:
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        return body


class PanelRowClassBomb500Tests(_QuietCollectors):
    """The found 500: PANELS bombs re-raised inside the router's fallback."""

    def test_class_bomb_row_answers_every_action_not_a_500(self):
        # suggest_panels' bare isinstance(panel, dict) ran a second time in
        # the router's own error fallback: a raw 500 on every action.
        rows = (_ClassBomb(), _SANE, _HEALTH)
        with mock.patch.object(assistant_svc, "PANELS", rows):
            for body in (
                {"query": "dashboard", "action": "find"},
                {"query": "", "action": "brief"},
                {"query": "what is up", "action": "ask"},
                {"query": "", "action": "page", "path": "/"},
            ):
                self._ok(self._ask(**body))

    def test_class_bomb_row_sibling_still_matches_the_find(self):
        rows = (_ClassBomb(), _DOCKER)
        with mock.patch.object(assistant_svc, "PANELS", rows):
            body = self._ok(self._ask(query="docker", action="find"))
        self.assertIn("docker", [p.get("id") for p in body["panels"]])

    def test_class_bomb_id_cell_answers_not_a_500(self):
        # _panel_id's isinstance(raw, str) blew inside the same by_id
        # comprehension: one poisoned id cell was a raw 500 on every turn.
        rows = ({"id": _ClassBomb(), "path": "/x", "title": {"en": "X"}}, _SANE)
        with mock.patch.object(assistant_svc, "PANELS", rows):
            body = self._ok(self._ask(query="dashboard", action="find"))
        self.assertIn("dashboard", [p.get("id") for p in body["panels"]])

    def test_class_bomb_path_on_a_wanted_row_drops_the_row_only(self):
        # With a down count the fallback selects services/health/logs; the
        # poisoned services path raised out of its isinstance(path, str).
        status = _status()
        status["counts"] = {"ok": 0, "warn": 0, "down": 2, "stopped": 0}
        rows = ({"id": "services", "path": _ClassBomb(), "title": {"en": "S"}}, _HEALTH)
        with (
            mock.patch("hub.status.peek_status", return_value=status),
            mock.patch.object(assistant_svc, "PANELS", rows),
        ):
            body = self._ok(self._ask())
        ids = [p.get("id") for p in body["panels"]]
        self.assertNotIn("services", ids)
        self.assertIn("health", ids)

    def test_class_bomb_title_on_a_wanted_row_falls_back_to_its_id(self):
        status = _status()
        status["counts"] = {"ok": 0, "warn": 0, "down": 2, "stopped": 0}
        rows = ({"id": "services", "path": "/services", "title": _ClassBomb()}, _HEALTH)
        with (
            mock.patch("hub.status.peek_status", return_value=status),
            mock.patch.object(assistant_svc, "PANELS", rows),
        ):
            body = self._ok(self._ask())
        by_id = {p.get("id"): p for p in body["panels"]}
        self.assertEqual(by_id["services"]["title"], "services")
        self.assertIn("health", by_id)


class CatalogClassBombWipeTests(_QuietCollectors):
    """GET /api/assistant/catalog kept wiping every row on one class bomb."""

    def _catalog_ids(self, rows) -> list:
        with mock.patch.object(assistant_svc, "PANELS", tuple(rows)):
            body = self._ok(self.client.get("/api/assistant/catalog?locale=en"))
        return [p.get("id") for p in body["panels"]]

    def test_bomb_row_and_cells_keep_the_sane_sibling(self):
        for rows in (
            (_ClassBomb(), _DOCKER),
            ({"id": _ClassBomb(), "path": "/x", "title": {"en": "X"}}, _DOCKER),
            ({"id": "x", "path": _ClassBomb(), "title": {"en": "X"}}, _DOCKER),
        ):
            self.assertIn("docker", self._catalog_ids(rows))

    def test_bomb_title_and_aliases_keep_their_own_row_too(self):
        ids = self._catalog_ids((
            {"id": "x", "path": "/x", "title": _ClassBomb(), "aliases": _ClassBomb()},
            _DOCKER,
        ))
        self.assertEqual(sorted(ids), ["docker", "x"])

    def test_page_turn_with_a_bomb_path_row_keeps_the_sane_here(self):
        rows = ({"id": "x", "path": _ClassBomb(), "title": {"en": "X"}}, _DOCKER)
        with mock.patch.object(assistant_svc, "PANELS", rows):
            body = self._ok(self._ask(query="", action="page", path="/docker"))
        self.assertEqual(body["snapshot"].get("here", {}).get("id"), "docker")


class SnapshotClassBombWipeTests(_QuietCollectors):
    """build_snapshot degrades the poisoned cell, never the siblings."""

    def _brief_with_status(self, status):
        with mock.patch("hub.status.peek_status", return_value=status):
            return self._ok(self._ask())

    def test_system_wrapper_bomb_keeps_the_counts(self):
        status = _status()
        status["system"] = _ClassBomb()
        body = self._brief_with_status(status)
        self.assertEqual(body["snapshot"]["counts"]["ok"], 3)

    def test_system_cell_bomb_keeps_the_sibling_cells(self):
        status = _status()
        status["system"]["load"] = _ClassBomb()
        body = self._brief_with_status(status)
        self.assertIsNone(body["snapshot"]["load"])
        self.assertEqual(body["snapshot"]["cpu_load_pct"], 1.0)
        self.assertEqual(body["snapshot"]["counts"]["ok"], 3)

    def test_count_cell_bomb_drops_to_zero_keeps_the_siblings(self):
        status = _status()
        status["counts"]["ok"] = _ClassBomb()
        body = self._brief_with_status(status)
        self.assertEqual(body["snapshot"]["counts"]["ok"], 0)
        self.assertEqual(body["snapshot"]["load"], "0.10 / 0.20 / 0.30")

    def test_problems_and_row_bombs_keep_the_sane_problem(self):
        status = _status()
        status["problems"] = [_ClassBomb(), {"name": "web", "state": "down", "detail": "d"}]
        body = self._brief_with_status(status)
        self.assertEqual([p["name"] for p in body["snapshot"]["problems"]], ["web"])

    def test_ollama_and_ups_wrapper_bombs_keep_the_system_cells(self):
        for target, bomb in (
            ("hub.ollama_svc.status", _ClassBomb()),
            ("hub.ups_svc.ups_snapshot", _ClassBomb()),
        ):
            with mock.patch(target, return_value=bomb):
                body = self._ok(self._ask())
            self.assertEqual(body["snapshot"]["load"], "0.10 / 0.20 / 0.30")

    def test_ollama_resident_row_bomb_keeps_the_sane_sibling(self):
        snap = {"reachable": True, "resident": [_ClassBomb(), {"name": "sane"}]}
        with mock.patch("hub.ollama_svc.status", return_value=snap):
            body = self._ok(self._ask())
        self.assertEqual(body["snapshot"]["ollama"]["resident"], ["sane"])

    def test_ups_cell_bombs_keep_the_section_and_the_siblings(self):
        ups = {"present": True, "source": _ClassBomb(),
               "percent": 42, "charging": _ClassBomb()}
        with mock.patch("hub.ups_svc.ups_snapshot", return_value=ups):
            body = self._ok(self._ask())
        self.assertEqual(body["snapshot"]["ups"]["percent"], 42)
        self.assertEqual(body["snapshot"]["load"], "0.10 / 0.20 / 0.30")

    def test_peek_bomb_falls_through_to_full_status(self):
        # The old bare isinstance raised into the blanket except and skipped
        # the full_status() retry the sane path still had.
        with (
            mock.patch("hub.status.peek_status", return_value=_ClassBomb()),
            mock.patch("hub.status.full_status", return_value=_status()),
        ):
            body = self._ok(self._ask())
        self.assertEqual(body["snapshot"]["counts"]["ok"], 3)


class ChatResultClassBombTests(_QuietCollectors):
    """The gates past _run_llm's try keep the answer / fall back cleanly."""

    def _with_llm(self, chat_result):
        return (
            mock.patch(
                "hub.ollama_svc.status",
                return_value={"reachable": True, "resident": [{"name": "m"}]},
            ),
            mock.patch("hub.ollama_svc.chat", return_value=chat_result),
        )

    def test_bomb_result_wrapper_falls_to_the_brief_not_a_wipe(self):
        # isinstance(result, dict) ran outside _run_llm's try: the raise
        # dropped the turn to the router's rebuilt fallback and the snapshot
        # was built twice.  Now the turn degrades in place, snapshot intact.
        st, ch = self._with_llm(_ClassBomb())
        with st, ch:
            body = self._ok(self._ask(query="hi", action="ask"))
        self.assertFalse(body["used_llm"])
        self.assertEqual(body["snapshot"]["counts"]["ok"], 3)

    def test_bomb_model_cell_falls_back_to_the_picked_model(self):
        st, ch = self._with_llm({"content": "LLM SAYS HI", "model": _ClassBomb()})
        with st, ch:
            body = self._ok(self._ask(query="hi", action="ask"))
        self.assertIn("LLM SAYS HI", body["text"])
        self.assertEqual(body["model"], "m")

    def test_bomb_duration_cell_keeps_the_answer(self):
        st, ch = self._with_llm(
            {"content": "LLM SAYS HI", "model": "m", "duration_s": _ClassBomb()})
        with st, ch:
            body = self._ok(self._ask(query="hi", action="ask"))
        self.assertIn("LLM SAYS HI", body["text"])
        self.assertIsNone(body["duration_s"])


class PoisonedStoredKeyTests(_QuietCollectors):
    """A str-subclass stored key whose ``__eq__`` raises loses nothing."""

    def test_system_under_a_poisoned_key_is_recovered(self):
        # The bomb key shares "system"'s hash, so even dict.get hit the
        # poisoned compare — the whole system section used to drop silently.
        status = _status()
        status[_StrEqBombKey("system")] = status.pop("system")
        with mock.patch("hub.status.peek_status", return_value=status):
            body = self._ok(self._ask())
        self.assertEqual(body["snapshot"]["load"], "0.10 / 0.20 / 0.30")

    def test_ups_present_under_a_poisoned_key_keeps_the_section(self):
        ups = {_StrEqBombKey("present"): True, "source": "battery",
               "percent": 42, "charging": False}
        with mock.patch("hub.ups_svc.ups_snapshot", return_value=ups):
            body = self._ok(self._ask())
        self.assertEqual(body["snapshot"]["ups"]["percent"], 42)
        self.assertIn("dashboard", [p.get("id") for p in body["panels"]])


class ProbeFunctionTests(unittest.TestCase):
    """The new gates, held at the function level."""

    def test_isa_answers_false_when_the_probe_raises(self):
        self.assertFalse(assistant_svc._isa(_ClassBomb(), dict))
        self.assertFalse(assistant_svc._isa(_ClassBomb(), (str, bytes)))

    def test_isa_keeps_isinstance_semantics_for_sane_values(self):
        self.assertTrue(assistant_svc._isa({}, dict))
        self.assertTrue(assistant_svc._isa("x", (str, bytes)))
        self.assertFalse(assistant_svc._isa(1, str))

    def test_dget_walks_items_past_a_poisoned_stored_key(self):
        mapping = {_StrEqBombKey("k"): "value", "other": 1}
        self.assertEqual(assistant_svc._dget(mapping, "k"), "value")
        self.assertEqual(assistant_svc._dget(mapping, "other"), 1)
        self.assertIsNone(assistant_svc._dget(mapping, "missing"))

    def test_panel_id_drops_a_class_bomb_to_empty(self):
        self.assertEqual(assistant_svc._panel_id(_ClassBomb()), "")

    def test_helpers_never_raise_on_a_class_bomb(self):
        bomb = _ClassBomb()
        self.assertEqual(assistant_svc._safe_int(bomb, 7), 7)
        self.assertIsNone(assistant_svc._exact_number(bomb))
        self.assertIsNone(assistant_svc._jsonable(bomb))
        self.assertIsNone(assistant_svc._dget(bomb, "k"))

    def test_suggest_panels_and_fallback_brief_survive_bomb_snapshots(self):
        # Both run inside the router's error fallback: a raise is a 500.
        for snapshot in (
            {"counts": _ClassBomb(), "problems": _ClassBomb()},
            {"counts": {"down": _ClassBomb()}, "ups": _ClassBomb(),
             "ollama": _ClassBomb(), "disk_root_pct": _ClassBomb(),
             "engine_up": _ClassBomb(), "load": _ClassBomb()},
        ):
            assistant_svc.fallback_brief(snapshot, "en")
            assistant_svc.suggest_panels(snapshot, "en")


if __name__ == "__main__":
    unittest.main()
