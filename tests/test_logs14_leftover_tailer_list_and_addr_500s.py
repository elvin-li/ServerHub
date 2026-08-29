"""Fourteenth leftover sweep of the Logs surfaces, over the real app.

logs13 recovered honest storage behind a lying ``__class__``.  A leftover
``tail_file_lines`` answer that was not a list — a mapping, a subclass
``__iter__`` bomb, or a lying ``__class__`` claiming list — still 500'd
GET /api/logs/{id} at the bare ``"\\n".join(parts)`` / ``len(parts)``
after the file had already been read.  Non-str rows TypeError'd the
same join.  A leftover object-repr as a published id/name/path used to
leak a CPython ``<… object at 0x…>`` into the JSON body.

The list snapshot and ADDR belt fail-closed those shapes.  Stronger
union guards (``except BaseException`` with ``_CONTROL_FLOW`` re-raised)
stay untouched around every new path.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import logs_svc
from hub.app_factory import create_app
from hub.auth import require_auth

_app = None


def _client() -> TestClient:
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return TestClient(_app, raise_server_exceptions=False)


def _strict_utf8(resp) -> str:
    return resp.content.decode("utf-8")


class IterBombList(list):
    def __iter__(self):
        raise RuntimeError("leftover list __iter__ bomb")


class ClassBombList:
    @property
    def __class__(self):  # type: ignore[override]
        raise RuntimeError("leftover __class__ property bomb")


class ListImpostor:
    @property
    def __class__(self):  # type: ignore[override]
        return list


class _LogsSandbox(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log_path = os.path.join(self.tmp.name, "panel.log")
        with open(self.log_path, "w", encoding="utf-8") as fh:
            fh.write("line-one\nline-two\n")
        self.addCleanup(self.tmp.cleanup)

    def _list(self, cfg_value):
        with mock.patch.object(logs_svc, "cfg", lambda: cfg_value):
            resp = _client().get("/api/logs")
        self.assertNotEqual(resp.status_code, 500, _strict_utf8(resp)[:500])
        self.assertEqual(resp.status_code, 200, _strict_utf8(resp)[:500])
        return json.loads(_strict_utf8(resp))["sources"]

    def _tail(self, cfg_value, source_id, tailer=None):
        ctx = mock.patch.object(logs_svc, "cfg", lambda: cfg_value)
        extra = (
            mock.patch.object(logs_svc, "tail_file_lines", tailer)
            if tailer is not None
            else mock.patch.object(logs_svc, "tail_file_lines", logs_svc.tail_file_lines)
        )
        with ctx, extra:
            resp = _client().get(f"/api/logs/{source_id}")
        self.assertNotEqual(resp.status_code, 500, _strict_utf8(resp)[:500])
        self.assertEqual(resp.status_code, 200, _strict_utf8(resp)[:500])
        return json.loads(_strict_utf8(resp))


class TailerListSeamTests(_LogsSandbox):
    def _cfg(self):
        return {"log_sources": [{"id": "s1", "name": "Panel", "path": self.log_path}]}

    def test_mapping_tailer_answers_empty_lines_not_500(self):
        payload = self._tail(self._cfg(), "s1", tailer=lambda *a, **k: {0: "nope"})
        self.assertEqual(payload["log"], "")
        self.assertEqual(payload["lines"], 0)
        self.assertTrue(payload["exists"])

    def test_none_tailer_answers_empty_lines_not_500(self):
        payload = self._tail(self._cfg(), "s1", tailer=lambda *a, **k: None)
        self.assertEqual(payload["log"], "")
        self.assertEqual(payload["lines"], 0)

    def test_iter_bomb_list_keeps_stored_rows(self):
        payload = self._tail(
            self._cfg(), "s1", tailer=lambda *a, **k: IterBombList(["kept"]))
        self.assertEqual(payload["log"], "kept")
        self.assertEqual(payload["lines"], 1)

    def test_class_bomb_tailer_answer_answers_empty_lines_not_500(self):
        payload = self._tail(
            self._cfg(), "s1", tailer=lambda *a, **k: ClassBombList())
        self.assertEqual(payload["log"], "")
        self.assertEqual(payload["lines"], 0)

    def test_list_impostor_answers_empty_lines_not_500(self):
        payload = self._tail(
            self._cfg(), "s1", tailer=lambda *a, **k: ListImpostor())
        self.assertEqual(payload["log"], "")
        self.assertEqual(payload["lines"], 0)

    def test_non_str_rows_cost_themselves_and_honest_rows_survive(self):
        rows = [42, object(), "kept", b"bytes-row"]
        payload = self._tail(self._cfg(), "s1", tailer=lambda *a, **k: rows)
        self.assertIn("kept", payload["log"])
        self.assertIn("bytes-row", payload["log"])
        self.assertNotIn(" at 0x", payload["log"])

    def test_honest_on_disk_tail_still_renders(self):
        payload = self._tail(self._cfg(), "s1")
        self.assertEqual(payload["log"], "line-one\nline-two")
        self.assertEqual(payload["lines"], 2)


class AddrBeltTests(_LogsSandbox):
    def test_object_repr_name_does_not_leak_an_address(self):
        class _Named:
            def __str__(self):
                return object.__str__(self)

        rows = self._list({"log_sources": [
            {"id": "s1", "name": _Named(), "path": self.log_path}]})
        self.assertEqual(len(rows), 1)
        self.assertNotIn(" at 0x", json.dumps(rows))
        self.assertEqual(rows[0]["name"], "s1")

    def test_label_text_drops_addr_repr_and_keeps_plain_text(self):
        self.assertEqual(logs_svc._label_text("plain"), "plain")
        self.assertEqual(logs_svc._label_text("<x object at 0xabc123>"), "")
        self.assertEqual(logs_svc._rows_list({0: "nope"}), [])
        self.assertEqual(logs_svc._rows_list(["a", "b"]), ["a", "b"])


class ControlFlowStillPropagatesTests(unittest.TestCase):
    def test_keyboardinterrupt_from_class_property_propagates(self):
        class _KIClass:
            @property
            def __class__(self):  # type: ignore[override]
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            logs_svc._rows_list(_KIClass())
