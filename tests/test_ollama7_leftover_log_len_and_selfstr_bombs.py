"""Seventh leftover-500s sweep of the Ollama surface, over the real app.

The finds, past the ollama6 seals:

* GET /api/ollama/pull/log — a junk in-memory ``log`` value that is a str
  *subclass* whose ``__bool__`` or ``__len__`` raises.  ``_pull_log_lines``
  gated on ``isinstance(raw, str)`` and then probed truthiness with
  ``[raw] if raw else []`` — truthiness of a str subclass dispatches into
  its own ``__bool__``/``__len__``, so the bomb raised out of the route as
  a raw HTTP 500.  ollama6 sealed the *iteration* bombs on list/tuple logs
  but left the plain-str branch's truth test bound.
* Silent data loss (the json6/jobs6 self-``__str__`` class): a str subclass
  whose ``__str__`` returns *itself* keeps the subclass through
  ``str(value)``, so ``_utf8_text``'s bound ``.encode`` dispatched into a
  leftover override.  The old catch answered "" — the pull-row ``model``
  (scalar, nested dict value, and dict *key*), the joined log tail, and the
  ``pull_running`` 409's ``params.model`` all read back empty over real
  text.

Fixes, both in hub/ollama_svc.py, both established conventions: unbound
``str.__len__`` for the plain-str log truth test, and unbound
``str.encode(text, …)`` in ``_utf8_text`` so the carried text is laundered
to an exact str instead of dropped.

Stays-immune pins: GET /api/ollama/status keeps its 200 over the same junk
row, and the coded 409 mutex message recovers the busy model's real name.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import ollama_svc
from hub.app_factory import create_app
from hub.auth import require_auth

_app = None


def _client() -> TestClient:
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return TestClient(_app, raise_server_exceptions=False)


def _err_code(resp) -> str:
    detail = resp.json().get("detail")
    return detail.get("code", "") if isinstance(detail, dict) else ""


class _StrBoolBomb(str):
    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")


class _StrLenBomb(str):
    def __len__(self):
        raise RuntimeError("leftover __len__ bomb")


class _SelfStr(str):
    """``str(x)`` keeps the subclass (``__str__`` returns self); the bound
    ``.encode`` then dispatches into the bomb."""

    def __str__(self):
        return self

    def encode(self, *a, **k):
        raise RuntimeError("leftover .encode bomb")


class _OllamaHttp(unittest.TestCase):
    """Patched cfg, saved/restored pull row, invalidated status snapshot."""

    def setUp(self):
        super().setUp()
        self.client = _client()
        patched = mock.patch.object(ollama_svc, "cfg", lambda: {"settings": {}})
        patched.start()
        self.addCleanup(patched.stop)
        saved_pull = {k: (list(v) if isinstance(v, list) else v)
                      for k, v in ollama_svc._pull.items()}

        def restore_pull():
            ollama_svc._pull.clear()
            ollama_svc._pull.update(saved_pull)

        self.addCleanup(restore_pull)
        self._set_pull(**self._base_row())
        self.addCleanup(ollama_svc.status.invalidate)
        ollama_svc.status.invalidate()

    @staticmethod
    def _base_row() -> dict:
        return dict(running=False, rc=0, model="m1", started="10:00:00",
                    finished="10:00:05", log=["line"])

    def _set_pull(self, **row):
        ollama_svc._pull.clear()
        ollama_svc._pull.update(row)

    def _pull_log_200(self, **junk):
        row = self._base_row()
        row.update(junk)
        self._set_pull(**row)
        resp = self.client.get("/api/ollama/pull/log")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        # The body must be strict UTF-8 JSON with no surviving surrogates.
        payload = json.loads(resp.text)
        resp.text.encode("utf-8")
        return payload


class StrSubclassLogBombHttpTests(_OllamaHttp):
    """Raw 500s on the pre-fix tree: the plain-str log truth test."""

    def test_str_bool_bomb_log_keeps_pull_log_up(self):
        payload = self._pull_log_200(log=_StrBoolBomb("tail"))
        self.assertEqual(payload["log"], "tail")
        self.assertEqual(payload["model"], "m1")

    def test_str_len_bomb_log_keeps_pull_log_up(self):
        payload = self._pull_log_200(log=_StrLenBomb("tail"))
        self.assertEqual(payload["log"], "tail")

    def test_empty_str_subclass_log_still_answers_empty(self):
        payload = self._pull_log_200(log=_StrBoolBomb(""))
        self.assertEqual(payload["log"], "")

    def test_status_stays_200_over_the_same_junk_log(self):
        self._set_pull(**{**self._base_row(), "log": _StrLenBomb("tail")})
        with (
            mock.patch.object(ollama_svc, "binary_path", return_value=None),
            mock.patch.object(
                ollama_svc, "_ollama_open",
                side_effect=ConnectionRefusedError(111, "refused"),
            ),
            mock.patch("hub.launchd_cache.listing", side_effect=OSError("sandbox")),
        ):
            resp = self.client.get("/api/ollama/status", params={"force": "true"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertFalse(json.loads(resp.text)["pull"]["running"])


class SelfStrEncodeBombRecoveryTests(_OllamaHttp):
    """The self-``__str__`` class: real text recovered, never dropped to ""."""

    def test_model_self_str_bomb_recovers_the_real_name(self):
        payload = self._pull_log_200(model=_SelfStr("keep-model"))
        self.assertEqual(payload["model"], "keep-model")

    def test_nested_dict_value_and_key_recover_their_text(self):
        payload = self._pull_log_200(
            model={"k": _SelfStr("keep-v"), _SelfStr("keep-key"): "v"},
        )
        self.assertEqual(payload["model"], {"k": "keep-v", "keep-key": "v"})

    def test_log_tail_self_str_bomb_recovers_the_text(self):
        payload = self._pull_log_200(log=_SelfStr("keep-log"))
        self.assertEqual(payload["log"], "keep-log")

    def test_busy_409_recovers_the_real_busy_model(self):
        row = self._base_row()
        row["running"] = True
        row["model"] = _SelfStr("busy-model")
        self._set_pull(**row)
        with mock.patch.object(ollama_svc, "binary_path", return_value="/fake/ollama"):
            resp = self.client.post("/api/ollama/pull", json={"model": "m2"})
        self.assertEqual(resp.status_code, 409, resp.text[:300])
        self.assertEqual(_err_code(resp), "ollama.pull_running")
        self.assertEqual(resp.json()["detail"]["params"]["model"], "busy-model")


class SanitizerUnitPins(unittest.TestCase):
    """The helpers themselves: bombs launder, healthy text is untouched."""

    def test_utf8_text_self_str_bomb_launders_to_exact_str(self):
        out = ollama_svc._utf8_text(_SelfStr("keep"))
        self.assertEqual(out, "keep")
        self.assertIs(type(out), str)

    def test_utf8_text_still_scrubs_lone_surrogates(self):
        out = ollama_svc._utf8_text("a\ud800b")
        self.assertEqual(out, "a?b")
        out.encode("utf-8")

    def test_pull_log_lines_survives_the_str_subclass_bombs(self):
        for raw in (_StrBoolBomb("x"), _StrLenBomb("x")):
            with self.subTest(bomb=type(raw).__name__):
                self.assertEqual(ollama_svc._pull_log_lines(raw), ["x"])
        self.assertEqual(ollama_svc._pull_log_lines(_StrBoolBomb("")), [])


if __name__ == "__main__":
    unittest.main()
