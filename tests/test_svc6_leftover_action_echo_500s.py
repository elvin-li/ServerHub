"""Sixth leftover-500s sweep — POST /api/action rides the bulk-route shapes.

svc5 pinned POST /api/services/bulk-action against a ``run_action`` seam
handing back a huge int rc, a lone-surrogate message or a raised
RecursionError: each rides inside the 200 as a per-id failure.  This sweep
re-drove the *single-action* echo — POST /api/action, the route the
Services page start/stop buttons and the menu-bar client call — with the
same shapes and found **four live 500s** the bulk route already absorbed:

* an over-cap rc with empty out/err hit ``f"exit {rc}"``, whose int->str
  conversion raises CPython's digit-cap ValueError;
* an int-subclass ``__eq__`` bomb rc blew the bare ``ok = rc == 0``;
* a ``__bool__`` bomb blew the ``err or out`` truth test;
* a message whose ``str()`` raises RecursionError blew the shaping (only
  the encode was guarded).

The fix shapes the echo through ``_message_text`` (bytes decode, non-finite
float blank, RecursionError -> type name, UTF-8 scrub — the existing
menubar pins keep their exact shapes) and guards the rc compare and the
exit fallback, so a failed action always answers the designed coded
``{ok: false, message}`` body, never a traceback 500.

Stays-immune pins ride along re-asserting the bulk route absorbs the same
shapes per-id (the eq-bomb rc and bool-bomb err svc5 did not cover).
"""
from __future__ import annotations

import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import actions
from hub.app_factory import create_app
from hub.auth import require_auth
from hub.routers import api as api_mod

#: Built arithmetically: int("9" * 5000) itself trips the digit cap.
_HUGE_INT = 10 ** 5000

_APP = None


def _client() -> TestClient:
    global _APP
    if _APP is None:
        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: None
    return TestClient(_APP, raise_server_exceptions=False)


class _BoolBomb:
    def __bool__(self):
        raise RuntimeError("bool bomb")


class _EqBombInt(int):
    def __eq__(self, other):
        raise RuntimeError("int eq bomb")

    __hash__ = int.__hash__


class _RecStr:
    def __str__(self):
        raise RecursionError()


def _is_leftover_500(r) -> bool:
    """True only for an uncoded traceback 500, not the designed ok:false body."""
    if r.status_code != 500:
        return False
    try:
        body = r.json()
    except Exception:
        return True
    detail = body.get("detail") if isinstance(body, dict) else None
    if isinstance(detail, dict) and detail.get("code"):
        return False
    if isinstance(body, dict) and "ok" in body and "message" in body:
        return False
    return True


class ActionEchoStaysCodedTests(unittest.TestCase):
    """The single-action echo absorbs the seam shapes the bulk route rides."""

    def _post(self, rv):
        with mock.patch.object(actions, "run_action", return_value=rv):
            return _client().post(
                "/api/action", json={"target": "t", "action": "start"},
            )

    def test_huge_rc_with_empty_output_is_the_coded_failure(self):
        r = self._post((_HUGE_INT, "", ""))
        self.assertFalse(_is_leftover_500(r), r.text[:300])
        body = r.json()
        self.assertFalse(body["ok"])
        self.assertTrue(body["message"].startswith("exit"))

    def test_renderable_rc_keeps_the_exit_message(self):
        r = self._post((7, "", ""))
        self.assertFalse(_is_leftover_500(r), r.text[:300])
        self.assertEqual(r.json()["message"], "exit 7")

    def test_eq_bomb_rc_reads_as_failure(self):
        r = self._post((_EqBombInt(0), "out", "err"))
        self.assertFalse(_is_leftover_500(r), r.text[:300])
        body = r.json()
        self.assertFalse(body["ok"])
        self.assertEqual(body["message"], "err")

    def test_bool_bomb_err_does_not_500_the_truth_test(self):
        r = self._post((1, "out", _BoolBomb()))
        self.assertFalse(_is_leftover_500(r), r.text[:300])
        self.assertFalse(r.json()["ok"])

    def test_recursionerror_message_degrades_to_the_type_name(self):
        r = self._post((1, "", _RecStr()))
        self.assertFalse(_is_leftover_500(r), r.text[:300])
        self.assertEqual(r.json()["message"], "_RecStr")

    def test_menubar_pins_keep_their_shapes(self):
        # bytes decode, surrogate scrub, non-finite float blanks to exit rc.
        r = self._post((0, b"done", ""))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["message"], "done")
        r = self._post((0, "ok\ud800", ""))
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("\ud800", r.json()["message"])
        r = self._post((1, float("inf"), float("nan")))
        self.assertFalse(_is_leftover_500(r), r.text[:300])
        self.assertEqual(r.json()["message"], "exit 1")


class BulkStaysImmunePins(unittest.TestCase):
    """The bulk route keeps absorbing the same shapes per-id."""

    def _post(self, rv):
        with mock.patch.object(actions, "run_action", return_value=rv):
            return _client().post(
                "/api/services/bulk-action",
                json={"ids": ["a"], "action": "start"},
            )

    def test_eq_bomb_rc_rides_as_per_id_failure(self):
        r = self._post((_EqBombInt(0), "out", "err"))
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertFalse(r.json()["results"][0]["ok"])

    def test_bool_bomb_err_rides_as_per_id_failure(self):
        r = self._post((1, "out", _BoolBomb()))
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertFalse(r.json()["results"][0]["ok"])


class MessageTextUnitPins(unittest.TestCase):
    def test_message_text_shapes(self):
        self.assertEqual(api_mod._message_text(None), "")
        self.assertEqual(api_mod._message_text(b"x\xff"), "x\ufffd")
        self.assertEqual(api_mod._message_text(float("inf")), "")
        self.assertEqual(api_mod._message_text(float("nan")), "")
        self.assertEqual(api_mod._message_text(1.5), "1.5")
        self.assertEqual(api_mod._message_text("a\ud800b"), "a?b")
        self.assertEqual(api_mod._message_text(_RecStr()), "_RecStr")


if __name__ == "__main__":
    unittest.main()
