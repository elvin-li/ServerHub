"""Eighth leftover-500s sweep of the PhotosHub surfaces: an rc-subclass whose
``__eq__`` bombs, over the real mounted app.

photos6 sealed an int-subclass rc whose ``__str__`` raises — planted through
the ``run_watchdog`` seam the photos4 ctl tests already patch — by routing
``_jsonable`` through the unbound ``int.__index__``.  photos7 sealed the str
sibling of that same bomb.  But ``run_action`` tests the *raw* rc before it
ever reaches ``_jsonable``:

    rc = run_watchdog(...)
    if rc == -1 and not _ctl_on_disk(cmd[0]):
        ...
    return _jsonable({"ok": rc == 0, "exit_code": rc, ...})

so the ``rc == -1`` / ``rc == 0`` comparisons ran the *bound* ``__eq__``.  An
rc-subclass whose ``__eq__`` raises — the ``__str__`` bomb's sibling from the
identical ``run_watchdog`` seam — sailed past every int-subclass guard photos6
added and raised out of the route, turning POST /api/photoshub/action into the
catch-all coded **500** ``photoshub.action_failed``: the sanitizer built to
prevent the 500 never got the value.

The fix laundered the rc to a plain int via the unbound ``int.__index__`` (the
``_jsonable`` convention) *before* the comparisons, so the equality tests and
the ``exit_code`` field both run on a launderable value.  A ``__bool__`` bomb
was already immune — the comparisons use ``__eq__``, not truthiness — and is
pinned here so the fix does not narrow to only one dunder.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import photoshub_svc  # noqa: E402

#: Built arithmetically: int("9" * 5000) itself trips the digit cap.
_HUGE_INT = 10 ** 5000

_APP = None


def _client():
    global _APP
    from fastapi.testclient import TestClient
    from hub.auth import require_auth

    if _APP is None:
        from hub.app_factory import create_app

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    # raise_server_exceptions=False: a real 500 must arrive as HTTP 500, not
    # as a re-raised exception that would mask which route crashed.
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _IntEqBomb(int):
    """The rc leftover: an int whose equality tests raise."""

    def __eq__(self, other):
        raise RuntimeError("int eq bomb")

    def __ne__(self, other):
        raise RuntimeError("int ne bomb")

    __hash__ = int.__hash__


class _IntBoolBomb(int):
    """The immune sibling: an int whose truthiness raises."""

    def __bool__(self):
        raise RuntimeError("int bool bomb")


class BombRcActionHttpTests(unittest.TestCase):
    """The reproduced leftover: POST action 500'd on an ``__eq__``-bomb rc."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="photos8-bomb-4f1c-"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.hub = self.tmp / "PhotosHub"
        (self.hub / "config").mkdir(parents=True)
        (self.hub / "state").mkdir()
        (self.hub / "bin").mkdir()
        self.photoctl = self.hub / "bin" / "photoctl"
        self.photoctl.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.photoctl.chmod(0o755)
        for patched in (
            mock.patch.object(photoshub_svc, "HUB", self.hub),
            mock.patch.object(photoshub_svc, "CFG_PATH",
                              self.hub / "config" / "config.json"),
            mock.patch.object(photoshub_svc, "STATE", self.hub / "state"),
            mock.patch.object(photoshub_svc, "BIN_PHOTOCTL", self.photoctl),
            mock.patch.object(photoshub_svc, "SCRIPTS", self.hub / "scripts"),
        ):
            patched.start()
            self.addCleanup(patched.stop)
        self.client = _client()

    def _post(self, rc):
        with mock.patch.object(photoshub_svc, "run_watchdog", return_value=rc):
            return self.client.post(
                "/api/photoshub/action", json={"action": "status"},
            )

    def test_eq_bomb_rc_keeps_the_raw_200_shape(self):
        # Pre-fix: the coded 500 photoshub.action_failed ("int eq bomb"),
        # raised at ``rc == -1`` before the value reached _jsonable.
        resp = self._post(_IntEqBomb(0))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        out = resp.json()
        _starlette(out)
        self.assertTrue(out["ok"])
        self.assertEqual(out["exit_code"], 0)

    def test_nonzero_eq_bomb_rc_reports_its_exit_code(self):
        resp = self._post(_IntEqBomb(2))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        out = resp.json()
        _starlette(out)
        self.assertFalse(out["ok"])
        self.assertEqual(out["exit_code"], 2)

    def test_overcap_eq_bomb_rc_still_drops_its_exit_code(self):
        # Coercion cannot resurrect the unrenderable: past CPython's digit cap
        # the laundered rc drops to null exactly like the photos6 __str__ bomb.
        resp = self._post(_IntEqBomb(_HUGE_INT))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        out = resp.json()
        _starlette(out)
        self.assertIsNone(out["exit_code"])
        # A huge non-zero rc is not success.
        self.assertFalse(out["ok"])

    def test_bool_bomb_rc_stays_immune(self):
        # The comparisons use __eq__, never truthiness, so a __bool__ bomb was
        # always immune; pin it so the fix does not narrow to one dunder.
        resp = self._post(_IntBoolBomb(0))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        out = resp.json()
        _starlette(out)
        self.assertTrue(out["ok"])
        self.assertEqual(out["exit_code"], 0)

    def test_a_plain_rc_still_reports_its_exit_code(self):
        resp = self._post(3)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["exit_code"], 3)


class RcIntLaunderContractTests(unittest.TestCase):
    """The helper contract: coerce to a plain int, never run the bomb dunder."""

    def test_plain_int_is_unchanged(self):
        self.assertEqual(photoshub_svc._rc_int(0), 0)
        self.assertEqual(photoshub_svc._rc_int(-1), -1)
        self.assertEqual(photoshub_svc._rc_int(137), 137)

    def test_eq_bomb_launders_to_a_plain_int(self):
        out = photoshub_svc._rc_int(_IntEqBomb(2))
        self.assertIs(type(out), int)
        # Compares without raising now (the whole point).
        self.assertEqual(out, 2)

    def test_overcap_eq_bomb_launders_to_a_plain_int(self):
        out = photoshub_svc._rc_int(_IntEqBomb(_HUGE_INT))
        self.assertIs(type(out), int)
        self.assertEqual(out, _HUGE_INT)

    def test_non_int_rc_is_left_for_jsonable(self):
        # photos7's str-subclass rc flows through this same seam; a non-int rc
        # keeps its own value (its __eq__ against 0/-1 does not raise) and
        # _jsonable scrubs it for the exit_code field.
        self.assertEqual(photoshub_svc._rc_int("boom"), "boom")
        self.assertIsNone(photoshub_svc._rc_int(None))

    def test_bool_rc_is_left_alone(self):
        self.assertIs(photoshub_svc._rc_int(True), True)


if __name__ == "__main__":
    unittest.main()
