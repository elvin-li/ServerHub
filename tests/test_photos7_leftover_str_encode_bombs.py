"""Seventh leftover-500s sweep of the PhotosHub/Immich surfaces: str-subclass
``encode`` bombs in the text scrubs, over the real mounted app.

photos6 routed both service ``_jsonable`` sanitizers through unbound
base-type probes (``int.__index__``, ``float.__float__``,
``bytes``/``bytearray.decode``, ``dict.items``, ``base.__iter__``), but the
str leg of the scrub still ran *bound*: ``_utf8_text`` / ``_as_text`` called
``value.encode("utf-8", "replace")`` on whatever str they were handed.  A
str-subclass whose ``__str__`` returns itself and whose ``encode`` raises —
the self-``__str__`` encode-bomb class the dash7 sensors sweep already
sealed elsewhere — sailed past ``str()`` untouched and blew the bound call:

* ``photoshub_svc._jsonable`` raised out of the response sweep, turning
  POST /api/photoshub/action into the catch-all coded **500**
  ``photoshub.action_failed`` on a bomb rc planted through the same
  ``run_watchdog`` seam photos6 already used for the int-subclass rc.
* ``immich_svc._as_text`` raised out of ``run_checks`` on a bomb sh output,
  collapsing the whole Immich block of GET /api/health/checks into ONE
  "check failed" warn row — the exact wipe photos6 fixed for the *bytes*
  subclass, resurrected by its str sibling.
* ``errors.exc_detail`` had the same bound encode on ``str(exc)``, and
  ``str(exc)`` hands back the exception's message *object* when it is
  already a str — so a bomb message raised inside the coded-error handler
  itself and turned the coded 500 into an uncoded one.

The fix is unbound ``str.encode`` (the ``_decode_bytes`` convention), plus
skipping ``str()`` for values that are already str instances — so a str
subclass with a ``__str__`` bomb keeps its real text instead of degrading
to "" (the ``int.__index__``-keeps-the-number precedent).
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

from hub import health_svc, immich_svc, photoshub_svc  # noqa: E402
from hub.errors import exc_detail  # noqa: E402

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


class _StrEncodeBomb(str):
    """The self-``__str__`` encode bomb: str() cannot launder it."""

    def __str__(self):
        return self

    __repr__ = __str__

    def encode(self, *args, **kwargs):
        raise RuntimeError("str encode bomb")


class _StrStrBomb(str):
    """A str subclass whose ``__str__`` raises; the text must survive."""

    def __str__(self):
        raise RuntimeError("str str bomb")

    __repr__ = __str__


class _SelfStrToBomb:
    """A non-str value whose ``__str__`` returns an encode-bomb subclass."""

    def __str__(self):
        return _StrEncodeBomb("boom")


class BombRcActionHttpTests(unittest.TestCase):
    """The reproduced photoshub leftover: POST action 500'd on a str bomb rc."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="photos7-bomb-d6a8-"))
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

    def test_str_subclass_encode_bomb_rc_keeps_the_raw_200_shape(self):
        # Pre-fix: the coded 500 photoshub.action_failed ("str encode bomb").
        resp = self._post(_StrEncodeBomb("boom"))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        out = resp.json()
        _starlette(out)
        self.assertFalse(out["ok"])
        self.assertEqual(out["exit_code"], "boom")

    def test_bomb_message_on_a_raising_status_stays_the_coded_500(self):
        """exc_detail itself: a bomb exception message must not go uncoded."""
        with mock.patch.object(
            photoshub_svc, "status",
            side_effect=RuntimeError(_StrEncodeBomb("boom")),
        ):
            resp = self.client.get("/api/photoshub/status")
        # Pre-fix: exc_detail's bound encode re-raised inside the except
        # handler — an uncoded plain-text 500 instead of the coded payload.
        self.assertEqual(resp.status_code, 500)
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["detail"]["code"], "photoshub.status_failed")

    def test_a_plain_rc_still_reports_its_exit_code(self):
        resp = self._post(2)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["exit_code"], 2)


class StrBombWipedImmichHealthTests(unittest.TestCase):
    """The reproduced immich leftover: one encode bomb wiped every check."""

    def _run(self, ps_out):
        with (
            mock.patch.object(immich_svc, "sh", return_value=(0, ps_out, "")),
            mock.patch.object(immich_svc, "engine_up", return_value=True),
            mock.patch.object(immich_svc, "port_open", return_value=False),
            mock.patch.object(
                immich_svc, "loaded_labels", return_value=frozenset(),
            ),
            mock.patch.object(
                immich_svc, "_http", return_value=(None, "refused"),
            ),
        ):
            immich_svc.run_checks.cache_clear()
            self.addCleanup(immich_svc.run_checks.cache_clear)
            return immich_svc.run_checks(force=True)

    def test_str_subclass_ps_output_keeps_every_check_row(self):
        # Pre-fix: run_checks raised RuntimeError("str encode bomb") and
        # health_svc collapsed the whole block to one "check failed" row.
        snap = self._run(_StrEncodeBomb("running\thealthy Up 3 days"))
        _starlette(snap)
        ids = [c["id"] for c in snap["checks"]]
        self.assertIn("immich_ct_immich_server", ids)
        self.assertIn("immich_worker", ids)
        self.assertIn("immich_keepalive", ids)
        server = next(
            c for c in snap["checks"] if c["id"] == "immich_ct_immich_server"
        )
        self.assertEqual(server["detail"], "healthy Up 3 days")
        self.assertTrue(server["ok"])

    def test_health_checks_route_keeps_the_immich_rows(self):
        """The wipe as the operator saw it: GET /api/health/checks."""
        client = _client()
        with (
            mock.patch.object(
                immich_svc, "sh",
                return_value=(0, _StrEncodeBomb("running\tUp 2 days"), ""),
            ),
            mock.patch.object(immich_svc, "engine_up", return_value=True),
            mock.patch.object(immich_svc, "port_open", return_value=False),
            mock.patch.object(
                immich_svc, "loaded_labels", return_value=frozenset(),
            ),
            mock.patch.object(
                immich_svc, "_http", return_value=(None, "refused"),
            ),
        ):
            immich_svc.run_checks.cache_clear()
            self.addCleanup(immich_svc.run_checks.cache_clear)
            saved = dict(health_svc._cache)
            health_svc._cache.update(t=0.0, v=None)
            self.addCleanup(lambda: health_svc._cache.update(saved))
            resp = client.get("/api/health/checks")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        ids = [c.get("id") for c in body["checks"]]
        # Pre-fix the block was ONE collapsed row: id="immich", "check failed".
        self.assertIn("immich_ct_immich_server", ids)
        self.assertIn("immich_worker", ids)
        self.assertNotIn("immich", ids)


class _StrScrubContractTests:
    """The scrub contract both modules share: never raise, keep the text."""

    mod = None

    def _js(self, value):
        return self.mod._jsonable({"wrap": value})["wrap"]

    def test_encode_bomb_value_keeps_its_text(self):
        self.assertEqual(self._js(_StrEncodeBomb("panel")), "panel")

    def test_encode_bomb_key_keeps_its_text(self):
        out = self.mod._jsonable({_StrEncodeBomb("k"): 1})
        self.assertEqual(out, {"k": 1})

    def test_surrogate_wearing_the_bomb_still_scrubs(self):
        # The scrub must still do its actual job on the bomb subclass.
        self.assertEqual(self._js(_StrEncodeBomb("a\ud800b")), "a?b")

    def test_self_str_bomb_object_degrades_to_its_text(self):
        # A non-str whose __str__ returns the bomb: pre-fix the encode blew
        # and _jsonable's last-resort except turned the value into None.
        self.assertEqual(self._js(_SelfStrToBomb()), "boom")

    def test_str_str_bomb_keeps_its_text(self):
        # A str instance skips str() now, so the __str__ bomb never fires
        # and the real text survives (the int.__index__ precedent).
        self.assertEqual(self._js(_StrStrBomb("kept")), "kept")

    def test_utf8_text_encode_bomb_still_scrubs(self):
        self.assertEqual(self.mod._utf8_text(_StrEncodeBomb("x")), "x")

    def test_as_text_encode_bomb_still_scrubs(self):
        self.assertEqual(self.mod._as_text(_StrEncodeBomb("x")), "x")

    def test_plain_str_still_passes_through(self):
        self.assertEqual(self._js("plain"), "plain")
        self.assertEqual(self.mod._as_text("a\ud800b"), "a?b")


class PhotoshubStrScrubContractTests(_StrScrubContractTests, unittest.TestCase):
    mod = photoshub_svc


class ImmichStrScrubContractTests(_StrScrubContractTests, unittest.TestCase):
    mod = immich_svc


class ExcDetailBombMessageTests(unittest.TestCase):
    """errors.exc_detail: the coded-error path must survive a bomb message."""

    def test_bomb_message_still_yields_its_text(self):
        # Pre-fix: str(exc) returned the bomb object itself and the bound
        # encode re-raised out of the except handler using exc_detail.
        self.assertEqual(
            exc_detail(RuntimeError(_StrEncodeBomb("msg"))), "msg",
        )

    def test_surrogate_bomb_message_still_scrubs(self):
        self.assertEqual(
            exc_detail(RuntimeError(_StrEncodeBomb("a\ud800b"))), "a?b",
        )

    def test_plain_message_is_unchanged(self):
        self.assertEqual(exc_detail(RuntimeError("plain")), "plain")


if __name__ == "__main__":
    unittest.main()
