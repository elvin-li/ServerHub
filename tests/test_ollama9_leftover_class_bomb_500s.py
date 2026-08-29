"""Ninth leftover-500s sweep of the Ollama pull-log / settings / status grain.

ollama8 pinned the surfaces as immune at the subclass-bomb shapes (bound
truth tests, bound ``.encode`` / ``.get`` / ``.items``).  This sweep found a
class the whole grain missed: ``isinstance`` consults ``value.__class__``
whenever the exact-type check misses, so a leftover whose ``__class__`` is a
*raising property* detonated the bare rank gates themselves — one line ahead
of all the laundering the earlier sweeps built.  Confirmed raw 500s at HEAD:

* GET /api/ollama/pull/log — a ``__class__``-property bomb as the pull row's
  ``rc`` / ``model`` / ``log`` (scalar), as one *line* in ``log``, or as a
  nested ``model`` mapping value, through ``_jsonable`` / ``_pull_log_lines``'
  bare gates;
* GET /api/settings — the same bomb as the top-level config, the ``settings``
  block, the ``settings.ollama`` block, ``ollama.url`` / ``.label``
  (``_as_map`` / ``settings_text``), and riding sibling fields (``adaptive``,
  ``notify.enabled``, ``metrics_interval``, ``stacks``) through ``_flag`` /
  ``_truthy`` / ``_finite`` / ``_json_list``'s bare gates;
* GET /api/settings — a bytes-subclass whose ``__bytes__`` raises (the old
  ``bytes(value).decode`` copy dispatched into the override) and a leftover
  whose ``isoformat`` is a raising property (bare ``getattr`` probe; the
  default only swallows AttributeError);
* GET /api/ollama/status — every cfg-side shape above surfaced as the coded
  500 ``ollama.status_failed``, and a detonating ``cfg()`` loader itself did
  too (``_settings`` had no try around the read).

Fixes: the ``_isa`` guarded-isinstance convention (system/status/usage_svc
rule) on every leftover-reachable gate in ``hub.ollama_svc`` and the
GET-render helpers of ``hub.routers.settings_api``; unbound base decode
behind the bytes gates (kills the ``__bytes__`` dispatch); a guarded
``isoformat`` probe; try/except around ``cfg()`` in ``_settings``.

Stays-immune pins (no source change needed, shape verified at HEAD):
a float-subclass ``rc`` whose ``__eq__`` / ``__float__`` raises (base
coercion reads under the override), a ``__bytes__``-bomb ``ollama.url``
(``ollama_svc._decode_bytes`` was already unbound), and a leftover FIFO
occupying a LaunchAgent plist path (``read_bytes_capped``'s
O_NONBLOCK/S_ISREG guard) beside a clean agent.

Every case must answer HTTP 200 with a strictly UTF-8-encodable body and the
healthy sibling fields kept.  No product-version bump: 3.9.3 stays.
"""
from __future__ import annotations

import json
import os
import plistlib
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import ollama_svc
from hub.app_factory import create_app
from hub.auth import require_auth
from hub.routers import settings_api

_app = None


def _client() -> TestClient:
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return TestClient(_app, raise_server_exceptions=False)


# ── the bomb menagerie (the shapes ollama5/6/7/8 never planted) ──────────────

class _Boom(RuntimeError):
    pass


def _class_bomb():
    """A leftover whose ``__class__`` is a raising property.

    ``isinstance(bomb, anything)`` misses the exact-type fast path and then
    consults ``__class__`` — detonating the bare gate itself.
    """
    class _ClassBomb:
        @property
        def __class__(self):
            raise _Boom("leftover __class__ property bomb")

    return object.__new__(_ClassBomb)


class _BytesDunderBomb(bytes):
    def __bytes__(self):
        raise _Boom("leftover __bytes__ bomb")


class _IsoPropBomb:
    @property
    def isoformat(self):
        raise _Boom("leftover isoformat property bomb")


class _FloatEqBomb(float):
    def __eq__(self, other):
        raise _Boom("leftover __eq__ bomb")

    def __hash__(self):
        return 0


class _FloatFloatBomb(float):
    def __float__(self):
        raise _Boom("leftover __float__ bomb")


class _PullLogHttp(unittest.TestCase):
    """Patched cfg + saved/restored pull row + invalidated status snapshot."""

    def setUp(self):
        super().setUp()
        self.client = _client()
        patched = mock.patch.object(ollama_svc, "cfg", lambda: {"settings": {}})
        patched.start()
        self.addCleanup(patched.stop)
        saved = {k: (list(v) if isinstance(v, list) else v)
                 for k, v in ollama_svc._pull.items()}

        def restore():
            ollama_svc._pull.clear()
            ollama_svc._pull.update(saved)

        self.addCleanup(restore)
        self.addCleanup(ollama_svc.status.invalidate)
        ollama_svc.status.invalidate()

    @staticmethod
    def _base_row() -> dict:
        return dict(running=False, rc=0, model="m1", started="10:00:00",
                    finished="10:00:05", log=["line"])

    def _pull_log_200(self, **junk):
        row = self._base_row()
        row.update(junk)
        ollama_svc._pull.clear()
        ollama_svc._pull.update(row)
        resp = self.client.get("/api/ollama/pull/log")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        resp.text.encode("utf-8")  # strict UTF-8, no surviving surrogate
        return json.loads(resp.text)


class PullLogClassBombs(_PullLogHttp):
    """Each field of the in-memory pull row, poisoned with a ``__class__``
    bomb, used to 500 GET /api/ollama/pull/log raw."""

    def test_class_bomb_rc_degrades_and_keeps_siblings(self):
        payload = self._pull_log_200(rc=_class_bomb())
        self.assertEqual(payload["model"], "m1")
        self.assertEqual(payload["log"], "line")

    def test_class_bomb_model_degrades_and_keeps_siblings(self):
        payload = self._pull_log_200(model=_class_bomb())
        self.assertEqual(payload["rc"], 0)
        self.assertEqual(payload["log"], "line")

    def test_class_bomb_log_scalar_drops_to_empty_log(self):
        payload = self._pull_log_200(log=_class_bomb())
        self.assertEqual(payload["log"], "")
        self.assertEqual(payload["model"], "m1")

    def test_class_bomb_log_line_drops_alone(self):
        payload = self._pull_log_200(log=["keep", _class_bomb(), "tail"])
        self.assertEqual(payload["log"], "keep\ntail")

    def test_class_bomb_nested_model_value_degrades(self):
        payload = self._pull_log_200(model={"k": _class_bomb(), "keep": "v"})
        self.assertEqual(payload["model"]["keep"], "v")

    def test_class_bomb_mapping_key_degrades_and_keeps_real_key(self):
        payload = self._pull_log_200(model={_class_bomb(): "v", "keep": "k"})
        self.assertEqual(payload["model"]["keep"], "k")


class PullLogRcStaysImmune(_PullLogHttp):
    """Float-subclass ``__eq__``/``__float__`` bombs on ``rc`` were already
    immune (base ``float.__float__`` coercion reads under the override) —
    pinned so a later edit that reintroduces the bound probe trips here."""

    def test_float_eq_bomb_rc_recovers_the_base_value(self):
        payload = self._pull_log_200(rc=_FloatEqBomb(1.0))
        self.assertEqual(payload["rc"], 1.0)
        self.assertEqual(payload["model"], "m1")

    def test_float_float_bomb_rc_recovers_the_base_value(self):
        payload = self._pull_log_200(rc=_FloatFloatBomb(1.0))
        self.assertEqual(payload["rc"], 1.0)
        self.assertEqual(payload["model"], "m1")


class _SettingsHttp(unittest.TestCase):
    """Drive GET /api/settings + GET /api/ollama/status over a bombed cfg."""

    def setUp(self):
        super().setUp()
        self.client = _client()
        self.addCleanup(ollama_svc.status.invalidate)
        ollama_svc.status.invalidate()

    def _both_200(self, cfg_fn):
        ollama_svc.status.invalidate()
        with (
            mock.patch.object(ollama_svc, "cfg", cfg_fn),
            mock.patch("hub.routers.settings_api.cfg", cfg_fn),
        ):
            rs = self.client.get("/api/settings")
            self.assertEqual(rs.status_code, 200, rs.text[:300])
            rs.text.encode("utf-8")
            with (
                mock.patch.object(ollama_svc, "binary_path", return_value=None),
                mock.patch.object(
                    ollama_svc, "_ollama_open",
                    side_effect=ConnectionRefusedError(111, "refused"),
                ),
                mock.patch("hub.launchd_cache.listing", side_effect=OSError("sandbox")),
            ):
                rt = self.client.get("/api/ollama/status", params={"force": "true"})
            self.assertEqual(rt.status_code, 200, rt.text[:300])
            rt.text.encode("utf-8")
        ollama_svc.status.invalidate()
        return json.loads(rs.text), json.loads(rt.text)


class SettingsAndStatusClassBombs(_SettingsHttp):
    """A ``__class__`` bomb at every config level used to 500 GET
    /api/settings raw and GET /api/ollama/status coded."""

    def test_class_bomb_at_every_cfg_level(self):
        for name, make in {
            "top_level": lambda: _class_bomb(),
            "settings_block": lambda: {"settings": _class_bomb()},
            "ollama_block": lambda: {"settings": {"ollama": _class_bomb()}},
            "ollama_url": lambda: {"settings": {"ollama": {"url": _class_bomb()}}},
            "ollama_label": lambda: {"settings": {"ollama": {"label": _class_bomb()}}},
        }.items():
            with self.subTest(level=name):
                cfg_val = make()
                settings, status = self._both_200(lambda v=cfg_val: v)
                self.assertEqual(settings["ollama"]["url"], ollama_svc.DEFAULT_URL)
                self.assertEqual(status["url"], ollama_svc.DEFAULT_URL)
                self.assertFalse(status["url_rejected"])

    def test_class_bomb_sibling_fields_answer_defaults(self):
        cfg_val = {"settings": {
            "adaptive": _class_bomb(),
            "notify": {"enabled": _class_bomb()},
            "metrics_interval": _class_bomb(),
            "ollama": {"url": "http://127.0.0.1:11434"},
        }, "stacks": _class_bomb()}
        settings, _ = self._both_200(lambda: cfg_val)
        self.assertTrue(settings["adaptive"])
        # _truthy degrades an answerable non-bool through plain bool(); a
        # bare object is truthy — the pin is that it answers a bool at all
        # instead of detonating the gate.
        self.assertIsInstance(settings["notify"]["enabled"], bool)
        self.assertEqual(settings["metrics_interval"], 90)
        self.assertEqual(settings["stacks"], [])
        # The healthy ollama block beside the bombs still renders.
        self.assertEqual(settings["ollama"]["url"], "http://127.0.0.1:11434")

    def test_detonating_cfg_loader_reads_as_defaults(self):
        def bad_cfg():
            raise _Boom("cfg loader detonated")

        settings, status = self._both_200(bad_cfg)
        self.assertEqual(settings["ollama"]["url"], ollama_svc.DEFAULT_URL)
        self.assertEqual(status["url"], ollama_svc.DEFAULT_URL)

    def test_class_bomb_pull_rc_keeps_status_200(self):
        saved = {k: (list(v) if isinstance(v, list) else v)
                 for k, v in ollama_svc._pull.items()}
        ollama_svc._pull.update(rc=_class_bomb())
        try:
            _, status = self._both_200(lambda: {"settings": {}})
        finally:
            ollama_svc._pull.clear()
            ollama_svc._pull.update(saved)
        self.assertEqual(status["url"], ollama_svc.DEFAULT_URL)


class SettingsBytesAndIsoBombs(_SettingsHttp):
    def test_bytes_dunder_bomb_ui_locale_answers_default(self):
        # The old ``bytes(value).decode`` dispatched into the ``__bytes__``
        # override and 500'd the render; the unbound base decode reads the
        # real buffer, and the junk text then fails the whitelist to default.
        settings, _ = self._both_200(
            lambda: {"settings": {"ui": {"locale": _BytesDunderBomb(b"junk")}}})
        self.assertEqual(settings["ui"]["locale"], "zh-CN")

    def test_isoformat_property_bomb_degrades(self):
        # getattr's default only swallows AttributeError; the raising
        # property used to 500 GET /api/settings out of the probe itself.
        settings, _ = self._both_200(
            lambda: {"settings": {"ui": {"locale": _IsoPropBomb()}}})
        self.assertEqual(settings["ui"]["locale"], "zh-CN")

    def test_bytes_dunder_bomb_ollama_url_stays_immune(self):
        # ollama_svc._decode_bytes was already unbound — pin it: the decoded
        # junk is then visibly rejected by base_url back to the default.
        settings, status = self._both_200(
            lambda: {"settings": {"ollama": {"url": _BytesDunderBomb(b"junk")}}})
        self.assertEqual(status["url"], ollama_svc.DEFAULT_URL)
        self.assertTrue(status["url_rejected"])


@unittest.skipUnless(hasattr(os, "mkfifo"), "mkfifo not available")
class FifoPlistStaysImmune(unittest.TestCase):
    """A leftover FIFO occupying a LaunchAgent plist path beside a clean
    ollama agent keeps GET /api/ollama/status at 200 with the clean label
    discovered — read_bytes_capped's O_NONBLOCK/S_ISREG guard, pinned."""

    def setUp(self):
        super().setUp()
        self.client = _client()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.addCleanup(ollama_svc.status.invalidate)
        (self.tmp / "com.clean.ollama.plist").write_bytes(plistlib.dumps(
            {"Label": "com.clean.ollama", "ProgramArguments": ["ollama", "serve"]}))
        os.mkfifo(self.tmp / "fifo.ollama.plist")

    def test_status_200_with_clean_label(self):
        ollama_svc.status.invalidate()
        with (
            mock.patch.object(ollama_svc, "AGENTS_DIR", self.tmp),
            mock.patch.object(ollama_svc, "cfg", lambda: {"settings": {}}),
            mock.patch.object(ollama_svc, "binary_path", return_value=None),
            mock.patch.object(
                ollama_svc, "_ollama_open",
                side_effect=ConnectionRefusedError(111, "refused"),
            ),
            mock.patch("hub.launchd_cache.listing", side_effect=OSError("sandbox")),
        ):
            resp = self.client.get("/api/ollama/status", params={"force": "true"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        service = json.loads(resp.text)["service"]
        self.assertIn("com.clean.ollama", service["candidates"])
        ollama_svc.status.invalidate()


class SanitizerUnitPins(unittest.TestCase):
    """The helpers themselves at the ollama9 shapes."""

    def test_isa_answers_false_on_a_class_bomb(self):
        self.assertFalse(ollama_svc._isa(_class_bomb(), dict))
        self.assertFalse(settings_api._isa(_class_bomb(), (int, float)))

    def test_isa_still_matches_a_real_subclass(self):
        self.assertTrue(ollama_svc._isa(_FloatEqBomb(1.0), float))
        self.assertTrue(settings_api._isa(_BytesDunderBomb(b"x"), bytes))

    def test_settings_text_class_bomb_answers_empty(self):
        self.assertEqual(ollama_svc.settings_text(_class_bomb()), "")

    def test_settings_over_detonating_cfg_answers_empty(self):
        def bad_cfg():
            raise _Boom("cfg loader detonated")

        with mock.patch.object(ollama_svc, "cfg", bad_cfg):
            self.assertEqual(ollama_svc._settings(), {})
            self.assertEqual(ollama_svc.base_url(), ollama_svc.DEFAULT_URL)

    def test_pull_log_lines_class_bomb_scalar_answers_empty(self):
        self.assertEqual(ollama_svc._pull_log_lines(_class_bomb()), [])

    def test_ollama_jsonable_class_bomb_degrades_to_text(self):
        out = ollama_svc._jsonable(_class_bomb())
        self.assertIsInstance(out, str)

    def test_settings_jsonable_bytes_dunder_bomb_decodes_the_buffer(self):
        self.assertEqual(settings_api._jsonable(_BytesDunderBomb(b"keep")), "keep")
        self.assertEqual(settings_api._utf8_text(_BytesDunderBomb(b"keep")), "keep")

    def test_settings_jsonable_isoformat_property_bomb_degrades(self):
        out = settings_api._jsonable(_IsoPropBomb())
        self.assertIsInstance(out, str)


if __name__ == "__main__":
    unittest.main()
