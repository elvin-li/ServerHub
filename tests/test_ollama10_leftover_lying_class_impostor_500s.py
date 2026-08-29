"""Tenth leftover-500s sweep of the Ollama grain: *lying* ``__class__``
impostors past the ollama9 gates, over the real mounted app.

ollama9 sealed the ``__class__``-property *raising* bombs with ``_isa`` and
put most unbound base calls in a try — except three seams where the liar
class (the dash10/json9 impostor: a ``__class__`` property that *returns* a
claimed type while the real object is a plain object) still had nothing to
refuse it.  Confirmed live at HEAD:

* GET /api/ollama/pull/log — the bool gate in ``_jsonable`` returned anything
  answering ``isinstance(value, bool)`` verbatim.  Every other liar drops when
  its unbound base call (``dict.items`` / ``list.__iter__`` / ``bytes.decode``
  / ``int.__index__`` / ``float.__float__``) TypeErrors, but the bool gate had
  no call to make — and ``bool`` cannot be subclassed, so the C-level JSON
  encoder then refused the impostor downstream.  Planted as the pull row's
  ``rc`` / ``model`` / ``started``, or nested in a ``model`` mapping value, it
  500'd the route raw.  **Four live 500s.**
* GET /api/ollama/status — the same bool-liar pull fields rode ``pull_state``
  into the whole-page snapshot, survived the final ``_jsonable`` pass, and
  500'd the encoder at render time — *outside* the router's coded try, so the
  500 arrived raw.  **Two more.**
* GET /api/ollama/pull/log — a str-liar log *line* passed
  ``_pull_log_lines``' ``_isa(item, str)`` gate and was appended raw, so the
  bound ``str.join`` in ``pull_log`` TypeError'd the route.  **One more.**
* GET /api/ollama/status — a str-liar ``settings.ollama.url`` / ``.label``
  passed ``_as_text``'s str gate and the *unguarded* unbound ``str.encode``
  TypeError'd out of every ``base_url()`` / ``discover_label()`` caller: the
  coded 500 ``ollama.status_failed`` on status, and a lying 502
  (``unload_failed`` with descriptor gibberish) on the daemon POSTs.
  **Two more (plus the 502 lie).**

Fixes, keeping the conventions: the bool gate now requires the exact type
(``bool`` has no subclasses, so nothing legitimate is lost — the
status/system/storage_svc rule); ``_as_text``'s unbound encode runs in a try
and an impostor drops to "" (the ups_svc/wireguard rule), so a liar URL falls
back to the loopback default and a liar label reads as auto-discover; each
accepted log line is probed with unbound ``str.__len__``, which reads the
real storage — a genuine str subclass (bound ``__len__``/``__bool__`` bombs
included) still survives, only an impostor TypeErrors and drops alone.

Every case must answer without an HTTP 500, with a strictly UTF-8-encodable
body and the healthy sibling fields kept.  Do-not-weaken pins: the liar
shapes ollama9's laundering already dropped (int/float/bytes/dict/list liars,
the liar scalar ``log``, the liar ``busy`` model behind the 409) are pinned
too.  No product-version bump: 3.9.3 stays.
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
    # raise_server_exceptions=False: a real 500 must arrive as HTTP 500, not
    # as a re-raised exception that would mask which route crashed.
    return TestClient(_app, raise_server_exceptions=False)


# ── the impostor menagerie (the shapes ollama9 never planted) ────────────────

class _LyingBool:
    """Claims to be a bool; is not — and bool has no unbound call to refuse it."""

    @property
    def __class__(self):
        return bool


class _LyingInt:
    @property
    def __class__(self):
        return int


class _LyingFloat:
    @property
    def __class__(self):
        return float


class _LyingStr:
    @property
    def __class__(self):
        return str


class _LyingBytes:
    @property
    def __class__(self):
        return bytes


class _LyingDict:
    @property
    def __class__(self):
        return dict


class _LyingList:
    @property
    def __class__(self):
        return list


class _LenBombStr(str):
    """A *real* str subclass whose bound length/truth raises — must survive
    the unbound ``str.__len__`` probe (it reads the real storage)."""

    def __len__(self):
        raise RuntimeError("leftover __len__ bomb")

    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")


class _PullRowHttp(unittest.TestCase):
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

    def _plant(self, **junk):
        row = self._base_row()
        row.update(junk)
        ollama_svc._pull.clear()
        ollama_svc._pull.update(row)

    def _pull_log_200(self, **junk):
        self._plant(**junk)
        resp = self.client.get("/api/ollama/pull/log")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        resp.text.encode("utf-8")  # strict UTF-8, no surviving surrogate
        return json.loads(resp.text)


class PullLogBoolLiarTests(_PullRowHttp):
    """The ex-500s on GET /api/ollama/pull/log: the bool gate returned the
    impostor verbatim and the C-level encoder refused it."""

    def test_bool_liar_rc_drops_and_keeps_siblings(self):
        payload = self._pull_log_200(rc=_LyingBool())
        self.assertIsNone(payload["rc"])
        self.assertEqual(payload["model"], "m1")
        self.assertEqual(payload["log"], "line")

    def test_bool_liar_model_drops_and_keeps_siblings(self):
        payload = self._pull_log_200(model=_LyingBool())
        self.assertIsNone(payload["model"])
        self.assertEqual(payload["rc"], 0)
        self.assertEqual(payload["log"], "line")

    def test_bool_liar_started_drops_and_keeps_siblings(self):
        payload = self._pull_log_200(started=_LyingBool())
        self.assertIsNone(payload["started"])
        self.assertEqual(payload["finished"], "10:00:05")

    def test_bool_liar_nested_model_value_drops_alone(self):
        payload = self._pull_log_200(model={"k": _LyingBool(), "keep": "v"})
        self.assertIsNone(payload["model"]["k"])
        self.assertEqual(payload["model"]["keep"], "v")

    def test_real_bools_still_render_exactly(self):
        # The exact-type tightening must not cost a legitimate flag.
        payload = self._pull_log_200(rc=True, running=False)
        self.assertIs(payload["rc"], True)
        self.assertIs(payload["running"], False)


class PullLogStrLiarLineTests(_PullRowHttp):
    """The ex-500 where a str-liar log line rode into ``str.join``."""

    def test_str_liar_log_line_drops_alone(self):
        payload = self._pull_log_200(log=["keep", _LyingStr(), "tail"])
        self.assertEqual(payload["log"], "keep\ntail")
        self.assertEqual(payload["model"], "m1")

    def test_len_bomb_str_subclass_line_still_survives(self):
        # The unbound ``str.__len__`` probe reads the real storage: a real
        # subclass with bound ``__len__``/``__bool__`` bombs must not be the
        # collateral of the impostor guard.
        payload = self._pull_log_200(log=["keep", _LenBombStr("mid"), "tail"])
        self.assertEqual(payload["log"], "keep\nmid\ntail")


class PullLogLiarStaysImmune(_PullRowHttp):
    """Liar shapes ollama9's laundering already dropped — pinned so a gate
    reorder cannot reopen them."""

    def test_int_and_float_liars_drop_to_null(self):
        for liar in (_LyingInt(), _LyingFloat()):
            with self.subTest(liar=type(liar).__name__):
                payload = self._pull_log_200(rc=liar)
                self.assertIsNone(payload["rc"])
                self.assertEqual(payload["model"], "m1")

    def test_bytes_dict_and_list_liars_drop_to_null(self):
        for liar in (_LyingBytes(), _LyingDict(), _LyingList()):
            with self.subTest(liar=type(liar).__name__):
                payload = self._pull_log_200(model=liar)
                self.assertIn(payload["model"], (None, ""))
                self.assertEqual(payload["rc"], 0)

    def test_liar_scalar_log_answers_empty(self):
        for liar in (_LyingStr(), _LyingList()):
            with self.subTest(liar=type(liar).__name__):
                payload = self._pull_log_200(log=liar)
                self.assertEqual(payload["log"], "")
                self.assertEqual(payload["model"], "m1")

    def test_bool_liar_running_answers_a_real_bool(self):
        # _truthy degrades an answerable non-bool through plain bool(); a
        # bare object is truthy — the pin is that the field arrives as a
        # real JSON bool instead of detonating the encoder.
        payload = self._pull_log_200(running=_LyingBool())
        self.assertIs(payload["running"], True)

    def test_bool_liar_busy_model_keeps_the_409(self):
        self._plant(running=True, model=_LyingBool())
        with mock.patch.object(
            ollama_svc, "binary_path", return_value="/usr/local/bin/ollama"
        ):
            resp = self.client.post("/api/ollama/pull", json={"model": "m1"})
        self.assertEqual(resp.status_code, 409, resp.text[:300])
        self.assertEqual(
            json.loads(resp.text)["detail"]["code"], "ollama.pull_running")

    def test_str_liar_busy_model_keeps_the_delete_409(self):
        self._plant(running=True, model=_LyingStr())
        with mock.patch.object(
            ollama_svc, "binary_path", return_value="/usr/local/bin/ollama"
        ):
            resp = self.client.post(
                "/api/ollama/models/delete",
                json={"model": "m1", "confirm": True})
        self.assertEqual(resp.status_code, 409, resp.text[:300])
        self.assertEqual(
            json.loads(resp.text)["detail"]["code"], "ollama.pull_running")


class _StatusHttp(unittest.TestCase):
    """Drive GET /api/ollama/status hermetically over a bombed cfg."""

    def setUp(self):
        super().setUp()
        self.client = _client()
        self.addCleanup(ollama_svc.status.invalidate)
        ollama_svc.status.invalidate()

    def _status_200(self, cfg_val):
        ollama_svc.status.invalidate()
        with (
            mock.patch.object(ollama_svc, "cfg", lambda: cfg_val),
            mock.patch.object(ollama_svc, "binary_path", return_value=None),
            mock.patch.object(
                ollama_svc, "_ollama_open",
                side_effect=ConnectionRefusedError(111, "refused"),
            ),
            mock.patch("hub.launchd_cache.listing", side_effect=OSError("sandbox")),
        ):
            resp = self.client.get("/api/ollama/status", params={"force": "true"})
        ollama_svc.status.invalidate()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        resp.text.encode("utf-8")
        return json.loads(resp.text)


class StatusStrLiarSettingsTests(_StatusHttp):
    """The ex-coded-500s: a str-liar URL/label TypeError'd the unguarded
    unbound ``str.encode`` out of every base_url()/discover_label() caller."""

    def test_str_liar_url_reads_as_the_default(self):
        status = self._status_200(
            {"settings": {"ollama": {"url": _LyingStr()}}})
        self.assertEqual(status["url"], ollama_svc.DEFAULT_URL)
        # The impostor drops to "" (unconfigured), not to junk text that
        # base_url would then visibly reject.
        self.assertFalse(status["url_rejected"])

    def test_str_liar_label_reads_as_auto_discover(self):
        status = self._status_200(
            {"settings": {"ollama": {"label": _LyingStr()}}})
        self.assertEqual(status["url"], ollama_svc.DEFAULT_URL)
        self.assertIsInstance(status["service"], dict)

    def test_bool_liar_pull_rc_keeps_status_200(self):
        saved = {k: (list(v) if isinstance(v, list) else v)
                 for k, v in ollama_svc._pull.items()}
        ollama_svc._pull.update(rc=_LyingBool(), model=_LyingBool())
        try:
            status = self._status_200({"settings": {}})
        finally:
            ollama_svc._pull.clear()
            ollama_svc._pull.update(saved)
        self.assertIsNone(status["pull"]["rc"])
        self.assertIsNone(status["pull"]["model"])
        self.assertEqual(status["url"], ollama_svc.DEFAULT_URL)

    def test_other_scalar_liar_urls_stay_immune(self):
        # ollama9's laundering already dropped these; pinned.
        for liar in (_LyingBool(), _LyingBytes(), _LyingFloat(),
                     _LyingDict(), _LyingList()):
            with self.subTest(liar=type(liar).__name__):
                status = self._status_200(
                    {"settings": {"ollama": {"url": liar}}})
                self.assertEqual(status["url"], ollama_svc.DEFAULT_URL)
                self.assertFalse(status["url_rejected"])


class UnloadStrLiarUrlTests(unittest.TestCase):
    """The ex-lying-502: unload over a str-liar URL used to answer
    ``unload_failed`` carrying descriptor gibberish.  With the impostor
    dropped, the URL falls back to the default and a refused connection is
    the honest coded 503 ``ollama.unreachable``."""

    def test_unload_answers_the_coded_503_not_a_500(self):
        client = _client()
        ollama_svc.status.invalidate()
        self.addCleanup(ollama_svc.status.invalidate)
        with (
            mock.patch.object(
                ollama_svc, "cfg",
                lambda: {"settings": {"ollama": {"url": _LyingStr()}}}),
            mock.patch.object(
                ollama_svc, "_ollama_open",
                side_effect=ConnectionRefusedError(111, "refused"),
            ),
        ):
            resp = client.post("/api/ollama/models/unload", json={"model": "m1"})
        self.assertEqual(resp.status_code, 503, resp.text[:300])
        self.assertEqual(
            json.loads(resp.text)["detail"]["code"], "ollama.unreachable")


class SanitizerUnitPins(unittest.TestCase):
    """The helpers themselves at the ollama10 shapes."""

    def test_jsonable_drops_the_bool_liar_and_keeps_real_bools(self):
        self.assertIsNone(ollama_svc._jsonable(_LyingBool()))
        self.assertIs(ollama_svc._jsonable(True), True)
        self.assertIs(ollama_svc._jsonable(False), False)
        self.assertIsNone(ollama_svc._jsonable(None))

    def test_jsonable_nested_bool_liar_drops_alone(self):
        out = ollama_svc._jsonable({"k": _LyingBool(), "keep": 2})
        self.assertIsNone(out["k"])
        self.assertEqual(out["keep"], 2)
        json.dumps(out, allow_nan=False)

    def test_as_text_str_liar_answers_empty(self):
        self.assertEqual(ollama_svc._as_text(_LyingStr()), "")

    def test_as_text_keeps_a_real_str_subclass(self):
        self.assertEqual(ollama_svc._as_text(_LenBombStr("keep")), "keep")

    def test_settings_text_str_liar_answers_empty(self):
        self.assertEqual(ollama_svc.settings_text(_LyingStr()), "")

    def test_configured_url_str_liar_falls_back_to_default(self):
        with mock.patch.object(
            ollama_svc, "cfg",
            lambda: {"settings": {"ollama": {"url": _LyingStr()}}},
        ):
            self.assertEqual(ollama_svc.configured_url(), ollama_svc.DEFAULT_URL)
            self.assertEqual(ollama_svc.base_url(), ollama_svc.DEFAULT_URL)
            self.assertFalse(ollama_svc.url_was_rejected())

    def test_pull_log_lines_str_liar_item_drops_alone(self):
        self.assertEqual(
            ollama_svc._pull_log_lines(["keep", _LyingStr(), "tail"]),
            ["keep", "tail"])

    def test_pull_log_lines_keeps_the_len_bomb_subclass(self):
        out = ollama_svc._pull_log_lines([_LenBombStr("mid")])
        self.assertEqual(len(out), 1)
        self.assertEqual(str(out[0]), "mid")


if __name__ == "__main__":
    unittest.main()
