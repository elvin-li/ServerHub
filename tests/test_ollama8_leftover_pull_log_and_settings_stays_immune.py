"""Eighth leftover-500s sweep of the Ollama pull-log / settings surfaces.

ollama7 sealed the last two live 500s on these surfaces: the plain-str
``log`` truth test (``_pull_log_lines`` gated on ``[raw] if raw else []``,
which dispatched into a str-subclass ``__bool__``/``__len__`` bomb) and the
self-``__str__`` encode bomb (``_utf8_text`` used the bound ``.encode``).
This sweep re-walked GET /api/ollama/pull/log, GET /api/settings' ollama
block and the GET /api/ollama/status url/service fields hunting for a
*remaining* raw 500 in that grain and found none: the pull store reads
(``pull_state`` / ``_pull_log_lines`` / ``_utf8_text``), the settings text
coercer (``settings_text`` → ``configured_url`` → ``base_url`` →
``url_was_rejected``) and the plist label scan (``_candidate_labels`` /
``_plist_label_if_ollama`` behind ``read_bytes_capped``'s O_NONBLOCK/S_ISREG
FIFO guard) already carry the full unbound-base convention from ollama5/6/7
and the sibling sweeps.

So ollama8 folds no source change; it pins the surfaces that stay immune, at
shapes past the ones ollama7 already covers, so a later edit that reopens the
bound truth-test / bound ``.encode`` / bound ``.get`` / bound ``.items`` on
these two surfaces trips here:

* a str-subclass ``log`` whose ``__hash__`` / ``__eq__`` raises (join reads
  the raw buffer, never the override), an int-subclass ``rc`` whose
  ``__index__`` raises, a >4300-digit ``rc``, a lone-surrogate ``log`` line;
* a nested self-``__str__`` bomb riding a dict *key* and *value* in ``model``;
* every exotic YAML/plist scalar a SafeLoader/plistlib actually mints
  (date, datetime, set, bytes, inf/nan, >4300-digit int, list, dict) planted
  as ``settings.ollama.url`` / ``.label``;
* a dict-*subclass* ``.get``/``.items``/``__bool__`` bomb as the top-level
  config, the ``settings`` block, and the ``settings.ollama`` block;
* a torn/ExpatError/over-cap-hex-int plist beside a clean ollama agent in a
  real AGENTS_DIR (status keeps 200, the clean label is discovered).

Every case must answer HTTP 200 with a strictly UTF-8-encodable body, and the
recoverable real text (busy model name, log tail) must survive rather than
drop to "".  No product-version bump: 3.9.3 stays.
"""
from __future__ import annotations

import datetime
import json
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


# ── the bomb menagerie (past the shapes ollama5/6/7 already pin) ─────────────

class _StrHashBomb(str):
    def __hash__(self):
        raise RuntimeError("leftover __hash__ bomb")


class _StrEqBomb(str):
    def __eq__(self, other):
        raise RuntimeError("leftover __eq__ bomb")

    def __hash__(self):
        return 0


class _SelfStr(str):
    """``str(x)`` keeps the subclass; the bound ``.encode`` would then bomb."""

    def __str__(self):
        return self

    def encode(self, *a, **k):
        raise RuntimeError("leftover .encode bomb")


class _IntIndexBomb(int):
    def __index__(self):
        raise RuntimeError("leftover __index__ bomb")

    def __str__(self):
        raise RuntimeError("leftover __str__ bomb")


class _DictGetBomb(dict):
    def get(self, *a, **k):
        raise RuntimeError("leftover .get bomb")


class _DictItemsBomb(dict):
    def items(self):
        raise RuntimeError("leftover .items bomb")


class _DictBoolBomb(dict):
    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")


_HUGE_INT = 10 ** 4400
_SURROGATE = "tail\ud800end"

#: Every exotic scalar a YAML SafeLoader / plistlib actually mints on a
#: hand-edited settings.ollama.{url,label}.
_EXOTIC_SCALARS = {
    "date": datetime.date(2023, 8, 19),
    "datetime": datetime.datetime(2023, 8, 19, 10, 0, 0),
    "set": {"a", "b"},
    "bytes": b"\xff\xfe not-a-url",
    "inf": float("inf"),
    "nan": float("nan"),
    "huge_int": _HUGE_INT,
    "list": ["http://127.0.0.1:11434"],
    "dict": {"k": "v"},
    "none": None,
    "bool": True,
    "numeric_id": 2023,
}


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
        payload = json.loads(resp.text)
        resp.text.encode("utf-8")  # strict UTF-8, no surviving surrogate
        return payload


class PullLogStaysImmune(_PullLogHttp):
    def test_str_hash_bomb_log_holds(self):
        # str.join reads the raw buffer, never __hash__/__eq__ overrides.
        self.assertEqual(self._pull_log_200(log=_StrHashBomb("tail"))["log"], "tail")

    def test_str_eq_bomb_log_holds(self):
        self.assertEqual(self._pull_log_200(log=_StrEqBomb("tail"))["log"], "tail")

    def test_multi_line_subclass_log_joins_to_exact_str(self):
        payload = self._pull_log_200(log=[_StrHashBomb("a"), _SelfStr("b"), _StrEqBomb("c")])
        self.assertEqual(payload["log"], "a\nb\nc")

    def test_surrogate_log_line_is_scrubbed(self):
        payload = self._pull_log_200(log=[_SURROGATE])
        payload["log"].encode("utf-8")
        self.assertNotIn("\ud800", payload["log"])

    def test_int_index_bomb_rc_recovers_the_base_value(self):
        # Unbound ``int.__index__`` reads the base int under the override, so
        # the real rc survives rather than 500ing the digit-cap probe.
        payload = self._pull_log_200(rc=_IntIndexBomb(7))
        self.assertEqual(payload["rc"], 7)
        self.assertEqual(payload["model"], "m1")

    def test_huge_int_rc_drops_but_keeps_payload(self):
        payload = self._pull_log_200(rc=_HUGE_INT)
        self.assertIsNone(payload["rc"])
        self.assertEqual(payload["model"], "m1")

    def test_nested_self_str_key_and_value_in_model_recover(self):
        payload = self._pull_log_200(
            model={"k": _SelfStr("keep-v"), _SelfStr("keep-key"): "v"},
        )
        self.assertEqual(payload["model"], {"k": "keep-v", "keep-key": "v"})

    def test_busy_409_recovers_the_real_busy_model(self):
        # The pull_running mutex message still laundering the model name.
        ollama_svc._pull.clear()
        ollama_svc._pull.update({**self._base_row(),
                                 "running": True, "model": _SelfStr("busy")})
        with mock.patch.object(ollama_svc, "binary_path", return_value="/fake/ollama"):
            resp = self.client.post("/api/ollama/pull", json={"model": "m2"})
        self.assertEqual(resp.status_code, 409, resp.text[:300])
        self.assertEqual(_err_code(resp), "ollama.pull_running")
        self.assertEqual(resp.json()["detail"]["params"]["model"], "busy")


class _SettingsHttp(unittest.TestCase):
    """Drive GET /api/settings + GET /api/ollama/status over a bombed cfg."""

    def setUp(self):
        super().setUp()
        self.client = _client()
        self.addCleanup(ollama_svc.status.invalidate)
        ollama_svc.status.invalidate()

    def _both_200(self, cfg_val):
        ollama_svc.status.invalidate()
        with (
            mock.patch.object(ollama_svc, "cfg", lambda: cfg_val),
            mock.patch("hub.routers.settings_api.cfg", lambda: cfg_val),
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


class SettingsScalarsStayImmune(_SettingsHttp):
    def test_every_exotic_url_scalar_holds(self):
        for name, val in _EXOTIC_SCALARS.items():
            with self.subTest(url=name):
                self._both_200({"settings": {"ollama": {"url": val}}})

    def test_every_exotic_label_scalar_holds(self):
        for name, val in _EXOTIC_SCALARS.items():
            with self.subTest(label=name):
                self._both_200({"settings": {"ollama": {"label": val}}})

    def test_self_str_url_and_label_hold(self):
        settings, _ = self._both_200({"settings": {"ollama": {
            "url": _SelfStr("http://127.0.0.1:11434"),
            "label": _SelfStr("com.kiro.ollama"),
        }}})
        self.assertEqual(settings["ollama"]["label"], "com.kiro.ollama")


class SettingsSubclassBlocksStayImmune(_SettingsHttp):
    def test_dict_subclass_config_at_every_level(self):
        for name, cfg_val in {
            "top_get": _DictGetBomb(settings={"ollama": {}}),
            "settings_get": {"settings": _DictGetBomb(ollama={})},
            "ollama_get": {"settings": {"ollama": _DictGetBomb(
                url="http://127.0.0.1:11434", label="com.kiro.ollama")}},
            "ollama_items": {"settings": {"ollama": _DictItemsBomb(
                url="http://127.0.0.1:11434", label="com.kiro.ollama")}},
            "ollama_bool": {"settings": {"ollama": _DictBoolBomb(
                url="http://127.0.0.1:11434", label="com.kiro.ollama")}},
        }.items():
            with self.subTest(block=name):
                self._both_200(cfg_val)


class PlistScanStaysImmune(unittest.TestCase):
    """A torn / ExpatError / over-cap-hex plist beside a clean ollama agent
    keeps GET /api/ollama/status at 200 with the clean label discovered."""

    def setUp(self):
        super().setUp()
        self.client = _client()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.addCleanup(ollama_svc.status.invalidate)
        (self.tmp / "com.clean.ollama.plist").write_bytes(plistlib.dumps(
            {"Label": "com.clean.ollama", "ProgramArguments": ["ollama", "serve"]}))
        (self.tmp / "torn.plist").write_bytes(b"<plist><dict><key>ollama")
        (self.tmp / "hexint.plist").write_bytes(
            b"<?xml version='1.0'?><!DOCTYPE plist><plist version='1.0'><dict>"
            b"<key>ollama</key><integer>0x" + b"f" * 5000 + b"</integer>"
            b"</dict></plist>")

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
    """The helpers themselves at the ollama8 shapes."""

    def test_pull_log_lines_survives_hash_and_eq_bombs(self):
        # The subclass stays in the returned list (join launders it
        # downstream), so compare through the real pull_log() pipeline: an
        # exact-str join + _utf8_text, which never dispatches the override.
        for bomb in (_StrHashBomb("x"), _StrEqBomb("x")):
            joined = ollama_svc._utf8_text(
                "\n".join(ollama_svc._pull_log_lines(bomb)))
            self.assertEqual(joined, "x")
            self.assertIs(type(joined), str)

    def test_utf8_text_self_str_bomb_launders_to_exact_str(self):
        out = ollama_svc._utf8_text(_SelfStr("keep"))
        self.assertEqual(out, "keep")
        self.assertIs(type(out), str)

    def test_settings_text_exotic_scalars(self):
        self.assertEqual(ollama_svc.settings_text(2023), "2023")
        self.assertEqual(ollama_svc.settings_text(_HUGE_INT), "")
        self.assertEqual(ollama_svc.settings_text(datetime.date(2023, 8, 19)), "")
        self.assertEqual(ollama_svc.settings_text({"k": "v"}), "")
        self.assertEqual(ollama_svc.settings_text(["x"]), "")
        self.assertEqual(ollama_svc.settings_text(float("inf")), "")

    def test_configured_url_over_dict_subclass_block(self):
        cfg_val = {"settings": {"ollama": _DictGetBomb(url="http://127.0.0.1:9999")}}
        with mock.patch.object(ollama_svc, "cfg", lambda: cfg_val):
            # _mapping_get's ``dict.get`` fallback + the plain-dict copy in
            # _settings read the real url out from under the ``.get`` bomb
            # instead of raising into base_url()'s callers; the local origin
            # then survives rather than falling back to the default.
            self.assertEqual(ollama_svc.base_url(), "http://127.0.0.1:9999")
            self.assertFalse(ollama_svc.url_was_rejected())


if __name__ == "__main__":
    unittest.main()
