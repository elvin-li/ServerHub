"""Sixth leftover-500s sweep of the Ollama surface, over the real app.

The find: the pull store and the settings read never got the subclass-bomb
hardening the rest of the tree standardized on (the modules5 unbound
convention: ``hub.jobs._truthy`` / ``_log_lines``, ``hub.modules._jsonable``,
``hub.ups_svc._mapping_get``).  Driven through ``create_app()`` +
``TestClient(raise_server_exceptions=False)``, ten junk shapes were live raw
HTTP 500s on the pre-fix tree:

* GET /api/ollama/pull/log — eight junk in-memory ``_pull`` values:
  a ``__bool__``-bomb ``running`` (bare ``bool()`` in ``pull_state``), a
  list-subclass ``__iter__`` bomb in ``log`` (``_pull_log_lines`` iterated
  past its isinstance gate) and in ``model`` (``_jsonable``'s sequence
  branch), a dict-subclass ``items()`` bomb (``_jsonable`` called the bound
  method), a bytes-subclass ``decode`` bomb, an int-subclass ``__str__``
  bomb (only ValueError was caught around the digit-cap probe), a
  float-subclass ``__eq__`` bomb (the NaN/inf probes compare), and a
  property-bomb ``isoformat`` (bare ``getattr`` only swallows
  AttributeError);
* POST /api/ollama/pull and POST /api/ollama/models/delete — the same
  ``__bool__``-bomb ``running`` fired inside ``if _pull["running"]:`` (and a
  bomb ``model`` inside the truth test hidden in ``or ""``).

The same bombs took GET /api/ollama/status from 200 to a whole-page coded
500 ``ollama.status_failed``, and a dict-subclass ``.get`` bomb (or a
str-subclass ``.encode`` / int-subclass ``__str__`` bomb) planted in
``settings`` / ``settings.ollama`` raised out of ``base_url()`` into every
daemon POST — a lying ``unload_failed`` 502 blaming the daemon for a local
settings leftover, and the same whole-page status 500.

Fixes, all in hub/ollama_svc.py, all the established conventions:
``_truthy`` (jobs), unbound ``dict.items`` / ``base.__iter__`` /
``int.__index__`` / ``float.__float__`` / ``bytes.decode`` / ``str.encode``
in ``_jsonable`` / ``_as_text`` / ``settings_text`` (modules), guarded
``getattr`` (jobs), and ``_mapping_get`` + a plain-dict copy in
``_settings`` (ups_svc).

Stays-immune pin: a torn *binary* plist (``bplist00`` + garbage — plistlib
raises IndexError-shaped junk, not InvalidFileException) beside a clean
agent keeps GET /api/ollama/status at 200 with the clean label discovered.
"""
from __future__ import annotations

import json
import plistlib
import shutil
import tempfile
import time
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


class _BoolBomb:
    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")


class _DictGetBomb(dict):
    def get(self, *a, **k):
        raise RuntimeError("leftover .get bomb")


class _DictItemsBomb(dict):
    def items(self):
        raise RuntimeError("leftover .items bomb")


class _ListIterBomb(list):
    def __iter__(self):
        raise RuntimeError("leftover __iter__ bomb")


class _IntStrBomb(int):
    def __str__(self):
        raise RuntimeError("leftover __str__ bomb")


class _FloatEqBomb(float):
    def __eq__(self, other):
        raise RuntimeError("leftover __eq__ bomb")

    __ne__ = __eq__
    __hash__ = float.__hash__


class _BytesDecodeBomb(bytes):
    def decode(self, *a, **k):
        raise RuntimeError("leftover .decode bomb")


class _StrEncodeBomb(str):
    def encode(self, *a, **k):
        raise RuntimeError("leftover .encode bomb")


class _IsoPropBomb:
    @property
    def isoformat(self):
        raise RuntimeError("leftover property bomb")


class _OllamaHttp(unittest.TestCase):
    """Patched cfg, saved/restored pull row, invalidated status snapshot."""

    def setUp(self):
        super().setUp()
        self.client = _client()
        self._settings: dict = {}
        patched = mock.patch.object(ollama_svc, "cfg", lambda: {"settings": self._settings})
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

    def _agents_dir(self) -> Path:
        tmp = Path(tempfile.mkdtemp(prefix="serverhub-ollama6-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        patched = mock.patch.object(ollama_svc, "AGENTS_DIR", tmp)
        patched.start()
        self.addCleanup(patched.stop)
        return tmp

    def _daemon_refused(self):
        patched = mock.patch.object(
            ollama_svc, "_ollama_open",
            side_effect=ConnectionRefusedError(61, "refused"),
        )
        patched.start()
        self.addCleanup(patched.stop)

    def _status(self):
        self._agents_dir()
        self._daemon_refused()
        with (
            mock.patch.object(ollama_svc, "binary_path", return_value=None),
            mock.patch("hub.launchd_cache.listing", side_effect=OSError("sandbox")),
        ):
            return self.client.get("/api/ollama/status", params={"force": "true"})

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


class PullRowBombHttpTests(_OllamaHttp):
    """Raw 500s on the pre-fix tree: junk in-memory pull-row values."""

    def test_bool_bomb_running_keeps_pull_log_up(self):
        payload = self._pull_log_200(running=_BoolBomb())
        self.assertFalse(payload["running"])
        self.assertIn("line", payload["log"])

    def test_list_iter_bomb_log_salvages_the_real_lines(self):
        payload = self._pull_log_200(log=_ListIterBomb(["a", "b"]))
        self.assertEqual(payload["log"], "a\nb")
        self.assertEqual(payload["model"], "m1")

    def test_dict_items_bomb_model_keeps_the_row_shape(self):
        payload = self._pull_log_200(model=_DictItemsBomb({"x": 1}))
        self.assertIn("line", payload["log"])

    def test_list_iter_bomb_model_salvages_real_elements(self):
        payload = self._pull_log_200(model=_ListIterBomb(["kept"]))
        self.assertEqual(payload["model"], ["kept"])

    def test_bytes_decode_bomb_model_decodes_via_the_base(self):
        payload = self._pull_log_200(model=_BytesDecodeBomb(b"mm"))
        self.assertEqual(payload["model"], "mm")

    def test_int_str_bomb_rc_coerces_via_the_base(self):
        payload = self._pull_log_200(rc=_IntStrBomb(5))
        self.assertEqual(payload["rc"], 5)

    def test_float_eq_bomb_rc_coerces_via_the_base(self):
        payload = self._pull_log_200(rc=_FloatEqBomb(1.5))
        self.assertEqual(payload["rc"], 1.5)

    def test_isoformat_property_bomb_started_is_dropped(self):
        payload = self._pull_log_200(started=_IsoPropBomb())
        self.assertIn("line", payload["log"])

    def test_surrogate_key_in_a_junk_model_dict_is_scrubbed(self):
        payload = self._pull_log_200(model={"\ud800k": "v", b"\xffk": "w"})
        self.assertEqual(set(payload["model"].values()), {"v", "w"})

    def test_post_pull_survives_the_bool_bomb(self):
        row = self._base_row()
        row["running"] = _BoolBomb()
        row["model"] = _BoolBomb()
        self._set_pull(**row)
        with (
            mock.patch.object(ollama_svc, "binary_path", return_value="/fake/ollama"),
            mock.patch.object(ollama_svc, "run_watchdog", return_value=0),
        ):
            resp = self.client.post("/api/ollama/pull", json={"model": "m1"})
            self.assertEqual(resp.status_code, 200, resp.text[:300])
            self.assertEqual(json.loads(resp.text)["model"], "m1")
            # Wait for the worker so no thread leaks into the next test.
            for _ in range(200):
                if not ollama_svc._pull.get("running"):
                    break
                time.sleep(0.01)
            self.assertFalse(ollama_svc._pull.get("running"))

    def test_post_delete_survives_the_bool_bomb(self):
        row = self._base_row()
        row["running"] = _BoolBomb()
        self._set_pull(**row)
        with (
            mock.patch.object(ollama_svc, "binary_path", return_value="/fake/ollama"),
            mock.patch.object(ollama_svc, "run_watchdog", return_value=0),
        ):
            resp = self.client.post(
                "/api/ollama/models/delete",
                json={"model": "m1", "confirm": True},
            )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertTrue(json.loads(resp.text)["ok"])

    def test_a_real_running_pull_still_refuses_with_the_coded_409(self):
        # The fail-closed _truthy must not have broken the mutex itself.
        row = self._base_row()
        row["running"] = True
        row["model"] = "busy-model"
        self._set_pull(**row)
        with mock.patch.object(ollama_svc, "binary_path", return_value="/fake/ollama"):
            resp = self.client.post("/api/ollama/pull", json={"model": "m2"})
        self.assertEqual(resp.status_code, 409, resp.text[:300])
        self.assertEqual(_err_code(resp), "ollama.pull_running")
        detail = resp.json()["detail"]
        self.assertEqual(detail["params"]["model"], "busy-model")

    def test_status_stays_200_with_the_whole_junk_row(self):
        self._set_pull(running=_BoolBomb(), rc=_IntStrBomb(7),
                       model=_DictItemsBomb({"x": 1}), started=_IsoPropBomb(),
                       finished=_FloatEqBomb(2.5), log=_ListIterBomb(["l"]))
        resp = self._status()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        pull = json.loads(resp.text)["pull"]
        self.assertFalse(pull["running"])
        self.assertEqual(pull["rc"], 7)


class SettingsBombHttpTests(_OllamaHttp):
    """Dict-subclass / str-subclass bombs in settings must not blow routes."""

    def _unload(self):
        self._daemon_refused()
        return self.client.post("/api/ollama/models/unload", json={"model": "m1"})

    def test_settings_block_get_bomb_keeps_the_coded_error(self):
        with mock.patch.object(
            ollama_svc, "cfg",
            lambda: {"settings": _DictGetBomb({"ollama": {}})},
        ):
            resp = self._unload()
        self.assertIn(resp.status_code, (502, 503), resp.text[:300])
        self.assertIn(_err_code(resp), ("ollama.unload_failed", "ollama.unreachable"))

    def test_ollama_block_get_bomb_keeps_the_coded_error(self):
        self._settings["ollama"] = _DictGetBomb({"url": "http://127.0.0.1:11434"})
        resp = self._unload()
        self.assertIn(resp.status_code, (502, 503), resp.text[:300])
        self.assertIn(_err_code(resp), ("ollama.unload_failed", "ollama.unreachable"))

    def test_str_encode_bomb_url_still_reads_through_the_base(self):
        self._settings["ollama"] = {"url": _StrEncodeBomb("http://127.0.0.1:11434")}
        # The base-storage read keeps the configured value, so base_url()
        # still answers the sane origin instead of raising.
        self.assertEqual(ollama_svc.base_url(), "http://127.0.0.1:11434")
        resp = self._unload()
        self.assertIn(resp.status_code, (502, 503), resp.text[:300])

    def test_int_str_bomb_url_reads_as_unconfigured(self):
        self._settings["ollama"] = {"url": _IntStrBomb(2023)}
        self.assertEqual(ollama_svc.base_url(), ollama_svc.DEFAULT_URL)
        resp = self._unload()
        self.assertIn(resp.status_code, (502, 503), resp.text[:300])

    def test_status_stays_200_under_every_settings_bomb(self):
        for block in (
            _DictGetBomb({}),
            {"url": _StrEncodeBomb("http://127.0.0.1:11434")},
            {"label": _StrEncodeBomb("com.example.ollama")},
            {"label": _FloatEqBomb(3.5)},
            {"url": _IntStrBomb(2023)},
        ):
            with self.subTest(block=type(block).__name__ + repr(sorted(
                    dict.keys(block)))):
                self._settings.clear()
                self._settings["ollama"] = block
                resp = self._status()
                self.assertEqual(resp.status_code, 200, resp.text[:300])
                json.loads(resp.text)


class TornBinaryPlistStaysImmuneTests(_OllamaHttp):
    """A torn ``bplist00`` beside a clean agent: skipped, never a 500."""

    def test_torn_binary_plist_is_skipped_and_the_sibling_discovered(self):
        agents = self._agents_dir()
        # plistlib detects the binary magic then dies mid-parse with junk
        # offsets — an IndexError/ValueError shape, not InvalidFileException.
        (agents / "torn.ollama.plist").write_bytes(b"bplist00\x00\x01\x02")
        (agents / "clean.plist").write_bytes(plistlib.dumps({
            "Label": "local.ollama.serve",
            "ProgramArguments": ["/opt/homebrew/bin/ollama", "serve"],
        }))
        self._daemon_refused()
        with (
            mock.patch.object(ollama_svc, "binary_path", return_value=None),
            mock.patch("hub.launchd_cache.listing", side_effect=OSError("sandbox")),
        ):
            resp = self.client.get("/api/ollama/status", params={"force": "true"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        candidates = json.loads(resp.text)["service"]["candidates"]
        self.assertEqual(candidates, ["local.ollama.serve"])


if __name__ == "__main__":
    unittest.main()
