"""Eleventh leftover-500s sweep of the Ollama grain: hash-shadowing mapping
*keys*, over the real mounted app.

ollama10 sealed the lying-``__class__`` impostors; the gates it hardened all
probe *values*.  The stored *keys* were still trusted: even a plain-dict
``.get`` / ``.update`` probe compares against every stored key whose hash
collides, dispatching into that key's own ``__eq__`` inside the C-level
lookup — the host10 / jobs ``_mapping_get`` / ``_merged_section`` class the
ollama grain never got.  Confirmed live at HEAD, a leftover str-subclass key
whose text shadows a real field name and whose ``__eq__`` raises:

* planted in the in-memory pull row — ``_pull.get("running"/"model"/"rc"/
  "log")`` 500'd GET /api/ollama/pull/log raw, took GET /api/ollama/status to
  the coded 500, and 500'd POST /api/ollama/pull AND
  POST /api/ollama/models/delete out of the single-pull mutex scan; the
  ``_pull.update`` insert probe 500'd POST /api/ollama/pull before the pull
  ever started.
* planted beside ``url`` / ``label`` in ``settings.ollama`` —
  ``_settings().get(...)`` detonated out of every ``base_url()`` /
  ``discover_label()`` caller: the coded 500 ``ollama.status_failed`` on
  GET /api/ollama/status, a raw 500 on POST /api/ollama/models/delete
  (``_cli_env``), a raw 500 on the GET /api/settings render
  (``ollama.get("url")`` — the terminal render already used
  ``_mapping_get``), and a raw 500 on the PUT /api/settings ollama save
  (``dict(settings_section("ollama")).update(o)`` — the terminal save
  already used ``_merged_section``).

Fixes, keeping the conventions: ``_row_get`` (the jobs ``_mapping_get``
rule) on every pull-row read; ``_reset_pull_row`` drops a row the insert
probe cannot touch and publishes the real one into the same dict object;
``configured_url`` / ``discover_label`` read the settings block through the
module's ``_mapping_get``; the settings render and save reuse the guards the
terminal branch already had.  Only the shadowed field degrades to its
default — sibling fields, healthy rows, and the coded 4xx answers survive.

Do-not-weaken pins: the ollama10 liar drops, the ``_LenBombStr`` survivor,
real configured values beside a shadow key, and a *genuine* well-behaved
str-subclass key merging normally through the save.  No product-version
bump: 3.9.3 stays.
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


class _ShadowKey(str):
    """Same text and hash as a real field name; comparing it detonates."""

    def __eq__(self, other):
        raise RuntimeError("leftover __eq__ bomb")

    def __ne__(self, other):
        raise RuntimeError("leftover __ne__ bomb")

    def __hash__(self):
        return hash(str(self))


class _TameKey(str):
    """A genuine, well-behaved str subclass key — must NOT be collateral."""


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
    def _plant(row: dict):
        ollama_svc._pull.clear()
        # dict.update with a pre-built dict: inserting into the emptied
        # store cannot collide, so the bomb key lands intact for the test.
        dict.update(ollama_svc._pull, row)

    @staticmethod
    def _row(**overrides) -> dict:
        row = dict(running=False, rc=0, model="m1", started="10:00:00",
                   finished="10:00:05", log=["line"])
        row.update(overrides)
        return row

    def _pull_log_200(self) -> dict:
        resp = self.client.get("/api/ollama/pull/log")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        resp.text.encode("utf-8")
        return json.loads(resp.text)


class PullRowShadowKeyTests(_PullRowHttp):
    """The ex-raw-500s on the pull routes: bare ``_pull.get`` ran the bomb."""

    def test_shadow_running_key_reads_not_running_and_keeps_siblings(self):
        row = self._row()
        del row["running"]
        row[_ShadowKey("running")] = True
        self._plant(row)
        payload = self._pull_log_200()
        self.assertIs(payload["running"], False)
        self.assertEqual(payload["model"], "m1")
        self.assertEqual(payload["log"], "line")

    def test_shadow_rc_and_model_keys_degrade_alone(self):
        row = self._row()
        del row["rc"], row["model"]
        row[_ShadowKey("rc")] = 7
        row[_ShadowKey("model")] = "ghost"
        self._plant(row)
        payload = self._pull_log_200()
        self.assertIsNone(payload["rc"])
        self.assertIsNone(payload["model"])
        self.assertEqual(payload["started"], "10:00:00")

    def test_shadow_log_key_answers_empty_log(self):
        row = self._row()
        del row["log"]
        row[_ShadowKey("log")] = ["boom"]
        self._plant(row)
        payload = self._pull_log_200()
        self.assertEqual(payload["log"], "")
        self.assertEqual(payload["model"], "m1")

    def test_shadow_running_key_keeps_status_200(self):
        row = self._row()
        del row["running"]
        row[_ShadowKey("running")] = True
        self._plant(row)
        ollama_svc.status.invalidate()
        with (
            mock.patch.object(ollama_svc, "binary_path", return_value=None),
            mock.patch.object(
                ollama_svc, "_ollama_open",
                side_effect=ConnectionRefusedError(111, "refused")),
            mock.patch("hub.launchd_cache.listing", side_effect=OSError("no")),
        ):
            resp = self.client.get("/api/ollama/status", params={"force": "true"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertIs(json.loads(resp.text)["pull"]["running"], False)

    def test_shadow_model_key_keeps_the_pull_mutex_409(self):
        # running=True survives; the busy model name is the shadowed field —
        # the 409 must still arrive, with the model degraded to "".
        row = self._row(running=True)
        del row["model"]
        row[_ShadowKey("model")] = "busy"
        self._plant(row)
        with mock.patch.object(
            ollama_svc, "binary_path", return_value="/usr/local/bin/ollama"
        ):
            resp = self.client.post("/api/ollama/pull", json={"model": "m1"})
        self.assertEqual(resp.status_code, 409, resp.text[:300])
        self.assertEqual(
            json.loads(resp.text)["detail"]["code"], "ollama.pull_running")

    def test_shadow_model_key_keeps_the_delete_mutex_409(self):
        row = self._row(running=True)
        del row["model"]
        row[_ShadowKey("model")] = "busy"
        self._plant(row)
        with mock.patch.object(
            ollama_svc, "binary_path", return_value="/usr/local/bin/ollama"
        ):
            resp = self.client.post(
                "/api/ollama/models/delete",
                json={"model": "m1", "confirm": True})
        self.assertEqual(resp.status_code, 409, resp.text[:300])
        self.assertEqual(
            json.loads(resp.text)["detail"]["code"], "ollama.pull_running")

    def test_shadow_rc_key_cannot_500_the_pull_insert(self):
        # The ex-500 on the ``_pull.update`` insert probe: the junk row is
        # dropped whole and the real pull row is published in its place.
        row = self._row()
        del row["rc"]
        row[_ShadowKey("rc")] = 7
        self._plant(row)
        with (
            mock.patch.object(
                ollama_svc, "binary_path", return_value="/usr/local/bin/ollama"),
            mock.patch.object(ollama_svc, "run_watchdog", return_value=0),
        ):
            resp = self.client.post("/api/ollama/pull", json={"model": "m1"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(json.loads(resp.text)["model"], "m1")
        # The bomb key did not survive into the published row.
        self.assertEqual(
            sorted(map(str, ollama_svc._pull)),
            ["finished", "log", "model", "rc", "running", "started"])
        for key in ollama_svc._pull:
            self.assertIs(type(key), str)


class SettingsBlockShadowKeyTests(unittest.TestCase):
    """The ex-500s out of every base_url()/discover_label() caller."""

    def setUp(self):
        super().setUp()
        self.client = _client()
        self.addCleanup(ollama_svc.status.invalidate)
        ollama_svc.status.invalidate()

    def _status_200(self, block: dict) -> dict:
        ollama_svc.status.invalidate()
        with (
            mock.patch.object(
                ollama_svc, "cfg", lambda: {"settings": {"ollama": block}}),
            mock.patch.object(ollama_svc, "binary_path", return_value=None),
            mock.patch.object(
                ollama_svc, "_ollama_open",
                side_effect=ConnectionRefusedError(111, "refused")),
            mock.patch("hub.launchd_cache.listing", side_effect=OSError("no")),
        ):
            resp = self.client.get("/api/ollama/status", params={"force": "true"})
        ollama_svc.status.invalidate()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        resp.text.encode("utf-8")
        return json.loads(resp.text)

    def test_shadow_url_key_reads_as_the_default(self):
        status = self._status_200({_ShadowKey("url"): "http://x"})
        self.assertEqual(status["url"], ollama_svc.DEFAULT_URL)
        # The shadowed field is unreadable junk, not a rejected override.
        self.assertFalse(status["url_rejected"])

    def test_shadow_label_key_reads_as_auto_discover(self):
        status = self._status_200({_ShadowKey("label"): "com.x.ollama"})
        self.assertEqual(status["url"], ollama_svc.DEFAULT_URL)
        self.assertIsInstance(status["service"], dict)

    def test_real_url_beside_a_shadow_label_key_still_wins(self):
        # Do-not-weaken: the guard degrades only the shadowed field.
        status = self._status_200({
            "url": "http://192.168.1.5:11434",
            _ShadowKey("label"): "com.x.ollama",
        })
        self.assertEqual(status["url"], "http://192.168.1.5:11434")

    def test_shadow_url_key_cannot_500_the_delete_route(self):
        # The ex-raw-500: _cli_env -> base_url -> configured_url ran the bomb.
        with (
            mock.patch.object(
                ollama_svc, "cfg",
                lambda: {"settings": {"ollama": {_ShadowKey("url"): "x"}}}),
            mock.patch.object(
                ollama_svc, "binary_path", return_value="/usr/local/bin/ollama"),
            mock.patch.object(ollama_svc, "run_watchdog", return_value=0),
        ):
            resp = self.client.post(
                "/api/ollama/models/delete",
                json={"model": "m1", "confirm": True})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(json.loads(resp.text)["model"], "m1")

    def test_shadow_url_key_keeps_unload_at_the_coded_503(self):
        # The lying-502 shape: with the shadowed URL degraded to the default,
        # a refused connection is the honest coded 503 (the ollama10 pin).
        ollama_svc.status.invalidate()
        with (
            mock.patch.object(
                ollama_svc, "cfg",
                lambda: {"settings": {"ollama": {_ShadowKey("url"): "x"}}}),
            mock.patch.object(
                ollama_svc, "_ollama_open",
                side_effect=ConnectionRefusedError(111, "refused")),
        ):
            resp = self.client.post(
                "/api/ollama/models/unload", json={"model": "m1"})
        self.assertEqual(resp.status_code, 503, resp.text[:300])
        self.assertEqual(
            json.loads(resp.text)["detail"]["code"], "ollama.unreachable")


class SettingsRouteShadowKeyTests(unittest.TestCase):
    """The ex-raw-500s on the settings routes' ollama branch."""

    def setUp(self):
        super().setUp()
        self.client = _client()

    def test_render_over_a_shadow_url_key_answers_200_with_defaults(self):
        with mock.patch(
            "hub.routers.settings_api.cfg",
            lambda: {"settings": {"ollama": {_ShadowKey("url"): "http://x"}}},
        ):
            resp = self.client.get("/api/settings")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        block = json.loads(resp.text)["ollama"]
        self.assertEqual(block["url"], ollama_svc.DEFAULT_URL)
        self.assertEqual(block["label"], "")

    def test_render_keeps_the_real_label_beside_a_shadow_url_key(self):
        with mock.patch(
            "hub.routers.settings_api.cfg",
            lambda: {"settings": {"ollama": {
                _ShadowKey("url"): "http://x", "label": "com.me.ollama"}}},
        ):
            resp = self.client.get("/api/settings")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(
            json.loads(resp.text)["ollama"]["label"], "com.me.ollama")

    def _save(self, stored: dict, body: dict):
        captured: dict = {}

        def record(patch):
            captured.update(patch)
            return {"ok": True}

        with (
            mock.patch("hub.config.cfg",
                       lambda: {"settings": {"ollama": stored}}),
            mock.patch("hub.routers.settings_api.update_settings", record),
        ):
            resp = self.client.put("/api/settings", json={"ollama": body})
        return resp, captured

    def test_save_over_a_stored_shadow_key_answers_200_and_patch_wins(self):
        resp, captured = self._save(
            {_ShadowKey("url"): "http://x", "label": "com.me.ollama"},
            {"url": "http://127.0.0.1:11434"},
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        merged = captured["ollama"]
        self.assertEqual(merged["url"], "http://127.0.0.1:11434")
        # The probeable stored sibling survives; the bomb key is dropped.
        self.assertEqual(merged["label"], "com.me.ollama")
        for key in merged:
            self.assertIs(type(key), str)

    def test_save_keeps_a_tame_str_subclass_key(self):
        # Do-not-weaken: a genuine well-behaved subclass key is laundered to
        # its text, not made collateral of the bomb-key guard.
        resp, captured = self._save(
            {_TameKey("label"): "com.me.ollama"},
            {"url": "http://127.0.0.1:11434"},
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(captured["ollama"]["label"], "com.me.ollama")
        self.assertEqual(captured["ollama"]["url"], "http://127.0.0.1:11434")


class SanitizerUnitPins(unittest.TestCase):
    """The helpers themselves at the ollama11 shapes."""

    def test_row_get_degrades_only_the_shadowed_field(self):
        saved = {k: (list(v) if isinstance(v, list) else v)
                 for k, v in ollama_svc._pull.items()}
        try:
            ollama_svc._pull.clear()
            dict.update(ollama_svc._pull,
                        {_ShadowKey("rc"): 7, "model": "m1"})
            self.assertIsNone(ollama_svc._row_get("rc"))
            self.assertIs(ollama_svc._row_get("running", False), False)
            self.assertEqual(ollama_svc._row_get("model"), "m1")
        finally:
            ollama_svc._pull.clear()
            ollama_svc._pull.update(saved)

    def test_reset_pull_row_drops_the_junk_row_whole(self):
        saved = {k: (list(v) if isinstance(v, list) else v)
                 for k, v in ollama_svc._pull.items()}
        try:
            ollama_svc._pull.clear()
            dict.update(ollama_svc._pull, {_ShadowKey("rc"): 7})
            before = ollama_svc._pull
            ollama_svc._reset_pull_row(dict(running=True, rc=None, model="m1",
                                            started="10:00:00", finished=None,
                                            log=[]))
            # Same dict object (the tailing thread keeps its reference)...
            self.assertIs(ollama_svc._pull, before)
            # ...holding only the real row.
            self.assertEqual(ollama_svc._pull["model"], "m1")
            self.assertNotIn(7, ollama_svc._pull.values())
        finally:
            ollama_svc._pull.clear()
            ollama_svc._pull.update(saved)

    def test_configured_url_and_label_shadow_keys_read_as_unset(self):
        with mock.patch.object(
            ollama_svc, "cfg",
            lambda: {"settings": {"ollama": {
                _ShadowKey("url"): "x", _ShadowKey("label"): "y"}}},
        ):
            self.assertEqual(ollama_svc.configured_url(), ollama_svc.DEFAULT_URL)
            self.assertEqual(ollama_svc.base_url(), ollama_svc.DEFAULT_URL)
            self.assertFalse(ollama_svc.url_was_rejected())
            with mock.patch.object(
                ollama_svc, "_candidate_labels", return_value=[]
            ):
                self.assertIsNone(ollama_svc.discover_label(
                    loaded=frozenset(), running=frozenset()))

    def test_configured_values_still_read_exactly(self):
        # Do-not-weaken: the guarded reads keep honoring real settings.
        with mock.patch.object(
            ollama_svc, "cfg",
            lambda: {"settings": {"ollama": {
                "url": "http://192.168.1.5:11434", "label": "com.me.ollama"}}},
        ):
            self.assertEqual(
                ollama_svc.configured_url(), "http://192.168.1.5:11434")
            self.assertEqual(
                ollama_svc.discover_label(loaded=frozenset(),
                                          running=frozenset()),
                "com.me.ollama")


if __name__ == "__main__":
    unittest.main()
