"""Leftover Ollama engine-down 502s and numeric-YAML silent losses.

Two sweeps already pinned this domain's hex-plist over-cap ints, surrogate
plist stems, digit-cap parses, and the vanished-CLI rm 503.  This pass covers
what they left:

* engine-down on the daemon mutations: ``unload_model`` / ``quick_test`` /
  ``chat`` / ``start_chat_stream`` mapped a *connection-level* failure (the
  daemon is not accepting at all) to their generic 502s — the coded 503
  ``ollama.unreachable`` was registered in CODES and translated in all three
  locales but never raised anywhere.  Same rule as the vanished-CLI 503 in
  ``delete_model`` and docker's ``engine_up(force=True)``: the 503 fires only
  after a fresh /api/version probe on the FAILURE path confirms the daemon is
  down.  Timeouts, resets under a live daemon, and HTTP answers (auth
  failures included) keep their original coded shape, and the success path
  never probes;
* numeric YAML settings: ``_as_text`` / settings_api's ``_text`` gate on
  ``isinstance(str)``, so a hand-edited ``label: 2023`` read back as int and
  was silently dropped — discovery fell through to the plist scan and
  Start/Stop targeted a different agent, while GET /api/settings rendered an
  empty label over the configured one (which Save would then persist).  The
  fix is a ``str()`` probe, guarded because PyYAML parses ``0xfff…`` via
  ``int(raw, 16)`` — exempt from CPython's 4300-digit cap — so an over-cap
  *already-int* leftover would otherwise ValueError at ``str()`` time;
* stays-immune pins: over-cap YAML hex ints and lone-surrogate settings
  values keep answering safely through discover_label, GET /api/settings and
  GET /api/ollama/status.
"""
from __future__ import annotations

import io
import json
import unittest
import urllib.error
from unittest import mock

import yaml
from fastapi import HTTPException

from hub import ollama_svc
from hub.routers import settings_api

#: An already-int over-cap leftover, built arithmetically because
#: ``int("9" * 5000)`` itself trips the digit cap.
_HUGE_INT = 16 ** 5000


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _code(exc: HTTPException) -> str:
    return (exc.detail or {}).get("code", "")


def _refused() -> urllib.error.URLError:
    return urllib.error.URLError(ConnectionRefusedError(61, "Connection refused"))


class _FakeResp:
    """The minimal context-manager/read surface ``_api`` uses."""

    def __init__(self, payload: dict):
        self._raw = json.dumps(payload).encode("utf-8")

    def read(self, n: int = -1) -> bytes:
        out, self._raw = self._raw, b""
        return out

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeConfig(unittest.TestCase):
    def setUp(self):
        super().setUp()
        patched = mock.patch.object(ollama_svc, "cfg", lambda: {"settings": {}})
        patched.start()
        self.addCleanup(patched.stop)

    def _open_seq(self, *effects):
        """Patch ``_ollama_open`` with a call-counting side-effect sequence."""
        calls = []

        def fake_open(req, timeout):
            calls.append(req.full_url)
            effect = effects[min(len(calls), len(effects)) - 1]
            if isinstance(effect, BaseException):
                raise effect
            return effect

        patched = mock.patch.object(ollama_svc, "_ollama_open", side_effect=fake_open)
        patched.start()
        self.addCleanup(patched.stop)
        return calls


class EngineDownReclassTests(_FakeConfig):
    """Connection refused, confirmed by a fresh probe, is the coded 503."""

    def test_refused_unload_is_the_coded_503(self):
        self._open_seq(_refused(), _refused())
        with self.assertRaises(HTTPException) as ctx:
            ollama_svc.unload_model("qwen3.5:4b")
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_code(ctx.exception), "ollama.unreachable")

    def test_refused_quick_test_is_the_coded_503(self):
        self._open_seq(_refused(), _refused())
        with self.assertRaises(HTTPException) as ctx:
            ollama_svc.quick_test("qwen3.5:4b", "hi")
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_code(ctx.exception), "ollama.unreachable")

    def test_refused_chat_is_the_coded_503(self):
        self._open_seq(_refused(), _refused())
        with self.assertRaises(HTTPException) as ctx:
            ollama_svc.chat("qwen3.5:4b", [{"role": "user", "content": "hi"}])
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_code(ctx.exception), "ollama.unreachable")

    def test_refused_chat_stream_is_the_coded_503(self):
        # start_chat_stream connects before any NDJSON is produced, so the
        # router can still answer a coded JSON error instead of a dead stream.
        self._open_seq(_refused(), _refused())
        with self.assertRaises(HTTPException) as ctx:
            ollama_svc.start_chat_stream("qwen3.5:4b", [{"role": "user", "content": "hi"}])
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_code(ctx.exception), "ollama.unreachable")

    def test_timeout_keeps_generate_failed_and_never_probes(self):
        # socket.timeout is TimeoutError; a slow cold-load is not "down", so
        # the original 502 stays and no confirm probe is spent on it.
        calls = self._open_seq(urllib.error.URLError(TimeoutError("timed out")))
        with self.assertRaises(HTTPException) as ctx:
            ollama_svc.quick_test("qwen3.5:4b", "hi")
        self.assertEqual(ctx.exception.status_code, 502)
        self.assertEqual(_code(ctx.exception), "ollama.generate_failed")
        self.assertEqual(len(calls), 1)

    def test_daemon_http_answer_keeps_chat_failed_and_never_probes(self):
        # An HTTP-level failure comes from a daemon that is up (auth included):
        # the original coded shape must survive the reclassification.
        auth = urllib.error.HTTPError(
            "http://127.0.0.1:11434/api/chat", 401, "Unauthorized",
            {}, io.BytesIO(b'{"error":"unauthorized"}'),
        )
        calls = self._open_seq(auth)
        with self.assertRaises(HTTPException) as ctx:
            ollama_svc.start_chat_stream("qwen3.5:4b", [{"role": "user", "content": "hi"}])
        self.assertEqual(ctx.exception.status_code, 502)
        self.assertEqual(_code(ctx.exception), "ollama.chat_failed")
        self.assertEqual(len(calls), 1)

    def test_transient_refusal_with_a_live_daemon_keeps_the_original_shape(self):
        # The fresh probe answers: the daemon is up, so the refusal was not
        # engine-down and the raw failure stays the truth.
        calls = self._open_seq(_refused(), _FakeResp({"version": "0.32.9"}))
        with self.assertRaises(HTTPException) as ctx:
            ollama_svc.quick_test("qwen3.5:4b", "hi")
        self.assertEqual(ctx.exception.status_code, 502)
        self.assertEqual(_code(ctx.exception), "ollama.generate_failed")
        self.assertEqual(len(calls), 2)

    def test_success_path_never_probes(self):
        calls = self._open_seq(_FakeResp({
            "response": "ok", "eval_count": 100, "eval_duration": 2_000_000_000,
        }))
        result = ollama_svc.quick_test("qwen3.5:4b", "hi")
        self.assertTrue(result["ok"])
        self.assertEqual(result["tokens_per_s"], 50.0)
        self.assertEqual(len(calls), 1)
        _starlette(result)


class NumericYamlSettingsTests(unittest.TestCase):
    """A hand-edited numeric YAML value must not be silently dropped."""

    def _cfg(self, **ollama):
        return mock.patch.object(
            ollama_svc, "cfg", lambda: {"settings": {"ollama": ollama}},
        )

    def test_numeric_label_targets_the_configured_agent(self):
        with self._cfg(label=2023):
            got = ollama_svc.discover_label(loaded=frozenset(), running=frozenset())
        self.assertEqual(got, "2023")

    def test_numeric_label_survives_get_settings(self):
        with mock.patch.object(
            settings_api, "cfg",
            return_value={"settings": {"ollama": {"label": 2023}}},
        ):
            pub = settings_api._public_settings()
        self.assertEqual(pub["ollama"]["label"], "2023")
        _starlette(pub["ollama"])

    def test_numeric_url_is_rejected_visibly_not_silently(self):
        # A numeric url is junk either way, but coercing it lets base_url()
        # reject it with the UI's url_rejected warning instead of reading the
        # misconfiguration as "unconfigured".
        with self._cfg(url=11434):
            self.assertEqual(ollama_svc.configured_url(), "11434")
            self.assertEqual(ollama_svc.base_url(), ollama_svc.DEFAULT_URL)
            self.assertTrue(ollama_svc.url_was_rejected())


class OverCapYamlIntStaysImmuneTests(unittest.TestCase):
    """YAML hex ints dodge the digit cap; the str() probe must stay guarded."""

    def _cfg(self, **ollama):
        return mock.patch.object(
            ollama_svc, "cfg", lambda: {"settings": {"ollama": ollama}},
        )

    def test_yaml_hex_parses_past_the_digit_cap(self):
        # The attack vector is real: PyYAML routes 0x… through int(raw, 16),
        # which is exempt from the cap, so the leftover arrives already-int.
        doc = yaml.safe_load("label: 0x" + "f" * 5000)
        self.assertIsInstance(doc["label"], int)
        with self.assertRaises(ValueError):
            str(doc["label"])
        self.assertEqual(ollama_svc.settings_text(doc["label"]), "")

    def test_over_cap_label_and_url_answer_defaults_not_a_500(self):
        with (
            self._cfg(label=_HUGE_INT, url=_HUGE_INT),
            mock.patch.object(ollama_svc, "_candidate_labels", return_value=[]),
        ):
            self.assertIsNone(
                ollama_svc.discover_label(loaded=frozenset(), running=frozenset()),
            )
            self.assertEqual(ollama_svc.configured_url(), ollama_svc.DEFAULT_URL)

    def test_over_cap_values_in_get_settings_render(self):
        with mock.patch.object(
            settings_api, "cfg",
            return_value={"settings": {"ollama": {"label": _HUGE_INT, "url": _HUGE_INT}}},
        ):
            pub = settings_api._public_settings()
        self.assertEqual(pub["ollama"], {
            "url": ollama_svc.DEFAULT_URL, "label": "",
        })
        _starlette(pub)

    def test_settings_text_probe_shapes(self):
        self.assertEqual(ollama_svc.settings_text(2023), "2023")
        self.assertEqual(ollama_svc.settings_text("com.kiro.ollama"), "com.kiro.ollama")
        self.assertEqual(ollama_svc.settings_text(b"com.kiro.ollama"), "com.kiro.ollama")
        self.assertEqual(ollama_svc.settings_text(_HUGE_INT), "")
        self.assertEqual(ollama_svc.settings_text(True), "")
        self.assertEqual(ollama_svc.settings_text(None), "")
        self.assertEqual(ollama_svc.settings_text(float("inf")), "")
        self.assertEqual(ollama_svc.settings_text(float("nan")), "")
        self.assertEqual(ollama_svc.settings_text(["com.kiro.ollama"]), "")


class SurrogateSettingsValueStaysImmuneTests(unittest.TestCase):
    """Lone surrogates in hand-edited settings values stay scrubbed."""

    def _cfg(self):
        return mock.patch.object(ollama_svc, "cfg", lambda: {
            "settings": {"ollama": {"label": "lab\ud800el"}, "junk\ud800": 1},
        })

    def test_surrogate_label_is_sanitized_for_the_encoder(self):
        with self._cfg():
            label = ollama_svc.discover_label(loaded=frozenset(), running=frozenset())
        self.assertNotIn("\ud800", label)
        _starlette(label)

    def test_status_with_surrogate_settings_renders(self):
        self.addCleanup(ollama_svc.status.invalidate)
        with (
            self._cfg(),
            mock.patch.object(ollama_svc, "_api", side_effect=OSError("refused")),
            mock.patch.object(ollama_svc, "binary_path", return_value=None),
            mock.patch.object(ollama_svc, "_candidate_labels", return_value=[]),
            mock.patch("hub.launchd_cache.listing", side_effect=OSError("sandbox")),
        ):
            snap = ollama_svc.status(force=True)
        _starlette(snap)
        self.assertNotIn("\ud800", snap["service"]["label"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
