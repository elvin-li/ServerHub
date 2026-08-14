"""Ollama integration: parsing, argv safety, single-flight, discovery, gating.

Everything runs against fixtures or mocks — no test talks to a live daemon,
spawns `ollama`, or reads the operator's real LaunchAgents.  The payload
fixtures were captured verbatim from ollama 0.32.9 (`/api/tags`, `/api/ps`),
so the parsers are exercised against the real wire shapes.
"""
from __future__ import annotations

import json
import plistlib
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from fastapi import HTTPException  # noqa: E402

from hub import ollama_svc  # noqa: E402


def _code(exc: HTTPException) -> str:
    return (exc.detail or {}).get("code", "")


#: /api/tags, ollama 0.32.9, verbatim (one entry trimmed to the parsed fields).
TAGS_PAYLOAD = {
    "models": [
        {
            "name": "qwen3.5:4b",
            "model": "qwen3.5:4b",
            "modified_at": "2026-08-13T20:27:24.243845693+08:00",
            "size": 3413361762,
            "digest": "d9392d1338c2",
            "details": {
                "parent_model": "",
                "format": "gguf",
                "family": "qwen35",
                "families": ["qwen35"],
                "parameter_size": "4.2B",
                "quantization_level": "Q4_K_M",
                "context_length": 262144,
                "embedding_length": 2560,
            },
            "capabilities": ["completion", "tools", "thinking", "vision"],
        },
        {
            "name": "qwen3:4b-instruct-2507-q4_K_M",
            "model": "qwen3:4b-instruct-2507-q4_K_M",
            "modified_at": "2026-08-13T19:17:01.502422305+08:00",
            "size": 2497293803,
            "digest": "0edcdef34593",
            "details": {
                "family": "qwen3",
                "parameter_size": "4.0B",
                "quantization_level": "Q4_K_M",
                "context_length": 262144,
            },
            "capabilities": ["completion", "tools"],
        },
    ]
}

#: /api/ps, ollama 0.32.9, verbatim.  expires_at year 2318 is keep_alive=-1.
PS_PAYLOAD = {
    "models": [
        {
            "name": "qwen3.5:4b",
            "model": "qwen3.5:4b",
            "size": 3321207192,
            "digest": "d9392d1338c2",
            "details": {"family": "qwen35", "quantization_level": "Q4_K_M"},
            "expires_at": "2318-11-24T02:50:18.929807807+08:00",
            "size_vram": 3321207192,
            "context_length": 8192,
        }
    ]
}


class _NoRealConfig(unittest.TestCase):
    """Every test reads a synthetic settings dict, never the real services.yaml."""

    settings: dict = {}

    def setUp(self):
        super().setUp()
        patched = mock.patch.object(
            ollama_svc, "cfg", lambda: {"settings": dict(self.settings)}
        )
        patched.start()
        self.addCleanup(patched.stop)


class ModelNameValidation(_NoRealConfig):
    VALID = [
        "qwen3.5:4b",
        "llama3.2:3b",
        "qwen3:4b-instruct-2507-q4_K_M",
        "a",
        "A0",
        "registry.example.com/library/llama3:8b",
        "x" * 128,  # exactly the cap
    ]
    #: Includes the argv-injection shapes: a leading dash must never reach an
    #: `ollama pull` argv where it would parse as a flag.
    INVALID = [
        "",
        "-rf",
        "--insecure",
        "a b",
        "a;b",
        "a|b",
        "$(reboot)",
        "a" * 129,  # one past the cap
        ".hidden",
        "/leading-slash",
        ":tag-only",
        "模型",
        "a\nb",
        "a\tb",
    ]

    def test_accepts_real_model_references(self):
        for name in self.VALID:
            with self.subTest(name=name):
                self.assertEqual(ollama_svc.validate_model_name(f"  {name} "), name)

    def test_rejects_injection_shapes_with_a_400_code(self):
        for name in self.INVALID:
            with self.subTest(name=repr(name)):
                with self.assertRaises(HTTPException) as ctx:
                    ollama_svc.validate_model_name(name)
                self.assertEqual(ctx.exception.status_code, 400)
                self.assertEqual(_code(ctx.exception), "ollama.bad_model_name")


class TagsParsing(_NoRealConfig):
    def test_parses_the_captured_payload(self):
        models = ollama_svc.parse_tags(TAGS_PAYLOAD)
        self.assertEqual(len(models), 2)
        first = models[0]
        self.assertEqual(first["name"], "qwen3.5:4b")
        self.assertEqual(first["size"], 3413361762)
        self.assertEqual(first["family"], "qwen35")
        self.assertEqual(first["parameter_size"], "4.2B")
        self.assertEqual(first["quantization"], "Q4_K_M")
        self.assertEqual(first["context_length"], 262144)
        self.assertEqual(first["capabilities"], ["completion", "tools", "thinking", "vision"])
        self.assertTrue(first["modified"].startswith("2026-08-13"))

    def test_missing_optional_fields_do_not_raise(self):
        models = ollama_svc.parse_tags({"models": [{"name": "bare"}]})
        self.assertEqual(models[0]["capabilities"], [])
        self.assertEqual(models[0]["quantization"], "")
        self.assertEqual(models[0]["size"], 0)

    def test_empty_and_malformed_payloads_yield_no_models(self):
        self.assertEqual(ollama_svc.parse_tags({}), [])
        self.assertEqual(ollama_svc.parse_tags({"models": None}), [])
        self.assertEqual(ollama_svc.parse_tags(None), [])


class PsParsing(_NoRealConfig):
    def test_parses_the_captured_payload(self):
        resident = ollama_svc.parse_ps(PS_PAYLOAD)
        self.assertEqual(len(resident), 1)
        row = resident[0]
        self.assertEqual(row["name"], "qwen3.5:4b")
        self.assertEqual(row["size_vram"], 3321207192)
        self.assertEqual(row["context_length"], 8192)
        self.assertTrue(row["expires_at"].startswith("2318-"))

    def test_far_future_expiry_reads_as_keep_alive_forever(self):
        resident = ollama_svc.parse_ps(PS_PAYLOAD)
        self.assertTrue(resident[0]["forever"])

    def test_near_expiry_is_not_forever(self):
        payload = {"models": [{"name": "m", "expires_at": "2026-08-14T00:05:00+08:00"}]}
        self.assertFalse(ollama_svc.parse_ps(payload)[0]["forever"])

    def test_missing_expiry_is_not_forever(self):
        self.assertFalse(ollama_svc.parse_ps({"models": [{"name": "m"}]})[0]["forever"])


class StatusSnapshot(_NoRealConfig):
    def setUp(self):
        super().setUp()
        self.addCleanup(ollama_svc.status.invalidate)
        svc = mock.patch.object(
            ollama_svc, "_service_state",
            return_value={"label": "com.kiro.ollama", "loaded": True, "running": True, "pid": 42},
        )
        svc.start()
        self.addCleanup(svc.stop)

    def test_reachable_daemon_yields_full_snapshot(self):
        def fake_api(path, payload=None, timeout=None):
            return {
                "/api/version": {"version": "0.32.9"},
                "/api/tags": TAGS_PAYLOAD,
                "/api/ps": PS_PAYLOAD,
            }[path]

        with (
            mock.patch.object(ollama_svc, "_api", side_effect=fake_api),
            mock.patch.object(ollama_svc, "binary_path", return_value="/opt/homebrew/bin/ollama"),
        ):
            snap = ollama_svc.status(force=True)
        self.assertTrue(snap["reachable"])
        self.assertTrue(snap["installed"])
        self.assertEqual(snap["version"], "0.32.9")
        self.assertEqual(len(snap["models"]), 2)
        self.assertEqual(len(snap["resident"]), 1)
        self.assertEqual(snap["service"]["label"], "com.kiro.ollama")
        self.assertIn("pull", snap)

    def test_unreachable_daemon_degrades_instead_of_raising(self):
        with (
            mock.patch.object(ollama_svc, "_api", side_effect=OSError("connection refused")),
            mock.patch.object(ollama_svc, "binary_path", return_value="/opt/homebrew/bin/ollama"),
        ):
            snap = ollama_svc.status(force=True)
        self.assertFalse(snap["reachable"])
        self.assertTrue(snap["installed"])
        self.assertIn("connection refused", snap["error"])
        self.assertEqual(snap["models"], [])
        self.assertEqual(snap["resident"], [])

    def test_absent_ollama_reports_not_installed(self):
        with (
            mock.patch.object(ollama_svc, "_api", side_effect=OSError("refused")),
            mock.patch.object(ollama_svc, "binary_path", return_value=None),
            mock.patch.object(
                ollama_svc, "_service_state",
                return_value={"label": None, "loaded": False, "running": False, "pid": None},
            ),
        ):
            snap = ollama_svc.status(force=True)
        self.assertFalse(snap["installed"])


class _PullSandbox(_NoRealConfig):
    """Save/restore the module pull store so tests cannot leak into each other."""

    def setUp(self):
        super().setUp()
        self._saved = {k: (list(v) if isinstance(v, list) else v)
                       for k, v in ollama_svc._pull.items()}
        ollama_svc._pull.update(
            running=False, rc=None, model=None, started=None, finished=None, log=[],
        )
        self.addCleanup(ollama_svc._pull.update, self._saved)
        self.addCleanup(ollama_svc.status.invalidate)

    @staticmethod
    def _wait_not_running(deadline=5.0):
        end = time.time() + deadline
        while time.time() < end:
            if not ollama_svc._pull["running"]:
                return
            time.sleep(0.01)
        raise AssertionError("pull job never finished")


class PullSingleFlight(_PullSandbox):
    def test_second_concurrent_pull_is_refused(self):
        release = threading.Event()
        seen = {}

        def fake_watchdog(argv, *, timeout, log, env=None, cwd=None):
            seen["argv"] = list(argv)
            seen["env"] = dict(env or {})
            release.wait(5)
            return 0

        with (
            mock.patch.object(ollama_svc, "run_watchdog", side_effect=fake_watchdog),
            mock.patch.object(ollama_svc, "binary_path", return_value="/fake/bin/ollama"),
        ):
            state = ollama_svc.start_pull("llama3.2:3b")
            self.assertTrue(state["running"])
            with self.assertRaises(HTTPException) as ctx:
                ollama_svc.start_pull("qwen3.5:4b")
            self.assertEqual(ctx.exception.status_code, 409)
            self.assertEqual(_code(ctx.exception), "ollama.pull_running")
            release.set()
            self._wait_not_running()

        # The finished job frees the slot and reports its exit code.
        self.assertEqual(ollama_svc.pull_state()["rc"], 0)
        self.assertEqual(seen["argv"], ["/fake/bin/ollama", "pull", "llama3.2:3b"])
        # The CLI is pointed at the same daemon the panel monitors.
        self.assertEqual(seen["env"].get("OLLAMA_HOST"), "127.0.0.1:11434")

    def test_slot_reopens_after_completion(self):
        with (
            mock.patch.object(ollama_svc, "run_watchdog", return_value=0),
            mock.patch.object(ollama_svc, "binary_path", return_value="/fake/bin/ollama"),
        ):
            ollama_svc.start_pull("a:1")
            self._wait_not_running()
            # The freed slot accepts the next pull instead of raising 409.
            state = ollama_svc.start_pull("b:2")
            self.assertEqual(state["model"], "b:2")
            self._wait_not_running()
            self.assertEqual(ollama_svc.pull_state()["rc"], 0)

    def test_bad_name_is_rejected_before_the_slot_is_taken(self):
        with mock.patch.object(ollama_svc, "binary_path", return_value="/fake/bin/ollama"):
            with self.assertRaises(HTTPException) as ctx:
                ollama_svc.start_pull("-rf")
        self.assertEqual(_code(ctx.exception), "ollama.bad_model_name")
        self.assertFalse(ollama_svc._pull["running"])

    def test_missing_binary_is_a_503(self):
        with mock.patch.object(ollama_svc, "binary_path", return_value=None):
            with self.assertRaises(HTTPException) as ctx:
                ollama_svc.start_pull("llama3.2:3b")
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_code(ctx.exception), "ollama.not_installed")

    def test_pull_log_joins_the_captured_lines(self):
        ollama_svc._pull.update(log=["$ ollama pull x", "pulling manifest"])
        self.assertIn("pulling manifest", ollama_svc.pull_log()["log"])


class DeleteModel(_PullSandbox):
    def test_argv_and_success(self):
        seen = {}

        def fake_watchdog(argv, *, timeout, log, env=None, cwd=None):
            seen["argv"] = list(argv)
            log.append("deleted 'x:1'")
            return 0

        with (
            mock.patch.object(ollama_svc, "run_watchdog", side_effect=fake_watchdog),
            mock.patch.object(ollama_svc, "binary_path", return_value="/fake/bin/ollama"),
        ):
            result = ollama_svc.delete_model("x:1")
        self.assertTrue(result["ok"])
        self.assertEqual(seen["argv"], ["/fake/bin/ollama", "rm", "x:1"])

    def test_nonzero_exit_becomes_a_coded_500(self):
        with (
            mock.patch.object(ollama_svc, "run_watchdog", return_value=1),
            mock.patch.object(ollama_svc, "binary_path", return_value="/fake/bin/ollama"),
        ):
            with self.assertRaises(HTTPException) as ctx:
                ollama_svc.delete_model("x:1")
        self.assertEqual(_code(ctx.exception), "ollama.rm_failed")

    def test_refused_while_a_pull_runs(self):
        ollama_svc._pull.update(running=True, model="big:1")
        with mock.patch.object(ollama_svc, "binary_path", return_value="/fake/bin/ollama"):
            with self.assertRaises(HTTPException) as ctx:
                ollama_svc.delete_model("x:1")
        self.assertEqual(_code(ctx.exception), "ollama.pull_running")

    def test_injection_shape_never_reaches_an_argv(self):
        called = []
        with (
            mock.patch.object(ollama_svc, "run_watchdog", side_effect=lambda *a, **k: called.append(a) or 0),
            mock.patch.object(ollama_svc, "binary_path", return_value="/fake/bin/ollama"),
        ):
            with self.assertRaises(HTTPException):
                ollama_svc.delete_model("-rf")
        self.assertEqual(called, [])


class UnloadModel(_NoRealConfig):
    def setUp(self):
        super().setUp()
        self.addCleanup(ollama_svc.status.invalidate)

    def test_posts_keep_alive_zero_for_this_request_only(self):
        seen = {}

        def fake_api(path, payload=None, timeout=None):
            seen["path"], seen["payload"] = path, payload
            return {"done": True, "done_reason": "unload"}

        with mock.patch.object(ollama_svc, "_api", side_effect=fake_api):
            result = ollama_svc.unload_model("qwen3.5:4b")
        self.assertTrue(result["ok"])
        self.assertEqual(seen["path"], "/api/generate")
        self.assertEqual(seen["payload"], {"model": "qwen3.5:4b", "keep_alive": 0})

    def test_daemon_failure_becomes_a_coded_502(self):
        with mock.patch.object(ollama_svc, "_api", side_effect=OSError("refused")):
            with self.assertRaises(HTTPException) as ctx:
                ollama_svc.unload_model("qwen3.5:4b")
        self.assertEqual(ctx.exception.status_code, 502)
        self.assertEqual(_code(ctx.exception), "ollama.unload_failed")


class QuickTest(_NoRealConfig):
    def test_prompt_length_is_capped(self):
        with self.assertRaises(HTTPException) as ctx:
            ollama_svc.quick_test("m:1", "x" * (ollama_svc.MAX_PROMPT_CHARS + 1))
        self.assertEqual(_code(ctx.exception), "ollama.prompt_too_long")

    def test_blank_prompt_is_refused(self):
        with self.assertRaises(HTTPException) as ctx:
            ollama_svc.quick_test("m:1", "   ")
        self.assertEqual(_code(ctx.exception), "ollama.prompt_required")

    def test_generation_is_non_streaming_and_num_predict_clamped(self):
        seen = {}

        def fake_api(path, payload=None, timeout=None):
            seen["payload"] = payload
            return {"response": "hello", "eval_count": 10, "eval_duration": 2_000_000_000}

        with mock.patch.object(ollama_svc, "_api", side_effect=fake_api):
            result = ollama_svc.quick_test("m:1", "hi", num_predict=99999)
        self.assertIs(seen["payload"]["stream"], False)
        self.assertEqual(
            seen["payload"]["options"]["num_predict"], ollama_svc.MAX_NUM_PREDICT,
        )
        self.assertEqual(result["response"], "hello")
        self.assertEqual(result["tokens_per_s"], 5.0)

    def test_daemon_failure_becomes_a_coded_502(self):
        with mock.patch.object(ollama_svc, "_api", side_effect=OSError("timed out")):
            with self.assertRaises(HTTPException) as ctx:
                ollama_svc.quick_test("m:1", "hi")
        self.assertEqual(_code(ctx.exception), "ollama.generate_failed")

    def test_thinking_only_output_is_surfaced(self):
        # Real-daemon behaviour (qwen3.5:4b, num_predict=32): the entire capped
        # budget goes to reasoning and `response` comes back empty.  The trace
        # must reach the caller or the test box renders blank on success.
        def fake_api(path, payload=None, timeout=None):
            return {
                "response": "",
                "thinking": "The user greets me, so a short greeting back…",
                "eval_count": 32,
                "eval_duration": 1_400_000_000,
            }

        with mock.patch.object(ollama_svc, "_api", side_effect=fake_api):
            result = ollama_svc.quick_test("qwen3.5:4b", "hi")
        self.assertEqual(result["response"], "")
        self.assertTrue(result["thinking"].startswith("The user greets"))
        self.assertTrue(result["ok"])


class ChatMessages(_NoRealConfig):
    def test_empty_history_is_refused(self):
        with self.assertRaises(HTTPException) as ctx:
            ollama_svc.normalize_chat_messages([])
        self.assertEqual(_code(ctx.exception), "ollama.messages_required")

    def test_unknown_role_is_refused(self):
        with self.assertRaises(HTTPException) as ctx:
            ollama_svc.normalize_chat_messages([{"role": "tool", "content": "x"}])
        self.assertEqual(_code(ctx.exception), "ollama.bad_message")

    def test_last_turn_must_be_a_non_empty_user_message(self):
        with self.assertRaises(HTTPException) as ctx:
            ollama_svc.normalize_chat_messages([{"role": "assistant", "content": "hi"}])
        self.assertEqual(_code(ctx.exception), "ollama.prompt_required")
        with self.assertRaises(HTTPException) as ctx:
            ollama_svc.normalize_chat_messages([{"role": "user", "content": "   "}])
        self.assertEqual(_code(ctx.exception), "ollama.prompt_required")

    def test_per_message_length_is_capped(self):
        with self.assertRaises(HTTPException) as ctx:
            ollama_svc.normalize_chat_messages([
                {"role": "user", "content": "x" * (ollama_svc.MAX_PROMPT_CHARS + 1)},
            ])
        self.assertEqual(_code(ctx.exception), "ollama.prompt_too_long")

    def test_history_is_trimmed_to_the_last_n_and_keeps_the_prompt(self):
        msgs = []
        for i in range(ollama_svc.MAX_CHAT_MESSAGES + 4):
            msgs.append({"role": "user" if i % 2 == 0 else "assistant", "content": f"m{i}"})
        # Force the last turn to be the user prompt.
        msgs[-1] = {"role": "user", "content": "latest"}
        out = ollama_svc.normalize_chat_messages(msgs)
        self.assertEqual(len(out), ollama_svc.MAX_CHAT_MESSAGES)
        self.assertEqual(out[-1], {"role": "user", "content": "latest"})
        self.assertNotIn("m0", [m["content"] for m in out])

    def test_total_character_budget_drops_oldest_first(self):
        # Each body stays under the per-message cap; together they exceed
        # the history budget so the oldest turns are dropped first.
        big = "y" * ollama_svc.MAX_PROMPT_CHARS
        msgs = [
            {"role": "user", "content": big},
            {"role": "assistant", "content": big},
            {"role": "user", "content": big},
            {"role": "assistant", "content": big},
            {"role": "user", "content": "now"},
        ]
        out = ollama_svc.normalize_chat_messages(msgs)
        self.assertEqual(out[-1]["content"], "now")
        self.assertLessEqual(sum(len(m["content"]) for m in out), ollama_svc.MAX_CHAT_HISTORY_CHARS)
        self.assertLess(len(out), len(msgs))


class ChatTurn(_NoRealConfig):
    def test_posts_non_streaming_chat_and_returns_content(self):
        seen = {}

        def fake_api(path, payload=None, timeout=None):
            seen["path"], seen["payload"] = path, payload
            return {
                "message": {"role": "assistant", "content": "hello there"},
                "eval_count": 8,
                "eval_duration": 2_000_000_000,
            }

        with mock.patch.object(ollama_svc, "_api", side_effect=fake_api):
            result = ollama_svc.chat("qwen3.5:4b", [{"role": "user", "content": "hi"}])
        self.assertEqual(seen["path"], "/api/chat")
        self.assertIs(seen["payload"]["stream"], False)
        self.assertEqual(
            seen["payload"]["options"]["num_predict"], 128,
        )
        self.assertEqual(result["content"], "hello there")
        self.assertEqual(result["thinking"], "")
        self.assertEqual(result["tokens_per_s"], 4.0)
        self.assertTrue(result["ok"])

    def test_num_predict_is_clamped(self):
        seen = {}

        def fake_api(path, payload=None, timeout=None):
            seen["payload"] = payload
            return {"message": {"role": "assistant", "content": "x"}}

        with mock.patch.object(ollama_svc, "_api", side_effect=fake_api):
            ollama_svc.chat("m:1", [{"role": "user", "content": "hi"}], num_predict=99999)
        self.assertEqual(
            seen["payload"]["options"]["num_predict"], ollama_svc.MAX_NUM_PREDICT,
        )

    def test_thinking_only_reply_is_surfaced(self):
        def fake_api(path, payload=None, timeout=None):
            return {
                "message": {
                    "role": "assistant",
                    "content": "",
                    "thinking": "The user greets me, so a short greeting back…",
                },
                "eval_count": 32,
                "eval_duration": 1_400_000_000,
            }

        with mock.patch.object(ollama_svc, "_api", side_effect=fake_api):
            result = ollama_svc.chat("qwen3.5:4b", [{"role": "user", "content": "hi"}])
        self.assertEqual(result["content"], "")
        self.assertTrue(result["thinking"].startswith("The user greets"))
        self.assertTrue(result["ok"])

    def test_injection_shape_never_reaches_the_daemon(self):
        called = []
        with mock.patch.object(ollama_svc, "_api", side_effect=lambda *a, **k: called.append(a) or {}):
            with self.assertRaises(HTTPException) as ctx:
                ollama_svc.chat("-rf", [{"role": "user", "content": "hi"}])
        self.assertEqual(_code(ctx.exception), "ollama.bad_model_name")
        self.assertEqual(called, [])

    def test_daemon_failure_becomes_a_coded_502(self):
        with mock.patch.object(ollama_svc, "_api", side_effect=OSError("timed out")):
            with self.assertRaises(HTTPException) as ctx:
                ollama_svc.chat("m:1", [{"role": "user", "content": "hi"}])
        self.assertEqual(ctx.exception.status_code, 502)
        self.assertEqual(_code(ctx.exception), "ollama.chat_failed")


class _FakeHttp:
    """urlopen stand-in: readline() yields NDJSON, close() is recorded."""

    def __init__(self, lines: list[bytes]):
        self._lines = list(lines)
        self.closed = False

    def readline(self, limit=-1):
        if not self._lines:
            return b""
        return self._lines.pop(0)

    def close(self):
        self.closed = True


class ChatStream(_NoRealConfig):
    def test_yields_ndjson_lines_and_closes(self):
        chunks = [
            b'{"message":{"role":"assistant","content":"Hel"},"done":false}\n',
            b'{"message":{"role":"assistant","content":"lo"},"done":false}\n',
            b'{"message":{"role":"assistant","content":""},"done":true}\n',
        ]
        fake = _FakeHttp(chunks)
        with mock.patch.object(ollama_svc.urllib.request, "urlopen", return_value=fake):
            lines = list(ollama_svc.start_chat_stream(
                "qwen3.5:4b", [{"role": "user", "content": "hi"}],
            ))
        self.assertEqual(lines, chunks)
        self.assertTrue(fake.closed)

    def test_stream_is_true_on_the_wire(self):
        seen = {}
        fake = _FakeHttp([b'{"done":true}\n'])

        def fake_open(req, timeout=None):
            seen["url"] = req.full_url
            seen["body"] = json.loads(req.data.decode("utf-8"))
            return fake

        with mock.patch.object(ollama_svc.urllib.request, "urlopen", side_effect=fake_open):
            list(ollama_svc.start_chat_stream("m:1", [{"role": "user", "content": "hi"}]))
        self.assertTrue(seen["url"].endswith("/api/chat"))
        self.assertIs(seen["body"]["stream"], True)
        self.assertEqual(seen["body"]["model"], "m:1")

    def test_connect_failure_is_a_coded_502_before_any_bytes(self):
        with mock.patch.object(
            ollama_svc.urllib.request, "urlopen",
            side_effect=OSError("connection refused"),
        ):
            with self.assertRaises(HTTPException) as ctx:
                ollama_svc.start_chat_stream("m:1", [{"role": "user", "content": "hi"}])
        self.assertEqual(_code(ctx.exception), "ollama.chat_failed")

    def test_bad_name_never_opens_a_socket(self):
        opened = []
        with mock.patch.object(
            ollama_svc.urllib.request, "urlopen",
            side_effect=lambda *a, **k: opened.append(True),
        ):
            with self.assertRaises(HTTPException):
                ollama_svc.start_chat_stream("-rf", [{"role": "user", "content": "hi"}])
        self.assertEqual(opened, [])


class LabelDiscovery(_NoRealConfig):
    """Fake ~/Library/LaunchAgents populated with synthetic plists."""

    def _agents_dir(self, plists: dict[str, dict]) -> Path:
        tmp = Path(tempfile.mkdtemp(prefix="serverhub-ollama-agents-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        for filename, payload in plists.items():
            (tmp / filename).write_bytes(plistlib.dumps(payload))
        return tmp

    KIRO = {
        # ProgramArguments never says "ollama"; the reference lives in the
        # environment and log paths — exactly the real com.kiro.ollama shape.
        "Label": "com.kiro.ollama",
        "ProgramArguments": ["/bin/zsh", "/Users/x/kiro_tools/serve.sh"],
        "EnvironmentVariables": {"OLLAMA_HOST": "127.0.0.1:11434", "OLLAMA_KEEP_ALIVE": "-1"},
        "StandardErrorPath": "/Users/x/Library/Logs/ollama.error.log",
        "KeepAlive": True,
    }
    BREW = {
        "Label": "homebrew.mxcl.ollama",
        "ProgramArguments": ["/opt/homebrew/opt/ollama/bin/ollama", "serve"],
    }
    UNRELATED = {
        "Label": "com.example.unrelated",
        "ProgramArguments": ["/usr/bin/true"],
    }

    def test_scan_finds_the_custom_wrapper_agent(self):
        agents = self._agents_dir({
            "com.kiro.ollama.plist": self.KIRO,
            "com.example.unrelated.plist": self.UNRELATED,
        })
        with mock.patch.object(ollama_svc, "AGENTS_DIR", agents):
            self.assertEqual(
                ollama_svc.discover_label(loaded=frozenset()), "com.kiro.ollama",
            )

    def test_prefers_a_loaded_label_over_an_on_disk_one(self):
        agents = self._agents_dir({
            "com.kiro.ollama.plist": self.KIRO,
            "homebrew.mxcl.ollama.plist": self.BREW,
        })
        with mock.patch.object(ollama_svc, "AGENTS_DIR", agents):
            self.assertEqual(
                ollama_svc.discover_label(loaded=frozenset({"homebrew.mxcl.ollama"})),
                "homebrew.mxcl.ollama",
            )
            # Nothing loaded: deterministic alphabetical tie-break.
            self.assertEqual(
                ollama_svc.discover_label(loaded=frozenset()), "com.kiro.ollama",
            )

    def test_prefers_a_running_label_over_a_loaded_but_dead_one(self):
        # brew services left homebrew.mxcl.ollama loaded-in-error (no pid)
        # while the custom wrapper was the one actually serving :11434.
        agents = self._agents_dir({
            "com.kiro.ollama.plist": self.KIRO,
            "homebrew.mxcl.ollama.plist": self.BREW,
        })
        with mock.patch.object(ollama_svc, "AGENTS_DIR", agents):
            self.assertEqual(
                ollama_svc.discover_label(
                    loaded=frozenset({"homebrew.mxcl.ollama", "com.kiro.ollama"}),
                    running=frozenset({"com.kiro.ollama"}),
                ),
                "com.kiro.ollama",
            )

    def test_label_key_wins_over_the_filename(self):
        agents = self._agents_dir({
            "renamed-file.plist": self.KIRO,
        })
        with mock.patch.object(ollama_svc, "AGENTS_DIR", agents):
            self.assertEqual(
                ollama_svc.discover_label(loaded=frozenset()), "com.kiro.ollama",
            )

    def test_configured_label_overrides_discovery(self):
        agents = self._agents_dir({"com.kiro.ollama.plist": self.KIRO})
        self.settings = {"ollama": {"label": "custom.ollama.label"}}
        patched = mock.patch.object(
            ollama_svc, "cfg", lambda: {"settings": dict(self.settings)}
        )
        patched.start()
        self.addCleanup(patched.stop)
        with mock.patch.object(ollama_svc, "AGENTS_DIR", agents):
            self.assertEqual(
                ollama_svc.discover_label(loaded=frozenset()), "custom.ollama.label",
            )

    def test_no_reference_and_broken_plists_yield_none(self):
        agents = self._agents_dir({"com.example.unrelated.plist": self.UNRELATED})
        (agents / "broken.plist").write_bytes(b"not a plist at all")
        with mock.patch.object(ollama_svc, "AGENTS_DIR", agents):
            self.assertIsNone(ollama_svc.discover_label(loaded=frozenset()))

    def test_candidate_labels_lists_every_ollama_agent(self):
        agents = self._agents_dir({
            "com.kiro.ollama.plist": self.KIRO,
            "homebrew.mxcl.ollama.plist": self.BREW,
            "com.example.unrelated.plist": self.UNRELATED,
        })
        with mock.patch.object(ollama_svc, "AGENTS_DIR", agents):
            self.assertEqual(
                ollama_svc._candidate_labels(),
                ["com.kiro.ollama", "homebrew.mxcl.ollama"],
            )


class ServiceState(_NoRealConfig):
    """``_service_state`` must not trust an empty launchctl listing over the API."""

    KIRO = LabelDiscovery.KIRO
    BREW = LabelDiscovery.BREW
    _agents_dir = LabelDiscovery._agents_dir

    def _listing(self, jobs: dict[str, tuple[str, str]]):
        from hub.launchd_cache import Listing

        return Listing(jobs)

    def test_api_up_marks_running_when_listing_is_empty(self):
        agents = self._agents_dir({"com.kiro.ollama.plist": self.KIRO})
        with (
            mock.patch.object(ollama_svc, "AGENTS_DIR", agents),
            mock.patch("hub.launchd_cache.listing", return_value=self._listing({})),
        ):
            state = ollama_svc._service_state(reachable=True)
        self.assertEqual(state["label"], "com.kiro.ollama")
        self.assertTrue(state["running"])
        self.assertTrue(state["loaded"])
        self.assertTrue(state["inferred"])
        self.assertIsNone(state["pid"])
        self.assertEqual(state["candidates"], ["com.kiro.ollama"])

    def test_api_down_does_not_infer_running_from_an_empty_listing(self):
        agents = self._agents_dir({"com.kiro.ollama.plist": self.KIRO})
        with (
            mock.patch.object(ollama_svc, "AGENTS_DIR", agents),
            mock.patch("hub.launchd_cache.listing", return_value=self._listing({})),
        ):
            state = ollama_svc._service_state(reachable=False)
        self.assertFalse(state["running"])
        self.assertFalse(state["inferred"])
        self.assertIsNone(state["pid"])

    def test_listing_pid_is_not_inferred(self):
        agents = self._agents_dir({"com.kiro.ollama.plist": self.KIRO})
        jobs = self._listing({"com.kiro.ollama": ("42", "0")})
        with (
            mock.patch.object(ollama_svc, "AGENTS_DIR", agents),
            mock.patch("hub.launchd_cache.listing", return_value=jobs),
        ):
            state = ollama_svc._service_state(reachable=True)
        self.assertEqual(state["pid"], 42)
        self.assertTrue(state["running"])
        self.assertFalse(state["inferred"])

    def test_listing_exception_still_infers_from_a_reachable_api(self):
        agents = self._agents_dir({"com.kiro.ollama.plist": self.KIRO})
        with (
            mock.patch.object(ollama_svc, "AGENTS_DIR", agents),
            mock.patch("hub.launchd_cache.listing", side_effect=OSError("hang")),
        ):
            state = ollama_svc._service_state(reachable=True)
        self.assertTrue(state["running"])
        self.assertTrue(state["inferred"])
        self.assertEqual(state["label"], "com.kiro.ollama")

    def test_candidates_surface_every_ollama_agent(self):
        agents = self._agents_dir({
            "com.kiro.ollama.plist": self.KIRO,
            "homebrew.mxcl.ollama.plist": self.BREW,
        })
        jobs = self._listing({"com.kiro.ollama": ("9", "0")})
        with (
            mock.patch.object(ollama_svc, "AGENTS_DIR", agents),
            mock.patch("hub.launchd_cache.listing", return_value=jobs),
        ):
            state = ollama_svc._service_state(reachable=True)
        self.assertEqual(
            state["candidates"],
            ["com.kiro.ollama", "homebrew.mxcl.ollama"],
        )
        self.assertFalse(state["inferred"])


class HealthGating(_NoRealConfig):
    def test_hosts_without_ollama_get_no_row(self):
        with (
            mock.patch.object(ollama_svc, "binary_path", return_value=None),
            mock.patch.object(ollama_svc, "discover_label", return_value=None),
        ):
            self.assertEqual(ollama_svc.health_checks(), [])

    def test_reachable_daemon_is_one_ok_row_with_resident_count(self):
        def fake_api(path, payload=None, timeout=None):
            return {"/api/version": {"version": "0.32.9"}, "/api/ps": PS_PAYLOAD}[path]

        with (
            mock.patch.object(ollama_svc, "binary_path", return_value="/fake/bin/ollama"),
            mock.patch.object(ollama_svc, "discover_label", return_value="com.kiro.ollama"),
            mock.patch.object(ollama_svc, "_candidate_labels", return_value=["com.kiro.ollama"]),
            mock.patch.object(ollama_svc, "_api", side_effect=fake_api),
        ):
            rows = ollama_svc.health_checks()
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["ok"])
        self.assertIn("0.32.9", rows[0]["detail"])
        self.assertIn("qwen3.5:4b", rows[0]["detail"])

    def test_unreachable_daemon_degrades_to_a_warn_row(self):
        with (
            mock.patch.object(ollama_svc, "binary_path", return_value="/fake/bin/ollama"),
            mock.patch.object(ollama_svc, "discover_label", return_value="com.kiro.ollama"),
            mock.patch.object(ollama_svc, "_candidate_labels", return_value=["com.kiro.ollama"]),
            mock.patch.object(ollama_svc, "_api", side_effect=OSError("refused")),
        ):
            rows = ollama_svc.health_checks()
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]["ok"])
        self.assertEqual(rows[0]["level"], "warn")
        self.assertIn("com.kiro.ollama", rows[0]["fix"])

    def test_multiple_agents_add_a_warn_row_alongside_the_api_check(self):
        def fake_api(path, payload=None, timeout=None):
            return {"/api/version": {"version": "0.32.9"}, "/api/ps": PS_PAYLOAD}[path]

        with (
            mock.patch.object(ollama_svc, "binary_path", return_value="/fake/bin/ollama"),
            mock.patch.object(ollama_svc, "discover_label", return_value="com.kiro.ollama"),
            mock.patch.object(
                ollama_svc, "_candidate_labels",
                return_value=["com.kiro.ollama", "homebrew.mxcl.ollama"],
            ),
            mock.patch.object(ollama_svc, "_api", side_effect=fake_api),
        ):
            rows = ollama_svc.health_checks()
        ids = [r["id"] for r in rows]
        self.assertEqual(ids, ["ollama_duplicate_agents", "ollama_api"])
        self.assertFalse(rows[0]["ok"])
        self.assertIn("homebrew.mxcl.ollama", rows[0]["detail"])
        self.assertTrue(rows[1]["ok"])

    def test_health_svc_probe_never_raises(self):
        from hub import health_svc

        with mock.patch.object(ollama_svc, "health_checks", side_effect=RuntimeError("boom")):
            rows = health_svc._ollama_checks()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["level"], "warn")
        self.assertFalse(rows[0]["ok"])

    def test_health_svc_probe_passes_rows_through(self):
        with mock.patch.object(ollama_svc, "health_checks", return_value=[]):
            from hub import health_svc

            self.assertEqual(health_svc._ollama_checks(), [])


class RouterContract(_NoRealConfig):
    def test_every_endpoint_is_registered(self):
        # The leaf router owns the paths; the aggregate include is asserted by
        # importing it from the package router module, which is what the app
        # factory mounts behind require_auth.
        from hub.routers import ollama_api

        paths = {route.path for route in ollama_api.router.routes}
        for path in (
            "/api/ollama/status",
            "/api/ollama/pull",
            "/api/ollama/pull/log",
            "/api/ollama/models/delete",
            "/api/ollama/models/unload",
            "/api/ollama/test",
            "/api/ollama/chat",
        ):
            self.assertIn(path, paths)

    def test_the_aggregate_router_includes_the_ollama_routes(self):
        import hub.routers as routers_pkg

        source = (BASE / "hub" / "routers" / "__init__.py").read_text()
        self.assertIn("ollama_api", source)
        self.assertTrue(hasattr(routers_pkg, "ollama_api"))

    def test_delete_requires_the_explicit_confirm_flag(self):
        from hub.routers import ollama_api

        body = ollama_api.DeleteBody(model="qwen3.5:4b", confirm=False)
        with self.assertRaises(HTTPException) as ctx:
            ollama_api.delete_model(body, request=None)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(_code(ctx.exception), "ollama.confirm_required")

    def test_error_codes_are_registered_for_the_spa(self):
        from hub.errors import CODES

        for code in (
            "ollama.not_installed",
            "ollama.bad_model_name",
            "ollama.pull_running",
            "ollama.confirm_required",
            "ollama.rm_failed",
            "ollama.unload_failed",
            "ollama.generate_failed",
            "ollama.chat_failed",
            "ollama.prompt_too_long",
            "ollama.messages_required",
            "ollama.bad_message",
        ):
            self.assertIn(code, CODES)


class NativeCatalogEntry(_NoRealConfig):
    def test_entry_follows_the_brew_formula_schema(self):
        from hub.native_catalog import NATIVE_APPS

        entries = [a for a in NATIVE_APPS if a["id"] == "native-ollama"]
        self.assertEqual(len(entries), 1)
        app = entries[0]
        self.assertEqual(app["method"], "brew_formula")
        self.assertEqual(app["package"], "ollama")
        self.assertIn("bin:ollama", app["check"])
        self.assertTrue(app["service"])
        self.assertEqual(app["ports"], ["11434"])
        self.assertNotIn("url_hint", app)  # an API port is not a web UI
        self.assertIn("custom LaunchAgent", app["notes"])


class NativeOllamaBrewSkip(_NoRealConfig):
    """Install/start must not spawn a second brew daemon when :11434 is live.

    Every executor is mocked — these tests never call brew or launchctl.
    """

    def test_helper_reports_the_probed_port(self):
        from hub import native_catalog

        with mock.patch("hub.util.port_open", return_value=True) as poked:
            self.assertTrue(native_catalog.ollama_api_already_served())
        poked.assert_called_once_with(native_catalog.OLLAMA_API_PORT, host="127.0.0.1")
        with mock.patch("hub.util.port_open", return_value=False):
            self.assertFalse(native_catalog.ollama_api_already_served())

    def test_install_skips_brew_services_start_when_the_port_is_open(self):
        from hub import native_catalog

        ran: list[list] = []

        def fake_run(argv, **kwargs):
            ran.append(list(argv))
            return {"ok": True, "message": "started", "rc": 0}

        app = next(a for a in native_catalog.NATIVE_APPS if a["id"] == "native-ollama")
        with (
            mock.patch.object(native_catalog, "_is_installed", return_value=True),
            mock.patch.object(native_catalog, "ollama_api_already_served", return_value=True),
            mock.patch.object(native_catalog, "_run", side_effect=fake_run),
            mock.patch.object(native_catalog, "_run_brew", side_effect=fake_run),
        ):
            result = native_catalog._install_native(app, "native-ollama")
        self.assertTrue(result["ok"])
        self.assertIn("already served", result["message"])
        self.assertFalse(any("services" in cmd and "start" in cmd for cmd in ran))

    def test_install_starts_the_brew_service_when_the_port_is_closed(self):
        from hub import native_catalog

        ran: list[list] = []

        def fake_run(argv, **kwargs):
            ran.append(list(argv))
            return {"ok": True, "message": "started", "rc": 0}

        app = next(a for a in native_catalog.NATIVE_APPS if a["id"] == "native-ollama")
        with (
            mock.patch.object(native_catalog, "_is_installed", return_value=True),
            mock.patch.object(native_catalog, "ollama_api_already_served", return_value=False),
            mock.patch.object(native_catalog, "_run", side_effect=fake_run),
            mock.patch.object(native_catalog, "_run_brew", side_effect=fake_run),
        ):
            result = native_catalog._install_native(app, "native-ollama")
        self.assertTrue(result["ok"])
        self.assertTrue(any("services" in cmd and "start" in cmd for cmd in ran))

    def test_apps_start_skips_a_second_daemon_when_the_port_is_open(self):
        from hub import apps_manage_svc, native_catalog

        with (
            mock.patch.object(native_catalog, "ollama_api_already_served", return_value=True),
            mock.patch.object(native_catalog, "_run") as run,
            mock.patch.object(apps_manage_svc, "invalidate_inventory"),
        ):
            result = apps_manage_svc.action("native-ollama", "start")
        self.assertTrue(result["ok"])
        self.assertIn("already serving", result["message"])
        run.assert_not_called()

    def test_apps_start_calls_brew_when_the_port_is_closed(self):
        from hub import apps_manage_svc, native_catalog

        with (
            mock.patch.object(native_catalog, "ollama_api_already_served", return_value=False),
            mock.patch.object(
                native_catalog, "_run",
                return_value={"ok": True, "message": "started", "rc": 0},
            ) as run,
            mock.patch.object(apps_manage_svc, "invalidate_inventory"),
        ):
            result = apps_manage_svc.action("native-ollama", "start")
        self.assertTrue(result["ok"])
        run.assert_called_once()
        argv = run.call_args[0][0]
        self.assertIn("services", argv)
        self.assertIn("start", argv)
        self.assertIn("ollama", argv)


if __name__ == "__main__":
    unittest.main(verbosity=2)
