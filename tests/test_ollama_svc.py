"""Ollama integration: parsing, argv safety, single-flight, discovery, gating.

Everything runs against fixtures or mocks — no test talks to a live daemon,
spawns `ollama`, or reads the operator's real LaunchAgents.  The payload
fixtures were captured verbatim from ollama 0.32.9 (`/api/tags`, `/api/ps`),
so the parsers are exercised against the real wire shapes.
"""
from __future__ import annotations

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
            mock.patch.object(ollama_svc, "_api", side_effect=OSError("refused")),
        ):
            rows = ollama_svc.health_checks()
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]["ok"])
        self.assertEqual(rows[0]["level"], "warn")
        self.assertIn("com.kiro.ollama", rows[0]["fix"])

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
            "ollama.prompt_too_long",
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
