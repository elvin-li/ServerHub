"""Leftover Ollama 500s: hex-plist over-cap ints, surrogate plist stems, vanished CLI.

The digit-cap battery (test_leftover_ollama_health_usage_gateway_digit_500s)
pinned the *string* parses — over-cap sizes and ports arrive as str and die in
``int(str)``.  This sweep covers the shapes that dodge that cap:

* plistlib parses ``<integer>0xFFF…</integer>`` through ``int(raw, 16)``,
  which is exempt from CPython's 4300-digit conversion limit — so a leftover
  LaunchAgent carrying a hex integer parsed fine, and ``repr(pl)`` inside
  ``_plist_label_if_ollama`` then raised the digit-cap ValueError (guarded
  only for RecursionError) and 500'd GET /api/ollama/status through
  ``_candidate_labels``;
* the same class of *already-int* over-cap value passed both
  ``ollama_svc._safe_int`` (``int(int)`` never converts) and
  ``ollama_svc._jsonable`` (plain passthrough) untouched, and ValueError'd
  Starlette's ``json.dumps`` itself at encode time;
* an undecodable LaunchAgent filename surfaces as a lone-surrogate str
  (surrogateescape); ``_plist_label_if_ollama`` fell back to the raw
  ``path.stem``, and the label reached the ``health_checks`` fix strings
  uncleaned, failing Starlette's UTF-8 encode;
* ``delete_model`` mapped every non-zero rc to the coded 500
  ``ollama.rm_failed`` — including run_watchdog's -1 could-not-run sentinel
  for a CLI that vanished between ``binary_path()`` and the spawn.  That is
  the exact condition the up-front gate answers with the 503
  ``ollama.not_installed``.  Classification requires a disk confirm (same
  rule as vms/brew): rc -1 is also a SIGHUP-killed rm, so a still-present
  binary keeps its raw rm_failed result.
"""
from __future__ import annotations

import json
import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from hub import ollama_svc

#: Hex digits past CPython's 4300-digit int<->str conversion limit once parsed.
_HEX_HUGE = "0x" + "f" * 5000
# Built arithmetically: int("9" * 5000) itself trips the digit cap.
_HUGE_INT = 10 ** 5000


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _code(exc: HTTPException) -> str:
    return (exc.detail or {}).get("code", "")


def _hex_plist(label: str) -> bytes:
    """An ollama-referencing LaunchAgent whose Nice is a hex over-cap int.

    plistlib.dumps refuses to *write* such an int, but its parser accepts one:
    ``end_integer`` routes 0x-prefixed text through ``int(raw, 16)``, which is
    exempt from the digit cap.  Built by hand for exactly that reason.
    """
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"'
        ' "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0"><dict>\n'
        f"<key>Label</key><string>{label}</string>\n"
        "<key>ProgramArguments</key><array>"
        "<string>/opt/homebrew/bin/ollama</string><string>serve</string></array>\n"
        f"<key>Nice</key><integer>{_HEX_HUGE}</integer>\n"
        "</dict></plist>\n"
    ).encode()


class _FakeConfig(unittest.TestCase):
    def setUp(self):
        super().setUp()
        patched = mock.patch.object(ollama_svc, "cfg", lambda: {"settings": {}})
        patched.start()
        self.addCleanup(patched.stop)

    def _agents_dir(self) -> Path:
        tmp = Path(tempfile.mkdtemp(prefix="serverhub-ollama-hex-"))
        self.addCleanup(self._rm_tree, tmp)
        return tmp

    @staticmethod
    def _rm_tree(tmp: Path) -> None:
        for child in tmp.iterdir():
            child.unlink()
        tmp.rmdir()


class HexPlistIntegerTests(_FakeConfig):
    """A leftover hex ``<integer>`` LaunchAgent must not 500 the status page."""

    def test_hex_int_plist_is_skipped_not_raised(self):
        agents = self._agents_dir()
        (agents / "local.ollama.serve.plist").write_bytes(_hex_plist("local.ollama.serve"))
        got = ollama_svc._plist_label_if_ollama(agents / "local.ollama.serve.plist")
        self.assertIsNone(got)

    def test_candidate_labels_keep_the_healthy_agent(self):
        agents = self._agents_dir()
        (agents / "poisoned.plist").write_bytes(_hex_plist("poisoned.ollama"))
        (agents / "com.kiro.ollama.plist").write_bytes(plistlib.dumps({
            "Label": "com.kiro.ollama",
            "ProgramArguments": ["/bin/zsh", "/Users/x/kiro_tools/serve.sh"],
            "EnvironmentVariables": {"OLLAMA_HOST": "127.0.0.1:11434"},
        }))
        with mock.patch.object(ollama_svc, "AGENTS_DIR", agents):
            labels = ollama_svc._candidate_labels()
        self.assertEqual(labels, ["com.kiro.ollama"])

    def test_status_renders_instead_of_500ing(self):
        agents = self._agents_dir()
        (agents / "local.ollama.serve.plist").write_bytes(_hex_plist("local.ollama.serve"))
        self.addCleanup(ollama_svc.status.invalidate)
        with (
            mock.patch.object(ollama_svc, "AGENTS_DIR", agents),
            mock.patch.object(ollama_svc, "_api", side_effect=OSError("refused")),
            mock.patch.object(ollama_svc, "binary_path", return_value=None),
            mock.patch("hub.launchd_cache.listing", side_effect=OSError("sandbox")),
        ):
            snap = ollama_svc.status(force=True)
        _starlette(snap)
        self.assertFalse(snap["reachable"])
        self.assertEqual(snap["service"]["candidates"], [])


class OverCapIntCoercerTests(_FakeConfig):
    """Already-int over-cap values must never reach Starlette's json.dumps."""

    def test_jsonable_drops_an_over_cap_int(self):
        cleaned = ollama_svc._jsonable({
            "n": _HUGE_INT,
            "nested": [{"deep": _HUGE_INT}],
            "sane": 3413361762,
        })
        _starlette(cleaned)
        self.assertIsNone(cleaned["n"])
        self.assertIsNone(cleaned["nested"][0]["deep"])
        self.assertEqual(cleaned["sane"], 3413361762)

    def test_safe_int_bounds_an_already_int_over_cap(self):
        self.assertEqual(ollama_svc._safe_int(_HUGE_INT), 0)
        self.assertEqual(ollama_svc._safe_int(_HUGE_INT, 7), 7)
        self.assertEqual(ollama_svc._safe_int(3413361762), 3413361762)

    def test_parse_tags_with_over_cap_int_fields_still_encodes(self):
        models = ollama_svc.parse_tags({
            "models": [{
                "name": "qwen3.5:4b",
                "size": _HUGE_INT,
                "details": {"context_length": _HUGE_INT},
            }],
        })
        _starlette(models)
        self.assertEqual(models[0]["size"], 0)
        self.assertIsNone(models[0]["context_length"])


class SurrogatePlistStemTests(_FakeConfig):
    """An undecodable LaunchAgent filename must not poison labels or health rows."""

    def _surrogate_agents(self) -> Path:
        agents = self._agents_dir()
        # No Label key: discovery falls back to the file stem, which carries
        # the surrogateescape leftover of an undecodable on-disk name.
        (agents / "local.ollama\udcff.plist").write_bytes(plistlib.dumps({
            "ProgramArguments": ["/opt/homebrew/bin/ollama", "serve"],
        }))
        return agents

    def test_candidate_labels_are_utf8_encodable(self):
        with mock.patch.object(ollama_svc, "AGENTS_DIR", self._surrogate_agents()):
            labels = ollama_svc._candidate_labels()
        _starlette(labels)
        self.assertEqual(len(labels), 1)
        self.assertNotIn("\udcff", labels[0])

    def test_health_rows_survive_the_starlette_encode(self):
        with (
            mock.patch.object(ollama_svc, "AGENTS_DIR", self._surrogate_agents()),
            mock.patch.object(
                ollama_svc, "binary_path", return_value="/opt/homebrew/bin/ollama",
            ),
            mock.patch.object(ollama_svc, "_api", side_effect=OSError("refused")),
        ):
            rows = ollama_svc.health_checks()
        _starlette(rows)
        self.assertEqual(rows[0]["id"], "ollama_api")
        self.assertNotIn("\udcff", rows[0]["fix"])

    def test_a_real_label_key_still_wins_over_the_stem(self):
        agents = self._agents_dir()
        (agents / "renamed\udcff.plist").write_bytes(plistlib.dumps({
            "Label": "com.kiro.ollama",
            "ProgramArguments": ["/opt/homebrew/bin/ollama", "serve"],
        }))
        with mock.patch.object(ollama_svc, "AGENTS_DIR", agents):
            self.assertEqual(ollama_svc._candidate_labels(), ["com.kiro.ollama"])


class VanishedCliDeleteTests(_FakeConfig):
    """rm's could-not-run sentinel is the 503, but only after a disk confirm."""

    def setUp(self):
        super().setUp()
        self._saved = {k: (list(v) if isinstance(v, list) else v)
                       for k, v in ollama_svc._pull.items()}
        ollama_svc._pull.update(
            running=False, rc=None, model=None, started=None, finished=None, log=[],
        )
        self.addCleanup(ollama_svc._pull.update, self._saved)
        self.addCleanup(ollama_svc.status.invalidate)

    def test_vanished_binary_is_the_coded_503(self):
        # The real spawn path: binary_path answered a moment ago, the file is
        # gone by Popen time, run_watchdog eats the FileNotFoundError into -1,
        # and the disk re-check confirms the CLI is no longer there.
        with mock.patch.object(
            ollama_svc, "binary_path",
            side_effect=["/nonexistent/bin/ollama", None],
        ):
            with self.assertRaises(HTTPException) as ctx:
                ollama_svc.delete_model("qwen3.5:4b")
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_code(ctx.exception), "ollama.not_installed")

    def test_sentinel_with_a_present_binary_keeps_rm_failed(self):
        # rc -1 is also a SIGHUP-killed rm; while the binary is still on disk
        # the raw failure must be reported, not a false "not installed".
        with (
            mock.patch.object(
                ollama_svc, "binary_path", return_value="/fake/bin/ollama",
            ),
            mock.patch.object(ollama_svc, "run_watchdog", return_value=-1),
        ):
            with self.assertRaises(HTTPException) as ctx:
                ollama_svc.delete_model("qwen3.5:4b")
        self.assertEqual(ctx.exception.status_code, 500)
        self.assertEqual(_code(ctx.exception), "ollama.rm_failed")

    def test_ordinary_rm_failure_never_probes_the_disk_again(self):
        calls = []

        def probed():
            calls.append(True)
            return "/fake/bin/ollama"

        with (
            mock.patch.object(ollama_svc, "binary_path", side_effect=probed),
            mock.patch.object(ollama_svc, "run_watchdog", return_value=1),
        ):
            with self.assertRaises(HTTPException) as ctx:
                ollama_svc.delete_model("qwen3.5:4b")
        self.assertEqual(_code(ctx.exception), "ollama.rm_failed")
        self.assertEqual(len(calls), 1)

    def test_successful_rm_still_answers_ok(self):
        def fake_watchdog(argv, *, timeout, log, env=None, cwd=None):
            log.append("deleted 'qwen3.5:4b'")
            return 0

        with (
            mock.patch.object(
                ollama_svc, "binary_path", return_value="/fake/bin/ollama",
            ),
            mock.patch.object(ollama_svc, "run_watchdog", side_effect=fake_watchdog),
        ):
            result = ollama_svc.delete_model("qwen3.5:4b")
        self.assertTrue(result["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
