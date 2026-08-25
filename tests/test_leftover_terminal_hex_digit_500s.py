"""Leftover hex-int / non-str shapes in the terminal's settings and arguments.

The previous terminal digit hunt (test_leftover_terminal_logs_audit_jobs_digit
_500s.py) pinned the *decimal* shapes: a >4300-digit literal dies inside
``json.loads``/``int()`` itself, so every parser already had a ValueError to
absorb.  YAML is sneakier — ``0xFFF…`` hex parses with **no** digit limit
(only power-of-2 bases are capped), so ``settings.terminal.cwd``/``shell``
could hold a real int object past CPython's 4300-digit *str* cap.  This hunt
found and fixed:

* ``status()`` — the bare ``str()`` on the configured cwd/shell raised
  ValueError before ``_jsonable`` ever ran: a 500 on GET /api/terminal.
  Both now go through ``_config_text`` and fall back ($HOME / default shell);
* ``run_host()`` — the same bare ``str()`` on the configured shell 500'd
  POST /api/terminal/run before the command started;
* ``_resolve_cwd()`` — ``str(candidate)`` on the configured hex-int cwd
  raised out of the loop: a 500 on POST /api/terminal/run (host) and a
  bogus 4400 close on the PTY WebSocket handshake (``terminal_pty._argv``
  funnels through the same helper);
* ``_jsonable()`` — ints passed through unbounded, so a >4300-digit int
  anywhere in a payload reached Starlette's encoder and 500'd there (the
  sibling _jsonable clones in docker_cli/system_settings_svc/metrics_rollup
  already carried the str-probe guard; the terminal's copy did not);
* ``run_container()`` — ``container``/``target``/``command`` already
  tolerated leftover non-str values, but a non-str ``shell`` was an
  AttributeError on ``.strip()``.

UTF-8 sweep: a lone-surrogate configured shell keeps its existing path — the
spawn is refused as "invalid argument" inside ``_run`` and the receipt is
scrubbed by ``_response`` — pinned here so the ``_config_text`` fold cannot
regress it.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from hub import terminal_pty, terminal_svc

#: A real int object past CPython's 4300-digit int->str cap, built the way a
#: leftover YAML scalar builds it: hex parsing has no digit limit.
_HEX_HUGE = yaml.safe_load("v: 0x" + "F" * 5000)["v"]
#: Under the cap: str() succeeds, so the value must survive untouched.
_BIG = int("9" * 400)


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _AuditToTempMixin(unittest.TestCase):
    """Point the audit trail at a throwaway file for run_* tests."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="term-hex-pin-"))
        self.audit = self.dir / "terminal-audit.jsonl"
        patched = mock.patch.object(terminal_svc, "AUDIT_PATH", self.audit)
        patched.start()
        self.addCleanup(patched.stop)
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        # The audit writer leaves its flock sidecar next to the trail.
        shutil.rmtree(self.dir, ignore_errors=True)

    def _cfg(self, **section):
        patched = mock.patch.object(
            terminal_svc, "settings_section", return_value=section
        )
        patched.start()
        self.addCleanup(patched.stop)


class TerminalStatusHexIntPinTests(_AuditToTempMixin):
    """GET /api/terminal renders whatever the terminal settings hold."""

    def test_hex_huge_cwd_falls_back_to_home_not_a_500(self):
        self._cfg(cwd=_HEX_HUGE)
        payload = terminal_svc.status()
        self.assertEqual(payload["cwd"], terminal_svc._home_dir())
        _starlette(payload)

    def test_hex_huge_shell_falls_back_to_the_default_not_a_500(self):
        self._cfg(shell=_HEX_HUGE)
        payload = terminal_svc.status()
        self.assertEqual(payload["shell"], terminal_svc._default_shell())
        _starlette(payload)

    def test_sane_configured_values_stay_verbatim(self):
        self._cfg(cwd="/tmp", shell="/bin/sh")
        payload = terminal_svc.status()
        self.assertEqual(payload["cwd"], "/tmp")
        self.assertEqual(payload["shell"], "/bin/sh")
        _starlette(payload)


class TerminalRunHexIntPinTests(_AuditToTempMixin):
    """POST /api/terminal/run (host) with poisoned terminal settings."""

    def test_hex_huge_shell_runs_through_the_default_shell(self):
        self._cfg(host_enabled=True, shell=_HEX_HUGE)
        result = terminal_svc.run_host("echo leftover", timeout=5)
        self.assertTrue(result["ok"])
        self.assertIn("leftover", result["stdout"])
        _starlette(result)

    def test_hex_huge_cwd_runs_from_home(self):
        self._cfg(host_enabled=True, cwd=_HEX_HUGE)
        result = terminal_svc.run_host("echo hi", timeout=5)
        self.assertTrue(result["ok"])
        _starlette(result)

    def test_surrogate_shell_keeps_the_invalid_argument_receipt(self):
        # A lone surrogate cannot reach exec on this platform: the spawn is
        # ValueError inside Popen, absorbed as the rc-127 receipt.  Pinned so
        # the _config_text fold keeps strings verbatim instead of scrubbing
        # them into a path that half-exists.
        self._cfg(host_enabled=True, shell="/bin/\ud800sh")
        result = terminal_svc.run_host("echo hi", timeout=5)
        self.assertFalse(result["ok"])
        self.assertEqual(result["rc"], 127)
        _starlette(result)


class ResolveCwdHexIntPinTests(_AuditToTempMixin):
    """_resolve_cwd feeds both the one-shot host run and the PTY handshake."""

    def test_hex_huge_configured_cwd_falls_back_to_home(self):
        self._cfg(cwd=_HEX_HUGE)
        self.assertEqual(
            terminal_svc._resolve_cwd(None), terminal_svc._home_dir()
        )

    def test_pty_argv_survives_the_hex_huge_cwd(self):
        # The PTY handshake used to close 4400 on the same ValueError; the
        # session must open with a usable start directory instead.
        self._cfg(host_enabled=True, cwd=_HEX_HUGE)
        argv, cwd = terminal_pty._argv("host", "", "")
        self.assertTrue(argv)
        self.assertEqual(cwd, terminal_svc._home_dir())

    def test_requested_directory_still_wins(self):
        self._cfg(cwd=_HEX_HUGE)
        self.assertEqual(terminal_svc._resolve_cwd("/tmp"), "/tmp")


class JsonableHugeIntPinTests(unittest.TestCase):
    """_jsonable is the last line before Starlette's allow_nan=False encoder."""

    def test_over_cap_int_is_dropped_like_inf(self):
        self.assertIsNone(terminal_svc._jsonable(_HEX_HUGE))
        cleaned = terminal_svc._jsonable({"cwd": _HEX_HUGE, "rc": 0})
        self.assertEqual(cleaned, {"cwd": None, "rc": 0})
        _starlette(cleaned)

    def test_over_cap_int_nested_in_lists_is_dropped(self):
        cleaned = terminal_svc._jsonable([1, [_HEX_HUGE], {"x": _HEX_HUGE}])
        self.assertEqual(cleaned, [1, [None], {"x": None}])
        _starlette(cleaned)

    def test_under_cap_400_digit_int_survives(self):
        self.assertEqual(terminal_svc._jsonable(_BIG), _BIG)
        _starlette({"v": terminal_svc._jsonable(_BIG)})

    def test_bools_and_none_keep_their_identity(self):
        self.assertIs(terminal_svc._jsonable(True), True)
        self.assertIsNone(terminal_svc._jsonable(None))


class ContainerShellLeftoverPinTests(_AuditToTempMixin):
    """run_container tolerated non-str container but not non-str shell."""

    def test_non_str_shell_falls_back_to_bin_sh(self):
        self._cfg(host_enabled=False)
        seen: list[list[str]] = []

        def fake_run(argv, timeout, cwd=None):
            seen.append(list(argv))
            return {
                "ok": True, "rc": 0, "stdout": "", "stderr": "",
                "truncated": False, "duration_ms": 0,
            }

        for shell in (None, 7, 1.5, True, ["/bin/sh"], {"sh": 1}, b"/bin/sh"):
            with self.subTest(shell=type(shell).__name__):
                with mock.patch.object(terminal_svc, "_run", side_effect=fake_run):
                    result = terminal_svc.run_container(
                        "app", "echo hi", shell=shell, timeout=5
                    )
                self.assertEqual(seen[-1][4], "/bin/sh")
                _starlette(result)

    def test_str_shell_still_passes_through(self):
        self._cfg(host_enabled=False)
        seen: list[list[str]] = []

        def fake_run(argv, timeout, cwd=None):
            seen.append(list(argv))
            return {
                "ok": True, "rc": 0, "stdout": "", "stderr": "",
                "truncated": False, "duration_ms": 0,
            }

        with mock.patch.object(terminal_svc, "_run", side_effect=fake_run):
            terminal_svc.run_container("app", "echo hi", shell="/bin/bash")
        self.assertEqual(seen[-1][4], "/bin/bash")


class ConfigTextPinTests(unittest.TestCase):
    """The helper the status/run/resolve folds share."""

    def test_over_cap_int_is_empty(self):
        self.assertEqual(terminal_svc._config_text(_HEX_HUGE), "")

    def test_strings_are_verbatim_even_with_surrogates(self):
        # Scrubbing belongs to _jsonable at the response edge; the config
        # reader must not mangle a value it only needs to compare and spawn.
        self.assertEqual(terminal_svc._config_text("/tmp"), "/tmp")
        self.assertEqual(terminal_svc._config_text("a\ud800b"), "a\ud800b")

    def test_none_is_empty_and_small_ints_render(self):
        self.assertEqual(terminal_svc._config_text(None), "")
        self.assertEqual(terminal_svc._config_text(7), "7")


if __name__ == "__main__":
    unittest.main()
