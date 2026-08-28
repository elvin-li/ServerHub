"""Terminal leftover sweep #12: home/tailer provider seams and constant bombs.

A fresh hunt over the terminal JSON surfaces (GET /api/terminal,
POST /api/terminal/run, GET /api/terminal/history) after the term11
runner-seam/collider sweep, replaying the leftover zoo through the
provider seams the sibling ``*12`` sweeps established (backups12's
``user_home``, storage12's raising providers, ollama12's answer shapes,
gateway11's bin constants).  Found genuinely live raw 500s:

* **fixed** — ``_home_dir`` ran the ``user_home`` provider seam bare and
  ``str()``'d its answer bare.  A raising provider — or one answering a
  leftover whose ``__str__`` bombs — detonated GET /api/terminal (the
  status cwd fallback) and POST /api/terminal/run (``_resolve_cwd``
  builds its candidate tuple eagerly, so the bomb fired even when the
  requested cwd was perfectly fine).  An unusable answer now degrades to
  the HOME/"/" fallback the no-home case already took;

* **fixed** — ``recent_audit`` guarded its tailer with ``except OSError``
  only and trusted the answer shape.  A patched ``tail_file_lines`` that
  raises any other type, one answering a non-iterable (or a generator
  that raises mid-walk), and a non-str row handed to ``json.loads``
  (TypeError, outside the old ``(ValueError, RecursionError)`` net) each
  unwound out of GET /api/terminal/history as a raw 500.  Junk now
  answers the same empty pane a missing file does, and a junk row costs
  itself while honest rows beside it survive;

* **fixed** — ``_audit``'s catch was a six-type shortlist, but the write
  path crosses the lock, the ``secure_io`` writers, stat, chmod and the
  tail-trim — every one a patched seam that raises whatever it likes.  A
  ``RuntimeError`` out of ``file_lock``/``append_text`` unwound through
  the trail write as a raw 500 on POST /api/terminal/run *after* the
  command had already executed (the hub.audit.record() rule);

* **fixed** — ``execute`` dispatched with a bare ``shell or "/bin/sh"``,
  running a caller-supplied value's own ``__bool__`` one line ahead of
  ``run_container``'s launder: a str-subclass shell whose ``__bool__``
  bombs detonated the dispatcher itself;

* **fixed** — ``_docker_vanished`` interpolated the ``DOCKER`` constant
  bare and ``Path()``'d it bare, and rc 127 is also what a shell answers
  for a command missing *inside* the container — so the probe runs on
  honest receipts.  A leftover constant whose ``__format__``/``__str__``
  bombs, or a non-str constant (``Path()`` TypeError, outside the
  ``(OSError, ValueError)`` net), was a raw 500 after the command had
  executed.  An unrenderable constant now names no sentinel and confirms
  nothing.

Stays-immune pins: an honest home still reads through, honest audit rows
still list, a run whose writer seam raised still answers its own receipt,
an empty shell still defaults to ``/bin/sh``, honest vanished-CLI
evidence still earns the coded 503, and the term11 union guards
(``_spawn_receipt``'s stub, the honest daemon-down 503) stay pinned.
"""
from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi.testclient import TestClient

from hub import terminal_svc
from hub.auth import require_auth

_APP = None


def _client() -> TestClient:
    global _APP
    if _APP is None:
        from hub.app_factory import create_app

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> str:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    text = json.dumps(payload, ensure_ascii=False, allow_nan=False)
    text.encode("utf-8")
    return text


def _receipt(**kw) -> dict:
    base = {
        "ok": True, "rc": 0, "stdout": "x", "stderr": "",
        "truncated": False, "duration_ms": 1,
    }
    base.update(kw)
    return base


class _StrBomb:
    """Leftover whose rendering raises — ``str()`` and f-strings both blow."""

    def __str__(self):
        raise RuntimeError("leftover __str__ bomb")

    def __repr__(self):
        return "strbomb"


class _BoolBombStr(str):
    """Str subclass whose truthiness probe raises (the dispatcher's ``or``)."""

    def __bool__(self):
        raise RuntimeError("leftover shell __bool__ bomb")


class _FormatBombStr(str):
    """Str subclass whose f-string interpolation raises."""

    def __format__(self, spec):
        raise RuntimeError("leftover constant format bomb")


class _PathishConstant:
    """Non-str constant that still honestly names the CLI path."""

    def __init__(self, text: str):
        self._text = text

    def __str__(self):
        return self._text


class _RunSandbox(unittest.TestCase):
    """Scratch audit path, host_enabled on, seams patched per-request."""

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.audit = Path(tmp.name) / "terminal-audit.jsonl"
        patcher = mock.patch.object(terminal_svc, "AUDIT_PATH", self.audit)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client = _client()

    def _post(self, target="container", run=None, engine_up=None, extra=()):
        body = {"command": "echo hi", "target": target}
        if target == "container":
            body["container"] = "web"
        patches = [
            mock.patch.object(
                terminal_svc, "settings_section",
                return_value={"host_enabled": True},
            ),
            mock.patch.object(
                terminal_svc, "engine_up",
                engine_up if engine_up is not None else (lambda force=False: True),
            ),
        ]
        if run is not None:
            patches.append(mock.patch.object(terminal_svc, "_run", run))
        patches.extend(extra)
        for p in patches:
            p.start()
        try:
            return self.client.post("/api/terminal/run", json=body)
        finally:
            for p in patches:
                p.stop()

    def assert_coded_not_500(self, response, status: int) -> dict:
        self.assertEqual(response.status_code, status, response.text[:300])
        body = response.json()
        _starlette(body)
        return body


class HomeProviderSeamTests(_RunSandbox):
    """``user_home`` is a patched provider seam (the backups12 rule): a
    raising provider or a ``__str__``-bombing answer used to 500 the status
    payload and the host run's eagerly-built cwd fallback."""

    @staticmethod
    def _raising_home():
        raise RuntimeError("leftover home provider bomb")

    def test_status_survives_a_raising_home_provider(self):
        with mock.patch.object(
            terminal_svc, "settings_section", return_value={}
        ), mock.patch.object(terminal_svc, "user_home", self._raising_home):
            resp = self.client.get("/api/terminal")
        body = self.assert_coded_not_500(resp, 200)
        # The fallback still names a directory string, never a crash.
        self.assertIsInstance(body["cwd"], str)
        self.assertTrue(body["cwd"])

    def test_status_survives_a_str_bomb_home_answer(self):
        with mock.patch.object(
            terminal_svc, "settings_section", return_value={}
        ), mock.patch.object(
            terminal_svc, "user_home", lambda: _StrBomb()
        ):
            resp = self.client.get("/api/terminal")
        body = self.assert_coded_not_500(resp, 200)
        self.assertIsInstance(body["cwd"], str)

    def test_host_run_survives_a_raising_home_provider(self):
        # _resolve_cwd builds its candidate tuple eagerly, so the provider
        # ran even when the requested cwd was perfectly usable.
        body = self.assert_coded_not_500(
            self._post(
                target="host",
                run=lambda *a, **k: _receipt(),
                extra=(
                    mock.patch.object(
                        terminal_svc, "user_home", self._raising_home
                    ),
                ),
            ),
            200,
        )
        self.assertEqual(body["rc"], 0)
        self.assertEqual(body["target"], "host")

    def test_home_dir_honest_answers_still_read_through(self):
        with mock.patch.object(
            terminal_svc, "user_home", lambda: Path("/somewhere/home")
        ):
            self.assertEqual(terminal_svc._home_dir(), "/somewhere/home")
        with mock.patch.object(
            terminal_svc, "user_home", lambda: b"/bytes/home"
        ):
            self.assertEqual(terminal_svc._home_dir(), "/bytes/home")

    def test_home_dir_junk_degrades_to_the_env_fallback(self):
        expected = os.environ.get("HOME", "").strip() or "/"
        for provider in (self._raising_home, lambda: _StrBomb(), lambda: ""):
            with self.subTest(provider=provider):
                with mock.patch.object(terminal_svc, "user_home", provider):
                    self.assertEqual(terminal_svc._home_dir(), expected)


class HistoryTailerSeamTests(_RunSandbox):
    """``tail_file_lines`` is a patched provider seam: a raise outside
    OSError, a non-iterable answer, or non-str rows used to 500
    GET /api/terminal/history."""

    def _get_history(self, tailer):
        # A real file so the exists() gate passes and the tailer runs.
        self.audit.write_text('{"command": "seed", "rc": 0}\n')
        with mock.patch.object(
            terminal_svc, "settings_section", return_value={}
        ), mock.patch.object(terminal_svc, "tail_file_lines", tailer):
            return self.client.get("/api/terminal/history")

    def test_raising_tailer_answers_the_empty_pane(self):
        boom = mock.Mock(side_effect=RuntimeError("leftover tailer bomb"))
        body = self.assert_coded_not_500(self._get_history(boom), 200)
        self.assertEqual(body["entries"], [])

    def test_non_iterable_tailer_answer_answers_the_empty_pane(self):
        body = self.assert_coded_not_500(
            self._get_history(lambda *a, **k: None), 200
        )
        self.assertEqual(body["entries"], [])

    def test_generator_that_raises_mid_walk_answers_the_empty_pane(self):
        def _gen(*a, **k):
            yield '{"command": "early", "rc": 0}'
            raise RuntimeError("leftover mid-walk bomb")

        body = self.assert_coded_not_500(self._get_history(_gen), 200)
        self.assertEqual(body["entries"], [])

    def test_junk_rows_cost_themselves_and_honest_rows_survive(self):
        rows = [
            42,
            object(),
            b'{"command": "bytes-row", "rc": 0}',
            '{"command": "kept", "rc": 0}',
            "not json at all",
        ]
        body = self.assert_coded_not_500(
            self._get_history(lambda *a, **k: rows), 200
        )
        commands = [row.get("command") for row in body["entries"]]
        self.assertIn("kept", commands)
        self.assertIn("bytes-row", commands)
        self.assertNotIn(42, commands)

    def test_raising_loader_seam_costs_the_row_not_the_route(self):
        boom = mock.Mock(side_effect=RuntimeError("leftover loader bomb"))
        self.audit.write_text('{"command": "seed", "rc": 0}\n')
        with mock.patch.object(
            terminal_svc, "settings_section", return_value={}
        ), mock.patch.object(terminal_svc, "safe_json_loads", boom):
            resp = self.client.get("/api/terminal/history")
        body = self.assert_coded_not_500(resp, 200)
        self.assertEqual(body["entries"], [])

    def test_honest_rows_on_disk_still_list(self):
        self.audit.write_text(
            '{"command": "first", "rc": 0}\n{"command": "second", "rc": 1}\n'
        )
        with mock.patch.object(
            terminal_svc, "settings_section", return_value={}
        ):
            resp = self.client.get("/api/terminal/history")
        body = self.assert_coded_not_500(resp, 200)
        commands = [row.get("command") for row in body["entries"]]
        self.assertEqual(commands, ["first", "second"])


class AuditWriterSeamTests(_RunSandbox):
    """The trail write crosses lock/writer/stat/chmod seams; a raise there
    used to 500 the run *after* the command had already executed."""

    def test_raising_append_seam_keeps_the_receipt(self):
        boom = mock.Mock(side_effect=RuntimeError("leftover writer bomb"))
        for target in ("host", "container"):
            with self.subTest(target=target):
                body = self.assert_coded_not_500(
                    self._post(
                        target=target,
                        run=lambda *a, **k: _receipt(),
                        extra=(
                            mock.patch.object(
                                terminal_svc.secure_io, "append_text", boom
                            ),
                        ),
                    ),
                    200,
                )
                self.assertEqual(body["rc"], 0)
                self.assertEqual(body["target"], target)

    def test_raising_lock_seam_keeps_the_receipt(self):
        boom = mock.Mock(side_effect=RuntimeError("leftover lock bomb"))
        body = self.assert_coded_not_500(
            self._post(
                target="host",
                run=lambda *a, **k: _receipt(),
                extra=(
                    mock.patch.object(
                        terminal_svc.secure_io, "file_lock", boom
                    ),
                ),
            ),
            200,
        )
        self.assertEqual(body["rc"], 0)

    def test_honest_runs_still_reach_the_trail(self):
        self.assert_coded_not_500(
            self._post(target="host", run=lambda *a, **k: _receipt()), 200
        )
        with mock.patch.object(
            terminal_svc, "settings_section", return_value={}
        ):
            resp = self.client.get("/api/terminal/history")
        body = self.assert_coded_not_500(resp, 200)
        commands = [row.get("command") for row in body["entries"]]
        self.assertIn("echo hi", commands)


class DispatcherShellProbeTests(unittest.TestCase):
    """``execute``'s old ``shell or "/bin/sh"`` ran a caller-supplied
    value's own ``__bool__`` ahead of run_container's launder."""

    def _execute(self, shell):
        captured = {}

        def _fake_run(argv, timeout, cwd=None):
            captured["argv"] = list(argv)
            return _receipt()

        with mock.patch.object(
            terminal_svc, "settings_section",
            return_value={"host_enabled": True},
        ), mock.patch.object(
            terminal_svc, "engine_up", lambda force=False: True
        ), mock.patch.object(
            terminal_svc, "_run", _fake_run
        ), mock.patch.object(
            terminal_svc, "_audit", lambda entry: None
        ):
            out = terminal_svc.execute(
                "container", "echo hi", container="web", shell=shell
            )
        return out, captured["argv"]

    def test_bool_bomb_shell_cannot_detonate_the_dispatcher(self):
        out, argv = self._execute(_BoolBombStr("zsh"))
        self.assertEqual(out["rc"], 0)
        # The subclass's honest text still names the shell to exec.
        self.assertEqual(argv[4], "zsh")

    def test_empty_shell_still_defaults(self):
        out, argv = self._execute("")
        self.assertEqual(out["rc"], 0)
        self.assertEqual(argv[4], "/bin/sh")

    def test_non_str_shell_still_defaults(self):
        out, argv = self._execute(_StrBomb())
        self.assertEqual(out["rc"], 0)
        self.assertEqual(argv[4], "/bin/sh")


class DockerConstantBombTests(_RunSandbox):
    """rc 127 is an honest in-container answer too, so the vanished probe
    runs on real receipts — a DOCKER constant bomb there was a raw 500
    after the command had executed (the gateway11 bin-constant rule)."""

    _RC127 = _receipt(rc=127, ok=False, stdout="", stderr="sh: 1: foo: junk")

    def test_format_bomb_constant_keeps_the_receipt(self):
        with mock.patch.object(
            terminal_svc, "DOCKER", _FormatBombStr("/usr/local/bin/docker")
        ):
            body = self.assert_coded_not_500(
                self._post(run=lambda *a, **k: dict(self._RC127)), 200
            )
        self.assertEqual(body["rc"], 127)

    def test_unrenderable_constant_confirms_nothing(self):
        # Even with the engine probe answering "down" and a sentinel-shaped
        # stderr, a constant that cannot name the CLI matches no sentinel:
        # the coded 503 still requires honest evidence.
        receipt = _receipt(
            rc=127, ok=False, stdout="",
            stderr="not found: /usr/local/bin/docker",
        )
        with mock.patch.object(terminal_svc, "DOCKER", _StrBomb()):
            body = self.assert_coded_not_500(
                self._post(
                    run=lambda *a, **k: dict(receipt),
                    engine_up=lambda force=False: False,
                ),
                200,
            )
        self.assertEqual(body["rc"], 127)

    def test_non_str_constant_with_honest_evidence_still_earns_the_503(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        gone = str(Path(tmp.name) / "docker")
        receipt = _receipt(
            rc=127, ok=False, stdout="", stderr=f"not found: {gone}"
        )
        with mock.patch.object(terminal_svc, "DOCKER", _PathishConstant(gone)):
            body = self.assert_coded_not_500(
                self._post(
                    run=lambda *a, **k: dict(receipt),
                    engine_up=lambda force=False: False,
                ),
                503,
            )
        self.assertEqual(body["detail"]["code"], "container.engine_down")

    def test_honest_vanished_cli_is_still_the_coded_503(self):
        # The term11 pin must not weaken: a real str constant, the exact
        # rc-127 sentinel and a confirmed-absent CLI still translate.
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        gone = str(Path(tmp.name) / "docker")
        receipt = _receipt(
            rc=127, ok=False, stdout="", stderr=f"not found: {gone}"
        )
        with mock.patch.object(terminal_svc, "DOCKER", gone):
            body = self.assert_coded_not_500(
                self._post(
                    run=lambda *a, **k: dict(receipt),
                    engine_up=lambda force=False: False,
                ),
                503,
            )
        self.assertEqual(body["detail"]["code"], "container.engine_down")


class SanitizerUnitPinTests(unittest.TestCase):
    """The unit contracts the route fixes rely on — and the term11 union
    guards this sweep must not weaken."""

    def test_docker_vanished_launders_the_constant(self):
        receipt = {"rc": 127, "stderr": "not found: /nope/docker"}
        with mock.patch.object(
            terminal_svc, "DOCKER", _PathishConstant("/nope/docker")
        ):
            self.assertIs(terminal_svc._docker_vanished(receipt), True)
        with mock.patch.object(terminal_svc, "DOCKER", _StrBomb()):
            self.assertIs(terminal_svc._docker_vanished(receipt), False)
        with mock.patch.object(
            terminal_svc, "DOCKER", _FormatBombStr("/nope/docker")
        ):
            # A format bomb on a subclass still *names* the path through the
            # unbound base copy, so honest evidence keeps translating.
            self.assertIs(terminal_svc._docker_vanished(receipt), True)

    def test_recent_audit_tailer_junk_answers_empty(self):
        fake_path = mock.Mock()
        fake_path.exists.return_value = True
        with mock.patch.object(
            terminal_svc, "AUDIT_PATH", fake_path
        ), mock.patch.object(
            terminal_svc, "tail_file_lines",
            mock.Mock(side_effect=RuntimeError("boom")),
        ):
            self.assertEqual(terminal_svc.recent_audit(5), [])

    def test_spawn_receipt_stub_is_still_the_junk_sentinel(self):
        # term11 do-not-weaken pin: a raising runner still degrades to the
        # rc -255 stub with an empty stderr.
        with mock.patch.object(
            terminal_svc, "_run", mock.Mock(side_effect=RuntimeError("bomb"))
        ):
            out = terminal_svc._spawn_receipt(["sh"], 5)
        self.assertEqual(out["rc"], -255)
        self.assertEqual(out["stderr"], "")
        self.assertIs(type(out), dict)

    def test_engine_confirmed_down_still_requires_an_honest_answer(self):
        # term11 do-not-weaken pin.
        with mock.patch.object(
            terminal_svc, "engine_up", lambda force=False: False
        ):
            self.assertIs(terminal_svc._engine_confirmed_down(), True)

        def _raise(force=False):
            raise RuntimeError("leftover probe bomb")

        with mock.patch.object(terminal_svc, "engine_up", _raise):
            self.assertIs(terminal_svc._engine_confirmed_down(), False)


if __name__ == "__main__":
    unittest.main()
