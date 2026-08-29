"""Terminal leftover sweep #11: mutation-field colliders and the runner seam.

A fresh hunt over the terminal HTTP surfaces (POST /api/terminal/run host
*and* container branches, GET /api/terminal/history) replayed the leftover
zoo through the established in-process seams — poisoned ``_run`` receipts
and patched ``engine_up`` / ``looks_engine_down`` probes — and found
genuinely live raw 500s term 10 had not reached:

* **fixed** — ``run_host``/``run_container`` *write* ``target`` /
  ``container`` / ``cwd`` onto the receipt after the command ran, but
  ``_RECEIPT_DEFAULTS`` never seeded those fields.  A leftover str-subclass
  key whose ``__hash__`` lands on one of them slipped through
  ``_receipt_map``'s copy untouched (no seeded key to collide with, so its
  ``__eq__`` never ran), and the bare ``result["target"] = ...`` writes
  then probed that bucket and ran the stored key's own raising ``__eq__``
  — a raw 500 on POST /api/terminal/run *after* the command had already
  executed.  ``_receipt_map`` now seeds sentinel placeholders so every
  such collider drops at insert time exactly like the transport-field
  shadows, and strips untouched placeholders so the response shape is
  byte-for-byte unchanged;

* **fixed** — the runner call itself was bare: a patched ``_run`` that
  *raises* (any exception type) unwound out of both run branches as a raw
  500.  ``_spawn_receipt`` passes coded ``HTTPException``s through — the
  timeout answer stays the coded 504 — and degrades any other raise to the
  ``rc -255`` stub, never ``127`` and never ``-1``, so an unusable runner
  answer can neither forge the vanished-CLI confirm nor read like the
  engine-down phrases;

* **fixed** — the failure branch's ``or``/``not`` ran the patched
  ``looks_engine_down`` / ``engine_up`` seams bare: a raising probe, or
  one answering a leftover whose ``__bool__`` bombs, detonated right after
  the command ran — and ``_cfg_truthy`` alone would have read the bombing
  answer as falsy and *minted* the coded 503 from junk.
  ``_looks_engine_down`` treats an unreadable answer as no classification
  and ``_engine_confirmed_down`` requires an honest falsy answer, so the
  503 still needs real evidence and junk hands the receipt back verbatim.

Stays-immune pins: an honest daemon-down receipt still earns the coded
503, the vanished-CLI 503 still fires only after the on-disk confirm, the
transport-field shadow keys still degrade to the ``-255`` junk sentinel,
and the audit trail still records a run whose runner raised.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi.testclient import TestClient

from hub import terminal_svc
from hub.auth import require_auth
from hub.errors import api_error

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


class _ColliderKey(str):
    """Str-subclass key whose hash shadows a *mutation* field and whose
    ``__eq__`` raises when a later write probes the shared bucket."""

    _shadow = "target"

    def __new__(cls, shadow: str):
        self = super().__new__(cls, "weird-" + shadow)
        self._shadow = shadow
        return self

    def __hash__(self):
        return hash(self._shadow)

    def __eq__(self, other):
        raise RuntimeError("leftover collider eq bomb")

    def __ne__(self, other):
        raise RuntimeError("leftover collider ne bomb")


class _BoolBomb:
    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")


def _receipt(**kw) -> dict:
    base = {
        "ok": True, "rc": 0, "stdout": "x", "stderr": "",
        "truncated": False, "duration_ms": 1,
    }
    base.update(kw)
    return base


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

    def _post(self, target="container", run=None, engine_up=None, looks=None):
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
        if looks is not None:
            patches.append(
                mock.patch.object(terminal_svc, "looks_engine_down", looks)
            )
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


class MutationFieldColliderTests(_RunSandbox):
    """A collider key whose hash lands on ``target``/``container``/``cwd``
    used to slip through the receipt copy and detonate the bare post-run
    writes — a raw 500 after the command had already executed."""

    def _run_with_collider(self, shadow: str, target: str):
        receipt = _receipt()
        receipt[_ColliderKey(shadow)] = "junk"
        return self._post(target=target, run=lambda *a, **k: dict(receipt))

    def test_collider_keys_cannot_500_either_branch(self):
        for shadow in ("target", "container", "cwd"):
            for target in ("host", "container"):
                with self.subTest(shadow=shadow, target=target):
                    body = self.assert_coded_not_500(
                        self._run_with_collider(shadow, target), 200
                    )
                    # The collider drops; the honest receipt survives and
                    # the post-run writes land on clean buckets.
                    self.assertEqual(body["rc"], 0)
                    self.assertEqual(body["target"], target)

    def test_container_write_still_lands_after_a_collider(self):
        body = self.assert_coded_not_500(
            self._run_with_collider("container", "container"), 200
        )
        self.assertEqual(body["container"], "web")

    def test_host_response_shape_is_unchanged(self):
        body = self.assert_coded_not_500(
            self._post(target="host", run=lambda *a, **k: _receipt()), 200
        )
        # The placeholder seeding must not leak: a host run still has no
        # ``container`` key, and every seeded transport field is present.
        self.assertNotIn("container", body)
        for field in ("ok", "rc", "stdout", "stderr", "truncated",
                      "duration_ms", "target", "cwd"):
            self.assertIn(field, body)

    def test_honest_receipt_cwd_still_reads_through(self):
        # A receipt that legitimately carries a mutation field keeps it —
        # the placeholder is overwritten, not enforced.
        out = terminal_svc._receipt_map(_receipt(container="from-receipt"))
        self.assertEqual(out["container"], "from-receipt")


class RaisingRunnerSeamTests(_RunSandbox):
    """A patched runner that raises used to unwind out of the route as a
    raw 500; it now degrades to the failed-command stub — and the stub can
    never forge the vanished-CLI 503."""

    def test_raising_runner_degrades_to_the_stub(self):
        boom = mock.Mock(side_effect=RuntimeError("leftover runner bomb"))
        for target in ("host", "container"):
            with self.subTest(target=target):
                body = self.assert_coded_not_500(
                    self._post(target=target, run=boom), 200
                )
                # The junk sentinel, never the honest-looking -1 or the
                # spawn sentinel 127.
                self.assertEqual(body["rc"], -255)
                self.assertEqual(body["stdout"], "")
                self.assertIs(body["ok"], False)

    def test_coded_timeout_passes_through_untouched(self):
        boom = mock.Mock(side_effect=api_error("terminal.timeout", seconds=30))
        for target in ("host", "container"):
            with self.subTest(target=target):
                body = self.assert_coded_not_500(
                    self._post(target=target, run=boom), 504
                )
                self.assertEqual(body["detail"]["code"], "terminal.timeout")

    def test_raising_runner_cannot_forge_the_vanished_503(self):
        # Even with the engine probe answering "down" and the CLI genuinely
        # absent on disk, a raising runner is not the rc-127 spawn sentinel:
        # the stub's stderr is empty, so neither classifier matches and the
        # run stays a plain receipt — the 503 requires honest evidence.
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        gone = str(Path(tmp.name) / "docker")
        boom = mock.Mock(side_effect=RuntimeError("leftover runner bomb"))
        with mock.patch.object(terminal_svc, "DOCKER", gone):
            body = self.assert_coded_not_500(
                self._post(run=boom, engine_up=lambda force=False: False), 200
            )
        self.assertEqual(body["rc"], -255)

    def test_audit_still_records_a_run_whose_runner_raised(self):
        boom = mock.Mock(side_effect=RuntimeError("leftover runner bomb"))
        self.assert_coded_not_500(self._post(target="host", run=boom), 200)
        with mock.patch.object(
            terminal_svc, "settings_section", return_value={"host_enabled": True}
        ):
            resp = self.client.get("/api/terminal/history")
        body = self.assert_coded_not_500(resp, 200)
        rows = [r for r in body["entries"] if r.get("command") == "echo hi"]
        self.assertTrue(rows)
        self.assertEqual(rows[-1]["rc"], -255)


class EngineProbeSeamTests(_RunSandbox):
    """The failure branch's bare ``or``/``not`` used to run the patched
    probe seams raw — a raising probe or a ``__bool__``-bombing answer was
    a raw 500 after the command ran, and a junk answer must not mint the
    coded 503 either."""

    _DOWN = _receipt(rc=1, stderr="cannot connect to the docker daemon")

    def test_engine_up_raising_keeps_the_receipt(self):
        def _raise(force=False):
            raise RuntimeError("leftover probe bomb")

        body = self.assert_coded_not_500(
            self._post(run=lambda *a, **k: dict(self._DOWN), engine_up=_raise),
            200,
        )
        self.assertEqual(body["rc"], 1)

    def test_engine_up_bool_bomb_answer_confirms_nothing(self):
        body = self.assert_coded_not_500(
            self._post(
                run=lambda *a, **k: dict(self._DOWN),
                engine_up=lambda force=False: _BoolBomb(),
            ),
            200,
        )
        # An unreadable answer is not a confirmed-down answer: the coded
        # 503 replaces the command's own output and requires honest
        # evidence, so junk hands the receipt back verbatim.
        self.assertEqual(body["rc"], 1)

    def test_looks_engine_down_raising_keeps_the_receipt(self):
        def _raise(text):
            raise RuntimeError("leftover classifier bomb")

        body = self.assert_coded_not_500(
            self._post(
                run=lambda *a, **k: dict(_receipt(rc=1, stderr="boom")),
                engine_up=lambda force=False: False,
                looks=_raise,
            ),
            200,
        )
        self.assertEqual(body["rc"], 1)

    def test_looks_engine_down_bomb_answer_keeps_the_receipt(self):
        body = self.assert_coded_not_500(
            self._post(
                run=lambda *a, **k: dict(_receipt(rc=1, stderr="boom")),
                engine_up=lambda force=False: False,
                looks=lambda text: _BoolBomb(),
            ),
            200,
        )
        self.assertEqual(body["rc"], 1)

    def test_honest_daemon_down_is_still_the_coded_503(self):
        body = self.assert_coded_not_500(
            self._post(
                run=lambda *a, **k: dict(self._DOWN),
                engine_up=lambda force=False: False,
            ),
            503,
        )
        self.assertEqual(body["detail"]["code"], "container.engine_down")

    def test_honest_vanished_cli_is_still_the_coded_503(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        gone = str(Path(tmp.name) / "docker")
        receipt = _receipt(rc=127, stdout="", stderr=f"not found: {gone}")
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
    """The unit contracts the route fixes rely on."""

    def test_receipt_map_drops_mutation_field_colliders(self):
        for shadow in ("target", "container", "cwd"):
            with self.subTest(shadow=shadow):
                receipt = _receipt()
                receipt[_ColliderKey(shadow)] = "junk"
                out = terminal_svc._receipt_map(receipt)
                # The collider is gone, the placeholder is stripped, and the
                # later bare write cannot meet a hostile key in the bucket.
                self.assertNotIn(shadow, out)
                out[shadow] = "written"
                self.assertEqual(out[shadow], "written")
                self.assertEqual(out["rc"], 0)

    def test_receipt_map_strips_untouched_placeholders(self):
        out = terminal_svc._receipt_map(_receipt())
        for field in terminal_svc._MUTATED_FIELDS:
            self.assertNotIn(field, out)
        for key, default in terminal_svc._RECEIPT_DEFAULTS.items():
            self.assertIn(key, out)

    def test_receipt_map_transport_shadow_still_reads_the_junk_sentinel(self):
        # The term10 contract must not weaken: a transport-field shadow key
        # (hash and text both ``rc``) still degrades to -255, never 0.
        class _EqBombKey(str):
            __hash__ = str.__hash__

            def __eq__(self, other):
                raise RuntimeError("leftover key eq bomb")

            def __ne__(self, other):
                raise RuntimeError("leftover key ne bomb")

        out = terminal_svc._receipt_map({_EqBombKey("rc"): 0, "stdout": "kept"})
        self.assertEqual(out["rc"], -255)
        self.assertEqual(out["stdout"], "kept")

    def test_spawn_receipt_passes_coded_errors_and_degrades_raises(self):
        from fastapi import HTTPException

        with mock.patch.object(
            terminal_svc, "_run",
            mock.Mock(side_effect=api_error("terminal.timeout", seconds=5)),
        ):
            with self.assertRaises(HTTPException) as ctx:
                terminal_svc._spawn_receipt(["sh"], 5)
            self.assertEqual(ctx.exception.status_code, 504)
        with mock.patch.object(
            terminal_svc, "_run", mock.Mock(side_effect=RuntimeError("bomb"))
        ):
            out = terminal_svc._spawn_receipt(["sh"], 5)
        self.assertEqual(out["rc"], -255)
        self.assertEqual(out["stderr"], "")
        self.assertIs(type(out), dict)

    def test_engine_confirmed_down_requires_an_honest_answer(self):
        cases = [
            (lambda force=False: False, True),
            (lambda force=False: True, False),
            (lambda force=False: _BoolBomb(), False),
        ]
        for probe, expected in cases:
            with mock.patch.object(terminal_svc, "engine_up", probe):
                self.assertIs(terminal_svc._engine_confirmed_down(), expected)

        def _raise(force=False):
            raise RuntimeError("leftover probe bomb")

        with mock.patch.object(terminal_svc, "engine_up", _raise):
            self.assertIs(terminal_svc._engine_confirmed_down(), False)

    def test_looks_engine_down_guard_truth_table(self):
        with mock.patch.object(
            terminal_svc, "looks_engine_down", lambda text: True
        ):
            self.assertIs(terminal_svc._looks_engine_down("x"), True)
        with mock.patch.object(
            terminal_svc, "looks_engine_down", lambda text: _BoolBomb()
        ):
            self.assertIs(terminal_svc._looks_engine_down("x"), False)

        def _raise(text):
            raise RuntimeError("leftover classifier bomb")

        with mock.patch.object(terminal_svc, "looks_engine_down", _raise):
            self.assertIs(terminal_svc._looks_engine_down("x"), False)


if __name__ == "__main__":
    unittest.main()
