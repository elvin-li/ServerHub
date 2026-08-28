"""Twelfth leftover-500s sweep of the Ollama grain: the launchd-listing seam
and the watchdog-runner answer shapes, over the real mounted app.

ollama11 sealed hash-shadowing mapping *keys* in the pull row and the settings
block.  Two seams were still trusted raw, and both were confirmed live at
HEAD:

* the cached launchd listing consumed by ``_service_state`` /
  ``discover_label``.  The try only covered the ``listing()`` *call*; the
  reads were bare.  A junk cached object whose ``__bool__`` bombs, whose
  ``loaded`` / ``running`` are raising properties, or whose ``pid_for``
  raises — and a leftover str-subclass *element* inside a real frozenset
  whose ``__eq__`` bombs on the membership probe (the health12/dash12
  shadow-element class), a junk pid answer (str-subclass ``__bool__`` bomb,
  int-subclass ``__eq__`` bomb blowing ``_safe_int``'s own ``in`` probe),
  and a non-set view — each took GET /api/ollama/status to the coded 500
  ``ollama.status_failed``.
* the ``run_watchdog`` answer seam in ``delete_model``.  ``rc != 0``
  dispatches into the answer's own ``__ne__``, so a junk rc shape 500'd
  POST /api/ollama/models/delete raw; a leftover *raising* runner did the
  same (and in the pull thread silently skipped the ``rc`` verdict); and
  ``"\\n".join(log)`` TypeError'd on junk runner log lines — on the
  *success* return too.

Fixes, keeping the conventions: ``_label_set`` (exact-str laundering, the
``_pull_log_lines`` unbound-iteration rule) + ``_listing_attr`` +
``_listing_pid`` on the listing seam; ``_run_cli`` + ``_exact_rc`` (unbound
``int.__index__`` base coercion, could-not-run -1 sentinel) on the runner
seam, with the delete tail joined through ``_pull_log_lines`` /
``_utf8_text``.  Junk degrades to the empty/default shape or the coded
``rm_failed`` / ``not_installed`` answers; genuine values — a real label
wrapped in a bomb subclass, a genuine rc carried by a subclass, a real pid —
survive exactly (do-not-weaken).  No product-version bump: 3.9.3 stays.
"""
from __future__ import annotations

import json
import time
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


class _BoolBombListing:
    """Junk cached listing whose truth test detonates."""

    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")


class _RaisingAttrListing:
    """Junk cached listing: every view read raises."""

    @property
    def loaded(self):
        raise RuntimeError("leftover loaded bomb")

    @property
    def running(self):
        raise RuntimeError("leftover running bomb")

    def pid_for(self, label):
        raise RuntimeError("leftover pid_for bomb")


class _ShadowLabel(str):
    """Same text and hash as a real label; the membership probe detonates."""

    def __eq__(self, other):
        raise RuntimeError("leftover __eq__ bomb")

    def __ne__(self, other):
        raise RuntimeError("leftover __ne__ bomb")

    def __hash__(self):
        return hash(str(self))


class _BoolBombStr(str):
    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")

    def __len__(self):
        raise RuntimeError("leftover __len__ bomb")


class _EqBombInt(int):
    def __eq__(self, other):
        raise RuntimeError("leftover __eq__ bomb")

    def __ne__(self, other):
        raise RuntimeError("leftover __ne__ bomb")

    def __hash__(self):
        return int.__hash__(self)


class _StrBombInt(int):
    def __str__(self):
        raise RuntimeError("leftover __str__ bomb")

    def __index__(self):
        raise RuntimeError("leftover __index__ bomb")


class _FakeListing:
    """Listing-shaped stand-in with injectable views and pid answers."""

    def __init__(self, loaded=frozenset(), running=frozenset(), pids=None):
        self.loaded = loaded
        self.running = running
        self._pids = pids or {}

    def pid_for(self, label):
        return self._pids.get(str(label))


class StatusListingSeamTests(unittest.TestCase):
    """The ex-coded-500s on GET /api/ollama/status from the listing seam."""

    def setUp(self):
        super().setUp()
        self.client = _client()
        self.addCleanup(ollama_svc.status.invalidate)
        ollama_svc.status.invalidate()

    def _status_200(self, listing_value, labels=None) -> dict:
        ollama_svc.status.invalidate()
        patches = [
            mock.patch.object(ollama_svc, "cfg", lambda: {"settings": {}}),
            mock.patch.object(ollama_svc, "binary_path", return_value=None),
            mock.patch.object(
                ollama_svc, "_ollama_open",
                side_effect=ConnectionRefusedError(111, "refused")),
            mock.patch("hub.launchd_cache.listing",
                       lambda force=False: listing_value),
        ]
        if labels is not None:
            patches.append(mock.patch.object(
                ollama_svc, "_candidate_labels", return_value=labels))
        from contextlib import ExitStack
        with ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            resp = self.client.get("/api/ollama/status", params={"force": "true"})
        ollama_svc.status.invalidate()
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        resp.text.encode("utf-8")
        return json.loads(resp.text)

    def test_bool_bomb_listing_answers_200_with_the_empty_service_shape(self):
        status = self._status_200(_BoolBombListing())
        service = status["service"]
        self.assertIsNone(service["label"])
        self.assertIs(service["running"], False)

    def test_raising_view_properties_answer_200(self):
        status = self._status_200(_RaisingAttrListing(), labels=["com.me.ollama"])
        service = status["service"]
        # The candidate scan still names the on-disk agent; the junk views
        # simply read as "nothing loaded".
        self.assertEqual(service["label"], "com.me.ollama")
        self.assertIs(service["loaded"], False)
        self.assertIsNone(service["pid"])

    def test_shadow_element_in_the_views_keeps_its_real_text(self):
        # Do-not-weaken: the bomb wrapper drops, the label text survives, so
        # the running rank still beats the alphabetical tie-break.
        shadow = _ShadowLabel("com.me.ollama")
        status = self._status_200(
            _FakeListing(loaded=frozenset([shadow]), running=frozenset([shadow])),
            labels=["aaa.ollama", "com.me.ollama"],
        )
        service = status["service"]
        self.assertEqual(service["label"], "com.me.ollama")
        self.assertIs(service["loaded"], True)

    def test_pid_bool_bomb_str_subclass_keeps_the_real_pid(self):
        status = self._status_200(
            _FakeListing(
                loaded=frozenset(["com.me.ollama"]),
                running=frozenset(["com.me.ollama"]),
                pids={"com.me.ollama": _BoolBombStr("123")},
            ),
            labels=["com.me.ollama"],
        )
        service = status["service"]
        self.assertEqual(service["pid"], 123)
        self.assertIs(service["running"], True)

    def test_pid_eq_bomb_int_subclass_keeps_the_real_pid(self):
        # The ex-detonation inside _safe_int's own ``raw in (None, "")``.
        status = self._status_200(
            _FakeListing(
                loaded=frozenset(["com.me.ollama"]),
                pids={"com.me.ollama": _EqBombInt(42)},
            ),
            labels=["com.me.ollama"],
        )
        self.assertEqual(status["service"]["pid"], 42)

    def test_str_bomb_int_subclass_pid_keeps_the_real_pid(self):
        # Do-not-weaken: the unbound base coercion reads the real value
        # underneath the ``__index__``/``__str__`` overrides.
        status = self._status_200(
            _FakeListing(
                loaded=frozenset(["com.me.ollama"]),
                pids={"com.me.ollama": _StrBombInt(7)},
            ),
            labels=["com.me.ollama"],
        )
        self.assertEqual(status["service"]["pid"], 7)

    def test_overcap_and_nondigit_pids_read_as_not_running(self):
        for junk in ("9" * 5000, "abc"):
            status = self._status_200(
                _FakeListing(
                    loaded=frozenset(["com.me.ollama"]),
                    pids={"com.me.ollama": junk},
                ),
                labels=["com.me.ollama"],
            )
            service = status["service"]
            self.assertIsNone(service["pid"])
            self.assertIs(service["running"], False)

    def test_non_set_views_answer_200(self):
        status = self._status_200(
            _FakeListing(loaded=None, running="junk"), labels=["com.me.ollama"])
        self.assertEqual(status["service"]["label"], "com.me.ollama")

    def test_healthy_listing_still_answers_exactly(self):
        # Do-not-weaken: the laundered seam keeps every genuine answer.
        status = self._status_200(
            _FakeListing(
                loaded=frozenset(["aaa.ollama", "com.me.ollama"]),
                running=frozenset(["com.me.ollama"]),
                pids={"com.me.ollama": "123"},
            ),
            labels=["aaa.ollama", "com.me.ollama"],
        )
        service = status["service"]
        self.assertEqual(service["label"], "com.me.ollama")
        self.assertIs(service["loaded"], True)
        self.assertIs(service["running"], True)
        self.assertEqual(service["pid"], 123)


class DeleteRunnerSeamTests(unittest.TestCase):
    """The ex-raw-500s on POST /api/ollama/models/delete at the runner seam."""

    def setUp(self):
        super().setUp()
        self.client = _client()
        self.addCleanup(ollama_svc.status.invalidate)
        ollama_svc.status.invalidate()

    def _delete(self, runner, binary="/usr/local/bin/ollama"):
        binary_mock = (
            mock.patch.object(ollama_svc, "binary_path", side_effect=binary)
            if isinstance(binary, list)
            else mock.patch.object(ollama_svc, "binary_path", return_value=binary)
        )
        runner_mock = (
            mock.patch.object(ollama_svc, "run_watchdog", side_effect=runner)
            if callable(runner) or isinstance(runner, Exception)
            else mock.patch.object(ollama_svc, "run_watchdog", return_value=runner)
        )
        with (
            mock.patch.object(ollama_svc, "cfg", lambda: {"settings": {}}),
            binary_mock,
            runner_mock,
        ):
            return self.client.post(
                "/api/ollama/models/delete",
                json={"model": "m1", "confirm": True})

    def test_eq_bomb_rc_zero_still_answers_the_real_success(self):
        # Do-not-weaken: the genuine exit code rides through the base
        # coercion; the bomb comparisons never run.
        resp = self._delete(_EqBombInt(0))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(json.loads(resp.text)["model"], "m1")

    def test_eq_bomb_rc_nonzero_keeps_the_coded_rm_failed(self):
        resp = self._delete(_EqBombInt(7))
        self.assertEqual(resp.status_code, 500, resp.text[:300])
        detail = json.loads(resp.text)["detail"]
        self.assertEqual(detail["code"], "ollama.rm_failed")
        self.assertIn("exit 7", detail["message"])

    def test_raising_runner_keeps_the_coded_rm_failed(self):
        resp = self._delete(RecursionError("leftover"))
        self.assertEqual(resp.status_code, 500, resp.text[:300])
        detail = json.loads(resp.text)["detail"]
        self.assertEqual(detail["code"], "ollama.rm_failed")
        self.assertIn("!! error", detail["message"])

    def test_raising_runner_with_a_vanished_cli_is_the_honest_503(self):
        # Gate sees the binary, the failure-path re-probe confirms it gone.
        def raising(argv, *, timeout, log, env=None, cwd=None):
            raise RecursionError("leftover")

        resp = self._delete(raising, binary=["/usr/local/bin/ollama", None])
        self.assertEqual(resp.status_code, 503, resp.text[:300])
        self.assertEqual(
            json.loads(resp.text)["detail"]["code"], "ollama.not_installed")

    def test_junk_log_lines_cannot_500_the_success_return(self):
        def junk_log(argv, *, timeout, log, env=None, cwd=None):
            log.extend([b"line-bytes", None, 5, "kept"])
            return 0

        resp = self._delete(junk_log)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        message = json.loads(resp.text)["message"]
        self.assertIn("line-bytes", message)
        self.assertIn("kept", message)

    def test_junk_log_lines_keep_the_coded_rm_failed(self):
        def junk_log(argv, *, timeout, log, env=None, cwd=None):
            log.extend([b"boom", None])
            return 2

        resp = self._delete(junk_log)
        self.assertEqual(resp.status_code, 500, resp.text[:300])
        detail = json.loads(resp.text)["detail"]
        self.assertEqual(detail["code"], "ollama.rm_failed")
        self.assertIn("boom", detail["message"])

    def test_surrogate_log_line_stays_utf8_renderable(self):
        def surrogate_log(argv, *, timeout, log, env=None, cwd=None):
            log.append("bad\ud800line")
            return 0

        resp = self._delete(surrogate_log)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        resp.text.encode("utf-8")
        self.assertIn("bad", json.loads(resp.text)["message"])

    def test_unanswerable_rc_shapes_read_as_the_sentinel(self):
        for junk in (float("inf"), None, "junk", 10 ** 5000):
            resp = self._delete(junk)
            self.assertEqual(resp.status_code, 500, resp.text[:300])
            detail = json.loads(resp.text)["detail"]
            self.assertEqual(detail["code"], "ollama.rm_failed")
            self.assertIn("exit -1", detail["message"])

    def test_str_bomb_rc_subclass_keeps_its_real_code(self):
        # Do-not-weaken: the unbound base coercion reads the genuine exit
        # code underneath the ``__index__``/``__str__`` overrides.
        resp = self._delete(_StrBombInt(3))
        self.assertEqual(resp.status_code, 500, resp.text[:300])
        detail = json.loads(resp.text)["detail"]
        self.assertEqual(detail["code"], "ollama.rm_failed")
        self.assertIn("exit 3", detail["message"])


class PullRunnerSeamTests(unittest.TestCase):
    """The silent-loss shape in the pull thread: a raising runner now lands
    the -1 verdict instead of leaving rc=None with no explanation."""

    def setUp(self):
        super().setUp()
        self.client = _client()
        saved = {k: (list(v) if isinstance(v, list) else v)
                 for k, v in ollama_svc._pull.items()}

        def restore():
            ollama_svc._pull.clear()
            ollama_svc._pull.update(saved)

        self.addCleanup(restore)
        self.addCleanup(ollama_svc.status.invalidate)
        ollama_svc.status.invalidate()

    def _pull_until_done(self, runner):
        with (
            mock.patch.object(ollama_svc, "cfg", lambda: {"settings": {}}),
            mock.patch.object(
                ollama_svc, "binary_path", return_value="/usr/local/bin/ollama"),
            mock.patch.object(ollama_svc, "run_watchdog", side_effect=runner),
        ):
            resp = self.client.post("/api/ollama/pull", json={"model": "m1"})
            self.assertEqual(resp.status_code, 200, resp.text[:300])
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if not ollama_svc._row_get("running"):
                    break
                time.sleep(0.02)
        self.assertFalse(ollama_svc._row_get("running"))

    def test_raising_runner_finishes_with_the_sentinel_verdict(self):
        def raising(argv, *, timeout, log, env=None, cwd=None):
            raise RecursionError("leftover")

        self._pull_until_done(raising)
        resp = self.client.get("/api/ollama/pull/log")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(resp.text)
        self.assertEqual(payload["rc"], -1)
        self.assertIn("!! error", payload["log"])

    def test_junk_rc_answer_lands_laundered_in_the_row(self):
        def junk_rc(argv, *, timeout, log, env=None, cwd=None):
            log.append("pulled")
            return _EqBombInt(0)

        self._pull_until_done(junk_rc)
        resp = self.client.get("/api/ollama/pull/log")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(resp.text)
        self.assertEqual(payload["rc"], 0)
        self.assertIs(type(ollama_svc._row_get("rc")), int)
        self.assertIn("pulled", payload["log"])


class SanitizerUnitPins(unittest.TestCase):
    """The new helpers themselves at the ollama12 shapes."""

    def test_label_set_drops_junk_and_keeps_real_text(self):
        shadow = _ShadowLabel("com.me.ollama")
        out = ollama_svc._label_set(frozenset([shadow, "other", b"raw", 5]))
        self.assertEqual(out, frozenset({"com.me.ollama", "other", "raw"}))
        for item in out:
            self.assertIs(type(item), str)
        self.assertEqual(ollama_svc._label_set(None), frozenset())
        self.assertEqual(ollama_svc._label_set("junk"), frozenset())

    def test_label_set_survives_a_subclass_iter_bomb(self):
        class _IterBombSet(frozenset):
            def __iter__(self):
                raise RuntimeError("leftover __iter__ bomb")

        # The unbound base iteration reads the real storage underneath.
        out = ollama_svc._label_set(_IterBombSet({"com.me.ollama"}))
        self.assertEqual(out, frozenset({"com.me.ollama"}))

    def test_listing_pid_shapes(self):
        jobs = _FakeListing(pids={"a": "123", "b": "abc", "c": "9" * 5000,
                                  "d": _EqBombInt(42), "e": True})
        self.assertEqual(ollama_svc._listing_pid(jobs, "a"), 123)
        self.assertIsNone(ollama_svc._listing_pid(jobs, "b"))
        self.assertIsNone(ollama_svc._listing_pid(jobs, "c"))
        self.assertEqual(ollama_svc._listing_pid(jobs, "d"), 42)
        self.assertIsNone(ollama_svc._listing_pid(jobs, "e"))
        self.assertIsNone(ollama_svc._listing_pid(None, "a"))
        self.assertIsNone(ollama_svc._listing_pid(_RaisingAttrListing(), "a"))

    def test_exact_rc_shapes(self):
        self.assertEqual(ollama_svc._exact_rc(0), 0)
        self.assertEqual(ollama_svc._exact_rc(124), 124)
        self.assertEqual(ollama_svc._exact_rc(_EqBombInt(7)), 7)
        # The unbound base coercion keeps the real value underneath the
        # ``__index__``/``__str__`` overrides (do-not-weaken).
        self.assertEqual(ollama_svc._exact_rc(_StrBombInt(3)), 3)
        self.assertEqual(ollama_svc._exact_rc(10 ** 5000), -1)
        self.assertEqual(ollama_svc._exact_rc(float("inf")), -1)
        self.assertEqual(ollama_svc._exact_rc(None), -1)
        self.assertEqual(ollama_svc._exact_rc("junk"), -1)
        self.assertEqual(ollama_svc._exact_rc(True), 1)
        for value in (0, 124, ollama_svc._exact_rc(_EqBombInt(7))):
            self.assertIs(type(ollama_svc._exact_rc(value)), int)


if __name__ == "__main__":
    unittest.main()
