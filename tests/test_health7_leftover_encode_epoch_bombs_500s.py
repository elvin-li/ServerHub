"""Seventh leftover-500s sweep of the Health / SMART surfaces, over the real app.

health6 sealed the bound int-``__str__`` / float-``__eq__`` / bytes-``decode``
/ dict-``items`` bombs.  Re-running the zoo with the *encode-side* and
*epoch-side* members surfaced live leftovers:

* ``health_svc._utf8_text`` / ``_as_text`` (and the smart/worker twins) ended
  with the bound ``text.encode(...)`` — ``str(x)`` of a subclass whose
  ``__str__`` answers *self* skips CPython's exact-str copy, so a str-subclass
  ``encode`` bomb planted in the cache snapshot 500'd GET /api/health/checks
  on every TTL hit, and the same bomb in a history row 500'd GET
  /api/smart/history.
* ``health_svc._fresh_snapshot`` caught only the arithmetic trio around
  ``time.time() - _cache["t"]`` — a numeric-subclass ``__rsub__`` bomb
  planted in the timestamp 500'd every GET /api/health/checks.
* ``smart_test_svc._schedule_epoch`` ran ``float(raw or 0)`` on the stored
  ``last_run`` — an int/float subclass whose ``__bool__``/``__float__``
  raises 500'd GET /api/smart through ``get_schedule()``, and the same raise
  escaped ``schedule_due()`` inside the scheduler tick, silently stopping
  every scheduled self-test.
* ``smart_test_svc._schedule_text`` used the bound ``.decode``/``.encode`` —
  a bytes/str-subclass bomb stored as ``interval``/``kind`` 500'd
  GET /api/smart.
* ``get_schedule()`` / ``set_schedule()`` iterated ``devices`` with the
  subclass's own ``__iter__`` (and ``devices or []`` with its ``__bool__``) —
  a list-subclass bomb 500'd GET /api/smart and PUT /api/smart/schedule for
  in-process callers.
* ``history(limit)`` ran ``int(limit or 100)`` — an int-subclass
  ``__bool__``/``__int__`` bomb raised out of GET /api/smart/history's
  service for in-process callers.
"""
from __future__ import annotations

import time
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import health_svc, smart_test_svc, worker_health
from hub.app_factory import create_app
from hub.auth import require_auth

_app = None


def _the_app():
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return _app


def _client() -> TestClient:
    # raise_server_exceptions=False: a real 500 must arrive as HTTP 500, not
    # as a re-raised exception that would mask which route crashed.
    return TestClient(_the_app(), raise_server_exceptions=False)


class _SelfStrEncodeBomb(str):
    """``str()`` answers *self* — the exact-str copy is skipped — so the
    bound ``encode`` override stays live into the surrogate scrub."""

    def __str__(self):
        return self

    def encode(self, *args, **kwargs):
        raise RuntimeError("encode bomb")


class _BoolBombInt(int):
    def __bool__(self):
        raise RuntimeError("bool bomb")


class _FloatBombInt(int):
    def __float__(self):
        raise RuntimeError("float bomb")


class _IterBombList(list):
    def __iter__(self):
        raise RuntimeError("iter bomb")


class _RSubBombFloat(float):
    def __rsub__(self, other):
        raise RuntimeError("rsub bomb")

    def __sub__(self, other):
        raise RuntimeError("sub bomb")


_CLEAN_SNAPSHOT = {
    "ts": "now",
    "summary": {"ok": 1, "warn": 0, "error": 0, "total": 1},
    "checks": [{"id": "x", "name": "X", "level": "ok", "ok": True,
                "detail": "", "fix": ""}],
    "healthy": True,
}


class _HealthCacheSandbox(unittest.TestCase):
    """Save/restore the module cache so poisonings cannot leak between tests."""

    def setUp(self):
        saved = dict(health_svc._cache)
        self.addCleanup(lambda: health_svc._cache.update(saved))
        health_svc._cache.update(t=0.0, v=None)


class HealthEncodeBombTests(_HealthCacheSandbox):
    """str-subclass encode bombs planted in the cached snapshot: 200, never 500."""

    def _hit_with(self, junk):
        bad = dict(_CLEAN_SNAPSHOT)
        bad["junk"] = junk
        health_svc._cache.update(t=time.time(), v=bad)
        return _client().get("/api/health/checks")

    def test_encode_bomb_value_is_salvaged_not_500(self):
        response = self._hit_with(_SelfStrEncodeBomb("x"))
        self.assertEqual(response.status_code, 200, response.text[:300])
        payload = response.json()
        # str.encode unbound: the real text survives the subclass bomb.
        self.assertEqual(payload["junk"], "x")
        self.assertEqual(payload["ts"], "now")

    def test_encode_bomb_key_is_salvaged_not_500(self):
        response = self._hit_with({_SelfStrEncodeBomb("k"): 1})
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["junk"], {"k": 1})

    def test_encode_bomb_surrogate_is_laundered(self):
        # The scrub still launders: a lone surrogate riding the bomb class
        # must come out replaced, not raise out of Starlette's encoder.
        response = self._hit_with(_SelfStrEncodeBomb("a\ud800b"))
        self.assertEqual(response.status_code, 200, response.text[:300])
        # encode-side ``replace`` substitutes ``?`` for the lone surrogate.
        self.assertEqual(response.json()["junk"], "a?b")

    def test_cache_timestamp_arith_bomb_is_treated_expired_not_500(self):
        # A numeric-subclass __rsub__ bomb planted in _cache["t"] raised
        # RuntimeError past the old arithmetic-trio except on every request.
        health_svc._cache.update(t=_RSubBombFloat(1.0), v=dict(_CLEAN_SNAPSHOT))
        with mock.patch.object(
            health_svc, "_collect_checks", return_value=dict(_CLEAN_SNAPSHOT)
        ):
            response = _client().get("/api/health/checks")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["ts"], "now")

    def test_text_helpers_direct_semantics(self):
        self.assertEqual(health_svc._utf8_text(_SelfStrEncodeBomb("x")), "x")
        self.assertEqual(health_svc._as_text(_SelfStrEncodeBomb("x")), "x")
        self.assertEqual(health_svc._jsonable(_SelfStrEncodeBomb("x")), "x")
        self.assertEqual(smart_test_svc._jsonable(_SelfStrEncodeBomb("x")), "x")
        self.assertEqual(worker_health._utf8_text(_SelfStrEncodeBomb("x")), "x")


class WorkerNameEncodeBombTests(_HealthCacheSandbox):
    """A worker registered under a bomb name must still render everywhere."""

    def test_snapshot_and_health_survive_the_bomb_name(self):
        name = _SelfStrEncodeBomb("w-bomb")
        worker_health.register(name, 60)
        self.addCleanup(worker_health.unregister, name)
        rows = worker_health.snapshot()
        self.assertIn("w-bomb", [w["name"] for w in rows])
        response = _client().get("/api/health/checks")
        self.assertEqual(response.status_code, 200, response.text[:300])
        checks = {c["id"]: c for c in response.json()["checks"]
                  if isinstance(c, dict) and "id" in c}
        self.assertIn("workers", checks)


class SmartScheduleEpochBombTests(unittest.TestCase):
    """last_run / interval / devices bombs in the stored schedule: salvage, never 500."""

    def setUp(self):
        self.addCleanup(smart_test_svc.invalidate)
        smart_test_svc.invalidate()

    def _overview_with(self, block):
        with (
            mock.patch.object(
                smart_test_svc, "cfg",
                return_value={"settings": {"smart_schedule": block}}),
            mock.patch.object(smart_test_svc, "sh", return_value=(1, "", "")),
        ):
            smart_test_svc.invalidate()
            return _client().get("/api/smart")

    def test_last_run_bool_bomb_int_is_salvaged_not_500(self):
        response = self._overview_with(
            {"interval": "daily", "last_run": _BoolBombInt(7)})
        self.assertEqual(response.status_code, 200, response.text[:300])
        # int.__index__ coercion: the real epoch survives, only the bomb dies.
        self.assertEqual(response.json()["schedule"]["last_run"], 7.0)

    def test_last_run_float_bomb_int_is_salvaged_not_500(self):
        response = self._overview_with(
            {"interval": "daily", "last_run": _FloatBombInt(7)})
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["schedule"]["last_run"], 7.0)

    def test_interval_encode_bomb_str_is_salvaged_not_500(self):
        response = self._overview_with(
            {"interval": _SelfStrEncodeBomb("daily")})
        self.assertEqual(response.status_code, 200, response.text[:300])
        # str.encode unbound: the real interval survives the subclass bomb.
        self.assertEqual(response.json()["schedule"]["interval"], "daily")

    def test_devices_iter_bomb_list_salvages_the_entries_not_500(self):
        response = self._overview_with(
            {"interval": "daily",
             "devices": _IterBombList(["/dev/disk0", "junk"])})
        self.assertEqual(response.status_code, 200, response.text[:300])
        # list.__iter__ unbound: the real nodes still walk, junk still drops.
        self.assertEqual(
            response.json()["schedule"]["devices"], ["/dev/disk0"])

    def test_schedule_due_survives_the_bombs(self):
        # The same raises used to escape the scheduler tick and silently
        # stop every scheduled self-test.
        for block in (
            {"interval": "daily", "last_run": _BoolBombInt(1),
             "devices": ["/dev/disk0"]},
            {"interval": "daily", "last_run": _FloatBombInt(1),
             "devices": ["/dev/disk0"]},
            {"interval": _SelfStrEncodeBomb("daily"),
             "devices": _IterBombList(["/dev/disk0"])},
        ):
            with mock.patch.object(
                smart_test_svc, "cfg",
                return_value={"settings": {"smart_schedule": block}},
            ):
                self.assertIsInstance(smart_test_svc.schedule_due(), bool)


class SmartHistoryAndSetScheduleBombTests(unittest.TestCase):
    """In-process bomb arguments and poisoned rows: coded answers, never raises."""

    def setUp(self):
        self.addCleanup(smart_test_svc.invalidate)
        smart_test_svc.invalidate()

    def test_encode_bomb_history_row_is_http_200(self):
        with mock.patch.object(
            smart_test_svc, "_load_history",
            return_value=[{"ts": 1, "s": _SelfStrEncodeBomb("x")}],
        ):
            response = _client().get("/api/smart/history")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["history"], [{"ts": 1, "s": "x"}])

    def test_history_limit_bool_bomb_int_is_salvaged(self):
        with mock.patch.object(
            smart_test_svc, "_load_history",
            return_value=[{"ts": i} for i in range(10)],
        ):
            rows = smart_test_svc.history(_BoolBombInt(3))
        # int.__index__ coercion: the real limit survives the bomb.
        self.assertEqual([r["ts"] for r in rows], [9, 8, 7])

    def test_set_schedule_iter_bomb_devices_is_the_coded_answer(self):
        with (
            mock.patch.object(
                smart_test_svc, "_device_nodes", return_value=["/dev/disk0"]),
            mock.patch.object(smart_test_svc, "update_settings") as saved,
        ):
            result = smart_test_svc.set_schedule(
                interval="daily", kind="short",
                devices=_IterBombList(["/dev/disk0", "junk"]),
            )
        self.assertTrue(result["ok"])
        # list.__iter__ unbound: the real node survives, junk still drops.
        self.assertEqual(
            saved.call_args[0][0]["smart_schedule"]["devices"], ["/dev/disk0"])


if __name__ == "__main__":
    unittest.main()
