"""Sixth leftover-500s sweep of the Health / SMART surfaces, over the real app.

The nested-unbound-jsonable zoo (the modules5 classes: a dict subclass
whose ``items()`` answers but yields non-pairs, an int subclass whose
``__str__`` raises, a float subclass whose ``__eq__`` raises, a bytes
subclass whose ``.decode`` raises, an object whose ``isoformat``
*property* raises) plus dict-subclass ``.get``/``__bool__`` bombs and
unhashable set membership were re-reproduced against GET
/api/health/checks and the SMART routes.  Live leftovers surfaced:

* ``health_svc._jsonable`` / ``smart_test_svc._jsonable`` probed ints with
  a bound ``str(value)`` catching only ValueError — an int subclass
  ``__str__`` bomb 500'd every TTL hit of GET /api/health/checks, and on
  the cold path one such value cost the *entire* ``checks`` list through
  the sequence-rank guard.  The float path called the subclass ``__eq__``,
  bytes used the bound ``.decode``, the dict path unpacked ``items()``
  results *outside* its try, and the ``isoformat`` probe used a bare
  ``getattr`` — each a 500 through ``_serve_cached`` and
  ``abort_test``/``history``.
* ``smart_test_svc.start_test`` read the run_admin result with bound
  ``admin.get`` and ``(admin or {})`` — a dict-subclass ``.get``/
  ``__bool__`` bomb 500'd POST /api/smart/test after the operator had
  already typed the admin password.
* ``smart_test_svc._schedule_cfg`` isinstance-gated the stored
  ``smart_schedule`` block but then handed the *subclass object* to
  ``get_schedule()``'s bound ``.get`` — a non-empty ``.get``/``__bool__``
  bomb 500'd GET /api/smart, and the same raise escaped ``schedule_due()``
  inside the scheduler tick, silently stopping every scheduled self-test.
* ``start_test``/``abort_test``/``set_schedule`` built the known-device
  set with a bare ``set(_device_nodes())`` — one unhashable entry in the
  listing TypeError'd POST /api/smart/test where every junk *device
  argument* already earns the coded ``bad_device`` refusal.
"""
from __future__ import annotations

import time
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import health_svc, smart_test_svc
from hub.app_factory import create_app
from hub.auth import require_auth
from hub.routers import nas_storage

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


class _StrBombInt(int):
    """The digit-cap probe's blind spot: ``str()`` raising non-ValueError."""

    def __str__(self):
        raise RuntimeError("str bomb")


class _EqBombFloat(float):
    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    __ne__ = __eq__
    __hash__ = float.__hash__


class _DecodeBombBytes(bytes):
    def decode(self, *args, **kwargs):
        raise RuntimeError("decode bomb")


class _NonPairItemsDict(dict):
    """``items()`` answers — past the old guard — but yields non-pairs."""

    def items(self):
        return [1, 2]


class _GetBombDict(dict):
    def get(self, *args, **kwargs):
        raise RuntimeError("get bomb")


class _BoolBombDict(dict):
    def __bool__(self):
        raise RuntimeError("bool bomb")


class _IsoformatPropertyBomb:
    @property
    def isoformat(self):
        raise RuntimeError("getattr bomb")


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

    def _hit_with(self, junk):
        bad = dict(_CLEAN_SNAPSHOT)
        bad["junk"] = junk
        health_svc._cache.update(t=time.time(), v=bad)
        return _client().get("/api/health/checks")


class HealthTtlHitNestedSubclassBombTests(_HealthCacheSandbox):
    """The modules5 zoo planted in the cached snapshot: 200, never 500."""

    def test_int_str_bomb_is_salvaged_not_500(self):
        response = self._hit_with(_StrBombInt(5))
        self.assertEqual(response.status_code, 200, response.text[:300])
        payload = response.json()
        # int.__index__ coercion: the *number* survives, only the bomb dies.
        self.assertEqual(payload["junk"], 5)
        self.assertEqual(payload["ts"], "now")

    def test_float_eq_bomb_is_salvaged_not_500(self):
        response = self._hit_with(_EqBombFloat(1.5))
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["junk"], 1.5)

    def test_bytes_decode_bomb_value_is_salvaged_not_500(self):
        response = self._hit_with(_DecodeBombBytes(b"x"))
        self.assertEqual(response.status_code, 200, response.text[:300])
        # bytes.decode unbound: the content survives the subclass bomb.
        self.assertEqual(response.json()["junk"], "x")

    def test_bytes_decode_bomb_key_is_salvaged_not_500(self):
        response = self._hit_with({_DecodeBombBytes(b"k"): 1})
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["junk"], {"k": 1})

    def test_non_pair_items_dict_drops_alone_not_500(self):
        response = self._hit_with(_NonPairItemsDict())
        self.assertEqual(response.status_code, 200, response.text[:300])
        payload = response.json()
        # Same drop as the items bomb the guard already absorbed: the
        # unreadable mapping dies alone, its siblings survive.
        self.assertIsNone(payload["junk"])
        self.assertEqual(payload["ts"], "now")

    def test_isoformat_property_bomb_is_http_200(self):
        response = self._hit_with(_IsoformatPropertyBomb())
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["ts"], "now")

    def test_jsonable_direct_semantics(self):
        # The salvage rules, pinned at the function level as well.
        self.assertEqual(health_svc._jsonable(_StrBombInt(7)), 7)
        self.assertEqual(health_svc._jsonable(_EqBombFloat(2.5)), 2.5)
        self.assertEqual(health_svc._jsonable(_DecodeBombBytes(b"ok")), "ok")
        self.assertIsNone(health_svc._jsonable(_NonPairItemsDict()))
        self.assertEqual(
            smart_test_svc._jsonable({"a": _StrBombInt(3), "b": "x"}),
            {"a": 3, "b": "x"},
        )
        self.assertIsNone(smart_test_svc._jsonable(_NonPairItemsDict()))


class HealthColdCollectionBombRowTests(_HealthCacheSandbox):
    """One poisoned provider row must never cost the whole checks payload."""

    def test_immich_int_str_bomb_row_keeps_the_checks_list(self):
        # Pre-fix the final _jsonable pass raised inside the sequence guard
        # and the *entire* checks list dropped to null — the page rendered
        # empty because one Immich row carried a hostile number.
        with (
            mock.patch.object(health_svc, "sh", return_value=(1, "", "")),
            mock.patch("hub.immich_svc.run_checks", return_value={"checks": [
                {"id": "im", "ok": True, "level": "ok", "n": _StrBombInt(5)},
            ]}),
        ):
            response = _client().get("/api/health/checks")
        self.assertEqual(response.status_code, 200, response.text[:300])
        checks = response.json()["checks"]
        self.assertIsInstance(checks, list)
        rows = {c["id"]: c for c in checks if isinstance(c, dict) and "id" in c}
        self.assertIn("disk_root", rows)
        self.assertIn("im", rows)
        self.assertEqual(rows["im"]["n"], 5)


class SmartAdminResultBombTests(unittest.TestCase):
    """run_admin results this module does not own: coded answers, never raw 500s."""

    def setUp(self):
        self.addCleanup(smart_test_svc.invalidate)
        smart_test_svc.invalidate()

    def _post(self, path, body, admin_result, capabilities=None):
        patches = [
            mock.patch.object(
                nas_storage, "require_admin_browser", return_value="admin"),
            mock.patch.object(
                smart_test_svc, "_device_nodes", return_value=["/dev/disk0"]),
            mock.patch.object(
                smart_test_svc, "sh", return_value=(1, "denied", "")),
            mock.patch.object(
                smart_test_svc, "run_admin", return_value=admin_result),
            mock.patch.object(
                smart_test_svc, "_smartctl_installed", return_value=True),
            mock.patch.object(smart_test_svc, "device_type", return_value=()),
        ]
        if capabilities is not None:
            patches.append(mock.patch.object(
                smart_test_svc, "_capabilities", return_value=capabilities))
        from contextlib import ExitStack

        with ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            return _client().post(path, json=body)

    _CAPS = {
        "readable": True, "available": True, "supported": ["short"],
        "reason": "", "device_type": "auto", "estimated_minutes": {},
        "detail": "",
    }

    def test_start_test_get_bomb_admin_result_is_http_200(self):
        response = self._post(
            "/api/smart/test", {"device": "/dev/disk0", "kind": "short"},
            _GetBombDict(ok=True), capabilities=self._CAPS,
        )
        self.assertEqual(response.status_code, 200, response.text[:300])
        # dict.get unbound: the real ok answer survives the subclass bomb.
        self.assertTrue(response.json()["ok"])

    def test_abort_int_str_bomb_result_is_http_200(self):
        response = self._post(
            "/api/smart/abort", {"device": "/dev/disk0"},
            {"ok": True, "n": _StrBombInt(5)},
        )
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["n"], 5)

    def test_abort_decode_bomb_result_is_http_200(self):
        response = self._post(
            "/api/smart/abort", {"device": "/dev/disk0"},
            {"ok": True, "b": _DecodeBombBytes(b"x")},
        )
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["b"], "x")

    def test_abort_non_pair_items_result_is_the_coded_failure(self):
        # Nothing salvageable from a mapping that lies about its pairs:
        # the coded admin.failed contract answers, never the raw crash page.
        response = self._post(
            "/api/smart/abort", {"device": "/dev/disk0"},
            _NonPairItemsDict(ok=True),
        )
        self.assertEqual(response.status_code, 500, response.text[:300])
        self.assertEqual(response.json()["detail"]["code"], "admin.failed")

    def test_unhashable_device_listing_is_the_coded_400(self):
        # The zoo's unhashable-set-membership entry: one junk row in the
        # device listing used to TypeError set() and 500 the route.
        with (
            mock.patch.object(
                nas_storage, "require_admin_browser", return_value="admin"),
            mock.patch.object(
                smart_test_svc, "_device_nodes",
                return_value=[["not-hashable"], {"nor": "this"}, "/dev/disk0"]),
            mock.patch.object(smart_test_svc, "sh", return_value=(1, "", "")),
        ):
            response = _client().post(
                "/api/smart/test", json={"device": "/dev/disk9", "kind": "short"})
        self.assertEqual(response.status_code, 400, response.text[:300])
        self.assertEqual(response.json()["detail"]["code"], "smart.bad_device")


class SmartScheduleSubclassBombTests(unittest.TestCase):
    """Dict-subclass bombs in the stored schedule block: salvage, never 500."""

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

    def test_get_bomb_schedule_block_is_http_200_and_salvaged(self):
        response = self._overview_with(_GetBombDict(interval="daily"))
        self.assertEqual(response.status_code, 200, response.text[:300])
        # The plain-dict copy salvages the real content past the bomb.
        self.assertEqual(response.json()["schedule"]["interval"], "daily")

    def test_bool_bomb_schedule_block_is_http_200_and_salvaged(self):
        response = self._overview_with(_BoolBombDict(interval="daily"))
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["schedule"]["interval"], "daily")

    def test_get_bomb_top_level_cfg_is_http_200(self):
        with (
            mock.patch.object(
                smart_test_svc, "cfg", return_value=_GetBombDict()),
            mock.patch.object(smart_test_svc, "sh", return_value=(1, "", "")),
        ):
            smart_test_svc.invalidate()
            response = _client().get("/api/smart")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["schedule"]["interval"], "off")

    def test_schedule_due_survives_the_bombs(self):
        # The same raise used to escape the scheduler tick and silently
        # stop every scheduled self-test.
        for block in (_GetBombDict(interval="daily"),
                      _BoolBombDict(interval="daily")):
            with mock.patch.object(
                smart_test_svc, "cfg",
                return_value={"settings": {"smart_schedule": block}},
            ):
                self.assertIsInstance(smart_test_svc.schedule_due(), bool)


class SmartHistoryRowBombTests(unittest.TestCase):
    """History rows this module does not own must render, never 500."""

    def setUp(self):
        self.addCleanup(smart_test_svc.invalidate)
        smart_test_svc.invalidate()

    def test_int_str_bomb_history_row_is_http_200(self):
        with mock.patch.object(
            smart_test_svc, "_load_history",
            return_value=[{"ts": 1, "n": _StrBombInt(5)}],
        ):
            response = _client().get("/api/smart/history")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["history"], [{"ts": 1, "n": 5}])


if __name__ == "__main__":
    unittest.main()
