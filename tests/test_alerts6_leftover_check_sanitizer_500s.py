"""Alerts sweep #6: subclass bombs that rode POST /api/alerts/check's own
unguarded seams.

A fresh hunt over the mounted alerts routes (create_app + TestClient,
raise_server_exceptions=False) with a poisoned source matrix found six
genuine leftover 500s, all raw tracebacks:

* ``check_once``'s final ``[_jsonable_alert(a) for a in emitted]`` is the one
  spot no try/except covers, and ``_jsonable_alert`` walked rows with *bound*
  calls: a dict-subclass ``items()`` bomb, a list-subclass ``__iter__`` bomb,
  an int-subclass ``__str__`` bomb raising anything but the digit-cap
  ValueError, a float-subclass ``__eq__`` bomb under the NaN/inf probes, a
  bytes-subclass ``decode`` bomb, a str-subclass whose ``__str__`` answers
  *self* carrying its bound ``encode`` bomb through ``_utf8_text``, and a
  raising ``isoformat`` property — any of them riding a row one of the three
  check feeders (ups_policy.sweep, freshness_svc.check_freshness,
  stale_runtime.remediate) handed back 500'd POST /api/alerts/check;
* a leftover cached status snapshot that is a dict *subclass* with a bombing
  ``.get`` blew ``_stamp_locale`` on every cache hit — ``full_status`` is the
  first thing ``check_once`` runs, before any per-check containment exists;
* the same cached snapshot carrying a self-``__str__`` str-subclass value
  blew ``status._utf8_text``'s bound ``encode`` inside ``_jsonable``;
* on a cold cache, a cfg() root that is a dict subclass with a bombing
  ``.get`` (and equally a poisoned ``settings`` *value*) raised out of
  ``_build_status``'s bare ``cfg().get(...)`` reads, and ``full_status``
  re-raises when it has no last-good snapshot;
* ``resource_mode()`` runs on *every* ``full_status`` call (``_status_ttl``
  → ``is_high``, cache hit included), and its ``settings.get(...)`` /
  ``v in ALLOWED`` reads detonated a dict-subclass ``.get`` bomb and a
  str-subclass ``__eq__`` bomb unconditionally.

Fixed to the modules5 unbound-base standard (``dict.items``, base
``__iter__``, ``int.__index__``, ``float.__float__``, unbound ``decode`` /
``str.encode``, guarded ``getattr``), plus plain-dict laundering of the
status cache and the cfg() reads.  Junk drops a field or a row — never the
route — and sane data around a poisoned wrapper survives.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import alerts, audit, auth, config, notify_channels, resource_mode
from hub import status as status_mod
from hub.app_factory import create_app
from hub.auth import require_auth

#: Built arithmetically: int("9" * 5000) itself trips the digit cap.
_HUGE_INT = 10 ** 4400

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return _APP


class _DictGetBomb(dict):
    def get(self, *a):
        raise RuntimeError("get bomb")


class _DictItemsBomb(dict):
    def items(self):
        raise RuntimeError("items bomb")


class _ListIterBomb(list):
    def __iter__(self):
        raise RuntimeError("iter bomb")


class _IntStrBomb(int):
    def __str__(self):
        raise RuntimeError("int str bomb")


class _FloatEqBomb(float):
    def __eq__(self, other):
        raise RuntimeError("float eq bomb")

    __hash__ = float.__hash__


class _BytesDecodeBomb(bytes):
    def decode(self, *a, **k):
        raise RuntimeError("bytes decode bomb")


class _SelfStrBomb(str):
    """str subclass whose __str__ answers *self*, keeping the subclass —
    and its bound ``encode`` bomb — alive through a bare str() copy."""

    def __str__(self):
        return self

    def encode(self, *a, **k):
        raise RuntimeError("encode bomb")


class _StrEqBomb(str):
    def __eq__(self, other):
        raise RuntimeError("str eq bomb")

    __hash__ = str.__hash__


class _IsoPropertyBomb:
    @property
    def isoformat(self):
        raise RuntimeError("isoformat property bomb")


#: One row per bomb class, plus a whole-row items bomb; the sane fields on
#: each row must survive the scrub.
def _bomb_rows() -> list:
    return [
        {"t": 1, "id": "x", "detail": _DictItemsBomb({"a": 1})},
        {"t": 1, "id": "y", "ports": _ListIterBomb([7])},
        {"t": _IntStrBomb(5), "id": "z"},
        {"t": 1, "id": "w", "pct": _FloatEqBomb(1.5)},
        {"t": 1, "id": "v", "blob": _BytesDecodeBomb(b"x")},
        {"t": 1, "id": "u", "path": _SelfStrBomb("p")},
        {"t": 1, "id": "s", "when": _IsoPropertyBomb()},
        {"t": 1, "id": "r", "big": _HUGE_INT},
        _DictItemsBomb({"t": 1, "id": "q"}),
    ]


class _Alerts6Sandbox(unittest.TestCase):
    """Scratch config + journal + state, and the real app's TestClient."""

    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="serverhub-alerts6-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.root = Path(tmp)
        self.data = self.root / "data"
        self.data.mkdir()
        for target, attr, value in (
            (config, "YAML_PATH", self.root / "services.yaml"),
            (config, "DATA_DIR", self.data),
            (config, "BASE", self.root),
            (config, "_LOCK_PATH", self.data / ".services.yaml.lock"),
            (alerts, "ALERTS_FILE", self.data / "alerts.jsonl"),
            (alerts, "STATE_FILE", self.data / "alert_state.json"),
            (notify_channels, "SECRETS_FILE", self.data / "notify-credentials.json"),
            (audit, "AUDIT_PATH", self.data / "auth-audit.jsonl"),
            (auth, "SECRET_FILE", self.data / ".session-secret"),
        ):
            patched = mock.patch.object(target, attr, value)
            patched.start()
            self.addCleanup(patched.stop)
        self.addCleanup(config.reload_cfg)
        config.reload_cfg()
        self.client = TestClient(app(), raise_server_exceptions=False)

    def patch(self, target, attr, value):
        patched = mock.patch.object(target, attr, value)
        patched.start()
        self.addCleanup(patched.stop)

    def warm_cache(self, snapshot):
        """Plant *snapshot* as a fresh cached status (far-future stamp)."""
        self.patch(status_mod, "_status_cache", {"t": 10 ** 12, "v": snapshot})

    def assert_check_200(self) -> list:
        r = self.client.post("/api/alerts/check")
        self.assertEqual(r.status_code, 200, r.text[:200])
        body = r.json()
        # Starlette's encode already ran; re-encode to pin renderability.
        json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        return body["emitted"]


class FeederRowBombPins(_Alerts6Sandbox):
    """Poisoned rows handed back by the three unwrapped check feeders reach
    ``check_once``'s final sanitize with no try/except above it."""

    def _assert_rows_scrubbed(self, emitted: list):
        by_id = {row.get("id"): row for row in emitted if isinstance(row, dict)}
        # Sane data on each poisoned row survives; the junk field degrades.
        self.assertEqual(by_id["x"]["detail"], {"a": 1})   # items-bomb wrapper
        self.assertEqual(by_id["y"]["ports"], [7])          # iter-bomb wrapper
        self.assertEqual(by_id["z"]["t"], 5)                # int __str__ bomb
        self.assertEqual(by_id["w"]["pct"], 1.5)            # float __eq__ bomb
        self.assertEqual(by_id["v"]["blob"], "x")           # bytes decode bomb
        self.assertEqual(by_id["u"]["path"], "p")           # self-str encode bomb
        self.assertIsNone(by_id["r"]["big"])                # over-cap int drops
        self.assertIn("q", by_id)                           # whole-row items bomb

    def test_ups_policy_rows_scrub_never_500(self):
        from hub import ups_policy
        self.patch(ups_policy, "sweep", lambda now: _bomb_rows())
        self._assert_rows_scrubbed(self.assert_check_200())

    def test_freshness_rows_scrub_never_500(self):
        from hub import freshness_svc
        self.patch(freshness_svc, "check_freshness",
                   lambda prev, ns, now, targets=None: _bomb_rows())
        self._assert_rows_scrubbed(self.assert_check_200())

    def test_stale_runtime_rows_scrub_never_500(self):
        from hub import stale_runtime
        self.patch(stale_runtime, "remediate", lambda now=None: _bomb_rows())
        self._assert_rows_scrubbed(self.assert_check_200())


class StatusCacheBombPins(_Alerts6Sandbox):
    """``check_once`` runs ``full_status`` before any containment exists;
    a poisoned cached snapshot must degrade, never 500 the check."""

    def test_dict_subclass_get_bomb_snapshot_answers_200(self):
        self.warm_cache(_DictGetBomb({"groups": [], "locale": "en"}))
        self.assert_check_200()

    def test_selfstr_encode_bomb_value_in_snapshot_answers_200(self):
        self.warm_cache({"groups": [], "locale": "en", "x": _SelfStrBomb("p")})
        self.assert_check_200()

    def test_sane_rows_in_a_poisoned_snapshot_still_sweep(self):
        """The get-bomb wrapper's real groups keep feeding the service
        sweep: transitions still record state under the same ids."""
        self.warm_cache(_DictGetBomb({
            "groups": [{"group": "g", "services": [
                {"id": "svc1", "state": "ok", "name": "Svc"},
            ]}],
            "locale": "en",
        }))
        self.assert_check_200()
        state = json.loads((self.data / "alert_state.json").read_text())
        self.assertEqual(state.get("svc1"), "ok")


class ColdCfgBombPins(_Alerts6Sandbox):
    """On a cold status cache ``_build_status`` reads cfg() bare, and
    ``full_status`` re-raises with no last-good snapshot to fall back on."""

    def test_cfg_root_get_bomb_cold_build_answers_200(self):
        self.patch(status_mod, "_status_cache", {"t": 0.0, "v": None})
        self.patch(status_mod, "cfg", lambda: _DictGetBomb({}))
        self.assert_check_200()

    def test_settings_value_get_bomb_cold_build_answers_200(self):
        self.patch(status_mod, "_status_cache", {"t": 0.0, "v": None})
        self.patch(status_mod, "cfg", lambda: {"settings": _DictGetBomb({})})
        self.assert_check_200()


class ResourceModeBombPins(_Alerts6Sandbox):
    """``resource_mode()`` runs on every ``full_status`` call via
    ``_status_ttl`` → ``is_high`` — a bomb there 500'd even cache hits."""

    def test_settings_get_bomb_answers_200(self):
        self.patch(resource_mode, "cfg", lambda: {"settings": _DictGetBomb({})})
        self.warm_cache({"groups": [], "locale": "en"})
        self.assert_check_200()

    def test_str_subclass_eq_bomb_mode_answers_200(self):
        self.patch(resource_mode, "cfg",
                   lambda: {"settings": {"resource_mode": _StrEqBomb("low")}})
        self.warm_cache({"groups": [], "locale": "en"})
        self.assert_check_200()

    def test_bomb_mode_falls_back_to_default(self):
        with mock.patch.object(resource_mode, "cfg",
                               lambda: {"settings": _DictGetBomb({})}):
            self.assertEqual(resource_mode.resource_mode(), "low")
        with mock.patch.object(
            resource_mode, "cfg",
            lambda: {"settings": {"resource_mode": _StrEqBomb("high")}},
        ):
            # The eq bomb never runs; the exact-str copy still matches.
            self.assertEqual(resource_mode.resource_mode(), "high")


class SanitizerFunctionPins(unittest.TestCase):
    """Function-level pins on the hardened helpers, so a regression is
    caught even if a future refactor moves the route seams around."""

    def test_jsonable_alert_unbound_base_walk(self):
        ja = alerts._jsonable_alert
        self.assertEqual(ja(_DictItemsBomb({"a": 1})), {"a": 1})
        self.assertEqual(ja({"x": _ListIterBomb([1])}), {"x": [1]})
        self.assertEqual(ja(_IntStrBomb(5)), 5)
        self.assertEqual(ja(_FloatEqBomb(1.5)), 1.5)
        self.assertEqual(ja(_BytesDecodeBomb(b"x")), "x")
        self.assertEqual(ja(_SelfStrBomb("x")), "x")
        self.assertIsNone(ja(_HUGE_INT))
        # A raising isoformat property degrades to text, never a raise.
        self.assertIsInstance(ja(_IsoPropertyBomb()), str)

    def test_utf8_text_unbound_encode_and_decode(self):
        self.assertEqual(alerts._utf8_text(_BytesDecodeBomb(b"x")), "x")
        self.assertEqual(alerts._utf8_text(_SelfStrBomb("x")), "x")
        self.assertEqual(notify_channels._utf8_text(_SelfStrBomb("x")), "x")
        self.assertEqual(status_mod._utf8_text(_SelfStrBomb("x")), "x")

    def test_stamp_helpers_base_coerce(self):
        self.assertEqual(alerts._alert_ts(_FloatEqBomb(1.5)), 1)
        self.assertEqual(alerts._alert_ts(_IntStrBomb(5)), 5)
        self.assertEqual(alerts._as_epoch(_FloatEqBomb(2.5)), 2)
        self.assertEqual(alerts._service_id(_IntStrBomb(5)), "5")

    def test_format_alert_absorbs_arbitrary_format_bombs(self):
        self.assertEqual(alerts._format_alert("{v}", v=_SelfStrBomb("x")), "x")

        class _FormatBomb:
            def __format__(self, spec):
                raise RuntimeError("format bomb")

            def __str__(self):
                return "fb"

        # The numeric spec forces __format__; the fallback renders str().
        self.assertIn("fb", alerts._format_alert("v={v:.0f}", v=_FormatBomb()))

    def test_append_alert_items_bomb_row_never_raises(self):
        tmp = Path(tempfile.mkdtemp(prefix="serverhub-alerts6-append-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        with mock.patch.object(alerts, "ALERTS_FILE", tmp / "alerts.jsonl"):
            alerts._append_alert(_DictItemsBomb({"t": 1, "id": "q"}))
            rows = (tmp / "alerts.jsonl").read_text().splitlines()
        self.assertEqual(json.loads(rows[0])["id"], "q")


if __name__ == "__main__":
    unittest.main()
