"""Settings8 leftover sweep: subclass bombs past the json5 laundering.

json5 sealed GET /api/settings against dict-subclass ``.get``/``items``/
``__iter__`` bombs by laundering each *section* through ``dict(...)``.  A
hostile re-sweep of the Settings / system_settings / http_guard surfaces
over the real ``create_app()`` + TestClient(raise_server_exceptions=False)
found the same bomb class still detonating one layer deeper — on the
*scalar* reads the laundering cannot reach — and on the sibling route the
json5 fix never touched:

* **GET /api/settings/other was never laundered at all.**
  ``system_settings_svc.get_other_settings`` opened with the exact read
  json5 replaced in settings_api — ``cfg().get("settings") or {}`` — so a
  config root / settings map with a bombing ``.get`` or ``__bool__``
  raised on the first line; an ``ip_aliases.ips`` list *subclass* whose
  ``__iter__`` raises passed the isinstance gate and blew the clean-ips
  loop.  Each was a raw 500 where GET /api/settings already answered 200.

* **Int/float scalar bombs past the ValueError-only digit-cap catch.**
  ``_finite`` / ``_finite_number`` / ``_jsonable`` / ``_json_atom`` /
  ``_json_tree`` probed ``str(value)`` catching only ValueError and ran
  the NaN/inf checks on the raw value: an int subclass whose ``__str__``
  bombs, or a float subclass whose ``__eq__`` bombs (the modules5 class),
  raised out of GET /api/settings, /api/settings/thresholds and
  /api/settings/other — one poisoned threshold or stack port cost the
  whole page.  Fixed with the unbound base coercions
  (``int.__index__`` / ``float.__float__``) every other sanitized module
  already uses.

* **Truthiness and membership reflect into the leftover.**
  ``bool(notify.get("enabled"))``, the ``has_password`` or-chain, the
  terminal ``host_enabled`` read, and ``s.get("resource_mode") in
  ("low", "high")`` all dispatch into the stored value's own
  ``__bool__`` / ``__eq__`` — a bomb there 500'd GET /api/settings (and
  /other for resource_mode, where a str-*subclass* ``__eq__`` bomb gets
  reflected priority even against a plain str).

* **http_guard's text coercion was a bare ``str(raw or "")``.**
  An over-cap YAML hex/octal int handed to any gate built on
  ``_url_parts`` / ``_utf8_host`` raised CPython's 4300-digit ``str()``
  ValueError (uncaught — the try starts after the coercion), and a
  ``__bool__``/``__str__`` bomb raised whatever it liked, escaping
  ``local_http_origin`` / ``is_allowed_webhook_url`` /
  ``local_connect_peer`` / ``notify_connect_peer`` /
  ``is_allowed_notify_host`` instead of answering "not a URL".

* **``bytes.decode`` bombs in the sanitizers.**  Every
  ``value.decode("utf-8", "replace")`` dispatched into a bytes-subclass
  override; base-copied through ``bytes(...)`` first now.

get_management_access carried the same dead ``cfg().get("settings")``
read and an unguarded ``bool(auth.get("enabled"))``; both only degraded
the bundle section to an error row (the bundle absorbs), but are fixed to
the same rule and pinned here as the section surviving.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import config, http_guard, system_settings_svc
from hub.app_factory import create_app
from hub.auth import require_auth
from hub.routers import settings_api


class GetBomb(dict):
    """Passes ``isinstance(x, dict)``; ``.get`` raises."""

    def get(self, *a, **k):
        raise RuntimeError("get bomb")


class BoolBombDict(dict):
    def __bool__(self):
        raise RuntimeError("bool bomb dict")


class IterBombList(list):
    def __iter__(self):
        raise RuntimeError("iter bomb")


class BoolBomb:
    def __bool__(self):
        raise RuntimeError("bool bomb")


class StrBombInt(int):
    """Passes ``isinstance(x, int)``; ``__index__``/``__str__`` raise."""

    def __index__(self):
        raise RuntimeError("index bomb")

    def __str__(self):
        raise RuntimeError("str bomb")


class EqBombFloat(float):
    """Passes ``isinstance(x, float)``; the NaN/inf probes reflect into it."""

    def __float__(self):
        raise RuntimeError("float bomb")

    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    __hash__ = float.__hash__


class EqBombStr(str):
    """A str subclass gets reflected ``__eq__`` priority in ``x in tuple``."""

    def __eq__(self, other):
        raise RuntimeError("eq bomb str")

    __hash__ = str.__hash__


class DecodeBombBytes(bytes):
    def decode(self, *a, **k):
        raise RuntimeError("decode bomb")


def _base(**settings_extra) -> dict:
    return {
        "settings": {"host_ip": "10.0.0.9", **settings_extra},
        "stacks": [],
        "log_sources": [],
        "groups_order": [],
    }


class _SettingsHttpPin(unittest.TestCase):
    """Drives the real mounted routes with a poisoned cfg() snapshot."""

    def _client(self) -> TestClient:
        app = create_app()
        app.dependency_overrides[require_auth] = lambda: None
        self.addCleanup(app.dependency_overrides.clear)
        return TestClient(app, raise_server_exceptions=False)

    def _get(self, path: str, cfg_value):
        client = self._client()
        # cfg was imported by name into each consumer, so every seam the
        # route reads through gets the same poisoned snapshot.
        with (
            mock.patch.object(config, "cfg", return_value=cfg_value),
            mock.patch.object(system_settings_svc, "cfg", return_value=cfg_value),
            mock.patch.object(settings_api, "cfg", return_value=cfg_value),
        ):
            return client.get(path)

    def _ok_body(self, path: str, cfg_value) -> dict:
        resp = self._get(path, cfg_value)
        self.assertEqual(resp.status_code, 200, resp.text[:400])
        body = resp.json()
        # The body Starlette encoded must be re-encodable under the same
        # allow_nan=False / UTF-8 contract it used.
        json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        return body


class OtherSettingsBombPins(_SettingsHttpPin):
    """GET /api/settings/other opened with the read json5 fixed elsewhere."""

    def test_config_root_get_bomb_answers_200(self):
        body = self._ok_body("/api/settings/other", GetBomb(_base()))
        self.assertEqual(body["resource_mode"], "low")
        self.assertEqual(body["metrics_interval"], 90)

    def test_settings_map_get_bomb_answers_200(self):
        snap = {"settings": GetBomb({"adaptive": True, "metrics_interval": 60})}
        body = self._ok_body("/api/settings/other", snap)
        # dict(...) laundering keeps the values the bomb was holding.
        self.assertEqual(body["metrics_interval"], 60)

    def test_settings_bool_bomb_shapes_answer_200(self):
        for label, settings in (
            ("dict-subclass __bool__", BoolBombDict({"adaptive": True})),
            ("non-mapping __bool__", BoolBomb()),
        ):
            with self.subTest(shape=label):
                body = self._ok_body("/api/settings/other", {"settings": settings})
                self.assertEqual(body["resource_mode"], "low")

    def test_ip_alias_iter_bomb_degrades_to_empty_ips(self):
        snap = _base(ip_aliases={
            "ips": IterBombList(["10.0.0.5"]),
            "netmask": "255.255.255.0",
            "auto_bind": True,
        })
        body = self._ok_body("/api/settings/other", snap)
        # The bombing list degrades alone; its healthy siblings survive.
        self.assertEqual(body["ip_aliases"]["ips"], [])
        self.assertEqual(body["ip_aliases"]["netmask"], "255.255.255.0")
        self.assertTrue(body["ip_aliases"]["auto_bind"])

    def test_resource_mode_eq_bombs_default_to_low(self):
        for label, mode in (
            ("float __eq__", EqBombFloat(1.0)),
            ("str-subclass __eq__", EqBombStr("high")),
        ):
            with self.subTest(shape=label):
                body = self._ok_body("/api/settings/other", _base(resource_mode=mode))
                # The str subclass carries real text; the float bomb cannot
                # be a mode at all.  Both must answer without raising.
                self.assertIn(body["resource_mode"], ("low", "high"))

    def test_scalar_number_bombs_are_recovered_by_base_coercion(self):
        snap = _base(
            metrics_interval=StrBombInt(60),
            alert_interval=EqBombFloat(30.0),
        )
        body = self._ok_body("/api/settings/other", snap)
        # The unbound base coercions read the C-level value under the
        # bombing overrides, so the stored number survives as an exact
        # int/float instead of costing the page (or even the field).
        self.assertEqual(body["metrics_interval"], 60)
        self.assertEqual(body["alert_interval"], 30.0)


class ThresholdsRouteBombPins(_SettingsHttpPin):
    """GET /api/settings/thresholds over scalar bombs in the stored section."""

    def test_number_bombs_are_recovered_by_base_coercion(self):
        snap = _base(thresholds={
            "cpu_pct": StrBombInt(91),
            "mem_pct": EqBombFloat(92.0),
            "disk_pct": 85,
            "enabled": True,
        })
        body = self._ok_body("/api/settings/thresholds", snap)
        # The unbound base coercions read the C-level values under the
        # bombing overrides: the stored numbers land exactly.
        self.assertEqual(body["cpu_pct"], 91)
        self.assertEqual(body["mem_pct"], 92.0)
        self.assertEqual(body["disk_pct"], 85)
        self.assertTrue(body["enabled"])

    def test_decode_bomb_bytes_key_is_scrubbed_not_raised(self):
        snap = _base(thresholds={DecodeBombBytes(b"cpu_pct"): 91, "disk_pct": 85})
        body = self._ok_body("/api/settings/thresholds", snap)
        self.assertEqual(body["disk_pct"], 85)


class PublicSettingsBombPins(_SettingsHttpPin):
    """GET /api/settings: scalar bombs one layer past the json5 laundering."""

    def test_metrics_interval_str_bomb_is_recovered(self):
        body = self._ok_body("/api/settings", _base(metrics_interval=StrBombInt(60)))
        # Base coercion recovers the stored value under the bombing override.
        self.assertEqual(body["metrics_interval"], 60)
        # A healthy sibling proves nothing else was disturbed.
        self.assertEqual(body["host_ip"], "10.0.0.9")

    def test_resource_mode_eq_bombs_default_to_low(self):
        for label, mode in (
            ("float __eq__", EqBombFloat(1.0)),
            ("str-subclass __eq__", EqBombStr("weird")),
        ):
            with self.subTest(shape=label):
                body = self._ok_body("/api/settings", _base(resource_mode=mode))
                self.assertEqual(body["resource_mode"], "low")

    def test_threshold_number_bombs_are_recovered(self):
        body = self._ok_body(
            "/api/settings",
            _base(thresholds={"mem_pct": EqBombFloat(92.0), "cpu_pct": StrBombInt(91)}),
        )
        self.assertEqual(body["thresholds"]["mem_pct"], 92.0)
        self.assertEqual(body["thresholds"]["cpu_pct"], 91)

    def test_flag_bool_bombs_read_as_false(self):
        snap = _base(
            notify={
                "enabled": BoolBomb(),
                "ha_token": BoolBomb(),
                "webhook_url": BoolBomb(),
            },
            auth={"password_hash": BoolBomb(), "password": BoolBomb()},
            terminal={"host_enabled": BoolBomb()},
        )
        body = self._ok_body("/api/settings", snap)
        self.assertFalse(body["notify"]["enabled"])
        self.assertFalse(body["notify"]["has_token"])
        self.assertFalse(body["notify"]["has_webhook"])
        self.assertFalse(body["auth"]["has_password"])
        self.assertFalse(body["terminal"]["host_enabled"])

    def test_nested_stack_bombs_are_recovered_not_500(self):
        snap = {
            "settings": {"host_ip": "10.0.0.9"},
            "stacks": [{"port": StrBombInt(80), "name": DecodeBombBytes(b"s1")}],
            "log_sources": [],
            "groups_order": [],
        }
        body = self._ok_body("/api/settings", snap)
        self.assertEqual(len(body["stacks"]), 1)
        # Base coercion recovers the port under the bombing override, and
        # the decode-bomb name is base-copied and survives as text.
        self.assertEqual(body["stacks"][0]["port"], 80)
        self.assertEqual(body["stacks"][0]["name"], "s1")

    def test_over_cap_int_still_drops_like_inf(self):
        # The genuinely unrenderable leftover keeps its json5-era drop:
        # >4300 digits cannot be JSON-encoded at all.
        body = self._ok_body("/api/settings", _base(metrics_interval=OVER_CAP_INT))
        self.assertEqual(body["metrics_interval"], 90)


class ManagementSectionBombPins(_SettingsHttpPin):
    """The bundle's Management Access section survives instead of erroring."""

    def _mgmt(self, cfg_value) -> dict:
        with (
            mock.patch.object(config, "cfg", return_value=cfg_value),
            mock.patch.object(system_settings_svc, "cfg", return_value=cfg_value),
        ):
            return system_settings_svc.get_management_access()

    def test_auth_enabled_bool_bomb_reads_false(self):
        out = self._mgmt(_base(auth={"enabled": BoolBomb(), "username": "admin"}))
        self.assertNotIn("error", out)
        self.assertFalse(out["auth_enabled"])
        self.assertEqual(out["username"], "admin")

    def test_config_root_get_bomb_still_renders_the_section(self):
        out = self._mgmt(GetBomb(_base()))
        self.assertNotIn("error", out)
        self.assertEqual(out["panel_port"], 8086)

    def test_settings_system_route_answers_200_over_the_bombs(self):
        snap = _base(auth={"enabled": BoolBomb()}, resource_mode=EqBombFloat(1.0))
        body = self._ok_body("/api/settings/system", snap)
        self.assertIn("management", body)
        json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")


#: An already-parsed over-cap int: YAML hex/octal loads uncapped through
#: ``int(x, 16)``, so ``str()`` of it raises the 4300-digit ValueError.
OVER_CAP_INT = 1 << 20000


class HttpGuardCoercionPins(unittest.TestCase):
    """Every gate built on _url_parts / _utf8_host refuses, never raises."""

    URL_GATES = (
        http_guard.local_http_origin,
        http_guard.is_local_http_origin,
        http_guard.is_allowed_webhook_url,
    )
    HOST_GATES = (
        http_guard.local_connect_peer,
        http_guard.notify_connect_peer,
        http_guard.is_allowed_notify_host,
    )

    def test_over_cap_int_is_refused_not_valueerror(self):
        for fn in (*self.URL_GATES, *self.HOST_GATES):
            with self.subTest(gate=fn.__name__):
                self.assertIn(fn(OVER_CAP_INT), (None, False))

    def test_bool_and_str_bombs_never_raise(self):
        for leftover in (BoolBomb(), StrBombInt(5)):
            # URL gates refuse (the coerced text is not an http(s) URL);
            # host gates judge the coerced text exactly like a typed host,
            # so the pin there is termination, not the verdict.
            for fn in self.URL_GATES:
                with self.subTest(gate=fn.__name__, leftover=type(leftover).__name__):
                    self.assertIn(fn(leftover), (None, False))
            for fn in self.HOST_GATES:
                with self.subTest(gate=fn.__name__, leftover=type(leftover).__name__):
                    fn(leftover)

    def test_decode_bomb_bytes_are_base_copied(self):
        # A bytes leftover decodes through the base type; the bomb never fires
        # and the decoded text is judged like any typed URL/host.
        self.assertEqual(
            http_guard.local_http_origin(DecodeBombBytes(b"http://127.0.0.1:8080")),
            "http://127.0.0.1:8080",
        )
        self.assertTrue(
            http_guard.is_allowed_notify_host(DecodeBombBytes(b"ntfy.sh"))
        )

    def test_good_urls_and_hosts_keep_their_answers(self):
        self.assertEqual(
            http_guard.local_http_origin("http://127.0.0.1:8080/"),
            "http://127.0.0.1:8080",
        )
        self.assertIsNone(http_guard.local_http_origin("http://[::1"))
        self.assertIsNone(http_guard.local_http_origin("http://127.0.0.1:99999"))
        self.assertTrue(http_guard.is_allowed_webhook_url("https://ntfy.sh/topic"))
        self.assertEqual(http_guard.local_connect_peer("127.0.0.1"), "127.0.0.1")
        self.assertIsNone(http_guard.local_connect_peer("\ud800"))


if __name__ == "__main__":
    unittest.main()
