"""Twelfth leftover-500s sweep of the Apps catalog surface.

The live leftovers
==================
catalog11 laundered the *text* streams a leftover ``sh()`` hands back, but
every launchctl helper still compared the **rc** slot raw, and
``catalog_remote.source_url()`` still trusted the shape of the stored
config section.  Reproduced over ``create_app()`` + ``TestClient(
raise_server_exceptions=False)`` as raw HTTP 500s:

* ``POST /api/catalog/native-screen-sharing/install`` and ``/uninstall`` —
  ``_screen_sharing_on``'s bare ``rc == 0`` probes run after every enable /
  disable attempt; an rc-subclass whose ``__eq__`` raises detonated them.
* ``POST /api/catalog/native-filebrowser/uninstall`` and
  ``POST /api/catalog/native-homeassistant/uninstall`` —
  ``_launchctl_unload``'s ``rc != 0`` / ``rc in (0, 3, 5)`` probes blew on
  the same bomb; a >4300-digit leftover rc passed every comparison and then
  ValueError'd the ``f"exit {rc}"`` fallback past CPython's int->str digit
  cap; and a stdout whose ``__bool__`` raises detonated
  ``_launchctl_is_loaded``'s confirmation probe.
* ``GET /api/catalog/remote`` (and every ``POST /api/catalog/remote/check``
  behind it) — ``source_url()``'s bare bound ``section.get("url")`` was four
  raw 500s: a leftover dict *subclass* whose ``.get`` bombs, a section that
  is not a mapping at all (``catalog_remote: []`` by hand), a raising
  ``__class__`` property detonating the gate, and a *hash-shadowing* key
  (same hash as ``"url"``, raising ``__eq__``) detonating the compare inside
  the C-level lookup itself.

The fixes are the shared conventions: ``_rc_int`` (``int.__index__``
underneath a subclass override; junk → -255, never the -1 timeout /
not-found sentinel) at every ``sh()`` / ``run_capped`` rc consumer,
``_as_text`` before any truthiness or f-string on the streams, and
``source_url`` going through a fail-closed ``_isinst`` gate plus the
unbound ``dict.get`` in a try (the config.settings_section convention) —
which also means a dict-subclass ``.get`` bomb now *recovers* the genuine
URL through the C-level storage instead of erroring.

Field-level pins ride along: ``_port_list`` no longer lets an item
``__eq__`` bomb empty a row's ports (and drops a >4300-digit port before it
can ValueError ``_resolve_url``), ``catalog._plain_str_list`` survives a
scalar ``__eq__`` bomb, and GET /api/catalog keeps all native rows —
not an emptied native half — under every rc-bomb shape.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import catalog, catalog_remote, native_catalog  # noqa: E402

_app = None
_client = None


def _the_client():
    """One app for the module: create_app() is expensive and stateless here."""
    global _app, _client
    if _client is None:
        from fastapi.testclient import TestClient

        from hub.app_factory import create_app
        from hub.auth import require_auth

        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
        _client = TestClient(_app, raise_server_exceptions=False)
    return _client


class _RcEqBomb(int):
    """An honest int value under a raising ``__eq__``/``__ne__`` override."""

    def __eq__(self, other):  # noqa: D105
        raise RuntimeError("rc eq bomb")

    def __ne__(self, other):
        raise RuntimeError("rc ne bomb")

    __hash__ = int.__hash__


class _RcStrBomb(int):
    """An int subclass whose ``__str__`` raises (f-string kryptonite)."""

    def __str__(self):
        raise RuntimeError("rc str bomb")


class _BoolBombStr(str):
    """A stream whose truthiness raises — ``bool(out)``'s kryptonite."""

    def __bool__(self):
        raise RuntimeError("bool bomb")


class _Lie:
    """``__class__`` answers a type the object is not — a claim, not a raise."""

    def __init__(self, claim):
        self._claim = claim

    @property
    def __class__(self):  # type: ignore[override]
        return self._claim

    def __hash__(self):
        return 17


class _ClassBomb:
    """``__class__`` is a raising property: a bare isinstance gate's kryptonite."""

    @property
    def __class__(self):  # noqa: A003
        raise RuntimeError("class bomb")


#: Hex spelling dodges CPython's parse-time digit cap; str() of the value is
#: the ValueError the digit-cap probes must swallow.
_HUGE_INT = int("0x" + "f" * 4400, 16)


#: sh() result shapes that each used to be a live raw 500 on the routes below.
_SH_ZOO = {
    "rc-eq-bomb": lambda: (_RcEqBomb(0), "", ""),
    "rc-str-bomb": lambda: (_RcStrBomb(3), "", ""),
    "rc-huge-int": lambda: (_HUGE_INT, "", ""),
    "rc-int-liar": lambda: (_Lie(int), "", ""),
    "rc-class-bomb": lambda: (_ClassBomb(), "", ""),
    "out-bool-bomb": lambda: (0, _BoolBombStr("x"), ""),
    "out-surrogate": lambda: (1, "boot\ud800out", "er\ud800r"),
}


class _NativeOpsSandbox(unittest.TestCase):
    """Hermetic native-store ops: temp trees, no real subprocess spawns."""

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        tmp = Path(self._tmp.name)
        self.templates = tmp / "templates"
        self.templates.mkdir()
        self.services = tmp / "services"
        self.services.mkdir()
        self.remote_dir = tmp / "catalog-remote"
        self.remote_dir.mkdir()
        self.home = tmp / "home"
        (self.home / "Library" / "LaunchAgents").mkdir(parents=True)
        catalog.invalidate_listing()
        self.addCleanup(catalog.invalidate_listing)
        native_catalog.list_native_apps.invalidate()
        self.addCleanup(native_catalog.list_native_apps.invalidate)
        for module, name, value in (
            (catalog, "TEMPLATES", self.templates),
            (catalog, "SERVICES_ROOT", self.services),
            (native_catalog, "SERVICES_ROOT", self.services),
            (catalog_remote, "REMOTE_DIR", self.remote_dir),
            (catalog_remote, "STATE_PATH", self.remote_dir / "state.json"),
        ):
            self.stack.enter_context(mock.patch.object(module, name, value))
        self.client = _the_client()

    def _with_sh(self, make):
        """Every ``sh`` spawn answers *make()*; brew runs fail plainly."""
        return mock.patch.multiple(
            native_catalog,
            sh=lambda *a, _m=make, **k: _m(),
            run_capped=lambda *a, **k: (1, "brew said no"),
        )

    def _post(self, path: str, body: dict):
        resp = self.client.post(path, json=body)
        # The response body itself must survive Starlette's UTF-8 encode.
        resp.content.decode("utf-8")
        return resp


class NativeOpsRcBombTests(_NativeOpsSandbox):
    """Junk in the sh() rc slot no longer 500s the native store operations."""

    def test_screen_sharing_install_survives_every_rc_shape(self):
        for name, make in _SH_ZOO.items():
            with self.subTest(shape=name), self._with_sh(make):
                resp = self._post(
                    "/api/catalog/native-screen-sharing/install",
                    {"confirm": True},
                )
                self.assertEqual(resp.status_code, 200, resp.text[:300])
                body = resp.json()
                self.assertIsInstance(body["ok"], bool)
                self.assertEqual(body["stack_id"], "native-screen-sharing")

    def test_screen_sharing_uninstall_survives_every_rc_shape(self):
        for name, make in _SH_ZOO.items():
            with self.subTest(shape=name), self._with_sh(make):
                resp = self._post(
                    "/api/catalog/native-screen-sharing/uninstall",
                    {"confirm": True, "remove_data": False},
                )
                self.assertEqual(resp.status_code, 200, resp.text[:300])
                self.assertIsInstance(resp.json()["ok"], bool)

    def test_filebrowser_uninstall_survives_every_rc_shape(self):
        for name, make in _SH_ZOO.items():
            with self.subTest(shape=name), self._with_sh(make):
                resp = self._post(
                    "/api/catalog/native-filebrowser/uninstall",
                    {"confirm": True, "remove_data": False},
                )
                self.assertEqual(resp.status_code, 200, resp.text[:300])
                body = resp.json()
                # The bootout scrub degrades; the install tree is absent.
                self.assertIs(body["ok"], True)
                self.assertIn("not found", body["message"])

    def test_homeassistant_uninstall_survives_every_rc_shape(self):
        for name, make in _SH_ZOO.items():
            with self.subTest(shape=name), self._with_sh(make):
                resp = self._post(
                    "/api/catalog/native-homeassistant/uninstall",
                    {"confirm": True, "remove_data": False},
                )
                self.assertEqual(resp.status_code, 200, resp.text[:300])
                self.assertIs(resp.json()["ok"], True)

    def test_filebrowser_install_survives_every_rc_shape(self):
        """The _launchctl_load path: bombs in rc/out and surrogate streams.

        The brew step is skipped by planting the binary, so the request
        reaches the LaunchAgent bootstrap whose rc probes and message
        f-string used to detonate.
        """
        agents_dir = self.home / "Library" / "LaunchAgents"
        fb = self.services / "filebrowser"
        fb.mkdir(exist_ok=True)
        (fb / "filebrowser-bin").write_text("#!/bin/sh\n", encoding="utf-8")
        for name, make in _SH_ZOO.items():
            with self.subTest(shape=name), self._with_sh(make), \
                    mock.patch("hub.paths.AGENTS_DIR", agents_dir), \
                    mock.patch.object(
                        native_catalog, "user_home", lambda: self.home
                    ), \
                    mock.patch.object(
                        native_catalog, "_process_running", lambda *_a: False
                    ):
                resp = self._post(
                    "/api/catalog/native-filebrowser/install",
                    {"confirm": True},
                )
                self.assertEqual(resp.status_code, 200, resp.text[:300])
                body = resp.json()
                # The binary is present, so install reports ready even when
                # the LaunchAgent bootstrap itself failed.
                self.assertIs(body["ok"], True)
                self.assertEqual(body["stack_id"], "native-filebrowser")

    def test_store_overview_keeps_every_native_row_under_rc_bombs(self):
        """Field-level, not half-level: the rc bomb used to raise out of
        list_native_apps and empty the entire native half of the store."""
        for name, make in _SH_ZOO.items():
            with self.subTest(shape=name), self._with_sh(make):
                native_catalog.list_native_apps.invalidate()
                resp = self.client.get("/api/catalog")
                resp.content.decode("utf-8")
                self.assertEqual(resp.status_code, 200, resp.text[:300])
                self.assertEqual(
                    resp.json()["native_count"], len(native_catalog.NATIVE_APPS)
                )

    def test_control_clean_probe_still_reads_running(self):
        with self._with_sh(lambda: (0, "state = running", "")):
            resp = self._post(
                "/api/catalog/native-screen-sharing/install",
                {"confirm": True},
            )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertIs(resp.json()["ok"], True)


class _GetBombDict(dict):
    def get(self, *a, **k):  # noqa: D102
        raise RuntimeError("get bomb")


class _KeyLiar:
    """Hash-shadows a target key; the C-level lookup's ``__eq__`` raises."""

    def __init__(self, mimic):
        self._h = hash(mimic)

    def __hash__(self):
        return self._h

    def __eq__(self, other):
        raise RuntimeError("key eq bomb")


class RemoteStatusCfgSectionTests(_NativeOpsSandbox):
    """GET /api/catalog/remote survives every poisoned config-section shape."""

    def _status_with_section(self, section):
        with mock.patch(
            "hub.config.settings_section", lambda name, _s=section: _s
        ):
            resp = self.client.get("/api/catalog/remote")
        resp.content.decode("utf-8")
        return resp

    def test_poisoned_sections_degrade_to_not_configured(self):
        for name, section in (
            ("not-a-dict", ["https://x.example/i.json"]),
            ("none", None),
            ("hash-shadow-key", {_KeyLiar("url"): "https://x.example/i.json"}),
            ("dict-liar", _Lie(dict)),
            ("class-bomb", _ClassBomb()),
        ):
            with self.subTest(section=name):
                resp = self._status_with_section(section)
                self.assertEqual(resp.status_code, 200, resp.text[:300])
                body = resp.json()
                self.assertIs(body["configured"], False)
                self.assertEqual(body["url"], "")

    def test_get_bomb_subclass_recovers_the_genuine_url(self):
        # The unbound dict.get reads the C-level storage underneath the
        # override, so the stored URL survives its own poisoned container.
        resp = self._status_with_section(
            _GetBombDict(url="https://example.com/index.json")
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertIs(body["configured"], True)
        self.assertEqual(body["url"], "https://example.com/index.json")

    def test_raising_settings_provider_degrades_to_not_configured(self):
        def boom(name):
            raise RuntimeError("cfg provider bomb")

        with mock.patch("hub.config.settings_section", boom):
            resp = self.client.get("/api/catalog/remote")
        resp.content.decode("utf-8")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertIs(resp.json()["configured"], False)

    def test_control_clean_section_stays_exact(self):
        raw = "https://ex.example/catalog/index.json"
        resp = self._status_with_section({"url": raw})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["url"], raw)


class RcIntTwinTests(unittest.TestCase):
    """The shared _rc_int rule, pinned on both catalog twins."""

    _TWINS = (native_catalog._rc_int, catalog._rc_int)

    def test_honest_statuses_pass_untouched(self):
        for rc_int in self._TWINS:
            with self.subTest(twin=rc_int.__module__):
                self.assertEqual(rc_int(0), 0)
                self.assertEqual(rc_int(3), 3)
                self.assertEqual(rc_int(-1), -1)  # timeout / not-found sentinel
                self.assertEqual(rc_int(True), 1)
                self.assertEqual(rc_int("2"), 2)

    def test_subclass_bombs_read_their_honest_value(self):
        # int.__index__ reads the real storage underneath the override.
        for rc_int in self._TWINS:
            with self.subTest(twin=rc_int.__module__):
                self.assertEqual(rc_int(_RcEqBomb(0)), 0)
                self.assertEqual(rc_int(_RcStrBomb(5)), 5)

    def test_junk_reads_minus_255_never_the_sentinel(self):
        for rc_int in self._TWINS:
            for junk in (_HUGE_INT, _Lie(int), _Lie(bool), _ClassBomb(), None, "x"):
                with self.subTest(twin=rc_int.__module__, junk=type(junk).__name__):
                    self.assertEqual(rc_int(junk), -255)


class LaunchctlHelperUnitTests(unittest.TestCase):
    """The launchctl helpers defuse rc/stream junk in place."""

    def _with_sh(self, make):
        return mock.patch.object(
            native_catalog, "sh", lambda *a, _m=make, **k: _m()
        )

    def test_unload_message_stays_utf8_under_every_shape(self):
        for name, make in _SH_ZOO.items():
            with self.subTest(shape=name), self._with_sh(make), mock.patch.object(
                native_catalog, "_process_running", lambda *_a: False
            ):
                out = native_catalog._launchctl_unload("local.test")
                self.assertIsInstance(out["message"], str)
                out["message"].encode("utf-8")
                self.assertIsInstance(out["ok"], bool)

    def test_load_message_stays_utf8_under_every_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            plist = Path(tmp) / "local.test.plist"
            plist.write_text("<plist/>", encoding="utf-8")
            for name, make in _SH_ZOO.items():
                with self.subTest(shape=name), self._with_sh(make), \
                        mock.patch.object(
                            native_catalog, "_process_running", lambda *_a: False
                        ):
                    out = native_catalog._launchctl_load("local.test", plist)
                    self.assertIsInstance(out["message"], str)
                    out["message"].encode("utf-8")
                    self.assertIsInstance(out["ok"], bool)

    def test_is_loaded_survives_bool_bomb_stdout(self):
        with self._with_sh(lambda: (0, _BoolBombStr("x"), "")):
            self.assertIs(native_catalog._launchctl_is_loaded("local.test"), True)
        with self._with_sh(lambda: (_RcEqBomb(0), "y", "")):
            self.assertIs(native_catalog._launchctl_is_loaded("local.test"), True)
        with self._with_sh(lambda: (1, "y", "")):
            self.assertIs(native_catalog._launchctl_is_loaded("local.test"), False)

    def test_screen_sharing_probe_reads_honestly_under_bombs(self):
        with self._with_sh(lambda: (_RcEqBomb(0), "state = running", "")):
            self.assertIs(native_catalog._screen_sharing_on(), True)
        with self._with_sh(lambda: (_HUGE_INT, "", "")):
            self.assertIs(native_catalog._screen_sharing_on(), False)


class PortListFieldLevelTests(unittest.TestCase):
    """_port_list drops junk items alone; siblings and controls survive."""

    def test_eq_bomb_item_keeps_its_honest_value(self):
        out = native_catalog._port_list([_RcEqBomb(8080), "80"])
        self.assertEqual(out, [8080, "80"])

    def test_huge_int_item_drops_and_siblings_survive(self):
        out = native_catalog._port_list([_HUGE_INT, "80"])
        self.assertEqual(out, ["80"])

    def test_str_subclass_launders_to_plain_str(self):
        class _SelfStr(str):
            def encode(self, *a, **k):
                raise RuntimeError("encode bomb")

        out = native_catalog._port_list([_SelfStr("8080"), "x\ud800y"])
        self.assertEqual(out, ["8080", "x?y"])
        self.assertIs(type(out[0]), str)

    def test_resolve_url_skips_unrenderable_ports(self):
        out = native_catalog._resolve_url("", "h", [_HUGE_INT, "8080"])
        self.assertEqual(out, "http://h:8080")

    def test_controls_stay_exact(self):
        self.assertEqual(
            native_catalog._port_list(["1883", b"80"]), ["1883", "80"]
        )
        self.assertEqual(native_catalog._port_list("8080"), ["8080"])
        self.assertEqual(native_catalog._port_list(None), [])


class PlainStrListEqBombTests(unittest.TestCase):
    """catalog._plain_str_list: the scalar emptiness probe cannot detonate."""

    def test_eq_bomb_scalar_degrades_through_plain_str(self):
        class _EqBombObj:
            def __eq__(self, other):
                raise RuntimeError("eq bomb")

            __hash__ = object.__hash__

            def __str__(self):
                return "tagged"

        self.assertEqual(catalog._plain_str_list(_EqBombObj()), ["tagged"])

    def test_controls_stay_exact(self):
        self.assertEqual(catalog._plain_str_list(None), [])
        self.assertEqual(catalog._plain_str_list(""), [])
        self.assertEqual(catalog._plain_str_list(False), [])
        self.assertEqual(catalog._plain_str_list(["a", "", "b"]), ["a", "b"])
        self.assertEqual(catalog._plain_str_list("solo"), ["solo"])


class SourceUrlUnitTests(unittest.TestCase):
    """source_url(): every poisoned section shape, unit-pinned."""

    def _with_section(self, section):
        return mock.patch(
            "hub.config.settings_section", lambda name, _s=section: _s
        )

    def test_poisoned_shapes_degrade_to_empty(self):
        for name, section in (
            ("not-a-dict", ["x"]),
            ("none", None),
            ("hash-shadow-key", {_KeyLiar("url"): "https://x/i.json"}),
            ("dict-liar", _Lie(dict)),
            ("class-bomb", _ClassBomb()),
        ):
            with self.subTest(section=name), self._with_section(section):
                self.assertEqual(catalog_remote.source_url(), "")

    def test_get_bomb_subclass_recovers_the_stored_url(self):
        with self._with_section(_GetBombDict(url="https://e.example/i.json")):
            self.assertEqual(
                catalog_remote.source_url(), "https://e.example/i.json"
            )

    def test_exact_str_stays_byte_for_byte_untouched(self):
        # The catalog8/catalog11 pin: a lone-surrogate URL must keep its
        # coded bad_url refusal, never be laundered into a fetchable
        # replacement-char host.
        raw = "https://e\ud800x.com/i.json"
        with self._with_section({"url": raw}):
            self.assertEqual(catalog_remote.source_url(), raw)


if __name__ == "__main__":
    unittest.main()
