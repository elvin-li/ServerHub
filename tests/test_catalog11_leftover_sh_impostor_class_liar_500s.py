"""Eleventh leftover-500s sweep of the Apps catalog surface.

The live leftovers
==================
The native store's system/LaunchAgent operations scrub their subprocess
output through ``native_catalog._as_text``, and that scrub still trusted the
shape of what ``sh()`` handed back.  ``isinstance`` honours a *lying*
``__class__`` property (and detonates on a *raising* one), so one leftover
output object — the json9/modules9 impostor class — raised straight out of
the route, reproduced over ``create_app()`` + ``TestClient(
raise_server_exceptions=False)`` as raw HTTP 500s:

* ``POST /api/catalog/native-screen-sharing/install`` — the
  ``launchctl print system/com.apple.screensharing`` probe's output feeds
  ``_as_text``; a ``__class__`` answering bytes/bytearray passed the gate and
  blew the unbound ``bytes.decode`` outside any try, a ``__class__``
  answering str passed the str gate and blew the unbound ``str.encode``, and
  a raising ``__class__`` property detonated the gate itself.
* ``POST /api/catalog/native-screen-sharing/uninstall`` — the same probe
  runs after every disable attempt.
* ``POST /api/catalog/native-filebrowser/uninstall`` and
  ``POST /api/catalog/native-homeassistant/uninstall`` — the ``launchctl
  bootout`` scrub in ``_launchctl_unload`` runs ``_as_text`` on both output
  streams before anything guards it.

The fix is the modules9/json9 convention, applied to every catalog launder
twin: type gates go through ``_isinst`` (a raising ``__class__`` answers
False), each unbound base call runs in a try (a raise means "not really this
type", so the impostor degrades like any other junk leftover), and
``catalog_remote._jsonable``'s first gate renders only a genuine
``type(value) is bool`` — a bool-claiming impostor used to be returned raw
into Starlette's ``allow_nan=False`` encoder.  The list launder twins
(``catalog._plain_str_list`` / ``_plain_ports`` / ``native_catalog._port_list``)
copy through ``list(...)`` first, so a list-claiming impostor that is not
iterable costs only itself.

Stays-immune pins ride along: the catalog10 store-overview merge already
drops dict/bool/str-claiming impostor rows (the ``_isinst`` gate plus
``_jsonable``'s base ``dict()`` copy), and the sunny-day controls keep every
pin honest.
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
from hub.routers import catalog as catalog_router  # noqa: E402

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


class _Lie:
    """``__class__`` answers a type the object is not — a claim, not a raise.

    ``isinstance`` (so ``_isinst``) honours the claim, but the real object is
    an ordinary ``_Lie`` — none of the unbound base descriptors apply to it.
    """

    def __init__(self, claim):
        self._claim = claim

    @property
    def __class__(self):  # type: ignore[override]
        return self._claim

    def __hash__(self):  # usable as a mapping key
        return 17


class _ClassBomb:
    """``__class__`` is a raising property: a bare isinstance gate's kryptonite."""

    @property
    def __class__(self):  # noqa: A003
        raise RuntimeError("class bomb")


#: sh() output shapes that each used to be a live raw 500 on the routes below.
_SH_OUTPUT_ZOO = {
    "str-liar": lambda: _Lie(str),
    "bytes-liar": lambda: _Lie(bytes),
    "bytearray-liar": lambda: _Lie(bytearray),
    "class-bomb": _ClassBomb,
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
        catalog.invalidate_listing()
        self.addCleanup(catalog.invalidate_listing)
        for module, name, value in (
            (catalog, "TEMPLATES", self.templates),
            (catalog, "SERVICES_ROOT", self.services),
            (native_catalog, "SERVICES_ROOT", self.services),
            (catalog_remote, "REMOTE_DIR", self.remote_dir),
            (catalog_remote, "STATE_PATH", self.remote_dir / "state.json"),
        ):
            self.stack.enter_context(mock.patch.object(module, name, value))
        self.client = _the_client()

    def _with_sh_output(self, out):
        """Every ``sh``/``_run`` spawn answers rc 0 with *out* as stdout."""
        return mock.patch.multiple(
            native_catalog,
            sh=lambda *a, **k: (0, out, ""),
            run_capped=lambda *a, **k: (1, "brew said no"),
        )

    def _post(self, path: str, body: dict):
        resp = self.client.post(path, json=body)
        # The response body itself must survive Starlette's UTF-8 encode.
        resp.content.decode("utf-8")
        return resp


class NativeOpsShImpostorTests(_NativeOpsSandbox):
    """Impostor launchctl output no longer 500s the native store operations."""

    def test_screen_sharing_install_survives_every_impostor_shape(self):
        for name, make in _SH_OUTPUT_ZOO.items():
            with self.subTest(output=name), self._with_sh_output(make()):
                resp = self._post(
                    "/api/catalog/native-screen-sharing/install",
                    {"confirm": True},
                )
                self.assertEqual(resp.status_code, 200, resp.text[:300])
                body = resp.json()
                # The impostor never renders as "state = running", so the
                # legacy rc==0 probe answers: enabled.
                self.assertIs(body["ok"], True)
                self.assertEqual(body["stack_id"], "native-screen-sharing")

    def test_screen_sharing_uninstall_survives_every_impostor_shape(self):
        for name, make in _SH_OUTPUT_ZOO.items():
            with self.subTest(output=name), self._with_sh_output(make()):
                resp = self._post(
                    "/api/catalog/native-screen-sharing/uninstall",
                    {"confirm": True, "remove_data": False},
                )
                self.assertEqual(resp.status_code, 200, resp.text[:300])
                body = resp.json()
                # Every disable attempt failed and the probe still reads
                # "on", so the honest answer is a clean coded failure body —
                # never a raw 500.
                self.assertIs(body["ok"], False)
                self.assertIn("message", body)

    def test_filebrowser_uninstall_survives_every_impostor_shape(self):
        for name, make in _SH_OUTPUT_ZOO.items():
            with self.subTest(output=name), self._with_sh_output(make()):
                resp = self._post(
                    "/api/catalog/native-filebrowser/uninstall",
                    {"confirm": True, "remove_data": False},
                )
                self.assertEqual(resp.status_code, 200, resp.text[:300])
                body = resp.json()
                # The bootout scrub survives; the install tree is absent.
                self.assertIs(body["ok"], True)
                self.assertIn("not found", body["message"])

    def test_homeassistant_uninstall_survives_every_impostor_shape(self):
        for name, make in _SH_OUTPUT_ZOO.items():
            with self.subTest(output=name), self._with_sh_output(make()):
                resp = self._post(
                    "/api/catalog/native-homeassistant/uninstall",
                    {"confirm": True, "remove_data": False},
                )
                self.assertEqual(resp.status_code, 200, resp.text[:300])
                self.assertIs(resp.json()["ok"], True)

    def test_control_clean_probe_output_still_reads_running(self):
        with self._with_sh_output("state = running"):
            resp = self._post(
                "/api/catalog/native-screen-sharing/install",
                {"confirm": True},
            )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        # The probe reads "state = running", so install reports success.
        self.assertIs(body["ok"], True)
        self.assertTrue(body["message"])


_GOOD_NATIVE = {
    "id": "native-x",
    "name": "X",
    "kind": "native",
    "installed": False,
    "featured": False,
}


class StoreOverviewImpostorRowsStayImmune(_NativeOpsSandbox):
    """The catalog10 merge gates already drop lying-row impostors: pinned."""

    def setUp(self):
        super().setUp()
        (self.templates / "app.yml").write_text(
            "---\nname: App\ndesc: d\n---\nservices:\n  a:\n    image: x\n",
            encoding="utf-8",
        )

    def _store(self, native_rows):
        def fake_list(force=False):
            return native_rows

        with mock.patch.object(native_catalog, "list_native_apps", fake_list):
            catalog.invalidate_listing()
            resp = self.client.get("/api/catalog")
        resp.content.decode("utf-8")
        return resp

    def test_lying_impostor_rows_drop_and_siblings_survive(self):
        for claim in (dict, bool, str, list):
            with self.subTest(claim=claim.__name__):
                resp = self._store([_GOOD_NATIVE, _Lie(claim)])
                self.assertEqual(resp.status_code, 200, resp.text[:300])
                body = resp.json()
                self.assertEqual(body["native_count"], 1)
                self.assertIn("app", [t["id"] for t in body["templates"]])


class AsTextImpostorTests(unittest.TestCase):
    """Every catalog ``_as_text`` twin defuses the impostor class in place."""

    _HELPERS = (
        native_catalog._as_text,
        catalog_router._as_text,
        catalog_remote._as_text,
    )

    def test_bytes_liar_degrades_instead_of_raising(self):
        for helper in self._HELPERS:
            for claim in (bytes, bytearray):
                with self.subTest(helper=helper.__module__, claim=claim.__name__):
                    out = helper(_Lie(claim))
                    self.assertIsInstance(out, str)

    def test_str_liar_never_reaches_the_unbound_encode_raw(self):
        for helper in self._HELPERS:
            with self.subTest(helper=helper.__module__):
                self.assertIsInstance(helper(_Lie(str)), str)

    def test_class_bomb_renders_as_plain_text(self):
        for helper in self._HELPERS:
            with self.subTest(helper=helper.__module__):
                self.assertIsInstance(helper(_ClassBomb()), str)

    def test_controls_stay_byte_exact(self):
        for helper in self._HELPERS:
            with self.subTest(helper=helper.__module__):
                self.assertEqual(helper(b"ok"), "ok")
                self.assertEqual(helper("x\ud800y"), "x?y")
                self.assertEqual(helper(None), "")


class PlainStrAndPortTwinTests(unittest.TestCase):
    """catalog/native list-and-scalar launder twins under the same zoo."""

    def test_plain_str_impostors_degrade_to_default(self):
        for claim in (bytes, bytearray, str):
            with self.subTest(claim=claim.__name__):
                self.assertEqual(catalog._plain_str(_Lie(claim), "d"), "d")
        # A raising ``__class__`` renders as plain repr text, never a raise.
        self.assertIsInstance(catalog._plain_str(_ClassBomb()), str)
        self.assertEqual(catalog._plain_str("x"), "x")

    def test_plain_str_list_list_liar_costs_only_itself(self):
        self.assertEqual(catalog._plain_str_list(_Lie(list)), [])
        self.assertEqual(catalog._plain_str_list(["a", "", "b"]), ["a", "b"])

    def test_plain_ports_impostor_items_drop_and_siblings_survive(self):
        out = catalog._plain_ports([_Lie(bytes), 8080, _Lie(int), "80/tcp"])
        self.assertEqual(out, [8080, "80/tcp"])
        self.assertEqual(catalog._plain_ports(_Lie(list)), [])

    def test_native_port_list_impostor_items_drop_and_siblings_survive(self):
        out = native_catalog._port_list([_Lie(bytes), "8080", _ClassBomb()])
        self.assertEqual(out, ["8080"])
        self.assertEqual(native_catalog._port_list(_Lie(list)), [])
        self.assertEqual(native_catalog._port_list(["1883", b"80"]), ["1883", "80"])


class RemoteJsonableImpostorTests(unittest.TestCase):
    """catalog_remote._jsonable: the json9/modules9 arms, unit-pinned."""

    def test_bool_liar_drops_instead_of_riding_raw(self):
        # bool is final: only a genuine bool may reach Starlette's encoder.
        self.assertIsNone(catalog_remote._jsonable(_Lie(bool)))
        self.assertIs(catalog_remote._jsonable(True), True)
        self.assertIs(catalog_remote._jsonable(False), False)

    def test_container_and_scalar_liars_drop(self):
        for claim in (str, bytes, bytearray, dict, list, tuple, set, frozenset, int):
            with self.subTest(claim=claim.__name__):
                self.assertIsNone(catalog_remote._jsonable(_Lie(claim)))

    def test_lying_key_drops_alone_and_siblings_render(self):
        out = catalog_remote._jsonable(
            {_Lie(bytes): 1, _Lie(str): 2, "keep": "v"}
        )
        self.assertEqual(out, {"keep": "v"})

    def test_class_bomb_degrades_to_text(self):
        self.assertIsInstance(catalog_remote._jsonable(_ClassBomb()), str)

    def test_controls_stay_exact(self):
        payload = {"a": 1, "b": [True, "x", 1.5], b"k": "v"}
        self.assertEqual(
            catalog_remote._jsonable(payload),
            {"a": 1, "b": [True, "x", 1.5], "k": "v"},
        )


class SourceUrlImpostorTests(unittest.TestCase):
    """source_url(): a lying str claim in the stored config cannot raise."""

    def _with_url(self, url):
        return mock.patch(
            "hub.config.settings_section", lambda name: {"url": url}
        )

    def test_str_liar_degrades_to_junk_text(self):
        with self._with_url(_Lie(str)):
            out = catalog_remote.source_url()
        self.assertIsInstance(out, str)

    def test_class_bomb_degrades_to_junk_text(self):
        with self._with_url(_ClassBomb()):
            out = catalog_remote.source_url()
        self.assertIsInstance(out, str)

    def test_exact_str_stays_byte_for_byte_untouched(self):
        # The catalog8 pin: a lone-surrogate URL must keep its coded bad_url
        # refusal, never be laundered into a fetchable replacement-char host.
        raw = "https://e\ud800x.com/i.json"
        with self._with_url(raw):
            self.assertEqual(catalog_remote.source_url(), raw)


if __name__ == "__main__":
    unittest.main()
