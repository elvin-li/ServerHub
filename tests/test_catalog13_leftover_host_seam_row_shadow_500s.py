"""Thirteenth leftover-500s sweep of the Apps catalog surface.

The live leftovers
==================
catalog12 sealed the ``sh()`` rc slot and the stored config section; two
seam families were still read raw after it.  Reproduced over
``create_app()`` + ``TestClient(raise_server_exceptions=False)``:

* the **host seam** off the docker half — ``catalog.host_ip`` (a seam this
  module does not own; tests and tooling patch it) was consumed raw by the
  url-hint fallback's f-string in ``_build_listing``, by ``auto_var_values``
  (whose values ``_expand_auto`` calls ``.replace`` on for every template
  default carrying ``{{...}}``, inside ``_parse_template`` whose only guard
  is ``except OSError``), and by install's HOST_IP injection *before* the
  broad rollback try even starts.  A provider that raises — or answers
  bytes, ``None``, or a ``__str__`` bomb — was a raw 500 on
  GET /api/catalog/templates and POST /api/catalog/{id}/install, and
  silently emptied the docker half of GET /api/catalog.  The native install
  branches read the same seam through ``_host_for_url()`` into f-strings
  after the install had already succeeded.

* the **native listing's snapshot shapes** — ``list_native_apps`` read the
  brew-services rows, the installed-package set, the advertised host, the
  launchd label set and the process table raw, and ``fan_out`` re-raises:
  a rows/set ``__bool__`` bomb detonating the ``or`` fallbacks, one row
  with a bare-``isinstance`` class bomb / bound ``.get`` bomb / name
  ``__bool__`` bomb / >4300-digit name, a hash-shadowing member planted in
  the launchd or installed set (same hash, raising ``__eq__``, detonating
  the C-level ``in`` compare), a raising process scan, or a host bomb
  reaching ``_resolve_url``'s bare gate — each emptied the *entire* native
  half of GET /api/catalog instead of costing only itself.

The fixes are the shared conventions: a laundered ``_safe_host_ip`` /
``_host_for_url`` (junk degrades to the same "" an honest empty probe
answers), row-level ``_service_states`` / ``_installed_set`` launderers
(``_isinst`` gates, unbound ``dict.get`` in a try, ``_as_text`` reading the
honest value underneath a subclass override), guarded launchd/process
probes, and ``_resolve_url`` gating its host/hint through the unbound base
encode.  Junk costs only itself; genuine values pass byte-for-byte.
"""
from __future__ import annotations

import shutil
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


class _StrBomb:
    """``str()`` / f-string kryptonite."""

    def __str__(self):
        raise RuntimeError("str bomb")


class _BoolBombStr(str):
    """A str whose truthiness raises — ``or`` / ``if`` kryptonite."""

    def __bool__(self):
        raise RuntimeError("bool bomb")


class _GetBombDict(dict):
    """An honest mapping under a raising bound ``.get`` override."""

    def get(self, *a, **k):  # noqa: D102
        raise RuntimeError("get bomb")


class _ClassBomb:
    """``__class__`` is a raising property: a bare isinstance gate's kryptonite."""

    @property
    def __class__(self):  # noqa: A003
        raise RuntimeError("class bomb")


class _Lie:
    """``__class__`` answers a type the object is not — a claim, not a raise."""

    def __init__(self, claim):
        self._claim = claim

    @property
    def __class__(self):  # type: ignore[override]
        return self._claim

    def __hash__(self):
        return 17


class _KeyLiar(str):
    """Hash-shadows its honest text; the C-level ``in`` compare raises."""

    def __eq__(self, other):
        raise RuntimeError("member eq bomb")

    def __hash__(self):
        return hash(str.__str__(self))


class _RowsBoolBomb(list):
    """A row list whose truthiness raises — the ``or []`` fallback kryptonite."""

    def __bool__(self):
        raise RuntimeError("rows bool bomb")


class _SetBoolBomb(set):
    """An installed set whose truthiness raises — ``or set()`` kryptonite."""

    def __bool__(self):
        raise RuntimeError("set bool bomb")


#: Hex spelling dodges CPython's parse-time digit cap; str() of the value is
#: the ValueError the digit-cap probes must swallow.
_HUGE_INT = int("0x" + "f" * 4400, 16)


#: host-seam shapes that each used to be a live raw 500 (or a silently
#: emptied docker half) on the routes below.
_HOST_ZOO = {
    "raising": mock.Mock(side_effect=RuntimeError("host bomb")),
    "str-bomb": lambda: _StrBomb(),
    "bytes": lambda: b"192.168.1.9",
    "none": lambda: None,
    "huge-int": lambda: _HUGE_INT,
    "surrogate": lambda: "192.168\ud800.9",
    "str-liar": lambda: _Lie(str),
    "bool-bomb": lambda: _BoolBombStr("192.168.1.9"),
}


class _CatalogSandbox(unittest.TestCase):
    """Hermetic catalog trees + no real subprocess spawns."""

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
        # Hermetic native probes: no launchctl / brew / ps spawns.
        self.stack.enter_context(mock.patch.multiple(
            native_catalog,
            sh=lambda *a, **k: (1, "", ""),
            run_capped=lambda *a, **k: (1, "no"),
        ))
        self.client = _the_client()

    def _fresh(self):
        catalog.invalidate_listing()
        native_catalog.list_native_apps.invalidate()

    def _write_demo(self):
        (self.templates / "demo.yml").write_text(
            "---\n"
            "name: Demo\n"
            "desc: demo app\n"
            "ports: [8080]\n"
            "vars:\n"
            "  - name: DATA_DIR\n"
            '    default: "{{SERVICES}}/demo"\n'
            "---\n"
            "services:\n"
            "  demo:\n"
            "    image: demo:latest\n"
            "    ports:\n"
            '      - "8080:80"\n',
            encoding="utf-8",
        )

    def _get(self, path: str):
        resp = self.client.get(path)
        # The response body itself must survive Starlette's UTF-8 encode.
        resp.content.decode("utf-8")
        return resp

    def _post(self, path: str, body: dict):
        resp = self.client.post(path, json=body)
        resp.content.decode("utf-8")
        return resp


class HostSeamDockerRouteTests(_CatalogSandbox):
    """Junk on the host seam no longer 500s the docker catalog routes."""

    def test_templates_route_survives_every_host_shape(self):
        self._write_demo()
        for name, hip in _HOST_ZOO.items():
            with self.subTest(shape=name), \
                    mock.patch.object(catalog, "host_ip", hip):
                self._fresh()
                resp = self._get("/api/catalog/templates")
                self.assertEqual(resp.status_code, 200, resp.text[:300])
                rows = resp.json()["templates"]
                self.assertEqual([r["id"] for r in rows], ["demo"])
                # The auto-var expansion still lands: the default was
                # {{SERVICES}}/demo and SERVICES is not the poisoned seam.
                self.assertEqual(
                    rows[0]["vars"][0]["default"], f"{self.services}/demo"
                )

    def test_overview_keeps_the_docker_half_under_every_host_shape(self):
        self._write_demo()
        for name, hip in _HOST_ZOO.items():
            with self.subTest(shape=name), \
                    mock.patch.object(catalog, "host_ip", hip):
                self._fresh()
                resp = self._get("/api/catalog")
                self.assertEqual(resp.status_code, 200, resp.text[:300])
                self.assertEqual(resp.json()["docker_count"], 1)

    def test_install_survives_every_host_shape(self):
        self._write_demo()
        for name, hip in _HOST_ZOO.items():
            with self.subTest(shape=name), \
                    mock.patch.object(catalog, "host_ip", hip):
                self._fresh()
                shutil.rmtree(self.services / "demo", ignore_errors=True)
                resp = self._post(
                    "/api/catalog/demo/install", {"confirm": True}
                )
                self.assertEqual(resp.status_code, 200, resp.text[:300])
                body = resp.json()
                # No docker CLI in the sandbox: the coded keep-the-files
                # shape, never a raw 500 or a rollback over host junk.
                self.assertIsInstance(body["ok"], bool)
                host = body["variables"]["HOST_IP"]
                self.assertIsInstance(host, str)
                host.encode("utf-8")

    def test_bytes_host_recovers_its_honest_address(self):
        # Decodable bytes are an honest value in a junk wrapper.
        self._write_demo()
        with mock.patch.object(catalog, "host_ip", lambda: b"192.168.1.9"):
            self._fresh()
            shutil.rmtree(self.services / "demo", ignore_errors=True)
            resp = self._post("/api/catalog/demo/install", {"confirm": True})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["variables"]["HOST_IP"], "192.168.1.9")

    def test_control_clean_host_stays_exact(self):
        self._write_demo()
        with mock.patch.object(catalog, "host_ip", lambda: "192.168.9.9"):
            self._fresh()
            resp = self._get("/api/catalog/templates")
            self.assertEqual(resp.status_code, 200, resp.text[:300])
            row = resp.json()["templates"][0]
            self.assertEqual(row["url_hint"], "http://192.168.9.9:8080")
            shutil.rmtree(self.services / "demo", ignore_errors=True)
            self._fresh()
            resp = self._post("/api/catalog/demo/install", {"confirm": True})
            self.assertEqual(resp.status_code, 200, resp.text[:300])
            self.assertEqual(
                resp.json()["variables"]["HOST_IP"], "192.168.9.9"
            )


class NativeRowShadowTests(_CatalogSandbox):
    """One poisoned snapshot shape costs itself, never the native half."""

    def _native_count(self):
        self._fresh()
        resp = self._get("/api/catalog")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        return resp.json()["native_count"]

    def test_every_snapshot_shape_keeps_all_native_rows(self):
        shapes = {
            "rows-bool-bomb": mock.patch.object(
                native_catalog, "brew_services_list",
                lambda: _RowsBoolBomb(),
            ),
            "row-get-bomb": mock.patch.object(
                native_catalog, "brew_services_list",
                lambda: [_GetBombDict(name="x", status="started")],
            ),
            "row-name-bool-bomb": mock.patch.object(
                native_catalog, "brew_services_list",
                lambda: [{"name": _BoolBombStr("x"), "status": "started"}],
            ),
            "row-huge-int-name": mock.patch.object(
                native_catalog, "brew_services_list",
                lambda: [{"name": _HUGE_INT, "status": "started"}],
            ),
            "row-class-bomb": mock.patch.object(
                native_catalog, "brew_services_list",
                lambda: [_ClassBomb()],
            ),
            "rows-dict-liar": mock.patch.object(
                native_catalog, "brew_services_list",
                lambda: [_Lie(dict)],
            ),
            "launchd-hash-shadow": mock.patch.object(
                native_catalog, "launchd_running_labels",
                lambda: frozenset({_KeyLiar("local.filebrowser")}),
            ),
            "launchd-raising": mock.patch.object(
                native_catalog, "launchd_running_labels",
                mock.Mock(side_effect=RuntimeError("launchd bomb")),
            ),
            "process-scan-raising": mock.patch.object(
                native_catalog, "process_matches",
                mock.Mock(side_effect=RuntimeError("ps bomb")),
            ),
            "host-bool-bomb": mock.patch.object(
                native_catalog, "host_ip", lambda: _BoolBombStr("h"),
            ),
            "host-class-bomb": mock.patch.object(
                native_catalog, "host_ip", lambda: _ClassBomb(),
            ),
            "host-str-liar": mock.patch.object(
                native_catalog, "host_ip", lambda: _Lie(str),
            ),
            "installed-set-bool-bomb": mock.patch.object(
                native_catalog, "_brew_list_installed",
                lambda: _SetBoolBomb(),
            ),
            "installed-set-hash-shadow": mock.patch.object(
                native_catalog, "_brew_list_installed",
                lambda: {_KeyLiar("nothing-in-catalog")},
            ),
        }
        for name, patcher in shapes.items():
            with self.subTest(shape=name), patcher:
                self.assertEqual(
                    self._native_count(), len(native_catalog.NATIVE_APPS)
                )

    def test_bomb_row_siblings_keep_their_honest_state(self):
        # The poisoned row drops alone; the honest syncthing row beside it
        # still reads installed + running.
        with mock.patch.object(
            native_catalog, "brew_services_list",
            lambda: [
                _GetBombDict(name="junk", status="junk"),
                {"name": "syncthing", "status": "started"},
            ],
        ), mock.patch.object(
            native_catalog, "_brew_list_installed", lambda: {"syncthing"}
        ):
            self._fresh()
            resp = self._get("/api/catalog")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        rows = resp.json()["templates"]
        row = next(r for r in rows if r.get("id") == "native-syncthing")
        self.assertIs(row["installed"], True)
        self.assertIs(row["running"], True)

    def test_hash_shadow_member_keeps_its_honest_package(self):
        # _installed_set reads the honest text underneath the bomb wrapper,
        # so the package it names still shows as installed.
        with mock.patch.object(
            native_catalog, "_brew_list_installed",
            lambda: {_KeyLiar("syncthing")},
        ):
            self._fresh()
            resp = self._get("/api/catalog")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        rows = resp.json()["templates"]
        row = next(r for r in rows if r.get("id") == "native-syncthing")
        self.assertIs(row["installed"], True)

    def test_control_clean_snapshots_stay_exact(self):
        with mock.patch.object(
            native_catalog, "brew_services_list",
            lambda: [{"name": "syncthing", "status": "Started"}],
        ), mock.patch.object(
            native_catalog, "_brew_list_installed", lambda: {"syncthing"}
        ), mock.patch.object(
            native_catalog, "host_ip", lambda: "192.168.9.9"
        ):
            self._fresh()
            resp = self._get("/api/catalog")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        rows = resp.json()["templates"]
        row = next(r for r in rows if r.get("id") == "native-syncthing")
        self.assertIs(row["installed"], True)
        self.assertIs(row["running"], True)
        self.assertEqual(row["url_hint"], "http://192.168.9.9:8384")


class NativeInstallHostSeamTests(_CatalogSandbox):
    """The install response's URL f-strings survive a poisoned host seam."""

    def test_filebrowser_install_survives_every_host_shape(self):
        agents_dir = self.home / "Library" / "LaunchAgents"
        fb = self.services / "filebrowser"
        fb.mkdir(exist_ok=True)
        (fb / "filebrowser-bin").write_text("#!/bin/sh\n", encoding="utf-8")
        for name, hip in _HOST_ZOO.items():
            with self.subTest(shape=name), \
                    mock.patch.object(native_catalog, "host_ip", hip), \
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
                # the host seam is junk; the URL stays renderable JSON.
                self.assertIs(body["ok"], True)
                self.assertIsInstance(body["url"], str)
                body["url"].encode("utf-8")


class SafeHostIpUnitTests(unittest.TestCase):
    """catalog._safe_host_ip: every poisoned shape, unit-pinned."""

    def test_junk_shapes_degrade_to_empty(self):
        for name, hip in (
            ("raising", mock.Mock(side_effect=RuntimeError("boom"))),
            ("str-bomb", lambda: _StrBomb()),
            ("none", lambda: None),
            ("huge-int", lambda: _HUGE_INT),
            ("str-liar", lambda: _Lie(str)),
            ("class-bomb", lambda: _ClassBomb()),
        ):
            with self.subTest(shape=name), \
                    mock.patch.object(catalog, "host_ip", hip):
                self.assertEqual(catalog._safe_host_ip(), "")

    def test_honest_values_recover(self):
        with mock.patch.object(catalog, "host_ip", lambda: "10.0.0.7"):
            self.assertEqual(catalog._safe_host_ip(), "10.0.0.7")
        with mock.patch.object(catalog, "host_ip", lambda: b"10.0.0.7"):
            self.assertEqual(catalog._safe_host_ip(), "10.0.0.7")
        with mock.patch.object(
            catalog, "host_ip", lambda: "10.0\ud800.7"
        ):
            # Lone surrogate laundered, never a Starlette UTF-8 500.
            self.assertEqual(catalog._safe_host_ip(), "10.0?.7")

    def test_auto_var_values_stay_exact_strs_under_host_bombs(self):
        with mock.patch.object(
            catalog, "host_ip", mock.Mock(side_effect=RuntimeError("boom"))
        ):
            values = catalog.auto_var_values()
        for key, value in values.items():
            self.assertIs(type(value), str, key)
            value.encode("utf-8")
        self.assertEqual(values["HOST_IP"], "")


class ServiceStatesUnitTests(unittest.TestCase):
    """_service_states: junk rows drop alone; honest values recover."""

    def test_poisoned_containers_degrade_to_empty(self):
        for name, rows in (
            ("none", None),
            ("scalar", 7),
            ("rows-bool-bomb-empty", _RowsBoolBomb()),
            ("list-liar", _Lie(list)),
            ("class-bomb", _ClassBomb()),
        ):
            with self.subTest(shape=name):
                self.assertEqual(native_catalog._service_states(rows), {})

    def test_junk_rows_drop_and_siblings_survive(self):
        rows = [
            _ClassBomb(),
            _Lie(dict),
            {"name": _BoolBombStr("x"), "status": "started"},
            {"name": _HUGE_INT, "status": "started"},
            {"name": "syncthing", "status": "Started"},
        ]
        states = native_catalog._service_states(rows)
        self.assertEqual(states.get("syncthing"), "started")
        # The name __bool__ bomb keeps its honest text (identity gates only).
        self.assertEqual(states.get("x"), "started")
        self.assertNotIn("", states)

    def test_get_bomb_row_recovers_its_honest_fields(self):
        # The unbound dict.get reads the C-level storage underneath the
        # override, so the genuine row survives its own poisoned container.
        states = native_catalog._service_states(
            [_GetBombDict(name="redis", status="error")]
        )
        self.assertEqual(states, {"redis": "error"})


class InstalledSetUnitTests(unittest.TestCase):
    """_installed_set: bombs launder to their honest package names."""

    def test_poisoned_containers_degrade_to_empty(self):
        for name, raw in (
            ("none", None),
            ("scalar", "syncthing"),
            ("set-liar", _Lie(set)),
            ("class-bomb", _ClassBomb()),
        ):
            with self.subTest(shape=name):
                self.assertEqual(native_catalog._installed_set(raw), set())

    def test_bomb_members_keep_their_honest_text(self):
        out = native_catalog._installed_set(
            {_KeyLiar("syncthing"), "redis", b"gitea"}
        )
        self.assertEqual(out, {"syncthing", "redis", "gitea"})
        for member in out:
            self.assertIs(type(member), str)

    def test_bool_bomb_set_still_reads_its_members(self):
        out = native_catalog._installed_set(_SetBoolBomb({"redis"}))
        self.assertEqual(out, {"redis"})


class ResolveUrlHostGateTests(unittest.TestCase):
    """_resolve_url gates its host/hint without a bare isinstance."""

    def test_junk_hosts_degrade_to_localhost(self):
        for name, host in (
            ("class-bomb", _ClassBomb()),
            ("bool-bomb", _BoolBombStr("")),
            ("str-liar", _Lie(str)),
            ("none", None),
            ("mapping", {}),
        ):
            with self.subTest(shape=name):
                out = native_catalog._resolve_url(
                    "http://{{HOST}}:8384", host, []
                )
                self.assertEqual(out, "http://localhost:8384")

    def test_surrogate_host_stays_renderable(self):
        out = native_catalog._resolve_url(
            "http://{{HOST}}:8384", "h\ud800st", []
        )
        self.assertEqual(out, "http://h?st:8384")
        out.encode("utf-8")

    def test_control_clean_host_stays_exact(self):
        self.assertEqual(
            native_catalog._resolve_url("http://{{HOST}}:8384", "10.0.0.7", []),
            "http://10.0.0.7:8384",
        )
        self.assertEqual(
            native_catalog._resolve_url("", "10.0.0.7", ["8096"]),
            "http://10.0.0.7:8096",
        )


class HostForUrlUnitTests(unittest.TestCase):
    """native_catalog._host_for_url: seam junk degrades to ""."""

    def test_junk_shapes_degrade_to_empty(self):
        for name, hip in (
            ("raising", mock.Mock(side_effect=RuntimeError("boom"))),
            ("str-bomb", lambda: _StrBomb()),
            ("none", lambda: None),
            ("bytes", lambda: b"10.0.0.7"),
            ("str-liar", lambda: _Lie(str)),
            ("class-bomb", lambda: _ClassBomb()),
        ):
            with self.subTest(shape=name), \
                    mock.patch.object(native_catalog, "host_ip", hip):
                self.assertEqual(native_catalog._host_for_url(), "")

    def test_honest_host_stays_exact(self):
        with mock.patch.object(native_catalog, "host_ip", lambda: "10.0.0.7"):
            self.assertEqual(native_catalog._host_for_url(), "10.0.0.7")


class LaunchdProbeGuardTests(unittest.TestCase):
    """The launchd/process probes read junk as "not running", never raise."""

    def test_hash_shadow_label_falls_through_to_the_process_probe(self):
        with mock.patch.object(
            native_catalog, "launchd_running_labels",
            lambda: frozenset({_KeyLiar("local.filebrowser")}),
        ), mock.patch.object(
            native_catalog, "process_matches", lambda *_a: True
        ):
            self.assertIs(
                native_catalog._launchd_or_process_running(
                    "local.filebrowser", "filebrowser",
                    native_catalog._LaunchdSnapshot(),
                ),
                True,
            )

    def test_raising_scans_read_as_not_running(self):
        with mock.patch.object(
            native_catalog, "launchd_running_labels",
            mock.Mock(side_effect=RuntimeError("launchd bomb")),
        ), mock.patch.object(
            native_catalog, "process_matches",
            mock.Mock(side_effect=RuntimeError("ps bomb")),
        ):
            self.assertIs(
                native_catalog._launchd_or_process_running(
                    "local.filebrowser", "filebrowser",
                    native_catalog._LaunchdSnapshot(),
                ),
                False,
            )

    def test_control_clean_listing_still_reads_running(self):
        with mock.patch.object(
            native_catalog, "launchd_running_labels",
            lambda: frozenset({"local.filebrowser"}),
        ):
            self.assertIs(
                native_catalog._launchd_or_process_running(
                    "local.filebrowser", "filebrowser",
                    native_catalog._LaunchdSnapshot(),
                ),
                True,
            )


if __name__ == "__main__":
    unittest.main()
