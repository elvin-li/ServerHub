"""Eighth leftover-500s sweep of the Apps catalog surface.

The live leftover
=================
``catalog_remote.source_url()`` read the stored source with a bare
``str(section.get("url"))``.  YAML *hex/octal* int spellings dodge the
decimal digit-cap loader (``int(x, 16)`` has no cap), so a hand-edited
``settings.catalog_remote.url: 0xfff…`` (4400 hex digits) arrived in the
config as a >4300-digit int whose ``str()`` is CPython's digit-cap
ValueError — reproduced over ``create_app()`` + ``TestClient(
raise_server_exceptions=False)`` as a raw HTTP 500 on **both**
GET /api/catalog/remote and POST /api/catalog/remote/check, until the
operator repaired services.yaml by hand.

The fix routes non-str config values through ``_as_text`` (the
load_yaml_int_capped drop, one value wide): the huge int degrades to "" —
"no source configured" — and every other junk shape (``!!binary``, list,
``.inf``) degrades to text ``validate_source_url`` refuses with its coded
400.  A real *str* is returned untouched, so a lone-surrogate URL keeps its
coded ``catalog_remote.bad_url`` instead of being laundered into a
fetchable replacement-char host.

What else this wave pins (the unbound convention)
=================================================
``catalog_remote._as_text`` / ``_jsonable``, ``catalog._plain_str`` /
``_plain_ports``, ``native_catalog._as_text`` and the catalog router's
``_as_text`` now follow the docker_cli/jobs base-type convention:
``dict(...)`` / ``list(...)`` copies, ``int.__index__`` /
``float.__float__`` coercions, unbound ``str.encode`` / ``bytes.decode``.
A nested subclass whose ``items`` / ``__iter__`` / ``__eq__`` / ``__str__``
/ ``encode`` / ``decode`` bombs now costs only the poisoned value, never
the launderer that was supposed to defuse it.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import catalog, catalog_remote, config, native_catalog  # noqa: E402
from hub.routers import catalog as catalog_router  # noqa: E402

#: Hex spelling dodges the int(str) digit cap at parse time, so this arrives
#: in the config as an int str()/json.dumps cannot render.
_HUGE_HEX = "0x" + "f" * 4400

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


class _CatalogSandbox(unittest.TestCase):
    """Template dir + services root + remote dir in a per-test temp tree."""

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
            (catalog_remote, "REMOTE_DIR", self.remote_dir),
            (catalog_remote, "STATE_PATH", self.remote_dir / "state.json"),
        ):
            self.stack.enter_context(mock.patch.object(module, name, value))
        for name, value in (
            ("browser_authenticated", lambda request: True),
            ("request_username", lambda request: "admin"),
            ("is_admin", lambda username: True),
            ("request_client_id", lambda request: "127.0.0.1"),
        ):
            self.stack.enter_context(
                mock.patch.object(catalog_router.auth, name, value)
            )
        self.client = _the_client()


class _ConfigSandbox(_CatalogSandbox):
    """Save/restore services.yaml so hostile configs stay per-test."""

    def setUp(self):
        super().setUp()
        yaml_path = config.YAML_PATH
        saved = yaml_path.read_bytes() if yaml_path.is_file() else None

        def restore():
            if saved is None:
                try:
                    yaml_path.unlink()
                except OSError:
                    pass
            else:
                yaml_path.write_bytes(saved)
            config.reload_cfg()

        self.addCleanup(restore)
        self.yaml_path = yaml_path

    def write_config(self, text: str) -> None:
        self.yaml_path.parent.mkdir(parents=True, exist_ok=True)
        self.yaml_path.write_text(text, encoding="utf-8")
        config.reload_cfg()


#: Junk ``settings.catalog_remote.url`` shapes an operator hand-edit (or a
#: restored backup) can put in services.yaml.  None of them may 500 — and
#: none may trigger a network fetch: everything is refused before _fetch.
_CONFIG_URL_ZOO = {
    "huge-hex-int": (
        f"settings:\n  catalog_remote:\n    url: {_HUGE_HEX}\n",
        "catalog_remote.not_configured",
    ),
    "huge-octal-int": (
        "settings:\n  catalog_remote:\n    url: 0o" + "7" * 5200 + "\n",
        None,  # PyYAML version-dependent (int or str) — any coded 400 is right
    ),
    "lone-surrogate": (
        'settings:\n  catalog_remote:\n    url: "https://e\\ud800x.com/i.json"\n',
        "catalog_remote.bad_url",
    ),
    "binary-bytes": (
        'settings:\n  catalog_remote:\n    url: !!binary "gIGC"\n',
        "catalog_remote.bad_url",
    ),
    "list-url": (
        "settings:\n  catalog_remote:\n    url: [a, b]\n",
        "catalog_remote.bad_url",
    ),
    "inf-url": (
        "settings:\n  catalog_remote:\n    url: .inf\n",
        "catalog_remote.bad_url",
    ),
    "section-not-a-map": (
        "settings:\n  catalog_remote: [1]\n",
        "catalog_remote.not_configured",
    ),
}


class ConfigUrlZooTests(_ConfigSandbox):
    """A poisoned stored source URL keeps the remote surface coded, not 500."""

    def test_status_and_check_survive_the_config_url_zoo(self):
        for name, (text, want_code) in _CONFIG_URL_ZOO.items():
            with self.subTest(config=name):
                self.write_config(text)
                status = self.client.get("/api/catalog/remote")
                self.assertEqual(status.status_code, 200, status.text[:300])
                status.content.decode("utf-8")
                check = self.client.post("/api/catalog/remote/check")
                self.assertEqual(check.status_code, 400, check.text[:300])
                code = check.json()["detail"]["code"]
                if want_code is not None:
                    self.assertEqual(code, want_code)
                else:
                    self.assertIn(
                        code,
                        ("catalog_remote.bad_url", "catalog_remote.not_configured"),
                    )

    def test_huge_hex_url_reads_as_not_configured(self):
        self.write_config(f"settings:\n  catalog_remote:\n    url: {_HUGE_HEX}\n")
        resp = self.client.get("/api/catalog/remote")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertEqual(body["url"], "")
        self.assertFalse(body["configured"])

    def test_put_still_repairs_a_poisoned_url(self):
        self.write_config(f"settings:\n  catalog_remote:\n    url: {_HUGE_HEX}\n")
        resp = self.client.put("/api/catalog/remote", json={"url": ""})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        after = self.client.get("/api/catalog/remote")
        self.assertEqual(after.status_code, 200, after.text[:300])
        self.assertFalse(after.json()["configured"])


# ── unbound-convention bombs ─────────────────────────────────────────────────


class _SelfStr(str):
    """``str()`` keeps the subclass, so a bound ``.encode`` bomb stays live."""

    def __str__(self):
        return self

    def encode(self, *a, **k):  # noqa: A003
        raise RuntimeError("encode bomb")


class _BoomBytes(bytes):
    def decode(self, *a, **k):
        raise RuntimeError("decode bomb")


class _BoomDict(dict):
    def items(self):
        raise RuntimeError("items bomb")

    def get(self, *a, **k):
        raise RuntimeError("get bomb")

    def __bool__(self):
        raise RuntimeError("bool bomb")


class _BoomList(list):
    def __iter__(self):
        raise RuntimeError("iter bomb")


class _BoomInt(int):
    def __str__(self):
        raise RuntimeError("str bomb")


class _BoomFloat(float):
    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    def __ne__(self, other):
        raise RuntimeError("ne bomb")

    __hash__ = float.__hash__


class _IsoBomb:
    @property
    def isoformat(self):
        raise RuntimeError("property bomb")


class UnboundAsTextTests(unittest.TestCase):
    """Every catalog ``_as_text`` twin defuses self-str / decode bombs."""

    def test_self_str_encode_bomb(self):
        for helper in (
            catalog_remote._as_text,
            native_catalog._as_text,
            catalog_router._as_text,
        ):
            with self.subTest(helper=helper.__module__):
                self.assertEqual(helper(_SelfStr("x\ud800y")), "x?y")

    def test_bytes_subclass_decode_bomb(self):
        for helper in (
            catalog_remote._as_text,
            native_catalog._as_text,
            catalog_router._as_text,
        ):
            with self.subTest(helper=helper.__module__):
                self.assertEqual(helper(_BoomBytes(b"ok")), "ok")

    def test_float_subclass_eq_bomb(self):
        for helper in (
            catalog_remote._as_text,
            native_catalog._as_text,
            catalog_router._as_text,
        ):
            with self.subTest(helper=helper.__module__):
                self.assertEqual(helper(_BoomFloat(1.5)), "1.5")

    def test_huge_int_degrades_to_empty(self):
        huge = int(_HUGE_HEX, 16)
        self.assertEqual(catalog_remote._as_text(huge), "")


class UnboundJsonableTests(unittest.TestCase):
    """catalog_remote._jsonable defuses nested subclass bombs (docker_cli twin)."""

    def test_dict_subclass_items_bomb(self):
        out = catalog_remote._jsonable({"row": _BoomDict({"a": 1})})
        self.assertEqual(out, {"row": {"a": 1}})

    def test_list_subclass_iter_bomb(self):
        out = catalog_remote._jsonable({"rows": _BoomList([1, 2])})
        self.assertEqual(out, {"rows": None})

    def test_int_subclass_str_bomb(self):
        out = catalog_remote._jsonable({"n": _BoomInt(7)})
        self.assertEqual(out, {"n": 7})
        self.assertIs(type(out["n"]), int)

    def test_float_subclass_eq_bomb(self):
        out = catalog_remote._jsonable({"f": _BoomFloat(1.5)})
        self.assertEqual(out, {"f": 1.5})
        self.assertIs(type(out["f"]), float)

    def test_bytes_subclass_decode_bomb(self):
        out = catalog_remote._jsonable({_BoomBytes(b"k"): _BoomBytes(b"v")})
        self.assertEqual(out, {"k": "v"})

    def test_self_str_encode_bomb(self):
        out = catalog_remote._jsonable({"s": _SelfStr("x\ud800")})
        self.assertEqual(out, {"s": "x?"})

    def test_isoformat_property_bomb(self):
        # Degrades to repr text (never raises) — the docker_cli twin's shape.
        out = catalog_remote._jsonable(_IsoBomb())
        self.assertIsInstance(out, str)

    def test_huge_int_drops(self):
        self.assertIsNone(catalog_remote._jsonable(int(_HUGE_HEX, 16)))

    def test_save_state_survives_a_poisoned_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            with mock.patch.object(
                catalog_remote, "REMOTE_DIR", Path(tmp)
            ), mock.patch.object(catalog_remote, "STATE_PATH", state_path):
                catalog_remote._save_state({
                    "templates": _BoomDict({"a": {"version": _BoomInt(3)}}),
                    "last_check": _SelfStr("t\ud800"),
                    "junk": _BoomList([1]),
                })
                written = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertEqual(written["templates"], {"a": {"version": 3}})
        self.assertEqual(written["last_check"], "t?")
        self.assertIsNone(written["junk"])


class PlainStrPortsTests(unittest.TestCase):
    """catalog._plain_str / _plain_ports keep their answers under bombs."""

    def test_plain_str_bombs(self):
        self.assertEqual(catalog._plain_str(_SelfStr("x\ud800")), "x?")
        self.assertEqual(catalog._plain_str(_BoomBytes(b"ok")), "ok")
        self.assertEqual(catalog._plain_str(_BoomFloat(2.5)), "2.5")
        self.assertEqual(catalog._plain_str(float("inf"), "d"), "d")

    def test_plain_ports_bombs(self):
        huge = int(_HUGE_HEX, 16)
        out = catalog._plain_ports(
            [_BoomInt(8080), _BoomFloat(1.5), huge, float("inf"), "80/tcp", None]
        )
        self.assertEqual(out, [8080, "1.5", "80/tcp"])
        self.assertIs(type(out[0]), int)


if __name__ == "__main__":
    unittest.main()
