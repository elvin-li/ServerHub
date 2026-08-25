"""Leftover over-digit-cap ints and surrogates on the catalog / Apps surface.

Prior sweeps fixed this class on the settings, health, storage and usage
domains: a >4300-digit leftover int rides a sanitizer whose int branch (or
int passthrough) predates CPython's int->str digit cap, and the ValueError
then fires far from the value's origin — in an f-string, ``str()`` call or
Starlette's ``json.dumps``.  The digit cap only guards *decimal* text, so
YAML's hex/octal int forms (``0xfff…``) mint such ints from any file the
panel parses with ``yaml.safe_load``: a template's front matter, or the
services.yaml overrides block.  This hunt covered the store's survivors:

* **fixed** — ``catalog._plain_ports`` appended an already-int port
  untouched.  A template front matter ``ports: [0xfff…]`` (4000 hex digits)
  then 500'd GET /api/catalog/templates outright — ``str(port_spec)`` in the
  url_hint fallback raises before a single item is returned — and silently
  emptied the docker half of GET /api/catalog (catalog_overview absorbs the
  raise into an empty templates list).  Over-cap ints are now dropped, the
  same rule as the inf float the loop already skips;
* **fixed** — ``apps_manage_svc._field_text`` returned ``str(value)`` bare
  on the int branch.  A services.yaml override ``port: 0xfff…`` reached it
  through ``_launchd_apps`` and 500'd GET /api/apps/managed/detail for every
  launchd app (and cost GET /api/apps/managed whole collector sections,
  absorbed by the fallback);
* **fixed** — ``catalog_remote._jsonable`` and
  ``service_credentials._json_safe`` passed ints through untouched, so a
  poisoned summary / index row ValueError'd Starlette's ``json.dumps`` on
  GET /api/catalog/remote and GET /api/apps/credentials after the handler
  had already succeeded.  Both now drop what ``str()`` cannot render, the
  same rule as their inf float siblings;
* **fixed** — ``catalog._build_listing`` emitted the ``path`` field as a raw
  ``str(dest)`` while every sibling field went through ``_plain_str``.  A
  front-matter ``id`` carrying a lone surrogate (``"\\udc80"`` — exactly the
  range surrogateescape can also mint from on-disk bytes) with a matching
  Services directory then UnicodeEncodeError'd Starlette's UTF-8 encode and
  500'd GET /api/catalog and /api/catalog/templates.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import apps_manage_svc, catalog, catalog_remote, service_credentials  # noqa: E402
from hub.launchd_cache import Listing  # noqa: E402

#: Past CPython's default 4300-digit str<->int conversion limit.
_HUGE_INT = 10 ** 5000
#: The reachable spelling: hex is exempt from the digit cap, so YAML mints
#: the huge int where a decimal literal would already fail to parse.
_HEX_HUGE = "0x" + "f" * 4000


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class YamlHexMintsOverCapIntsPin(unittest.TestCase):
    """The vector: safe_load of a hex scalar is an int str() cannot render."""

    def test_hex_yaml_dodges_the_decimal_digit_cap(self):
        value = yaml.safe_load(_HEX_HUGE)
        self.assertIsInstance(value, int)
        with self.assertRaises(ValueError):
            str(value)


class CatalogPlainPortsDigitPinTests(unittest.TestCase):
    """Every port the listing emits passes through ``_plain_ports``."""

    def test_over_cap_int_port_is_dropped_not_a_500(self):
        self.assertEqual(catalog._plain_ports([_HUGE_INT]), [])
        _starlette({"ports": catalog._plain_ports([_HUGE_INT])})

    def test_sane_ports_still_pass_through(self):
        self.assertEqual(
            catalog._plain_ports([8080, "9090/udp", _HUGE_INT]),
            [8080, "9090/udp"],
        )

    def test_inf_nan_and_junk_still_fall_back(self):
        for port in (float("inf"), float("-inf"), float("nan"), None, "", True):
            with self.subTest(port=str(port)[:12]):
                self.assertEqual(catalog._plain_ports([port]), [])


class _CatalogSandbox(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        tmp = Path(self._tmp.name)
        self.templates = tmp / "templates"
        self.templates.mkdir()
        self.services = tmp / "services"
        self.services.mkdir()
        catalog.invalidate_listing()
        self.addCleanup(catalog.invalidate_listing)
        for target, value in (
            ("TEMPLATES", self.templates),
            ("SERVICES_ROOT", self.services),
        ):
            patched = mock.patch.object(catalog, target, value)
            patched.start()
            self.addCleanup(patched.stop)
        patched = mock.patch.object(
            catalog.catalog_remote, "remote_template_files", return_value=[]
        )
        patched.start()
        self.addCleanup(patched.stop)

    def listing(self) -> list:
        return catalog.list_templates(force=True)


class CatalogListingHexPortPinTests(_CatalogSandbox):
    """GET /api/catalog and /api/catalog/templates with a poisoned template."""

    def test_hex_huge_port_without_url_template_renders(self):
        # No url_template: the url_hint fallback runs str(port_spec) on every
        # port, which is where the raise used to fire — before json.dumps and
        # outside any per-template except, costing the whole listing.
        (self.templates / "poison.yml").write_text(
            f"---\nname: Poison\ndesc: d\nports: [{_HEX_HUGE}]\n---\n"
            "services:\n  a:\n    image: example/a\n"
        )
        items = self.listing()
        self.assertEqual([r["id"] for r in items], ["poison"])
        self.assertEqual(items[0]["ports"], [])
        _starlette(items)

    def test_hex_huge_port_beside_a_sane_one_keeps_the_sane_one(self):
        (self.templates / "poison.yml").write_text(
            f'---\nname: Poison\ndesc: d\nports: [{_HEX_HUGE}, "8080"]\n'
            'url_template: "http://{{HOST_IP}}:8080"\n---\n'
            "services:\n  a:\n    image: example/a\n"
        )
        items = self.listing()
        self.assertEqual(items[0]["ports"], ["8080"])
        _starlette(items)

    def test_catalog_overview_keeps_the_docker_half(self):
        # The raise was absorbed by catalog_overview's try into an *empty*
        # docker list — the store rendered, with every template missing.
        (self.templates / "poison.yml").write_text(
            f"---\nname: Poison\ndesc: d\nports: [{_HEX_HUGE}]\n---\n"
            "services:\n  a:\n    image: example/a\n"
        )
        with mock.patch(
            "hub.native_catalog.list_native_apps", return_value=[]
        ):
            out = catalog.catalog_overview()
        self.assertEqual(out["docker_count"], 1)
        _starlette(out)

    def test_a_sane_template_still_reports_its_ports_and_url(self):
        (self.templates / "ok.yml").write_text(
            '---\nname: Ok\ndesc: d\nports: ["8080"]\n---\n'
            "services:\n  a:\n    image: example/a\n"
        )
        with mock.patch.object(catalog, "host_ip", return_value="192.0.2.9"):
            items = self.listing()
        self.assertEqual(items[0]["ports"], ["8080"])
        self.assertEqual(items[0]["url_hint"], "http://192.0.2.9:8080")


class CatalogListingSurrogatePathPinTests(_CatalogSandbox):
    """The installed ``path`` field is cleaned like every sibling field."""

    def test_surrogate_id_with_installed_dir_renders(self):
        # \udc80 is in the surrogateescape range, so the matching directory
        # really can exist on disk — the id and the path both carried the
        # lone surrogate, and only the path skipped _plain_str.
        (self.templates / "clean.yml").write_text(
            '---\nid: "app\\udc80x"\nname: A\ndesc: d\n---\n'
            "services:\n  a:\n    image: example/a\n"
        )
        dest = self.services / "app\udc80x"
        dest.mkdir()
        (dest / "docker-compose.yml").write_text("services: {}\n")
        items = self.listing()
        self.assertEqual(len(items), 1)
        self.assertTrue(items[0]["installed"])
        self.assertNotIn("\udc80", items[0]["path"] or "")
        _starlette(items)

    def test_a_clean_installed_path_is_still_reported(self):
        (self.templates / "ok.yml").write_text(
            "---\nname: Ok\ndesc: d\n---\nservices:\n  a:\n    image: example/a\n"
        )
        dest = self.services / "ok"
        dest.mkdir()
        (dest / "docker-compose.yml").write_text("services: {}\n")
        items = self.listing()
        self.assertTrue(items[0]["installed"])
        self.assertEqual(items[0]["path"], str(dest))


class FieldTextDigitPinTests(unittest.TestCase):
    """``_field_text`` renders what str() can, and falls back otherwise."""

    def test_over_cap_int_falls_back(self):
        self.assertEqual(apps_manage_svc._field_text(_HUGE_INT, "fb"), "fb")

    def test_optional_text_over_cap_int_is_none(self):
        self.assertIsNone(apps_manage_svc._optional_text(_HUGE_INT))

    def test_sane_numbers_still_render(self):
        self.assertEqual(apps_manage_svc._field_text(8080, ""), "8080")
        self.assertEqual(apps_manage_svc._field_text(2.5, ""), "2.5")


class LaunchdOverridePortDigitPinTests(unittest.TestCase):
    """GET /api/apps/managed/detail walks ``_launchd_apps`` for every row;
    a poisoned services.yaml override must cost one field, not the page."""

    def setUp(self):
        import plistlib

        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        agents = Path(self._tmp.name) / "LaunchAgents"
        agents.mkdir()
        (agents / "com.example.worker.plist").write_bytes(plistlib.dumps({
            "Label": "com.example.worker",
            "ProgramArguments": ["/usr/bin/true"],
        }))
        for patched in (
            mock.patch("hub.paths.AGENTS_DIR", agents),
            mock.patch(
                "hub.launchd_cache.listing", return_value=Listing({})
            ),
            mock.patch(
                "hub.config.override",
                # The exact YAML-hex leftover: name/port/group arrive as an
                # over-cap int instead of text.
                return_value={"name": _HUGE_INT, "port": _HUGE_INT, "group": _HUGE_INT},
            ),
        ):
            patched.start()
            self.addCleanup(patched.stop)

    def test_poisoned_override_renders_the_row(self):
        rows = apps_manage_svc._launchd_apps()
        self.assertEqual([r["source_id"] for r in rows], ["com.example.worker"])
        row = rows[0]
        self.assertEqual(row["name"], "com.example.worker")
        self.assertEqual(row["ports_summary"], "")
        self.assertEqual(row["category"], "other")
        _starlette(rows)


class RemoteAndCredentialsSanitizerDigitPinTests(unittest.TestCase):
    """Both store-adjacent sanitizers drop what json.dumps cannot render."""

    def test_catalog_remote_jsonable_drops_over_cap_ints(self):
        cleaned = catalog_remote._jsonable(
            {"count": _HUGE_INT, "ok": True, "nested": [_HUGE_INT, 7]}
        )
        self.assertEqual(
            cleaned, {"count": None, "ok": True, "nested": [None, 7]}
        )
        _starlette(cleaned)

    def test_service_credentials_json_safe_drops_over_cap_ints(self):
        cleaned = service_credentials._json_safe(
            {"updated_at": _HUGE_INT, "applied": False}
        )
        self.assertEqual(cleaned, {"updated_at": None, "applied": False})
        _starlette(cleaned)

    def test_public_item_with_a_poisoned_stamp_renders(self):
        item = service_credentials.public_item({
            "service_id": "docker:teslamate",
            "display_name": "TeslaMate",
            "username": "admin",
            "updated_at": _HUGE_INT,
        })
        self.assertIsNone(item["updated_at"])
        self.assertEqual(item["username"], "admin")
        _starlette(item)

    def test_sane_ints_still_pass_both(self):
        self.assertEqual(catalog_remote._jsonable({"n": 3}), {"n": 3})
        self.assertEqual(
            service_credentials._json_safe({"updated_at": 1_755_000_000}),
            {"updated_at": 1_755_000_000},
        )


if __name__ == "__main__":
    unittest.main()
