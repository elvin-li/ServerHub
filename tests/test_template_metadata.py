"""Every shipped template must expose its own metadata to the app store.

_parse_template() swallows front-matter YAML errors (`except Exception: pass`)
and falls back to a generated name/desc.  That is the right runtime behaviour --
one malformed template should not take the catalog down -- but it fails
silently, so a template can ship with its entire listing discarded and the only
symptom is a card reading "Compose template foo.yml" in the UI.

Two templates shipped that way for a while: `dockge.yml` and `navidrome.yml`
each had an unquoted `default: {{SERVICES}}` scalar, which YAML reads as a flow
mapping with an unhashable key, so their descriptions, labels and help text
never reached a user.  These tests turn that silent failure into a loud one.
"""
import re
import sys
import unittest
from pathlib import Path

import yaml

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import catalog  # noqa: E402

TEMPLATE_DIR = BASE / "templates"
CJK = re.compile(r"[\u4e00-\u9fff]")


def _template_files():
    return sorted(
        set(TEMPLATE_DIR.glob("*.yml")) | set(TEMPLATE_DIR.glob("*.yaml"))
    )


class TemplateFrontMatter(unittest.TestCase):
    def test_there_are_templates_to_check(self):
        self.assertGreater(len(_template_files()), 20)

    def test_front_matter_parses(self):
        for path in _template_files():
            with self.subTest(template=path.name):
                match = catalog.FM_RE.match(path.read_text(errors="replace"))
                self.assertIsNotNone(
                    match, f"{path.name} has no front-matter document"
                )
                try:
                    meta = yaml.safe_load(match.group(1))
                except Exception as exc:  # noqa: BLE001 - report the real cause
                    self.fail(
                        f"{path.name} front matter is not valid YAML, so the "
                        f"catalog will silently discard its entire listing: {exc}"
                    )
                self.assertIsInstance(meta, dict, path.name)

    def test_placeholders_in_defaults_are_quoted(self):
        # `default: {{HOME}}/Music` parses as a flow mapping, not a string.
        # Quoting is the whole fix, so pin it directly for a clearer failure
        # than the YAML error the previous test would raise.
        bad = []
        for path in _template_files():
            for i, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("default:"):
                    value = stripped.split("default:", 1)[1].strip()
                    if value.startswith("{{"):
                        bad.append(f"{path.name}:{i}: {stripped}")
        self.assertEqual(
            bad, [], "quote these defaults so the front matter stays valid YAML"
        )


class TemplateListing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.items = catalog.list_templates(force=True)

    def test_no_template_falls_back_to_a_generated_description(self):
        generated = [
            t["id"]
            for t in self.items
            if str(t.get("desc", "")).startswith("Compose template ")
        ]
        self.assertEqual(
            generated,
            [],
            "these templates lost their metadata and show a placeholder card",
        )

    def test_every_template_has_a_name_and_description(self):
        for t in self.items:
            with self.subTest(template=t.get("id")):
                self.assertTrue(str(t.get("name") or "").strip())
                self.assertTrue(str(t.get("desc") or "").strip())

    def test_listing_text_is_english(self):
        # The app store is the product's shop window for overseas markets.
        offenders = []
        for t in self.items:
            fields = [t.get("name"), t.get("desc"), t.get("notes")]
            fields += [v.get("label") for v in (t.get("vars") or [])]
            fields += [v.get("help") for v in (t.get("vars") or [])]
            if any(CJK.search(str(f or "")) for f in fields):
                offenders.append(t.get("id"))
        self.assertEqual(offenders, [], "user-visible template text must be English")

    def test_no_template_hardcodes_a_timezone(self):
        # A shipped template carrying the author's own zone puts every overseas
        # install on the wrong clock.  Templates ask for {{TZ}} instead, which
        # resolves to whatever the host is set to.
        offenders = []
        for path in _template_files():
            for i, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
                if re.search(r"(TZ|TIME_ZONE)\s*[=:]\s*\"?[A-Z][A-Za-z_]+/", line):
                    offenders.append(f"{path.name}:{i}: {line.strip()}")
        self.assertEqual(offenders, [], "use {{TZ}} instead of a literal zone")

    def test_declared_variable_defaults_are_expanded(self):
        # A default still carrying {{...}} would be shown verbatim in the
        # install form and written into the deployed compose file.
        leaked = []
        for t in self.items:
            for v in t.get("vars") or []:
                if "{{" in str(v.get("default") or ""):
                    leaked.append(f"{t['id']}.{v['name']}={v['default']}")
        self.assertEqual(leaked, [], "unexpanded placeholder reached the install form")


class HostTimezone(unittest.TestCase):
    def test_returns_an_iana_zone_or_utc(self):
        zone = catalog.host_timezone()
        self.assertTrue(zone)
        self.assertNotIn("zoneinfo", zone)
        self.assertFalse(zone.startswith("/"))

    def test_falls_back_to_utc_when_localtime_is_not_a_symlink(self):
        import os as _os

        real = _os.readlink

        def boom(path):
            raise OSError("not a symlink")

        _os.readlink = boom
        try:
            self.assertEqual(catalog.host_timezone(), "UTC")
        finally:
            _os.readlink = real

    def test_no_template_hardcodes_a_language(self):
        # Same reasoning as the timezone guard: a shipped OCR or UI language
        # list belonging to the author is wrong for every other install.
        offenders = []
        for path in _template_files():
            for i, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
                if re.search(r"(OCR_LANGUAGE|LANGS)\s*=\s*[a-z]{2,}", line):
                    offenders.append(f"{path.name}:{i}: {line.strip()}")
        self.assertEqual(
            offenders, [], "use {{OCR_LANG}} / {{UI_LANGS}} instead of literals"
        )

    def test_tz_is_an_auto_var(self):
        # Auto-vars are hidden from the install form and injected at render
        # time; if TZ were missing here, templates using {{TZ}} would fail with
        # "missing required variable TZ".
        self.assertIn("TZ", catalog.AUTO_VARS)
        self.assertIn("TZ", catalog.auto_var_values())


class HostLanguage(unittest.TestCase):
    def test_language_vars_are_auto_vars(self):
        for name in ("OCR_LANG", "UI_LANGS"):
            self.assertIn(name, catalog.AUTO_VARS)
            self.assertIn(name, catalog.auto_var_values())

    def test_tag_normalisation(self):
        cases = {
            "en-CN": "en",
            "en": "en",
            "zh-Hans-CN": "zh-hans",
            "zh-Hant-TW": "zh-hant",
            "zh-TW": "zh-hant",
            "zh-CN": "zh-hans",
            "zh": "zh-hans",
            "pt-BR": "pt",
            "ja-JP": "ja",
            "": "",
        }
        for tag, expected in cases.items():
            with self.subTest(tag=tag):
                self.assertEqual(catalog._normalise_lang(tag), expected)

    def test_english_is_always_present(self):
        # Dropping the English model wrecks OCR on the latin text present in
        # nearly every document, and English is the UI fallback language.
        self.assertIn("eng", catalog.host_ocr_languages().split("+"))
        self.assertIn("en_GB", catalog.host_ui_languages().split(","))

    def test_preferred_language_comes_first(self):
        self.assertEqual(
            catalog.host_ocr_languages().split("+")[0],
            catalog._LANG_CODES[catalog.host_languages()[0]][0],
        )

    def test_rendering_for_other_hosts(self):
        # The values this machine produces are not the interesting case; a
        # German or English-only host must get sane lists too.
        real = catalog.host_languages
        try:
            catalog.host_languages = lambda: ("en",)
            self.assertEqual(catalog.host_ocr_languages(), "eng")
            self.assertEqual(catalog.host_ui_languages(), "en_GB")

            catalog.host_languages = lambda: ("de", "en")
            self.assertEqual(catalog.host_ocr_languages(), "deu+eng")
            self.assertEqual(catalog.host_ui_languages(), "de_DE,en_GB")

            catalog.host_languages = lambda: ("ja",)
            self.assertEqual(catalog.host_ocr_languages(), "jpn+eng")
        finally:
            catalog.host_languages = real

    def test_unsupported_languages_fall_back_to_english(self):
        # An unmapped tag must not become a request for a nonexistent pack.
        self.assertEqual(catalog._normalise_lang("xx-YY"), "xx")
        self.assertNotIn("xx", catalog._LANG_CODES)
        self.assertTrue(catalog.host_languages())


if __name__ == "__main__":
    unittest.main()
