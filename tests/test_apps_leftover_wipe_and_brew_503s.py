"""Apps-page leftovers: journal wipes, surrogate keys, hex-YAML ids, brew 503s.

Continues test_leftover_catalog_apps_store_500s (render-time 500s) and
test_catalog_cli_missing_leftover_503 (vanished docker/brew on the install
paths) across the *persistence* and *action* paths that still lost data or
answered uncoded shapes:

* **fixed** — ``service_credentials._load`` decoded the index without a
  ``parse_int`` hook.  ``json.loads`` of a >4300-digit number is the digit-cap
  *ValueError* (not JSONDecodeError) for the whole document, so one poisoned
  ``updated_at`` made ``_load`` return ``{}`` — and the very next
  :func:`store`/:func:`delete` rewrote service-credentials.json from that
  empty snapshot, silently wiping every sibling service's index row and
  orphaning its keychain entry;
* **fixed** — the same load kept lone-surrogate KEYS (``json.loads`` happily
  mints one from an escaped ``"\\ud800…"``), and ``_save`` only sanitized row
  *values*.  The surrogate key rode into ``json.dumps(ensure_ascii=False)``
  and the UTF-8 write raised UnicodeEncodeError — swallowed by ``_save``'s
  broad except — so every subsequent save (the row just stored included) was
  a silent no-op on disk while the API reported success;
* **fixed** — ``catalog_remote._load_state`` had the same missing hook: one
  poisoned ``synced`` stamp emptied state.json's in-memory view and the next
  ``_save_state`` dropped the configured source URL and every synced
  template's version/sha records;
* **fixed** — ``catalog_remote._validate_template_text`` probed front-matter
  ``name``/``desc``/``id`` with bare ``str()``.  PyYAML resolves ``0x…`` /
  ``0o…`` scalars through ``int(x, 16)`` / ``int(x, 8)``, which the CPython
  digit cap does not police, so a >4300-digit hex int arrived as a live int
  whose ``str()`` raised — escaping the sync loop and 500'ing the whole
  POST /api/catalog/remote/check instead of rejecting one template;
* **fixed** — ``catalog._build_listing`` gated the front-matter id with a
  strict ``isinstance(tid, str)``: a numeric YAML id (``id: 8080``, the
  unquoted twin of ``id: "8080"``) was silently renamed to the filename
  instead of coercing via a ``str()`` probe (over-cap hex ids keep the stem);
* **fixed** — ``native_catalog._uninstall_native``'s ``brew_formula`` and
  ``brew_multi`` branches spawned brew bare.  A brew that vanished
  mid-request fell into the ``not _is_installed(app)`` fallback — blind
  while ``brew list`` itself is gone — and reported a *successful* uninstall
  of an app that is still fully installed;
* **fixed** — ``apps_manage_svc.action``'s brew ``services start/stop/
  restart`` path handed the uncoded ``{ok: false, message: "not found"}``
  sentinel straight to the SPA instead of the coded 503 every sibling brew
  spawn raises after confirming the binary is really gone from disk.
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

from fastapi import HTTPException  # noqa: E402

from hub import apps_manage_svc, catalog, catalog_remote, native_catalog, service_credentials  # noqa: E402

#: Past CPython's default 4300-digit str<->int conversion limit; hex spelling
#: dodges the cap at parse time, so YAML/JSON really can mint the int.
_HUGE_DIGITS = "9" * 5000
_HEX_HUGE = "0x" + "f" * 4000

#: What hub.util.run_capped reports when the binary is gone (sentinel).
BREW_SENTINEL = {"ok": False, "message": "not found", "rc": -1}


def _detail(ctx) -> dict:
    detail = ctx.exception.detail
    return detail if isinstance(detail, dict) else {"code": str(detail)}


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class HugeJsonIntIsValueErrorPin(unittest.TestCase):
    """The vector: json.loads of the digit run raises ValueError, and it is
    NOT a JSONDecodeError — the except clause that 'only' meant syntax
    errors caught it too, which is how one number cost the whole journal."""

    def test_json_loads_huge_int_is_a_plain_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            json.loads('{"n": %s}' % _HUGE_DIGITS)
        self.assertNotIsInstance(ctx.exception, json.JSONDecodeError)


class CredentialsIndexHugeIntWipeTests(unittest.TestCase):
    """One poisoned number must not empty the credentials journal."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.index = Path(self._tmp.name) / "service-credentials.json"
        patched = mock.patch.object(service_credentials, "INDEX_FILE", self.index)
        patched.start()
        self.addCleanup(patched.stop)

    def test_huge_int_field_keeps_the_sibling_rows(self):
        self.index.write_text(
            '{"immich": {"username": "admin", "updated_at": %s},'
            ' "gitea": {"username": "bob", "updated_at": 1}}' % _HUGE_DIGITS
        )
        loaded = service_credentials._load()
        self.assertEqual(sorted(loaded), ["gitea", "immich"])
        # The poisoned number drops to None; the row survives and renders.
        self.assertIsNone(loaded["immich"]["updated_at"])
        _starlette(loaded)

    def test_the_next_save_no_longer_wipes_the_journal(self):
        self.index.write_text(
            '{"gitea": {"username": "bob", "updated_at": %s}}' % _HUGE_DIGITS
        )
        # The exact store() sequence: items = _load(); items[new] = row; _save.
        items = service_credentials._load()
        items["jellyfin"] = {"username": "carol", "updated_at": 2}
        service_credentials._save(items)
        after = json.loads(self.index.read_text())
        self.assertEqual(sorted(after), ["gitea", "jellyfin"])

    def test_a_sane_index_round_trips_unchanged(self):
        self.index.write_text('{"gitea": {"username": "bob", "updated_at": 7}}')
        loaded = service_credentials._load()
        self.assertEqual(loaded["gitea"]["updated_at"], 7)
        service_credentials._save(loaded)
        self.assertEqual(json.loads(self.index.read_text()), loaded)

    def test_true_garbage_still_reads_as_empty(self):
        self.index.write_text("{not json")
        self.assertEqual(service_credentials._load(), {})


class CredentialsSurrogateKeyTests(unittest.TestCase):
    """Mapping keys are scrubbed before they become lookup keys — and before
    they can poison the next write."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.index = Path(self._tmp.name) / "service-credentials.json"
        patched = mock.patch.object(service_credentials, "INDEX_FILE", self.index)
        patched.start()
        self.addCleanup(patched.stop)

    def test_load_scrubs_the_key_not_just_the_values(self):
        self.index.write_text(
            '{"\\ud800bad": {"username": "x"}, "gitea": {"username": "bob"}}'
        )
        loaded = service_credentials._load()
        for key in loaded:
            self.assertFalse(
                any("\ud800" <= ch <= "\udfff" for ch in key),
                f"surrogate survived into lookup key {key!r}",
            )
        _starlette(loaded)

    def test_save_with_a_surrogate_key_still_persists_every_row(self):
        # Belt and braces for a key minted *after* load: the one bad key must
        # not silently abort the whole write.
        service_credentials._save({
            "\ud800bad": {"username": "x"},
            "gitea": {"username": "bob"},
            "jellyfin": {"username": "carol"},
        })
        after = json.loads(self.index.read_text())
        self.assertIn("gitea", after)
        self.assertIn("jellyfin", after)

    def test_store_sequence_after_a_poisoned_file_reaches_the_disk(self):
        self.index.write_text(
            '{"\\ud800bad": {"username": "x"}, "gitea": {"username": "bob"}}'
        )
        items = service_credentials._load()
        items["jellyfin"] = {"username": "carol"}
        service_credentials._save(items)
        after = json.loads(self.index.read_text())
        self.assertIn("jellyfin", after, "save was silently swallowed")
        self.assertIn("gitea", after)


class RemoteStateHugeIntWipeTests(unittest.TestCase):
    """state.json: one poisoned stamp must not drop the source registration."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        tmp = Path(self._tmp.name)
        self.state = tmp / "state.json"
        for target, value in (("STATE_PATH", self.state), ("REMOTE_DIR", tmp)):
            patched = mock.patch.object(catalog_remote, target, value)
            patched.start()
            self.addCleanup(patched.stop)

    def test_huge_int_stamp_keeps_url_and_templates(self):
        self.state.write_text(
            '{"url": "https://example.com/index.json",'
            ' "templates": {"jellyfin": {"version": "1", "synced": %s}}}'
            % _HUGE_DIGITS
        )
        st = catalog_remote._load_state()
        self.assertEqual(st.get("url"), "https://example.com/index.json")
        self.assertIn("jellyfin", st.get("templates") or {})
        _starlette(st)

    def test_save_after_the_poisoned_read_keeps_the_registry(self):
        self.state.write_text(
            '{"url": "https://example.com/index.json",'
            ' "templates": {"jellyfin": {"version": "1", "synced": %s}}}'
            % _HUGE_DIGITS
        )
        st = catalog_remote._load_state()
        st["last_check"] = "2026-08-25T00:00:00+0000"
        catalog_remote._save_state(st)
        after = json.loads(self.state.read_text())
        self.assertEqual(after.get("url"), "https://example.com/index.json")
        self.assertIn("jellyfin", after.get("templates") or {})

    def test_a_sane_state_still_round_trips(self):
        self.state.write_text('{"url": "https://example.com/i.json", "templates": {}}')
        st = catalog_remote._load_state()
        self.assertEqual(st["url"], "https://example.com/i.json")


class RemoteValidateHexIdTests(unittest.TestCase):
    """POST /api/catalog/remote/check: one hostile template is one rejection,
    never a ValueError that costs the whole sync."""

    BODY = "---\n%s---\nservices:\n  a:\n    image: example/a\n"

    def test_huge_hex_id_is_a_rejection_not_a_500(self):
        text = self.BODY % f"name: X\ndesc: Y\nid: {_HEX_HUGE}\n"
        reason = catalog_remote._validate_template_text(text, expected_id="jellyfin")
        self.assertEqual(reason, "front matter id does not match the manifest id")

    def test_huge_hex_name_is_a_rejection_not_a_500(self):
        text = self.BODY % f"name: {_HEX_HUGE}\ndesc: Y\n"
        self.assertEqual(
            catalog_remote._validate_template_text(text),
            "front matter lacks a name",
        )

    def test_huge_hex_desc_is_a_rejection_not_a_500(self):
        text = self.BODY % f"name: X\ndesc: {_HEX_HUGE}\n"
        self.assertEqual(
            catalog_remote._validate_template_text(text),
            "front matter lacks a desc",
        )

    def test_a_numeric_id_matching_the_manifest_still_passes(self):
        # str() probe, not isinstance gate: `id: 2024` for manifest id "2024".
        text = self.BODY % "name: X\ndesc: Y\nid: 2024\n"
        self.assertEqual(
            catalog_remote._validate_template_text(text, expected_id="2024"), ""
        )

    def test_a_clean_template_still_validates(self):
        text = self.BODY % "name: X\ndesc: Y\nid: jellyfin\n"
        self.assertEqual(
            catalog_remote._validate_template_text(text, expected_id="jellyfin"), ""
        )


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


class CatalogNumericIdProbeTests(_CatalogSandbox):
    """`id: 8080` behaves like `id: "8080"` — str() probe, not isinstance."""

    BODY = "services:\n  a:\n    image: example/a\n"

    def test_numeric_front_matter_id_coerces_to_its_string(self):
        (self.templates / "nginx.yml").write_text(
            f"---\nid: 8080\nname: N\ndesc: d\n---\n{self.BODY}"
        )
        items = self.listing()
        self.assertEqual([r["id"] for r in items], ["8080"])
        _starlette(items)

    def test_quoted_and_unquoted_numeric_ids_agree(self):
        (self.templates / "a.yml").write_text(
            f"---\nid: 2024\nname: A\ndesc: d\n---\n{self.BODY}"
        )
        (self.templates / "b.yml").write_text(
            f'---\nid: "2024"\nname: B\ndesc: d\n---\n{self.BODY}'
        )
        ids = {r["id"] for r in self.listing()}
        self.assertEqual(ids, {"2024"})

    def test_over_cap_hex_id_keeps_the_stem_not_a_500(self):
        (self.templates / "poison.yml").write_text(
            f"---\nid: {_HEX_HUGE}\nname: P\ndesc: d\n---\n{self.BODY}"
        )
        items = self.listing()
        self.assertEqual([r["id"] for r in items], ["poison"])
        _starlette(items)

    def test_bool_and_null_ids_keep_the_stem(self):
        (self.templates / "flagged.yml").write_text(
            f"---\nid: true\nname: F\ndesc: d\n---\n{self.BODY}"
        )
        (self.templates / "empty.yml").write_text(
            f"---\nid:\nname: E\ndesc: d\n---\n{self.BODY}"
        )
        ids = sorted(r["id"] for r in self.listing())
        self.assertEqual(ids, ["empty", "flagged"])

    def test_a_string_id_is_still_honoured(self):
        (self.templates / "file.yml").write_text(
            f"---\nid: custom\nname: C\ndesc: d\n---\n{self.BODY}"
        )
        self.assertEqual([r["id"] for r in self.listing()], ["custom"])


class NativeUninstallBrewVanishedTests(unittest.TestCase):
    """_uninstall_native: brew_formula / brew_multi spawns carry the same
    coded 503 as _run_brew, only after the filesystem confirms brew is gone."""

    def _uninstall(self, app, *, is_file, run=None, installed=True):
        with (
            mock.patch.object(
                native_catalog, "_run", run or mock.Mock(return_value=dict(BREW_SENTINEL))
            ),
            mock.patch.object(native_catalog, "_is_file", is_file),
            mock.patch.object(native_catalog, "_is_installed", return_value=installed),
        ):
            return native_catalog._uninstall_native(app, app["id"])

    FORMULA = {"id": "native-x", "method": "brew_formula", "package": "xpkg",
               "service": True}
    MULTI = {"id": "native-y", "method": "brew_multi", "packages": ["p1", "p2"]}

    def test_formula_uninstall_raises_the_coded_503(self):
        with self.assertRaises(HTTPException) as ctx:
            self._uninstall(self.FORMULA, is_file=mock.Mock(return_value=False))
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_detail(ctx)["code"], "catalog.brew_missing")

    def test_multi_uninstall_raises_instead_of_fake_success(self):
        # Pre-fix this reported ok=True ("this app is gone") because
        # _is_installed cannot see a formula while brew itself is missing.
        with self.assertRaises(HTTPException) as ctx:
            self._uninstall(
                self.MULTI, is_file=mock.Mock(return_value=False), installed=False
            )
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_detail(ctx)["code"], "catalog.brew_missing")

    def test_sentinel_while_brew_is_still_present_keeps_the_raw_result(self):
        r = self._uninstall(
            self.FORMULA, is_file=mock.Mock(return_value=True), installed=True
        )
        self.assertEqual(r["ok"], False)
        self.assertIn("not found", r["message"])

    def test_a_real_brew_failure_keeps_its_output(self):
        run = mock.Mock(return_value={
            "ok": False, "message": "Error: xpkg is not installed", "rc": 1,
        })
        checker = mock.Mock(return_value=False)
        r = self._uninstall(self.FORMULA, is_file=checker, run=run, installed=True)
        self.assertIn("not installed", r["message"])
        # A real exit is not the sentinel: the filesystem is never consulted.
        checker.assert_not_called()

    def test_a_successful_uninstall_still_reports_ok(self):
        run = mock.Mock(return_value={"ok": True, "message": "Uninstalled xpkg", "rc": 0})
        r = self._uninstall(
            self.MULTI, is_file=mock.Mock(return_value=True), run=run, installed=False
        )
        self.assertTrue(r["ok"])


class AppsActionBrewVanishedTests(unittest.TestCase):
    """POST /api/apps/managed/action for a brew formula: start/stop/restart
    answer the coded 503, not the uncoded two-word sentinel."""

    APP = {"id": "native-x", "method": "brew_formula", "package": "xpkg"}

    def _action(self, name, *, is_file, run=None):
        with (
            mock.patch.object(native_catalog, "NATIVE_APPS", [dict(self.APP)]),
            mock.patch.object(
                native_catalog, "_run", run or mock.Mock(return_value=dict(BREW_SENTINEL))
            ),
            mock.patch.object(native_catalog, "_is_file", is_file),
            mock.patch.object(apps_manage_svc, "invalidate_inventory", lambda: None),
        ):
            return apps_manage_svc.action("native-x", name)

    def test_start_stop_restart_raise_the_coded_503(self):
        for name in ("start", "stop", "restart"):
            with self.subTest(action=name):
                with self.assertRaises(HTTPException) as ctx:
                    self._action(name, is_file=mock.Mock(return_value=False))
                self.assertEqual(ctx.exception.status_code, 503)
                self.assertEqual(_detail(ctx)["code"], "catalog.brew_missing")

    def test_sentinel_while_brew_is_still_present_keeps_the_dict(self):
        r = self._action("stop", is_file=mock.Mock(return_value=True))
        self.assertEqual(r["ok"], False)
        self.assertEqual(r["message"], "not found")

    def test_a_real_brew_exit_stays_raw(self):
        run = mock.Mock(return_value={
            "ok": False, "message": "Error: xpkg has no service", "rc": 1,
        })
        checker = mock.Mock(return_value=False)
        r = self._action("stop", is_file=checker, run=run)
        self.assertIn("no service", r["message"])
        checker.assert_not_called()

    def test_a_successful_action_still_reports_ok(self):
        run = mock.Mock(return_value={
            "ok": True, "message": "Successfully started `xpkg`", "rc": 0,
        })
        r = self._action("start", is_file=mock.Mock(return_value=True), run=run)
        self.assertTrue(r["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
