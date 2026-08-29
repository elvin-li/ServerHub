"""Host11 leftover sweep: runner-seam / answer-shape / config-reader bombs on
the host identity and system-settings JSON routes, over the mounted app.

host10 sealed the bool-liar, hash-shadowing-key and rc-``__ne__`` families on
these surfaces.  Re-running the wave-11 bomb zoo against the survivors found
three fresh families of live raw 500s:

* **The spawn seam itself was still bare.**  ``_rc_int`` guarded every rc
  *probe*, but the ``rc, out, err = sh(...)`` unpack one step earlier
  dispatched into the answer's own iteration — a torn two-field tuple, a
  scalar, a tuple subclass whose bound ``__iter__`` bombs, or a runner that
  *raises* instead of answering each 500'd PUT /api/identity and
  POST /api/settings/power outright, and GET /api/identity through the
  future reads (whose ``_result`` catch only covers a raising future, not a
  poisoned answer).  The vms11 ``_sh3``/``_spawn`` rule: junk degrades to
  ``(-255, "", "")`` — nonzero, and never the ``-1`` spawn *sentinel*, so a
  poisoned answer can neither claim success nor forge the vanished-CLI 503,
  which stays reserved for an honest sentinel plus the on-disk confirm.

* **List-subclass inventories detonated past the row laundering.**
  ``get_disk_settings`` laundered each power-disk *row* but sliced and
  counted the *lists* bare: a leftover list subclass whose
  ``__getitem__``/``__len__``/``__iter__`` bombs passed the isinstance
  gates whole and 500'd GET /api/settings/disk on ``power_disks[:20]`` and
  ``len(disks) or len(power_disks)``.  The unbound ``list.__iter__`` copy
  reads the C-level storage, so honest rows in a subclass wrapper survive.

* **Two config readers never got the settings_section guards.**
  ``config.override`` and ``config.panel_locale`` called ``cfg()`` bare and
  ran their unbound ``dict.get`` reads outside any try — a raising snapshot
  provider, or a leftover hash-shadowing "overrides"/"settings"/"ui"/sid
  key detonating the C-level compare, raised out of every per-row services
  read and the cold GET /api/status locale probe.

Stays-immune pins ride along: honest triples (the vanished-spawn sentinel
included) pass ``_sh3`` untouched, the disk-confirmed 503s still fire on an
honest sentinel, and sane configs still answer their stored values.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import config as hub_config
from hub import disk_power_svc, identity_svc, power_svc, system_settings_svc
from hub.auth import require_auth

_APP = None


def _client() -> TestClient:
    global _APP
    if _APP is None:
        from hub.app_factory import create_app

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: None
    # raise_server_exceptions=False: a real 500 must arrive as HTTP 500, not
    # as a re-raised exception that would mask which route crashed.
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _RaisingRunner:
    """A patched ``sh`` that raises instead of answering."""

    def __call__(self, *a, **k):
        raise RuntimeError("runner bomb")


class _IterBombTuple(tuple):
    """An honest 3-tuple underneath; the bound ``__iter__`` raises."""

    def __iter__(self):
        raise RuntimeError("iter bomb")


class _BombList(list):
    """Honest rows underneath; every bound sequence read raises."""

    def __iter__(self):
        raise RuntimeError("iter bomb")

    def __len__(self):
        raise RuntimeError("len bomb")

    def __getitem__(self, item):
        raise RuntimeError("getitem bomb")


class _ClassBomb:
    """A leftover that cannot answer what it is: ``isinstance`` itself raises."""

    @property
    def __class__(self):
        raise RuntimeError("class bomb")


class _BoolBomb:
    """A leftover whose truth test raises — bare ``or`` chains detonate."""

    def __bool__(self):
        raise RuntimeError("bool bomb")


class _ShadowKey(str):
    """A str subclass shadowing another key's hash slot; ``__eq__`` raises."""

    def __new__(cls, shadow: str):
        self = str.__new__(cls, "shadow:" + shadow)
        self._h = hash(shadow)
        return self

    def __hash__(self):
        return self._h

    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    def __ne__(self, other):
        raise RuntimeError("ne bomb")


class _HttpPin(unittest.TestCase):
    def setUp(self):
        self.client = _client()

    def _ok_body(self, resp) -> dict:
        self.assertEqual(resp.status_code, 200, resp.text[:400])
        body = resp.json()
        _starlette(body)
        return body


# ---------------------------------------------------------------------------
# GET /api/identity: answer-shape junk and unowned-provider bombs
# ---------------------------------------------------------------------------


class IdentityGetAnswerShapeTests(_HttpPin):
    """The ex-500s: a patched sh whose *answer* the unpack cannot take."""

    def test_torn_two_field_answer_degrades_every_spawn_field(self):
        with mock.patch.object(identity_svc, "sh", return_value=(1, "")):
            body = self._ok_body(self.client.get("/api/identity"))
        # -255 is never rc 0: the hostname falls back to platform.node()
        # and the scutil fields degrade to empty instead of a 500.
        self.assertIsInstance(body["hostname"], str)
        self.assertEqual(body["computer_name"], "")
        self.assertEqual(body["local_hostname"], "")

    def test_scalar_answer_degrades_the_same_way(self):
        with mock.patch.object(identity_svc, "sh", return_value=7):
            body = self._ok_body(self.client.get("/api/identity"))
        self.assertEqual(body["computer_name"], "")

    def test_iter_bomb_wrapper_still_surrenders_its_honest_answer(self):
        # Stays-immune: the unbound copy reads the C-level storage, so an
        # honest answer riding a subclass wrapper is salvaged, not dropped.
        wrapped = _IterBombTuple((0, "boxy", ""))
        with mock.patch.object(identity_svc, "sh", return_value=wrapped):
            body = self._ok_body(self.client.get("/api/identity"))
        self.assertEqual(body["hostname"], "boxy")
        self.assertEqual(body["computer_name"], "boxy")

    def test_bool_bomb_host_ip_answer_degrades_to_empty(self):
        with mock.patch.object(
            identity_svc, "effective_host_ip", return_value=_BoolBomb(),
        ):
            body = self._ok_body(self.client.get("/api/identity"))
        self.assertEqual(body["host_ip"], "")

    def test_raising_configured_host_costs_only_its_own_field(self):
        with mock.patch.object(
            identity_svc, "configured_host",
            side_effect=RuntimeError("provider bomb"),
        ):
            body = self._ok_body(self.client.get("/api/identity"))
        self.assertEqual(body["host_ip_config"], "")
        self.assertIsInstance(body["hostname"], str)


# ---------------------------------------------------------------------------
# PUT /api/identity: raising runner, and the 503 stays disk-confirmed
# ---------------------------------------------------------------------------


class IdentityPutRunnerSeamTests(_HttpPin):
    def test_raising_runner_answers_the_privileges_branch(self):
        with mock.patch.object(identity_svc, "sh", _RaisingRunner()):
            body = self._ok_body(self.client.put(
                "/api/identity", json={"computer_name": "box"},
            ))
        self.assertIn("administrator privileges", body["message"])

    def test_raising_runner_cannot_forge_the_vanished_scutil_503(self):
        # Junk reads as -255, never the honest -1 sentinel: even with the
        # binary genuinely gone from disk the classifier is never consulted
        # off a runner that could not answer.
        with (
            mock.patch.object(identity_svc, "sh", _RaisingRunner()),
            mock.patch.object(identity_svc, "SCUTIL", "/nonexistent/scutil"),
        ):
            body = self._ok_body(self.client.put(
                "/api/identity", json={"computer_name": "box"},
            ))
        self.assertIn("administrator privileges", body["message"])

    def test_torn_answer_shape_keeps_the_route(self):
        with mock.patch.object(identity_svc, "sh", return_value=("x",)):
            body = self._ok_body(self.client.put(
                "/api/identity", json={"computer_name": "box"},
            ))
        self.assertIn("administrator privileges", body["message"])

    def test_vanished_scutil_503_still_fires_on_the_honest_sentinel(self):
        # The host10 pin re-asserted over the new _spawn seam: an honest
        # (-1, "", "not found") answer plus the on-disk confirm still mints
        # the coded 503 — the laundering must not eat the real sentinel.
        with (
            mock.patch.object(
                identity_svc, "sh", return_value=(-1, "", "not found"),
            ),
            mock.patch.object(identity_svc, "SCUTIL", "/nonexistent/scutil"),
        ):
            resp = self.client.put(
                "/api/identity", json={"computer_name": "box"},
            )
        self.assertEqual(resp.status_code, 503, resp.text[:400])
        self.assertEqual(
            resp.json()["detail"]["code"], "identity.scutil_missing",
        )


# ---------------------------------------------------------------------------
# POST /api/settings/power: the pmset runner seam
# ---------------------------------------------------------------------------


class PowerPrefRunnerSeamTests(_HttpPin):
    def _put(self) -> "TestClient.post":
        return self.client.post(
            "/api/settings/power", json={"key": "sleep", "value": 10},
        )

    def test_raising_runner_answers_ok_false_with_the_manual_hint(self):
        with mock.patch.object(system_settings_svc, "sh", _RaisingRunner()):
            body = self._ok_body(self._put())
        self.assertIs(body["ok"], False)
        self.assertIn("run manually", body["message"])

    def test_torn_answer_shape_answers_ok_false(self):
        with mock.patch.object(system_settings_svc, "sh", return_value=(1,)):
            body = self._ok_body(self._put())
        self.assertIs(body["ok"], False)

    def test_junk_answer_cannot_forge_the_vanished_pmset_503(self):
        # -255 is never the -1 sentinel: with the binary genuinely gone the
        # classifier still refuses to mint the 503 off an unusable answer.
        with (
            mock.patch.object(system_settings_svc, "sh", return_value=7),
            mock.patch.object(power_svc, "PMSET", "/nonexistent/pmset"),
        ):
            body = self._ok_body(self._put())
        self.assertIs(body["ok"], False)

    def test_vanished_pmset_503_still_fires_on_the_honest_sentinel(self):
        with (
            mock.patch.object(
                system_settings_svc, "sh",
                return_value=(-1, "", "not found"),
            ),
            mock.patch.object(power_svc, "PMSET", "/nonexistent/pmset"),
        ):
            resp = self._put()
        self.assertEqual(resp.status_code, 503, resp.text[:400])
        self.assertEqual(
            resp.json()["detail"]["code"], "power.pmset_missing",
        )

    def test_honest_success_still_answers_ok_true(self):
        with mock.patch.object(
            system_settings_svc, "sh", return_value=(0, "", ""),
        ):
            body = self._ok_body(self._put())
        self.assertIs(body["ok"], True)


# ---------------------------------------------------------------------------
# GET /api/settings/disk: list-subclass inventory bombs
# ---------------------------------------------------------------------------


class DiskSettingsListBombTests(_HttpPin):
    def test_bomb_list_wrapper_still_surrenders_its_honest_rows(self):
        rows = _BombList([{"id": "disk4", "name": "Media", "size_gb": 2}])
        with mock.patch.object(
            disk_power_svc, "list_power_disks", return_value=rows,
        ):
            body = self._ok_body(self.client.get("/api/settings/disk"))
        self.assertEqual(body["power_disks"][0]["id"], "disk4")
        self.assertEqual(body["power_disks"][0]["name"], "Media")

    def test_len_bomb_disks_inventory_keeps_the_count(self):
        snapshot = ({}, _BombList([{"x": 1}, {"y": 2}]))
        with mock.patch.object(
            system_settings_svc, "_storage_snapshot", return_value=snapshot,
        ):
            body = self._ok_body(self.client.get("/api/settings/disk"))
        self.assertEqual(body["disk_count"], 2)

    def test_class_bomb_inventory_degrades_to_empty_rows(self):
        with mock.patch.object(
            disk_power_svc, "list_power_disks", return_value=_ClassBomb(),
        ):
            body = self._ok_body(self.client.get("/api/settings/disk"))
        self.assertEqual(body["power_disks"], [])


# ---------------------------------------------------------------------------
# config.override / config.panel_locale: the readers settings_section left out
# ---------------------------------------------------------------------------


class ConfigOverrideReaderTests(unittest.TestCase):
    def test_shadow_overrides_root_key_degrades_to_empty(self):
        with mock.patch.object(
            hub_config, "cfg", return_value={_ShadowKey("overrides"): {}},
        ):
            self.assertEqual(hub_config.override("svc"), {})

    def test_shadow_sid_key_degrades_to_empty(self):
        with mock.patch.object(
            hub_config, "cfg",
            return_value={"overrides": {_ShadowKey("svc"): {"url": "x"}}},
        ):
            self.assertEqual(hub_config.override("svc"), {})

    def test_raising_snapshot_provider_degrades_to_empty(self):
        with mock.patch.object(
            hub_config, "cfg", side_effect=RuntimeError("cfg bomb"),
        ):
            self.assertEqual(hub_config.override("svc"), {})

    def test_sane_override_still_answers_its_stored_copy(self):
        with mock.patch.object(
            hub_config, "cfg",
            return_value={"overrides": {"svc": {"url": "http://x"}}},
        ):
            self.assertEqual(hub_config.override("svc"), {"url": "http://x"})


class ConfigPanelLocaleReaderTests(unittest.TestCase):
    def test_shadow_settings_root_key_answers_the_default(self):
        with mock.patch.object(
            hub_config, "cfg", return_value={_ShadowKey("settings"): {}},
        ):
            self.assertEqual(
                hub_config.panel_locale(), hub_config.DEFAULT_UI_LOCALE,
            )

    def test_shadow_ui_key_answers_the_default(self):
        with mock.patch.object(
            hub_config, "cfg",
            return_value={"settings": {_ShadowKey("ui"): {}}},
        ):
            self.assertEqual(
                hub_config.panel_locale(), hub_config.DEFAULT_UI_LOCALE,
            )

    def test_raising_snapshot_provider_answers_the_default(self):
        with mock.patch.object(
            hub_config, "cfg", side_effect=RuntimeError("cfg bomb"),
        ):
            self.assertEqual(
                hub_config.panel_locale(), hub_config.DEFAULT_UI_LOCALE,
            )

    def test_sane_locale_still_answers_its_stored_value(self):
        with mock.patch.object(
            hub_config, "cfg",
            return_value={"settings": {"ui": {"locale": "en"}}},
        ):
            self.assertEqual(hub_config.panel_locale(), "en")


# ---------------------------------------------------------------------------
# Unit pins on the new seam launders
# ---------------------------------------------------------------------------


class RunnerSeamUnitPins(unittest.TestCase):
    def test_sh3_passes_honest_triples_untouched(self):
        for mod in (identity_svc, system_settings_svc):
            self.assertEqual(mod._sh3((0, "out", "err")), (0, "out", "err"))
            # The vanished-spawn sentinel is an honest answer and survives.
            self.assertEqual(
                mod._sh3((-1, "", "not found")), (-1, "", "not found"),
            )

    def test_sh3_degrades_shape_junk_and_never_the_sentinel(self):
        for mod in (identity_svc, system_settings_svc):
            for junk in ((1, ""), (1, "", "", ""), 7, None, "x", object()):
                self.assertEqual(mod._sh3(junk), (-255, "", ""))

    def test_sh3_salvages_an_honest_answer_in_a_bombed_wrapper(self):
        wrapped = _IterBombTuple((0, "a", "b"))
        for mod in (identity_svc, system_settings_svc):
            self.assertEqual(mod._sh3(wrapped), (0, "a", "b"))

    def test_spawn_reads_a_raising_runner_as_junk_not_the_sentinel(self):
        for mod in (identity_svc, system_settings_svc):
            with mock.patch.object(mod, "sh", _RaisingRunner()):
                self.assertEqual(mod._spawn(["/bin/true"], 3), (-255, "", ""))

    def test_as_list_salvages_rows_from_a_bombed_wrapper(self):
        rows = _BombList([1, 2])
        self.assertEqual(system_settings_svc._as_list(rows), [1, 2])
        self.assertEqual(system_settings_svc._as_list(_ClassBomb()), [])
        self.assertEqual(system_settings_svc._as_list("junk"), [])

    def test_rc_int_junk_never_reads_as_the_sentinel(self):
        self.assertEqual(system_settings_svc._rc_int(_ClassBomb()), -255)
        self.assertEqual(system_settings_svc._rc_int(None), -255)
        self.assertEqual(system_settings_svc._rc_int(-1), -1)
        self.assertEqual(system_settings_svc._rc_int(0), 0)


if __name__ == "__main__":
    unittest.main()
