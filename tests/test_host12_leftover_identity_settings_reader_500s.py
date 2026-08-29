"""Host12 leftover sweep: saver-seam / config-root / stdlib-probe bombs on the
host identity and system-settings JSON routes, over the mounted app.

host11 sealed the spawn seam (``_sh3``/``_spawn``), the list-subclass
inventories, and the ``override``/``panel_locale`` config readers.  Re-running
the wave-12 bomb zoo against the survivors found four fresh families of live
raw 500s:

* **The settings saver itself was a bare seam on PUT /api/identity.**
  ``set_identity`` called ``update_settings(patch)`` naked: hub.config's own
  failures arrive as coded HTTPExceptions, but a leftover saver that raises a
  *plain* exception 500'd the PUT raw after validation had already passed.
  Honest coded 503s (``settings.save_failed`` / ``settings.config_unreadable``)
  still pass through untouched; anything else launders to the coded save 503,
  and "Panel settings updated" is never claimed off a raise.

* **The post-save refresh 500'd a write that had already landed.**
  ``_save_full_locked`` ran ``reload_cfg()`` bare after the atomic replace, and
  ``reload_cfg`` reads through ``cfg()`` — a snapshot provider that raises
  (the cache does not own it; tests and tooling patch it) blew PUT
  /api/identity and every other ``mutate()`` *after* services.yaml had been
  rewritten, answering an error for a save that succeeded.  The refresh is
  best-effort: the mtime changed, so the next honest ``cfg()`` re-reads anyway.

* **Two config-reader root gates ran a bare isinstance.**
  ``config.settings_section`` and ``system_settings_svc._settings_map``
  guarded the ``cfg()`` *call* but probed its *answer* with bare
  ``isinstance`` — and ``isinstance`` consults ``value.__class__`` when the
  exact-type check misses, so a snapshot root (or stored settings/section
  value) whose ``__class__`` is a raising property detonated the gate itself
  and 500'd GET /api/settings/other and /api/settings/thresholds one step
  ahead of every guard below it.  ``config.override``'s rank gates shared the
  hole.

* **Two stdlib probes and one truth test still ran bare in return dicts.**
  ``get_identity`` called ``platform.machine()`` naked in the ``arch``/
  ``model`` fields (and ``platform.node()`` in the hostname fallback), so a
  raising provider 500'd GET /api/identity while its ``configured_host``
  sibling already degraded per-field.  ``get_datetime_info`` ran ``tz or ""``
  on the time_zone answer — a seam this module does not own — so a leftover
  ``__bool__`` bomb detonated the truth test and 500'd
  GET /api/settings/datetime (the get_identity ``_pick`` rule this route
  never got).

Stays-immune pins ride along: honest saves still answer "Panel settings
updated", the honest coded save 503s still surface, sane configs still answer
their stored values, and the host11 ``_sh3`` sentinel rules hold.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import config as hub_config
from hub import identity_svc, system_settings_svc
from hub.auth import require_auth
from hub.errors import api_error

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


class _BoolBomb:
    """A leftover whose truth test raises — bare ``or`` chains detonate."""

    def __bool__(self):
        raise RuntimeError("bool bomb")


class _ClassBomb:
    """A leftover that cannot answer what it is: ``isinstance`` itself raises."""

    @property
    def __class__(self):
        raise RuntimeError("class bomb")


class _HttpPin(unittest.TestCase):
    def setUp(self):
        self.client = _client()

    def _ok_body(self, resp) -> dict:
        self.assertEqual(resp.status_code, 200, resp.text[:400])
        body = resp.json()
        _starlette(body)
        return body


# ---------------------------------------------------------------------------
# PUT /api/identity: the settings-saver seam
# ---------------------------------------------------------------------------


class IdentityPutSaverSeamTests(_HttpPin):
    def test_raising_saver_answers_the_coded_save_503_not_a_raw_500(self):
        with mock.patch.object(
            identity_svc, "update_settings",
            side_effect=RuntimeError("saver bomb"),
        ):
            resp = self.client.put("/api/identity", json={"comment": "c"})
        self.assertEqual(resp.status_code, 503, resp.text[:400])
        self.assertEqual(
            resp.json()["detail"]["code"], "settings.save_failed",
        )

    def test_honest_coded_save_failure_passes_through_untouched(self):
        # Stays-immune: the laundering must not repaint hub.config's own
        # coded refusals — config_unreadable keeps its code and status.
        with mock.patch.object(
            identity_svc, "update_settings",
            side_effect=api_error("settings.config_unreadable"),
        ):
            resp = self.client.put("/api/identity", json={"comment": "c"})
        self.assertEqual(resp.status_code, 503, resp.text[:400])
        self.assertEqual(
            resp.json()["detail"]["code"], "settings.config_unreadable",
        )

    def test_raise_never_claims_the_panel_settings_updated_message(self):
        with mock.patch.object(
            identity_svc, "update_settings",
            side_effect=RuntimeError("saver bomb"),
        ):
            resp = self.client.put("/api/identity", json={"comment": "c"})
        self.assertNotIn("Panel settings updated", resp.text)

    def test_honest_save_still_answers_updated(self):
        body = self._ok_body(self.client.put(
            "/api/identity", json={"comment": "host12 honest save"},
        ))
        self.assertIs(body["ok"], True)
        self.assertIn("Panel settings updated", body["message"])


# ---------------------------------------------------------------------------
# PUT /api/identity: the post-save refresh must not fail a landed write
# ---------------------------------------------------------------------------


class MutateRefreshSeamTests(_HttpPin):
    def test_raising_snapshot_provider_costs_only_the_refresh(self):
        # The save goes to disk before the cache refresh runs; a provider
        # that raises used to 500 the PUT *after* services.yaml had already
        # been rewritten — an error answered for a write that succeeded.
        with (
            mock.patch.object(
                hub_config, "cfg", side_effect=RuntimeError("cfg bomb"),
            ),
            mock.patch.object(
                identity_svc, "cfg", side_effect=RuntimeError("cfg bomb"),
            ),
        ):
            body = self._ok_body(self.client.put(
                "/api/identity", json={"comment": "host12 refresh seam"},
            ))
        self.assertIs(body["ok"], True)
        self.assertIn("Panel settings updated", body["message"])
        # The write really landed: the on-disk YAML carries the comment.
        self.assertIn(
            "host12 refresh seam", hub_config.YAML_PATH.read_text(),
        )

    def test_next_honest_read_sees_the_saved_value(self):
        self._ok_body(self.client.put(
            "/api/identity", json={"comment": "host12 readback"},
        ))
        body = self._ok_body(self.client.get("/api/identity"))
        self.assertEqual(body["comment"], "host12 readback")

    def test_update_settings_still_returns_the_written_section(self):
        # Unit pin on the guarded refresh: mutate() answers the data it
        # wrote even when the snapshot provider is raising.
        with mock.patch.object(
            hub_config, "cfg", side_effect=RuntimeError("cfg bomb"),
        ):
            written = hub_config.update_settings(
                {"server_comment": "host12 unit"},
            )
        self.assertEqual(written["server_comment"], "host12 unit")


# ---------------------------------------------------------------------------
# GET /api/settings/thresholds and /other: class-bomb config roots
# ---------------------------------------------------------------------------


class ConfigRootClassBombTests(_HttpPin):
    def _bombed_cfg(self, value):
        return (
            mock.patch.object(hub_config, "cfg", return_value=value),
            mock.patch.object(system_settings_svc, "cfg", return_value=value),
        )

    def test_class_bomb_root_answers_default_thresholds(self):
        p1, p2 = self._bombed_cfg(_ClassBomb())
        with p1, p2:
            body = self._ok_body(self.client.get("/api/settings/thresholds"))
        self.assertEqual(body["cpu_pct"], 90)
        self.assertIs(body["enabled"], True)

    def test_class_bomb_root_answers_default_other_settings(self):
        p1, p2 = self._bombed_cfg(_ClassBomb())
        with p1, p2:
            body = self._ok_body(self.client.get("/api/settings/other"))
        self.assertEqual(body["metrics_interval"], 90)
        self.assertIs(body["adaptive"], True)

    def test_class_bomb_settings_block_degrades_the_same_way(self):
        p1, p2 = self._bombed_cfg({"settings": _ClassBomb()})
        with p1, p2:
            body = self._ok_body(self.client.get("/api/settings/thresholds"))
        self.assertEqual(body["disk_pct"], 90)


class SettingsSectionRankGateUnitPins(unittest.TestCase):
    def test_class_bomb_at_every_rank_degrades_to_empty(self):
        for root in (
            _ClassBomb(),
            {"settings": _ClassBomb()},
            {"settings": {"thresholds": _ClassBomb()}},
        ):
            with mock.patch.object(hub_config, "cfg", return_value=root):
                self.assertEqual(
                    hub_config.settings_section("thresholds"), {},
                )

    def test_override_rank_gates_degrade_to_empty(self):
        for root in (
            _ClassBomb(),
            {"overrides": _ClassBomb()},
            {"overrides": {"svc": _ClassBomb()}},
        ):
            with mock.patch.object(hub_config, "cfg", return_value=root):
                self.assertEqual(hub_config.override("svc"), {})

    def test_settings_map_class_bomb_root_degrades_to_empty(self):
        with mock.patch.object(
            system_settings_svc, "cfg", return_value=_ClassBomb(),
        ):
            self.assertEqual(system_settings_svc._settings_map(), {})

    def test_sane_config_still_answers_its_stored_values(self):
        # Stays-immune: the new gates must not eat honest sections.
        with mock.patch.object(
            hub_config, "cfg",
            return_value={"settings": {"thresholds": {"cpu_pct": 55}}},
        ):
            self.assertEqual(
                hub_config.settings_section("thresholds"), {"cpu_pct": 55},
            )
        with mock.patch.object(
            hub_config, "cfg",
            return_value={"overrides": {"svc": {"url": "http://x"}}},
        ):
            self.assertEqual(hub_config.override("svc"), {"url": "http://x"})


# ---------------------------------------------------------------------------
# GET /api/identity: bare stdlib probes in the return dict
# ---------------------------------------------------------------------------


class IdentityPlatformProbeTests(_HttpPin):
    def test_raising_machine_costs_only_its_own_fields(self):
        with mock.patch.object(
            identity_svc.platform, "machine",
            side_effect=RuntimeError("machine bomb"),
        ):
            body = self._ok_body(self.client.get("/api/identity"))
        self.assertEqual(body["arch"], "")
        self.assertIsInstance(body["hostname"], str)

    def test_junk_spawn_plus_raising_node_keeps_the_route(self):
        # Both fallbacks poisoned at once: the hostname spawn answers shape
        # junk (so the node() fallback branch is actually taken) and node()
        # raises — the field degrades to "" instead of a raw 500.
        with (
            mock.patch.object(identity_svc, "sh", return_value=7),
            mock.patch.object(
                identity_svc.platform, "node",
                side_effect=RuntimeError("node bomb"),
            ),
        ):
            body = self._ok_body(self.client.get("/api/identity"))
        self.assertEqual(body["hostname"], "")

    def test_honest_spawn_still_answers_the_hostname(self):
        # Stays-immune (the host11 _sh3 pin re-asserted over the new
        # guards): an honest triple flows through untouched.
        with mock.patch.object(
            identity_svc, "sh", return_value=(0, "boxy", ""),
        ):
            body = self._ok_body(self.client.get("/api/identity"))
        self.assertEqual(body["hostname"], "boxy")


# ---------------------------------------------------------------------------
# GET /api/settings/datetime: the time_zone answer's truth test
# ---------------------------------------------------------------------------


class DatetimeTimezoneSeamTests(_HttpPin):
    def test_bool_bomb_timezone_answer_degrades_to_empty(self):
        with mock.patch.object(
            identity_svc, "time_zone", return_value=_BoolBomb(),
        ):
            body = self._ok_body(self.client.get("/api/settings/datetime"))
        self.assertEqual(body["timezone"], "")
        self.assertIsInstance(body["now"], str)

    def test_raising_timezone_provider_degrades_to_empty(self):
        with mock.patch.object(
            identity_svc, "time_zone",
            side_effect=RuntimeError("tz bomb"),
        ):
            body = self._ok_body(self.client.get("/api/settings/datetime"))
        self.assertEqual(body["timezone"], "")

    def test_honest_timezone_still_flows_through(self):
        with mock.patch.object(
            identity_svc, "time_zone", return_value="Asia/Shanghai",
        ):
            body = self._ok_body(self.client.get("/api/settings/datetime"))
        self.assertEqual(body["timezone"], "Asia/Shanghai")


if __name__ == "__main__":
    unittest.main()
