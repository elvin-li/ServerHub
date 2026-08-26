"""Host6 leftover sweep: disk / scheduler / diagnostics raw-500s over the real app.

A hostile re-sweep of the Host Settings / pmset / identity surfaces over
``create_app()`` + ``TestClient(raise_server_exceptions=False)`` found four
routes still answering raw 500s while their heavily-sanitized siblings
(GET /api/settings/power, /other, /thresholds, /api/identity) already
degraded the identical leftovers:

* **GET /api/settings/disk passed the SMART snapshot through raw.**
  ``get_disk_settings`` sanitized its power-disk *rows* with ``_json_atom``
  but handed ``smart`` (and only ``smart``) straight to Starlette: a
  leftover ``\\ud800`` value, an over-cap plist/YAML hex int, raw non-UTF-8
  bytes, a ``decode()``-bomb bytes subclass or an ``items()``-bomb dict
  subclass inside it each 500'd this route while the *same* data rendered
  fine inside GET /api/settings/system (whose bundle ``_json_tree``'s
  everything).  A power-disk row that is a dict *subclass* with a bombing
  ``.get`` passed the isinstance gate and raised out of the field reads,
  and a ``get_power_info`` result of the same class blew the disksleep
  read one line up.

* **GET /api/settings/scheduler reflected into the timer rows.**
  ``get_scheduler_summary`` gated rows with ``isinstance(t, dict)`` then
  read them with the *bound* ``.get`` — a dict-subclass row bomb raised
  straight out — and every field rode a bare ``or`` chain
  (``t.get("label") or t.get("id") or …``) that dispatched into a
  leftover value's own ``__bool__``.  A timers value that is a list
  subclass whose ``__iter__`` bombs passed the old ``or []`` and blew the
  slice below the try.

* **GET /api/scheduler (the Unraid alias) never sanitized at all.**
  It handed ``launchd_timers()`` rows straight to Starlette while
  GET /api/settings/scheduler slimmed and scrubbed the same data — a
  ``\\ud800`` label or an over-cap interval answered a raw 500 here and a
  200 there.

* **GET /api/diagnostics: the one collector without a try.**
  ``collect_diagnostics`` promises "every section absorbs its own
  failure", and the eleven ``_diag_*`` sections do — but ``_diag_host``
  rode the same ``fan_out`` (whose ``ex.map`` re-raises on iteration)
  with no guard, so a raise out of ``platform_string`` / ``platform.node``
  cost the whole diagnostics bundle instead of one header field.

Also pinned as staying immune: PUT /api/identity over a torn (non-UTF-8)
services.yaml answers the coded ``settings.config_unreadable`` 503 through
``_read_disk_for_mutate`` and leaves the file byte-identical on disk.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import config, identity_svc, system_settings_svc, tools_svc
from hub.app_factory import create_app
from hub.auth import require_auth
from hub.routers import unraid_parity


class GetBomb(dict):
    """Passes ``isinstance(x, dict)``; the bound ``.get`` raises."""

    def get(self, *a, **k):
        raise RuntimeError("get bomb")


class ItemsBomb(dict):
    """Passes ``isinstance(x, dict)``; the bound ``items()`` raises."""

    def items(self):
        raise RuntimeError("items bomb")


class IterBombList(list):
    """Passes ``isinstance(x, list)``; iterating it raises."""

    def __iter__(self):
        raise RuntimeError("iter bomb")


class BoolBomb:
    def __bool__(self):
        raise RuntimeError("bool bomb")


class DecodeBombBytes(bytes):
    def decode(self, *a, **k):
        raise RuntimeError("decode bomb")


#: An already-parsed over-cap int: YAML/plist hex loads uncapped through
#: ``int(x, 16)``, so ``str()`` of it raises the 4300-digit ValueError and
#: json.dumps cannot render it at all.
OVER_CAP_INT = 1 << 20000
SURROGATE = "\ud800leftover"


class _HttpPin(unittest.TestCase):
    def _client(self) -> TestClient:
        app = create_app()
        app.dependency_overrides[require_auth] = lambda: None
        self.addCleanup(app.dependency_overrides.clear)
        return TestClient(app, raise_server_exceptions=False)

    def _ok_body(self, resp) -> dict:
        self.assertEqual(resp.status_code, 200, resp.text[:400])
        body = resp.json()
        # The body Starlette encoded must be re-encodable under the same
        # allow_nan=False / UTF-8 contract it used.
        json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        return body


class DiskSettingsRoutePins(_HttpPin):
    """GET /api/settings/disk: the raw ``smart`` passthrough and row bombs."""

    def _get(self, smart=None, disks=None, power_disks=None, power=None):
        client = self._client()
        with (
            mock.patch.object(
                system_settings_svc, "_storage_snapshot",
                return_value=(smart if smart is not None else {}, disks or []),
            ),
            mock.patch.object(
                system_settings_svc, "_power_disks",
                return_value=power_disks if power_disks is not None else [],
            ),
            mock.patch.object(
                system_settings_svc, "get_power_info",
                return_value=power if power is not None else {},
            ),
        ):
            return client.get("/api/settings/disk")

    def test_smart_surrogate_value_is_scrubbed_not_500(self):
        body = self._ok_body(self._get(smart={"status": SURROGATE, "health": "PASSED"}))
        self.assertEqual(body["smart"]["health"], "PASSED")
        self.assertIn("leftover", body["smart"]["status"])

    def test_smart_over_cap_int_drops_like_inf(self):
        body = self._ok_body(self._get(smart={"temp": OVER_CAP_INT, "health": "PASSED"}))
        self.assertIsNone(body["smart"]["temp"])
        self.assertEqual(body["smart"]["health"], "PASSED")

    def test_smart_items_bomb_subclass_drops_the_node_only(self):
        body = self._ok_body(self._get(smart=ItemsBomb({"health": "PASSED"})))
        # The bombing mapping degrades alone; the healthy siblings survive.
        self.assertIsNone(body["smart"])
        self.assertEqual(body["power_disks"], [])
        self.assertIn("disk_count", body)

    def test_smart_raw_and_decode_bomb_bytes_are_base_decoded(self):
        body = self._ok_body(self._get(smart={
            "raw": b"\xff\xfePASSED",
            "note": DecodeBombBytes(b"ok"),
        }))
        self.assertIn("PASSED", body["smart"]["raw"])
        self.assertEqual(body["smart"]["note"], "ok")

    def test_power_disk_get_bomb_row_is_laundered_not_500(self):
        body = self._ok_body(self._get(power_disks=[
            GetBomb({"id": "disk4", "name": "Media", "power_state": "active", "size_gb": 5}),
        ]))
        # dict(...) laundering keeps the values the bomb was holding.
        self.assertEqual(body["power_disks"][0]["id"], "disk4")
        self.assertEqual(body["power_disks"][0]["name"], "Media")
        self.assertEqual(body["power_disks"][0]["size_gb"], 5)

    def test_power_snapshot_get_bomb_is_laundered_not_500(self):
        body = self._ok_body(self._get(power=GetBomb({"disksleep": 10})))
        self.assertEqual(body["disksleep_minutes"], 10)


class SchedulerSummaryRoutePins(_HttpPin):
    """GET /api/settings/scheduler over timer-row subclass bombs."""

    def _get(self, timers):
        client = self._client()
        with mock.patch.object(tools_svc, "launchd_timers", return_value=timers):
            return client.get("/api/settings/scheduler")

    def test_get_bomb_row_is_laundered_not_500(self):
        body = self._ok_body(self._get([
            GetBomb({"label": "com.example.job", "interval": 300, "path": "/tmp/x.plist"}),
        ]))
        self.assertEqual(body["timers"][0]["label"], "com.example.job")
        self.assertEqual(body["timers"][0]["interval"], 300)
        self.assertEqual(body["count"], 1)

    def test_bool_bomb_label_falls_through_the_or_chain(self):
        body = self._ok_body(self._get([
            {"label": BoolBomb(), "id": "com.example.fallback", "interval": 60},
        ]))
        # The bombing value reads as "not it"; the next key answers.
        self.assertEqual(body["timers"][0]["label"], "com.example.fallback")
        self.assertEqual(body["timers"][0]["interval"], 60)

    def test_iter_bomb_timers_list_degrades_to_the_error_row(self):
        body = self._ok_body(self._get(IterBombList([{"label": "x"}])))
        self.assertEqual(body["timers"], [])
        self.assertEqual(body["count"], 0)
        self.assertIn("error", body)

    def test_over_cap_interval_drops_like_inf(self):
        body = self._ok_body(self._get([
            {"label": "com.example.huge", "interval": OVER_CAP_INT},
        ]))
        self.assertEqual(body["timers"][0]["label"], "com.example.huge")
        self.assertIsNone(body["timers"][0]["interval"])


class SchedulerAliasRoutePins(_HttpPin):
    """GET /api/scheduler (Unraid alias) sanitizes like its settings sibling."""

    def _get(self, timers):
        client = self._client()
        with mock.patch.object(unraid_parity, "launchd_timers", return_value=timers):
            return client.get("/api/scheduler")

    def test_surrogate_label_is_scrubbed_not_500(self):
        body = self._ok_body(self._get([
            {"label": SURROGATE, "interval_sec": 300, "program": "backup.sh"},
        ]))
        self.assertIn("leftover", body["timers"][0]["label"])
        self.assertEqual(body["timers"][0]["program"], "backup.sh")
        self.assertEqual(body["count"], 1)

    def test_over_cap_interval_drops_like_inf(self):
        body = self._ok_body(self._get([
            {"label": "com.example.huge", "interval_sec": OVER_CAP_INT},
        ]))
        self.assertIsNone(body["timers"][0]["interval_sec"])
        self.assertEqual(body["timers"][0]["label"], "com.example.huge")

    def test_non_list_timers_degrade_to_empty(self):
        body = self._ok_body(self._get({"not": "a list"}))
        self.assertEqual(body["timers"], [])
        self.assertEqual(body["count"], 0)

    def test_get_bomb_row_stays_immune(self):
        body = self._ok_body(self._get([GetBomb({"label": "com.example.job"})]))
        self.assertEqual(body["timers"][0]["label"], "com.example.job")


class DiagnosticsHostHeaderPins(_HttpPin):
    """GET /api/diagnostics: the host header absorbs its own failure."""

    def test_platform_string_bomb_costs_one_field_not_the_bundle(self):
        client = self._client()
        with mock.patch.object(
            identity_svc, "platform_string", side_effect=RuntimeError("boom"),
        ):
            body = self._ok_body(client.get("/api/diagnostics"))
        # The header degrades in place; every sibling section still answers.
        self.assertEqual(body["platform"], "")
        self.assertIn("boom", body["host_error"])
        for section in ("identity", "datetime", "power", "management", "other"):
            self.assertIn(section, body)

    def test_platform_node_oserror_does_not_500(self):
        import platform as platform_mod

        client = self._client()
        with mock.patch.object(platform_mod, "node", side_effect=OSError("gone")):
            body = self._ok_body(client.get("/api/diagnostics"))
        self.assertIn("generated_at", body)
        self.assertIn("identity", body)


class IdentityMutateTornYamlStaysImmune(_HttpPin):
    """PUT /api/identity over a torn services.yaml: coded 503, file intact."""

    def test_torn_yaml_answers_coded_503_and_stays_byte_identical(self):
        client = self._client()
        yaml_path = config.YAML_PATH
        original = yaml_path.read_bytes() if yaml_path.exists() else None

        def restore():
            if original is None:
                yaml_path.unlink(missing_ok=True)
            else:
                yaml_path.write_bytes(original)
            config.reload_cfg()

        self.addCleanup(restore)
        torn = b"settings:\n  host_ip: 10.0.0.9\n\xff\xfe torn by power loss"
        yaml_path.parent.mkdir(parents=True, exist_ok=True)
        yaml_path.write_bytes(torn)
        config.reload_cfg()

        resp = client.put("/api/identity", json={"comment": "new comment"})
        self.assertEqual(resp.status_code, 503, resp.text[:400])
        detail = resp.json()["detail"]
        self.assertEqual(detail["code"], "settings.config_unreadable")
        # The file the operator could still fix stays byte-identical.
        self.assertEqual(yaml_path.read_bytes(), torn)


if __name__ == "__main__":
    unittest.main()
