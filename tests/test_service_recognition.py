"""Generalized recognition and adoption of auto-discovered services.

Orphan listeners used to surface as ``proc :port`` with a bare port-number
heuristic deciding whether they got a URL, and there was no way to promote one
into a managed entry short of hand-editing services.yaml.  These tests pin the
three pieces that changed that:

  * the signature library recognises well-known daemons by process name
    (strong) or default port (weak hint),
  * the orphan-listener scan applies those signatures to naming and to the
    URL decision — a recognised non-HTTP daemon must never be linked, because
    the probe's ``GET /`` line shows up in its logs as an attack, and
  * adopting an auto item writes a port-checked ``scripts`` entry into the
    config instead of a ``pgrep``-checked ``apps`` one, because the process
    name lsof reports is truncated and the pgrep check would always fail.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import adaptive, config, service_signatures, services_manage_svc  # noqa: E402
from hub.discovery import apps as apps_discovery  # noqa: E402


class IdentifyTests(unittest.TestCase):
    def test_process_name_match_is_high_confidence(self):
        sig = service_signatures.identify("postgres", None)
        self.assertIsNotNone(sig)
        self.assertEqual(sig["name"], "PostgreSQL")
        self.assertEqual(sig["confidence"], "high")
        self.assertIs(sig["http"], False)

    def test_lsof_truncated_process_name_still_matches(self):
        # lsof truncates COMMAND to ~9 chars: "redis-server" reports as
        # "redis-ser".  The signature must match the prefix in both directions.
        sig = service_signatures.identify("redis-ser", 6390)
        self.assertIsNotNone(sig)
        self.assertEqual(sig["slug"], "redis")
        self.assertEqual(sig["confidence"], "high")

    def test_port_only_match_is_low_confidence(self):
        sig = service_signatures.identify("mystery", 5432)
        self.assertIsNotNone(sig)
        self.assertEqual(sig["slug"], "postgres")
        self.assertEqual(sig["confidence"], "low")

    def test_generic_runtime_never_renames(self):
        # "node" identifies the runtime, not the service, so it must not carry
        # high confidence — the orphan scan keeps the raw name for it.
        sig = service_signatures.identify("node", 3999)
        self.assertIsNotNone(sig)
        self.assertEqual(sig["confidence"], "runtime")

    def test_short_token_does_not_swallow_longer_names(self):
        # "nodered" must not match the "node" runtime prefix rule.
        sig = service_signatures.identify("nodered", None)
        self.assertIsNone(sig)

    def test_unknown_process_yields_none(self):
        self.assertIsNone(service_signatures.identify("totally-unknown", 47123))

    def test_suggest_id_slugs_and_deduplicates(self):
        self.assertEqual(service_signatures.suggest_id("Redis Server!"), "redis-server")
        self.assertEqual(
            service_signatures.suggest_id("redis", taken={"redis", "redis-2"}),
            "redis-3",
        )
        self.assertEqual(service_signatures.suggest_id("", "", taken=set()), "service")


class OrphanSignatureTests(unittest.TestCase):
    ROWS = [
        # Redis on a non-default port ≥8000: the old port heuristic linked it.
        {"proc": "redis-ser", "pid": "500", "bind": "127.0.0.1:8079", "port": 8079},
        # Grafana on 3000: recognised web UI.
        {"proc": "grafana", "pid": "501", "bind": "*:3000", "port": 3000},
        # Unknown daemon: behaviour must stay exactly as before.
        {"proc": "mystery", "pid": "502", "bind": "*:8200", "port": 8200},
    ]

    def _orphans(self):
        with patch.object(adaptive, "lsof_listen_snapshot", return_value=self.ROWS), \
                patch.object(adaptive, "host_ip", return_value="192.0.2.10"):
            items = adaptive.discover_orphan_listeners(set(), set())
        return {item["meta"]["port"]: item for item in items}

    def test_recognised_non_http_daemon_gets_no_url(self):
        redis = self._orphans()[8079]
        self.assertIsNone(
            redis["url"],
            "Redis marked http=False must not be linked even on a webish port; "
            "probing it writes SECURITY ATTACK lines into its log",
        )
        self.assertEqual(redis["name"], "Redis :8079")
        self.assertEqual(redis["meta"]["signature"]["slug"], "redis")

    def test_recognised_web_daemon_is_named_and_linked(self):
        grafana = self._orphans()[3000]
        self.assertEqual(grafana["name"], "Grafana :3000")
        self.assertEqual(grafana["url"], "http://192.0.2.10:3000")
        self.assertIn("Grafana", grafana["detail"])

    def test_unknown_daemon_keeps_legacy_behaviour(self):
        mystery = self._orphans()[8200]
        self.assertEqual(mystery["name"], "mystery :8200")
        self.assertEqual(mystery["url"], "http://192.0.2.10:8200")
        self.assertNotIn("signature", mystery["meta"])

    def test_auto_items_offer_adopt(self):
        for item in self._orphans().values():
            self.assertIn("adopt", item["actions"])


def _auto_service(port=8079, sig=True):
    meta = {"port": port, "pid": "500", "process": "redis-ser"}
    if sig:
        meta["signature"] = {
            "slug": "redis", "name": "Redis", "category": "Databases",
            "http": False, "confidence": "high",
        }
    return {
        "id": f"auto.port.{port}", "kind": "auto", "name": f"Redis :{port}",
        "url": None, "meta": meta,
    }


class AdoptTests(unittest.TestCase):
    def _adopt(self, svc, patch_body=None, existing=None):
        """Run adopt_service against an in-memory config; returns (result, data)."""
        data = {"scripts": list(existing or []), "overrides": {svc["id"]: {"hide": True}}}

        def fake_mutate(mutator):
            mutator(data)
            return data

        with patch.object(services_manage_svc, "find_service", return_value=svc), \
                patch.object(services_manage_svc, "_full_process_name", return_value="redis-server"), \
                patch.object(services_manage_svc, "cfg", return_value=data), \
                patch.object(services_manage_svc, "invalidate_status"), \
                patch.object(config, "mutate", side_effect=fake_mutate):
            result = services_manage_svc.adopt_service(svc["id"], patch_body or {})
        return result, data

    def test_adopt_writes_a_port_checked_scripts_entry(self):
        result, data = self._adopt(_auto_service())
        self.assertTrue(result["ok"])
        entry = data["scripts"][0]
        self.assertEqual(entry["id"], "redis")
        self.assertEqual(entry["name"], "Redis")
        self.assertEqual(entry["group"], "Databases")
        self.assertEqual(entry["ports"], [8079])
        self.assertEqual(entry["adopted_from"]["auto_id"], "auto.port.8079")

    def test_adopt_clears_stale_overrides_for_the_auto_id(self):
        # A hide/override keyed on auto.port.NNNN would apply to nothing once
        # the port is claimed by the adopted entry.
        _, data = self._adopt(_auto_service())
        self.assertNotIn("auto.port.8079", data["overrides"])

    def test_adopt_respects_caller_overrides_and_deduplicates_id(self):
        result, data = self._adopt(
            _auto_service(),
            patch_body={"name": "Cache", "group": "Infra", "ports": [8079, 8080]},
            existing=[{"id": "redis", "ports": [6379]}],
        )
        entry = data["scripts"][-1]
        self.assertEqual(result["id"], "redis-2")
        self.assertEqual(entry["name"], "Cache")
        self.assertEqual(entry["group"], "Infra")
        self.assertEqual(entry["ports"], [8079, 8080])

    def test_adopt_unrecognised_service_falls_back_to_process_name(self):
        svc = _auto_service(sig=False)
        with patch.object(services_manage_svc, "find_service", return_value=svc), \
                patch.object(services_manage_svc, "_full_process_name", return_value="mystery-daemon"), \
                patch.object(services_manage_svc, "cfg", return_value={}), \
                patch.object(services_manage_svc, "invalidate_status"), \
                patch.object(config, "mutate", side_effect=lambda m: (m({"scripts": []}), {})[1]):
            result = services_manage_svc.adopt_service(svc["id"], {})
        self.assertEqual(result["id"], "mystery-daemon")
        self.assertEqual(result["entry"]["group"], "Adopted")

    def test_adopt_refuses_non_auto_services(self):
        svc = {"id": "nginx", "kind": "launchd"}
        with patch.object(services_manage_svc, "find_service", return_value=svc):
            with self.assertRaises(HTTPException) as ctx:
                services_manage_svc.adopt_service("nginx", {})
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail["code"], "services.adopt_not_auto")

    def test_adopt_requires_a_valid_port(self):
        svc = _auto_service()
        svc["meta"].pop("port")
        with patch.object(services_manage_svc, "find_service", return_value=svc), \
                patch.object(services_manage_svc, "_full_process_name", return_value=""), \
                patch.object(services_manage_svc, "cfg", return_value={}):
            with self.assertRaises(HTTPException) as ctx:
                services_manage_svc.adopt_service(svc["id"], {"ports": ["nope", 0]})
        self.assertEqual(ctx.exception.detail["code"], "services.adopt_no_port")


class ScriptActionGatingTests(unittest.TestCase):
    """Scripts only advertise the actions the registry can execute.

    An adopted entry has no start/stop commands, and the old collector offered
    Start/Stop buttons for it anyway — every click failed server-side.
    """

    SCRIPTS = [
        {"id": "adopted", "ports": [1]},
        {"id": "managed", "ports": [1], "start": "run.sh", "stop": "kill.sh"},
    ]

    def _collect(self, port_up):
        with patch.object(apps_discovery, "cfg", return_value={"scripts": self.SCRIPTS}), \
                patch.object(apps_discovery, "port_open", return_value=port_up):
            items = apps_discovery.collect_scripts()
        return {item["id"]: item for item in items}

    def test_commandless_script_offers_no_actions(self):
        items = self._collect(port_up=True)
        self.assertEqual(items["adopted"]["actions"], [])
        items = self._collect(port_up=False)
        self.assertEqual(items["adopted"]["actions"], [])

    def test_script_with_commands_keeps_its_actions(self):
        items = self._collect(port_up=True)
        self.assertEqual(items["managed"]["actions"], ["restart", "stop"])
        items = self._collect(port_up=False)
        self.assertEqual(items["managed"]["actions"], ["start"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
