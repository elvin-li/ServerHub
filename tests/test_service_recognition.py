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

    def test_lsof_hex_escape_in_process_name_is_unescaped(self):
        # macOS lsof encodes a space in COMMAND as \x20 (the field cannot
        # contain a literal space).  "Plex Media Server" therefore arrives as
        # "Plex\x20M" after the usual ~9-char truncation.
        self.assertEqual(service_signatures.unescape_proc_name(r"Plex\x20M"), "Plex M")
        self.assertEqual(service_signatures.unescape_proc_name(r"Plex\040T"), "Plex T")
        self.assertEqual(service_signatures.unescape_proc_name("redis-ser"), "redis-ser")

    def test_escaped_process_name_still_port_matches(self):
        sig = service_signatures.identify(r"Plex\x20M", 32400)
        self.assertIsNotNone(sig)
        self.assertEqual(sig["slug"], "plex")
        self.assertEqual(sig["confidence"], "low")

    def test_suggest_id_slugs_and_deduplicates(self):
        self.assertEqual(service_signatures.suggest_id("Redis Server!"), "redis-server")
        self.assertEqual(
            service_signatures.suggest_id("redis", taken={"redis", "redis-2"}),
            "redis-3",
        )
        self.assertEqual(service_signatures.suggest_id("", "", taken=set()), "service")

    def test_operator_signature_overrides_builtin_slug(self):
        extras = [service_signatures.parse_signature({
            "slug": "redis", "name": "Cache", "category": "Infra",
            "procs": ["redis-ser"], "http": True, "brew": "my-redis",
        })]
        sig = service_signatures.identify("redis-ser", 6379, extras=extras)
        self.assertEqual(sig["name"], "Cache")
        self.assertEqual(sig["category"], "Infra")
        self.assertIs(sig["http"], True)
        self.assertEqual(sig["brew"], "my-redis")

    def test_operator_signature_matches_unknown_process(self):
        extras = [service_signatures.parse_signature({
            "slug": "my-api", "name": "My API", "category": "Apps",
            "procs": ["uvicorn"], "ports": [8100], "http": True,
        })]
        sig = service_signatures.identify("uvicorn", 8100, extras=extras)
        self.assertEqual(sig["slug"], "my-api")
        self.assertEqual(sig["confidence"], "high")

    def test_image_basename_strips_registry_tag_and_digest(self):
        self.assertEqual(service_signatures.image_basename("grafana/grafana:latest"), "grafana")
        self.assertEqual(service_signatures.image_basename("redis:7"), "redis")
        self.assertEqual(
            service_signatures.image_basename("ghcr.io/foo/uptime-kuma@sha256:abc"),
            "uptime-kuma",
        )
        self.assertEqual(service_signatures.image_basename("sha256:deadbeef"), "")

    def test_image_match_is_high_confidence(self):
        sig = service_signatures.identify(image="grafana/grafana:11")
        self.assertEqual(sig["slug"], "grafana")
        self.assertEqual(sig["confidence"], "high")

    def test_image_matches_slug_when_procs_empty(self):
        # uptime-kuma has no process tokens; the image name is the identity.
        sig = service_signatures.identify(image="louislam/uptime-kuma:latest")
        self.assertEqual(sig["slug"], "uptime-kuma")
        self.assertEqual(sig["confidence"], "high")

    def test_runtime_image_stays_a_runtime_hint(self):
        sig = service_signatures.identify(image="python:3.12")
        self.assertEqual(sig["confidence"], "runtime")

    def test_parse_signature_tolerates_non_list_procs_and_ports(self):
        sig = service_signatures.parse_signature({
            "slug": "x", "procs": 1, "ports": 8080,
        })
        self.assertIsNotNone(sig)
        self.assertEqual(sig["procs"], ())
        self.assertEqual(sig["ports"], ())

    def test_parse_signature_rejects_option_shaped_brew(self):
        sig = service_signatures.parse_signature({
            "slug": "x", "procs": ["x"], "brew": "--all",
        })
        self.assertIsNotNone(sig)
        self.assertIsNone(sig["brew"])

    def test_brew_formula_from_cellar_and_opt_paths(self):
        self.assertEqual(
            service_signatures.brew_formula_from_path(
                "/opt/homebrew/opt/postgresql@17/bin/postgres"
            ),
            "postgresql@17",
        )
        self.assertEqual(
            service_signatures.brew_formula_from_path(
                "/usr/local/Cellar/redis/7.2.4/bin/redis-server"
            ),
            "redis",
        )
        self.assertIsNone(service_signatures.brew_formula_from_path("/usr/bin/redis-server"))

    def test_infer_control_prefers_path_over_signature_brew(self):
        sig = {"confidence": "high", "brew": "postgresql"}
        ctrl = service_signatures.infer_control(
            sig, "/opt/homebrew/opt/postgresql@17/bin/postgres"
        )
        self.assertEqual(ctrl["formula"], "postgresql@17")
        self.assertIn("services start postgresql@17", ctrl["start"])
        self.assertIn("services stop postgresql@17", ctrl["stop"])

    def test_infer_control_uses_signature_brew_without_a_path(self):
        ctrl = service_signatures.infer_control(
            {"confidence": "high", "brew": "redis"}, ""
        )
        self.assertEqual(ctrl["formula"], "redis")
        self.assertTrue(ctrl["start"].endswith("services start redis"))


class OrphanSignatureTests(unittest.TestCase):
    ROWS = [
        # Redis on a non-default port ≥8000: the old port heuristic linked it.
        {"proc": "redis-ser", "pid": "500", "bind": "127.0.0.1:8079", "port": 8079},
        # Grafana on 3000: recognised web UI.
        {"proc": "grafana", "pid": "501", "bind": "*:3000", "port": 3000},
        # Unknown daemon: behaviour must stay exactly as before.
        {"proc": "mystery", "pid": "502", "bind": "*:8200", "port": 8200},
    ]

    def _orphans(self, rows=None):
        with patch.object(adaptive, "lsof_listen_snapshot", return_value=rows or self.ROWS), \
                patch.object(adaptive, "host_ip", return_value="192.0.2.10"), \
                patch.object(adaptive, "configured_signatures", return_value=[]):
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

    def test_same_pid_ports_collapse_to_one_item(self):
        rows = [
            {"proc": "redis-ser", "pid": "500", "bind": "127.0.0.1:6379", "port": 6379},
            {"proc": "redis-ser", "pid": "500", "bind": "127.0.0.1:6380", "port": 6380},
        ]
        items = self._orphans(rows)
        self.assertEqual(list(items), [6379])
        redis = items[6379]
        self.assertEqual(redis["ports"], [6379, 6380])
        self.assertEqual(redis["name"], "Redis :6379 :6380")
        self.assertIsNone(redis["url"])
        self.assertEqual(redis["id"], "auto.port.6379")

    def test_hex_escaped_lsof_name_is_shown_unescaped(self):
        # Captured shape: lsof COMMAND for "Plex Media Server" is Plex\x20M.
        rows = [
            {"proc": r"Plex\x20M", "pid": "900", "bind": "*:32400", "port": 32400},
            {"proc": r"Plex\x20M", "pid": "900", "bind": "*:32401", "port": 32401},
            {"proc": r"Plex\x20T", "pid": "901", "bind": "*:32600", "port": 32600},
        ]
        items = self._orphans(rows)
        plex = items[32400]
        self.assertEqual(plex["name"], "Plex M :32400 :32401")
        self.assertNotIn(r"\x20", plex["name"])
        self.assertEqual(plex["meta"]["process"], "Plex M")
        self.assertEqual(items[32600]["name"], "Plex T :32600")

    def test_parse_lsof_unescapes_command_field(self):
        line = (
            r"Plex\x20M   900 exampleuser   13u  IPv4 0xabc      0t0  "
            "TCP *:32400 (LISTEN)"
        )
        rows = adaptive._parse_lsof_listen("COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n" + line)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["proc"], "Plex M")
        self.assertEqual(rows[0]["port"], 32400)


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
    def _adopt(self, svc, patch_body=None, existing=None, process="redis-server", signatures=None):
        """Run adopt_service against an in-memory config; returns (result, data)."""
        data = {
            "scripts": list(existing or []),
            "overrides": {svc["id"]: {"hide": True}},
        }
        if signatures is not None:
            data["service_signatures"] = list(signatures)

        def fake_mutate(mutator):
            mutator(data)
            return data

        with patch.object(services_manage_svc, "find_service", return_value=svc), \
                patch.object(services_manage_svc, "_full_process_name", return_value=process), \
                patch.object(services_manage_svc, "_process_command_path", return_value=""), \
                patch.object(services_manage_svc, "configured_signatures", return_value=[]), \
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
        self.assertTrue(entry["start"].endswith("services start redis"))
        self.assertTrue(entry["stop"].endswith("services stop redis"))
        self.assertEqual(entry["adopted_from"]["brew"], "redis")

    def test_adopt_clears_stale_overrides_for_the_auto_id(self):
        # A hide/override keyed on auto.port.NNNN would apply to nothing once
        # the port is claimed by the adopted entry.
        _, data = self._adopt(_auto_service())
        self.assertNotIn("auto.port.8079", data["overrides"])

    def test_adopt_survives_overrides_that_are_not_a_map(self):
        svc = _auto_service()
        data = {
            "scripts": [],
            "overrides": ["not-a-map"],
            "apps": {"not": "a-list"},
        }

        def fake_mutate(mutator):
            mutator(data)
            return data

        with patch.object(services_manage_svc, "find_service", return_value=svc), \
                patch.object(services_manage_svc, "_full_process_name", return_value="redis-server"), \
                patch.object(services_manage_svc, "_process_command_path", return_value=""), \
                patch.object(services_manage_svc, "configured_signatures", return_value=[]), \
                patch.object(services_manage_svc, "cfg", return_value=data), \
                patch.object(services_manage_svc, "invalidate_status"), \
                patch.object(config, "mutate", side_effect=fake_mutate):
            result = services_manage_svc.adopt_service(svc["id"], {})
        self.assertTrue(result["ok"])
        self.assertEqual(data["overrides"], ["not-a-map"])

    def test_adopt_survives_scripts_that_are_not_a_list(self):
        """`scripts: null` (or a leftover map) used to AttributeError on append."""
        for scripts in (None, {"redis": {}}, "nope"):
            with self.subTest(scripts=scripts):
                svc = _auto_service()
                data = {"scripts": scripts, "overrides": {}}

                def fake_mutate(mutator, captured=data):
                    mutator(captured)
                    return captured

                with patch.object(services_manage_svc, "find_service", return_value=svc), \
                        patch.object(services_manage_svc, "_full_process_name", return_value="redis-server"), \
                        patch.object(services_manage_svc, "_process_command_path", return_value=""), \
                        patch.object(services_manage_svc, "configured_signatures", return_value=[]), \
                        patch.object(services_manage_svc, "cfg", return_value=data), \
                        patch.object(services_manage_svc, "invalidate_status"), \
                        patch.object(config, "mutate", side_effect=fake_mutate):
                    result = services_manage_svc.adopt_service(svc["id"], {})
                self.assertTrue(result["ok"])
                self.assertIsInstance(data["scripts"], list)
                self.assertEqual(data["scripts"][0]["id"], "redis")

    def test_adopt_defaults_survives_a_non_dict_signature(self):
        svc = _auto_service()
        svc["meta"]["signature"] = "redis"
        svc["signature"] = ["oops"]
        with patch.object(services_manage_svc, "_full_process_name", return_value="mystery"), \
                patch.object(services_manage_svc, "_process_command_path", return_value=""), \
                patch.object(services_manage_svc, "configured_signatures", return_value=[]), \
                patch.object(services_manage_svc, "identify", return_value=None), \
                patch.object(services_manage_svc, "cfg", return_value={}):
            defaults = services_manage_svc.adopt_defaults(svc)
        self.assertEqual(defaults["process"], "mystery")
        self.assertEqual(defaults["group"], "Adopted")

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
                patch.object(services_manage_svc, "_process_command_path", return_value=""), \
                patch.object(services_manage_svc, "configured_signatures", return_value=[]), \
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
                patch.object(services_manage_svc, "_process_command_path", return_value=""), \
                patch.object(services_manage_svc, "cfg", return_value={}):
            with self.assertRaises(HTTPException) as ctx:
                services_manage_svc.adopt_service(svc["id"], {"ports": ["nope", 0]})
        self.assertEqual(ctx.exception.detail["code"], "services.adopt_no_port")

    def test_adopt_explicit_empty_start_clears_inference(self):
        result, data = self._adopt(_auto_service(), patch_body={"start": "", "stop": ""})
        entry = data["scripts"][0]
        self.assertNotIn("start", entry)
        self.assertNotIn("stop", entry)
        self.assertTrue(result["ok"])

    def test_adopt_collects_sibling_ports_from_meta(self):
        svc = _auto_service()
        svc["meta"]["ports"] = [8079, 8081]
        _, data = self._adopt(svc)
        self.assertEqual(data["scripts"][0]["ports"], [8079, 8081])

    def test_adopt_skips_remember_for_high_confidence_match(self):
        # Redis is already in the library; writing another rule would be noise.
        result, data = self._adopt(_auto_service())
        self.assertNotIn("service_signatures", data)
        self.assertNotIn("signature", result)

    def test_adopt_remember_writes_and_upserts_signature(self):
        result, data = self._adopt(
            _auto_service(),
            patch_body={"remember": True},
            signatures=[{"slug": "redis", "name": "Old", "ports": [6379]}],
        )
        row = data["service_signatures"][0]
        self.assertEqual(len(data["service_signatures"]), 1)
        self.assertEqual(row["slug"], "redis")
        self.assertEqual(row["name"], "Redis")
        self.assertEqual(row["category"], "Databases")
        self.assertIn("redis-server", row["procs"])
        self.assertEqual(row["ports"], [8079])
        self.assertIs(row["http"], False)
        self.assertEqual(result["signature"]["slug"], "redis")

    def test_service_detail_tolerates_list_meta(self):
        svc = {
            "id": "auto.port.9",
            "kind": "auto",
            "name": "mystery :9",
            "meta": ["not", "a", "map"],
            "actions": [],
        }
        with (
            patch.object(services_manage_svc, "find_service", return_value=svc),
            patch.object(services_manage_svc, "override", return_value={}),
            patch.object(services_manage_svc, "adopt_defaults", return_value={}),
        ):
            detail = services_manage_svc.service_detail("auto.port.9")
        self.assertEqual(detail["meta"], {})
        self.assertIsNone(detail["process"])

    def test_adopt_tolerates_list_meta(self):
        svc = _auto_service()
        svc["meta"] = ["oops"]
        result, data = self._adopt(
            svc, patch_body={"ports": [8079], "id": "redis", "name": "Redis"},
        )
        self.assertTrue(result["ok"])
        self.assertEqual(data["scripts"][0]["adopted_from"]["auto_id"], svc["id"])

    def test_adopt_remember_omits_generic_runtime_from_procs(self):
        svc = {
            "id": "auto.port.3999", "kind": "auto", "name": "node :3999",
            "url": "http://127.0.0.1:3999",
            "meta": {"port": 3999, "pid": "9", "process": "node"},
        }
        _, data = self._adopt(
            svc,
            patch_body={"id": "my-api", "name": "My API", "group": "Apps", "remember": True},
            process="node",
        )
        row = data["service_signatures"][0]
        self.assertEqual(row["slug"], "my-api")
        self.assertEqual(row["name"], "My API")
        self.assertNotIn("procs", row)
        self.assertEqual(row["ports"], [3999])
        self.assertIs(row["http"], True)


class ScriptManageTests(unittest.TestCase):
    """Edit and forget rewrite the scripts[] entry, not the learned signature."""

    def _run(self, data, fn):
        def fake_mutate(mutator):
            mutator(data)
            return data

        with patch.object(services_manage_svc, "cfg", return_value=data), \
                patch.object(config, "mutate", side_effect=fake_mutate), \
                patch.object(services_manage_svc, "invalidate_status"):
            return fn()

    def test_update_script_rewrites_fields_and_clears_empty_commands(self):
        data = {"scripts": [{
            "id": "redis", "name": "Redis", "group": "Databases",
            "ports": [6379], "start": "old-start", "stop": "old-stop",
            "url": "http://127.0.0.1:6379",
        }]}
        result = self._run(data, lambda: services_manage_svc.update_script("redis", {
            "name": "Cache",
            "ports": [6379, 6380],
            "start": "",
            "url": "",
        }))
        entry = data["scripts"][0]
        self.assertEqual(result["entry"]["name"], "Cache")
        self.assertEqual(entry["name"], "Cache")
        self.assertEqual(entry["ports"], [6379, 6380])
        self.assertNotIn("start", entry)
        self.assertEqual(entry["stop"], "old-stop")
        self.assertNotIn("url", entry)

    def test_update_script_unknown_id_is_not_found(self):
        data = {"scripts": []}
        with self.assertRaises(HTTPException) as ctx:
            self._run(data, lambda: services_manage_svc.update_script("missing", {"name": "X"}))
        self.assertEqual(ctx.exception.detail["code"], "services.script_not_found")

    def test_forget_script_removes_entry_and_override_keeps_signature(self):
        data = {
            "scripts": [{"id": "redis", "name": "Redis", "ports": [6379]}],
            "overrides": {"redis": {"name": "Cache"}},
            "service_signatures": [{"slug": "redis", "name": "Redis", "ports": [6379]}],
        }
        result = self._run(data, lambda: services_manage_svc.forget_script("redis"))
        self.assertTrue(result["ok"])
        self.assertEqual(result["removed"]["id"], "redis")
        self.assertEqual(data["scripts"], [])
        self.assertNotIn("redis", data["overrides"])
        self.assertEqual(data["service_signatures"][0]["slug"], "redis")

    def test_forget_script_unknown_id_is_not_found(self):
        data = {"scripts": [{"id": "other", "ports": [1]}]}
        with self.assertRaises(HTTPException) as ctx:
            self._run(data, lambda: services_manage_svc.forget_script("missing"))
        self.assertEqual(ctx.exception.detail["code"], "services.script_not_found")

    def test_forget_script_survives_overrides_that_are_not_a_map(self):
        data = {
            "scripts": [{"id": "redis", "name": "Redis", "ports": [6379]}],
            "overrides": ["not-a-map"],
        }
        result = self._run(data, lambda: services_manage_svc.forget_script("redis"))
        self.assertTrue(result["ok"])
        self.assertEqual(data["scripts"], [])
        self.assertEqual(data["overrides"], ["not-a-map"])


class SignatureManageTests(unittest.TestCase):
    """Operator rules are listed, upserted and forgotten independently of scripts."""

    def _run(self, data, fn):
        def fake_mutate(mutator):
            mutator(data)
            return data

        with patch.object(services_manage_svc, "cfg", return_value=data), \
                patch.object(config, "mutate", side_effect=fake_mutate), \
                patch.object(services_manage_svc, "invalidate_status"):
            return fn()

    def test_upsert_writes_and_replaces_same_slug(self):
        data = {"service_signatures": []}
        result = self._run(data, lambda: services_manage_svc.upsert_signature({
            "slug": "my-api", "name": "My API", "ports": [8100], "http": True,
        }))
        self.assertEqual(result["signature"]["slug"], "my-api")
        self._run(data, lambda: services_manage_svc.upsert_signature({
            "slug": "my-api", "name": "API", "ports": [8100],
        }))
        self.assertEqual(len(data["service_signatures"]), 1)
        self.assertEqual(data["service_signatures"][0]["name"], "API")

    def test_upsert_rejects_empty_slug(self):
        with self.assertRaises(HTTPException) as ctx:
            services_manage_svc.upsert_signature({"name": "X"})
        self.assertEqual(ctx.exception.detail["code"], "services.signature_invalid")

    def test_forget_signature_removes_operator_rule(self):
        data = {"service_signatures": [
            {"slug": "my-api", "name": "My API", "ports": [8100]},
            {"slug": "keep", "name": "Keep"},
        ]}
        result = self._run(data, lambda: services_manage_svc.forget_signature("my-api"))
        self.assertEqual(result["slug"], "my-api")
        self.assertEqual([r["slug"] for r in data["service_signatures"]], ["keep"])

    def test_forget_signature_unknown_slug_is_not_found(self):
        data = {"service_signatures": []}
        with self.assertRaises(HTTPException) as ctx:
            self._run(data, lambda: services_manage_svc.forget_signature("missing"))
        self.assertEqual(ctx.exception.detail["code"], "services.signature_not_found")

    def test_list_signatures_reports_builtin_count(self):
        with patch.object(services_manage_svc, "configured_signatures", return_value=[]):
            listed = services_manage_svc.list_signatures()
        self.assertEqual(listed["signatures"], [])
        self.assertGreater(listed["builtin_count"], 10)


class ContainerSignatureTests(unittest.TestCase):
    """docker ps image field feeds the same signature library as orphans."""

    def setUp(self):
        from hub.discovery import containers

        self.containers = containers
        self.addCleanup(containers.invalidate_containers)

    def _discover(self, docker_output, overrides=None):
        self.containers.invalidate_containers()
        with patch.object(self.containers, "sh", return_value=(0, docker_output, "")), \
                patch.object(self.containers, "override", side_effect=lambda n: (overrides or {}).get(n, {})), \
                patch.object(self.containers, "resolve_value", side_effect=lambda v: v), \
                patch.object(self.containers, "configured_signatures", return_value=[]):
            return self.containers.discover_containers(force=True)

    def test_aligned_name_uses_signature(self):
        items, _ = self._discover(
            "grafana\trunning\tUp 2 hours\tgrafana/grafana:latest\tstack\n"
        )
        self.assertEqual(items[0]["name"], "Grafana")
        self.assertEqual(items[0]["group"], "Containers · stack")
        self.assertEqual(items[0]["signature"]["slug"], "grafana")

    def test_custom_name_keeps_id_and_gets_chip(self):
        items, _ = self._discover("cache\trunning\tUp\tredis:7\t\n")
        self.assertEqual(items[0]["name"], "cache")
        self.assertEqual(items[0]["group"], "Databases")
        self.assertEqual(items[0]["signature"]["slug"], "redis")

    def test_name_override_wins(self):
        items, _ = self._discover(
            "grafana\trunning\tUp\tgrafana/grafana:latest\t\n",
            overrides={"grafana": {"name": "Dash", "group": "Infra"}},
        )
        self.assertEqual(items[0]["name"], "Dash")
        self.assertEqual(items[0]["group"], "Infra")
        self.assertEqual(items[0]["signature"]["slug"], "grafana")


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

    def test_script_retries_a_flapping_port(self):
        seen = {}

        def flap(port, **_):
            seen[port] = seen.get(port, 0) + 1
            return seen[port] > 1

        with patch.object(apps_discovery, "cfg", return_value={"scripts": [
            {"id": "gravity", "ports": [3001, 3010]},
        ]}), patch.object(apps_discovery, "port_open", side_effect=flap):
            items = apps_discovery.collect_scripts()
        self.assertEqual(items[0]["state"], "ok")
        self.assertEqual(seen[3001], 2)
        self.assertEqual(seen[3010], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
