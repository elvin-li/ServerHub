"""Grouping rules: first match wins, overrides win, XiaomiHub → 智能家居."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import group_rules, services_manage_svc  # noqa: E402
from hub.discovery import containers  # noqa: E402


def _json(payload) -> None:
    json.dumps(payload, allow_nan=False).encode("utf-8")


class Recursing:
    def __str__(self):
        raise RecursionError("nested")


class MatchOrderTests(unittest.TestCase):
    def test_first_matching_rule_wins(self):
        rules = [
            {"id": "a", "group": "First", "compose_project": "demo"},
            {"id": "b", "group": "Second", "compose_project": "demo"},
        ]
        self.assertEqual(
            group_rules.match_group({"compose_project": "demo"}, rules=rules),
            "First",
        )

    def test_explicit_group_beats_a_matching_rule(self):
        rules = [{"id": "a", "group": "First", "compose_project": "demo"}]
        self.assertIsNone(
            group_rules.match_group(
                {"compose_project": "demo"},
                explicit="Infra",
                rules=rules,
            )
        )
        self.assertEqual(
            group_rules.resolve_group(
                {"compose_project": "demo"},
                explicit="Infra",
                fallback="Containers · demo",
                rules=rules,
            ),
            "Infra",
        )

    def test_interval_jobs_beat_the_gravity_prefix(self):
        with patch.object(group_rules, "cfg", return_value={}):
            self.assertEqual(
                group_rules.match_group(
                    {"id": "com.gravity.rotate-logs"},
                    launchd_interval=True,
                ),
                "定时任务",
            )
            self.assertEqual(
                group_rules.match_group({"id": "com.gravity.api"}),
                "Gravity 量化",
            )


class SeedAndYamlTests(unittest.TestCase):
    def test_missing_key_uses_seeds_without_writing(self):
        with patch.object(group_rules, "cfg", return_value={}):
            listed = group_rules.list_rules()
        self.assertEqual(listed["source"], "seed")
        ids = [r["id"] for r in listed["rules"]]
        self.assertEqual(
            ids,
            ["scheduled-tasks", "smart-home", "gravity", "gateway", "teslamate"],
        )
        self.assertEqual(listed["rules"][1]["group"], "智能家居")

    def test_empty_yaml_list_disables_seeds(self):
        with patch.object(group_rules, "cfg", return_value={"group_rules": []}):
            self.assertIsNone(
                group_rules.match_group({"compose_project": "xiaomihub"})
            )
            self.assertEqual(group_rules.list_rules()["source"], "yaml")
            self.assertEqual(group_rules.list_rules()["rules"], [])

    def test_present_yaml_list_is_the_full_set(self):
        data = {"group_rules": [
            {"id": "only", "group": "Custom", "compose_project": "xiaomihub"},
        ]}
        with patch.object(group_rules, "cfg", return_value=data):
            self.assertEqual(
                group_rules.match_group({"compose_project": "xiaomihub"}),
                "Custom",
            )
            self.assertIsNone(
                group_rules.match_group({"compose_project": "teslamate"})
            )


class ContainerGroupTests(unittest.TestCase):
    def setUp(self):
        containers.invalidate_containers()
        self.addCleanup(containers.invalidate_containers)

    def _discover(self, docker_output, overrides=None, cfg=None):
        containers.invalidate_containers()
        with patch.object(containers, "sh", return_value=(0, docker_output, "")), \
                patch.object(containers, "override", side_effect=lambda n: (overrides or {}).get(n, {})), \
                patch.object(containers, "resolve_value", side_effect=lambda v: v), \
                patch.object(containers, "configured_signatures", return_value=[]), \
                patch.object(group_rules, "cfg", return_value=cfg if cfg is not None else {}):
            return containers.discover_containers(force=True)

    def test_xiaomihub_compose_lands_in_smart_home(self):
        items, _ = self._discover(
            "miot_central\trunning\tUp\tmiot:latest\txiaomihub\n"
        )
        self.assertEqual(items[0]["group"], "智能家居")
        self.assertEqual(items[0]["id"], "miot_central")

    def test_unrelated_compose_keeps_project_group(self):
        items, _ = self._discover(
            "grafana\trunning\tUp 2 hours\tgrafana/grafana:latest\tstack\n"
        )
        self.assertEqual(items[0]["group"], "Containers · stack")
        self.assertEqual(items[0]["name"], "Grafana")

    def test_container_override_group_wins(self):
        items, _ = self._discover(
            "miot_central\trunning\tUp\tmiot:latest\txiaomihub\n",
            overrides={"miot_central": {"group": "Infra"}},
        )
        self.assertEqual(items[0]["group"], "Infra")


class AdoptGroupTests(unittest.TestCase):
    def test_miot_process_defaults_to_smart_home(self):
        svc = {
            "id": "auto.port.18080",
            "kind": "auto",
            "name": "miot_central :18080",
            "meta": {
                "port": 18080, "ports": [18080],
                "process": "miot_central", "pid": "1",
            },
        }
        with patch.object(services_manage_svc, "_full_process_name", return_value="miot_central"), \
                patch.object(services_manage_svc, "_process_command_path", return_value=""), \
                patch.object(services_manage_svc, "configured_signatures", return_value=[]), \
                patch.object(services_manage_svc, "identify", return_value=None), \
                patch.object(group_rules, "cfg", return_value={}):
            defaults = services_manage_svc.adopt_defaults(svc)
        self.assertEqual(defaults["group"], "智能家居")

    def test_adopt_explicit_group_still_wins(self):
        svc = {
            "id": "auto.port.18080",
            "kind": "auto",
            "meta": {"port": 18080, "ports": [18080], "process": "miot_central", "pid": "1"},
        }
        data = {"scripts": [], "overrides": {}}

        def fake_mutate(mutator):
            mutator(data)
            return data

        with patch.object(services_manage_svc, "find_service", return_value=svc), \
                patch.object(services_manage_svc, "_full_process_name", return_value="miot_central"), \
                patch.object(services_manage_svc, "_process_command_path", return_value=""), \
                patch.object(services_manage_svc, "configured_signatures", return_value=[]), \
                patch.object(services_manage_svc, "identify", return_value=None), \
                patch.object(services_manage_svc, "cfg", return_value=data), \
                patch.object(services_manage_svc, "invalidate_status"), \
                patch.object(group_rules, "cfg", return_value={}), \
                patch("hub.config.mutate", side_effect=fake_mutate):
            result = services_manage_svc.adopt_service(
                svc["id"], {"group": "Infra", "name": "MiOT"},
            )
        self.assertEqual(result["entry"]["group"], "Infra")


class LeftoverTests(unittest.TestCase):
    def test_inf_non_list_and_bad_regex_do_not_raise(self):
        with patch.object(group_rules, "cfg", return_value={"group_rules": float("inf")}):
            listed = group_rules.list_rules()
            self.assertEqual(listed["rules"], [])
            self.assertIsNone(group_rules.match_group({"compose_project": "xiaomihub"}))
        _json(listed)

        parsed = group_rules.parse_rule({
            "id": "x",
            "group": "Home",
            "launchd_re": ["(unclosed", "*"],
            "ports": [float("inf"), float("nan"), 8123, True],
            "compose_project": Recursing(),
        })
        self.assertEqual(parsed["ports"], (8123,))
        self.assertEqual(parsed["launchd_re"], ())
        self.assertTrue(parsed["has_matcher"])

        self.assertIsNone(group_rules.parse_rule(["not", "a", "dict"]))
        self.assertEqual(
            group_rules.resolve_group(Recursing(), fallback="Apps"),
            "Apps",
        )
        self.assertEqual(
            group_rules.match_group({"compose_project": Recursing()}, rules=[
                {"group": Recursing(), "compose_project": "x"},
            ]),
            None,
        )

    def test_surrogate_group_is_utf8_safe(self):
        parsed = group_rules.parse_rule({
            "id": "x",
            "group": "Home\ud800",
            "compose_project": "demo",
        })
        _json(group_rules.yaml_rule(parsed))
        self.assertIn("Home", parsed["group"])


class SaveApiTests(unittest.TestCase):
    def _mutate(self, data, fn):
        def fake(mutator):
            mutator(data)
            return data

        with patch.object(group_rules, "mutate", side_effect=fake), \
                patch.object(group_rules, "cfg", return_value=data):
            return fn()

    def test_replace_all_writes_yaml_and_empty_clears_seeds(self):
        data = {}
        result = self._mutate(data, lambda: group_rules.save_rules({
            "rules": [{"group": "Home", "compose_project": "demo"}],
        }))
        self.assertEqual(data["group_rules"][0]["compose_project"], "demo")
        self.assertEqual(result["source"], "yaml")
        self._mutate(data, lambda: group_rules.save_rules({"rules": []}))
        self.assertEqual(data["group_rules"], [])

    def test_upsert_from_seeds_materialises_the_list(self):
        data = {}
        self._mutate(data, lambda: group_rules.save_rules({
            "group": "Home",
            "compose_project": ["demo"],
        }))
        ids = [r["id"] for r in data["group_rules"]]
        self.assertIn("smart-home", ids)
        self.assertIn("home", ids)
        self.assertEqual(len(ids), 6)

    def test_delete_unknown_id_is_not_found(self):
        data = {"group_rules": [{"id": "keep", "group": "Home", "compose_project": "x"}]}
        with self.assertRaises(HTTPException) as ctx:
            self._mutate(data, lambda: group_rules.delete_rule("missing"))
        self.assertEqual(ctx.exception.detail["code"], "services.group_rule_not_found")
        self.assertEqual(len(data["group_rules"]), 1)

    def test_invalid_rule_is_rejected(self):
        data = {}
        with self.assertRaises(HTTPException) as ctx:
            self._mutate(data, lambda: group_rules.save_rules({"compose_project": "x"}))
        self.assertEqual(ctx.exception.detail["code"], "services.group_rule_invalid")
        self.assertNotIn("group_rules", data)

    def test_matcherless_rule_is_rejected(self):
        data = {}
        with self.assertRaises(HTTPException) as ctx:
            self._mutate(data, lambda: group_rules.save_rules({"group": "Home"}))
        self.assertEqual(ctx.exception.detail["code"], "services.group_rule_invalid")
        self.assertNotIn("group_rules", data)

    def test_yaml_apps_blank_group_uses_rules(self):
        with patch.object(group_rules, "cfg", return_value={}):
            self.assertEqual(
                group_rules.resolve_yaml_entry_group(
                    {"id": "gravity", "group": ""},
                    fallback="Custom",
                ),
                "Gravity 量化",
            )
            self.assertEqual(
                group_rules.resolve_yaml_entry_group(
                    {"id": "gravity", "group": "Apps"},
                    fallback="Custom",
                ),
                "Apps",
            )


class LeftoverClassBombTests(unittest.TestCase):
    """Bare isinstance used to 500 grouping on leftover __class__ bombs."""

    def test_str_list_class_bomb_is_empty_not_a_raise(self):
        class ClassBomb:
            @property
            def __class__(self):
                raise RuntimeError("class bomb")

        self.assertEqual(group_rules._str_list(ClassBomb()), ())

    def test_port_list_class_bomb_is_empty_not_a_raise(self):
        class ClassBomb:
            @property
            def __class__(self):
                raise RuntimeError("class bomb")

        self.assertEqual(group_rules._port_list(ClassBomb()), ())

    def test_match_group_class_bomb_service_is_none_not_a_raise(self):
        class ClassBomb:
            @property
            def __class__(self):
                raise RuntimeError("class bomb")

        self.assertIsNone(group_rules.match_group(ClassBomb(), rules=[]))

    def test_bool_id_still_does_not_become_a_string_list(self):
        self.assertEqual(group_rules._str_list(True), ())
        self.assertEqual(group_rules._port_list(True), ())
