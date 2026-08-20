"""json.loads RecursionError is not ValueError.

A leftover deeply nested store used to 500 GET /api/brew/services,
GET /api/catalog/remote, GET /api/apps/credentials, GET /api/wireguard,
GET /api/smart, GET /api/ups, and pg-dump password lookup.
twofa / api-keys / notify secrets already catch RecursionError.

Follow-up: photoshub config/status, docker-update-status, orbctl/docker
inspect, cloudflared state, alert_state, metrics latest_sample, compose
validate, and catalog front matter only caught ValueError/YAMLError (or
relied on ``except Exception``) so RecursionError still 500'd the page.

Follow-up: leftover ``!!timestamp .inf`` / ``2026-13-01`` / a 5000-digit int
raise AttributeError/ValueError/TypeError — not YAMLError — and used to 500
POST /api/compose, GET /api/catalog, and GET /api/export/services-yaml.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from hub import (
    alerts, assistant_svc, backups, brew_cache, catalog, catalog_remote,
    cloudflared_svc, compose_svc, config, containers_svc, docker_cli, metrics,
    metrics_rollup, notify_channels, photoshub_svc, service_credentials,
    services_manage_svc, shares_svc, smart_test_svc, ups_policy, vms_svc,
    wireguard_svc,
)
from hub.routers import settings_api

NESTED = '{"k":' * 12000 + "1" + "}" * 12000


class NestedJsonLoadTests(unittest.TestCase):
    def test_brew_disk_cache_does_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "brew.json"
            path.write_text(NESTED)
            with mock.patch.object(brew_cache, "_DISK", path):
                self.assertIsNone(brew_cache._read_disk_file())

    def test_catalog_remote_state_does_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            path.write_text(NESTED)
            with mock.patch.object(catalog_remote, "STATE_PATH", path):
                self.assertEqual(catalog_remote._load_state(), {})

    def test_backup_secrets_do_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "backup-credentials.json"
            path.write_text(NESTED)
            with mock.patch.object(backups, "BACKUP_SECRETS_FILE", path):
                self.assertEqual(backups._pg_password("immich"), "")

    def test_service_credentials_do_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "service-credentials.json"
            path.write_text(NESTED)
            with mock.patch.object(service_credentials, "INDEX_FILE", path):
                self.assertEqual(service_credentials._load(), {})

    def test_wireguard_registry_does_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "wireguard-peers.json"
            path.write_text(NESTED)
            with mock.patch.object(wireguard_svc, "REGISTRY_PATH", path):
                self.assertEqual(wireguard_svc._load_registry(), {"peers": {}})

    def test_smart_history_does_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "smart-history.json"
            path.write_text(NESTED)
            with mock.patch.object(smart_test_svc, "HISTORY_PATH", path):
                self.assertEqual(smart_test_svc._load_history(), [])

    def test_ups_policy_state_does_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ups-policy-state.json"
            path.write_text(NESTED)
            with mock.patch.object(ups_policy, "STATE_FILE", path):
                self.assertEqual(ups_policy._load_state(), {})
                json.dumps(ups_policy.public_state(), allow_nan=False)


class HugeStateFileTests(unittest.TestCase):
    """``read_text()`` of a leftover multi-MB store used to OOM the request."""

    def _huge(self, name: str) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / name
        path.write_bytes(b"x" * (2 * 1024 * 1024))
        return path

    def test_huge_brew_disk_cache_does_not_oom(self):
        path = self._huge("brew.json")
        with mock.patch.object(brew_cache, "_DISK", path):
            self.assertIsNone(brew_cache._read_disk_file())

    def test_huge_catalog_remote_state_does_not_oom(self):
        path = self._huge("state.json")
        with mock.patch.object(catalog_remote, "STATE_PATH", path):
            self.assertEqual(catalog_remote._load_state(), {})
            json.dumps(catalog_remote.status(), allow_nan=False)

    def test_huge_backup_secrets_do_not_oom(self):
        path = self._huge("backup-credentials.json")
        with mock.patch.object(backups, "BACKUP_SECRETS_FILE", path):
            self.assertEqual(backups._pg_password("immich"), "")

    def test_huge_wireguard_registry_does_not_oom(self):
        path = self._huge("wireguard-peers.json")
        with mock.patch.object(wireguard_svc, "REGISTRY_PATH", path):
            self.assertEqual(wireguard_svc._load_registry(), {"peers": {}})

    def test_huge_ups_policy_state_does_not_oom(self):
        path = self._huge("ups-policy-state.json")
        with mock.patch.object(ups_policy, "STATE_FILE", path):
            self.assertEqual(ups_policy._load_state(), {})
            json.dumps(ups_policy.public_state(), allow_nan=False)

    def test_huge_notify_secrets_do_not_oom(self):
        path = self._huge("notify-credentials.json")
        with mock.patch.object(notify_channels, "SECRETS_FILE", path):
            self.assertEqual(notify_channels._load_secrets(), {})

    def test_huge_alert_state_does_not_oom(self):
        path = self._huge("alert_state.json")
        with mock.patch.object(alerts, "STATE_FILE", path):
            self.assertEqual(alerts._load_state(), {})

    def test_huge_smart_history_does_not_oom(self):
        path = self._huge("smart-tests.json")
        with mock.patch.object(smart_test_svc, "HISTORY_PATH", path):
            self.assertEqual(smart_test_svc._load_history(), [])

    def test_huge_container_update_status_does_not_oom(self):
        path = self._huge("docker-update-status.json")
        with mock.patch.object(containers_svc, "UPDATE_STATUS_PATH", path):
            self.assertEqual(containers_svc._load_update_status(), {})

    def test_huge_service_credentials_do_not_oom(self):
        path = self._huge("service-credentials.json")
        with mock.patch.object(service_credentials, "INDEX_FILE", path):
            self.assertEqual(service_credentials._load(), {})

    def test_huge_photoshub_config_does_not_oom(self):
        path = self._huge("config.json")
        with mock.patch.object(photoshub_svc, "CFG_PATH", path):
            self.assertEqual(photoshub_svc._cfg(), {})

    def test_huge_assistant_catalog_does_not_oom(self):
        """``Path.read_text()`` of leftover assistant_*.json used to OOM import/ask."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (path / "x.json").write_bytes(b"x" * (2 * 1024 * 1024))
            with mock.patch.object(assistant_svc, "_HERE", path):
                self.assertIsNone(assistant_svc._load_json("x.json"))

    def test_huge_cloudflared_state_does_not_oom(self):
        path = self._huge("serverhub-state.json")
        with (
            mock.patch.object(cloudflared_svc, "STATE_FILE", path),
            mock.patch.object(cloudflared_svc, "_ensure_dirs"),
            mock.patch.object(cloudflared_svc, "_path_is_file", return_value=True),
        ):
            self.assertEqual(cloudflared_svc._load_state(), {})

    def test_huge_metrics_rollup_state_does_not_oom(self):
        path = self._huge("metrics-rollup-state.json")
        metrics_rollup._state_loaded = False
        self.addCleanup(setattr, metrics_rollup, "_state_loaded", False)
        with mock.patch.object(metrics_rollup, "STATE_FILE", path):
            metrics_rollup._load_state_locked()
        json.dumps(dict(metrics_rollup._state), allow_nan=False)

    def test_huge_services_yaml_does_not_oom_cfg(self):
        path = self._huge("services.yaml")
        with mock.patch.object(config, "YAML_PATH", path):
            self.assertEqual(config._read_disk(), {})

    def test_huge_services_yaml_export_is_coded_not_500(self):
        path = self._huge("services.yaml")
        with mock.patch("hub.paths.CONFIG_FILE", path):
            with self.assertRaises(HTTPException) as ctx:
                settings_api.export_services_yaml()
        self.assertEqual(ctx.exception.status_code, 500)
        detail = ctx.exception.detail
        self.assertEqual(
            detail.get("code") if isinstance(detail, dict) else detail,
            "system_settings.export_failed",
        )


NESTED_YAML = "{k: " * 12000 + "1" + "}" * 12000


class NestedYamlLoadTests(unittest.TestCase):
    def test_nested_services_yaml_does_not_500_read(self):
        """yaml.safe_load RecursionError is not YAMLError; cfg() used to 500."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "services.yaml"
            path.write_text(NESTED_YAML)
            with mock.patch.object(config, "YAML_PATH", path):
                self.assertEqual(config._read_disk(), {})

    def test_nested_services_yaml_export_is_coded_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "services.yaml"
            path.write_text(NESTED_YAML)
            with mock.patch("hub.paths.CONFIG_FILE", path):
                with self.assertRaises(HTTPException) as ctx:
                    settings_api.export_services_yaml()
            self.assertEqual(ctx.exception.status_code, 500)
            detail = ctx.exception.detail
            self.assertEqual(
                detail.get("code") if isinstance(detail, dict) else detail,
                "system_settings.export_failed",
            )


class NestedJsonLoadRestTests(unittest.TestCase):
    """Sites that only caught ValueError / Exception around json.loads."""

    def test_photoshub_status_json_does_not_500(self):
        """``json.loads`` RecursionError is not ValueError; GET /api/photoshub used to 500."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "status.json"
            path.write_text(NESTED)
            self.assertIsNone(photoshub_svc._load_json(path))
            self.assertEqual(photoshub_svc._load_json_obj(path), {})

    def test_photoshub_config_does_not_500_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(NESTED)
            with mock.patch.object(photoshub_svc, "CFG_PATH", path):
                self.assertEqual(photoshub_svc._cfg(), {})
                with self.assertRaises(HTTPException) as ctx:
                    photoshub_svc._cfg_strict()
        detail = ctx.exception.detail
        self.assertEqual(
            detail.get("code") if isinstance(detail, dict) else detail,
            "photoshub.bad_config",
        )

    def test_container_update_status_does_not_500(self):
        """Leftover nested docker-update-status.json used to 500 GET /api/containers."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "docker-update-status.json"
            path.write_text(NESTED)
            with mock.patch.object(containers_svc, "UPDATE_STATUS_PATH", path):
                self.assertEqual(containers_svc._load_update_status(), {})

    def test_container_inspect_json_does_not_500_list(self):
        ps = "abc123\tnginx\tnginx:latest\trunning\tUp\t\t\t\t\n"

        def fake_docker(*args, **kwargs):
            if args and args[0] == "ps":
                return (0, ps, "")
            return (0, NESTED, "")

        with (
            mock.patch.object(containers_svc, "engine_up", return_value=True),
            mock.patch.object(containers_svc, "docker", side_effect=fake_docker),
            mock.patch.object(containers_svc, "override", return_value={}),
            mock.patch.object(
                containers_svc, "resolve_value", side_effect=lambda x: x or {},
            ),
            mock.patch.object(containers_svc, "_load_update_status", return_value={}),
        ):
            ok, items = containers_svc._build_container_list()
        self.assertTrue(ok)
        self.assertEqual(items[0]["id"], "nginx")
        json.dumps(items, allow_nan=False)

    def test_docker_json_nested_ndjson_does_not_500(self):
        with mock.patch.object(docker_cli, "docker", return_value=(0, NESTED, "")):
            data, rc, err = docker_cli.docker_json(["inspect", "nginx"])
        self.assertEqual(rc, 0)
        self.assertEqual(data, [])
        json.dumps(data, allow_nan=False)

    def test_docker_json_skips_nested_ndjson_siblings(self):
        """One leftover nested {{json .}} row used to empty the whole listing."""
        payload = '{"Id":"good"}\n' + NESTED + '\n{"Id":"also"}'
        with mock.patch.object(docker_cli, "docker", return_value=(0, payload, "")):
            data, rc, err = docker_cli.docker_json(
                ["ps", "--format", "{{json .}}"]
            )
        self.assertEqual(rc, 0)
        self.assertEqual([row.get("Id") for row in data], ["good", "also"])
        json.dumps(data, allow_nan=False)

    def test_orbctl_nested_json_does_not_500_vms(self):
        """``json.loads`` RecursionError is not ValueError; GET /api/vms used to 500."""

        def fake_sh(cmd, **kw):
            if "-f" in cmd:
                return (0, NESTED, "")
            return (1, "", "no")

        with (
            mock.patch.object(vms_svc, "_orb_available", return_value=True),
            mock.patch.object(vms_svc, "sh", side_effect=fake_sh),
            mock.patch.object(vms_svc, "override", return_value={}),
        ):
            items = vms_svc._list_orb_machines_uncached()
        self.assertEqual(items, [])
        json.dumps(items, allow_nan=False)

    def test_service_detail_inspect_does_not_500(self):
        with (
            mock.patch.object(services_manage_svc, "DOCKER", "/bin/sh"),
            mock.patch.object(
                services_manage_svc.cli_args, "is_safe_positional", return_value=True,
            ),
            mock.patch.object(
                services_manage_svc, "sh", return_value=(0, NESTED, ""),
            ),
        ):
            self.assertEqual(services_manage_svc._docker_inspect("nginx"), {})

    def test_cloudflared_state_does_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "serverhub-state.json"
            path.write_text(NESTED)
            with (
                mock.patch.object(cloudflared_svc, "STATE_FILE", path),
                mock.patch.object(cloudflared_svc, "_ensure_dirs"),
                mock.patch.object(cloudflared_svc, "_path_is_file", return_value=True),
            ):
                self.assertEqual(cloudflared_svc._load_state(), {})

    def test_alert_state_does_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "alert_state.json"
            path.write_text(NESTED)
            with mock.patch.object(alerts, "STATE_FILE", path):
                self.assertEqual(alerts._load_state(), {})

    def test_notify_secrets_do_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify-credentials.json"
            path.write_text(NESTED)
            with mock.patch.object(notify_channels, "SECRETS_FILE", path):
                self.assertEqual(notify_channels._load_secrets(), {})

    def test_metrics_latest_sample_does_not_500(self):
        """``json.loads`` RecursionError is not ValueError; alert sweep used to 500."""
        metrics._last_sample = None
        self.addCleanup(setattr, metrics, "_last_sample", None)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "metrics.jsonl"
            path.write_text('{"t": 1, "cpu_used_pct": 1.0}\n')
            with (
                mock.patch.object(metrics, "METRICS_FILE", path),
                mock.patch.object(metrics.json, "loads", side_effect=RecursionError),
            ):
                self.assertIsNone(metrics.latest_sample())

    def test_sharing_json_does_not_500_list(self):
        with self.assertRaises(ValueError):
            shares_svc._json_shares(NESTED)
        with (
            mock.patch.object(
                shares_svc, "sh",
                side_effect=[(0, NESTED, ""), (1, "", ""), (1, "", "")],
            ),
            mock.patch.object(shares_svc, "host_ip", return_value="192.0.2.1"),
        ):
            rows = shares_svc.list_smb_shares(include_sizes=False)
        self.assertEqual(rows, [])
        json.dumps(rows, allow_nan=False)

    def test_inflight_backup_marker_does_not_500_recover(self):
        """Lifespan recover_interrupted_stack_backups used to RecursionError."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # 64KB marker cap; ~10k levels RecursionError json.loads (~60KB).
            nested = '{"k":' * 10000 + "1" + "}" * 10000
            (root / f"{backups._INFLIGHT_PREFIX}nested").write_text(nested)
            with (
                mock.patch.object(backups, "DATA_DIR", root),
                mock.patch.object(backups, "_find_stack", return_value={}),
                mock.patch.object(backups, "_run_argv", return_value=(0, "", "")),
                mock.patch("hub.alerts.emit_alert"),
            ):
                recovered = backups.recover_interrupted_stack_backups()
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0]["stack"], "nested")
        json.dumps(recovered, allow_nan=False)

    def test_stack_mounts_nested_compose_json_is_error_not_500(self):
        """json.loads RecursionError used to 500 POST /api/backups/stack mounts."""
        with mock.patch.object(backups, "_run_argv", return_value=(0, NESTED, "")):
            binds, vols, err = backups._stack_mounts("/tmp/c.yml", None)
        self.assertEqual(binds, [])
        self.assertEqual(vols, [])
        self.assertIn("unparsable", err)
        json.dumps({"err": err}, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_stack_mounts_recursing_loads_is_error_not_500(self):
        class Recursing(ValueError):
            def __str__(self):
                raise RecursionError("nested")

        with (
            mock.patch.object(backups, "_run_argv", return_value=(0, "{}", "")),
            mock.patch.object(backups.json, "loads", side_effect=Recursing("bad")),
        ):
            binds, vols, err = backups._stack_mounts("/tmp/c.yml", None)
        self.assertEqual(binds, [])
        self.assertIn("unparsable", err)
        json.dumps({"err": err}, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertIn("Recursing", err)


class NestedYamlLoadRestTests(unittest.TestCase):
    def test_nested_compose_text_is_invalid_not_500(self):
        """yaml.safe_load RecursionError is not YAMLError; POST /api/compose used to 500."""
        with mock.patch.object(compose_svc, "run_capped", return_value=(0, "ok")):
            out = compose_svc.validate_compose_text(NESTED_YAML, cwd="/tmp")
        self.assertFalse(out["ok"])
        self.assertIsInstance(out["message"], str)
        json.dumps(out, allow_nan=False)

    def test_nested_catalog_front_matter_does_not_500(self):
        """yaml.safe_load RecursionError is not YAMLError; GET /api/catalog used to 500."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested.yml"
            path.write_text(
                "---\n" + NESTED_YAML + "\n---\nservices:\n  x:\n    image: a:1\n"
            )
            meta, body = catalog._parse_template(path)
        self.assertEqual(meta["id"], "nested")
        self.assertIn("services:", body)
        json.dumps(meta, allow_nan=False)

    def test_nested_remote_front_matter_is_rejected(self):
        text = "---\n" + NESTED_YAML + "\n---\nservices:\n  x:\n    image: a:1\n"
        reason = catalog_remote._validate_template_text(text, "demo")
        self.assertIn("front matter", reason)

    def test_nested_remote_compose_body_is_rejected(self):
        text = "---\nname: Demo\ndesc: A demo\n---\n" + NESTED_YAML
        reason = catalog_remote._validate_template_text(text, "demo")
        self.assertIn("compose body", reason)

    def test_nested_compose_directives_scan_does_not_500(self):
        text = "---\nname: Demo\ndesc: A demo\n---\n" + NESTED_YAML
        self.assertEqual(catalog_remote.scan_compose_directives(text), [])

    def test_leftover_timestamp_inf_compose_is_invalid_not_500(self):
        """yaml.safe_load AttributeError is not YAMLError; POST /api/compose used to 500."""
        with mock.patch.object(compose_svc, "run_capped", return_value=(0, "ok")):
            out = compose_svc.validate_compose_text(
                "services:\n  x:\n    image: a:1\n    created: !!timestamp .inf\n",
                cwd="/tmp",
            )
        self.assertFalse(out["ok"])
        self.assertIsInstance(out["message"], str)
        json.dumps(out, allow_nan=False)

    def test_leftover_huge_int_compose_is_invalid_not_500(self):
        """yaml.safe_load ValueError is not YAMLError; POST /api/compose used to 500."""
        with mock.patch.object(compose_svc, "run_capped", return_value=(0, "ok")):
            out = compose_svc.validate_compose_text(
                "services:\n  x:\n    image: a:1\n    cpu: " + "9" * 5000 + "\n",
                cwd="/tmp",
            )
        self.assertFalse(out["ok"])
        json.dumps(out, allow_nan=False)

    def test_leftover_timestamp_inf_catalog_front_matter_does_not_500(self):
        """yaml.safe_load AttributeError is not YAMLError; GET /api/catalog used to 500."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "stamp.yml"
            path.write_text(
                "---\nname: Demo\ndesc: A demo\ncreated: !!timestamp .inf\n"
                "---\nservices:\n  x:\n    image: a:1\n"
            )
            meta, body = catalog._parse_template(path)
        self.assertEqual(meta["id"], "stamp")
        self.assertIn("services:", body)
        json.dumps(meta, allow_nan=False)

    def test_leftover_invalid_date_catalog_front_matter_does_not_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baddate.yml"
            path.write_text(
                "---\nname: Demo\ndesc: A demo\ncreated: 2026-13-01\n"
                "---\nservices:\n  x:\n    image: a:1\n"
            )
            meta, body = catalog._parse_template(path)
        json.dumps(meta, allow_nan=False)
        self.assertIn("services:", body)

    def test_leftover_timestamp_inf_remote_front_matter_is_rejected(self):
        text = (
            "---\nname: Demo\ndesc: A demo\ncreated: !!timestamp .inf\n"
            "---\nservices:\n  x:\n    image: a:1\n"
        )
        reason = catalog_remote._validate_template_text(text, "demo")
        self.assertIn("front matter", reason)

    def test_leftover_timestamp_inf_compose_body_is_rejected(self):
        text = (
            "---\nname: Demo\ndesc: A demo\n"
            "---\nservices:\n  x:\n    image: a:1\n    created: !!timestamp .inf\n"
        )
        reason = catalog_remote._validate_template_text(text, "demo")
        self.assertIn("compose body", reason)

    def test_leftover_timestamp_inf_directives_scan_does_not_500(self):
        text = (
            "---\nname: Demo\ndesc: A demo\n"
            "---\nservices:\n  x:\n    image: a:1\n    created: !!timestamp .inf\n"
        )
        self.assertEqual(catalog_remote.scan_compose_directives(text), [])

    def test_leftover_timestamp_inf_export_is_coded_not_500(self):
        """GET /api/export/services-yaml used to AttributeError leftover ``!!timestamp .inf``."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "services.yaml"
            path.write_text("settings:\n  last_run: !!timestamp .inf\n")
            import hub.paths as paths
            with mock.patch.object(paths, "CONFIG_FILE", path):
                with self.assertRaises(HTTPException) as ctx:
                    settings_api.export_services_yaml()
        detail = ctx.exception.detail
        code = detail["code"] if isinstance(detail, dict) else str(detail)
        self.assertEqual(code, "system_settings.export_failed")
