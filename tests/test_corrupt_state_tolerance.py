"""A truncated or garbage state file must degrade to empty state, not raise.

Every reader under data/ is exercised against the same three corpses: a
truncated JSON fragment, plain-text garbage, and raw bytes that are not valid
UTF-8 (a torn write after power loss produces exactly that).  A reader that
raises here takes an API endpoint to 500 at best, and at worst kills the
background thread that called it — the alert engine reads several of these
files every sweep.

The non-UTF-8 case is the one that actually caught bugs: ``read_text()``
raises ``UnicodeDecodeError`` (a ValueError, not an OSError), which sailed
past ``except OSError`` guards in the alerts journal and the metrics ring
buffer — the reader raised and, worse, both files' trim passes stayed
disabled forever after one corrupt byte.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import (  # noqa: E402
    alerts, api_keys, backups, cloudflared_svc, containers_svc, metrics,
    notify_channels, scheduler_svc, service_credentials, smart_test_svc,
    twofa_svc, ups_policy,
)

#: (label, bytes) — every reader is tried against each.
CORPSES = (
    ("truncated-json", b'{"keys": [{"id": "a", "na'),
    ("text-garbage", b"this is not json at all\n<<<>>>\n"),
    ("binary-junk", b"\x00\xff\xfe{" + b"\x80" * 32),
)


class _Corpses(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="serverhub-corrupt-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))

    def corpse(self, label: str, payload: bytes) -> Path:
        path = self.tmp / f"{label}.state"
        path.write_bytes(payload)
        return path

    def check_all(self, module, attr, reader, expect):
        """Patch *module.attr* to each corpse and assert *reader* degrades."""
        for label, payload in CORPSES:
            with self.subTest(corpse=label):
                with mock.patch.object(module, attr, self.corpse(label, payload)):
                    self.assertEqual(reader(), expect)


class StateReaderTolerance(_Corpses):
    def test_alert_state(self):
        self.check_all(alerts, "STATE_FILE", alerts._load_state, {})

    def test_alert_state_wrong_json_type_is_empty(self):
        """A JSON array used to raise ``prev.get`` and silence the alerter."""
        path = self.tmp / "alert_state.json"
        path.write_text("[]")
        with mock.patch.object(alerts, "STATE_FILE", path):
            self.assertEqual(alerts._load_state(), {})
        path.write_text('"oops"')
        with mock.patch.object(alerts, "STATE_FILE", path):
            self.assertEqual(alerts._load_state(), {})

    def test_alerts_journal(self):
        self.check_all(alerts, "ALERTS_FILE", alerts.list_alerts, [])

    def test_alerts_journal_mixed_corruption_keeps_good_lines(self):
        """One mangled line must cost that line, not the whole journal."""
        path = self.tmp / "alerts.jsonl"
        path.write_bytes(
            b'{"t": 1, "id": "ok-1"}\n'
            b"\xff\xfe not a line\n"
            b'{"t": 2, "id": "ok-2"}\n'
        )
        with mock.patch.object(alerts, "ALERTS_FILE", path):
            got = [a["id"] for a in alerts.list_alerts()]
        self.assertEqual(got, ["ok-2", "ok-1"], "newest first, corrupt line skipped")

    def test_alerts_journal_inf_field_does_not_500(self):
        """Starlette allow_nan=False: leftover Infinity used to 500 GET /api/alerts."""
        path = self.tmp / "alerts.jsonl"
        path.write_text(json.dumps({"t": 1, "id": "x", "cpu": float("inf")}) + "\n")
        with mock.patch.object(alerts, "ALERTS_FILE", path):
            got = alerts.list_alerts()
            leftover = alerts.list_alerts(float("inf"))
        self.assertEqual(got[0]["id"], "x")
        self.assertIsNone(got[0]["cpu"])
        json.dumps(got, allow_nan=False)
        self.assertEqual(leftover, got)

    def test_alerts_trim_survives_binary_junk(self):
        """The count-gated trim must keep working after a torn write."""
        path = self.tmp / "alerts.jsonl"
        path.write_bytes(b"\xff\xfe broken\n" * 10)
        with mock.patch.object(alerts, "ALERTS_FILE", path), \
             mock.patch.object(alerts, "_appends_since_trim", alerts._TRIM_EVERY - 1):
            alerts._append_alert({"t": 1, "id": "x"})  # crosses the trim gate
        self.assertIn(b'"id": "x"', path.read_bytes())

    def test_metrics_history_and_latest(self):
        for label, payload in CORPSES:
            with self.subTest(corpse=label):
                with mock.patch.object(metrics, "METRICS_FILE",
                                       self.corpse(label, payload)), \
                     mock.patch.object(metrics, "_last_sample", None):
                    self.assertEqual(metrics.history(60), [])
                    self.assertIsNone(metrics.latest_sample())

    def test_metrics_trim_survives_binary_junk(self):
        path = self.tmp / "metrics.jsonl"
        path.write_bytes(b"\xff\xfe broken\n" * 10)
        # _last_trim/_last_flush are patched so this test's flush cannot
        # shift the time gates other tests observe.
        with mock.patch.object(metrics, "METRICS_FILE", path), \
             mock.patch.object(metrics, "_last_trim", 0.0), \
             mock.patch.object(metrics, "_last_flush", 0.0):
            with metrics._lock:
                metrics._write_buf.append('{"t": 1}\n')
                metrics._flush_buf_locked(force_trim=True)
        self.assertIn(b'{"t": 1}', path.read_bytes())

    def test_schedule_runs_journal(self):
        self.check_all(scheduler_svc, "RUNS_PATH", scheduler_svc.runs, [])
        self.check_all(scheduler_svc, "RUNS_PATH", scheduler_svc.last_runs_by_job, {})

    def test_ups_policy_state(self):
        self.check_all(ups_policy, "STATE_FILE", ups_policy._load_state, {})

    def test_api_keys_store(self):
        self.check_all(api_keys, "STORE_FILE", api_keys._load, [])

    def test_twofa_store(self):
        self.check_all(twofa_svc, "STORE_FILE", twofa_svc._load, {})

    def test_twofa_non_object_user_row_does_not_500(self):
        """A list/string under the username used to raise ``entry.get`` on login."""
        path = self.tmp / "twofa.json"
        path.write_text(json.dumps({"admin": ["not", "a", "row"]}))
        with mock.patch.object(twofa_svc, "STORE_FILE", path):
            self.assertEqual(twofa_svc.status("admin")["enabled"], False)
            self.assertFalse(twofa_svc.enabled("admin"))
        path.write_text(json.dumps({"admin": "oops"}))
        with mock.patch.object(twofa_svc, "STORE_FILE", path):
            self.assertFalse(twofa_svc.enabled("admin"))

    def test_notify_secrets(self):
        self.check_all(notify_channels, "SECRETS_FILE",
                       notify_channels._load_secrets, {})

    def test_notify_non_object_channel_secrets_are_empty(self):
        path = self.tmp / "notify.json"
        path.write_text(json.dumps({"ha": ["token"]}))
        with mock.patch.object(notify_channels, "SECRETS_FILE", path):
            self.assertEqual(notify_channels.channel_secrets("ha"), {})

    def test_service_credentials_index(self):
        self.check_all(
            service_credentials, "INDEX_FILE", service_credentials._load, {},
        )

    def test_service_credentials_non_object_rows_are_dropped(self):
        path = self.tmp / "creds.json"
        path.write_text(json.dumps({
            "native:ok": {"username": "a"},
            "native:bad": ["nope"],
        }))
        with mock.patch.object(service_credentials, "INDEX_FILE", path):
            loaded = service_credentials._load()
        self.assertEqual(list(loaded), ["native:ok"])
        self.assertEqual(loaded["native:ok"]["username"], "a")

    def test_backup_json_object_survives_corpses(self):
        for label, payload in CORPSES:
            with self.subTest(corpse=label):
                path = self.corpse(label, payload)
                self.assertEqual(backups._json_object(path), {})

    def test_smart_test_history(self):
        self.check_all(smart_test_svc, "HISTORY_PATH",
                       smart_test_svc._load_history, [])

    def test_smart_test_history_drops_non_object_rows(self):
        path = self.tmp / "smart-tests.json"
        path.write_text(json.dumps([1, {"device": "/dev/disk4", "ok": True}, "x"]))
        with mock.patch.object(smart_test_svc, "HISTORY_PATH", path):
            got = smart_test_svc._load_history()
        self.assertEqual(got, [{"device": "/dev/disk4", "ok": True}])

    def test_wireguard_registry_drops_non_object_peers(self):
        from hub import wireguard_svc

        path = self.tmp / "wireguard-peers.json"
        path.write_text(json.dumps({
            "peers": {
                "good": {"name": "laptop"},
                "bad": ["nope"],
            },
        }))
        with mock.patch.object(wireguard_svc, "REGISTRY_PATH", path):
            got = wireguard_svc._load_registry()
        self.assertEqual(list(got["peers"]), ["good"])
        self.assertEqual(got["peers"]["good"]["name"], "laptop")

    def test_config_list_keys_drop_non_object_rows(self):
        from hub import config as cfgmod

        data = cfgmod._as_config({
            "apps": ["oops", {"id": "jellyfin"}],
            "stacks": ["x", {"id": "immich"}],
            "scripts": [1, {"id": "backup"}],
            "groups_order": ["a", "b"],
            "group_rules": ["oops", {"id": "smart-home", "group": "Home"}],
        })
        self.assertEqual(data["apps"], [{"id": "jellyfin"}])
        self.assertEqual(data["stacks"], [{"id": "immich"}])
        self.assertEqual(data["scripts"], [{"id": "backup"}])
        self.assertEqual(data["groups_order"], ["a", "b"])
        self.assertEqual(data["group_rules"], [{"id": "smart-home", "group": "Home"}])

    def test_settings_section_rejects_a_non_mapping(self):
        from hub import config as cfgmod

        with mock.patch.object(cfgmod, "cfg", return_value={
            "settings": {
                "notify": ["not", "a", "map"],
                "files": "nope",
                "maintenance_env": ["PATH=/tmp"],
                "thresholds": 90,
                "wireguard": None,
            },
        }):
            self.assertEqual(cfgmod.settings_section("notify"), {})
            self.assertEqual(cfgmod.settings_section("files"), {})
            self.assertEqual(cfgmod.settings_section("thresholds"), {})
            self.assertEqual(cfgmod.settings_section("wireguard"), {})
            self.assertEqual(cfgmod.maintenance_env(), {})
            self.assertEqual(cfgmod.settings_section("terminal"), {})
            self.assertEqual(cfgmod.settings_section("ups"), {})
            self.assertEqual(cfgmod.settings_section("smart_schedule"), {})
            self.assertEqual(cfgmod.settings_section("storage_pool"), {})
            self.assertEqual(cfgmod.settings_section("catalog_remote"), {})
            self.assertEqual(cfgmod.settings_section("ollama"), {})
            self.assertEqual(cfgmod.settings_section("vm_console"), {})

    def test_schedules_that_are_not_a_list_become_empty(self):
        from hub import config as cfgmod

        data = cfgmod._as_config({"schedules": 1})
        self.assertEqual(data["schedules"], [])
        data = cfgmod._as_config({"schedules": ["oops", {"id": "job-1"}]})
        self.assertEqual(data["schedules"], [{"id": "job-1"}])

    def test_notify_raw_cfg_and_dispatch_tolerate_a_list(self):
        from hub import notify_channels

        with mock.patch.object(notify_channels.config, "settings_section", return_value={}):
            self.assertEqual(notify_channels._raw_notify_cfg(), {})
        with mock.patch.object(
            notify_channels.config, "cfg",
            return_value={"settings": {"notify": ["x"]}},
        ):
            # settings_section is the real one; cfg is mocked so notify is a list.
            self.assertEqual(notify_channels._raw_notify_cfg(), {})
            result = notify_channels.dispatch("T", "m", level="down")
            self.assertFalse(result["ok"])

    def test_wireguard_conf_int_falls_back(self):
        from hub import wireguard_svc

        self.assertEqual(wireguard_svc._conf_int("51820/udp", 51820), 51820)
        self.assertEqual(wireguard_svc._conf_int("auto", 1420), 1420)
        self.assertEqual(wireguard_svc._conf_int(None, 51820), 51820)

    def test_cloudflared_state_wrong_json_type_is_empty(self):
        path = self.tmp / "cf-state.json"
        path.write_text("[]")
        with mock.patch.object(cloudflared_svc, "STATE_FILE", path):
            self.assertEqual(cloudflared_svc._load_state(), {})
        path.write_text('"oops"')
        with mock.patch.object(cloudflared_svc, "STATE_FILE", path):
            self.assertEqual(cloudflared_svc._load_state(), {})

    def test_cloudflared_nested_tunnel_name_is_coded_not_500(self):
        """A mapping leftover in tunnel_name used to raise ``dict.strip`` on Restart."""
        for value in ({"id": "home"}, ["home"], True):
            with self.subTest(value=value):
                with self.assertRaises(HTTPException) as ctx:
                    cloudflared_svc._tunnel_argv(value)
                self.assertEqual(ctx.exception.detail["code"], "cloudflared.invalid_name")
        # An unquoted numeric tunnel name is a real id, not junk: the old
        # isinstance gate silently refused to restart tunnel "1".
        self.assertEqual(cloudflared_svc._tunnel_argv(1), "1")
        with self.assertRaises(HTTPException) as ctx:
            cloudflared_svc._tunnel_argv("")
        self.assertEqual(ctx.exception.detail["code"], "cloudflared.tunnel_required")

        fake_token = mock.Mock()
        fake_token.is_file.return_value = False
        with (
            mock.patch.object(cloudflared_svc, "TOKEN_FILE", fake_token),
            mock.patch.object(
                cloudflared_svc, "_load_state",
                return_value={"tunnel_name": {"id": "x"}},
            ),
            mock.patch.object(cloudflared_svc, "_logged_in", return_value=True),
        ):
            with self.assertRaises(HTTPException) as ctx:
                cloudflared_svc.restart()
        self.assertEqual(ctx.exception.detail["code"], "cloudflared.invalid_name")

    def test_container_update_status_wrong_json_type_is_empty(self):
        path = self.tmp / "update-status.json"
        path.write_text("[]")
        with mock.patch.object(containers_svc, "UPDATE_STATUS_PATH", path):
            self.assertEqual(containers_svc._load_update_status(), {})
        path.write_text('"oops"')
        with mock.patch.object(containers_svc, "UPDATE_STATUS_PATH", path):
            self.assertEqual(containers_svc._load_update_status(), {})

    def test_metrics_non_numeric_t_is_coerced_or_skipped(self):
        import time as _time
        path = self.tmp / "metrics.jsonl"
        now = int(_time.time())
        path.write_text(
            json.dumps({"t": str(now), "cpu_used_pct": 3}) + "\n"
            + json.dumps({"t": float("inf"), "cpu_used_pct": 9}) + "\n"
            + '{"t": NaN, "cpu_used_pct": 8}\n'
        )
        with mock.patch.object(metrics, "METRICS_FILE", path), \
             mock.patch.object(metrics, "_last_sample", None):
            with metrics._lock:
                metrics._write_buf.clear()
            got = metrics.history(60)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["t"], now)
        self.assertEqual(got[0]["cpu_used_pct"], 3)

    def test_metrics_history_skips_non_object_rows(self):
        """A JSON array line used to raise ``list.get`` on /api/metrics."""
        import time as _time
        path = self.tmp / "metrics.jsonl"
        now = int(_time.time())
        path.write_text(
            f'[]\n"oops"\n{{"t": {now}, "cpu_used_pct": 1}}\n'
        )
        with mock.patch.object(metrics, "METRICS_FILE", path), \
             mock.patch.object(metrics, "_last_sample", None):
            with metrics._lock:
                metrics._write_buf.clear()
            got = metrics.history(60)
            self.assertEqual(len(got), 1)
            self.assertEqual(got[0]["cpu_used_pct"], 1)

        path.write_text('[]\n"oops"\n')
        with mock.patch.object(metrics, "METRICS_FILE", path), \
             mock.patch.object(metrics, "_last_sample", None):
            self.assertIsNone(metrics.latest_sample())
        path.write_text(f'[]\n{{"t": {now}, "cpu_used_pct": 2}}\n')
        with mock.patch.object(metrics, "METRICS_FILE", path), \
             mock.patch.object(metrics, "_last_sample", None):
            got = metrics.latest_sample()
            self.assertEqual(got["cpu_used_pct"], 2)

    def test_alerts_journal_skips_non_object_rows(self):
        path = self.tmp / "alerts.jsonl"
        path.write_text('[]\n{"t": 1, "id": "ok"}\n"nope"\n')
        with mock.patch.object(alerts, "ALERTS_FILE", path):
            got = alerts.list_alerts()
        self.assertEqual([a["id"] for a in got], ["ok"])

    def test_alerts_limit_zero_is_not_the_whole_file(self):
        """``lines[-0:]`` is the entire list in Python."""
        path = self.tmp / "alerts.jsonl"
        path.write_text('{"t": 1, "id": "a"}\n{"t": 2, "id": "b"}\n')
        with mock.patch.object(alerts, "ALERTS_FILE", path):
            got = alerts.list_alerts(0)
        self.assertEqual(len(got), 1)


class DockerInspectObjectTests(unittest.TestCase):
    def test_first_object_from_a_list(self):
        from hub.docker_cli import inspect_object
        self.assertEqual(inspect_object('[{"Id": "abc"}]'), {"Id": "abc"})

    def test_bare_object(self):
        from hub.docker_cli import inspect_object
        self.assertEqual(inspect_object('{"Id": "abc"}'), {"Id": "abc"})

    def test_docker_json_drops_non_objects(self):
        from hub import docker_cli

        with mock.patch.object(
            docker_cli, "docker",
            return_value=(0, '[1, {"Name": "n"}, "oops"]', ""),
        ):
            data, rc, err = docker_cli.docker_json(
                ["images", "--format", "{{json .}}"]
            )
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")
        self.assertEqual(data, [{"Name": "n"}])

    def test_empty_list_and_garbage_are_none(self):
        from hub.docker_cli import inspect_object
        self.assertIsNone(inspect_object("[]"))
        self.assertIsNone(inspect_object('"oops"'))
        self.assertIsNone(inspect_object("{"))
        self.assertIsNone(inspect_object("not json"))

    def test_deeply_nested_inspect_does_not_500(self):
        """``json.loads`` RecursionError is not ValueError; inspect used to 500."""
        from hub.docker_cli import inspect_object
        blob = "[" + '{"k":' * 12000 + "1" + "}" * 12000 + "]"
        self.assertIsNone(inspect_object(blob))

    def test_container_list_enrich_tolerates_a_bare_object(self):
        from hub import containers_svc

        def fake_docker(*args, **kwargs):
            if args and args[0] == "ps":
                return (0, "abc123\tnginx\tnginx:latest\trunning\tUp\t\t\t\t\n", "")
            return (
                0,
                '{"Name": "/nginx", "HostConfig": {"NetworkMode": "bridge",'
                ' "RestartPolicy": {"Name": "always"}},'
                ' "NetworkSettings": {"Networks": {}}}',
                "",
            )

        with mock.patch.object(containers_svc, "engine_up", return_value=True), \
             mock.patch.object(containers_svc, "docker", side_effect=fake_docker), \
             mock.patch.object(containers_svc, "override", return_value={}), \
             mock.patch.object(containers_svc, "resolve_value", side_effect=lambda x: x or {}), \
             mock.patch.object(containers_svc, "_load_update_status", return_value={}):
            ok, items = containers_svc._build_container_list()
        self.assertTrue(ok)
        self.assertEqual(items[0]["id"], "nginx")
        self.assertEqual(items[0]["network"], "bridge")

    def test_inspect_container_empty_list_is_not_found_not_500(self):
        from fastapi import HTTPException
        from hub import containers_svc

        with mock.patch.object(containers_svc, "docker", return_value=(0, "[]", "")):
            with self.assertRaises(HTTPException) as caught:
                containers_svc.inspect_container("nginx")
        self.assertEqual(caught.exception.status_code, 404)
        self.assertEqual(caught.exception.detail["code"], "container.not_found")

    def test_inspect_container_tolerates_non_object_nested_fields(self):
        from hub import containers_svc

        payload = json.dumps({
            "Id": "abc123def456",
            "Name": "/nginx",
            "Config": ["oops"],
            "HostConfig": "nope",
            "State": [],
            "NetworkSettings": [],
            "Mounts": {"0": {"Source": "/x"}},
        })
        with mock.patch.object(containers_svc, "docker", return_value=(0, payload, "")):
            info = containers_svc.inspect_container("nginx")
        self.assertEqual(info["Id"], "abc123def456")
        self.assertEqual(info["Env"], [])
        self.assertEqual(info["Networks"], [])
        self.assertEqual(info["Mounts"], [])

    def test_recreate_tolerates_non_string_inspect_fields(self):
        from hub import containers_svc

        payload = json.dumps({
            "HostConfig": {
                "RestartPolicy": {"Name": "unless-stopped"},
                "NetworkMode": 1,
                "PortBindings": {80: [{"HostPort": 8080, "HostIp": None}]},
                "Binds": ["/data:/data", 12],
            },
            "Config": {
                "Env": ["FOO=bar", {"not": "str"}, None],
                "Cmd": ["nginx", "-g", "daemon off;"],
            },
        })
        job = {"log": []}
        with mock.patch.object(containers_svc, "docker", return_value=(0, payload, "")):
            with mock.patch.object(containers_svc, "run_capped", return_value=(0, "")):
                ok = containers_svc._recreate_simple("nginx", "nginx:latest", job, {})
        self.assertTrue(ok)

    def test_container_list_enrich_survives_wrong_nested_types(self):
        """One bad inspect row used to abort enrichment for every container."""
        from hub import containers_svc

        inspect = json.dumps([
            {
                "Name": "/bad",
                "Created": 12345,
                "Config": {"Image": ["not", "a", "str"]},
                "HostConfig": {"NetworkMode": ["bridge"], "RestartPolicy": "always"},
                "NetworkSettings": {"Networks": {"n": {"IPAddress": 10}}},
                "Mounts": "nope",
            },
            {
                "Name": "/good",
                "Created": "2024-01-01T00:00:00Z",
                "Config": {"Image": "nginx:latest"},
                "HostConfig": {
                    "NetworkMode": "bridge",
                    "RestartPolicy": {"Name": "always"},
                },
                "NetworkSettings": {"Networks": {"n": {"IPAddress": "10.0.0.2"}}},
                "Mounts": [{"Source": "/a", "Destination": "/b", "Type": "bind"}],
            },
        ])
        ps = (
            "aaa\tbad\told:tag\trunning\tUp\t\t\t\t\n"
            "bbb\tgood\tnginx:latest\trunning\tUp\t\t\t\t\n"
        )

        def fake_docker(*args, **kwargs):
            if args and args[0] == "ps":
                return (0, ps, "")
            return (0, inspect, "")

        with mock.patch.object(containers_svc, "engine_up", return_value=True), \
             mock.patch.object(containers_svc, "docker", side_effect=fake_docker), \
             mock.patch.object(containers_svc, "override", return_value={}), \
             mock.patch.object(containers_svc, "resolve_value", side_effect=lambda x: x or {}), \
             mock.patch.object(
                 containers_svc, "_load_update_status",
                 return_value={"nginx:latest": "true", "old:tag": {"status": "false"}},
             ):
            ok, items = containers_svc._build_container_list()
        self.assertTrue(ok)
        by_id = {row["id"]: row for row in items}
        self.assertEqual(by_id["good"]["network"], "bridge")
        self.assertEqual(by_id["good"]["ip"], "10.0.0.2")
        self.assertEqual(by_id["good"]["image"], "nginx:latest")
        self.assertIsNone(by_id["good"]["update"])
        self.assertEqual(by_id["bad"]["image"], "old:tag")
        self.assertIsNone(by_id["bad"]["ip"])
        self.assertEqual(by_id["bad"]["network"], "n")
        self.assertEqual(by_id["bad"]["update"], False)

    def test_inspect_env_and_binds_drop_wrong_types(self):
        from hub import containers_svc

        payload = json.dumps({
            "Id": "abc123def456",
            "Name": "/nginx",
            "Config": {"Env": ["FOO=bar", 12, None, {"K": "V"}]},
            "HostConfig": {"Binds": {"/a": "/b"}},
        })
        with mock.patch.object(containers_svc, "docker", return_value=(0, payload, "")):
            info = containers_svc.inspect_container("nginx")
        self.assertEqual(info["Env"], ["FOO=bar"])
        self.assertEqual(info["Binds"], [])

    def test_docker_json_garbage_is_empty_not_raw_text(self):
        from hub import docker_cli

        with mock.patch.object(
            docker_cli, "docker", return_value=(0, "not json {{", ""),
        ):
            data, rc, err = docker_cli.docker_json(
                ["images", "--format", "{{json .}}"]
            )
        self.assertEqual(rc, 0)
        self.assertEqual(data, [])

        with mock.patch.object(docker_cli, "docker", return_value=(0, "42", "")):
            data, rc, err = docker_cli.docker_json(["images"])
        self.assertEqual(data, [])

    def test_list_images_drops_non_objects(self):
        from hub import containers_svc

        with mock.patch.object(
            containers_svc, "docker_json", return_value=("oops", 0, ""),
        ):
            self.assertEqual(containers_svc.list_images(), [])
        with mock.patch.object(
            containers_svc, "docker_json", return_value=({"Id": "x"}, 0, ""),
        ):
            self.assertEqual(containers_svc.list_images(), [{"Id": "x"}])


class ContainerJobStoreTypeTests(unittest.TestCase):
    def setUp(self):
        from hub import containers_svc
        self.svc = containers_svc
        self._saved = dict(containers_svc._cjobs)
        containers_svc._cjobs.clear()

    def tearDown(self):
        self.svc._cjobs.clear()
        self.svc._cjobs.update(self._saved)

    def test_latest_jobs_skips_unhashable_stack_ids(self):
        self.svc._cjobs["a"] = {
            "running": False, "stack_id": ["proj"], "action": "up",
            "log": [1, "ok"], "rc": 0,
        }
        self.svc._cjobs["b"] = {
            "running": False, "stack_id": "ok", "action": "up",
            "log": ["done"], "rc": 0,
        }
        got = self.svc.latest_stack_jobs()
        self.assertEqual([j["stack_id"] for j in got], ["ok"])
        log = self.svc.stack_job_log("a")
        self.assertIn("ok", log["log"])

    def test_register_coerces_non_str_stack_id(self):
        j = self.svc._register_job("t1", stack_id=["proj"], action="up")
        self.assertEqual(j["stack_id"], "")
        self.svc.latest_stack_jobs()

    def test_update_job_non_str_labels_are_not_unhashable(self):
        payload = json.dumps({
            "Config": {
                "Image": ["nginx", "latest"],
                "Labels": {
                    "com.docker.compose.project": ["p"],
                    "com.docker.compose.project.working_dir": 1,
                    "com.docker.compose.project.config_files": ["a.yml"],
                    "com.docker.compose.service": ["web"],
                },
            }
        })
        with mock.patch.object(self.svc, "docker", return_value=(0, payload, "")), \
             mock.patch.object(self.svc.threading, "Thread"):
            result = self.svc.start_update_container_job("nginx")
        self.assertTrue(result.get("ok"))
        self.svc.latest_stack_jobs()
        job = self.svc._cjobs[result["job_id"]]
        self.assertEqual(job["stack_id"], "nginx")


class ComposeYamlTypeTests(unittest.TestCase):
    def test_list_yaml_is_invalid_without_spawning_docker(self):
        from hub import compose_svc

        with mock.patch.object(compose_svc, "run_capped") as run:
            got = compose_svc.validate_compose_text("- not: a mapping\n- still: a list\n")
        self.assertFalse(got.get("ok"))
        run.assert_not_called()
        self.assertIn("mapping", got.get("message") or "")


class OrbListingTypeTests(unittest.TestCase):
    def test_json_non_list_machines_falls_through(self):
        from hub import vms_svc

        def fake_sh(cmd, **kw):
            if "-f" in cmd:
                return (0, json.dumps({"machines": 3}), "")
            return (0, "NAME STATE\nok running\n", "")

        with mock.patch.object(vms_svc, "_orb_available", return_value=True), \
             mock.patch.object(vms_svc, "sh", side_effect=fake_sh), \
             mock.patch.object(vms_svc, "override", return_value={}):
            items = vms_svc._list_orb_machines_uncached()
        self.assertEqual([i["orb_name"] for i in items], ["ok"])

    def test_json_non_str_fields_are_skipped_not_fatal(self):
        from hub import vms_svc
        payload = json.dumps([
            {"name": 1, "state": 2},
            {"name": "web", "state": "running"},
        ])

        def fake_sh(cmd, **kw):
            if "-f" in cmd:
                return (0, payload, "")
            return (1, "", "no")

        with mock.patch.object(vms_svc, "_orb_available", return_value=True), \
             mock.patch.object(vms_svc, "sh", side_effect=fake_sh), \
             mock.patch.object(vms_svc, "override", return_value={}):
            items = vms_svc._list_orb_machines_uncached()
        self.assertEqual([i["orb_name"] for i in items], ["web"])

    def test_bytes_json_listing_does_not_500(self):
        from hub import vms_svc
        payload = b'[{"name":"web","state":"running"}]'

        def fake_sh(cmd, **kw):
            if "-f" in cmd:
                return (0, payload, "")
            return (1, "", "no")

        with mock.patch.object(vms_svc, "_orb_available", return_value=True), \
             mock.patch.object(vms_svc, "sh", side_effect=fake_sh), \
             mock.patch.object(vms_svc, "override", return_value={}):
            items = vms_svc._list_orb_machines_uncached()
        self.assertEqual([i["orb_name"] for i in items], ["web"])

    def test_orb_shell_does_not_spawn_ssh(self):
        from hub import vms_svc

        with mock.patch.object(vms_svc, "_orb_available", return_value=True), \
             mock.patch.object(vms_svc, "sh") as sh:
            out = vms_svc._orb_action("web", "shell")
        sh.assert_not_called()
        self.assertTrue(out["ok"])
        self.assertEqual(out["command"], "orb -m web")
        self.assertIsInstance(out["message"], str)

    def test_utm_action_bytes_message_is_text(self):
        from hub import vms_svc

        with mock.patch.object(vms_svc, "_utm_available", return_value=True), \
             mock.patch.object(vms_svc, "sh", return_value=(0, b"started\n", b"")), \
             mock.patch.object(vms_svc, "_invalidate"):
            out = vms_svc._utm_action("Windows 11", "start")
        self.assertTrue(out["ok"])
        self.assertIsInstance(out["message"], str)
        self.assertIn("started", out["message"])


class MaintenanceJobIdTests(unittest.TestCase):
    def test_unhashable_job_id_does_not_raise(self):
        from hub import jobs
        self.assertIsNone(jobs.get_job(["x"]))
        self.assertIsNone(jobs.start_job({"id": ["x"], "command": "true"}))
        self.assertEqual(jobs.job_state(["x"])["running"], False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
