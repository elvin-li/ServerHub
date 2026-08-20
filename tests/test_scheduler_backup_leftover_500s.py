"""Leftover 500s on scheduler jobs, backup targets, and maintenance.

YAML ``.inf`` / JSON ``1e400`` used to OverflowError ``int()`` or leak into
Starlette's allow_nan=False encoder; a LaunchAgents tree that cannot be
listed used to raise on POST /api/backups/configs; a junk in-memory job
row used to AttributeError GET /api/maintenance/{id}/log.

Follow-up: YAML ``!!binary`` / ``!!set`` / ``.inf`` keys and tuple-inf still
leaked (``_jsonable`` only walked dict/list/float); an incomplete job dict
or ``log: [bytes]`` still 500'd the log endpoint; ``st_mtime = inf`` still
OverflowError'd GET /api/backups; leftover compose ``volumes: true`` / a
NUL bind path still raised out of stack backup.

Follow-up 2: leftover Infinity in PhotosHub backup_status.json, leftover
rsync ``--version`` / dry-run bytes, YAML timestamps / ``!!set`` SMART
kind, a leftover directory named like backup_status.json, dying-mount
EIO on is_file/is_dir, and ``int(inf)`` on the runs limit each still
500'd a request path.

Follow-up 3: leftover ``run_capped`` bytes/None still TypeError'd
``.strip`` / JSON on postgres/immich/config dumps and stack-mount probe.
"""
from __future__ import annotations

import asyncio
import datetime
import errno
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import urlencode

from fastapi import FastAPI
from fastapi.encoders import jsonable_encoder

from hub import audit, backups, config, jobs, rsync_svc, scheduler_svc, snapshots_svc
from hub.routers import api as api_router
from hub.routers import settings_api
from hub.routers.scheduler_api import job_runs, all_runs
from hub.routers.scheduler_api import router as scheduler_router


async def _asgi_request(method, path, *, payload=None, query=None):
    app = FastAPI()
    app.include_router(scheduler_router)
    body = json.dumps(payload).encode() if payload is not None else b""
    sent = False
    messages: list[dict] = []

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1", "method": method, "scheme": "http",
        "path": path, "raw_path": path.encode(),
        "query_string": urlencode(query or {}).encode(), "root_path": "",
        "headers": [(b"content-type", b"application/json")],
        "server": ("localhost", 8086), "client": ("127.0.0.1", 1), "state": {},
    }
    await app(scope, receive, send)
    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    raw = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    return status, json.loads(raw or b"{}")


def request(method, path, *, payload=None, query=None):
    return asyncio.run(_asgi_request(method, path, payload=payload, query=query))


class _Sandbox(unittest.TestCase):
    def setUp(self):
        root = Path(os.environ.get("TMPDIR", "/tmp")) / f"serverhub-leftover-{os.getpid()}-{id(self)}"
        (root / "data").mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        for target, value in (
            ("YAML_PATH", root / "services.yaml"),
            ("DATA_DIR", root / "data"),
            ("BASE", root),
        ):
            patched = mock.patch.object(config, target, value)
            patched.start()
            self.addCleanup(patched.stop)
        self.addCleanup(config.reload_cfg)
        runs = mock.patch.object(scheduler_svc, "RUNS_PATH", root / "data" / "runs.jsonl")
        runs.start()
        self.addCleanup(runs.stop)
        recorder = mock.patch.object(audit, "record", lambda *a, **k: {})
        recorder.start()
        self.addCleanup(recorder.stop)

    def _create(self, **overrides):
        body = {
            "name": "nightly cleanup", "type": "command", "cron": "30 3 * * *",
            "enabled": True, "params": {"command": "echo hi"},
        }
        body.update(overrides)
        return request("POST", "/api/scheduler/jobs", payload=body)


class SchedulerYamlInfTests(_Sandbox):
    def test_inf_job_fields_do_not_500_the_list(self):
        scheduler_svc.save_job({
            "id": "job-inf", "name": "nightly", "type": "command",
            "cron": "* * * * *", "enabled": True,
            "timeout": float("inf"),
            "params": {"command": "true", "extra": float("nan")},
        })
        status, body = request("GET", "/api/scheduler/jobs")
        self.assertEqual(status, 200, body)
        json.dumps(body, allow_nan=False)
        job = body["jobs"][0]
        self.assertEqual(job["id"], "job-inf")
        self.assertIsNone(job.get("timeout"))
        self.assertIsNone((job.get("params") or {}).get("extra"))

    def test_inf_run_journal_does_not_500_runs(self):
        scheduler_svc.RUNS_PATH.write_text(
            json.dumps({
                "ts": float("inf"), "job": "job-inf", "status": "ok",
                "duration": float("nan"), "rc": 0,
            }) + "\n",
            encoding="utf-8",
        )
        status, body = request("GET", "/api/scheduler/runs")
        self.assertEqual(status, 200, body)
        json.dumps(body, allow_nan=False)
        self.assertEqual(body["runs"][0]["job"], "job-inf")
        self.assertIsNone(body["runs"][0].get("ts"))
        self.assertIsNone(body["runs"][0].get("duration"))

    def test_deeply_nested_run_journal_does_not_500_runs(self):
        """``json.loads`` RecursionError is not ValueError; GET /api/scheduler/runs used to 500."""
        good = json.dumps({"ts": 1_700_000_000, "job": "job-ok", "status": "ok", "rc": 0})
        nested = '{"k":' * 12000 + "1" + "}" * 12000
        scheduler_svc.RUNS_PATH.write_text(nested + "\n" + good + "\n", encoding="utf-8")
        status, body = request("GET", "/api/scheduler/runs")
        self.assertEqual(status, 200, body)
        json.dumps(body, allow_nan=False)
        self.assertEqual(body["runs"][0]["job"], "job-ok")

    def test_inf_retain_is_coded_not_500(self):
        status, body = self._create(
            type="stack_backup",
            params={"stack_id": "photoprism", "retain": float("inf")},
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["detail"]["code"], "scheduler.bad_params")

    def test_inf_bwlimit_is_coded_not_500(self):
        status, body = self._create(
            type="rsync",
            params={
                "direction": "push", "src": "/data", "dest": "/backup",
                "bwlimit_kbps": float("inf"),
            },
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["detail"]["code"], "rsync.bad_params")

    def test_yaml_binary_set_and_inf_key_do_not_500_the_list(self):
        """``_jsonable`` used to walk dict/list/float only; these YAML leftovers leaked."""
        config.YAML_PATH.write_text(
            "settings: {}\n"
            "schedules:\n"
            "  - id: job-bin\n"
            "    name: !!binary |\n"
            "      //4=\n"
            "    type: command\n"
            "    cron: '* * * * *'\n"
            "    enabled: true\n"
            "    .inf: oops\n"
            "    params:\n"
            "      command: 'true'\n"
            "      tags: !!set\n"
            "        nightly: null\n"
            "        .nan: null\n",
            encoding="utf-8",
        )
        config.reload_cfg()
        status, body = request("GET", "/api/scheduler/jobs")
        self.assertEqual(status, 200, body)
        json.dumps(body, allow_nan=False)
        job = body["jobs"][0]
        self.assertEqual(job["id"], "job-bin")
        self.assertIsInstance(job["name"], str)
        self.assertIn("oops", job.values())
        tags = (job.get("params") or {}).get("tags")
        self.assertIsInstance(tags, list)
        self.assertIn("nightly", tags)
        self.assertIn(None, tags)

    def test_leftover_surrogate_job_name_does_not_500_the_list(self):
        """A leftover ``\\ud800`` name still 500'd GET /api/scheduler/jobs UTF-8."""
        job = {
            "id": "job-surr", "name": "\ud800nightly", "type": "command",
            "cron": "* * * * *", "enabled": True,
            "params": {"command": "true"},
        }
        with mock.patch.object(scheduler_svc, "list_jobs", return_value=[job]):
            status, body = request("GET", "/api/scheduler/jobs")
        self.assertEqual(status, 200, body)
        json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertNotIn("\ud800", body["jobs"][0]["name"])

    def test_tuple_inf_params_do_not_500_the_list(self):
        job = {
            "id": "job-tup", "name": "nightly", "type": "command",
            "cron": "* * * * *", "enabled": True,
            "params": {"command": "true", "load": (float("inf"), 1.0)},
        }
        with mock.patch.object(scheduler_svc, "list_jobs", return_value=[job]):
            status, body = request("GET", "/api/scheduler/jobs")
        self.assertEqual(status, 200, body)
        json.dumps(body, allow_nan=False)
        self.assertEqual((body["jobs"][0].get("params") or {}).get("load"), [None, 1.0])

    def test_yaml_timestamp_does_not_500_the_list(self):
        """YAML ``created: 2026-08-19`` used to leak a date the encoder then rejected."""
        config.YAML_PATH.write_text(
            "settings: {}\n"
            "schedules:\n"
            "  - id: job-date\n"
            "    name: nightly\n"
            "    type: command\n"
            "    cron: '* * * * *'\n"
            "    enabled: true\n"
            "    created: 2026-08-19\n"
            "    params:\n"
            "      command: 'true'\n"
            "      tags: !!set\n"
            "        2026-08-19: null\n",
            encoding="utf-8",
        )
        config.reload_cfg()
        status, body = request("GET", "/api/scheduler/jobs")
        self.assertEqual(status, 200, body)
        json.dumps(body, allow_nan=False)
        job = body["jobs"][0]
        self.assertEqual(job["id"], "job-date")
        self.assertIsInstance(job.get("created"), str)
        tags = (job.get("params") or {}).get("tags")
        self.assertIsInstance(tags, list)


class BridgedSmartLeftoverTests(_Sandbox):
    def test_inf_last_run_does_not_500_the_job_list(self):
        schedule = {
            "interval": "weekly", "kind": "short",
            "last_run": float("inf"), "devices": ["/dev/disk4"],
        }
        with mock.patch("hub.smart_test_svc.get_schedule", lambda: dict(schedule)):
            status, body = request("GET", "/api/scheduler/jobs")
        self.assertEqual(status, 200, body)
        json.dumps(body, allow_nan=False)
        self.assertEqual(body["system"][0]["last_run"], 0)
        self.assertTrue(body["system"][0]["readonly"])

    def test_non_dict_schedule_does_not_500_the_job_list(self):
        with mock.patch("hub.smart_test_svc.get_schedule", lambda: None):
            status, body = request("GET", "/api/scheduler/jobs")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["system"], [])

    def test_unhashable_interval_does_not_500_the_job_list(self):
        schedule = {
            "interval": ["weekly"], "kind": "short",
            "last_run": 1000, "devices": ["/dev/disk4"],
        }
        with mock.patch("hub.smart_test_svc.get_schedule", lambda: dict(schedule)):
            status, body = request("GET", "/api/scheduler/jobs")
        self.assertEqual(status, 200, body)
        json.dumps(body, allow_nan=False)
        self.assertEqual(body["system"][0]["interval"], "off")
        self.assertFalse(body["system"][0]["enabled"])

    def test_inf_kind_and_devices_do_not_500_the_job_list(self):
        schedule = {
            "interval": "weekly",
            "kind": float("inf"),
            "last_run": 1000,
            "devices": [float("inf"), "/dev/disk4", datetime.date(2026, 8, 19)],
        }
        with mock.patch("hub.smart_test_svc.get_schedule", lambda: dict(schedule)):
            status, body = request("GET", "/api/scheduler/jobs")
        self.assertEqual(status, 200, body)
        json.dumps(body, allow_nan=False)
        row = body["system"][0]
        self.assertIsNone(row.get("kind"))
        self.assertIn("/dev/disk4", row["devices"])
        self.assertIn(None, row["devices"])

    def test_yaml_date_kind_and_set_devices_do_not_500(self):
        schedule = {
            "interval": "weekly",
            "kind": datetime.date(2026, 8, 19),
            "last_run": 1000,
            "devices": {"/dev/disk4"},
        }
        with mock.patch("hub.smart_test_svc.get_schedule", lambda: dict(schedule)):
            status, body = request("GET", "/api/scheduler/jobs")
        self.assertEqual(status, 200, body)
        json.dumps(body, allow_nan=False)
        row = body["system"][0]
        self.assertIsInstance(row.get("kind"), str)
        self.assertEqual(row["devices"], [])


class MaintenanceLeftoverTests(unittest.TestCase):
    def tearDown(self):
        jobs._jobs.clear()

    def test_inf_name_does_not_500_the_list(self):
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": [
            {"id": "backup-pg", "name": float("inf"), "desc": float("nan")},
        ]}):
            rows = api_router.api_maintenance()
        json.dumps(jsonable_encoder(rows), allow_nan=False)
        self.assertEqual(rows[0]["id"], "backup-pg")
        self.assertEqual(rows[0]["name"], "backup-pg")

    def test_junk_job_row_does_not_500_log(self):
        jobs._jobs["ghost"] = "not-a-dict"
        self.assertFalse(jobs.job_state("ghost")["running"])
        body = api_router.api_maintenance_log("ghost")
        json.dumps(body, allow_nan=False)
        self.assertIn("not run yet", body["log"])

    def test_bytes_name_and_set_desc_do_not_500_the_list(self):
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": [
            {
                "id": "backup-pg",
                "name": b"\xff Backup",
                "desc": {float("nan"), "weekly"},
            },
        ]}):
            rows = api_router.api_maintenance()
        json.dumps(jsonable_encoder(rows), allow_nan=False)
        self.assertEqual(rows[0]["id"], "backup-pg")
        self.assertIsInstance(rows[0]["name"], str)
        self.assertIsInstance(rows[0]["desc"], list)
        self.assertIn("weekly", rows[0]["desc"])
        self.assertIn(None, rows[0]["desc"])

    def test_incomplete_row_and_bytes_log_do_not_500(self):
        jobs._jobs["ghost"] = {}
        body = api_router.api_maintenance_log("ghost")
        json.dumps(jsonable_encoder(body), allow_nan=False)
        self.assertFalse(body["running"])
        self.assertIn("waiting", body["log"])

        jobs._jobs["ghost"] = {
            "running": False, "rc": float("inf"), "started": "00:00:00",
            "finished": float("nan"), "log": [b"ok", None, 1, "done"],
        }
        body = api_router.api_maintenance_log("ghost")
        json.dumps(jsonable_encoder(body), allow_nan=False)
        self.assertIsNone(body["rc"])
        self.assertIsNone(body["finished"])
        self.assertIn("ok", body["log"])
        self.assertIn("done", body["log"])
        self.assertNotIn("None", body["log"])

    def test_inf_rc_does_not_500_the_list(self):
        jobs._jobs["backup-pg"] = {
            "running": False, "rc": float("inf"), "finished": float("nan"),
        }
        with mock.patch.object(jobs, "cfg", return_value={"maintenance": [
            {"id": "backup-pg", "name": "Backup"},
        ]}):
            rows = api_router.api_maintenance()
        json.dumps(jsonable_encoder(rows), allow_nan=False)
        self.assertEqual(rows[0]["id"], "backup-pg")
        self.assertIsNone(rows[0]["rc"])
        self.assertIsNone(rows[0]["finished"])


class BackupLeftoverTests(unittest.TestCase):
    def test_inf_pg_port_is_dropped_not_500(self):
        parsed = backups.pg_targets([
            {"id": "bad", "db": "d", "port": float("inf")},
            {"id": "good", "db": "d", "port": 5432},
        ])
        self.assertEqual([t["id"] for t in parsed], ["good"])
        json.dumps(parsed, allow_nan=False)

    def test_unreadable_launchagents_does_not_500_config_backup(self):
        root = Path(tempfile.mkdtemp(prefix="serverhub-cfgbak-oserr-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        backup_root = root / "backups"
        backup_root.mkdir()
        config_file = root / "services.yaml"
        config_file.write_text("settings: {}\n")
        home = root / "home"
        library = home / "Library"
        library.mkdir(parents=True)
        (library / "LaunchAgents").mkdir()
        os.chmod(library, 0)
        self.addCleanup(os.chmod, library, 0o755)

        calls: list[list[str]] = []

        def fake_capped(argv, timeout=10, env=None, cwd=None, cap=2048):
            calls.append(list(argv))
            Path(argv[2]).write_bytes(b"x" * 2048)
            return 0, ""

        with mock.patch.object(backups, "BACKUP_ROOT", backup_root), \
             mock.patch.object(backups, "CONFIG_FILE", config_file), \
             mock.patch.object(backups, "DATA_DIR", root / "empty-data"), \
             mock.patch.object(backups, "cfg", lambda: {}), \
             mock.patch.object(Path, "home", return_value=home), \
             mock.patch.object(backups, "run_capped", fake_capped):
            result = backups._backup_configs()
        self.assertTrue(result["ok"], result)
        self.assertEqual(calls[0][3:], [str(config_file)])

    def test_huge_size_does_not_500_scan(self):
        """A 400-digit leftover ``st_size`` OverflowError'd GET /api/backups."""
        root = Path(tempfile.mkdtemp(prefix="serverhub-bak-size-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        artefact = root / "teslamate_20260819_000000.sql.bak"
        artefact.write_bytes(b"dump")
        real_stat = Path.stat

        def fake_stat(self, *a, **k):
            st = real_stat(self, *a, **k)
            if self.name == artefact.name:
                return type("St", (), {
                    "st_size": 10 ** 400,
                    "st_mtime": st.st_mtime,
                    "st_mode": st.st_mode,
                })()
            return st

        with mock.patch.object(backups, "BACKUP_ROOT", root), \
             mock.patch.object(backups, "DATA_DIR", root / "empty-data"), \
             mock.patch.object(Path, "home", return_value=root / "no-home"), \
             mock.patch.object(Path, "stat", fake_stat):
            rows = backups.scan_backups()
        json.dumps(rows, allow_nan=False)
        self.assertEqual(rows, [])

    def test_inf_mtime_does_not_500_scan(self):
        root = Path(tempfile.mkdtemp(prefix="serverhub-bak-mtime-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        artefact = root / "teslamate_20260819_000000.sql.bak"
        artefact.write_bytes(b"dump")
        real_stat = Path.stat

        def fake_stat(self, *a, **k):
            st = real_stat(self, *a, **k)
            if self.name == artefact.name:
                return type("St", (), {
                    "st_size": st.st_size,
                    "st_mtime": float("inf"),
                    "st_mode": st.st_mode,
                })()
            return st

        with mock.patch.object(backups, "BACKUP_ROOT", root), \
             mock.patch.object(backups, "DATA_DIR", root / "empty-data"), \
             mock.patch.object(Path, "home", return_value=root / "no-home"), \
             mock.patch.object(Path, "stat", fake_stat):
            rows = backups.scan_backups()
        json.dumps(rows, allow_nan=False)
        self.assertEqual(rows, [])

    def test_inf_immich_mtime_is_dropped_not_500(self):
        root = Path(tempfile.mkdtemp(prefix="serverhub-immich-mtime-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        dump = root / "immich_20260819_000000.sql.gz"
        dump.write_bytes(b"gz")
        real_stat = Path.stat

        def fake_stat(self, *a, **k):
            st = real_stat(self, *a, **k)
            if self.name == dump.name:
                return type("St", (), {
                    "st_size": st.st_size,
                    "st_mtime": float("nan"),
                    "st_mode": st.st_mode,
                })()
            return st

        with mock.patch.object(backups, "BACKUP_ROOT", root), \
             mock.patch.object(Path, "stat", fake_stat):
            self.assertIsNone(backups._immich_latest())

    def test_jsonable_tuple_inf_bytes_and_inf_key(self):
        out = backups._jsonable({
            float("inf"): 1,
            "pct": (float("inf"), 1.0),
            "note": b"\xff\xfe",
        })
        json.dumps(out, allow_nan=False)
        self.assertEqual(out["pct"], [None, 1.0])
        self.assertIsInstance(out["note"], str)
        self.assertEqual(out.get("inf"), 1)

    def test_jsonable_surrogate_reason_and_key_do_not_500(self):
        """A leftover ``\\ud800`` in backup_status.json still 500'd GET /api/backups UTF-8."""
        out = backups._jsonable({
            "reason": "\ud800oops",
            "size_human": "12G",
            "\ud800": "x",
        })
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertNotIn("\ud800", out["reason"])
        self.assertNotIn("\ud800", out)

    def test_inf_written_bytes_does_not_leak_into_json(self):
        """FUSE ``st_size = inf`` used to 500 POST /api/backups/* under allow_nan=False."""
        root = Path(tempfile.mkdtemp(prefix="serverhub-bak-wbytes-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        dest = root / "teslamate_20260819_000000.sql.bak"
        dest.write_bytes(b"dump")
        real_stat = Path.stat

        def fake_stat(self, *a, **k):
            st = real_stat(self, *a, **k)
            if self.name == dest.name:
                return type("St", (), {
                    "st_size": float("inf"),
                    "st_mtime": st.st_mtime,
                    "st_mode": st.st_mode,
                })()
            return st

        with mock.patch.object(Path, "stat", fake_stat):
            size = backups._written_bytes(dest)
        self.assertEqual(size, 0)
        json.dumps({"size_mb": round(size / 1024 / 1024, 2) if size else 0}, allow_nan=False)

    def test_scan_surrogate_filename_does_not_500(self):
        """A leftover ``\\ud800`` artefact name still 500'd GET /api/backups UTF-8."""
        class FakePath:
            suffix = ".bak"
            name = "\ud800.sql.bak"
            parent = Path("/tmp")

            def is_file(self):
                return True

            def stat(self):
                return type("St", (), {
                    "st_size": 10,
                    "st_mtime": 1_700_000_000,
                    "st_mode": 0,
                })()

            def __str__(self):
                return "/tmp/\ud800.sql.bak"

        root = Path(tempfile.mkdtemp(prefix="serverhub-bak-surr-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        with mock.patch.object(backups, "BACKUP_ROOT", root), \
             mock.patch.object(backups, "DATA_DIR", root / "empty-data"), \
             mock.patch.object(Path, "home", return_value=root / "no-home"), \
             mock.patch.object(Path, "is_dir", lambda self: self == root), \
             mock.patch.object(Path, "rglob", lambda self, pat: [FakePath()]):
            rows = backups.scan_backups()
        json.dumps(rows, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertEqual(len(rows), 1)
        self.assertNotIn("\ud800", rows[0]["name"])
        self.assertNotIn("\ud800", rows[0]["path"])

    def test_non_list_volumes_and_nul_bind_do_not_raise(self):
        compose = {
            "services": {
                "app": {"volumes": True},
                "db": {"volumes": [
                    {"type": "bind", "source": "/tmp/\x00data", "target": "/d"},
                    {"type": "volume", "source": "ok", "target": "/v"},
                ]},
            },
            "volumes": {"ok": {"name": "stack_ok"}},
        }
        with mock.patch.object(
            backups, "_run_argv",
            return_value=(0, json.dumps(compose), ""),
        ):
            binds, volumes, err = backups._stack_mounts("/tmp/c.yml", None)
        self.assertEqual(err, "")
        self.assertEqual(binds, [])
        self.assertEqual(volumes, ["stack_ok"])


class BackupStateJsonLeftoverTests(unittest.TestCase):
    def test_inf_backup_status_does_not_500_the_page(self):
        root = Path(tempfile.mkdtemp(prefix="serverhub-bak-state-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        state = root / "state"
        state.mkdir()
        (state / "backup_status.json").write_text(
            '{"ok": true, "last_success": Infinity, "last_attempt": NaN,'
            ' "size_human": "12G", "reason": "ok"}',
            encoding="utf-8",
        )
        (state / "panel_status.json").write_text(
            '{"backup": {"ok": true, "last_success": 1e400},'
            ' "originals": {"local_original_pct": Infinity, "assets_active": 3}}',
            encoding="utf-8",
        )
        with (
            mock.patch.object(backups, "PHOTOSHUB_CFG", root / "missing.json"),
            mock.patch.object(backups, "PHOTOSHUB_STATE", state),
            mock.patch.object(backups, "BACKUP_ROOT", root / "nobackups"),
            mock.patch.object(backups, "scan_backups", return_value=[]),
            mock.patch.object(backups, "pg_targets", return_value=[]),
        ):
            body = settings_api.get_backups()
        json.dumps(body, allow_nan=False)
        backup = body["immich"]["layers"]["originals"]["backup"]
        self.assertEqual(backup.get("size_human"), "12G")
        self.assertNotIn("last_success", backup)
        self.assertNotIn("pct", body["immich"]["layers"]["originals"])

    def test_surrogate_backup_status_does_not_500_the_page(self):
        """A leftover ``\\ud800`` reason still 500'd GET /api/backups UTF-8."""
        root = Path(tempfile.mkdtemp(prefix="serverhub-bak-surr-status-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        state = root / "state"
        state.mkdir()
        (state / "backup_status.json").write_text(
            '{"ok": true, "reason": "\\ud800oops", "size_human": "12G",'
            ' "\\ud800": 1}',
            encoding="utf-8",
        )
        with (
            mock.patch.object(backups, "PHOTOSHUB_CFG", root / "missing.json"),
            mock.patch.object(backups, "PHOTOSHUB_STATE", state),
            mock.patch.object(backups, "BACKUP_ROOT", root / "nobackups"),
            mock.patch.object(backups, "scan_backups", return_value=[]),
            mock.patch.object(backups, "pg_targets", return_value=[]),
        ):
            body = settings_api.get_backups()
        json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        backup = body["immich"]["layers"]["originals"]["backup"]
        self.assertEqual(backup.get("size_human"), "12G")
        self.assertNotIn("\ud800", backup.get("reason", ""))
        self.assertNotIn("\ud800", backup)

    def test_leftover_directory_named_status_json_does_not_500(self):
        root = Path(tempfile.mkdtemp(prefix="serverhub-bak-dirfile-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        cfg = root / "config.json"
        cfg.mkdir()
        state = root / "state"
        state.mkdir()
        (state / "backup_status.json").mkdir()
        (state / "panel_status.json").mkdir()
        (state / "external_backup_status.json").mkdir()
        with (
            mock.patch.object(backups, "PHOTOSHUB_CFG", cfg),
            mock.patch.object(backups, "PHOTOSHUB_STATE", state),
            mock.patch.object(backups, "BACKUP_ROOT", root / "nobackups"),
        ):
            layers = backups.immich_layers()
        json.dumps(layers, allow_nan=False)
        self.assertEqual(layers["originals"]["backup"], {})

    def test_leftover_credentials_directory_is_not_chmodded(self):
        root = Path(tempfile.mkdtemp(prefix="serverhub-bak-creds-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        creds = root / "backup-credentials.json"
        creds.mkdir()
        os.chmod(creds, 0o755)
        with mock.patch.object(backups, "BACKUP_SECRETS_FILE", creds):
            self.assertEqual(backups._pg_password("teslamate"), "")
        self.assertTrue(creds.is_dir())
        self.assertEqual(creds.stat().st_mode & 0o777, 0o755)

    def test_deeply_nested_credentials_do_not_500_password(self):
        """``json.loads`` RecursionError is not ValueError; POST /api/backups/postgres used to 500."""
        root = Path(tempfile.mkdtemp(prefix="serverhub-bak-nested-creds-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        creds = root / "backup-credentials.json"
        creds.write_text('{"k":' * 12000 + "1" + "}" * 12000, encoding="utf-8")
        with mock.patch.object(backups, "BACKUP_SECRETS_FILE", creds):
            self.assertEqual(backups._pg_password("teslamate"), "")

    def test_huge_credentials_do_not_oom_password(self):
        """``read_text()`` of leftover multi-MB backup-credentials.json used to OOM dump."""
        root = Path(tempfile.mkdtemp(prefix="serverhub-bak-huge-creds-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        creds = root / "backup-credentials.json"
        creds.write_bytes(b"x" * (2 * 1024 * 1024))
        with mock.patch.object(backups, "BACKUP_SECRETS_FILE", creds):
            self.assertEqual(backups._pg_password("teslamate"), "")

    def test_deeply_nested_status_json_does_not_500_the_page(self):
        """``json.loads`` RecursionError is not ValueError; GET /api/backups used to 500."""
        root = Path(tempfile.mkdtemp(prefix="serverhub-bak-nested-status-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        state = root / "state"
        state.mkdir()
        nested = '{"k":' * 12000 + "1" + "}" * 12000
        (state / "backup_status.json").write_text(nested, encoding="utf-8")
        (state / "panel_status.json").write_text(nested, encoding="utf-8")
        with (
            mock.patch.object(backups, "PHOTOSHUB_CFG", root / "missing.json"),
            mock.patch.object(backups, "PHOTOSHUB_STATE", state),
            mock.patch.object(backups, "BACKUP_ROOT", root / "nobackups"),
            mock.patch.object(backups, "scan_backups", return_value=[]),
            mock.patch.object(backups, "pg_targets", return_value=[]),
        ):
            body = settings_api.get_backups()
        json.dumps(body, allow_nan=False)
        self.assertEqual(body["immich"]["layers"]["originals"]["backup"], {})

    def test_huge_status_json_does_not_oom_the_page(self):
        """``read_text()`` of leftover multi-MB backup_status.json used to OOM GET /api/backups."""
        root = Path(tempfile.mkdtemp(prefix="serverhub-bak-huge-status-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        state = root / "state"
        state.mkdir()
        (state / "backup_status.json").write_bytes(b"x" * (2 * 1024 * 1024))
        (state / "panel_status.json").write_bytes(b"x" * (2 * 1024 * 1024))
        with (
            mock.patch.object(backups, "PHOTOSHUB_CFG", root / "missing.json"),
            mock.patch.object(backups, "PHOTOSHUB_STATE", state),
            mock.patch.object(backups, "BACKUP_ROOT", root / "nobackups"),
            mock.patch.object(backups, "scan_backups", return_value=[]),
            mock.patch.object(backups, "pg_targets", return_value=[]),
        ):
            body = settings_api.get_backups()
        json.dumps(body, allow_nan=False)
        self.assertEqual(body["immich"]["layers"]["originals"]["backup"], {})

    def test_huge_immich_env_does_not_oom_layers(self):
        root = Path(tempfile.mkdtemp(prefix="serverhub-bak-huge-env-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        (root / ".env").write_bytes(b"x" * (2 * 1024 * 1024))
        with mock.patch.object(backups, "IMMICH_ROOT", root):
            self.assertEqual(backups._immich_media_from_env(), "")

    def test_huge_db_env_is_unreadable_not_oom(self):
        root = Path(tempfile.mkdtemp(prefix="serverhub-bak-huge-dbenv-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        path = root / "db.env"
        path.write_bytes(b"x" * (2 * 1024 * 1024))
        with mock.patch.object(backups, "IMMICH_DB_ENV", path):
            with self.assertRaises(RuntimeError):
                backups._immich_conn()

    def test_file_occupying_backup_root_does_not_500_config_backup(self):
        root = Path(tempfile.mkdtemp(prefix="serverhub-bak-rootfile-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        backup_root = root / "backups"
        backup_root.write_text("i am a file")
        config_file = root / "services.yaml"
        config_file.write_text("settings: {}\n")
        with mock.patch.object(backups, "BACKUP_ROOT", backup_root), \
             mock.patch.object(backups, "CONFIG_FILE", config_file), \
             mock.patch.object(backups, "DATA_DIR", root / "empty-data"), \
             mock.patch.object(backups, "cfg", lambda: {}), \
             mock.patch.object(Path, "home", return_value=root / "no-home"):
            result = backups.backup_configs()
        self.assertFalse(result["ok"], result)
        json.dumps(result, allow_nan=False)

    def test_scan_home_runtimeerror_does_not_500(self):
        """``Path.home()`` RuntimeError used to 500 GET /api/backups artefact scan."""
        missing = Path("/tmp/serverhub-no-backup-home-leftover")
        with (
            mock.patch.object(Path, "home", side_effect=RuntimeError("HOME")),
            mock.patch.object(backups, "BACKUP_ROOT", missing),
            mock.patch.object(backups, "DATA_DIR", missing),
        ):
            rows = backups.scan_backups()
        self.assertEqual(rows, [])
        json.dumps(rows, allow_nan=False)

    def test_eio_on_immich_paths_does_not_500_the_page(self):
        def eio(self, *a, **k):
            raise OSError(errno.EIO, "I/O error")

        with (
            mock.patch.object(Path, "is_file", eio),
            mock.patch.object(Path, "is_dir", eio),
            mock.patch.object(backups, "scan_backups", return_value=[]),
            mock.patch.object(backups, "pg_targets", return_value=[]),
        ):
            body = settings_api.get_backups()
        json.dumps(body, allow_nan=False)
        self.assertFalse(body["immich"]["available"])


class RsyncBytesAndEioTests(unittest.TestCase):
    def setUp(self):
        with rsync_svc._preview_guard:
            rsync_svc._preview_running.clear()
        rsync_svc.invalidate()
        self.addCleanup(rsync_svc.invalidate)

    def test_probe_leftover_bytes_do_not_500(self):
        def fake_is_file(self):
            return str(self) == "/usr/bin/rsync"

        with mock.patch.object(Path, "is_file", fake_is_file), \
             mock.patch.object(
                 rsync_svc, "sh",
                 return_value=(0, b"rsync  version 3.4.1  protocol version 32\n", b""),
             ):
            info = rsync_svc.probe_rsync()
        json.dumps(info, allow_nan=False)
        self.assertTrue(info["available"])
        self.assertEqual(info["variant"], "rsync3")

    def test_probe_is_file_eio_does_not_500(self):
        with mock.patch.object(
            Path, "is_file",
            side_effect=OSError(errno.EIO, "I/O error"),
        ):
            info = rsync_svc.probe_rsync()
        json.dumps(info, allow_nan=False)
        self.assertFalse(info["available"])

    def test_preview_leftover_bytes_lines_do_not_500(self):
        class Pipe:
            def __init__(self, chunks):
                self.chunks = list(chunks)

            def readline(self, cap=-1):
                return self.chunks.pop(0) if self.chunks else ""

            def close(self):
                pass

        class Proc:
            def __init__(self):
                self.stdout = Pipe([b">f+++++++++ new/file.txt\n", b""])
                self.stderr = Pipe([b"permission denied\n", b""])
                self.pid = 2 ** 22 + 1
                self.returncode = None

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                self.returncode = 0
                return 0

        info = {
            "available": True, "path": "/usr/bin/rsync",
            "variant": "rsync3", "version": "3.4.1",
            "supports": {"itemize": True, "progress2": True,
                         "compress": True, "bwlimit": True},
        }
        with mock.patch.object(rsync_svc, "binary_info", lambda force=False: info), \
             mock.patch.object(rsync_svc.subprocess, "Popen", lambda *a, **k: Proc()):
            summary = rsync_svc.preview(
                {"direction": "push", "src": "/data", "dest": "/backup"}
            )
        json.dumps(summary, allow_nan=False)
        self.assertEqual(summary["creates"], 1)
        self.assertIn("permission denied", summary["message"])

    def test_parse_dry_run_leftover_bytes_do_not_500(self):
        summary = rsync_svc.parse_dry_run(
            b">f+++++++++ new/file.txt\n*deleting   gone.txt\n",
            itemize=True,
        )
        json.dumps(summary, allow_nan=False)
        self.assertEqual(summary["creates"], 1)
        self.assertEqual(summary["deletes"], 1)


class SnapshotBytesLeftoverTests(unittest.TestCase):
    def test_latestbackup_bytes_do_not_500(self):
        with mock.patch.object(
            snapshots_svc, "sh",
            return_value=(0, b"/Volumes/TM/2026-08-03-160000", ""),
        ):
            latest = snapshots_svc._tm_latest_backup()
        self.assertIn("2026-08-03-160000", latest)
        self.assertEqual(
            snapshots_svc._snapshot_date(latest), "2026-08-03-160000"
        )
        json.dumps({"latest": latest}, allow_nan=False)

    def test_latestbackup_none_and_int_do_not_500(self):
        with mock.patch.object(snapshots_svc, "sh", return_value=(0, None, "")):
            self.assertEqual(snapshots_svc._tm_latest_backup(), "")
        with mock.patch.object(snapshots_svc, "sh", return_value=(0, 123, "")):
            self.assertEqual(snapshots_svc._tm_latest_backup(), "123")

    def test_create_snapshot_leftover_none_int_does_not_500(self):
        with mock.patch.object(snapshots_svc, "sh", return_value=(1, None, 5)):
            result = snapshots_svc.create_snapshot()
        json.dumps(result, allow_nan=False)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "failed")

    def test_overview_leftover_bytes_latest_does_not_500(self):
        snapshots_svc.invalidate()
        self.addCleanup(snapshots_svc.invalidate)
        with (
            mock.patch.object(
                snapshots_svc, "_tm_destinations",
                return_value={"Destinations": []},
            ),
            mock.patch.object(snapshots_svc, "_tm_status", return_value={}),
            mock.patch.object(
                snapshots_svc, "sh",
                return_value=(0, b"/Volumes/TM/2026-08-03-160000", ""),
            ),
        ):
            out = snapshots_svc.time_machine_overview()
        json.dumps(out, allow_nan=False)
        self.assertIn("2026-08-03-160000", out["latest_backup"])


class BackupRunCappedLeftoverTests(unittest.TestCase):
    def test_pg_dump_bytes_and_none_do_not_500(self):
        """Leftover ``run_capped`` bytes used to TypeError POST /api/backups/postgres."""
        root = Path(tempfile.mkdtemp(prefix="serverhub-pg-leftover-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        target = {
            "id": "pg", "host": "127.0.0.1", "port": 5432,
            "user": "u", "db": "d", "password_env": "",
        }
        for payload in (b"DUMP OK", None, 7):
            with mock.patch.object(backups, "BACKUP_ROOT", root), \
                 mock.patch.object(backups, "_private_dest", lambda p: p), \
                 mock.patch.object(backups, "_written_bytes", return_value=100), \
                 mock.patch.object(backups, "_discard"), \
                 mock.patch.object(backups, "_prune"), \
                 mock.patch.object(backups, "_pg_env", return_value={}), \
                 mock.patch.object(backups, "run_capped", return_value=(0, payload)):
                out = backups._dump_one_postgres(target)
            json.dumps(out, allow_nan=False)
            self.assertIsInstance(out["message"], str)

    def test_immich_script_bytes_do_not_500(self):
        root = Path(tempfile.mkdtemp(prefix="serverhub-immich-leftover-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        script = root / "backup-db.sh"
        script.write_text("#!/bin/sh\n")
        with mock.patch.object(backups, "BACKUP_ROOT", root), \
             mock.patch.object(backups, "IMMICH_ROOT", root), \
             mock.patch.object(backups, "IMMICH_SCRIPT", script), \
             mock.patch.object(
                 backups, "_immich_latest",
                 return_value={"name": "immich_x.sql.gz", "size_mb": 1},
             ), \
             mock.patch.object(backups, "run_capped", return_value=(0, b"ok")):
            out = backups._backup_immich_script()
        json.dumps(out, allow_nan=False)
        self.assertIsInstance(out["message"], str)

    def test_immich_script_recursing_exc_does_not_500(self):
        """``str(exc)`` RecursionError used to 500 POST /api/backups/immich."""
        class Recursing(Exception):
            def __str__(self):
                raise RecursionError("nested")

        root = Path(tempfile.mkdtemp(prefix="serverhub-immich-recursing-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        with mock.patch.object(backups, "BACKUP_ROOT", root), \
             mock.patch.object(backups, "IMMICH_ROOT", root), \
             mock.patch.object(backups, "IMMICH_SCRIPT", root / "backup-db.sh"), \
             mock.patch.object(backups, "run_capped", side_effect=Recursing()):
            out = backups._backup_immich_script()
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertFalse(out["ok"])
        self.assertEqual(out["message"], "Recursing")

    def test_immich_native_recursing_conn_does_not_500(self):
        class Recursing(Exception):
            def __str__(self):
                raise RecursionError("nested")

        with mock.patch.object(backups, "_pg18_dump", return_value="/bin/true"), \
             mock.patch.object(backups, "_immich_conn", side_effect=Recursing()):
            out = backups._backup_immich_native()
        json.dumps(out, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.assertFalse(out["ok"])
        self.assertEqual(out["message"], "Recursing")

    def test_stack_mounts_none_and_bytes_do_not_500(self):
        """Leftover None from ``run_capped`` used to AttributeError ``.strip``."""
        with mock.patch.object(backups, "run_capped", return_value=(1, None)):
            binds, vols, err = backups._stack_mounts("/tmp/c.yml", None)
        json.dumps({"err": err}, allow_nan=False)
        self.assertIsInstance(err, str)
        with mock.patch.object(backups, "run_capped", return_value=(1, b"fail")):
            binds, vols, err = backups._stack_mounts("/tmp/c.yml", None)
        json.dumps({"err": err}, allow_nan=False)
        self.assertIsInstance(err, str)

    def test_configs_bytes_message_does_not_500(self):
        root = Path(tempfile.mkdtemp(prefix="serverhub-cfg-leftover-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        backup_root = root / "backups"
        backup_root.mkdir()
        config_file = root / "services.yaml"
        config_file.write_text("settings: {}\n")
        dest = backup_root / "configs_leftover.tgz"

        def fake_capped(argv, timeout=10, env=None, cwd=None, cap=2048):
            Path(argv[2]).write_bytes(b"x" * 64)
            return 0, b"tar ok"

        with mock.patch.object(backups, "BACKUP_ROOT", backup_root), \
             mock.patch.object(backups, "CONFIG_FILE", config_file), \
             mock.patch.object(backups, "DATA_DIR", root / "empty-data"), \
             mock.patch.object(backups, "cfg", lambda: {}), \
             mock.patch.object(Path, "home", return_value=root / "no-home"), \
             mock.patch.object(backups, "_private_dest", lambda p: dest), \
             mock.patch.object(backups, "_prune"), \
             mock.patch.object(backups, "run_capped", fake_capped):
            result = backups._backup_configs()
        json.dumps(result, allow_nan=False)
        self.assertIsInstance(result["message"], str)


class SchedulerIntInfLeftoverTests(_Sandbox):
    def test_inf_runs_limit_is_clamped_not_500(self):
        scheduler_svc.save_job({
            "id": "job-lim", "name": "nightly", "type": "command",
            "cron": "* * * * *", "enabled": True,
            "params": {"command": "true"},
        })
        body = job_runs("job-lim", limit=float("inf"))
        json.dumps(body, allow_nan=False)
        self.assertEqual(body["runs"], [])
        body = all_runs(limit=float("nan"))
        json.dumps(body, allow_nan=False)
        self.assertEqual(body["runs"], [])
        json.dumps(scheduler_svc.runs(limit=float("inf")), allow_nan=False)
        json.dumps(scheduler_svc.runs(limit=float("nan")), allow_nan=False)

    def test_inf_clock_does_not_500_execute(self):
        """``int(time.time())`` OverflowError on leftover inf used to abort a run."""
        job = {
            "id": "job-clock", "name": "nightly", "type": "command",
            "cron": "* * * * *", "enabled": True,
            "params": {"command": "true"},
        }
        with mock.patch.object(scheduler_svc.time, "time", return_value=float("inf")), \
             mock.patch.dict(scheduler_svc._RUNNERS, {"command": lambda job, log: 0}):
            entry = scheduler_svc._execute(job, "manual")
        json.dumps(entry, allow_nan=False)
        self.assertEqual(entry["status"], "ok")
        self.assertEqual(entry["ts"], 0)
        self.assertEqual(entry["duration"], 0.0)

        with scheduler_svc._running_guard:
            scheduler_svc._running.add("job-clock")
        try:
            with mock.patch.object(scheduler_svc.time, "time", return_value=float("inf")):
                skipped = scheduler_svc._execute(job, "schedule")
        finally:
            with scheduler_svc._running_guard:
                scheduler_svc._running.discard("job-clock")
        json.dumps(skipped, allow_nan=False)
        self.assertEqual(skipped["status"], "skipped")
        self.assertEqual(skipped["ts"], 0)


class JobsSchedulerJsonableLeftoverTests(unittest.TestCase):
    def test_isoformat_inf_does_not_500_maintenance_or_jobs(self):
        """A leftover ``isoformat()`` returning inf used to 500 GET /api/maintenance."""
        class _Stamp:
            def isoformat(self):
                return float("inf")

        self.assertIsNone(jobs._jsonable(_Stamp()))
        self.assertIsNone(scheduler_svc._jsonable(_Stamp()))
        self.assertIsNone(backups._jsonable(_Stamp()))
        self.assertIsNone(audit._jsonable(_Stamp()))
        for fn in (jobs._jsonable, scheduler_svc._jsonable, backups._jsonable, audit._jsonable):
            out = fn({
                "when": _Stamp(),
                "name": datetime.date(2026, 8, 19),
                "blob": b"ok",
                "tags": {"nightly"},
                "n": float("inf"),
            })
            json.dumps(out, allow_nan=False)
            self.assertIsNone(out["when"])
            self.assertEqual(out["name"], "2026-08-19")
            self.assertEqual(out["blob"], "ok")
            self.assertEqual(out["tags"], ["nightly"])
            self.assertIsNone(out["n"])


if __name__ == "__main__":
    unittest.main()
