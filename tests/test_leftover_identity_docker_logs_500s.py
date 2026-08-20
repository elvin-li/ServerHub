"""Leftover inf / ``\\ud800`` 500s on remaining routers.

YAML ``name: "\\ud800"`` 500'd GET /api/logs and GET /api/identity under
Starlette's UTF-8 encode. Docker ``{{json .}}`` ``Infinity`` / a leftover
``\\ud800`` Name 500'd GET /api/docker/info. Plist leftover names 500'd
GET /api/raid and GET /api/snapshots; leftover ``\\ud800`` in nfsd status
or an exports path 500'd GET /api/nfs. The same lone surrogate still
leaked through ollama / photoshub / health / tools / apps payloads.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest import mock

from hub import (
    docker_info_svc,
    health_svc,
    identity_svc,
    logs_svc,
    nfs_svc,
    nginx_svc,
    ollama_svc,
    photoshub_svc,
    raid_svc,
    snapshots_svc,
    status,
    tools_svc,
)
from hub.docker_cli import _as_text as docker_as_text
from hub.docker_cli import _jsonable as docker_jsonable
from hub.routers import logs as logs_router
from hub.routers import nas_common, nas_storage, unraid_parity
from fastapi import HTTPException


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


SUR = "ok\ud800"


class DockerAsTextRecursionLeftoverTests(unittest.TestCase):
    def test_recursing_str_does_not_raise(self):
        """str(e) RecursionError used to 500 docker/container leftover messages."""
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(docker_as_text(Recursing()), "Recursing")
        _starlette({"message": docker_as_text(Recursing())})

    def test_docker_info_as_text_recursing_does_not_500(self):
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(docker_info_svc._as_text(Recursing()), "Recursing")
        _starlette({"message": docker_info_svc._as_text(Recursing())})

    def test_snapshots_as_text_recursing_does_not_500(self):
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(snapshots_svc._as_text(Recursing()), "Recursing")
        _starlette({"message": snapshots_svc._as_text(Recursing())})

    def test_nginx_as_text_recursing_does_not_500(self):
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(nginx_svc._as_text(Recursing()), "Recursing")
        _starlette({"message": nginx_svc._as_text(Recursing())})


class LogsSurrogateLeftoverTests(unittest.TestCase):
    def test_leftover_surrogate_name_does_not_500(self):
        """YAML ``name: "\\ud800"`` used to 500 GET /api/logs."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.log"
            path.write_text("x\n", encoding="utf-8")
            with mock.patch("hub.logs_svc.cfg", return_value={
                "log_sources": [{"id": "app", "name": SUR, "path": str(path)}],
            }):
                rows = logs_svc.log_sources()
                payload = logs_router.sources()
        self.assertEqual(rows[0]["id"], "app")
        self.assertNotIn("\ud800", rows[0]["name"])
        _starlette(rows)
        _starlette(payload)

    def test_utf8_text_recursing_does_not_500(self):
        """leftover ``str(e)`` RecursionError used to 500 GET /api/logs."""
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(logs_svc._utf8_text(Recursing()), "Recursing")
        _starlette({"n": logs_svc._utf8_text(Recursing())})


class IdentitySurrogateLeftoverTests(unittest.TestCase):
    def _identity(self, comment):
        with (
            mock.patch.object(
                identity_svc, "cfg",
                return_value={"settings": {"server_comment": comment}},
            ),
            mock.patch.object(identity_svc, "sh", return_value=(0, "host", "")),
            mock.patch.object(identity_svc, "time_zone", return_value="UTC"),
            mock.patch.object(identity_svc, "platform_string", return_value="mac"),
            mock.patch.object(identity_svc, "effective_host_ip", return_value="1.2.3.4"),
            mock.patch.object(identity_svc, "configured_host", return_value="1.2.3.4"),
        ):
            return identity_svc.get_identity()

    def test_leftover_surrogate_comment_does_not_500(self):
        """YAML ``server_comment: "\\ud800"`` used to 500 GET /api/identity."""
        ident = self._identity(SUR)
        self.assertNotIn("\ud800", ident["comment"])
        _starlette(ident)

    def test_leftover_date_and_bytes_comment_do_not_500(self):
        ident = self._identity(date(2026, 8, 19))
        _starlette(ident)
        ident = self._identity(b"lab")
        self.assertEqual(ident["comment"], "lab")
        _starlette(ident)

    def test_recursing_comment_does_not_500(self):
        """leftover ``str(exc)`` RecursionError used to 500 GET /api/identity."""
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        ident = self._identity(Recursing())
        self.assertEqual(ident["comment"], "Recursing")
        _starlette(ident)


class DockerInfoLeftoverTests(unittest.TestCase):
    def _info(self, info_json: str, version_json: str = '{"Server":{"Version":"27.1"}}'):
        def fake_docker(*args, **kwargs):
            return (0, info_json, "") if "info" in args else (0, version_json, "")

        with (
            mock.patch.object(docker_info_svc, "engine_up", lambda: True),
            mock.patch.object(docker_info_svc, "docker", fake_docker),
            mock.patch.object(docker_info_svc, "sh", lambda *a, **k: (0, "", "")),
        ):
            return docker_info_svc.engine_info()

    def test_leftover_infinity_memtotal_does_not_500(self):
        """Python json.loads accepts Infinity; Starlette allow_nan=False does not."""
        data = self._info('{"ServerVersion":"27.1","MemTotal": Infinity, "NCPU": 8}')
        self.assertEqual(data["info"]["ServerVersion"], "27.1")
        self.assertIsNone(data["info"]["MemTotal"])
        _starlette(data)
        with (
            mock.patch.object(docker_info_svc, "engine_up", lambda: True),
            mock.patch.object(
                docker_info_svc, "docker",
                lambda *a, **k: (0, '{"MemTotal": Infinity}', "") if "info" in a else (0, "{}", ""),
            ),
            mock.patch.object(docker_info_svc, "sh", lambda *a, **k: (0, "", "")),
        ):
            _starlette(unraid_parity.api_docker_info())

    def test_leftover_surrogate_name_does_not_500(self):
        data = self._info('{"ServerVersion":"27.1","Name": "ok\\ud800"}')
        self.assertNotIn("\ud800", data["info"]["Name"])
        _starlette(data)

    def test_deeply_nested_info_does_not_500(self):
        """``json.loads`` RecursionError is not ValueError; leftover nested
        ``docker info --format {{json .}}`` used to 500 GET /api/docker/info."""
        nested = '{"k":' * 12000 + "1" + "}" * 12000
        data = self._info(nested, version_json=nested)
        _starlette(data)
        self.assertTrue(data["engine_up"])
        with mock.patch.object(
            docker_info_svc, "docker", lambda *a, **k: (0, nested, ""),
        ):
            _starlette(docker_info_svc._slim_info())
            self.assertEqual(docker_info_svc._version(), {})


class RaidSurrogateLeftoverTests(unittest.TestCase):
    def test_leftover_surrogate_name_does_not_500(self):
        """Plist leftover ``Name: \\ud800`` used to 500 GET /api/raid."""
        with mock.patch.object(raid_svc, "_plist", return_value={
            "AppleRAIDSets": [{
                "AppleRAIDSetUUID": "abc",
                "Name": SUR,
                "Status": "Online",
                "Level": "mirror",
                "Size": 10,
            }],
        }):
            sets = raid_svc.list_sets()
        self.assertEqual(len(sets), 1)
        self.assertNotIn("\ud800", sets[0]["name"])
        _starlette(sets)


class NasCommonLeftoverTests(unittest.TestCase):
    def _code(self, exc: HTTPException) -> str:
        detail = exc.detail
        return detail["code"] if isinstance(detail, dict) else str(detail)

    def test_leftover_non_dict_admin_result_is_coded_not_500(self):
        """Leftover None / inf AttributeError'd NAS POST handlers."""
        for leftover in (None, float("inf"), "nope", ["x"]):
            with self.assertRaises(HTTPException) as ctx:
                nas_common.raise_for_admin_result(leftover)
            self.assertEqual(self._code(ctx.exception), "admin.failed")
            with self.assertRaises(HTTPException) as ctx:
                nas_common.raise_service_error(leftover, {"bad_action": "nfs.bad_action"})
            self.assertEqual(self._code(ctx.exception), "admin.failed")

    def test_leftover_inf_ok_payload_does_not_500(self):
        out = nas_common.raise_for_admin_result({
            "ok": True, "name": "ok\ud800", "n": float("inf"),
        })
        _starlette(out)
        self.assertTrue(out["ok"])
        self.assertNotIn("\ud800", out["name"])
        self.assertIsNone(out["n"])

    def test_leftover_non_str_error_param_keys_do_not_500(self):
        with self.assertRaises(HTTPException) as ctx:
            nas_common.raise_service_error(
                {"ok": False, "error": "bad_action", 1: "x", "device": "disk1"},
                {"bad_action": "nfs.bad_action"},
            )
        self.assertEqual(self._code(ctx.exception), "nfs.bad_action")


class NfsSurrogateLeftoverTests(unittest.TestCase):
    def test_leftover_surrogate_exports_line_does_not_500(self):
        parsed = nfs_svc._parse_line(f"/tmp/{SUR} everyone")
        self.assertIsNotNone(parsed)
        self.assertNotIn("\ud800", parsed["path"])
        self.assertNotIn("\ud800", parsed["raw"])
        _starlette(parsed)

    def test_leftover_preview_rows_do_not_500(self):
        """Non-dict export rows / leftover ``\\ud800`` used to 500 GET preview."""
        with mock.patch.object(
            nfs_svc, "read_exports",
            return_value=[
                {"raw": f"/export {SUR}"},
                "not-a-dict",
                {"path": "/x"},
                float("inf"),
            ],
        ):
            resp = nas_storage.api_nfs_preview()
        body = bytes(resp.body).decode("utf-8")
        self.assertNotIn("\ud800", body)

    def test_leftover_surrogate_nfsd_status_does_not_500(self):
        self.addCleanup(nfs_svc.overview.invalidate)
        with (
            mock.patch.object(nfs_svc, "sh", return_value=(0, f"nfsd is running {SUR}", "")),
            mock.patch.object(nfs_svc, "read_exports", return_value=[]),
            mock.patch.object(nfs_svc, "_exports_exists", return_value=False),
        ):
            data = nfs_svc.overview(force=True)
        self.assertNotIn("\ud800", data["server"]["detail"])
        _starlette(data)


class SnapshotSurrogateLeftoverTests(unittest.TestCase):
    def test_leftover_surrogate_destination_does_not_500(self):
        with (
            mock.patch.object(
                snapshots_svc, "_tm_destinations",
                return_value={"Destinations": [{
                    "ID": "1", "Name": SUR, "Kind": "Local",
                    "MountPoint": "/", "URL": "",
                }]},
            ),
            mock.patch.object(snapshots_svc, "_tm_status", return_value={}),
            mock.patch.object(snapshots_svc, "_tm_latest_backup", return_value=""),
        ):
            out = snapshots_svc.time_machine_overview()
        self.assertNotIn("\ud800", out["destinations"][0]["name"])
        _starlette(out)

    def test_leftover_surrogate_snapshot_name_does_not_500(self):
        with mock.patch.object(snapshots_svc, "_plist", return_value={
            "Snapshots": [{
                "SnapshotName": SUR,
                "SnapshotUUID": "u",
                "SnapshotXID": 1,
            }],
        }):
            items = snapshots_svc.list_snapshots("/")
        self.assertNotIn("\ud800", items[0]["name"])
        _starlette(items)


class HealthSurrogateLeftoverTests(unittest.TestCase):
    def test_leftover_surrogate_check_row_does_not_500(self):
        """A leftover ``\\ud800`` detail used to 500 GET /api/health/checks."""
        payload = health_svc._jsonable({
            "checks": [{
                "id": "nginx", "name": SUR, "detail": SUR, "ok": True,
            }],
        })
        self.assertNotIn("\ud800", payload["checks"][0]["name"])
        self.assertNotIn("\ud800", payload["checks"][0]["detail"])
        _starlette(payload)


class OllamaSurrogateLeftoverTests(unittest.TestCase):
    def test_leftover_surrogate_model_name_does_not_500(self):
        models = ollama_svc.parse_tags({"models": [{"name": SUR, "size": 1}]})
        self.assertNotIn("\ud800", models[0]["name"])
        _starlette(models)
        _starlette(ollama_svc._jsonable({"name": SUR, "size": float("inf")}))


class PhotosHubSurrogateLeftoverTests(unittest.TestCase):
    def test_leftover_surrogate_config_does_not_500(self):
        snap = photoshub_svc._jsonable({"people": {"yuanbao": {"name": SUR}}})
        self.assertNotIn("\ud800", snap["people"]["yuanbao"]["name"])
        _starlette(snap)


class AppsDockerJsonableLeftoverTests(unittest.TestCase):
    def test_leftover_surrogate_inspect_does_not_500(self):
        """Leftover ``\\ud800`` in docker inspect used to 500 GET /api/apps/managed."""
        cleaned = docker_jsonable({"name": SUR, "n": float("inf")})
        self.assertNotIn("\ud800", cleaned["name"])
        self.assertIsNone(cleaned["n"])
        _starlette(cleaned)


class ToolsPlistLeftoverTests(unittest.TestCase):
    def test_leftover_surrogate_label_does_not_500(self):
        """Leftover ``\\ud800`` in a LaunchAgent Label used to 500 GET /api/scheduler."""
        cleaned = tools_svc._plist_jsonable({"Label": SUR, "StartInterval": float("inf")})
        self.assertNotIn("\ud800", cleaned["Label"])
        self.assertIsNone(cleaned["StartInterval"])
        _starlette(cleaned)


class DiagnosticsDownloadJsonDumpsLeftoverTests(unittest.TestCase):
    def test_leftover_inf_does_not_500_download(self):
        """json.dumps without allow_nan=False used to 500 GET /api/diagnostics/download."""
        with mock.patch.object(
            unraid_parity.system_settings_svc,
            "collect_diagnostics",
            return_value={"n": float("inf"), "ok": True, "blob": b"x"},
        ):
            resp = unraid_parity.api_diagnostics_download()
        raw = resp.body
        text = bytes(raw).decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw
        parsed = json.loads(text)
        json.dumps(parsed, allow_nan=False)
        self.assertIsNone(parsed["n"])
        self.assertIs(parsed["ok"], True)
        self.assertEqual(parsed["blob"], "x")

    def test_leftover_surrogate_does_not_500_download_utf8(self):
        with mock.patch.object(
            unraid_parity.system_settings_svc,
            "collect_diagnostics",
            return_value={"name": SUR},
        ):
            resp = unraid_parity.api_diagnostics_download()
        raw = resp.body
        if isinstance(raw, (bytes, bytearray)):
            text = bytes(raw).decode("utf-8")
        else:
            text = raw.encode("utf-8").decode("utf-8")
        self.assertNotIn("\ud800", text)


class AccountApiRecursionLeftoverTests(unittest.TestCase):
    def test_recursing_valueerror_is_coded_not_500(self):
        """leftover ``str(exc)`` RecursionError used to 500 POST /api/accounts."""
        from hub.routers import accounts_api, api_keys_api
        from hub.errors import exc_detail

        class Recursing(ValueError):
            def __str__(self):
                raise RecursionError("nested")

        err = accounts_api._account_error(Recursing("exists"))
        _starlette(err.detail)
        self.assertEqual(err.detail["code"], "accounts.bad_username")
        mapped = api_keys_api._CREATE_ERRORS.get(
            exc_detail(Recursing(), cap=64), "apikeys.name_required",
        )
        self.assertEqual(mapped, "apikeys.name_required")
        from hub.errors import api_error
        wrapped = api_error(mapped)
        _starlette(wrapped.detail)


class InfClockStrftimeLeftoverTests(unittest.TestCase):
    def test_overflow_strftime_does_not_500_get_ts(self):
        """Leftover ``time.time() = inf`` OverflowError'd request-path JSON ``ts``.

        RecursionError is not ValueError; OverflowError is not ValueError.
        """
        from hub import storage_pool_svc, usage_svc

        with mock.patch("hub.util.time.strftime", side_effect=OverflowError):
            with (
                mock.patch.object(raid_svc, "list_sets", return_value=[]),
                mock.patch.object(raid_svc, "candidate_devices", return_value=[]),
            ):
                raid = raid_svc.overview(force=True)
            with (
                mock.patch.object(nfs_svc, "read_exports", return_value=[]),
                mock.patch.object(nfs_svc, "_nfsd_status", return_value={"running": False}),
                mock.patch.object(nfs_svc, "_exports_exists", return_value=False),
            ):
                nfs = nfs_svc.overview(force=True)
            with (
                mock.patch.object(ollama_svc, "_api", side_effect=OSError("down")),
                mock.patch.object(ollama_svc, "binary_path", return_value=""),
                mock.patch.object(
                    ollama_svc, "_service_state",
                    return_value={"label": "", "loaded": False, "running": False},
                ),
                mock.patch.object(
                    ollama_svc, "pull_state",
                    return_value={"running": False, "model": "", "log": []},
                ),
            ):
                ollama = ollama_svc.status(force=True)
            with (
                mock.patch.object(usage_svc, "scan_roots", return_value=[]),
                mock.patch.object(usage_svc, "spotlight_status", return_value={}),
            ):
                usage = usage_svc.overview()
            with (
                mock.patch.object(
                    storage_pool_svc, "_pool_config",
                    return_value={"members": [], "name": "pool", "policy": "most-free"},
                ),
                mock.patch.object(storage_pool_svc, "_candidates", return_value=[]),
            ):
                pool = storage_pool_svc._build()
            with mock.patch.object(
                unraid_parity.system_settings_svc,
                "collect_diagnostics",
                return_value={"ok": True},
            ):
                resp = unraid_parity.api_diagnostics_download()
        for payload in (raid, nfs, ollama, usage, pool):
            _starlette(payload)
            self.assertEqual(payload["ts"], "")
        headers = getattr(resp, "headers", {}) or {}
        disp = headers.get("content-disposition") or headers.get("Content-Disposition") or ""
        self.assertIn("serverhub-diagnostics-.json", disp)


class Utf8TextRecursionLeftoverTests(unittest.TestCase):
    def test_utf8_text_recursing_does_not_500(self):
        """str() RecursionError is not ValueError; leftover ``__str__`` used to 500."""
        from hub.docker_cli import _utf8_text as docker_utf8

        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        for fn in (
            photoshub_svc._utf8_text, docker_utf8, ollama_svc._utf8_text,
            status._utf8_text, nas_common._utf8_text,
        ):
            self.assertEqual(fn(Recursing()), "Recursing")
            _starlette({"k": fn(Recursing())})


class NasHealthRaidJsonableLeftoverTests(unittest.TestCase):
    def test_isoformat_inf_does_not_500_nas_health(self):
        """A leftover ``isoformat()`` returning inf used to 500 NAS / health JSON."""
        class _Stamp:
            def isoformat(self):
                return float("inf")

        self.assertIsNone(nas_common._jsonable(_Stamp()))
        self.assertIsNone(health_svc._jsonable(_Stamp()))
        out = nas_common._jsonable({
            "when": _Stamp(),
            "name": date(2026, 8, 19),
            "blob": b"nas",
            "tags": {"ok"},
            "n": float("inf"),
        })
        _starlette(out)
        self.assertIsNone(out["when"])
        self.assertEqual(out["name"], "2026-08-19")
        self.assertEqual(out["blob"], "nas")
        self.assertEqual(out["tags"], ["ok"])
        self.assertIsNone(out["n"])
        cleaned = health_svc._jsonable({"when": _Stamp(), "ok": True})
        _starlette(cleaned)
        self.assertIsNone(cleaned["when"])
