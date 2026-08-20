"""Leftover json.dumps without allow_nan=False used to 500 request paths.

VM status logs, the assistant snapshot prompt, stack-backup inflight
markers, catalog vars/README, and GET /api/diagnostics/download each used
to raise ValueError/TypeError/OverflowError or write Infinity that later
failed Starlette's encoder.
"""
from __future__ import annotations

import datetime
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import apps_manage_svc, assistant_svc, backups, catalog, terminal_svc
from hub.routers import unraid_parity


def _json(payload) -> None:
    json.dumps(payload, allow_nan=False)


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class AppsVmLogsJsonDumpsLeftoverTests(unittest.TestCase):
    def test_leftover_inf_bytes_date_do_not_500(self):
        """json.dumps of leftover Infinity used to 500 GET /api/apps/.../logs."""
        with mock.patch.object(apps_manage_svc, "_vm_detail", return_value={
            "name": "box",
            "load": float("inf"),
            "blob": b"hello",
            "when": datetime.date(2026, 8, 19),
            "ips": [float("nan")],
        }):
            out = apps_manage_svc._vm_logs("box")
        self.assertTrue(out["ok"])
        self.assertNotIn("Infinity", out["log"])
        parsed = json.loads(out["log"])
        _json(parsed)
        _starlette(out)
        self.assertEqual(parsed["blob"], "hello")
        self.assertIsNone(parsed["load"])

    def test_leftover_dumps_recursion_does_not_500(self):
        """json.dumps RecursionError is not ValueError; GET /api/apps/.../logs used to 500."""
        with (
            mock.patch.object(apps_manage_svc, "_vm_detail", return_value={"name": "box"}),
            mock.patch.object(apps_manage_svc.json, "dumps", side_effect=RecursionError),
        ):
            out = apps_manage_svc._vm_logs("box")
        self.assertTrue(out["ok"])
        self.assertEqual(out["log"], "")
        _starlette(out)


class AssistantSystemPromptJsonDumpsLeftoverTests(unittest.TestCase):
    def test_leftover_inf_bytes_date_do_not_raise(self):
        """json.dumps(_jsonable(snapshot)) without allow_nan=False used to
        write Infinity into the LLM prompt path."""
        text = assistant_svc._system_prompt({
            "load": float("inf"),
            "blob": b"1.0 / 1.0 / 1.0",
            "when": datetime.date(2026, 8, 19),
            "name": "ok\ud800",
        }, "en")
        self.assertIn("Snapshot:", text)
        self.assertNotIn("Infinity", text)
        self.assertIn("1.0 / 1.0 / 1.0", text)
        self.assertNotIn("\ud800", text)
        text.encode("utf-8")

    def test_leftover_dumps_recursion_does_not_raise(self):
        """json.dumps RecursionError is not ValueError; leftover nested snapshot used to 500."""
        with mock.patch.object(assistant_svc.json, "dumps", side_effect=RecursionError):
            text = assistant_svc._system_prompt({"ok": True}, "en")
        self.assertIn("Snapshot:", text)
        self.assertIn("{}", text)


class BackupInflightJsonDumpsLeftoverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        patch = mock.patch.object(backups, "DATA_DIR", self.tmp)
        patch.start()
        self.addCleanup(patch.stop)

    def test_leftover_inf_time_does_not_raise(self):
        """int(time.time()) OverflowError on leftover inf used to abort backup."""
        with mock.patch("hub.backups.time.time", return_value=float("inf")):
            backups._write_inflight("photoprism", "/tmp/compose.yml")
        rec = json.loads(backups._inflight_marker("photoprism").read_text())
        _json(rec)
        self.assertEqual(rec["ts"], 0)
        self.assertEqual(rec["stack"], "photoprism")

    def test_leftover_inf_stack_and_path_do_not_raise(self):
        backups._write_inflight(float("inf"), float("nan"))
        markers = list(self.tmp.glob("stack-backup-inflight-*"))
        self.assertTrue(markers)
        rec = json.loads(markers[0].read_text())
        _json(rec)
        self.assertIsNone(rec.get("stack"))
        self.assertIsNone(rec.get("compose_path"))

    def test_leftover_bytes_path_does_not_raise(self):
        backups._write_inflight("photoprism", b"/tmp/compose.yml")
        rec = json.loads(backups._inflight_marker("photoprism").read_text())
        _json(rec)
        self.assertEqual(rec["compose_path"], "/tmp/compose.yml")


class CatalogVarsJsonDumpsLeftoverTests(unittest.TestCase):
    def _install(self, *, variables=None, host_ip="10.0.0.1", tz="UTC"):
        home = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(home, ignore_errors=True))
        (home / "Services").mkdir()
        src = home / "ok.yml"
        src.write_text(
            "---\nname: Ok\ndesc: d\nvars:\n  - name: NOTE\n    required: false\n"
            "---\nservices:\n  x:\n    image: a:1\n"
        )
        with (
            mock.patch.object(catalog, "SERVICES_ROOT", home / "Services"),
            mock.patch.object(catalog, "template_file", return_value=src),
            mock.patch.object(catalog, "DOCKER", ""),
            mock.patch.object(catalog, "host_ip", return_value=host_ip),
            mock.patch.object(catalog, "host_timezone", return_value=tz),
            mock.patch.object(catalog, "_check_ports_free"),
            mock.patch.object(catalog, "_register_stack"),
            mock.patch("shutil.which", return_value=""),
        ):
            out = catalog.install_template("ok", variables or {})
        dest = home / "Services" / "ok"
        return out, dest

    def test_leftover_inf_host_ip_does_not_500_install(self):
        """HOST_IP inf used to write Infinity into .serverhub-vars.json and 500
        the install JSON body under Starlette's allow_nan=False encoder."""
        out, dest = self._install(host_ip=float("inf"))
        _starlette(out)
        self.assertEqual(out["variables"].get("HOST_IP"), "")
        raw = (dest / ".serverhub-vars.json").read_text(encoding="utf-8")
        parsed = json.loads(raw)
        _json(parsed)
        self.assertEqual(parsed.get("HOST_IP"), "")
        readme = (dest / "README.serverhub.md").read_text(encoding="utf-8")
        self.assertNotIn("Infinity", readme)

    def test_leftover_date_tz_does_not_500_install(self):
        out, dest = self._install(tz=datetime.date(2026, 8, 19))
        _starlette(out)
        raw = json.loads((dest / ".serverhub-vars.json").read_text(encoding="utf-8"))
        _json(raw)
        self.assertTrue(str(raw.get("TZ", "")).startswith("2026-08-19"))

    def test_leftover_surrogate_var_does_not_500_install(self):
        out, dest = self._install(variables={"NOTE": "x\ud800y"})
        _starlette(out)
        raw = (dest / ".serverhub-vars.json").read_text(encoding="utf-8")
        self.assertNotIn("\ud800", raw)
        _json(json.loads(raw))
        readme = (dest / "README.serverhub.md").read_text(encoding="utf-8")
        self.assertNotIn("\ud800", readme)


class DiagnosticsDownloadJsonDumpsLeftoverTests(unittest.TestCase):
    def _body(self, payload):
        with mock.patch.object(
            unraid_parity.system_settings_svc,
            "collect_diagnostics",
            return_value=payload,
        ):
            resp = unraid_parity.api_diagnostics_download()
        raw = resp.body
        if isinstance(raw, (bytes, bytearray)):
            text = bytes(raw).decode("utf-8")
        else:
            text = raw.encode("utf-8").decode("utf-8")
        return json.loads(text)

    def test_leftover_inf_is_null_not_500(self):
        """json.dumps without allow_nan=False used to 500 the download."""
        parsed = self._body({"n": float("inf"), "ok": True})
        _json(parsed)
        self.assertIsNone(parsed["n"])
        self.assertIs(parsed["ok"], True)

    def test_leftover_bytes_date_do_not_500(self):
        parsed = self._body({
            "blob": b"hello",
            "when": datetime.date(2026, 8, 19),
        })
        _json(parsed)
        self.assertEqual(parsed["blob"], "hello")
        self.assertTrue(str(parsed["when"]).startswith("2026-08-19"))

    def test_leftover_surrogate_does_not_500_utf8(self):
        """A leftover ``\\ud800`` still 500'd PlainTextResponse UTF-8 encode."""
        parsed = self._body({"name": "ok\ud800"})
        dumped = json.dumps(parsed, ensure_ascii=False)
        dumped.encode("utf-8")
        self.assertNotIn("\ud800", dumped)

    def test_leftover_dumps_recursion_does_not_500(self):
        """json.dumps RecursionError is not ValueError; leftover nested diagnostics used to 500."""
        with (
            mock.patch.object(
                unraid_parity.system_settings_svc,
                "collect_diagnostics",
                return_value={"ok": True},
            ),
            mock.patch("json.dumps", side_effect=RecursionError),
        ):
            resp = unraid_parity.api_diagnostics_download()
        raw = resp.body
        text = bytes(raw).decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw
        self.assertEqual(json.loads(text), {})

    def test_overflow_strftime_does_not_500_filename(self):
        """Leftover inf clock OverflowError'd GET /api/diagnostics/download filename."""
        with (
            mock.patch("hub.util.time.strftime", side_effect=OverflowError),
            mock.patch.object(
                unraid_parity.system_settings_svc,
                "collect_diagnostics",
                return_value={"ok": True},
            ),
        ):
            resp = unraid_parity.api_diagnostics_download()
        headers = getattr(resp, "headers", {}) or {}
        disp = headers.get("content-disposition") or headers.get("Content-Disposition") or ""
        self.assertIn("serverhub-diagnostics-.json", disp)


class TerminalClockLeftoverTests(unittest.TestCase):
    def test_now_infinite_clock_does_not_raise(self):
        """int(time.time()) OverflowError on leftover inf used to 500 POST /api/terminal."""
        with mock.patch.object(terminal_svc.time, "time", return_value=float("inf")):
            ts = terminal_svc._now()
        self.assertEqual(ts, 0)

    def test_utf8_text_recursing_does_not_500(self):
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(terminal_svc._utf8_text(Recursing()), "Recursing")
        _starlette({"k": terminal_svc._utf8_text(Recursing())})
        self.assertEqual(assistant_svc._utf8_text(Recursing()), "Recursing")
        _starlette({"k": assistant_svc._utf8_text(Recursing())})
        self.assertEqual(backups._utf8_text(Recursing()), "Recursing")
        _starlette({"k": backups._utf8_text(Recursing())})

    def test_isoformat_inf_does_not_500_jsonable(self):
        """A leftover ``isoformat()`` returning inf used to 500 terminal/assistant JSON."""
        class _Stamp:
            def isoformat(self):
                return float("inf")

        self.assertIsNone(terminal_svc._jsonable(_Stamp()))
        self.assertIsNone(assistant_svc._jsonable(_Stamp()))
        for fn in (terminal_svc._jsonable, assistant_svc._jsonable):
            out = fn({
                "when": _Stamp(),
                "name": datetime.date(2026, 8, 19),
                "blob": b"ok",
                "tags": {"run"},
                "n": float("inf"),
            })
            _starlette(out)
            self.assertIsNone(out["when"])
            self.assertEqual(out["name"], "2026-08-19")
            self.assertEqual(out["blob"], "ok")
            self.assertEqual(out["tags"], ["run"])
            self.assertIsNone(out["n"])


if __name__ == "__main__":
    unittest.main()
