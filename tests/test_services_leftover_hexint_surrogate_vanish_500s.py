"""Services sweep leftovers: hex-plist over-cap ints, surrogate commands, confirmed vanish.

Three classes of leftover on the Services surface (launchctl discovery, script
collection, uninstall preview, container actions/logs), each pinned by tests
that fail on the pre-fix code:

* **Over-cap hex plist/YAML ints.**  ``plistlib`` parses
  ``<integer>0xFFF…</integer>`` via ``int(raw, 16)`` — exempt from CPython's
  4300-digit str<->int cap — and ``yaml.safe_load`` does the same for
  ``ports: [0xFFF…]``.  A hand-edited leftover therefore *loads* fine and the
  first ``str()`` / f-string / ``json.dumps`` on the value raised the
  digit-cap ValueError:

  - ``status._jsonable`` passed the raw int through to the JSON encoder, so
    /api/status, /api/services and every detail echo 500'd;
  - ``discover_launchd`` died on ``Path(str(Program)).name`` and on the
    ``f" · :{port}"`` detail line, silently dropping *every* launchd row;
  - ``collect_scripts`` died on the partially-running detail's port list,
    silently dropping every script row;
  - ``services_uninstall_svc._agent_paths`` died on ``str(Label/Program/
    WorkingDirectory)``, which 500'd the uninstall preview of the poisoned
    agent *and of every healthy sibling* (the preview parses each plist in
    AGENTS_DIR to compute can_remove_data).

* **Lone-surrogate start/stop commands.**  ``_clean_cmd`` silently *mangled*
  the JSON ``"\\ud800"`` escape (``x\\ud800rm`` became ``x?rm``) and stored a
  command the operator never wrote.  A surrogate command can never be spawned
  (Popen's argv UTF-8 encode refuses it), so — the scheduler-command rule —
  adopt/update now answer the coded 400 ``services.bad_command`` instead.

* **Vanished-CLI 503 only after disk confirm.**  A DOCKER binary that
  vanished before the spawn is ``sh()``'s exact ``(-1, "not found")``
  sentinel.  ``actions.run_action`` handed it back as an uncoded
  ``{ok: false, message: "not found"}`` the SPA cannot translate, and
  ``service_logs`` returned it as the container's "log" body.  The sentinel
  alone is not proof (any FileNotFoundError spawn collapses into it), so the
  binary must be confirmed gone from disk before the coded 503
  ``container.engine_down`` — the compose_svc / catalog convention.
"""
from __future__ import annotations

import json
import plistlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import HTTPException  # noqa: E402

from hub import actions  # noqa: E402
from hub import services_manage_svc as sms  # noqa: E402
from hub import services_uninstall_svc as uninstall_svc  # noqa: E402
from hub.discovery import apps as apps_discovery  # noqa: E402
from hub.discovery import launchd as launchd_discovery  # noqa: E402
from hub.status import _jsonable  # noqa: E402

#: Parses uncapped through plist/yaml hex loading, unrenderable by str().
OVER_CAP_HEX = "0x" + "f" * 5000
OVER_CAP_INT = int("f" * 5000, 16)

SUR = "x\ud800rm"


def _starlette(payload) -> None:
    """Starlette's exact JSON render — raises on anything unencodable."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class StatusJsonableOverCapIntTests(unittest.TestCase):
    def test_over_cap_int_is_dropped_not_500(self):
        """_jsonable used to pass the raw int through; json.dumps then raised."""
        row = _jsonable({"id": "s1", "port": OVER_CAP_INT, "ports": [OVER_CAP_INT]})
        self.assertIsNone(row["port"])
        self.assertEqual(row["ports"], [None])
        _starlette(row)

    def test_normal_ints_survive(self):
        row = _jsonable({"port": 8080, "pid": 123, "flag": True})
        self.assertEqual(row["port"], 8080)
        self.assertEqual(row["pid"], 123)
        self.assertIs(row["flag"], True)

    def test_service_detail_with_hex_plist_interval_is_encodable(self):
        """A hex ``<integer>`` StartInterval used to 500 GET detail's echo."""
        pl = {
            "Label": "job",
            "ProgramArguments": ["/bin/true"],
            "StartInterval": OVER_CAP_INT,
        }
        svc = {
            "id": "job", "name": "job", "kind": "launchd",
            "state": "ok", "actions": ["detail"],
        }
        with (
            patch.object(sms, "find_service", return_value=svc),
            patch.object(sms, "override", return_value={}),
            patch.object(sms, "_load_plist", return_value=pl),
            patch.object(sms, "_plist_path", return_value=Path("/tmp/job.plist")),
            patch.object(sms, "sh", return_value=(0, "state = running\n", "")),
        ):
            detail = sms.service_detail("job")
        _starlette(detail)


class DiscoverLaunchdOverCapTests(unittest.TestCase):
    def _write_hex_program_plist(self, agents: Path) -> None:
        # plistlib.dumps refuses over-cap ints on *write*; a hand-edited XML
        # plist parses them fine on *read* — exactly the hostile leftover.
        (agents / "bad.plist").write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<plist version="1.0"><dict>'
            "<key>Label</key><string>com.bad.job</string>"
            f"<key>Program</key><integer>{OVER_CAP_HEX}</integer>"
            "</dict></plist>",
            encoding="utf-8",
        )

    def test_hex_program_does_not_kill_the_collector(self):
        """One poisoned plist used to vanish *every* launchd row."""
        with tempfile.TemporaryDirectory() as tmp:
            agents = Path(tmp)
            self._write_hex_program_plist(agents)
            (agents / "ok.plist").write_bytes(plistlib.dumps({
                "Label": "com.ok.job", "ProgramArguments": ["/bin/true"],
            }))
            with (
                patch.object(launchd_discovery, "AGENTS_DIR", str(agents)),
                patch.object(launchd_discovery, "launchctl_table", return_value={}),
                patch.object(launchd_discovery, "override", return_value={}),
                patch.object(launchd_discovery, "configured_signatures", return_value=[]),
                patch.object(launchd_discovery, "configured_group_rules", return_value=[]),
            ):
                items = launchd_discovery.discover_launchd()
            labels = [i.get("id") for i in items]
            self.assertIn("com.ok.job", labels)
            self.assertIn("com.bad.job", labels)
            _starlette(items)

    def test_hex_override_port_does_not_kill_the_collector(self):
        """A hand-edited ``port: 0xFFF…`` override died in the detail f-string."""
        with tempfile.TemporaryDirectory() as tmp:
            agents = Path(tmp)
            (agents / "a.plist").write_bytes(plistlib.dumps({
                "Label": "com.a.job", "ProgramArguments": ["/bin/true"],
                "KeepAlive": True,
            }))
            (agents / "b.plist").write_bytes(plistlib.dumps({
                "Label": "com.b.job", "ProgramArguments": ["/bin/true"],
            }))

            def fake_override(label):
                return {"port": OVER_CAP_INT} if label == "com.a.job" else {}

            with (
                patch.object(launchd_discovery, "AGENTS_DIR", str(agents)),
                patch.object(
                    launchd_discovery, "launchctl_table",
                    return_value={"com.a.job": ("123", "0")},
                ),
                patch.object(launchd_discovery, "override", fake_override),
                patch.object(launchd_discovery, "configured_signatures", return_value=[]),
                patch.object(launchd_discovery, "configured_group_rules", return_value=[]),
                patch.object(launchd_discovery, "_probe_port", return_value=True),
                patch.object(launchd_discovery, "pid_exe_path", return_value=None),
            ):
                items = launchd_discovery.discover_launchd()
            labels = [i.get("id") for i in items]
            self.assertIn("com.a.job", labels)
            self.assertIn("com.b.job", labels)
            _starlette(items)


class CollectScriptsOverCapPortTests(unittest.TestCase):
    def test_hex_port_in_partially_up_script_does_not_kill_the_collector(self):
        """``ports: [3000, 0xFFF…]`` died in the partially-running detail."""
        cfg_data = {"scripts": [
            {"id": "good", "name": "good", "ports": [3000]},
            {"id": "bad", "name": "bad", "ports": [3000, OVER_CAP_INT]},
        ]}

        def fake_port_open(port, *a, **k):
            return port == 3000

        with (
            patch.object(apps_discovery, "cfg", return_value=cfg_data),
            patch.object(apps_discovery, "port_open", fake_port_open),
            patch.object(apps_discovery, "configured_group_rules", return_value=[]),
        ):
            items = apps_discovery.collect_scripts()
        self.assertEqual([i["id"] for i in items], ["good", "bad"])
        _starlette(items)


class UninstallPreviewOverCapPlistTests(unittest.TestCase):
    def _agents(self, tmp: Path) -> Path:
        agents = tmp / "LaunchAgents"
        agents.mkdir()
        (agents / "com.bad.job.plist").write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<plist version="1.0"><dict>'
            "<key>Label</key><string>com.bad.job</string>"
            "<key>ProgramArguments</key><array>"
            f"<integer>{OVER_CAP_HEX}</integer></array>"
            "</dict></plist>",
            encoding="utf-8",
        )
        (agents / "com.ok.job.plist").write_bytes(plistlib.dumps({
            "Label": "com.ok.job",
            "ProgramArguments": ["/usr/bin/true"],
            "WorkingDirectory": str(tmp / "Services" / "okjob"),
        }))
        (tmp / "Services" / "okjob").mkdir(parents=True)
        return agents

    def test_preview_of_poisoned_agent_does_not_500(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            agents = self._agents(tmp)
            with (
                patch.object(uninstall_svc, "AGENTS_DIR", agents),
                patch.object(uninstall_svc, "SERVICES_ROOT", tmp / "Services"),
            ):
                info = uninstall_svc.preview("com.bad.job")
            _starlette(info)

    def test_preview_of_healthy_sibling_does_not_500(self):
        """_other_agents_in parses every plist, so one leftover 500'd them all."""
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            agents = self._agents(tmp)
            with (
                patch.object(uninstall_svc, "AGENTS_DIR", agents),
                patch.object(uninstall_svc, "SERVICES_ROOT", tmp / "Services"),
            ):
                info = uninstall_svc.preview("com.ok.job")
            self.assertTrue(info["can_remove_data"])
            _starlette(info)


class VanishedDockerCliTests(unittest.TestCase):
    def test_run_action_vanished_cli_is_coded_503_after_disk_confirm(self):
        """The ``(-1, "not found")`` sentinel used to come back uncoded."""
        with (
            patch.object(actions, "registry", return_value={"web": ("container", {})}),
            patch.object(actions, "sh", return_value=(-1, "", "not found")),
            patch("hub.actions.engine_up", return_value=False),
            patch("hub.actions.cli_on_disk", return_value=False),
        ):
            with self.assertRaises(HTTPException) as ctx:
                actions.run_action("web", "stop")
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(ctx.exception.detail.get("code"), "container.engine_down")

    def test_run_action_sentinel_alone_is_not_engine_down(self):
        """No disk confirm, no 503: execve ENOENTs for present-but-broken too."""
        with (
            patch.object(actions, "registry", return_value={"web": ("container", {})}),
            patch.object(actions, "sh", return_value=(-1, "", "not found")),
            patch("hub.actions.cli_on_disk", return_value=True),
        ):
            rc, out, err = actions.run_action("web", "stop")
        self.assertEqual(rc, -1)

    def test_service_logs_vanished_cli_is_coded_503_after_disk_confirm(self):
        """The sentinel used to be returned as the container's "log" body."""
        svc = {"id": "web", "kind": "container", "name": "web"}
        with (
            patch.object(sms, "find_service", return_value=svc),
            patch.object(sms, "DOCKER", "/usr/local/bin/docker"),
            patch.object(sms, "sh", return_value=(-1, "", "not found")),
            patch.object(sms, "engine_up", return_value=False),
            patch.object(sms, "cli_on_disk", return_value=False),
        ):
            with self.assertRaises(HTTPException) as ctx:
                sms.service_logs("web")
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(ctx.exception.detail.get("code"), "container.engine_down")

    def test_service_logs_sentinel_alone_keeps_the_raw_answer(self):
        svc = {"id": "web", "kind": "container", "name": "web"}
        with (
            patch.object(sms, "find_service", return_value=svc),
            patch.object(sms, "DOCKER", "/usr/local/bin/docker"),
            patch.object(sms, "sh", return_value=(-1, "", "not found")),
            patch.object(sms, "engine_up", return_value=True),
            patch.object(sms, "cli_on_disk", return_value=True),
        ):
            out = sms.service_logs("web")
        self.assertEqual(out["log"], "not found")


class SurrogateCommandRejectionTests(unittest.TestCase):
    def _assert_bad_command(self, ctx) -> None:
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail.get("code"), "services.bad_command")

    def test_clean_cmd_rejects_instead_of_mangling(self):
        """``x\\ud800rm`` used to be stored as ``x?rm`` — a command the
        operator never wrote."""
        with self.assertRaises(HTTPException) as ctx:
            sms._clean_cmd(SUR)
        self._assert_bad_command(ctx)

    def test_clean_cmd_still_accepts_and_trims_normal_text(self):
        self.assertEqual(sms._clean_cmd("  npm start  "), "npm start")
        self.assertIsNone(sms._clean_cmd("a\nb"))
        self.assertIsNone(sms._clean_cmd(None))

    def test_update_script_surrogate_start_is_coded_400(self):
        data = {"scripts": [{"id": "s1", "name": "old", "ports": [3000]}]}

        def fake_mutate(fn):
            fn(data)
            return data

        with (
            patch.object(sms, "cfg", return_value=data),
            patch.object(sms.config, "mutate", fake_mutate),
            patch.object(sms, "invalidate_status"),
        ):
            with self.assertRaises(HTTPException) as ctx:
                sms.update_script("s1", {"start": SUR})
        self._assert_bad_command(ctx)
        # The refusal must beat the mutation: nothing half-written.
        self.assertNotIn("start", data["scripts"][0])

    def test_adopt_surrogate_start_is_coded_400(self):
        auto = {
            "id": "auto:1", "name": "node", "kind": "auto",
            "meta": {"pid": 0, "process": "node", "ports": [3000]},
        }
        applied: dict = {}

        def fake_mutate(fn):
            fn(applied)
            return applied

        with (
            patch.object(sms, "find_service", return_value=auto),
            patch.object(sms, "_taken_service_ids", return_value=set()),
            patch.object(sms.config, "mutate", fake_mutate),
            patch.object(sms, "invalidate_status"),
        ):
            with self.assertRaises(HTTPException) as ctx:
                sms.adopt_service("auto:1", {"start": SUR, "remember": False})
        self._assert_bad_command(ctx)
        self.assertFalse(applied.get("scripts"))


if __name__ == "__main__":
    unittest.main()
