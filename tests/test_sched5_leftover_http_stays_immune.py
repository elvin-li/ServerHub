"""Fifth scheduler leftover sweep — HTTP stays-immune pins.

This sweep re-probed the Scheduler surfaces (jobs CRUD, enable, run-now, run
history, the rsync preview helpers, and the launchd system-tab route) through
``create_app()`` + ``TestClient(raise_server_exceptions=False)`` with the
hunted leftover classes and found **no live 500** — the fixes from the four
earlier sched sweeps hold.  These pins keep the exact probes from regressing
silently:

* **Mutations over poisoned sibling rows.**  A mutation rewrites the *whole*
  ``schedules:`` list, so a clean row's PUT/enable/DELETE must survive
  siblings a hand edit left behind: a surrogate-id row carrying surrogate
  keys AND values, a ``!!binary`` row with a YAML-date cron and ``!!set``
  enabled, and an over-cap hex-int id (uncapped via ``int(raw, 16)``, then
  unrenderable by ``str()``).  The clean row's mutation answers 200, the
  poisoned rows ride through the YAML re-dump untouched, and the list stays
  renderable.

* **run-now dispatch of stored junk jobs never raises out of the runner.**
  A stored job with an unknown ``type``, junk rsync params (mapping
  direction, int src) or ``.inf`` stack params answers the fire-and-forget
  200 and journals a *failed* run — the runner contract (`_execute` never
  raises) observed at the HTTP layer, sibling routes still 200 after.

* **The Scheduler page's system tab (GET /api/scheduler) against a plist
  zoo.**  Truncated XML (ExpatError), a non-dict root, invalid UTF-8 bytes,
  an over-cap plist, a FIFO and a directory squatting ``*.plist`` names, a
  ``<date>`` Label, a dict ProgramArguments and ``<data>`` argv entries: each
  degrades or is skipped per file, the healthy sibling timer always
  survives, and ``count`` equals the rows served.

* **Boundary shapes.**  A surrogate name in a JSON body is refused by
  validation as a renderable 422 (a lone surrogate can never reach the YAML
  store through the API); a huge-digit cron answers the coded 400 with the
  echoed expression truncated; hostile ``limit`` query strings are 422s
  whose bodies still render.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from fastapi.testclient import TestClient  # noqa: E402

from hub import audit, backups, config, scheduler_svc, tools_svc  # noqa: E402
from hub.app_factory import create_app  # noqa: E402
from hub.auth import require_auth  # noqa: E402

#: Loads through YAML hex parsing (uncapped); unrenderable by str().
OVER_CAP_HEX = "0x" + "f" * 5000

_app = None


def _the_app():
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return _app


def _client() -> TestClient:
    return TestClient(_the_app(), raise_server_exceptions=False)


def _encodable(body) -> None:
    """The exact render Starlette performs: ensure_ascii=False then UTF-8."""
    json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _Sandbox(unittest.TestCase):
    """Scratch services.yaml + run journal, audit captured away."""

    def setUp(self):
        root = Path(os.environ.get("TMPDIR", "/tmp")) / (
            f"serverhub-sched5-http-{os.getpid()}-{id(self)}"
        )
        (root / "data").mkdir(parents=True, exist_ok=True)
        self.root = root
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
        runs = mock.patch.object(
            scheduler_svc, "RUNS_PATH", root / "data" / "schedule-runs.jsonl"
        )
        runs.start()
        self.addCleanup(runs.stop)
        recorder = mock.patch.object(audit, "record", lambda event, **f: {})
        recorder.start()
        self.addCleanup(recorder.stop)

    def _write_yaml(self, text: str) -> None:
        (self.root / "services.yaml").write_text(text, encoding="utf-8")
        config.reload_cfg()


_POISONED_SIBLINGS_YAML = (
    'schedules:\n'
    '  - id: "s\\ud800urr"\n'
    '    name: "n\\ud800"\n'
    '    "\\ud800key": "\\udfffval"\n'
    '    type: command\n'
    '    cron: "* * * * *"\n'
    '    enabled: true\n'
    '    params: {command: "echo \\ud800hi"}\n'
    '  - id: !!binary aGVsbG8=\n'
    '    name: bin\n'
    '    type: command\n'
    '    cron: 2024-01-01\n'
    '    enabled: !!set {1: null}\n'
    '    params: {command: !!binary aGVsbG8=}\n'
    f'  - id: {OVER_CAP_HEX}\n'
    '    name: overcap\n'
    '    type: command\n'
    "    cron: '* * * * *'\n"
    '    enabled: true\n'
    '    params: {command: echo}\n'
    '  - id: victim\n'
    '    name: v\n'
    '    type: command\n'
    "    cron: '30 3 * * *'\n"
    '    enabled: true\n'
    '    params: {command: echo hi}\n'
)


class MutationsOverPoisonedSiblings(_Sandbox):
    """The clean row's mutations succeed; the poisoned siblings ride the
    whole-list YAML re-dump untouched; the list stays renderable."""

    def setUp(self):
        super().setUp()
        self._write_yaml(_POISONED_SIBLINGS_YAML)

    def _names(self) -> list:
        return [
            j.get("name") for j in scheduler_svc.list_jobs()
        ]

    def test_list_renders_over_the_poisoned_store(self):
        resp = _client().get("/api/scheduler/jobs")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _encodable(body)
        self.assertEqual(len(body["jobs"]), 4)
        # The scrub is response-side only: no row carries a lone surrogate.
        self.assertNotIn("\ud800", resp.text)

    def test_put_on_the_clean_row_keeps_every_sibling(self):
        resp = _client().put("/api/scheduler/jobs/victim", json={
            "name": "renamed", "type": "command", "cron": "0 4 * * *",
            "enabled": True, "params": {"command": "echo hi"}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _encodable(resp.json())
        self.assertEqual(resp.json()["job"]["name"], "renamed")
        rows = scheduler_svc.list_jobs()
        self.assertEqual(len(rows), 4)
        self.assertEqual(self._names()[-1], "renamed")
        # The surrogate row survived the re-dump byte-for-byte as a value.
        self.assertEqual(rows[0].get("name"), "n\ud800")
        self.assertEqual(rows[1].get("id"), b"hello")

    def test_enable_toggle_on_the_clean_row_keeps_every_sibling(self):
        resp = _client().post(
            "/api/scheduler/jobs/victim/enable", json={"enabled": False})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _encodable(resp.json())
        self.assertFalse(resp.json()["job"]["enabled"])
        rows = scheduler_svc.list_jobs()
        self.assertEqual(len(rows), 4)
        self.assertFalse(rows[-1]["enabled"])
        self.assertTrue(rows[2]["enabled"])  # over-cap hex sibling untouched

    def test_delete_then_create_over_the_poisoned_store(self):
        resp = _client().delete("/api/scheduler/jobs/victim")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(len(scheduler_svc.list_jobs()), 3)
        resp = _client().post("/api/scheduler/jobs", json={
            "id": "fresh", "name": "f", "type": "command",
            "cron": "* * * * *", "enabled": True,
            "params": {"command": "echo hi"}})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _encodable(resp.json())
        self.assertEqual(len(scheduler_svc.list_jobs()), 4)

    def test_surrogate_id_in_the_path_is_the_coded_400(self):
        """The path regex refuses the surrogate before any lookup — the row
        exists but is addressable only after the operator fixes its id."""
        resp = _client().post(
            "/api/scheduler/jobs/s%ED%A0%80urr/enable",
            json={"enabled": False})
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "scheduler.bad_id")
        _encodable(resp.json())


_JUNK_RUNNER_YAML = """
schedules:
  - id: weird
    name: w
    type: mystery
    cron: "* * * * *"
    enabled: true
    params: {x: 1}
  - id: rsyncjob
    name: r
    type: rsync
    cron: "* * * * *"
    enabled: true
    params: {direction: sideways, src: 77, dest: [1, 2]}
  - id: stackjob
    name: s
    type: stack_backup
    cron: "* * * * *"
    enabled: true
    params: {stack_id: .inf, retain: .nan}
"""


class RunNowJunkDispatch(_Sandbox):
    """run-now on stored junk jobs: fire-and-forget 200, a *failed* journal
    record, and the sibling routes still answer afterwards."""

    def setUp(self):
        super().setUp()
        self._write_yaml(_JUNK_RUNNER_YAML)

    def _run_and_wait(self, jid: str) -> dict:
        resp = _client().post(f"/api/scheduler/jobs/{jid}/run-now")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _encodable(body)
        self.assertTrue(body.get("started"), body)
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            hits = scheduler_svc.runs(jid, limit=1)
            if hits:
                return hits[0]
            time.sleep(0.05)
        self.fail(f"run-now of {jid} never journalled a record")

    def test_unknown_type_journals_failed_not_raises(self):
        rec = self._run_and_wait("weird")
        self.assertEqual(rec["status"], "failed")
        self.assertEqual(rec["rc"], -1)
        self.assertIn("unknown job type", rec.get("tail") or "")

    def test_junk_rsync_params_journal_the_validation_refusal(self):
        from hub import rsync_svc
        available = {
            "available": True, "path": "/bin/false", "variant": "rsync3",
            "version": "3.2.7",
            "supports": {"itemize": True, "progress2": True,
                         "compress": True, "bwlimit": True},
        }
        # With a usable binary recorded, the *params* refusal is what lands
        # in the journal (without one, the truthful availability message
        # wins first — both are log lines, never raises).
        with mock.patch.object(rsync_svc, "binary_info", return_value=available):
            rec = self._run_and_wait("rsyncjob")
        self.assertEqual(rec["status"], "failed")
        self.assertEqual(rec["rc"], -1)
        self.assertIn("direction must be push or pull", rec.get("tail") or "")

    def test_junk_stack_params_never_raise_out_of_the_runner(self):
        with mock.patch.object(
            backups, "backup_stack", return_value={"ok": False},
        ) as bs:
            rec = self._run_and_wait("stackjob")
            self.assertEqual(rec["status"], "failed")
        # YAML ``.inf`` stack_id reaches the runner as its str() form; the
        # retain ``.nan`` degrades to the default instead of OverflowError.
        self.assertEqual(bs.call_args.args[0], "inf")
        self.assertEqual(bs.call_args.kwargs.get("retain"), backups.RETAIN)

    def test_sibling_routes_still_answer_after_junk_dispatch(self):
        self._run_and_wait("weird")
        for path in ("/api/scheduler/jobs", "/api/scheduler/runs"):
            resp = _client().get(path)
            self.assertEqual(resp.status_code, 200, (path, resp.text[:300]))
            _encodable(resp.json())


class LaunchdRoutePlistZoo(unittest.TestCase):
    """GET /api/scheduler (the system tab) against a LaunchAgents zoo: every
    hostile file degrades or is skipped per file, the healthy sibling
    survives, and the count matches the rows served."""

    def _zoo(self, tmp: Path) -> None:
        (tmp / "a.expat.plist").write_text(
            "<plist><dict><key>Label</key>", encoding="utf-8")
        (tmp / "b.notdict.plist").write_text(
            '<?xml version="1.0"?><plist version="1.0">'
            "<array><integer>1</integer></array></plist>")
        (tmp / "c.badutf8.plist").write_bytes(
            b'<?xml version="1.0"?><plist><dict><key>Label</key>'
            b"<string>\xff\xfe</string></dict></plist>")
        (tmp / "d.datelabel.plist").write_text(
            '<?xml version="1.0"?><plist version="1.0"><dict>'
            "<key>Label</key><date>2024-01-01T00:00:00Z</date>"
            "<key>StartInterval</key><string>60</string>"
            "<key>ProgramArguments</key><array><data>aGk=</data>"
            "<integer>5</integer></array></dict></plist>")
        (tmp / "e.progargsdict.plist").write_text(
            '<?xml version="1.0"?><plist version="1.0"><dict>'
            "<key>Label</key><string>e.progargsdict</string>"
            "<key>StartInterval</key><integer>5</integer>"
            "<key>ProgramArguments</key><dict><key>a</key><string>b</string>"
            "</dict></dict></plist>")
        (tmp / "f.huge.plist").write_bytes(
            b'<?xml version="1.0"?><plist version="1.0"><dict>'
            b"<key>Label</key><string>" + b"f" * (3 * 1024 * 1024)
            + b"</string></dict></plist>")
        if hasattr(os, "mkfifo"):
            os.mkfifo(tmp / "g.fifo.plist")
        (tmp / "h.dir.plist").mkdir()
        (tmp / "z.good.plist").write_text(
            '<?xml version="1.0"?><plist version="1.0"><dict>'
            "<key>Label</key><string>z.good</string>"
            "<key>StartInterval</key><integer>60</integer></dict></plist>")

    def test_plist_zoo_never_500s_and_keeps_the_sibling(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            agents = Path(tmp)
            self._zoo(agents)
            with mock.patch.object(
                tools_svc.os.path, "expanduser", return_value=str(agents),
            ):
                resp = _client().get("/api/scheduler")
                settings_resp = _client().get("/api/settings/scheduler")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _encodable(body)
        rows = {t["label"]: t for t in body["timers"]}
        self.assertIn("z.good", rows)
        self.assertEqual(rows["z.good"]["interval_sec"], 60)
        # The <date> Label falls back to the file stem; its string
        # StartInterval still coerces and its <data>/<integer> argv renders.
        self.assertIn("d.datelabel", rows)
        self.assertEqual(rows["d.datelabel"]["interval_sec"], 60)
        # A dict ProgramArguments is not argv; the row keeps an empty program.
        self.assertIn("e.progargsdict", rows)
        self.assertEqual(rows["e.progargsdict"]["program"], "")
        # Truncated XML, non-dict root, bad UTF-8, over-cap, FIFO and dir
        # nodes are skipped per file, never fatal.
        for gone in ("a.expat", "b.notdict", "c.badutf8", "f.huge",
                     "g.fifo", "h.dir"):
            self.assertNotIn(gone, rows)
        self.assertEqual(body["count"], len(body["timers"]))
        # The Settings page's summary of the same view degrades identically.
        self.assertEqual(settings_resp.status_code, 200)
        _encodable(settings_resp.json())
        labels = [t["label"] for t in settings_resp.json()["timers"]]
        self.assertIn("z.good", labels)


class BoundaryShapes(_Sandbox):
    """Request shapes at the validation boundary answer renderable 4xxs."""

    def setUp(self):
        super().setUp()
        self._write_yaml("schedules: []\n")

    def test_surrogate_name_body_is_a_renderable_422_nothing_stored(self):
        resp = _client().post(
            "/api/scheduler/jobs",
            content=(b'{"id": "sn", "name": "n\\ud800", "type": "command",'
                     b' "cron": "* * * * *",'
                     b' "params": {"command": "echo hi"}}'),
            headers={"content-type": "application/json"},
        )
        self.assertEqual(resp.status_code, 422, resp.text[:300])
        resp.content.decode("utf-8")  # body renders, surrogate scrubbed
        _encodable(resp.json())
        self.assertEqual(scheduler_svc.list_jobs(), [])

    def test_huge_digit_cron_is_the_coded_400_with_truncated_echo(self):
        cron = "9" * 100000 + " * * * *"
        resp = _client().post("/api/scheduler/jobs", json={
            "name": "n", "type": "command", "cron": cron,
            "params": {"command": "echo hi"}})
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        detail = resp.json()["detail"]
        self.assertEqual(detail["code"], "scheduler.bad_cron")
        # The echoed expression is capped, not the whole 100k payload.
        self.assertLessEqual(len(detail["params"]["cron"]), 80)
        _encodable(resp.json())
        self.assertEqual(scheduler_svc.list_jobs(), [])

    def test_hostile_limit_query_strings_are_renderable_422s(self):
        for query in ("limit=" + "9" * 5000, "limit=1e999",
                      "limit=%ED%A0%80", "limit=-inf"):
            for path in ("/api/scheduler/runs", "/api/scheduler/jobs/j1/runs"):
                resp = _client().get(f"{path}?{query}")
                self.assertEqual(
                    resp.status_code, 422, (path, query, resp.text[:300]))
                resp.content.decode("utf-8")
                _encodable(resp.json())


if __name__ == "__main__":
    unittest.main()
