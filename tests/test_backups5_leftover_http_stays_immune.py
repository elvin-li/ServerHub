"""Fifth leftover-500s sweep of the Backups surfaces, over the real mounted app.

The hunted classes (lone UTF-8 surrogates in keys AND values, the CPython
4300-digit int cap — including the hex-minted *already-int* form plists
produce through ``int(x, 16)`` — huge-number JSON, torn-IPv6 urlsplit
ValueError, leftover FIFOs, vanished-CLI 503-vs-500) were re-reproduced
against every surface the earlier backups/backups2/backups3/backups4 sweeps
left unprobed:

    GET  /api/backups            (FIFOs occupying every status store)
    POST /api/backups/postgres   (FIFO credentials, surrogate maintenance_env)
    POST /api/backups/immich     (the *native* pg_dump path end to end)
    POST /api/backups/configs    (hostile config_archive extras)
    GET  /api/snapshots          (hostile diskutil/tmutil plists)
    POST /api/snapshots/delete|thin, POST /api/timemachine/action
    backups.recover_interrupted_stack_backups (hostile crash markers)

One live leak was left: ``recover_interrupted_stack_backups`` appended the
raw ``stack_id`` / ``detail`` to its returned rows.  An undecodable marker
*filename* (os surrogateescape) or a ``\\ud800`` escape inside the marker
JSON put lone surrogates into that list — every other result this module
builds is ``_as_text``-scrubbed before it can meet a strict UTF-8 JSON
encoder, and this one raised ``UnicodeEncodeError`` out of
``json.dumps(..., ensure_ascii=False).encode("utf-8")``.  The row is now
scrubbed at the reporting edge while the raw id keeps driving the
``_find_stack`` lookup (a stack whose own id carries the same surrogates
must still match).

Everything else stayed immune and is pinned here so it cannot silently
regress at the layer the SPA actually talks to:

* plist-hex over-cap ints (``<integer>0xF…</integer>`` loads *already-int*,
  exempt from the digit cap) in every ``diskutil apfs listSnapshots`` /
  ``tmutil destinationinfo`` / ``tmutil status`` field cost their one field,
  never GET /api/snapshots; ``<data>`` / ``<date>`` leftovers, torn plists
  and wrong-shaped documents render an empty page instead of a traceback;
* surrogate mount / date_token / action bodies earn their coded 400s with
  UTF-8-clean bodies, and the audit line survives the surrogate action;
* leftover FIFOs occupying panel_status.json / backup_status.json /
  backup-credentials.json / immich .env / a ``.sql.bak`` artefact / a crash
  marker never hang the request (O_NONBLOCK + the regular-file check);
* the native Immich dump answers coded/uncoded ok:false — never 500 — for a
  torn-IPv6 DB_URL (urlsplit ValueError), an out-of-range port, a
  percent-encoded lone-surrogate password, a dump with no completion
  marker, a watchdog timeout (artefact discarded), a dest occupied by a
  directory, and an unwritable BACKUP_ROOT — and stays ok:true with the
  marker present;
* hostile ``backups.config_archive`` extras (surrogate keywords, NUL and
  relative paths, non-str junk) cost themselves, never the archive route;
* the ``_only_one`` guard answers the coded 409 ``backup.busy`` over HTTP.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import backups, snapshots_svc  # noqa: E402
from hub.routers import nas_common, nas_storage  # noqa: E402

#: The hex spelling parses uncapped (``int(x, 16)``), so a live over-cap int
#: really can exist in memory; only rendering it back is impossible.
_HUGE_HEX = "0x" + "f" * 4400

_APP = None


def _client():
    global _APP
    from fastapi.testclient import TestClient

    if _APP is None:
        from hub.app_factory import create_app
        from hub.auth import require_auth

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


def _strict_utf8(resp) -> str:
    """The body must already be valid UTF-8 — decode strictly on purpose."""
    return resp.content.decode("utf-8")


def _admin_browser(stack: ExitStack) -> None:
    """An administrator browser session, as nas_common resolves one."""
    stack.enter_context(mock.patch.object(
        nas_common.auth, "browser_authenticated", return_value=True))
    stack.enter_context(mock.patch.object(
        nas_common.auth, "request_username", return_value="admin"))
    stack.enter_context(mock.patch.object(
        nas_common.auth, "is_admin", return_value=True))
    stack.enter_context(mock.patch.object(
        nas_common.auth, "request_client_id", return_value="127.0.0.1"))
    stack.enter_context(mock.patch.object(
        nas_storage.audit, "record", lambda *a, **k: {}))


def _plist(body: str) -> str:
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            f'<plist version="1.0">{body}</plist>')


# ── GET /api/snapshots: hostile diskutil / tmutil plists ─────────────────────

_SNAP_LIST = _plist(
    "<dict><key>Snapshots</key><array>"
    # plist-hex over-cap already-ints in every field
    f"<dict><key>SnapshotName</key><integer>{_HUGE_HEX}</integer>"
    f"<key>SnapshotUUID</key><integer>{_HUGE_HEX}</integer>"
    f"<key>SnapshotXID</key><integer>{_HUGE_HEX}</integer>"
    f"<key>Purgeable</key><integer>{_HUGE_HEX}</integer></dict>"
    # <data> (bytes) and <date> (datetime) leftovers
    "<dict><key>SnapshotName</key><data>//7/</data>"
    "<key>SnapshotXID</key><date>2026-08-01T00:00:00Z</date></dict>"
    # a normal row that must survive its hostile siblings
    "<dict><key>SnapshotName</key>"
    "<string>com.apple.TimeMachine.2026-08-03-160000.local</string>"
    "<key>SnapshotXID</key><integer>42</integer>"
    "<key>Purgeable</key><true/></dict>"
    # non-dict entries
    "<string>junk</string><integer>7</integer>"
    "</array></dict>")

_TM_DEST = _plist(
    "<dict><key>Destinations</key><array>"
    f"<dict><key>ID</key><integer>{_HUGE_HEX}</integer>"
    "<key>Name</key><data>/v8=</data>"
    f"<key>Kind</key><integer>{_HUGE_HEX}</integer>"
    f"<key>MountPoint</key><integer>{_HUGE_HEX}</integer>"
    f"<key>URL</key><integer>{_HUGE_HEX}</integer>"
    f"<key>LastDestination</key><integer>{_HUGE_HEX}</integer></dict>"
    "</array></dict>")

_TM_STATUS = _plist(
    "<dict>"
    f"<key>Running</key><integer>{_HUGE_HEX}</integer>"
    f"<key>BackupPhase</key><integer>{_HUGE_HEX}</integer>"
    "<key>Progress</key><dict>"
    # finite 1e308 is not inf; the *100 scaling overflow is the guarded edge
    "<key>Percent</key><real>1e308</real></dict>"
    "</dict>")


def _fake_sh_zoo(argv, timeout=10, **kwargs):
    if "listSnapshots" in argv:
        return 0, _SNAP_LIST, ""
    if "destinationinfo" in argv:
        # tmutil writes diagnostics ahead of the XML on some failures
        return 0, "diag noise\n" + _TM_DEST, ""
    if "status" in argv:
        return 0, _TM_STATUS, ""
    if "latestbackup" in argv:
        return 0, "/Volumes/TM/2026-08-03-160000.backup", ""
    return 0, _plist("<dict/>"), ""


class SnapshotsPlistZooHttpTests(unittest.TestCase):
    """GET /api/snapshots with the plist leftover zoo: 200, clean, complete."""

    def _get(self, fake_sh):
        snapshots_svc.invalidate()
        try:
            with mock.patch.object(snapshots_svc, "sh", fake_sh):
                return _client().get("/api/snapshots?force=true")
        finally:
            snapshots_svc.invalidate()

    def test_over_cap_plist_hex_fields_cost_fields_never_the_page(self):
        resp = self._get(_fake_sh_zoo)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        text = _strict_utf8(resp)
        self.assertNotIn("4300", text)
        payload = json.loads(text)
        snaps = payload["volumes"][0]["snapshots"]
        # The over-cap and data/date rows degrade; the normal row survives.
        names = [s["name"] for s in snaps]
        self.assertIn("com.apple.TimeMachine.2026-08-03-160000.local", names)
        good = next(s for s in snaps
                    if s["name"].startswith("com.apple.TimeMachine"))
        self.assertEqual(good["xid"], 42)
        self.assertEqual(good["date_token"], "2026-08-03-160000")
        hostile = next(s for s in snaps if s["name"] == "")
        self.assertIsNone(hostile["xid"])
        tm = payload["time_machine"]
        # Over-cap MountPoint/ID/Kind/URL each cost their field only.
        self.assertEqual(len(tm["destinations"]), 1)
        self.assertEqual(tm["destinations"][0]["mount"], "")
        # 1e308 * 100 overflows to inf: percent drops, Running stays truthy.
        self.assertIsNone(tm["percent"])
        self.assertTrue(tm["running"])

    def test_torn_plists_render_an_empty_page_not_a_traceback(self):
        def torn(argv, timeout=10, **kwargs):
            if "listSnapshots" in argv:
                return 0, "<?xml version='1.0'?><plist><dict><key>Snap", ""
            return 0, "<?xml", ""
        resp = self._get(torn)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["total"], 0)

    def test_wrong_shaped_documents_keep_the_page(self):
        def shapes(argv, timeout=10, **kwargs):
            if "listSnapshots" in argv:
                return 0, _plist("<dict><key>Snapshots</key>"
                                 "<dict><key>a</key><string>b</string></dict>"
                                 "</dict>"), ""
            if "status" in argv:
                return 0, _plist(
                    "<dict><key>Running</key><true/>"
                    "<key>Progress</key><dict>"
                    f"<key>Percent</key><integer>{_HUGE_HEX}</integer>"
                    "</dict></dict>"), ""
            if "destinationinfo" in argv:
                return 0, _plist("<array><string>x</string></array>"), ""
            if "latestbackup" in argv:
                return 0, b"\xff\xfebad", ""
            return 0, "", ""
        resp = self._get(shapes)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["total"], 0)
        self.assertIsNone(payload["time_machine"]["percent"])


class SnapshotMutationHostileBodyTests(unittest.TestCase):
    """Hostile bodies earn coded 400s with UTF-8-clean bodies, never 500s."""

    def _post(self, path, raw: bytes):
        with ExitStack() as stack:
            _admin_browser(stack)
            return _client().post(
                path, content=raw,
                headers={"content-type": "application/json"})

    def test_surrogate_mount_is_the_coded_400_with_a_clean_body(self):
        resp = self._post("/api/snapshots/delete",
                          b'{"mount": "/Volumes/\\ud800x", "confirm": true}')
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        text = _strict_utf8(resp)
        self.assertNotIn("\ud800", text)
        self.assertEqual(json.loads(text)["detail"]["code"],
                         "snapshot.bad_mount")

    def test_surrogate_date_token_is_the_coded_400(self):
        resp = self._post(
            "/api/snapshots/delete",
            b'{"mount": "/", "date_token": "\\ud800", "confirm": true}')
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        self.assertEqual(json.loads(_strict_utf8(resp))["detail"]["code"],
                         "snapshot.bad_token")

    def test_4000_digit_urgency_is_the_coded_400(self):
        # Under json's 4300-digit parse cap, so it arrives as a real int and
        # must die in the range check, not in a render.
        resp = self._post("/api/snapshots/thin",
                          b'{"mount": "/", "urgency": ' + b"9" * 4000 + b"}")
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        self.assertEqual(json.loads(_strict_utf8(resp))["detail"]["code"],
                         "snapshot.bad_urgency")

    def test_surrogate_action_is_the_coded_400_with_the_real_audit(self):
        # No audit stub: the route's audit.record line runs with the
        # surrogate ``tm_…`` action and must not raise into the request.
        from hub import audit
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                nas_common.auth, "browser_authenticated", return_value=True))
            stack.enter_context(mock.patch.object(
                nas_common.auth, "request_username", return_value="admin"))
            stack.enter_context(mock.patch.object(
                nas_common.auth, "is_admin", return_value=True))
            stack.enter_context(mock.patch.object(
                nas_common.auth, "request_client_id", return_value="127.0.0.1"))
            stack.enter_context(mock.patch.object(
                audit, "AUDIT_PATH", Path(tmp) / "audit.jsonl"))
            resp = _client().post(
                "/api/timemachine/action",
                content=b'{"action": "st\\ud800art"}',
                headers={"content-type": "application/json"})
            self.assertEqual(resp.status_code, 400, resp.text[:300])
            text = _strict_utf8(resp)
            self.assertNotIn("\ud800", text)
            self.assertEqual(json.loads(text)["detail"]["code"],
                             "snapshot.bad_action")
            # The trail took the scrubbed line rather than losing it.
            trail = (Path(tmp) / "audit.jsonl").read_text(encoding="utf-8")
            self.assertIn("tm_st", trail)
            self.assertNotIn("\ud800", trail)

    def test_5000_digit_action_is_the_coded_400(self):
        resp = self._post("/api/timemachine/action",
                          b'{"action": "' + b"9" * 5000 + b'"}')
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        self.assertEqual(json.loads(_strict_utf8(resp))["detail"]["code"],
                         "snapshot.bad_action")


# ── the Backups page sandbox ─────────────────────────────────────────────────

class _BackupsSandbox(unittest.TestCase):
    """Private BACKUP_ROOT / DATA_DIR / PhotosHub / Immich state per test."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.backup_root = root / "backups"
        self.backup_root.mkdir()
        self.data_dir = root / "data"
        self.data_dir.mkdir()
        self.photos_state = root / "photoshub-state"
        self.photos_state.mkdir()
        self.immich_root = root / "immich"
        self.immich_root.mkdir()
        for name, value in (
            ("BACKUP_ROOT", self.backup_root),
            ("DATA_DIR", self.data_dir),
            ("BACKUP_SECRETS_FILE", self.data_dir / "backup-credentials.json"),
            ("PHOTOSHUB_CFG", root / "photoshub" / "config.json"),
            ("PHOTOSHUB_STATE", self.photos_state),
            ("IMMICH_ROOT", self.immich_root),
            ("IMMICH_SCRIPT", self.immich_root / "backup-db.sh"),
            ("IMMICH_DB_ENV", self.immich_root / "db.env"),
        ):
            patched = mock.patch.object(backups, name, value)
            patched.start()
            self.addCleanup(patched.stop)

    def _request_bounded(self, method: str, path: str, deadline: float = 20.0):
        """Drive one request on a worker thread so a regression that hangs
        (a FIFO parked in ``open()``) fails the test instead of the suite."""
        box: list = []

        def run():
            box.append(getattr(_client(), method)(path))

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        worker.join(timeout=deadline)
        self.assertFalse(worker.is_alive(),
                         f"{method.upper()} {path} hung past {deadline}s")
        return box[0]


class BackupsFifoHttpTests(_BackupsSandbox):
    """Leftover FIFOs occupying every store must not hang or 500."""

    def test_fifos_everywhere_keep_the_page_and_the_dump(self):
        os.mkfifo(self.photos_state / "panel_status.json")
        os.mkfifo(self.photos_state / "backup_status.json")
        os.mkfifo(self.photos_state / "external_backup_status.json")
        os.mkfifo(self.backup_root / "fifo_trap.sql.bak")
        os.mkfifo(self.immich_root / ".env")
        os.mkfifo(self.data_dir / "backup-credentials.json")
        resp = self._request_bounded("get", "/api/backups")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        # The FIFO is not an artefact: it must not be listed as a backup.
        self.assertEqual(payload["total"], 0)
        resp = self._request_bounded("post", "/api/backups/postgres")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertFalse(json.loads(_strict_utf8(resp))["ok"])


class ImmichNativeDumpHttpTests(_BackupsSandbox):
    """POST /api/backups/immich down the *native* pg_dump path."""

    def _db_env(self, url: str):
        (self.immich_root / "db.env").write_text(
            f"DB_URL={url}\n", encoding="utf-8")

    def _fake_pg(self, script: str) -> Path:
        fake = Path(self._tmp.name) / "pg_dump"
        fake.write_text(script, encoding="utf-8")
        fake.chmod(0o755)
        return fake

    def _post(self, pg: Path):
        with mock.patch.object(backups, "_PG18_DUMPS", (pg,)):
            return _client().post("/api/backups/immich")

    def test_torn_ipv6_db_url_is_ok_false_not_500(self):
        # urlsplit of ``[::1`` (no closing bracket) raises ValueError.
        self._db_env("postgresql://immich:pw@[::1:5433/immich")
        resp = self._post(Path("/bin/sh"))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertFalse(json.loads(_strict_utf8(resp))["ok"])

    def test_out_of_range_port_is_ok_false_not_500(self):
        # ``parsed.port`` raises ValueError past 65535.
        self._db_env("postgresql://immich:pw@127.0.0.1:99999999/immich")
        resp = self._post(Path("/bin/sh"))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertFalse(json.loads(_strict_utf8(resp))["ok"])

    def test_percent_encoded_surrogate_password_is_clean_ok_false(self):
        # unquote() of %ed%a0%80 mints a lone surrogate into PGPASSWORD.
        self._db_env("postgresql://immich:%ed%a0%80pw@127.0.0.1:5433/immich")
        pg = self._fake_pg("#!/bin/sh\nexit 1\n")
        resp = self._post(pg)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        text = _strict_utf8(resp)
        self.assertNotIn("\ud800", text)
        self.assertFalse(json.loads(text)["ok"])

    def test_dump_without_completion_marker_is_discarded_ok_false(self):
        self._db_env("postgresql://immich:pw@127.0.0.1:5433/immich")
        pg = self._fake_pg("#!/bin/sh\nprintf 'partial output'\n"
                           "printf 'noise \\xff' >&2\nexit 3\n")
        resp = self._post(pg)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertFalse(json.loads(_strict_utf8(resp))["ok"])
        self.assertEqual(list(self.backup_root.glob("immich_*")), [])

    def test_complete_dump_is_ok_true(self):
        self._db_env("postgresql://immich:pw@127.0.0.1:5433/immich")
        pg = self._fake_pg("#!/bin/sh\necho 'stuff'\n"
                           "echo '-- PostgreSQL database dump complete'\n"
                           "exit 0\n")
        resp = self._post(pg)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertTrue(payload["ok"])
        self.assertIn("immich_", payload["path"])

    def test_watchdog_timeout_answers_coded_message_and_discards(self):
        self._db_env("postgresql://immich:pw@127.0.0.1:5433/immich")
        pg = self._fake_pg("#!/bin/sh\necho part\nsleep 30\n")
        with mock.patch.object(backups, "_IMMICH_TIMEOUT", 2):
            resp = self._post(pg)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "immich dump timed out")
        self.assertEqual(list(self.backup_root.glob("immich_*")), [])

    def test_dest_occupied_by_a_directory_steps_past_not_500(self):
        # A leftover *directory* squatting on the stamped name is EEXIST to
        # the O_EXCL create, so _private_dest steps to ``…-2`` and the dump
        # still lands — never an IsADirectoryError 500 out of gzip.open.
        self._db_env("postgresql://immich:pw@127.0.0.1:5433/immich")
        pg = self._fake_pg("#!/bin/sh\n"
                           "echo '-- PostgreSQL database dump complete'\n")
        with mock.patch.object(backups, "strftime_now", return_value="TRAP"):
            (self.backup_root / "immich_TRAP.sql.gz").mkdir()
            resp = self._post(pg)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertTrue(payload["ok"], payload)
        self.assertTrue(payload["path"].endswith("immich_TRAP-2.sql.gz"))

    def test_unwritable_backup_root_is_ok_false_not_500(self):
        self._db_env("postgresql://immich:pw@127.0.0.1:5433/immich")
        pg = self._fake_pg("#!/bin/sh\n"
                           "echo '-- PostgreSQL database dump complete'\n")
        os.chmod(self.backup_root, 0o500)
        self.addCleanup(os.chmod, self.backup_root, 0o700)
        resp = self._post(pg)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertFalse(json.loads(_strict_utf8(resp))["ok"])

    def test_immich_root_occupied_by_a_file_is_ok_false_not_500(self):
        # The script path spawns with cwd=IMMICH_ROOT; a file there is
        # NotADirectoryError inside Popen, reported as the run's message.
        script = Path(self._tmp.name) / "backup-db.sh"
        script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        script.chmod(0o755)
        not_a_dir = Path(self._tmp.name) / "immich-file"
        not_a_dir.write_text("not a dir", encoding="utf-8")
        with (
            mock.patch.object(backups, "IMMICH_ROOT", not_a_dir),
            mock.patch.object(backups, "IMMICH_SCRIPT", script),
        ):
            resp = _client().post("/api/backups/immich")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertFalse(json.loads(_strict_utf8(resp))["ok"])


class ConfigArchiveHostileExtrasHttpTests(_BackupsSandbox):
    """Hostile config_archive extras cost themselves, never the route."""

    def setUp(self):
        super().setUp()
        self.cfg_file = Path(self._tmp.name) / "services.yaml"
        self.cfg_file.write_text("settings: {}\n", encoding="utf-8")
        patched = mock.patch.object(backups, "CONFIG_FILE", self.cfg_file)
        patched.start()
        self.addCleanup(patched.stop)

    def _hostile_cfg(self) -> dict:
        return {
            "backups": {
                "config_archive": {
                    "agent_keywords": ["\ud800bad", 123, None, {"x": 1}],
                    "extra_paths": [
                        "/tmp/\ud800weird", "relative/path",
                        "~norealuser/x", "/tmp/\x00nul", 12345,
                        str(self.cfg_file),
                    ],
                },
                "postgres": "not-a-list",
            },
            "settings": {
                "maintenance_env": {"\ud800k": "\ud800v", 123: 456},
            },
        }

    def test_hostile_extras_still_archive_the_config(self):
        with mock.patch.object(backups, "cfg", return_value=self._hostile_cfg()):
            resp = _client().post("/api/backups/configs")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        text = _strict_utf8(resp)
        self.assertNotIn("\ud800", text)
        payload = json.loads(text)
        self.assertTrue(payload["ok"], payload)
        self.assertTrue(payload["path"].endswith(".tgz"))

    def test_not_a_list_postgres_keeps_the_page_and_the_dump_refusal(self):
        with mock.patch.object(backups, "cfg", return_value=self._hostile_cfg()):
            resp = _client().get("/api/backups")
            self.assertEqual(resp.status_code, 200, resp.text[:300])
            self.assertEqual(
                json.loads(_strict_utf8(resp))["postgres_targets"], [])
            resp = _client().post("/api/backups/postgres")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"], "not_configured")

    def test_busy_job_is_the_coded_409_over_http(self):
        lock = backups._job_locks.setdefault("configs", threading.Lock())
        self.assertTrue(lock.acquire(blocking=False))
        try:
            resp = _client().post("/api/backups/configs")
        finally:
            lock.release()
        self.assertEqual(resp.status_code, 409, resp.text[:300])
        self.assertEqual(json.loads(_strict_utf8(resp))["detail"]["code"],
                         "backup.busy")


class ScanOdditiesHttpTests(_BackupsSandbox):
    """Deep trees, device symlinks and hidden artefacts keep the listing."""

    def test_deep_tree_and_dev_symlink_keep_the_page(self):
        deep = self.backup_root
        for i in range(30):
            deep = deep / f"d{i}"
        deep.mkdir(parents=True)
        (deep / "x.tar.bak.gz").write_text("x", encoding="utf-8")
        (self.backup_root / ".hidden.sql.bak").write_text("h", encoding="utf-8")
        try:
            (self.backup_root / "link.sql").symlink_to("/dev/zero")
        except OSError:
            pass
        resp = _client().get("/api/backups")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        names = {row["name"] for row in payload["backups"]}
        self.assertIn("x.tar.bak.gz", names)
        self.assertIn(".hidden.sql.bak", names)
        # /dev/zero is a device node, not an artefact.
        self.assertNotIn("link.sql", names)


class RecoveryHostileMarkerTests(unittest.TestCase):
    """Crash markers: hostile names/contents cost detail, never the scan.

    The surrogate rows are the fix this sweep landed: an undecodable marker
    filename (os surrogateescape) or a ``\\ud800`` escape in the marker JSON
    put lone surrogates into the returned rows, which raised
    UnicodeEncodeError out of a strict UTF-8 JSON encode.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.data_dir = Path(self._tmp.name) / "data"
        self.data_dir.mkdir()
        patched = mock.patch.object(backups, "DATA_DIR", self.data_dir)
        patched.start()
        self.addCleanup(patched.stop)

    def _recover(self, deadline: float = 20.0) -> list:
        box: list = []
        errors: list = []

        def run():
            try:
                box.append(backups.recover_interrupted_stack_backups())
            except Exception as exc:  # noqa: BLE001 — the pin is "never raises"
                errors.append(exc)

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        worker.join(timeout=deadline)
        self.assertFalse(worker.is_alive(),
                         f"recovery hung past {deadline}s")
        self.assertEqual(errors, [], f"recovery raised: {errors!r}")
        return box[0]

    def test_hostile_markers_recover_clean_and_are_consumed(self):
        prefix = backups._INFLIGHT_PREFIX
        os.mkfifo(self.data_dir / f"{prefix}fifo1")
        (self.data_dir / f"{prefix}huge").write_text(
            '{"stack": "s", "compose_path": "/nonexistent.yml", '
            '"ts": ' + "9" * 5000 + "}", encoding="utf-8")
        (self.data_dir / f"{prefix}deep").write_text(
            "[" * 5000 + "]" * 5000, encoding="utf-8")
        # undecodable marker filename (os surrogateescape mints surrogates)
        os.close(os.open(
            bytes(self.data_dir) + b"/" + prefix.encode() + b"\xff\xfe",
            os.O_WRONLY | os.O_CREAT, 0o600))
        # a \ud800 escape in the marker JSON itself
        (self.data_dir / f"{prefix}surr").write_text(
            '{"stack": "s\\ud800tack", "compose_path": ""}',
            encoding="utf-8")
        with (
            mock.patch.object(backups, "_run_argv",
                              return_value=(1, "compose fail", "")),
            mock.patch.object(backups, "_find_stack", return_value=None),
        ):
            recovered = self._recover()
        self.assertEqual(len(recovered), 5)
        # The returned rows must survive Starlette's strict encode.
        json.dumps(recovered, ensure_ascii=False,
                   allow_nan=False).encode("utf-8")
        stacks = {row["stack"] for row in recovered}
        self.assertNotIn("s\ud800tack", stacks)
        self.assertTrue(any("tack" in s for s in stacks))
        # Every marker — including the hostile ones — was consumed, so the
        # scan does not repeat on every future restart.
        self.assertEqual(list(self.data_dir.glob(f"{prefix}*")), [])

    def test_recorded_compose_path_still_drives_the_restart(self):
        prefix = backups._INFLIGHT_PREFIX
        (self.data_dir / f"{prefix}media").write_text(
            '{"stack": "media", "compose_path": "/srv/compose.yml"}',
            encoding="utf-8")
        calls: list = []

        def fake_run_argv(argv, *, timeout, cap=4000):
            calls.append(argv)
            return 0, "started", ""

        with (
            mock.patch.object(backups, "_run_argv", fake_run_argv),
            mock.patch.object(backups, "_find_stack", return_value=None),
        ):
            recovered = self._recover()
        self.assertEqual(len(recovered), 1)
        self.assertIs(recovered[0]["started"], True)
        self.assertEqual(recovered[0]["detail"], "restarted")
        self.assertIn("/srv/compose.yml", calls[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
