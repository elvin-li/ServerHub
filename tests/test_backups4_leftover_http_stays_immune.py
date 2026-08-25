"""Fourth leftover-500s sweep of the Backups page, over the real mounted app.

The hunted classes (lone UTF-8 surrogates in keys AND values, the CPython
4300-digit int cap — including the hex/octal-minted form that arrives
already-int — huge-number JSON stores, vanished-CLI 503-vs-500) were
re-reproduced against every route the Backups page talks to:

    GET  /api/backups
    POST /api/backups/postgres
    POST /api/backups/immich
    POST /api/backups/configs
    GET  /api/backups/rsync/binary
    POST /api/backups/rsync/preview

One live leak was left: the ``f"exit {rc}"`` render in the immich script
job's result sat outside every try, so an over-cap exit code with no other
output raised the digit-cap ValueError out of ``_backup_immich_script`` and
500'd POST /api/backups/immich *after the run had already finished*.  The
postgres dump's broad ``except Exception`` kept the 200 on the same shape
but answered with CPython's digit-cap internals ("Exceeds the limit (4300
digits) …") as the entire message, and the compose stop/start/config and
tar renders fed the scheduler journal through the same bare f-strings.
All of those now go through ``backups._exit_text`` and degrade to ``exit
unknown`` (the brew_svc rule), costing the number and never the request.

Everything else was already immune at the module layer (backups2/backups3),
but none of those pins exercises request routing, Pydantic body parsing,
app_factory's sanitizing error handlers, the routes' audit lines, or
Starlette's strict UTF-8 render of the final body.  This battery pins the
whole cycle through ``create_app()`` so the immunity cannot silently regress
at the layer the SPA actually talks to:

* hex-minted over-cap ints, lone-surrogate values and ``.inf`` ports in
  ``backups.postgres`` cost their one entry, never GET /api/backups — and a
  numeric ``id:`` coerces through the str() probe instead of being dropped
  for not being a str;
* one >4300-digit number literal in panel_status.json / backup_status.json
  costs that field, never the layer cards (``json.loads`` raises the
  digit-cap ValueError, NOT JSONDecodeError — the document must survive);
* surrogate keys AND values in those stores, and undecodable on-disk
  artefact names (os surrogateescape), are scrubbed before Starlette's
  strict UTF-8 encode; a ``{path}``-braced artefact name cannot KeyError
  the restore-hint interpolation;
* a >4300-digit integer literal in a request body is FastAPI's body-parse
  400 (never 500), and the rsync preview's coded 400s echo hostile
  patterns/directions back scrubbed;
* pg_dump / tar / backup-db.sh / rsync answering run_capped's
  ``(-1, "not found")`` sentinel become the coded 503 (or the coded
  not_configured refusal) only after a fresh disk probe confirms the tool
  actually left the disk; the same sentinel while the tool is still present
  keeps the raw result;
* the mutating backup routes still write their BACKUP_RUN audit line.
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import backups, rsync_svc
from hub.app_factory import create_app
from hub.auth import require_auth
from hub.routers import settings_api

#: Past CPython's default 4300-digit str<->int conversion limit.
_HUGE_DIGITS = "9" * 5000
#: The hex spelling parses uncapped (``int(x, 16)``), so a live over-cap int
#: really can exist in memory; only rendering it back is impossible.
_HUGE_INT = int("f" * 4400, 16)

#: What hub.util.run_capped returns when the binary is gone (sentinel) — and
#: also what a SIGHUP-killed run whose tail read "not found" looks like.
SENTINEL = (-1, "not found")

_RSYNC_OK = {
    "available": True, "path": "/usr/bin/rsync", "variant": "rsync3",
    "version": "3.2.7",
    "supports": {"itemize": True, "progress2": True,
                 "compress": True, "bwlimit": True},
}

_app = None


def _the_app():
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return _app


async def _asgi_request(method, path, *, body=None, raw_body=None):
    """Drive the full panel app (middleware + handlers) through one cycle."""
    app = _the_app()
    payload = raw_body if raw_body is not None else (
        b"{}" if body is None else json.dumps(body).encode("utf-8")
    )
    sent = False
    messages: list[dict] = []

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": payload, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1", "method": method, "scheme": "http",
        "path": path, "raw_path": path.encode(), "query_string": b"",
        "root_path": "",
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
            (b"host", b"localhost:8086"),
        ],
        "server": ("localhost", 8086), "client": ("127.0.0.1", 1), "state": {},
    }
    await app(scope, receive, send)
    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    raw = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    # The body must already be valid UTF-8 — decode strictly on purpose.
    return status, raw.decode("utf-8")


def request(method, path, *, body=None, raw_body=None):
    return asyncio.run(_asgi_request(method, path, body=body, raw_body=raw_body))


class _BackupsSandbox(unittest.TestCase):
    """Private BACKUP_ROOT / DATA_DIR / PhotosHub state per test."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.backup_root = root / "backups"
        self.backup_root.mkdir()
        self.data_dir = root / "data"
        self.data_dir.mkdir()
        self.photos_state = root / "photoshub-state"
        immich_root = root / "immich"
        immich_root.mkdir()
        self.immich_script = immich_root / "backup-db.sh"
        for name, value in (
            ("BACKUP_ROOT", self.backup_root),
            ("DATA_DIR", self.data_dir),
            ("BACKUP_SECRETS_FILE", self.data_dir / "backup-credentials.json"),
            ("PHOTOSHUB_CFG", root / "photoshub" / "config.json"),
            ("PHOTOSHUB_STATE", self.photos_state),
            ("IMMICH_ROOT", immich_root),
            ("IMMICH_SCRIPT", self.immich_script),
            ("IMMICH_DB_ENV", immich_root / "db.env"),
        ):
            patched = mock.patch.object(backups, name, value)
            patched.start()
            self.addCleanup(patched.stop)

    def _cfg(self, postgres):
        return mock.patch.object(
            backups, "cfg", return_value={"backups": {"postgres": postgres}},
        )

    def _install_immich_script(self):
        self.immich_script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.immich_script.chmod(0o755)


class BackupsListHostileConfigHttpTests(_BackupsSandbox):
    """GET /api/backups with the leftover zoo in ``backups.postgres``."""

    def test_hostile_entries_cost_themselves_never_the_page(self):
        hostile = [
            {"id": _HUGE_INT, "db": "x"},              # over-cap already-int id
            {"id": "s1", "db": _HUGE_INT},             # over-cap already-int db
            {"id": "s2", "db": "d\ud800b"},            # lone-surrogate value
            {"id": "s3", "db": "db", "port": float("inf")},
            {"id": 123, "db": "numericdb"},            # numeric id: str() probe
            {"id": "good", "db": "realdb", "port": 5433},
        ]
        with self._cfg(hostile):
            status, text = request("GET", "/api/backups")
        self.assertEqual(status, 200, text[:300])
        self.assertNotIn("\ud800", text)
        targets = {t["id"]: t for t in json.loads(text)["postgres_targets"]}
        # The bad entries drop one by one; the numeric id coerces to "123"
        # through the str() probe instead of vanishing for not being a str.
        self.assertEqual(sorted(targets), ["123", "good"])
        self.assertEqual(targets["123"]["db"], "numericdb")
        self.assertEqual(targets["good"]["port"], 5433)

    def test_surrogate_backup_root_renders_scrubbed(self):
        with mock.patch.object(
            backups, "BACKUP_ROOT", Path("/tmp/b\udcffad-home/backups"),
        ):
            status, text = request("GET", "/api/backups")
        self.assertEqual(status, 200, text[:300])
        self.assertNotIn("\udcff", text)
        self.assertIn("ad-home", json.loads(text)["root"])


class BackupsListPoisonedStoresHttpTests(_BackupsSandbox):
    """Poisoned PhotosHub status stores cost fields, never the layer cards."""

    def setUp(self):
        super().setUp()
        self._install_immich_script()
        self.photos_state.mkdir(parents=True)

    def test_huge_int_and_surrogates_in_status_json_keep_the_document(self):
        (self.photos_state / "panel_status.json").write_text(
            '{"originals": {"local_original_pct": 91,'
            ' "originals_human": "1.2\\ud800TB", "assets_active": %s},'
            ' "backup": {"ok": true, "last_success": "\\ud800today",'
            ' "reason": NaN}, "\\ud800key": "\\udc80v"}' % _HUGE_DIGITS,
            encoding="utf-8",
        )
        (self.photos_state / "backup_status.json").write_text(
            '{"ok": false, "reason": "r\\ud800", "size_human": %s}' % _HUGE_DIGITS,
            encoding="utf-8",
        )
        status, text = request("GET", "/api/backups")
        self.assertEqual(status, 200, text[:300])
        self.assertNotIn("\ud800", text)
        self.assertNotIn("\udc80", text)
        layers = json.loads(text)["immich"]["layers"]
        # json.loads of the huge literal is the digit-cap ValueError, not
        # JSONDecodeError: the parse_int hook must drop the one number and
        # keep every sibling instead of reading the whole store as corrupt.
        originals = layers["originals"]
        self.assertEqual(originals["pct"], 91)
        self.assertIn("TB", originals["size_human"])
        self.assertEqual(originals["backup"]["ok"], False)
        self.assertIn("r", originals["backup"]["reason"])

    def test_undecodable_and_braced_artefact_names_keep_the_listing(self):
        # os surrogateescape mints lone surrogates from an undecodable
        # on-disk name; a {path}-braced name used to KeyError str.format in
        # the restore-hint interpolation.
        os.close(os.open(
            bytes(self.backup_root) + b"/bad_\xff\xfe.sql.bak",
            os.O_WRONLY | os.O_CREAT, 0o600,
        ))
        (self.backup_root / "configs_{path}{oops}.tgz").write_text("x")
        (self.backup_root / "immich_20260101_000000.sql.gz").write_text("d")
        status, text = request("GET", "/api/backups")
        self.assertEqual(status, 200, text[:300])
        for ch in ("\ud800", "\udcff", "\udcfe"):
            self.assertNotIn(ch, text)
        payload = json.loads(text)
        self.assertEqual(payload["total"], 3)
        names = {row["name"] for row in payload["backups"]}
        self.assertIn("configs_{path}{oops}.tgz", names)
        self.assertIn("immich_20260101_000000.sql.gz", names)


class BackupsImmichExitRenderHttpTests(_BackupsSandbox):
    """The immich job result survives over-cap exit codes and surrogates."""

    def setUp(self):
        super().setUp()
        self._install_immich_script()

    def _run(self, run_result):
        with mock.patch.object(backups, "run_capped", return_value=run_result):
            return request("POST", "/api/backups/immich")

    def test_over_cap_exit_code_is_exit_unknown_not_500(self):
        # The f"exit {rc}" render sat outside every try: an over-cap rc with
        # empty output raised the digit-cap ValueError out of
        # _backup_immich_script and 500'd the route after the run finished.
        status, text = self._run((_HUGE_INT, ""))
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "exit unknown")

    def test_surrogate_script_output_is_scrubbed(self):
        status, text = self._run((1, "dump \ud800failed"))
        self.assertEqual(status, 200, text[:300])
        self.assertNotIn("\ud800", text)
        self.assertFalse(json.loads(text)["ok"])

    def test_script_vanished_mid_request_is_the_coded_refusal(self):
        # The gate saw the script; the spawn reported the sentinel; the
        # fresh disk probe on the failure path confirms it left the disk.
        def vanish(argv, **kwargs):
            self.immich_script.unlink()
            return SENTINEL
        with mock.patch.object(backups, "run_capped", side_effect=vanish):
            status, text = request("POST", "/api/backups/immich")
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"], "not_configured")

    def test_sentinel_while_the_script_is_on_disk_keeps_the_raw_result(self):
        # A signal-killed run is also rc -1: a still-present script must
        # keep its raw result instead of a false "not available".
        status, text = self._run(SENTINEL)
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "not found")
        self.assertNotIn("error", payload)


class BackupsPostgresHttpTests(_BackupsSandbox):
    """POST /api/backups/postgres through the mounted route."""

    ONE = [{"id": "teslamate", "db": "teslamate"}]

    def _run(self, run, *, on_disk=None):
        patches = [
            self._cfg(self.ONE),
            mock.patch.object(backups, "run_capped", run),
        ]
        if on_disk is not None:
            patches.append(
                mock.patch.object(backups, "_tool_on_disk", return_value=on_disk)
            )
        with patches[0], patches[1], (
            patches[2] if len(patches) == 3 else mock.patch.object(backups, "log")
        ):
            return request("POST", "/api/backups/postgres")

    def test_unconfigured_is_a_sentence_not_an_error(self):
        status, text = request("POST", "/api/backups/postgres")
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"], "not_configured")

    def test_over_cap_exit_code_is_exit_unknown_not_internals(self):
        # The broad catch kept the 200 but the message used to be CPython's
        # digit-cap internals ("Exceeds the limit (4300 digits) …").
        status, text = self._run(mock.Mock(return_value=(_HUGE_INT, "")))
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "exit unknown")
        self.assertNotIn("4300", text)

    def test_vanished_pg_dump_is_503_only_after_disk_confirm(self):
        status, text = self._run(mock.Mock(return_value=SENTINEL), on_disk=False)
        self.assertEqual(status, 503, text[:300])
        self.assertEqual(json.loads(text)["detail"]["code"], "backup.tool_missing")

    def test_sentinel_while_pg_dump_is_on_disk_keeps_the_raw_result(self):
        status, text = self._run(mock.Mock(return_value=SENTINEL), on_disk=True)
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "not found")

    def test_surrogate_dump_output_is_scrubbed(self):
        status, text = self._run(mock.Mock(return_value=(1, "err \ud800 out")))
        self.assertEqual(status, 200, text[:300])
        self.assertNotIn("\ud800", text)

    def test_the_run_is_audited(self):
        with mock.patch.object(settings_api.audit, "record") as record:
            status, text = request("POST", "/api/backups/postgres")
        self.assertEqual(status, 200, text[:300])
        record.assert_called_once()
        self.assertEqual(record.call_args.kwargs.get("kind"), "postgres")
        self.assertIs(record.call_args.kwargs.get("ok"), False)


class BackupsConfigsHttpTests(_BackupsSandbox):
    """POST /api/backups/configs through the mounted route."""

    def setUp(self):
        super().setUp()
        cfg_file = Path(self._tmp.name) / "services.yaml"
        cfg_file.write_text("settings: {}\n", encoding="utf-8")
        patched = mock.patch.object(backups, "CONFIG_FILE", cfg_file)
        patched.start()
        self.addCleanup(patched.stop)

    def test_vanished_tar_is_503_only_after_disk_confirm(self):
        with (
            mock.patch.object(backups, "run_capped", return_value=SENTINEL),
            mock.patch.object(backups, "_tool_on_disk", return_value=False),
        ):
            status, text = request("POST", "/api/backups/configs")
        self.assertEqual(status, 503, text[:300])
        self.assertEqual(json.loads(text)["detail"]["code"], "backup.tool_missing")

    def test_sentinel_while_tar_is_on_disk_keeps_the_raw_result(self):
        with (
            mock.patch.object(backups, "run_capped", return_value=SENTINEL),
            mock.patch.object(backups, "_tool_on_disk", return_value=True),
        ):
            status, text = request("POST", "/api/backups/configs")
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "not found")

    def test_surrogate_tar_output_is_scrubbed(self):
        with mock.patch.object(
            backups, "run_capped", return_value=(1, "tar: \ud800boom"),
        ):
            status, text = request("POST", "/api/backups/configs")
        self.assertEqual(status, 200, text[:300])
        self.assertNotIn("\ud800", text)
        self.assertFalse(json.loads(text)["ok"])


class RsyncPreviewBodyGuardHttpTests(unittest.TestCase):
    """Hostile request bodies through the real app's parse + coded 400s."""

    def _bi(self):
        return mock.patch.object(
            rsync_svc, "binary_info",
            mock.Mock(return_value=dict(_RSYNC_OK), invalidate=lambda: None),
        )

    def test_huge_int_literal_in_the_body_is_400_not_500(self):
        # json.loads raises the digit-cap ValueError (not JSONDecodeError);
        # FastAPI's body-parse guard must map it to 400.
        status, text = request(
            "POST", "/api/backups/rsync/preview",
            raw_body=b'{"bwlimit_kbps": ' + b"9" * 5000 + b"}",
        )
        self.assertEqual(status, 400, text[:300])

    def test_surrogate_exclude_echo_is_the_coded_400_with_a_clean_body(self):
        # The coded rejection echoes the pattern back in message AND params;
        # both must be scrubbed before Starlette's strict UTF-8 encode.
        with self._bi():
            status, text = request(
                "POST", "/api/backups/rsync/preview",
                raw_body=b'{"src": "/a", "dest": "/b", "exclude": ["p\\ud800at"]}',
            )
        self.assertEqual(status, 400, text[:300])
        self.assertNotIn("\ud800", text)
        self.assertEqual(json.loads(text)["detail"]["code"], "rsync.bad_exclude")

    def test_surrogate_direction_echo_is_the_coded_400(self):
        with self._bi():
            status, text = request(
                "POST", "/api/backups/rsync/preview",
                raw_body=b'{"direction": "pu\\ud800ll", "src": "/a", "dest": "/b"}',
            )
        self.assertEqual(status, 400, text[:300])
        self.assertNotIn("\ud800", text)
        self.assertEqual(json.loads(text)["detail"]["code"], "rsync.bad_direction")

    def test_huge_digit_string_bwlimit_is_the_coded_400(self):
        # Arrives as str, dies in int(str) at the digit cap — must stay the
        # coded parameter rejection, never a 500.
        with self._bi():
            status, text = request(
                "POST", "/api/backups/rsync/preview",
                body={"src": "/a", "dest": "/b", "bwlimit_kbps": _HUGE_DIGITS},
            )
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(json.loads(text)["detail"]["code"], "rsync.bad_params")

    def test_option_injection_in_exclude_stays_the_coded_400(self):
        with self._bi():
            status, text = request(
                "POST", "/api/backups/rsync/preview",
                body={"src": "/a", "dest": "/b", "exclude": ["--delete-after"]},
            )
        self.assertEqual(status, 400, text[:300])
        self.assertEqual(json.loads(text)["detail"]["code"], "rsync.bad_exclude")


class RsyncPreviewVanishedHttpTests(unittest.TestCase):
    """Confirmed-vanished rsync is the coded 503; unconfirmed keeps the raw dict."""

    def _preview(self, *, on_disk):
        with (
            mock.patch.object(
                rsync_svc, "binary_info",
                mock.Mock(return_value=dict(_RSYNC_OK), invalidate=lambda: None),
            ),
            mock.patch.object(
                rsync_svc.subprocess, "Popen",
                side_effect=FileNotFoundError(2, "No such file"),
            ),
            mock.patch.object(rsync_svc, "_binary_on_disk", return_value=on_disk),
            mock.patch.object(rsync_svc, "invalidate"),
        ):
            return request(
                "POST", "/api/backups/rsync/preview",
                body={"src": "/a", "dest": "/b"},
            )

    def test_vanished_mid_request_is_503_only_after_disk_confirm(self):
        status, text = self._preview(on_disk=False)
        self.assertEqual(status, 503, text[:300])
        self.assertEqual(json.loads(text)["detail"]["code"], "rsync.unavailable")

    def test_spawn_enoent_with_the_binary_still_present_keeps_the_raw_result(self):
        # execve also ENOENTs for a still-present binary whose loader is
        # gone; that must keep the truthful raw result, not fake a 503.
        status, text = self._preview(on_disk=True)
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["rc"], -1)

    def test_binary_probe_answers_the_page_shape(self):
        with mock.patch.object(
            rsync_svc, "probe_rsync", return_value=dict(_RSYNC_OK),
        ):
            rsync_svc.invalidate()
            try:
                status, text = request("GET", "/api/backups/rsync/binary")
            finally:
                rsync_svc.invalidate()
        self.assertEqual(status, 200, text[:300])
        payload = json.loads(text)
        self.assertTrue(payload["available"])
        self.assertEqual(payload["variant"], "rsync3")


class BackupsExitTextUnitTests(unittest.TestCase):
    """The shared render helper: number or ``exit unknown``, never a raise."""

    def test_normal_rc_renders_verbatim(self):
        self.assertEqual(backups._exit_text(1), "exit 1")
        self.assertEqual(backups._exit_text(-1), "exit -1")

    def test_over_cap_rc_renders_as_exit_unknown(self):
        self.assertEqual(backups._exit_text(_HUGE_INT), "exit unknown")

    def test_stack_journal_lines_survive_an_over_cap_compose_exit(self):
        # The compose stop/start and tar renders feed the scheduler journal
        # through the same f-strings; they must degrade, not raise.
        log: list = []
        stack = {"id": "s", "compose_path": "/tmp/compose.yml", "path": "/tmp"}
        with tempfile.TemporaryDirectory() as tmp, (
            mock.patch.object(backups, "BACKUP_ROOT", Path(tmp) / "backups")
        ), (
            mock.patch.object(backups, "DATA_DIR", Path(tmp) / "data")
        ), (
            mock.patch.object(backups, "_find_stack", return_value=stack)
        ), (
            mock.patch.object(backups, "_engine_up", return_value=True)
        ), (
            mock.patch.object(backups, "_stack_mounts", return_value=([], [], ""))
        ), (
            mock.patch.object(backups, "_run_argv", return_value=(_HUGE_INT, "", ""))
        ):
            result = backups.backup_stack("s", log=log)
        self.assertFalse(result["ok"])
        joined = "\n".join(log)
        self.assertIn("exit unknown", joined)
        self.assertNotIn("4300", joined)


if __name__ == "__main__":
    unittest.main()
