"""Eighth leftover-500s sweep of the Backups surfaces, over the real app.

backups7 sealed the *text* half of the ``run_capped`` seam — ``_as_text`` /
``_utf8_text`` / ``_cfg_text`` / ``_jsonable`` all moved to unbound base
operations.  What it never touched: the **rc half of the same seam**, which
still ran raw dunders everywhere it landed.  An int subclass whose
``__eq__`` / ``__ne__`` / ``__str__`` raises passes every ``isinstance``
and, on the pre-fix tree:

* POST /api/backups/immich — ``_cli_vanished``'s bare ``rc != -1`` and the
  ``ok = rc == 0`` / ``(text or _exit_text(rc))`` renders all sit *outside*
  the spawn's try, so a bombed rc 500'd the route after the script had
  already produced its artefact; a subclass ``__str__`` bomb rode the
  f-string's empty format spec (which dispatches to ``__str__``) past
  ``_exit_text``'s old narrow catch tuple on the empty-output path;
* POST /api/backups/postgres and /configs — the same bomb detonated at
  ``ok = rc == 0`` *inside* the jobs' broad catches: a dump/tar that had
  already written every byte was ``_discard``'ed and the 200 lied ok:false
  with the bomb's text as the run's own failure (the exact contract
  backups7 restored for the text half);
* the stack seam ``_run_argv`` handed the bomb through raw, and
  ``_backup_stack`` compares ``rc != 0`` bare — including in the
  finally-restart that is this module's one promise.

Fix, in hub/backups.py, the established convention one seam further:
``_exit_code`` coerces rc with the same unbound ``int.__index__`` base
read ``_jsonable`` already uses, so a bomb wrapping a genuine 0 keeps its
successful run and uncoercible junk fails every probe closed as None;
``_cli_vanished`` / the three jobs / ``_run_argv`` coerce at the seam and
``_exit_text`` catches broadly (and renders None as ``exit unknown``).
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import backups
from hub.app_factory import create_app
from hub.auth import require_auth

_app = None


def _client() -> TestClient:
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return TestClient(_app, raise_server_exceptions=False)


def _strict_utf8(resp) -> str:
    """The body must already be valid UTF-8 — decode strictly on purpose."""
    return resp.content.decode("utf-8")


class _IntEqBomb(int):
    """Passes ``isinstance(x, int)``; any equality probe raises."""

    def __eq__(self, other):
        raise RuntimeError("leftover eq bomb")

    def __ne__(self, other):
        raise RuntimeError("leftover ne bomb")

    __hash__ = int.__hash__


class _IntStrBomb(int):
    """Passes ``isinstance(x, int)``; rendering it raises.  The f-string's
    empty format spec dispatches to ``__str__``, so this is a RuntimeError
    out of ``f"exit {rc}"`` — not the digit-cap ValueError the old catch
    tuple knew about."""

    def __str__(self):
        raise RuntimeError("leftover __str__ bomb")

    __repr__ = __str__


_ENTRY = {"id": "t1", "db": "db1"}
_IMMICH_INFO = {"available": True, "via": "script", "last": None, "layers": None}


class ExitCodeSeamTests(unittest.TestCase):
    """The rc coercion reads the real exit status underneath any override."""

    def test_exact_ints_pass_through_unchanged(self):
        self.assertEqual(backups._exit_code(0), 0)
        self.assertEqual(backups._exit_code(-1), -1)
        self.assertIs(backups._exit_code(None), None)

    def test_subclass_bombs_unwrap_to_their_real_exit_status(self):
        for bomb, real in ((_IntEqBomb(0), 0), (_IntEqBomb(-1), -1),
                           (_IntStrBomb(3), 3)):
            out = backups._exit_code(bomb)
            self.assertEqual(out, real)
            self.assertIs(type(out), int)

    def test_uncoercible_junk_drops_to_none_never_raises(self):
        for junk in ("0", 2.0, object(), b"0"):
            self.assertIsNone(backups._exit_code(junk))

    def test_exit_text_survives_str_bomb_and_huge_digit_rc(self):
        # Pre-fix: the __str__ bomb raised RuntimeError out of the render.
        self.assertEqual(backups._exit_text(_IntStrBomb(3)), "exit unknown")
        self.assertEqual(backups._exit_text(None), "exit unknown")
        # >4300 digits: the digit-cap ValueError stays swallowed.
        self.assertEqual(backups._exit_text(10 ** 5000), "exit unknown")
        self.assertEqual(backups._exit_text(3), "exit 3")

    def test_cli_vanished_probe_survives_a_bombed_rc(self):
        # Pre-fix: ``rc != -1`` dispatched to the bomb's __ne__ and raised.
        self.assertFalse(backups._cli_vanished(_IntEqBomb(0), "ok", "tar"))
        with mock.patch.object(backups, "_tool_on_disk", lambda tool: False):
            self.assertTrue(
                backups._cli_vanished(_IntEqBomb(-1), "not found", "pg_dump")
            )
        # Junk rc is never the spawn sentinel: the raw result stays truth.
        with mock.patch.object(backups, "_tool_on_disk", lambda tool: False):
            self.assertFalse(backups._cli_vanished("−1", "not found", "pg_dump"))

    def test_run_argv_hands_back_an_exact_int_rc(self):
        # Pre-fix: the stack seam passed the bomb through raw, and
        # _backup_stack's bare ``rc != 0`` — including the finally-restart —
        # was the next dispatch.
        with mock.patch.object(backups, "run_capped",
                               lambda *a, **k: (_IntEqBomb(0), "ok")):
            rc, out, err = backups._run_argv(["docker", "ps"], timeout=5)
        self.assertIs(type(rc), int)
        self.assertEqual(rc, 0)
        with mock.patch.object(backups, "run_capped",
                               lambda *a, **k: (object(), "junk")):
            rc, out, err = backups._run_argv(["docker", "ps"], timeout=5)
        self.assertIs(type(rc), int)
        self.assertEqual(rc, -1)


class _BackupsSandbox(unittest.TestCase):
    """Private BACKUP_ROOT / DATA_DIR / CONFIG_FILE per test."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.backup_root = root / "backups"
        self.backup_root.mkdir()
        self.data_dir = root / "data"
        self.data_dir.mkdir()
        self.cfg_file = root / "services.yaml"
        self.cfg_file.write_text("settings: {}\n", encoding="utf-8")
        for name, value in (
            ("BACKUP_ROOT", self.backup_root),
            ("DATA_DIR", self.data_dir),
            ("BACKUP_SECRETS_FILE", self.data_dir / "backup-credentials.json"),
            ("CONFIG_FILE", self.cfg_file),
        ):
            patched = mock.patch.object(backups, name, value)
            patched.start()
            self.addCleanup(patched.stop)

    def _post(self, path: str, *, cfg_value=None, expect: int = 200):
        if cfg_value is None:
            resp = _client().post(path)
        else:
            with mock.patch.object(backups, "cfg", lambda: cfg_value):
                resp = _client().post(path)
        self.assertEqual(resp.status_code, expect, resp.text[:300])
        return json.loads(_strict_utf8(resp))


class ImmichScriptRcBombTests(_BackupsSandbox):
    """POST /api/backups/immich: a bombed rc costs nothing real.

    ``_cli_vanished`` / ``ok = rc == 0`` / ``_exit_text`` all run *outside*
    the spawn's try here, so on the pre-fix tree each bomb was a bare 500.
    """

    def _post_immich(self, fake_run, expect: int = 200):
        with mock.patch.object(backups, "immich_backup_info",
                               lambda: dict(_IMMICH_INFO)), \
             mock.patch.object(backups, "run_capped", fake_run):
            resp = _client().post("/api/backups/immich")
        self.assertEqual(resp.status_code, expect, resp.text[:300])
        return json.loads(_strict_utf8(resp))

    def test_eq_bomb_rc_keeps_the_successful_run(self):
        artefact = self.backup_root / "immich_20260101_000000.sql.gz"

        def fake(argv, timeout=None, **kwargs):
            artefact.write_bytes(b"fake dump\n")
            return _IntEqBomb(0), "immich dump ok"

        payload = self._post_immich(fake)
        # Pre-fix: RuntimeError out of ``rc != -1`` — a 500 after the
        # script had already produced this artefact.
        self.assertTrue(payload["ok"], payload)
        self.assertEqual(payload["message"], "immich dump ok")
        self.assertEqual(Path(payload["path"]), artefact)
        self.assertTrue(artefact.is_file())

    def test_str_bomb_rc_with_empty_output_reports_its_real_exit(self):
        payload = self._post_immich(
            lambda argv, timeout=None, **kwargs: (_IntStrBomb(3), "")
        )
        # Pre-fix: RuntimeError out of ``f"exit {rc}"`` — a 500 instead of
        # the honest failure row.  The base coercion reads the real 3.
        self.assertFalse(payload["ok"], payload)
        self.assertEqual(payload["message"], "exit 3")

    def test_bombed_sentinel_with_vanished_script_keeps_the_coded_refusal(self):
        with mock.patch.object(backups, "_tool_on_disk", lambda tool: False):
            payload = self._post_immich(
                lambda argv, timeout=None, **kwargs: (_IntEqBomb(-1), "not found")
            )
        # The bomb wraps the genuine spawn sentinel: the up-front gate's
        # coded answer, never the bare two-word sentinel (or a 500).
        self.assertFalse(payload["ok"], payload)
        self.assertEqual(payload["error"], "not_configured")


class PostgresRcBombTests(_BackupsSandbox):
    """POST /api/backups/postgres: a bombed rc no longer destroys the
    artefact it is reporting on (the backups7 contract, rc half)."""

    _CFG = {"backups": {"postgres": [dict(_ENTRY)]}}

    def test_eq_bomb_rc_keeps_the_successful_dump(self):
        def fake(argv, timeout=None, env=None, **kwargs):
            Path(argv[-1]).write_bytes(b"fake dump\n")
            return _IntEqBomb(0), "dump ok"

        with mock.patch.object(backups, "run_capped", fake):
            payload = self._post("/api/backups/postgres", cfg_value=self._CFG)
        # Pre-fix: the __eq__ bomb raised inside the broad catch, the
        # already-written dump was _discard'ed, and the 200 lied ok:false
        # with "leftover eq bomb" as the dump's failure.
        self.assertTrue(payload["ok"], payload)
        self.assertEqual(payload["message"], "dump ok")
        dest = Path(payload["path"])
        self.assertTrue(dest.is_file(), dest)
        self.assertEqual(dest.read_bytes(), b"fake dump\n")

    def test_bombed_sentinel_with_vanished_pg_dump_keeps_the_coded_503(self):
        with mock.patch.object(backups, "run_capped",
                               lambda *a, **k: (_IntEqBomb(-1), "not found")), \
             mock.patch.object(backups, "_tool_on_disk", lambda tool: False), \
             mock.patch.object(backups, "cfg", lambda: self._CFG):
            resp = _client().post("/api/backups/postgres")
        # Pre-fix: the bomb raised at ``rc != -1``, the broad catch
        # flattened the coded state into an uncoded ok:false lie.
        self.assertEqual(resp.status_code, 503, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["detail"]["code"], "backup.tool_missing")
        # The placeholder was discarded: no ghost artefact in the listing.
        self.assertEqual(list(self.backup_root.glob("t1_*")), [])


class ConfigArchiveRcBombTests(_BackupsSandbox):
    """POST /api/backups/configs: same rc-seam contract as the dumps."""

    def test_eq_bomb_rc_keeps_the_successful_archive(self):
        def fake(argv, timeout=None, env=None, **kwargs):
            # argv is ["/usr/bin/tar", "czf", dest, *members].
            Path(argv[2]).write_bytes(b"fake tar\n")
            return _IntEqBomb(0), "tar ok"

        with mock.patch.object(backups, "run_capped", fake):
            payload = self._post("/api/backups/configs")
        # Pre-fix: same as the postgres shape — the finished archive was
        # discarded and the 200 lied ok:false over the bomb's text.
        self.assertTrue(payload["ok"], payload)
        self.assertEqual(payload["message"], "tar ok")
        dest = Path(payload["path"])
        self.assertTrue(dest.is_file(), dest)
        self.assertEqual(dest.read_bytes(), b"fake tar\n")

    def test_bombed_sentinel_with_vanished_tar_keeps_the_coded_503(self):
        with mock.patch.object(backups, "run_capped",
                               lambda *a, **k: (_IntEqBomb(-1), "not found")), \
             mock.patch.object(backups, "_tool_on_disk", lambda tool: False):
            resp = _client().post("/api/backups/configs")
        self.assertEqual(resp.status_code, 503, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["detail"]["code"], "backup.tool_missing")
        self.assertEqual(list(self.backup_root.glob("configs_*")), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
