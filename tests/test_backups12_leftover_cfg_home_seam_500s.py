"""Twelfth leftover-500s sweep of the Backups JSON routes: the *provider
seams* — ``cfg`` and ``user_home`` — whose calls sat outside every guard.

backups11 sealed the torn-DB_URL coercion in ``_immich_conn``.  The fuzz that
led here confirms the four Backups JSON routes (GET /api/backups,
POST /api/backups/{postgres,immich,configs}) now answer every cfg-*value*
bomb, ``run_capped`` seam shape, and JSON-store leftover without a 500.  Two
provider seams survived, both the class ``hub.config.settings_section``
already guards ("a snapshot provider that raises used to escape this
helper") and this module never got:

* ``cfg()`` — every cfg *read* in hub/backups.py goes through
  ``_mapping_get``'s tries, but the ``cfg()`` call itself was bare.  A
  leftover provider that raises 500'd GET /api/backups out of the route's
  ``pg_targets()`` render (and once more per listed row via ``scan_backups``
  → ``restore_hint`` → ``pg_targets``, whose per-row catch only covers
  OSError), POST /api/backups/postgres out of ``_backup_postgres``'s bare
  ``pg_targets()``, and POST /api/backups/configs out of
  ``config_archive_extra_paths`` (outside the tar try) and
  ``agent_keywords`` (reached through ``_wanted_agent`` inside a catch that
  only covers OSError).  In ``_pg_env`` the same raise landed *inside* the
  dump's broad catch instead — the finished artefact was ``_discard``'ed and
  the provider's text reported as pg_dump's failure, the backups8/10 lie
  shape.  **Three live route 500s plus one lie.**

* ``user_home()`` — ``hub.paths.user_home`` guards ``Path.home()``
  internally, but the module seam was joined bare: ``home / "Services" /
  "teslamate" / "backups"`` in ``scan_backups`` and the LaunchAgents join in
  ``_backup_configs``.  A leftover provider that raises — or answers *text*
  / bytes / junk instead of a Path — detonated the join (TypeError on
  ``str.__truediv__``) and 500'd GET /api/backups and
  POST /api/backups/configs outside every catch.  **Four more live 500s
  across the raise/str/int/bytes/object shapes.**

The fix routes both seams through guarded readers: ``_cfg_map`` (raise /
non-dict → ``{}``, the same "nothing configured" an empty services.yaml
means) and ``_user_home`` (raise/junk → None; a textual answer still names
a real directory and is kept as a Path, surrogates included).  Conflict
policy: the stronger union guards backups6-11 pinned (``_isa``,
``type(x) is bool``, the guarded ``_decode_bytes``, the try around
``dict.get`` in ``_mapping_get``, ``_iter_list``, ``_exit_code``, the
guarded ``urlparse``/``.port`` in ``_immich_conn``) are re-pinned below and
must not be weakened.  Product version stays 3.9.3.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import __version__, backups
from hub.app_factory import create_app
from hub.auth import require_auth

_app = None


def _client() -> TestClient:
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    # raise_server_exceptions=False: a real 500 must arrive as HTTP 500, not
    # as a re-raised exception that would mask which route crashed.
    return TestClient(_app, raise_server_exceptions=False)


def _strict_utf8(resp) -> str:
    """The body must already be valid UTF-8 — decode strictly on purpose."""
    return resp.content.decode("utf-8")


def _raising_provider(*_a, **_k):
    raise RuntimeError("leftover snapshot provider bomb")


class _LyingPath:
    """Claims to be a Path; is not.  No ``__fspath__`` to answer with, so the
    guarded reader must drop it instead of letting ``/`` TypeError."""

    @property
    def __class__(self):
        return Path


class _FspathBombPath(Path):
    """A *real* Path subclass whose ``__fspath__`` raises — the round-trip
    must drop it rather than carry the bound bomb into a join."""

    def __fspath__(self):
        raise RuntimeError("leftover __fspath__ bomb")


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
        self.home = root / "home"
        for name, value in (
            ("BACKUP_ROOT", self.backup_root),
            ("DATA_DIR", self.data_dir),
            ("BACKUP_SECRETS_FILE", self.data_dir / "backup-credentials.json"),
            ("CONFIG_FILE", self.cfg_file),
            ("PHOTOSHUB_CFG", root / "no-photoshub.json"),
            ("PHOTOSHUB_STATE", root / "no-photoshub-state"),
            ("IMMICH_ROOT", root / "immich"),
            ("IMMICH_SCRIPT", root / "immich" / "backup-db.sh"),
            ("IMMICH_DB_ENV", root / "immich" / "db.env"),
        ):
            patched = mock.patch.object(backups, name, value)
            patched.start()
            self.addCleanup(patched.stop)


class GetBackupsRaisingCfgTests(_BackupsSandbox):
    """The ex-500s on GET /api/backups: the bare ``cfg()`` call in
    ``_backups_cfg`` sat outside every guard."""

    def _get(self, expect: int = 200):
        resp = _client().get("/api/backups")
        self.assertEqual(resp.status_code, expect, resp.text[:300])
        return json.loads(_strict_utf8(resp))

    def test_raising_cfg_answers_empty_targets(self):
        with mock.patch.object(backups, "cfg", _raising_provider):
            payload = self._get()
        self.assertEqual(payload["postgres_targets"], [])

    def test_raising_cfg_beside_a_listed_row_keeps_the_listing(self):
        # scan_backups calls restore_hint(name) -> pg_targets() per artefact
        # inside a catch that only covers OSError, so a listed row used to
        # re-detonate the provider once per row.
        (self.backup_root / "teslamate_20260101_000000.sql.bak").write_bytes(
            b"x" * 16
        )
        with mock.patch.object(backups, "cfg", _raising_provider):
            payload = self._get()
        names = [r["name"] for r in payload["backups"]]
        self.assertIn("teslamate_20260101_000000.sql.bak", names)
        self.assertEqual(payload["postgres_targets"], [])

    def test_raising_user_home_keeps_the_page(self):
        with mock.patch.object(backups, "user_home", _raising_provider):
            payload = self._get()
        self.assertEqual(payload["total"], 0)

    def test_junk_shaped_user_home_keeps_the_page(self):
        for junk in (42, b"\xff\xfe", object(), _LyingPath()):
            with self.subTest(junk=type(junk).__name__):
                with mock.patch.object(backups, "user_home", lambda j=junk: j):
                    payload = self._get()
                self.assertEqual(payload["postgres_targets"], [])

    def test_text_user_home_still_names_the_teslamate_root(self):
        # A textual answer names a real directory: the extra scan root must
        # keep working, not silently drop to "no home".
        tm = self.home / "Services" / "teslamate" / "backups"
        tm.mkdir(parents=True)
        (tm / "teslamate_20260102_000000.sql.bak").write_bytes(b"y" * 16)
        with mock.patch.object(backups, "user_home", lambda: str(self.home)):
            payload = self._get()
        names = [r["name"] for r in payload["backups"]]
        self.assertIn("teslamate_20260102_000000.sql.bak", names)


class PostPgBackupRaisingCfgTests(_BackupsSandbox):
    """The ex-500 on POST /api/backups/postgres: ``_backup_postgres``'s bare
    ``pg_targets()`` read ran before any broad catch."""

    def test_raising_cfg_answers_the_coded_not_configured(self):
        with mock.patch.object(backups, "cfg", _raising_provider):
            resp = _client().post("/api/backups/postgres")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"], "not_configured")
        self.assertNotIn("provider bomb", payload["message"])


class PostConfigsBackupSeamTests(_BackupsSandbox):
    """The ex-500s on POST /api/backups/configs: raising cfg detonated
    ``config_archive_extra_paths`` outside the tar try and
    ``agent_keywords`` past its OSError-only catch; a raising or
    wrong-shape ``user_home`` detonated the LaunchAgents join."""

    def _post_configs(self, **patches):
        ctx = [
            mock.patch.object(backups, name, value)
            for name, value in patches.items()
        ]
        ctx.append(
            mock.patch.object(backups, "run_capped", return_value=(1, "tar: fail"))
        )
        for p in ctx:
            p.start()
            self.addCleanup(p.stop)
        resp = _client().post("/api/backups/configs")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        return json.loads(_strict_utf8(resp))

    def _plant_agents(self) -> Path:
        agents = self.home / "Library" / "LaunchAgents"
        agents.mkdir(parents=True)
        (agents / "com.example.serverhub.plist").write_text("<plist/>")
        return self.home

    def test_raising_cfg_still_reaches_tar(self):
        home = self._plant_agents()
        payload = self._post_configs(
            cfg=_raising_provider, user_home=lambda: home,
        )
        # The request survived the provider and the honest tar failure is
        # the answer — not a 500 out of config_archive_extra_paths or
        # agent_keywords.
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "tar: fail")

    def test_raising_user_home_still_reaches_tar(self):
        payload = self._post_configs(
            cfg=lambda: {}, user_home=_raising_provider,
        )
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "tar: fail")

    def test_junk_shaped_user_home_still_reaches_tar(self):
        for junk in ("nul\x00", 42, b"\xff", object()):
            with self.subTest(junk=type(junk).__name__):
                with (
                    mock.patch.object(backups, "cfg", lambda: {}),
                    mock.patch.object(backups, "user_home", lambda j=junk: j),
                    mock.patch.object(
                        backups, "run_capped", return_value=(1, "tar: fail")
                    ),
                ):
                    resp = _client().post("/api/backups/configs")
                self.assertEqual(resp.status_code, 200, resp.text[:300])
                payload = json.loads(_strict_utf8(resp))
                self.assertFalse(payload["ok"])
                self.assertEqual(payload["message"], "tar: fail")

    def test_text_user_home_still_archives_the_wanted_agents(self):
        # Do-not-weaken the other way: a textual home must keep selecting
        # LaunchAgents, not degrade to "no home".
        home = self._plant_agents()
        captured: list[list[str]] = []

        def fake_run(cmd, **_k):
            captured.append(list(cmd))
            return 0, ""

        with (
            mock.patch.object(backups, "cfg", lambda: {}),
            mock.patch.object(backups, "user_home", lambda: str(home)),
            mock.patch.object(backups, "run_capped", fake_run),
        ):
            resp = _client().post("/api/backups/configs")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        plists = [a for a in captured[0] if a.endswith(".plist")]
        self.assertEqual(
            plists,
            [str(home / "Library" / "LaunchAgents" / "com.example.serverhub.plist")],
        )


class PostImmichImmunityPin(_BackupsSandbox):
    """POST /api/backups/immich reads neither seam on its refusal path —
    pinned so a later edit cannot quietly add a bare read."""

    def test_raising_providers_keep_the_coded_refusal(self):
        with (
            mock.patch.object(backups, "cfg", _raising_provider),
            mock.patch.object(backups, "user_home", _raising_provider),
        ):
            resp = _client().post("/api/backups/immich")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"], "not_configured")


class CfgMapUnitTests(unittest.TestCase):
    """The guarded snapshot reader itself."""

    def test_raising_provider_reads_as_nothing_configured(self):
        with mock.patch.object(backups, "cfg", _raising_provider):
            self.assertEqual(backups._cfg_map(), {})

    def test_non_dict_snapshots_read_as_nothing_configured(self):
        for junk in (None, 42, "text", [1], object()):
            with self.subTest(junk=type(junk).__name__):
                with mock.patch.object(backups, "cfg", lambda j=junk: j):
                    self.assertEqual(backups._cfg_map(), {})

    def test_real_snapshot_passes_through(self):
        snap = {"backups": {"postgres": [{"id": "t", "db": "d"}]}}
        with mock.patch.object(backups, "cfg", lambda: snap):
            self.assertIs(backups._cfg_map(), snap)
            self.assertEqual(
                [t["id"] for t in backups.pg_targets()], ["t"]
            )


class UserHomeUnitTests(unittest.TestCase):
    """The guarded home reader itself."""

    def test_raising_provider_reads_as_no_home(self):
        with mock.patch.object(backups, "user_home", _raising_provider):
            self.assertIsNone(backups._user_home())

    def test_none_and_junk_read_as_no_home(self):
        for junk in (None, 42, object(), _LyingPath(), ""):
            with self.subTest(junk=repr(junk)[:24]):
                with mock.patch.object(backups, "user_home", lambda j=junk: j):
                    self.assertIsNone(backups._user_home())

    def test_path_and_text_answers_are_kept(self):
        with mock.patch.object(backups, "user_home", lambda: Path("/tmp/h")):
            self.assertEqual(backups._user_home(), Path("/tmp/h"))
        with mock.patch.object(backups, "user_home", lambda: "/tmp/h"):
            self.assertEqual(backups._user_home(), Path("/tmp/h"))
        with mock.patch.object(backups, "user_home", lambda: b"/tmp/h"):
            self.assertEqual(backups._user_home(), Path("/tmp/h"))

    def test_surrogate_home_is_kept_not_dropped(self):
        # An undecodable HOME legitimately carries lone surrogates
        # (os surrogateescape); the reader must keep naming it.
        with mock.patch.object(backups, "user_home", lambda: "/tmp/h\udcff"):
            self.assertEqual(backups._user_home(), Path("/tmp/h\udcff"))

    def test_fspath_bomb_subclass_reads_as_no_home(self):
        with mock.patch.object(
            backups, "user_home", lambda: _FspathBombPath("/tmp/h")
        ):
            self.assertIsNone(backups._user_home())


class PgEnvRaisingCfgLieTests(unittest.TestCase):
    """The lie half: a raising provider inside the dump's broad catch used to
    discard the finished artefact and blame pg_dump."""

    def test_raising_cfg_skips_the_overlay_and_keeps_the_env(self):
        with (
            mock.patch.object(backups, "cfg", _raising_provider),
            mock.patch.object(
                backups, "BACKUP_SECRETS_FILE",
                Path("/nonexistent/backup-credentials.json"),
            ),
        ):
            env = backups._pg_env({"id": "t", "password_env": ""})
        self.assertIsInstance(env, dict)
        self.assertNotIn("PGPASSWORD", env)

    def test_real_overlay_still_applies(self):
        # Do-not-weaken: the healthy maintenance_env read keeps working.
        with (
            mock.patch.object(
                backups, "cfg",
                lambda: {"settings": {"maintenance_env": {"PATH_EXTRA": "/x"}}},
            ),
            mock.patch.object(
                backups, "BACKUP_SECRETS_FILE",
                Path("/nonexistent/backup-credentials.json"),
            ),
        ):
            env = backups._pg_env({"id": "t", "password_env": ""})
        self.assertEqual(env["PATH_EXTRA"], "/x")


class ConflictPolicyPinTests(unittest.TestCase):
    """Re-pin the union guards this sweep must keep (do not weaken)."""

    def test_isa_class_bomb_is_false_never_raises(self):
        class ClassBomb:
            @property
            def __class__(self):
                raise RuntimeError("class bomb")
            __hash__ = object.__hash__

        self.assertFalse(backups._isa(ClassBomb(), dict))
        self.assertTrue(backups._isa({}, dict))

    def test_mapping_get_survives_get_bombs(self):
        class GetBomb(dict):
            def get(self, *a, **k):
                raise RuntimeError("get bomb")

        d = GetBomb()
        dict.__setitem__(d, "id", "real")
        self.assertEqual(backups._mapping_get(d, "id"), "real")
        self.assertIsNone(backups._mapping_get(object(), "id"))

    def test_jsonable_bool_gate_uses_type_is_bool(self):
        class LyingBool:
            @property
            def __class__(self):
                return bool

        self.assertIsNone(backups._jsonable(LyingBool()))
        self.assertIs(backups._jsonable(True), True)

    def test_as_text_guarded_decode_keeps_real_bytes(self):
        class DecodeBomb(bytes):
            def decode(self, *a, **k):
                raise RuntimeError("decode bomb")

        self.assertEqual(backups._as_text(DecodeBomb(b"ok\xff")), "ok\ufffd")
        self.assertEqual(backups._as_text(b"tar ok"), "tar ok")

    def test_iter_list_keeps_real_elements_and_drops_liars(self):
        class IterBomb(list):
            def __iter__(self):
                raise RuntimeError("iter bomb")

        class LyingList:
            @property
            def __class__(self):
                return list

        self.assertEqual(backups._iter_list(IterBomb([1, 2])), [1, 2])
        self.assertEqual(backups._iter_list(LyingList()), [])

    def test_exit_code_keeps_a_wrapped_genuine_status(self):
        class EqBomb(int):
            def __eq__(self, other):
                raise RuntimeError("eq bomb")
            __ne__ = __eq__
            __hash__ = int.__hash__

        self.assertEqual(backups._exit_code(EqBomb(0)), 0)
        self.assertIsNone(backups._exit_code(object()))

    def test_immich_conn_guarded_urlparse_and_port_stay(self):
        # backups11's pins: a torn DB_URL raises the coded RuntimeError, a
        # healthy IPv6 URL still parses.
        import shutil as _shutil

        root = Path(tempfile.mkdtemp(prefix="serverhub-backups12-"))
        self.addCleanup(_shutil.rmtree, root, ignore_errors=True)
        env = root / "db.env"

        def conn(url):
            env.write_text(f"DB_URL={url}\n", encoding="utf-8")
            with mock.patch.object(backups, "IMMICH_DB_ENV", env):
                return backups._immich_conn()

        with self.assertRaises(RuntimeError):
            conn("postgres://u:p@[::1:5433/immich")
        with self.assertRaises(RuntimeError):
            conn("postgres://u:p@127.0.0.1:notaport/immich")
        good = conn("postgresql://immich:s3cret@[::1]:5433/immich")
        self.assertEqual(good["host"], "::1")
        self.assertEqual(good["port"], 5433)

    def test_product_version_stays(self):
        self.assertEqual(__version__, "3.9.4")


if __name__ == "__main__":
    unittest.main(verbosity=2)
