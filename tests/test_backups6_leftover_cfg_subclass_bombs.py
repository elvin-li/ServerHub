"""Sixth leftover-500s sweep of the Backups surfaces, over the real app.

The find: the ``backups:`` cfg-readers in hub/backups.py never got the
subclass-bomb hardening the rest of the tree standardized on (the modules5
unbound convention: ``hub.ups_svc._mapping_get``, ``hub.jobs._truthy``,
``hub.modules._jsonable``'s unbound ``dict.items`` / ``base.__iter__``).
Driven through ``create_app()`` + ``TestClient(raise_server_exceptions=False)``,
thirteen junk shapes were live raw HTTP 500s on the pre-fix tree:

* GET /api/backups — a dict-subclass ``.get`` bomb as the whole config, as
  the ``backups:`` block, or as one ``backups.postgres`` entry; a
  list-subclass ``__iter__`` bomb as ``backups.postgres``; a ``__bool__``
  bomb detonated by the truth test hidden in ``entry.get(key) or ""`` on
  ``id`` / ``db``; and a comparison bomb whose ``__eq__`` fired inside
  ``port_raw in (None, "")`` — every one raised out of ``pg_targets()``
  (also reached per-row via ``restore_hint``) and 500'd the whole page;
* POST /api/backups/postgres — the same ``pg_targets()`` shapes 500'd the
  dump route before any dump ran;
* POST /api/backups/configs — the same ``.get`` bombs raised out of
  ``config_archive_extra_paths()``, a list-subclass ``__iter__`` bomb as
  ``extra_paths`` raised out of its loop, and the same bomb as
  ``agent_keywords`` raised out of ``agent_keywords()`` as soon as one
  LaunchAgents plist was up for the ``_wanted_agent`` test.

Two adjacent lies (200s, but wrong) fixed by the same conventions: a
dict-subclass ``.get`` / ``items()`` bomb in ``settings`` /
``settings.maintenance_env`` was swallowed by the broad catch around the
postgres dump and reported as the *dump's* failure ("leftover .get bomb")
while pg_dump never even spawned — the dump now runs, and ``dict.items``
reads the real environment overlay underneath a poisoned ``items()``.

Fixes, all in hub/backups.py, all the established conventions:
``_mapping_get`` (ups_svc) for every ``backups:`` / ``config_archive`` /
entry / settings read, ``_truthy`` (jobs) for the ``or ""`` truth tests,
unbound ``list.__iter__`` (modules) for the three config list walks, and a
broad drop-this-entry catch around the port parse.

Stays-immune pins: a ``__bool__`` bomb as the whole ``backups:`` block, an
int-subclass ``__str__`` bomb as a target id (the ``_cfg_text`` broad
catch), and the ``.get``-bomb entry keeping its *real* data (``dict.get``
reads the storage underneath the override, so a subclass that only
poisoned its method keeps its sane target).
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


class _BoolBomb:
    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")


class _DictGetBomb(dict):
    def get(self, *a, **k):
        raise RuntimeError("leftover .get bomb")


class _DictItemsBomb(dict):
    def items(self):
        raise RuntimeError("leftover .items bomb")


class _ListIterBomb(list):
    def __iter__(self):
        raise RuntimeError("leftover __iter__ bomb")


class _FloatEqBomb(float):
    def __eq__(self, other):
        raise RuntimeError("leftover __eq__ bomb")

    __ne__ = __eq__
    __hash__ = float.__hash__


class _IntStrBomb(int):
    def __str__(self):
        raise RuntimeError("leftover __str__ bomb")


_ENTRY = {"id": "t1", "db": "db1"}


class _CfgZoo(unittest.TestCase):
    """Drive one route with one hostile cfg overlay planted via backups.cfg."""

    def _get_backups(self, cfg_value):
        with mock.patch.object(backups, "cfg", lambda: cfg_value):
            resp = _client().get("/api/backups")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        return json.loads(_strict_utf8(resp))


class BackupsPageCfgBombTests(_CfgZoo):
    """GET /api/backups: every pg_targets shape costs its entry, not the page."""

    def test_get_bomb_as_the_whole_config_keeps_the_page(self):
        payload = self._get_backups(_DictGetBomb())
        self.assertEqual(payload["postgres_targets"], [])

    def test_get_bomb_as_the_backups_block_keeps_the_page(self):
        payload = self._get_backups({"backups": _DictGetBomb()})
        self.assertEqual(payload["postgres_targets"], [])

    def test_iter_bomb_postgres_list_keeps_its_real_entries(self):
        payload = self._get_backups(
            {"backups": {"postgres": _ListIterBomb([dict(_ENTRY)])}})
        # Unbound list.__iter__ reads past the poisoned override: the real
        # target survives its hostile container.
        self.assertEqual([t["id"] for t in payload["postgres_targets"]], ["t1"])

    def test_get_bomb_entry_keeps_its_real_data(self):
        payload = self._get_backups(
            {"backups": {"postgres": [_DictGetBomb(_ENTRY)]}})
        # dict.get reads the storage underneath the override: a subclass
        # that only poisoned its method keeps its sane target.
        self.assertEqual([t["id"] for t in payload["postgres_targets"]], ["t1"])

    def test_eq_bomb_port_costs_the_entry_not_the_page(self):
        payload = self._get_backups(
            {"backups": {"postgres": [dict(_ENTRY, port=_FloatEqBomb(1.0))]}})
        self.assertEqual(payload["postgres_targets"], [])

    def test_bool_bomb_id_and_db_cost_the_entry_not_the_page(self):
        payload = self._get_backups({"backups": {"postgres": [
            {"id": _BoolBomb(), "db": "d"},
            {"id": "t", "db": _BoolBomb()},
            dict(_ENTRY),
        ]}})
        self.assertEqual([t["id"] for t in payload["postgres_targets"]], ["t1"])

    def test_bool_bomb_as_the_backups_block_stays_immune(self):
        payload = self._get_backups({"backups": _BoolBomb()})
        self.assertEqual(payload["postgres_targets"], [])

    def test_int_str_bomb_id_stays_immune(self):
        payload = self._get_backups(
            {"backups": {"postgres": [dict(_ENTRY, id=_IntStrBomb(5))]}})
        self.assertEqual(payload["postgres_targets"], [])


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

    def _post(self, path: str, cfg_value):
        with mock.patch.object(backups, "cfg", lambda: cfg_value):
            resp = _client().post(path)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        return json.loads(_strict_utf8(resp))


class PostgresDumpCfgBombTests(_BackupsSandbox):
    """POST /api/backups/postgres: bombed config still answers, dumps still run."""

    def _fake_run_capped(self, seen_envs: list):
        def fake(argv, timeout=None, env=None, **kwargs):
            seen_envs.append(env or {})
            # argv ends with ``-f <dest>``: produce the artefact the size
            # check judges success by.
            Path(argv[-1]).write_bytes(b"fake dump\n")
            return 0, "dump ok"
        return fake

    def test_get_bomb_config_is_the_coded_not_configured(self):
        payload = self._post("/api/backups/postgres", _DictGetBomb())
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"], "not_configured")

    def test_iter_bomb_list_and_get_bomb_entry_still_dump(self):
        envs: list = []
        with mock.patch.object(backups, "run_capped", self._fake_run_capped(envs)):
            payload = self._post("/api/backups/postgres", {
                "backups": {"postgres": _ListIterBomb([_DictGetBomb(_ENTRY)])},
            })
        self.assertTrue(payload["ok"], payload)
        self.assertIn("t1_", payload["path"])

    def test_settings_get_bomb_no_longer_blames_the_dump(self):
        # Pre-fix this was ok:false "leftover .get bomb" — pg_dump never ran.
        envs: list = []
        with mock.patch.object(backups, "run_capped", self._fake_run_capped(envs)):
            payload = self._post("/api/backups/postgres", {
                "settings": _DictGetBomb(),
                "backups": {"postgres": [dict(_ENTRY)]},
            })
        self.assertTrue(payload["ok"], payload)

    def test_maintenance_env_items_bomb_keeps_its_real_overlay(self):
        envs: list = []
        with mock.patch.object(backups, "run_capped", self._fake_run_capped(envs)):
            payload = self._post("/api/backups/postgres", {
                "settings": {"maintenance_env": _DictItemsBomb(
                    {"MAINT_KEY": "maint-value"})},
                "backups": {"postgres": [dict(_ENTRY)]},
            })
        self.assertTrue(payload["ok"], payload)
        # dict.items read the real storage underneath the poisoned items().
        self.assertEqual(envs[0].get("MAINT_KEY"), "maint-value")


class ConfigArchiveCfgBombTests(_BackupsSandbox):
    """POST /api/backups/configs: bombed archive config still archives."""

    def test_get_bomb_config_still_archives(self):
        payload = self._post("/api/backups/configs", _DictGetBomb())
        self.assertTrue(payload["ok"], payload)
        self.assertTrue(payload["path"].endswith(".tgz"))

    def test_get_bomb_config_archive_block_still_archives(self):
        payload = self._post("/api/backups/configs",
                             {"backups": {"config_archive": _DictGetBomb()}})
        self.assertTrue(payload["ok"], payload)

    def test_iter_bomb_extra_paths_still_archives(self):
        payload = self._post("/api/backups/configs", {
            "backups": {"config_archive": {
                "extra_paths": _ListIterBomb([str(self.cfg_file)])}},
        })
        self.assertTrue(payload["ok"], payload)

    def test_iter_bomb_agent_keywords_with_a_live_plist_still_archives(self):
        # Pre-fix the bomb only detonated once a LaunchAgents plist reached
        # the _wanted_agent test — exactly the install that has agents worth
        # archiving.
        home = Path(self._tmp.name) / "home"
        agents = home / "Library" / "LaunchAgents"
        agents.mkdir(parents=True)
        (agents / "local.serverhub.plist").write_text(
            "<plist/>", encoding="utf-8")
        hostile_cfg = {
            "backups": {"config_archive": {
                "agent_keywords": _ListIterBomb(["extra-kw"])}},
        }
        with mock.patch.object(backups, "user_home", lambda: home):
            payload = self._post("/api/backups/configs", hostile_cfg)
        self.assertTrue(payload["ok"], payload)
        with mock.patch.object(backups, "cfg", lambda: hostile_cfg):
            # Unbound iteration kept the real extras too.
            self.assertIn("extra-kw", backups.agent_keywords())


if __name__ == "__main__":
    unittest.main(verbosity=2)
