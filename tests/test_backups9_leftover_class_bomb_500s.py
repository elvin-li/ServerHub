"""Ninth leftover-500s sweep of the Backups listing surfaces, over the real app.

backups8 sealed the *rc half* of the ``run_capped`` seam.  What it never
touched: the raw ``isinstance`` type gates in the ``services.yaml``
config readers, every one of which sits *outside* a try.  CPython's
``isinstance`` consults ``value.__class__`` whenever the exact-type check
misses, so a poisoned ``backups`` / ``config_archive`` / ``postgres``
value (or one of its entries) whose ``__class__`` is a *raising property*
detonated the gate itself — a bare 500 out of

* GET /api/backups — ``_backups_cfg`` / ``pg_targets`` read
  ``backups`` and ``backups.postgres`` to render the ``postgres_targets``
  rows (and again from ``scan_backups`` → ``restore_hint`` → ``pg_targets``
  per listed artefact);
* POST /api/backups/postgres — the same ``pg_targets`` read;
* POST /api/backups/configs — ``agent_keywords`` /
  ``config_archive_extra_paths`` read ``config_archive`` and its
  ``agent_keywords`` / ``extra_paths`` lists.

This is the ``__class__``-property class the worker_health / wireguard /
usage sweeps already sealed elsewhere, reaching hub/backups.py one seam
further: a new ``_isa`` gate that answers False for a value that cannot
say what it is, so the poisoned entry is *dropped* (or the block treated
as unset) and every healthy sibling target/keyword/path is kept — the
one-bad-entry-costs-only-itself contract ``pg_targets`` already promises
for over-cap ints and lone surrogates.
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


class _ClassBomb:
    """Passes nothing: ``isinstance(x, anything)`` consults ``__class__``
    when the exact-type check misses, and this one raises."""

    @property
    def __class__(self):  # noqa: A003 — deliberately shadowing the dunder
        raise RuntimeError("leftover __class__ bomb")

    __hash__ = object.__hash__


class IsaGateTests(unittest.TestCase):
    """``_isa`` reads the real type underneath a raising ``__class__``."""

    def test_real_types_still_match(self):
        self.assertTrue(backups._isa({}, dict))
        self.assertTrue(backups._isa([], list))
        self.assertTrue(backups._isa("x", str))

        class DictSub(dict):
            pass

        self.assertTrue(backups._isa(DictSub(), dict))

    def test_class_bomb_answers_false_never_raises(self):
        # Pre-fix: the bare isinstance in the config readers raised here.
        self.assertFalse(backups._isa(_ClassBomb(), dict))
        self.assertFalse(backups._isa(_ClassBomb(), list))
        self.assertFalse(backups._isa(_ClassBomb(), str))


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

    def _get(self, *, cfg_value, expect: int = 200):
        with mock.patch.object(backups, "cfg", lambda: cfg_value):
            resp = _client().get("/api/backups")
        self.assertEqual(resp.status_code, expect, resp.text[:300])
        return json.loads(_strict_utf8(resp))


class GetBackupsClassBombTests(_BackupsSandbox):
    """GET /api/backups: a ``__class__``-property bomb in config is dropped."""

    def test_backups_value_is_a_class_bomb(self):
        # Pre-fix: ``_backups_cfg``'s ``isinstance(raw, dict)`` raised.
        payload = self._get(cfg_value={"backups": _ClassBomb()})
        self.assertEqual(payload["postgres_targets"], [])

    def test_postgres_value_is_a_class_bomb(self):
        # Pre-fix: ``pg_targets``'s ``isinstance(raw, list)`` raised.
        payload = self._get(cfg_value={"backups": {"postgres": _ClassBomb()}})
        self.assertEqual(payload["postgres_targets"], [])

    def test_config_archive_value_is_a_class_bomb(self):
        # Pre-fix: ``_config_archive_cfg``'s ``isinstance(raw, dict)`` raised.
        payload = self._get(
            cfg_value={"backups": {"config_archive": _ClassBomb()}}
        )
        self.assertEqual(payload["postgres_targets"], [])

    def test_poisoned_entry_costs_only_itself_and_keeps_siblings(self):
        # A bomb entry beside a healthy one drops only the bomb.
        cfg_value = {
            "backups": {
                "postgres": [
                    _ClassBomb(),
                    {"id": "good", "db": "d1"},
                    _ClassBomb(),
                    {"id": "also_good", "db": "d2"},
                ]
            }
        }
        payload = self._get(cfg_value=cfg_value)
        ids = [t["id"] for t in payload["postgres_targets"]]
        self.assertEqual(ids, ["good", "also_good"])

    def test_scan_backups_row_restore_hint_survives_the_bomb(self):
        # scan_backups calls restore_hint(name) -> pg_targets() per artefact,
        # so a listed row used to detonate the same gate on GET /api/backups.
        (self.backup_root / "teslamate_20260101_000000.sql.bak").write_bytes(
            b"x" * 16
        )
        payload = self._get(cfg_value={"backups": {"postgres": _ClassBomb()}})
        names = [r["name"] for r in payload["backups"]]
        self.assertIn("teslamate_20260101_000000.sql.bak", names)


class PgTargetsClassBombTests(unittest.TestCase):
    """The helper that renders the rows drops bombs one by one."""

    def test_list_bomb_drops_to_empty(self):
        with mock.patch.object(
            backups, "cfg", lambda: {"backups": {"postgres": _ClassBomb()}}
        ):
            self.assertEqual(backups.pg_targets(), [])

    def test_entry_bomb_keeps_healthy_targets(self):
        cfg_value = {
            "backups": {"postgres": [_ClassBomb(), {"id": "keep", "db": "d"}]}
        }
        with mock.patch.object(backups, "cfg", lambda: cfg_value):
            ids = [t["id"] for t in backups.pg_targets()]
        self.assertEqual(ids, ["keep"])


class ConfigArchiveClassBombTests(unittest.TestCase):
    """agent_keywords / config_archive_extra_paths drop bombs, keep siblings."""

    def test_agent_keywords_block_bomb_degrades_to_defaults(self):
        with mock.patch.object(
            backups, "cfg", lambda: {"backups": {"config_archive": _ClassBomb()}}
        ):
            kws = backups.agent_keywords()
        self.assertEqual(kws, backups.DEFAULT_AGENT_KEYWORDS)

    def test_agent_keywords_list_bomb_and_entry_bomb_keep_good_entries(self):
        cfg_value = {
            "backups": {"config_archive": {"agent_keywords": [_ClassBomb(), "myapp"]}}
        }
        with mock.patch.object(backups, "cfg", lambda: cfg_value):
            kws = backups.agent_keywords()
        self.assertIn("myapp", kws)
        self.assertEqual(kws[: len(backups.DEFAULT_AGENT_KEYWORDS)],
                         backups.DEFAULT_AGENT_KEYWORDS)

        with mock.patch.object(
            backups, "cfg",
            lambda: {"backups": {"config_archive": {"agent_keywords": _ClassBomb()}}},
        ):
            self.assertEqual(backups.agent_keywords(), backups.DEFAULT_AGENT_KEYWORDS)

    def test_extra_paths_list_bomb_and_entry_bomb_keep_good_entries(self):
        cfg_value = {
            "backups": {
                "config_archive": {"extra_paths": [_ClassBomb(), "/etc/hosts"]}
            }
        }
        with mock.patch.object(backups, "cfg", lambda: cfg_value):
            paths = backups.config_archive_extra_paths()
        self.assertEqual(paths, [Path("/etc/hosts")])

        with mock.patch.object(
            backups, "cfg",
            lambda: {"backups": {"config_archive": {"extra_paths": _ClassBomb()}}},
        ):
            self.assertEqual(backups.config_archive_extra_paths(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
