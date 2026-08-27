"""Tenth leftover-500s sweep of the Backups listing and ``run_capped``
surfaces: *lying* ``__class__`` impostors past the backups9 gates, over the
real mounted app.

backups9 sealed the ``__class__``-property *raising* bombs with ``_isa`` —
but ``_isa`` answers what ``isinstance`` answers, and ``isinstance``
consults ``value.__class__`` when the exact-type check misses.  A *lying*
impostor (the ollama10/dash10/json9 shape: a plain object whose
``__class__`` property *returns* the claimed type) therefore passes every
``_isa`` gate, and the unbound base call that follows had nothing to
refuse it.  Confirmed live at HEAD:

* GET /api/backups — a liar-list ``backups.postgres`` passed
  ``pg_targets``' ``_isa(raw, list)`` gate and ``_iter_list``'s unbound
  ``list.__iter__`` TypeError'd the descriptor itself, a bare 500 — both
  from the route's ``postgres_targets`` render and again per listed row
  via ``scan_backups`` → ``restore_hint`` → ``pg_targets``.
* POST /api/backups/postgres — the same ``pg_targets`` read, before the
  job's broad catches even start.
* POST /api/backups/configs — a liar-list ``extra_paths`` detonated
  ``config_archive_extra_paths``' ``_iter_list``, and a liar-list
  ``agent_keywords`` detonated ``agent_keywords``' — both raise out of
  ``_backup_configs`` *outside* its tar try.  **Five live 500s.**

Also sealed, at the seams where the broad catches turned the impostor into
a lie instead of a 500 (the backups8 rc-``__eq__`` class, text half):

* ``_as_text`` — a liar-bytes ``run_capped`` text passed the bare bytes
  isinstance and the unbound ``bytes.decode`` TypeError'd inside the
  immich/postgres/configs broad catches: the successful artefact was
  ``_discard``'ed and the 200 lied ok:false with descriptor gibberish as
  the run's failure.  The impostor now drops to "" and the message falls
  back to the honest ``_exit_text(rc)`` / "fail".
* ``_pg_env`` — a liar-dict ``settings.maintenance_env`` passed the bare
  isinstance and TypeError'd ``dict.items`` inside the dump's broad catch:
  same discarded-artefact lie, blaming pg_dump for a config leftover the
  dump never read.  A junk overlay is skipped; the dump keeps its env.
* ``_jsonable`` — the bool gate returned anything answering
  ``isinstance(value, bool)`` verbatim (``bool`` cannot be subclassed, so
  there was no unbound call to refuse a liar) and the C-level encoder then
  refused it; liar bytes/dict/list TypeError'd their unbound base calls
  uncaught.  All gates now run ``_isa`` and every unbound call sits in a
  try, matching ``hub.ollama_svc._jsonable``.

Every case must answer without an HTTP 500, with a strictly
UTF-8-encodable body, and one bad value must cost only itself: healthy
sibling targets/keywords/paths are kept.  Do-not-weaken pins ride along:
the real-subclass bombs backups7/8/9 sealed (list ``__iter__``, bytes
``.decode``, int ``__eq__`` wrapping a genuine exit status, the raising
``__class__`` property) must keep their existing answers.  No product
version bump: 3.9.3 stays.
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
    # raise_server_exceptions=False: a real 500 must arrive as HTTP 500, not
    # as a re-raised exception that would mask which route crashed.
    return TestClient(_app, raise_server_exceptions=False)


def _strict_utf8(resp) -> str:
    """The body must already be valid UTF-8 — decode strictly on purpose."""
    return resp.content.decode("utf-8")


# ── the impostor menagerie (the shapes backups9 never planted) ────────────────

class _LyingList:
    """Claims to be a list; is not.  Passes ``_isa(x, list)`` because
    ``isinstance`` consults the lying ``__class__``; the unbound
    ``list.__iter__`` then TypeErrors — the descriptor has no real list
    storage to read."""

    @property
    def __class__(self):
        return list


class _LyingDict:
    @property
    def __class__(self):
        return dict


class _LyingStr:
    @property
    def __class__(self):
        return str


class _LyingBytes:
    @property
    def __class__(self):
        return bytes


class _LyingInt:
    @property
    def __class__(self):
        return int


class _LyingFloat:
    @property
    def __class__(self):
        return float


class _LyingBool:
    """Claims to be a bool; is not — and bool has no unbound call to refuse it."""

    @property
    def __class__(self):
        return bool


# ── the real-subclass survivors the impostor guards must not cost ────────────

class _IterBombList(list):
    """A *real* list subclass whose bound ``__iter__`` raises — the unbound
    ``list.__iter__`` reads the real storage and must keep the elements."""

    def __iter__(self):
        raise RuntimeError("leftover __iter__ bomb")


class _DecodeBombBytes(bytes):
    """A *real* bytes subclass whose bound ``.decode`` raises — the unbound
    ``bytes.decode`` must still decode the real storage."""

    def decode(self, *a, **k):
        raise RuntimeError("leftover decode bomb")


class _IntEqBomb(int):
    """A *real* int subclass wrapping a genuine exit status whose comparisons
    raise — ``int.__index__`` must keep reading the value underneath."""

    def __eq__(self, other):
        raise RuntimeError("leftover __eq__ bomb")

    def __ne__(self, other):
        raise RuntimeError("leftover __ne__ bomb")

    __hash__ = int.__hash__


class _ClassBomb:
    """The backups9 shape: ``__class__`` is a *raising* property.  Pinned so
    the liar fixes cannot reopen it."""

    @property
    def __class__(self):  # noqa: A003 — deliberately shadowing the dunder
        raise RuntimeError("leftover __class__ bomb")

    __hash__ = object.__hash__


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
        ):
            patched = mock.patch.object(backups, name, value)
            patched.start()
            self.addCleanup(patched.stop)

    def _get(self, *, cfg_value, expect: int = 200):
        with mock.patch.object(backups, "cfg", lambda: cfg_value):
            resp = _client().get("/api/backups")
        self.assertEqual(resp.status_code, expect, resp.text[:300])
        return json.loads(_strict_utf8(resp))


class GetBackupsLiarListTests(_BackupsSandbox):
    """The ex-500s on GET /api/backups: the liar rode ``_isa`` into the
    unbound ``list.__iter__``."""

    def test_liar_list_postgres_answers_empty_targets(self):
        # Pre-fix: ``_iter_list``'s ``list.__iter__`` TypeError'd raw.
        payload = self._get(cfg_value={"backups": {"postgres": _LyingList()}})
        self.assertEqual(payload["postgres_targets"], [])

    def test_liar_list_beside_a_listed_row_keeps_the_listing(self):
        # scan_backups calls restore_hint(name) -> pg_targets() per artefact,
        # so a listed row used to detonate the same descriptor per row.
        (self.backup_root / "teslamate_20260101_000000.sql.bak").write_bytes(
            b"x" * 16
        )
        payload = self._get(cfg_value={"backups": {"postgres": _LyingList()}})
        names = [r["name"] for r in payload["backups"]]
        self.assertIn("teslamate_20260101_000000.sql.bak", names)
        self.assertEqual(payload["postgres_targets"], [])

    def test_liar_entries_cost_only_themselves(self):
        # Entry-rank liars beside healthy targets: dict/str/list impostors
        # drop one by one, the healthy siblings render.
        cfg_value = {
            "backups": {
                "postgres": [
                    _LyingDict(),
                    {"id": "good", "db": "d1"},
                    _LyingList(),
                    _LyingStr(),
                    {"id": "also_good", "db": "d2"},
                ]
            }
        }
        payload = self._get(cfg_value=cfg_value)
        ids = [t["id"] for t in payload["postgres_targets"]]
        self.assertEqual(ids, ["good", "also_good"])

    def test_liar_scalar_fields_drop_their_entry_alone(self):
        # A liar str/int in one entry's fields is junk, not a name: that
        # entry drops, the healthy sibling stays.
        cfg_value = {
            "backups": {
                "postgres": [
                    {"id": _LyingStr(), "db": "d1"},
                    {"id": "portliar", "db": "d2", "port": _LyingInt()},
                    {"id": "keep", "db": "d3"},
                ]
            }
        }
        payload = self._get(cfg_value=cfg_value)
        ids = [t["id"] for t in payload["postgres_targets"]]
        self.assertEqual(ids, ["keep"])

    def test_liar_dict_backups_block_reads_as_unset(self):
        payload = self._get(cfg_value={"backups": _LyingDict()})
        self.assertEqual(payload["postgres_targets"], [])


class PostPgBackupLiarListTests(_BackupsSandbox):
    """The ex-500 on POST /api/backups/postgres."""

    def test_liar_list_postgres_answers_the_coded_not_configured(self):
        with mock.patch.object(
            backups, "cfg", lambda: {"backups": {"postgres": _LyingList()}}
        ):
            resp = _client().post("/api/backups/postgres")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        payload = json.loads(_strict_utf8(resp))
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"], "not_configured")


class PostConfigsBackupLiarListTests(_BackupsSandbox):
    """The ex-500s on POST /api/backups/configs: liar ``extra_paths`` /
    ``agent_keywords`` lists detonated before the tar try."""

    def _post_configs(self, cfg_value):
        with (
            mock.patch.object(backups, "cfg", lambda: cfg_value),
            mock.patch.object(
                backups, "run_capped", return_value=(1, "tar: fail")
            ),
        ):
            resp = _client().post("/api/backups/configs")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        return json.loads(_strict_utf8(resp))

    def test_liar_list_extra_paths_still_reaches_tar(self):
        payload = self._post_configs(
            {"backups": {"config_archive": {"extra_paths": _LyingList()}}}
        )
        # The request survived the liar and the honest tar failure is the
        # answer — not a 500 out of config_archive_extra_paths.
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "tar: fail")

    def test_liar_entries_in_extra_paths_keep_good_siblings(self):
        cfg_value = {
            "backups": {
                "config_archive": {
                    "extra_paths": [_LyingStr(), "/etc/hosts", _LyingList()]
                }
            }
        }
        with mock.patch.object(backups, "cfg", lambda: cfg_value):
            self.assertEqual(
                backups.config_archive_extra_paths(), [Path("/etc/hosts")]
            )

    def test_liar_list_agent_keywords_still_reaches_tar(self):
        # agent_keywords only runs when a LaunchAgents plist is up for the
        # _wanted_agent test, so plant one under a sandbox home.
        agents = self.home / "Library" / "LaunchAgents"
        agents.mkdir(parents=True)
        (agents / "com.example.serverhub.plist").write_text("<plist/>")
        with mock.patch.object(backups, "user_home", lambda: self.home):
            payload = self._post_configs(
                {"backups": {"config_archive": {"agent_keywords": _LyingList()}}}
            )
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "tar: fail")

    def test_liar_agent_keywords_degrade_to_defaults(self):
        with mock.patch.object(
            backups, "cfg",
            lambda: {"backups": {"config_archive": {"agent_keywords": _LyingList()}}},
        ):
            self.assertEqual(
                backups.agent_keywords(), backups.DEFAULT_AGENT_KEYWORDS
            )

    def test_liar_keyword_entries_keep_good_extras(self):
        cfg_value = {
            "backups": {
                "config_archive": {
                    "agent_keywords": [_LyingStr(), "myapp", _LyingDict()]
                }
            }
        }
        with mock.patch.object(backups, "cfg", lambda: cfg_value):
            kws = backups.agent_keywords()
        self.assertIn("myapp", kws)
        self.assertEqual(kws[: len(backups.DEFAULT_AGENT_KEYWORDS)],
                         backups.DEFAULT_AGENT_KEYWORDS)


class RunCappedSeamLiarTests(_BackupsSandbox):
    """The rc/text halves of the ``run_capped`` seam at the liar shapes:
    never a 500, and never descriptor gibberish blaming the tool."""

    def _post_configs_with(self, seam):
        with (
            mock.patch.object(backups, "cfg", lambda: {"settings": {}}),
            mock.patch.object(backups, "run_capped", return_value=seam),
        ):
            resp = _client().post("/api/backups/configs")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        return json.loads(_strict_utf8(resp))

    def test_liar_int_rc_answers_exit_unknown_not_a_500(self):
        payload = self._post_configs_with((_LyingInt(), "tar said things"))
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["message"], "tar said things")

    def test_liar_bytes_text_answers_the_honest_fail_not_gibberish(self):
        # Pre-fix: _as_text's unbound decode TypeError'd inside the broad
        # catch and the message carried CPython descriptor internals.
        payload = self._post_configs_with((1, _LyingBytes()))
        self.assertFalse(payload["ok"])
        self.assertNotIn("descriptor", payload["message"])
        self.assertEqual(payload["message"], "fail")

    def test_liar_bool_rc_and_liar_bytes_text_together(self):
        payload = self._post_configs_with((_LyingBool(), _LyingBytes()))
        self.assertFalse(payload["ok"])
        self.assertNotIn("descriptor", payload["message"])


class SanitizerUnitPins(unittest.TestCase):
    """The helpers themselves at the backups10 shapes."""

    def test_iter_list_liar_degrades_to_no_entries(self):
        self.assertEqual(backups._iter_list(_LyingList()), [])
        self.assertEqual(backups._iter_list(_LyingDict()), [])
        self.assertEqual(backups._iter_list(_ClassBomb()), [])

    def test_iter_list_keeps_a_real_subclass_bomb_and_plain_lists(self):
        # Do-not-weaken: the backups7 contract — the unbound base read
        # yields the real elements underneath a bound ``__iter__`` bomb.
        self.assertEqual(list(backups._iter_list(_IterBombList([1, 2]))), [1, 2])
        self.assertEqual(list(backups._iter_list(["a"])), ["a"])

    def test_jsonable_drops_the_bool_liar_and_keeps_real_bools(self):
        self.assertIsNone(backups._jsonable(_LyingBool()))
        self.assertIs(backups._jsonable(True), True)
        self.assertIs(backups._jsonable(False), False)
        self.assertIsNone(backups._jsonable(None))

    def test_jsonable_drops_the_container_and_scalar_liars(self):
        for liar in (_LyingBytes(), _LyingDict(), _LyingList(),
                     _LyingInt(), _LyingFloat()):
            with self.subTest(liar=type(liar).__name__):
                self.assertIsNone(backups._jsonable(liar))

    def test_jsonable_nested_liar_drops_alone(self):
        out = backups._jsonable({"k": _LyingBool(), "b": _LyingBytes(), "keep": 2})
        self.assertIsNone(out["k"])
        self.assertIsNone(out["b"])
        self.assertEqual(out["keep"], 2)
        json.dumps(out, allow_nan=False)

    def test_jsonable_keeps_the_real_subclass_survivors(self):
        # Do-not-weaken: backups7's unbound-base answers stay.
        self.assertEqual(
            backups._jsonable(_DecodeBombBytes(b"ok\xff")), "ok\ufffd"
        )
        self.assertEqual(backups._jsonable(_IterBombList([1, 2])), [1, 2])

    def test_jsonable_class_bomb_still_encodes_without_raising(self):
        # The backups9 shape: pre-_isa the *first* bare gate raised out of
        # the walker.  A value that cannot answer what it is now falls
        # through to the text renderer — encodable, siblings kept.
        out = backups._jsonable({"k": _ClassBomb(), "keep": 1})
        self.assertIsInstance(out["k"], str)
        self.assertEqual(out["keep"], 1)
        json.dumps(out, allow_nan=False)

    def test_as_text_liar_bytes_drops_to_empty(self):
        self.assertEqual(backups._as_text(_LyingBytes()), "")

    def test_as_text_keeps_real_bytes_and_the_decode_bomb_subclass(self):
        self.assertEqual(backups._as_text(b"tar ok"), "tar ok")
        self.assertEqual(backups._as_text(_DecodeBombBytes(b"ok\xff")), "ok\ufffd")

    def test_utf8_text_liar_bytes_drops_to_empty(self):
        self.assertEqual(backups._utf8_text(_LyingBytes()), "")
        self.assertEqual(backups._utf8_text(_DecodeBombBytes(b"ok\xff")), "ok\ufffd")

    def test_exit_code_liar_int_is_junk_not_an_exit_status(self):
        self.assertIsNone(backups._exit_code(_LyingInt()))
        self.assertIsNone(backups._exit_code(_LyingBool()))
        # Do-not-weaken (backups8): a real subclass wrapping a genuine
        # status keeps its value through the unbound coercion.
        self.assertEqual(backups._exit_code(_IntEqBomb(0)), 0)
        self.assertEqual(backups._exit_code(_IntEqBomb(7)), 7)

    def test_exit_text_liar_rc_answers_exit_unknown(self):
        # The empty format spec dispatches into the liar's __format__/str —
        # a plain object renders, but None (what _exit_code hands back for
        # a liar) must keep the honest sentinel.
        self.assertEqual(backups._exit_text(None), "exit unknown")

    def test_cli_vanished_liar_rc_is_never_the_sentinel(self):
        self.assertFalse(
            backups._cli_vanished(_LyingInt(), "not found", "pg_dump")
        )
        self.assertFalse(backups._cli_vanished(None, "not found", "pg_dump"))


class PgEnvLiarOverlayTests(unittest.TestCase):
    """A junk ``maintenance_env`` overlay is skipped, never a raise that the
    dump's broad catch would report as pg_dump's failure."""

    def _env(self, overlay):
        with (
            mock.patch.object(
                backups, "cfg",
                lambda: {"settings": {"maintenance_env": overlay}},
            ),
            mock.patch.object(
                backups, "BACKUP_SECRETS_FILE",
                Path("/nonexistent/backup-credentials.json"),
            ),
        ):
            return backups._pg_env({"id": "t", "password_env": ""})

    def test_liar_dict_overlay_is_skipped_and_env_still_builds(self):
        env = self._env(_LyingDict())
        self.assertIsInstance(env, dict)
        self.assertNotIn("PGPASSWORD", env)

    def test_class_bomb_overlay_is_skipped_too(self):
        env = self._env(_ClassBomb())
        self.assertIsInstance(env, dict)

    def test_real_overlay_still_applies(self):
        env = self._env({"PATH_EXTRA": "/opt/homebrew/bin"})
        self.assertEqual(env["PATH_EXTRA"], "/opt/homebrew/bin")


if __name__ == "__main__":
    unittest.main(verbosity=2)
