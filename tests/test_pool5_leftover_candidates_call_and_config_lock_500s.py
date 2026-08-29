"""Fifth leftover-500s sweep of the Pool routes, over the real mounted app.

The hunted classes were re-reproduced against ``create_app()`` with
``raise_server_exceptions=False``.  Three live leaks survived the
pool/pool2/pool3/pool4 batteries, all on seams those pins stopped short of:

* ``storage_pool_svc._candidates`` guarded the *iteration* of
  ``storage_svc.list_volumes()`` (the pool4 fix) but not the **call**: a
  listing that raised outright still 500'd every pool route at once —
  GET /api/storage/pool, plan, save, and clear *after* its config write had
  already landed.  Same fix family, one seam earlier: the call now sits
  under the guard and no candidates is the honest degrade.

* One hostile **row** cost the whole table: a dict *subclass* passes the
  ``isinstance(vol, dict)`` gate with a ``.get`` that raises (the same
  passes-the-gate-refuses-the-protocol class as pool4's iteration bomb, one
  level down), and raised out of the shaping loop — all four routes 500'd
  while every healthy sibling row was droppable collateral.  Rows now
  degrade individually: the hostile row drops, its siblings keep rendering.

* ``config._file_lock`` fell back to the in-process lock when the lock file
  could not be **created** (EIO on ``os.open``) but let the identical
  failure one syscall later — EIO/ENOLCK out of ``fcntl.flock`` on a dying
  mount under data/ — raise raw OSError out of every ``mutate()``:
  POST /api/storage/pool/save and /clear answered a bare 500 after
  validation had already passed.  Likewise the backup-retention sweep in
  ``_save_full_locked``: the scandir under ``DATA_DIR.glob()`` re-raises
  EIO, and losing the *retention trim* (housekeeping, after the pre-image
  copy and before the atomic replace) used to 500 a save that had
  otherwise succeeded.  Both now degrade — the flock to the in-process
  lock, the trim to skipped — and the save answers 200.

The rest of the battery pins HTTP layers the probe proved immune, so a
regression cannot ship silently: ``Infinity``/``NaN`` JSON literals that
``json.loads`` happily materialises, a multipart body on a JSON route,
invalid percent-encoded UTF-8 in the query string, invalid-UTF-8 body
bytes, and an ``inf%`` df capacity row.
"""
from __future__ import annotations

import fcntl as _real_fcntl
import json
import unittest
from unittest import mock

from hub import config, disk_snapshot, storage_pool_svc, storage_svc

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


#: A complete, well-formed poolable volume row: the point of the survival
#: pins is that *this* row keeps rendering next to the hostile ones.
_VAULT = {
    "device": "/dev/disk6s1",
    "mount": "/Volumes/Vault",
    "kind": "external",
    "total_gb": 10.0,
    "used_gb": 1.0,
    "avail_gb": 9.0,
    "pct": 10,
    "disk_id": "disk6",
    "filesystem": "apfs",
}


class _GetBombDict(dict):
    """Passes ``isinstance(x, dict)``; raises the moment ``.get`` is called —
    pool4's iteration bomb, one level down."""

    def get(self, *args, **kwargs):
        raise ValueError("get bomb")


def _pool_write_env(test):
    """A coherent cfg/update_settings pair for before/after-write asserts."""
    test.settings = {}

    def fake_update(patch: dict) -> dict:
        test.settings.update(patch)
        return test.settings

    for patcher in (
        mock.patch.object(storage_pool_svc, "update_settings", side_effect=fake_update),
        mock.patch.object(storage_pool_svc, "cfg",
                          side_effect=lambda: {"settings": test.settings}),
    ):
        patcher.start()
        test.addCleanup(patcher.stop)


class PoolCandidatesRaisingCallTests(unittest.TestCase):
    """A volume listing that raises at the *call* (not just iteration) must
    cost the candidate table, never the request — pre-fix all four routes
    answered a bare 500, clear after its config write had already landed."""

    def setUp(self):
        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)

    def test_get_pool_raising_listing_degrades_to_200_missing_members(self):
        with (
            mock.patch.object(storage_svc, "list_volumes",
                              side_effect=ValueError("boom")),
            mock.patch.object(
                storage_pool_svc, "cfg",
                return_value={"settings": {"storage_pool": {
                    "name": "media", "members": ["/Volumes/Vault"],
                    "policy": "most-free", "min_free_gb": 0,
                }}},
            ),
        ):
            resp = _client().get("/api/storage/pool?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        # Honest degrade: the configured member is *visible* as missing,
        # not silently rendered as a healthy empty pool.
        self.assertIs(body["configured"], True)
        self.assertEqual(body["members"], [])
        self.assertEqual(body["missing_members"], ["/Volumes/Vault"])
        self.assertEqual(body["summary"]["member_count"], 0)

    def test_plan_raising_listing_is_the_coded_400_not_500(self):
        # OSError: a dying disk under a df read is the realistic raise.
        with mock.patch.object(storage_svc, "list_volumes",
                               side_effect=OSError(5, "eio")):
            resp = _client().post(
                "/api/storage/pool/plan",
                json={"mounts": ["/Volumes/Vault"], "policy": "most-free"},
            )
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "storage_pool.not_poolable")

    def test_save_raising_listing_refuses_before_writing(self):
        _pool_write_env(self)
        # RecursionError is not ValueError; it must still be contained.
        with mock.patch.object(storage_svc, "list_volumes",
                               side_effect=RecursionError("deep")):
            resp = _client().post(
                "/api/storage/pool/save",
                json={"mounts": ["/Volumes/Vault"], "policy": "most-free"},
            )
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "storage_pool.not_poolable")
        # The refusal fired in _validate, before update_settings.
        self.assertEqual(self.settings, {})

    def test_clear_raising_listing_still_clears_and_answers_200(self):
        _pool_write_env(self)
        self.settings["storage_pool"] = {
            "name": "media", "members": ["/Volumes/Vault"],
            "policy": "most-free", "min_free_gb": 0,
        }
        with mock.patch.object(storage_svc, "list_volumes",
                               side_effect=TypeError("boom")):
            resp = _client().post("/api/storage/pool/clear")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertIs(body["configured"], False)
        self.assertIs(body["applied"], True)
        self.assertEqual(self.settings["storage_pool"]["members"], [])


class PoolCandidatesRowBombTests(unittest.TestCase):
    """One hostile row must drop alone; its healthy siblings keep rendering
    and the mutations on those siblings keep working."""

    def setUp(self):
        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)

    def test_get_bomb_row_drops_but_the_healthy_sibling_renders(self):
        volumes = [_GetBombDict(_VAULT), dict(_VAULT)]
        with (
            mock.patch.object(storage_svc, "list_volumes", return_value=volumes),
            mock.patch.object(
                storage_pool_svc, "cfg",
                return_value={"settings": {"storage_pool": {
                    "name": "media", "members": ["/Volumes/Vault"],
                    "policy": "most-free", "min_free_gb": 0,
                }}},
            ),
        ):
            resp = _client().get("/api/storage/pool?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertEqual([m["mount"] for m in body["members"]], ["/Volumes/Vault"])
        self.assertEqual(body["missing_members"], [])
        self.assertEqual(body["summary"]["member_count"], 1)

    def test_save_next_to_a_bomb_row_still_lands(self):
        _pool_write_env(self)
        volumes = [_GetBombDict(_VAULT), dict(_VAULT)]
        with mock.patch.object(storage_svc, "list_volumes", return_value=volumes):
            resp = _client().post(
                "/api/storage/pool/save",
                json={"mounts": ["/Volumes/Vault"], "policy": "most-free"},
            )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIs(resp.json()["applied"], True)
        self.assertEqual(self.settings["storage_pool"]["members"], ["/Volumes/Vault"])


class _EIOFcntl:
    """fcntl whose flock raises EIO — the dying-data/-mount seam."""

    LOCK_EX = _real_fcntl.LOCK_EX
    LOCK_UN = _real_fcntl.LOCK_UN

    @staticmethod
    def flock(fd, op):
        raise OSError(5, "eio")


class _EIOGlobDataDir(type(config.DATA_DIR)):
    """DATA_DIR whose glob() scandir re-raises EIO mid-retention-sweep."""

    def glob(self, pattern):
        raise OSError(5, "eio")


class PoolConfigLockDegradeTests(unittest.TestCase):
    """A services.yaml write whose *ancillary* I/O fails (flock, retention
    glob) must still land the save with 200 — the real config chain, no
    update_settings mock.  Pre-fix both answered a bare 500 after
    validation had already passed (flock even before the write began)."""

    def setUp(self):
        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)
        try:
            self._saved = config.YAML_PATH.read_bytes()
        except OSError:
            self._saved = None
        config.YAML_PATH.write_text("settings: {}\n", encoding="utf-8")
        config.reload_cfg()

        def restore():
            if self._saved is None:
                try:
                    config.YAML_PATH.unlink()
                except OSError:
                    pass
            else:
                config.YAML_PATH.write_bytes(self._saved)
            config.reload_cfg()

        self.addCleanup(restore)
        patcher = mock.patch.object(
            storage_svc, "list_volumes", return_value=[dict(_VAULT)]
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_flock_eio_save_still_lands_200(self):
        with mock.patch.object(config, "fcntl", _EIOFcntl):
            resp = _client().post(
                "/api/storage/pool/save",
                json={"mounts": ["/Volumes/Vault"], "policy": "most-free"},
            )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIs(resp.json()["applied"], True)
        # The write landed on disk despite the unusable cross-process lock.
        on_disk = config._read_disk()
        self.assertEqual(
            on_disk["settings"]["storage_pool"]["members"], ["/Volumes/Vault"]
        )

    def test_flock_eio_clear_still_lands_200(self):
        _client().post(
            "/api/storage/pool/save",
            json={"mounts": ["/Volumes/Vault"], "policy": "most-free"},
        )
        with mock.patch.object(config, "fcntl", _EIOFcntl):
            resp = _client().post("/api/storage/pool/clear")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIs(resp.json()["configured"], False)
        self.assertEqual(
            config._read_disk()["settings"]["storage_pool"]["members"], []
        )

    def test_retention_glob_eio_save_still_lands_200(self):
        eio_dir = _EIOGlobDataDir(str(config.DATA_DIR))
        with mock.patch.object(config, "DATA_DIR", eio_dir):
            resp = _client().post(
                "/api/storage/pool/save",
                json={"mounts": ["/Volumes/Vault"], "policy": "most-free"},
            )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIs(resp.json()["applied"], True)
        self.assertEqual(
            config._read_disk()["settings"]["storage_pool"]["members"],
            ["/Volumes/Vault"],
        )


class PoolHttpStaysImmunePins(unittest.TestCase):
    """Layers the pool5 probe found already immune, pinned so a regression
    in any of them cannot ship silently."""

    def setUp(self):
        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)

    def test_invalid_percent_utf8_force_is_422_with_utf8_body(self):
        resp = _client().get("/api/storage/pool?force=%ff%fe")
        self.assertEqual(resp.status_code, 422, resp.text[:200])
        # The body must already be valid UTF-8 — decode strictly on purpose.
        json.loads(resp.content.decode("utf-8"))

    def test_infinity_and_nan_literals_are_422_with_renderable_body(self):
        """json.loads happily materialises ``Infinity``/``NaN``; the 422
        echo of that input must survive the allow_nan=False encoder."""
        for raw in (
            b'{"mounts": [Infinity]}',
            b'{"mounts": [NaN]}',
            b'{"mounts": ["/x"], "policy": Infinity}',
        ):
            resp = _client().post(
                "/api/storage/pool/plan", content=raw,
                headers={"content-type": "application/json"},
            )
            self.assertEqual(resp.status_code, 422, resp.text[:200])
            json.loads(resp.content.decode("utf-8"))

    def test_nan_min_free_literal_saves_zero_floor(self):
        _pool_write_env(self)
        with mock.patch.object(storage_svc, "list_volumes",
                               return_value=[dict(_VAULT)]):
            resp = _client().post(
                "/api/storage/pool/save",
                content=b'{"mounts": ["/Volumes/Vault"], "min_free_gb": NaN}',
                headers={"content-type": "application/json"},
            )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(self.settings["storage_pool"]["min_free_gb"], 0.0)

    def test_multipart_body_on_the_json_route_is_422_not_500(self):
        resp = _client().post(
            "/api/storage/pool/plan", files={"mounts": ("a.txt", b"/x")}
        )
        self.assertEqual(resp.status_code, 422, resp.text[:200])
        json.loads(resp.content.decode("utf-8"))

    def test_invalid_utf8_body_bytes_are_the_coded_parse_4xx(self):
        resp = _client().post(
            "/api/storage/pool/plan", content=b'{"mounts": ["\xff\xfe"]}',
            headers={"content-type": "application/json"},
        )
        self.assertIn(resp.status_code, (400, 422), resp.text[:200])
        json.loads(resp.content.decode("utf-8"))

    def test_inf_pct_df_row_keeps_rendering(self):
        """`inf%` in the capacity column falls back to the computed percent
        instead of dropping (or 500ing) the row."""
        table = ("Filesystem 1024-blocks Used Avail Capacity Mounted on\n"
                 "/dev/disk6s1 1048576000 104857600 943718400 inf% /Volumes/X\n")
        disk_snapshot._df_table.invalidate()
        self.addCleanup(disk_snapshot._df_table.invalidate)
        with mock.patch.object(disk_snapshot, "sh", return_value=(0, table, "")):
            resp = _client().get("/api/storage/pool?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        mounts = [c["mount"] for c in resp.json()["unassigned"]]
        self.assertIn("/Volumes/X", mounts)


if __name__ == "__main__":
    unittest.main(verbosity=2)
