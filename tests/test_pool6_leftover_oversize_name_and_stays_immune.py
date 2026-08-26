"""Sixth leftover-500s sweep of the storage-pool routes, over the real app.

The zoo (dict-subclass protocol bombs, over-cap digit ints, huge JSON
number literals, numeric/hand-edited YAML shapes, FIFO-squatted paths,
surrogates in keys and values, seam calls that raise outright) was
re-reproduced against ``create_app()`` with
``raise_server_exceptions=False``.  One live leftover survived the
pool/pool2/pool3/pool4/pool5 batteries:

* **POST /api/storage/pool/save persisted an unbounded display name.**
  ``save_pool`` scrubbed ``name`` (the pool4 surrogate/digit-cap fix) but
  never capped it — the exact class ``vms.name_too_long`` /
  ``identity.value_too_long`` / the notify caps closed everywhere else.
  A multi-MB label was refused only by the *whole-file* save cap as a
  ``settings.save_failed`` 503, blaming the disk for oversized input; and
  a label just under that cap landed with HTTP 200 and ballooned
  services.yaml to ~900KB — crowding every sibling writer toward the 1MB
  read cap beyond which every ``cfg()`` answers ``{}`` (the wipe shape the
  notify sweep documented).  Fixed with the coded 400
  ``storage_pool.name_too_long`` (cap 64, matching the accounts / apikeys
  / disk / vms name caps), measured on the scrubbed text after ``_text``,
  before any write.  The three SPA locales carry the key.

The rest of the battery pins seams the probe proved immune, so a
regression cannot ship silently:

* per-row protocol bombs riding a real ``list_volumes`` listing — an
  unhashable ``kind``, an ``__eq__`` bomb ``avail_gb`` (detonated by
  ``raw in (None, "")``), a float-subclass ``__float__`` bomb, a
  str-subclass ``encode`` bomb mount, a ``__bool__`` bomb ``disk_id``,
  and dict-subclass ``items()``/``keys()`` bombs — hostile rows drop (or
  render through the unbound-``dict.get`` storage underneath), healthy
  siblings keep rendering, and save next to them still lands;
* a FIFO squatting services.yaml: GET degrades to defaults without
  hanging (the O_NONBLOCK + regular-file read rule), and save answers
  200 with a regular file back in place;
* hand-edited YAML junk under ``settings.storage_pool`` — a ``!!timestamp``
  name (renders as its isoformat text), a dict ``members``, a list
  ``policy``, uncapped hex over-digit-cap ints as name and member — all
  HTTP 200 with the sane sibling member still resolved;
* a lone-surrogate mount that scrub-matches a real candidate saves 200
  (the audit write included) and persists the scrubbed member;
* a ``1e309`` JSON literal as ``min_free_gb`` saves with the 0.0 floor.
"""
from __future__ import annotations

import os
import stat as stat_mod
import unittest
from unittest import mock

from hub import config, storage_pool_svc, storage_svc

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


class _RealYamlMixin(unittest.TestCase):
    """Tests that assert on services.yaml bytes run over the real config
    chain — no update_settings mock — with the original file restored."""

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
            try:
                if not stat_mod.S_ISREG(os.lstat(config.YAML_PATH).st_mode):
                    os.unlink(config.YAML_PATH)
            except OSError:
                pass
            if self._saved is None:
                try:
                    config.YAML_PATH.unlink()
                except OSError:
                    pass
            else:
                config.YAML_PATH.write_bytes(self._saved)
            config.reload_cfg()

        self.addCleanup(restore)

    def _mount_vault(self):
        patcher = mock.patch.object(
            storage_svc, "list_volumes", return_value=[dict(_VAULT)]
        )
        patcher.start()
        self.addCleanup(patcher.stop)


class PoolOversizeNameTests(_RealYamlMixin):
    """The live pool6 leftover: an unbounded pool name.  Pre-fix, a multi-MB
    label answered the settings.save_failed 503 (blaming the disk for
    oversized input) and a just-under-cap label landed with 200, ballooning
    services.yaml toward the 1MB read cap every sibling writer shares."""

    def test_multi_mb_name_is_the_coded_400_not_the_save_failed_503(self):
        self._mount_vault()
        before = config.YAML_PATH.read_bytes()
        resp = _client().post(
            "/api/storage/pool/save",
            json={"mounts": ["/Volumes/Vault"], "policy": "most-free",
                  "name": "N" * (1024 * 1024)},
        )
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        detail = resp.json()["detail"]
        self.assertEqual(detail["code"], "storage_pool.name_too_long")
        self.assertEqual(detail["params"]["max"], 64)
        # Nothing was written: the file stays byte-identical.
        self.assertEqual(config.YAML_PATH.read_bytes(), before)

    def test_just_under_the_read_cap_name_is_refused_not_ballooned(self):
        """The sneakier pre-fix shape: 900k landed with HTTP 200 and grew
        services.yaml to ~900KB — one more such value away from the 1MB
        read cap beyond which every cfg() answers {}."""
        self._mount_vault()
        resp = _client().post(
            "/api/storage/pool/save",
            json={"mounts": ["/Volumes/Vault"], "policy": "most-free",
                  "name": "N" * 900_000},
        )
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        self.assertEqual(
            resp.json()["detail"]["code"], "storage_pool.name_too_long"
        )
        self.assertLess(config.YAML_PATH.stat().st_size, 4096)

    def test_cap_boundary_64_saves_65_refuses(self):
        self._mount_vault()
        resp = _client().post(
            "/api/storage/pool/save",
            json={"mounts": ["/Volumes/Vault"], "name": "N" * 64},
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(resp.json()["name"], "N" * 64)
        on_disk = config._read_disk()["settings"]["storage_pool"]
        self.assertEqual(on_disk["name"], "N" * 64)

        resp = _client().post(
            "/api/storage/pool/save",
            json={"mounts": ["/Volumes/Vault"], "name": "N" * 65},
        )
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        self.assertEqual(
            resp.json()["detail"]["code"], "storage_pool.name_too_long"
        )
        # The earlier save survives the refused one.
        self.assertEqual(
            config._read_disk()["settings"]["storage_pool"]["name"], "N" * 64
        )

    def test_cap_is_measured_on_the_scrubbed_text(self):
        """A lone surrogate scrubs 1:1 (encode-side "replace" substitutes
        "?"), so a 64-code-point name with a surrogate still fits, and its
        persisted form is clean."""
        self._mount_vault()
        resp = _client().post(
            "/api/storage/pool/save",
            content=(b'{"mounts": ["/Volumes/Vault"], "name": "\\ud800'
                     + b"N" * 63 + b'"}'),
            headers={"content-type": "application/json"},
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(resp.json()["name"], "?" + "N" * 63)
        # The response body is already valid UTF-8 — decode strictly.
        resp.content.decode("utf-8")
        self.assertEqual(
            config._read_disk()["settings"]["storage_pool"]["name"],
            "?" + "N" * 63,
        )

    def test_whitespace_padding_past_the_cap_still_saves_after_strip(self):
        self._mount_vault()
        resp = _client().post(
            "/api/storage/pool/save",
            json={"mounts": ["/Volumes/Vault"],
                  "name": " " * 200 + "media" + " " * 200},
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(resp.json()["name"], "media")


class _EqBomb:
    def __eq__(self, other):
        raise RuntimeError("leftover __eq__ bomb")

    __hash__ = None


class _BoolBomb:
    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")


class _FloatBomb(float):
    def __float__(self):
        raise RuntimeError("leftover __float__ bomb")


class _EncodeBombStr(str):
    def __str__(self):
        raise RuntimeError("leftover __str__ bomb")

    def encode(self, *a, **k):
        raise RuntimeError("leftover encode bomb")


class _ItemsBomb(dict):
    def items(self):
        raise RuntimeError("leftover items bomb")


class _KeysBomb(dict):
    def keys(self):
        raise RuntimeError("leftover keys bomb")


class PoolRowProtocolBombPins(unittest.TestCase):
    """Stays-immune: per-row protocol bombs beyond pool5's ``.get`` bomb.
    Hostile rows drop individually (or render through the real storage
    underneath a poisoned method); the healthy sibling keeps rendering and
    stays saveable."""

    def setUp(self):
        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)
        self.rows = [
            # Unhashable kind: ``in POOLABLE_KINDS`` needs a hash.
            {**_VAULT, "mount": "/Volumes/A", "kind": ["external"]},
            # ``_finite_float``'s ``raw in (None, "")`` detonates __eq__.
            {**_VAULT, "mount": "/Volumes/B", "avail_gb": _EqBomb()},
            {**_VAULT, "mount": "/Volumes/C", "total_gb": _FloatBomb(3.0)},
            {**_VAULT, "mount": _EncodeBombStr("/Volumes/D")},
            # ``disk_id`` rides ``_text(...) or None``: __bool__ detonates.
            {**_VAULT, "mount": "/Volumes/E", "disk_id": _BoolBomb()},
            # Subclasses that poison one protocol but keep real storage:
            # dict.get reads underneath, so these rows *survive*.
            _ItemsBomb({**_VAULT, "mount": "/Volumes/F"}),
            _KeysBomb({**_VAULT, "mount": "/Volumes/G"}),
            dict(_VAULT),
        ]

    def test_overview_drops_hostile_rows_and_keeps_the_rest(self):
        with mock.patch.object(storage_svc, "list_volumes",
                               return_value=list(self.rows)):
            resp = _client().get("/api/storage/pool?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        resp.content.decode("utf-8")
        mounts = [c["mount"] for c in resp.json()["unassigned"]]
        self.assertIn("/Volumes/Vault", mounts)
        # The poisoned-method-but-real-storage rows keep rendering.
        self.assertIn("/Volumes/F", mounts)
        self.assertIn("/Volumes/G", mounts)
        # The protocol-bomb rows drop alone.
        for gone in ("/Volumes/A", "/Volumes/B", "/Volumes/C", "/Volumes/D"):
            self.assertNotIn(gone, mounts)

    def test_save_next_to_the_bomb_rows_still_lands(self):
        settings = {}
        with (
            mock.patch.object(storage_svc, "list_volumes",
                              return_value=list(self.rows)),
            mock.patch.object(storage_pool_svc, "update_settings",
                              side_effect=lambda p: settings.update(p) or settings),
            mock.patch.object(storage_pool_svc, "cfg",
                              side_effect=lambda: {"settings": settings}),
        ):
            resp = _client().post(
                "/api/storage/pool/save",
                json={"mounts": ["/Volumes/Vault"], "policy": "most-free"},
            )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIs(resp.json()["applied"], True)
        self.assertEqual(settings["storage_pool"]["members"], ["/Volumes/Vault"])


class PoolFifoConfigPins(_RealYamlMixin):
    """Stays-immune: a FIFO squatting services.yaml.  The capped reader
    opens O_NONBLOCK and refuses non-regular files, so GET answers the
    defaults instead of parking a worker forever; the mutate path treats
    the occupant as holding no YAML to lose, and save puts a regular file
    back."""

    def setUp(self):
        super().setUp()
        self._mount_vault()
        config.YAML_PATH.unlink()
        os.mkfifo(config.YAML_PATH)
        config.reload_cfg()
        storage_pool_svc.invalidate_pool()

    def test_get_pool_with_fifo_config_degrades_to_200_defaults(self):
        resp = _client().get("/api/storage/pool?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertIs(body["configured"], False)
        self.assertIn("/Volumes/Vault", [c["mount"] for c in body["unassigned"]])

    def test_save_with_fifo_config_lands_and_restores_a_regular_file(self):
        resp = _client().post(
            "/api/storage/pool/save",
            json={"mounts": ["/Volumes/Vault"], "policy": "most-free"},
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertIs(resp.json()["applied"], True)
        self.assertTrue(stat_mod.S_ISREG(os.stat(config.YAML_PATH).st_mode))
        self.assertEqual(
            config._read_disk()["settings"]["storage_pool"]["members"],
            ["/Volumes/Vault"],
        )


class PoolHostileYamlPins(_RealYamlMixin):
    """Stays-immune: hand-edited services.yaml junk under storage_pool."""

    def test_timestamp_name_dict_members_list_policy_render_200(self):
        config.YAML_PATH.write_text(
            "settings:\n"
            "  storage_pool:\n"
            "    name: 2026-01-02\n"
            "    members: {a: 1}\n"
            "    policy: [most-free]\n"
            "    min_free_gb: [1, 2]\n",
            encoding="utf-8",
        )
        config.reload_cfg()
        storage_pool_svc.invalidate_pool()
        self._mount_vault()
        resp = _client().get("/api/storage/pool?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        resp.content.decode("utf-8")
        body = resp.json()
        # YAML loads the bare date as datetime.date; _text renders its
        # isoformat text instead of the silent "pool" default.
        self.assertEqual(body["name"], "2026-01-02")
        # A dict cannot be a member list; a list is the first-item policy.
        self.assertIs(body["configured"], False)
        self.assertEqual(body["policy"], "most-free")

    def test_hex_over_digit_cap_name_and_member_read_absent_not_500(self):
        """YAML hex loads uncapped (``int(x, 16)``); its str() is the same
        digit-cap ValueError json.dumps would raise.  The over-cap name
        reads as the default and the over-cap member drops; the sane
        sibling member still resolves against the live candidate."""
        config.YAML_PATH.write_text(
            "settings:\n"
            "  storage_pool:\n"
            "    name: 0x" + "f" * 5000 + "\n"
            "    members: [0x" + "f" * 5000 + ", /Volumes/Vault]\n",
            encoding="utf-8",
        )
        config.reload_cfg()
        storage_pool_svc.invalidate_pool()
        self._mount_vault()
        resp = _client().get("/api/storage/pool?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertEqual(body["name"], "pool")
        self.assertEqual([m["mount"] for m in body["members"]],
                         ["/Volumes/Vault"])
        self.assertEqual(body["missing_members"], [])


class PoolHttpStaysImmunePins(_RealYamlMixin):
    """Stays-immune: HTTP shapes the pool6 probe found already clean."""

    def test_surrogate_mount_scrub_matches_the_candidate_and_saves(self):
        """A df mount carrying a lone surrogate and the client echo of it
        scrub to the same "?" form (encode-side "replace"); the save lands
        (audit write included) and the persisted member is clean."""
        raw_vol = dict(_VAULT, mount="/Volumes/Va\ud800ult",
                       device="/dev/disk7s1", disk_id="disk7")
        with mock.patch.object(storage_svc, "list_volumes",
                               return_value=[raw_vol]):
            resp = _client().post(
                "/api/storage/pool/save",
                content=b'{"mounts": ["/Volumes/Va\\ud800ult"]}',
                headers={"content-type": "application/json"},
            )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        resp.content.decode("utf-8")
        self.assertEqual(
            config._read_disk()["settings"]["storage_pool"]["members"],
            ["/Volumes/Va?ult"],
        )

    def test_1e309_min_free_literal_saves_the_zero_floor(self):
        """json.loads materialises ``1e309`` as float inf; the floor
        degrades to 0.0 instead of persisting inf into services.yaml."""
        self._mount_vault()
        resp = _client().post(
            "/api/storage/pool/save",
            content=b'{"mounts": ["/Volumes/Vault"], "min_free_gb": 1e309}',
            headers={"content-type": "application/json"},
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(
            config._read_disk()["settings"]["storage_pool"]["min_free_gb"], 0.0
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
