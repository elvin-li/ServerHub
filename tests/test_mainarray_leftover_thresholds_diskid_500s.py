"""Leftover 500s and silent lookup misses on the Main Array page's backend.

Two leftovers, both of the "scrub before it becomes a key" class:

1. GET /api/settings/thresholds copied YAML mapping *keys* verbatim into the
   response dict.  A leftover ``\\ud800`` key blew up Starlette's UTF-8
   encode, and a >4300-digit int key (YAML hex/octal parses these happily)
   ValueError'd the encoder's key stringify — both 500'd the endpoint that
   the Main Array page reads for its SMART temperature colouring.

2. ``storage_svc._volume_row`` gated disk_id scrubbing behind a strict
   ``isinstance(disk_id, str)``, so a numeric id that was *already an int*
   rode through unchanged while ``aggregate_capacity`` stringified the same
   id for its group key.  ``storage_overview``'s shared-pool marking then
   compared ``42 in {"42"}`` and silently missed — the UI's shared-pool
   badge vanished with no error anywhere.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from hub import storage_svc, system_settings_svc
from hub.routers.unraid_parity import router as parity_router

#: Past CPython's default 4300-digit int<->str conversion limit: a valid
#: Python int that neither ``str()`` nor ``json.dumps`` can render.
_HUGE_INT = 10 ** 5000


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(parity_router)
    return TestClient(app, raise_server_exceptions=False)


class ThresholdsKeyScrubTests(unittest.TestCase):
    """GET /api/settings/thresholds must scrub mapping keys, not just values."""

    def _get(self, section: dict):
        with mock.patch.object(
            system_settings_svc, "settings_section", return_value=section,
        ):
            return _client().get("/api/settings/thresholds")

    def test_surrogate_yaml_key_does_not_500(self):
        resp = self._get({"smart_temp_c": 70, "\ud800junk": 5})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["smart_temp_c"], 70)
        for key in data:
            # the poisoned key must arrive scrubbed, never as a lone surrogate
            key.encode("utf-8")

    def test_huge_int_yaml_key_is_dropped_not_500(self):
        resp = self._get({_HUGE_INT: 60, "smart_temp_c": 70})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["smart_temp_c"], 70)
        # the unrenderable key is gone, defaults intact
        self.assertEqual(data["smart_wear_pct"], 90)

    def test_bytes_yaml_key_still_applies(self):
        resp = self._get({b"smart_temp_c": 55})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["smart_temp_c"], 55)

    def test_already_int_yaml_key_coerces_via_str_probe(self):
        # A numeric YAML key (unquoted 42) must coerce through str(), not
        # crash nor shadow the known keys around it.
        resp = self._get({42: 33, "smart_wear_pct": 80})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["smart_wear_pct"], 80)
        self.assertEqual(data.get("42"), 33)

    def test_get_thresholds_output_is_always_encodable(self):
        with mock.patch.object(
            system_settings_svc, "settings_section",
            return_value={"\ud800junk": 5, _HUGE_INT: 60, True: 44, b"k": 1},
        ):
            _starlette(system_settings_svc.get_thresholds())


def _vol(mount: str, disk_id, total=100.0, used=50.0, avail=50.0, pct=50) -> dict:
    return {
        "device": f"/dev/{mount.rsplit('/', 1)[-1]}",
        "mount": mount,
        "kind": "external",
        "total_gb": total,
        "used_gb": used,
        "avail_gb": avail,
        "pct": pct,
        "disk_id": disk_id,
        "filesystem": f"/dev/{mount.rsplit('/', 1)[-1]}",
    }


class DiskIdStrProbeTests(unittest.TestCase):
    """Already-int disk ids must coerce via str(), not an isinstance gate."""

    def _overview(self, vols):
        with (
            mock.patch.object(storage_svc, "list_volumes", return_value=vols),
            mock.patch.object(storage_svc, "smart_devices", lambda: []),
        ):
            return storage_svc.storage_overview()

    def test_int_disk_id_is_stringified_everywhere(self):
        data = self._overview([_vol("/Volumes/A", 42), _vol("/Volumes/B", 42)])
        _starlette(data)
        self.assertEqual([v["disk_id"] for v in data["volumes"]], ["42", "42"])
        self.assertEqual([d["disk_id"] for d in data["array"]["devices"]], ["42", "42"])
        self.assertEqual(
            [g["disk_id"] for g in data["array"]["capacity_groups"]], ["42"],
        )

    def test_int_disk_id_shared_pool_badge_matches(self):
        # Two same-size volumes on disk 42 form a shared pool; the marking
        # used to compare int 42 against the stringified group key "42" and
        # silently drop the badge.
        data = self._overview([_vol("/Volumes/A", 42), _vol("/Volumes/B", 42)])
        groups = data["array"]["capacity_groups"]
        self.assertEqual(groups[0]["mode"], "shared_pool")
        self.assertTrue(
            all(d.get("shared_pool") for d in data["array"]["devices"]),
            "int disk_id must still light the shared-pool badge",
        )

    def test_huge_int_disk_id_drops_to_none_not_500(self):
        data = self._overview([_vol("/Volumes/C", _HUGE_INT, total=10.0,
                                    used=1.0, avail=9.0, pct=10)])
        _starlette(data)
        self.assertEqual([v["disk_id"] for v in data["volumes"]], [None])

    def test_surrogate_disk_id_is_scrubbed_consistently(self):
        data = self._overview([
            _vol("/Volumes/A", "disk\ud8006"), _vol("/Volumes/B", "disk\ud8006"),
        ])
        _starlette(data)
        vol_ids = {v["disk_id"] for v in data["volumes"]}
        grp_ids = {g["disk_id"] for g in data["array"]["capacity_groups"]}
        self.assertEqual(vol_ids, grp_ids)
        self.assertTrue(
            all(d.get("shared_pool") for d in data["array"]["devices"]),
            "scrubbed ids must stay consistent between volumes and groups",
        )

    def test_finite_float_disk_id_coerces_like_the_group_key(self):
        data = self._overview([_vol("/Volumes/A", 6.0), _vol("/Volumes/B", 6.0)])
        _starlette(data)
        vol_ids = {v["disk_id"] for v in data["volumes"]}
        grp_ids = {g["disk_id"] for g in data["array"]["capacity_groups"]}
        self.assertEqual(vol_ids, grp_ids)


if __name__ == "__main__":
    unittest.main()
