"""Fourth leftover-500s sweep of the Pool routes, over the real mounted app.

The hunted classes (collections that pass ``isinstance`` but refuse
*iteration*, already-int over-cap numbers, lone UTF-8 surrogates, vanished
CLI) were re-reproduced against ``create_app()`` with
``raise_server_exceptions=False``.  The pool3 battery pinned the surrogate /
digit-cap / body-parse classes on a bare ``FastAPI()`` app; this sweep found
one live leak those pins could not see:

* ``storage_pool_svc._candidates`` iterated ``storage_svc.list_volumes()``
  behind only an ``isinstance(volumes, list)`` gate — the exact class the
  usage4 / storage4 sweeps sealed everywhere else (``usage_svc.scan_roots``,
  ``storage_svc._jsonable``, the storage router's ``_rendered`` funnel, which
  the pool routes do not pass through).  A volume listing that passes the
  gate but refuses iteration raised out of the loop and 500'd every pool
  route at once: GET /api/storage/pool, POST /api/storage/pool/plan,
  POST /api/storage/pool/save — and POST /api/storage/pool/clear *after*
  its config write had already landed, so the pool was gone but the
  operator saw a bare 500.  Fixed by materializing the listing under its
  own guard (the ups_svc/storage_svc/usage_svc rule): no candidates is the
  honest degrade — the overview answers 200 with the configured members
  reported missing, plan/save answer their coded refusals before any write,
  and clear completes with 200.

The rest of the battery re-pins the pool3 classes over the *real* mounted
app (middleware, body parsing, audit write included), plus the vanished-df
degrade, so a regression in any layer pool3's bare app skipped cannot ship
silently.
"""
from __future__ import annotations

import json
import plistlib
import sys
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import disk_snapshot, storage_pool_svc, storage_svc  # noqa: E402

#: Parsed from real plist bytes: plistlib's ``<integer>`` handler runs
#: ``int(x, 16)`` for the ``0x`` form, which CPython's 4300-digit str->int
#: parse cap does not bound, so the leftover arrives *already-int* and only
#: fails at render time (``str()`` / ``json.dumps``).
_HUGE_INT = plistlib.loads(
    b'<?xml version="1.0"?><plist version="1.0"><dict>'
    b"<key>v</key><integer>0x" + b"F" * 4400 + b"</integer>"
    b"</dict></plist>"
)["v"]

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


class _IterBombList(list):
    """Passes ``isinstance(x, list)``; raises the moment it is iterated."""

    def __iter__(self):
        raise ValueError("iteration bomb")


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


def _pool_write_env(test):
    """list_volumes + a coherent cfg/update_settings pair for write tests."""
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


class PoolCandidatesIterationBombTests(unittest.TestCase):
    """A volume listing that refuses iteration must cost the candidate
    table, never the request — pre-fix all four routes answered a bare 500,
    clear after its config write had already landed."""

    def setUp(self):
        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)

    def test_get_pool_bombed_listing_degrades_to_200_missing_members(self):
        with (
            mock.patch.object(storage_svc, "list_volumes",
                              return_value=_IterBombList([dict(_VAULT)])),
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
        self.assertEqual(body["unassigned"], [])
        self.assertEqual(body["summary"]["member_count"], 0)

    def test_plan_bombed_listing_is_the_coded_400_not_500(self):
        with mock.patch.object(storage_svc, "list_volumes",
                               return_value=_IterBombList([dict(_VAULT)])):
            resp = _client().post(
                "/api/storage/pool/plan",
                json={"mounts": ["/Volumes/Vault"], "policy": "most-free"},
            )
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "storage_pool.not_poolable")

    def test_save_bombed_listing_refuses_before_writing(self):
        _pool_write_env(self)
        with mock.patch.object(storage_svc, "list_volumes",
                               return_value=_IterBombList([dict(_VAULT)])):
            resp = _client().post(
                "/api/storage/pool/save",
                json={"mounts": ["/Volumes/Vault"], "policy": "most-free"},
            )
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "storage_pool.not_poolable")
        # The refusal fired in _validate, before update_settings.
        self.assertEqual(self.settings, {})

    def test_clear_bombed_listing_still_clears_and_answers_200(self):
        """Pre-fix the config write landed and *then* the overview rebuild
        500'd: the pool was gone but the operator saw a crash."""
        _pool_write_env(self)
        self.settings["storage_pool"] = {
            "name": "media", "members": ["/Volumes/Vault"],
            "policy": "most-free", "min_free_gb": 0,
        }
        with mock.patch.object(storage_svc, "list_volumes",
                               return_value=_IterBombList([dict(_VAULT)])):
            resp = _client().post("/api/storage/pool/clear")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertIs(body["configured"], False)
        self.assertIs(body["applied"], True)
        self.assertEqual(self.settings["storage_pool"]["members"], [])


class PoolHostileYamlHttpRegressionPins(unittest.TestCase):
    """The pool3 hostile-YAML classes, re-pinned through the real mounted
    app (security middleware and strict UTF-8 render included)."""

    def setUp(self):
        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)

    def test_surrogates_over_cap_int_and_numeric_member_stay_200(self):
        volumes = [
            dict(_VAULT),
            # Surrogate mount that must still match the identically-broken
            # YAML member below — both sides scrub before the lookup.
            dict(_VAULT, mount="/Volumes/Su\ud800rr", used_gb=_HUGE_INT,
                 avail_gb="9" * 5000),
            # An over-cap already-int mount cannot name a directory: the row
            # can only drop, never raise.
            dict(_VAULT, mount=_HUGE_INT, filesystem=float("-inf")),
            "not-a-dict",
            None,
        ]
        with (
            mock.patch.object(storage_svc, "list_volumes", return_value=volumes),
            mock.patch.object(
                storage_pool_svc, "cfg",
                return_value={"settings": {"storage_pool": {
                    "name": "p\ud800ool",
                    # str member, surrogate member, over-cap already-int,
                    # numeric YAML id, unmounted path.
                    "members": ["/Volumes/Vault", "/Volumes/Su\ud800rr",
                                _HUGE_INT, 123, "/gone"],
                    "policy": "least-used-pct",
                    "min_free_gb": float("inf"),
                }}},
            ),
        ):
            resp = _client().get("/api/storage/pool?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        # The body must already be valid UTF-8 — decode strictly on purpose.
        body = json.loads(resp.content.decode("utf-8"))
        self.assertEqual(body["name"], "p?ool")
        mounts = [m["mount"] for m in body["members"]]
        self.assertIn("/Volumes/Vault", mounts)
        self.assertIn("/Volumes/Su?rr", mounts)
        # The numeric YAML member reads as its string form and is *visible*
        # as missing — the over-cap int is the only one that can drop.
        self.assertIn("123", body["missing_members"])
        self.assertIn("/gone", body["missing_members"])
        self.assertNotIn("\ud800", resp.text)

    def test_huge_json_int_literal_in_body_is_the_coded_400(self):
        """json.loads raises ValueError (NOT JSONDecodeError) for the whole
        document past the digit cap; the body-parse guard answers 400."""
        raw = b'{"mounts": [' + b"9" * 5000 + b'], "policy": "most-free"}'
        resp = _client().post(
            "/api/storage/pool/plan", content=raw,
            headers={"content-type": "application/json"},
        )
        self.assertEqual(resp.status_code, 400, resp.text[:200])
        self.assertIn("error parsing the body", resp.text)


class PoolVanishedDfDegradeTests(unittest.TestCase):
    """A vanished /bin/df is swallowed by util.sh (rc -1, "not found"), so
    the mount table reads empty.  Pool is a read-only accounting view over
    that table — the honest answer is 200 with no candidates and the
    configured members reported missing, never a 500 (and not a 503: no
    privileged failure path is involved)."""

    def setUp(self):
        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)
        disk_snapshot._df_table.invalidate()
        self.addCleanup(disk_snapshot._df_table.invalidate)

    def test_vanished_df_reads_as_empty_candidates_not_500(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                disk_snapshot, "sh", return_value=(-1, "", "not found")))
            # The "/" fallback row storage_svc synthesises is system-kind and
            # never poolable; keep the pin independent of the host's disk.
            stack.enter_context(mock.patch.object(
                storage_pool_svc, "cfg",
                return_value={"settings": {"storage_pool": {
                    "name": "media", "members": ["/Volumes/Vault"],
                    "policy": "most-free", "min_free_gb": 0,
                }}},
            ))
            resp = _client().get("/api/storage/pool?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertEqual(body["members"], [])
        self.assertEqual(body["missing_members"], ["/Volumes/Vault"])
        self.assertEqual(body["unassigned"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
