"""Pool / RAID leftover sweep: over-cap already-ints, vanished diskutil, numeric YAML.

Three classes of leftover, each pinned by tests that fail on the pre-fix code:

* **Over-cap already-int mutation arguments.**  YAML/plist hex loads uncapped
  (``int(x, 16)`` is exempt from CPython's 4300-digit parse cap), so an
  in-process leftover arrived *already-int* and the bare ``str()`` in
  ``raid_svc._check_devices`` / ``_resolve_set`` / ``remove_member`` raised
  the int->str digit-cap ValueError — a 500 on POST /api/raid/sets, /delete,
  /repair and /members/* where every other junk value gets the coded refusal.
  ``(level or "").strip()`` siblings AttributeError'd the same routes.  The
  fix is a str() probe, not an ``isinstance(str)`` gate: a finite numeric
  leftover keeps behaving as its string form.

* **Vanished diskutil answered the generic 500.**  A diskutil gone between
  the eligibility check and the spawn surfaced as ``admin.failed`` (500,
  "the privileged macOS operation failed") — an answer that sends the
  operator back to a password dialog that cannot help.  The coded 503
  ``raid.diskutil_missing`` now fires only after a fresh disk probe on the
  failure path confirms the binary is gone (the vms/brew/rsync rule); with
  diskutil still on disk, or on a non-spawn-shaped message, the raw failure
  keeps its own shape and the probe never runs.

* **Numeric YAML pool fields silently vanished.**  services.yaml is
  hand-editable, so ``storage_pool: {name: 2026}`` arrives already-int and
  ``storage_pool_svc._text``'s isinstance-shaped gate read it as the default
  "pool"; a numeric member disappeared from the view entirely — not even
  listed as missing.  Both now coerce via the str() probe; only an over-cap
  leftover (whose str() is the digit-cap ValueError) still reads as absent.

The surrogate lookup-key behaviour this page already has (YAML members and
volume mounts scrubbed identically before either becomes a dict key, admin
payload keys scrubbed in ``raid_svc._jsonable``) is pinned so it stays.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from fastapi import HTTPException

from hub import raid_svc, storage_pool_svc, storage_svc
from hub.errors import CODES
from hub.routers import nas_storage

#: Past CPython's default 4300-digit int<->str conversion limit.  A valid
#: Python int — every ``isinstance(x, int)`` fast path accepts it — whose
#: ``str()`` raises the same ValueError ``json.dumps`` would.
_HUGE_INT = int("f" * 5000, 16)

_MIRROR = {
    "uuid": "abcd1234", "name": "Mirror", "level": "mirror",
    "members": [
        {"uuid": "m1", "healthy": True},
        {"uuid": "m2", "healthy": True},
        {"uuid": "m3", "healthy": True},
    ],
    "member_count": 3,
}


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class RaidDigitCapCodedRefusalTests(unittest.TestCase):
    """Over-cap already-int arguments earn the coded refusal, never the raise."""

    def test_huge_int_device_is_the_coded_refusal(self):
        """Pre-fix: str(10**...) ValueError'd POST /api/raid/sets."""
        with self.assertRaises(raid_svc.RaidError) as ctx:
            raid_svc.create_set(
                level="mirror", name="Mirror", filesystem="APFS",
                devices=[_HUGE_INT, "disk5"], confirm=True,
                confirm_phrase="ERASE",
            )
        self.assertEqual(ctx.exception.code, "raid.bad_device")

    def test_huge_int_set_uuid_is_the_coded_refusal(self):
        """Pre-fix: str() ValueError'd POST /api/raid/delete before the regex."""
        with self.assertRaises(raid_svc.RaidError) as ctx:
            raid_svc.delete_set(set_uuid=_HUGE_INT, confirm=True, confirm_phrase="x")
        self.assertEqual(ctx.exception.code, "raid.bad_set")

    def test_huge_int_member_uuid_is_the_coded_refusal(self):
        with mock.patch.object(raid_svc, "list_sets", return_value=[dict(_MIRROR)]):
            with self.assertRaises(raid_svc.RaidError) as ctx:
                raid_svc.remove_member(
                    set_uuid="abcd1234", member_uuid=_HUGE_INT, confirm=True,
                )
        self.assertEqual(ctx.exception.code, "raid.member_not_found")

    def test_huge_int_level_name_and_phrase_are_coded(self):
        """``(level or "").strip()`` AttributeError'd the same routes."""
        cases = (
            ({"level": _HUGE_INT}, "raid.bad_level"),
            ({"name": _HUGE_INT}, "raid.bad_name"),
            ({"confirm_phrase": _HUGE_INT}, "raid.confirm_phrase_mismatch"),
        )
        for overrides, code in cases:
            with self.subTest(code=code):
                kwargs = dict(
                    level="mirror", name="Mirror", filesystem="APFS",
                    devices=["disk4", "disk5"], confirm=True,
                    confirm_phrase="ERASE",
                )
                kwargs.update(overrides)
                with self.assertRaises(raid_svc.RaidError) as ctx:
                    raid_svc.create_set(**kwargs)
                self.assertEqual(ctx.exception.code, code)

    def test_huge_int_delete_phrase_is_coded(self):
        with mock.patch.object(raid_svc, "list_sets", return_value=[dict(_MIRROR)]):
            with self.assertRaises(raid_svc.RaidError) as ctx:
                raid_svc.delete_set(
                    set_uuid="abcd1234", confirm=True, confirm_phrase=_HUGE_INT,
                )
        self.assertEqual(ctx.exception.code, "raid.confirm_name_mismatch")

    def test_finite_numeric_arguments_keep_their_string_form(self):
        """str() probe, not an isinstance gate: ``4`` behaves as ``"4"`` —
        the same coded refusal a junk string device gets."""
        with self.assertRaises(raid_svc.RaidError) as ctx:
            raid_svc._check_devices([4], minimum=1)
        self.assertEqual(ctx.exception.code, "raid.bad_device")
        self.assertEqual(ctx.exception.params.get("device"), "4")
        # A numeric name renders as "123" (a valid set name), so validation
        # proceeds to the confirm gate rather than dropping the value.
        with self.assertRaises(raid_svc.RaidError) as ctx:
            raid_svc.create_set(
                level="mirror", name=123, filesystem="APFS",
                devices=["disk4", "disk5"], confirm=False, confirm_phrase="",
            )
        self.assertEqual(ctx.exception.code, "raid.confirm_required")

    def test_router_funnel_translates_to_the_coded_400(self):
        """Through _raid_call, the entry every /api/raid mutation uses."""
        with (
            mock.patch.object(nas_storage, "require_admin_browser", return_value="admin"),
            mock.patch.object(nas_storage, "client_host", return_value="127.0.0.1"),
            mock.patch.object(nas_storage.audit, "record", lambda *a, **k: {}),
        ):
            with self.assertRaises(HTTPException) as ctx:
                nas_storage._raid_call(
                    raid_svc.delete_set, mock.Mock(), "delete",
                    set_uuid=_HUGE_INT, confirm=True, confirm_phrase="x",
                )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail["code"], "raid.bad_set")


class RaidVanishedDiskutilTests(unittest.TestCase):
    """The vanished-CLI 503 fires only after a fresh disk probe confirms the
    gone binary, and only on the mutation-failure path."""

    VANISHED = {
        "ok": False, "error": "failed",
        "message": "sh: /usr/sbin/diskutil: command not found",
    }

    def _delete(self, admin_result, on_disk):
        probe = mock.Mock(return_value=on_disk)
        with (
            mock.patch.object(raid_svc, "list_sets", return_value=[dict(_MIRROR)]),
            mock.patch.object(raid_svc, "run_admin", return_value=dict(admin_result)),
            mock.patch.object(raid_svc, "invalidate"),
            mock.patch.object(raid_svc, "_diskutil_on_disk", probe),
        ):
            result = raid_svc.delete_set(
                set_uuid="abcd1234", confirm=True, confirm_phrase="Mirror",
            )
        return result, probe

    def test_code_status_is_503(self):
        """A demotion would silently turn "install the tool" back into a
        generic failure (smart.smartctl_missing / backup.tool_missing rule)."""
        self.assertEqual(CODES["raid.diskutil_missing"][0], 503)

    def test_confirmed_gone_classifies(self):
        """Pre-fix this answered the generic 500 ``admin.failed``."""
        result, probe = self._delete(self.VANISHED, on_disk=False)
        self.assertEqual(result, {"ok": False, "error": "diskutil_missing"})
        probe.assert_called_once_with()

    def test_router_funnel_answers_the_coded_503(self):
        with (
            mock.patch.object(nas_storage, "require_admin_browser", return_value="admin"),
            mock.patch.object(nas_storage, "client_host", return_value="127.0.0.1"),
            mock.patch.object(nas_storage.audit, "record", lambda *a, **k: {}),
            mock.patch.object(raid_svc, "list_sets", return_value=[dict(_MIRROR)]),
            mock.patch.object(raid_svc, "run_admin", return_value=dict(self.VANISHED)),
            mock.patch.object(raid_svc, "invalidate"),
            mock.patch.object(raid_svc, "_diskutil_on_disk", return_value=False),
        ):
            with self.assertRaises(HTTPException) as ctx:
                nas_storage._raid_call(
                    raid_svc.delete_set, mock.Mock(), "delete",
                    set_uuid="abcd1234", confirm=True, confirm_phrase="Mirror",
                )
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(ctx.exception.detail["code"], "raid.diskutil_missing")

    def test_still_on_disk_keeps_the_raw_failure(self):
        """execve also ENOENTs for a still-present binary whose loader is
        broken: with diskutil confirmably on disk the raw failure is the
        truth, never the tool-absent 503."""
        result, probe = self._delete(self.VANISHED, on_disk=True)
        self.assertEqual(result["error"], "failed")
        self.assertIn("command not found", result["message"])
        probe.assert_called_once_with()

    def test_non_spawn_message_never_probes(self):
        """A timeout / genuine diskutil exit is not a missing binary: no
        second filesystem look, the original shape survives."""
        result, probe = self._delete(
            {"ok": False, "error": "failed", "message": "sudo timeout"},
            on_disk=False,
        )
        self.assertEqual(result["error"], "failed")
        probe.assert_not_called()

    def test_authorization_failures_are_never_reclassified(self):
        for error in ("password_required", "password_incorrect", "cancelled"):
            with self.subTest(error=error):
                result, probe = self._delete(
                    {"ok": False, "error": error}, on_disk=False,
                )
                self.assertEqual(result["error"], error)
                probe.assert_not_called()

    def test_ok_path_never_probes(self):
        result, probe = self._delete({"ok": True, "message": "deleted"}, on_disk=False)
        self.assertTrue(result["ok"])
        probe.assert_not_called()


_VAULT = {
    "device": "/dev/disk6s1",
    "mount": "/Volumes/Vault",
    "kind": "external",
    "total_gb": 10,
    "used_gb": 1,
    "avail_gb": 9,
    "pct": 10,
    "disk_id": "disk6",
    "filesystem": "apfs",
}


class PoolNumericYamlFieldTests(unittest.TestCase):
    """Hand-edited numeric YAML pool fields behave as their string form."""

    def setUp(self):
        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)

    def _overview(self, pool_cfg: dict, volumes=None) -> dict:
        with (
            mock.patch.object(
                storage_svc, "list_volumes",
                return_value=volumes if volumes is not None else [dict(_VAULT)],
            ),
            mock.patch.object(
                storage_pool_svc, "cfg",
                return_value={"settings": {"storage_pool": pool_cfg}},
            ),
        ):
            return storage_pool_svc.pool_overview(force=True)

    def test_numeric_name_reads_as_its_string_form(self):
        """Pre-fix ``name: 2026`` silently read as the default "pool"."""
        overview = self._overview({
            "name": 2026, "members": ["/Volumes/Vault"], "policy": "most-free",
        })
        _starlette(overview)
        self.assertEqual(overview["name"], "2026")

    def test_numeric_member_is_visible_as_missing_not_vanished(self):
        """Pre-fix a numeric member disappeared entirely — the operator's
        hand-edited row was silently lost from the view."""
        overview = self._overview({
            "name": "pool", "members": ["/Volumes/Vault", 123],
            "policy": "most-free",
        })
        _starlette(overview)
        self.assertEqual([m["mount"] for m in overview["members"]], ["/Volumes/Vault"])
        self.assertEqual(overview["missing_members"], ["123"])

    def test_over_cap_fields_still_read_as_absent(self):
        """Only the unrenderable leftover drops (the digit-cap ValueError is
        exactly what json.dumps would raise on it)."""
        overview = self._overview({
            "name": _HUGE_INT,
            "members": [_HUGE_INT, "/Volumes/Vault"],
            "policy": _HUGE_INT,
        })
        _starlette(overview)
        self.assertEqual(overview["name"], "pool")
        self.assertEqual([m["mount"] for m in overview["members"]], ["/Volumes/Vault"])
        self.assertEqual(overview["missing_members"], [])

    def test_bool_fields_never_ride_the_int_path(self):
        """bool is int's subclass; ``name: true`` must not render as "True"."""
        overview = self._overview({
            "name": True, "members": ["/Volumes/Vault"], "policy": "most-free",
        })
        _starlette(overview)
        self.assertEqual(overview["name"], "pool")


class SurrogateLookupKeyPins(unittest.TestCase):
    """Already-safe behaviour, pinned: mapping keys are scrubbed before they
    become lookup keys, on both sides of every join."""

    def setUp(self):
        storage_pool_svc.invalidate_pool()
        self.addCleanup(storage_pool_svc.invalidate_pool)

    def test_surrogate_member_and_mount_scrub_to_the_same_key(self):
        """A ``\\ud800`` YAML member must still match the identically-broken
        volume mount: both sides scrub before the by_mount lookup."""
        vol = dict(_VAULT, mount="/Volumes/Va\ud800ult")
        with (
            mock.patch.object(storage_svc, "list_volumes", return_value=[vol]),
            mock.patch.object(
                storage_pool_svc, "cfg",
                return_value={"settings": {"storage_pool": {
                    "name": "p", "members": ["/Volumes/Va\ud800ult"],
                    "policy": "most-free",
                }}},
            ),
        ):
            overview = storage_pool_svc.pool_overview(force=True)
        _starlette(overview)
        self.assertEqual(len(overview["members"]), 1)
        self.assertEqual(overview["missing_members"], [])
        self.assertNotIn("\ud800", overview["members"][0]["mount"])

    def test_surrogate_admin_payload_keys_and_values_are_scrubbed(self):
        with (
            mock.patch.object(raid_svc, "list_sets", return_value=[dict(_MIRROR)]),
            mock.patch.object(raid_svc, "run_admin", return_value={
                "ok": True, "me\ud800ssage": "done", "detail": "x\ud800y",
            }),
            mock.patch.object(raid_svc, "invalidate"),
        ):
            out = raid_svc.delete_set(
                set_uuid="abcd1234", confirm=True, confirm_phrase="Mirror",
            )
        _starlette(out)
        self.assertTrue(out["ok"])
        for key, value in out.items():
            self.assertNotIn("\ud800", key)
            if isinstance(value, str):
                self.assertNotIn("\ud800", value)


if __name__ == "__main__":
    unittest.main()
