"""Users-page leftover sweep #3: the identity write path was the gap.

GET /api/users, the panel-accounts CRUD, twofa store parsing and the
session-epoch keys were hardened by the earlier sweeps (huge already-int
uids, surrogate names, int/bool YAML keys, digit-cap ``json.loads``).  What
this sweep found still broken sits behind PUT /api/identity:

* **A vanished scutil answered the rename with ok:true.**  ``sh`` reports a
  FileNotFoundError spawn as the ``(-1, "", "not found")`` sentinel, and
  ``set_identity`` folded that into "Setting ComputerName needs
  administrator privileges: not found" — the rename was silently lost and
  the message blamed the wrong thing.  Now: the sentinel triggers a *fresh*
  on-disk probe of the same path the spawn used (failure path only — a
  successful spawn never pays the stat), and only a really-absent binary
  becomes the coded 503 ``identity.scutil_missing``.  A timeout keeps its
  sentinel, a real scutil authorization exit keeps its message, and a
  still-present CLI that printed exactly "not found" keeps its raw shape.

* **A lone-surrogate computer name sailed past validation.**  The control-
  character check passes ``\ud800`` (ord 0xD800), so the surrogate reached
  the scutil argv and died as a spawn-level UnicodeEncodeError dressed up
  as the administrator-privileges message.  No encoder (argv, Bonjour,
  JSON) can carry a lone surrogate, so it is ``identity.bad_name`` now.

* **A surrogate comment / host_ip was persisted raw into services.yaml.**
  The patch dict itself could never be JSON-encoded again, and every
  consumer of ``settings.host_ip`` had to re-scrub the value forever.
  Both fields now go through the same ``_as_text`` scrub as the read path
  before they become YAML — which also means an over-cap already-int
  comment (YAML hex loads through the uncapped ``int(x, 16)``) degrades to
  "" instead of ValueError-ing ``str()``.

The read paths were already immune and are pinned here as stays-immune:
GET /api/identity degrades every vanished CLI to "" and stays
JSON-encodable, and GET /api/users scrubs surrogate pwd/grp fields.
"""
from __future__ import annotations

import json
import unittest
from collections import namedtuple
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import yaml
from fastapi import HTTPException

from hub import identity_svc, users_svc

#: What a leftover YAML/plist hex literal loads as: ``int(x, 16)`` is exempt
#: from CPython's 4300-digit str<->int cap, so the value exists fine as an
#: int and only explodes at str()/dump time.
HUGE_INT = int("F" * 5000, 16)
SUR = "Lab\ud800"


def _starlette_json(payload) -> bytes:
    """Starlette JSONResponse encoding: allow_nan=False + UTF-8."""
    return json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _code(exc: HTTPException) -> str:
    detail = exc.detail
    return detail["code"] if isinstance(detail, dict) else str(detail)


class SetIdentityVanishedScutilTests(unittest.TestCase):
    """PUT /api/identity: coded 503 only after a fresh failure-path probe."""

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.scutil = Path(tmp.name) / "scutil"
        patcher = mock.patch.object(identity_svc, "SCUTIL", str(self.scutil))
        patcher.start()
        self.addCleanup(patcher.stop)

    def _set(self, sh_result):
        with (
            mock.patch.object(identity_svc, "sh", return_value=sh_result) as spawned,
            mock.patch.object(identity_svc, "update_settings") as saved,
            mock.patch.object(identity_svc, "get_identity", return_value={}),
        ):
            out = identity_svc.set_identity(computer_name="HomeLab")
        return out, spawned, saved

    def test_vanished_scutil_is_a_coded_503_not_a_fake_ok(self):
        """The old shape was ok:true + a message blaming administrator
        privileges — the rename was silently lost."""
        with self.assertRaises(HTTPException) as ctx:
            self._set((-1, "", "not found"))
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(_code(ctx.exception), "identity.scutil_missing")
        _starlette_json(ctx.exception.detail)

    def test_timeout_keeps_its_original_shape(self):
        """A slow scutil is not a missing one; the sentinel differs and the
        disk is never probed."""
        out, _, _ = self._set((-1, "", "timeout"))
        _starlette_json(out)
        self.assertTrue(out["ok"])
        self.assertIn("timeout", out["message"])

    def test_authorization_failure_keeps_its_original_shape(self):
        """A real scutil exit (needs admin) never matches the sentinel."""
        out, _, _ = self._set((1, "", "Operation not permitted"))
        _starlette_json(out)
        self.assertTrue(out["ok"])
        self.assertIn("administrator privileges", out["message"])
        self.assertIn("Operation not permitted", out["message"])

    def test_sentinel_with_cli_still_on_disk_keeps_the_raw_result(self):
        """rc -1 is also what a signal-killed run reports; a still-present
        binary that printed exactly "not found" must not be upgraded to the
        vanished-binary 503 (defer to the fresh probe)."""
        self.scutil.write_text("#!/bin/sh\n")
        out, _, _ = self._set((-1, "", "not found"))
        _starlette_json(out)
        self.assertTrue(out["ok"])
        self.assertIn("not found", out["message"])

    def test_probe_runs_on_the_failure_path_only(self):
        """A successful spawn never pays the stat."""
        with (
            mock.patch.object(identity_svc, "sh", return_value=(0, "", "")),
            mock.patch.object(identity_svc, "update_settings"),
            mock.patch.object(identity_svc, "get_identity", return_value={}),
            mock.patch.object(identity_svc, "_scutil_missing") as probe,
        ):
            out = identity_svc.set_identity(computer_name="HomeLab")
        probe.assert_not_called()
        self.assertTrue(out["ok"])
        self.assertIn("ComputerName set", out["message"])


class SetIdentitySurrogateNameTests(unittest.TestCase):
    def test_lone_surrogate_name_is_bad_name_not_a_spawn_error(self):
        """The control-char check passes ``\\ud800``; the surrogate used to
        reach the scutil argv and die as a spawn-level UnicodeEncodeError
        dressed up as the administrator-privileges message."""
        with (
            mock.patch.object(identity_svc, "sh") as spawned,
            mock.patch.object(identity_svc, "update_settings"),
            mock.patch.object(identity_svc, "get_identity", return_value={}),
        ):
            with self.assertRaises(HTTPException) as ctx:
                identity_svc.set_identity(computer_name=SUR)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(_code(ctx.exception), "identity.bad_name")
        spawned.assert_not_called()
        _starlette_json(ctx.exception.detail)


class SetIdentityScrubbedPersistenceTests(unittest.TestCase):
    def _patched(self, **kwargs) -> dict:
        seen: dict = {}
        with (
            mock.patch.object(
                identity_svc, "update_settings", side_effect=seen.update,
            ),
            mock.patch.object(identity_svc, "get_identity", return_value={}),
        ):
            out = identity_svc.set_identity(**kwargs)
        _starlette_json(out)
        return seen

    def test_surrogate_comment_and_host_ip_are_scrubbed_before_yaml(self):
        """The raw ``\\ud800`` used to land in services.yaml, where the patch
        dict itself could never be JSON-encoded again and every host_ip
        consumer re-scrubbed it forever."""
        seen = self._patched(comment=SUR, host_ip="10.0.0.5\ud800")
        _starlette_json(seen)
        self.assertNotIn("\ud800", seen["server_comment"])
        self.assertNotIn("\ud800", seen["host_ip"])
        self.assertTrue(seen["server_comment"].startswith("Lab"))
        self.assertTrue(seen["host_ip"].startswith("10.0.0.5"))
        yaml.safe_dump(seen, allow_unicode=True)

    def test_over_cap_int_comment_degrades_instead_of_valueerror(self):
        """An already-int past the digit cap blows bare ``str()``; the scrub
        must degrade it, not 500 the save."""
        seen = self._patched(comment=HUGE_INT, host_ip=HUGE_INT)
        _starlette_json(seen)
        self.assertEqual(seen["server_comment"], "")
        self.assertEqual(seen["host_ip"], "")
        yaml.safe_dump(seen)


class GetIdentityVanishedCliStaysImmuneTests(unittest.TestCase):
    def test_every_cli_vanished_degrades_and_encodes(self):
        """The read path keeps degrading: a host with no scutil/sysctl must
        still render the Identification card, never 500 or 503 a GET."""
        with (
            mock.patch.object(identity_svc, "sh", return_value=(-1, "", "not found")),
            mock.patch.object(identity_svc, "cfg", return_value={"settings": {}}),
            mock.patch.object(identity_svc, "time_zone", return_value=""),
            mock.patch.object(identity_svc, "platform_string", return_value="mac"),
            mock.patch.object(identity_svc, "effective_host_ip", return_value=""),
            mock.patch.object(identity_svc, "configured_host", return_value="auto"),
        ):
            ident = identity_svc.get_identity()
        _starlette_json(ident)
        self.assertEqual(ident["computer_name"], "")
        self.assertEqual(ident["local_hostname"], "")


_Pw = namedtuple("Pw", "pw_name pw_passwd pw_uid pw_gid pw_gecos pw_dir pw_shell")


class UsersOverviewSurrogateStaysImmuneTests(unittest.TestCase):
    def test_surrogate_pwd_and_group_fields_are_scrubbed(self):
        """Open Directory leftovers with lone surrogates in every text field
        must cost the surrogate, never the row or the page."""
        entry = _Pw(SUR, "x", 501, 20, "G\ud800ecos", "/Users/\ud800", "/bin/z\ud800sh")
        group = mock.Mock()
        group.gr_name = "st\ud800aff"
        with (
            mock.patch.object(users_svc.pwd, "getpwall", return_value=[entry]),
            mock.patch.object(users_svc.grp, "getgrnam", side_effect=KeyError),
            mock.patch.object(users_svc.grp, "getgrgid", return_value=group),
            mock.patch.object(users_svc.os, "getgrouplist", return_value=[20]),
        ):
            out = users_svc.overview()
        _starlette_json(out)
        row = out["users"][0]
        for field in ("name", "gecos", "home", "shell"):
            self.assertNotIn("\ud800", row[field])
        self.assertEqual(len(row["groups"]), 1)
        self.assertNotIn("\ud800", row["groups"][0])


if __name__ == "__main__":
    unittest.main()
