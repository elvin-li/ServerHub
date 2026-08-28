"""Users-page leftover sweep #12: raising runners at the guarded-answer seams.

Sweep 11 sealed the ``sh``-answer unwrap bombs and the rc liars: every
``rc, out, err`` unpack now reads the real C-level storage through ``_sh3``
and every exit-status probe rides ``_rc_int``.  Driving GET and PUT
/api/shares/acl again through ``create_app()`` +
``TestClient(raise_server_exceptions=False)`` found the class one token to
the *left* of all of that — the guarded-call family the wireguard
(``_sh_answer``), usage and smart sweeps already seal elsewhere:

* **Every spawn seam launders the answer but ran the call bare.**
  ``share_acl_svc`` does not own ``sh`` (tests and tooling patch it), and a
  leftover stub that *raises* instead of answering never reached ``_sh3``
  at all: a raw 500 on GET and PUT /api/shares/acl out of ``read_acl``
  before any gate ran, a raw 500 through the picker half of the GET out of
  both dscl reads in ``local_users`` (one raising per-user RealName read
  cost the whole picker), and a raw 500 on the PUT's owner-run path out of
  ``_run_unprivileged`` one line ahead of its failure funnel.  ``_sh_call``
  now guards the call itself: a raising runner reads as ``(-255, "", "")``
  — nonzero (a runner that cannot answer is never consent to claim
  success), never the ``-1`` spawn sentinel, and with no marker text it can
  never mint the disk-confirmed vanished-CLI 503 — while an honest answer,
  the ``-1`` sentinel included, keeps riding ``_sh3`` untouched.

* **Both escalation seams laundered ``run_admin_sequence``'s answer but
  ran the helper bare.**  A raising leftover stub blew ``set_user_access``
  one token ahead of the ``_plain_result`` launder built for its junk
  *answers* — a raw 500 on PUT /api/shares/acl in place of the coded
  authorization failure, on the owner needs-root retry and on the
  not-owned path alike.  ``_admin_sequence`` reads a raising helper as the
  generic coded failure; honest answers — ``cancelled`` /
  ``password_required`` shapes included — pass through unchanged.

The remaining pins lock the honest flows across the refactor: the ``-1``
sentinel still earns the disk-confirmed 503, and a clean spawn chain still
answers the page.
"""
from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi.testclient import TestClient

from hub import api_keys, audit, auth, config, share_acl_svc, twofa_svc
from hub.app_factory import create_app
from hub.routers import shares as shares_router

PASSWORD = "correct-horse-battery"

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
    return _APP


def _boom(*args, **kwargs):
    raise RuntimeError("raising runner leftover")


# ── unit pins: _sh_call / _admin_sequence ────────────────────────────────────


class ShCallUnitTests(unittest.TestCase):
    def test_raising_runner_reads_as_junk_never_the_sentinel(self):
        """The live leftover: the call itself raised before _sh3 could
        launder anything.  -255 is nonzero and never the -1 sentinel."""
        with mock.patch.object(share_acl_svc, "sh", side_effect=_boom):
            self.assertEqual(
                share_acl_svc._sh_call(["/bin/ls"], timeout=1), (-255, "", "")
            )

    def test_honest_answers_pass_through_untouched(self):
        with mock.patch.object(share_acl_svc, "sh", return_value=(0, "out", "err")):
            self.assertEqual(
                share_acl_svc._sh_call(["/bin/ls"], timeout=1), (0, "out", "err")
            )
        # The vanished-spawn sentinel must survive so the confirmed-vanished
        # 503 classification (marker + fresh disk probe) still works.
        with mock.patch.object(share_acl_svc, "sh", return_value=(-1, "", "not found")):
            self.assertEqual(
                share_acl_svc._sh_call(["/bin/ls"], timeout=1),
                (-1, "", "not found"),
            )

    def test_junk_answers_still_ride_the_sh3_launder(self):
        with mock.patch.object(share_acl_svc, "sh", return_value=None):
            self.assertEqual(
                share_acl_svc._sh_call(["/bin/ls"], timeout=1), (-255, "", "")
            )


class AdminSequenceUnitTests(unittest.TestCase):
    def test_raising_helper_reads_as_the_coded_failure(self):
        with mock.patch.object(
            share_acl_svc.macos_admin, "run_admin_sequence", side_effect=_boom
        ):
            self.assertEqual(
                share_acl_svc._admin_sequence([["/bin/chmod"]]),
                {"ok": False, "error": "failed"},
            )

    def test_honest_answers_keep_riding_plain_result(self):
        for answer, expected in (
            ({"ok": True}, {"ok": True}),
            (
                {"ok": False, "error": "cancelled"},
                {"ok": False, "error": "cancelled"},
            ),
            (None, {"ok": False, "error": "failed"}),
        ):
            with mock.patch.object(
                share_acl_svc.macos_admin,
                "run_admin_sequence",
                return_value=answer,
            ):
                self.assertEqual(
                    share_acl_svc._admin_sequence([["/bin/chmod"]]), expected
                )


# ── app sandbox ──────────────────────────────────────────────────────────────


class _AppSandbox(unittest.TestCase):
    """Scratch services.yaml + data dir; a signed-in admin client per test."""

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        data = self.root / "data"
        data.mkdir()
        self.data = data
        self.yaml_path = self.root / "services.yaml"
        for target, attr, value in (
            (config, "YAML_PATH", self.yaml_path),
            (config, "DATA_DIR", data),
            (config, "BASE", self.root),
            (config, "_LOCK_PATH", data / ".services.yaml.lock"),
            (auth, "SECRET_FILE", data / ".session-secret"),
            (auth, "SETUP_TOKEN_FILE", data / ".setup-token"),
            (auth, "LOCAL_TOKEN_FILE", data / ".local-client-token"),
            (twofa_svc, "STORE_FILE", data / "twofa.json"),
            (api_keys, "STORE_FILE", data / "api-keys.json"),
            (audit, "AUDIT_PATH", data / "auth-audit.jsonl"),
        ):
            patcher = mock.patch.object(target, attr, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(config.reload_cfg)
        auth._secret_cache = None
        auth._login_attempts.clear()
        api_keys._last_seen.clear()
        config.reload_cfg()
        self.client = TestClient(app(), raise_server_exceptions=False)

    def claim_and_sign_in(self) -> None:
        self.yaml_path.write_text(
            "settings:\n"
            "  auth:\n"
            "    enabled: true\n"
            "    username: admin\n"
            f'    password_hash: "{auth.hash_password(PASSWORD)}"\n',
            encoding="utf-8",
        )
        config.reload_cfg()
        auth._login_attempts.clear()
        response = self.client.post(
            "/api/auth/login", json={"username": "admin", "password": PASSWORD}
        )
        self.assertEqual(response.status_code, 200)


# ── GET/PUT /api/shares/acl: a raising sh at every spawn seam ────────────────


def _ls_listing(path: str) -> str:
    return (
        f"drwxr-xr-x+ 5 a0000  staff  160 Aug  4 13:42 {path}\n"
        " 0: user:alice allow read\n"
    )


class ShareAclRaisingRunnerTests(_AppSandbox):
    def setUp(self):
        super().setUp()
        self.share_dir = self.root / "share"
        self.share_dir.mkdir()
        patcher = mock.patch.object(
            shares_router.shares_svc,
            "list_smb_shares",
            return_value=[{"path": str(self.share_dir)}],
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        self.claim_and_sign_in()

    def _fake_sh(self, raising=()):
        """An ``sh`` stub whose named seams *raise* instead of answering."""
        listing = _ls_listing(str(self.share_dir))
        answers = {
            "ls": (0, listing, ""),
            "dscl": (0, "alice 501\n", ""),
            "dscl_read": (0, "RealName: Alice\n", ""),
            "chmod": (0, "", ""),
        }

        def seam(argv):
            if argv[0] == share_acl_svc.LS:
                return "ls"
            if argv[0] == share_acl_svc.DSCL and "-list" in argv:
                return "dscl"
            if argv[0] == share_acl_svc.DSCL:
                return "dscl_read"
            if argv[0] == share_acl_svc.CHMOD:
                return "chmod"
            return ""

        def fake_sh(argv, timeout=0, **kwargs):
            name = seam(argv)
            if name in raising:
                raise RuntimeError(f"raising {name} leftover")
            return answers.get(name, (1, "", ""))

        return fake_sh

    def _get(self, raising=()):
        with mock.patch.object(
            share_acl_svc, "sh", side_effect=self._fake_sh(raising)
        ):
            return self.client.get(
                "/api/shares/acl", params={"path": str(self.share_dir)}
            )

    def test_raising_ls_is_the_coded_read_failure_not_a_raw_500(self):
        """The live leftover: a raising sh blew read_acl before any gate
        ran — an uncoded 500 on GET /api/shares/acl.  The coded read
        failure is the honest answer for a spawn that cannot answer."""
        response = self._get(raising={"ls"})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.acl_read_failed"
        )

    def test_raising_ls_cannot_forge_the_vanished_cli_503(self):
        """A raising runner carries no marker text and never the -1
        sentinel, so it cannot mint acl_tool_missing even with the tool
        honestly gone from disk."""
        with mock.patch.object(share_acl_svc, "_tool_on_disk", return_value=False):
            response = self._get(raising={"ls"})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.acl_read_failed"
        )

    def test_raising_dscl_list_degrades_to_the_empty_picker(self):
        """The same raising stub out of local_users used to 500 the whole
        GET; it now costs the picker only — the ACL half still answers."""
        response = self._get(raising={"dscl"})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["users"], [])
        self.assertIn("alice", [e["name"] for e in payload["entries"]])

    def test_raising_realname_read_costs_the_real_name_only(self):
        """One raising per-user RealName read used to cost the whole picker
        as a raw 500; the row now keeps its username."""
        response = self._get(raising={"dscl_read"})
        self.assertEqual(response.status_code, 200)
        rows = response.json()["users"]
        self.assertEqual([u["username"] for u in rows], ["alice"])
        self.assertEqual(rows[0]["real_name"], "")

    def test_clean_spawn_chain_still_answers_the_page(self):
        response = self._get()
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("alice", [u["username"] for u in payload["users"]])
        self.assertIn("alice", [e["name"] for e in payload["entries"]])

    # ── PUT: raising chmod / raising run_admin_sequence ──────────────────────

    def _put(self, raising=()):
        # The scratch share directory is owned by this process, so the PUT
        # takes the owner-run path straight into _run_unprivileged.
        with mock.patch.object(
            share_acl_svc, "sh", side_effect=self._fake_sh(raising)
        ):
            return self.client.put(
                "/api/shares/acl",
                json={
                    "path": str(self.share_dir),
                    "username": "alice",
                    "level": "readwrite",
                },
            )

    def test_raising_chmod_is_the_coded_failure_never_success(self):
        """The live leftover: a raising sh blew _run_unprivileged one line
        ahead of its failure funnel — a raw 500 on PUT /api/shares/acl."""
        response = self._put(raising={"chmod"})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_failed"
        )

    def test_raising_chmod_cannot_forge_the_vanished_cli_503(self):
        with mock.patch.object(share_acl_svc, "_tool_on_disk", return_value=False):
            response = self._put(raising={"chmod"})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_failed"
        )

    def test_honest_vanished_chmod_still_earns_the_coded_503(self):
        """The guard must not cost the confirmed-vanished classification:
        the -1 sentinel plus the marker plus the fresh disk probe still
        ride _sh_call untouched."""
        fake = self._fake_sh()

        def vanished(argv, timeout=0, **kwargs):
            if argv[0] == share_acl_svc.CHMOD:
                return (-1, "", "not found")
            return fake(argv, timeout=timeout, **kwargs)

        with (
            mock.patch.object(share_acl_svc, "sh", side_effect=vanished),
            mock.patch.object(share_acl_svc, "_tool_on_disk", return_value=False),
        ):
            response = self.client.put(
                "/api/shares/acl",
                json={
                    "path": str(self.share_dir),
                    "username": "alice",
                    "level": "readwrite",
                },
            )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.acl_tool_missing"
        )

    def _put_needs_root(self, admin):
        """Drive the owner needs-root retry into the admin helper *admin*."""
        fake = self._fake_sh()

        def refused(argv, timeout=0, **kwargs):
            if argv[0] == share_acl_svc.CHMOD:
                return (1, "", "chmod: Operation not permitted")
            return fake(argv, timeout=timeout, **kwargs)

        with (
            mock.patch.object(share_acl_svc, "sh", side_effect=refused),
            mock.patch.object(
                share_acl_svc.macos_admin, "run_admin_sequence", admin
            ),
        ):
            return self.client.put(
                "/api/shares/acl",
                json={
                    "path": str(self.share_dir),
                    "username": "alice",
                    "level": "readwrite",
                },
            )

    def test_raising_admin_helper_is_the_coded_failure_not_a_raw_500(self):
        """The live leftover: a raising run_admin_sequence stub blew the
        escalation seam one token ahead of _plain_result — a raw 500 on
        PUT /api/shares/acl in place of the coded authorization failure."""
        response = self._put_needs_root(mock.Mock(side_effect=_boom))
        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_failed"
        )

    def test_honest_cancelled_admin_answer_keeps_its_coded_409(self):
        """Guarding the call must not flatten honest refusals: a cancelled
        authorization still answers its own coded shape."""
        response = self._put_needs_root(
            mock.Mock(return_value={"ok": False, "error": "cancelled"})
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_cancelled"
        )


if __name__ == "__main__":
    unittest.main()
