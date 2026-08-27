"""Seventh Account-domain sweep: the token files' *parent* directory.

account3/4/5 hardened the member-account CRUD and the sign-in surface,
account6 pinned the role gates and the config-node corners, and login7
pinned FIFOs squatting the three mode-0600 token files ``hub.auth`` owns.
Every one of those leftovers is a bad *file*.  This sweep re-hunted the same
surfaces asking the next question — what if the ``data/`` **directory** the
token has to be written into is the leftover — and found the last live 500s
on the first-run and menu-bar paths:

* **fixed** — ``_persistent_token`` minted its replacement token with an
  exclusive ``os.open``, whose only guarded failure was ``FileExistsError``.
  A ``data/`` the panel cannot write (a restored backup left 0500, a
  read-only volume, an installation copied without its ownership) therefore
  raised ``PermissionError`` — a raw 500 out of GET /api/auth/setup-token
  and POST /api/auth/setup, i.e. an installation that could not be claimed
  at all, with no coded status saying why.  The same raise reached every
  protected route a direct-loopback client called with the menu-bar header,
  because ``require_auth`` → ``local_client_authenticated`` reads
  ``.local-client-token`` through this helper.
* **fixed** — the ``path.parent.mkdir(parents=True, exist_ok=True)`` one line
  above was unguarded too, so a leftover *regular file* squatting ``data/``
  itself (``exist_ok`` only forgives an existing *directory*) raised
  ``FileExistsError`` before the open was even attempted — the same 500 set,
  reachable no matter the directory permissions.
* **fixed** — ``path.chmod(0o600)`` on the *read* branch caught nothing, so a
  token that had read back perfectly was thrown away by a ``PermissionError``
  from the mode fix-up on a read-only volume.
* **fixed** — ``consume_setup_token`` caught only ``FileNotFoundError``.  It
  runs *after* ``set_password`` has committed the credential, so its
  ``PermissionError`` on a read-only ``data/`` answered 500 on a claim that
  had already succeeded: the administrator existed, ``setup_required()`` was
  already False (so no later claim could ever succeed either), and the
  browser got neither the session cookie nor a coded reason.

The fix is the degrade ``_secret()`` two screens down already applied to the
same shapes: every branch answers, and a token that cannot be persisted is
minted process-locally and cached per path — so the token GET
/api/auth/setup-token discloses is still the token POST /api/auth/setup
accepts, and a wrong one is still refused.

The rest of the module pins the corners this sweep drove and found already
immune, so a later change cannot quietly reopen them: hostile YAML shapes in
``settings.auth`` that earlier waves did not send (recursive anchors,
``!!timestamp`` / ``!!binary`` names, ``!!set`` collections, bool/null/float
epoch keys), poisoned audit trails on the sign-in path, and torn or
duplicated session-cookie transports.  Everything is driven through
``create_app()`` + ``TestClient`` with ``raise_server_exceptions=False``.
"""
from __future__ import annotations

import json
import os
import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi.testclient import TestClient

from hub import api_keys, audit, auth, config, twofa_svc
from hub.app_factory import create_app

PASSWORD = "correct-horse-battery"
MEMBER_PASSWORD = "kid-password-12"
NEW_PASSWORD = "brand-new-pass-1"
HUGE_LITERAL = "9" * 4400
HEX_HUGE = "0x" + "F" * 5000

#: A read-only directory does not stop root, so the permission-shaped pins
#: are skipped there.  The "data/ is a regular file" shapes below cover the
#: same two code paths for any uid, so the sweep keeps its teeth under root.
_NOT_ROOT = hasattr(os, "geteuid") and os.geteuid() != 0

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
    return _APP


class _AppSandbox(unittest.TestCase):
    """Scratch services.yaml + data dir; a fresh client per test."""

    #: Whether setUp creates ``data/`` as a directory.  The token-store pins
    #: below flip this to plant a regular file in its place.
    data_is_dir = True

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        data = self.root / "data"
        if self.data_is_dir:
            data.mkdir()
        else:
            data.write_text("leftover file squatting data/", encoding="utf-8")
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
        # Restore the mode unconditionally so TemporaryDirectory can clean up
        # after a test that made data/ read-only.
        self.addCleanup(self._restore_data_mode)
        self.addCleanup(config.reload_cfg)
        self.addCleanup(auth._token_fallbacks.clear)
        auth._secret_cache = None
        auth._token_fallbacks.clear()
        auth._login_attempts.clear()
        api_keys._last_seen.clear()
        self.write_config("settings:\n  auth:\n    enabled: true\n")
        self.client = TestClient(app(), raise_server_exceptions=False)

    def _restore_data_mode(self):
        try:
            if self.data.is_dir():
                os.chmod(self.data, 0o700)
        except OSError:
            pass

    def write_config(self, text: str) -> None:
        self.yaml_path.write_text(text, encoding="utf-8", errors="surrogatepass")
        config.reload_cfg()

    def claim(self) -> None:
        auth.set_password(PASSWORD, "admin")

    def freeze_data_dir(self) -> None:
        """Make ``data/`` unwritable, the shape a restored backup leaves."""
        os.chmod(self.data, 0o500)

    def loopback(self):
        """Answer the direct-loopback probe True, as a browser on the Mac."""
        return mock.patch.object(auth, "is_direct_loopback", lambda request: True)

    def sign_in(self, client=None, username="admin", password=PASSWORD):
        auth._login_attempts.clear()
        response = (client or self.client).post(
            "/api/auth/login", json={"username": username, "password": password}
        )
        self.assertEqual(response.status_code, 200, response.text[:300])
        return response

    def assertJsonEncodable(self, response):
        """Starlette already encoded it; re-encode to prove no inf/surrogate."""
        json.dumps(response.json(), ensure_ascii=False, allow_nan=False)

    def assertCode(self, response, status: int, code: str):
        self.assertEqual(response.status_code, status, response.text[:300])
        self.assertEqual(response.json()["detail"]["code"], code)

    def assertNotServerError(self, response):
        """No raw 500: either below 500, or a *coded* dependency status."""
        if response.status_code < 500:
            return
        detail = response.json().get("detail")
        self.assertIsInstance(detail, dict, response.text[:300])
        self.assertTrue(detail.get("code"), response.text[:300])


@unittest.skipUnless(_NOT_ROOT, "a read-only directory does not stop root")
class UnwritableDataDirSetupTokenTests(_AppSandbox):
    """An unwritable ``data/`` must not 500 the first-run claim."""

    def test_setup_token_disclosure_answers_and_is_stable(self):
        """The exclusive create raised PermissionError straight out of the route.

        Both calls must also answer the *same* token: a fresh value per call
        would mean the token shown in the setup form could never satisfy the
        claim that follows it.
        """
        self.freeze_data_dir()
        with self.loopback():
            first = self.client.get("/api/auth/setup-token")
            second = self.client.get("/api/auth/setup-token")
        self.assertEqual(first.status_code, 200, first.text[:300])
        self.assertEqual(second.status_code, 200, second.text[:300])
        token = first.json()["setup_token"]
        self.assertTrue(token)
        self.assertEqual(second.json()["setup_token"], token)
        # Nothing was persisted — the point of the degrade is that it answers
        # without writing — so the frozen directory is still empty.
        self.assertFalse((self.data / ".setup-token").exists())

    def test_disclosed_token_still_completes_the_claim(self):
        self.freeze_data_dir()
        with self.loopback():
            token = self.client.get("/api/auth/setup-token").json()["setup_token"]
            claimed = self.client.post(
                "/api/auth/setup",
                json={"username": "admin", "password": NEW_PASSWORD,
                      "setup_token": token},
            )
        self.assertEqual(claimed.status_code, 200, claimed.text[:300])
        self.assertTrue(claimed.json()["ok"])
        self.assertFalse(auth.setup_required())
        # The claim handed out a real session, not just a 200.
        self.assertTrue(claimed.cookies.get(auth.COOKIE_NAME))

    def test_a_wrong_token_is_still_refused_in_always_mode(self):
        """The degrade must not become "any token claims the panel"."""
        self.write_config(
            "settings:\n  auth:\n    enabled: true\n    setup_token_mode: always\n"
        )
        self.freeze_data_dir()
        with self.loopback():
            token = self.client.get("/api/auth/setup-token").json()["setup_token"]
            rejected = self.client.post(
                "/api/auth/setup",
                json={"username": "admin", "password": NEW_PASSWORD,
                      "setup_token": "not-the-token"},
            )
            self.assertCode(rejected, 403, "auth.bad_setup_token")
            self.assertTrue(auth.setup_required())
            accepted = self.client.post(
                "/api/auth/setup",
                json={"username": "admin", "password": NEW_PASSWORD,
                      "setup_token": token},
            )
        self.assertEqual(accepted.status_code, 200, accepted.text[:300])
        self.assertFalse(auth.setup_required())

    def test_claim_consuming_an_unremovable_token_stays_200(self):
        """``consume_setup_token`` ran after the credential was committed.

        Its PermissionError answered 500 on a claim that had *already*
        succeeded — administrator created, ``setup_required()`` already
        False, so no retry could ever succeed — and never set the cookie.
        """
        (self.data / ".setup-token").write_text("real-setup-token\n", encoding="utf-8")
        self.freeze_data_dir()
        with self.loopback():
            # Loopback in auto mode does not have to present the token, so
            # the claim reaches consume_setup_token() on its success path.
            claimed = self.client.post(
                "/api/auth/setup",
                json={"username": "admin", "password": NEW_PASSWORD},
            )
        self.assertEqual(claimed.status_code, 200, claimed.text[:300])
        self.assertTrue(claimed.json()["ok"])
        self.assertFalse(auth.setup_required())
        self.assertTrue(claimed.cookies.get(auth.COOKIE_NAME))
        # The file could not be removed, which is exactly why it must not
        # cost the response; the closed window is what revokes it.
        self.assertTrue((self.data / ".setup-token").exists())
        with self.loopback():
            again = self.client.post(
                "/api/auth/setup",
                json={"username": "someone-else", "password": NEW_PASSWORD,
                      "setup_token": "real-setup-token"},
            )
        self.assertCode(again, 409, "auth.already_setup")

    def test_readable_token_survives_a_failing_chmod(self):
        """The read branch's unguarded ``chmod`` discarded a good token.

        The shape is a read-only *mount* (EROFS), not a read-only directory:
        owning the inode is enough to chmod it inside a 0500 parent, so the
        failure has to come from the filesystem.  ``Path.chmod`` is patched
        for exactly that syscall, which is what the panel meets on a config
        volume remounted read-only after an unclean shutdown.
        """
        token_file = self.data / ".setup-token"
        token_file.write_text("real-setup-token\n", encoding="utf-8")
        real_chmod = Path.chmod

        def refuse_chmod(self_path, mode, **kwargs):
            if str(self_path) == str(token_file):
                raise PermissionError(30, "Read-only file system")
            return real_chmod(self_path, mode, **kwargs)

        with mock.patch.object(Path, "chmod", refuse_chmod), self.loopback():
            response = self.client.get("/api/auth/setup-token")
        self.assertEqual(response.status_code, 200, response.text[:300])
        # The token on disk is still the one the claim will be checked against.
        self.assertEqual(response.json()["setup_token"], "real-setup-token")

    def test_unreadable_token_beside_a_frozen_parent_is_stable(self):
        """Unlink fails too, so the minted fallback must be remembered."""
        path = self.data / ".setup-token"
        path.write_text("real-setup-token\n", encoding="utf-8")
        os.chmod(path, 0o000)
        self.addCleanup(os.chmod, path, 0o600)
        self.freeze_data_dir()
        with self.loopback():
            first = self.client.get("/api/auth/setup-token")
            second = self.client.get("/api/auth/setup-token")
            self.assertEqual(first.status_code, 200, first.text[:300])
            token = first.json()["setup_token"]
            self.assertTrue(token)
            self.assertEqual(second.json()["setup_token"], token)
            claimed = self.client.post(
                "/api/auth/setup",
                json={"username": "admin", "password": NEW_PASSWORD,
                      "setup_token": token},
            )
        self.assertEqual(claimed.status_code, 200, claimed.text[:300])
        self.assertFalse(auth.setup_required())


@unittest.skipUnless(_NOT_ROOT, "a read-only directory does not stop root")
class UnwritableDataDirSessionTests(_AppSandbox):
    """A claimed panel on an unwritable ``data/`` keeps answering coded."""

    def test_local_client_header_is_coded_401_not_500(self):
        """``require_auth`` reads .local-client-token through the same helper.

        Every protected route a direct-loopback client called with the
        menu-bar header inherited the mint's PermissionError as a raw 500 —
        with no credential of any kind.
        """
        self.claim()
        self.freeze_data_dir()
        auth._secret_cache = None
        with self.loopback():
            # /api/health is deliberately excluded: the unauthenticated
            # liveness route is registered ahead of the protected router and
            # never reaches require_auth.
            for path in ("/api/status", "/api/launcher", "/api/maintenance"):
                with self.subTest(path=path):
                    response = self.client.get(
                        path, headers={auth.LOCAL_TOKEN_HEADER: "junk-token"}
                    )
                    self.assertCode(response, 401, "auth.login_required")

    def test_signed_in_account_surfaces_stay_usable(self):
        """Sign-in, the account table and logout must survive a frozen data/."""
        self.claim()
        self.freeze_data_dir()
        auth._secret_cache = None
        self.sign_in()
        for path in ("/api/auth/status", "/api/auth/accounts", "/api/auth/totp",
                     "/api/audit/auth"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200, response.text[:300])
                self.assertJsonEncodable(response)
        auth._login_attempts.clear()
        created = self.client.post(
            "/api/auth/accounts",
            json={"username": "kid", "password": MEMBER_PASSWORD},
        )
        self.assertEqual(created.status_code, 200, created.text[:300])
        logout = self.client.post("/api/auth/logout")
        self.assertEqual(logout.status_code, 200, logout.text[:300])


class DataDirIsAFileTokenTests(_AppSandbox):
    """A leftover regular *file* squatting ``data/`` — no uid escapes this.

    ``mkdir(parents=True, exist_ok=True)`` only forgives an existing
    *directory*, so this raised FileExistsError before the open was even
    attempted: the same 500 set as the read-only case, and reachable as
    root too.
    """

    data_is_dir = False

    def test_setup_token_disclosure_answers_and_is_stable(self):
        with self.loopback():
            first = self.client.get("/api/auth/setup-token")
            second = self.client.get("/api/auth/setup-token")
        self.assertEqual(first.status_code, 200, first.text[:300])
        token = first.json()["setup_token"]
        self.assertTrue(token)
        self.assertEqual(second.json()["setup_token"], token)
        # data/ is untouched: still the leftover file, never a directory.
        self.assertTrue(self.data.is_file())

    def test_disclosed_token_still_completes_the_claim(self):
        with self.loopback():
            token = self.client.get("/api/auth/setup-token").json()["setup_token"]
            claimed = self.client.post(
                "/api/auth/setup",
                json={"username": "admin", "password": NEW_PASSWORD,
                      "setup_token": token},
            )
        self.assertEqual(claimed.status_code, 200, claimed.text[:300])
        self.assertFalse(auth.setup_required())
        self.assertTrue(claimed.cookies.get(auth.COOKIE_NAME))

    def test_a_wrong_token_is_still_refused(self):
        self.write_config(
            "settings:\n  auth:\n    enabled: true\n    setup_token_mode: always\n"
        )
        with self.loopback():
            rejected = self.client.post(
                "/api/auth/setup",
                json={"username": "admin", "password": NEW_PASSWORD,
                      "setup_token": "not-the-token"},
            )
        self.assertCode(rejected, 403, "auth.bad_setup_token")
        self.assertTrue(auth.setup_required())

    def test_local_client_header_is_coded_401_not_500(self):
        self.claim()
        auth._secret_cache = None
        with self.loopback():
            response = self.client.get(
                "/api/status", headers={auth.LOCAL_TOKEN_HEADER: "junk-token"}
            )
        self.assertCode(response, 401, "auth.login_required")

    def test_login_and_status_stay_usable(self):
        self.claim()
        auth._secret_cache = None
        self.sign_in()
        status = self.client.get("/api/auth/status")
        self.assertEqual(status.status_code, 200, status.text[:300])
        self.assertJsonEncodable(status)
        self.assertTrue(status.json()["authenticated"])


class LeftoverNodeAtTokenPathTests(_AppSandbox):
    """A directory / nested tree occupying a token path, driven over HTTP.

    login7 pinned the FIFO shape; these are the sibling nodes
    ``_drop_leftover_nonfile`` handles.  The empty-directory and symlink-loop
    cases were already immune; the *non-empty* directory was not — ``rmdir``
    cannot clear it, so the mint fell through to the same unguarded
    exclusive-create this sweep fixed.
    """

    def test_directory_at_setup_token_does_not_500_the_claim(self):
        (self.data / ".setup-token").mkdir()
        with self.loopback():
            disclosed = self.client.get("/api/auth/setup-token")
            self.assertEqual(disclosed.status_code, 200, disclosed.text[:300])
            claimed = self.client.post(
                "/api/auth/setup",
                json={"username": "admin", "password": NEW_PASSWORD},
            )
        self.assertEqual(claimed.status_code, 200, claimed.text[:300])
        self.assertFalse(auth.setup_required())

    def test_nonempty_directory_at_local_token_is_coded_401(self):
        """``rmdir`` cannot clear a non-empty tree, so the mint must degrade."""
        self.claim()
        squat = self.data / ".local-client-token"
        squat.mkdir()
        (squat / "junk").write_text("x", encoding="utf-8")
        with self.loopback():
            response = self.client.get(
                "/api/status", headers={auth.LOCAL_TOKEN_HEADER: "junk-token"}
            )
        self.assertCode(response, 401, "auth.login_required")

    def test_nonempty_directory_at_setup_token_still_answers(self):
        squat = self.data / ".setup-token"
        squat.mkdir()
        (squat / "junk").write_text("x", encoding="utf-8")
        with self.loopback():
            first = self.client.get("/api/auth/setup-token")
            second = self.client.get("/api/auth/setup-token")
        self.assertEqual(first.status_code, 200, first.text[:300])
        token = first.json()["setup_token"]
        self.assertTrue(token)
        self.assertEqual(second.json()["setup_token"], token)

    def test_symlink_loop_at_setup_token_still_answers(self):
        path = self.data / ".setup-token"
        path.symlink_to(path)
        with self.loopback():
            response = self.client.get("/api/auth/setup-token")
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertTrue(response.json()["setup_token"])

    def test_session_secret_directory_does_not_500_login(self):
        self.claim()
        (self.data / ".session-secret").mkdir()
        auth._secret_cache = None
        response = self.client.post(
            "/api/auth/login", json={"username": "admin", "password": PASSWORD}
        )
        self.assertEqual(response.status_code, 200, response.text[:300])
        # The process-local key signs a cookie that verifies in this process.
        status = self.client.get("/api/auth/status")
        self.assertTrue(status.json()["authenticated"])


class HostileYamlAuthShapeTests(_AppSandbox):
    """Stays-immune: ``settings.auth`` YAML shapes earlier waves never sent.

    Recursive anchors, non-string scalar tags and ``!!set`` collections all
    survive ``yaml.safe_load`` and reach ``accounts()`` / ``_clean_epochs``
    / the account writers.  Each corner must answer a coded status or a
    JSON-encodable 200, never a raw 500 — and the mutations must still land.
    """

    def _shapes(self) -> dict[str, str]:
        admin_hash = auth.hash_password(PASSWORD)
        member_hash = auth.hash_password(MEMBER_PASSWORD)
        head = (
            "settings:\n  auth:\n    enabled: true\n    username: admin\n"
            f'    password_hash: "{admin_hash}"\n'
        )
        member = (
            "      - username: kid\n"
            f'        password_hash: "{member_hash}"\n'
            "        role: member\n"
        )
        return {
            # A YAML anchor pointing the row's resources at the accounts list
            # it lives in: the walk sees a list of dicts where it expects ids.
            "recursive accounts anchor":
                head + "    accounts: &a\n" + member + "        resources: *a\n",
            # The auth block containing itself — every reader that copies it
            # (``dict(auth)``, ``_renderable``) meets the cycle.
            "recursive auth block":
                "settings:\n  auth: &auth\n    enabled: true\n    username: admin\n"
                f'    password_hash: "{admin_hash}"\n    self: *auth\n'
                "    accounts:\n" + member + "        resources: []\n",
            # A cyclic session_epochs mapping, which every auth write rewrites.
            "recursive session_epochs":
                head + "    accounts:\n" + member + "        resources: []\n"
                + "    session_epochs: &e\n      admin: 1\n      loop: *e\n",
            # A row whose own key aliases the row: _account_rows copies it.
            "self-aliasing accounts row":
                head + "    accounts:\n      - &row\n        username: kid\n"
                f'        password_hash: "{member_hash}"\n'
                "        role: member\n        resources: []\n        again: *row\n",
            # Non-string scalar tags where a name is expected.
            "timestamp legacy username":
                "settings:\n  auth:\n    enabled: true\n"
                "    username: !!timestamp 2024-01-01\n"
                f'    password_hash: "{admin_hash}"\n',
            "binary legacy username":
                "settings:\n  auth:\n    enabled: true\n"
                "    username: !!binary |\n      /w==\n"
                f'    password_hash: "{admin_hash}"\n',
            # !!set loads as a dict, so the list-shaped readers see a mapping.
            "set accounts": head + "    accounts: !!set\n      ? kid\n",
            "set resources":
                head + "    accounts:\n" + member
                + "        resources: !!set\n          ? plex\n",
            # Epoch keys YAML renders as non-strings.
            "bool / null / float epoch keys":
                head + "    accounts:\n" + member + "        resources: []\n"
                + "    session_epochs:\n      true: 3\n      null: 4\n      1.5: 5\n",
            "date epoch value":
                head + "    accounts:\n" + member + "        resources: []\n"
                + "    session_epochs:\n      admin: 2024-01-01\n",
            # Over-cap hex ints in every auth slot at once: YAML parses these
            # through ``int(x, 16)``, which the digit cap does not bound.
            "over-cap hex everywhere":
                "settings:\n  auth:\n    enabled: true\n    username: admin\n"
                f'    password_hash: "{admin_hash}"\n'
                f"    setup_token_mode: {HEX_HUGE}\n"
                f"    session_epochs:\n      admin: {HEX_HUGE}\n"
                f"      ? {HEX_HUGE}\n      : 1\n"
                "    accounts:\n" + member + f"        resources: [{HEX_HUGE}]\n",
        }

    def test_every_shape_keeps_the_account_surface_coded(self):
        for label, text in self._shapes().items():
            with self.subTest(shape=label):
                self.setUp()  # fresh sandbox per shape
                self.write_config(text)
                client = self.client
                status = client.get("/api/auth/status")
                self.assertEqual(status.status_code, 200, status.text[:300])
                self.assertJsonEncodable(status)
                auth._login_attempts.clear()
                login = client.post(
                    "/api/auth/login",
                    json={"username": "admin", "password": PASSWORD},
                )
                self.assertNotServerError(login)
                if login.status_code != 200 or not login.json().get("ok"):
                    # A shape that destroys the admin credential is allowed to
                    # refuse the sign-in; it must simply not 500.
                    continue
                for path in ("/api/auth/accounts", "/api/auth/status",
                             "/api/audit/auth", "/api/services"):
                    response = client.get(path)
                    self.assertEqual(response.status_code, 200,
                                     f"{path}: {response.text[:300]}")
                    self.assertJsonEncodable(response)
                for method, path, body in (
                    ("POST", "/api/auth/accounts",
                     {"username": "z9", "password": "x" * 12, "resources": []}),
                    ("PUT", "/api/auth/accounts/kid/resources",
                     {"resources": ["plex"]}),
                    ("POST", "/api/auth/accounts/kid/password",
                     {"new_password": "y" * 12}),
                    ("POST", "/api/auth/change-password",
                     {"username": "admin", "current_password": PASSWORD,
                      "new_password": PASSWORD + "q"}),
                    ("DELETE", "/api/auth/accounts/kid", None),
                ):
                    auth._login_attempts.clear()
                    response = client.request(method, path, json=body)
                    self.assertNotServerError(response)
                logout = client.post("/api/auth/logout")
                self.assertEqual(logout.status_code, 200, logout.text[:300])

    def test_recursive_epochs_logout_still_revokes(self):
        """The cycle must not silently cost the revocation logout promises."""
        admin_hash = auth.hash_password(PASSWORD)
        self.write_config(
            "settings:\n  auth:\n    enabled: true\n    username: admin\n"
            f'    password_hash: "{admin_hash}"\n'
            "    session_epochs: &e\n      admin: 1\n      loop: *e\n"
        )
        self.sign_in()
        pre = self.client.get("/api/auth/status")
        self.assertTrue(pre.json()["authenticated"])
        logout = self.client.post("/api/auth/logout")
        self.assertEqual(logout.status_code, 200, logout.text[:300])
        post = self.client.get("/api/auth/status")
        self.assertEqual(post.status_code, 200, post.text[:300])
        self.assertFalse(post.json()["authenticated"])


class PoisonedAuditTrailOnSignInTests(_AppSandbox):
    """Stays-immune: a leftover ``auth-audit.jsonl`` on the sign-in path.

    ``record()`` swallows its own failures, but the *reader* is an HTTP route
    and the shaping runs ahead of the swallow — so each of these has to keep
    GET /api/audit/auth at a JSON-encodable 200 *and* keep the sign-in it
    would be logging at its own status.
    """

    TRAILS = {
        "over-cap int row": HUGE_LITERAL + "\n",
        "over-cap int field": '{"event": "e", "n": ' + HUGE_LITERAL + "}\n",
        "over-cap int key": '{"event": "e", "' + HUGE_LITERAL + '": 1}\n',
        "inf / nan literals": '{"event": "e", "a": 1e999, "b": NaN, "c": Infinity}\n',
        "lone surrogate field": '{"event": "e", "u": "\\ud800"}\n',
        "deeply nested row": '{"a": ' * 200 + "1" + "}" * 200 + "\n",
        "over-cap float digits": '{"event": "e", "f": ' + "1" * 5000 + ".5}\n",
        "non-mapping rows": '[1, 2, 3]\n"text"\nnull\ntrue\n',
        "NUL in a field": '{"event": "e\\u0000x"}\n',
        "torn final line": '{"event": "ok"}\n{"event": "torn", "x": \n',
        "byte-order mark": '\ufeff{"event": "e"}\n',
    }

    def test_reader_and_sign_in_stay_coded(self):
        for label, text in self.TRAILS.items():
            with self.subTest(trail=label):
                self.setUp()
                self.claim()
                self.sign_in()
                audit.AUDIT_PATH.write_text(
                    text, encoding="utf-8", errors="surrogatepass"
                )
                for query in ("", "?limit=1", "?limit=500"):
                    response = self.client.get("/api/audit/auth" + query)
                    self.assertEqual(response.status_code, 200,
                                     response.text[:300])
                    self.assertJsonEncodable(response)
                # A failed sign-in appends to the poisoned trail.
                auth._login_attempts.clear()
                failed = self.client.post(
                    "/api/auth/login",
                    json={"username": "admin", "password": "wrong-password"},
                )
                self.assertCode(failed, 401, "auth.bad_credentials")
                # …and the reader still answers afterwards.
                after = self.client.get("/api/audit/auth")
                self.assertEqual(after.status_code, 200, after.text[:300])
                self.assertJsonEncodable(after)

    def test_junk_limit_values_are_coded_not_500(self):
        self.claim()
        self.sign_in()
        for query in ("limit=" + HUGE_LITERAL, "limit=%ED%A0%80", "limit=1e999",
                      "limit=0x10", "limit=%00", "limit=inf", "limit=+5",
                      "limit=1&limit=" + HUGE_LITERAL):
            with self.subTest(query=query):
                response = self.client.get("/api/audit/auth?" + query)
                self.assertLess(response.status_code, 500, response.text[:300])
                self.assertJsonEncodable(response)


class TornSessionCookieTransportTests(_AppSandbox):
    """Stays-immune: torn / duplicated ``Cookie`` headers on the auth routes.

    The header is parsed before any of our code runs, so a duplicated or
    attribute-bearing value decides which token ``verify_session`` sees.  Each
    must answer coded, and a good cookie must keep working beside junk.
    """

    PATHS = (
        "/api/auth/status",
        "/api/auth/accounts",
        "/api/auth/totp",
        "/api/audit/auth",
    )

    def _cookie_variants(self, good: str) -> dict[str, str]:
        name = auth.COOKIE_NAME
        return {
            "good then junk": f"{name}={good}; {name}=junk",
            "junk then good": f"{name}=junk; {name}={good}",
            "quoted good": f'{name}="{good}"',
            "spaced": f" {name} = {good} ",
            "with attributes": f"{name}={good}; Path=/; HttpOnly",
            "empty value": f"{name}=",
            "no equals sign": name,
            "truncated good": f"{name}={good[:-5]}",
            "trailing separator": f"{name}={good}.",
            "extra b64 padding": f"{name}={good}==",
            "pair flood": ("a=b; " * 4000) + f"{name}={good}",
        }

    def test_every_variant_answers_coded(self):
        self.claim()
        good = self.sign_in().cookies.get(auth.COOKIE_NAME)
        for label, cookie in self._cookie_variants(good).items():
            header = [(b"cookie", cookie.encode("latin-1", "replace"))]
            for path in self.PATHS:
                with self.subTest(cookie=label, path=path):
                    response = self.client.get(path, headers=header)
                    self.assertNotServerError(response)
                    self.assertJsonEncodable(response)
            with self.subTest(cookie=label, path="logout"):
                logout = self.client.post("/api/auth/logout", headers=header)
                self.assertNotServerError(logout)
            with self.subTest(cookie=label, path="change-password"):
                auth._login_attempts.clear()
                changed = self.client.post(
                    "/api/auth/change-password",
                    json={"username": "admin", "current_password": PASSWORD,
                          "new_password": PASSWORD + "1"},
                    headers=header,
                )
                self.assertNotServerError(changed)

    def test_a_repeated_cookie_name_resolves_last_value_wins(self):
        """The duplicate can only revoke, never grant.

        ``http.cookies.SimpleCookie`` (what Starlette parses with) keeps the
        *last* value for a repeated name, so appending a junk copy signs the
        caller out and appending a good copy after junk signs them in.  Both
        directions are fail-safe — a junk value never authenticates anything
        — and this pins which one the panel actually sees so a future parser
        change cannot silently flip it.
        """
        self.claim()
        good = self.sign_in().cookies.get(auth.COOKIE_NAME)
        name = auth.COOKIE_NAME
        for label, cookie, expected in (
            ("good then junk", f"{name}={good}; {name}=junk", False),
            ("junk then good", f"{name}=junk; {name}={good}", True),
        ):
            with self.subTest(cookie=label):
                status = self.client.get(
                    "/api/auth/status", headers=[(b"cookie", cookie.encode())]
                )
                self.assertEqual(status.status_code, 200, status.text[:300])
                self.assertIs(status.json()["authenticated"], expected)
        # The admin table follows the same resolution rather than 500ing.
        listing = self.client.get(
            "/api/auth/accounts",
            headers=[(b"cookie", f"{name}={good}; {name}=junk".encode())],
        )
        self.assertCode(listing, 401, "admin.browser_session_required")


class MixedCredentialTransportTests(_AppSandbox):
    """Stays-immune: a session cookie arriving beside other credentials.

    ``require_auth`` checks the cookie first and the account routes demand it
    outright, so a bearer key or menu-bar header riding along must change
    nothing — and must not 500 either guard.
    """

    def test_cookie_beside_bearer_and_local_headers_stays_200(self):
        self.claim()
        self.sign_in()
        for label, headers in {
            "bearer key-shaped": {"authorization": "Bearer shk_" + "a" * 40},
            "bearer junk": {"authorization": "Bearer not-a-key"},
            "local token": {auth.LOCAL_TOKEN_HEADER: "junk-token"},
            "both": {"authorization": "Bearer shk_" + "a" * 40,
                     auth.LOCAL_TOKEN_HEADER: "junk-token"},
        }.items():
            for path in ("/api/auth/status", "/api/auth/accounts",
                         "/api/auth/totp", "/api/settings"):
                with self.subTest(headers=label, path=path):
                    response = self.client.get(path, headers=headers)
                    self.assertEqual(response.status_code, 200,
                                     response.text[:300])
                    self.assertJsonEncodable(response)

    def test_key_shaped_bearer_without_a_cookie_is_coded(self):
        self.claim()
        client = TestClient(app(), raise_server_exceptions=False)
        for label, header in {
            "unknown key": "Bearer shk_" + "a" * 40,
            "oversize key": "Bearer shk_" + "a" * 9000,
            "scheme only": "Basic",
            "colonless basic": "Basic bm8tY29sb24taGVyZQ==",
        }.items():
            with self.subTest(header=label):
                accounts = client.get(
                    "/api/auth/accounts", headers={"authorization": header}
                )
                self.assertCode(accounts, 401, "admin.browser_session_required")
                settings = client.get(
                    "/api/settings", headers={"authorization": header}
                )
                self.assertNotServerError(settings)
                self.assertLess(settings.status_code, 500)


class UnusualHttpMethodTests(_AppSandbox):
    """Stays-immune: methods the account routes do not declare.

    A route that answers 405 must do so from the router, not from a handler
    that ran with the wrong shape — and the member-session gate reads the
    method, so an unusual one must not slip past it.
    """

    METHODS = ("HEAD", "OPTIONS", "TRACE", "PATCH", "PROPFIND")
    PATHS = (
        "/api/auth/status",
        "/api/auth/accounts",
        "/api/auth/logout",
        "/api/auth/totp",
        "/api/audit/auth",
        "/api/auth/setup-token",
        "/api/auth/accounts/kid/resources",
    )

    def test_no_method_answers_a_raw_500(self):
        self.claim()
        self.sign_in()
        for method in self.METHODS:
            for path in self.PATHS:
                with self.subTest(method=method, path=path):
                    response = self.client.request(method, path)
                    self.assertNotServerError(response)


class MemberSessionUnwritableDataTests(_AppSandbox):
    """Stays-immune: a member session on a panel whose data/ is a leftover file."""

    data_is_dir = False

    def test_member_reads_and_logout_stay_coded(self):
        admin_hash = auth.hash_password(PASSWORD)
        member_hash = auth.hash_password(MEMBER_PASSWORD)
        self.write_config(
            "settings:\n  auth:\n    enabled: true\n    username: admin\n"
            f'    password_hash: "{admin_hash}"\n    accounts:\n'
            "      - username: kid\n"
            f'        password_hash: "{member_hash}"\n'
            "        role: member\n        resources: [plex]\n"
        )
        auth._secret_cache = None
        member = TestClient(app(), raise_server_exceptions=False)
        self.sign_in(member, "kid", MEMBER_PASSWORD)
        for path in ("/api/auth/status", "/api/status", "/api/services",
                     "/api/auth/totp"):
            with self.subTest(path=path):
                response = member.get(path)
                self.assertEqual(response.status_code, 200, response.text[:300])
                self.assertJsonEncodable(response)
        # The admin-only surfaces still refuse with their coded 403.
        self.assertCode(member.get("/api/auth/accounts"), 403,
                        "admin.admin_required")
        self.assertCode(member.get("/api/settings"), 403, "auth.admin_required")
        logout = member.post("/api/auth/logout")
        self.assertEqual(logout.status_code, 200, logout.text[:300])
        after = member.get("/api/auth/status")
        self.assertEqual(after.status_code, 200, after.text[:300])
        self.assertFalse(after.json()["authenticated"])


class TokenFallbackUnitContractTests(unittest.TestCase):
    """The fallback cache is per *path* and only used when the write fails."""

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.addCleanup(auth._token_fallbacks.clear)
        auth._token_fallbacks.clear()

    def test_writable_path_persists_and_does_not_cache(self):
        path = self.root / "token"
        value = auth._persistent_token(path)
        self.assertTrue(value)
        self.assertEqual(path.read_text(encoding="utf-8").strip(), value)
        self.assertNotIn(str(path), auth._token_fallbacks)
        # Second call reads the file back, not the cache.
        self.assertEqual(auth._persistent_token(path), value)

    @unittest.skipUnless(_NOT_ROOT, "a read-only directory does not stop root")
    def test_unwritable_parent_caches_per_path(self):
        parent = self.root / "frozen"
        parent.mkdir()
        os.chmod(parent, 0o500)
        self.addCleanup(os.chmod, parent, 0o700)
        first = auth._persistent_token(parent / "a")
        second = auth._persistent_token(parent / "b")
        self.assertTrue(first)
        self.assertTrue(second)
        # Distinct paths get distinct tokens; each one is stable.
        self.assertNotEqual(first, second)
        self.assertEqual(auth._persistent_token(parent / "a"), first)
        self.assertEqual(auth._persistent_token(parent / "b"), second)
        self.assertFalse((parent / "a").exists())

    def test_parent_is_a_regular_file(self):
        squat = self.root / "data"
        squat.write_text("leftover", encoding="utf-8")
        value = auth._persistent_token(squat / "token")
        self.assertTrue(value)
        self.assertEqual(auth._persistent_token(squat / "token"), value)
        # The leftover file is left for the operator to inspect.
        self.assertTrue(squat.is_file())

    def test_consume_setup_token_swallows_an_unremovable_file(self):
        path = self.root / "setup-token"
        path.mkdir()
        (path / "junk").write_text("x", encoding="utf-8")
        with mock.patch.object(auth, "SETUP_TOKEN_FILE", path):
            auth.consume_setup_token()  # must not raise
        self.assertTrue(path.is_dir())

    def test_consume_setup_token_still_removes_a_real_file(self):
        path = self.root / "setup-token-file"
        path.write_text("tok\n", encoding="utf-8")
        with mock.patch.object(auth, "SETUP_TOKEN_FILE", path):
            auth.consume_setup_token()
        self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
