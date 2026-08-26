"""Sixth Account-domain sweep: role-gate and config-node stays-immune pins.

The account3/4/5 waves hardened the member-account CRUD router and the
sign-in surface.  This sweep re-hunted the *role* seams those waves did not
drive over HTTP — the member-session gates in ``hub.auth.require_auth`` /
``member_request_authorized``, the member filtering in
``hub/routers/services_api.py``, and the account mutations' dependency on a
readable services.yaml — and found no live 500 left.  Every corner answers a
coded status, pinned here through ``create_app()`` + ``TestClient`` with
``raise_server_exceptions=False``:

* a signed-in *member* hitting every admin-only services/account route
  answers the coded 403 (``auth.admin_required`` / ``admin.admin_required``),
  the member-whitelisted reads stay 200, and junk ``{sid}`` path parameters
  on the resource-gated detail route — a percent-encoded lone surrogate,
  ``%00``, a 4300-digit spelling — fail closed to the coded 403 before any
  service lookup;
* a member row whose ``resources`` list carries YAML junk (over-cap hex,
  ``.inf`` / ``.nan``, a nested list, a mapping, a numeric id, a
  lone-surrogate escape) still signs in, and status / services / auth-status
  stay 200 and JSON-encodable — junk ids are coerced or dropped, never 500;
* the four account mutations against a services.yaml that is unreadable *on
  disk* while the in-memory snapshot still verifies the session (torn to
  non-UTF-8, grown past the read cap, replaced by a whole-document list
  paste, over-deep nesting — each with the mtime preserved, the shape a torn
  same-tick write or a ``cp -p``-restored backup leaves) answer the coded
  503 ``settings.config_unreadable`` and leave the file byte-identical,
  while the list read and logout stay 200;
* a leftover FIFO squatting services.yaml must not park the account list —
  the O_NONBLOCK read path answers instead of hanging;
* hostile ``Authorization`` transports on the account routes (a latin-1
  0xFF byte, torn base64, a credential without a colon, a 9 KB value, a
  junk scheme) and junk session cookies (60 KB, non-base64, NUL, deep
  base64) all answer the coded 401;
* change-password bodies carrying a >4300-digit number literal (a plain
  ValueError out of the parse, not JSONDecodeError — 400), an iterbomb nest
  and lone-surrogate fields (422) stay coded;
* an admin rename through change-password to a colon name or other
  non-conforming spelling answers the coded 400 ``accounts.bad_username``;
* a numeric YAML member (``username: 2024``) rotates its own password over
  HTTP, and its logout beside poisoned ``session_epochs`` rows (an over-cap
  hex counter, a ``!!timestamp`` key) stays 200, actually revokes the
  session, and re-dumps the epochs under renderable string spellings;
* deleting a member beside poisoned ``session_epochs`` rows (over-cap hex
  value, a surrogate-escape key, an explicit-key over-cap hex int) stays
  200 and drops the row;
* a member row replaced by unusable YAML mid-session fails closed — the
  next member request is the coded 401 and auth-status reads
  unauthenticated, never a 500.
"""
from __future__ import annotations

import base64
import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import yaml
from fastapi.testclient import TestClient

from hub import api_keys, audit, auth, config, twofa_svc
from hub.app_factory import create_app

PASSWORD = "correct-horse-battery"
MEMBER_PASSWORD = "kid-password-12"
HUGE_LITERAL = "9" * 4400
HEX_HUGE = "0x" + "F" * 5000
NEST_ARRAY = "[" * 3000 + "1" + "]" * 3000

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
    return _APP


class _AppSandbox(unittest.TestCase):
    """Scratch services.yaml + data dir; a fresh client per test."""

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

    def write_config(self, text: str) -> None:
        self.yaml_path.write_text(text, encoding="utf-8", errors="surrogatepass")
        config.reload_cfg()

    def claim(self) -> None:
        self.write_config("settings:\n  auth:\n    enabled: true\n")
        auth.set_password(PASSWORD, "admin")

    def sign_in(self, client=None, username="admin", password=PASSWORD):
        auth._login_attempts.clear()
        response = (client or self.client).post(
            "/api/auth/login", json={"username": username, "password": password}
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response

    def create_member(self, name="kid", resources=None):
        auth._login_attempts.clear()
        response = self.client.post(
            "/api/auth/accounts",
            json={"username": name, "password": MEMBER_PASSWORD,
                  "resources": resources or []},
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response

    def member_client(self, name="kid", password=MEMBER_PASSWORD) -> TestClient:
        client = TestClient(app(), raise_server_exceptions=False)
        self.sign_in(client, name, password)
        return client

    def assertJsonEncodable(self, response):
        """Starlette already encoded it; re-encode to prove no inf/surrogate."""
        json.dumps(response.json(), ensure_ascii=False, allow_nan=False)

    def assertCode(self, response, status: int, code: str):
        self.assertEqual(response.status_code, status, response.text)
        self.assertEqual(response.json()["detail"]["code"], code)


class MemberRoleGateHttpTests(_AppSandbox):
    """A member session meets a coded refusal on every admin surface."""

    #: (method, path, json body) — the admin-only routes a member's cookie can
    #: physically reach.  Each must answer the coded 403, never a 500 and
    #: never a 200 that quietly performed the admin action.
    ADMIN_ONLY = (
        ("GET", "/api/services/signatures", None),
        ("PUT", "/api/services/signatures", {"slug": "x"}),
        ("GET", "/api/services/group-rules", None),
        ("PUT", "/api/services/group-rules", {}),
        ("DELETE", "/api/services/group-rules/x", None),
        ("POST", "/api/services/plex/adopt", {}),
        ("PUT", "/api/services/plex/script", {}),
        ("DELETE", "/api/services/plex/script", None),
        ("GET", "/api/services/plex/logs", None),
        ("GET", "/api/services/plex/uninstall/preview", None),
        ("PUT", "/api/services/plex/override", {}),
        ("POST", "/api/services/plex/hide", {}),
        ("POST", "/api/services/bulk-action", {"ids": ["plex"], "action": "start"}),
        ("GET", "/api/settings", None),
        ("GET", "/api/audit/auth", None),
        ("GET", "/api/launcher", None),
        ("POST", "/api/action", {"id": "x", "action": "start"}),
        ("GET", "/api/maintenance", None),
    )

    def test_admin_only_routes_answer_coded_403(self):
        self.claim()
        self.sign_in()
        self.create_member("kid", ["plex"])
        member = self.member_client()
        for method, path, body in self.ADMIN_ONLY:
            with self.subTest(route=f"{method} {path}"):
                auth._login_attempts.clear()
                response = member.request(method, path, json=body)
                self.assertCode(response, 403, "auth.admin_required")

    def test_member_account_routes_answer_coded_403(self):
        self.claim()
        self.sign_in()
        self.create_member("kid", ["plex"])
        member = self.member_client()
        listing = member.get("/api/auth/accounts")
        self.assertCode(listing, 403, "admin.admin_required")
        create = member.post(
            "/api/auth/accounts", json={"username": "z", "password": "x" * 12}
        )
        self.assertCode(create, 403, "admin.admin_required")

    def test_member_whitelisted_reads_stay_200(self):
        self.claim()
        self.sign_in()
        self.create_member("kid", ["plex"])
        member = self.member_client()
        for path in ("/api/health", "/api/status", "/api/services",
                     "/api/auth/status"):
            with self.subTest(path=path):
                response = member.get(path)
                self.assertEqual(response.status_code, 200, response.text)
                self.assertJsonEncodable(response)

    def test_junk_sid_on_member_detail_fails_closed_coded(self):
        """The resource gate rejects junk ids before any service lookup."""
        self.claim()
        self.sign_in()
        self.create_member("kid", ["plex"])
        member = self.member_client()
        for junk in ("%ED%A0%80", "%00", "9" * 4300, "no-such-grant"):
            with self.subTest(sid=junk):
                response = member.get(f"/api/services/{junk}/detail")
                self.assertCode(response, 403, "auth.admin_required")


class PoisonedResourcesMemberHttpTests(_AppSandbox):
    """Junk resource grants never 500 a member's sign-in or reads."""

    def _write_poisoned_member(self) -> None:
        self.write_config(
            "settings:\n  auth:\n    enabled: true\n    username: admin\n"
            f'    password_hash: "{auth.hash_password(PASSWORD)}"\n'
            "    accounts:\n"
            "      - username: kid\n"
            f'        password_hash: "{auth.hash_password(MEMBER_PASSWORD)}"\n'
            "        role: member\n"
            f"        resources: [plex, {HEX_HUGE}, .inf, .nan, [a, b],"
            ' {k: v}, 2024, "s\\ud800"]\n'
        )

    def test_member_reads_stay_200_and_encodable(self):
        self._write_poisoned_member()
        member = self.member_client()
        for path in ("/api/services", "/api/status", "/api/auth/status"):
            with self.subTest(path=path):
                response = member.get(path)
                self.assertEqual(response.status_code, 200, response.text)
                self.assertJsonEncodable(response)
        status = member.get("/api/auth/status").json()
        # The real grant survives; the coercible junk is stringified and the
        # unrenderable / unencodable entries are dropped, never 500.
        self.assertIn("plex", status["resources"])
        for entry in status["resources"]:
            self.assertIsInstance(entry, str)
        self.assertNotIn("", status["resources"])

    def test_detail_on_numeric_grant_is_coded_not_500(self):
        self._write_poisoned_member()
        member = self.member_client()
        response = member.get("/api/services/2024/detail")
        # The numeric grant coerces to its string spelling and clears the
        # resource gate; no such service exists, so the coded 404 follows.
        self.assertCode(response, 404, "services.not_found")


class UnreadableConfigAccountMutationTests(_AppSandbox):
    """Account mutations refuse an unreadable services.yaml with the coded 503.

    The on-disk file is corrupted with its mtime preserved (``os.utime``), the
    shape a torn same-tick write by a sibling process or a ``cp -p``-restored
    backup leaves behind: the in-memory snapshot still verifies the admin's
    session, so the request reaches ``config.mutate`` — whose
    ``_read_disk_for_mutate`` re-read must refuse rather than patch a ``{}``
    fallback and wipe the file with an HTTP 200.
    """

    CORRUPTIONS = (
        ("non-utf8 torn bytes", b"settings:\n  auth:\n    x: \xff\xfe\n"),
        ("oversize past the read cap",
         b"# pad\n" + b"#" + b"x" * (2 * 1024 * 1024) + b"\n"),
        ("whole-document list paste", b"- a\n- b\n"),
        ("over-deep nesting", b"a: " + b"[" * 3000 + b"1" + b"]" * 3000),
    )

    def _corrupt_keeping_mtime(self, blob: bytes) -> bytes:
        st = self.yaml_path.stat()
        self.yaml_path.write_bytes(blob)
        os.utime(self.yaml_path, ns=(st.st_atime_ns, st.st_mtime_ns))
        return self.yaml_path.read_bytes()

    def test_mutations_answer_coded_503_and_file_stays_intact(self):
        for label, blob in self.CORRUPTIONS:
            with self.subTest(corruption=label):
                self.setUp()  # fresh sandbox per corruption shape
                self.claim()
                self.sign_in()
                self.create_member("kid")
                raw = self._corrupt_keeping_mtime(blob)
                for method, path, body in (
                    ("POST", "/api/auth/accounts",
                     {"username": "z2", "password": "x" * 12, "resources": []}),
                    ("PUT", "/api/auth/accounts/kid/resources",
                     {"resources": ["a"]}),
                    ("POST", "/api/auth/accounts/kid/password",
                     {"new_password": "y" * 12}),
                    ("DELETE", "/api/auth/accounts/kid", None),
                ):
                    auth._login_attempts.clear()
                    response = self.client.request(method, path, json=body)
                    self.assertCode(response, 503, "settings.config_unreadable")
                # The file the operator could still fix is byte-identical.
                self.assertEqual(self.yaml_path.read_bytes(), raw)
                # Reads and the best-effort logout writer stay coded / 200.
                listing = self.client.get("/api/auth/accounts")
                self.assertEqual(listing.status_code, 200, listing.text)
                self.assertJsonEncodable(listing)
                logout = self.client.post("/api/auth/logout")
                self.assertEqual(logout.status_code, 200, logout.text)


@unittest.skipUnless(hasattr(os, "mkfifo"), "mkfifo not available")
class FifoConfigAccountListTests(_AppSandbox):
    """A FIFO squatting services.yaml must not park the account list.

    A plain ``open()`` of a FIFO blocks until a writer appears — strictly
    worse than a 500.  The capped O_NONBLOCK reader answers instead, and the
    cached snapshot keeps the admin table serving.
    """

    def test_list_answers_from_cache_instead_of_hanging(self):
        self.claim()
        self.sign_in()
        self.create_member("kid")
        st = self.yaml_path.stat()
        self.yaml_path.unlink()
        os.mkfifo(self.yaml_path)
        os.utime(self.yaml_path, ns=(st.st_atime_ns, st.st_mtime_ns))
        response = self.client.get("/api/auth/accounts")
        self.assertEqual(response.status_code, 200, response.text)
        names = {row["username"] for row in response.json()["accounts"]}
        self.assertEqual(names, {"admin", "kid"})
        logout = self.client.post("/api/auth/logout")
        self.assertEqual(logout.status_code, 200, logout.text)


class HostileTransportAccountRouteTests(_AppSandbox):
    """Junk Authorization headers / cookies answer the coded 401, never 500."""

    HEADERS = (
        ("latin-1 0xff basic", b"Basic " + base64.b64encode(b"adm\xffn:pw")),
        ("torn base64 basic", b"Basic %%%not-base64%%%"),
        ("colonless basic", b"Basic " + base64.b64encode(b"no-colon-here")),
        ("empty basic", b"Basic "),
        ("9kb basic", b"Basic " + b"A" * 9000),
        ("junk scheme", b"\xff\xfe garbage"),
    )

    COOKIES = (
        ("60kb cookie", "A" * 60000),
        ("non-b64 cookie", "%%%///~~~"),
        ("nul cookie", "abc\x00def"),
        ("deep-b64 cookie", "AAAA" * 4000),
    )

    def test_junk_authorization_headers_stay_coded_401(self):
        self.claim()
        for label, header in self.HEADERS:
            with self.subTest(header=label):
                client = TestClient(app(), raise_server_exceptions=False)
                auth._login_attempts.clear()
                response = client.get(
                    "/api/auth/accounts", headers=[(b"authorization", header)]
                )
                self.assertCode(response, 401, "admin.browser_session_required")

    def test_junk_session_cookies_stay_coded_401(self):
        self.claim()
        for label, cookie in self.COOKIES:
            with self.subTest(cookie=label):
                client = TestClient(app(), raise_server_exceptions=False)
                client.cookies.set(auth.COOKIE_NAME, cookie)
                listing = client.get("/api/auth/accounts")
                self.assertCode(listing, 401, "admin.browser_session_required")
                create = client.post(
                    "/api/auth/accounts",
                    json={"username": "z", "password": "x" * 12},
                )
                self.assertCode(create, 401, "admin.browser_session_required")


class ChangePasswordHostileBodyTests(_AppSandbox):
    """Leftover-shaped change-password bodies stay coded 4xx."""

    def _raw_post(self, payload: str):
        auth._login_attempts.clear()
        return self.client.post(
            "/api/auth/change-password",
            content=payload.encode("utf-8", "surrogatepass"),
            headers={"content-type": "application/json"},
        )

    def test_huge_number_literal_is_400_not_500(self):
        """>4300 digits raises a plain ValueError in the parse — not
        JSONDecodeError — which FastAPI maps to 400."""
        self.claim()
        self.sign_in()
        response = self._raw_post(
            '{"username": "admin", "current_password": "' + PASSWORD
            + '", "new_password": ' + HUGE_LITERAL + "}"
        )
        self.assertEqual(response.status_code, 400, response.text)

    def test_iterbomb_and_surrogate_bodies_stay_coded(self):
        self.claim()
        self.sign_in()
        for label, payload in (
            ("iterbomb new_password",
             '{"username": "admin", "current_password": "' + PASSWORD
             + '", "new_password": ' + NEST_ARRAY + "}"),
            ("surrogate username",
             '{"username": "\\ud800", "current_password": "' + PASSWORD
             + '", "new_password": "new-password-123"}'),
            ("surrogate new_password",
             '{"username": "admin", "current_password": "' + PASSWORD
             + '", "new_password": "new-pw-\\ud800-123"}'),
        ):
            with self.subTest(body=label):
                response = self._raw_post(payload)
                self.assertGreaterEqual(response.status_code, 400)
                self.assertLess(response.status_code, 500)
                self.assertJsonEncodable(response)

    def test_admin_rename_to_invalid_spellings_is_coded_400(self):
        self.claim()
        self.sign_in()
        for target in ("key:mon", "..weird", ":", "a b"):
            with self.subTest(target=target):
                auth._login_attempts.clear()
                response = self.client.post(
                    "/api/auth/change-password",
                    json={"username": target, "current_password": PASSWORD,
                          "new_password": PASSWORD + "9"},
                )
                self.assertCode(response, 400, "accounts.bad_username")


class NumericMemberRoleHttpTests(_AppSandbox):
    """A numeric YAML member walks self-rotation and logout revocation."""

    def _write_numeric_member(self, epochs: str = "") -> None:
        self.write_config(
            "settings:\n  auth:\n    enabled: true\n    username: admin\n"
            f'    password_hash: "{auth.hash_password(PASSWORD)}"\n    accounts:\n'
            "      - username: 2024\n"
            f'        password_hash: "{auth.hash_password(MEMBER_PASSWORD)}"\n'
            "        role: member\n"
            "        resources: [plex]\n" + epochs
        )

    def test_numeric_member_rotates_its_own_password_over_http(self):
        self._write_numeric_member()
        member = self.member_client("2024")
        auth._login_attempts.clear()
        response = member.post(
            "/api/auth/change-password",
            json={"username": "2024", "current_password": MEMBER_PASSWORD,
                  "new_password": MEMBER_PASSWORD + "x"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["username"], "2024")
        # The rotation landed: the new password signs in, the old one fails.
        fresh = TestClient(app(), raise_server_exceptions=False)
        self.sign_in(fresh, "2024", MEMBER_PASSWORD + "x")
        auth._login_attempts.clear()
        stale = fresh.post(
            "/api/auth/login",
            json={"username": "2024", "password": MEMBER_PASSWORD},
        )
        self.assertCode(stale, 401, "auth.bad_credentials")

    def test_numeric_member_logout_beside_poisoned_epochs_revokes(self):
        self._write_numeric_member(
            "    session_epochs:\n"
            f"      2024: {HEX_HUGE}\n"
            "      ? !!timestamp 2024-01-01\n"
            "      : 3\n"
        )
        member = self.member_client("2024")
        pre = member.get("/api/auth/status").json()
        self.assertTrue(pre["authenticated"])
        self.assertEqual(pre["role"], "member")
        logout = member.post("/api/auth/logout")
        self.assertEqual(logout.status_code, 200, logout.text)
        post = member.get("/api/auth/status").json()
        self.assertFalse(post["authenticated"])
        # The rewritten epochs are renderable string spellings: the over-cap
        # hex counter folded to a real int and the timestamp key to its text.
        reparsed = yaml.safe_load(self.yaml_path.read_text())
        epochs = reparsed["settings"]["auth"]["session_epochs"]
        self.assertEqual(set(epochs), {"2024", "2024-01-01"})
        self.assertEqual(epochs["2024"], 2)

    def test_delete_member_beside_poisoned_epochs_stays_200(self):
        self.write_config(
            "settings:\n  auth:\n    enabled: true\n    username: admin\n"
            f'    password_hash: "{auth.hash_password(PASSWORD)}"\n    accounts:\n'
            "      - username: kid\n"
            f'        password_hash: "{auth.hash_password(MEMBER_PASSWORD)}"\n'
            "        role: member\n"
            "    session_epochs:\n"
            f"      kid: {HEX_HUGE}\n"
            '      "bad\\ud800": 2\n'
            f"      ? {HEX_HUGE}\n"
            "      : 9\n"
        )
        self.sign_in()
        deleted = self.client.request("DELETE", "/api/auth/accounts/kid")
        self.assertEqual(deleted.status_code, 200, deleted.text)
        listing = self.client.get("/api/auth/accounts")
        self.assertEqual(listing.status_code, 200, listing.text)
        self.assertJsonEncodable(listing)
        names = {row["username"] for row in listing.json()["accounts"]}
        self.assertEqual(names, {"admin"})


class VanishedMemberRowMidSessionTests(_AppSandbox):
    """A member row replaced by junk mid-session fails closed, never 500."""

    def test_member_session_dies_coded_after_row_turns_to_junk(self):
        self.claim()
        self.sign_in()
        self.create_member("kid", ["plex"])
        member = self.member_client()
        # The hand-edited row's username becomes an unusable YAML list, so
        # accounts() no longer resolves the name the cookie carries.
        self.write_config(
            "settings:\n  auth:\n    enabled: true\n    username: admin\n"
            f'    password_hash: "{auth.hash_password(PASSWORD)}"\n    accounts:\n'
            "      - username: [kid, x]\n        password_hash: x\n"
        )
        services = member.get("/api/services")
        self.assertCode(services, 401, "auth.login_required")
        detail = member.get("/api/services/plex/detail")
        self.assertCode(detail, 401, "auth.login_required")
        status = member.get("/api/auth/status")
        self.assertEqual(status.status_code, 200, status.text)
        self.assertJsonEncodable(status)
        self.assertFalse(status.json()["authenticated"])


if __name__ == "__main__":
    unittest.main()
