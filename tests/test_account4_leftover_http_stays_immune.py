"""Fourth Account-domain sweep: stays-immune pins over the real ASGI app.

A fresh hunt across the Account surface (Account.vue's endpoints: TOTP
self-service, the two-step sign-in, member-account CRUD, change-password)
found no live 500 left.  Two probe matrices — poisoned twofa.json / YAML
type leftovers / hostile transport bodies / dying-disk nodes — all answer
coded statuses; the only 5xx anywhere is the *deliberate* coded 503
``settings.save_failed`` for a disk that cannot be written.  This module
pins the corners no earlier sweep covered, all through ``create_app()``
with ``raise_server_exceptions=False`` semantics (TestClient default app):

* iterbomb bodies: a JSON body nested thousands of levels deep raises
  RecursionError inside the parse — neither JSONDecodeError nor the
  digit-cap ValueError the earlier sweeps pinned — and every TOTP /
  accounts / login route must keep answering a coded 4xx;
* transport oddities on the TOTP routes: UTF-16-encoded JSON (the BOM
  autodetect path), form/multipart bodies, an empty body, a huge
  content-type header;
* leftover FIFOs occupying ``twofa.json`` and its ``.lock`` — a plain
  ``open()`` of a FIFO parks until a writer appears, which is worse than a
  500 (``read_text_capped`` answers OSError(EINVAL) instead, and
  ``_drop_leftover_nonfile`` reclaims the path on the next save);
* poisoned store shapes the account3 sweep did not reach over HTTP:
  ``recovery`` as a dict / a string, ``confirmed_at`` as a >4300-digit
  *string* and as JSON ``1e309``, a lone-surrogate ``pending_secret``,
  scalar / top-level-list documents, bare ``NaN`` / ``Infinity`` literals,
  non-UTF-8 bytes, and a 2 MB store past the read cap;
* YAML *type* leftovers in ``settings.auth``: ``!!binary`` password_hash
  and username, ``!!timestamp`` usernames and epoch keys, ``!!set``
  resources, ``.inf`` role — status / login / logout stay coded;
* the full two-step 2FA sign-in (password → pending token → recovery
  code) completing over HTTP while ``session_epochs`` carries over-cap
  hex-int leftovers, including the disable that bumps the epoch;
* EIO persisting services.yaml: account create answers the coded 503
  ``settings.save_failed`` (a dependency state, not an unhandled 500),
  while logout and TOTP enroll — both best-effort writers — stay 200;
* junk session cookies on GET /api/auth/totp, and junk forwarded headers
  parsed by a *trusted* proxy peer on both sign-in steps.
"""
from __future__ import annotations

import json
import os
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi.testclient import TestClient

from hub import api_keys, audit, auth, config, totp, twofa_svc
from hub.app_factory import create_app

PASSWORD = "correct-horse-battery"
HUGE_LITERAL = "9" * 4400
HEX_HUGE = "0x" + "F" * 5000
NEST_ARRAY = "[" * 3000 + "1" + "]" * 3000
NEST_OBJECT = '{"k":' * 3000 + "1" + "}" * 3000

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
    return _APP


class _AppSandbox(unittest.TestCase):
    """Scratch services.yaml + data dir; a fresh signed-in client per test."""

    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        data = self.root / "data"
        data.mkdir()
        self.data = data
        self.twofa_store = data / "twofa.json"
        self.yaml_path = self.root / "services.yaml"
        for target, attr, value in (
            (config, "YAML_PATH", self.yaml_path),
            (config, "DATA_DIR", data),
            (config, "BASE", self.root),
            (config, "_LOCK_PATH", data / ".services.yaml.lock"),
            (auth, "SECRET_FILE", data / ".session-secret"),
            (auth, "SETUP_TOKEN_FILE", data / ".setup-token"),
            (auth, "LOCAL_TOKEN_FILE", data / ".local-client-token"),
            (twofa_svc, "STORE_FILE", self.twofa_store),
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
        self.client = TestClient(app())

    def write_config(self, text: str) -> None:
        self.yaml_path.write_text(text, encoding="utf-8")
        config.reload_cfg()

    def claim(self) -> None:
        self.write_config("settings:\n  auth:\n    enabled: true\n")
        auth.set_password(PASSWORD, "admin")

    def sign_in(self, client=None, username="admin", password=PASSWORD):
        auth._login_attempts.clear()
        response = (client or self.client).post(
            "/api/auth/login", json={"username": username, "password": password}
        )
        self.assertEqual(response.status_code, 200)
        return response

    def raw_post(self, path: str, payload, content_type="application/json"):
        auth._login_attempts.clear()
        body = payload if isinstance(payload, bytes) else payload.encode(
            "utf-8", "surrogatepass"
        )
        return self.client.post(
            path, content=body, headers={"content-type": content_type}
        )


def _code_at(secret: str, timestamp=None) -> str:
    return totp.totp_at(secret, int(time.time()) if timestamp is None else timestamp)


class IterbombBodyHttpTests(_AppSandbox):
    """A body nested thousands of levels deep RecursionErrors ``json.loads``.

    That is neither JSONDecodeError nor the digit-cap ValueError the earlier
    sweeps pinned; the parse layer must still answer a coded 4xx on every
    Account route rather than letting the RecursionError become a 500.
    """

    PATHS = (
        "/api/auth/login",
        "/api/auth/change-password",
        "/api/auth/accounts",
        "/api/auth/totp/verify",
        "/api/auth/totp/confirm",
        "/api/auth/totp/disable",
        "/api/auth/totp/recovery",
        "/api/auth/totp/admin-disable",
    )

    def test_deeply_nested_bodies_stay_coded_4xx(self):
        self.claim()
        self.sign_in()
        for path in self.PATHS:
            for label, payload in (
                ("array", NEST_ARRAY),
                ("object", NEST_OBJECT),
                ("nested field", '{"code": ' + NEST_ARRAY + "}"),
            ):
                with self.subTest(path=path, nest=label):
                    response = self.raw_post(path, payload)
                    self.assertGreaterEqual(response.status_code, 400)
                    self.assertLess(response.status_code, 500)

    def test_transport_oddities_stay_coded_4xx(self):
        """UTF-16 JSON, form/multipart bodies, empty body, huge content-type."""
        self.claim()
        self.sign_in()
        cases = (
            ("utf-16 json", '{"code": "123456"}'.encode("utf-16"),
             "application/json"),
            ("form body", b"code=123456", "application/x-www-form-urlencoded"),
            ("multipart",
             b"--x\r\nContent-Disposition: form-data; name=code\r\n\r\n1\r\n--x--\r\n",
             "multipart/form-data; boundary=x"),
            ("empty body", b"", "application/json"),
            ("huge content-type", b"{}", "application/json; " + "a" * 8000),
            ("octet junk", b"\x00\x01\x02", "application/octet-stream"),
        )
        for path in ("/api/auth/totp/confirm", "/api/auth/totp/verify"):
            for label, body, ctype in cases:
                with self.subTest(path=path, body=label):
                    response = self.raw_post(path, body, content_type=ctype)
                    self.assertGreaterEqual(response.status_code, 400)
                    self.assertLess(response.status_code, 500)


class PoisonedStoreShapesHttpTests(_AppSandbox):
    """twofa.json shapes the account3 sweep did not pin over HTTP."""

    def test_status_stays_200_for_every_unreached_shape(self):
        self.claim()
        self.sign_in()
        for label, document in (
            ("recovery dict",
             '{"admin": {"enabled": true, "secret": "AAAA", "recovery": {"a": 1}}}'),
            ("recovery string",
             '{"admin": {"enabled": true, "secret": "AAAA", "recovery": "xx"}}'),
            ("confirmed_at huge string",
             '{"admin": {"enabled": true, "secret": "AAAA", '
             '"confirmed_at": "' + HUGE_LITERAL + '"}}'),
            ("confirmed_at 1e309",
             '{"admin": {"enabled": true, "secret": "AAAA", "confirmed_at": 1e309}}'),
            ("pending surrogate",
             '{"admin": {"pending_secret": "\\ud800AAAA"}}'),
            ("bare NaN and Infinity",
             '{"admin": {"enabled": true, "secret": "AAAA", '
             '"note": NaN, "n2": Infinity, "n3": -Infinity}}'),
            ("entry scalar", '{"admin": 12}'),
            ("entry null", '{"admin": null}'),
            ("top-level list", '[{"admin": 1}]'),
            ("top-level number", "12"),
        ):
            with self.subTest(poison=label):
                self.twofa_store.write_text(
                    document, encoding="utf-8", errors="surrogatepass"
                )
                response = self.client.get("/api/auth/totp")
                self.assertEqual(response.status_code, 200)
                body = response.json()
                # Unspendable recovery shapes count zero; an unparseable
                # confirmed_at reads as null — never a raised encoder error.
                if "recovery" in label:
                    self.assertEqual(body["recovery_remaining"], 0)
                if "confirmed_at" in label:
                    self.assertIsNone(body["confirmed_at"])

    def test_code_bearing_routes_stay_coded_beside_each_shape(self):
        self.claim()
        self.sign_in()
        for label, document in (
            ("recovery dict",
             '{"admin": {"enabled": true, "secret": "AAAA", "recovery": {"a": 1}}}'),
            ("pending surrogate", '{"admin": {"pending_secret": "\\ud800AAAA"}}'),
            ("entry scalar", '{"admin": 12}'),
            ("top-level list", '[{"admin": 1}]'),
        ):
            with self.subTest(poison=label):
                self.twofa_store.write_text(
                    document, encoding="utf-8", errors="surrogatepass"
                )
                for path in (
                    "/api/auth/totp/disable",
                    "/api/auth/totp/recovery",
                    "/api/auth/totp/confirm",
                ):
                    auth._login_attempts.clear()
                    response = self.client.post(path, json={"code": "000000"})
                    self.assertGreaterEqual(response.status_code, 400)
                    self.assertLess(response.status_code, 500)
                    self.assertIn(
                        response.json()["detail"]["code"],
                        {"auth.totp_not_enabled", "auth.bad_totp",
                         "auth.totp_not_pending"},
                    )

    def test_unreadable_store_bytes_read_as_disabled_not_500(self):
        self.claim()
        self.sign_in()
        for label, blob in (
            ("non-utf8 bytes", b'{"admin": {"enabled": true, "secret": "\xff\xfe"}}'),
            ("2mb past the cap", b"x" * (2 * 1024 * 1024)),
        ):
            with self.subTest(store=label):
                self.twofa_store.write_bytes(blob)
                response = self.client.get("/api/auth/totp")
                self.assertEqual(response.status_code, 200)
                self.assertFalse(response.json()["enabled"])


@unittest.skipUnless(hasattr(os, "mkfifo"), "mkfifo not available")
class LeftoverFifoNodeHttpTests(_AppSandbox):
    """A FIFO occupying the store (or its lock) must not hang or 500.

    A plain ``open()`` of a FIFO parks the request until a writer appears —
    strictly worse than a 500.  ``read_text_capped`` opens O_NONBLOCK and
    answers OSError(EINVAL); the next save reclaims the path.
    """

    def test_fifo_store_reads_disabled_and_enroll_reclaims_it(self):
        self.claim()
        self.sign_in()
        os.mkfifo(self.twofa_store)
        response = self.client.get("/api/auth/totp")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["enabled"])
        enrolled = self.client.post("/api/auth/totp/enroll")
        self.assertEqual(enrolled.status_code, 200)
        self.assertTrue(enrolled.json()["secret"])
        # _drop_leftover_nonfile reclaimed the path: the pending secret landed.
        self.assertTrue(self.twofa_store.is_file())
        self.assertIn("admin", json.loads(self.twofa_store.read_text()))

    def test_fifo_lock_does_not_hang_enroll(self):
        self.claim()
        self.sign_in()
        os.mkfifo(str(self.twofa_store) + ".lock")
        enrolled = self.client.post("/api/auth/totp/enroll")
        self.assertEqual(enrolled.status_code, 200)
        self.assertTrue(enrolled.json()["secret"])


class YamlTypeLeftoverHttpTests(_AppSandbox):
    """YAML type leftovers in settings.auth: binary/timestamp/set/.inf."""

    POISONS = (
        ("binary password_hash",
         "settings:\n  auth:\n    enabled: true\n    username: admin\n"
         "    password_hash: !!binary aGVsbG8=\n"),
        ("binary username",
         "settings:\n  auth:\n    enabled: true\n    username: admin\n"
         "    password_hash: 'scrypt$x'\n    accounts:\n"
         "      - username: !!binary /w==\n        password_hash: 'scrypt$x'\n"
         "        role: member\n"),
        ("timestamp username",
         "settings:\n  auth:\n    enabled: true\n    username: admin\n"
         "    password_hash: 'scrypt$x'\n    accounts:\n"
         "      - username: 2024-06-01 12:00:00\n        password_hash: 'scrypt$x'\n"
         "        role: member\n"),
        ("set resources",
         "settings:\n  auth:\n    enabled: true\n    username: admin\n"
         "    password_hash: 'scrypt$x'\n    accounts:\n"
         "      - username: kid\n        password_hash: 'scrypt$x'\n"
         "        role: member\n        resources: !!set\n          ? a\n          ? b\n"),
        ("inf role and nan resource",
         "settings:\n  auth:\n    enabled: true\n    username: admin\n"
         "    password_hash: 'scrypt$x'\n    accounts:\n"
         "      - username: kid\n        password_hash: 'scrypt$x'\n"
         "        role: .inf\n        resources: [.nan]\n"),
        ("timestamp epoch key",
         "settings:\n  auth:\n    enabled: true\n    username: admin\n"
         "    password_hash: 'scrypt$x'\n    session_epochs:\n"
         "      2024-01-01: 3\n      admin: 2024-01-01\n"),
    )

    def test_status_login_and_logout_stay_coded(self):
        for label, document in self.POISONS:
            with self.subTest(poison=label):
                self.write_config(document)
                status = self.client.get("/api/auth/status")
                self.assertEqual(status.status_code, 200)
                for username in ("admin", "kid"):
                    auth._login_attempts.clear()
                    login = self.client.post(
                        "/api/auth/login",
                        json={"username": username, "password": "wrong-pw-1"},
                    )
                    self.assertGreaterEqual(login.status_code, 400)
                    self.assertLess(login.status_code, 500)
                auth._login_attempts.clear()
                # Logout's epoch bump is best-effort; the poison must not
                # turn "you are signed out" into an error.
                logout = self.client.post("/api/auth/logout")
                self.assertEqual(logout.status_code, 200)
                totp_status = self.client.get("/api/auth/totp")
                self.assertGreaterEqual(totp_status.status_code, 200)
                self.assertLess(totp_status.status_code, 500)


class TwoStepUnderHostileEpochsHttpTests(_AppSandbox):
    """The whole 2FA sign-in completes while session_epochs carries hex junk.

    Unit pins cover create_session / bump_session_epoch under the over-cap
    hex leftover; this walks the composed HTTP flow: password step → pending
    token → recovery-code verify → self-service disable (which bumps the
    epoch and re-issues the cookie in the same response).
    """

    def test_two_step_and_disable_complete(self):
        self.claim()
        self.sign_in()
        enrolled = self.client.post("/api/auth/totp/enroll")
        self.assertEqual(enrolled.status_code, 200)
        secret = enrolled.json()["secret"]
        auth._login_attempts.clear()
        confirmed = self.client.post(
            "/api/auth/totp/confirm", json={"code": _code_at(secret)}
        )
        self.assertEqual(confirmed.status_code, 200)
        recovery = confirmed.json()["recovery_codes"]

        # Splice the hostile epochs in *after* enrollment so every later
        # step (token mint, verify, the disable bump) reads through them.
        # The over-cap key needs YAML explicit-key syntax: a plain key is
        # scanner-capped at 1024 chars, so the whole document would be
        # unparseable rather than a loadable leftover.
        self.write_config(
            "settings:\n  auth:\n    enabled: true\n    username: admin\n"
            f'    password_hash: "{auth.hash_password(PASSWORD)}"\n'
            "    session_epochs:\n"
            f"      admin: {HEX_HUGE}\n"
            f"      ? {HEX_HUGE}\n"
            "      : 3\n"
        )
        fresh = TestClient(app())
        auth._login_attempts.clear()
        first = fresh.post(
            "/api/auth/login", json={"username": "admin", "password": PASSWORD}
        )
        self.assertEqual(first.status_code, 200)
        self.assertTrue(first.json()["totp_required"])
        auth._login_attempts.clear()
        second = fresh.post(
            "/api/auth/totp/verify",
            json={"pending": first.json()["pending"], "code": recovery[0]},
        )
        self.assertEqual(second.status_code, 200)
        self.assertTrue(second.json()["ok"])
        auth._login_attempts.clear()
        disabled = fresh.post(
            "/api/auth/totp/disable", json={"code": recovery[1]}
        )
        self.assertEqual(disabled.status_code, 200)
        # The bump landed past the corrupt window and the hex rows are gone.
        stored = (self.yaml_path.read_text())
        self.assertNotIn("0xF", stored)


class DyingDiskHttpTests(_AppSandbox):
    """EIO persisting services.yaml during Account mutations.

    Account create answers the *coded* 503 settings.save_failed — a named
    dependency state, not an unhandled 500 — while the best-effort writers
    (logout's epoch bump, TOTP enroll's pending-secret save) stay 200.
    """

    def test_create_is_coded_503_and_best_effort_writers_stay_200(self):
        self.claim()
        self.sign_in()
        with mock.patch.object(
            config.secure_io, "replace_secret_text",
            side_effect=OSError(5, "I/O error"),
        ):
            created = self.client.post(
                "/api/auth/accounts",
                json={"username": "kid", "password": "x" * 12, "resources": []},
            )
            self.assertEqual(created.status_code, 503)
            self.assertEqual(
                created.json()["detail"]["code"], "settings.save_failed"
            )
            # twofa_svc._save swallows the same OSError: enrollment still
            # answers with a pairing secret instead of failing the request.
            enrolled = self.client.post("/api/auth/totp/enroll")
            self.assertEqual(enrolled.status_code, 200)
            self.assertTrue(enrolled.json()["secret"])
            auth._login_attempts.clear()
            logout = self.client.post("/api/auth/logout")
            self.assertEqual(logout.status_code, 200)


class JunkTransportIdentityHttpTests(_AppSandbox):
    """Junk cookies on the TOTP routes and junk forwarded headers on sign-in."""

    def test_junk_session_cookies_answer_coded_401(self):
        self.claim()
        for label, cookie in (
            ("huge", "serverhub_session=" + "A" * 100000),
            ("percent surrogate", "serverhub_session=%ED%A0%80"),
            ("dot spray", "serverhub_session=" + "." * 5000),
            ("pipe salad", "serverhub_session=AAAA.BBBB.CCCC|||"),
        ):
            with self.subTest(cookie=label):
                response = self.client.get(
                    "/api/auth/totp", headers={"cookie": cookie}
                )
                self.assertEqual(response.status_code, 401)
                self.assertEqual(
                    response.json()["detail"]["code"], "auth.login_required"
                )
                auth._login_attempts.clear()
                logout = self.client.post(
                    "/api/auth/logout", headers={"cookie": cookie}
                )
                self.assertEqual(logout.status_code, 200)

    def test_junk_forwarded_headers_from_a_trusted_proxy_stay_coded(self):
        """The forwarded-hop parse runs only for trusted peers — force it."""
        self.claim()
        header_sets = (
            {"forwarded": "for=" + "z" * 10000},
            {"x-forwarded-for": ",".join(["1.2.3.4"] * 5000)},
            {"cf-connecting-ip": "0x" + "f" * 5000},
            {"x-real-ip": "%ED%A0%80"},
            {"x-forwarded-for": "6.6.6.6," + "9" * 5000},
        )
        with mock.patch.object(auth, "_peer_in_trusted_proxy", return_value=True):
            for i, headers in enumerate(header_sets):
                with self.subTest(headers=i):
                    auth._login_attempts.clear()
                    login = self.client.post(
                        "/api/auth/login",
                        json={"username": "admin", "password": "wrong-pw-1"},
                        headers=headers,
                    )
                    self.assertEqual(login.status_code, 401)
                    self.assertEqual(
                        login.json()["detail"]["code"], "auth.bad_credentials"
                    )
                    auth._login_attempts.clear()
                    verify = self.client.post(
                        "/api/auth/totp/verify",
                        json={"pending": "x", "code": "123456"},
                        headers=headers,
                    )
                    self.assertEqual(verify.status_code, 401)
                    self.assertEqual(
                        verify.json()["detail"]["code"],
                        "auth.totp_pending_invalid",
                    )


if __name__ == "__main__":
    unittest.main()
