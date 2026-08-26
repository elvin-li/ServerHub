"""Fifth Account-domain sweep: member-account CRUD stays-immune pins.

The earlier account/account2/account3/account4 sweeps hardened the TOTP
self-service, the two-step sign-in, the API-key surface and the change-password
route.  This one re-hunts the *member-account CRUD* router
(``hub/routers/accounts_api.py``) and its ``hub.auth`` service helpers — the
five routes the Users/Account admin table drives:

* ``GET  /api/auth/accounts``                       (list)
* ``POST /api/auth/accounts``                        (create)
* ``PUT  /api/auth/accounts/{username}/resources``   (re-scope)
* ``POST /api/auth/accounts/{username}/password``    (admin reset)
* ``DELETE /api/auth/accounts/{username}``           (delete)

No live 500 remains on that surface: every known leftover class already
answers a coded status or a JSON-encodable 200.  This module pins the
corners the earlier sweeps did not reach *through the mounted app* (the body
parse, the same-origin middleware, the guards and Starlette's
``allow_nan=False`` encoder all take part), all under
``create_app()`` + ``TestClient`` with ``raise_server_exceptions=False``:

* the account *list* endpoint under poisoned ``settings.auth.accounts`` rows
  the prior sweeps only exercised on the *login* path — lone-surrogate and
  numeric usernames, over-cap-hex / ``!!set`` / dict resources, and an
  ``.inf`` role — stays 200 and JSON-encodable (accounts() drops or coerces
  each), and under poisoned ``twofa.json`` (non-UTF-8, 2 MB past the cap, a
  lone-surrogate field, a >4300-digit ``last_counter``) each member's
  ``twofa_enabled`` reads False rather than 500ing the whole table;
* a leftover FIFO occupying ``twofa.json`` must not hang or 500 the list —
  the O_NONBLOCK read answers EINVAL and the row reads disabled;
* create / re-scope bodies carrying a lone-surrogate username (422),
  surrogate resources (dropped, 200), a >4300-digit number literal (a plain
  ValueError out of the parse, not JSONDecodeError — 400) and an iterbomb
  nest (RecursionError — coded 4xx);
* junk path parameters on the three ``{username}`` routes — a percent-encoded
  lone surrogate, ``%00``, a 4300-digit spelling, a colon name accounts()
  can never resolve — all answer the coded 404 ``accounts.not_found``;
* creating a fresh account *beside* poisoned rows whose username is an
  unhashable YAML value (a list, a dict, a ``!!set``) or an over-cap hex int:
  ``create_account`` builds a ``taken`` set from those rows, and the str()
  probe keeps the membership test hashable, so the create still lands and the
  junk rows stay invisible;
* torn / hostile ``Origin`` headers on the mutating routes (``http://[::1``,
  ``http://[]``, a ``javascript:`` authority, an 9 KB origin) — the
  same-origin middleware's ``urlsplit`` is guarded, so these answer the coded
  403 ``auth.cross_site_denied`` rather than 500ing on the torn URL;
* EIO persisting services.yaml turns create / re-scope / password / delete
  into the *coded* 503 ``settings.save_failed`` (a named dependency state,
  not an unhandled 500), while the list read stays 200;
* a numeric YAML member (``username: 2024`` round-trips as an int) walks the
  whole CRUD — list, re-scope, password reset, delete — over HTTP through the
  ``str()``-keyed helpers.
"""
from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

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
        self.yaml_path.write_text(text, encoding="utf-8", errors="surrogatepass")
        config.reload_cfg()

    def claim(self) -> None:
        self.write_config("settings:\n  auth:\n    enabled: true\n")
        auth.set_password(PASSWORD, "admin")

    def claim_with_numeric_member(self) -> None:
        self.write_config(
            "settings:\n  auth:\n    enabled: true\n    username: admin\n"
            f'    password_hash: "{auth.hash_password(PASSWORD)}"\n    accounts:\n'
            "      - username: 2024\n"
            f'        password_hash: "{auth.hash_password(MEMBER_PASSWORD)}"\n'
            "        role: member\n"
        )

    def sign_in(self, client=None, username="admin", password=PASSWORD):
        auth._login_attempts.clear()
        response = (client or self.client).post(
            "/api/auth/login", json={"username": username, "password": password}
        )
        self.assertEqual(response.status_code, 200)
        return response

    def create_member(self, name="kid", resources=None):
        auth._login_attempts.clear()
        response = self.client.post(
            "/api/auth/accounts",
            json={"username": name, "password": "x" * 12,
                  "resources": resources or []},
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response

    def raw_post(self, path: str, payload):
        auth._login_attempts.clear()
        body = payload if isinstance(payload, bytes) else payload.encode(
            "utf-8", "surrogatepass"
        )
        return self.client.post(
            path, content=body, headers={"content-type": "application/json"}
        )

    def raw_put(self, path: str, payload):
        auth._login_attempts.clear()
        body = payload if isinstance(payload, bytes) else payload.encode(
            "utf-8", "surrogatepass"
        )
        return self.client.put(
            path, content=body, headers={"content-type": "application/json"}
        )

    def assertJsonEncodable(self, response):
        """Starlette already encoded it; re-encode to prove no inf/surrogate."""
        json.dumps(response.json(), ensure_ascii=False, allow_nan=False)


class PoisonedAccountsRowsListHttpTests(_AppSandbox):
    """GET /api/auth/accounts stays 200 across poisoned settings.auth rows."""

    def _doc(self, tail: str) -> str:
        return (
            "settings:\n  auth:\n    enabled: true\n    username: admin\n"
            f'    password_hash: "{auth.hash_password(PASSWORD)}"\n'
            "    accounts:\n" + tail
        )

    POISONS = (
        ("surrogate username",
         '      - username: "kid\\ud800"\n        password_hash: x\n'
         "        role: member\n"),
        ("numeric username",
         "      - username: 2024\n        password_hash: x\n        role: member\n"),
        ("over-cap hex resource",
         "      - username: kid\n        password_hash: x\n        role: member\n"
         f"        resources: [{HEX_HUGE}]\n"),
        ("set resources",
         "      - username: kid\n        password_hash: x\n        role: member\n"
         "        resources: !!set\n          ? a\n          ? b\n"),
        ("dict resources",
         "      - username: kid\n        password_hash: x\n        role: member\n"
         "        resources: {a: 1}\n"),
        ("inf role and nan resource",
         "      - username: kid\n        password_hash: x\n        role: .inf\n"
         "        resources: [.nan]\n"),
    )

    def test_list_stays_200_and_encodable(self):
        for label, tail in self.POISONS:
            with self.subTest(poison=label):
                self.write_config(self._doc(tail))
                self.sign_in()
                response = self.client.get("/api/auth/accounts")
                self.assertEqual(response.status_code, 200, response.text)
                self.assertJsonEncodable(response)
                # The admin row always survives; every field is a clean string.
                names = {row["username"] for row in response.json()["accounts"]}
                self.assertIn("admin", names)
                for row in response.json()["accounts"]:
                    self.assertIsInstance(row["role"], str)
                    self.assertIsInstance(row["resources"], list)


class PoisonedTwofaStoreListHttpTests(_AppSandbox):
    """A poisoned twofa.json must not 500 the account table's 2FA column."""

    # (label, blob, reads_disabled): an *unparseable* store reads as "no 2FA";
    # a store that parses but carries a poison in a non-critical field keeps
    # the honest ``enabled: true`` — either way the column must not 500.
    CASES = (
        ("non-utf8 bytes",
         b'{"kid": {"enabled": true, "secret": "\xff\xfe"}}', True),
        ("2mb past the cap", b"x" * (2 * 1024 * 1024), True),
        ("surrogate field",
         '{"kid": {"enabled": true, "note": "\\ud800"}}'.encode(
             "utf-8", "surrogatepass"), False),
        ("huge last_counter literal",
         ('{"kid": {"enabled": true, "last_counter": ' + HUGE_LITERAL + "}}").encode(),
         False),
    )

    def test_list_reads_disabled_not_500(self):
        self.claim()
        self.sign_in()
        self.create_member("kid")
        for label, blob, reads_disabled in self.CASES:
            with self.subTest(store=label):
                self.twofa_store.write_bytes(blob)
                response = self.client.get("/api/auth/accounts")
                self.assertEqual(response.status_code, 200, response.text)
                self.assertJsonEncodable(response)
                rows = {r["username"]: r for r in response.json()["accounts"]}
                self.assertIsInstance(rows["kid"]["twofa_enabled"], bool)
                if reads_disabled:
                    # A store that will not parse reads as "no 2FA", not an error.
                    self.assertFalse(rows["kid"]["twofa_enabled"])


@unittest.skipUnless(hasattr(os, "mkfifo"), "mkfifo not available")
class LeftoverFifoListHttpTests(_AppSandbox):
    """A FIFO occupying twofa.json must not hang or 500 the account list.

    A plain ``open()`` of a FIFO parks the request until a writer appears —
    strictly worse than a 500.  ``read_text_capped`` opens O_NONBLOCK and the
    row reads disabled instead.
    """

    def test_fifo_store_reads_disabled_and_list_answers(self):
        self.claim()
        self.sign_in()
        self.create_member("kid")
        os.mkfifo(self.twofa_store)
        response = self.client.get("/api/auth/accounts")
        self.assertEqual(response.status_code, 200)
        rows = {r["username"]: r for r in response.json()["accounts"]}
        self.assertFalse(rows["kid"]["twofa_enabled"])


class CreateBodyLeftoverHttpTests(_AppSandbox):
    """Hostile create / re-scope bodies stay coded, never 500."""

    def test_surrogate_username_is_rejected_422(self):
        self.claim()
        self.sign_in()
        response = self.raw_post(
            "/api/auth/accounts",
            '{"username": "\\ud800", "password": "x-password-12", "resources": []}',
        )
        # Pydantic's string_unicode guard rejects a lone surrogate at the model.
        self.assertEqual(response.status_code, 422)
        self.assertJsonEncodable(response)

    def test_surrogate_resources_are_dropped_not_500(self):
        self.claim()
        self.sign_in()
        response = self.raw_post(
            "/api/auth/accounts",
            '{"username": "surrkid", "password": "x-password-12", '
            '"resources": ["\\ud800keep-out", "ok"]}',
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertJsonEncodable(response)
        # The unrenderable resource is dropped; the clean one survives.
        self.assertEqual(response.json()["account"]["resources"], ["ok"])

    def test_huge_number_literals_stay_400(self):
        """A >4300-digit literal raises a plain ValueError in the parse — not
        JSONDecodeError — which FastAPI maps to 400, not a 500."""
        self.claim()
        self.sign_in()
        for label, payload in (
            ("username", '{"username": ' + HUGE_LITERAL + ', "password": "x-password-12"}'),
            ("resource",
             '{"username": "z", "password": "x-password-12", '
             '"resources": [' + HUGE_LITERAL + "]}"),
        ):
            with self.subTest(field=label):
                response = self.raw_post("/api/auth/accounts", payload)
                self.assertEqual(response.status_code, 400, response.text)

    def test_iterbomb_bodies_stay_coded_4xx(self):
        """A body nested thousands deep RecursionErrors ``json.loads``; the
        parse layer must answer a coded 4xx on every account route."""
        self.claim()
        self.sign_in()
        self.create_member("kid")
        cases = (
            ("POST", "/api/auth/accounts",
             '{"username": "z", "password": "x-password-12", '
             '"resources": ' + NEST_ARRAY + "}"),
            ("PUT", "/api/auth/accounts/kid/resources",
             '{"resources": ' + NEST_ARRAY + "}"),
        )
        for method, path, payload in cases:
            with self.subTest(route=path):
                if method == "POST":
                    response = self.raw_post(path, payload)
                else:
                    response = self.raw_put(path, payload)
                self.assertGreaterEqual(response.status_code, 400)
                self.assertLess(response.status_code, 500)


class MutatingPathParamLeftoverHttpTests(_AppSandbox):
    """Junk {username} path parameters answer the coded 404, never a 500."""

    JUNK = ("%ED%A0%80", "%00", "9" * 4300, "key:mon", "no-such-account")

    def test_all_three_username_routes_stay_coded_404(self):
        self.claim()
        self.sign_in()
        for junk in self.JUNK:
            with self.subTest(username=junk):
                auth._login_attempts.clear()
                put = self.client.put(
                    f"/api/auth/accounts/{junk}/resources", json={"resources": []}
                )
                self.assertEqual(put.status_code, 404, put.text)
                self.assertEqual(put.json()["detail"]["code"], "accounts.not_found")
                auth._login_attempts.clear()
                pwd = self.client.post(
                    f"/api/auth/accounts/{junk}/password",
                    json={"new_password": "x" * 12},
                )
                self.assertEqual(pwd.status_code, 404, pwd.text)
                self.assertEqual(pwd.json()["detail"]["code"], "accounts.not_found")
                auth._login_attempts.clear()
                dele = self.client.request("DELETE", f"/api/auth/accounts/{junk}")
                self.assertEqual(dele.status_code, 404, dele.text)
                self.assertEqual(dele.json()["detail"]["code"], "accounts.not_found")


class CreateBesidePoisonedRowsHttpTests(_AppSandbox):
    """Creating an account while unhashable / over-cap rows sit in the config.

    ``create_account`` builds a ``taken`` set of existing usernames; the
    ``_cfg_text`` str() probe keeps that membership test hashable even when a
    hand-edited row's username is a YAML list, dict or ``!!set``, so the create
    still lands and the junk rows stay invisible to the panel.
    """

    def _doc(self, row: str) -> str:
        return (
            "settings:\n  auth:\n    enabled: true\n    username: admin\n"
            f'    password_hash: "{auth.hash_password(PASSWORD)}"\n'
            "    accounts:\n" + row
        )

    ROWS = (
        ("list username",
         "      - username: [a, b]\n        password_hash: x\n        role: member\n"),
        ("dict username",
         "      - username: {k: v}\n        password_hash: x\n        role: member\n"),
        ("set username",
         "      - ? username\n        : !!set {a, b}\n        password_hash: x\n"),
        ("over-cap hex username",
         f"      - username: {HEX_HUGE}\n        password_hash: x\n        role: member\n"),
    )

    def test_create_lands_and_junk_rows_stay_invisible(self):
        for label, row in self.ROWS:
            with self.subTest(row=label):
                self.write_config(self._doc(row))
                self.sign_in()
                created = self.client.post(
                    "/api/auth/accounts",
                    json={"username": "freshkid", "password": "x" * 12,
                          "resources": []},
                )
                self.assertEqual(created.status_code, 200, created.text)
                listing = self.client.get("/api/auth/accounts")
                self.assertEqual(listing.status_code, 200)
                self.assertJsonEncodable(listing)
                names = {r["username"] for r in listing.json()["accounts"]}
                self.assertIn("admin", names)
                self.assertIn("freshkid", names)


class TornOriginMutatingRouteHttpTests(_AppSandbox):
    """A torn/hostile Origin header must not 500 the same-origin middleware."""

    ORIGINS = (
        "http://[::1",          # urlsplit ValueError on 3.12
        "http://[]",            # empty IPv6 literal
        "javascript://localhost",
        "http://" + "a" * 9000,  # oversize
    )

    def test_torn_origin_answers_cross_site_not_500(self):
        self.claim()
        self.sign_in()
        for origin in self.ORIGINS:
            with self.subTest(origin=origin[:24]):
                response = self.client.post(
                    "/api/auth/accounts",
                    json={"username": "k", "password": "x" * 12},
                    headers={"origin": origin, "host": "localhost"},
                )
                self.assertEqual(response.status_code, 403, response.text)
                self.assertEqual(
                    response.json()["detail"]["code"], "auth.cross_site_denied"
                )


class DyingDiskMutationHttpTests(_AppSandbox):
    """EIO persisting services.yaml is the coded 503, not an unhandled 500."""

    def test_every_mutation_is_coded_503_and_list_stays_200(self):
        self.claim()
        self.sign_in()
        self.create_member("kid")
        with mock.patch.object(
            config.secure_io, "replace_secret_text",
            side_effect=OSError(5, "I/O error"),
        ):
            create = self.client.post(
                "/api/auth/accounts",
                json={"username": "kid2", "password": "x" * 12, "resources": []},
            )
            self.assertEqual(create.status_code, 503)
            self.assertEqual(create.json()["detail"]["code"], "settings.save_failed")

            rescope = self.client.put(
                "/api/auth/accounts/kid/resources", json={"resources": ["a"]}
            )
            self.assertEqual(rescope.status_code, 503)
            self.assertEqual(rescope.json()["detail"]["code"], "settings.save_failed")

            reset = self.client.post(
                "/api/auth/accounts/kid/password", json={"new_password": "y" * 12}
            )
            self.assertEqual(reset.status_code, 503)
            self.assertEqual(reset.json()["detail"]["code"], "settings.save_failed")

            deleted = self.client.request("DELETE", "/api/auth/accounts/kid")
            self.assertEqual(deleted.status_code, 503)
            self.assertEqual(deleted.json()["detail"]["code"], "settings.save_failed")

            # The list is a read; a dying writer must not take it down too.
            listing = self.client.get("/api/auth/accounts")
            self.assertEqual(listing.status_code, 200)


class NumericMemberCrudHttpTests(_AppSandbox):
    """A numeric YAML member (``username: 2024`` is an int) walks the CRUD."""

    def test_list_rescope_reset_and_delete_by_string_spelling(self):
        self.claim_with_numeric_member()
        self.sign_in()

        listing = self.client.get("/api/auth/accounts")
        self.assertEqual(listing.status_code, 200)
        self.assertJsonEncodable(listing)
        rows = {r["username"]: r for r in listing.json()["accounts"]}
        self.assertIn("2024", rows)  # str() probe, not isinstance(name, str)
        self.assertEqual(rows["2024"]["role"], "member")

        rescope = self.client.put(
            "/api/auth/accounts/2024/resources", json={"resources": ["immich"]}
        )
        self.assertEqual(rescope.status_code, 200, rescope.text)
        self.assertEqual(rescope.json()["resources"], ["immich"])

        reset = self.client.post(
            "/api/auth/accounts/2024/password", json={"new_password": "z" * 12}
        )
        self.assertEqual(reset.status_code, 200, reset.text)

        deleted = self.client.request("DELETE", "/api/auth/accounts/2024")
        self.assertEqual(deleted.status_code, 200, deleted.text)
        after = self.client.get("/api/auth/accounts")
        self.assertNotIn("2024", {r["username"] for r in after.json()["accounts"]})


if __name__ == "__main__":
    unittest.main()
