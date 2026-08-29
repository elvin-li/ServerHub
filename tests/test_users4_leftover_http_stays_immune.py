"""Users-page leftover sweep #4: HTTP-layer pins over the real ASGI app.

The first three sweeps hardened the Users surface mostly at unit level
(``users_svc``/``auth``/``twofa_svc``/``identity_svc`` called directly, guards
mocked out).  This sweep re-walks the same routes through ``create_app()`` +
``TestClient(raise_server_exceptions=False)`` — body parse, same-origin
middleware, route guards and Starlette's allow_nan=False encoder included —
and found one live leftover:

* **PUT /api/auth/accounts/{name}/resources silently lost the write for a
  whitespace-padded YAML row.**  ``accounts()`` strips usernames, so a
  hand-edited ``username: "kid "`` resolves as account "kid" everywhere —
  the row lists as "kid", "kid" signs in, delete and password-reset match it
  (both compare ``.strip()``) — but ``set_account_resources``'s apply loop
  compared the *unstripped* row name, matched nothing, and answered 200 with
  the granted list while services.yaml kept the old grants forever.  The loop
  now strips, same as its two siblings.

Everything else was already immune and is pinned here at the HTTP layer:

* GET /api/users keeps answering 200 and keeps the healthy rows when Open
  Directory hands back surrogate-poisoned fields, an already-int uid past
  CPython's digit cap (``int(pw_uid)`` performs no string conversion, so the
  cap probe never fires on it), a ``getpwall`` that raises, or an iterator
  that dies mid-walk;
* GET /api/auth/accounts survives poisoned services.yaml rows — an over-cap
  hex-int username (YAML ``0x…`` loads uncapped through ``int(x, 16)``), a
  lone-surrogate username escape, a non-dict row, junk resources/roles —
  dropping or scrubbing only the poison, never a healthy sibling;
* POST /api/auth/accounts beside a poisoned sibling persists without wiping
  that sibling; junk bodies stay coded 4xx (a >4300-digit JSON number
  literal is a *plain* ValueError out of ``json.loads``, not
  JSONDecodeError, and must map to 400); junk path usernames on DELETE stay
  the coded 404;
* PUT /api/identity answers the coded 503 for a vanished scutil only after
  the on-disk re-probe of the exact path the spawn used (failure path only),
  keeps a still-present binary's raw result, rejects a lone-surrogate
  computer name as the coded 400, and scrubs a surrogate comment before it
  becomes YAML; GET /api/identity keeps degrading every vanished CLI to "".
"""
from __future__ import annotations

import json
import unittest
from collections import namedtuple
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import yaml
from fastapi.testclient import TestClient

from hub import api_keys, audit, auth, config, identity_svc, twofa_svc, users_svc
from hub.app_factory import create_app

PASSWORD = "correct-horse-battery"
MEMBER_PASSWORD = "kid-password-12"
#: >4300 digits: json.loads raises the digit-cap ValueError (not
#: JSONDecodeError) when converting the literal.
HUGE_LITERAL = "9" * 4400
#: What a leftover YAML ``0x…`` loads as — ``int(x, 16)`` is exempt from the
#: cap, so the value exists fine as an int and only explodes at str()/dump.
HUGE_HEX = "0x" + "F" * 5000

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
    return _APP


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

    def write_config(self, text: str) -> None:
        self.yaml_path.write_text(text, encoding="utf-8")
        config.reload_cfg()

    def claim(self, extra_accounts: str = "") -> None:
        self.write_config(
            "settings:\n"
            "  auth:\n"
            "    enabled: true\n"
            "    username: admin\n"
            f'    password_hash: "{auth.hash_password(PASSWORD)}"\n'
            + extra_accounts
        )

    def sign_in(self, client=None, username="admin", password=PASSWORD):
        auth._login_attempts.clear()
        response = (client or self.client).post(
            "/api/auth/login", json={"username": username, "password": password}
        )
        self.assertEqual(response.status_code, 200)
        return response

    def raw_json(self, method: str, path: str, payload: str):
        return self.client.request(
            method,
            path,
            content=payload.encode("utf-8", "surrogatepass"),
            headers={"content-type": "application/json"},
        )

    def stored_auth(self) -> dict:
        return yaml.safe_load(self.yaml_path.read_text())["settings"]["auth"]


MEMBER_HASH_LINE = '        password_hash: "%s"\n'


def _member_rows(*rows: str) -> str:
    return "    accounts:\n" + "".join(rows)


class PaddedUsernameResourcesTests(_AppSandbox):
    """The live leftover: a padded YAML row lost every resources write."""

    def _claim_with_padded_member(self):
        self.claim(_member_rows(
            '      - username: "kid "\n'
            + MEMBER_HASH_LINE % auth.hash_password(MEMBER_PASSWORD)
            + "        role: member\n"
            "        resources: []\n"
        ))
        self.sign_in()

    def test_resources_write_lands_for_the_padded_row(self):
        """accounts() presents ``"kid "`` as "kid"; the PUT used to answer
        200 with the granted list while services.yaml kept [] forever."""
        self._claim_with_padded_member()
        response = self.client.put(
            "/api/auth/accounts/kid/resources", json={"resources": ["plex"]}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["resources"], ["plex"])
        rows = self.stored_auth()["accounts"]
        self.assertEqual(rows[0]["resources"], ["plex"])
        listing = self.client.get("/api/auth/accounts")
        self.assertEqual(listing.status_code, 200)
        by_name = {r["username"]: r for r in listing.json()["accounts"]}
        self.assertEqual(by_name["kid"]["resources"], ["plex"])

    def test_padded_row_siblings_stay_managed(self):
        """Password reset and delete already stripped — pin that they keep
        working on the same padded row, and that a namesake create is the
        coded 409 rather than a second identity."""
        self._claim_with_padded_member()
        duplicate = self.client.post(
            "/api/auth/accounts",
            json={"username": "kid", "password": MEMBER_PASSWORD},
        )
        self.assertEqual(duplicate.status_code, 409)
        self.assertEqual(duplicate.json()["detail"]["code"], "accounts.exists")
        reset = self.client.post(
            "/api/auth/accounts/kid/password",
            json={"new_password": "fresh-password-12"},
        )
        self.assertEqual(reset.status_code, 200)
        deleted = self.client.delete("/api/auth/accounts/kid")
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(self.stored_auth()["accounts"], [])


class PoisonedAccountRowsHttpTests(_AppSandbox):
    """GET /api/auth/accounts over poisoned services.yaml rows."""

    def _claim_with_poison(self):
        self.claim(_member_rows(
            # Over-cap hex-int username: loads fine as an int, explodes only
            # at str()/dump time — the row must be dropped, not the page.
            f"      - username: {HUGE_HEX}\n"
            '        password_hash: "x"\n'
            "        role: member\n"
            # Lone-surrogate username escape (double-quoted YAML \\uD800).
            '      - username: "\\uD800kid"\n'
            '        password_hash: "x"\n'
            "        role: member\n"
            # A non-dict row.
            '      - "just-a-string"\n'
            # Healthy sibling with junk resources and a junk role.
            "      - username: dave\n"
            + MEMBER_HASH_LINE % auth.hash_password(MEMBER_PASSWORD)
            + f"        role: {HUGE_HEX}\n"
            "        resources:\n"
            f"          - {HUGE_HEX}\n"
            '          - "\\uDFFF"\n'
            '          - "plex"\n'
        ))

    def test_listing_stays_200_and_keeps_the_healthy_rows(self):
        self._claim_with_poison()
        self.sign_in()
        response = self.client.get("/api/auth/accounts")
        self.assertEqual(response.status_code, 200)
        rows = {r["username"]: r for r in response.json()["accounts"]}
        self.assertIn("admin", rows)
        self.assertIn("dave", rows)
        # The poison rows are dropped, not 500ing every healthy sibling.
        self.assertEqual(len(rows), 2)
        # Junk role degrades to member; junk resources are scrubbed to the
        # one renderable id.
        self.assertEqual(rows["dave"]["role"], "member")
        self.assertEqual(rows["dave"]["resources"], ["plex"])

    def test_the_healthy_member_still_signs_in_through_the_poison(self):
        self._claim_with_poison()
        member = TestClient(app(), raise_server_exceptions=False)
        self.sign_in(member, "dave", MEMBER_PASSWORD)


class AccountsWriteBesidePoisonHttpTests(_AppSandbox):
    """Creates/junk bodies over the mounted CRUD routes."""

    def test_create_beside_a_poisoned_sibling_does_not_wipe_it(self):
        """The sibling row carries an over-cap int field; the auth-block
        scrub must drop only that field, never the row, and the new write
        must land beside it."""
        self.claim(_member_rows(
            "      - username: kid\n"
            + MEMBER_HASH_LINE % auth.hash_password(MEMBER_PASSWORD)
            + "        role: member\n"
            f"        junk: {HUGE_HEX}\n"
        ))
        self.sign_in()
        created = self.client.post(
            "/api/auth/accounts",
            json={"username": "eve", "password": "eve-password-12"},
        )
        self.assertEqual(created.status_code, 200)
        rows = self.stored_auth()["accounts"]
        names = [r.get("username") for r in rows]
        self.assertEqual(names, ["kid", "eve"])
        self.assertNotIn("junk", rows[0])
        # What config.mutate does on save must stay possible.
        yaml.safe_dump(self.stored_auth(), allow_unicode=True)

    def test_junk_bodies_stay_coded_4xx(self):
        self.claim()
        self.sign_in()
        for label, method, path, payload in (
            ("huge username literal", "POST", "/api/auth/accounts",
             '{"username": ' + HUGE_LITERAL + ', "password": "x-password-12"}'),
            ("surrogate username", "POST", "/api/auth/accounts",
             '{"username": "\\ud800kid", "password": "x-password-12"}'),
            ("huge resources literal", "PUT", "/api/auth/accounts/kid/resources",
             '{"resources": [' + HUGE_LITERAL + "]}"),
            ("huge password literal", "POST", "/api/auth/accounts/kid/password",
             '{"new_password": ' + HUGE_LITERAL + "}"),
        ):
            with self.subTest(body=label):
                response = self.raw_json(method, path, payload)
                self.assertGreaterEqual(response.status_code, 400)
                self.assertLess(response.status_code, 500)

    def test_surrogate_username_is_rejected_by_the_body_model(self):
        """pydantic's constrained str refuses the lone surrogate — a coded
        422 whose detail the app's sanitized validation handler can encode
        (the stock handler echoing the raw input is what used to 500)."""
        self.claim()
        self.sign_in()
        response = self.raw_json(
            "POST", "/api/auth/accounts",
            '{"username": "\\ud800kid", "password": "x-password-12"}',
        )
        self.assertEqual(response.status_code, 422)
        response.json()  # the detail body itself must stay renderable

    def test_surrogate_resources_are_scrubbed_not_500(self):
        """A lone-surrogate resource id can never name a service; it is
        dropped at creation instead of 500ing Starlette's encoder."""
        self.claim()
        self.sign_in()
        response = self.raw_json(
            "POST", "/api/auth/accounts",
            '{"username": "eve", "password": "eve-password-12", '
            '"resources": ["\\ud800", "plex"]}',
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["account"]["resources"], ["plex"])

    def test_junk_path_usernames_answer_the_coded_404(self):
        self.claim()
        self.sign_in()
        for junk in ("%ED%A0%80", "9" * 4300, "%00"):
            with self.subTest(username=junk):
                response = self.client.delete(f"/api/auth/accounts/{junk}")
                self.assertEqual(response.status_code, 404)
                self.assertEqual(
                    response.json()["detail"]["code"], "accounts.not_found"
                )


_Pw = namedtuple("Pw", "pw_name pw_passwd pw_uid pw_gid pw_gecos pw_dir pw_shell")
#: An already-int past the digit cap: ``int(pw_uid)`` succeeds (no string
#: conversion happens) so only the str() probe can catch it.
HUGE_INT = int("F" * 5000, 16)
SUR = "e\ud800ve"


class _DyingIterator:
    """pwd iterator whose directory service dies after the first row."""

    def __init__(self, first):
        self._rows = iter([first])

    def __iter__(self):
        return self

    def __next__(self):
        try:
            return next(self._rows)
        except StopIteration:
            raise OSError(5, "directory service died")


class UsersEndpointHttpTests(_AppSandbox):
    """GET /api/users through the mounted app and its auth dependency."""

    def _get_users(self, entries):
        self.claim()
        self.sign_in()
        with (
            mock.patch.object(users_svc.pwd, "getpwall", return_value=entries),
            mock.patch.object(users_svc.grp, "getgrnam", side_effect=KeyError),
            mock.patch.object(users_svc.grp, "getgrgid", side_effect=KeyError),
            mock.patch.object(users_svc.os, "getgrouplist", return_value=[20]),
        ):
            return self.client.get("/api/users")

    def test_surrogate_and_huge_uid_rows_cost_only_themselves(self):
        bad = _Pw("mal", "x", HUGE_INT, 20, "Mal", "/Users/mal", "/bin/zsh")
        poisoned = _Pw(SUR, "x", 501, 20, "G\ud800", "/U/\ud800", "/bin/z\ud800")
        good = _Pw("dave", "x", 504, 20, "Dave", "/Users/dave", "/bin/zsh")
        response = self._get_users([bad, poisoned, good])
        self.assertEqual(response.status_code, 200)
        body = response.json()
        names = [u["name"] for u in body["users"]]
        # The huge-uid row is dropped; the surrogate row survives scrubbed.
        self.assertNotIn("mal", names)
        self.assertIn("dave", names)
        self.assertEqual(len(names), 2)
        self.assertNotIn("\ud800", json.dumps(body, ensure_ascii=False))
        self.assertEqual(body["count"], 2)

    def test_getpwall_raising_is_an_empty_page_not_500(self):
        self.claim()
        self.sign_in()
        with mock.patch.object(
            users_svc.pwd, "getpwall", side_effect=OSError(5, "EIO")
        ):
            response = self.client.get("/api/users")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["users"], [])

    def test_directory_service_dying_mid_walk_keeps_collected_rows(self):
        good = _Pw("dave", "x", 504, 20, "Dave", "/Users/dave", "/bin/zsh")
        response = self._get_users(_DyingIterator(good))
        self.assertEqual(response.status_code, 200)
        self.assertEqual([u["name"] for u in response.json()["users"]], ["dave"])


class IdentityHttpTests(_AppSandbox):
    """PUT/GET /api/identity through the mounted app."""

    def setUp(self):
        super().setUp()
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.scutil = Path(tmp.name) / "scutil"
        patcher = mock.patch.object(identity_svc, "SCUTIL", str(self.scutil))
        patcher.start()
        self.addCleanup(patcher.stop)

    def _put(self, body: dict, sh_result):
        with (
            mock.patch.object(identity_svc, "sh", return_value=sh_result),
            mock.patch.object(identity_svc, "get_identity", return_value={}),
        ):
            return self.client.put("/api/identity", json=body)

    def test_vanished_scutil_is_the_coded_503_over_http(self):
        """503 only after the fresh on-disk probe of the same path the spawn
        used — the failure path pays the stat, a success never does."""
        self.claim()
        self.sign_in()
        response = self._put({"computer_name": "HomeLab"}, (-1, "", "not found"))
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["detail"]["code"], "identity.scutil_missing")

    def test_sentinel_with_cli_still_on_disk_keeps_the_raw_result(self):
        """rc -1 is also a signal-killed run; a still-present binary that
        printed exactly "not found" must not upgrade to the 503."""
        self.claim()
        self.sign_in()
        self.scutil.write_text("#!/bin/sh\n")
        response = self._put({"computer_name": "HomeLab"}, (-1, "", "not found"))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["ok"])
        self.assertIn("not found", response.json()["message"])

    def test_surrogate_computer_name_is_the_coded_400(self):
        self.claim()
        self.sign_in()
        with (
            mock.patch.object(identity_svc, "sh") as spawned,
            mock.patch.object(identity_svc, "get_identity", return_value={}),
        ):
            response = self.raw_json(
                "PUT", "/api/identity", '{"computer_name": "Lab\\ud800"}'
            )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"]["code"], "identity.bad_name")
        spawned.assert_not_called()

    def test_huge_comment_literal_body_stays_400(self):
        """json.loads of the >4300-digit literal raises plain ValueError,
        not JSONDecodeError — the body parse must still answer 400."""
        self.claim()
        self.sign_in()
        response = self.raw_json(
            "PUT", "/api/identity", '{"comment": ' + HUGE_LITERAL + "}"
        )
        self.assertEqual(response.status_code, 400)

    def test_surrogate_comment_is_scrubbed_before_yaml(self):
        """The raw ``\\ud800`` used to be persisted into services.yaml where
        every consumer had to re-scrub it forever."""
        self.claim()
        self.sign_in()
        with mock.patch.object(identity_svc, "get_identity", return_value={}):
            response = self.raw_json(
                "PUT", "/api/identity", '{"comment": "Lab\\ud800"}'
            )
        self.assertEqual(response.status_code, 200)
        stored = yaml.safe_load(self.yaml_path.read_text())["settings"]
        # utf-8/"replace" on the *encode* side substitutes "?".
        self.assertEqual(stored["server_comment"], "Lab?")

    def test_get_identity_with_every_cli_vanished_stays_200(self):
        self.claim()
        self.sign_in()
        with (
            mock.patch.object(identity_svc, "sh", return_value=(-1, "", "not found")),
            mock.patch.object(identity_svc, "time_zone", return_value=""),
            mock.patch.object(identity_svc, "platform_string", return_value="mac"),
            mock.patch.object(identity_svc, "effective_host_ip", return_value=""),
        ):
            response = self.client.get("/api/identity")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["computer_name"], "")
        self.assertEqual(body["local_hostname"], "")


if __name__ == "__main__":
    unittest.main()
