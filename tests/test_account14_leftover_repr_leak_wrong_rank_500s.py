"""Fourteenth Account-domain sweep: repr address leaks and wrong-rank drops.

account13 sealed the BaseException-shaped bombs; this sweep hunts what the
guards *themselves* still did wrong on the jobs14/bookmarks14 shapes:

* **fixed — a default-``object.__repr__`` leftover in ``settings.auth``
  rendered a raw heap address into response bodies**: planted as the stored
  username it rode verbatim into the *unauthenticated* GET /api/auth/status
  suggested username (and its function-repr / exception-wrapped variants did
  the same through the C-level ``__repr__`` the slot probe cannot see); as a
  row username it became an account name on GET /api/auth/accounts; as a
  resources element it reached the accounts table and the POST
  /api/auth/login response.  ``_cfg_text``'s coercion arm now drops the
  default-repr shape (slot probe on the real ``type``) and scrubs the
  address-regex belt; real str storage stays verbatim data.
* **fixed — genuine str storage riding a ``__str__`` bomb was dropped at
  the wrong rank**: the dispatching ``str(raw)`` ran the override first, so
  a real-str ``password_hash`` read as "" — the administrator's sessions
  stopped verifying and every login 401'd — and a real-str member username
  read as "" and vaporized the whole account.  ``_cfg_text`` now reads real
  str storage through unbound ``str.__str__`` (the jobs14 ``_str_text``
  rule), so the honest text underneath the bomb is kept.
* **fixed — a genuine int logout counter whose ``__class__`` lied ``bool``
  read as 0** through ``_epoch_count``'s ``_isinst`` gate (isinstance
  honours the lie once the real-type check misses): logout answered 200 and
  recorded the bump, and every "revoked" cookie quietly went back to
  verifying for its full 7-day TTL.  The bool arm now probes the C-level
  type slot (``_real``), which the lie cannot swap.

Plus stays-immune pins: the encode-bomb str hash that the exact-str
laundering already recovered, real str data containing an address-shaped
substring staying verbatim, a real bool epoch still reading 0, and the
coercion arm still rendering honest scalars.
"""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi.testclient import TestClient

from hub import audit, auth, config
from hub.app_factory import create_app

PASSWORD = "correct-horse-battery"
MEMBER_PASSWORD = "kid-password-12"

#: CPython's angle-repr shape — a raw heap address, never account data.
ADDR = re.compile(r" at 0x[0-9a-fA-F]+>")

_APP = None


def app():
    global _APP
    if _APP is None:
        _APP = create_app()
    return _APP


# ── leftover shapes ───────────────────────────────────────────────────────────
class Blank:
    """Never overrides __str__/__repr__: str() answers object.__repr__ —
    ``<… object at 0x7f…>``, a raw heap address."""


class StrBombStr(str):
    """Genuine str storage whose ``__str__`` override raises.

    The honest text sits in the C-level storage; only the dispatching
    ``str()`` detonates.  Dropping it to "" threw a real credential / a
    real account name away at the wrong rank.
    """

    def __str__(self):  # noqa: D105
        raise RuntimeError("leftover __str__ bomb")


class EncodeBombStr(str):
    """Genuine str storage whose ``__str__`` returns itself and ``encode``
    raises — the json6 shape the exact-str laundering already recovers."""

    def __str__(self):  # noqa: D105
        return self

    def encode(self, *a, **k):  # noqa: D102
        raise RuntimeError("leftover encode bomb")


class LyingBoolInt(int):
    """Genuine int storage whose ``__class__`` property lies ``bool``."""

    @property
    def __class__(self):  # noqa: D105
        return bool


class _AppSandbox(unittest.TestCase):
    """Scratch services.yaml + data dir with one admin + one member account."""

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
            (audit, "AUDIT_PATH", data / "auth-audit.jsonl"),
        ):
            patcher = mock.patch.object(target, attr, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(config.reload_cfg)
        self.addCleanup(auth._token_fallbacks.clear)
        auth._secret_cache = None
        auth._token_fallbacks.clear()
        auth._login_attempts.clear()
        self.admin_hash = auth.hash_password(PASSWORD)
        self.member_hash = auth.hash_password(MEMBER_PASSWORD)
        self.yaml_path.write_text(
            "settings:\n  auth:\n    enabled: true\n    username: admin\n"
            f'    password_hash: "{self.admin_hash}"\n'
            "    accounts:\n"
            "    - username: kid\n"
            f'      password_hash: "{self.member_hash}"\n'
            "      role: member\n"
            "      resources: []\n",
            encoding="utf-8",
        )
        config.reload_cfg()
        self.client = TestClient(app(), raise_server_exceptions=False)
        self.sign_in()

    def base_auth(self, **extra) -> dict:
        block = {
            "enabled": True,
            "username": "admin",
            "password_hash": self.admin_hash,
        }
        block.update(extra)
        return {"settings": {"auth": block}}

    def member_row(self, **extra) -> dict:
        row = {
            "username": "kid",
            "password_hash": self.member_hash,
            "role": "member",
            "resources": [],
        }
        row.update(extra)
        return row

    def poisoned(self, cfg_value):
        """Serve *cfg_value* to every hub.auth reader (auth imports cfg)."""
        return mock.patch.object(auth, "cfg", return_value=cfg_value)

    def sign_in(self, client=None, username="admin", password=PASSWORD):
        auth._login_attempts.clear()
        response = (client or self.client).post(
            "/api/auth/login", json={"username": username, "password": password}
        )
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertTrue(response.json().get("ok"), response.text[:300])
        return response

    def assertNoAddress(self, response):
        """No heap address anywhere in the body, and it re-encodes clean."""
        self.assertIsNone(ADDR.search(response.text), response.text[:400])
        json.dumps(response.json(), ensure_ascii=False, allow_nan=False)


class ReprAddressLeakTests(_AppSandbox):
    """Default-repr leftovers must never render a heap address into a body."""

    def test_default_repr_username_never_leaks_into_unclaimed_status(self):
        # No hash in the poisoned block: setup_required is True, so the
        # unauthenticated status offers a suggested username — which used to
        # be the leftover's object.__repr__, heap address and all, to any
        # scanner with no credential at all.
        scanner = TestClient(app(), raise_server_exceptions=False)
        with self.poisoned({"settings": {"auth": {"username": Blank()}}}):
            status = scanner.get("/api/auth/status")
            self.assertEqual(status.status_code, 200, status.text[:300])
            self.assertNoAddress(status)
            self.assertEqual(status.json()["username"], "admin")

    def test_function_repr_username_takes_the_belt_not_the_body(self):
        # A function's C-level __repr__ is invisible to the slot probe (the
        # type overrides __repr__), so only the address-regex belt sees it.
        scanner = TestClient(app(), raise_server_exceptions=False)
        with self.poisoned({"settings": {"auth": {"username": lambda: None}}}):
            status = scanner.get("/api/auth/status")
            self.assertEqual(status.status_code, 200, status.text[:300])
            self.assertNoAddress(status)
            self.assertEqual(status.json()["username"], "admin")

    def test_exception_wrapping_a_junk_arg_renders_no_address(self):
        # str(RuntimeError(<junk>)) renders the *message object's* default
        # repr — an address embedded in otherwise honest-looking text.
        scanner = TestClient(app(), raise_server_exceptions=False)
        with self.poisoned(
            {"settings": {"auth": {"username": RuntimeError(Blank())}}}
        ):
            status = scanner.get("/api/auth/status")
            self.assertEqual(status.status_code, 200, status.text[:300])
            self.assertNoAddress(status)
            self.assertEqual(status.json()["username"], "admin")

    def test_default_repr_row_username_drops_the_row_not_an_address(self):
        # The junk row used to be *listed* under its heap-address name on
        # the Users table; it now drops like any other unusable name while
        # its healthy sibling stays.
        shape = self.base_auth(
            accounts=[self.member_row(username=Blank()), self.member_row()]
        )
        with self.poisoned(shape):
            listing = self.client.get("/api/auth/accounts")
            self.assertEqual(listing.status_code, 200, listing.text[:300])
            self.assertNoAddress(listing)
            names = [a["username"] for a in listing.json()["accounts"]]
            self.assertIn("kid", names)

    def test_default_repr_resources_element_drops_alone(self):
        # The poisoned element costs itself only — on the admin's table and
        # in the member's own login response body.
        shape = self.base_auth(
            accounts=[self.member_row(resources=[Blank(), "files"])]
        )
        with self.poisoned(shape):
            listing = self.client.get("/api/auth/accounts")
            self.assertEqual(listing.status_code, 200, listing.text[:300])
            self.assertNoAddress(listing)
            rows = {a["username"]: a for a in listing.json()["accounts"]}
            self.assertEqual(rows["kid"]["resources"], ["files"])
            member = TestClient(app(), raise_server_exceptions=False)
            login = self.sign_in(member, "kid", MEMBER_PASSWORD)
            self.assertNoAddress(login)
            self.assertEqual(login.json()["resources"], ["files"])


class GenuineStrRecoveryTests(_AppSandbox):
    """Real str storage behind a bombed override keeps its honest text."""

    def test_str_bomb_member_username_keeps_the_member_signing_in(self):
        # The dispatching str() used to run the override, read "", and drop
        # the whole account: the member's login 401'd and the row vanished
        # from the Users table even though the name was right there in the
        # C-level storage the unbound read now answers.
        shape = self.base_auth(
            accounts=[self.member_row(username=StrBombStr("kid"))]
        )
        with self.poisoned(shape):
            member = TestClient(app(), raise_server_exceptions=False)
            self.sign_in(member, "kid", MEMBER_PASSWORD)
            listing = self.client.get("/api/auth/accounts")
            self.assertEqual(listing.status_code, 200, listing.text[:300])
            names = [a["username"] for a in listing.json()["accounts"]]
            self.assertIn("kid", names)

    def test_str_bomb_admin_hash_keeps_sessions_verifying(self):
        # A real-str hash riding the bomb used to read as "": the admin's
        # outstanding session stopped verifying and every login 401'd —
        # the credential died at the wrong rank.
        with self.poisoned(
            self.base_auth(password_hash=StrBombStr(self.admin_hash))
        ):
            status = self.client.get("/api/auth/status")
            self.assertEqual(status.status_code, 200, status.text[:300])
            self.assertTrue(status.json()["authenticated"], status.text[:300])
            self.sign_in()

    def test_encode_bomb_hash_stays_recovered(self):
        # Pinned: the exact-str laundering already kept this shape's text;
        # the unbound-read rewrite must not regress it.
        with self.poisoned(
            self.base_auth(password_hash=EncodeBombStr(self.admin_hash))
        ):
            status = self.client.get("/api/auth/status")
            self.assertEqual(status.status_code, 200, status.text[:300])
            self.assertTrue(status.json()["authenticated"], status.text[:300])


class LyingBoolEpochTests(_AppSandbox):
    """A logout counter lying ``bool`` must not un-revoke sessions."""

    def test_lying_bool_epoch_keeps_the_revocation(self):
        # setUp signed in at epoch 0.  An honest counter of 1 revokes that
        # cookie; the same count behind a lying __class__ used to read as 0
        # and quietly resurrect it for its full TTL.
        with self.poisoned(
            self.base_auth(session_epochs={"admin": LyingBoolInt(1)})
        ):
            status = self.client.get("/api/auth/status")
            self.assertEqual(status.status_code, 200, status.text[:300])
            self.assertFalse(status.json()["authenticated"], status.text[:300])

    def test_real_bool_epoch_still_reads_zero(self):
        # Pinned: YAML true/false-ish junk in an epoch slot keeps counting
        # as 0 — the epoch-0 cookie keeps verifying, no 500 either way.
        with self.poisoned(self.base_auth(session_epochs={"admin": True})):
            status = self.client.get("/api/auth/status")
            self.assertEqual(status.status_code, 200, status.text[:300])
            self.assertTrue(status.json()["authenticated"], status.text[:300])


class GuardUnitTests(unittest.TestCase):
    """The hardened helpers' contracts, in isolation."""

    def test_cfg_text_drops_the_default_repr_shape(self):
        self.assertEqual(auth._cfg_text(Blank()), "")
        self.assertEqual(auth._cfg_text(object()), "")

    def test_cfg_text_belt_catches_the_c_level_repr(self):
        self.assertEqual(auth._cfg_text(lambda: None), "")
        self.assertEqual(auth._cfg_text(RuntimeError(Blank())), "")

    def test_cfg_text_recovers_real_str_storage_under_the_bomb(self):
        self.assertEqual(auth._cfg_text(StrBombStr("kid")), "kid")
        self.assertEqual(auth._cfg_text(EncodeBombStr("kid")), "kid")

    def test_cfg_text_keeps_real_str_data_verbatim(self):
        # An operator's actual text is data, address-shaped or not: the
        # belt runs on the coercion arm only.
        self.assertEqual(auth._cfg_text("srv at 0xdead>"), "srv at 0xdead>")

    def test_cfg_text_still_renders_honest_scalars(self):
        self.assertEqual(auth._cfg_text(123), "123")
        self.assertEqual(auth._cfg_text(True), "True")

    def test_epoch_count_reads_the_lying_bool_counter_honestly(self):
        self.assertEqual(auth._epoch_count(LyingBoolInt(5)), 5)

    def test_epoch_count_still_reads_a_real_bool_as_zero(self):
        self.assertEqual(auth._epoch_count(True), 0)
        self.assertEqual(auth._epoch_count(False), 0)

    def test_real_probe_reads_the_type_slot_not_the_lie(self):
        self.assertFalse(auth._real(LyingBoolInt(1), bool))
        self.assertTrue(auth._real(LyingBoolInt(1), int))
        self.assertTrue(auth._real(True, bool))

    def test_control_flow_keeps_propagating(self):
        # The coercion arm's union guard must not swallow a Ctrl-C.
        class _KIStr:
            def __str__(self):  # noqa: D105
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            auth._cfg_text(_KIStr())


if __name__ == "__main__":
    unittest.main(verbosity=2)
