"""Leftover 500s on auth / 2FA after the last_counter-inf and surrogate-encode fixes.

JSON ``1e309`` in any twofa.json field (not just last_counter), a sibling
Infinity row, YAML ``username: "\\ud800"``, a leftover ``.session-secret``
directory, and ``urllib.parse.quote`` on a lone-surrogate account name each
used to raise on the request path.

Follow-up leftovers: inf/NaN/bytes extra fields and a leftover list-vs-dict
``keys`` document 500'd API-key listing/create/Bearer persist; a leftover
store or ``.lock`` directory (and EIO replacing it) 500'd enroll and key
create; pwd ``pw_gecos`` bytes / ``\\ud800`` and getpwall EIO 500'd GET
``/api/users``; leftover ``\\ud800`` account resources 500'd create/update.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import os
import unittest
from collections import namedtuple
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from fastapi import HTTPException, Request

from hub import api_keys, auth, totp, twofa_svc, users_svc
from hub.routers import accounts_api, api_keys_api, auth_api

NOW = 1_700_000_000


def _request() -> Request:
    return Request({
        "type": "http",
        "method": "GET",
        "path": "/api/auth/status",
        "headers": [],
        "scheme": "http",
        "server": ("localhost", 8086),
        "client": ("127.0.0.1", 1),
    })


def _starlette_json(payload) -> bytes:
    """Starlette JSONResponse encoding: allow_nan=False + UTF-8."""
    return json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _code_at(secret: str, timestamp: int) -> str:
    return totp.totp_at(secret, timestamp)


class TwofaLeftoverStoreTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = Path(tmp.name) / "twofa.json"
        patcher = mock.patch.object(twofa_svc, "STORE_FILE", self.store)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.huge = json.loads("1e309")

    def test_leftover_inf_extra_field_does_not_500_totp_verify(self):
        secret = totp.generate_secret()
        self.store.write_text(json.dumps({
            "admin": {
                "enabled": True,
                "secret": secret,
                "last_counter": 0,
                "recovery": [self.huge, "aa"],
                "note": self.huge,
            },
        }))
        code = _code_at(secret, NOW + 60)
        self.assertTrue(twofa_svc.verify_totp_code("admin", code, timestamp=NOW + 60))
        stored = json.loads(self.store.read_text())
        json.dumps(stored, allow_nan=False)
        self.assertIsInstance(stored["admin"]["last_counter"], int)

    def test_sibling_inf_row_does_not_500_enroll_or_disable(self):
        self.store.write_text(json.dumps({
            "kid": self.huge,
            "admin": {"enabled": False, "recovery": self.huge},
        }))
        enrollment = twofa_svc.begin_enrollment("admin")
        self.assertTrue(enrollment["secret"])
        self.assertFalse(twofa_svc.disable("nobody"))
        json.dumps(json.loads(self.store.read_text()), allow_nan=False)

    def test_leftover_surrogate_in_store_does_not_500_save(self):
        self.store.write_text(json.dumps({
            "admin": {"enabled": False, "secret": "\ud800", "label": "\ud800"},
        }))
        twofa_svc.begin_enrollment("admin")
        json.dumps(json.loads(self.store.read_text()), ensure_ascii=False)

    def test_enroll_lone_surrogate_username_does_not_500(self):
        out = twofa_svc.begin_enrollment("\ud800")
        self.assertIn("otpauth://totp/", out["otpauth_uri"])
        _starlette_json(out)

    def test_deeply_nested_store_does_not_500_load(self):
        """``json.loads`` RecursionError is not ValueError; login used to 500."""
        self.store.write_text('{"k":' * 12000 + "1" + "}" * 12000)
        self.assertEqual(twofa_svc._load(), {})

    def test_loadable_nested_extra_field_does_not_500_save(self):
        """A nest just under the JSON cap RecursionError'd ``_json_safe`` on enroll."""
        extra = {}
        cur = extra
        for _ in range(40):
            cur["k"] = {}
            cur = cur["k"]
        self.store.write_text(json.dumps({
            "admin": {"enabled": False, "extra": extra},
        }))
        out = twofa_svc.begin_enrollment("admin")
        self.assertTrue(out["secret"])
        json.dumps(json.loads(self.store.read_text()), allow_nan=False)

    def test_huge_store_does_not_oom_status(self):
        """``read_text()`` of leftover multi-MB twofa.json used to OOM login."""
        self.store.write_bytes(b"x" * (2 * 1024 * 1024))
        snap = twofa_svc.status("admin")
        _starlette_json(snap)
        self.assertFalse(snap["enabled"])

    def test_nested_row_under_parser_cap_does_not_500_save(self):
        """A nest json.loads accepts then RecursionError'd the Python walker on save."""
        nested = {"enabled": False, "secret": "A"}
        for _ in range(80):
            nested = {"child": nested}
        self.store.write_text(json.dumps({"admin": nested}))
        out = twofa_svc.begin_enrollment("kid")
        self.assertTrue(out["secret"])
        _starlette_json(out)
        json.dumps(json.loads(self.store.read_text()), allow_nan=False)

    def test_leftover_inf_time_does_not_500_confirm(self):
        """``int(time.time())`` OverflowError on leftover inf used to 500 enroll confirm."""
        enrollment = twofa_svc.begin_enrollment("admin")
        secret = enrollment["secret"]
        code = _code_at(secret, NOW)
        with mock.patch.object(twofa_svc.time, "time", return_value=float("inf")):
            codes = twofa_svc.confirm_enrollment("admin", code, timestamp=NOW)
        self.assertTrue(codes)
        stored = json.loads(self.store.read_text())
        json.dumps(stored, allow_nan=False)
        self.assertEqual(stored["admin"]["confirmed_at"], 0)

    def test_leftover_inf_does_not_500_recovery_spend(self):
        enrollment = twofa_svc.begin_enrollment("admin")
        secret = enrollment["secret"]
        codes = twofa_svc.confirm_enrollment(
            "admin", _code_at(secret, NOW), timestamp=NOW
        )
        raw = json.loads(self.store.read_text())
        raw["admin"]["extra"] = self.huge
        raw["kid"] = self.huge
        self.store.write_text(json.dumps(raw))
        self.assertTrue(twofa_svc.use_recovery_code("admin", codes[0]))
        json.dumps(json.loads(self.store.read_text()), allow_nan=False)


class TotpUriLeftoverTests(unittest.TestCase):
    def test_otpauth_uri_lone_surrogate_account_does_not_500(self):
        uri = totp.otpauth_uri(totp.generate_secret(), "adm\ud800in")
        self.assertTrue(uri.startswith("otpauth://totp/"))

    def test_leftover_inf_timestamp_does_not_500_verify(self):
        """``int(inf)`` OverflowError'd TOTP verify; JSON 1e309 is inf."""
        secret = totp.generate_secret()
        for stamp in (float("inf"), float("-inf"), float("nan"), json.loads("1e309"), 10**100):
            with self.subTest(stamp=stamp):
                self.assertIsNone(totp.verify(secret, "123456", timestamp=stamp))

    def test_leftover_uint64_max_counter_window_does_not_500(self):
        """Drift window past 2**64 used to OverflowError struct.pack on verify."""
        secret = totp.generate_secret()
        stamp = (2**64 - 1) * totp.STEP_SECONDS
        self.assertIsNone(totp.verify(secret, "123456", timestamp=stamp))


class SessionClockLeftoverTests(unittest.TestCase):
    def test_create_session_infinite_clock_does_not_500(self):
        """int(time.time()) OverflowError on leftover inf used to 500 login."""
        cfg = {"username": "admin", "password_hash": "hash-admin"}
        with (
            mock.patch.object(auth, "_auth_cfg", return_value=cfg),
            mock.patch.object(auth, "_secret", return_value=b"x" * 32),
            mock.patch.object(auth.time, "time", return_value=float("inf")),
        ):
            token = auth.create_session("admin")
        self.assertTrue(token)
        self.assertIsInstance(token, str)

    def test_pending_totp_infinite_clock_does_not_500(self):
        cfg = {"username": "admin", "password_hash": "hash-admin"}
        with (
            mock.patch.object(auth, "_auth_cfg", return_value=cfg),
            mock.patch.object(auth, "_secret", return_value=b"x" * 32),
            mock.patch.object(auth.time, "time", return_value=float("inf")),
        ):
            token = auth.create_pending_totp_token("admin")
        self.assertTrue(token)
        self.assertIsInstance(token, str)


class SessionSecretLeftoverTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        auth._secret_cache = None
        self.addCleanup(setattr, auth, "_secret_cache", None)

    def test_huge_secret_file_does_not_oom_session(self):
        """``read_bytes()`` of leftover multi-MB ``.session-secret`` used to OOM login."""
        sec = self.root / "secret"
        sec.write_bytes(b"x" * (2 * 1024 * 1024))
        cfg = {"username": "admin", "password_hash": "hash-admin"}
        with (
            mock.patch.object(auth, "SECRET_FILE", sec),
            mock.patch.object(auth, "_auth_cfg", return_value=cfg),
        ):
            auth._secret_cache = None
            token = auth.create_session("admin")
            self.assertEqual(len(auth._secret()), 32)
            self.assertTrue(auth.verify_session(token))

    def test_huge_setup_token_does_not_oom(self):
        """``read_text()`` of leftover multi-MB ``.setup-token`` used to OOM setup."""
        path = self.root / "setup-token"
        path.write_bytes(b"x" * (2 * 1024 * 1024))
        value = auth._persistent_token(path)
        self.assertLessEqual(len(value), 128)
        self.assertTrue(value)

    def test_leftover_setup_token_directory_does_not_500(self):
        path = self.root / "setup-token-dir"
        path.mkdir()
        value = auth._persistent_token(path)
        self.assertTrue(value)
        self.assertLessEqual(len(value), 128)

    def test_huge_secret_fileexists_race_does_not_oom_session(self):
        """FileExistsError path used ``read_bytes()`` unbounded after a leftover multi-MB file."""
        sec = self.root / "secret-race"
        sec.write_bytes(b"x" * (2 * 1024 * 1024))
        real_open = os.open

        def fake_open(path, flags, mode=0o777, *args, **kwargs):
            if str(path) == str(sec):
                raise FileExistsError(17, "exists")
            return real_open(path, flags, mode, *args, **kwargs)

        cfg = {"username": "admin", "password_hash": "hash-admin"}
        with (
            mock.patch.object(auth, "SECRET_FILE", sec),
            mock.patch.object(auth, "_auth_cfg", return_value=cfg),
            mock.patch("hub.auth.os.open", side_effect=fake_open),
            mock.patch.object(Path, "unlink", side_effect=OSError(1, "denied")),
        ):
            auth._secret_cache = None
            token = auth.create_session("admin")
            self.assertEqual(len(auth._secret()), 32)
            self.assertTrue(auth.verify_session(token))

    def test_leftover_secret_directory_does_not_500_session(self):
        sec = self.root / "secret-as-dir"
        sec.mkdir()
        cfg = {
            "username": "admin",
            "password_hash": "hash-admin",
        }
        with (
            mock.patch.object(auth, "SECRET_FILE", sec),
            mock.patch.object(auth, "_auth_cfg", return_value=cfg),
        ):
            auth._secret_cache = None
            token = auth.create_session("admin")
            self.assertTrue(auth.verify_session(token))
            self.assertEqual(auth.session_username(token), "admin")

    def test_well_formed_cookie_plus_secret_dir_does_not_500_verify(self):
        sec = self.root / "secret-as-dir"
        sec.mkdir()
        payload = b"admin|9999999999|0123456789abcdef"
        raw = base64.urlsafe_b64encode(payload + b"." + b"x" * 32).decode().rstrip("=")
        with mock.patch.object(auth, "SECRET_FILE", sec):
            auth._secret_cache = None
            self.assertFalse(auth.verify_session(raw))

    def test_non_ascii_signed_version_does_not_500_verify(self):
        sec = self.root / "sec"
        cfg = {"username": "admin", "password_hash": "hash-admin"}
        with (
            mock.patch.object(auth, "SECRET_FILE", sec),
            mock.patch.object(auth, "_auth_cfg", return_value=cfg),
        ):
            auth._secret_cache = None
            secret = auth._secret()
            payload = "admin|9999999999|versíon".encode()
            sig = hmac.new(secret, payload, hashlib.sha256).digest()
            token = base64.urlsafe_b64encode(payload + b"." + sig).decode().rstrip("=")
            self.assertFalse(auth.verify_session(token))
            pending_payload = "totp-pending|admin|9999999999|versíon".encode()
            pending = base64.urlsafe_b64encode(
                pending_payload + b"." + hmac.new(secret, pending_payload, hashlib.sha256).digest()
            ).decode().rstrip("=")
            self.assertEqual(auth.pending_totp_username(pending), "")


class AuthApiLeftoverJsonTests(unittest.TestCase):
    def test_leftover_surrogate_setup_username_does_not_500_status(self):
        with mock.patch.object(
            auth, "_auth_cfg", return_value={"username": "\ud800"}
        ):
            body = auth_api.auth_status(_request())
        _starlette_json(body)
        self.assertEqual(body["username"], "admin")
        self.assertTrue(body["setup_required"])

    def test_leftover_surrogate_resources_do_not_500_json(self):
        cfg = {
            "username": "admin",
            "password_hash": "hash-admin",
            "accounts": [{
                "username": "mom",
                "password_hash": "hash-mom",
                "role": "member",
                "resources": ["jellyfin", "\ud800", "\udfff"],
            }],
        }
        with mock.patch.object(auth, "_auth_cfg", return_value=cfg):
            resources = auth.allowed_resources("mom")
            names = list(auth.accounts())
        _starlette_json({"resources": resources, "accounts": names})
        self.assertEqual(resources, ["jellyfin"])
        self.assertIn("mom", names)

    def test_leftover_surrogate_list_account_is_dropped(self):
        cfg = {
            "username": "admin",
            "password_hash": "hash-admin",
            "accounts": [{"username": "\ud800", "password_hash": "x", "role": "member"}],
        }
        with mock.patch.object(auth, "_auth_cfg", return_value=cfg):
            self.assertNotIn("\ud800", auth.accounts())
            _starlette_json({"accounts": list(auth.accounts())})

    def test_leftover_surrogate_resources_do_not_500_create(self):
        with mock.patch.object(auth, "config_mutate"):
            out = auth.create_account(
                "kid", "correct-horse", resources=["jellyfin", "\ud800"]
            )
        _starlette_json(out)
        self.assertEqual(out["resources"], ["jellyfin"])

    def test_leftover_inf_resources_do_not_500_create(self):
        with mock.patch.object(auth, "config_mutate"):
            out = auth.create_account(
                "kid", "correct-horse", resources=json.loads("1e309")
            )
        _starlette_json(out)
        self.assertEqual(out["resources"], [])

    def test_leftover_surrogate_resources_do_not_500_set(self):
        with (
            mock.patch.object(
                auth, "account",
                return_value={"username": "mom", "role": auth.ROLE_MEMBER},
            ),
            mock.patch.object(auth, "config_mutate"),
        ):
            granted = auth.set_account_resources("mom", ["jellyfin", "\ud800"])
        _starlette_json({"resources": granted})
        self.assertEqual(granted, ["jellyfin"])

    def test_recursing_setup_valueerror_is_coded_not_500(self):
        """``str(exc)`` RecursionError used to 500 POST /api/auth/setup."""
        class Recursing(ValueError):
            def __str__(self):
                raise RecursionError("nested")

        body = auth_api.SetupBody(username="admin", password="correct-horse")
        with (
            mock.patch.object(auth, "setup_required", return_value=True),
            mock.patch.object(auth, "complete_setup", side_effect=Recursing("bad_username")),
        ):
            with self.assertRaises(HTTPException) as ctx:
                auth_api.auth_setup(body, _request(), mock.Mock())
        _starlette_json(ctx.exception.detail)
        self.assertEqual(ctx.exception.detail["code"], "auth.password_too_short")

    def test_recursing_account_error_is_coded_not_500(self):
        """``str(exc)`` RecursionError used to 500 POST /api/accounts."""
        class Recursing(ValueError):
            def __str__(self):
                raise RecursionError("nested")

        err = accounts_api._account_error(Recursing("exists"))
        self.assertIsInstance(err, HTTPException)
        _starlette_json(err.detail)
        self.assertEqual(err.detail["code"], "accounts.bad_username")


class TwofaLeftoverNodeTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = Path(tmp.name) / "twofa.json"
        patcher = mock.patch.object(twofa_svc, "STORE_FILE", self.store)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_leftover_store_directory_does_not_500_enroll(self):
        self.store.mkdir()
        out = twofa_svc.begin_enrollment("admin")
        self.assertTrue(out["secret"])
        _starlette_json(out)
        self.assertTrue(self.store.is_file())

    def test_leftover_lock_directory_does_not_500_enroll(self):
        lock = Path(str(self.store) + ".lock")
        lock.mkdir()
        out = twofa_svc.begin_enrollment("admin")
        self.assertTrue(out["secret"])
        _starlette_json(out)

    def test_leftover_eio_on_save_does_not_500_enroll(self):
        with mock.patch.object(
            twofa_svc.secure_io, "replace_secret_text",
            side_effect=OSError(5, "I/O error"),
        ):
            out = twofa_svc.begin_enrollment("admin")
        self.assertTrue(out["secret"])
        _starlette_json(out)

    def test_leftover_eio_on_lock_open_does_not_500_enroll(self):
        real_open = os.open

        def fake_open(path, flags, mode=0o777, *args, **kwargs):
            if str(path).endswith(".lock"):
                raise OSError(5, "I/O error")
            return real_open(path, flags, mode, *args, **kwargs)

        with mock.patch("hub.twofa_svc.os.open", side_effect=fake_open):
            out = twofa_svc.begin_enrollment("admin")
        self.assertTrue(out["secret"])
        _starlette_json(out)


class ApiKeysLeftoverStoreTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = Path(tmp.name) / "api-keys.json"
        patcher = mock.patch.object(api_keys, "STORE_FILE", self.store)
        patcher.start()
        self.addCleanup(patcher.stop)
        api_keys._last_seen.clear()
        self.huge = json.loads("1e309")

    def test_leftover_inf_extra_field_does_not_500_create_or_verify(self):
        rec, token = api_keys.create("mon", "member")
        raw = json.loads(self.store.read_text())
        raw["keys"][0]["note"] = self.huge
        raw["keys"][0]["flag"] = float("nan")
        self.store.write_text(json.dumps(raw))
        sibling, _ = api_keys.create("other", "member")
        _starlette_json(sibling)
        hit = api_keys.verify(token)
        self.assertIsNotNone(hit)
        _starlette_json(hit)
        listed = api_keys.list_public()
        _starlette_json(listed)
        json.dumps(json.loads(self.store.read_text()), allow_nan=False)

    def test_leftover_bytes_in_record_do_not_500_save(self):
        rec, token = api_keys.create("mon", "member")
        keys = api_keys._load()
        keys[0]["blob"] = b"\xff\xfe"
        keys[0]["name"] = b"mon"
        api_keys._save(keys)
        stored = json.loads(self.store.read_text())
        json.dumps(stored, ensure_ascii=False, allow_nan=False)
        listed = api_keys.list_public()
        _starlette_json(listed)
        self.assertEqual(listed[0]["id"], rec["id"])
        self.assertIsNotNone(api_keys.verify(token))

    def test_deeply_nested_store_does_not_500_list(self):
        """``json.loads`` RecursionError is not ValueError; Bearer used to 500."""
        self.store.write_text('{"k":' * 12000 + "1" + "}" * 12000)
        self.assertEqual(api_keys.list_public(), [])

    def test_huge_store_does_not_oom_list_or_verify(self):
        """``read_text()`` of leftover multi-MB api-keys.json used to OOM Bearer."""
        self.store.write_bytes(b"x" * (2 * 1024 * 1024))
        listed = api_keys.list_public()
        _starlette_json(listed)
        self.assertEqual(listed, [])
        self.assertIsNone(api_keys.verify("shk_" + "A" * 43))

    def test_leftover_keys_inf_does_not_500_list_or_create(self):
        self.store.write_text(json.dumps({"keys": self.huge}))
        self.assertEqual(api_keys.list_public(), [])
        rec, _ = api_keys.create("n", "member")
        _starlette_json(rec)
        json.dumps(json.loads(self.store.read_text()), allow_nan=False)

    def test_leftover_top_level_list_is_read(self):
        rec, token = api_keys.create("mon", "member")
        raw = json.loads(self.store.read_text())
        self.store.write_text(json.dumps(raw["keys"]))
        listed = api_keys.list_public()
        _starlette_json(listed)
        self.assertEqual(listed[0]["name"], "mon")
        self.assertIsNotNone(api_keys.verify(token))

    def test_leftover_keys_dict_is_read(self):
        rec, token = api_keys.create("mon", "member")
        raw = json.loads(self.store.read_text())
        self.store.write_text(json.dumps({"keys": {rec["id"]: raw["keys"][0]}}))
        listed = api_keys.list_public()
        _starlette_json(listed)
        self.assertEqual(listed[0]["id"], rec["id"])
        self.assertIsNotNone(api_keys.verify(token))

    def test_leftover_surrogate_name_does_not_500_list_or_create(self):
        rec, _ = api_keys.create("mon", "member")
        raw = json.loads(self.store.read_text())
        raw["keys"][0]["name"] = "\ud800"
        self.store.write_text(json.dumps(raw))
        listed = api_keys.list_public()
        _starlette_json(listed)
        sibling, _ = api_keys.create("ok", "member")
        _starlette_json(sibling)
        json.dumps(json.loads(self.store.read_text()), ensure_ascii=False, allow_nan=False)

    def test_create_surrogate_name_does_not_500(self):
        rec, _ = api_keys.create("adm\ud800in", "member")
        _starlette_json(rec)
        self.assertTrue(rec["name"])

    def test_public_view_leftover_bytes_and_inf_do_not_500(self):
        view = api_keys.public_view({
            "id": b"ak_x",
            "name": b"mon",
            "role": b"member",
            "created": self.huge,
            "expires": b"never",
            "last_used": b"1724000000",
        })
        _starlette_json(view)
        self.assertEqual(view["name"], "mon")
        self.assertIsNone(view["created"])

    def test_leftover_store_directory_does_not_500_create(self):
        self.store.mkdir()
        rec, token = api_keys.create("n", "member")
        _starlette_json(rec)
        self.assertTrue(self.store.is_file())
        self.assertIsNotNone(api_keys.verify(token))

    def test_leftover_lock_directory_does_not_500_create(self):
        lock = Path(str(self.store) + ".lock")
        lock.mkdir()
        rec, _ = api_keys.create("n", "member")
        _starlette_json(rec)

    def test_leftover_eio_on_save_does_not_500_create(self):
        with mock.patch.object(
            api_keys.secure_io, "replace_secret_text",
            side_effect=OSError(5, "I/O error"),
        ):
            rec, _ = api_keys.create("n", "member")
        _starlette_json(rec)

    def test_create_inf_expires_days_is_coded_not_500(self):
        with self.assertRaises(ValueError) as raised:
            api_keys.create("n", "member", expires_days=self.huge)
        self.assertEqual(str(raised.exception), "bad_expiry")

    def test_recursing_create_valueerror_is_coded_not_500(self):
        """``str(exc)`` RecursionError used to 500 POST /api/api-keys."""
        class Recursing(ValueError):
            def __str__(self):
                raise RecursionError("nested")

        body = api_keys_api.ApiKeyCreateBody(name="mon", role="member")
        with (
            mock.patch.object(
                api_keys_api, "require_admin_browser", return_value="admin",
            ),
            mock.patch.object(
                api_keys_api.api_keys, "create", side_effect=Recursing("bad_name"),
            ),
        ):
            with self.assertRaises(HTTPException) as ctx:
                api_keys_api.api_keys_create(body, mock.Mock())
        _starlette_json(ctx.exception.detail)
        self.assertEqual(ctx.exception.detail["code"], "apikeys.name_required")

    def test_save_dumps_recursion_does_not_500(self):
        """json.dumps RecursionError is not OSError; create used to 500."""
        rec, token = api_keys.create("mon", "member")
        with mock.patch.object(api_keys.json, "dumps", side_effect=RecursionError):
            api_keys._save([{"id": rec["id"], "name": "mon", "role": "member"}])
        stored = json.loads(self.store.read_text())
        json.dumps(stored, allow_nan=False)
        self.assertTrue(stored.get("keys"))

    def test_inf_clock_does_not_500_create_or_verify(self):
        """``int(time.time())`` OverflowError on leftover inf used to 500 Bearer."""
        with mock.patch.object(api_keys.time, "time", return_value=float("inf")):
            rec, token = api_keys.create("clock", "member", expires_days=7)
        _starlette_json(rec)
        self.assertEqual(rec["created"], 0)
        with mock.patch.object(api_keys.time, "time", return_value=float("inf")):
            hit = api_keys.verify(token)
        self.assertIsNotNone(hit)
        _starlette_json(hit)


_Pw = namedtuple("Pw", "pw_name pw_passwd pw_uid pw_gid pw_gecos pw_dir pw_shell")
_Gr = namedtuple("Gr", "gr_name gr_passwd gr_gid gr_mem")


class UsersLeftoverPwdTests(unittest.TestCase):
    def test_leftover_gecos_bytes_do_not_500(self):
        entry = _Pw(
            b"alice", b"x", 501, 20, b"Alice Smith,Room", b"/Users/alice", b"/bin/zsh",
        )
        with (
            mock.patch.object(users_svc.pwd, "getpwall", return_value=[entry]),
            mock.patch.object(users_svc.grp, "getgrnam", side_effect=KeyError),
            mock.patch.object(
                users_svc.grp, "getgrgid",
                return_value=_Gr(b"staff", b"x", 20, []),
            ),
            mock.patch.object(users_svc.os, "getgrouplist", return_value=[20]),
        ):
            out = users_svc.overview()
        _starlette_json(out)
        self.assertEqual(out["users"][0]["name"], "alice")
        self.assertEqual(out["users"][0]["gecos"], "Alice Smith")
        self.assertEqual(out["users"][0]["groups"], ["staff"])

    def test_leftover_gecos_surrogate_does_not_500(self):
        entry = _Pw("bob", "x", 502, 20, "Bo\ud800b,Room", "/Users/bob", "/bin/zsh")
        with (
            mock.patch.object(users_svc.pwd, "getpwall", return_value=[entry]),
            mock.patch.object(users_svc.grp, "getgrnam", side_effect=KeyError),
            mock.patch.object(users_svc.grp, "getgrgid", side_effect=KeyError),
            mock.patch.object(users_svc.os, "getgrouplist", return_value=[20]),
        ):
            out = users_svc.overview()
        _starlette_json(out)
        self.assertNotIn("\ud800", out["users"][0]["gecos"])

    def test_getpwall_eio_does_not_500(self):
        with (
            mock.patch.object(
                users_svc.pwd, "getpwall", side_effect=OSError(5, "I/O error")
            ),
            mock.patch.object(users_svc.grp, "getgrnam", side_effect=KeyError),
        ):
            out = users_svc.overview()
        _starlette_json(out)
        self.assertEqual(out["users"], [])
        self.assertEqual(out["count"], 0)

    def test_getgrnam_eio_does_not_500(self):
        entry = _Pw("carol", "x", 503, 20, "Carol", "/Users/carol", "/bin/zsh")
        with (
            mock.patch.object(users_svc.pwd, "getpwall", return_value=[entry]),
            mock.patch.object(
                users_svc.grp, "getgrnam", side_effect=OSError(5, "I/O error")
            ),
            mock.patch.object(users_svc.grp, "getgrgid", side_effect=KeyError),
            mock.patch.object(users_svc.os, "getgrouplist", return_value=[20]),
        ):
            out = users_svc.overview()
        _starlette_json(out)
        self.assertEqual(out["users"][0]["name"], "carol")

    def test_getpwall_typeerror_does_not_500(self):
        """Open Directory leftover TypeError is not OSError; GET /api/users 500'd."""
        with (
            mock.patch.object(users_svc.pwd, "getpwall", side_effect=TypeError("od")),
            mock.patch.object(users_svc.grp, "getgrnam", side_effect=KeyError),
        ):
            out = users_svc.overview()
        _starlette_json(out)
        self.assertEqual(out["users"], [])

    def test_getpwall_keyerror_does_not_500(self):
        with (
            mock.patch.object(users_svc.pwd, "getpwall", side_effect=KeyError("od")),
            mock.patch.object(users_svc.grp, "getgrnam", side_effect=KeyError),
        ):
            out = users_svc.overview()
        _starlette_json(out)
        self.assertEqual(out["users"], [])

    def test_directory_service_death_mid_listing_does_not_500(self):
        def gen():
            yield _Pw("alice", "x", 501, 20, "Alice", "/Users/alice", "/bin/zsh")
            raise RuntimeError("directory service died")

        with (
            mock.patch.object(users_svc.pwd, "getpwall", return_value=gen()),
            mock.patch.object(users_svc.grp, "getgrnam", side_effect=KeyError),
            mock.patch.object(users_svc.grp, "getgrgid", side_effect=KeyError),
            mock.patch.object(users_svc.os, "getgrouplist", return_value=[20]),
        ):
            out = users_svc.overview()
        _starlette_json(out)
        self.assertEqual([u["name"] for u in out["users"]], ["alice"])

    def test_leftover_inf_uid_is_skipped_not_500(self):
        bad = _Pw("eve", "x", json.loads("1e309"), 20, "Eve", "/Users/eve", "/bin/zsh")
        good = _Pw("dave", "x", 504, 20, "Dave", "/Users/dave", "/bin/zsh")
        with (
            mock.patch.object(users_svc.pwd, "getpwall", return_value=[bad, good]),
            mock.patch.object(users_svc.grp, "getgrnam", side_effect=KeyError),
            mock.patch.object(users_svc.grp, "getgrgid", side_effect=KeyError),
            mock.patch.object(users_svc.os, "getgrouplist", return_value=[20]),
        ):
            out = users_svc.overview()
        _starlette_json(out)
        self.assertEqual([u["name"] for u in out["users"]], ["dave"])


class Utf8TextRecursionLeftoverTests(unittest.TestCase):
    def test_twofa_and_api_keys_recursing_str_does_not_500(self):
        """leftover ``str()`` RecursionError used to 500 twofa / api-keys dumps."""
        class Recursing:
            def __str__(self):
                raise RecursionError("nested")

        self.assertEqual(twofa_svc._utf8_text(Recursing()), "Recursing")
        _starlette_json({"k": twofa_svc._utf8_text(Recursing())})
        self.assertEqual(api_keys._utf8_text(Recursing()), "Recursing")
        _starlette_json({"k": api_keys._utf8_text(Recursing())})

    def test_isoformat_inf_date_bytes_set_do_not_500(self):
        """Leftover YAML dates/!!set/isoformat inf used to 500 twofa / api-keys dumps."""
        class _Stamp:
            def isoformat(self):
                return float("inf")

        self.assertIsNone(twofa_svc._json_safe(_Stamp()))
        self.assertIsNone(api_keys._json_safe(_Stamp()))
        for fn in (twofa_svc._json_safe, api_keys._json_safe):
            out = fn({
                "when": _Stamp(),
                "name": datetime.date(2026, 8, 19),
                "blob": b"secret",
                "tags": {"totp"},
                "n": float("inf"),
            })
            _starlette_json(out)
            self.assertIsNone(out["when"])
            self.assertEqual(out["name"], "2026-08-19")
            self.assertEqual(out["blob"], "secret")
            self.assertEqual(out["tags"], ["totp"])
            self.assertIsNone(out["n"])


if __name__ == "__main__":
    unittest.main()
