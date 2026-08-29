"""Eleventh leftover-500s sweep of the Backups routes: the torn-DB_URL
coercion in ``_immich_conn`` — the last unguarded ``urlparse``/``.port`` leak
on POST /api/backups/immich — plus do-not-weaken pins for the union guards
backups6-10 pinned.

backups10 sealed the *lying* ``__class__`` impostor menagerie across the cfg
and ``run_capped`` seams; the aggressive fuzz that led here confirms the four
Backups JSON routes (GET /api/backups, POST /api/backups/{postgres,immich,
configs}) now answer every cfg/JSON bomb without a 500.  One coercion path
survived, in the Immich *native* dump's connection reader:

* ``_immich_conn`` reads ``DB_URL`` out of ``~/Services/immich/db.env`` and
  hands it straight to ``urllib.parse.urlparse``.  A torn IPv6 literal in the
  netloc (``postgres://u:p@[::1:5433/db`` — a ``[`` with no closing bracket)
  makes urlsplit raise ``ValueError("Invalid IPv6 URL")``, the catalog5
  leftover class; an out-of-range or non-numeric port (``host:9999999999…``,
  ``host:notaport``) makes the ``parsed.port`` accessor raise ``ValueError``
  a few lines later.  Both are *raw stdlib* errors, not this helper's
  documented ``RuntimeError`` — its own comment promises to raise
  ``RuntimeError`` for an unusable db.env, and every existing caller/test
  keys off that.  Only ``_backup_immich_native``'s broad ``except Exception``
  kept the raw ValueError from being a 500, and it flattened CPython-internal
  text ("Invalid IPv6 URL", "Port out of range 0-65535") into the dump's
  ``ok:false`` message instead of a coded reason — exactly the accidental
  catch these sweeps replace with an intentional guard so a narrower or
  direct caller (as these unit tests are) is safe too.

The fix guards the parse and the port read, raising the coded ``RuntimeError``
a torn db.env should give.  A real ``[::1]`` / ``127.0.0.1`` DB_URL and the
pre-existing ``RuntimeError`` refusals (unreadable db.env, no password) are
do-not-weaken pins.  The conflict-policy guards (``_isa``, ``type(x) is bool``,
the guarded ``_decode_bytes``, the try around ``cfg()`` / ``dict.get`` in
``_mapping_get``) are re-pinned so a later edit cannot quietly weaken them.
Product version stays 3.9.3.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import backups
from hub.app_factory import create_app
from hub.auth import require_auth

_app = None


def _client() -> TestClient:
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    # raise_server_exceptions=False: a real 500 must arrive as HTTP 500, not
    # as a re-raised exception that would mask which route crashed.
    return TestClient(_app, raise_server_exceptions=False)


def _strict_utf8(resp) -> str:
    """The body must already be valid UTF-8 — decode strictly on purpose."""
    return resp.content.decode("utf-8")


#: CPython-internal urlparse/.port text that must never surface as a result.
_INTERNAL_FRAGMENTS = ("Invalid IPv6 URL", "Port out of range", "cast to integer")

_TORN = {
    "torn_ipv6": "postgres://u:p@[::1:5433/immich",
    "huge_port": "postgres://u:p@127.0.0.1:99999999999999999999/immich",
    "bad_port": "postgres://u:p@127.0.0.1:notaport/immich",
}
_VALID = {
    "ipv6": "postgresql://immich:s3cret@[::1]:5433/immich",
    "ipv4": "postgresql://immich:s3cret@127.0.0.1:5433/immich",
    "default_port": "postgresql://immich:s3cret@db.local/immich",
}


def _db_env(url: str) -> Path:
    root = Path(tempfile.mkdtemp(prefix="serverhub-backups11-"))
    env = root / "db.env"
    env.write_text(f"DB_URL={url}\n", encoding="utf-8")
    return env


class ImmichConnTornUrlUnitTests(unittest.TestCase):
    """The helper itself: a torn DB_URL raises the coded ``RuntimeError``,
    never a raw ``ValueError`` carrying CPython-internal text."""

    def _conn(self, url):
        env = _db_env(url)
        self.addCleanup(shutil.rmtree, env.parent, ignore_errors=True)
        with mock.patch.object(backups, "IMMICH_DB_ENV", env):
            return backups._immich_conn()

    def test_torn_shapes_raise_runtimeerror_not_valueerror(self):
        for name, url in _TORN.items():
            with self.subTest(name=name):
                with self.assertRaises(RuntimeError) as ctx:
                    self._conn(url)
                # Not the raw stdlib ValueError, and no internal text leaked.
                self.assertNotIsInstance(ctx.exception, ValueError)
                msg = str(ctx.exception)
                for frag in _INTERNAL_FRAGMENTS:
                    self.assertNotIn(frag, msg)
                self.assertIn("db.env", msg)

    def test_valid_urls_still_parse(self):
        # Do-not-weaken: the guard must not reject a healthy DB_URL.
        conn = self._conn(_VALID["ipv6"])
        self.assertEqual(conn["host"], "::1")
        self.assertEqual(conn["port"], 5433)
        self.assertEqual(conn["password"], "s3cret")
        conn = self._conn(_VALID["ipv4"])
        self.assertEqual(conn["host"], "127.0.0.1")
        self.assertEqual(conn["db"], "immich")
        conn = self._conn(_VALID["default_port"])
        # No :port in the URL means the Immich default, not a raise.
        self.assertEqual(conn["port"], 5433)
        self.assertEqual(conn["host"], "db.local")

    def test_existing_runtimeerror_contracts_still_hold(self):
        # Do-not-weaken: an unreadable db.env and a password-less DB_URL keep
        # raising the coded RuntimeError they always did.
        missing = Path(tempfile.mkdtemp(prefix="serverhub-backups11-")) / "gone.env"
        with mock.patch.object(backups, "IMMICH_DB_ENV", missing):
            with self.assertRaises(RuntimeError):
                backups._immich_conn()
        with self.assertRaises(RuntimeError) as ctx:
            self._conn("postgresql://immich@127.0.0.1:5433/immich")
        self.assertIn("password", str(ctx.exception))


class ImmichNativeRouteTornUrlTests(unittest.TestCase):
    """POST /api/backups/immich, native path: a torn db.env answers a clean
    coded ``ok:false`` — never a 500, never CPython-internal text."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.backup_root = root / "backups"
        self.backup_root.mkdir()
        self.immich = root / "immich"
        self.immich.mkdir()
        # A real executable so _pg18_dump() resolves and the native path (not
        # the script path) is chosen; it is never actually spawned because
        # _immich_conn refuses first.
        self.pg18 = root / "pg_dump"
        self.pg18.write_text("#!/bin/sh\nexit 0\n")
        self.pg18.chmod(0o755)
        for patched in (
            mock.patch.object(backups, "BACKUP_ROOT", self.backup_root),
            mock.patch.object(backups, "IMMICH_ROOT", self.immich),
            # script absent -> immich_backup_info() picks "native"
            mock.patch.object(backups, "IMMICH_SCRIPT", self.immich / "backup-db.sh"),
            mock.patch.object(backups, "IMMICH_DB_ENV", self.immich / "db.env"),
            mock.patch.object(backups, "_PG18_DUMPS", (self.pg18,)),
            mock.patch.object(backups, "PHOTOSHUB_CFG", root / "no-photoshub.json"),
            mock.patch.object(backups, "PHOTOSHUB_STATE", root / "no-photoshub-state"),
        ):
            patched.start()
            self.addCleanup(patched.stop)

    def _post(self):
        resp = _client().post("/api/backups/immich")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        return json.loads(_strict_utf8(resp))

    def test_torn_dburl_answers_clean_coded_failure(self):
        for name, url in _TORN.items():
            with self.subTest(name=name):
                (self.immich / "db.env").write_text(f"DB_URL={url}\n", encoding="utf-8")
                payload = self._post()
                self.assertFalse(payload["ok"])
                for frag in _INTERNAL_FRAGMENTS:
                    self.assertNotIn(frag, payload["message"])
                self.assertIn("db.env", payload["message"])
                # No artefact left behind on the refusal.
                self.assertEqual(
                    list(self.backup_root.glob("immich_*.sql.gz")), []
                )

    def test_native_reaches_the_conn_reader(self):
        # Sanity: with a db.env present the sandbox really does drive the
        # native path (else the torn-URL assertions above would be vacuous).
        (self.immich / "db.env").write_text(
            f"DB_URL={_VALID['ipv4']}\n", encoding="utf-8"
        )
        self.assertEqual(backups.immich_backup_info()["via"], "native")


class ConflictPolicyPinTests(unittest.TestCase):
    """Re-pin the union guards the sweep must keep (do not weaken)."""

    def test_mapping_get_survives_get_and_items_bombs(self):
        class GetBomb(dict):
            def get(self, *a, **k):
                raise RuntimeError("get bomb")

        d = GetBomb()
        dict.__setitem__(d, "id", "real")
        # try around both the bound .get and the unbound dict.get read.
        self.assertEqual(backups._mapping_get(d, "id"), "real")
        self.assertIsNone(backups._mapping_get(d, "missing"))
        self.assertIsNone(backups._mapping_get(object(), "id"))

    def test_isa_class_bomb_is_false_never_raises(self):
        class ClassBomb:
            @property
            def __class__(self):
                raise RuntimeError("class bomb")
            __hash__ = object.__hash__

        self.assertFalse(backups._isa(ClassBomb(), dict))
        self.assertTrue(backups._isa({}, dict))
        self.assertTrue(backups._isa("x", str))

    def test_jsonable_bool_gate_uses_type_is_bool(self):
        class LyingBool:
            @property
            def __class__(self):
                return bool

        self.assertIsNone(backups._jsonable(LyingBool()))
        self.assertIs(backups._jsonable(True), True)
        self.assertIs(backups._jsonable(False), False)

    def test_as_text_guarded_decode_keeps_real_bytes(self):
        class DecodeBomb(bytes):
            def decode(self, *a, **k):
                raise RuntimeError("decode bomb")

        # unbound bytes.decode reads the real storage under the bound bomb.
        self.assertEqual(backups._as_text(DecodeBomb(b"ok\xff")), "ok\ufffd")
        self.assertEqual(backups._as_text(b"tar ok"), "tar ok")

    def test_get_backups_still_immune_to_a_class_bomb_cfg(self):
        # The backups9/10 route pins ride along: a raising-__class__ cfg block
        # must not 500 GET /api/backups.
        class ClassBomb:
            @property
            def __class__(self):
                raise RuntimeError("class bomb")
            __hash__ = object.__hash__

        with mock.patch.object(backups, "cfg", lambda: {"backups": ClassBomb()}):
            resp = _client().get("/api/backups")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        payload = json.loads(_strict_utf8(resp))
        self.assertEqual(payload["postgres_targets"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
