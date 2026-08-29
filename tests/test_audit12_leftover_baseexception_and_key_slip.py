"""Audit-trail leftover sweep #12: BaseException-shaped bombs, the
secret-key classifier slip, and the claimed-base decode gap.

audit11 sealed recent()'s limit clamp; every guard in hub/audit.py still
stopped at ``except Exception``.  This sweep re-armed the already-sealed
vectors over the real mounted app (create_app + TestClient,
raise_server_exceptions=False) with a *BaseException* subclass — the shape
a watchdog/timeout-style leftover raises — and re-hunted the redaction and
decode seams, finding three live leftovers:

* **fixed, raise out of record()** — a field (or the event itself) whose
  ``__class__`` property, ``__str__``, ``isoformat`` or ``__getattr__``
  raised a BaseException subclass sailed past ``_isa``'s catch, past every
  sibling guard, past record()'s shaping net *and* past its disk net —
  a raw 500 out of the JSON mutation being audited, from the one module
  whose first guarantee is that logging never breaks the request.  The
  same shape in a limit's ``__int__``/``__index__`` blew out of recent().
  Every swallow site now reaches down to ``except BaseException`` while
  re-raising genuine control flow (KeyboardInterrupt, SystemExit).

* **fixed, secret value written to disk** — ``_is_secret_key`` probed the
  key with ``str(key)``, which runs a str subclass's own bound ``__str__``.
  A key *named* ``password`` whose ``__str__`` raised made the classifier
  answer "no name here" — while ``_jsonable`` rendered that same key's
  real text through the unbound base encode and the plaintext value landed
  on disk under its secret name.  The route's read-side re-redact kept it
  off the wire, but the on-disk trail carried it.  The classifier now
  reads the key through the same ``_utf8_text`` scrub the writer uses, so
  the two can never disagree about a key's name.

* **fixed, field content vanished at the wrong rank** — ``_utf8_text``
  picked the decode base off the *claimed* ``__class__``, so a genuine
  bytearray lying ``bytes`` was handed to ``bytes.decode``, rejected by
  the descriptor, and its perfectly decodable text degraded to "".  Both
  bases are now tried against the real storage; a total impostor still
  fails both and drops exactly as before.

Stays-immune pins ride along: Exception-shaped bombs from the audit9/11
waves stay closed beside the widened guards, honest rows and limits keep
their exact behavior, and absurd query strings stay 4xx.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import audit
from hub.app_factory import create_app
from hub.auth import require_auth

_APP = None


def _client() -> TestClient:
    global _APP
    if _APP is None:
        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: this raising is the 500."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _Watchdog(BaseException):
    """A leftover raise that is BaseException-shaped but *not* Exception."""


class _ClassBaseBomb:
    """``__class__`` property raises a BaseException subclass."""

    @property
    def __class__(self):  # type: ignore[override]
        raise _Watchdog("class access bomb")


class _StrBaseBomb:
    def __str__(self):
        raise _Watchdog("str bomb")


class _IsoBaseBomb:
    def isoformat(self):
        raise _Watchdog("isoformat bomb")


class _GetattrBaseBomb:
    def __getattr__(self, name):
        raise _Watchdog("getattr probe bomb")


class _HashBaseBombKey:
    """Hashes once for the kwargs dict, re-raises on redact()'s rebuild."""

    def __init__(self, text):
        self._t = text
        self._hashed = 0

    def __hash__(self):
        self._hashed += 1
        if self._hashed > 1:
            raise _Watchdog("rebuild hash bomb")
        return hash(self._t)

    def __str__(self):
        return self._t


class _IntBaseBomb:
    def __int__(self):
        raise _Watchdog("int bomb")


class _IndexBaseBomb:
    def __index__(self):
        raise _Watchdog("index bomb")


class _SecretStrBombKey(str):
    """Named like a secret; its bound ``__str__`` raises Exception."""

    def __str__(self):
        raise RuntimeError("bound str bomb")


class _SecretBaseStrBombKey(str):
    """Same slip, re-armed with a BaseException subclass."""

    def __str__(self):
        raise _Watchdog("bound str base bomb")


class _ByteArrayLyingBytes(bytearray):
    """Genuine bytearray storage; ``__class__`` claims ``bytes``."""

    @property
    def __class__(self):  # type: ignore[override]
        return bytes


class _BytesImpostor:
    """Claims ``bytes`` while carrying neither bytes-like layout."""

    @property
    def __class__(self):  # type: ignore[override]
        return bytes


class _TrailCase(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="audit12-pin-"))
        self.auth_path = self.dir / "auth-audit.jsonl"
        patched = mock.patch.object(audit, "AUDIT_PATH", self.auth_path)
        patched.start()
        self.addCleanup(patched.stop)
        # rmtree: record() takes secure_io.file_lock, which leaves a .lock
        # sibling beside the trail.
        self.addCleanup(shutil.rmtree, self.dir, True)

    def _record(self, event="auth.login.failed", **fields) -> dict:
        entry = audit.record(event, **fields)
        _starlette(entry)
        return entry

    def _disk_text(self) -> str:
        try:
            return self.auth_path.read_text(encoding="utf-8")
        except OSError:
            return ""

    def _http_body(self, url="/api/audit/auth?limit=100") -> dict:
        resp = _client().get(url)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        return body


class BaseExceptionBombRecordTests(_TrailCase):
    """Each vector raised raw out of record() — through both nets — before
    the guards reached past ``Exception``."""

    def test_class_property_base_bomb_field_costs_only_itself(self):
        entry = self._record(username="amy", junk=_ClassBaseBomb())
        self.assertEqual(entry.get("username"), "amy")
        body = self._http_body()
        self.assertEqual(body["entries"][0].get("username"), "amy")

    def test_str_base_bomb_field_degrades_to_empty_text(self):
        entry = self._record(username="amy", junk=_StrBaseBomb())
        self.assertEqual(entry.get("username"), "amy")
        self.assertEqual(entry.get("junk"), "")
        self.assertEqual(self._http_body()["entries"][0].get("junk"), "")

    def test_isoformat_and_getattr_base_bombs_cost_only_their_fields(self):
        entry = self._record(
            username="amy", iso=_IsoBaseBomb(), probe=_GetattrBaseBomb()
        )
        self.assertEqual(entry.get("username"), "amy")
        self.assertEqual(self._http_body()["entries"][0].get("username"), "amy")

    def test_rebuild_hash_base_bomb_key_keeps_the_siblings(self):
        detail = {_HashBaseBombKey("note"): "v", "ok": 1}
        entry = self._record(username="amy", detail=detail)
        self.assertEqual(entry.get("username"), "amy")
        self.assertEqual(self._http_body()["entries"][0].get("username"), "amy")

    def test_base_bomb_as_the_event_still_writes_a_line(self):
        entry = audit.record(_ClassBaseBomb(), username="amy")
        _starlette(entry)
        self.assertIn("ts", entry)
        self.assertIn("event", entry)
        body = self._http_body()
        self.assertEqual(len(body["entries"]), 1)

    def test_nested_base_bombs_in_a_set_field_degrade_to_a_list(self):
        entry = self._record(username="amy", bag={_ClassBaseBomb(), "x"})
        self.assertEqual(entry.get("username"), "amy")
        self.assertEqual(self._http_body()["entries"][0].get("username"), "amy")


class BaseExceptionLimitClampTests(_TrailCase):
    """recent() must read the default window, never re-raise the bomb."""

    def setUp(self):
        super().setUp()
        for i in range(3):
            audit.record("auth.login.ok", username=f"amy{i}")

    def test_base_bomb_limits_read_the_default_window(self):
        for lim in (_IntBaseBomb(), _IndexBaseBomb(), _ClassBaseBomb()):
            rows = audit.recent(lim)
            _starlette(rows)
            self.assertEqual(len(rows), 3, f"limit={type(lim).__name__}")

    def test_honest_limits_keep_their_exact_behavior(self):
        self.assertEqual(len(audit.recent(2)), 2)
        self.assertEqual(len(audit.recent(-5)), 1)
        self.assertEqual(len(audit.recent(10**9)), 3)


class SecretKeyClassifierSlipTests(_TrailCase):
    """A secret-named key whose bound ``__str__`` raises used to slip the
    classifier while the writer rendered its real name — plaintext on disk."""

    def test_exception_str_bomb_secret_key_never_reaches_disk(self):
        entry = self._record(
            **{_SecretStrBombKey("password"): "hunter2", "username": "amy"}
        )
        self.assertEqual(entry.get("username"), "amy")
        self.assertNotIn("password", entry)
        disk = self._disk_text()
        self.assertNotIn("hunter2", disk)
        self.assertNotIn("hunter2", json.dumps(self._http_body()))

    def test_baseexception_str_bomb_secret_key_never_reaches_disk(self):
        # Pre-fix this shape was even worse: the BaseException blew past the
        # classifier's catch and 500'd the audited request outright.
        entry = self._record(
            **{_SecretBaseStrBombKey("password"): "hunter3", "username": "amy"}
        )
        self.assertEqual(entry.get("username"), "amy")
        self.assertNotIn("password", entry)
        self.assertNotIn("hunter3", self._disk_text())

    def test_plain_secret_and_public_exception_keys_still_classify(self):
        # The classifier rewrite must not move the honest behavior: secret
        # names drop, the public-key exception list still passes through.
        entry = self._record(username="amy", password="x", pubkey="pk")
        self.assertNotIn("password", entry)
        self.assertEqual(entry.get("pubkey"), "pk")

    def test_bytes_named_secret_key_nested_in_a_detail_still_drops(self):
        # ``**kwargs`` refuses non-str keys, but a nested detail dict does
        # not; the classifier now reads the bytes name through the same
        # scrub the writer uses, and the value still vanishes.
        entry = self._record(
            username="amy", detail={b"password": "hunter4", "ok": 1}
        )
        self.assertEqual(entry.get("username"), "amy")
        self.assertEqual(entry.get("detail", {}).get("ok"), 1)
        self.assertNotIn("hunter4", self._disk_text())


class DecodeFidelityTests(_TrailCase):
    """Real content behind a lying ``__class__`` used to vanish to ""; a
    total impostor still degrades exactly as before."""

    def test_bytearray_lying_bytes_keeps_its_content(self):
        entry = self._record(username="amy", note=_ByteArrayLyingBytes(b"kept"))
        self.assertEqual(entry.get("note"), "kept")
        self.assertEqual(self._http_body()["entries"][0].get("note"), "kept")

    def test_total_bytes_impostor_still_degrades_to_empty_text(self):
        entry = self._record(username="amy", note=_BytesImpostor())
        self.assertEqual(entry.get("note"), "")
        self.assertEqual(entry.get("username"), "amy")


class ControlFlowStillPropagatesTests(_TrailCase):
    """The launder must not eat genuine control flow: a Ctrl-C or an
    interpreter shutdown raised mid-record keeps propagating."""

    def test_keyboardinterrupt_from_class_property_propagates(self):
        class _KIBomb:
            @property
            def __class__(self):  # type: ignore[override]
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            audit.record("auth.login.failed", junk=_KIBomb())

    def test_systemexit_from_str_propagates(self):
        class _SEBomb:
            def __str__(self):
                raise SystemExit(3)

        with self.assertRaises(SystemExit):
            audit.record("auth.login.failed", junk=_SEBomb())

    def test_keyboardinterrupt_from_a_limit_propagates(self):
        class _KIInt:
            def __int__(self):
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            audit.recent(_KIInt())


class ExceptionShapesStayClosedTests(_TrailCase):
    """audit9/11 coverage must survive the widened catch."""

    def test_exception_class_bomb_field_still_costs_only_itself(self):
        class _ClassExcBomb:
            @property
            def __class__(self):  # type: ignore[override]
                raise RuntimeError("class access bomb")

        entry = self._record(username="amy", junk=_ClassExcBomb())
        self.assertEqual(entry.get("username"), "amy")
        self.assertEqual(self._http_body()["entries"][0].get("username"), "amy")

    def test_route_limit_junk_stays_4xx(self):
        audit.record("auth.login.ok", username="amy")
        for q in ("9" * 5000, "1e400", "nan", "0x10"):
            resp = _client().get(f"/api/audit/auth?limit={q}")
            self.assertLess(resp.status_code, 500, f"limit={q[:20]}")
            self.assertGreaterEqual(resp.status_code, 400, f"limit={q[:20]}")
            _starlette(resp.json())


if __name__ == "__main__":
    unittest.main()
