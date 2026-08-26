"""Sixth docker-surface leftover-500 sweep: poisoned ``_cjobs`` row bombs.

The docker/docker2..docker5 sweeps pinned the dict-subclass ``.get()`` /
``__bool__`` row bombs in the stack-job store, but the *nested* unbound
families (the modules5 class) were still live on the docker surfaces.
Reproduced over the real mounted app (``create_app()`` +
``TestClient(raise_server_exceptions=False)``), a poisoned ``_cjobs`` row —
the store outlives the request that wrote it — still produced raw HTTP 500s
on GET /api/stacks and GET /api/stacks/jobs/{id}:

* an int-subclass ``rc``/``started``/``finished`` whose ``__str__`` raised
  blew ``docker_cli._jsonable``'s digit-cap probe (only ValueError was
  caught);
* a float-subclass field whose ``__ne__``/``__eq__`` raised blew the
  NaN/inf probes (``value != value``);
* a bytes-subclass field whose bound ``.decode`` raised escaped the bytes
  branch;
* a str-subclass field whose ``__str__`` returns self and whose bound
  ``.encode`` raised escaped ``_utf8_text``/``_as_text``'s final scrub;
* a str-subclass ``stack_id`` (or job key) whose ``__eq__`` raised passed
  the isinstance gates in ``stack_job_log``'s fallback scan — the reflected
  operand gives the subclass priority even with the plain str on the left —
  and one whose hash collides with the queried id detonated inside
  ``dict.get`` itself;
* a str-subclass ``stack_id`` with a ``__len__`` bomb blew the truthiness
  check in ``latest_stack_jobs``, and a ``__hash__`` bomb blew its
  ``by[sid]`` insert.

Fixes: ``docker_cli._jsonable``/``_utf8_text``/``_as_text`` now follow the
unbound base-type convention (``int.__index__``, ``float.__float__``,
unbound ``bytes.decode`` / ``str.encode`` — the hub.modules/hub.status
shape), and ``containers_svc`` gained ``_plain_text`` (exact-str copy via
``str.__str__``) for the job-scan compares plus a guarded ``dict.get`` in
``stack_job_log``.  These tests pin all of it.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from fastapi.testclient import TestClient  # noqa: E402

from hub import containers_svc  # noqa: E402
from hub.app_factory import create_app  # noqa: E402
from hub.auth import require_auth  # noqa: E402

_app = None


def _the_app():
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return _app


def _client() -> TestClient:
    # raise_server_exceptions=False: a real 500 must arrive as HTTP 500, not
    # as a re-raised exception that would mask which route crashed.
    return TestClient(_the_app(), raise_server_exceptions=False)


class IntStrBomb(int):
    def __str__(self):
        raise RuntimeError("int __str__ bomb")

    __repr__ = __str__


class FloatCmpBomb(float):
    def __ne__(self, other):
        raise RuntimeError("float __ne__ bomb")

    def __eq__(self, other):
        raise RuntimeError("float __eq__ bomb")

    __hash__ = float.__hash__


class BytesDecodeBomb(bytes):
    def decode(self, *a, **k):
        raise RuntimeError("bytes decode bomb")


class StrEncodeBomb(str):
    # __str__ returning self keeps the subclass alive through str(), so the
    # bound .encode bomb is what the final UTF-8 scrub would have hit.
    def __str__(self):
        return self

    def encode(self, *a, **k):
        raise RuntimeError("str encode bomb")


class StrEqBomb(str):
    def __eq__(self, other):
        raise RuntimeError("str __eq__ bomb")

    __hash__ = str.__hash__


class StrLenBomb(str):
    def __len__(self):
        raise RuntimeError("str __len__ bomb")


class StrHashBomb(str):
    def __hash__(self):
        raise RuntimeError("str __hash__ bomb")


def _row(**over) -> dict:
    row = {
        "running": False, "rc": 0, "log": ["line"],
        "started": "10:00:00", "finished": "10:00:01",
        "stack_id": "s1", "action": "up",
    }
    row.update(over)
    return row


class _JobStoreBase(unittest.TestCase):
    def setUp(self):
        self._saved = dict(containers_svc._cjobs)
        containers_svc._cjobs.clear()
        self.addCleanup(self._restore)

    def _restore(self):
        containers_svc._cjobs.clear()
        containers_svc._cjobs.update(self._saved)

    def assert_clean(self, r, label: str):
        self.assertLess(
            r.status_code, 500, f"{label}: raw {r.status_code}: {r.text[:300]}"
        )
        r.text.encode("utf-8")


class NestedUnboundBombFieldPins(_JobStoreBase):
    """Every scalar bomb family in every job-row field stays a 2xx answer."""

    BOMBS = {
        "int_str": IntStrBomb(7),
        "float_cmp": FloatCmpBomb(1.5),
        "bytes_decode": BytesDecodeBomb(b"xx"),
        "str_encode": StrEncodeBomb("xx"),
    }
    FIELDS = ("rc", "started", "finished", "stack_id", "action", "code",
              "log", "running")

    def test_bomb_fields_never_500_stack_routes(self):
        c = _client()
        for name, bomb in self.BOMBS.items():
            for field in self.FIELDS:
                with self.subTest(bomb=name, field=field):
                    containers_svc._cjobs.clear()
                    containers_svc._cjobs["job1"] = _row(**{field: bomb})
                    for url in ("/api/stacks/jobs/job1", "/api/stacks"):
                        self.assert_clean(c.get(url), f"{name}/{field} {url}")

    def test_bomb_nested_inside_log_list_never_500s(self):
        c = _client()
        for name, bomb in self.BOMBS.items():
            with self.subTest(bomb=name):
                containers_svc._cjobs.clear()
                containers_svc._cjobs["job1"] = _row(log=["ok", bomb, "tail"])
                for url in ("/api/stacks/jobs/job1", "/api/stacks"):
                    self.assert_clean(c.get(url), f"log[{name}] {url}")

    def test_bomb_rc_coerces_to_base_value_and_siblings_survive(self):
        containers_svc._cjobs["job1"] = _row(rc=IntStrBomb(1))
        r = _client().get("/api/stacks/jobs/job1")
        self.assertEqual(r.status_code, 200, r.text[:300])
        payload = r.json()
        # The base coercion sheds only the subclass; the real value and the
        # row's other data survive.
        self.assertEqual(payload["rc"], 1)
        self.assertEqual(payload["stack_id"], "s1")
        self.assertIn("line", payload["log"])


class EqHashLenBombScanPins(_JobStoreBase):
    """str-subclass operator bombs in ids/keys never blow the job scans."""

    def test_eq_bomb_stack_id_keeps_fallback_scan_alive(self):
        containers_svc._cjobs["job1"] = _row(stack_id=StrEqBomb("s1"))
        c = _client()
        # Poll by a *different* id: the fallback scan walks every row and
        # its compares used to raise out of the poisoned one.
        self.assert_clean(c.get("/api/stacks/jobs/other"), "eq stack_id poll")
        self.assert_clean(c.get("/api/stacks"), "eq stack_id stacks")

    def test_eq_bomb_key_keeps_fallback_scan_alive(self):
        containers_svc._cjobs[StrEqBomb("job1")] = _row()
        c = _client()
        self.assert_clean(c.get("/api/stacks/jobs/other"), "eq key poll")
        self.assert_clean(c.get("/api/stacks"), "eq key stacks")

    def test_eq_bomb_key_direct_hit_still_finds_the_job(self):
        # Same string content, so the hashes collide and dict.get compares
        # the queried plain str against the bomb key — that comparison used
        # to detonate inside the lookup itself.
        containers_svc._cjobs[StrEqBomb("job1")] = _row(rc=7)
        r = _client().get("/api/stacks/jobs/job1")
        self.assertEqual(r.status_code, 200, r.text[:300])
        payload = r.json()
        # The fallback scan re-finds the row through the exact-str copy.
        self.assertEqual(payload["rc"], 7)
        self.assertEqual(payload["job_id"], "job1")

    def test_len_bomb_stack_id_keeps_stacks_listing_alive(self):
        containers_svc._cjobs["job1"] = _row(stack_id=StrLenBomb("s1"))
        self.assert_clean(_client().get("/api/stacks"), "len stack_id stacks")

    def test_hash_bomb_stack_id_keeps_stacks_listing_alive(self):
        # A value is never hashed at insert, so an unconditional __hash__
        # bomb is insertable — latest_stack_jobs' by[sid] used to detonate.
        containers_svc._cjobs["job1"] = _row(stack_id=StrHashBomb("s1"))
        self.assert_clean(_client().get("/api/stacks"), "hash stack_id stacks")

    def test_healthy_sibling_job_still_listed_beside_bomb_rows(self):
        containers_svc._cjobs["bad"] = _row(stack_id=StrHashBomb("bombed"))
        containers_svc._cjobs["good"] = _row(stack_id="healthy", rc=0)
        r = _client().get("/api/stacks")
        self.assertEqual(r.status_code, 200, r.text[:300])
        jobs = r.json()["jobs"]
        self.assertTrue(
            any(j.get("stack_id") == "healthy" for j in jobs),
            f"healthy job vanished behind a bomb row: {jobs}",
        )


class JsonableUnboundUnitPins(unittest.TestCase):
    """docker_cli._jsonable itself follows the unbound base convention."""

    def test_scalar_bombs_coerce_to_base_values(self):
        from hub.docker_cli import _jsonable
        # The unbound base coercion sheds the subclass but keeps the value.
        for bomb, want in ((IntStrBomb(7), 7), (FloatCmpBomb(1.5), 1.5),
                           (BytesDecodeBomb(b"x"), "x")):
            with self.subTest(bomb=type(bomb).__name__):
                out = _jsonable({"field": bomb})
                self.assertEqual(out, {"field": want})
                self.assertIs(type(out["field"]), type(want))

    def test_str_encode_bomb_scrubs_to_text(self):
        from hub.docker_cli import _jsonable
        out = _jsonable({"field": StrEncodeBomb("ok")})
        # The unbound str.encode scrub keeps the real characters.
        self.assertEqual(out, {"field": "ok"})

    def test_plain_and_huge_values_keep_prior_behavior(self):
        from hub.docker_cli import _jsonable
        huge = 10 ** 5000  # dodges the digit cap that int(str) would hit
        out = _jsonable({
            "n": 5, "f": 1.5, "inf": float("inf"), "huge": huge,
            "s": "a\ud800b", "b": b"\xff", "sub": IntStrBomb(1),
        })
        self.assertEqual(out["n"], 5)
        self.assertEqual(out["f"], 1.5)
        self.assertIsNone(out["inf"])
        self.assertIsNone(out["huge"])
        self.assertNotIn("\ud800", out["s"])
        self.assertIsInstance(out["b"], str)


if __name__ == "__main__":
    unittest.main()
