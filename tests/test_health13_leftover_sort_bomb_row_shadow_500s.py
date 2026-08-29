"""Thirteenth leftover-500s sweep of the Health surfaces.

health12 sealed the ``__bool__``-bomb values under honest keys (backup-dir,
port rows, the nginx pair), the brew-row shadow keys, the running-labels
shadow elements and the ``problems`` field bombs.  Re-running the zoo one
seam over — the registry *name* keys, the ``problems`` row *keys*, and the
KeepAlive glob's exception net — surfaced live leftovers:

* ``str(x)`` of a subclass whose ``__str__`` answers *self* skips CPython's
  exact-str copy, so ``worker_health._name_key`` still answered the subclass
  with its comparison hooks live: a planted registry name whose
  ``__lt__``/``__gt__`` raises detonated ``sorted``'s key compare inside
  ``snapshot()`` — the workers row, honest dead-worker reports included,
  silently vanished from GET /api/health/checks, and a bare ``problems()``
  re-raised the same bomb;
* ``worker_health.problems`` read row fields with unbound ``dict.get``,
  which still runs the *stored keys'* own ``__eq__`` during the hash probe:
  a hash-shadowing junk key riding a row (same hash as ``name``/``alive``/
  ``age_sec``, raising ``__eq__``) raised through the per-row try and
  silently dropped that worker's dead/stale report — a dead worker passed
  as healthy, the exact fail-open direction health12's ``alive`` launder
  exists to prevent;
* the KeepAlive glob caught only ``(OSError, TypeError, ValueError)``: a
  leftover path-like ``AGENTS_DIR`` whose ``__fspath__`` raises
  RuntimeError escaped the narrow net out of ``Path(AGENTS_DIR)`` itself,
  after the fan-out — a raw 500 on every GET /api/health/checks.

Conflict policy is pinned, not re-claimed: ``_isa`` stays fail-closed,
``_rc_int`` junk still reads ``-255`` (never the ``-1`` vanished sentinel),
``type is bool`` stays the exact-bool gate in ``_jsonable``, ``_truthy``
stays fail-closed, ``_mapping_get`` degrades only the shadowed field,
``_label_set`` still launders to exact strs, ``_ping_deadline`` keeps its
shape, and the ``wg.ping_missing`` 503 stays disk-confirm-only.  Product
version stays 3.9.3.
"""
from __future__ import annotations

import json
import plistlib
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from fastapi.testclient import TestClient  # noqa: E402

from hub import health_svc, wireguard_svc, worker_health  # noqa: E402
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


def _no_surrogates(payload) -> None:
    """What Starlette's JSONResponse does to the body (allow_nan=False)."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _shadow_key(target: str):
    """A str-subclass key whose hash shadows *target* and whose ``__eq__``
    raises (the vms/terminal/health11 hash-shadow zoo shape)."""

    class Shadow(str):
        __hash__ = lambda self: hash(target)  # noqa: E731

        def __eq__(self, other):
            raise RuntimeError("shadow eq bomb")

        __ne__ = __eq__

    return Shadow("junk-" + target)


class _SortBombName(str):
    """A registry name whose ``str()`` keeps the subclass and whose
    comparison hooks raise: the sorted-key detonator."""

    def __str__(self):
        return self  # skips CPython's exact-str copy

    def _boom(self, other):
        raise RuntimeError("sort bomb")

    __lt__ = __gt__ = __le__ = __ge__ = _boom


class _StrBomb:
    """A name that cannot say what it is called."""

    def __str__(self):
        raise RuntimeError("str bomb")


class _ClassBomb:
    """A leftover that cannot answer what it is: ``isinstance`` raises."""

    @property
    def __class__(self):
        raise RuntimeError("class bomb")


class _FspathBomb:
    """A leftover path-like whose ``__fspath__`` raises RuntimeError —
    outside the old (OSError, TypeError, ValueError) net."""

    def __fspath__(self):
        raise RuntimeError("fspath bomb")


def _liar(cls, text="liar"):
    """A lying ``__class__`` impostor (the docker10/json9 shape)."""

    class Liar:
        __class__ = property(lambda self: cls)

        def __str__(self):
            return text

    return Liar()


class _HealthCacheSandbox(unittest.TestCase):
    """Force a fresh collection and restore the module cache afterwards."""

    def setUp(self):
        saved = dict(health_svc._cache)

        def _restore():
            health_svc._cache.clear()
            health_svc._cache.update(saved)

        self.addCleanup(_restore)
        health_svc._cache.clear()
        health_svc._cache.update(t=0.0, v=None)

    def _checks(self, resp):
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        return {c["id"]: c for c in body["checks"] if isinstance(c, dict)}


class _WorkerRegistrySandbox(unittest.TestCase):
    """Plant registry entries and restore the real table afterwards."""

    def setUp(self):
        saved = dict(worker_health._workers)

        def _restore():
            worker_health._workers.clear()
            worker_health._workers.update(saved)

        self.addCleanup(_restore)
        worker_health._workers.clear()

    @staticmethod
    def _entry(alive: bool) -> dict:
        # A never-started Thread is honestly not alive; the current thread is.
        thread = threading.current_thread() if alive else threading.Thread()
        return {"thread": thread, "interval": 60.0, "beat": time.time()}


# --------------------------------------------------------------------------
# The registry sort: a comparison-bomb name must not wipe the workers row
# --------------------------------------------------------------------------
class SnapshotSortBombTests(_WorkerRegistrySandbox):
    def _plant_bomb_and_dead_worker(self):
        worker_health._workers["aaa-dead"] = self._entry(alive=False)
        worker_health._workers[_SortBombName("zz-bomb")] = self._entry(alive=True)

    def test_sort_bomb_name_keeps_every_snapshot_row(self):
        # Pre-fix: _name_key answered the subclass with its ``__lt__`` live,
        # sorted's key compare raised, and snapshot() blew up.
        self._plant_bomb_and_dead_worker()
        rows = worker_health.snapshot()
        self.assertEqual([r["name"] for r in rows], ["aaa-dead", "zz-bomb"])
        self.assertEqual({type(r["name"]) for r in rows}, {str})
        self.assertFalse(rows[0]["alive"])
        self.assertTrue(rows[1]["alive"])

    def test_bare_problems_still_reports_the_dead_worker(self):
        # Pre-fix: problems()'s rows=None path re-raised the sort bomb.
        self._plant_bomb_and_dead_worker()
        self.assertIn("aaa-dead: thread died", worker_health.problems())

    def test_workers_row_renders_on_the_health_page(self):
        # Pre-fix: _worker_checks swallowed the raise and the workers row —
        # the honest dead-worker report included — silently vanished.
        self._plant_bomb_and_dead_worker()
        # Fresh collection: another test's 45s TTL snapshot must not mask
        # the planted registry.
        saved = dict(health_svc._cache)

        def _restore():
            health_svc._cache.clear()
            health_svc._cache.update(saved)

        self.addCleanup(_restore)
        health_svc._cache.clear()
        health_svc._cache.update(t=0.0, v=None)
        # No context manager: entering the client would run the lifespan and
        # register the real workers on top of the planted registry.
        resp = _client().get("/api/health/checks")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        rows = {r["id"]: r for r in body["checks"] if isinstance(r, dict)}
        self.assertIn("workers", rows)
        self.assertFalse(rows["workers"]["ok"])
        self.assertIn("aaa-dead: thread died", rows["workers"]["detail"])

    def test_name_key_answers_exact_strs_only(self):
        key = worker_health._name_key(_SortBombName("zz-bomb"))
        self.assertIs(type(key), str)
        self.assertEqual(key, "zz-bomb")
        # Honest exact strs pass through untouched.
        self.assertIs(worker_health._name_key("sampler"), "sampler")
        # A ``__str__`` bomb still keys deterministically by its type.
        self.assertEqual(worker_health._name_key(_StrBomb()), "_StrBomb")

    def test_register_stores_an_exact_str_key(self):
        worker_health.register(_SortBombName("zz-bomb"), 60,
                               thread=threading.current_thread())
        self.assertEqual({type(k) for k in worker_health._workers}, {str})
        # beat()/unregister() agree on the laundered key.
        worker_health.beat(_SortBombName("zz-bomb"))
        worker_health.unregister(_SortBombName("zz-bomb"))
        self.assertNotIn("zz-bomb", worker_health._workers)


# --------------------------------------------------------------------------
# problems(): shadow keys riding a row must degrade the field, not the report
# --------------------------------------------------------------------------
class ProblemsRowShadowTests(unittest.TestCase):
    def test_shadowed_alive_is_reported_dead_not_dropped(self):
        # Pre-fix: the bound hash probe ran the stored shadow key's __eq__,
        # raised through the per-row try, and the row silently passed as
        # healthy — the fail-open direction this page exists to warn about.
        row = {"name": "w", "stale": False}
        row[_shadow_key("alive")] = True
        self.assertEqual(worker_health.problems(rows=[row]),
                         ["w: thread died"])

    def test_shadowed_name_keeps_the_report_with_placeholder(self):
        row = {"alive": False, "stale": False}
        row[_shadow_key("name")] = "gone"
        self.assertEqual(worker_health.problems(rows=[row]),
                         ["?: thread died"])

    def test_shadowed_age_keeps_the_stale_report(self):
        # Pre-fix: dict.get(w, "age_sec") detonated and the stale report of
        # a wedged worker vanished; the shadowed field now reads 0 alone.
        row = {"name": "s", "alive": True, "stale": True, "interval": 2.0}
        row[_shadow_key("age_sec")] = 99.0
        self.assertEqual(worker_health.problems(rows=[row]),
                         ["s: last tick 0s ago (interval 2s)"])

    def test_poisoned_row_never_costs_its_siblings(self):
        row = {"name": "w"}
        row[_shadow_key("alive")] = True
        rows = [row, {"name": "dead2", "alive": False, "stale": False}]
        self.assertEqual(worker_health.problems(rows=rows),
                         ["w: thread died", "dead2: thread died"])

    def test_honest_stale_row_report_shape_unchanged(self):
        rows = [{"name": "s", "alive": True, "stale": True,
                 "age_sec": 10.0, "interval": 2.0}]
        self.assertEqual(worker_health.problems(rows=rows),
                         ["s: last tick 10s ago (interval 2s)"])


# --------------------------------------------------------------------------
# The KeepAlive glob: an fspath bomb reads as no agents, never a 500
# --------------------------------------------------------------------------
class KeepAliveGlobBombTests(_HealthCacheSandbox):
    def test_fspath_bomb_agents_dir_is_not_a_500(self):
        # Pre-fix: RuntimeError out of Path(AGENTS_DIR) escaped the old
        # (OSError, TypeError, ValueError) net after the fan-out — a raw
        # 500 on every GET /api/health/checks.
        with mock.patch.object(health_svc, "AGENTS_DIR", _FspathBomb()):
            rows = self._checks(_client().get("/api/health/checks"))
        # The KeepAlive rows drop; the page still renders its other rows.
        self.assertIn("disk_root", rows)
        self.assertIn("backup_dir", rows)

    def test_honest_keepalive_plist_still_warns(self):
        agents = Path(tempfile.mkdtemp(prefix="health13-agents-"))
        label = "com.test13.keepalive"
        (agents / f"{label}.plist").write_bytes(
            plistlib.dumps({"Label": label, "KeepAlive": True})
        )
        with mock.patch.object(health_svc, "AGENTS_DIR", agents), \
                mock.patch.object(health_svc, "launchd_running_labels",
                                  lambda: frozenset()):
            rows = self._checks(_client().get("/api/health/checks"))
        self.assertIn(f"la_{label}", rows)
        self.assertFalse(rows[f"la_{label}"]["ok"])


# --------------------------------------------------------------------------
# Conflict-policy pins (health8–12): do not weaken the union guards
# --------------------------------------------------------------------------
class ConflictPolicyPins(unittest.TestCase):
    def test_rc_int_junk_reads_minus_255_never_the_vanished_sentinel(self):
        self.assertEqual(health_svc._rc_int(_ClassBomb()), -255)
        self.assertEqual(health_svc._rc_int("junk"), -255)
        self.assertNotEqual(health_svc._rc_int(_ClassBomb()), -1)

    def test_isa_stays_fail_closed(self):
        self.assertFalse(health_svc._isa(_ClassBomb(), dict))
        self.assertFalse(worker_health._isa(_ClassBomb(), dict))

    def test_truthy_stays_fail_closed(self):
        class BoolBomb:
            def __bool__(self):
                raise RuntimeError("bool bomb")

        self.assertIs(health_svc._truthy(BoolBomb()), False)
        self.assertIs(worker_health._truthy(BoolBomb()), False)

    def test_jsonable_type_is_bool_gate_unchanged(self):
        self.assertIs(health_svc._jsonable(True), True)
        self.assertIs(health_svc._jsonable(False), False)
        self.assertIs(health_svc._jsonable(_liar(bool)), True)

    def test_mapping_get_degrades_only_the_shadowed_field(self):
        d = {"keep": 2}
        d[_shadow_key("gone")] = 1
        self.assertIsNone(health_svc._mapping_get(d, "gone"))
        self.assertEqual(health_svc._mapping_get(d, "keep"), 2)
        self.assertIsNone(worker_health._mapping_get(d, "gone"))
        self.assertEqual(worker_health._mapping_get(d, "keep"), 2)

    def test_label_set_still_launders_to_exact_strs(self):
        out = health_svc._label_set({_shadow_key("x"), "honest"})
        self.assertEqual({type(e) for e in out}, {str})
        self.assertIn("honest", out)

    def test_ping_deadline_shape_unchanged(self):
        self.assertEqual(wireguard_svc._ping_deadline(_ClassBomb()), 800)
        self.assertEqual(wireguard_svc._ping_deadline(800), 800)
        self.assertEqual(wireguard_svc._ping_deadline(None), 800)

    def test_problems_still_reports_dead_worker(self):
        dead = {"name": "w", "alive": False, "stale": False}
        self.assertEqual(worker_health.problems(rows=[dead]),
                         ["w: thread died"])


if __name__ == "__main__":
    unittest.main()
