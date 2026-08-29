"""Twelfth leftover-500s sweep of the Health surfaces.

health11 sealed the hash-shadow cache keys, the bool-liars through
``_jsonable``, the worker-registry shadow keys, the ``sh()`` answer-shape
unpack in the SMART probe and the nginx shadow-field collapse.  Re-running
the zoo with ``__bool__``-bomb *values* under honest keys, and with shadow
elements inside the running-labels *set*, surfaced live leftovers:

* an ``os.access`` answer whose ``__bool__`` raises escaped the backup-dir
  try raw — the ``if not ok`` fix-string probe on the ``_check`` call sits
  *outside* every guard, so it raised out of ``_collect_checks`` itself: a
  raw 500 on every GET /api/health/checks, the last bare truth test on the
  page;
* the same bomb answered by ``port_open`` rode ``_probe_port``'s own try
  (the raise only fires later, in ``_port_checks``'s ``if up``) — ``_safe``
  swallowed it and every port row silently vanished;
* under an honest ``running`` / ``ok`` key in the nginx overview and
  config-test answers, the bomb raised through the pair-wide try — a
  *running* nginx collapsed into the combined not-installed error row and
  the config-syntax sibling vanished (the health11 shadow-key collapse,
  one seam over: the *value* this time, not the key);
* the brew loop still read rows with bound ``.get`` behind a bare
  ``isinstance``: a hash-shadowing junk key riding a row (same hash as
  ``name``/``status``, raising ``__eq__``) knocked the postgresql@18 row —
  the exact row this page exists to show — out of the payload through the
  per-row try;
* ``frozenset(running_labels)`` copied the probe's *elements* as they
  were, and set membership compares the lookup key against the **stored**
  elements: a shadow element (same hash as ``homebrew.mxcl.postgresql@18``
  or a KeepAlive label) detonated ``in running_labels`` inside the
  per-row trys and silently dropped the brew launchd re-check and the
  agent's KeepAlive warning;
* ``worker_health.problems`` truth-tested raw row fields (``name or "?"``,
  ``if not …alive``): a ``__bool__``-bomb field dropped that worker's
  dead/stale report through the per-row try — the poisoned worker passed
  as healthy.  A bombed ``alive`` now reads as the "thread died" report,
  fail-closed in the direction the page exists to warn about.

Conflict policy is pinned, not re-claimed: ``_isa`` stays fail-closed,
``_rc_int`` junk still reads ``-255`` (never the ``-1`` vanished sentinel),
``type is bool`` stays the exact-bool gate in ``_jsonable``, ``_mapping_get``
degrades only the shadowed field, ``_ping_deadline`` keeps its shape, and
the ``wg.ping_missing`` 503 stays disk-confirm-only.  Product version stays
3.9.3.
"""
from __future__ import annotations

import json
import sys
import tempfile
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


class _BoolBomb:
    """A value that cannot answer whether it is true."""

    def __bool__(self):
        raise RuntimeError("bool bomb")


class _ClassBomb:
    """A leftover that cannot answer what it is: ``isinstance`` raises."""

    @property
    def __class__(self):
        raise RuntimeError("class bomb")


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


# --------------------------------------------------------------------------
# The backup-dir truth test: the last one outside every guard
# --------------------------------------------------------------------------
class BackupDirBoolBombTests(_HealthCacheSandbox):
    def _with_backups_dir(self, access):
        tmp = tempfile.mkdtemp(prefix="health12-home-")
        home = Path(tmp)
        (home / "Services" / "backups").mkdir(parents=True)
        with mock.patch.object(health_svc, "user_home", lambda: home), \
                mock.patch("os.access", access):
            return _client().get("/api/health/checks")

    def test_bool_bomb_access_answer_is_not_a_500(self):
        # Pre-fix: ``ok`` escaped the try raw and the ``if not ok``
        # fix-string probe raised out of _collect_checks — a raw 500.
        rows = self._checks(self._with_backups_dir(lambda *a, **k: _BoolBomb()))
        self.assertIn("backup_dir", rows)
        # An answer that cannot say whether the dir is writable reads as
        # not-writable: the row warns instead of the route dying.
        self.assertFalse(rows["backup_dir"]["ok"])

    def test_honest_writable_dir_still_renders_ok(self):
        rows = self._checks(self._with_backups_dir(lambda *a, **k: True))
        self.assertTrue(rows["backup_dir"]["ok"])


# --------------------------------------------------------------------------
# port_open answering a __bool__ bomb: rows must render, not vanish
# --------------------------------------------------------------------------
class PortRowBoolBombTests(_HealthCacheSandbox):
    def test_bool_bomb_port_answer_keeps_every_port_row(self):
        # Pre-fix: the raise fired in _port_checks's ``if up`` comprehension,
        # _safe swallowed it, and all four port rows silently vanished.
        with mock.patch.object(health_svc, "port_open", lambda p: _BoolBomb()):
            rows = self._checks(_client().get("/api/health/checks"))
        for pid in ("port_8443", "port_8123", "port_8281"):
            self.assertIn(pid, rows)
            self.assertFalse(rows[pid]["ok"])
            self.assertEqual(rows[pid]["detail"], "port not responding")

    def test_honest_open_port_still_renders_reachable(self):
        with mock.patch.object(health_svc, "port_open", lambda p: True):
            rows = self._checks(_client().get("/api/health/checks"))
        self.assertTrue(rows["port_8443"]["ok"])

    def test_probe_port_launders_the_answer(self):
        with mock.patch.object(health_svc, "port_open", lambda p: _BoolBomb()):
            self.assertIs(health_svc._probe_port(80), False)
        with mock.patch.object(health_svc, "port_open", lambda p: True):
            self.assertIs(health_svc._probe_port(80), True)

    def test_truthy_is_fail_closed(self):
        self.assertIs(health_svc._truthy(_BoolBomb()), False)
        self.assertIs(health_svc._truthy(_ClassBomb()), True)  # object() truth
        self.assertIs(health_svc._truthy(True), True)
        self.assertIs(health_svc._truthy(0), False)


# --------------------------------------------------------------------------
# nginx pair: __bool__-bomb values under honest keys must not collapse it
# --------------------------------------------------------------------------
class NginxPairBoolBombTests(unittest.TestCase):
    def _pair(self, overview, test_answer):
        with mock.patch.object(health_svc, "nginx_overview", lambda: overview), \
                mock.patch.object(health_svc, "nginx_test", lambda: test_answer):
            return health_svc._nginx_pair()

    def test_bool_bomb_running_keeps_the_config_sibling(self):
        # Pre-fix: bool(bomb) raised inside the pair-wide try — a running
        # nginx collapsed into the combined not-installed error row.
        pair = self._pair({"running": _BoolBomb(), "pid": 1, "site_count": 2},
                          {"ok": True, "message": "ok"})
        self.assertEqual([c["id"] for c in pair], ["nginx", "nginx_conf"])
        self.assertFalse(pair[0]["ok"])
        self.assertTrue(pair[1]["ok"])

    def test_bool_bomb_test_ok_keeps_both_rows(self):
        # Pre-fix: the ``if not t_ok`` fix-string probe raised the same way.
        pair = self._pair({"running": True, "pid": 1, "site_count": 2},
                          {"ok": _BoolBomb(), "message": "syntax?"})
        self.assertEqual([c["id"] for c in pair], ["nginx", "nginx_conf"])
        self.assertTrue(pair[0]["ok"])
        self.assertFalse(pair[1]["ok"])
        self.assertEqual(pair[1]["fix"], "Check ~/Services/nginx/conf.d/")

    def test_honest_overview_still_renders_running(self):
        pair = self._pair({"running": True, "pid": 12, "site_count": 3},
                          {"ok": True, "message": "ok"})
        self.assertTrue(pair[0]["ok"])
        self.assertIn("pid=12", pair[0]["detail"])


# --------------------------------------------------------------------------
# brew rows: shadow keys degrade one field, never the row
# --------------------------------------------------------------------------
class BrewRowShadowTests(_HealthCacheSandbox):
    def _with_brew(self, rows, labels=frozenset()):
        with mock.patch.object(health_svc, "brew_services_list", lambda: rows), \
                mock.patch.object(health_svc, "launchd_running_labels",
                                  lambda: labels):
            return self._checks(_client().get("/api/health/checks"))

    def test_shadowed_status_row_still_renders(self):
        # Pre-fix: the bound ``s.get("status")`` probe landed on the shadow
        # slot, raised through the per-row try, and the postgresql@18 row
        # silently vanished.
        row = {"name": "postgresql@18"}
        row[_shadow_key("status")] = 1
        rows = self._with_brew([row])
        self.assertIn("brew_postgresql@18", rows)
        self.assertFalse(rows["brew_postgresql@18"]["ok"])
        self.assertEqual(rows["brew_postgresql@18"]["detail"], "unknown")

    def test_poisoned_row_drops_alone_siblings_render(self):
        bad = {"status": "started"}
        bad[_shadow_key("name")] = 1
        rows = self._with_brew([bad, {"name": "grafana", "status": "started"}])
        self.assertIn("brew_grafana", rows)
        self.assertTrue(rows["brew_grafana"]["ok"])

    def test_class_bomb_row_drops_alone(self):
        rows = self._with_brew(
            [_ClassBomb(), {"name": "mosquitto", "status": "started"}])
        self.assertIn("brew_mosquitto", rows)


# --------------------------------------------------------------------------
# running-labels: shadow elements are laundered out of the membership set
# --------------------------------------------------------------------------
class RunningLabelShadowTests(_HealthCacheSandbox):
    LABEL = "homebrew.mxcl.postgresql@18"

    def _with_labels(self, labels):
        with mock.patch.object(health_svc, "launchd_running_labels",
                               lambda: labels), \
                mock.patch.object(
                    health_svc, "brew_services_list",
                    lambda: [{"name": "postgresql@18", "status": "none"}]):
            return self._checks(_client().get("/api/health/checks"))

    def test_shadow_element_keeps_the_brew_recheck_row(self):
        # Pre-fix: the membership probe compared against the stored shadow
        # element, raised through the per-row try, and the postgres row —
        # the exact row this page exists to show — silently vanished.
        rows = self._with_labels({_shadow_key(self.LABEL), "other.honest"})
        self.assertIn("brew_postgresql@18", rows)
        self.assertFalse(rows["brew_postgresql@18"]["ok"])

    def test_honest_label_still_upgrades_none_to_running(self):
        rows = self._with_labels(frozenset({self.LABEL}))
        self.assertTrue(rows["brew_postgresql@18"]["ok"])
        self.assertEqual(rows["brew_postgresql@18"]["detail"],
                         "running (launchd)")

    def test_label_set_launders_to_exact_strs(self):
        out = health_svc._label_set({_shadow_key("x"), "honest"})
        self.assertEqual({type(e) for e in out}, {str})
        self.assertIn("honest", out)
        self.assertNotIn("x", out)  # membership probe must not raise

    def test_label_set_walks_a_subclass_iter_bomb_by_storage(self):
        class IterBomb(frozenset):
            def __iter__(self):
                raise RuntimeError("iter bomb")

        out = health_svc._label_set(IterBomb({"a", "b"}))
        self.assertEqual(out, frozenset({"a", "b"}))

    def test_label_set_rejects_junk_shapes(self):
        self.assertEqual(health_svc._label_set(_liar(set)), frozenset())
        self.assertEqual(health_svc._label_set(_ClassBomb()), frozenset())
        self.assertEqual(health_svc._label_set(None), frozenset())
        self.assertEqual(health_svc._label_set(["l1", "l2"]),
                         frozenset({"l1", "l2"}))


# --------------------------------------------------------------------------
# worker_health.problems: bombed fields fail toward the report
# --------------------------------------------------------------------------
class WorkerProblemsFieldBombTests(unittest.TestCase):
    def test_bool_bomb_alive_is_reported_dead_not_dropped(self):
        # Pre-fix: ``if not …alive`` raised through the per-row try and the
        # poisoned worker silently passed as healthy.
        rows = [{"name": "w", "alive": _BoolBomb(), "stale": False},
                {"name": "dead2", "alive": False, "stale": False}]
        self.assertEqual(worker_health.problems(rows=rows),
                         ["w: thread died", "dead2: thread died"])

    def test_bool_bomb_name_keeps_its_report(self):
        class NameBoolBomb(str):
            def __bool__(self):
                raise RuntimeError("name bool bomb")

        rows = [{"name": NameBoolBomb("nm"), "alive": False, "stale": False}]
        self.assertEqual(worker_health.problems(rows=rows),
                         ["nm: thread died"])

    def test_bool_bomb_stale_reads_not_stale(self):
        rows = [{"name": "w", "alive": True, "stale": _BoolBomb()}]
        self.assertEqual(worker_health.problems(rows=rows), [])

    def test_missing_name_still_reports_with_placeholder(self):
        self.assertEqual(
            worker_health.problems(rows=[{"alive": False, "stale": False}]),
            ["?: thread died"])

    def test_honest_stale_row_report_shape_unchanged(self):
        rows = [{"name": "s", "alive": True, "stale": True,
                 "age_sec": 10.0, "interval": 2.0}]
        self.assertEqual(worker_health.problems(rows=rows),
                         ["s: last tick 10s ago (interval 2s)"])


# --------------------------------------------------------------------------
# Conflict-policy pins (health8–11): do not weaken the union guards
# --------------------------------------------------------------------------
class ConflictPolicyPins(unittest.TestCase):
    def test_rc_int_junk_reads_minus_255_never_the_vanished_sentinel(self):
        self.assertEqual(health_svc._rc_int(_ClassBomb()), -255)
        self.assertEqual(health_svc._rc_int("junk"), -255)
        self.assertNotEqual(health_svc._rc_int(_ClassBomb()), -1)

    def test_isa_stays_fail_closed(self):
        self.assertFalse(health_svc._isa(_ClassBomb(), dict))
        self.assertFalse(worker_health._isa(_ClassBomb(), dict))

    def test_jsonable_type_is_bool_gate_unchanged(self):
        self.assertIs(health_svc._jsonable(True), True)
        self.assertIs(health_svc._jsonable(False), False)
        self.assertIs(health_svc._jsonable(_liar(bool)), True)

    def test_mapping_get_degrades_only_the_shadowed_field(self):
        d = {"keep": 2}
        d[_shadow_key("gone")] = 1
        self.assertIsNone(health_svc._mapping_get(d, "gone"))
        self.assertEqual(health_svc._mapping_get(d, "keep"), 2)

    def test_ping_deadline_shape_unchanged(self):
        self.assertEqual(wireguard_svc._ping_deadline(_ClassBomb()), 800)
        self.assertEqual(wireguard_svc._ping_deadline(800), 800)
        self.assertEqual(wireguard_svc._ping_deadline(None), 800)

    def test_smart_answer_shape_guard_unchanged(self):
        with mock.patch.object(health_svc, "sh", lambda *a, **k: _liar(tuple)):
            self.assertEqual(health_svc._smart_checks(), [])
        with mock.patch.object(
            health_svc, "sh",
            lambda *a, **k: (0, "SMART overall-health: PASSED", ""),
        ):
            rows = health_svc._smart_checks()
        self.assertEqual(rows[0]["id"], "smart_disk0")

    def test_problems_still_reports_dead_worker(self):
        dead = {"name": "w", "alive": False, "stale": False}
        self.assertEqual(worker_health.problems(rows=[dead]),
                         ["w: thread died"])


if __name__ == "__main__":
    unittest.main()
