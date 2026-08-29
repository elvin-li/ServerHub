"""Eleventh leftover-500s sweep of the Health / worker / ping surfaces.

health10 sealed the lying-``__class__`` impostors on the unbound-descriptor
seams.  Re-running the zoo with the vms/terminal *hash-shadowing* key shape
and the docker11 *answer-shape* bombs surfaced live leftovers:

* a str-subclass key whose hash shadows ``v``/``t`` and whose ``__eq__``
  raises, planted in ``health_svc._cache``, detonated the bare
  ``_cache["v"]`` subscript in ``_fresh_snapshot`` (and the final
  ``_cache.update`` insert compare in ``_collect_checks``) — a raw 500 on
  every GET /api/health/checks, the one cache poisoning ``_serve_cached``
  could never reach;
* a *bool-liar* (lying ``__class__`` answering ``bool`` over a plain
  object) passed ``_jsonable``'s ``_isa(value, bool)`` gate and was
  returned **raw** — Starlette's encoder then 500'd GET /api/health/checks
  on every TTL hit and on the fresh collection alike (the raw Immich/
  Ollama rows bypass ``_check``);
* the same shadow key planted in a worker-registry entry raised out of
  ``snapshot()``'s bound ``entry.get`` (silently wiping the workers row),
  and shadowing a real worker *name* raised out of the C-level compare
  inside ``register()`` / ``beat()`` / ``unregister()`` on the worker's
  own thread — killing the exact loop the registry exists to watch;
* an ``sh()`` *answer-shape* bomb (tuple-liar, 2-tuple, tuple subclass
  whose ``__iter__`` raises) detonated the bare ``rc, out, _ = …`` unpack
  in ``_smart_checks``; ``_safe`` swallowed the raise and the SMART row
  silently vanished (the docker11 rule, on the health surface);
* a shadow key over ``running`` in the nginx overview collapsed a
  *running* nginx into the combined not-installed error row and dropped
  the config-syntax sibling (the over-cap-int collapse class, one seam
  over) — now each shadowed field degrades to its default alone.

Conflict policy is pinned, not re-claimed: ``_isa`` stays fail-closed,
``_rc_int`` junk still reads ``-255`` (never the ``-1`` vanished
sentinel), ``_decode_bytes``/``_as_text`` still absorb the health10 liars,
``_ping_deadline`` keeps its shape, and the health8/9 ``wg.ping_missing``
503 fires only after the disk confirm.  Product version stays 3.9.3.
"""
from __future__ import annotations

import json
import sys
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from fastapi.testclient import TestClient  # noqa: E402

from hub import health_svc, wireguard_svc, worker_health  # noqa: E402
from hub.app_factory import create_app  # noqa: E402
from hub.auth import require_auth  # noqa: E402

INSTALL = {
    "installed": True, "conf_exists": True, "conf_path": "", "conf_dir": "",
    "wg": "wg", "wg_quick": "wg-quick", "wireguard_go": "",
    "tools_version": "v1", "userspace_version": "", "probe_failed": False,
}

#: sh()'s exact FileNotFoundError sentinel for a vanished binary.
_VANISHED = (-1, "", "not found")

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
    raises: inserting it downgrades the dict off the unicode fast path, and
    any later C-level probe for *target* lands on its slot and detonates
    the compare.  The vms/terminal/network hash-shadow zoo shape."""

    class Shadow(str):
        __hash__ = lambda self: hash(target)  # noqa: E731

        def __eq__(self, other):
            raise RuntimeError("shadow eq bomb")

        __ne__ = __eq__

    return Shadow("junk-" + target)


def _liar(cls, text="liar"):
    """A lying ``__class__`` impostor (the docker10/json9 shape)."""

    class Liar:
        __class__ = property(lambda self: cls)

        def __str__(self):
            return text

    return Liar()


class _ClassBomb:
    """A leftover that cannot answer what it is: ``isinstance`` raises."""

    @property
    def __class__(self):
        raise RuntimeError("class bomb")


class _HealthCacheSandbox(unittest.TestCase):
    """Save/restore the module cache so poisonings cannot leak between tests."""

    def setUp(self):
        saved = dict(health_svc._cache)

        def _restore():
            health_svc._cache.clear()
            health_svc._cache.update(saved)

        self.addCleanup(_restore)
        health_svc._cache.clear()
        health_svc._cache.update(t=0.0, v=None)

    _CLEAN_SNAPSHOT = {
        "ts": "now",
        "summary": {"ok": 1, "warn": 0, "error": 0, "total": 1},
        "checks": [{"id": "x", "name": "X", "level": "ok", "ok": True,
                    "detail": "", "fix": ""}],
        "healthy": True,
    }


# --------------------------------------------------------------------------
# Hash-shadowing keys in the module cache itself
# --------------------------------------------------------------------------
class CacheRootShadowKeyTests(_HealthCacheSandbox):
    """A shadow key planted in ``_cache`` re-collects; it never 500s."""

    def test_shadowed_v_slot_recollects_instead_of_500(self):
        # Pre-fix: the bare ``_cache["v"]`` subscript in _fresh_snapshot
        # raised RuntimeError out of the C-level compare on every request.
        health_svc._cache.clear()
        health_svc._cache[_shadow_key("v")] = 1
        resp = _client().get("/api/health/checks")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        self.assertIn("checks", body)
        self.assertIn("summary", body)

    def test_shadowed_t_slot_survives_the_cache_write(self):
        # Pre-fix: the collection succeeded and then the final
        # ``_cache.update(t=…, v=…)`` insert compare detonated — a 500 at
        # the very end of a healthy run.
        health_svc._cache.clear()
        health_svc._cache["v"] = None
        health_svc._cache[_shadow_key("t")] = 1
        resp = _client().get("/api/health/checks")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _no_surrogates(resp.json())

    def test_poisoned_cache_is_evicted_and_ttl_serves_again(self):
        health_svc._cache.clear()
        health_svc._cache[_shadow_key("v")] = 1
        first = _client().get("/api/health/checks")
        self.assertEqual(first.status_code, 200, first.text[:300])
        # The clear+rewrite evicted the bomb: the fresh snapshot landed and
        # the next request is an ordinary TTL hit, not another 500.
        self.assertEqual(
            [type(k) for k in health_svc._cache.keys()], [str, str])
        second = _client().get("/api/health/checks")
        self.assertEqual(second.status_code, 200, second.text[:300])
        self.assertEqual(second.json()["ts"], first.json()["ts"])

    def test_mapping_get_degrades_only_the_shadowed_field(self):
        d = {"keep": 2}
        d[_shadow_key("gone")] = 1
        self.assertIsNone(health_svc._mapping_get(d, "gone"))
        self.assertEqual(health_svc._mapping_get(d, "keep"), 2)
        self.assertEqual(health_svc._mapping_get(_ClassBomb(), "k", "d"), "d")


# --------------------------------------------------------------------------
# Bool-liars through _jsonable
# --------------------------------------------------------------------------
class BoolLiarJsonableTests(_HealthCacheSandbox):
    """A bool-liar is laundered to its truth value, never returned raw."""

    def test_ttl_hit_bool_liar_does_not_500(self):
        bad = dict(self._CLEAN_SNAPSHOT)
        bad["junk"] = _liar(bool)
        health_svc._cache.update(t=time.time(), v=bad)
        resp = _client().get("/api/health/checks")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        # The liar laundered to the truth value it claims; siblings intact.
        self.assertIs(body["junk"], True)
        self.assertEqual(body["checks"][0]["id"], "x")

    def test_fresh_collection_bool_liar_row_does_not_500(self):
        # The raw Immich rows bypass _check, so the liar rode the fresh
        # collection into Starlette's encoder — a 500 with no cache at all.
        from hub import immich_svc

        with mock.patch.object(
            immich_svc, "run_checks",
            lambda: {"checks": [{"id": "imm", "ok": _liar(bool),
                                 "level": "warn"}]},
        ):
            resp = _client().get("/api/health/checks")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        ids = [c.get("id") for c in body["checks"] if isinstance(c, dict)]
        self.assertIn("imm", ids)

    def test_jsonable_launders_bool_liar_to_exact_bool(self):
        out = health_svc._jsonable(_liar(bool))
        self.assertIs(out, True)

    def test_jsonable_bool_liar_with_bool_bomb_drops(self):
        class BoolBombLiar:
            __class__ = property(lambda self: bool)

            def __bool__(self):
                raise RuntimeError("bool bomb")

        self.assertIsNone(health_svc._jsonable(BoolBombLiar()))

    def test_jsonable_keeps_genuine_bools(self):
        self.assertIs(health_svc._jsonable(True), True)
        self.assertIs(health_svc._jsonable(False), False)
        self.assertEqual(health_svc._jsonable({"b": False}), {"b": False})


# --------------------------------------------------------------------------
# Worker registry: shadow keys in entries and over worker names
# --------------------------------------------------------------------------
class _WorkerRegistrySandbox(unittest.TestCase):
    """Save/restore the registry so plantings cannot leak between tests."""

    def setUp(self):
        saved = dict(worker_health._workers)

        def _restore():
            worker_health._workers.clear()
            worker_health._workers.update(saved)

        self.addCleanup(_restore)
        worker_health._workers.clear()

    CLEAN = {"thread": None, "interval": 60.0, "beat": 0.0}


class WorkerRegistryShadowTests(_WorkerRegistrySandbox):
    """Shadow keys cost one field or one slot — never a thread, never a row."""

    def test_snapshot_survives_shadowed_entry_field(self):
        # Pre-fix: the bound ``entry.get("thread")`` probe landed on the
        # shadow slot, raised, and the workers row silently vanished.
        entry = {"interval": 60.0, "beat": 0.0}
        entry[_shadow_key("thread")] = 1
        worker_health._workers["w"] = entry
        worker_health._workers["ok"] = dict(self.CLEAN)
        rows = worker_health.snapshot()
        self.assertEqual([r["name"] for r in rows], ["ok", "w"])
        _no_surrogates(rows)

    def test_register_evicts_the_shadow_and_lands(self):
        # Pre-fix: the C-level insert compare raised out of register() on
        # the worker's own thread — killing the loop at its first act.
        worker_health._workers["other"] = dict(self.CLEAN)
        worker_health._workers[_shadow_key("alert-engine")] = {"interval": 1}
        worker_health.register("alert-engine", 60, thread=None)
        names = sorted(k for k in worker_health._workers if type(k) is str)
        self.assertEqual(names, ["alert-engine", "other"])

    def test_beat_on_shadowed_name_is_a_noop_not_a_raise(self):
        worker_health._workers[_shadow_key("alert-engine")] = {"interval": 1}
        worker_health.beat("alert-engine")  # must not raise

    def test_beat_still_updates_an_honest_entry(self):
        worker_health.register("h", 60, thread=None)
        dict.__setitem__(worker_health._workers["h"], "beat", 0.0)
        worker_health.beat("h")
        self.assertGreater(worker_health._workers["h"]["beat"], 0.0)

    def test_unregister_evicts_the_shadow_and_keeps_siblings(self):
        worker_health._workers["other"] = dict(self.CLEAN)
        worker_health._workers[_shadow_key("w")] = {"interval": 1}
        worker_health.unregister("w")  # must not raise
        self.assertIn("other", worker_health._workers)

    def test_health_workers_row_survives_shadowed_entry(self):
        saved = dict(health_svc._cache)

        def _restore():
            health_svc._cache.clear()
            health_svc._cache.update(saved)

        self.addCleanup(_restore)
        health_svc._cache.clear()
        health_svc._cache.update(t=0.0, v=None)
        entry = {"interval": 60.0, "beat": 0.0}
        entry[_shadow_key("thread")] = 1
        worker_health._workers["w"] = entry
        resp = _client().get("/api/health/checks")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        ids = [c.get("id") for c in body["checks"] if isinstance(c, dict)]
        # Pre-fix snapshot() raised and this row silently vanished.
        self.assertIn("workers", ids)


# --------------------------------------------------------------------------
# sh() answer-shape bombs into the SMART probe
# --------------------------------------------------------------------------
class SmartAnswerShapeTests(unittest.TestCase):
    """Junk shapes keep the empty-row fallback; an honest triplet renders."""

    def _smart_with(self, answer):
        with mock.patch.object(health_svc, "sh", lambda *a, **k: answer):
            return health_svc._smart_checks()

    def test_tuple_liar_answer_reads_as_failure(self):
        # Pre-fix: the bare unpack raised TypeError; _safe swallowed it and
        # the SMART row silently vanished from GET /api/health/checks.
        self.assertEqual(self._smart_with(_liar(tuple)), [])

    def test_two_tuple_answer_reads_as_failure(self):
        self.assertEqual(self._smart_with((0, "PASSED")), [])

    def test_scalar_answer_reads_as_failure(self):
        self.assertEqual(self._smart_with(None), [])

    def test_tuple_subclass_iter_bomb_reads_as_failure(self):
        class IterBomb(tuple):
            def __iter__(self):
                raise RuntimeError("iter bomb")

        answer = IterBomb((0, "SMART overall-health: PASSED", ""))
        self.assertEqual(self._smart_with(answer), [])

    def test_honest_triplet_still_renders_the_row(self):
        rows = self._smart_with(
            (0, "SMART overall-health self-assessment test result: PASSED", ""))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], "smart_disk0")
        self.assertTrue(rows[0]["ok"])


# --------------------------------------------------------------------------
# nginx pair: shadowed overview fields degrade alone
# --------------------------------------------------------------------------
class NginxShadowFieldTests(unittest.TestCase):
    def test_shadowed_running_keeps_the_config_sibling(self):
        # Pre-fix: the bound ``ngx.get("running")`` probe raised inside the
        # pair-wide try — a running nginx collapsed into the combined
        # not-installed error row and the config-syntax check vanished.
        ngx = {"pid": 12, "site_count": 3}
        ngx[_shadow_key("running")] = 1
        with mock.patch.object(health_svc, "nginx_overview", lambda: ngx), \
                mock.patch.object(health_svc, "nginx_test",
                                  lambda: {"ok": True, "message": "ok"}):
            pair = health_svc._nginx_pair()
        self.assertEqual([c["id"] for c in pair], ["nginx", "nginx_conf"])
        self.assertTrue(pair[1]["ok"])

    def test_honest_overview_still_renders_running(self):
        ngx = {"running": True, "pid": 12, "site_count": 3}
        with mock.patch.object(health_svc, "nginx_overview", lambda: ngx), \
                mock.patch.object(health_svc, "nginx_test",
                                  lambda: {"ok": True, "message": "ok"}):
            pair = health_svc._nginx_pair()
        self.assertTrue(pair[0]["ok"])
        self.assertIn("pid=12", pair[0]["detail"])

    def test_shadowed_level_row_still_counts_in_the_summary(self):
        # _row_flags is nested in _collect_checks; pin it through the route.
        # Pre-fix the bound ``c.get`` probes raised through the per-row try
        # and the shadowed row silently fell out of the summary sums.
        saved = dict(health_svc._cache)

        def _restore():
            health_svc._cache.clear()
            health_svc._cache.update(saved)

        self.addCleanup(_restore)
        health_svc._cache.clear()
        health_svc._cache.update(t=0.0, v=None)
        from hub import immich_svc

        row = {"id": "imm", "ok": True}
        row[_shadow_key("level")] = 1
        with mock.patch.object(
            immich_svc, "run_checks", lambda: {"checks": [row]}
        ):
            resp = _client().get("/api/health/checks")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        ids = [c.get("id") for c in body["checks"] if isinstance(c, dict)]
        self.assertIn("imm", ids)
        self.assertGreaterEqual(body["summary"]["ok"], 1)


# --------------------------------------------------------------------------
# Conflict-policy pins (health8–10): do not weaken the union guards
# --------------------------------------------------------------------------
class _MountedWgRouteTests(unittest.TestCase):
    """Real app, auth overridden, admin guard and installation patched."""

    def setUp(self):
        from hub.routers import wireguard_api

        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.client = _client()
        self.stack.enter_context(mock.patch.object(
            wireguard_api, "require_admin_browser", lambda request: "admin"
        ))
        self.stack.enter_context(mock.patch.object(
            wireguard_svc, "installation", lambda: dict(INSTALL)
        ))

    CLEAN = {"public_key": "pk-clean", "name": "phone", "ip": "10.10.0.2/32"}

    def _ping_with(self, records, sh_answer=(0, "64 bytes: time=1.2 ms", ""),
                   gone=None):
        patches = [
            mock.patch.object(wireguard_svc, "peer_records", return_value=records),
            mock.patch.object(
                wireguard_svc, "sh", lambda cmd, timeout=10, **k: sh_answer),
        ]
        if gone is not None:
            patches.append(mock.patch.object(
                wireguard_svc, "_ping_cli_gone", return_value=gone))
        with ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            return self.client.post("/api/wireguard/ping")


class ConflictPolicyPins(_MountedWgRouteTests):
    """The health8–10 union guards stay exactly as strong as they are."""

    def test_vanished_cli_503_still_fires_after_disk_confirm(self):
        resp = self._ping_with([dict(self.CLEAN)], sh_answer=_VANISHED, gone=True)
        self.assertEqual(resp.status_code, 503, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "wg.ping_missing")

    def test_sentinel_without_disk_confirm_keeps_honest_rows(self):
        resp = self._ping_with([dict(self.CLEAN)], sh_answer=_VANISHED, gone=False)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertFalse(resp.json()["results"][0]["reachable"])

    def test_ping_deadline_shape_unchanged(self):
        self.assertEqual(wireguard_svc._ping_deadline(_ClassBomb()), 800)
        self.assertEqual(wireguard_svc._ping_deadline(800), 800)
        self.assertEqual(wireguard_svc._ping_deadline(None), 800)

    def test_rc_int_junk_reads_minus_255_never_the_vanished_sentinel(self):
        class EqBomb(int):
            def __eq__(self, other):
                raise RuntimeError("eq bomb")

        self.assertEqual(health_svc._rc_int(EqBomb(0)), 0)
        self.assertEqual(health_svc._rc_int(_ClassBomb()), -255)
        self.assertEqual(health_svc._rc_int("junk"), -255)
        self.assertNotEqual(health_svc._rc_int(_ClassBomb()), -1)

    def test_health10_liar_launders_still_absorb(self):
        self.assertEqual(health_svc._decode_bytes(_liar(bytes, "hb")), "")
        self.assertEqual(health_svc._as_text(_liar(bytes, "hx")), "hx")
        self.assertEqual(worker_health._utf8_text(_liar(bytes, "wb")), "wb")

    def test_isa_stays_fail_closed(self):
        self.assertFalse(health_svc._isa(_ClassBomb(), dict))
        self.assertFalse(worker_health._isa(_ClassBomb(), dict))

    def test_problems_still_reports_dead_worker(self):
        dead = {"name": "w", "alive": False, "stale": False}
        self.assertEqual(worker_health.problems(rows=[dead]), ["w: thread died"])


if __name__ == "__main__":
    unittest.main()
