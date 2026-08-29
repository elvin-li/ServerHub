"""Ninth leftover-500s sweep of the Health / SMART / ping / worker surfaces.

health8 sealed the ping-deadline, poisoned-peer-row and worker-registry
numeric bombs.  Re-running the zoo with the *``__class__``-property* and
*rc-``__eq__``* members surfaced live leftovers:

* ``isinstance`` consults ``value.__class__`` when the exact-type check
  misses, so a leftover whose ``__class__`` is a *raising property*
  detonated the gates themselves: planted as (or nested in) the cached
  snapshot it 500'd ``health_svc._fresh_snapshot`` / ``_jsonable`` on every
  GET /api/health/checks; returned as a check row (or as the rows object)
  from the Immich/Ollama probe modules it 500'd ``_as_checks`` /
  ``_row_flags`` after every probe had already answered; planted as a peer
  listing or row it 500'd POST /api/wireguard/ping out of
  ``_ping_targets``'s own gates; and planted in the worker registry it
  raised out of ``snapshot()``/``problems()`` (silently wiping the workers
  row), out of ``beat()`` on the worker's own thread, and out of
  ``register()``/``loop_interval()`` on the start path.
* ``rc``-subclass ``__eq__`` bombs from a patched/odd ``sh`` detonated the
  bare ``rc == -1`` / ``rc == 0`` / ``rc in (0, 4)`` probes:
  ``wireguard_svc._ping_spawn_sentinel`` re-raised through ``fan_out`` and
  500'd POST /api/wireguard/ping; ``smart_test_svc._device_nodes`` and
  ``passwordless_available`` 500'd GET /api/smart from inside
  ``overview()``'s fan-out; ``start_test``/``abort_test``'s own spawn
  500'd POST /api/smart/test and /abort; and ``health_svc._smart_checks``
  silently wiped the SMART row.  ``int.__index__`` salvages the honest
  exit status; only a value that cannot answer one reads as failure.
* ``worker_health.snapshot`` sorted with a bare ``str(kv[0])`` — a planted
  over-cap-int (or ``__str__``-bomb) name key raised out of snapshot()
  and wiped the workers row.
* ``worker_health._coerce_now`` caught only the arithmetic trio — a
  float-subclass ``__float__`` bomb passed to ``snapshot(now=...)`` raised
  for in-process callers.
* Generic iterables (a patched ``peer_records`` / ``problems(rows=...)``)
  that answer ``iter()`` but raise mid-iteration blew the walk past the
  per-row drops; rows already yielded now survive.

Already-immune vectors are pinned rather than re-claimed: the
``_ping_deadline`` clamp, the health8 ``wg.ping_missing`` 503 (disk-confirm
only), the FIFO-occupied history journal, the over-cap JSON number in the
history journal, the isoformat property bomb, and the garbage LaunchAgent
plist.
"""
from __future__ import annotations

import json
import os
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

from hub import health_svc, smart_test_svc, wireguard_svc, worker_health  # noqa: E402
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


class _ClassBomb:
    """A leftover that cannot answer what it is: ``isinstance`` itself raises."""

    @property
    def __class__(self):
        raise RuntimeError("class bomb")


class _EqBombInt(int):
    """An rc whose comparison raises — ``rc == 0`` / ``rc in (0, 4)`` detonate."""

    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    def __ne__(self, other):
        raise RuntimeError("ne bomb")

    __hash__ = int.__hash__


class _FloatBombFloat(float):
    def __float__(self):
        raise RuntimeError("float bomb")


class _IsoBombProperty:
    """getattr(value, 'isoformat') itself raises — the property is the bomb."""

    @property
    def isoformat(self):
        raise RuntimeError("isoformat bomb")


_CLEAN_SNAPSHOT = {
    "ts": "now",
    "summary": {"ok": 1, "warn": 0, "error": 0, "total": 1},
    "checks": [{"id": "x", "name": "X", "level": "ok", "ok": True,
                "detail": "", "fix": ""}],
    "healthy": True,
}


class _HealthCacheSandbox(unittest.TestCase):
    """Save/restore the module cache so poisonings cannot leak between tests."""

    def setUp(self):
        saved = dict(health_svc._cache)
        self.addCleanup(lambda: health_svc._cache.update(saved))
        health_svc._cache.update(t=0.0, v=None)


class HealthCacheClassBombTests(_HealthCacheSandbox):
    """__class__-property bombs planted in the cache: 200, never 500."""

    def _ttl_hit_with(self, junk):
        bad = dict(_CLEAN_SNAPSHOT)
        bad["junk"] = junk
        health_svc._cache.update(t=time.time(), v=bad)
        return _client().get("/api/health/checks")

    def test_whole_snapshot_class_bomb_recollects(self):
        # isinstance(hit, dict) in _fresh_snapshot detonated on the bomb —
        # a 500 on every request until the TTL rolled.
        health_svc._cache.update(t=time.time(), v=_ClassBomb())
        resp = _client().get("/api/health/checks")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        self.assertIn("checks", body)

    def test_nested_class_bomb_value_drops_siblings_survive(self):
        resp = self._ttl_hit_with(_ClassBomb())
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        # The sane sibling rows keep rendering.
        self.assertEqual(body["checks"][0]["id"], "x")

    def test_nested_class_bomb_dict_key_drops_pair_alone(self):
        resp = self._ttl_hit_with({_ClassBomb(): 1, "keep": 2})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        # The torn pair drops; its sibling key survives.
        self.assertEqual(body["junk"].get("keep"), 2)

    def test_isoformat_property_bomb_stays_immune(self):
        # Pin: getattr's except already absorbs a raising isoformat property.
        resp = self._ttl_hit_with(_IsoBombProperty())
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _no_surrogates(resp.json())


class HealthProbeRowClassBombTests(_HealthCacheSandbox):
    """Bomb rows from the probe modules cost only themselves at summary time."""

    def test_class_bomb_check_row_drops_alone(self):
        clean = health_svc._check("i", "Immich", "ok", True, "fine")
        with mock.patch.object(
            health_svc, "_immich_checks", return_value=[_ClassBomb(), clean]
        ):
            resp = _client().get("/api/health/checks")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        ids = [c.get("id") for c in body["checks"] if isinstance(c, dict)]
        self.assertIn("i", ids)

    def test_class_bomb_rows_object_drops_to_no_rows(self):
        with mock.patch.object(
            health_svc, "_immich_checks", return_value=_ClassBomb()
        ):
            resp = _client().get("/api/health/checks")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _no_surrogates(resp.json())

    def test_smart_row_survives_rc_eq_bomb(self):
        # The honest exit status is salvaged through int.__index__, so the
        # PASSED row renders instead of silently vanishing.
        with mock.patch.object(
            health_svc, "sh",
            lambda cmd, timeout=10, **k: (_EqBombInt(0), "SMART overall: PASSED", ""),
        ):
            rows = health_svc._smart_checks()
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["ok"])


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


class WorkerRegistryClassBombTests(_WorkerRegistrySandbox):
    """Registry bombs cost only their own entry, never the workers row."""

    def test_snapshot_drops_class_bomb_entry_alone(self):
        worker_health._workers["ok"] = dict(self.CLEAN)
        worker_health._workers["bomb"] = _ClassBomb()
        rows = worker_health.snapshot()
        self.assertEqual([r["name"] for r in rows], ["ok"])

    def test_snapshot_survives_overcap_int_name_key(self):
        # The bare str() sort key ValueError'd past CPython's digit cap.
        worker_health._workers[10 ** 5000] = dict(self.CLEAN)
        worker_health._workers["ok"] = dict(self.CLEAN)
        rows = worker_health.snapshot()
        self.assertEqual(len(rows), 2)
        _no_surrogates(rows)

    def test_snapshot_now_float_bomb_answers(self):
        worker_health._workers["ok"] = dict(self.CLEAN)
        rows = worker_health.snapshot(now=_FloatBombFloat(1.0))
        self.assertEqual(len(rows), 1)

    def test_problems_drops_class_bomb_row_keeps_sibling(self):
        dead = {"name": "w", "alive": False, "stale": False}
        out = worker_health.problems(rows=[_ClassBomb(), dead])
        self.assertEqual(out, ["w: thread died"])

    def test_problems_generator_raising_midway_keeps_yielded_rows(self):
        def rows():
            yield {"name": "w", "alive": False, "stale": False}
            raise RuntimeError("mid-iteration bomb")

        self.assertEqual(worker_health.problems(rows=rows()), ["w: thread died"])

    def test_beat_over_class_bomb_entry_is_a_noop(self):
        # A raise here lands on the worker's own thread and kills the loop.
        worker_health._workers["w"] = _ClassBomb()
        worker_health.beat("w")

    def test_register_class_bomb_interval_takes_default(self):
        worker_health.register("w", _ClassBomb(), thread=None)
        rows = worker_health.snapshot()
        self.assertEqual(rows[0]["interval"], 60.0)

    def test_loop_interval_class_bomb_takes_default(self):
        self.assertEqual(worker_health.loop_interval(_ClassBomb(), 90), 90)

    def test_health_workers_row_survives_planted_bomb(self):
        saved = dict(health_svc._cache)
        self.addCleanup(lambda: health_svc._cache.update(saved))
        health_svc._cache.update(t=0.0, v=None)
        worker_health._workers["real"] = dict(self.CLEAN)
        worker_health._workers["bomb"] = _ClassBomb()
        resp = _client().get("/api/health/checks")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        ids = [c.get("id") for c in body["checks"] if isinstance(c, dict)]
        # Pre-fix snapshot() raised and this row silently vanished.
        self.assertIn("workers", ids)


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


class PingClassBombAndRcTests(_MountedWgRouteTests):
    """__class__-property and rc-__eq__ bombs: 200/503 coded, never 500."""

    def test_class_bomb_records_object_answers_empty(self):
        resp = self._ping_with(_ClassBomb())
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["results"], [])

    def test_class_bomb_row_drops_alone(self):
        resp = self._ping_with([_ClassBomb(), dict(self.CLEAN)])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        self.assertEqual([r["name"] for r in body["results"]], ["phone"])

    def test_generator_records_raising_midway_keeps_yielded_rows(self):
        def rows():
            yield dict(self.CLEAN)
            raise RuntimeError("mid-iteration bomb")

        resp = self._ping_with(rows())
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual([r["name"] for r in resp.json()["results"]], ["phone"])

    def test_rc_eq_bomb_keeps_honest_unreachable_row(self):
        # The sentinel probe ``rc == -1`` used to re-raise through fan_out.
        resp = self._ping_with([dict(self.CLEAN)], sh_answer=(_EqBombInt(2), "", "boom"))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertFalse(body["results"][0]["reachable"])
        self.assertEqual(body["reachable"], 0)

    def test_rc_eq_bomb_value_is_salvaged_not_defaulted(self):
        # int.__index__ keeps the honest exit: a bombed rc 0 still reads
        # reachable rather than degrading to a false alarm.
        resp = self._ping_with(
            [dict(self.CLEAN)], sh_answer=(_EqBombInt(0), "64 bytes: time=1.2 ms", ""))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertTrue(resp.json()["results"][0]["reachable"])

    def test_ping_deadline_class_bomb_stays_immune(self):
        # Pin: the health8 clamp already runs its gates inside the try.
        self.assertEqual(wireguard_svc._ping_deadline(_ClassBomb()), 800)

    def test_vanished_cli_503_still_fires_after_disk_confirm(self):
        # Pin: the health8 coded 503 survives the rc coercion.
        resp = self._ping_with([dict(self.CLEAN)], sh_answer=_VANISHED, gone=True)
        self.assertEqual(resp.status_code, 503, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "wg.ping_missing")

    def test_vanished_cli_503_fires_through_a_bombed_rc(self):
        # A bombed rc -1 still coerces to the exact sentinel value.
        resp = self._ping_with(
            [dict(self.CLEAN)], sh_answer=(_EqBombInt(-1), "", "not found"), gone=True)
        self.assertEqual(resp.status_code, 503, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "wg.ping_missing")

    def test_sentinel_without_disk_confirm_keeps_honest_rows(self):
        # Pin: the disk probe still gates the 503.
        resp = self._ping_with([dict(self.CLEAN)], sh_answer=_VANISHED, gone=False)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertFalse(resp.json()["results"][0]["reachable"])


class _SmartSandbox(unittest.TestCase):
    """Clear the per-process transport cache so probes cannot leak."""

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        saved = dict(smart_test_svc._device_type_cache)

        def _restore():
            smart_test_svc._device_type_cache.clear()
            smart_test_svc._device_type_cache.update(saved)

        self.addCleanup(_restore)
        smart_test_svc._device_type_cache.clear()
        from hub.routers import nas_storage
        self.stack.enter_context(mock.patch.object(
            nas_storage, "require_admin_browser", lambda request: "admin"
        ))


class SmartRcBombTests(_SmartSandbox):
    """rc-__eq__ bombs from a patched sh: coded answers, never 500."""

    def _sh(self, rc, out="", err=""):
        return mock.patch.object(
            smart_test_svc, "sh", lambda cmd, timeout=10, **k: (rc, out, err))

    def test_get_smart_survives_rc_eq_bomb(self):
        # _device_nodes and passwordless_available both compared the bomb.
        with self._sh(_EqBombInt(0), out=""):
            resp = _client().get("/api/smart?force=true")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _no_surrogates(resp.json())

    def test_post_smart_test_survives_rc_eq_bomb(self):
        with (
            mock.patch.object(
                smart_test_svc, "_device_nodes", return_value=["/dev/disk0"]),
            self._sh(_EqBombInt(0), out="Short self-test routine"),
        ):
            resp = _client().post(
                "/api/smart/test", json={"device": "/dev/disk0", "kind": "short"})
        self.assertNotEqual(resp.status_code, 500, resp.text[:300])
        _no_surrogates(resp.json())

    def test_post_smart_abort_survives_rc_eq_bomb(self):
        with (
            mock.patch.object(
                smart_test_svc, "_device_nodes", return_value=["/dev/disk0"]),
            self._sh(_EqBombInt(0), out="aborted"),
        ):
            resp = _client().post("/api/smart/abort", json={"device": "/dev/disk0"})
        self.assertNotEqual(resp.status_code, 500, resp.text[:300])
        _no_surrogates(resp.json())


class SmartHistoryJournalPinTests(unittest.TestCase):
    """Stays-immune pins for the history journal reader."""

    def _with_history_path(self, path):
        return mock.patch.object(smart_test_svc, "HISTORY_PATH", Path(path))

    def test_fifo_occupied_journal_answers_empty(self):
        # Pin: read_text_capped opens O_NONBLOCK and refuses non-regular
        # files, so a leftover FIFO cannot park GET /api/smart/history.
        import tempfile
        d = tempfile.mkdtemp(prefix="health9-fifo-")
        fifo = os.path.join(d, "smart-tests.json")
        os.mkfifo(fifo)
        self.addCleanup(os.unlink, fifo)
        with self._with_history_path(fifo):
            resp = _client().get("/api/smart/history")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["history"], [])

    def test_overcap_json_number_drops_alone_row_survives(self):
        # Pin: the parse_int hook drops the number, not the document —
        # int() of a >4300-digit run is ValueError, not JSONDecodeError.
        import tempfile
        d = tempfile.mkdtemp(prefix="health9-json-")
        journal = Path(d) / "smart-tests.json"
        journal.write_text(
            '[{"ts": ' + "1" * 5000 + ', "device": "/dev/disk0", "ok": true},'
            ' {"ts": 5, "device": "/dev/disk1", "ok": false}]',
            encoding="utf-8",
        )
        self.addCleanup(journal.unlink)
        with self._with_history_path(journal):
            resp = _client().get("/api/smart/history")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        rows = resp.json()["history"]
        _no_surrogates(rows)
        self.assertEqual(len(rows), 2)
        devices = {r["device"] for r in rows}
        self.assertEqual(devices, {"/dev/disk0", "/dev/disk1"})
        by_dev = {r["device"]: r for r in rows}
        self.assertIsNone(by_dev["/dev/disk0"]["ts"])
        self.assertEqual(by_dev["/dev/disk1"]["ts"], 5)


class KeepalivePlistGarbagePinTests(_HealthCacheSandbox):
    """Stays-immune pin: a garbage LaunchAgent plist drops alone."""

    def test_expat_garbage_plist_does_not_500(self):
        import tempfile
        d = tempfile.mkdtemp(prefix="health9-plist-")
        (Path(d) / "junk.plist").write_bytes(b"\x00\x01 not a plist <unclosed")
        with mock.patch.object(health_svc, "AGENTS_DIR", d):
            resp = _client().get("/api/health/checks")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _no_surrogates(resp.json())


if __name__ == "__main__":
    unittest.main()
