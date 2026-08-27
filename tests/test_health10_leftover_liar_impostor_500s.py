"""Tenth leftover-500s sweep of the Health / worker / ping surfaces.

health9 sealed the ``__class__``-property *raising* bombs and the
rc-``__eq__`` bombs on these surfaces.  Re-running the zoo with the
docker10 / json9 *lying*-``__class__`` impostor surfaced live leftovers:
``isinstance`` (and therefore every ``_isa`` gate) answers True when
``value.__class__`` is a *property that returns a claimed type* while the
real object is a plain ``object`` — so the value passes the type gate and
then detonates the *unbound base method* the gate was protecting, because
that C-level descriptor checks the real type and refuses the impostor:

* a bytes-/bytearray-liar peer ``ip`` / ``name`` / ``public_key`` passed
  ``wireguard_svc._as_text``'s ``_isa(value, bytes)`` gate and made
  ``bytes.decode(value, …)`` raise ``TypeError`` — a raw 500 on POST
  /api/wireguard/ping, past ``_ping_targets``'s own gates;
* a str-liar in the same positions rode the ``_isa(value, str)`` branch as
  *text* and made the trailing unbound ``str.encode(text, …)`` raise the
  same way;
* a list-liar ``peer_records`` (or ``problems(rows=…)``) passed the
  ``_isa(records, list)`` gate and made ``list.__iter__(records)`` raise —
  a raw 500 on POST /api/wireguard/ping and, in the worker registry, the
  same silent wipe of the workers row;
* a bytes-liar worker-name key made ``worker_health._utf8_text`` raise out
  of ``snapshot()`` and silently wiped the workers row from GET
  /api/health/checks — the health9 immune pin, reopened by the impostor;
* ``health_svc._decode_bytes`` raised on the same impostor for any caller
  that reaches it outside ``_jsonable``'s per-pair guard.

The fix keeps the unbound-base-method convention (a genuine subclass whose
bound ``.decode`` / ``.encode`` / ``__iter__`` is a bomb still matches
through the C-level type check and is laundered) but runs the descriptor
inside a ``try``: a liar that the descriptor refuses falls through to the
generic guarded ``str()`` / pull-loop path, dropping to its own text
instead of 500ing the route.

Conflict policy is pinned, not re-claimed: ``ping_peers`` /
``_ping_deadline`` / ``_ping_targets`` keep their shapes, the health8/9
``wg.ping_missing`` 503 (disk-confirm only) still fires, and ``_isa``
stays.  Product version stays 3.9.3.
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


def _liar(cls, text="liar"):
    """A lying ``__class__`` impostor: ``isinstance`` answers *cls*, the real
    object is a plain ``object`` that only knows how to ``str()`` itself.

    This is the docker10 / json9 shape.  Unlike ``_ClassBomb`` (whose
    ``__class__`` *raises*), the liar passes every ``_isa`` gate and only
    detonates the unbound base method the gate was guarding.
    """

    class Liar:
        __class__ = property(lambda self: cls)

        def __str__(self):
            return text

    return Liar()


class _ClassBomb:
    """A leftover that cannot answer what it is: ``isinstance`` itself raises.

    Kept alongside the liars so the two shapes are pinned together and a
    refactor cannot fix one while reopening the other.
    """

    @property
    def __class__(self):
        raise RuntimeError("class bomb")


# --------------------------------------------------------------------------
# WireGuard ping surface
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


class PingLiarImpostorTests(_MountedWgRouteTests):
    """Lying ``__class__`` impostors on the ping surface: 200, never 500."""

    def test_bytes_liar_ip_does_not_500(self):
        # _as_text's _isa(value, bytes) gate said True; bytes.decode(liar)
        # raised TypeError past _ping_targets and 500'd the route.
        rec = dict(self.CLEAN, ip=_liar(bytes))
        resp = self._ping_with([rec])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _no_surrogates(resp.json())

    def test_bytearray_liar_ip_does_not_500(self):
        rec = dict(self.CLEAN, ip=_liar(bytearray))
        resp = self._ping_with([rec])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _no_surrogates(resp.json())

    def test_bytes_liar_name_and_pubkey_render_coded(self):
        rec = dict(self.CLEAN, name=_liar(bytes), public_key=_liar(bytes))
        resp = self._ping_with([rec])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        # The row survives with its host resolved from the clean ``ip``.
        self.assertEqual([r["ip"] for r in body["results"]], ["10.10.0.2"])

    def test_str_liar_ip_resolves_to_its_host(self):
        # The str-liar rode the _isa(value, str) branch as text; the trailing
        # unbound str.encode(text) raised. Now it renders its honest __str__.
        rec = dict(self.CLEAN, ip=_liar(str, "10.10.0.9/32"))
        resp = self._ping_with([rec])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        self.assertEqual([r["ip"] for r in body["results"]], ["10.10.0.9"])

    def test_list_liar_records_object_answers_empty(self):
        # peer_records() itself is a list-liar: _ping_targets' _isa gate said
        # True and list.__iter__(liar) raised TypeError past every guard.
        resp = self._ping_with(_liar(list))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["results"], [])

    def test_bytes_liar_row_drops_alone_sibling_survives(self):
        # A whole row that is not a dict but claims to be one via a lying
        # __class__ still drops at the _isa(record, dict) gate; a bytes-liar
        # *field* on an honest row must not take the sibling down with it.
        rec = dict(self.CLEAN, ip=_liar(bytes))
        resp = self._ping_with([rec, dict(self.CLEAN, name="keep")])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        names = [r["name"] for r in resp.json()["results"]]
        self.assertIn("keep", names)


class PingConflictPolicyPins(_MountedWgRouteTests):
    """Do not weaken the health-leftover pins the sweep must preserve."""

    def test_ping_deadline_class_bomb_stays_immune(self):
        self.assertEqual(wireguard_svc._ping_deadline(_ClassBomb()), 800)

    def test_ping_deadline_default_unchanged(self):
        self.assertEqual(wireguard_svc._ping_deadline(800), 800)
        self.assertEqual(wireguard_svc._ping_deadline(None), 800)

    def test_vanished_cli_503_still_fires_after_disk_confirm(self):
        resp = self._ping_with([dict(self.CLEAN)], sh_answer=_VANISHED, gone=True)
        self.assertEqual(resp.status_code, 503, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "wg.ping_missing")

    def test_sentinel_without_disk_confirm_keeps_honest_rows(self):
        resp = self._ping_with([dict(self.CLEAN)], sh_answer=_VANISHED, gone=False)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertFalse(resp.json()["results"][0]["reachable"])

    def test_class_bomb_row_still_drops_alone(self):
        # The health9 raising-__class__ pin: a row that cannot answer what it
        # is drops at the _isa gate, its clean sibling renders.
        resp = self._ping_with([_ClassBomb(), dict(self.CLEAN)])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual([r["name"] for r in resp.json()["results"]], ["phone"])


# --------------------------------------------------------------------------
# Worker registry
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


class WorkerRegistryLiarTests(_WorkerRegistrySandbox):
    """Registry impostors cost only their own entry, never the workers row."""

    def test_snapshot_survives_bytes_liar_name_key(self):
        # _utf8_text's bytes branch made bytes.decode(liar) raise out of
        # snapshot() and silently wiped the workers row.
        worker_health._workers[_liar(bytes)] = dict(self.CLEAN)
        worker_health._workers["ok"] = dict(self.CLEAN)
        rows = worker_health.snapshot()
        self.assertEqual(len(rows), 2)
        _no_surrogates(rows)

    def test_snapshot_survives_str_liar_name_key(self):
        worker_health._workers[_liar(str, "srv")] = dict(self.CLEAN)
        rows = worker_health.snapshot()
        self.assertEqual(len(rows), 1)
        _no_surrogates(rows)

    def test_problems_list_liar_rows_answers_empty(self):
        # list.__iter__(liar) raised out of problems() when a caller handed
        # a lying list; now it falls to the guarded pull loop.
        self.assertEqual(worker_health.problems(rows=_liar(list)), [])

    def test_problems_still_reports_dead_worker(self):
        dead = {"name": "w", "alive": False, "stale": False}
        self.assertEqual(worker_health.problems(rows=[dead]), ["w: thread died"])

    def test_health_workers_row_survives_bytes_liar_name(self):
        saved = dict(health_svc._cache)
        self.addCleanup(lambda: health_svc._cache.update(saved))
        health_svc._cache.update(t=0.0, v=None)
        worker_health._workers["real"] = dict(self.CLEAN)
        worker_health._workers[_liar(bytes)] = dict(self.CLEAN)
        resp = _client().get("/api/health/checks")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        ids = [c.get("id") for c in body["checks"] if isinstance(c, dict)]
        # Pre-fix snapshot() raised and this row silently vanished.
        self.assertIn("workers", ids)


# --------------------------------------------------------------------------
# Health cache / launder unit pins
# --------------------------------------------------------------------------
class _HealthCacheSandbox(unittest.TestCase):
    """Save/restore the module cache so poisonings cannot leak between tests."""

    def setUp(self):
        saved = dict(health_svc._cache)
        self.addCleanup(lambda: health_svc._cache.update(saved))
        health_svc._cache.update(t=0.0, v=None)

    _CLEAN_SNAPSHOT = {
        "ts": "now",
        "summary": {"ok": 1, "warn": 0, "error": 0, "total": 1},
        "checks": [{"id": "x", "name": "X", "level": "ok", "ok": True,
                    "detail": "", "fix": ""}],
        "healthy": True,
    }


class HealthCacheLiarTests(_HealthCacheSandbox):
    """Bytes-liars planted in the cache: 200, never 500; siblings survive."""

    def _ttl_hit_with(self, junk):
        bad = dict(self._CLEAN_SNAPSHOT)
        bad["junk"] = junk
        health_svc._cache.update(t=time.time(), v=bad)
        return _client().get("/api/health/checks")

    def test_nested_bytes_liar_value_drops_siblings_survive(self):
        resp = self._ttl_hit_with(_liar(bytes))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        self.assertEqual(body["checks"][0]["id"], "x")

    def test_nested_bytes_liar_dict_key_drops_pair_alone(self):
        resp = self._ttl_hit_with({_liar(bytes): 1, "keep": 2})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        self.assertEqual(body["junk"].get("keep"), 2)


class LaunderUnitPins(unittest.TestCase):
    """Every launderer absorbs the liar instead of the descriptor raising."""

    def test_wg_as_text_absorbs_bytes_liar(self):
        self.assertEqual(wireguard_svc._as_text(_liar(bytes, "b")), "b")

    def test_wg_as_text_absorbs_bytearray_liar(self):
        self.assertEqual(wireguard_svc._as_text(_liar(bytearray, "ba")), "ba")

    def test_wg_as_text_absorbs_str_liar(self):
        self.assertEqual(wireguard_svc._as_text(_liar(str, "s")), "s")

    def test_wg_as_text_real_bytes_still_decode(self):
        self.assertEqual(wireguard_svc._as_text(b"real"), "real")

    def test_health_decode_bytes_absorbs_liar(self):
        self.assertEqual(health_svc._decode_bytes(_liar(bytes, "hb")), "hb")

    def test_health_as_text_absorbs_bytes_liar(self):
        self.assertEqual(health_svc._as_text(_liar(bytes, "hx")), "hx")

    def test_health_jsonable_bytes_liar_renders_text(self):
        self.assertEqual(health_svc._jsonable(_liar(bytes, "jb")), "jb")

    def test_worker_utf8_text_absorbs_bytes_liar(self):
        self.assertEqual(worker_health._utf8_text(_liar(bytes, "wb")), "wb")

    def test_real_bytes_and_bytearray_still_decode_everywhere(self):
        self.assertEqual(health_svc._decode_bytes(bytearray(b"r")), "r")
        self.assertEqual(worker_health._utf8_text(b"r"), "r")


if __name__ == "__main__":
    unittest.main()
