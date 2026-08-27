"""Eighth leftover-500s sweep of the Health / SMART / ping surfaces, over the real app.

health7 sealed the encode-side and epoch-side subclass bombs on
GET /api/health/checks and the SMART routes.  Re-running the same zoo against
the *ping* surfaces and the worker-liveness registry surfaced live leftovers:

* ``wireguard_svc.ping_peers`` clamped its deadline with
  ``int(timeout_ms or 800)`` behind the arithmetic trio only — an int/float
  subclass whose ``__bool__``/``__int__`` raises blew the clamp for
  in-process callers (the smart_test_svc._schedule_epoch class, on the ping
  surface).
* ``ping_peers`` walked ``peer_records()`` raw.  The walk does not own the
  provider (tests and tooling patch it): a non-dict row TypeError'd
  ``record["ip"]``, a row without ``ip`` KeyError'd, an already-int ``ip``
  AttributeError'd ``.split``, and a list-subclass ``__iter__`` bomb raised
  out of the loop header — each a raw 500 on POST /api/wireguard/ping where
  every blank-ip peer already drops silently.
* A vanished ``/sbin/ping`` answered POST /api/wireguard/ping with 200 and
  every peer "unreachable" — blaming healthy tunnels for a missing host tool,
  the same lie POST /api/tools/net/ping and the failover tick already upgrade
  to a coded 503.  Now ``wg.ping_missing`` (503), on the ``sh`` spawn-sentinel
  failure path only and only after a fresh disk probe confirms the binary is
  gone; a present-but-failing ping keeps its honest unreachable rows.
* ``tools_svc._clamp_int`` ran ``int(raw)`` behind the arithmetic trio — an
  int-subclass ``__int__`` bomb raised out of POST /api/tools/net/ping's
  service for in-process callers.
* ``cli_args._normalise`` called the *bound* ``value.strip(" \\t")`` — a
  str-subclass ``.strip`` bomb detonated the very predicate
  (``is_safe_hostname`` / ``is_safe_positional``) that exists to refuse junk,
  and ``net_ping``'s own ``host.strip()`` repeated the call after the guard.
* ``worker_health`` probed entries with ``float(...)`` / ``raw or 0`` /
  ``str(name)`` behind narrow excepts — an interval/beat/name subclass bomb
  raised out of register() on the worker's own thread, out of
  ``loop_interval`` on the scheduler start path, and out of ``snapshot()`` /
  ``problems()``, silently wiping the workers row from GET /api/health/checks
  (the health7 wipe class, one field over).
"""
from __future__ import annotations

import json
import sys
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import cli_args, tools_svc, wireguard_svc, worker_health  # noqa: E402

INSTALL = {
    "installed": True, "conf_exists": True, "conf_path": "", "conf_dir": "",
    "wg": "wg", "wg_quick": "wg-quick", "wireguard_go": "",
    "tools_version": "v1", "userspace_version": "", "probe_failed": False,
}

#: sh()'s exact FileNotFoundError sentinel for a vanished binary.
_VANISHED = (-1, "", "not found")


def _no_surrogates(payload) -> None:
    """What Starlette's JSONResponse does to the body (allow_nan=False)."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _BoolBombInt(int):
    def __bool__(self):
        raise RuntimeError("bool bomb")


class _IntBombInt(int):
    def __int__(self):
        raise RuntimeError("int bomb")


class _BoolBombFloat(float):
    def __bool__(self):
        raise RuntimeError("bool bomb")

    def __float__(self):
        raise RuntimeError("float bomb")


class _FloatBombFloat(float):
    def __float__(self):
        raise RuntimeError("float bomb")


class _StripBombStr(str):
    def strip(self, *args):
        raise RuntimeError("strip bomb")


class _StrBombName:
    def __str__(self):
        raise RuntimeError("str bomb")


class _IterBombList(list):
    def __iter__(self):
        raise RuntimeError("iter bomb")


class _GetBombDict(dict):
    def get(self, *args):
        raise RuntimeError("get bomb")


class _MountedWgRouteTests(unittest.TestCase):
    """Real app, auth overridden, admin guard and installation patched."""

    def setUp(self):
        from fastapi.testclient import TestClient

        from hub.app_factory import create_app
        from hub.auth import require_auth
        from hub.routers import wireguard_api

        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        app = create_app()
        app.dependency_overrides[require_auth] = lambda: True
        self.addCleanup(app.dependency_overrides.clear)
        # raise_server_exceptions=False: a real 500 must arrive as HTTP 500,
        # not as a re-raised exception that would mask which route crashed.
        self.client = TestClient(app, raise_server_exceptions=False)
        self.stack.enter_context(mock.patch.object(
            wireguard_api, "require_admin_browser", lambda request: "admin"
        ))
        self.stack.enter_context(mock.patch.object(
            wireguard_svc, "installation", lambda: dict(INSTALL)
        ))


class PingDeadlineBombTests(unittest.TestCase):
    """timeout_ms subclass bombs: the coded clamp answers, never a raise."""

    def test_bomb_timeouts_do_not_raise(self):
        # ``int(timeout_ms or 800)`` behind the arithmetic trio: these bombs
        # raise RuntimeError and used to escape ping_peers for in-process
        # callers.
        with mock.patch.object(wireguard_svc, "peer_records", return_value=[]):
            for bomb in (_BoolBombInt(800), _IntBombInt(800), _BoolBombFloat(800.0)):
                out = wireguard_svc.ping_peers(bomb)
                self.assertTrue(out["ok"])
                self.assertEqual(out["results"], [])

    def test_bomb_timeout_value_is_salvaged_not_defaulted(self):
        # int.__index__ coercion: the real number survives, only the bomb dies.
        self.assertEqual(wireguard_svc._ping_deadline(_BoolBombInt(1234)), 1234)
        self.assertEqual(wireguard_svc._ping_deadline(_IntBombInt(300)), 300)
        # The junk answers pinned by earlier sweeps keep their default.
        for junk in ("nope", float("inf"), [800], True, None):
            self.assertEqual(wireguard_svc._ping_deadline(junk), 800)


class PingPoisonedRecordTests(_MountedWgRouteTests):
    """Junk peer rows drop alone: POST /api/wireguard/ping stays 200."""

    CLEAN = {"public_key": "pk-clean", "name": "phone", "ip": "10.10.0.2/32"}

    def _ping_with(self, records):
        with (
            mock.patch.object(
                wireguard_svc, "peer_records", return_value=records),
            mock.patch.object(
                wireguard_svc, "sh",
                lambda cmd, timeout=10, **k: (0, "64 bytes: time=1.2 ms", "")),
        ):
            return self.client.post("/api/wireguard/ping")

    def test_non_dict_record_drops_alone(self):
        resp = self._ping_with([42, self.CLEAN])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _no_surrogates(body)
        self.assertEqual([r["name"] for r in body["results"]], ["phone"])

    def test_record_without_ip_drops_alone(self):
        resp = self._ping_with([{"public_key": "pk-junk", "name": "n"}, self.CLEAN])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual([r["ip"] for r in resp.json()["results"]], ["10.10.0.2"])

    def test_already_int_ip_behaves_as_its_string_form(self):
        # The raid_svc._req_text convention: a finite numeric keeps behaving
        # as its text form rather than AttributeError'ing ``.split``.
        resp = self._ping_with([{"public_key": "pk", "name": "n", "ip": 123}])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["results"][0]["ip"], "123")

    def test_iter_bomb_records_list_salvages_the_entries(self):
        # list.__iter__ unbound: the real rows still walk.
        resp = self._ping_with(_IterBombList([self.CLEAN]))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual([r["name"] for r in resp.json()["results"]], ["phone"])

    def test_get_bomb_dict_record_drops_alone(self):
        # Unbound ``dict.get``: the subclass's own ``.get`` never runs.
        bomb = _GetBombDict(public_key="pk-bomb", name="b", ip="10.10.0.3/32")
        resp = self._ping_with([bomb, self.CLEAN])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(
            [r["name"] for r in resp.json()["results"]], ["b", "phone"])


class PingVanishedCliTests(_MountedWgRouteTests):
    """Confirmed-vanished /sbin/ping is the coded 503, never an unreachable lie."""

    CLEAN = [{"public_key": "pk", "name": "phone", "ip": "10.10.0.2/32"}]

    def _ping(self, sh_answer, gone: bool):
        with (
            mock.patch.object(
                wireguard_svc, "peer_records", return_value=list(self.CLEAN)),
            mock.patch.object(
                wireguard_svc, "sh", lambda cmd, timeout=10, **k: sh_answer),
            mock.patch.object(
                wireguard_svc, "_ping_cli_gone", return_value=gone),
        ):
            return self.client.post("/api/wireguard/ping")

    def test_sentinel_plus_disk_confirm_is_503(self):
        resp = self._ping(_VANISHED, gone=True)
        self.assertEqual(resp.status_code, 503, resp.text[:300])
        self.assertEqual(resp.json()["detail"]["code"], "wg.ping_missing")

    def test_sentinel_but_binary_on_disk_keeps_honest_rows(self):
        # A patched/odd sh whose output merely reads "not found" while the
        # binary is still present must not become the tool-absent 503.
        resp = self._ping(_VANISHED, gone=False)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertFalse(body["results"][0]["reachable"])
        self.assertEqual(body["reachable"], 0)

    def test_real_ping_failure_never_pays_the_disk_probe(self):
        # A present-but-failing ping (host actually down) keeps its honest
        # unreachable row even when the stat would read gone.
        resp = self._ping((2, "", "Request timeout"), gone=True)
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertFalse(resp.json()["results"][0]["reachable"])

    def test_cli_gone_stat_errors_read_as_present(self):
        # EIO/ESTALE on a dying mount must not upgrade a failure to the 503.
        with mock.patch.object(
            Path, "is_file", side_effect=OSError(5, "I/O error")
        ):
            self.assertFalse(wireguard_svc._ping_cli_gone())


class NetPingBombTests(unittest.TestCase):
    """count / host subclass bombs: coded answers, never raises."""

    def test_count_int_bomb_is_salvaged_not_500(self):
        with mock.patch.object(tools_svc, "_sh", return_value=(0, "ok", "")):
            out = tools_svc.net_ping("example.com", _IntBombInt(7))
        # int.__index__ coercion: the real count survives the bomb.
        self.assertEqual(out["count"], 7)
        json.dumps(out, allow_nan=False)

    def test_count_bool_bomb_keeps_the_default(self):
        with mock.patch.object(tools_svc, "_sh", return_value=(0, "ok", "")):
            out = tools_svc.net_ping("example.com", _BoolBombInt(3))
        self.assertEqual(out["count"], 3)

    def test_strip_bomb_host_still_pings(self):
        # The bound ``.strip`` bomb used to detonate is_safe_hostname itself.
        with mock.patch.object(tools_svc, "_sh", return_value=(0, "ok", "")):
            out = tools_svc.net_ping(_StripBombStr("example.com"), 1)
        self.assertTrue(out["ok"])
        self.assertEqual(out["host"], "example.com")
        # The argv host is the exact base str, not the bomb subclass.
        self.assertIs(type(out["host"]), str)


class CliArgsStripBombTests(unittest.TestCase):
    """The argv-safety predicates absorb the very junk they exist to refuse."""

    def test_predicates_survive_a_strip_bomb(self):
        self.assertTrue(cli_args.is_safe_hostname(_StripBombStr("example.com")))
        self.assertTrue(cli_args.is_safe_positional(_StripBombStr("disk0")))
        self.assertFalse(cli_args.is_safe_hostname(_StripBombStr("-fbomb")))

    def test_normalise_answers_the_exact_base_str(self):
        text = cli_args._normalise(_StripBombStr("  host  "))
        self.assertEqual(text, "host")
        self.assertIs(type(text), str)


class WorkerHealthBombTests(unittest.TestCase):
    """Interval / beat / name bombs cost one field, never the registry."""

    def _clean(self, name):
        self.addCleanup(worker_health.unregister, name)

    def test_register_interval_bomb_does_not_raise(self):
        # float(interval) behind the arithmetic trio used to re-raise the
        # bomb on the worker's own thread — killing the loop this registry
        # exists to watch.
        worker_health.register("h8-interval", _FloatBombFloat(60.0))
        self._clean("h8-interval")
        rows = {w["name"]: w for w in worker_health.snapshot()}
        self.assertEqual(rows["h8-interval"]["interval"], 60.0)

    def test_snapshot_survives_a_planted_beat_bomb(self):
        worker_health.register("h8-beat", 60)
        self._clean("h8-beat")
        worker_health._workers["h8-beat"]["beat"] = _BoolBombFloat(1.0)
        rows = {w["name"]: w for w in worker_health.snapshot()}
        # The bomb reads as never-beaten: alive but stale, never a raise.
        self.assertIn("h8-beat", rows)
        self.assertTrue(rows["h8-beat"]["stale"])
        _no_surrogates(list(rows.values()))

    def test_health_page_workers_row_survives_the_beat_bomb(self):
        # Pre-fix, snapshot() raised and _worker_checks silently wiped the
        # workers row from GET /api/health/checks — the exact dead-worker
        # blindness this registry exists to prevent.
        from fastapi.testclient import TestClient

        from hub import health_svc
        from hub.app_factory import create_app
        from hub.auth import require_auth

        app = create_app()
        app.dependency_overrides[require_auth] = lambda: None
        self.addCleanup(app.dependency_overrides.clear)
        saved = dict(health_svc._cache)
        self.addCleanup(lambda: health_svc._cache.update(saved))
        health_svc._cache.update(t=0.0, v=None)

        worker_health.register("h8-page", 60)
        self._clean("h8-page")
        worker_health._workers["h8-page"]["beat"] = _BoolBombFloat(1.0)
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/api/health/checks")
        self.assertEqual(response.status_code, 200, response.text[:300])
        checks = {c["id"]: c for c in response.json()["checks"]
                  if isinstance(c, dict) and "id" in c}
        self.assertIn("workers", checks)

    def test_loop_interval_bombs_are_salvaged_not_raised(self):
        # int.__index__ / float.__float__ coercion: the real number survives
        # the bomb and clamps as any plain value would.
        self.assertEqual(worker_health.loop_interval(_IntBombInt(900), 900), 900)
        self.assertEqual(worker_health.loop_interval(_BoolBombFloat(120.0), 90), 120)

    def test_str_bomb_name_registers_and_unregisters_deterministically(self):
        name = _StrBombName()
        worker_health.register(name, 60)
        rows = [w["name"] for w in worker_health.snapshot()]
        self.assertIn("_StrBombName", rows)
        worker_health.beat(name)  # keys must agree — no raise, no orphan
        worker_health.unregister(name)
        self.assertNotIn(
            "_StrBombName", [w["name"] for w in worker_health.snapshot()])

    def test_problems_survives_bomb_rows(self):
        # An iter-bomb rows list answers empty rather than raising out of
        # the loop header (pre-fix it wiped the workers row).
        self.assertEqual(worker_health.problems(rows=_IterBombList([])), [])
        # Unbound ``dict.get``: a get-bomb row is *salvaged*, not dropped.
        dead = {"name": "ok-row", "alive": False}
        out = worker_health.problems(
            rows=[_GetBombDict(name="bomb", alive=False), dead])
        self.assertEqual(out, ["bomb: thread died", "ok-row: thread died"])
        # A field-level ``__bool__`` bomb drops its own row alone; the
        # sibling's dead-thread report survives.
        out = worker_health.problems(
            rows=[{"name": "boom", "alive": True, "stale": _BoolBombInt(1)}, dead])
        self.assertEqual(out, ["ok-row: thread died"])


if __name__ == "__main__":
    unittest.main()
