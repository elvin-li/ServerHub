"""Host9 leftover sweep: __class__-property / impostor / rc / t-slot bombs in
the host identity and _json_tree sanitizers, over the real mounted app.

host8 sealed the ``isoformat`` / ``__bytes__`` bombs in ``_json_tree`` /
``_json_atom``; dash9 hardened ``host_address``'s own gates with ``_isa`` /
``_rc_int`` / guarded truthiness.  Re-running the dash9 bomb zoo against the
*siblings* of those seams found a fresh family of live raw 500s:

* **``system_settings_svc``'s json-tree family still ran bare gates.**  Every
  rank check in ``_json_tree`` / ``_json_atom`` / ``_utf8_text`` / ``_as_text``
  was a bare ``isinstance``, which consults ``value.__class__`` when the
  exact-type check misses — so a leftover whose ``__class__`` is a *raising
  property* detonated the first gate itself, as a value and as a mapping key,
  and 500'd the scheduler trio (GET /api/scheduler, /api/system/scheduler,
  /api/settings/scheduler).  A *lying* ``__class__`` (claims bytes, is not)
  passed the gate and TypeError'd the unguarded unbound ``base.decode`` in
  both the value arm and the key arm.  A dict-subclass ``items()`` answering
  torn pairs ValueError'd the ``for k, v`` unpack outside its try.

* **``identity_svc`` trusted its config and rc reads.**  A ``__class__``-
  property bomb stored as the server comment blew ``_as_text``'s bytes gate;
  ``cfg()`` raising, a config root that cannot answer ``isinstance``, and an
  rc-subclass ``__eq__`` bomb from a patched/odd ``sh`` each 500'd
  GET /api/identity on its bare ``root = cfg()`` / ``rc == 0`` reads.

* **``system_extra._host_snapshot`` kept four bare probes.**  Its ``_as_text``
  used the *bound* ``value.decode`` (a bytes-subclass decode bomb raised out
  of the scrub) and a bare bytes gate; ``_mem_gb`` / ``_ncpu_int`` and the
  hostname/model reads ran bare ``rc != 0`` / ``rc == 0`` (RuntimeError past
  the typed catches); and ``bool(peek_engine())`` was evaluated *eagerly* as
  the fallback argument, so a ``__bool__`` bomb planted in the engine cache
  500'd GET /api/system/host even when the probe future succeeded.

* **``host_address._cached_detection`` trusted the ``t`` slot.**  The catch
  around ``float(_detect_cache["t"])`` was the typed numeric trio, so a
  leftover stamp whose ``__float__`` raises RuntimeError escaped it and 500'd
  every host_ip() consumer — the same cache whose ``value`` slot dash9
  already absorbs.

Fixes follow the dash9 / nas8 convention: ``_isa`` (isinstance inside try) on
every rank gate, try-wrapped unbound base calls for lying impostors,
``_rc_int`` for the rc probes, guarded truthiness for the ``__bool__`` bombs,
a blanket catch on the cache-stamp read, and per-entry drops that keep every
sane sibling.

Stays-immune pins ride along: the huge-int drop in ``_json_tree``, the
torn-IPv6 ``urlsplit`` catch in ``normalize_local_url``, identity's already
unbound bytes decode, the list-subclass ``__iter__`` drop, and
``resolve_value``'s deliberate raise-on-junk contract.
"""
from __future__ import annotations

import json
import time
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import docker_cli, host_address, identity_svc, system_settings_svc, tools_svc
from hub.auth import require_auth
from hub.routers import system_extra, unraid_parity

_APP = None


def _client() -> TestClient:
    global _APP
    if _APP is None:
        from hub.app_factory import create_app

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: None
    # raise_server_exceptions=False: a real 500 must arrive as HTTP 500, not
    # as a re-raised exception that would mask which route crashed.
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _ClassBomb:
    """A leftover that cannot answer what it is: ``isinstance`` itself raises."""

    @property
    def __class__(self):
        raise RuntimeError("class bomb")


class _LyingBytes:
    """Claims to be bytes; is not — the unbound ``bytes.decode`` TypeErrors."""

    @property
    def __class__(self):
        return bytes


class _BoolBomb:
    """A leftover whose truthiness probe raises."""

    def __bool__(self):
        raise RuntimeError("bool bomb")


class _FloatBomb:
    """A cache stamp whose ``__float__`` raises — not the typed numeric trio."""

    def __float__(self):
        raise RuntimeError("float bomb")


class _EqBombInt(int):
    """An rc whose comparison raises — ``rc == 0`` / ``rc != 0`` detonate."""

    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    def __ne__(self, other):
        raise RuntimeError("ne bomb")

    __hash__ = int.__hash__


class _DecodeBombBytes(bytes):
    """Real bytes whose *bound* ``.decode`` is a bomb; the base bytes are sane."""

    def decode(self, *a, **k):
        raise RuntimeError("decode bomb")


class _TornItemsDict(dict):
    """A dict subclass whose ``items()`` answers torn (three-tuple) pairs."""

    def items(self):
        return [("torn", 1, 2)]


class _IterBombList(list):
    """A list subclass whose ``__iter__`` raises (host8 sealed this arm)."""

    def __iter__(self):
        raise RuntimeError("iter bomb")


class _HttpPin(unittest.TestCase):
    def setUp(self):
        self.client = _client()

    def _ok_body(self, resp) -> dict:
        self.assertEqual(resp.status_code, 200, resp.text[:400])
        body = resp.json()
        _starlette(body)
        return body


# ---------------------------------------------------------------------------
# _json_tree family: the scheduler trio over poisoned timer rows
# ---------------------------------------------------------------------------


class _SchedulerTrioPin(_HttpPin):
    """Drive all three scheduler views over one leftover timers answer.

    /api/scheduler holds its own import-time reference to launchd_timers,
    so both the tools_svc attribute and the router's copy are patched.
    """

    def _bodies(self, timers) -> dict[str, dict]:
        with (
            mock.patch.object(tools_svc, "launchd_timers", return_value=timers),
            mock.patch.object(
                unraid_parity, "launchd_timers", return_value=timers,
            ),
        ):
            return {
                path: self._ok_body(self.client.get(path))
                for path in (
                    "/api/scheduler",
                    "/api/system/scheduler",
                    "/api/settings/scheduler",
                )
            }


class JsonTreeClassBombHttpTests(_SchedulerTrioPin):
    """The ex-500s: a ``__class__``-property bomb anywhere in the tree."""

    def test_class_bomb_value_keeps_the_row_and_its_siblings(self):
        bodies = self._bodies([
            {"label": "com.example.job", "interval_sec": 60,
             "program": _ClassBomb()},
        ])
        for path in ("/api/scheduler", "/api/system/scheduler"):
            row = bodies[path]["timers"][0]
            # The bomb costs only its own field: it renders as junk text.
            self.assertIsInstance(row["program"], str)
            self.assertEqual(row["label"], "com.example.job")

    def test_class_bomb_mapping_key_keeps_the_sibling_entries(self):
        bodies = self._bodies([
            {"label": "com.example.job", "interval_sec": 60,
             "calendar": {_ClassBomb(): 1, "Minute": 5}},
        ])
        for path in ("/api/scheduler", "/api/system/scheduler",
                     "/api/settings/scheduler"):
            calendar = bodies[path]["timers"][0]["calendar"]
            self.assertEqual(calendar["Minute"], 5)
            # The bombed key renders through str() and keeps its value.
            self.assertIn(1, calendar.values())


class JsonTreeLyingImpostorHttpTests(_SchedulerTrioPin):
    """The ex-500s: lying ``__class__`` bytes impostors, values and keys."""

    def test_lying_bytes_value_drops_and_the_label_survives(self):
        bodies = self._bodies([
            {"label": "com.example.job", "interval_sec": 60,
             "program": _LyingBytes()},
        ])
        for path in ("/api/scheduler", "/api/system/scheduler"):
            row = bodies[path]["timers"][0]
            self.assertIsNone(row["program"])
            self.assertEqual(row["label"], "com.example.job")

    def test_lying_bytes_key_drops_and_its_siblings_survive(self):
        bodies = self._bodies([
            {"label": "com.example.job", "interval_sec": 60,
             "calendar": {_LyingBytes(): 1, "Minute": 5}},
        ])
        for path in ("/api/scheduler", "/api/system/scheduler",
                     "/api/settings/scheduler"):
            self.assertEqual(
                bodies[path]["timers"][0]["calendar"], {"Minute": 5},
            )


class JsonTreeTornItemsHttpTests(_SchedulerTrioPin):
    """The ex-500: a dict-subclass ``items()`` answering torn pairs."""

    def test_torn_items_drop_per_entry_not_the_route(self):
        bodies = self._bodies([
            {"label": "com.example.job", "interval_sec": 60,
             "calendar": _TornItemsDict()},
        ])
        for path in ("/api/scheduler", "/api/system/scheduler"):
            row = bodies[path]["timers"][0]
            self.assertEqual(row["calendar"], {})
            self.assertEqual(row["label"], "com.example.job")


class JsonTreeSanitizerUnitPins(unittest.TestCase):
    """Direct pins so the diagnostics/bundle riders of _json_tree hold too."""

    def test_json_tree_class_bomb_value_renders_as_text(self):
        self.assertIsInstance(system_settings_svc._json_tree(_ClassBomb()), str)

    def test_json_tree_class_bomb_key_keeps_siblings(self):
        out = system_settings_svc._json_tree({_ClassBomb(): 1, "y": 2})
        self.assertEqual(out["y"], 2)
        self.assertIn(1, out.values())

    def test_json_tree_lying_bytes_value_and_key_drop(self):
        self.assertIsNone(system_settings_svc._json_tree(_LyingBytes()))
        self.assertEqual(
            system_settings_svc._json_tree({_LyingBytes(): 1, "y": 2}),
            {"y": 2},
        )

    def test_json_tree_torn_items_drop_per_entry(self):
        self.assertEqual(system_settings_svc._json_tree(_TornItemsDict()), {})

    def test_json_atom_class_bomb_and_lying_bytes(self):
        self.assertIsInstance(system_settings_svc._json_atom(_ClassBomb()), str)
        self.assertIsNone(system_settings_svc._json_atom(_LyingBytes()))

    def test_text_scrubbers_absorb_both_bomb_shapes(self):
        self.assertIsInstance(system_settings_svc._utf8_text(_ClassBomb()), str)
        self.assertIsInstance(system_settings_svc._utf8_text(_LyingBytes()), str)
        self.assertIsInstance(system_settings_svc._as_text(_ClassBomb()), str)
        self.assertIsInstance(system_settings_svc._as_text(_LyingBytes()), str)


# ---------------------------------------------------------------------------
# GET /api/identity: config / rc bombs under get_identity
# ---------------------------------------------------------------------------


class IdentityRouteBombTests(_HttpPin):
    """The ex-500s on GET /api/identity."""

    def _get_identity(self) -> dict:
        return self._ok_body(self.client.get("/api/identity"))

    def test_class_bomb_comment_renders_as_junk_text(self):
        with mock.patch.object(
            identity_svc, "cfg",
            return_value={"settings": {"server_comment": _ClassBomb()}},
        ):
            body = self._get_identity()
        # The bomb costs only its own field; the identity siblings survive.
        self.assertIsInstance(body["comment"], str)
        self.assertIsInstance(body["hostname"], str)

    def test_cfg_raising_degrades_to_an_empty_settings_read(self):
        def boom():
            raise RuntimeError("cfg bomb")

        with mock.patch.object(identity_svc, "cfg", boom):
            body = self._get_identity()
        self.assertEqual(body["comment"], "")

    def test_class_bomb_config_root_degrades_the_same_way(self):
        bomb = _ClassBomb()
        with mock.patch.object(identity_svc, "cfg", lambda: bomb):
            body = self._get_identity()
        self.assertEqual(body["comment"], "")

    def test_rc_eq_bomb_from_a_patched_sh_keeps_the_route(self):
        with mock.patch.object(
            identity_svc, "sh", return_value=(_EqBombInt(0), "boxname", ""),
        ):
            body = self._get_identity()
        # _rc_int salvages the honest zero, so the sh answer is kept.
        self.assertEqual(body["hostname"], "boxname")

    def test_identity_as_text_absorbs_both_bomb_shapes(self):
        self.assertIsInstance(identity_svc._as_text(_ClassBomb()), str)
        self.assertIsInstance(identity_svc._as_text(_LyingBytes()), str)


# ---------------------------------------------------------------------------
# GET /api/system/host: sh / engine-cache / detect-cache bombs
# ---------------------------------------------------------------------------


class HostRouteBombTests(_HttpPin):
    """The ex-500s on GET /api/system/host."""

    def _get_host(self) -> dict:
        return self._ok_body(self.client.get("/api/system/host?force=true"))

    def test_rc_eq_bomb_from_a_patched_sh_keeps_the_route(self):
        with mock.patch.object(
            system_extra, "sh", return_value=(_EqBombInt(0), "boxname", ""),
        ):
            body = self._get_host()
        self.assertEqual(body["hostname"], "boxname")

    def test_bound_decode_bomb_in_sh_output_salvages_the_bytes(self):
        with mock.patch.object(
            system_extra, "sh",
            return_value=(0, _DecodeBombBytes(b"boxname"), ""),
        ):
            body = self._get_host()
        # The unbound base decode salvages the real C-level bytes.
        self.assertEqual(body["hostname"], "boxname")

    def test_bool_bomb_in_the_engine_cache_reads_as_down(self):
        saved = dict(docker_cli._engine_cache)
        self.addCleanup(lambda: docker_cli._engine_cache.update(saved))
        docker_cli._engine_cache.update(t=time.time(), v=_BoolBomb())
        body = self._get_host()
        self.assertIs(body["orbstack"], False)

    def test_float_bomb_stamp_in_the_detect_cache_reads_as_a_miss(self):
        saved = dict(host_address._detect_cache)
        self.addCleanup(host_address.invalidate_routing)
        self.addCleanup(lambda: host_address._detect_cache.update(saved))
        host_address._detect_cache.update(t=_FloatBomb(), value="10.0.0.5")
        with mock.patch.object(
            host_address, "configured_host", return_value="auto",
        ):
            body = self._get_host()
        # An unreadable stamp is a miss: the address is re-detected.
        self.assertIsInstance(body["host_ip"], str)

    def test_host_route_scrub_and_probe_units(self):
        self.assertIsInstance(system_extra._as_text(_ClassBomb()), str)
        self.assertIsInstance(system_extra._as_text(_LyingBytes()), str)
        self.assertEqual(
            system_extra._as_text(_DecodeBombBytes(b"ok")), "ok",
        )
        # _rc_int salvages the honest zero underneath both probes.
        self.assertEqual(system_extra._mem_gb(_EqBombInt(0), str(2**30)), 1.0)
        self.assertEqual(system_extra._ncpu_int(_EqBombInt(0), "8"), 8)

    def test_cached_detection_float_bomb_stamp_unit(self):
        saved = dict(host_address._detect_cache)
        self.addCleanup(host_address.invalidate_routing)
        self.addCleanup(lambda: host_address._detect_cache.update(saved))
        host_address._detect_cache.update(t=_FloatBomb(), value="10.0.0.5")
        self.assertEqual(host_address._cached_detection(time.time()), "")


# ---------------------------------------------------------------------------
# Stays-immune pins: vectors the sweep re-probed and found already sealed
# ---------------------------------------------------------------------------


class StaysImmunePins(unittest.TestCase):
    """Already-immune vectors, pinned so a refactor cannot regress them."""

    def test_json_tree_huge_int_still_drops(self):
        # CPython's int->str digit cap: json.dumps of a >4300-digit int is
        # ValueError.  _json_tree already drops it (the host8 arm) — pinned
        # against the json.loads/dumps huge-number class.
        self.assertIsNone(system_settings_svc._json_tree(10 ** 5000))
        _starlette(system_settings_svc._json_tree({"n": 10 ** 5000}))

    def test_json_tree_iter_bomb_list_still_drops_to_null(self):
        self.assertIsNone(system_settings_svc._json_tree(_IterBombList([1])))

    def test_torn_ipv6_url_stays_unsplit_not_raised(self):
        # ``urlsplit``/``.port`` ValueError a torn bracket and an absurd
        # port; the existing catch keeps the raw URL for both shapes.
        for raw in ("http://[::1:8080/x", "http://[::1]:99999999999/x"):
            self.assertEqual(host_address.normalize_local_url(raw), raw)

    def test_identity_bound_decode_bomb_already_salvaged(self):
        # identity_svc._as_text moved to the unbound base decode in brew6;
        # pinned so the host9 restructure keeps salvaging the real bytes.
        self.assertEqual(identity_svc._as_text(_DecodeBombBytes(b"ok")), "ok")

    def test_resolve_value_still_raises_a_nested_class_bomb(self):
        # Deliberate contract (bookmarks5 / docker9): callers wrap the walk
        # and treat a raise as "the value is junk" — host9 must not launder
        # the bomb through.
        with self.assertRaises(RuntimeError):
            host_address.resolve_value({"u": "x", "junk": _ClassBomb()})


if __name__ == "__main__":
    unittest.main()
