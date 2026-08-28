"""Twelfth docker-surface leftover-500 sweep: the listing / stats / df memos.

The live leftovers
==================
docker11 sealed the ``sh()`` answer *shape* and the ``_engine_cache`` memo —
but three more module-lifetime stores feeding the docker listing / inspect /
df JSON routes still read out raw, and each one reproduced as a raw HTTP 500
over ``create_app()`` + ``TestClient(raise_server_exceptions=False)``:

* ``containers_svc._container_list_cached``'s ``ttl_memo`` cache dict
  outlives every request, and its hit went out to a bare
  ``flag, rows = …`` unpack plus per-row ``dict(x)`` copies: a junk stamp
  (a str, a float-subclass ``__rsub__`` bomb) detonated the wrapper's own
  ``now - hit[0]`` freshness probe, a non-tuple hit detonated ``hit[0]``
  itself, a 2-tuple whose value slot is ``None``/a scalar detonated the
  unpack, a ``__bool__``-bomb flag blew ``if not engine_up_flag``, a
  ``__class__``-property-bomb row blew the ``dict(x)`` copy, and a row
  missing ``raw_state`` KeyError'd the projects fold — raw 500s on
  GET /api/containers and GET /api/stacks until the TTL lapsed;
* ``containers_svc._stats_cached`` is the same kind of store one seam
  deeper: a junk hit detonated the bare ``dict(_stats_cached())`` copy in
  ``list_containers`` and the ``i["id"]`` subscript inside the stats
  refresh — the same raw 500s;
* ``tools_svc.docker_disk_usage``'s memo hit was returned *verbatim* by
  GET /api/docker/df: a junk stamp / non-tuple hit raised in the wrapper,
  a ``__class__``-property-bomb value detonated Starlette's encoder, and a
  bare scalar value went out as the whole response body — the wrong shape
  entirely, engine flag and all.

The fixes stay at the consumer funnels: ``_cached_list_view`` /
``_cached_stats_view`` (containers_svc) and the ``docker_disk_usage``
launder over ``_docker_df_cached`` (tools_svc) read each memo inside a try,
validate the answer's exact shape (``type(pair) is tuple``,
``type(flag) is bool`` — the docker11 ``_cache_view`` convention), re-found
rows through ``_plain_job`` + ``_jsonable``, evict junk once
(``invalidate`` never compares keys, the health11 rule) and re-probe; junk
that survives eviction reads as engine-unknown / no-stats / engine-down —
the same coded answers as a stopped engine, never a raw 500 and never the
``-1`` timeout / not-found sentinel.

The docker11 sh-shape funnel and engine-memo view, the docker10 ``_rc_int``
funnel, docker9 ``_isa`` gates and the vanished-CLI disk-confirm contract
are untouched; ride-along pins below keep the mocked-memo contract older
suites rely on (exact ``(True, [row])`` tuples pass through unchanged).
Product version stays 3.9.3.
"""
from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from fastapi.testclient import TestClient  # noqa: E402

from hub import containers_svc, docker_cli, tools_svc  # noqa: E402
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


class ClassBomb:
    """Leftover whose ``__class__`` is a raising property."""

    @property
    def __class__(self):
        raise RuntimeError("class bomb")


class BoolBomb:
    def __bool__(self):
        raise RuntimeError("bool bomb")


class RSubBombFloat(float):
    """The reflected operand a float subclass wins: ``now - stamp``."""

    def __rsub__(self, other):
        raise RuntimeError("rsub bomb")


class GetItemBombTuple(tuple):
    def __getitem__(self, item):
        raise RuntimeError("getitem bomb")


class IterBombList(list):
    def __iter__(self):
        raise RuntimeError("iter bomb")


class DictGetBomb(dict):
    def get(self, *a, **k):
        raise RuntimeError("get bomb")

    def items(self):
        raise RuntimeError("items bomb")

    def __bool__(self):
        raise RuntimeError("bool bomb")


class KeyBomb:
    """Hash-shadows the zero-arg memo key ``()``; comparing it raises."""

    def __hash__(self):
        return hash(())

    def __eq__(self, other):
        raise RuntimeError("eq bomb")


def _liar(cls, text="liar"):
    """``__class__`` answers *cls* while the real type is a plain object."""

    class Liar:
        __class__ = property(lambda self: cls)

        def __str__(self):
            return text

    return Liar()


def _ok_sh(cmd, timeout=10, shell=False, env=None):
    return 0, "", ""


def _raising_sh(cmd, timeout=10, shell=False, env=None):
    raise RuntimeError("sh detonates")


def _reset_docker_memos():
    docker_cli.invalidate_engine_state()
    containers_svc.invalidate_container_lists()
    tools_svc.docker_disk_usage.invalidate()


def _plant(memo, entry) -> None:
    """Plant *entry* as the memo's zero-arg cache hit."""
    memo._cache[()] = entry


_NOW = time.time
_ROW = {
    "id": "web", "name": "web", "raw_name": "web", "raw_state": "running",
    "state": "ok", "project": "site", "image": "nginx:latest",
}

#: Cache-entry shapes that each used to 500 the listing / df routes raw.
MEMO_ENTRY_ZOO = {
    "hit-scalar": lambda: 5,
    "hit-none-value": lambda: (_NOW(), None),
    "hit-scalar-value": lambda: (_NOW(), 7),
    "hit-three-slot": lambda: (_NOW(), (True, []), "extra"),
    "stamp-str": lambda: ("yesterday", (True, [dict(_ROW)])),
    "stamp-rsub-bomb": lambda: (RSubBombFloat(0.0), (True, [dict(_ROW)])),
    "hit-getitem-bomb": lambda: GetItemBombTuple((_NOW(), (True, []))),
    "hit-class-bomb": lambda: ClassBomb(),
}

#: Pair shapes for the listing memo's *value* slot specifically.
LIST_VALUE_ZOO = {
    "flag-bool-bomb": lambda: (BoolBomb(), []),
    "flag-bool-liar": lambda: (_liar(bool), []),
    "flag-int-one": lambda: (1, []),
    "rows-scalar": lambda: (True, 7),
    "rows-iter-bomb": lambda: (True, IterBombList([dict(_ROW)])),
    "row-class-bomb": lambda: (True, [ClassBomb()]),
    "row-missing-columns": lambda: (True, [{"id": "x"}]),
    "row-bool-liar": lambda: (True, [_liar(bool)]),
}


class ListingPairPins(unittest.TestCase):
    """``_listing_pair``: exact answers pass, junk reads as None."""

    def test_exact_pair_passes_with_refounded_rows(self):
        pair = containers_svc._listing_pair((True, [dict(_ROW)]))
        self.assertIsNotNone(pair)
        flag, rows = pair
        self.assertIs(flag, True)
        self.assertEqual(rows, [_ROW])
        # Re-founded, not shared: a caller edit cannot reach the source row.
        self.assertIsNot(rows[0], _ROW)

    def test_engine_down_pair_passes(self):
        self.assertEqual(containers_svc._listing_pair((False, [])), (False, []))

    def test_junk_pairs_read_as_none(self):
        for name, make in {
            "none": lambda: None,
            "scalar": lambda: 5,
            "three-slot": lambda: (True, [], "extra"),
            "getitem-bomb-tuple": lambda: GetItemBombTuple((True, [])),
            "flag-bool-bomb": lambda: (BoolBomb(), []),
            "flag-bool-liar": lambda: (_liar(bool), []),
            "flag-int": lambda: (1, []),
        }.items():
            with self.subTest(shape=name):
                self.assertIsNone(containers_svc._listing_pair(make()))

    def test_junk_rows_degrade_without_taking_the_pair(self):
        flag, rows = containers_svc._listing_pair(
            (True, [ClassBomb(), dict(_ROW), _liar(dict)]))
        self.assertIs(flag, True)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], "web")

    def test_dict_subclass_row_keeps_its_data_but_loses_its_bombs(self):
        flag, rows = containers_svc._listing_pair(
            (True, [DictGetBomb(dict(_ROW))]))
        self.assertIs(flag, True)
        self.assertEqual(rows[0]["id"], "web")
        self.assertIs(type(rows[0]), dict)

    def test_iter_bomb_rows_read_as_junk_pair(self):
        self.assertIsNone(
            containers_svc._listing_pair((True, IterBombList([dict(_ROW)]))))


class CachedViewEvictionPins(unittest.TestCase):
    """A planted memo entry is evicted and the probe re-runs once."""

    def setUp(self):
        _reset_docker_memos()
        self.addCleanup(_reset_docker_memos)

    def test_list_view_heals_through_eviction(self):
        for name, make in {**MEMO_ENTRY_ZOO, **LIST_VALUE_ZOO}.items():
            entries = (
                make() if name in MEMO_ENTRY_ZOO else (_NOW(), make())
            )
            with self.subTest(shape=name):
                with mock.patch.object(docker_cli, "sh", new=_ok_sh):
                    _reset_docker_memos()
                    _plant(containers_svc._container_list_cached, entries)
                    flag, rows = containers_svc._cached_list_view()
                # Healthy sh: eviction + one re-probe answers the real
                # engine state, so junk costs nothing visible.  The
                # row-shaped values are legitimate pairs and pass directly.
                self.assertIs(type(flag), bool)
                self.assertIs(type(rows), list)

    def test_list_view_junk_that_survives_reads_engine_unknown(self):
        # sh raising: the re-probe cannot answer either, so the view
        # degrades to the coded engine-down listing — never a raise, never
        # the -1 sentinel shape.
        with mock.patch.object(docker_cli, "sh", new=_raising_sh):
            _plant(containers_svc._container_list_cached, (_NOW(), None))
            self.assertEqual(containers_svc._cached_list_view(), (False, []))

    def test_poisoned_key_is_evicted_not_a_raise(self):
        # A hash-shadowing key detonates inside the memo's own cache.get;
        # invalidate() never compares keys, so eviction always lands.
        with mock.patch.object(docker_cli, "sh", new=_ok_sh):
            containers_svc._container_list_cached._cache[KeyBomb()] = (
                _NOW(), (True, []))
            flag, rows = containers_svc._cached_list_view()
        self.assertIs(type(flag), bool)
        self.assertEqual(rows, [])

    def test_clean_hit_is_served_without_a_probe(self):
        # Sunny-day control: a legit cached answer must not be taxed with
        # eviction or a re-probe.
        def forbidden_sh(cmd, timeout=10, shell=False, env=None):
            raise AssertionError("clean hit must not re-probe")

        _plant(containers_svc._container_list_cached,
               (_NOW(), (True, [dict(_ROW)])))
        with mock.patch.object(docker_cli, "sh", new=forbidden_sh):
            flag, rows = containers_svc._cached_list_view()
        self.assertIs(flag, True)
        self.assertEqual(rows[0]["id"], "web")

    def test_stats_view_heals_and_degrades(self):
        with mock.patch.object(docker_cli, "sh", new=_ok_sh):
            _plant(containers_svc._stats_cached, (_NOW(), 7))
            self.assertEqual(containers_svc._cached_stats_view(), {})
        _reset_docker_memos()
        _plant(containers_svc._stats_cached,
               (_NOW(), {"web": {"cpu": "1%", "mem": "10MiB"}}))
        stats = containers_svc._cached_stats_view()
        self.assertEqual(stats["web"]["cpu"], "1%")


class DfPayloadPins(unittest.TestCase):
    """``_df_payload`` / ``docker_disk_usage``: junk never leaves the funnel."""

    def setUp(self):
        _reset_docker_memos()
        self.addCleanup(_reset_docker_memos)

    def test_exact_payload_passes(self):
        payload = {"engine_up": True, "raw": "x", "lines": [{"type": "Images"}]}
        cleaned = tools_svc._df_payload(payload)
        self.assertEqual(cleaned, payload)
        self.assertIsNot(cleaned, payload)

    def test_junk_payloads_read_as_none(self):
        for name, value in {
            "scalar": 7,
            "none": None,
            "list": [],
            "class-bomb": ClassBomb(),
            "dict-liar": _liar(dict),
            "flag-missing": {"raw": "", "lines": []},
            "flag-int": {"engine_up": 1, "raw": "", "lines": []},
            "flag-bool-bomb": {"engine_up": BoolBomb(), "raw": "", "lines": []},
        }.items():
            with self.subTest(shape=name):
                self.assertIsNone(tools_svc._df_payload(value))

    def test_dict_subclass_payload_is_refounded(self):
        cleaned = tools_svc._df_payload(
            DictGetBomb({"engine_up": False, "raw": "", "lines": []}))
        self.assertIs(type(cleaned), dict)
        self.assertIs(cleaned["engine_up"], False)

    def test_df_heals_through_eviction(self):
        def df_sh(cmd, timeout=10, shell=False, env=None):
            return 0, "Images  3  2  1.2GB  300MB (25%)", ""

        for name, make in MEMO_ENTRY_ZOO.items():
            with self.subTest(shape=name):
                with mock.patch.object(docker_cli, "sh", new=df_sh):
                    _reset_docker_memos()
                    _plant(tools_svc._docker_df_cached, make())
                    payload = tools_svc.docker_disk_usage()
                self.assertIs(type(payload), dict)
                self.assertIs(type(payload.get("engine_up")), bool)

    def test_df_junk_that_survives_reads_engine_down(self):
        with mock.patch.object(docker_cli, "sh", new=_raising_sh):
            _plant(tools_svc._docker_df_cached, (_NOW(), ClassBomb()))
            payload = tools_svc.docker_disk_usage()
        self.assertEqual(payload, {"engine_up": False, "raw": "", "lines": []})

    def test_scalar_value_never_escapes_as_the_response_shape(self):
        # Before the launder GET /api/docker/df answered a bare ``7`` (HTTP
        # 200, wrong shape entirely) for a planted scalar hit.
        with mock.patch.object(docker_cli, "sh", new=_raising_sh):
            _plant(tools_svc._docker_df_cached, (_NOW(), 7))
            payload = tools_svc.docker_disk_usage()
        self.assertIs(type(payload), dict)
        self.assertIs(type(payload["engine_up"]), bool)

    def test_public_invalidate_still_drops_the_memo(self):
        _plant(tools_svc._docker_df_cached,
               (_NOW(), {"engine_up": True, "raw": "x", "lines": []}))
        tools_svc.docker_disk_usage.invalidate()
        self.assertEqual(tools_svc._docker_df_cached._cache, {})


class _RouteHarness(unittest.TestCase):
    """Drive the real routes with one leftover planted in a memo store."""

    URLS = (
        ("GET", "/api/containers", None),
        ("GET", "/api/containers?stats=true", None),
        ("GET", "/api/stacks", None),
        ("GET", "/api/images", None),
        ("GET", "/api/volumes", None),
        ("GET", "/api/networks", None),
        ("GET", "/api/containers/web/inspect", None),
        ("GET", "/api/docker/info", None),
        ("GET", "/api/docker/df", None),
        ("GET", "/api/docker/sizes", None),
        ("POST", "/api/containers/all", {"action": "stop"}),
    )

    def drive_routes(self, label):
        client = _client()
        for method, url, body in self.URLS:
            r = (client.get(url) if method == "GET"
                 else client.post(url, json=body))
            self.assert_never_raw_500(r, f"{label} {method} {url}")

    def assert_never_raw_500(self, r, label: str):
        # A junk memo legitimately classifies as the coded engine-down 503;
        # anything else at or above 500 is the raw crash this sweep kills.
        if r.status_code >= 500:
            self.assertEqual(r.status_code, 503, f"{label}: raw "
                             f"{r.status_code}: {r.text[:300]}")
            self.assertEqual(
                r.json()["detail"]["code"], "container.engine_down",
                f"{label}: uncoded 503: {r.text[:300]}")
        r.content.decode("utf-8")
        return r


class MemoStorePlantsRoutesNeverRaw500(_RouteHarness):
    """Every planted memo shape over every docker route: coded answers only."""

    def _drive(self, memo, entry, label, sh_impl=_ok_sh):
        with mock.patch.object(docker_cli, "sh", new=sh_impl):
            _reset_docker_memos()
            _plant(memo, entry)
            try:
                self.drive_routes(label)
            finally:
                _reset_docker_memos()

    def test_listing_memo_plants_never_raw_500(self):
        for name, make in MEMO_ENTRY_ZOO.items():
            with self.subTest(shape=name):
                self._drive(containers_svc._container_list_cached, make(),
                            f"list-{name}")

    def test_listing_value_plants_never_raw_500(self):
        for name, make in LIST_VALUE_ZOO.items():
            with self.subTest(shape=name):
                self._drive(containers_svc._container_list_cached,
                            (_NOW(), make()), f"list-value-{name}")

    def test_stats_memo_plants_never_raw_500(self):
        for name, make in MEMO_ENTRY_ZOO.items():
            with self.subTest(shape=name):
                self._drive(containers_svc._stats_cached, make(),
                            f"stats-{name}")

    def test_df_memo_plants_never_raw_500(self):
        for name, make in MEMO_ENTRY_ZOO.items():
            with self.subTest(shape=name):
                self._drive(tools_svc._docker_df_cached, make(),
                            f"df-{name}")

    def test_plants_with_a_raising_sh_never_raw_500(self):
        # Both seams at once: junk in the store AND a probe that cannot
        # answer.  The routes must still degrade to their coded answers.
        for memo, label in (
            (containers_svc._container_list_cached, "list"),
            (containers_svc._stats_cached, "stats"),
            (tools_svc._docker_df_cached, "df"),
        ):
            with self.subTest(seam=label):
                self._drive(memo, (_NOW(), ClassBomb()),
                            f"{label}-raising-sh", sh_impl=_raising_sh)

    def test_poisoned_memo_key_never_raw_500(self):
        with mock.patch.object(docker_cli, "sh", new=_ok_sh):
            _reset_docker_memos()
            containers_svc._container_list_cached._cache[KeyBomb()] = (
                _NOW(), (True, []))
            tools_svc._docker_df_cached._cache[KeyBomb()] = (
                _NOW(), {"engine_up": True, "raw": "", "lines": []})
            try:
                self.drive_routes("key-bomb")
            finally:
                _reset_docker_memos()


class StaysImmuneRideAlongs(_RouteHarness):
    """Contracts older suites rely on, pinned so a refactor cannot break
    them: exact mocked pairs pass through, clean df output still parses,
    and a poisoned row costs itself rather than the listing."""

    def setUp(self):
        _reset_docker_memos()
        self.addCleanup(_reset_docker_memos)

    def test_mocked_exact_pair_contract_survives(self):
        # Suites patch _container_list_cached with return_value=(True,[row])
        # — the launder must keep serving those rows verbatim.
        with (
            mock.patch.object(containers_svc, "_container_list_cached",
                              return_value=(True, [dict(_ROW)])),
            mock.patch.object(containers_svc, "_stats_cached",
                              return_value={"web": {"cpu": "2%"}}),
        ):
            payload = containers_svc.list_containers()
        self.assertIs(payload["engine_up"], True)
        self.assertEqual(payload["containers"][0]["id"], "web")
        self.assertEqual(payload["stats"]["web"]["cpu"], "2%")
        self.assertEqual(payload["projects"],
                         [{"name": "site", "count": 1, "running": 1}])

    def test_clean_df_round_trip_still_parses(self):
        def df_sh(cmd, timeout=10, shell=False, env=None):
            return 0, ("TYPE  TOTAL  ACTIVE  SIZE  RECLAIMABLE\n"
                       "Images  3  2  1.2GB  300MB (25%)"), ""

        with mock.patch.object(docker_cli, "sh", new=df_sh):
            r = _client().get("/api/docker/df")
        self.assertEqual(r.status_code, 200, r.text[:300])
        body = r.json()
        self.assertIs(body["engine_up"], True)
        self.assertEqual(body["lines"][0]["type"], "Images")
        self.assertEqual(body["lines"][0]["total"], "3")

    def test_poisoned_row_costs_itself_not_the_listing(self):
        with mock.patch.object(docker_cli, "sh", new=_ok_sh):
            _plant(containers_svc._container_list_cached,
                   (_NOW(), (True, [dict(_ROW), ClassBomb()])))
            r = _client().get("/api/containers?stats=false")
        self.assert_never_raw_500(r, "poisoned sibling row")
        self.assertEqual(r.status_code, 200, r.text[:300])
        ids = [c.get("id") for c in r.json()["containers"]]
        self.assertEqual(ids, ["web"])

    def test_stacks_listing_survives_a_listing_plant(self):
        with mock.patch.object(docker_cli, "sh", new=_ok_sh):
            _plant(containers_svc._container_list_cached, (_NOW(), None))
            r = _client().get("/api/stacks")
        self.assert_never_raw_500(r, "stacks after plant")
        self.assertEqual(r.status_code, 200, r.text[:300])
        body = r.json()
        self.assertIsInstance(body["stacks"], list)
        self.assertIsInstance(body["jobs"], list)

    def test_prune_still_reports_fresh_df_through_the_funnel(self):
        def sh_ok_df(cmd, timeout=10, shell=False, env=None):
            if "df" in cmd:
                return 0, "Images  1  1  10MB  0B (0%)", ""
            return 0, "pruned", ""

        with mock.patch.object(docker_cli, "sh", new=sh_ok_df):
            _reset_docker_memos()
            out = tools_svc.docker_prune(what="dangling", confirm=True)
        self.assertIs(out["ok"], True)
        self.assertIs(type(out["df"]), dict)
        self.assertIs(out["df"]["engine_up"], True)


if __name__ == "__main__":
    unittest.main()
