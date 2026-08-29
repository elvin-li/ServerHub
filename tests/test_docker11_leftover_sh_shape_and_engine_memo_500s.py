"""Eleventh docker-surface leftover-500 sweep: sh() *shape* junk + engine memo.

The live leftovers
==================
docker10 laundered the *rc slot* of the ``sh()`` tuple through ``_rc_int``
at the ``docker_cli.docker()`` funnel, and docker9 routed the listing rank
gates through ``_isa`` — but three seams one step ahead of those launders
still reproduced as raw HTTP 500s over ``create_app()`` +
``TestClient(raise_server_exceptions=False)``:

* the whole-answer *shape* of ``sh()`` went out to a bare
  ``rc, out, err = sh(...)`` unpack inside ``docker()``.  ``hub.util.sh``
  is a boundary this module does not own (tests and tooling patch it — the
  health9 rule), and a leftover riding the shape — a 2-tuple, a 4-tuple,
  ``None``, a scalar, a list/tuple *subclass* whose ``__iter__`` raises, a
  ``__class__``-property bomb — detonated the unpack itself and 500'd
  essentially every docker route at once: GET /api/containers, /api/stacks,
  /api/images, /api/volumes, /api/networks, /api/containers/{name}/inspect,
  /api/docker/df, /api/docker/sizes and the action / exec / prune
  mutations;
* the ``_engine_cache`` memo dict outlives every request, and both slots
  went out raw: a junk ``t`` (a float-subclass ``__rsub__`` bomb, a str)
  detonated the bare ``time.time() - t < TTL`` freshness probe, and a
  ``__bool__``-bomb ``v`` rode out as ``engine_up``'s answer and blew the
  caller's own ``if not engine_up()`` — raw 500s on GET /api/containers and
  GET /api/stacks (the tools twins were saved only by their ``_safe_flag``);
* the ``_engine_timeouts`` module global is the same kind of store, and a
  junk counter (an int-subclass ``__add__`` bomb, a str) detonated the
  ``+= 1`` inside the lock the moment one probe timed out — raw 500s on
  every listing route for the duration of the load storm.

The fixes stay at the ``docker_cli`` funnel: the ``sh()`` answer unwraps
inside a try and a junk shape reads as ``(-255, "", "")`` — the same -255
``_rc_int`` assigns junk rc values, never the ``-1`` timeout / not-found
sentinel, never success — so the routes degrade to their coded answers;
``_cache_view`` reads the memo with ``type(v) is bool`` (bool cannot be
subclassed, so the exact check is complete and a bool-liar reads as "never
probed") and a guarded freshness probe (junk ``t`` reads as stale);
``_timeouts_int`` launders the counter through the unbound base coercion (a
real subclass keeps its value and loses its bombs; junk reads as the
tolerance spent, so a timeout through an uncountable counter reports
engine-down instead of re-serving a stale answer).  ``peek_engine`` answers
through the same view so a memo bomb cannot reach the badge renderers.

The docker10 ``_rc_int`` funnel, docker9 ``_isa`` gates, docker7 cfg guards
and the vanished-CLI disk-confirm contract are untouched; ride-along pins
below keep the already-absorbed wave-11 shapes (isoformat property bombs,
nested unbound jsonable, >4300-digit job scalars) closed.  Product version
stays 3.9.3.
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
    """The reflected operand a float subclass wins: ``time.time() - t``."""

    def __rsub__(self, other):
        raise RuntimeError("rsub bomb")


class LtBombFloat(float):
    def __lt__(self, other):
        raise RuntimeError("lt bomb")

    def __gt__(self, other):
        raise RuntimeError("gt bomb")


class IterBombList(list):
    def __iter__(self):
        raise RuntimeError("iter bomb")


class IterBombTuple(tuple):
    def __iter__(self):
        raise RuntimeError("iter bomb")


class AddBombInt(int):
    def __add__(self, other):
        raise RuntimeError("add bomb")

    def __radd__(self, other):
        raise RuntimeError("radd bomb")


class LtBombInt(int):
    def __lt__(self, other):
        raise RuntimeError("lt bomb")


class IsoBomb:
    """Object whose ``isoformat`` attribute access raises non-AttributeError."""

    @property
    def isoformat(self):
        raise RuntimeError("isoformat bomb")


def _liar(cls, text="liar"):
    """``__class__`` answers *cls* while the real type is a plain object."""

    class Liar:
        __class__ = property(lambda self: cls)

        def __str__(self):
            return text

    return Liar()


#: Whole-answer shapes for ``sh`` that each used to 500 every docker route
#: at the ``rc, out, err = sh(...)`` unpack inside ``docker()``.
SH_SHAPE_ZOO = {
    "two-tuple": lambda: (0, ""),
    "four-tuple": lambda: (0, "", "", ""),
    "none": lambda: None,
    "scalar-int": lambda: 7,
    "iter-bomb-list": lambda: IterBombList([0, "", ""]),
    "iter-bomb-tuple": lambda: IterBombTuple((0, "", "")),
    "class-bomb": lambda: ClassBomb(),
    "bool-liar": lambda: _liar(bool),
}


def _sh_returning(value):
    def fake_sh(cmd, timeout=10, shell=False, env=None):
        return value

    return fake_sh


def _sh_raising(cmd, timeout=10, shell=False, env=None):
    raise RuntimeError("sh itself detonates")


def _ok_sh(cmd, timeout=10, shell=False, env=None):
    return 0, "", ""


def _timeout_sh(cmd, timeout=10, shell=False, env=None):
    return -1, "", "timeout"


def _reset_docker_memos():
    docker_cli.invalidate_engine_state()
    containers_svc.invalidate_container_lists()
    tools_svc.docker_disk_usage.invalidate()


class DockerFunnelShapePins(unittest.TestCase):
    """``docker()`` survives any whole-answer shape ``sh`` hands back."""

    def test_junk_shapes_read_as_dash_255_and_empty_streams(self):
        for name, make in SH_SHAPE_ZOO.items():
            with self.subTest(shape=name):
                with mock.patch.object(docker_cli, "sh",
                                       new=_sh_returning(make())):
                    rc, out, err = docker_cli.docker("info", timeout=5)
                self.assertIs(type(rc), int)
                self.assertEqual(rc, -255)
                self.assertEqual((out, err), ("", ""))

    def test_sh_that_raises_reads_as_dash_255(self):
        with mock.patch.object(docker_cli, "sh", new=_sh_raising):
            rc, out, err = docker_cli.docker("info", timeout=5)
        self.assertEqual((rc, out, err), (-255, "", ""))

    def test_junk_shape_never_reads_as_the_sentinels_or_success(self):
        # -1 is the timeout / not-found sentinel and 0 is success; a junk
        # shape must be neither, or a bombed answer could flip a failure
        # into "engine ok" or into the vanished-CLI classification.
        for name, make in SH_SHAPE_ZOO.items():
            with self.subTest(shape=name):
                with mock.patch.object(docker_cli, "sh",
                                       new=_sh_returning(make())):
                    rc, _, _ = docker_cli.docker("info", timeout=5)
                self.assertNotIn(rc, (0, -1))

    def test_clean_three_tuple_passes_untouched(self):
        def clean_sh(cmd, timeout=10, shell=False, env=None):
            return 3, "out text", "err text"

        with mock.patch.object(docker_cli, "sh", new=clean_sh):
            rc, out, err = docker_cli.docker("ps", timeout=5)
        self.assertEqual((rc, out, err), (3, "out text", "err text"))
        self.assertIs(type(rc), int)

    def test_engine_up_survives_a_junk_shape(self):
        # Before the guarded unwrap this raised out of the unpack inside
        # engine_up's own probe and 500'd every route that consults it.
        for name, make in SH_SHAPE_ZOO.items():
            with self.subTest(shape=name):
                with mock.patch.object(docker_cli, "sh",
                                       new=_sh_returning(make())):
                    docker_cli.invalidate_engine_state()
                    try:
                        self.assertIs(docker_cli.engine_up(force=True), False)
                    finally:
                        docker_cli.invalidate_engine_state()


class EngineMemoViewPins(unittest.TestCase):
    """``_cache_view`` / ``peek_engine``: junk memo slots read as unknown."""

    def setUp(self):
        docker_cli.invalidate_engine_state()
        self.addCleanup(docker_cli.invalidate_engine_state)

    def _plant(self, t, v):
        docker_cli._engine_cache.update(t=t, v=v)

    def test_exact_bool_and_fresh_t_pass_through(self):
        self._plant(time.time() + 10**6, True)
        self.assertEqual(docker_cli._cache_view(), (True, True))
        self._plant(time.time() + 10**6, False)
        self.assertEqual(docker_cli._cache_view(), (False, True))

    def test_stale_t_reads_as_stale(self):
        self._plant(0.0, True)
        self.assertEqual(docker_cli._cache_view(), (True, False))

    def test_junk_v_reads_as_never_probed(self):
        for name, v in (
            ("bool-bomb", BoolBomb()),
            ("class-bomb", ClassBomb()),
            ("bool-liar", _liar(bool)),
            ("int-one", 1),
            ("str-true", "true"),
        ):
            with self.subTest(shape=name):
                self._plant(time.time() + 10**6, v)
                value, _fresh = docker_cli._cache_view()
                self.assertIsNone(value)

    def test_junk_t_reads_as_stale_not_a_raise(self):
        for name, t in (
            ("rsub-bomb", RSubBombFloat(0.0)),
            ("str", "yesterday"),
            ("none", None),
        ):
            with self.subTest(shape=name):
                self._plant(t, True)
                value, fresh = docker_cli._cache_view()
                self.assertIs(value, True)
                self.assertIs(fresh, False)

    def test_lt_bomb_t_is_defused_not_a_raise(self):
        # ``time.time() - t`` runs through ``float.__rsub__`` and answers an
        # exact float, so the subclass ``__lt__`` never gets an operand: the
        # bomb is defused and the value's own freshness answer survives.
        self._plant(LtBombFloat(time.time() + 10**6), True)
        value, fresh = docker_cli._cache_view()
        self.assertIs(value, True)
        self.assertIs(fresh, True)
        self._plant(LtBombFloat(0.0), True)
        value, fresh = docker_cli._cache_view()
        self.assertIs(value, True)
        self.assertIs(fresh, False)

    def test_peek_engine_never_hands_the_bomb_out(self):
        self._plant(time.time() + 10**6, BoolBomb())
        self.assertIsNone(docker_cli.peek_engine())
        self._plant(time.time() + 10**6, True)
        self.assertIs(docker_cli.peek_engine(), True)


class TimeoutCounterPins(unittest.TestCase):
    """``_timeouts_int``: exact through, subclass defused, junk fails closed."""

    def test_exact_ints_pass_through(self):
        for value in (0, 1, 2, 3):
            self.assertEqual(docker_cli._timeouts_int(value), value)
            self.assertIs(type(docker_cli._timeouts_int(value)), int)

    def test_subclass_keeps_its_value_but_loses_its_bombs(self):
        for bomb in (AddBombInt(1), LtBombInt(2)):
            with self.subTest(bomb=type(bomb).__name__):
                out = docker_cli._timeouts_int(bomb)
                self.assertIs(type(out), int)
                self.assertEqual(out, int.__index__(bomb))

    def test_junk_reads_as_the_tolerance_spent(self):
        # Fail closed: junk is not evidence recent probes succeeded, so it
        # must not buy extra re-serves of a possibly-stale "up".
        for name, value in (
            ("str", "three"),
            ("none", None),
            ("bool", True),
            ("bool-liar", _liar(bool)),
            ("int-liar", _liar(int)),
            ("class-bomb", ClassBomb()),
        ):
            with self.subTest(shape=name):
                self.assertEqual(docker_cli._timeouts_int(value),
                                 docker_cli._TIMEOUT_TOLERANCE)

    def test_engine_up_timeout_path_survives_a_junk_counter(self):
        for name, junk in (
            ("add-bomb", AddBombInt(0)),
            ("lt-bomb", LtBombInt(0)),
            ("str", "three"),
        ):
            with self.subTest(shape=name):
                with mock.patch.object(docker_cli, "sh", new=_timeout_sh):
                    docker_cli.invalidate_engine_state()
                    docker_cli._engine_timeouts = junk
                    try:
                        self.assertIs(docker_cli.engine_up(force=True), False)
                    finally:
                        docker_cli.invalidate_engine_state()


class _RouteHarness(unittest.TestCase):
    """Drive the real routes with one leftover planted under the seams."""

    URLS = (
        ("GET", "/api/containers", None),
        ("GET", "/api/stacks", None),
        ("GET", "/api/images", None),
        ("GET", "/api/volumes", None),
        ("GET", "/api/networks", None),
        ("GET", "/api/containers/web/inspect", None),
        ("GET", "/api/docker/info", None),
        ("GET", "/api/docker/df", None),
        ("GET", "/api/docker/sizes", None),
        ("GET", "/api/stacks/jobs/some-job", None),
        ("POST", "/api/containers/web/exec",
         {"command": "echo hi", "shell": "/bin/sh"}),
        ("POST", "/api/containers/web/action", {"action": "stop"}),
        ("POST", "/api/prune", {"kind": "system"}),
    )

    def drive_routes(self, label):
        client = _client()
        for method, url, body in self.URLS:
            r = (client.get(url) if method == "GET"
                 else client.post(url, json=body))
            self.assert_never_raw_500(r, f"{label} {method} {url}")

    def assert_never_raw_500(self, r, label: str):
        # A junk seam legitimately classifies as the coded engine-down 503
        # (the probe cannot answer "up" through junk); anything else at or
        # above 500 is the raw crash this sweep exists to kill.
        if r.status_code >= 500:
            self.assertEqual(r.status_code, 503, f"{label}: raw "
                             f"{r.status_code}: {r.text[:300]}")
            self.assertEqual(
                r.json()["detail"]["code"], "container.engine_down",
                f"{label}: uncoded 503: {r.text[:300]}")
        r.content.decode("utf-8")
        return r


class JunkShShapesRoutesNeverRaw500(_RouteHarness):
    """Every junk ``sh`` shape over every docker route: coded answers only."""

    def _drive(self, sh_impl, label):
        with mock.patch.object(docker_cli, "sh", new=sh_impl):
            _reset_docker_memos()
            try:
                self.drive_routes(label)
            finally:
                _reset_docker_memos()

    def test_junk_shapes_never_raw_500(self):
        for name, make in SH_SHAPE_ZOO.items():
            with self.subTest(shape=name):
                self._drive(_sh_returning(make()), name)

    def test_raising_sh_never_raw_500(self):
        self._drive(_sh_raising, "raising-sh")


class EngineMemoRoutesNeverRaw500(_RouteHarness):
    """Leftovers planted in the engine memo / counter: coded answers only."""

    def _drive_with_cache(self, t, v, label):
        with mock.patch.object(docker_cli, "sh", new=_ok_sh):
            _reset_docker_memos()
            docker_cli._engine_cache.update(t=t, v=v)
            try:
                self.drive_routes(label)
            finally:
                _reset_docker_memos()

    def test_memo_bombs_never_raw_500(self):
        for name, (t, v) in {
            "t-rsub-bomb": (RSubBombFloat(0.0), True),
            "t-lt-bomb": (LtBombFloat(time.time() + 10**6), True),
            "t-str": ("yesterday", True),
            "v-bool-bomb": (time.time() + 10**6, BoolBomb()),
            "v-class-bomb": (time.time() + 10**6, ClassBomb()),
            "v-bool-liar": (time.time() + 10**6, _liar(bool)),
        }.items():
            with self.subTest(shape=name):
                self._drive_with_cache(t, v, name)

    def test_junk_timeout_counter_never_raw_500(self):
        for name, junk in {
            "add-bomb": AddBombInt(0),
            "str": "three",
        }.items():
            with self.subTest(shape=name):
                with mock.patch.object(docker_cli, "sh", new=_timeout_sh):
                    _reset_docker_memos()
                    docker_cli._engine_timeouts = junk
                    try:
                        self.drive_routes(f"timeouts-{name}")
                    finally:
                        _reset_docker_memos()

    def test_clean_rc_zero_still_reads_as_success(self):
        # Sunny-day control: the launder must not tax an honest exit status.
        def clean_sh(cmd, timeout=10, shell=False, env=None):
            return 0, "done", ""

        with mock.patch.object(docker_cli, "sh", new=clean_sh):
            _reset_docker_memos()
            try:
                r = _client().post(
                    "/api/containers/web/exec",
                    json={"command": "echo hi", "shell": "/bin/sh"})
            finally:
                _reset_docker_memos()
        self.assertEqual(r.status_code, 200, r.text[:300])
        body = r.json()
        self.assertIs(body["ok"], True)
        self.assertEqual(body["rc"], 0)
        self.assertEqual(body["output"], "done")


class StaysImmuneRideAlongs(_RouteHarness):
    """Wave-11 hunt shapes already absorbed upstream, pinned so a refactor
    cannot reopen them: isoformat property bombs, nested unbound jsonable,
    >4300-digit scalars and self-``__str__`` encode bombs in a poisoned
    ``_cjobs`` row."""

    class DictGetBomb(dict):
        def get(self, *a, **k):
            raise RuntimeError("get bomb")

        def items(self):
            raise RuntimeError("items bomb")

        def __bool__(self):
            raise RuntimeError("bool bomb")

    class EncodeBombStr(str):
        def __str__(self):
            return self

        def encode(self, *a, **k):
            raise RuntimeError("encode bomb")

    def test_poisoned_job_row_shapes_stay_immune(self):
        rows = {
            "iso-bomb-rc": {"running": False, "rc": IsoBomb(), "log": [],
                            "started": "x", "finished": "y",
                            "stack_id": "s1", "action": "up"},
            "huge-int-rc": {"running": False, "rc": 10 ** 5000, "log": [],
                            "started": "x", "finished": "y",
                            "stack_id": "s1", "action": "up"},
            "nested-dict-bomb-rc": {
                "running": False,
                "rc": self.DictGetBomb({"inner": IsoBomb()}),
                "log": [], "started": "x", "finished": "y",
                "stack_id": "s1", "action": "up"},
            "encode-bomb-log": {
                "running": False, "rc": 0,
                "log": [self.EncodeBombStr("boom")],
                "started": "x", "finished": "y",
                "stack_id": "s1", "action": "up"},
        }
        client = _client()
        with mock.patch.object(docker_cli, "sh", new=_ok_sh):
            for name, row in rows.items():
                with self.subTest(shape=name):
                    _reset_docker_memos()
                    containers_svc._cjobs.clear()
                    containers_svc._cjobs["poisoned-job"] = row
                    try:
                        r = client.get("/api/stacks/jobs/poisoned-job")
                        self.assert_never_raw_500(r, f"{name} job log")
                        self.assertEqual(r.status_code, 200, r.text[:300])
                        r2 = client.get("/api/stacks")
                        self.assert_never_raw_500(r2, f"{name} stacks")
                    finally:
                        containers_svc._cjobs.clear()
                        _reset_docker_memos()

    def test_vanished_cli_stays_503_only_after_disk_confirm(self):
        # The sentinel alone is any FileNotFoundError spawn; with the binary
        # still on disk the mutation must keep its raw failure mapping.
        def vanished_sh(cmd, timeout=10, shell=False, env=None):
            return -1, "", "not found"

        client = _client()
        with mock.patch.object(docker_cli, "sh", new=vanished_sh):
            _reset_docker_memos()
            try:
                with mock.patch.object(docker_cli.Path, "exists",
                                       return_value=False):
                    r = client.post("/api/containers/web/action",
                                    json={"action": "stop"})
                self.assertEqual(r.status_code, 503, r.text[:300])
                self.assertEqual(r.json()["detail"]["code"],
                                 "container.engine_down")
                _reset_docker_memos()
                with mock.patch.object(docker_cli.Path, "exists",
                                       return_value=True):
                    r2 = client.post("/api/containers/web/action",
                                     json={"action": "stop"})
                # CLI still on disk: the sentinel is a vanished cwd, not a
                # vanished docker — no engine-down 503, the raw failure keeps
                # its ok:false shape.
                self.assertEqual(r2.status_code, 200, r2.text[:300])
                self.assertIs(r2.json()["ok"], False)
            finally:
                _reset_docker_memos()


if __name__ == "__main__":
    unittest.main()
