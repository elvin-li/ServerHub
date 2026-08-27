"""Tenth docker-surface leftover-500 sweep: junk ``rc`` shapes from ``sh``.

The live leftovers
==================
docker9 routed every *listing* rank gate through the guarded ``_isa`` and
wrapped the unbound base copies, and ``docker_cli.docker()`` has always
scrubbed the two text streams of the ``sh()`` tuple through ``_as_text`` —
but the *rc* slot went out raw to every consumer.  ``hub.util.sh`` is a
boundary this module does not own (tests and tooling patch it — the
health9 / hub.host_address._rc_int rule), so one leftover rc shape — the
catalog11 / json9 impostor class riding the third channel — reproduced as
raw HTTP 500s over ``create_app()`` + ``TestClient(
raise_server_exceptions=False)``:

* an int-subclass rc whose ``__eq__``/``__ne__`` raises detonated the bare
  ``rc == -1`` probe inside ``engine_up`` and 500'd essentially every
  docker route at once: GET /api/containers, /api/stacks, /api/images,
  /api/volumes, /api/networks, GET /api/containers/{name}/inspect and the
  action / exec / restart-policy / prune mutations;
* a lying-``__class__`` impostor (claims bool / int / str, is none of
  them) and a raising ``__class__`` property rode ``exec_in_container``'s
  raw ``"rc": rc`` echo into the response encoder — the bool/int liar is
  unserializable (bool is final; the encoder trusts the claim, ``dumps``
  does not) and the class bomb detonates the encoder's own isinstance rank
  gates — a raw 500 on POST /api/containers/{name}/exec;
* a >4300-digit int rc passed every gate untouched and ValueError'd
  ``str()`` past CPython's digit cap — ``container_action``'s
  ``f"exit {rc}"`` 500'd POST /api/containers/{name}/action, and the
  encoder 500'd the exec echo the same way.

The fix is the host_address._rc_int convention applied at the one funnel,
``docker_cli.docker()``: the rc is laundered to an *exact* int through the
unbound base coercion (a real subclass keeps its value, an ``__index__`` /
``__eq__`` bomb cannot fire, a lying impostor TypeErrors and drops) with a
digit-cap probe, and junk reads as ``-255`` — no honest exit status, and
distinct from the ``-1`` timeout / not-found sentinel, so junk can never
be misread as a timeout, a vanished CLI, or success.  A junk rc therefore
degrades to the coded ``container.engine_down`` classification (the forced
probe cannot answer "up" through a junk rc), never a raw 500.  The docker7
cfg guards, docker9 ``_isa`` gates and ``_job_scalar``/``_log_text``
fail-closed funnels are untouched.

Stays-immune pins ride along: the docker9 liar coverage stopped at
str/bytes impostors in cfg rows and job fields; the bool / int / float /
dict / list liar shapes in the same positions were already absorbed by the
``_isa`` + unbound-copy convention and are pinned here so a refactor
cannot reopen them.  Product version stays 3.9.3.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from fastapi.testclient import TestClient  # noqa: E402

from hub import config, containers_svc, docker_cli  # noqa: E402
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


def _liar(cls, text="liar"):
    """``__class__`` answers *cls* while the real type is a plain object."""

    class Liar:
        __class__ = property(lambda self: cls)

        def __str__(self):
            return text

    return Liar()


class IntEqBomb(int):
    """A real int whose comparison operators raise — the ``rc != 0`` killer."""

    def __eq__(self, other):
        raise RuntimeError("rc eq bomb")

    def __ne__(self, other):
        raise RuntimeError("rc ne bomb")

    __hash__ = int.__hash__


class IntIndexBomb(int):
    def __index__(self):
        raise RuntimeError("rc index bomb")


#: rc shapes that each used to 500 at least one docker route.
RC_ZOO = {
    "class-bomb": lambda: ClassBomb(),
    "bool-liar": lambda: _liar(bool),
    "int-liar": lambda: _liar(int),
    "str-liar": lambda: _liar(str),
    "huge-int": lambda: 10 ** 5000,
    "none": lambda: None,
}


def _sh_with_rc(rc):
    def fake_sh(cmd, timeout=10, shell=False, env=None):
        return rc, "", ""

    return fake_sh


class RcIntUnitPins(unittest.TestCase):
    """``_rc_int``: exact status through, junk reads as -255, never -1/0."""

    def test_exact_ints_pass_through_untouched(self):
        for value in (0, 1, -1, 124, 137, -255):
            self.assertEqual(docker_cli._rc_int(value), value)
            self.assertIs(type(docker_cli._rc_int(value)), int)

    def test_real_bools_coerce_to_ints(self):
        self.assertEqual(docker_cli._rc_int(True), 1)
        self.assertEqual(docker_cli._rc_int(False), 0)
        self.assertIs(type(docker_cli._rc_int(True)), int)

    def test_subclass_launders_to_exact_int_and_defuses_the_bombs(self):
        # The value survives; the bound __eq__/__index__ bombs cannot fire
        # in any later ``rc != 0`` probe because the unbound base coercion
        # reads the C-level value and the result is exact.
        for bomb in (IntEqBomb(3), IntIndexBomb(3)):
            with self.subTest(bomb=type(bomb).__name__):
                out = docker_cli._rc_int(bomb)
                self.assertIs(type(out), int)
                self.assertEqual(out, 3)

    def test_junk_shapes_read_as_dash_255(self):
        for name, make in RC_ZOO.items():
            with self.subTest(shape=name):
                out = docker_cli._rc_int(make())
                self.assertIs(type(out), int)
                self.assertEqual(out, -255)

    def test_junk_never_reads_as_the_sentinels_or_success(self):
        # -1 is the timeout / not-found sentinel and 0 is success; junk must
        # be neither, or a bombed rc could flip a failure into "engine ok".
        for name, make in RC_ZOO.items():
            with self.subTest(shape=name):
                self.assertNotIn(docker_cli._rc_int(make()), (0, -1))


class DockerFunnelRcPins(unittest.TestCase):
    """``docker()`` hands back an exact-int rc no matter what ``sh`` says."""

    def test_every_junk_rc_shape_launders_at_the_funnel(self):
        for name, make in RC_ZOO.items():
            with self.subTest(shape=name):
                with mock.patch.object(docker_cli, "sh", new=_sh_with_rc(make())):
                    rc, out, err = docker_cli.docker("info", timeout=5)
                self.assertIs(type(rc), int)
                self.assertEqual(rc, -255)
                self.assertEqual((out, err), ("", ""))

    def test_eq_bomb_subclass_keeps_its_value_but_loses_its_teeth(self):
        with mock.patch.object(docker_cli, "sh", new=_sh_with_rc(IntEqBomb(0))):
            rc, _, _ = docker_cli.docker("info", timeout=5)
        self.assertIs(type(rc), int)
        self.assertEqual(rc, 0)

    def test_engine_up_survives_an_eq_bomb_rc(self):
        # Before the funnel launder this raised out of ``rc == -1`` and
        # 500'd every route that consults the engine.
        with mock.patch.object(docker_cli, "sh", new=_sh_with_rc(IntEqBomb(1))):
            docker_cli.invalidate_engine_state()
            try:
                self.assertIs(docker_cli.engine_up(force=True), False)
            finally:
                docker_cli.invalidate_engine_state()


class _RouteHarness(unittest.TestCase):
    """Drive the real routes with one junk rc shape wired under ``sh``."""

    URLS = (
        ("GET", "/api/containers", None),
        ("GET", "/api/stacks", None),
        ("GET", "/api/images", None),
        ("GET", "/api/volumes", None),
        ("GET", "/api/networks", None),
        ("GET", "/api/containers/web/inspect", None),
        ("GET", "/api/docker/info", None),
        ("POST", "/api/containers/web/exec",
         {"command": "echo hi", "shell": "/bin/sh"}),
        ("POST", "/api/containers/web/action", {"action": "stop"}),
        ("POST", "/api/containers/batch", {"action": "stop", "names": ["web"]}),
        ("POST", "/api/containers/web/restart-policy", {"policy": "always"}),
        ("POST", "/api/prune", {"kind": "system"}),
    )

    def _drive(self, rc, label):
        client = _client()
        with mock.patch.object(docker_cli, "sh", new=_sh_with_rc(rc)):
            docker_cli.invalidate_engine_state()
            containers_svc.invalidate_container_lists()
            try:
                for method, url, body in self.URLS:
                    r = (client.get(url) if method == "GET"
                         else client.post(url, json=body))
                    self.assert_never_raw_500(r, f"{label} {method} {url}")
            finally:
                docker_cli.invalidate_engine_state()
                containers_svc.invalidate_container_lists()

    def assert_never_raw_500(self, r, label: str):
        # A junk rc legitimately classifies as the coded engine-down 503
        # (the forced probe cannot answer "up" through junk); anything else
        # at or above 500 is the raw crash this sweep exists to kill.
        if r.status_code >= 500:
            self.assertEqual(r.status_code, 503, f"{label}: raw "
                             f"{r.status_code}: {r.text[:300]}")
            self.assertEqual(
                r.json()["detail"]["code"], "container.engine_down",
                f"{label}: uncoded 503: {r.text[:300]}")
        r.content.decode("utf-8")
        return r


class JunkRcRoutesNeverRaw500(_RouteHarness):
    """Every junk rc shape over every docker route: coded answers only."""

    def test_junk_rc_shapes_never_raw_500(self):
        for name, make in RC_ZOO.items():
            with self.subTest(shape=name):
                self._drive(make(), name)

    def test_eq_bomb_rc_never_raw_500(self):
        # Both the "success" and "failure" values: the 0 used to 500 out of
        # ``engine_up``'s ``rc == -1`` probe before anything else ran.
        for value in (0, 1):
            with self.subTest(value=value):
                self._drive(IntEqBomb(value), f"eq-bomb-{value}")


class ExecAndActionEchoPins(_RouteHarness):
    """The two routes that echoed / rendered the raw rc answer coded now."""

    def test_exec_echoes_the_laundered_rc_not_the_impostor(self):
        for name, make in RC_ZOO.items():
            with self.subTest(shape=name):
                with mock.patch.object(docker_cli, "sh",
                                       new=_sh_with_rc(make())):
                    docker_cli.invalidate_engine_state()
                    try:
                        r = _client().post(
                            "/api/containers/web/exec",
                            json={"command": "echo hi", "shell": "/bin/sh"})
                    finally:
                        docker_cli.invalidate_engine_state()
                self.assert_never_raw_500(r, f"exec {name}")
                if r.status_code == 200:
                    body = r.json()
                    self.assertIs(body["ok"], False)
                    self.assertEqual(body["rc"], -255)

    def test_action_with_huge_int_rc_answers_coded_not_500(self):
        # ``f"exit {rc}"`` on a >4300-digit rc used to ValueError mid-render.
        with mock.patch.object(docker_cli, "sh", new=_sh_with_rc(10 ** 5000)):
            docker_cli.invalidate_engine_state()
            try:
                r = _client().post("/api/containers/web/action",
                                   json={"action": "stop"})
            finally:
                docker_cli.invalidate_engine_state()
        self.assert_never_raw_500(r, "action huge-int")
        if r.status_code == 200:
            body = r.json()
            self.assertIs(body["ok"], False)
            self.assertEqual(body["message"], "exit -255")

    def test_clean_rc_zero_still_reads_as_success(self):
        # Sunny-day control: the launder must not tax an honest exit status.
        def fake_sh(cmd, timeout=10, shell=False, env=None):
            return 0, "done", ""

        with mock.patch.object(docker_cli, "sh", new=fake_sh):
            docker_cli.invalidate_engine_state()
            try:
                r = _client().post(
                    "/api/containers/web/exec",
                    json={"command": "echo hi", "shell": "/bin/sh"})
            finally:
                docker_cli.invalidate_engine_state()
        self.assertEqual(r.status_code, 200, r.text[:300])
        body = r.json()
        self.assertIs(body["ok"], True)
        self.assertEqual(body["rc"], 0)
        self.assertEqual(body["output"], "done")


if __name__ == "__main__":
    unittest.main()
