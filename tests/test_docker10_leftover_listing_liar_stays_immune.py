"""Tenth docker-surface sweep, part two: listing liar shapes stay immune.

docker9 pinned the raising-``__class__`` bomb and the *str/bytes*-lying
impostors in cfg stack rows and ``_cjobs`` job fields.  The catalog11 /
json9 class is wider — an impostor may claim bool / int / float / dict /
list / tuple / set, carry its own ``items()`` that yields non-pairs, or a
working ``__iter__`` behind a list claim — and each claim aims at a
different rank arm of the ``_isa`` funnels (``docker_cli._jsonable``,
``containers_svc._field_text`` / ``_plain_job`` / ``_str_list`` /
``_job_scalar`` / ``_log_text``).  This wave drove that full zoo over the
real mounted app (``create_app()`` + ``TestClient(
raise_server_exceptions=False)``) in every leftover position — the whole
``stacks:`` value, stack rows and each row field, override fields, whole
``_cjobs`` rows and each job field, log items, and the single-runner mutex
scan on POST /api/stacks/{id}/run.

Every shape already answers below 500: the docker9 convention (guarded
``_isa`` gates plus try-wrapped unbound base copies — ``dict()`` /
``list()`` / ``str.__str__`` / ``int.__index__`` / ``float.__float__`` /
``bytes.decode`` through the C-level storage) absorbs the wider zoo, and
``_jsonable``'s exact ``type(value) is bool`` gate keeps a bool-claiming
impostor from riding raw into Starlette's encoder.  No source change
accompanies this file: it is an immunity pin, so a refactor of these
funnels cannot silently reopen a surface.  Product version stays 3.9.3.
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

from hub import config, containers_svc  # noqa: E402
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
    return TestClient(_the_app(), raise_server_exceptions=False)


def _liar(cls, text="liar"):
    """``__class__`` answers *cls*; the real type is a plain object."""

    class Liar:
        __class__ = property(lambda self: cls)

        def __str__(self):
            return text

    return Liar()


class DictLiarWithItems:
    """Claims dict and carries working ``keys``/``items`` — ``dict(value)``
    succeeds, so the laundered copy (not the impostor) must be what walks."""

    __class__ = property(lambda self: dict)

    def keys(self):
        return ["k"]

    def __getitem__(self, key):
        return "v"

    def items(self):
        return ["not-a-pair"]


class DictLiarBombKeys:
    """Claims dict; ``dict(value)`` detonates on its ``keys()``."""

    __class__ = property(lambda self: dict)

    def keys(self):
        raise RuntimeError("keys bomb")


class ListLiarWithIter:
    """Claims list with a working ``__iter__`` yielding a nested liar."""

    __class__ = property(lambda self: list)

    def __iter__(self):
        return iter(["a", _liar(str)])


#: The wider impostor zoo aimed at every rank arm of the _isa funnels.
LIAR_ZOO = {
    "bool-liar": lambda: _liar(bool),
    "int-liar": lambda: _liar(int),
    "float-liar": lambda: _liar(float),
    "dict-liar": lambda: _liar(dict),
    "list-liar": lambda: _liar(list),
    "tuple-liar": lambda: _liar(tuple),
    "set-liar": lambda: _liar(set),
    "dict-liar-items": DictLiarWithItems,
    "dict-liar-bombkeys": DictLiarBombKeys,
    "list-liar-iter": ListLiarWithIter,
}


def _fake_docker(*args, timeout=None):
    a = list(args)
    if a and a[0] == "ps":
        return 0, ("id\tweb\timg\trunning\tUp 2 days\t0.0.0.0:80->80/tcp\t"
                   "proj\tsvc\t12MB"), ""
    if a and a[0] == "stats":
        return 0, "web\t1%\t1MiB / 2MiB\t50%\t1B/2B\t3B/4B", ""
    return 0, '[{"Name": "/web", "Config": {"Image": "img"}}]', ""


class _Harness(unittest.TestCase):
    def assert_clean(self, r, label: str):
        self.assertLess(
            r.status_code, 500, f"{label}: raw {r.status_code}: {r.text[:300]}"
        )
        r.content.decode("utf-8")
        return r


class CfgLiarShapesStayImmune(_Harness):
    """The wider liar zoo in every cfg position keeps the listings alive."""

    HEALTHY = {"id": "keeper", "containers": ["a"]}

    def _get(self, cfg_value, label, urls=("/api/containers", "/api/stacks")):
        with (
            mock.patch.object(containers_svc, "docker",
                              side_effect=_fake_docker),
            mock.patch.object(containers_svc, "engine_up", return_value=True),
            mock.patch.object(containers_svc, "cfg", return_value=cfg_value),
            mock.patch.object(config, "cfg", return_value=cfg_value),
        ):
            containers_svc.invalidate_container_lists()
            try:
                c = _client()
                out = {}
                for url in urls:
                    out[url] = self.assert_clean(c.get(url), f"{label} {url}")
                return out
            finally:
                containers_svc.invalidate_container_lists()

    def test_whole_stacks_value_liars_never_500(self):
        for name, make in LIAR_ZOO.items():
            with self.subTest(shape=name):
                self._get({"stacks": make()}, f"stacks-value:{name}")

    def test_stack_row_liars_drop_and_keep_siblings(self):
        for name, make in LIAR_ZOO.items():
            with self.subTest(shape=name):
                resp = self._get({"stacks": [make(), dict(self.HEALTHY)]},
                                 f"stack-row:{name}")
                rows = resp["/api/stacks"].json()["stacks"]
                self.assertIn("keeper", [s.get("id") for s in rows])

    def test_stack_field_liars_never_500(self):
        for name, make in LIAR_ZOO.items():
            for field in ("id", "name", "path", "compose_file", "containers"):
                with self.subTest(shape=name, field=field):
                    row = {"id": "s", "path": "/tmp/x", "containers": ["a"],
                           field: make()}
                    self._get({"stacks": [row]}, f"field:{field}:{name}")

    def test_override_field_liars_never_500(self):
        for name, make in LIAR_ZOO.items():
            for field in ("name", "group", "url", "hide"):
                with self.subTest(shape=name, field=field):
                    self._get({"overrides": {"web": {field: make()}}},
                              f"override:{field}:{name}")

    def test_cfg_root_liars_never_500(self):
        for name, make in LIAR_ZOO.items():
            with self.subTest(shape=name):
                self._get(make(), f"cfg-root:{name}")


class JobStoreLiarShapesStayImmune(_Harness):
    """The wider liar zoo riding ``_cjobs`` keeps the job reads alive."""

    def setUp(self):
        self._saved = dict(containers_svc._cjobs)
        containers_svc._cjobs.clear()
        self.addCleanup(self._restore)

    def _restore(self):
        containers_svc._cjobs.clear()
        containers_svc._cjobs.update(self._saved)

    @staticmethod
    def _row(**over):
        row = {
            "running": False, "rc": 0, "log": ["line"],
            "started": "10:00:00", "finished": "10:00:01",
            "stack_id": "s1", "action": "up",
        }
        row.update(over)
        return row

    def _get_all(self, label):
        c = _client()
        for url in ("/api/stacks/jobs/job1", "/api/stacks",
                    "/api/stacks/jobs/other"):
            self.assert_clean(c.get(url), f"{label} {url}")

    def test_whole_row_liars_never_500(self):
        for name, make in LIAR_ZOO.items():
            with self.subTest(shape=name):
                containers_svc._cjobs.clear()
                containers_svc._cjobs["job1"] = make()
                containers_svc._cjobs["job2"] = self._row(stack_id="keeper")
                self._get_all(f"row:{name}")
                r = _client().get("/api/stacks")
                jobs = r.json()["jobs"]
                self.assertIn("keeper", [j.get("stack_id") for j in jobs])

    def test_job_field_liars_never_500(self):
        for name, make in LIAR_ZOO.items():
            for field in ("running", "rc", "stack_id", "action", "log",
                          "started", "finished", "code"):
                with self.subTest(shape=name, field=field):
                    containers_svc._cjobs.clear()
                    containers_svc._cjobs["job1"] = self._row(
                        **{field: make()})
                    self._get_all(f"field:{field}:{name}")

    def test_log_item_liars_never_500(self):
        for name, make in LIAR_ZOO.items():
            with self.subTest(shape=name):
                containers_svc._cjobs.clear()
                containers_svc._cjobs["job1"] = self._row(log=["ok", make()])
                self._get_all(f"log-item:{name}")


class MutexScanLiarRowsStayImmune(_Harness):
    """Liar rows in ``_cjobs`` neither 500 nor wedge the single-runner mutex."""

    def setUp(self):
        self._saved = dict(containers_svc._cjobs)
        containers_svc._cjobs.clear()
        self.addCleanup(self._restore)

    def _restore(self):
        containers_svc._cjobs.clear()
        containers_svc._cjobs.update(self._saved)

    def test_liar_rows_read_as_not_running(self):
        for name, make in LIAR_ZOO.items():
            with self.subTest(shape=name):
                # Unit-level: junk is not a live job (the docker9 rule) —
                # counting it as running would wedge every stack run.
                self.assertIs(containers_svc._row_running(make()), False)

    def test_run_with_liar_row_answers_coded_not_500(self):
        cfg_value = {"stacks": [{"id": "web",
                                 "path": "/tmp/definitely-missing-docker10",
                                 "containers": ["a"]}]}
        for name, make in LIAR_ZOO.items():
            with self.subTest(shape=name):
                containers_svc._cjobs.clear()
                containers_svc._cjobs["old"] = make()
                with (
                    mock.patch.object(containers_svc, "docker",
                                      side_effect=_fake_docker),
                    mock.patch.object(containers_svc, "engine_up",
                                      return_value=True),
                    mock.patch.object(containers_svc, "cfg",
                                      return_value=cfg_value),
                    mock.patch.object(config, "cfg", return_value=cfg_value),
                ):
                    containers_svc.invalidate_container_lists()
                    try:
                        r = _client().post("/api/stacks/web/run",
                                           json={"action": "up"})
                    finally:
                        containers_svc.invalidate_container_lists()
                # The liar row drops from the mutex scan; the named stack
                # resolves and answers the coded no-compose 400 — never
                # job_running, never a raw 500.
                self.assertEqual(r.status_code, 400, r.text[:300])
                self.assertIn("container.no_compose_file", r.text)


if __name__ == "__main__":
    unittest.main()
