"""Ninth docker-surface leftover-500 sweep: ``__class__``-property bombs.

docker4–8 hardened the listing/jsonable sanitisers behind GET /api/containers,
GET /api/stacks, GET /api/stacks/jobs/{id}, GET /api/images and
POST /api/stacks/{id}/run against method-bombing dict/list/str/int/float
*subclasses* — every guard keyed off a bare ``isinstance`` gate.  But
``isinstance`` consults ``value.__class__`` whenever the exact-type check
misses, so a leftover whose ``__class__`` is a *raising property* detonated
the gate itself, one step ahead of all of that hardening (the nas8 /
catalog10 rule), and a *lying* ``__class__`` (answers ``str``/``bytes``
without being one) sailed through the gate and TypeError'd the unbound
``str.__str__`` / ``bytes.decode`` copies one line later:

* the whole ``stacks:`` value, a stack row, and every stack row field
  (id / name / path / compose_file / containers) as a ``__class__`` bomb
  each 500'd GET /api/stacks and POST /api/stacks/{id}/run out of
  ``_stack_paths`` / ``_plain_job`` / ``_field_text`` / ``_str_list``;
* lying-``__class__`` str impostors in id / name / path (and a lying-bytes
  id) 500'd the same routes out of ``_field_text``'s unbound copies;
* a ``__class__``-bomb ``_cjobs`` row 500'd GET /api/stacks/jobs/{id},
  GET /api/stacks *and* — through the single-runner mutex scan in
  ``_register_job`` — POST /api/stacks/{id}/run until the panel restarted;
* ``__class__``-bomb job-row scalars (rc / stack_id / action / started),
  the ``log`` value and a poisoned log *item* 500'd the job renders out of
  ``docker_cli._jsonable`` / ``_plain_text`` / ``_job_log_lines`` /
  ``_as_text``.

The fix routes every rank gate on these paths through a guarded ``_isa``
(real subclasses still match through the C-level type check; only a value
that cannot answer what it is takes the non-matching branch) and wraps the
unbound base copies so an impostor drops like any other junk leftover.  A
bombed row/field degrades — the row lists without it or drops — and its
siblings always survive.  Product version stays 3.9.3.
"""
from __future__ import annotations

import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
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
    # raise_server_exceptions=False: a real 500 must arrive as HTTP 500, not
    # as a re-raised exception that would mask which route crashed.
    return TestClient(_the_app(), raise_server_exceptions=False)


class ClassBomb:
    """Leftover whose ``__class__`` is a raising property.

    ``isinstance`` consults ``__class__`` when the exact-type check misses,
    so every bare gate detonates on this value.
    """

    @property
    def __class__(self):
        raise RuntimeError("class bomb")


class LyingStr:
    """Claims to be a ``str`` via ``__class__`` without being one."""

    @property
    def __class__(self):
        return str


class LyingBytes:
    """Claims to be ``bytes`` via ``__class__`` without being one."""

    @property
    def __class__(self):
        return bytes


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


class _CfgZoo(_Harness):
    """Drive the listing routes over one hostile cfg snapshot."""

    def _patched(self, cfg_value):
        return (
            mock.patch.object(containers_svc, "docker", side_effect=_fake_docker),
            mock.patch.object(containers_svc, "engine_up", return_value=True),
            mock.patch.object(containers_svc, "cfg", return_value=cfg_value),
            mock.patch.object(config, "cfg", return_value=cfg_value),
        )

    def _get(self, cfg_value, urls=("/api/containers", "/api/stacks")):
        patches = self._patched(cfg_value)
        with patches[0], patches[1], patches[2], patches[3]:
            containers_svc.invalidate_container_lists()
            try:
                c = _client()
                out = {}
                for url in urls:
                    out[url] = self.assert_clean(c.get(url), url)
                return out
            finally:
                containers_svc.invalidate_container_lists()

    def _post_run(self, cfg_value, stack_id="web", action="up"):
        patches = self._patched(cfg_value)
        with patches[0], patches[1], patches[2], patches[3]:
            containers_svc.invalidate_container_lists()
            try:
                return _client().post(
                    f"/api/stacks/{stack_id}/run", json={"action": action})
            finally:
                containers_svc.invalidate_container_lists()


class StacksValueAndRowClassBombs(_CfgZoo):
    """``stacks:`` value / row ``__class__`` bombs used to 500 GET /api/stacks."""

    HEALTHY = {"id": "keeper", "containers": ["a"]}

    def test_stacks_value_class_bomb_never_500s(self):
        self._get({"stacks": ClassBomb()})

    def test_stack_row_class_bomb_drops_row_and_keeps_sibling(self):
        resp = self._get({"stacks": [ClassBomb(), dict(self.HEALTHY)]})
        rows = resp["/api/stacks"].json()["stacks"]
        self.assertIn("keeper", [s.get("id") for s in rows])

    def test_row_field_class_bombs_never_500(self):
        for field in ("id", "name", "path", "compose_file", "containers"):
            with self.subTest(field=field):
                row = {"id": "s", "path": "/tmp/x", "containers": ["a"],
                       field: ClassBomb()}
                resp = self._get(
                    {"stacks": [row, dict(self.HEALTHY)]})
                rows = resp["/api/stacks"].json()["stacks"]
                self.assertIn("keeper", [s.get("id") for s in rows])

    def test_pathless_row_id_class_bomb_never_500s(self):
        self._get({"stacks": [{"id": ClassBomb(), "containers": ["a"]},
                              dict(self.HEALTHY)]})

    def test_run_with_class_bomb_sibling_row_still_finds_stack(self):
        # The bombed row drops; the named stack resolves and answers the
        # coded no-compose 400 — never unknown_stack, never a raw 500.
        r = self._post_run({"stacks": [
            ClassBomb(),
            {"id": "web", "path": "/tmp/definitely-missing-docker9",
             "containers": ["a"]},
        ]})
        self.assertEqual(r.status_code, 400, r.text[:300])
        self.assertIn("container.no_compose_file", r.text)


class LyingClassImpostorFields(_CfgZoo):
    """Lying-``__class__`` impostors used to TypeError the unbound copies."""

    def test_lying_str_stack_fields_never_500(self):
        for field in ("id", "name", "path", "compose_file"):
            with self.subTest(field=field):
                row = {"id": "s", "path": "/tmp/x", "containers": ["a"],
                       field: LyingStr()}
                self._get({"stacks": [row]})

    def test_lying_bytes_stack_id_never_500s(self):
        self._get({"stacks": [{"id": LyingBytes(), "path": "/tmp/x",
                               "containers": ["a"]}]})

    def test_lying_str_pathless_id_never_500s(self):
        self._get({"stacks": [{"id": LyingStr(), "containers": ["a"]}]})


class JobRowClassBombs(_Harness):
    """``__class__`` bombs riding ``_cjobs`` rows used to 500 the job reads."""

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

    def test_whole_row_class_bomb_never_500s(self):
        containers_svc._cjobs["job1"] = ClassBomb()
        self._get_all("row-bomb")

    def test_row_class_bomb_keeps_sibling_job_listed(self):
        containers_svc._cjobs["job1"] = ClassBomb()
        containers_svc._cjobs["job2"] = self._row(stack_id="keeper")
        r = self.assert_clean(_client().get("/api/stacks"), "sibling")
        jobs = r.json()["jobs"]
        self.assertIn("keeper", [j.get("stack_id") for j in jobs])

    def test_scalar_field_class_bombs_never_500(self):
        for field in ("rc", "stack_id", "action", "log", "started",
                      "finished"):
            with self.subTest(field=field):
                containers_svc._cjobs.clear()
                containers_svc._cjobs["job1"] = self._row(**{field: ClassBomb()})
                self._get_all(f"field:{field}")

    def test_log_item_class_bomb_never_500s(self):
        containers_svc._cjobs["job1"] = self._row(log=["ok", ClassBomb()])
        self._get_all("log-item")

    def test_class_bomb_key_never_500s(self):
        # The mapping KEY itself as a bomb: _plain_job's key laundering and
        # _plain_text(k) in the fallback scan both meet it.
        containers_svc._cjobs["job1"] = self._row(**{"rc": 0})
        row = self._row()
        poisoned = {ClassBomb(): "x"}
        poisoned.update(row)
        containers_svc._cjobs["job2"] = poisoned
        self._get_all("bomb-key")

    def test_lying_impostor_fields_never_500(self):
        for field, value in (("rc", LyingStr()), ("stack_id", LyingStr()),
                             ("log", LyingBytes())):
            with self.subTest(field=field):
                containers_svc._cjobs.clear()
                containers_svc._cjobs["job1"] = self._row(**{field: value})
                self._get_all(f"lying:{field}")


class MutexScanClassBomb(_Harness):
    """A ``__class__``-bomb row in ``_cjobs`` used to 500 the run mutex scan.

    ``_register_job`` scans every retained row through ``_row_running`` →
    ``_plain_job`` before starting a job; the bomb detonated the row gate
    and 500'd POST /api/stacks/{id}/run for a stack whose compose exists.
    The junk row must count as *not running* — treating it as live would
    wedge the single-runner mutex forever.
    """

    def setUp(self):
        self._saved = dict(containers_svc._cjobs)
        containers_svc._cjobs.clear()
        self.addCleanup(self._restore)

    def _restore(self):
        containers_svc._cjobs.clear()
        containers_svc._cjobs.update(self._saved)

    def test_bomb_row_does_not_500_or_wedge_the_mutex(self):
        workdir = tempfile.mkdtemp(prefix="docker9-stack-")
        (Path(workdir) / "docker-compose.yml").write_text("services: {}\n")
        containers_svc._cjobs["old"] = ClassBomb()
        cfg_value = {"stacks": [{"id": "web", "path": workdir,
                                 "containers": ["a"]}]}
        with (
            mock.patch.object(containers_svc, "docker",
                              side_effect=_fake_docker),
            mock.patch.object(containers_svc, "engine_up", return_value=True),
            mock.patch.object(containers_svc, "cfg", return_value=cfg_value),
            mock.patch.object(config, "cfg", return_value=cfg_value),
        ):
            containers_svc.invalidate_container_lists()
            r = _client().post("/api/stacks/web/run", json={"action": "up"})
            containers_svc.invalidate_container_lists()
        self.assert_clean(r, "mutex")
        body = r.json()
        self.assertTrue(body.get("ok"), body)
        job_id = body.get("job_id")
        # Let the spawned job thread finish (the docker CLI is absent in the
        # test environment, so it fails fast) before the store is restored.
        deadline = time.time() + 10
        while time.time() < deadline:
            row = containers_svc._cjobs.get(job_id)
            if isinstance(row, dict) and row.get("running") is False:
                break
            time.sleep(0.05)


if __name__ == "__main__":
    unittest.main()
