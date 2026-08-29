"""Ninth docker-surface sweep: vectors that already answer below 500.

Companion to test_docker9_leftover_class_property_bombs_500s.  While that
file pins the ``__class__``-property-bomb 500s this sweep sealed, the
families here were probed the same way and found already immune — each pin
keeps a future refactor of the sanitisers from silently reopening one:

* the cfg *root* as a ``__class__`` bomb (``_stack_paths`` resolves it
  inside its own try; ``override()`` detonates inside the per-row
  ``resolve_value`` try and the row lists without its override);
* ``__class__`` bombs and lying-``__class__`` impostors in *override*
  values — the ``resolve_value(override(name))`` try eats the walk's raise
  and GET /api/containers keeps the row;
* a FIFO occupying docker-update-status.json (``read_text_capped`` opens
  O_NONBLOCK and refuses non-regular files: no hang, no 500);
* an ``isoformat``-property bomb and a ``__bytes__`` bomb in a job scalar
  (``_jsonable``'s guarded getattr / str fallthrough absorb both);
* a float-subclass ``__eq__``/``__ne__`` bomb ``rc`` (the unbound
  ``float.__float__`` coercion disarms it before the NaN/inf probes);
* a ``__bool__``-safe ``running`` gate: ``bool()`` never consults
  ``__class__``, so a bomb ``running`` value stays covered by ``_truthy``;
* GET /api/images over NDJSON carrying a huge float (``1e999`` decodes to
  inf and drops) beside a healthy sibling row, and over a vanished docker
  CLI — coded 503 ``container.engine_down`` after the forced probe
  confirms, never a raw 500.

No source change accompanies these pins.  Product version stays 3.9.3.
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
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
    return TestClient(_the_app(), raise_server_exceptions=False)


class ClassBomb:
    @property
    def __class__(self):
        raise RuntimeError("class bomb")


class LyingStr:
    @property
    def __class__(self):
        return str


class IsoformatBomb:
    """Object whose ``isoformat`` attribute is a raising property."""

    @property
    def isoformat(self):
        raise RuntimeError("isoformat bomb")


class BytesDunderBomb:
    def __bytes__(self):
        raise RuntimeError("bytes bomb")


class FloatCmpBomb(float):
    def __eq__(self, other):
        raise RuntimeError("float eq bomb")

    __ne__ = __eq__
    __hash__ = float.__hash__


class BoolBomb:
    def __bool__(self):
        raise RuntimeError("bool bomb")


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


class CfgRootAndOverrideBombPins(_Harness):
    """cfg-root / override-value bombs stay off both listings."""

    def _get(self, cfg_value):
        with (
            mock.patch.object(containers_svc, "docker", side_effect=_fake_docker),
            mock.patch.object(containers_svc, "engine_up", return_value=True),
            mock.patch.object(containers_svc, "cfg", return_value=cfg_value),
            mock.patch.object(config, "cfg", return_value=cfg_value),
        ):
            containers_svc.invalidate_container_lists()
            try:
                c = _client()
                out = {}
                for url in ("/api/containers", "/api/stacks"):
                    out[url] = self.assert_clean(c.get(url), url)
                return out
            finally:
                containers_svc.invalidate_container_lists()

    def test_cfg_root_class_bomb_stays_immune(self):
        self._get(ClassBomb())

    def test_override_value_class_bombs_keep_container_row(self):
        for field in ("name", "url", "group", "hide"):
            with self.subTest(field=field):
                resp = self._get({"overrides": {"web": {field: ClassBomb()}}})
                rows = resp["/api/containers"].json()["containers"]
                self.assertIn("web", [r.get("id") for r in rows])

    def test_override_lying_str_value_stays_immune(self):
        self._get({"overrides": {"web": {"name": LyingStr()}}})


class UpdateStatusFifoPin(_Harness):
    """A FIFO at docker-update-status.json cannot hang or 500 the listing."""

    def test_fifo_update_status_stays_immune(self):
        path = containers_svc.UPDATE_STATUS_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        prior = path.read_bytes() if path.exists() else None
        if path.exists():
            path.unlink()
        os.mkfifo(path)
        try:
            with (
                mock.patch.object(containers_svc, "docker",
                                  side_effect=_fake_docker),
                mock.patch.object(containers_svc, "engine_up",
                                  return_value=True),
            ):
                containers_svc.invalidate_container_lists()
                try:
                    self.assert_clean(_client().get("/api/containers"), "fifo")
                finally:
                    containers_svc.invalidate_container_lists()
        finally:
            path.unlink()
            if prior is not None:
                path.write_bytes(prior)


class JobScalarRenderProbePins(_Harness):
    """isoformat/__bytes__/rc-cmp/running bombs in job rows stay immune."""

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

    def test_render_probe_bombs_stay_immune(self):
        cases = {
            "isoformat": self._row(started=IsoformatBomb()),
            "bytes_dunder": self._row(started=BytesDunderBomb()),
            "rc_float_cmp": self._row(rc=FloatCmpBomb(1.5)),
            "running_bool_bomb": self._row(running=BoolBomb()),
            "running_class_bomb": self._row(running=ClassBomb()),
        }
        for name, row in cases.items():
            with self.subTest(case=name):
                containers_svc._cjobs.clear()
                containers_svc._cjobs["job1"] = row
                self._get_all(name)


class ImagesListingPins(_Harness):
    """GET /api/images NDJSON/CLI edge cases stay coded, never raw."""

    def _get_images(self, fake):
        with (
            mock.patch.object(docker_cli, "docker", side_effect=fake),
            mock.patch.object(containers_svc, "docker", side_effect=fake),
        ):
            return _client().get("/api/images")

    def test_huge_float_row_drops_field_and_keeps_sibling(self):
        def fake(*args, timeout=None):
            a = list(args)
            if a and a[0] == "images":
                return 0, ('{"Repository":"keep","Tag":"y"}\n'
                           '{"Repository":"big","Size":1e999}'), ""
            return 0, "", ""

        with mock.patch.object(containers_svc, "engine_up", return_value=True):
            r = self.assert_clean(self._get_images(fake), "huge-float")
        repos = [row.get("Repository") for row in r.json()["images"]]
        self.assertIn("keep", repos)
        self.assertIn("big", repos)

    def test_vanished_cli_is_coded_503_after_disk_confirm(self):
        # run_capped/sh report a vanished binary as the exact (-1, "not
        # found") sentinel; the inventory read must answer the coded
        # engine-down 503 (the forced probe cannot say "up" while the CLI
        # is gone), never a raw 500.
        def fake(*args, timeout=None):
            return -1, "", "not found"

        with mock.patch.object(containers_svc, "engine_up", return_value=False):
            r = self._get_images(fake)
        self.assertEqual(r.status_code, 503, r.text[:300])
        self.assertIn("container.engine_down", r.text)


if __name__ == "__main__":
    unittest.main()
