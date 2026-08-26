"""Seventh docker-surface leftover-500 sweep: cfg/override subclass bombs.

docker6 sealed the poisoned ``_cjobs`` row bombs; this wave hunted the other
store the docker listing routes read on every request — the in-memory config
snapshot (``cfg()`` root, ``stacks:`` rows, ``overrides:`` values).
Reproduced over the real mounted app (``create_app()`` +
``TestClient(raise_server_exceptions=False)``), six families were still raw
HTTP 500s on the pre-fix tree:

* a dict-subclass ``.get`` bomb as the whole cfg root raised out of
  ``_stack_paths``'s bare ``cfg().get("stacks")`` — GET /api/stacks and
  POST /api/stacks/{id}/run;
* an int-subclass stack ``id``/``name`` whose ``__str__`` raised blew
  ``_field_text``'s digit-cap probe (only ValueError was caught);
* a float-subclass stack field whose ``__eq__``/``__ne__`` raised blew
  ``_field_text``'s NaN/inf probes (``value != value``);
* a ``__bool__``-bomb ``hide`` override detonated the bare truth test in
  ``_build_container_list`` — GET /api/containers and GET /api/stacks;
* a dict-subclass ``items()`` / list-subclass ``__iter__`` bomb nested in
  an override value raised out of ``resolve_value``'s walk;
* a str-subclass override KEY whose ``__eq__`` raises detonated inside
  ``dict.get`` when its hash collides with the container's name.

Fixes, all in hub/containers_svc.py, all established conventions:
``_field_text`` gained the unbound base coercions (``int.__index__`` /
``float.__float__`` — the docker_cli._jsonable shape), ``_stack_paths``
reads ``stacks`` through a guarded ``dict.get`` (the backups6
``_mapping_get`` class), and ``_build_container_list`` guards the
``resolve_value(override(name))`` call and runs ``hide`` through
``_truthy``.  These tests pin all of it, plus stays-immune pins for the
shapes that already held (whole-override method bombs, surrogate override
values, huge-int JSON journal entries).
"""
from __future__ import annotations

import sys
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


class DictGetBomb(dict):
    def get(self, *a, **k):
        raise RuntimeError("leftover .get bomb")


class DictItemsBomb(dict):
    def items(self):
        raise RuntimeError("leftover .items bomb")


class ListIterBomb(list):
    def __iter__(self):
        raise RuntimeError("leftover __iter__ bomb")


class BoolBomb:
    def __bool__(self):
        raise RuntimeError("leftover __bool__ bomb")


class IntStrBomb(int):
    def __str__(self):
        raise RuntimeError("int __str__ bomb")

    __repr__ = __str__


class FloatCmpBomb(float):
    def __ne__(self, other):
        raise RuntimeError("float __ne__ bomb")

    def __eq__(self, other):
        raise RuntimeError("float __eq__ bomb")

    __hash__ = float.__hash__


class StrEqBomb(str):
    def __eq__(self, other):
        raise RuntimeError("str __eq__ bomb")

    __hash__ = str.__hash__


def _fake_docker(*args, timeout=None):
    a = list(args)
    if a and a[0] == "ps":
        return 0, ("id\tweb\timg\trunning\tUp 2 days\t0.0.0.0:80->80/tcp\t"
                   "proj\tsvc\t12MB"), ""
    if a and a[0] == "stats":
        return 0, "web\t1%\t1MiB / 2MiB\t50%\t1B/2B\t3B/4B", ""
    return 0, '[{"Name": "/web", "Config": {"Image": "img"}}]', ""


class _CfgZoo(unittest.TestCase):
    """Drive the docker listing routes with one hostile cfg snapshot.

    ``config.cfg`` is patched alongside ``containers_svc.cfg`` because the
    ``override()`` reader lives in hub.config and resolves the snapshot
    through its own module global.
    """

    def _routes(self, cfg_value, urls=("/api/containers", "/api/stacks")):
        out = {}
        with (
            mock.patch.object(containers_svc, "docker", side_effect=_fake_docker),
            mock.patch.object(containers_svc, "engine_up", return_value=True),
            mock.patch.object(containers_svc, "cfg", return_value=cfg_value),
            mock.patch.object(config, "cfg", return_value=cfg_value),
        ):
            containers_svc.invalidate_container_lists()
            try:
                c = _client()
                for url in urls:
                    r = c.get(url)
                    self.assertLess(
                        r.status_code, 500,
                        f"{url}: raw {r.status_code}: {r.text[:300]}",
                    )
                    # The body must already be valid UTF-8 — decode strictly.
                    out[url] = r.content.decode("utf-8")
                    out[url, "json"] = r.json()
            finally:
                containers_svc.invalidate_container_lists()
        return out


class StacksCfgRootBombPins(_CfgZoo):
    """GET /api/stacks + POST run survive a bombed cfg root."""

    def test_get_bomb_cfg_root_keeps_stacks_listing(self):
        out = self._routes(DictGetBomb())
        self.assertEqual(out["/api/stacks", "json"]["stacks"], [])

    def test_get_bomb_cfg_root_keeps_stack_run_coded(self):
        with (
            mock.patch.object(containers_svc, "cfg", return_value=DictGetBomb()),
            mock.patch.object(config, "cfg", return_value=DictGetBomb()),
        ):
            r = _client().post("/api/stacks/web/run", json={"action": "up"})
        # No stack can resolve from a bombed snapshot: coded 404, never raw.
        self.assertEqual(r.status_code, 404, r.text[:300])
        self.assertIn("container.unknown_stack", r.text)

    def test_eq_bomb_stacks_key_keeps_the_listing(self):
        # Same content as "stacks": the hashes collide and dict.get compares
        # the plain key against the bomb inside the lookup itself.
        out = self._routes({StrEqBomb("stacks"): [{"id": "s", "containers": ["a"]}]})
        self.assertEqual(out["/api/stacks", "json"]["stacks"], [])


class StackFieldScalarBombPins(_CfgZoo):
    """int/float subclass bombs in stacks: rows cost the field, not the page."""

    def test_int_str_bomb_stack_id_and_name_never_500(self):
        for field in ("id", "name"):
            with self.subTest(field=field):
                row = {"id": "s", "containers": ["a"], field: IntStrBomb(7)}
                out = self._routes({"stacks": [row]})
                self.assertNotIn("500", out["/api/stacks"][:15])

    def test_float_cmp_bomb_stack_id_never_500s(self):
        out = self._routes(
            {"stacks": [{"id": FloatCmpBomb(1.5), "containers": ["a"]}]})
        self.assertIsInstance(out["/api/stacks", "json"]["stacks"], list)

    def test_bombed_row_does_not_cost_its_healthy_sibling(self):
        out = self._routes({"stacks": [
            {"id": IntStrBomb(7), "containers": ["a"]},
            {"id": "healthy", "containers": ["b"]},
        ]})
        ids = [s.get("id") for s in out["/api/stacks", "json"]["stacks"]]
        self.assertIn("healthy", ids)


class OverrideBombPins(_CfgZoo):
    """overrides: bombs cost the override, never the container listing."""

    def _containers(self, overrides) -> list:
        out = self._routes({"overrides": overrides})
        payload = out["/api/containers", "json"]
        self.assertTrue(payload["engine_up"])
        return payload["containers"]

    def test_bool_bomb_hide_keeps_the_container_listed(self):
        # Junk is not a hide instruction: the row must not vanish either.
        rows = self._containers({"web": {"hide": BoolBomb()}})
        self.assertIn("web", [r.get("raw_name") for r in rows])

    def test_nested_items_bomb_override_value_never_500s(self):
        rows = self._containers({"web": {"name": DictItemsBomb({"x": 1})}})
        self.assertIn("web", [r.get("raw_name") for r in rows])

    def test_nested_iter_bomb_override_value_never_500s(self):
        rows = self._containers({"web": {"name": ListIterBomb(["a"])}})
        self.assertIn("web", [r.get("raw_name") for r in rows])

    def test_eq_bomb_override_key_never_500s(self):
        # Same content as the container name: hash collision makes dict.get
        # compare the queried plain str against the bomb key.
        rows = self._containers({StrEqBomb("web"): {"name": "x"}})
        self.assertIn("web", [r.get("raw_name") for r in rows])

    def test_scalar_bomb_override_fields_never_500(self):
        for field, bomb in (
            ("name", IntStrBomb(5)),
            ("group", FloatCmpBomb(2.5)),
            ("url", IntStrBomb(5)),
        ):
            with self.subTest(field=field):
                rows = self._containers({"web": {field: bomb}})
                self.assertIn("web", [r.get("raw_name") for r in rows])

    def test_whole_override_method_bombs_keep_their_real_data(self):
        # Stays-immune: override() launders through the C-level dict copy,
        # so a subclass that only poisoned items()/get keeps its sane name.
        for zoo in (DictItemsBomb({"name": "friendly"}),
                    DictGetBomb({"name": "friendly"})):
            with self.subTest(bomb=type(zoo).__name__):
                rows = self._containers({"web": zoo})
                names = {r.get("raw_name"): r.get("name") for r in rows}
                self.assertEqual(names.get("web"), "friendly")

    def test_surrogate_override_name_publishes_scrubbed(self):
        # Stays-immune: the lone surrogate never reaches Starlette's encoder.
        out = self._routes({"overrides": {"web": {"name": "\ud800x"}}})
        self.assertNotIn("\ud800", out["/api/containers"])


class FieldTextUnboundUnitPins(unittest.TestCase):
    """_field_text itself follows the unbound base convention."""

    def test_scalar_bombs_coerce_to_base_renderings(self):
        # The base coercion sheds only the subclass; the value survives.
        self.assertEqual(containers_svc._field_text(IntStrBomb(7)), "7")
        self.assertEqual(containers_svc._field_text(FloatCmpBomb(1.5)), "1.5")

    def test_huge_and_nonfinite_values_keep_prior_fallbacks(self):
        huge = 10 ** 5000  # dodges the digit cap that int(str) would hit
        self.assertEqual(containers_svc._field_text(huge, "fb"), "fb")
        self.assertEqual(containers_svc._field_text(float("inf"), "fb"), "fb")
        self.assertEqual(containers_svc._field_text(float("nan"), "fb"), "fb")
        self.assertEqual(containers_svc._field_text(3, "fb"), "3")
        self.assertEqual(containers_svc._field_text(1.25, "fb"), "1.25")


if __name__ == "__main__":
    unittest.main()
