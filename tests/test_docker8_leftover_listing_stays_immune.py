"""Eighth docker-surface leftover-500 sweep: nothing left to fold.

docker4/5 pinned the ports-wipe / surrogate stack surfaces and the docker
inventory stays-immune shapes; docker6 sealed the poisoned ``_cjobs`` row
bombs; docker7 sealed the ``cfg()`` root / ``stacks:`` row / ``overrides:``
value subclass bombs.  This wave re-swept every listing/jsonable sanitiser
that GET /api/containers, GET /api/stacks, GET /api/stacks/jobs/{id},
GET /api/images and POST /api/stacks/{id}/run read on each request, driving
a broad battery of leftover bomb families over the *real* mounted app
(``create_app()`` + ``TestClient(raise_server_exceptions=False)``):

* ``cfg()`` root as a dict-subclass whose ``get``/``items``/``keys``/
  ``__bool__``/``__len__`` raises (docker7 pinned only ``.get`` and the
  hash-colliding ``__eq__`` key);
* the whole ``stacks:`` value as a list-subclass whose ``__iter__`` /
  ``__len__`` / ``__bool__`` raises (docker7 pinned poisoned *rows*, not the
  list wrapper ``_stack_paths`` runs ``list()`` over);
* the ``str``-subclass families docker6 met only in job rows — a self-
  ``__str__`` ``.encode`` bomb, a ``__str__`` bomb, a ``__len__`` bomb — plus
  a NUL byte and a ``bytes``-subclass ``.decode`` bomb, in every stack and
  override text field;
* the address-book template walk reached through an override value that
  carries a ``{name}`` token (``resolve_value`` → ``resolve_template`` →
  ``template_variables``) when the book itself is poisoned;
* deeply nested and self-referential (cyclic) override / stack payloads,
  which ``resolve_value``'s depth cap and ``_jsonable``'s must both survive;
* pathological ``docker inspect`` / ``docker images`` JSON — a >4300-digit
  int, ``Infinity``/``NaN``, a ``\\ud800`` surrogate, a torn object, a
  12k-deep nest — that the enrichment and image listing decode;
* on-disk ``docker-update-status.json`` poisoned with a huge int, a
  surrogate, ``Infinity`` or non-UTF-8 bytes, read by the /api/containers
  enrichment;
* dict-subclass ``_cjobs`` rows and a ``__bool__``-bomb ``running`` value
  reached through the single-runner mutex on POST /api/stacks/{id}/run.

Every family already answers below 500.  No source change accompanies this
file: it is an immunity pin, so a future refactor of the sanitisers cannot
silently reopen a surface an earlier sweep sealed.  Product version stays
3.9.3.
"""
from __future__ import annotations

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
    # raise_server_exceptions=False: a real 500 must arrive as HTTP 500, not
    # as a re-raised exception that would mask which route crashed.
    return TestClient(_the_app(), raise_server_exceptions=False)


# --------------------------------------------------------------------------
# bomb families
# --------------------------------------------------------------------------
class DictGetBomb(dict):
    def get(self, *a, **k):
        raise RuntimeError("get bomb")


class DictItemsBomb(dict):
    def items(self):
        raise RuntimeError("items bomb")


class DictKeysBomb(dict):
    def keys(self):
        raise RuntimeError("keys bomb")


class DictBoolBomb(dict):
    def __bool__(self):
        raise RuntimeError("dict bool bomb")


class DictLenBomb(dict):
    def __len__(self):
        raise RuntimeError("dict len bomb")


class ListIterBomb(list):
    def __iter__(self):
        raise RuntimeError("iter bomb")


class ListLenBomb(list):
    def __len__(self):
        raise RuntimeError("list len bomb")


class ListBoolBomb(list):
    def __bool__(self):
        raise RuntimeError("list bool bomb")


class BoolBomb:
    def __bool__(self):
        raise RuntimeError("bool bomb")


class IntStrBomb(int):
    def __str__(self):
        raise RuntimeError("int str bomb")

    __repr__ = __str__


class IntIndexBomb(int):
    def __index__(self):
        raise RuntimeError("int index bomb")


class FloatCmpBomb(float):
    def __ne__(self, other):
        raise RuntimeError("float ne bomb")

    def __eq__(self, other):
        raise RuntimeError("float eq bomb")

    __hash__ = float.__hash__


class FloatFloatBomb(float):
    def __float__(self):
        raise RuntimeError("float float bomb")


class StrEncodeBomb(str):
    # __str__ returning self keeps the subclass alive through str(), so the
    # bound .encode bomb is what a naive final UTF-8 scrub would have hit.
    def __str__(self):
        return self

    def encode(self, *a, **k):
        raise RuntimeError("str encode bomb")


class StrStrBomb(str):
    def __str__(self):
        raise RuntimeError("str str bomb")

    __repr__ = __str__


class StrLenBomb(str):
    def __len__(self):
        raise RuntimeError("str len bomb")


class StrEqBomb(str):
    def __eq__(self, other):
        raise RuntimeError("str eq bomb")

    __hash__ = str.__hash__


class StrHashBomb(str):
    def __hash__(self):
        raise RuntimeError("str hash bomb")


class BytesDecodeBomb(bytes):
    def decode(self, *a, **k):
        raise RuntimeError("bytes decode bomb")


#: Scalar leftovers a stack/override field or job row may still carry.
SCALAR_BOMBS = {
    "int_str": IntStrBomb(7),
    "int_index": IntIndexBomb(7),
    "float_cmp": FloatCmpBomb(1.5),
    "float_float": FloatFloatBomb(1.5),
    "str_encode": StrEncodeBomb("xx"),
    "str_str": StrStrBomb("xx"),
    "str_len": StrLenBomb("xx"),
    "bytes_decode": BytesDecodeBomb(b"xx"),
    "huge_int": 10 ** 5000,  # past CPython's int->str digit cap
    "surrogate": "\ud800x",
    "nul": "a\x00b",
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
    """Assert a route answers below 500 and in strict UTF-8."""

    def assert_clean(self, r, label: str):
        self.assertLess(
            r.status_code, 500, f"{label}: raw {r.status_code}: {r.text[:300]}"
        )
        # The body must already be valid UTF-8 — decode strictly.
        r.content.decode("utf-8")


class _CfgZoo(_Harness):
    """Drive the docker listing routes with one hostile cfg snapshot.

    ``config.cfg`` is patched alongside ``containers_svc.cfg`` because the
    ``override()`` reader lives in hub.config and resolves the snapshot
    through its own module global.
    """

    def _get(self, cfg_value, urls=("/api/containers", "/api/stacks")):
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
                    self.assert_clean(c.get(url), f"{url}")
            finally:
                containers_svc.invalidate_container_lists()

    def _post_run(self, cfg_value, stack_id="web", action="up"):
        with (
            mock.patch.object(containers_svc, "docker", side_effect=_fake_docker),
            mock.patch.object(containers_svc, "engine_up", return_value=True),
            mock.patch.object(containers_svc, "cfg", return_value=cfg_value),
            mock.patch.object(config, "cfg", return_value=cfg_value),
        ):
            containers_svc.invalidate_container_lists()
            try:
                return _client().post(
                    f"/api/stacks/{stack_id}/run", json={"action": action})
            finally:
                containers_svc.invalidate_container_lists()


class CfgRootSubclassBombPins(_CfgZoo):
    """The whole cfg root as a method-bombing dict subclass stays immune."""

    def test_root_method_bombs_keep_listings_alive(self):
        for name, cls in (
            ("get", DictGetBomb), ("items", DictItemsBomb),
            ("keys", DictKeysBomb), ("bool", DictBoolBomb),
            ("len", DictLenBomb),
        ):
            with self.subTest(bomb=name):
                self._get(cls())

    def test_root_method_bombs_keep_stack_run_coded(self):
        # No stack resolves from a bombed snapshot: coded 404, never raw.
        for cls in (DictGetBomb, DictItemsBomb, DictBoolBomb):
            with self.subTest(bomb=cls.__name__):
                r = self._post_run(cls())
                self.assertEqual(r.status_code, 404, r.text[:300])
                self.assertIn("container.unknown_stack", r.text)


class StacksListWrapperBombPins(_CfgZoo):
    """The ``stacks:`` value as a poisoned list subclass stays immune.

    ``_stack_paths`` runs ``list()`` over it through the C storage, so an
    overridden ``__iter__`` / ``__len__`` / ``__bool__`` cannot fire the
    walk.
    """

    def test_stacks_list_subclass_bombs_never_500(self):
        row = {"id": "s", "path": "/tmp/x", "containers": ["a"]}
        for name, cls in (
            ("iter", ListIterBomb), ("len", ListLenBomb), ("bool", ListBoolBomb),
        ):
            with self.subTest(bomb=name):
                self._get({"stacks": cls([row])})


class StackRowFieldBombPins(_CfgZoo):
    """Every scalar bomb family in every stack text field stays a 2xx."""

    def test_scalar_bombs_in_stack_fields_never_500(self):
        for name, bomb in SCALAR_BOMBS.items():
            for field in ("id", "name", "compose_file", "path"):
                with self.subTest(bomb=name, field=field):
                    row = {"id": "s", "path": "/tmp/x", "containers": ["a"]}
                    row[field] = bomb
                    self._get({"stacks": [row]})

    def test_scalar_bombs_in_containers_item_never_500(self):
        for name, bomb in SCALAR_BOMBS.items():
            with self.subTest(bomb=name):
                self._get({"stacks": [{"id": "s", "containers": [bomb]}]})

    def test_containers_value_bombs_never_500(self):
        for name, val in (("iter", ListIterBomb(["a"])), ("bool", BoolBomb())):
            with self.subTest(bomb=name):
                self._get({"stacks": [{"id": "s", "containers": val}]})


class OverrideFieldBombPins(_CfgZoo):
    """Every scalar bomb family in every override field stays a 2xx."""

    def test_scalar_bombs_in_override_fields_never_500(self):
        for name, bomb in SCALAR_BOMBS.items():
            for field in ("name", "group", "url", "hide"):
                with self.subTest(bomb=name, field=field):
                    self._get({"overrides": {"web": {field: bomb}}})

    def test_nested_container_bombs_in_override_value_never_500(self):
        for name, val in (
            ("items", DictItemsBomb({"x": 1})),
            ("iter", ListIterBomb(["a"])),
            ("bool_hide", BoolBomb()),
        ):
            with self.subTest(bomb=name):
                self._get({"overrides": {"web": {"name": val, "hide": val}}})


class TemplateAddressBookBombPins(_CfgZoo):
    """A ``{name}`` override token walks a poisoned address book unharmed.

    ``resolve_value`` → ``resolve_template`` → ``template_variables`` reads
    ``settings.address_book`` only when a value carries a ``{...}`` token;
    ``template_variables`` swallows a poisoned book, so the listing holds.
    """

    def test_addressbook_scalar_bombs_never_500(self):
        for name, bomb in SCALAR_BOMBS.items():
            with self.subTest(bomb=name):
                self._get({
                    "overrides": {"web": {"url": "http://{host}/x",
                                          "name": "{nm}"}},
                    "settings": {"address_book": {"nm": bomb}},
                })

    def test_addressbook_method_bomb_never_500(self):
        self._get({
            "overrides": {"web": {"name": "{k}"}},
            "settings": {"address_book": DictItemsBomb({"k": "v"})},
        })


class DeepAndCyclicPayloadPins(_CfgZoo):
    """Depth caps and cycle guards keep pathological shapes off the routes."""

    @staticmethod
    def _nest(depth):
        node = {"x": 1}
        for _ in range(depth):
            node = {"y": node}
        return node

    def test_deeply_nested_override_and_stack_never_500(self):
        self._get({"overrides": {"web": {"name": self._nest(500)}}})
        self._get({"stacks": [{"id": "s", "path": "/tmp/x",
                               "containers": ["a"], "extra": self._nest(500)}]})

    def test_self_referential_override_never_500(self):
        cyc: dict = {}
        cyc["self"] = cyc
        self._get({"overrides": {"web": {"name": cyc}}})


class InspectImagesJsonPins(_Harness):
    """Pathological docker inspect / images JSON stays off the routes.

    ``_build_container_list`` decodes the batch ``docker inspect`` through
    ``parse_int_capped`` + ``_jsonable``; ``list_images`` decodes
    ``{{json .}}`` NDJSON through ``docker_json``.  Both are patched: the
    enrichment reads ``containers_svc.docker`` while ``docker_json`` calls
    ``docker_cli.docker``.
    """

    HUGE = "9" * 5000
    DEEP = "[" + "{\"a\":" * 3000 + "1" + "}" * 3000 + "]"

    def _make_fake(self, inspect_out=None, images_out=None):
        def fake(*args, timeout=None):
            a = list(args)
            if a and a[0] == "ps":
                return 0, ("id\tweb\timg\trunning\tUp\t0.0.0.0:80->80/tcp\t"
                           "proj\tsvc\t12MB"), ""
            if a and a[0] == "stats":
                return 0, "web\t1%\t1MiB / 2MiB\t50%\t1B/2B\t3B/4B", ""
            if a and a[0] == "images":
                return 0, images_out if images_out is not None else \
                    '{"Repository":"x","Tag":"y"}', ""
            if a and a[0] == "inspect":
                return 0, inspect_out if inspect_out is not None else \
                    '[{"Name":"/web","Config":{"Image":"img"}}]', ""
            return 0, "", ""
        return fake

    def _get_containers(self, inspect_out, label):
        with (
            mock.patch.object(containers_svc, "docker",
                              side_effect=self._make_fake(inspect_out=inspect_out)),
            mock.patch.object(containers_svc, "engine_up", return_value=True),
        ):
            containers_svc.invalidate_container_lists()
            try:
                self.assert_clean(_client().get("/api/containers"), label)
            finally:
                containers_svc.invalidate_container_lists()

    def _get_images(self, images_out, label):
        fake = self._make_fake(images_out=images_out)
        with (
            mock.patch.object(docker_cli, "docker", side_effect=fake),
            mock.patch.object(containers_svc, "docker", side_effect=fake),
            mock.patch.object(containers_svc, "engine_up", return_value=True),
        ):
            self.assert_clean(_client().get("/api/images"), label)

    def test_pathological_inspect_json_never_500(self):
        cases = {
            "huge_int": '[{"Name":"/web","Config":{"Image":"img"},"SizeRootFs":'
                        + self.HUGE + '}]',
            "Infinity": '[{"Name":"/web","Config":{"Image":"img"},"X":Infinity}]',
            "NaN": '[{"Name":"/web","Config":{"Image":"img"},"X":NaN}]',
            "surrogate": '[{"Name":"/web","Config":{"Image":"img"},'
                         '"note":"a\\ud800b"}]',
            "deep": self.DEEP,
            "torn": '[{"Name":"/web","Confi',
            "not_list": '{"Name":"/web","Config":{"Image":"img"}}',
            "huge_in_restart": '[{"Name":"/web","Config":{"Image":"img"},'
                               '"HostConfig":{"RestartPolicy":{"Name":"always",'
                               '"MaximumRetryCount":' + self.HUGE + '}}}]',
        }
        for name, out in cases.items():
            with self.subTest(case=name):
                self._get_containers(out, f"inspect:{name}")

    def test_pathological_images_json_never_500(self):
        cases = {
            "huge_int": '{"Repository":"x","Tag":"y","Size":' + self.HUGE + '}',
            "Infinity": '{"Repository":"x","VirtualSize":Infinity}',
            "surrogate": '{"Repository":"a\\ud800b"}',
            "ndjson_huge": '{"Repository":"x"}\n{"Repository":"y","Size":'
                           + self.HUGE + '}',
        }
        for name, out in cases.items():
            with self.subTest(case=name):
                self._get_images(out, f"images:{name}")


class UpdateStatusOnDiskBombPins(_Harness):
    """Poisoned docker-update-status.json cannot 500 GET /api/containers.

    The enrichment reads it through ``read_text_capped`` + ``safe_json_loads``
    (``parse_int_capped``) + ``_jsonable``.
    """

    def _fake(self, *args, timeout=None):
        return _fake_docker(*args, timeout=timeout)

    def _with_status(self, content, label):
        path = containers_svc.UPDATE_STATUS_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        prior = path.read_bytes() if path.exists() else None
        try:
            path.write_bytes(content if isinstance(content, bytes)
                             else content.encode("utf-8"))
            with (
                mock.patch.object(containers_svc, "docker", side_effect=self._fake),
                mock.patch.object(containers_svc, "engine_up", return_value=True),
            ):
                containers_svc.invalidate_container_lists()
                try:
                    self.assert_clean(_client().get("/api/containers"), label)
                finally:
                    containers_svc.invalidate_container_lists()
        finally:
            if prior is not None:
                path.write_bytes(prior)
            else:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass

    def test_poisoned_update_status_never_500(self):
        huge = "9" * 5000
        cases = {
            "ok": '{"img":{"status":"true","update":true},"_checked_at":"now"}',
            "huge_int": '{"img":{"status":' + huge + '}}',
            "surrogate": '{"img":{"note":"a\\ud800b"}}',
            "Infinity": '{"img":Infinity}',
            "non_utf8": b'\xff\xfe not utf8',
        }
        for name, content in cases.items():
            with self.subTest(case=name):
                self._with_status(content, f"upd:{name}")


class JobStoreSubclassAndMutexPins(_Harness):
    """dict-subclass ``_cjobs`` rows and a bomb ``running`` stay immune.

    docker6 pinned the plain-dict poisoned rows; these pin the row itself
    being a method-bombing *subclass* (``_plain_job``'s C-level copy) and a
    ``__bool__``-bomb ``running`` reached through the single-runner mutex on
    POST /api/stacks/{id}/run (``_row_running`` → ``_truthy``).
    """

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

    class RowGetBomb(dict):
        def get(self, *a, **k):
            raise RuntimeError("row get bomb")

    class RowItemsBomb(dict):
        def items(self):
            raise RuntimeError("row items bomb")

    class RowBoolBomb(dict):
        def __bool__(self):
            raise RuntimeError("row bool bomb")

    def test_dict_subclass_job_rows_never_500(self):
        c = _client()
        for cls in (self.RowGetBomb, self.RowItemsBomb, self.RowBoolBomb):
            with self.subTest(bomb=cls.__name__):
                containers_svc._cjobs.clear()
                containers_svc._cjobs["job1"] = cls(self._row())
                for url in ("/api/stacks/jobs/job1", "/api/stacks",
                            "/api/stacks/jobs/other"):
                    self.assert_clean(c.get(url), f"{cls.__name__} {url}")

    def test_poisoned_running_row_keeps_mutex_scan_alive(self):
        cfg_value = {"stacks": [{"id": "web", "path": "/tmp/x",
                                 "containers": ["a"]}]}
        rows = (
            ("get", self.RowGetBomb(self._row(running=True))),
            ("bool", self.RowBoolBomb(self._row(running=True))),
            ("running", self._row(running=BoolBomb())),
        )
        for name, row in rows:
            with self.subTest(bomb=name):
                containers_svc._cjobs.clear()
                containers_svc._cjobs["old"] = row
                with (
                    mock.patch.object(containers_svc, "docker",
                                      side_effect=_fake_docker),
                    mock.patch.object(containers_svc, "engine_up",
                                      return_value=True),
                    mock.patch.object(containers_svc, "cfg",
                                      return_value=cfg_value),
                    mock.patch.object(config, "cfg", return_value=cfg_value),
                ):
                    r = _client().post("/api/stacks/web/run",
                                       json={"action": "up"})
                self.assert_clean(r, f"mutex {name}")


if __name__ == "__main__":
    unittest.main()
