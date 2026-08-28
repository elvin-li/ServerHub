"""Compose leftover sweep #12: home-provider and stack-row seam 500s.

A twelfth adversarial pass over the Compose surfaces (GET/PUT
/api/compose/{id}, POST /api/compose/{id}/validate, POST
/api/compose/validate, POST /api/compose) through the real ``create_app``
wiring with ``TestClient(raise_server_exceptions=False)`` found live
unhandled-500 classes on two provider seams compose11 never fed:

* **the ``user_home`` provider seam** — ``save_compose``,
  ``validate_compose_text`` and ``create_stack`` consumed the seam bare: a
  provider that *raises* escaped before any catch, and a *textual* answer
  detonated the ``home / "Services"`` joins (TypeError on
  ``str.__truediv__``) — ``validate_compose_text`` builds its default
  working directory and ``create_stack`` its stack root *outside* every
  try, so each was a raw 500 on POST /api/compose/validate and
  POST /api/compose (the backups12 / gateway12 rule).  ``_home_path`` now
  launders the seam: raise/junk degrades to None (the coded "no home"
  answers), text/bytes homes are kept as Paths;
* **the stack-listing/row seam** — ``_find_stack`` iterated
  ``_stack_paths()``'s answer raw (a raising provider, a non-list, or a
  list-subclass ``__iter__`` bomb took down every compose route; a
  non-dict row AttributeError'd the bound ``.get``; an id ``__eq__`` bomb
  detonated the match probe), and ``get_compose`` / ``_io_compose_path`` /
  ``validate_stack`` read row fields with bound ``.get`` and *bare*
  isinstance gates — a ``__class__``-property-bomb path/id/name field
  500'd GET/PUT /api/compose/{id} and POST /api/compose/{id}/validate.
  Rows now ride ``_plain_job`` + unbound ``_row_get`` + ``_disk_text``
  exact-str copies; junk rows drop (the empty-row rule) and junk fields
  fall back;
* **direct-call entry gates** — ``save_compose`` / ``create_stack``
  decoded bytes content through the *bound* ``.decode`` and probed it with
  bound ``strip`` (a bytes-subclass decode bomb / str-subclass strip bomb
  raised raw — the compose11 validate-gate rule, applied to its twins).

The compose11 union guards (``_isa``, guarded decode, ``_rc_int``,
``_disk_text``, ``_finite_mtime``, ``_utf8_text``) are re-pinned here so a
conflict resolution cannot silently weaken them.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import compose_svc, containers_svc  # noqa: E402
from hub.compose_svc import (  # noqa: E402
    _disk_text, _finite_mtime, _home_path, _row_get, _spawnable_dir, _utf8_text,
)

VALID_COMPOSE = "services:\n  web:\n    image: nginx:alpine\n"

#: >4300 digits: ``str()`` of it is itself the ValueError past CPython's cap.
_HUGE_INT = 10 ** 4400


# ── The wave-12 zoo ──────────────────────────────────────────────────────────
def _liar(claim):
    """A lying ``__class__`` impostor: passes ``_isa(x, claim)``, has none of
    the claimed type's C-level layout, so unbound base calls TypeError."""
    return type("Liar", (object,), {"__class__": property(lambda self: claim)})()


class ClassBomb:
    """``__class__`` is a raising property — detonates bare isinstance."""

    @property
    def __class__(self):  # noqa: D401
        raise RuntimeError("boom __class__")


class EqBomb:
    """An object whose ``==``/``!=`` raise — the id match-probe bomb shape."""

    def __eq__(self, other):
        raise RuntimeError("boom __eq__")

    def __ne__(self, other):
        raise RuntimeError("boom __ne__")

    def __hash__(self):
        return 3


class IntEqBomb(int):
    """int subclass whose ``==``/``!=`` raise — the rc-probe bomb shape."""

    def __eq__(self, other):
        raise RuntimeError("boom int __eq__")

    def __ne__(self, other):
        raise RuntimeError("boom int __ne__")

    def __hash__(self):
        return 7


class IntCoercionBomb(int):
    """int subclass whose coercion hooks raise — ``int(x)`` dispatches in."""

    def __int__(self):
        raise RuntimeError("boom __int__")

    def __index__(self):
        raise RuntimeError("boom __index__")


class LenBombStr(str):
    """str subclass whose ``__len__`` raises — detonates truthiness probes."""

    def __len__(self):
        raise RuntimeError("boom __len__")


class StripBombStr(str):
    """str subclass whose ``strip`` raises — the bound entry-gate probe."""

    def strip(self, *a):
        raise RuntimeError("boom strip")


class EncodeBombStr(str):
    """str subclass whose bound ``.encode`` raises a non-Unicode error."""

    def encode(self, *a, **k):
        raise RuntimeError("boom encode")


class DecodeBombBytes(bytes):
    """bytes subclass whose bound ``.decode`` raises — only the unbound base
    decode disarms it."""

    def decode(self, *a, **k):
        raise RuntimeError("boom decode")


class GetBombDict(dict):
    """dict subclass whose bound ``.get`` raises; the C storage is honest."""

    def get(self, *a, **k):
        raise RuntimeError("boom get")


class IterBombList(list):
    """list subclass whose ``__iter__`` raises mid-listing."""

    def __iter__(self):
        raise RuntimeError("boom __iter__")


class KeyEqBomb(str):
    """str-subclass KEY whose ``__eq__`` raises: on hash collision with the
    looked-up field name the reflected operand hands it priority."""

    __hash__ = str.__hash__

    def __eq__(self, other):
        raise RuntimeError("boom key __eq__")

    def __ne__(self, other):
        raise RuntimeError("boom key __ne__")


# ── Unit pins: the new funnels absorb every shape ────────────────────────────
class HomePathUnitTests(unittest.TestCase):
    def _with_home(self, **kw):
        return mock.patch.object(compose_svc, "user_home", **kw)

    def test_raising_provider_reads_none(self):
        # The bare seam call sat outside every catch in three functions.
        with self._with_home(side_effect=RuntimeError("boom home")):
            self.assertIsNone(_home_path())

    def test_real_path_passes_through(self):
        with self._with_home(return_value=Path("/tmp/h-13cb")):
            self.assertEqual(_home_path(), Path("/tmp/h-13cb"))

    def test_textual_answer_kept_as_path(self):
        # A textual answer still names a real directory (the backups12 rule).
        with self._with_home(return_value="/tmp/h-13cb"):
            self.assertEqual(_home_path(), Path("/tmp/h-13cb"))

    def test_bytes_answer_kept_as_path(self):
        with self._with_home(return_value=b"/tmp/h-13cb"):
            self.assertEqual(_home_path(), Path("/tmp/h-13cb"))

    def test_junk_answers_read_none(self):
        for junk in (None, 42, "", ClassBomb(), _liar(str), object()):
            with self.subTest(junk=type(junk).__name__):
                with self._with_home(return_value=junk):
                    self.assertIsNone(_home_path())


class RowGetUnitTests(unittest.TestCase):
    def test_plain_dict_reads(self):
        self.assertEqual(_row_get({"id": "a"}, "id"), "a")
        self.assertIsNone(_row_get({}, "id"))

    def test_get_bomb_subclass_reads_through_c_storage(self):
        # dict.get unbound bypasses the bound bomb (the docker7 convention).
        self.assertEqual(_row_get(GetBombDict({"id": "a"}), "id"), "a")

    def test_junk_rows_read_empty(self):
        for junk in (None, 42, "x", ["id"], ClassBomb(), _liar(dict)):
            with self.subTest(junk=type(junk).__name__):
                self.assertIsNone(_row_get(junk, "id"))

    def test_key_eq_bomb_collision_reads_empty_not_raises(self):
        row = {KeyEqBomb("id"): "a"}
        self.assertIsNone(_row_get(row, "id"))


class SpawnableDirUnitTests(unittest.TestCase):
    def test_exact_str_passes(self):
        self.assertEqual(_spawnable_dir("/tmp/x"), "/tmp/x")

    def test_str_subclass_launders_to_exact(self):
        for text in (LenBombStr("/tmp/x"), EncodeBombStr("/tmp/x")):
            out = _spawnable_dir(text)
            self.assertIs(type(out), str)
            self.assertEqual(out, "/tmp/x")

    def test_surrogate_still_refused(self):
        self.assertIsNone(_spawnable_dir("/tmp/\udcff"))

    def test_junk_reads_none(self):
        for junk in (None, 42, b"/tmp/x", ClassBomb(), _liar(str)):
            with self.subTest(junk=type(junk).__name__):
                self.assertIsNone(_spawnable_dir(junk))


# ── HTTP sandbox: real app wiring + a real stack on disk ─────────────────────
class _Compose12Sandbox(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        from hub.app_factory import create_app
        from hub.auth import require_auth

        cls._app = create_app()
        cls._app.dependency_overrides[require_auth] = lambda: True
        cls.client = TestClient(cls._app, raise_server_exceptions=False)

    @classmethod
    def tearDownClass(cls):
        cls._app.dependency_overrides.clear()

    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="compose12-13cb-"))
        self.addCleanup(lambda: shutil.rmtree(self.home, ignore_errors=True))
        self.stack_dir = self.home / "Services" / "app-13cb"
        self.stack_dir.mkdir(parents=True)
        self.compose_file = self.stack_dir / "docker-compose.yml"
        self.compose_file.write_text(VALID_COMPOSE)
        p = mock.patch.object(compose_svc, "user_home", return_value=self.home)
        p.start()
        self.addCleanup(p.stop)
        cp = mock.patch.object(containers_svc, "user_home", return_value=self.home)
        cp.start()
        self.addCleanup(cp.stop)

    def _assert_renders(self, resp):
        self.assertLess(resp.status_code, 500, resp.text)
        self.assertNotIn("\ud800", json.dumps(resp.json()))
        return resp

    def _put(self, extra="# w\n", check=False):
        return self.client.put(
            "/api/compose/app-13cb",
            content=json.dumps({"content": VALID_COMPOSE + extra, "check": check}),
            headers={"Content-Type": "application/json"},
        )

    def _good_row(self):
        return {
            "id": "app-13cb",
            "name": "app-13cb",
            "path": str(self.stack_dir),
            "compose_file": "docker-compose.yml",
            "compose_path": str(self.compose_file),
            "os_path": str(self.stack_dir),
            "os_compose_path": str(self.compose_file),
            "containers": [],
            "source": "config",
        }


class HomeSeamHttpTests(_Compose12Sandbox):
    """user_home provider bombs degrade to the coded answers, never 500."""

    def _with_home(self, **kw):
        return mock.patch.object(compose_svc, "user_home", **kw)

    def _with_ok_run(self):
        return mock.patch.object(compose_svc, "run_capped", return_value=(0, ""))

    def test_raising_home_provider_never_500s(self):
        # The seam call sat outside every catch in save/validate/create.
        with self._with_home(side_effect=RuntimeError("boom home")):
            put = self._assert_renders(self._put())
            self.assertEqual(put.status_code, 400)
            self.assertEqual(
                put.json()["detail"]["code"], "container.no_compose_file"
            )
            v = self._assert_renders(self.client.post(
                "/api/compose/validate", json={"content": VALID_COMPOSE},
            ))
            self.assertEqual(v.status_code, 200)
            self.assertFalse(v.json().get("ok"))
            create = self._assert_renders(self.client.post(
                "/api/compose", json={"id": "new-13cb", "content": VALID_COMPOSE},
            ))
            self.assertEqual(create.status_code, 400)
            self.assertEqual(create.json()["detail"]["code"], "compose.invalid")

    def test_textual_home_still_serves_the_save(self):
        # Text names the same real directory — the save must keep working.
        with self._with_home(return_value=str(self.home)):
            resp = self._put(extra="# text-home\n")
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(
            self.compose_file.read_text(), VALID_COMPOSE + "# text-home\n"
        )

    def test_bytes_home_still_serves_the_save(self):
        with self._with_home(return_value=str(self.home).encode()):
            resp = self._put(extra="# bytes-home\n")
        self.assertEqual(resp.status_code, 200, resp.text)

    def test_textual_home_still_serves_create_and_validate(self):
        with self._with_home(return_value=str(self.home)), self._with_ok_run():
            v = self._assert_renders(self.client.post(
                "/api/compose/validate", json={"content": VALID_COMPOSE},
            ))
            self.assertEqual(v.status_code, 200)
            self.assertTrue(v.json().get("ok"))
            create = self._assert_renders(self.client.post(
                "/api/compose", json={"id": "new-13cb", "content": VALID_COMPOSE},
            ))
        shutil.rmtree(self.home / "Services" / "new-13cb", ignore_errors=True)
        self.assertEqual(create.status_code, 200, create.text)

    def test_junk_home_shapes_never_500(self):
        for junk in (42, ClassBomb(), _liar(str), object()):
            with self.subTest(junk=type(junk).__name__):
                with self._with_home(return_value=junk):
                    put = self._assert_renders(self._put())
                    self.assertEqual(put.status_code, 400)
                    v = self._assert_renders(self.client.post(
                        "/api/compose/validate", json={"content": VALID_COMPOSE},
                    ))
                    self.assertEqual(v.status_code, 200)
                    self.assertFalse(v.json().get("ok"))
                    create = self._assert_renders(self.client.post(
                        "/api/compose",
                        json={"id": "new-13cb", "content": VALID_COMPOSE},
                    ))
                    self.assertEqual(create.status_code, 400)


class StackRowSeamHttpTests(_Compose12Sandbox):
    """Junk riding the stack-listing seam drops, falls back, never 500s."""

    def _with_rows(self, **kw):
        return mock.patch.object(compose_svc, "_stack_paths", **kw)

    def test_raising_listing_provider_answers_404(self):
        with self._with_rows(side_effect=RuntimeError("boom listing")):
            for resp in (
                self.client.get("/api/compose/app-13cb"),
                self._put(),
                self.client.post("/api/compose/app-13cb/validate"),
            ):
                self._assert_renders(resp)
                self.assertEqual(resp.status_code, 404)
                self.assertEqual(
                    resp.json()["detail"]["code"], "compose.unknown_stack"
                )

    def test_non_list_listing_answers_404(self):
        for junk in (None, 42, "rows", ClassBomb(), _liar(list), {"id": "x"}):
            with self.subTest(junk=type(junk).__name__):
                with self._with_rows(return_value=junk):
                    resp = self._assert_renders(
                        self.client.get("/api/compose/app-13cb")
                    )
                self.assertEqual(resp.status_code, 404)

    def test_iter_bomb_listing_answers_404(self):
        with self._with_rows(return_value=IterBombList([self._good_row()])):
            resp = self._assert_renders(self.client.get("/api/compose/app-13cb"))
        self.assertEqual(resp.status_code, 404)

    def test_junk_rows_drop_and_the_honest_row_still_matches(self):
        rows = [
            None, 42, "row", ["id"], ClassBomb(), _liar(dict),
            {"id": EqBomb()}, {"id": ClassBomb()}, self._good_row(),
        ]
        with self._with_rows(return_value=rows):
            resp = self._assert_renders(self.client.get("/api/compose/app-13cb"))
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json().get("content"), VALID_COMPOSE)

    def test_eq_bomb_id_alone_answers_404_not_500(self):
        with self._with_rows(return_value=[{"id": EqBomb()}]):
            resp = self._assert_renders(self.client.get("/api/compose/app-13cb"))
        self.assertEqual(resp.status_code, 404)

    def test_get_bomb_dict_subclass_row_still_readable(self):
        # _plain_job's C-level copy disarms the bound bomb; the row serves.
        with self._with_rows(return_value=[GetBombDict(self._good_row())]):
            resp = self._assert_renders(self.client.get("/api/compose/app-13cb"))
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json().get("content"), VALID_COMPOSE)

    def test_key_eq_bomb_key_row_still_matches(self):
        row = self._good_row()
        del row["id"]
        row[KeyEqBomb("id")] = "app-13cb"
        with self._with_rows(return_value=[row]):
            resp = self._assert_renders(self.client.get("/api/compose/app-13cb"))
        self.assertEqual(resp.status_code, 200, resp.text)

    def test_bomb_os_compose_path_falls_back_to_published_twin(self):
        for bomb in (ClassBomb(), _liar(str), 42, EqBomb()):
            with self.subTest(bomb=type(bomb).__name__):
                row = self._good_row()
                row["os_compose_path"] = bomb
                with self._with_rows(return_value=[row]):
                    resp = self._assert_renders(
                        self.client.get("/api/compose/app-13cb")
                    )
                self.assertEqual(resp.status_code, 200, resp.text)
                self.assertEqual(resp.json().get("content"), VALID_COMPOSE)

    def test_len_bomb_str_subclass_path_launders_and_serves(self):
        row = self._good_row()
        row["os_compose_path"] = LenBombStr(str(self.compose_file))
        with self._with_rows(return_value=[row]):
            resp = self._assert_renders(self.client.get("/api/compose/app-13cb"))
        self.assertEqual(resp.status_code, 200, resp.text)

    def test_all_junk_path_fields_answer_coded_400(self):
        row = self._good_row()
        row["os_compose_path"] = ClassBomb()
        row["compose_path"] = 42
        with self._with_rows(return_value=[row]):
            get = self._assert_renders(self.client.get("/api/compose/app-13cb"))
            put = self._assert_renders(self._put())
        for resp in (get, put):
            self.assertEqual(resp.status_code, 400)
            self.assertEqual(
                resp.json()["detail"]["code"], "container.no_compose_file"
            )

    def test_bomb_name_and_path_fields_render_with_fallbacks(self):
        row = self._good_row()
        row["name"] = ClassBomb()
        row["path"] = _liar(str)
        with self._with_rows(return_value=[row]):
            resp = self._assert_renders(self.client.get("/api/compose/app-13cb"))
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json().get("name"), "app-13cb")
        self.assertIsNone(resp.json().get("path"))

    def test_validate_stack_bomb_os_path_falls_back(self):
        row = self._good_row()
        row["os_path"] = ClassBomb()
        with self._with_rows(return_value=[row]), \
                mock.patch.object(compose_svc, "run_capped", return_value=(0, "")):
            resp = self._assert_renders(
                self.client.post("/api/compose/app-13cb/validate")
            )
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertTrue(resp.json().get("ok"))

    def test_save_still_writes_through_the_laundered_row(self):
        with self._with_rows(return_value=[GetBombDict(self._good_row())]):
            resp = self._put(extra="# row\n")
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(
            self.compose_file.read_text(), VALID_COMPOSE + "# row\n"
        )


class DirectCallGateTests(_Compose12Sandbox):
    """The save/create content entry gates absorb bombs (direct-call seam)."""

    def test_decode_bomb_bytes_content_saves_through_unbound_decode(self):
        out = compose_svc.save_compose(
            "app-13cb", DecodeBombBytes(VALID_COMPOSE.encode()), validate=False
        )
        self.assertTrue(out.get("ok"))
        self.assertEqual(self.compose_file.read_text(), VALID_COMPOSE)

    def test_strip_bomb_str_subclass_content_saves(self):
        out = compose_svc.save_compose(
            "app-13cb", StripBombStr(VALID_COMPOSE), validate=False
        )
        self.assertTrue(out.get("ok"))

    def test_junk_content_answers_coded_400_not_raise(self):
        for junk in (None, 42, ClassBomb(), _liar(str)):
            with self.subTest(junk=type(junk).__name__):
                try:
                    compose_svc.save_compose("app-13cb", junk, validate=False)
                except Exception as e:
                    self.assertEqual(getattr(e, "status_code", None), 400, e)
                else:
                    self.fail("junk content must refuse with the coded 400")

    def test_create_stack_decode_bomb_content_creates(self):
        with mock.patch.object(compose_svc, "run_capped", return_value=(0, "")):
            out = compose_svc.create_stack(
                "new-13cb", None, DecodeBombBytes(VALID_COMPOSE.encode())
            )
        self.addCleanup(lambda: shutil.rmtree(
            self.home / "Services" / "new-13cb", ignore_errors=True
        ))
        self.assertTrue(out.get("ok"))

    def test_create_stack_junk_content_answers_coded_400(self):
        try:
            compose_svc.create_stack("new2-13cb", None, ClassBomb())
        except Exception as e:
            self.assertEqual(getattr(e, "status_code", None), 400, e)
        else:
            self.fail("junk content must refuse with the coded 400")


class ConflictGuardPins(_Compose12Sandbox):
    """Do-not-weaken re-pins of the compose10/11 union guards."""

    def test_rc_int_junk_clamps_to_minus_255_never_minus_one(self):
        from hub.docker_cli import _rc_int
        for junk in (ClassBomb(), _liar(int), _HUGE_INT, "boom", None):
            with self.subTest(junk=type(junk).__name__):
                self.assertEqual(_rc_int(junk), -255)
        self.assertEqual(_rc_int(IntEqBomb(-1)), -1)

    def test_disk_text_exact_copy_and_junk_none(self):
        out = _disk_text(LenBombStr("x"))
        self.assertIs(type(out), str)
        self.assertEqual(out, "x")
        self.assertEqual(_disk_text(DecodeBombBytes(b"ab")), "ab")
        for junk in (None, 42, ClassBomb(), _liar(str), ["x"]):
            self.assertIsNone(_disk_text(junk))

    def test_finite_mtime_still_fails_closed(self):
        self.assertEqual(_finite_mtime(IntCoercionBomb(5)), 0)
        self.assertEqual(_finite_mtime(_HUGE_INT), 0)
        self.assertEqual(_finite_mtime(float("inf")), 0)
        self.assertEqual(_finite_mtime(1700000000), 1700000000)

    def test_utf8_text_still_renders_bombs_and_scrubs_surrogates(self):
        self.assertIsInstance(_utf8_text(ClassBomb()), str)
        self.assertNotIn("\ud800", _utf8_text("a\ud800b"))

    def test_validate_entry_gate_still_a_verdict(self):
        out = compose_svc.validate_compose_text(ClassBomb())
        self.assertFalse(out.get("ok"))
        self.assertIsInstance(out.get("message"), str)

    def test_raising_cfg_keeps_the_stack_listing_alive(self):
        # The try/except around cfg() inside _stack_paths stays load-bearing.
        with mock.patch.object(containers_svc, "cfg", side_effect=RuntimeError):
            rows = containers_svc._stack_paths()
        self.assertIsInstance(rows, list)

    def test_stays_immune_compose_sweep_still_clean(self):
        for resp in (
            self.client.get("/api/compose/app-13cb"),
            self.client.post("/api/compose/app-13cb/validate"),
            self._put(extra="# sweep\n"),
            self.client.post(
                "/api/compose/validate", json={"content": VALID_COMPOSE}
            ),
        ):
            self._assert_renders(resp)


if __name__ == "__main__":
    unittest.main()
