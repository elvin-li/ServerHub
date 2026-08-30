"""Compose leftover sweep #11: reader/stat-seam coercion-bomb 500s.

An eleventh adversarial pass over the Compose/stacks surfaces (GET
/api/stacks, GET/PUT /api/compose/{id}, POST /api/compose/{id}/validate,
POST /api/compose/validate, POST /api/compose, POST /api/stacks/{id}/run,
GET /api/stacks/jobs/{id}) through the real ``create_app`` wiring with
``TestClient(raise_server_exceptions=False)`` found live unhandled-500
classes on the two provider seams compose4/compose9 already treated as
poisonable (``Path.stat`` and ``read_text_capped``) but only ever fed with
*plain* junk — never with wave-10/11 coercion bombs:

* **``st_mtime`` raising-property stat wrappers** — ``get_compose`` read
  ``st.st_mtime`` one line *outside* its try, so a leftover FUSE/SMB stat
  result whose ``st_mtime`` is a raising property 500'd the read after the
  compose text was already in hand;
* **int-/float-subclass ``st_mtime`` coercion bombs** — ``_finite_mtime``
  caught only ``(TypeError, ValueError, OverflowError, OSError)``, but
  ``int(...)`` dispatches into the subclass's ``__int__`` / ``__index__`` /
  ``__trunc__``, so a hook raising RuntimeError blew straight through the
  tuple (the docker10 ``_rc_int`` rule) and 500'd GET /api/compose/{id};
* **reader-seam junk** — ``get_compose`` consumed ``read_text_capped``'s
  return raw: a str-subclass ``__len__`` bomb detonated the ``size`` probe,
  a ``__class__``-property bomb detonated ``_utf8_text``'s old bare
  ``isinstance`` entry gate, and ``save_compose`` handed a non-str return
  (bytes/None/int) to ``replace_secret_text`` inside a handler that only
  caught ``OSError`` — each one a raw 500 on GET/PUT /api/compose/{id} and
  POST /api/compose/{id}/validate;
* **runner-seam rc bombs** — ``validate_compose_text`` fed the raw
  ``run_capped`` rc to its ``== 0`` / ``== -1`` probes; an int-subclass
  ``__eq__`` bomb was only saved by the blanket except (misreporting the
  bomb's repr as a YAML error), and junk must never read as the ``-1``
  vanished-CLI sentinel — the ``_rc_int`` funnel now clamps junk to -255,
  which is no honest exit status and is distinct from every sentinel.

The fixes: ``_finite_mtime`` fails closed on *any* coercion-hook raise and
re-coerces to an exact int through the unbound base ``__index__``; the
``st_mtime`` attribute read is guarded; ``_disk_text`` launders the reader
seam once (exact-str copy through ``str.__str__``, unbound bytes decode,
junk → coded 400); ``_utf8_text`` gates through ``_isa`` with unbound
decode/encode; and the runner rc rides the docker10 ``_rc_int`` funnel.
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
from hub.compose_svc import _disk_text, _finite_mtime, _utf8_text  # noqa: E402

VALID_COMPOSE = "services:\n  web:\n    image: nginx:alpine\n"

#: >4300 digits: ``str()`` of it is itself the ValueError past CPython's cap.
_HUGE_INT = 10 ** 4400


# ── The wave-11 zoo ──────────────────────────────────────────────────────────
def _liar(claim):
    """A lying ``__class__`` impostor: passes ``_isa(x, claim)``, has none of
    the claimed type's C-level layout, so unbound base calls TypeError."""
    return type("Liar", (object,), {"__class__": property(lambda self: claim)})()


class ClassBomb:
    """``__class__`` is a raising property — detonates bare isinstance."""

    @property
    def __class__(self):  # noqa: D401
        raise RuntimeError("boom __class__")


class IntCoercionBomb(int):
    """int subclass whose coercion hooks raise — ``int(x)`` dispatches in."""

    def __int__(self):
        raise RuntimeError("boom __int__")

    def __index__(self):
        raise RuntimeError("boom __index__")


class IntEqBomb(int):
    """int subclass whose ``==``/``!=`` raise — the rc-probe bomb shape."""

    def __eq__(self, other):
        raise RuntimeError("boom int __eq__")

    def __ne__(self, other):
        raise RuntimeError("boom int __ne__")

    def __hash__(self):
        return 7


class FloatTruncBomb(float):
    """float subclass whose ``__trunc__``/``__int__`` raise."""

    def __trunc__(self):
        raise RuntimeError("boom __trunc__")

    def __int__(self):
        raise RuntimeError("boom __int__")


class SelfStrEncodeBomb(str):
    """str subclass whose ``__str__`` answers self and ``.encode`` raises —
    only an *unbound* base encode disarms it."""

    def __str__(self):
        return self

    def encode(self, *a, **k):
        raise RuntimeError("boom encode")


class LenBombStr(str):
    """str subclass whose ``__len__`` raises — detonates any ``len()`` probe."""

    def __len__(self):
        raise RuntimeError("boom __len__")


class DecodeBombBytes(bytes):
    """bytes subclass whose bound ``.decode`` raises — the unbound base
    decode must be the one that runs."""

    def decode(self, *a, **k):
        raise RuntimeError("boom decode")


class StMtimePropBomb:
    """A leftover stat wrapper whose ``st_mtime`` is a raising property."""

    st_mode = 0o100644
    st_size = 10

    @property
    def st_mtime(self):
        raise RuntimeError("boom st_mtime")


class _WrapStat:
    """A real stat result with only ``st_mtime`` replaced."""

    def __init__(self, real, mtime):
        self._real = real
        self._mtime = mtime

    def __getattr__(self, name):
        return getattr(self._real, name)

    @property
    def st_mtime(self):
        return self._mtime


# ── Unit pins: the three funnels absorb every shape ──────────────────────────
class FiniteMtimeUnitTests(unittest.TestCase):
    def test_int_coercion_bomb_reads_zero(self):
        # ``int(x)`` dispatches into the subclass hook; RuntimeError is not
        # in the old four-class tuple and used to escape as a raw 500.
        self.assertEqual(_finite_mtime(IntCoercionBomb(5)), 0)

    def test_float_trunc_bomb_reads_zero(self):
        self.assertEqual(_finite_mtime(FloatTruncBomb(5.0)), 0)

    def test_class_bomb_and_liar_read_zero(self):
        self.assertEqual(_finite_mtime(ClassBomb()), 0)
        self.assertEqual(_finite_mtime(_liar(int)), 0)

    def test_huge_already_int_reads_zero(self):
        self.assertEqual(_finite_mtime(_HUGE_INT), 0)

    def test_result_is_exact_int(self):
        class SelfIntBomb(int):
            """``__int__`` answers self: the exact-int recoercion must run so
            a subclass ``__repr__`` bomb cannot reach the JSON encoder."""

            def __int__(self):
                return self

            def __repr__(self):
                raise RuntimeError("boom __repr__")

        out = _finite_mtime(SelfIntBomb(7))
        self.assertIs(type(out), int)
        self.assertEqual(out, 7)

    def test_plain_values_unaffected(self):
        self.assertEqual(_finite_mtime(1700000000), 1700000000)
        self.assertEqual(_finite_mtime(1700000000.9), 1700000000)
        self.assertEqual(_finite_mtime(float("inf")), 0)
        self.assertEqual(_finite_mtime(None), 0)


class DiskTextUnitTests(unittest.TestCase):
    def test_exact_str_passes_through(self):
        self.assertEqual(_disk_text("services: {}"), "services: {}")

    def test_str_subclass_launders_to_exact(self):
        out = _disk_text(LenBombStr("x"))
        self.assertIs(type(out), str)
        self.assertEqual(out, "x")
        out = _disk_text(SelfStrEncodeBomb("y"))
        self.assertIs(type(out), str)
        self.assertEqual(out, "y")

    def test_bytes_decode_is_unbound(self):
        self.assertEqual(_disk_text(b"services: {}"), "services: {}")
        self.assertEqual(_disk_text(DecodeBombBytes(b"ab")), "ab")

    def test_junk_reads_none(self):
        for junk in (None, 42, ClassBomb(), _liar(str), _liar(bytes), ["x"]):
            self.assertIsNone(_disk_text(junk))


class Utf8TextUnitTests(unittest.TestCase):
    def test_class_bomb_degrades_not_raises(self):
        # The old bare ``isinstance(value, (bytes, bytearray))`` entry gate
        # read the bomb's ``__class__`` and raised; it must render instead.
        out = _utf8_text(ClassBomb())
        self.assertIsInstance(out, str)

    def test_self_str_encode_bomb_survives_unbound_encode(self):
        self.assertEqual(_utf8_text(SelfStrEncodeBomb("ok")), "ok")

    def test_decode_bomb_bytes_survive_unbound_decode(self):
        self.assertEqual(_utf8_text(DecodeBombBytes(b"ok")), "ok")

    def test_lying_impostors_degrade_to_text_not_raise(self):
        # A lying ``__class__`` is a claim, not an error (the modules8 rule):
        # the unbound decode TypeErrors and the impostor renders as its repr
        # — JSON-safe junk text rather than a raise.
        for impostor in (_liar(str), _liar(bytes)):
            out = _utf8_text(impostor)
            self.assertIsInstance(out, str)
            json.dumps(out)

    def test_surrogates_still_scrubbed(self):
        self.assertNotIn("\ud800", _utf8_text("a\ud800b"))


# ── HTTP sandbox: real app wiring + a real stack on disk ─────────────────────
class _Compose11Sandbox(unittest.TestCase):
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
        self.home = Path(tempfile.mkdtemp(prefix="compose11-7e2b-"))
        self.addCleanup(lambda: shutil.rmtree(self.home, ignore_errors=True))
        self.stack_dir = self.home / "Services" / "app-7e2b"
        self.stack_dir.mkdir(parents=True)
        (self.stack_dir / "docker-compose.yml").write_text(VALID_COMPOSE)
        p = mock.patch.object(compose_svc, "user_home", return_value=self.home)
        p.start()
        self.addCleanup(p.stop)
        cp = mock.patch.object(containers_svc, "user_home", return_value=self.home)
        cp.start()
        self.addCleanup(cp.stop)
        self._saved_jobs = dict(containers_svc._cjobs)
        containers_svc._cjobs.clear()
        self.addCleanup(self._restore_jobs)

    def _restore_jobs(self):
        containers_svc._cjobs.clear()
        containers_svc._cjobs.update(self._saved_jobs)

    def _assert_renders(self, resp):
        self.assertLess(resp.status_code, 500, resp.text)
        self.assertNotIn("\ud800", json.dumps(resp.json()))
        return resp

    def _stat_patch(self, mtime=None, prop_bomb=False):
        real_stat = Path.stat

        def fake_stat(path, *a, **k):
            st = real_stat(path, *a, **k)
            if str(path).endswith("docker-compose.yml"):
                if prop_bomb:
                    return StMtimePropBomb()
                return _WrapStat(st, mtime)
            return st

        return mock.patch.object(Path, "stat", fake_stat)


class StatSeamHttpTests(_Compose11Sandbox):
    """st_mtime coercion/property bombs degrade to ``mtime: 0``, never 500."""

    def _get(self):
        return self.client.get("/api/compose/app-7e2b")

    def test_st_mtime_property_bomb_never_500s(self):
        # ``st.st_mtime`` was read one line outside the try — a raising
        # property 500'd the read after the compose text was already in hand.
        with self._stat_patch(prop_bomb=True):
            resp = self._assert_renders(self._get())
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json().get("mtime"), 0)

    def test_int_coercion_bomb_st_mtime_reads_zero(self):
        with self._stat_patch(mtime=IntCoercionBomb(5)):
            resp = self._assert_renders(self._get())
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json().get("mtime"), 0)

    def test_float_trunc_bomb_st_mtime_reads_zero(self):
        with self._stat_patch(mtime=FloatTruncBomb(5.0)):
            resp = self._assert_renders(self._get())
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json().get("mtime"), 0)

    def test_junk_st_mtime_shapes_never_500(self):
        for name, mtime in (
            ("class-bomb", ClassBomb()),
            ("liar-int", _liar(int)),
            ("huge-int", _HUGE_INT),
            ("eq-bomb-int", IntEqBomb(5)),
        ):
            with self.subTest(shape=name):
                with self._stat_patch(mtime=mtime):
                    resp = self._assert_renders(self._get())
                self.assertEqual(resp.status_code, 200)
                json.dumps(resp.json())


class ReaderSeamHttpTests(_Compose11Sandbox):
    """Junk riding ``read_text_capped``'s return degrades, never 500s."""

    def _with_read(self, value):
        return mock.patch.object(compose_svc, "read_text_capped", return_value=value)

    def _sweep(self):
        out = []
        out.append(self.client.get("/api/compose/app-7e2b"))
        out.append(self.client.post("/api/compose/app-7e2b/validate"))
        out.append(self.client.put(
            "/api/compose/app-7e2b",
            content=json.dumps({"content": VALID_COMPOSE + "# e\n", "check": False}),
            headers={"Content-Type": "application/json"},
        ))
        for resp in out:
            self._assert_renders(resp)
        return out

    def test_len_bomb_str_subclass_text_never_500s(self):
        # ``size: len(text)`` on the raw return used to detonate the bomb.
        with self._with_read(LenBombStr(VALID_COMPOSE)):
            get, _, _ = self._sweep()
        self.assertEqual(get.status_code, 200)
        self.assertEqual(get.json().get("content"), VALID_COMPOSE)
        self.assertEqual(get.json().get("size"), len(VALID_COMPOSE))

    def test_self_str_encode_bomb_text_never_500s(self):
        with self._with_read(SelfStrEncodeBomb(VALID_COMPOSE)):
            get, _, _ = self._sweep()
        self.assertEqual(get.status_code, 200)
        self.assertEqual(get.json().get("content"), VALID_COMPOSE)

    def test_class_bomb_text_answers_coded_400_never_500(self):
        # ``_utf8_text``'s old bare isinstance entry gate read the bomb's
        # ``__class__``; the junk now reads as "no usable compose text".
        with self._with_read(ClassBomb()):
            get, validate, put = self._sweep()
        self.assertEqual(get.status_code, 400)
        self.assertEqual(
            get.json()["detail"]["code"], "container.no_compose_file"
        )

    def test_bytes_text_decodes_instead_of_500ing_the_save(self):
        # PUT handed the raw bytes to replace_secret_text — TypeError, not
        # OSError, escaped the backup handler.
        with self._with_read(DecodeBombBytes(VALID_COMPOSE.encode())):
            get, validate, put = self._sweep()
        self.assertEqual(get.status_code, 200)
        self.assertEqual(get.json().get("content"), VALID_COMPOSE)
        self.assertEqual(put.status_code, 200)

    def test_none_and_int_text_degrade_to_coded_4xx(self):
        for junk in (None, 42):
            with self.subTest(junk=junk):
                with self._with_read(junk):
                    get, validate, put = self._sweep()
                self.assertEqual(get.status_code, 400)
                # The save skips the unusable backup and still succeeds.
                self.assertEqual(put.status_code, 200)

    def test_save_still_writes_through_junk_backup_read(self):
        with self._with_read(ClassBomb()):
            resp = self.client.put(
                "/api/compose/app-7e2b",
                content=json.dumps({"content": VALID_COMPOSE + "# w\n", "check": False}),
                headers={"Content-Type": "application/json"},
            )
        self.assertEqual(resp.status_code, 200, resp.text)
        on_disk = (self.stack_dir / "docker-compose.yml").read_text()
        self.assertEqual(on_disk, VALID_COMPOSE + "# w\n")


class RunnerRcHttpTests(_Compose11Sandbox):
    """rc bombs from the compose-config runner degrade through ``_rc_int``."""

    def _with_run(self, ret):
        return mock.patch.object(compose_svc, "run_capped", return_value=ret)

    def test_rc_eq_bomb_is_a_verdict_not_a_500(self):
        # The bomb used to be saved only by the blanket except, misreporting
        # its repr as the YAML error; _rc_int launders it before the probes.
        with self._with_run((IntEqBomb(1), "boom output")):
            resp = self._assert_renders(
                self.client.post("/api/compose/validate", json={"content": VALID_COMPOSE})
            )
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.json().get("ok"))

    def test_rc_eq_bomb_carrying_minus_one_keeps_sentinel_semantics(self):
        # int.__index__ reads the honest value through the bomb: a real -1
        # sentinel stays -1 (vanished-CLI classification still possible).
        from hub.docker_cli import _rc_int
        self.assertEqual(_rc_int(IntEqBomb(-1)), -1)

    def test_junk_rc_never_misreads_as_vanished_cli(self):
        # A liar rc with the exact "not found" sentinel text must not fake
        # the vanished-CLI 503: junk clamps to -255, never the -1 sentinel.
        with self._with_run((_liar(int), "not found")), \
                mock.patch.object(compose_svc, "cli_on_disk", return_value=False), \
                mock.patch.object(compose_svc, "engine_up", return_value=False):
            resp = self._assert_renders(
                self.client.post("/api/compose/validate", json={"content": VALID_COMPOSE})
            )
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.json().get("ok"))
        self.assertNotEqual(resp.json().get("code"), "container.engine_down")

    def test_real_vanished_cli_still_answers_engine_down_503(self):
        # The compose4 contract stays: honest (-1, "not found") with the
        # binary confirmed gone from disk and the engine down is a coded 503.
        with self._with_run((-1, "not found")), \
                mock.patch.object(compose_svc, "cli_on_disk", return_value=False), \
                mock.patch.object(compose_svc, "engine_up", return_value=False):
            resp = self.client.put(
                "/api/compose/app-7e2b",
                content=json.dumps({"content": VALID_COMPOSE, "check": True}),
                headers={"Content-Type": "application/json"},
            )
        self.assertEqual(resp.status_code, 503, resp.text)
        self.assertEqual(resp.json()["detail"]["code"], "container.engine_down")

    def test_vanished_cli_with_docker_still_on_disk_is_engine_down_503(self):
        # GitHub runners keep a docker binary; leftover HTTP used to skip
        # the keep-the-stack path (catalog install/uninstall).
        with self._with_run((-1, "not found")), \
                mock.patch.object(compose_svc, "cli_on_disk", return_value=True), \
                mock.patch.object(compose_svc, "engine_up", return_value=False):
            resp = self.client.put(
                "/api/compose/app-7e2b",
                content=json.dumps({"content": VALID_COMPOSE, "check": True}),
                headers={"Content-Type": "application/json"},
            )
        self.assertEqual(resp.status_code, 503, resp.text)
        self.assertEqual(resp.json()["detail"]["code"], "container.engine_down")

    def test_junk_rc_shapes_never_500_validate_save_create(self):
        shapes = (
            ("class-bomb", ClassBomb()),
            ("liar-bool", _liar(bool)),
            ("huge-int", _HUGE_INT),
            ("str-bomb-rc", SelfStrEncodeBomb("0")),
        )
        for name, rc in shapes:
            with self.subTest(shape=name):
                with self._with_run((rc, "output")):
                    self._assert_renders(self.client.post(
                        "/api/compose/validate", json={"content": VALID_COMPOSE},
                    ))
                    self._assert_renders(self.client.put(
                        "/api/compose/app-7e2b",
                        content=json.dumps({"content": VALID_COMPOSE, "check": True}),
                        headers={"Content-Type": "application/json"},
                    ))
                    self._assert_renders(self.client.post(
                        "/api/compose",
                        json={"id": "new-7e2b", "content": VALID_COMPOSE},
                    ))
                shutil.rmtree(self.home / "Services" / "new-7e2b", ignore_errors=True)


class ValidateEntryGateTests(_Compose11Sandbox):
    """The validate entry gate itself is guarded (direct-call seam)."""

    def test_class_bomb_content_is_a_verdict_not_a_raise(self):
        out = compose_svc.validate_compose_text(ClassBomb())
        self.assertFalse(out.get("ok"))
        self.assertIsInstance(out.get("message"), str)

    def test_lying_str_impostor_content_is_a_verdict(self):
        out = compose_svc.validate_compose_text(_liar(str))
        self.assertFalse(out.get("ok"))

    def test_class_bomb_yaml_doc_is_a_verdict_not_a_raise(self):
        """yaml.safe_load answering a leftover whose ``__class__`` raises
        used to 500 at the bare ``isinstance(doc, dict)`` gate."""
        with mock.patch.object(compose_svc.yaml, "safe_load", return_value=ClassBomb()):
            out = compose_svc.validate_compose_text(VALID_COMPOSE)
        self.assertFalse(out.get("ok"))
        self.assertIsInstance(out.get("message"), str)

    def test_stays_immune_stack_sweep_still_clean(self):
        # The whole compose surface stays sub-500 with the fixes in place.
        for resp in (
            self.client.get("/api/stacks"),
            self.client.get("/api/compose/app-7e2b"),
            self.client.post("/api/compose/app-7e2b/validate"),
            self.client.post("/api/stacks/app-7e2b/run", json={"action": "down"}),
            self.client.get("/api/stacks/jobs/app-7e2b"),
        ):
            self._assert_renders(resp)


if __name__ == "__main__":
    unittest.main()
