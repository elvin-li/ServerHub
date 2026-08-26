"""Sixth leftover-500s sweep of the PhotosHub/Immich surfaces: subclass bombs
in the two service sanitizers, over the real mounted app.

photos/photos2/…/photos5 closed the surrogate, over-cap-int, torn-IPv6,
FIFO-hang, vanished-CLI and adversarial-Immich-body classes.  This sweep
re-drove the surfaces with the *subclass bomb* classes (the modules5 / dash6
/ files9 convention) through the seams the existing tests already use as
leftover ingress, and found two live leftovers in the sanitizers that still
carried only the bound (photos-era) probes:

* ``photoshub_svc._jsonable`` probed values through *bound* calls, so an
  int-subclass rc whose ``__str__`` raises — planted through the
  ``run_watchdog`` seam the photos4 ctl tests already patch — raised out of
  the response sweep and turned POST /api/photoshub/action into the
  catch-all coded **500** ``photoshub.action_failed``: the sanitizer built
  to prevent the 500 was what caused it.  The same bound probes blew on
  every other bomb class (float ``__eq__``, bytes/bytearray ``decode`` —
  value and key — dict ``items``, sequence ``__iter__``, getattr).
* ``immich_svc._as_text`` / ``_jsonable`` had the same bound pattern, and
  ``immich_svc``'s own docstring names the sh seam as its leftover ingress
  ("docker ps / ping leftovers: bytes used to TypeError…").  A
  bytes-*subclass* ``decode`` bomb from that same seam raised out of
  ``run_checks``; ``health_svc._immich_checks`` then collapsed the whole
  Immich block of GET /api/health/checks into ONE "check failed" warn row —
  containers, web, worker, ML, valkey, PG18, shim and keepalive all wiped
  with the poisoned field.

The fix routes both sanitizers through unbound base-type calls
(``int.__index__``, ``float.__float__``, ``bytes``/``bytearray.decode``,
``dict.items``, ``base.__iter__``, guarded getattr — the modules5
convention), so the poison is scrubbed field-level and the real content
survives: the rc keeps its number, the container status still decodes, and
the sane sibling checks outlive the bombed one.
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

from hub import health_svc, immich_svc, photoshub_svc  # noqa: E402

#: Built arithmetically: int("9" * 5000) itself trips the digit cap.
_HUGE_INT = 10 ** 5000

_APP = None


def _client():
    global _APP
    from fastapi.testclient import TestClient
    from hub.auth import require_auth

    if _APP is None:
        from hub.app_factory import create_app

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    # raise_server_exceptions=False: a real 500 must arrive as HTTP 500, not
    # as a re-raised exception that would mask which route crashed.
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _IntStrBomb(int):
    def __str__(self):
        raise RuntimeError("int str bomb")

    __repr__ = __str__


class _FloatEqBomb(float):
    def __eq__(self, other):
        raise RuntimeError("float eq bomb")

    def __ne__(self, other):
        raise RuntimeError("float ne bomb")

    __hash__ = float.__hash__


class _BytesDecodeBomb(bytes):
    def decode(self, *args, **kwargs):
        raise RuntimeError("bytes decode bomb")


class _BytearrayDecodeBomb(bytearray):
    def decode(self, *args, **kwargs):
        raise RuntimeError("bytearray decode bomb")


class _ItemsBomb(dict):
    def items(self):
        raise RuntimeError("items bomb")


class _TriplesItems(dict):
    def items(self):
        return [("a", 1, 2)]  # unpack ValueError in ``for k, v in ...``


class _IterBombList(list):
    def __iter__(self):
        raise RuntimeError("list iter bomb")


class _GetattrBomb:
    def __getattr__(self, name):
        raise RuntimeError(f"getattr bomb: {name}")


class BombRcActionHttpTests(unittest.TestCase):
    """The reproduced photoshub leftover: POST action 500'd on a bomb rc."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="photos6-bomb-2ab7-"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.hub = self.tmp / "PhotosHub"
        (self.hub / "config").mkdir(parents=True)
        (self.hub / "state").mkdir()
        (self.hub / "bin").mkdir()
        self.photoctl = self.hub / "bin" / "photoctl"
        self.photoctl.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.photoctl.chmod(0o755)
        for patched in (
            mock.patch.object(photoshub_svc, "HUB", self.hub),
            mock.patch.object(photoshub_svc, "CFG_PATH",
                              self.hub / "config" / "config.json"),
            mock.patch.object(photoshub_svc, "STATE", self.hub / "state"),
            mock.patch.object(photoshub_svc, "BIN_PHOTOCTL", self.photoctl),
            mock.patch.object(photoshub_svc, "SCRIPTS", self.hub / "scripts"),
        ):
            patched.start()
            self.addCleanup(patched.stop)
        self.client = _client()

    def _post(self, rc):
        with mock.patch.object(photoshub_svc, "run_watchdog", return_value=rc):
            return self.client.post(
                "/api/photoshub/action", json={"action": "status"},
            )

    def test_int_subclass_str_bomb_rc_keeps_the_raw_200_shape(self):
        # Pre-fix: the coded 500 photoshub.action_failed ("int str bomb").
        resp = self._post(_IntStrBomb(3))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        out = resp.json()
        _starlette(out)
        self.assertFalse(out["ok"])
        self.assertEqual(out["exit_code"], 3)

    def test_overcap_rc_wearing_the_bomb_subclass_still_drops(self):
        # Coercion cannot resurrect the unrenderable: past CPython's digit
        # cap the rc drops exactly like its plain-int sibling.
        resp = self._post(_IntStrBomb(_HUGE_INT))
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        out = resp.json()
        _starlette(out)
        self.assertIsNone(out["exit_code"])

    def test_a_plain_rc_still_reports_its_exit_code(self):
        resp = self._post(2)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["exit_code"], 2)


class _ImmichShSeamSandbox(unittest.TestCase):
    """immich_svc.run_checks with the sh / probe seams pinned deterministic."""

    def _run(self, ps_out):
        with (
            mock.patch.object(immich_svc, "sh", return_value=(0, ps_out, "")),
            mock.patch.object(immich_svc, "engine_up", return_value=True),
            mock.patch.object(immich_svc, "port_open", return_value=False),
            mock.patch.object(
                immich_svc, "loaded_labels", return_value=frozenset(),
            ),
            mock.patch.object(
                immich_svc, "_http", return_value=(None, "refused"),
            ),
        ):
            immich_svc.run_checks.cache_clear()
            self.addCleanup(immich_svc.run_checks.cache_clear)
            return immich_svc.run_checks(force=True)


class BytesBombWipedImmichHealthTests(_ImmichShSeamSandbox):
    """The reproduced immich leftover: one decode bomb wiped every check."""

    def test_bytes_subclass_ps_output_keeps_every_check_row(self):
        # Pre-fix: run_checks raised RuntimeError("bytes decode bomb") and
        # health_svc collapsed the whole block to one "check failed" row.
        snap = self._run(_BytesDecodeBomb(b"running\thealthy Up 3 days"))
        _starlette(snap)
        ids = [c["id"] for c in snap["checks"]]
        self.assertIn("immich_ct_immich_server", ids)
        self.assertIn("immich_worker", ids)
        self.assertIn("immich_keepalive", ids)
        server = next(
            c for c in snap["checks"] if c["id"] == "immich_ct_immich_server"
        )
        self.assertEqual(server["detail"], "healthy Up 3 days")
        self.assertTrue(server["ok"])

    def test_bytearray_bomb_ps_output_keeps_every_check_row(self):
        snap = self._run(_BytearrayDecodeBomb(b"exited\tExited (1)"))
        _starlette(snap)
        server = next(
            c for c in snap["checks"] if c["id"] == "immich_ct_immich_server"
        )
        self.assertFalse(server["ok"])
        self.assertEqual(server["detail"], "Exited (1)")

    def test_plain_ps_output_still_reads_the_same(self):
        snap = self._run("running\thealthy Up 3 days")
        server = next(
            c for c in snap["checks"] if c["id"] == "immich_ct_immich_server"
        )
        self.assertTrue(server["ok"])

    def test_health_checks_route_keeps_the_immich_rows(self):
        """The wipe as the operator saw it: GET /api/health/checks."""
        client = _client()
        with (
            mock.patch.object(
                immich_svc, "sh",
                return_value=(0, _BytesDecodeBomb(b"running\tUp 2 days"), ""),
            ),
            mock.patch.object(immich_svc, "engine_up", return_value=True),
            mock.patch.object(immich_svc, "port_open", return_value=False),
            mock.patch.object(
                immich_svc, "loaded_labels", return_value=frozenset(),
            ),
            mock.patch.object(
                immich_svc, "_http", return_value=(None, "refused"),
            ),
        ):
            immich_svc.run_checks.cache_clear()
            self.addCleanup(immich_svc.run_checks.cache_clear)
            saved = dict(health_svc._cache)
            health_svc._cache.update(t=0.0, v=None)
            self.addCleanup(lambda: health_svc._cache.update(saved))
            resp = client.get("/api/health/checks")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        _starlette(body)
        ids = [c.get("id") for c in body["checks"]]
        # Pre-fix the block was ONE collapsed row: id="immich", "check failed".
        self.assertIn("immich_ct_immich_server", ids)
        self.assertIn("immich_worker", ids)
        self.assertNotIn("immich", ids)


class _JsonableContractTests:
    """The sanitizer contract both modules share: never raise, keep content."""

    mod = None

    def _js(self, value):
        return self.mod._jsonable({"wrap": value})["wrap"]

    def test_int_str_bomb_keeps_its_number(self):
        self.assertEqual(self._js(_IntStrBomb(3)), 3)

    def test_overcap_int_wearing_the_bomb_still_drops(self):
        self.assertIsNone(self._js(_IntStrBomb(_HUGE_INT)))

    def test_float_eq_bomb_keeps_its_value(self):
        self.assertEqual(self._js(_FloatEqBomb(1.5)), 1.5)

    def test_inf_wearing_the_eq_bomb_still_drops(self):
        self.assertIsNone(self._js(_FloatEqBomb(float("inf"))))

    def test_bytes_decode_bomb_value_still_decodes(self):
        self.assertEqual(self._js(_BytesDecodeBomb(b"panel\xff")), "panel\ufffd")

    def test_bytearray_decode_bomb_value_still_decodes(self):
        self.assertEqual(self._js(_BytearrayDecodeBomb(b"p")), "p")

    def test_bytes_decode_bomb_key_still_decodes(self):
        out = self.mod._jsonable({_BytesDecodeBomb(b"k"): 1})
        self.assertEqual(out, {"k": 1})

    def test_dict_items_bomb_keeps_the_real_entries(self):
        self.assertEqual(self._js(_ItemsBomb(a=1)), {"a": 1})

    def test_torn_pair_items_cannot_bomb_the_walk(self):
        # dict.items(value) reads the C-level storage, so the overridden
        # triple-yielding items() never runs.
        self.assertEqual(self._js(_TriplesItems(a=1)), {"a": 1})

    def test_list_iter_bomb_keeps_the_real_elements(self):
        self.assertEqual(self._js(_IterBombList([1, 2])), [1, 2])

    def test_getattr_bomb_degrades_to_text(self):
        out = self._js(_GetattrBomb())
        self.assertIsInstance(out, str)

    def test_nested_bomb_scrubs_field_level(self):
        out = self._js({"sane": True, "bomb": [_ItemsBomb(b=2)]})
        self.assertEqual(out, {"sane": True, "bomb": [{"b": 2}]})

    def test_as_text_bytes_bomb_still_decodes(self):
        self.assertEqual(self.mod._as_text(_BytesDecodeBomb(b"x")), "x")

    def test_utf8_text_bytes_bomb_still_decodes(self):
        self.assertEqual(self.mod._utf8_text(_BytesDecodeBomb(b"x")), "x")


class PhotoshubJsonableContractTests(_JsonableContractTests, unittest.TestCase):
    mod = photoshub_svc


class ImmichJsonableContractTests(_JsonableContractTests, unittest.TestCase):
    mod = immich_svc


if __name__ == "__main__":
    unittest.main()
