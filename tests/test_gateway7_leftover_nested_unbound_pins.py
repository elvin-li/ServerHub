"""Leftover Gateway-page 500s #8: the nested ranks stay sealed — pins only.

Prior sweeps sealed GET /api/nginx field by field, the pid and conf-path
shapes, the vanished-CLI classes, the runner's raise/arity/rc ranks, and —
in gateway6 — brought hub/nginx_svc.py to the modules5 unbound convention
(``int.__index__`` / ``float.__float__`` / ``dict.items(value)`` /
``base.__iter__`` / unbound base decode / unbound ``str.encode``).  A fresh
hunt over the same mounted routes fired every class this wave was scoped
for — dict-subclass ``.get``/``items``/``__bool__`` bombs, nested unbound
coercions, surrogates, already-int over-cap numbers, and huge-number JSON
bodies whose ``json.loads`` raise is ValueError, not JSONDecodeError — and
found *no remaining 500*: the unbound walk recurses, so every rank gateway6
proved at top level holds one level down and deeper.

What was never pinned is exactly that: the prior batteries held the bombs
at top-level row-value/key rank only, and a refactor that flattened the
recursion (or re-bound one call inside it) would reopen the nested ranks
without failing a single existing test.  This battery holds them at the
HTTP layer:

* nested rank — the same bomb classes one level (and three levels) down
  inside a row: an int-subclass ``__str__`` bomb and an already-int
  over-cap number inside ``listens``, items/get/bool/keys/len-bomb dict
  *values*, iter-bomb list/tuple/set/frozenset values, and a surrogate
  beside an over-cap int in one row — the real entries survive, the
  unrenderable ones drop alone;
* slot-override rank — subclasses that bomb the very slots the fix calls:
  an int subclass overriding ``__index__`` itself and a float subclass
  overriding ``__float__`` itself (the unbound base call dodges the
  override and reads the real value through it);
* bytearray rank — gateway6 proved the bytes-subclass decode bomb;
  ``_decode_bytes`` classifies on ``isinstance(value, bytes)``, so the
  bytearray subclass takes the *other* branch, at value rank and as an odd
  runner's stdout;
* pid rank — a decode-bomb bytes pid and a self-``__str__`` encode-bomb
  str pid keep reporting the truthful running state; invalid-UTF-8 bytes
  are no pid_t digits and read as not running, never a 500;
* runner rank — an ``__index__``-bomb rc at the ``-t`` spawn and at both
  reload spawns (the coercion reads the real 0 through the bomb and the
  reload still reports "Reloaded"), an object stderr whose ``__str__`` and
  ``__repr__`` both raise, invalid-UTF-8 and lone-surrogate stderr text,
  and a self-``__str__`` encode-bomb str riding through reload's message
  concat and the kickstart answer;
* body rank — the huge-number JSON body against body-less
  POST /api/nginx/reload (the /test sibling is pinned in gateway5): the
  route must never parse it, and nothing on the path may catch
  JSONDecodeError alone.

``os.kill`` does not apply here: nothing in hub/nginx_svc.py or its router
signals a pid, and the Gateway backend owns no JSON journal — its only
persistence is the audit trail, whose loader already drops unparseable
lines one at a time (hub/audit.py).
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import nginx_svc
from hub.auth import require_auth

_APP = None

#: Already past CPython's 4300-digit int->str cap; hex loads are exempt.
_BIG = int("f" * 4200, 16)


def _client() -> TestClient:
    global _APP
    if _APP is None:
        from hub.app_factory import create_app

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _StrBombInt(int):
    def __str__(self):
        raise RuntimeError("int str bomb")


class _IndexBombInt(int):
    """Overrides the very slot the fix calls; the unbound base dodges it."""

    def __index__(self):
        raise RuntimeError("index bomb")


class _FloatBombFloat(float):
    """Overrides the very slot the fix calls; the unbound base dodges it."""

    def __float__(self):
        raise RuntimeError("float bomb")


class _SelfStr(str):
    def __str__(self):
        return self

    def encode(self, *a, **k):
        raise RuntimeError("encode bomb")


class _DecodeBombBytes(bytes):
    def decode(self, *a, **k):
        raise RuntimeError("decode bomb")


class _DecodeBombBA(bytearray):
    """The branch gateway6 never exercised: not bytes, so not bytes' base."""

    def decode(self, *a, **k):
        raise RuntimeError("ba decode bomb")


class _ItemsBombDict(dict):
    def items(self):
        raise RuntimeError("items bomb")


class _GetBombDict(dict):
    def get(self, *a, **k):
        raise RuntimeError("get bomb")


class _BoolBombDict(dict):
    def __bool__(self):
        raise RuntimeError("bool bomb")


class _KeysBombDict(dict):
    def keys(self):
        raise RuntimeError("keys bomb")


class _LenBombDict(dict):
    def __len__(self):
        raise RuntimeError("len bomb")


class _IterBombList(list):
    def __iter__(self):
        raise RuntimeError("iter bomb")


class _IterBombTuple(tuple):
    def __iter__(self):
        raise RuntimeError("tuple iter bomb")


class _IterBombSet(set):
    def __iter__(self):
        raise RuntimeError("set iter bomb")


class _IterBombFrozen(frozenset):
    def __iter__(self):
        raise RuntimeError("frozenset iter bomb")


class _ReprBombObj:
    def __str__(self):
        raise RuntimeError("obj str bomb")

    def __repr__(self):
        raise RuntimeError("obj repr bomb")


class _OddListing:
    def __init__(self, pid):
        self._pid = pid

    def pid_for(self, label):
        return self._pid


def _get_nginx(sites, listing=None):
    if listing is None:
        listing_patch = mock.patch(
            "hub.nginx_svc.launchd_listing", side_effect=OSError("sandbox")
        )
    else:
        listing_patch = mock.patch(
            "hub.nginx_svc.launchd_listing", return_value=listing
        )
    with (
        mock.patch.object(nginx_svc, "nginx_sites", return_value=sites),
        listing_patch,
    ):
        return _client().get("/api/nginx")


def _files(resp) -> dict:
    body = resp.json()
    _starlette(body)
    return {s["file"]: s for s in body["sites"]}


class NestedRankRoutePinTests(unittest.TestCase):
    """The top-level bomb classes, one level down: the recursion holds."""

    def test_int_bombs_nested_inside_listens_keep_the_real_port(self):
        resp = _get_nginx([
            {"file": "a.conf", "listens": [_StrBombInt(8080), _BIG]},
            {"file": "sane.conf", "listens": [80]},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        files = _files(resp)
        # The bombed int survives as its real value; the over-cap one drops
        # alone (nothing may render its digits), never the list or the row.
        self.assertEqual(files["a.conf"]["listens"], [8080, None])
        self.assertEqual(files["sane.conf"]["listens"], [80])

    def test_mapping_bomb_dict_values_keep_their_real_entries(self):
        for cls in (_ItemsBombDict, _GetBombDict, _BoolBombDict,
                    _KeysBombDict, _LenBombDict):
            with self.subTest(cls=cls.__name__):
                resp = _get_nginx([
                    {"file": "a.conf", "extra": cls({"k": "v"})},
                    {"file": "sane.conf"},
                ])
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                files = _files(resp)
                # dict.items(value) reads the storage, not the override:
                # the nested value keeps its real entries.
                self.assertEqual(files["a.conf"]["extra"], {"k": "v"})
                self.assertIn("sane.conf", files)

    def test_iter_bomb_sequence_values_keep_their_real_elements(self):
        for cls, seed in ((_IterBombList, ["x"]), (_IterBombTuple, ("x",)),
                          (_IterBombSet, {"x"}), (_IterBombFrozen, {"x"})):
            with self.subTest(cls=cls.__name__):
                resp = _get_nginx([
                    {"file": "a.conf", "seq": cls(seed)},
                    {"file": "sane.conf"},
                ])
                self.assertEqual(resp.status_code, 200, resp.text[:200])
                files = _files(resp)
                self.assertEqual(files["a.conf"]["seq"], ["x"])
                self.assertIn("sane.conf", files)

    def test_three_levels_down_the_walk_still_reads_through_the_bomb(self):
        resp = _get_nginx([
            {"file": "a.conf", "nested": [[{"deep": [_StrBombInt(1)]}]]},
            {"file": "sane.conf"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        files = _files(resp)
        self.assertEqual(files["a.conf"]["nested"], [[{"deep": [1]}]])

    def test_surrogate_beside_an_over_cap_int_in_one_row(self):
        resp = _get_nginx([
            {"file": "a.conf", "surr": "x \ud800 y", "big": _BIG},
            {"file": "sane.conf"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        files = _files(resp)
        self.assertNotIn("\ud800", files["a.conf"]["surr"])
        self.assertIn("x", files["a.conf"]["surr"])
        self.assertIsNone(files["a.conf"]["big"])

    def test_over_cap_int_key_drops_the_entry_not_the_row(self):
        resp = _get_nginx([
            {"file": "a.conf", "k": "v", _BIG: "unrenderable key"},
            {"file": "sane.conf"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        files = _files(resp)
        self.assertEqual(files["a.conf"], {"file": "a.conf", "k": "v"})


class SlotOverrideRoutePinTests(unittest.TestCase):
    """Subclasses that bomb the exact slots the unbound fix calls."""

    def test_index_bomb_int_value_survives_as_the_real_int(self):
        # int.__index__(value) is the base descriptor, fetched from int
        # itself: the subclass override never runs.
        resp = _get_nginx([
            {"file": "a.conf", "n": _IndexBombInt(3)},
            {"file": "sane.conf"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(_files(resp)["a.conf"]["n"], 3)

    def test_float_bomb_float_value_survives_as_the_real_float(self):
        resp = _get_nginx([
            {"file": "a.conf", "w": _FloatBombFloat(2.5)},
            {"file": "sane.conf"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(_files(resp)["a.conf"]["w"], 2.5)

    def test_bytearray_subclass_decode_bomb_takes_the_other_base_branch(self):
        # _decode_bytes classifies on isinstance(value, bytes): a bytearray
        # subclass is not bytes, so it must read through bytearray's base.
        resp = _get_nginx([
            {"file": "a.conf", "raw": _DecodeBombBA(b"x")},
            {"file": "sane.conf"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(_files(resp)["a.conf"]["raw"], "x")

    def test_object_whose_str_and_repr_both_raise_drops_to_empty(self):
        resp = _get_nginx([
            {"file": "a.conf", "o": _ReprBombObj()},
            {"file": "sane.conf"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        files = _files(resp)
        self.assertEqual(files["a.conf"]["o"], "")
        self.assertIn("sane.conf", files)


class PidRankRoutePinTests(unittest.TestCase):
    """Odd-listing pid shapes gateway6 never held at the HTTP layer."""

    def test_decode_bomb_bytes_pid_keeps_the_truthful_running_state(self):
        resp = _get_nginx([], listing=_OddListing(_DecodeBombBytes(b"88")))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["pid"], "88")
        self.assertTrue(body["running"])

    def test_self_str_encode_bomb_pid_keeps_the_truthful_running_state(self):
        resp = _get_nginx([], listing=_OddListing(_SelfStr("77")))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["pid"], "77")
        self.assertTrue(body["running"])

    def test_index_bomb_int_pid_keeps_the_truthful_running_state(self):
        resp = _get_nginx([], listing=_OddListing(_IndexBombInt(9)))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertEqual(body["pid"], "9")
        self.assertTrue(body["running"])

    def test_invalid_utf8_bytes_pid_is_no_pid_and_never_a_500(self):
        resp = _get_nginx([], listing=_OddListing(b"\xff\xfe12"))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIsNone(body["pid"])
        self.assertFalse(body["running"])


class _RealConf(unittest.TestCase):
    """A real empty nginx.conf so test_config reaches the spawn."""

    def setUp(self):
        conf = tempfile.NamedTemporaryFile(suffix=".conf", delete=False)
        conf.close()
        self.conf = Path(conf.name)
        self.addCleanup(self.conf.unlink)
        patched = mock.patch.object(nginx_svc, "NGINX_CONF", self.conf)
        patched.start()
        self.addCleanup(patched.stop)
        self.client = _client()


class RunnerRankRoutePinTests(_RealConf):
    """Odd-runner field shapes gateway6 never held at the HTTP layer."""

    def _post_test(self, sh_ret):
        with (
            mock.patch.object(nginx_svc, "sh", return_value=sh_ret),
            mock.patch.object(nginx_svc, "_nginx_present", return_value=True),
        ):
            return self.client.post("/api/nginx/test")

    def test_index_bomb_zero_rc_still_counts_as_success(self):
        resp = self._post_test((_IndexBombInt(0), "", "syntax is ok"))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertTrue(resp.json()["ok"])

    def test_bytearray_decode_bomb_stdout_degrades_to_the_base_text(self):
        resp = self._post_test((1, _DecodeBombBA(b"out text"), None))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertEqual(body["message"], "out text")

    def test_object_stderr_whose_str_and_repr_raise_degrades_to_empty(self):
        resp = self._post_test((1, "", _ReprBombObj()))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertFalse(body["ok"])
        self.assertEqual(body["message"], "")

    def test_invalid_utf8_stderr_keeps_the_readable_tail(self):
        resp = self._post_test((1, "", b"\xed\xa0\x80 raw"))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIn("raw", body["message"])

    def test_lone_surrogate_stderr_is_scrubbed_not_a_500(self):
        resp = self._post_test((1, "", "surr \udcff txt"))
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertNotIn("\udcff", body["message"])
        self.assertIn("surr", body["message"])

    def test_index_bomb_rcs_at_both_reload_spawns_still_report_reloaded(self):
        with (
            mock.patch.object(
                nginx_svc, "sh",
                side_effect=[(_IndexBombInt(0), "", "fine"),
                             (_IndexBombInt(0), "", "")],
            ),
            mock.patch.object(nginx_svc, "_nginx_present", return_value=True),
            mock.patch.object(nginx_svc, "invalidate_status"),
        ):
            resp = self.client.post("/api/nginx/reload")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertTrue(body["ok"])
        self.assertIn("Reloaded", body["message"])

    def test_self_str_encode_bomb_rides_reload_concat_and_kickstart(self):
        # The -t message concats onto "Reloaded\n" / feeds the kickstart
        # fallback; a self-__str__ str subclass keeps its encode bomb live
        # through every bound call on that path.
        with (
            mock.patch.object(
                nginx_svc, "sh",
                side_effect=[(0, "", _SelfStr("ok")), (1, "", "stale"),
                             (0, _SelfStr("kicked"), "")],
            ),
            mock.patch.object(nginx_svc, "_nginx_present", return_value=True),
            mock.patch.object(nginx_svc, "invalidate_launchd"),
            mock.patch.object(nginx_svc, "invalidate_status"),
        ):
            resp = self.client.post("/api/nginx/reload")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertTrue(body["ok"])
        self.assertEqual(body["message"], "kicked")

    def test_huge_number_json_body_on_the_bodyless_reload_stays_coded(self):
        # json.loads of these digits is ValueError, not JSONDecodeError;
        # the /test sibling is pinned in gateway5 — this holds /reload.
        with (
            mock.patch.object(nginx_svc, "sh", return_value=(0, "", "")),
            mock.patch.object(nginx_svc, "_nginx_present", return_value=True),
            mock.patch.object(nginx_svc, "invalidate_status"),
        ):
            resp = self.client.post(
                "/api/nginx/reload",
                content=("9" * 5000).encode(),
                headers={"Content-Type": "application/json"},
            )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertTrue(body["ok"])


if __name__ == "__main__":
    unittest.main()
