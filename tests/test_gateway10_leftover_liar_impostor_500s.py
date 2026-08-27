"""Leftover Gateway-page 500s #11: lying-``__class__`` impostors and rc forgery.

gateway9 grew ``_isinst`` so a *raising* ``__class__`` property could no
longer detonate the gates in hub/nginx_svc.py.  This wave re-ran the hunt
with the class vms10/shares10 already guard and this module never did: a
*lying* ``__class__`` property — one that quietly answers ``dict`` /
``list`` / ``bytes`` / ``bytearray`` / ``bool`` over no real storage of
that type.  ``_isinst`` honors the claim (isinstance consults ``__class__``
when the real-type fast check misses), and the very next line ran an
*unbound base descriptor* against the impostor — ``dict.items(value)``,
``list.__iter__(value)``, ``bytes.decode(value, ...)`` — which TypeErrors
outside every try.  Confirmed against the mounted routes before fixing —
each of these was an HTTP 500 with a raw traceback:

* GET /api/nginx, a lying-dict *row*: it passed ``_isinst(row, dict)`` in
  ``overview()`` and blew ``dict.items`` inside ``_jsonable``, taking every
  sane sibling site down with it;
* GET /api/nginx, a lying-dict / lying-list *value* (top level and nested
  two levels down): the same unbound reads at value rank;
* GET /api/nginx, a lying-bytes / lying-bytearray value:
  ``_decode_bytes``'s unbound ``base.decode`` TypeError'd out of the bytes
  arm;
* GET /api/nginx, a lying-bytes mapping *key* one level down: the key
  walk's ``_decode_bytes`` call, the same way;
* GET /api/nginx, a *bool-liar* value: ``_isinst(value, bool)`` honored the
  claim and returned the raw object, which rode into Starlette's
  ``json.dumps`` as a TypeError — the one gate where a guarded isinstance
  is not enough and only ``type(x) is bool`` holds;
* POST /api/nginx/test and both later spawn ranks of POST
  /api/nginx/reload, a lying-bytes stdout/stderr from a patched or odd
  ``sh``: ``_as_text``'s bytes arm hit the same unbound decode.

The fix: ``_decode_bytes`` answers ``None`` for an impostor and every
caller falls back to the plain text probe; the dict and sequence arms wrap
their unbound base reads and degrade the impostor to its text;
``_jsonable`` / ``_pid_text`` gate bool with ``type(x) is bool`` so a
bool-liar falls to the int arm, where the unbound ``int.__index__`` drops
it to null.

The rc seam moves to the vms10 convention: ``_sh_triple`` splits into
``_sh3`` (exact triple storage — unbound base reads through subclass
``__iter__`` bombs, wrong arity and impostors degrade to ``(-255, "", "")``)
and ``_rc_int`` (exact-int rc; junk reads -255, **never** the -1 spawn
sentinel).  Pre-fix a junk rc degraded to -1, so a poisoned rc beside a
leftover "not found" stderr could forge the vanished-CLI classifier and
mint the coded 503 out of an object instead of a real missing binary.  A
raising *runner* keeps the ``(-1, "", text)`` spawn shape — gateway5 pins
that classification, disk-confirmed in both directions, and this battery
re-pins it against the exact answer triple.

The rest pins ranks the hunt found already immune: a bool-liar / lying-int
rc (the coercion try already held), a bool-liar or lying-bytes pid from an
odd listing, a raising-``__eq__`` str-subclass key (the out-dict assignment
only ever handles exact strs), a raising isoformat *property* carrier
(``_jsonable`` never reads ``.isoformat``), True/False rcs (honest 1/0,
so a leftover True can never claim success), and a tuple-subclass answer
whose bound ``__iter__`` bombs (the unbound reads see the honest fields).

No exploit code here: every object below is an in-process leftover planted
against our own handlers through the documented provider seams.
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


class _LyingDict:
    """``__class__`` answers ``dict`` over no real mapping storage."""

    @property
    def __class__(self):
        return dict

    def __str__(self):
        return "lying-dict"


class _LyingList:
    @property
    def __class__(self):
        return list

    def __str__(self):
        return "lying-list"


class _LyingBytes:
    @property
    def __class__(self):
        return bytes

    def __str__(self):
        return "lying-bytes"


class _LyingBytearray:
    @property
    def __class__(self):
        return bytearray

    def __str__(self):
        return "lying-ba"


class _BoolLiar:
    """``__class__`` answers ``bool`` — only ``type(x) is bool`` holds."""

    @property
    def __class__(self):
        return bool

    def __str__(self):
        return "bool-liar"


class _LyingTuple:
    """Claims tuple over no real sequence storage (the sh-answer rank)."""

    @property
    def __class__(self):
        return tuple

    def __str__(self):
        return "lying-tuple"


class _IterBombTuple(tuple):
    """Real tuple storage behind a bound ``__iter__`` bomb."""

    def __iter__(self):
        raise RuntimeError("iter bomb")


class _EqBombStrKey(str):
    """Exact-str storage; the bound ``__eq__`` raises (hash-shadow rank)."""

    __hash__ = str.__hash__

    def __eq__(self, other):
        raise RuntimeError("eq bomb")

    def __ne__(self, other):
        raise RuntimeError("ne bomb")


class _IsoPropertyBomb:
    """``isoformat`` is a raising *property*, not a method."""

    @property
    def isoformat(self):
        raise RuntimeError("isoformat property bomb")

    def __str__(self):
        return "iso-prop-text"


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


class LyingImpostorGetRouteTests(unittest.TestCase):
    """Lying-``__class__`` leftovers on GET /api/nginx: each was a 500."""

    def test_lying_dict_row_drops_alone_keeps_the_sane_sibling(self):
        resp = _get_nginx([
            _LyingDict(),
            {"file": "sane.conf", "listens": [8080]},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        # The impostor passes the row gate on its claim, but the unbound
        # dict.items read degrades to text — not a dict, so the row drops
        # alone and the sane sibling renders.
        self.assertEqual([s["file"] for s in body["sites"]], ["sane.conf"])
        self.assertEqual(body["site_count"], 1)

    def test_lying_dict_value_degrades_to_text_keeps_siblings(self):
        resp = _get_nginx([
            {"file": "a.conf", "v": _LyingDict()},
            {"file": "sane.conf", "listens": [8080]},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        files = _files(resp)
        self.assertEqual(files["a.conf"]["v"], "lying-dict")
        self.assertEqual(files["sane.conf"]["listens"], [8080])

    def test_lying_impostor_values_two_levels_down_degrade_the_same(self):
        resp = _get_nginx([
            {"file": "a.conf", "d": {"deep": [_LyingDict(), _LyingList(), "ok"]}},
            {"file": "sane.conf"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        files = _files(resp)
        self.assertEqual(
            files["a.conf"]["d"]["deep"], ["lying-dict", "lying-list", "ok"]
        )
        self.assertIn("sane.conf", files)

    def test_lying_list_value_degrades_to_text(self):
        resp = _get_nginx([{"file": "a.conf", "v": _LyingList()}])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(_files(resp)["a.conf"]["v"], "lying-list")

    def test_lying_bytes_and_bytearray_values_degrade_to_text(self):
        resp = _get_nginx([
            {"file": "a.conf", "b": _LyingBytes(), "ba": _LyingBytearray()},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        row = _files(resp)["a.conf"]
        # _decode_bytes answers None for the impostors; the str() fallback
        # renders their text instead of TypeError'ing the unbound decode.
        self.assertEqual(row["b"], "lying-bytes")
        self.assertEqual(row["ba"], "lying-ba")

    def test_lying_bytes_key_stringifies_keeps_the_sibling_entry(self):
        resp = _get_nginx([
            {"file": "a.conf", "d": {_LyingBytes(): "v", "ok": "y"}},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        d = _files(resp)["a.conf"]["d"]
        self.assertEqual(d, {"lying-bytes": "v", "ok": "y"})

    def test_bool_liar_value_drops_to_null_not_a_500(self):
        resp = _get_nginx([
            {"file": "a.conf", "b": _BoolLiar(), "real": True, "ok": 7},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        row = _files(resp)["a.conf"]
        # type(x) is bool refuses the claim; the liar falls to the int arm
        # (bool claims int too) and the unbound int.__index__ drops it.
        # A real bool keeps passing through untouched.
        self.assertIsNone(row["b"])
        self.assertIs(row["real"], True)
        self.assertEqual(row["ok"], 7)

    def test_bool_liar_nested_in_a_list_drops_to_null_beside_siblings(self):
        resp = _get_nginx([
            {"file": "a.conf", "seq": [_BoolLiar(), False, 1]},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertEqual(_files(resp)["a.conf"]["seq"], [None, False, 1])


class _RealConf(unittest.TestCase):
    def setUp(self):
        conf = tempfile.NamedTemporaryFile(suffix=".conf", delete=False)
        conf.close()
        self.conf = Path(conf.name)
        self.addCleanup(self.conf.unlink)
        patched = mock.patch.object(nginx_svc, "NGINX_CONF", self.conf)
        patched.start()
        self.addCleanup(patched.stop)
        self.client = _client()

    def _post(self, path, sh_answers, present=True):
        with (
            mock.patch.object(nginx_svc, "sh", side_effect=sh_answers),
            mock.patch.object(
                nginx_svc, "_nginx_present", return_value=present
            ),
            mock.patch.object(nginx_svc, "invalidate_launchd"),
            mock.patch.object(nginx_svc, "invalidate_status"),
        ):
            return self.client.post(path)


class LyingImpostorShSeamRouteTests(_RealConf):
    """Lying-bytes ``sh`` fields on Test/Reload: each was an HTTP 500."""

    def test_lying_bytes_stderr_on_test_degrades_to_its_text(self):
        resp = self._post("/api/nginx/test", [(1, "", _LyingBytes())])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertFalse(body["ok"])
        self.assertEqual(body["message"], "lying-bytes")

    def test_lying_bytes_stdout_on_the_ok_path_keeps_the_success(self):
        resp = self._post("/api/nginx/test", [(0, _LyingBytes(), "")])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertTrue(body["ok"])
        self.assertEqual(body["message"], "lying-bytes")

    def test_lying_bytes_stderr_on_the_probe_keeps_the_invalid_branch(self):
        resp = self._post("/api/nginx/reload", [(1, "", _LyingBytes())])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertFalse(body["ok"])
        self.assertIn("Invalid configuration; not reloaded", body["message"])
        self.assertIn("lying-bytes", body["message"])

    def test_lying_bytes_stderr_at_the_reload_spawn_reaches_kickstart(self):
        resp = self._post(
            "/api/nginx/reload",
            [(0, "syntax ok", ""), (1, "", _LyingBytes()), (0, "", "")],
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertTrue(body["ok"])

    def test_lying_bytes_kickstart_answer_degrades_to_its_text(self):
        resp = self._post(
            "/api/nginx/reload",
            [(0, "syntax ok", ""), (1, "", "boom"), (0, "", _LyingBytes())],
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertTrue(body["ok"])
        self.assertEqual(body["message"], "lying-bytes")


class RcSentinelForgeryPinTests(_RealConf):
    """Junk rc reads -255, never the -1 sentinel: the 503 cannot be forged."""

    def test_junk_rc_beside_not_found_stderr_never_forges_the_503(self):
        # A str rc beside a literal "not found" stderr, with nginx really
        # gone from disk: pre-fix junk degraded to -1 — the exact spawn
        # sentinel — and minted the coded 503 out of a poisoned object.
        # Junk reads -255 now, so the plain failure branch holds.
        resp = self._post(
            "/api/nginx/test", [("junk", "", "not found")], present=False
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertFalse(body["ok"])
        self.assertEqual(body["message"], "not found")

    def test_real_sentinel_answer_is_the_coded_503_only_when_gone(self):
        # The honest sh spawn sentinel (-1, "", "not found"), binary gone:
        # the disk-confirmed classification stays exactly as gateway5 pinned
        # it for the raising-runner shape.
        resp = self._post(
            "/api/nginx/test", [(-1, "", "not found")], present=False
        )
        self.assertEqual(resp.status_code, 503, resp.text[:200])
        self.assertEqual(resp.json()["detail"]["code"], "nginx.not_found")

    def test_real_sentinel_answer_stays_raw_while_nginx_is_on_disk(self):
        resp = self._post(
            "/api/nginx/test", [(-1, "", "not found")], present=True
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertFalse(body["ok"])
        self.assertEqual(body["message"], "not found")

    def test_true_rc_is_never_a_success(self):
        # bool is int's subclass and True reads as the honest exit 1: a
        # leftover True can never claim "configuration ok".
        resp = self._post("/api/nginx/test", [(True, "", "err text")])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        self.assertFalse(body["ok"])
        self.assertEqual(body["message"], "err text")

    def test_false_rc_reads_as_the_honest_zero(self):
        resp = self._post("/api/nginx/test", [(False, "syntax is ok", "")])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertTrue(resp.json()["ok"])

    def test_bool_liar_rc_degrades_to_the_failure_branch(self):
        # The claim routes the liar into the int arm; int.__index__ finds
        # no real storage and the junk reads -255 — a failure, never a 500
        # and never the sentinel.
        resp = self._post("/api/nginx/test", [(_BoolLiar(), "", "err text")])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertFalse(body["ok"])
        self.assertEqual(body["message"], "err text")

    def test_float_subclass_eq_bomb_rc_stays_the_failure_branch(self):
        class _EqBombFloat(float):
            __hash__ = float.__hash__

            def __eq__(self, other):
                raise RuntimeError("eq bomb")

        # A float is no int: junk, -255, failure branch — the bombed
        # __eq__ never runs against the rc comparisons.
        resp = self._post(
            "/api/nginx/test", [(_EqBombFloat(0.0), "", "err text")]
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertFalse(resp.json()["ok"])

    def test_lying_tuple_sh_answer_degrades_to_ok_false(self):
        # The whole answer claims tuple over no real sequence storage:
        # _sh3's unbound read refuses it and the triple degrades to
        # (-255, "", "") — a plain failure, never a 500 or a forged 503.
        resp = self._post(
            "/api/nginx/test", [_LyingTuple()], present=False
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        self.assertFalse(resp.json()["ok"])

    def test_tuple_subclass_iter_bomb_answer_keeps_the_honest_fields(self):
        # Real tuple storage behind a bound __iter__ bomb: the unbound
        # base read sees the honest (1, "", "stale") and the message
        # survives — pre-fix the unpack caught the bomb and the answer
        # degraded to the raise text instead.
        resp = self._post(
            "/api/nginx/test", [_IterBombTuple((1, "", "stale"))]
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertFalse(body["ok"])
        self.assertEqual(body["message"], "stale")


class StaysImmunePinTests(_RealConf):
    """Ranks the hunt found already immune, pinned at the HTTP layer."""

    def test_eq_bomb_str_subclass_key_keeps_both_entries(self):
        resp = _get_nginx([
            {"file": "a.conf", "d": {_EqBombStrKey("x"): "v", "ok": "y"}},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        d = _files(resp)["a.conf"]["d"]
        # The out-dict assignment only ever handles exact strs (_as_text
        # rebuilds the key off the real storage), so the bound __eq__ bomb
        # never runs at hash-shadow rank; both entries survive.
        self.assertEqual(d, {"x": "v", "ok": "y"})

    def test_bool_liar_pid_from_an_odd_listing_stays_no_pid(self):
        resp = _get_nginx(
            [{"file": "sane.conf"}], listing=_OddListing(_BoolLiar())
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertIsNone(body["pid"])
        self.assertFalse(body["running"])
        self.assertEqual(body["site_count"], 1)

    def test_lying_bytes_pid_from_an_odd_listing_stays_no_pid(self):
        resp = _get_nginx(
            [{"file": "sane.conf"}], listing=_OddListing(_LyingBytes())
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        # _as_text refuses the lying decode and the str() text is no digit
        # run: no pid, not running, the table untouched.
        self.assertIsNone(body["pid"])
        self.assertFalse(body["running"])

    def test_isoformat_property_bomb_value_stringifies_not_500(self):
        resp = _get_nginx([
            {"file": "a.conf", "t": _IsoPropertyBomb()},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        # _jsonable never reads .isoformat — the carrier falls to the
        # str() probe before any encoder can touch the raising property.
        self.assertEqual(_files(resp)["a.conf"]["t"], "iso-prop-text")

    def test_wrong_arity_answers_still_degrade_to_ok_false(self):
        # gateway5's arity pin, re-held through the _sh3 rewrite: a
        # 2-tuple / bare-None answer reads (-255, "", "") now.
        for stub in [(0, "only-two"), None]:
            resp = self._post("/api/nginx/test", [stub])
            self.assertEqual(resp.status_code, 200, resp.text[:200])
            self.assertFalse(resp.json()["ok"])


if __name__ == "__main__":
    unittest.main()
