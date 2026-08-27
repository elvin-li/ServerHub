"""Leftover Gateway-page 500s #10: the ``__class__``-property bomb ranks.

gateway6 brought hub/nginx_svc.py to the modules5 unbound convention,
gateway7 held it at nested value rank, and gateway8 pinned the nested-key /
NaN-float ranks as stays-immune.  This wave re-ran the hunt over the mounted
GET /api/nginx, POST /api/nginx/test and POST /api/nginx/reload routes with
the one bomb class every *other* scrubber in the tree already guards
(assistant8/modules8/storage9/… all grew ``_isinst``) and this module never
did: a leftover whose ``__class__`` is a *raising property*.  CPython's
``isinstance`` consults the operand's ``__class__`` whenever the real-type
fast check misses, so every unguarded ``isinstance`` gate detonated it.
Confirmed against the mounted routes before fixing — each of these was an
HTTP 500 with a raw traceback:

* GET /api/nginx, a class-bomb site-row *value* (top level and nested in a
  list two levels down): ``_jsonable``'s first gate,
  ``isinstance(value, bool)``, raised straight out of ``overview()``'s
  scrub loop and took every sane sibling site down with it;
* GET /api/nginx, a class-bomb *row*: ``isinstance(row, dict)`` in
  ``overview()`` blew the same way before ``_jsonable`` ever saw the row;
* GET /api/nginx, a hashable class-bomb mapping *key* one level down:
  ``isinstance(k, (bytes, bytearray))`` in the key walk;
* GET /api/nginx, a class-bomb as the whole ``nginx_sites()`` *return*:
  ``isinstance(sites, list)`` sits outside the try that guards the call;
* POST /api/nginx/test, a class-bomb stdout/stderr from a patched or odd
  ``sh`` (the exact provider seam gateway5/6 fixed for raises, arity and
  field bombs): ``_as_text``'s ``isinstance(value, (bytes, bytearray))``
  raised on both the failure and the success branch;
* POST /api/nginx/reload, the same stderr bomb at all three spawn ranks —
  the ``-t`` probe, the ``-s reload`` spawn (inside
  ``_raise_if_cli_vanished(rc, _sh_message(err, out))``) and the kickstart
  answer.

The fix is the sibling scrubbers' ``_isinst`` (a guarded ``isinstance``
that reports False when the probe itself raises) applied to every gate in
``_as_text`` / ``_decode_bytes`` / ``_jsonable`` / ``_pid_text`` /
``overview()``.  A *lying* ``__class__`` (a property that answers ``int``)
is not an error: ``_isinst`` reports its claim and the numeric arm's
unbound ``int.__index__`` coercion then drops the impostor to null.

The rest of the battery pins ranks the same hunt found already immune, so
a refactor cannot quietly reopen them: the class-bomb *rc* (already
guarded — ``isinstance(rc, int)`` sits inside ``_sh_triple``'s try), the
class-bomb *pid* from an odd listing (``overview()``'s pid try), the
lying-``__class__`` impostor (isinstance honored the claim without raising
even pre-fix), a ``__bool__`` bomb and a raising-``isoformat`` carrier at
value rank
(``_jsonable`` never truth-tests a value and has no isoformat arm — both
fall to ``_as_text``'s ``str()``), and a hashable dict-subclass key whose
``items()`` raises (``str(k)`` is ``dict.__repr__`` off the real storage).

``os.kill`` does not apply here: nothing in hub/nginx_svc.py or its router
signals a pid, and the Gateway backend owns no JSON journal — its only
persistence is the audit trail, whose loader already drops unparseable
lines one at a time (hub/audit.py).  The vanished-CLI classification is
untouched: 503 stays disk-confirmed (gateway5 pins both directions).
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


class _ClassBomb:
    """``isinstance`` consults ``__class__`` when the fast check misses."""

    @property
    def __class__(self):
        raise RuntimeError("class bomb")

    def __str__(self):
        return "class-bomb-text"


class _HashableClassBomb:
    """The same bomb, hashable, so it can sit at mapping-key rank."""

    def __hash__(self):
        return 42

    @property
    def __class__(self):
        raise RuntimeError("key class bomb")

    def __str__(self):
        return "bomb-key"


class _LyingClassInt:
    """``__class__`` *answers* ``int`` — a claim, not an error."""

    @property
    def __class__(self):
        return int

    def __str__(self):
        return "impostor"


class _BoolBomb:
    def __bool__(self):
        raise RuntimeError("bool bomb")

    def __str__(self):
        return "bool-bomb-text"


class _IsoBomb:
    def isoformat(self):
        raise RuntimeError("isoformat bomb")

    def __str__(self):
        return "iso-bomb-text"


class _ItemsBombDictKey(dict):
    """Hashable dict subclass whose bound ``items`` raises."""

    __hash__ = object.__hash__

    def items(self):
        raise RuntimeError("items bomb")


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


class ClassBombGetRouteTests(unittest.TestCase):
    """Raising-``__class__`` leftovers on GET /api/nginx: each was a 500."""

    def test_class_bomb_value_degrades_to_text_keeps_siblings(self):
        resp = _get_nginx([
            {"file": "a.conf", "v": _ClassBomb()},
            {"file": "sane.conf", "listens": [8080]},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        files = _files(resp)
        # The bomb passes no isinstance gate, so it falls to _as_text and
        # serializes as its str(); the sane sibling site is untouched.
        self.assertEqual(files["a.conf"]["v"], "class-bomb-text")
        self.assertEqual(files["sane.conf"]["listens"], [8080])

    def test_class_bomb_value_two_levels_down_degrades_the_same(self):
        resp = _get_nginx([
            {"file": "a.conf", "d": {"deep": [_ClassBomb(), "ok"]}},
            {"file": "sane.conf"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        files = _files(resp)
        # The recursive walk hits the same guarded gates at every depth:
        # the bomb stringifies, the list sibling survives beside it.
        self.assertEqual(files["a.conf"]["d"]["deep"], ["class-bomb-text", "ok"])
        self.assertIn("sane.conf", files)

    def test_class_bomb_row_drops_alone_keeps_the_sane_sibling(self):
        resp = _get_nginx([
            _ClassBomb(),
            {"file": "sane.conf", "listens": [8080]},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        # The row gate reports "not a dict" instead of raising: the bomb
        # row drops, the sibling renders, and site_count counts survivors.
        self.assertEqual([s["file"] for s in body["sites"]], ["sane.conf"])
        self.assertEqual(body["site_count"], 1)

    def test_class_bomb_key_nested_stringifies_keeps_the_sibling_entry(self):
        resp = _get_nginx([
            {"file": "a.conf", "d": {_HashableClassBomb(): "v", "ok": "y"}},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        d = _files(resp)["a.conf"]["d"]
        # The key walk's bytes gate no longer detonates; str(k) renders the
        # bomb key and both entries keep their values.
        self.assertEqual(d, {"bomb-key": "v", "ok": "y"})

    def test_class_bomb_sites_return_degrades_to_an_empty_table(self):
        resp = _get_nginx(_ClassBomb())
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        # isinstance(sites, list) sat outside the try guarding the call;
        # the guarded gate reports "not a list" and the table renders empty.
        self.assertEqual(body["sites"], [])
        self.assertEqual(body["site_count"], 0)


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


class ClassBombShSeamRouteTests(_RealConf):
    """Class-bomb ``sh`` fields on Test/Reload: each was an HTTP 500."""

    def _post(self, path, sh_answers):
        with (
            mock.patch.object(nginx_svc, "sh", side_effect=sh_answers),
            mock.patch.object(nginx_svc, "_nginx_present", return_value=True),
        ):
            return self.client.post(path)

    def test_class_bomb_stderr_on_test_degrades_to_its_text(self):
        resp = self._post("/api/nginx/test", [(1, "", _ClassBomb())])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        # _as_text's bytes gate no longer detonates: the bomb serializes
        # as its str() and the failure stays a coded, readable answer.
        self.assertFalse(body["ok"])
        self.assertEqual(body["message"], "class-bomb-text")

    def test_class_bomb_stdout_on_the_ok_path_keeps_the_success(self):
        resp = self._post("/api/nginx/test", [(0, _ClassBomb(), "")])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        # rc 0 is still a success even when the probe text is a bomb.
        self.assertTrue(body["ok"])
        self.assertEqual(body["message"], "class-bomb-text")

    def test_class_bomb_stderr_on_the_probe_keeps_the_invalid_branch(self):
        resp = self._post("/api/nginx/reload", [(1, "", _ClassBomb())])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertFalse(body["ok"])
        self.assertIn("Invalid configuration; not reloaded", body["message"])
        self.assertIn("class-bomb-text", body["message"])

    def test_class_bomb_stderr_at_the_reload_spawn_reaches_kickstart(self):
        # -t passes, -s reload answers the bomb stderr, kickstart succeeds.
        # Pre-fix the vanished-CLI classification raised at _sh_message —
        # the coded-503 disk confirm never even ran.
        resp = self._post(
            "/api/nginx/reload",
            [(0, "syntax ok", ""), (1, "", _ClassBomb()), (0, "", "")],
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertTrue(body["ok"])

    def test_class_bomb_kickstart_answer_degrades_to_its_text(self):
        resp = self._post(
            "/api/nginx/reload",
            [(0, "syntax ok", ""), (1, "", "boom"), (0, "", _ClassBomb())],
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertTrue(body["ok"])
        self.assertEqual(body["message"], "class-bomb-text")


class StaysImmunePinTests(_RealConf):
    """Ranks the hunt found already immune, pinned at the HTTP layer."""

    def test_class_bomb_rc_was_already_guarded_inside_the_spawn_try(self):
        # isinstance(rc, int) sits inside _sh_triple's try: the bomb rc
        # degrades to the failure code, never a raise, and the disk-present
        # confirm keeps the raw (uncoded) failure rather than a 503.
        with (
            mock.patch.object(
                nginx_svc, "sh", return_value=(_ClassBomb(), "", "")
            ),
            mock.patch.object(nginx_svc, "_nginx_present", return_value=True),
        ):
            resp = self.client.post("/api/nginx/test")
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        self.assertFalse(body["ok"])

    def test_class_bomb_pid_from_an_odd_listing_stays_no_pid(self):
        resp = _get_nginx(
            [{"file": "sane.conf"}], listing=_OddListing(_ClassBomb())
        )
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        # _pid_text's gates report False and the text probe is no digit
        # run: no pid, not running, and the sites table is untouched.
        self.assertIsNone(body["pid"])
        self.assertFalse(body["running"])
        self.assertEqual(body["site_count"], 1)

    def test_bool_bomb_and_isoformat_bomb_values_stringify_not_500(self):
        resp = _get_nginx([
            {"file": "a.conf", "b": _BoolBomb(), "t": _IsoBomb()},
            {"file": "sane.conf"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        files = _files(resp)
        # _jsonable never truth-tests a value and has no isoformat arm:
        # both carriers fall to _as_text's str() and serialize as text.
        self.assertEqual(files["a.conf"]["b"], "bool-bomb-text")
        self.assertEqual(files["a.conf"]["t"], "iso-bomb-text")
        self.assertIn("sane.conf", files)

    def test_lying_class_int_value_drops_to_null_not_a_500(self):
        resp = _get_nginx([
            {"file": "a.conf", "n": _LyingClassInt(), "ok": 7},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        row = _files(resp)["a.conf"]
        # A lying __class__ is a claim, not an error — isinstance honored
        # it without raising even pre-fix, and _isinst keeps that: the int
        # arm's unbound int.__index__ then drops the impostor to null.
        self.assertIsNone(row["n"])
        self.assertEqual(row["ok"], 7)

    def test_dict_subclass_items_bomb_key_stringifies_keeps_the_entry(self):
        resp = _get_nginx([
            {"file": "a.conf", "d": {_ItemsBombDictKey(a=1): "v", "ok": "y"}},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        d = _files(resp)["a.conf"]["d"]
        # str(k) is dict.__repr__ off the real storage — the bound items()
        # bomb never runs at key rank; both entries survive.
        self.assertEqual(d["ok"], "y")
        self.assertIn("v", d.values())


if __name__ == "__main__":
    unittest.main()
