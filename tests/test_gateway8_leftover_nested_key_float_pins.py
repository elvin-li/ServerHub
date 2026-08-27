"""Leftover Gateway-page 500s #9: nested-key / NaN-float ranks stay sealed.

gateway6 brought hub/nginx_svc.py to the modules5 unbound convention and
gateway7 held that convention's *value* ranks one and three levels down
inside a site row.  This wave re-ran the same hunt over the mounted
GET /api/nginx, POST /api/nginx/test and POST /api/nginx/reload routes,
throwing the remaining bomb classes the prior batteries only ever held at
the top level, and found *no remaining 500*: ``_jsonable`` coerces every
key through the same unbound walk it applies to values, drops the
NaN/inf floats Starlette's ``allow_nan=False`` encoder would reject, and
stringifies exotic non-JSON builtins before the encode.

What was never pinned is exactly the ranks below — the prior batteries
proved these classes at *value* rank and at the top *row-key* rank only, so
a refactor that flattened the key coercion (or re-bound one call inside it)
would reopen them without failing a single existing test:

* nested-key rank — the over-cap int key gateway7 held at the top of a row,
  now one level down inside a *value* dict, beside a decode-bomb / invalid
  UTF-8 bytes key, a self-``__str__`` encode-bomb str key, and a lone
  surrogate key.  ``dict.items`` reads the storage and the key coercion
  (unbound ``bytes.decode`` / ``str(k)`` drop / unbound ``str.encode``)
  keeps the renderable siblings and drops only the unrenderable entry, never
  the row;
* NaN/inf float rank — gateway7's slot-override battery bombed ``__float__``
  itself; this holds the *values* that slot guards: a NaN and both infinities
  nested in a list drop to ``null`` (Starlette encodes with
  ``allow_nan=False`` and a raw NaN would 500), the finite sibling survives;
* exotic-builtin rank — a ``complex`` and a ``range`` value are neither the
  JSON scalar/mapping/sequence shapes ``_jsonable`` special-cases nor a
  bytes-like; the final ``_as_text`` stringifies them so the encoder never
  meets a type it cannot serialize.

``os.kill`` does not apply here: nothing in hub/nginx_svc.py or its router
signals a pid, and the Gateway backend owns no JSON journal — its only
persistence is the audit trail, whose loader already drops unparseable
lines one at a time (hub/audit.py).  These are stays-immune pins: the
surface holds today; the battery locks the ranks so a future refactor
cannot reopen them silently.
"""
from __future__ import annotations

import json
import math
import unittest
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


class _SelfStr(str):
    def __str__(self):
        return self

    def encode(self, *a, **k):
        raise RuntimeError("encode bomb")


class _DecodeBombBytes(bytes):
    def decode(self, *a, **k):
        raise RuntimeError("decode bomb")


def _get_nginx(sites):
    with (
        mock.patch.object(nginx_svc, "nginx_sites", return_value=sites),
        mock.patch("hub.nginx_svc.launchd_listing", side_effect=OSError("sandbox")),
    ):
        return _client().get("/api/nginx")


def _files(resp) -> dict:
    body = resp.json()
    _starlette(body)
    return {s["file"]: s for s in body["sites"]}


class NestedKeyRankPinTests(unittest.TestCase):
    """Bomb classes at *key* rank one level down inside a value dict."""

    def test_over_cap_int_key_nested_drops_the_entry_keeps_siblings(self):
        resp = _get_nginx([
            {"file": "a.conf", "d": {_BIG: "unrenderable", "ok": "y"}},
            {"file": "sane.conf"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        files = _files(resp)
        # The over-cap key has no renderable digits: its entry drops, the
        # sibling survives, and the row and every other site are untouched.
        self.assertEqual(files["a.conf"]["d"], {"ok": "y"})
        self.assertIn("sane.conf", files)

    def test_bytes_keys_nested_decode_through_the_unbound_base(self):
        resp = _get_nginx([
            {"file": "a.conf", "d": {b"bk": "x", _DecodeBombBytes(b"db"): "y"}},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        d = _files(resp)["a.conf"]["d"]
        # bytes.decode(value) reads the storage, not the subclass override:
        # both keys decode to their real text and keep their entries.
        self.assertEqual(d, {"bk": "x", "db": "y"})

    def test_invalid_utf8_bytes_key_nested_is_scrubbed_not_a_500(self):
        resp = _get_nginx([
            {"file": "a.conf", "d": {b"\xff\xfe": "y", "ok": "z"}},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        d = _files(resp)["a.conf"]["d"]
        # Undecodable bytes become U+FFFD replacements, never a surrogate the
        # encoder would reject; the sibling entry rides through intact.
        self.assertEqual(d["ok"], "z")
        self.assertNotIn(b"\xff\xfe", d)

    def test_self_str_encode_bomb_key_nested_dodges_the_override(self):
        resp = _get_nginx([
            {"file": "a.conf", "d": {_SelfStr("k"): "v"}},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        # str(key) stays the subclass (its __str__ answers self); the unbound
        # str.encode scrub dodges the live encode bomb and reads "k".
        self.assertEqual(_files(resp)["a.conf"]["d"], {"k": "v"})

    def test_surrogate_key_nested_is_scrubbed_not_a_500(self):
        resp = _get_nginx([
            {"file": "a.conf", "d": {"k\ud800z": "v"}},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        d = _files(resp)["a.conf"]["d"]
        key = next(iter(d))
        self.assertNotIn("\ud800", key)
        self.assertEqual(d[key], "v")


class NaNFloatRankPinTests(unittest.TestCase):
    """The values the __float__ slot guards: NaN and both infinities."""

    def test_nan_and_infinities_nested_in_a_list_drop_to_null(self):
        resp = _get_nginx([
            {"file": "a.conf", "vals": [1.5, float("nan"),
                                        float("inf"), float("-inf")]},
            {"file": "sane.conf"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        files = _files(resp)
        # allow_nan=False would 500 on a raw NaN/inf; the finite sibling keeps
        # its real value and the three non-finite ones drop to null.
        self.assertEqual(files["a.conf"]["vals"], [1.5, None, None, None])
        self.assertIn("sane.conf", files)

    def test_nan_as_a_dict_value_drops_to_null_keeps_the_sibling(self):
        resp = _get_nginx([
            {"file": "a.conf", "d": {"bad": float("nan"), "ok": 2.5}},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        d = _files(resp)["a.conf"]["d"]
        self.assertIsNone(d["bad"])
        self.assertEqual(d["ok"], 2.5)


class ExoticBuiltinRankPinTests(unittest.TestCase):
    """Non-JSON builtins the final _as_text stringifies before the encode."""

    def test_complex_and_range_values_stringify_not_500(self):
        resp = _get_nginx([
            {"file": "a.conf", "c": complex(1, 2), "rg": range(3)},
            {"file": "sane.conf"},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        row = _files(resp)["a.conf"]
        # Neither is a JSON scalar/mapping/sequence nor bytes-like; both reach
        # _as_text and serialize as their str(), so Starlette never meets a
        # type it cannot encode.
        self.assertIsInstance(row["c"], str)
        self.assertIsInstance(row["rg"], str)
        self.assertIn("1", row["c"])

    def test_the_whole_payload_round_trips_through_the_encoder(self):
        # A belt-and-braces check that the encoder Starlette actually uses
        # accepts the scrubbed payload with every exotic rank present at once.
        resp = _get_nginx([
            {"file": "a.conf",
             "d": {_BIG: "x", b"\xff\xfe": "y", _SelfStr("k"): "z"},
             "vals": [float("nan"), float("inf")],
             "c": complex(0, 1)},
        ])
        self.assertEqual(resp.status_code, 200, resp.text[:200])
        body = resp.json()
        _starlette(body)
        row = {s["file"]: s for s in body["sites"]}["a.conf"]
        self.assertEqual(row["vals"], [None, None])
        self.assertNotIn(math.nan, row["vals"])


if __name__ == "__main__":
    unittest.main()
