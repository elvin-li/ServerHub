"""Sixteenth leftover sweep of the Files page, over the real mounted app.

files15 sealed the host-address and spawn-env provider seams.  This pass
hunts the rank *behind* the seams: ``isinstance`` consults a value's
``__class__`` only after the real-MRO check misses, so a lying ``__class__``
steers a leftover into the arm of its *claim*, the unbound descriptor there
rejects the real storage, and an early return throws away honest data — the
wrong-rank degradations the logs13/audit13 sweeps sealed on their surfaces:

* ``_as_text`` picked its decode base off the claim, so a genuine bytearray
  lying bytes was handed to ``bytes.decode``, refused, and dropped to ``""``
  — and a genuine str lying bytes failed both base decodes and vanished the
  same way, although the str arm renders its real text verbatim;
* ``default_roots`` handed a genuine bytes root path claiming str to
  ``_try_resolve``'s dispatching ``str()``, which rendered its *repr*
  (``"b'/Volumes/media'"``) — the root resolved to a nonexistent
  cwd-relative path and silently vanished from every Files route although
  the directory it named was right there; a dict row carrying a plain bytes
  path dropped identically;
* ``_root_label``'s ``_isinst(value, bool)`` matched a lying claimed-bool
  over real str storage and dropped the id the YAML author wrote to the
  basename fallback, so the SPA's ``root_id`` answered ``files.unknown_root``
  (400) with the directory sitting right there;
* ``_max_upload_mb``'s bool gate matched the same lie over real int storage
  and silently reset the operator's configured cap to the 512 default —
  POST /api/files/upload accepted bodies the config said to refuse;
* ``_sh3``'s tuple gate matched a genuine list claiming tuple, the unbound
  ``tuple.__iter__`` refused the real layout, and an honest ``(0, out,
  err)`` degraded to the ``(-255, "", "")`` failure triple — the FileBrowser
  sidecar read as not-running on a runner that answered success; ``_rc_int``
  dropped a genuine float rc claiming int to ``-255`` one arm early.

One leak rode beside the rank bugs: the free-text coercion arm of
``_as_text`` ran ``str()`` on any leftover shape, and for a type that never
overrode ``__str__``/``__repr__`` the answer is the default
``object.__repr__`` — ``<X object at 0x7f...>``, a raw heap address — which
a junk root ``name``/``id`` carried verbatim into the GET /api/files body
(the bookmarks/assistant address-leak rule).

Every fix recovers the arm the *real* storage matches; total impostors — a
claim with no usable layout underneath — keep the established drops, and
tests pin both directions so a refactor cannot quietly reopen either.
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import files_svc
from hub.app_factory import create_app
from hub.auth import require_auth

_ADDR_RE = re.compile(r" at 0x[0-9a-fA-F]+>")

_client = None


def client() -> TestClient:
    global _client
    if _client is None:
        app = create_app()
        app.dependency_overrides[require_auth] = lambda: None
        _client = TestClient(app, raise_server_exceptions=False)
    return _client


def _assert_clean(test: unittest.TestCase, resp) -> None:
    text = resp.text
    test.assertFalse(
        any("\ud800" <= ch <= "\udfff" for ch in text),
        "lone surrogate survived into the HTTP body",
    )
    text.encode("utf-8")


def _assert_below_500(test: unittest.TestCase, resp, route: str) -> None:
    _assert_clean(test, resp)
    test.assertLess(resp.status_code, 500, f"{route}: {resp.status_code} {resp.text[:200]}")


# ── The leftover liar / impostor classes ─────────────────────────────────────

def _liar_prop(claim):
    return property(lambda self: claim)


def _liar(claim):
    """A total impostor: claims *claim*, carries no usable storage."""
    return type("Liar", (object,), {"__class__": property(lambda self: claim)})()


class StrLyingBytes(str):
    """Real str storage; ``__class__`` lies bytes."""

    __class__ = _liar_prop(bytes)


class BytearrayLyingBytes(bytearray):
    """Real bytearray storage; ``__class__`` lies bytes."""

    __class__ = _liar_prop(bytes)


class BytesLyingStr(bytes):
    """Real bytes storage; ``__class__`` lies str."""

    __class__ = _liar_prop(str)


class StrLyingBool(str):
    """Real str storage; ``__class__`` lies bool."""

    __class__ = _liar_prop(bool)


class IntLyingBool(int):
    """Real int storage; ``__class__`` lies bool."""

    __class__ = _liar_prop(bool)


class FloatLyingInt(float):
    """Real float storage; ``__class__`` lies int."""

    __class__ = _liar_prop(int)


class ListLyingTuple(list):
    """Real list storage; ``__class__`` lies tuple."""

    __class__ = _liar_prop(tuple)


class PlainJunk:
    """Never overrode ``__str__``/``__repr__``: renders as a heap address."""


class _FilesSandbox(unittest.TestCase):
    """One temp browsable root; ``settings_section`` patched with a plain dict
    carrying the leftover values (models hub.config's real laundering — the
    section mapping is re-dicted but the values inside are the leftovers)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "root"
        self.root.mkdir()
        (self.root / "a.txt").write_text("hi", encoding="utf-8")
        self.settings = {"roots": [{"id": "r", "path": str(self.root)}]}
        patched = mock.patch.object(
            files_svc, "settings_section", side_effect=lambda *_: self.settings
        )
        patched.start()
        self.addCleanup(patched.stop)

    def _drive_all(self):
        for route, resp in [
            ("GET /api/files", client().get("/api/files")),
            ("GET /api/files/list", client().get("/api/files/list")),
            ("GET /api/files/filebrowser", client().get("/api/files/filebrowser")),
        ]:
            _assert_below_500(self, resp, route)


# ── The fix #1: a lying-str bytes root path dropped the whole root ───────────

class BytesRootPathWrongRankTests(_FilesSandbox):
    """A genuine bytes path claiming str reached ``_try_resolve``'s ``str()``
    as its repr and the root vanished from every Files route."""

    def test_string_root_with_lying_class_still_lists(self):
        self.settings["roots"] = [BytesLyingStr(os.fsencode(self.root))]
        resp = client().get("/api/files")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        roots = resp.json()["roots"]
        self.assertEqual([r["path"] for r in roots], [str(self.root)], roots)

    def test_dict_row_with_plain_bytes_path_still_lists(self):
        self.settings["roots"] = [{"id": "r", "path": os.fsencode(self.root)}]
        resp = client().get("/api/files")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        roots = resp.json()["roots"]
        self.assertEqual([r["path"] for r in roots], [str(self.root)], roots)
        listing = client().get("/api/files/list", params={"root_id": "r"})
        self.assertEqual(listing.status_code, 200, listing.text[:300])
        self.assertEqual(listing.json()["items"][0]["name"], "a.txt")

    def test_total_str_impostor_row_still_drops_without_500(self):
        self.settings["roots"] = [_liar(str), {"id": "r2", "path": str(self.root)}]
        resp = client().get("/api/files")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual([r["id"] for r in resp.json()["roots"]], ["r2"])


# ── The fix #2: a lying-bool root id 400'd the id the YAML author wrote ──────

class RootIdWrongRankTests(_FilesSandbox):
    def test_str_id_lying_bool_keeps_its_honest_text(self):
        self.settings["roots"] = [{"id": StrLyingBool("teamroot"), "path": str(self.root)}]
        resp = client().get("/api/files")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["roots"][0]["id"], "teamroot")
        listing = client().get("/api/files/list", params={"root_id": "teamroot"})
        self.assertEqual(listing.status_code, 200, listing.text[:300])

    def test_honest_bool_id_keeps_the_basename_fallback(self):
        """YAML's ``id: yes`` footgun stays the basename, as before."""
        self.settings["roots"] = [{"id": True, "path": str(self.root)}]
        resp = client().get("/api/files")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["roots"][0]["id"], self.root.name)

    def test_total_bool_impostor_id_keeps_the_basename_fallback(self):
        self.settings["roots"] = [{"id": _liar(bool), "path": str(self.root)}]
        resp = client().get("/api/files")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["roots"][0]["id"], self.root.name)


# ── The fix #3: default object.__repr__ heap addresses leaked into the body ──

class ReprAddressLeakTests(_FilesSandbox):
    def test_junk_root_name_no_longer_leaks_a_heap_address(self):
        self.settings["roots"] = [{"id": "ok", "path": str(self.root), "name": PlainJunk()}]
        resp = client().get("/api/files")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        self.assertIsNone(_ADDR_RE.search(resp.text), resp.text[:300])
        self.assertEqual(resp.json()["roots"][0]["name"], self.root.name)

    def test_junk_root_id_no_longer_leaks_a_heap_address(self):
        self.settings["roots"] = [{"id": PlainJunk(), "path": str(self.root)}]
        resp = client().get("/api/files")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertIsNone(_ADDR_RE.search(resp.text), resp.text[:300])

    def test_a_file_literally_named_like_a_repr_stays_verbatim(self):
        """Real str storage is data, never scrubbed — only the coercion arm."""
        name = "notes at 0xCAFE>.txt"
        (self.root / name).write_text("x", encoding="utf-8")
        resp = client().get("/api/files/list", params={"root_id": "r"})
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertIn(name, [i["name"] for i in resp.json()["items"]])


# ── The fix #4: a lying-tuple runner answer read success as not-running ──────

class RunnerAnswerWrongRankTests(_FilesSandbox):
    def test_list_lying_tuple_answer_serves_its_honest_triple(self):
        answer = ListLyingTuple([0, "state = running\n    pid = 4242\n", ""])
        with mock.patch.object(files_svc, "sh", return_value=answer):
            resp = client().get("/api/files/filebrowser")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertTrue(body["running"], body)
        self.assertEqual(body["pid"], 4242)

    def test_total_tuple_impostor_answer_still_reads_not_running(self):
        with mock.patch.object(files_svc, "sh", return_value=_liar(tuple)):
            resp = client().get("/api/files/filebrowser")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertFalse(resp.json()["running"])


# ── The fix #5: a lying-bool upload cap silently disabled the config ─────────

class UploadCapWrongRankTests(_FilesSandbox):
    def test_int_cap_lying_bool_is_honoured(self):
        """The operator configured 1 MB; the lie used to reset it to 512 and
        POST /api/files/upload accepted bodies the config said to refuse."""
        self.settings["max_upload_mb"] = IntLyingBool(1)
        resp = client().post(
            "/api/files/upload",
            data={"path": str(self.root)},
            files={"file": ("big16.bin", b"x" * (1024 * 1024 + 4096))},
        )
        self.assertEqual(resp.status_code, 400, resp.text[:300])
        _assert_clean(self, resp)
        self.assertIn("upload limit", resp.text)
        self.assertFalse((self.root / "big16.bin").exists(), "torn upload left on disk")

    def test_small_upload_still_completes_under_the_recovered_cap(self):
        self.settings["max_upload_mb"] = IntLyingBool(1)
        resp = client().post(
            "/api/files/upload",
            data={"path": str(self.root)},
            files={"file": ("small16.bin", b"payload")},
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertTrue((self.root / "small16.bin").exists())

    def test_honest_bool_cap_keeps_the_512_default(self):
        self.settings["max_upload_mb"] = True
        self.assertEqual(files_svc._max_upload_mb(), 512)

    def test_total_bool_impostor_cap_keeps_the_512_default(self):
        self.settings["max_upload_mb"] = _liar(bool)
        self.assertEqual(files_svc._max_upload_mb(), 512)


# ── Unit pins for the recovered launderers ───────────────────────────────────

class AsTextWrongRankUnitTests(unittest.TestCase):
    def test_str_lying_bytes_keeps_its_text(self):
        self.assertEqual(files_svc._as_text(StrLyingBytes("honest text")), "honest text")

    def test_bytearray_lying_bytes_decodes_first_come(self):
        self.assertEqual(files_svc._as_text(BytearrayLyingBytes(b"honest ba")), "honest ba")

    def test_total_impostors_still_drop(self):
        for junk in (_liar(bytes), _liar(bytearray), _liar(str)):
            self.assertEqual(files_svc._as_text(junk), "")

    def test_default_repr_shapes_drop_instead_of_leaking(self):
        self.assertEqual(files_svc._as_text(PlainJunk()), "")
        self.assertEqual(files_svc._as_text(files_svc._as_text), "")

    def test_plain_and_subclass_storage_stays_verbatim(self):
        self.assertEqual(files_svc._as_text(b"ok"), "ok")
        self.assertEqual(files_svc._as_text(bytearray(b"ba")), "ba")
        self.assertEqual(files_svc._as_text("\ud800x"), "?x")
        self.assertEqual(files_svc._as_text(7), "7")
        self.assertEqual(files_svc._as_text(None), "")

    def test_real_str_named_like_a_repr_is_data(self):
        self.assertEqual(files_svc._as_text("x at 0xBEEF>"), "x at 0xBEEF>")


class Sh3AndRcIntWrongRankUnitTests(unittest.TestCase):
    def test_list_lying_tuple_recovers_the_honest_triple(self):
        self.assertEqual(
            files_svc._sh3(ListLyingTuple([0, "a", "b"])), (0, "a", "b")
        )

    def test_wrong_arity_and_impostor_answers_stay_junk(self):
        self.assertEqual(files_svc._sh3(ListLyingTuple([0, "a"])), (-255, "", ""))
        self.assertEqual(files_svc._sh3(_liar(tuple)), (-255, "", ""))
        self.assertEqual(files_svc._sh3(_liar(list)), (-255, "", ""))
        self.assertEqual(files_svc._sh3(None), (-255, "", ""))

    def test_float_rc_lying_int_recovers_the_honest_exit(self):
        self.assertEqual(files_svc._rc_int(FloatLyingInt(0.0)), 0)
        self.assertEqual(files_svc._rc_int(FloatLyingInt(3.0)), 3)

    def test_int_impostor_rc_stays_junk_never_minus_one(self):
        self.assertEqual(files_svc._rc_int(_liar(int)), -255)
        self.assertEqual(files_svc._rc_int(object()), -255)

    def test_exact_and_bool_codes_stay_pinned(self):
        self.assertEqual(files_svc._rc_int(0), 0)
        self.assertEqual(files_svc._rc_int(3), 3)
        self.assertEqual(files_svc._rc_int(True), 1)
        self.assertEqual(files_svc._rc_int(False), 0)


class RootLabelAndCfgPathUnitTests(unittest.TestCase):
    def test_str_label_lying_bool_keeps_its_text(self):
        self.assertEqual(files_svc._root_label(StrLyingBool("myid")), "myid")

    def test_honest_bools_and_none_keep_the_fallback(self):
        self.assertEqual(files_svc._root_label(True), "")
        self.assertEqual(files_svc._root_label(False), "")
        self.assertEqual(files_svc._root_label(None), "")

    def test_cfg_path_preserves_surrogates_for_the_os(self):
        """Undecodable filename bytes spell as surrogates; the launder must
        not replace them or the os calls stop matching the real file."""
        self.assertEqual(files_svc._cfg_path_text("/tmp/a\udcffb"), "/tmp/a\udcffb")
        self.assertEqual(files_svc._cfg_path_text(b"/tmp/a\xffb"), "/tmp/a\udcffb")

    def test_cfg_path_recovers_lying_storage_and_drops_junk(self):
        self.assertEqual(
            files_svc._cfg_path_text(BytesLyingStr(b"/tmp/x")), "/tmp/x"
        )
        self.assertEqual(
            files_svc._cfg_path_text(StrLyingBytes("/tmp/y")), "/tmp/y"
        )
        for junk in (None, True, False, _liar(str), PlainJunk()):
            self.assertIsNone(files_svc._cfg_path_text(junk))


class LeftoverWatchdogTimeout(BaseException):
    pass


class Files16BaseExceptionNetTests(unittest.TestCase):
    def test_fold_swallows_str_baseexception(self):
        class _StrBomb:
            def __str__(self):
                raise LeftoverWatchdogTimeout("fold watchdog")

        self.assertEqual(files_svc._fold(_StrBomb()), "")

    def test_sh_triple_swallows_runner_baseexception(self):
        def boom(*_a, **_k):
            raise LeftoverWatchdogTimeout("sh watchdog")

        with mock.patch.object(files_svc, "sh", boom):
            self.assertEqual(files_svc._sh_triple(["true"], timeout=1)[0], -255)

    def test_fold_still_propagates_keyboardinterrupt(self):
        class _Ki:
            def __str__(self):
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            files_svc._fold(_Ki())


if __name__ == "__main__":
    unittest.main()
