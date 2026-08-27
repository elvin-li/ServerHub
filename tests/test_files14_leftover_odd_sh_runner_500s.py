"""Fourteenth leftover-500s sweep of the Files page, over the real mounted app.

files13 sealed the section-key hash probes; files10-12 sealed the roots rows,
class-property bombs and lying-``__class__`` impostors on the settings
surface.  This pass re-fuzzed that whole zoo (still immune) and then hunted
the one provider every earlier files pass trusted: the **runner**.
``filebrowser_status`` did ``rc, out, _ = sh(...)`` and probed ``rc == 0``
bare, and the sidecar mutations fired ``sh(...)`` fire-and-forget — but this
module does not own ``sh`` (tests and tooling patch it; the
gateway5 / brew / docker_cli / host_address rule).  Confirmed live before
the fix — each of these answered a raw ``500 Internal Server Error`` on
GET /api/files (the Files page's first request: ``overview()`` embeds the
FileBrowser status beside the roots), GET /api/files/filebrowser, POST
/api/files/filebrowser/ensure and /stop:

* ``sh`` raising outright (RecursionError from a leftover ``str(e)`` on a
  nested exception is not ValueError; FileNotFoundError from a stub) rode
  straight to Starlette out of the status read and out of the ignored
  bootstrap/bootout/pkill spawns;
* a bare ``None`` / wrong-arity 2-tuple answer TypeError'd / ValueError'd
  the ``rc, out, _ = sh(...)`` unpack the same way;
* a tuple *subclass* whose bound ``__iter__`` bombs blew the same unpack;
* an rc int-subclass whose ``__eq__``/``__ne__`` raises detonated the bare
  ``rc == 0`` probe.

The fix is the nginx/brew ``_sh_triple`` rule: the spawn and the unpack move
inside a guard, junk degrades to the ``(-255, "", "")`` failure triple
(``-255`` is no honest exit, so a poisoned answer can never read as
success), and ``_rc_int`` launders the code through unbound
``int.__index__`` so an honest exit inside a bombed wrapper still serves
while a lying ``__class__`` impostor drops with the junk.

The rest of the battery pins shapes the same hunt found already immune, so
a refactor cannot quietly reopen them: rc liars/huge ints, bytes/surrogate
launchctl output, an over-cap pgrep pid, isoformat-property bombs and
hash-shadow keys inside roots rows, >4300-digit ints riding a row id and
the upload cap, and a huge-number JSON body against POST /api/files/mkdir
(``json.loads`` of those digits is ValueError, *not* JSONDecodeError, so
nothing here may catch JSONDecodeError alone).
"""
from __future__ import annotations

import plistlib
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from hub import files_svc
from hub.app_factory import create_app
from hub.auth import require_auth

#: Built arithmetically: int("9" * 5000) itself trips the digit cap.
_HUGE_INT = 16 ** 6000

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


# ── The leftover bomb / impostor classes ─────────────────────────────────────

def _liar(claim):
    """A plain object whose ``__class__`` property lies about its type."""
    return type("Liar", (object,), {"__class__": property(lambda self: claim)})()


class IntEqBomb(int):
    """An rc whose ``__eq__``/``__ne__`` raises — the bare probe detonates."""

    def __eq__(self, other):
        raise RuntimeError("rc eq bomb")

    def __ne__(self, other):
        raise RuntimeError("rc ne bomb")

    def __hash__(self):
        return 0


class IterBombTuple(tuple):
    """A 3-tuple in a subclass wrapper whose bound ``__iter__`` raises."""

    def __iter__(self):
        raise RuntimeError("tuple iter bomb")


class IterBombList(list):
    def __iter__(self):
        raise RuntimeError("list iter bomb")


class IsoBomb:
    @property
    def isoformat(self):
        raise RuntimeError("isoformat property bomb")


class HashShadowKey:
    """Hash-collides with a real mapping key; ``__eq__`` raises in the probe."""

    def __init__(self, target: str):
        self._h = hash(target)

    def __hash__(self):
        return self._h

    def __eq__(self, other):
        raise RuntimeError("shadow key eq bomb")


class _FilesRoutes(unittest.TestCase):
    def _fb_routes(self):
        return [
            ("GET /api/files", client().get("/api/files")),
            ("GET /api/files/filebrowser", client().get("/api/files/filebrowser")),
            ("POST /api/files/filebrowser/ensure", client().post("/api/files/filebrowser/ensure")),
            ("POST /api/files/filebrowser/stop", client().post("/api/files/filebrowser/stop")),
        ]

    def _drive_fb(self):
        for route, resp in self._fb_routes():
            _assert_below_500(self, resp, route)


# ── The fix: odd-runner shapes that each 500'd four Files routes ─────────────

class OddRunnerRouteTests(_FilesRoutes):
    """Raising / wrong-arity / bombed ``sh`` answers.  Each was an HTTP 500 on
    GET /api/files, GET /api/files/filebrowser, POST ensure and POST stop."""

    def _drive_with_sh(self, patcher):
        with patcher:
            self._drive_fb()

    def test_sh_raising_recursionerror_with_surrogate(self):
        self._drive_with_sh(
            mock.patch.object(files_svc, "sh", side_effect=RecursionError("deep \ud800"))
        )

    def test_sh_raising_filenotfound(self):
        self._drive_with_sh(
            mock.patch.object(files_svc, "sh", side_effect=FileNotFoundError("gone"))
        )

    def test_sh_answering_none(self):
        self._drive_with_sh(mock.patch.object(files_svc, "sh", return_value=None))

    def test_sh_answering_wrong_arity(self):
        self._drive_with_sh(mock.patch.object(files_svc, "sh", return_value=(0, "x")))

    def test_sh_answering_rc_eq_bomb(self):
        self._drive_with_sh(
            mock.patch.object(
                files_svc, "sh",
                return_value=(IntEqBomb(0), "state = running\n pid = 7", ""),
            )
        )

    def test_sh_answering_iterbomb_tuple_subclass(self):
        self._drive_with_sh(
            mock.patch.object(files_svc, "sh", return_value=IterBombTuple((0, "", "")))
        )

    def test_raising_sh_keeps_the_roots_payload(self):
        """The sidecar degrades to not-running; the roots beside it serve."""
        with mock.patch.object(files_svc, "sh", side_effect=RuntimeError("runner bomb")):
            resp = client().get("/api/files")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        body = resp.json()
        self.assertIsInstance(body["roots"], list)
        self.assertFalse(body["filebrowser"]["running"])

    def test_honest_answer_in_a_bombed_tuple_wrapper_still_serves(self):
        """The unbound base read sees the real storage: running + pid serve."""
        answer = IterBombTuple((0, "state = running\n pid = 42", ""))
        with mock.patch.object(files_svc, "sh", return_value=answer):
            resp = client().get("/api/files/filebrowser")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        body = resp.json()
        self.assertTrue(body["running"])
        self.assertEqual(body["pid"], 42)


class OddRunnerOndemandTests(unittest.TestCase):
    """POST /api/files/filebrowser/ondemand fires launchctl after the plist
    write; a raising runner used to 500 it with the plist already changed."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.plist = self.tmp / "local.filebrowser.plist"
        self.plist.write_bytes(
            plistlib.dumps({"Label": "local.filebrowser", "RunAtLoad": True, "KeepAlive": True})
        )
        patched = mock.patch.object(files_svc, "FB_PLIST", self.plist)
        patched.start()
        self.addCleanup(patched.stop)

    def test_raising_runner_still_answers_200_and_writes_the_plist(self):
        with mock.patch.object(files_svc, "sh", side_effect=RuntimeError("runner bomb")):
            resp = client().post(
                "/api/files/filebrowser/ondemand", json={"enabled": True}
            )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        self.assertTrue(resp.json()["ok"])
        written = plistlib.loads(self.plist.read_bytes())
        self.assertFalse(written["RunAtLoad"])
        self.assertFalse(written["KeepAlive"])

    def test_ensure_with_plist_and_raising_runner_stays_below_500(self):
        with mock.patch.object(files_svc, "sh", side_effect=RuntimeError("runner bomb")), \
                mock.patch.object(files_svc.time, "sleep", lambda *_: None):
            resp = client().post("/api/files/filebrowser/ensure")
        _assert_below_500(self, resp, "POST /api/files/filebrowser/ensure")


# ── Stays-immune: odd-runner value shapes the same hunt found sealed ─────────

class OddRunnerValueShapesStayImmuneTests(_FilesRoutes):
    def test_rc_int_liar_reads_as_failure(self):
        with mock.patch.object(files_svc, "sh", return_value=(_liar(int), "", "")):
            self._drive_fb()

    def test_rc_over_cap_int_reads_as_failure(self):
        with mock.patch.object(files_svc, "sh", return_value=(_HUGE_INT, "", "")):
            self._drive_fb()

    def test_bytes_output_still_parses(self):
        answer = (0, b"state = running\n pid = 9", b"")
        with mock.patch.object(files_svc, "sh", return_value=answer):
            resp = client().get("/api/files/filebrowser")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertTrue(resp.json()["running"])
        self.assertEqual(resp.json()["pid"], 9)

    def test_over_cap_pid_text_degrades_to_null(self):
        answer = (0, "state = running\n pid = " + "9" * 5000, "")
        with mock.patch.object(files_svc, "sh", return_value=answer):
            resp = client().get("/api/files/filebrowser")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        self.assertTrue(resp.json()["running"])
        self.assertIsNone(resp.json()["pid"])

    def test_surrogate_output_is_scrubbed(self):
        answer = (0, "state = running\n pid = 5 \ud800", "")
        with mock.patch.object(files_svc, "sh", return_value=answer):
            for route, resp in self._fb_routes():
                _assert_below_500(self, resp, route)


# ── Stays-immune: fresh settings-surface shapes files13's zoo never carried ──

class _FilesSandbox(unittest.TestCase):
    """One temp browsable root; ``settings_section`` patched with a plain dict
    carrying the leftover values/keys (models hub.config's real laundering)."""

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
        routes = [
            ("GET /api/files", client().get("/api/files")),
            ("GET /api/files/list", client().get("/api/files/list")),
            (
                "GET /api/files/download",
                client().get(
                    "/api/files/download",
                    params={"path": str(self.root / "a.txt")},
                ),
            ),
            (
                "POST /api/files/upload",
                client().post(
                    "/api/files/upload",
                    data={"path": str(self.root)},
                    files={"file": ("up14.bin", b"payload")},
                ),
            ),
        ]
        for route, resp in routes:
            _assert_below_500(self, resp, route)


class FreshSettingsShapesStayImmuneTests(_FilesSandbox):
    def test_isoformat_property_bomb_row_field(self):
        self.settings["roots"] = [
            {"id": IsoBomb(), "path": str(self.root)},
            {"id": "r", "path": str(self.root)},
        ]
        self._drive_all()

    def test_hash_shadow_key_inside_a_row_drops_that_row_alone(self):
        self.settings["roots"] = [
            {HashShadowKey("path"): "x", "id": "bombed"},
            {"id": "r", "path": str(self.root)},
        ]
        self._drive_all()
        resp = client().get("/api/files")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        ids = [x["id"] for x in resp.json()["roots"]]
        self.assertIn("r", ids)
        self.assertNotIn("bombed", ids)

    def test_over_cap_int_row_id_degrades_to_basename(self):
        self.settings["roots"] = [{"id": _HUGE_INT, "path": str(self.root)}]
        self._drive_all()
        resp = client().get("/api/files")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertIn("root", [x["id"] for x in resp.json()["roots"]])

    def test_over_cap_int_upload_cap_falls_back_to_512(self):
        self.settings["max_upload_mb"] = _HUGE_INT
        self.assertEqual(files_svc._max_upload_mb(), 512)
        self._drive_all()

    def test_iterbomb_list_subclass_roots_degrades_to_defaults(self):
        self.settings["roots"] = IterBombList([{"id": "r", "path": str(self.root)}])
        self._drive_all()

    def test_huge_number_json_body_is_not_a_500(self):
        """``json.loads`` of >4300 digits raises ValueError, not
        JSONDecodeError; the body parse must still answer 4xx."""
        body = '{"path": ' + "9" * 5000 + ', "name": "x"}'
        resp = client().post(
            "/api/files/mkdir",
            content=body,
            headers={"content-type": "application/json"},
        )
        _assert_below_500(self, resp, "POST /api/files/mkdir")
        self.assertGreaterEqual(resp.status_code, 400)


# ── Unit pins for the new launderers ─────────────────────────────────────────

class RcIntUnitTests(unittest.TestCase):
    def test_exact_int_passes(self):
        self.assertEqual(files_svc._rc_int(0), 0)
        self.assertEqual(files_svc._rc_int(3), 3)

    def test_bools_read_as_their_int_value(self):
        self.assertEqual(files_svc._rc_int(True), 1)
        self.assertEqual(files_svc._rc_int(False), 0)

    def test_honest_exit_in_a_bombed_wrapper_survives(self):
        self.assertEqual(files_svc._rc_int(IntEqBomb(3)), 3)
        self.assertEqual(files_svc._rc_int(IntEqBomb(0)), 0)

    def test_liar_and_junk_read_as_minus_255(self):
        self.assertEqual(files_svc._rc_int(_liar(int)), -255)
        self.assertEqual(files_svc._rc_int(None), -255)
        self.assertEqual(files_svc._rc_int(object()), -255)

    def test_over_cap_int_reads_as_minus_255(self):
        self.assertEqual(files_svc._rc_int(_HUGE_INT), -255)

    def test_numeric_text_converts(self):
        self.assertEqual(files_svc._rc_int("7"), 7)


class Sh3UnitTests(unittest.TestCase):
    def test_exact_triple_passes_untouched(self):
        self.assertEqual(files_svc._sh3((0, "a", "b")), (0, "a", "b"))

    def test_none_and_wrong_arity_degrade(self):
        self.assertEqual(files_svc._sh3(None), (-255, "", ""))
        self.assertEqual(files_svc._sh3((0, "a")), (-255, "", ""))
        self.assertEqual(files_svc._sh3((0, "a", "b", "c")), (-255, "", ""))

    def test_bombed_tuple_wrapper_serves_its_real_storage(self):
        self.assertEqual(files_svc._sh3(IterBombTuple((0, "a", "b"))), (0, "a", "b"))

    def test_bombed_list_wrapper_serves_its_real_storage(self):
        self.assertEqual(
            files_svc._sh3(IterBombList([0, "a", "b"])), (0, "a", "b")
        )

    def test_lying_tuple_impostor_degrades(self):
        self.assertEqual(files_svc._sh3(_liar(tuple)), (-255, "", ""))
        self.assertEqual(files_svc._sh3(_liar(list)), (-255, "", ""))

    def test_sh_triple_absorbs_a_raising_runner(self):
        with mock.patch.object(files_svc, "sh", side_effect=RuntimeError("bomb \ud800")):
            rc, out, err = files_svc._sh_triple(["/bin/true"], timeout=1)
        self.assertEqual(rc, -255)
        self.assertEqual(out, "")
        err.encode("utf-8")
        self.assertNotIn("\ud800", err)


if __name__ == "__main__":
    unittest.main()
