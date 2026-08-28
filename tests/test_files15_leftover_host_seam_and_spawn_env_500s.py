"""Fifteenth leftover-500s sweep of the Files page, over the real mounted app.

files14 sealed the runner: ``sh`` answers now travel through ``_sh_triple`` /
``_sh3`` / ``_rc_int`` and junk degrades to the ``(-255, "", "")`` failure
triple.  This pass re-fuzzed that seam (still immune) and then hunted the two
providers the FileBrowser sidecar *still* trusted after it:

* the **host-address provider**: ``filebrowser_status`` called ``host_ip()``
  bare and interpolated the answer into ``f"http://{host}:…"`` — and an
  f-string runs the answer's own ``__format__`` one seam *ahead* of the
  ``_as_text`` scrub wrapping the result.  This module does not own
  ``host_ip`` (tests and tooling patch it; the same rule the runner earned),
  so a provider raising outright — or answering a str subclass whose
  ``__format__`` bombs — was confirmed live as a raw ``500 Internal Server
  Error`` on GET /api/files (the Files page's first request: ``overview()``
  embeds the sidecar status beside the roots), GET /api/files/filebrowser,
  POST /api/files/filebrowser/ensure and /stop;

* the **spawn-env provider**: the direct-spawn branch of
  ``ensure_filebrowser`` evaluated ``utf8_env()`` inside a try whose except
  arm is typed ``(OSError, ValueError, TypeError)``, so a patched or odd
  provider raising anything else (RuntimeError, RecursionError) escaped the
  arm and 500'd POST /api/files/filebrowser/ensure raw, after the log/media
  directories were already created.

The fix is the provider-seam rule the sibling modules already follow:
``_host_text`` reduces every honest host answer (bytes, surrogates, subclass
wrappers) to an exact str the f-string cannot detonate on, and a raising or
unrenderable provider degrades to ``localhost`` — the sidecar URL is a hint,
not a gate, so the roots payload beside it keeps serving.  ``_spawn_env``
absorbs a raising env provider to ``{}`` (FileBrowser needs no inherited
variables to start) and materialises a dict-*subclass* answer through the
unbound ``dict.items`` so a hostile bound ``items`` cannot raise later inside
``Popen``'s own env walk, past the same typed arm.

The rest of the battery pins shapes the hunt found already immune, so a
refactor cannot quietly reopen them: bytes/surrogate/None/huge-int/liar host
answers, junk env answers, and the files14 runner shapes riding beside a
bombed host.  Deliberately NOT pinned to a different status: a spawn failure
with the binary still on disk stays the coded ``files.fb_start_failed`` that
test_files6 / the fb-hex battery already pin — this pass only launders the
*uncoded* stack 500s ahead of it.
"""
from __future__ import annotations

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


class FormatBombStr(str):
    """An honest-looking host whose ``__format__`` raises inside the f-string."""

    def __format__(self, spec):
        raise RuntimeError("host format bomb")


class StrBomb:
    """A host answer that cannot even render: ``__str__`` raises."""

    def __str__(self):
        raise RuntimeError("host str bomb")


class ItemsBombDict(dict):
    """A real env mapping in a subclass wrapper whose bound ``items`` raises."""

    def items(self):
        raise RuntimeError("env items bomb")

    def keys(self):
        raise RuntimeError("env keys bomb")

    def __iter__(self):
        raise RuntimeError("env iter bomb")


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


# ── The fix: host-provider shapes that each 500'd four Files routes ──────────

class HostSeamRouteTests(_FilesRoutes):
    """A raising ``host_ip`` / a ``__format__``-bomb answer.  Each was an HTTP
    500 on GET /api/files, GET /api/files/filebrowser, POST ensure and stop."""

    def _drive_with_host(self, patcher):
        with patcher, mock.patch.object(files_svc.time, "sleep", lambda *_: None):
            self._drive_fb()

    def test_host_provider_raising_runtimeerror(self):
        self._drive_with_host(
            mock.patch.object(files_svc, "host_ip", side_effect=RuntimeError("boom \ud800"))
        )

    def test_host_provider_raising_recursionerror(self):
        self._drive_with_host(
            mock.patch.object(files_svc, "host_ip", side_effect=RecursionError("deep"))
        )

    def test_host_format_bomb_answer(self):
        self._drive_with_host(
            mock.patch.object(files_svc, "host_ip", return_value=FormatBombStr("10.0.0.5"))
        )

    def test_raising_host_keeps_the_roots_payload(self):
        """The sidecar URL degrades to localhost; the roots beside it serve."""
        with mock.patch.object(files_svc, "host_ip", side_effect=RuntimeError("boom")):
            resp = client().get("/api/files")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        body = resp.json()
        self.assertIsInstance(body["roots"], list)
        self.assertEqual(body["filebrowser"]["url"], "http://localhost:8125")

    def test_format_bomb_still_serves_its_honest_text(self):
        """``_as_text`` reads the real str storage under the bombed wrapper."""
        with mock.patch.object(files_svc, "host_ip", return_value=FormatBombStr("10.0.0.5")):
            resp = client().get("/api/files/filebrowser")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["url"], "http://10.0.0.5:8125")


# ── Stays-immune: host answer shapes the same hunt found sealed ──────────────

class HostAnswerShapesStayImmuneTests(_FilesRoutes):
    def _drive_with_host(self, value):
        with mock.patch.object(files_svc, "host_ip", return_value=value), \
                mock.patch.object(files_svc.time, "sleep", lambda *_: None):
            self._drive_fb()

    def test_bytes_answer_decodes(self):
        with mock.patch.object(files_svc, "host_ip", return_value=b"192.168.1.4"):
            resp = client().get("/api/files/filebrowser")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["url"], "http://192.168.1.4:8125")

    def test_surrogate_answer_is_scrubbed(self):
        with mock.patch.object(files_svc, "host_ip", return_value="10.0.0.7\ud800"), \
                mock.patch.object(files_svc.time, "sleep", lambda *_: None):
            for route, resp in self._fb_routes():
                _assert_below_500(self, resp, route)

    def test_none_answer_degrades_to_localhost(self):
        with mock.patch.object(files_svc, "host_ip", return_value=None):
            resp = client().get("/api/files/filebrowser")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["url"], "http://localhost:8125")

    def test_over_cap_int_answer_degrades_to_localhost(self):
        """>4300 digits cannot render (CPython digit cap): junk, not a 500."""
        with mock.patch.object(files_svc, "host_ip", return_value=_HUGE_INT):
            resp = client().get("/api/files/filebrowser")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(resp.json()["url"], "http://localhost:8125")

    def test_str_bomb_and_liar_answers_stay_below_500(self):
        self._drive_with_host(StrBomb())
        self._drive_with_host(_liar(str))

    def test_bombed_host_beside_a_bombed_runner_still_serves(self):
        """Both sealed seams detonating together must not reopen either."""
        with mock.patch.object(files_svc, "host_ip", side_effect=RuntimeError("host bomb")), \
                mock.patch.object(files_svc, "sh", side_effect=RuntimeError("runner bomb")), \
                mock.patch.object(files_svc.time, "sleep", lambda *_: None):
            resp = client().get("/api/files")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        _assert_clean(self, resp)
        self.assertFalse(resp.json()["filebrowser"]["running"])


# ── The fix: the spawn-env provider on the direct-spawn branch ───────────────

class _SpawnSandbox(unittest.TestCase):
    """FB_BIN present, FB_PLIST absent, all sidecar paths inside one temp dir,
    ``Popen`` recorded rather than run, the runner answering not-running."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        fb_bin = self.tmp / "filebrowser-bin"
        fb_bin.write_bytes(b"#!/bin/sh\n")
        for name, value in [
            ("FB_BIN", fb_bin),
            ("FB_PLIST", self.tmp / "absent.plist"),
            ("FB_ROOT_DEFAULT", self.tmp / "media"),
            ("SERVICES_ROOT", self.tmp / "svc"),
            ("FB_LOG", self.tmp / "logs" / "fb.log"),
        ]:
            patched = mock.patch.object(files_svc, name, value)
            patched.start()
            self.addCleanup(patched.stop)
        for patched in (
            mock.patch.object(files_svc, "sh", return_value=(1, "", "")),
            mock.patch.object(files_svc.time, "sleep", lambda *_: None),
        ):
            patched.start()
            self.addCleanup(patched.stop)
        popen = mock.patch.object(files_svc.subprocess, "Popen")
        self.popen = popen.start()
        self.addCleanup(popen.stop)

    def _spawned_env(self):
        self.assertTrue(self.popen.called, "the spawn never ran")
        return self.popen.call_args.kwargs["env"]


class SpawnEnvSeamTests(_SpawnSandbox):
    def test_raising_env_provider_no_longer_500s_ensure(self):
        """RuntimeError escaped the typed (OSError, ValueError, TypeError) arm
        and was an HTTP 500 on POST /api/files/filebrowser/ensure."""
        with mock.patch.object(files_svc, "utf8_env", side_effect=RuntimeError("env bomb")):
            resp = client().post("/api/files/filebrowser/ensure")
        _assert_below_500(self, resp, "POST /api/files/filebrowser/ensure")
        self.assertEqual(self._spawned_env(), {})

    def test_recursionerror_env_provider_stays_below_500(self):
        with mock.patch.object(files_svc, "utf8_env", side_effect=RecursionError("deep")):
            resp = client().post("/api/files/filebrowser/ensure")
        _assert_below_500(self, resp, "POST /api/files/filebrowser/ensure")
        self.assertEqual(self._spawned_env(), {})

    def test_items_bomb_env_subclass_serves_its_real_storage(self):
        """The unbound ``dict.items`` read keeps the honest pairs; the bound
        bomb never reaches ``Popen``'s env walk."""
        answer = ItemsBombDict({"PATH": "/usr/bin", "LANG": "en_US.UTF-8"})
        with mock.patch.object(files_svc, "utf8_env", return_value=answer):
            resp = client().post("/api/files/filebrowser/ensure")
        _assert_below_500(self, resp, "POST /api/files/filebrowser/ensure")
        env = self._spawned_env()
        self.assertIs(type(env), dict)
        self.assertEqual(env, {"PATH": "/usr/bin", "LANG": "en_US.UTF-8"})

    def test_junk_env_answers_degrade_to_empty(self):
        for junk in (None, "text", 7, _liar(dict)):
            self.popen.reset_mock()
            with mock.patch.object(files_svc, "utf8_env", return_value=junk):
                resp = client().post("/api/files/filebrowser/ensure")
            _assert_below_500(self, resp, "POST /api/files/filebrowser/ensure")
            self.assertEqual(self._spawned_env(), {})

    def test_honest_env_passes_through_untouched(self):
        honest = {"PATH": "/usr/bin"}
        with mock.patch.object(files_svc, "utf8_env", return_value=honest):
            resp = client().post("/api/files/filebrowser/ensure")
        _assert_below_500(self, resp, "POST /api/files/filebrowser/ensure")
        self.assertIs(self._spawned_env(), honest)


# ── Unit pins for the new launderers ─────────────────────────────────────────

class HostTextUnitTests(unittest.TestCase):
    def test_exact_answer_passes(self):
        with mock.patch.object(files_svc, "host_ip", return_value="192.168.1.9"):
            self.assertEqual(files_svc._host_text(), "192.168.1.9")

    def test_answer_is_stripped(self):
        with mock.patch.object(files_svc, "host_ip", return_value="  10.0.0.2\n"):
            self.assertEqual(files_svc._host_text(), "10.0.0.2")

    def test_raising_provider_reads_as_localhost(self):
        with mock.patch.object(files_svc, "host_ip", side_effect=RuntimeError("boom")):
            self.assertEqual(files_svc._host_text(), "localhost")

    def test_none_empty_and_huge_read_as_localhost(self):
        for junk in (None, "", "   ", _HUGE_INT):
            with mock.patch.object(files_svc, "host_ip", return_value=junk):
                self.assertEqual(files_svc._host_text(), "localhost")

    def test_bytes_answer_decodes(self):
        with mock.patch.object(files_svc, "host_ip", return_value=b"172.16.0.3"):
            self.assertEqual(files_svc._host_text(), "172.16.0.3")

    def test_format_bomb_answers_its_honest_text(self):
        with mock.patch.object(files_svc, "host_ip", return_value=FormatBombStr("10.0.0.5")):
            self.assertEqual(files_svc._host_text(), "10.0.0.5")

    def test_surrogate_answer_is_scrubbed(self):
        with mock.patch.object(files_svc, "host_ip", return_value="a\ud800b"):
            text = files_svc._host_text()
        text.encode("utf-8")
        self.assertNotIn("\ud800", text)


class SpawnEnvUnitTests(unittest.TestCase):
    def test_exact_dict_passes_the_same_object(self):
        honest = {"A": "B"}
        with mock.patch.object(files_svc, "utf8_env", return_value=honest):
            self.assertIs(files_svc._spawn_env(), honest)

    def test_raising_provider_degrades_to_empty(self):
        with mock.patch.object(files_svc, "utf8_env", side_effect=RuntimeError("boom")):
            self.assertEqual(files_svc._spawn_env(), {})

    def test_items_bomb_subclass_serves_its_real_storage(self):
        answer = ItemsBombDict({"A": "B"})
        with mock.patch.object(files_svc, "utf8_env", return_value=answer):
            env = files_svc._spawn_env()
        self.assertIs(type(env), dict)
        self.assertEqual(env, {"A": "B"})

    def test_liar_and_scalar_junk_degrade_to_empty(self):
        for junk in (_liar(dict), None, "text", 7):
            with mock.patch.object(files_svc, "utf8_env", return_value=junk):
                self.assertEqual(files_svc._spawn_env(), {})


if __name__ == "__main__":
    unittest.main()
