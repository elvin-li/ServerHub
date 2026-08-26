"""WireGuard leftover-500 sweep #5: one live leftover found, fixed, pinned.

The live leftover
=================
``hub.wireguard_wstunnel.read_plist`` guarded ``plistlib.loads`` with the
enumerated tuple ``(OSError, plistlib.InvalidFileException, ValueError,
RecursionError)``.  That tuple loses against plistlib's XML path (the same
lesson ``files_svc`` already carries):

* a torn / truncated LaunchDaemon plist — exactly what a crash mid-write of
  ``/Library/LaunchDaemons/com.elvin.wstunnel-wg-server.plist`` leaves — makes
  expat raise ``xml.parsers.expat.ExpatError``, which subclasses ``Exception``
  directly, not ``ValueError``;
* a stray ``<key>`` outside any ``<dict>`` raises ``IndexError``;
* a junk ``<date>`` body raises ``AttributeError``
  (``NoneType.groupdict``).

``read_plist`` feeds the ``ttl_memo``'d ``live()``, which feeds
``wireguard_wstunnel.status()``, so all three of GET /api/wireguard,
GET /api/wireguard/settings and GET /api/wireguard/readiness answered raw
500s over the real mounted app (reproduced before the fix).  The fix follows
every sibling plist reader in this repo: ``except Exception``.

What stays pinned besides the fix
=================================
* ``read_plist`` unit pins for every junk class plistlib can produce,
  including the classes the old tuple *did* cover (oversize file, FIFO at the
  plist path, invalid UTF-8, non-plist bytes, junk ``<data>``/``<real>``) and
  the already-int over-cap hex ``<integer>`` argv that must survive as text.
* The remediate readback path: ``install_wstunnel`` re-reads the installed
  plist to verify what root is actually running; when that file is torn, the
  route must answer the *coded* ``wg.wstunnel_install_unverified`` — a
  rendered JSON 500 — never an uncaught ExpatError traceback.
* Stays-immune: ``listener_row`` with a torn IPv6 listen URL
  (``urlsplit``/``urlparse`` raise ValueError on ``.port``) answers ``None``,
  and the Network overview keeps its 200 with the torn plist in place.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from hub import wireguard_wstunnel  # noqa: E402

_EMPTY = {"listen": "", "restrict_to": ""}

#: A crash mid-write of the LaunchDaemon: valid prologue, truncated body.
#: plistlib raises xml.parsers.expat.ExpatError — not ValueError.
TORN_PLIST = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
    b'"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
    b'<plist version="1.0"><dict><key>ProgramArguments</key>'
    b'<array><string>/opt/homebrew/bin/wstu'
)
#: A stray <key> outside any <dict>: plistlib raises IndexError.
STRAY_KEY_PLIST = (
    b'<?xml version="1.0"?><plist version="1.0"><key>x</key></plist>'
)
#: A junk <date> body: plistlib raises AttributeError (NoneType.groupdict).
BAD_DATE_PLIST = (
    b'<?xml version="1.0"?><plist version="1.0">'
    b'<dict><key>a</key><date>junk</date></dict></plist>'
)
#: The three classes the old enumerated tuple let escape as raw 500s.
ESCAPED_CLASSES = {
    "torn_expat": TORN_PLIST,
    "stray_key_indexerror": STRAY_KEY_PLIST,
    "bad_date_attributeerror": BAD_DATE_PLIST,
}


def _no_surrogates(payload) -> None:
    """What Starlette's JSONResponse does to the body (allow_nan=False)."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class ReadPlistJunkUnitTests(unittest.TestCase):
    """Every junk class degrades to the empty snapshot, never an exception."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="wg5-plist-")
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def _read(self, data: bytes) -> dict:
        path = self.dir / "com.elvin.wstunnel-wg-server.plist"
        path.write_bytes(data)
        return wireguard_wstunnel.read_plist(path)

    def test_the_three_escaped_classes_now_answer_empty(self):
        for name, data in ESCAPED_CLASSES.items():
            with self.subTest(name=name):
                self.assertEqual(self._read(data), _EMPTY)

    def test_classes_the_old_tuple_already_covered_stay_covered(self):
        cases = {
            # plistlib.InvalidFileException on non-plist bytes.
            "not_a_plist": b"garbage bytes here",
            # binascii.Error (a ValueError subclass) on junk <data>.
            "bad_data": (
                b'<?xml version="1.0"?><plist version="1.0">'
                b'<dict><key>a</key><data>!!not-base64!!</data></dict></plist>'
            ),
            # ValueError on a non-float <real>.
            "bad_real": (
                b'<?xml version="1.0"?><plist version="1.0">'
                b'<dict><key>a</key><real>xx</real></dict></plist>'
            ),
            # ValueError: <key> inside an <array>.
            "key_in_array": (
                b'<?xml version="1.0"?><plist version="1.0">'
                b'<array><key>x</key></array></plist>'
            ),
            # Invalid UTF-8 in the XML body.
            "invalid_utf8": b'<?xml version="1.0"?><plist>\xff\xfe</plist>',
            # An empty <plist/> parses to None — not a dict.
            "non_dict_root": b'<?xml version="1.0"?><plist version="1.0"></plist>',
        }
        for name, data in cases.items():
            with self.subTest(name=name):
                self.assertEqual(self._read(data), _EMPTY)

    def test_oversize_plist_is_refused_by_the_read_cap(self):
        # Past the 256 KiB cap read_bytes_capped raises OSError(EFBIG); a
        # leftover multi-MB plist must not be loaded, let alone parsed.
        big = b'<?xml version="1.0"?><plist version="1.0"><dict>' + (
            b"<key>k</key><string>v</string>" * 20000
        )
        self.assertGreater(len(big), wireguard_wstunnel._PLIST_CAP)
        self.assertEqual(self._read(big), _EMPTY)

    def test_fifo_at_the_plist_path_answers_empty_not_a_hang_or_raise(self):
        fifo = self.dir / "fifo.plist"
        os.mkfifo(fifo)
        self.assertEqual(wireguard_wstunnel.read_plist(fifo), _EMPTY)

    def test_missing_file_answers_empty(self):
        self.assertEqual(
            wireguard_wstunnel.read_plist(self.dir / "absent.plist"), _EMPTY
        )

    def test_non_list_program_arguments_answers_empty(self):
        data = (
            b'<?xml version="1.0"?><plist version="1.0">'
            b"<dict><key>ProgramArguments</key><string>oops</string></dict></plist>"
        )
        self.assertEqual(self._read(data), _EMPTY)

    def test_over_cap_hex_integer_argv_survives_as_text(self):
        # plistlib parses <integer>0x…</integer> through int(x, 16), which
        # CPython's 4300-digit cap does not bound: the value arrives
        # already-int and a bare str() would raise the digit-cap ValueError.
        # _as_text must keep the surrounding listen/restrict tokens usable.
        huge_hex = b"0x" + b"f" * 5000
        data = (
            b'<?xml version="1.0"?><plist version="1.0">'
            b"<dict><key>ProgramArguments</key><array>"
            b"<string>/opt/homebrew/bin/wstunnel</string>"
            b"<string>server</string>"
            b"<integer>" + huge_hex + b"</integer>"
            b"<string>--restrict-to</string>"
            b"<string>127.0.0.1:51820</string>"
            b"<string>ws://0.0.0.0:8444</string>"
            b"</array></dict></plist>"
        )
        parsed = self._read(data)
        self.assertEqual(parsed["listen"], "ws://0.0.0.0:8444")
        self.assertEqual(parsed["restrict_to"], "127.0.0.1:51820")

    def test_torn_ipv6_listen_url_keeps_listener_row_immune(self):
        # urlparse(...).port raises ValueError on "ws://[::1:8444"; the
        # ports-tab row helper must answer None, not raise.
        self.assertIsNone(
            wireguard_wstunnel.listener_row({"listen": "ws://[::1:8444", "pid": 3})
        )


class _MountedRouteTests(unittest.TestCase):
    """Real app, auth overridden, plist path pointed at a scratch file."""

    def setUp(self):
        from fastapi.testclient import TestClient

        from hub.app_factory import create_app
        from hub.auth import require_auth

        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        app = create_app()
        app.dependency_overrides[require_auth] = lambda: True
        self.addCleanup(app.dependency_overrides.clear)
        self.client = TestClient(app, raise_server_exceptions=False)

        tmp = tempfile.TemporaryDirectory(prefix="wg5-http-")
        self.addCleanup(tmp.cleanup)
        self.plist = Path(tmp.name) / "com.elvin.wstunnel-wg-server.plist"
        self.stack.enter_context(mock.patch.object(
            wireguard_wstunnel, "PLIST_PATH", self.plist
        ))
        # live() memoises for 6 s; each request in these tests must re-read
        # the freshly written junk rather than a snapshot from a prior case.
        self.addCleanup(wireguard_wstunnel.live.invalidate)


class TornPlistHttpTests(_MountedRouteTests):
    """The live leftover: every escaped junk class over the mounted routes."""

    URLS = (
        "/api/wireguard",
        "/api/wireguard/settings",
        "/api/wireguard/readiness",
        "/api/system/network",
    )

    def test_every_escaped_class_answers_200_everywhere(self):
        for name, data in ESCAPED_CLASSES.items():
            self.plist.write_bytes(data)
            for url in self.URLS:
                with self.subTest(name=name, url=url):
                    wireguard_wstunnel.live.invalidate()
                    resp = self.client.get(url)
                    self.assertEqual(
                        resp.status_code, 200, f"{name} {url}: {resp.text[:300]}"
                    )
                    _no_surrogates(resp.json())

    def test_torn_plist_degrades_the_wstunnel_snapshot_to_defaults(self):
        self.plist.write_bytes(TORN_PLIST)
        wireguard_wstunnel.live.invalidate()
        resp = self.client.get("/api/wireguard/settings")
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        wst = resp.json()["wstunnel"]
        _no_surrogates(wst)
        # Nothing runs and the torn file contributed no listen/restrict, so
        # the snapshot reports the stored intent (defaults), not a crash.
        self.assertFalse(wst["running"])
        self.assertEqual(wst["listen"], wireguard_wstunnel.DEFAULT_LISTEN)
        # The torn file still *exists*, so "configured" may reflect that —
        # but the parse failure itself must not invent a live layout.
        self.assertEqual(wst["desired_restrict_to"], "127.0.0.1:51820")

    def test_fifo_at_the_daemon_path_keeps_the_routes_200(self):
        os.mkfifo(self.plist)
        for url in self.URLS:
            with self.subTest(url=url):
                wireguard_wstunnel.live.invalidate()
                resp = self.client.get(url)
                self.assertEqual(resp.status_code, 200, f"{url}: {resp.text[:300]}")
                _no_surrogates(resp.json())


class RemediateTornReadbackHttpTests(_MountedRouteTests):
    """install_wstunnel's post-install readback of a torn plist stays coded."""

    def setUp(self):
        super().setUp()
        from hub import wireguard_net_svc, wireguard_svc
        from hub.routers import wireguard_api

        self.stack.enter_context(mock.patch.object(
            wireguard_api, "require_admin_browser", lambda request: "admin"
        ))
        self.stack.enter_context(mock.patch.object(
            wireguard_svc, "installation",
            lambda: {"installed": True, "conf_exists": True, "conf_path": "",
                     "conf_dir": "", "wg": "wg", "wg_quick": "wg-quick",
                     "wireguard_go": "", "tools_version": "v1",
                     "userspace_version": "", "probe_failed": False},
        ))
        self.stack.enter_context(mock.patch.object(
            wireguard_wstunnel, "find_binary",
            lambda: wireguard_wstunnel.ALLOWED_BINARIES[0],
        ))
        # The privileged copy "succeeds" but what lands on disk is torn:
        # a crash between cp and bootstrap, or a filesystem that lied.
        self.stack.enter_context(mock.patch.object(
            wireguard_net_svc, "replace_secret_text",
            lambda path, content: Path(path),
        ))
        self.stack.enter_context(mock.patch.object(
            wireguard_net_svc, "run_admin_sequence",
            lambda cmds, timeout=180: {"ok": True},
        ))

    def test_torn_installed_plist_is_the_coded_unverified_500(self):
        self.plist.write_bytes(TORN_PLIST)
        resp = self.client.post(
            "/api/wireguard/remediate",
            json={"target": "wstunnel", "enabled": True},
        )
        # A coded, rendered JSON body — before the fix this was an uncaught
        # ExpatError traceback out of read_plist(target).
        self.assertEqual(resp.status_code, 500, resp.text[:300])
        payload = resp.json()
        _no_surrogates(payload)
        self.assertEqual(
            payload["detail"]["code"], "wg.wstunnel_install_unverified"
        )


if __name__ == "__main__":
    unittest.main()
