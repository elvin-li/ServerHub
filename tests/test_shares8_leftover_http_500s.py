"""Eighth leftover-500s sweep of the Shares / share-ACL surfaces.

After the shares6/shares7 folds sealed the dict-subclass ``.get`` / ``items()``
/ ``__bool__`` bombs, the nested ``_jsonable`` zoo, the ``__eq__`` / self-
``__str__`` ``encode`` probes and the ``raise_service_error`` param laundering,
this hunt drove every shares/ACL endpoint through both the router funnels
(mocked service returns) and the *real* service layer (hostile ``sharing`` /
``dscl`` / ``ls`` CLI output) over ``create_app()`` +
``TestClient(raise_server_exceptions=False)``.  The router funnels and the
service parsers stayed immune — no route answered a raw (uncoded) HTTP 500.

The one straggler was a *contract* leak in the public plist parser:

* **``parse_time_machine_records`` leaked ``xml.parsers.expat.ExpatError``** —
  a torn ``dscl -plist . -readall`` dump (malformed XML that has already begun
  parsing, e.g. an unclosed ``<array>``) raises ``ExpatError``, which — unlike
  ``plistlib.InvalidFileException`` (binary junk / empty output, itself a
  ``ValueError`` subclass) — is not a ``ValueError``.  The parser already
  normalised the *deeply-nested* ``RecursionError`` to ``ValueError`` (with
  its own test) precisely because it is a public, contract-bearing helper —
  every sibling plist reader (``raid_svc._plist``, ``snapshots_svc``,
  ``files_svc``, ``wireguard_wstunnel``) catches the whole family — but this
  one still let ``ExpatError`` escape untyped.  The live reader
  (``time_machine_records``) masks it with ``except Exception``, so the Shares
  page stayed 200; the fix closes the parser's own contract so any caller that
  catches the documented ``ValueError`` cannot 500.

The remaining classes below are pinned as *stays-immune*: they were sealed by
earlier sweeps and this hunt confirms they hold end to end.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest import mock
from xml.parsers.expat import ExpatError

from fastapi.testclient import TestClient

from hub import auth, share_acl_svc, shares_svc
from hub.app_factory import create_app
from hub.auth import require_auth

_app = None


def _the_app():
    global _app
    if _app is None:
        _app = create_app()
        _app.dependency_overrides[require_auth] = lambda: None
    return _app


def _client() -> TestClient:
    # raise_server_exceptions=False: a real 500 must arrive as HTTP 500 rather
    # than a re-raised exception that would mask which route crashed.
    return TestClient(_the_app(), raise_server_exceptions=False)


@contextmanager
def _admin_browser():
    with ExitStack() as stack:
        stack.enter_context(
            mock.patch.object(auth, "browser_authenticated", return_value=True))
        stack.enter_context(
            mock.patch.object(auth, "request_username", return_value="admin"))
        stack.enter_context(mock.patch.object(auth, "is_admin", return_value=True))
        yield


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _is_coded(response) -> bool:
    """A coded error carries ``detail.code``; a raw 500 is a bare traceback."""
    try:
        body = response.json()
    except Exception:
        return False
    return isinstance(body.get("detail"), dict) and bool(body["detail"].get("code"))


# ── the plist-parser contract: ValueError, never a leaked parse error ────────


class TimeMachineParserContractTests(unittest.TestCase):
    """``parse_time_machine_records`` fails as ``ValueError`` on any junk dump.

    The genuine leak is a torn XML dump: it raises ``ExpatError``, which a
    ``ValueError``-catching caller would not stop, while the parser's own
    docstring and its RecursionError sibling promise a ``ValueError`` failure.
    (``InvalidFileException`` from binary junk / empty output is already a
    ``ValueError`` subclass, so those never broke the contract — they are
    pinned here so a future hierarchy change cannot silently regress them.)
    """

    def test_expaterror_is_the_genuine_non_value_error_leak(self):
        # Guards the point of the fix: ExpatError is NOT a ValueError, so
        # pre-fix a torn XML dump escaped the parser's documented contract.
        self.assertFalse(issubclass(ExpatError, ValueError))

    def test_unclosed_xml_is_value_error_not_expat(self):
        # Pre-fix: xml.parsers.expat.ExpatError escaped untyped.
        with self.assertRaises(ValueError):
            shares_svc.parse_time_machine_records("<plist><array>")

    def test_truncated_array_body_is_value_error_not_expat(self):
        # A dump cut mid-record (the ``sh`` output cap) — another ExpatError.
        torn = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "">'
            '<plist version="1.0"><array><dict><key>dsAttrTypeStandard:RecordName'
        )
        with self.assertRaises(ValueError):
            shares_svc.parse_time_machine_records(torn)

    def test_non_plist_text_is_value_error(self):
        with self.assertRaises(ValueError):
            shares_svc.parse_time_machine_records("this is not a plist at all")

    def test_binary_junk_is_value_error(self):
        with self.assertRaises(ValueError):
            shares_svc.parse_time_machine_records(b"\x00\x01\x02bplist-nope")

    def test_empty_output_is_value_error(self):
        with self.assertRaises(ValueError):
            shares_svc.parse_time_machine_records("")

    def test_valid_non_array_keeps_its_own_value_error(self):
        # The isinstance branch (a valid plist that is not a top-level array)
        # must still raise ValueError, unchanged by the fix.
        with self.assertRaises(ValueError):
            shares_svc.parse_time_machine_records("<plist/>")


# ── the live reader and the Shares page stay immune to a torn plist ──────────


class TimeMachineReaderStaysImmuneTests(unittest.TestCase):
    """A torn ``dscl -plist -readall`` dump degrades to ``{}`` / a 200 page."""

    def test_reader_degrades_torn_plist_to_empty(self):
        for junk in ("<plist><array>", "not a plist", ""):
            with mock.patch("hub.shares_svc.sh", return_value=(0, junk, "")):
                self.assertEqual(shares_svc.time_machine_records(), {})

    def test_list_smb_shares_survives_a_torn_tm_plist(self):
        tmp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(tmp.cleanup)
        share_dir = str(Path(tmp.name).resolve())
        share_json = json.dumps({"Media": {"path": share_dir, "smb_name": "Media",
                                            "smb_shared": True}})

        def fake_sh(argv, **kwargs):
            a = list(argv)
            if a[:1] == [shares_svc.SHARING] and "-f" in a:
                return (0, share_json, "")
            if a[:1] == [shares_svc.SHARING]:
                return (0, "", "")
            if a[:2] == [shares_svc.DSCL, "-plist"]:
                return (0, "<plist><array>", "")  # torn -> ExpatError inside
            return (1, "", "")

        with mock.patch("hub.shares_svc.sh", side_effect=fake_sh):
            rows = shares_svc.list_smb_shares(include_sizes=False)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["record_name"], "Media")
        # The torn TM plist is absorbed: the row is present with TM off.
        self.assertFalse(rows[0]["time_machine"])
        _starlette(rows)

    def test_shares_page_answers_200_with_a_torn_tm_plist(self):
        tmp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(tmp.cleanup)
        share_dir = str(Path(tmp.name).resolve())
        share_json = json.dumps({"Media": {"path": share_dir, "smb_name": "Media",
                                            "smb_shared": True}})

        def fake_sh(argv, **kwargs):
            a = list(argv)
            if a[:1] == [shares_svc.SHARING] and "-f" in a:
                return (0, share_json, "")
            if a[:1] == [shares_svc.SHARING]:
                return (0, "", "")
            if a[:2] == [shares_svc.DSCL, "-plist"]:
                return (0, "not a plist", "")  # InvalidFileException inside
            return (1, "", "")

        with _admin_browser(), mock.patch("hub.shares_svc.sh", side_effect=fake_sh):
            response = _client().get("/api/shares")
        self.assertEqual(response.status_code, 200, response.text[:200])
        _starlette(response.json())


# ── stays-immune pins: the router funnels answer coded, never a raw 500 ──────


class RouterFunnelsStayImmuneTests(unittest.TestCase):
    """Every shares/ACL route answers coded (or 2xx) for hostile leftovers.

    These pin the shares6/shares7 folds end to end: whatever a privileged
    helper hands back, the route body is always the sanitized, coded shape —
    never a bare traceback.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self._tmp.cleanup)
        self.share_dir = str(Path(self._tmp.name).resolve())

    def _create(self, result):
        with _admin_browser(), mock.patch.object(
                shares_svc, "create_smb_share", return_value=result):
            return _client().post("/api/shares/smb", json={
                "path": "/tmp", "name": "M", "smb_name": "M"})

    def test_create_none_result_is_coded_not_raw_500(self):
        # A leftover ``None`` from the privileged helper degrades to
        # ``{"ok": False, "error": "failed"}`` and rides the coded
        # authorization-failed 500 rather than AttributeError'ing the route.
        response = self._create(None)
        self.assertEqual(response.status_code, 500, response.text[:200])
        self.assertTrue(_is_coded(response), response.text[:200])
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_failed")

    def test_overview_non_dict_answers_a_clean_page(self):
        for junk in (None, [1, 2], "nope"):
            with _admin_browser(), mock.patch.object(
                    shares_svc, "shares_overview", return_value=junk):
                response = _client().get("/api/shares")
            self.assertEqual(response.status_code, 200, response.text[:200])
            _starlette(response.json())

    def test_acl_get_none_state_is_coded_read_failure(self):
        with _admin_browser(), \
             mock.patch.object(shares_svc, "list_smb_shares", return_value=[
                 {"record_name": "M", "path": self.share_dir}]), \
             mock.patch.object(share_acl_svc, "read_acl", return_value=None), \
             mock.patch.object(share_acl_svc, "local_users", return_value=[]):
            response = _client().get("/api/shares/acl", params={"path": self.share_dir})
        self.assertEqual(response.status_code, 500, response.text[:200])
        self.assertTrue(_is_coded(response), response.text[:200])
        self.assertEqual(
            response.json()["detail"]["code"], "shares.acl_read_failed")

    def test_unknown_system_service_is_a_coded_400(self):
        with _admin_browser():
            response = _client().put(
                "/api/shares/system/not_a_service", json={"enabled": True})
        self.assertEqual(response.status_code, 400, response.text[:200])
        self.assertEqual(
            response.json()["detail"]["code"], "shares.unknown_service")


if __name__ == "__main__":
    unittest.main(verbosity=2)
