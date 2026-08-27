"""Ninth leftover-500s sweep of the Shares / share-ACL surfaces.

shares8 sealed the ``parse_time_machine_records`` ExpatError parser-contract
leak and nas8 planted ``_isa`` on ``shares_svc``.  This hunt drove every
shares/ACL endpoint through both the router funnels (mocked service returns)
and the real service layer (hostile ``sharing`` / ``dscl`` / ``ls`` output and
poisoned config rows) over ``create_app()`` +
``TestClient(raise_server_exceptions=False)``, looking for NEW vectors on the
already-hardened code.  Two stragglers turned up:

* **``shares_overview`` caught only ``OSError`` around ``gethostname``** — the
  hostname line sits one step *outside* the fan-out that rescues every other
  collector, and the route (``shares()``) pastes ``shares_overview()`` in
  without a guard of its own.  ``gethostname()`` decodes the system name, so a
  name it cannot decode raises ``UnicodeError`` (a *ValueError* subclass), not
  ``OSError`` — a raw HTTP 500 on GET /api/shares.  Its own siblings
  ``detect_lan_ip`` / ``normalize_local_url`` already treat every
  ``gethostname`` call as raising ``(OSError, UnicodeError, ValueError,
  TypeError)``; the fix brings this line into line.

* **``parse_time_machine_records`` leaked ``TypeError`` on non-text input** —
  the same public-parser contract shares8 sealed for ``ExpatError``, one shape
  further out.  A non-text leftover (int / dict / list, or a value whose
  ``__class__`` is a raising property so it answers neither ``str`` nor
  ``bytes``) reached ``plistlib.loads`` as a bare ``TypeError``, which is NOT a
  ``ValueError`` — so a caller catching the documented ``ValueError`` (the
  sibling ``_json_shares`` / raid_svc / snapshots_svc rule) would not stop it.
  The live reader masks it with ``except Exception`` so the page stayed 200;
  the fix closes the parser's own contract.

The remaining classes are pinned as *stays-immune*: earlier sweeps sealed them
and this hunt confirms they hold end to end.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest import mock

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


class _RaisingClass:
    """A leftover whose ``__class__`` is a raising property.

    ``isinstance`` consults ``__class__`` when the exact-type check misses, so a
    bare ``isinstance`` gate detonates on it — the account8 / nas8 bomb class.
    """

    @property
    def __class__(self):  # noqa: D401 - property, not a method
        raise RuntimeError("__class__ is a landmine")


# ── the genuine straggler: GET /api/shares survives a hostile hostname ───────


class OverviewHostnameStaysUpTests(unittest.TestCase):
    """``gethostname`` raising ``UnicodeError`` must not 500 GET /api/shares."""

    def test_gethostname_unicode_error_degrades_to_empty_name(self):
        # Pre-fix: shares_overview caught only OSError, so a UnicodeDecodeError
        # (a ValueError) escaped the whole page.
        boom = UnicodeDecodeError("utf-8", b"", 0, 1, "bad hostname")
        with _admin_browser(), \
             mock.patch("hub.shares_svc.socket.gethostname", side_effect=boom):
            response = _client().get("/api/shares")
        self.assertEqual(response.status_code, 200, response.text[:200])
        body = response.json()
        self.assertEqual(body["host"]["name"], "")
        _starlette(body)

    def test_gethostname_value_error_degrades_to_empty_name(self):
        with _admin_browser(), \
             mock.patch("hub.shares_svc.socket.gethostname",
                        side_effect=ValueError("embedded NUL")):
            response = _client().get("/api/shares")
        self.assertEqual(response.status_code, 200, response.text[:200])
        self.assertEqual(response.json()["host"]["name"], "")

    def test_overview_helper_survives_a_hostile_hostname(self):
        # The collector itself, not just the route: a torn hostname must not
        # take the whole payload down before the route can clean it.
        with mock.patch("hub.shares_svc.socket.gethostname",
                        side_effect=UnicodeError("torn")):
            overview = shares_svc.shares_overview()
        self.assertEqual(overview["host"]["name"], "")
        _starlette(overview)


# ── the parser-contract straggler: ValueError, never a leaked TypeError ──────


class TimeMachineParserNonTextContractTests(unittest.TestCase):
    """``parse_time_machine_records`` fails as ``ValueError`` on non-text junk.

    shares8 pinned the *torn XML* (ExpatError) and binary / empty
    (InvalidFileException) cases.  This pins the input-shape frontier: a
    non-text leftover, or a value whose ``__class__`` is a raising property,
    must not escape as the bare ``TypeError`` ``plistlib.loads`` raises.
    """

    def test_int_input_is_value_error_not_typeerror(self):
        with self.assertRaises(ValueError):
            shares_svc.parse_time_machine_records(1234567890)

    def test_dict_input_is_value_error_not_typeerror(self):
        with self.assertRaises(ValueError):
            shares_svc.parse_time_machine_records({"not": "bytes"})

    def test_list_input_is_value_error_not_typeerror(self):
        with self.assertRaises(ValueError):
            shares_svc.parse_time_machine_records(["not", "bytes"])

    def test_class_property_bomb_input_is_value_error(self):
        # isinstance(plist_text, str) on a ``__class__``-property bomb detonates
        # the gate itself; the parser must still answer its coded ValueError.
        with self.assertRaises(ValueError):
            shares_svc.parse_time_machine_records(_RaisingClass())

    def test_bytearray_input_still_parses(self):
        # A valid bytearray plist keeps working (no regression for bytes-like).
        data = bytearray(b"<plist><array/></plist>")
        self.assertEqual(shares_svc.parse_time_machine_records(data), {})

    def test_str_with_lone_surrogate_is_value_error(self):
        # A str the default encode could not represent used to leak
        # UnicodeEncodeError from outside the try; unbound ``str.encode`` with
        # ``replace`` keeps it inside the parser's ValueError contract.
        with self.assertRaises(ValueError):
            shares_svc.parse_time_machine_records("<plist>\ud800</plist")

    def test_valid_plist_still_parses(self):
        self.assertEqual(
            shares_svc.parse_time_machine_records("<plist><array/></plist>"), {})


class TimeMachineReaderMasksNonTextParseTests(unittest.TestCase):
    """The live reader / Shares page stay 200 even if the parser raises."""

    def test_reader_degrades_a_raising_parser_to_empty(self):
        with mock.patch("hub.shares_svc.sh", return_value=(0, "junk", "")), \
             mock.patch("hub.shares_svc.parse_time_machine_records",
                        side_effect=TypeError("leaked")):
            self.assertEqual(shares_svc.time_machine_records(), {})

    def test_shares_page_answers_200_when_the_tm_parser_raises(self):
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
                return (0, "whatever", "")
            return (1, "", "")

        with _admin_browser(), \
             mock.patch("hub.shares_svc.sh", side_effect=fake_sh), \
             mock.patch("hub.shares_svc.parse_time_machine_records",
                        side_effect=TypeError("leaked")):
            response = _client().get("/api/shares")
        self.assertEqual(response.status_code, 200, response.text[:200])
        _starlette(response.json())


# ── stays-immune pins: huge JSON numbers keep the listing (siblings kept) ────


class HugeJsonNumberStaysImmuneTests(unittest.TestCase):
    """An over-cap number in ``sharing -l -f json`` drops, siblings survive.

    ``int(str)`` past CPython's 4300-digit cap raises ``ValueError`` — not
    ``JSONDecodeError`` — from inside the decoder, so one poisoned field used
    to wipe the whole SMB listing.  ``_int_capped`` loads it as ``None``.
    """

    def test_json_shares_keeps_the_row_past_the_digit_cap(self):
        huge = "9" * 4600
        out = json.dumps({"Media": {"path": "/x", "smb_name": "M",
                                    "smb_shared": True}})
        # Splice a raw over-cap literal into a numeric field of the object.
        poisoned = out.replace('"smb_shared": true',
                               f'"smb_shared": true, "junk": {huge}')
        rows = shares_svc._json_shares(poisoned)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["record_name"], "Media")
        _starlette(rows)

    def test_list_smb_shares_survives_a_huge_number_field(self):
        huge = "8" * 4600
        base = json.dumps({"Media": {"path": None, "smb_name": "Media",
                                     "smb_shared": True}})
        share_json = base.replace('"smb_shared": true',
                                  '"smb_shared": true, "junk": ' + huge)

        def fake_sh(argv, **kwargs):
            a = list(argv)
            if a[:1] == [shares_svc.SHARING] and "-f" in a:
                return (0, share_json, "")
            return (1, "", "")

        with mock.patch("hub.shares_svc.sh", side_effect=fake_sh):
            rows = shares_svc.list_smb_shares(include_sizes=False)
        self.assertEqual([r["record_name"] for r in rows], ["Media"])
        _starlette(rows)


# ── stays-immune pins: poisoned quick_links config keeps the page 200 ────────


class PoisonedQuickLinksStaysImmuneTests(unittest.TestCase):
    """A ``__bool__``-bomb / hostile ``quick_links`` config must not 500."""

    def test_bool_bomb_quick_links_degrades_file_services(self):
        class BoolBomb:
            def __bool__(self):
                raise RuntimeError("truthiness landmine")

        # ``cfg().get("quick_links") or []`` evaluates the value's truthiness;
        # the ``_safe`` wrapper in shares_overview keeps the page up.
        with mock.patch("hub.shares_svc.cfg", return_value={"quick_links": BoolBomb()}):
            overview = shares_svc.shares_overview()
        self.assertIn("file_services", overview)
        _starlette(overview)

    def test_bool_bomb_quick_links_keeps_the_shares_page_200(self):
        class BoolBomb:
            def __bool__(self):
                raise RuntimeError("truthiness landmine")

        with _admin_browser(), \
             mock.patch("hub.shares_svc.cfg",
                        return_value={"quick_links": BoolBomb()}):
            response = _client().get("/api/shares")
        self.assertEqual(response.status_code, 200, response.text[:200])
        _starlette(response.json())


# ── stays-immune pins: hostile service results answer coded, never raw ───────


class ServiceResultStaysImmuneTests(unittest.TestCase):
    """A ``__class__``-property-bomb / dict-subclass service result is coded."""

    def _create(self, result):
        with _admin_browser(), mock.patch.object(
                shares_svc, "create_smb_share", return_value=result):
            return _client().post("/api/shares/smb", json={
                "path": "/tmp", "name": "M", "smb_name": "M"})

    def test_class_property_bomb_result_is_coded_not_raw_500(self):
        response = self._create(_RaisingClass())
        self.assertEqual(response.status_code, 500, response.text[:200])
        self.assertTrue(_is_coded(response), response.text[:200])
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_failed")

    def test_get_bomb_dict_subclass_result_maps_its_failure_coded(self):
        # A dict-*subclass* failure result whose bound ``.get`` raises (the
        # jobs/metrics row-bomb class) is laundered through ``dict()`` — the
        # C-level copy sidesteps the override — so its coded ``error`` still
        # maps to the mapped refusal instead of a raw 500.
        class GetBomb(dict):
            def get(self, *a, **k):
                raise RuntimeError("bound get landmine")

        response = self._create(GetBomb(ok=False, error="cancelled"))
        self.assertEqual(response.status_code, 409, response.text[:200])
        self.assertTrue(_is_coded(response), response.text[:200])
        self.assertEqual(
            response.json()["detail"]["code"], "shares.authorization_cancelled")


# ── stays-immune pins: a FIFO / blocking share path is a coded refusal ───────


class FifoSharePathStaysImmuneTests(unittest.TestCase):
    """A FIFO occupying a share/ACL path is the coded bad_path, not a hang."""

    def test_read_acl_on_a_fifo_is_coded_bad_path(self):
        tmp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(tmp.cleanup)
        fifo = str(Path(tmp.name) / "pipe")
        try:
            os.mkfifo(fifo)
        except (OSError, AttributeError, NotImplementedError):
            self.skipTest("mkfifo unavailable on this platform")
        # _validated_dir resolves then ``is_dir()`` (a stat, not an open), so a
        # FIFO is simply "not a directory" — no blocking open, coded refusal.
        with self.assertRaises(share_acl_svc.ShareAclError) as ctx:
            share_acl_svc.read_acl(fifo)
        self.assertEqual(ctx.exception.code, "shares.bad_path")

    def test_validate_share_path_on_a_fifo_is_coded_bad_path(self):
        tmp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(tmp.cleanup)
        fifo = str(Path(tmp.name) / "pipe")
        try:
            os.mkfifo(fifo)
        except (OSError, AttributeError, NotImplementedError):
            self.skipTest("mkfifo unavailable on this platform")
        with self.assertRaises(shares_svc.ShareValidationError) as ctx:
            shares_svc.validate_share_path(fifo)
        self.assertEqual(ctx.exception.code, "shares.bad_path")


if __name__ == "__main__":
    unittest.main(verbosity=2)
