"""Leftover >4300-digit numbers and digit-only hosts in the bookmark probes.

Prior passes pinned the bookmark list against unhashable YAML keys, leftover
datetime / bytes / inf fields, and lone surrogates (see
test_assistant_bookmarks_modules_leftover_500s.py).  A fresh hunt over the
same module through the digit-limit lens — CPython's 4300-digit str->int
ValueError and the shapes past a 32-bit dword — found one real hole and two
survivors to pin:

* the hole: ``_is_private_host`` called any dotless hostname a LAN name.
  ``_ip_from_host`` classifies integer IPs only up to the 32-bit dword and
  the 4300-digit cap; a digit-only host past either bound fell through and
  read as a LAN name, so an https bookmark (or a redirect target) spelled
  ``https://99999999999/`` was probed with TLS verification *off*.
  ``http_guard.local_http_origin`` already decided the rule: a host with no
  letter is an integer IP we failed to classify, not a LAN name.  Fixed to
  match (and a torn-IPv6 leftover ``fe80:`` is not a LAN name either);
* survivor: an over-cap port in the bookmark URL — ``http.client`` refuses
  the >4300-digit port as ``InvalidURL`` inside ``_get_hostport`` before any
  socket is opened, and ``_probe`` folds that into the row's ``error`` field,
  so GET /api/bookmarks renders the list instead of 500ing;
* survivor: ``_is_blocked_probe_host`` absorbs the over-cap ``int()`` inside
  ``_ip_from_host`` (guarded there), so classification itself never raises.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from hub import bookmarks_svc

#: Past CPython's default 4300-digit str<->int conversion limit.
_HUGE_DIGITS = "9" * 5000


def _starlette(payload) -> None:
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class DigitOnlyHostClassificationTests(unittest.TestCase):
    """The TLS-verification decision for every https bookmark and redirect."""

    def test_huge_digit_host_is_not_a_lan_name_and_does_not_raise(self):
        # int(host) over the cap ValueErrors inside _ip_from_host (guarded);
        # the dotless branch then used to call the leftover a LAN name and
        # turn certificate verification off for it.
        self.assertFalse(bookmarks_svc._is_private_host(_HUGE_DIGITS))
        self.assertFalse(bookmarks_svc._is_blocked_probe_host(_HUGE_DIGITS))

    def test_over_dword_digit_host_is_not_a_lan_name(self):
        # 99999999999 > 0xFFFFFFFF: int() succeeds but the dword bound fails
        # classification, which is "an integer IP we failed to classify",
        # not a reason to skip verification.
        self.assertFalse(bookmarks_svc._is_private_host("99999999999"))
        self.assertFalse(bookmarks_svc._is_blocked_probe_host("99999999999"))

    def test_torn_ipv6_leftover_is_not_a_lan_name(self):
        self.assertFalse(bookmarks_svc._is_private_host("fe80:"))

    def test_real_lan_names_and_private_dwords_still_classify(self):
        self.assertTrue(bookmarks_svc._is_private_host("nas"))
        self.assertTrue(bookmarks_svc._is_private_host("box.lan"))
        # 3232235777 is 192.168.1.1 as a decimal dword: still LAN.
        self.assertTrue(bookmarks_svc._is_private_host("3232235777"))
        # 134744072 is 8.8.8.8: still public.
        self.assertFalse(bookmarks_svc._is_private_host("134744072"))


class ProbeHugePortDigitPinTests(unittest.TestCase):
    """GET /api/bookmarks probes every link URL through ``_probe``."""

    def test_over_cap_port_answers_an_error_row_not_a_500(self):
        # http.client._get_hostport int()s the port text: 5000 nines raise
        # the digit-limit ValueError, surfaced as InvalidURL before any
        # socket is opened.  _probe absorbs it into the error field.
        with mock.patch(
            "socket.create_connection",
            side_effect=AssertionError("a socket must never be opened"),
        ):
            out = bookmarks_svc._probe(f"http://192.168.1.9:{_HUGE_DIGITS}/")
        self.assertFalse(out["ok"])
        self.assertIsNone(out["status"])
        self.assertTrue(out["error"])
        _starlette(out)

    def test_out_of_range_port_answers_an_error_row_not_a_500(self):
        # int("99999") succeeds, so this one *does* reach the connect layer,
        # whose failure (range check or refused socket) is absorbed the same
        # way.  The patch keeps the test off the network and stands in for
        # that failure.
        with mock.patch(
            "socket.create_connection",
            side_effect=OSError("port out of range"),
        ):
            out = bookmarks_svc._probe("http://192.0.2.1:99999/")
        self.assertFalse(out["ok"])
        self.assertTrue(out["error"])
        _starlette(out)


class ListBookmarksHugePortPinTests(unittest.TestCase):
    """The whole endpoint shape: one poisoned link must not drop the list."""

    def setUp(self):
        bookmarks_svc.list_bookmarks.invalidate()
        self.addCleanup(bookmarks_svc.list_bookmarks.invalidate)

    def test_bookmark_with_huge_port_renders_the_list(self):
        with (
            mock.patch.object(
                bookmarks_svc, "cfg",
                return_value={
                    "quick_links": [{
                        "name": "Huge",
                        "url": f"http://192.168.1.9:{_HUGE_DIGITS}",
                        "id": "huge",
                    }],
                    "overrides": {},
                },
            ),
            mock.patch.object(bookmarks_svc, "_backend_index", return_value={}),
            mock.patch(
                "socket.create_connection",
                side_effect=AssertionError("a socket must never be opened"),
            ),
        ):
            data = bookmarks_svc.list_bookmarks(force=True)
        self.assertEqual(len(data["bookmarks"]), 1)
        self.assertEqual(data["bookmarks"][0]["health"], "error")
        self.assertEqual(data["down"], 1)
        _starlette(data)


if __name__ == "__main__":
    unittest.main()
