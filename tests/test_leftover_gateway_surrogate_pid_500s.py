"""Leftover Gateway-page 500s: surrogate conf paths and odd pid shapes in
GET /api/nginx's overview.

Prior sweeps sealed the Gateway backend's parsers and CLI paths —
``adaptive.nginx_sites`` and ``_nginx_listen_ports`` against surrogate names,
NULs and over-cap digits (test_leftover_parse_500s, test_leftover_ollama_
health_usage_gateway_digit_500s), and POST /api/nginx/test | /reload against
the vanished-CLI sentinel with the disk confirm (test_modules_bookmarks_
leftover_hexint_surrogate_vanish_500s).  A fresh hunt over ``overview()``
itself — the one payload the Gateway page renders on every visit — found two
holes and pinned three survivors:

* ``overview()`` answered ``"conf": str(NGINX_CONF)`` / ``"conf_d":
  str(CONF_D)`` verbatim.  Those paths derive from ``Path.home()``, and a
  HOME whose on-disk name is undecodable arrives through os.environ's
  surrogateescape as a str carrying a lone ``\\udcff`` — every sibling field
  in the payload (site names, pid, sh output) is scrubbed, but the two conf
  paths rode raw to Starlette's UTF-8 encode and 500'd GET /api/nginx.
  Confirmed as an HTTP 500 through the mounted route before fixing;

* the pid answered by ``pid_for`` was trusted as-is.  The production
  ``Listing`` coerces its columns to str, but ``overview()`` does not own
  that object: a patched or odd listing (the same class ``_sh_message``
  already guards for ``sh``) can answer an *already-int* pid.  YAML/plist
  hex loads uncapped (``int(x, 16)`` is exempt from CPython's 4300-digit
  conversion limit), so an over-cap int passed straight into the payload
  and ValueError'd Starlette's own ``json.dumps`` — a second 500.  A bool
  pid (``True`` is an int) rode to JSON as ``true`` and the SPA's
  ``Number(true)`` rendered the lie "pid 1".  The fix is a str() probe
  plus a pid_t bound — a *finite* numeric pid (``743`` as int) must keep
  reporting running, not be hidden behind a strict ``isinstance(pid, str)``
  gate;

* survivors pinned rather than fixed: a surrogate label in the real
  ``launchctl list`` output is scrubbed by ``Listing`` before it becomes a
  lookup key (so it can never alias ``local.system-nginx``), an over-cap
  digit-string pid from the real listing is no real pid_t and reads as not
  running, and ``test_config``'s surrogate ``nginx -t`` stderr is already
  scrubbed by ``_as_text``.

The other two sweep classes do not apply here: nothing in hub/nginx_svc.py
or its routers signals a pid (no ``os.kill``), and the Gateway backend owns
no JSON journal — its only persistence is the audit trail, whose loader
already catches the digit-cap ValueError line-by-line (hub/audit.py).
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hub import nginx_svc
from hub.launchd_cache import Listing, _parse

#: Built arithmetically: int("9" * 5000) itself trips the digit cap.
_HUGE_INT = 10 ** 5000


def _starlette(payload) -> None:
    """What Starlette's JSONResponse does: ensure_ascii=False then UTF-8."""
    json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")


class _OddListing:
    """A listing whose pid column skipped Listing's coercion (patched/odd)."""

    def __init__(self, pid):
        self._pid = pid

    def pid_for(self, label):
        return self._pid


def _overview(pid):
    with (
        mock.patch.object(nginx_svc, "nginx_sites", return_value=[]),
        mock.patch("hub.nginx_svc.launchd_listing", return_value=_OddListing(pid)),
    ):
        return nginx_svc.overview()


class SurrogateConfPathTests(unittest.TestCase):
    """A surrogateescape HOME must not 500 GET /api/nginx at encode time."""

    def _overview_with_home(self, home: Path) -> dict:
        root = home / "Services" / "nginx"
        with (
            mock.patch.object(nginx_svc, "NGINX_CONF", root / "nginx.conf"),
            mock.patch.object(nginx_svc, "CONF_D", root / "conf.d"),
            mock.patch.object(nginx_svc, "nginx_sites", return_value=[]),
            mock.patch("hub.nginx_svc.launchd_listing", side_effect=OSError("sandbox")),
        ):
            return nginx_svc.overview()

    def test_surrogate_home_encodes_instead_of_500ing(self):
        ov = self._overview_with_home(Path("/Users/elv\udcffin"))
        _starlette(ov)
        self.assertNotIn("\udcff", ov["conf"])
        self.assertNotIn("\udcff", ov["conf_d"])

    def test_clean_home_paths_are_unchanged(self):
        ov = self._overview_with_home(Path("/Users/elvin"))
        _starlette(ov)
        self.assertEqual(ov["conf"], "/Users/elvin/Services/nginx/nginx.conf")
        self.assertEqual(ov["conf_d"], "/Users/elvin/Services/nginx/conf.d")


class OddPidShapeTests(unittest.TestCase):
    """Pid shapes that dodge Listing's coercion must not poison the payload."""

    def test_over_cap_int_pid_is_dropped_not_a_500(self):
        # str(10**5000) is the digit-cap ValueError; pre-fix the raw int rode
        # to Starlette's json.dumps and 500'd GET /api/nginx.
        ov = _overview(_HUGE_INT)
        _starlette(ov)
        self.assertIsNone(ov["pid"])
        self.assertFalse(ov["running"])

    def test_bool_pid_is_not_a_pid(self):
        # bool is int's subclass; ``true`` in JSON made the SPA print "pid 1".
        ov = _overview(True)
        _starlette(ov)
        self.assertIsNone(ov["pid"])
        self.assertFalse(ov["running"])

    def test_finite_int_pid_still_reports_running(self):
        # The str() probe, not a strict isinstance(pid, str) gate: a sane
        # already-int pid keeps matching.
        ov = _overview(743)
        _starlette(ov)
        self.assertEqual(ov["pid"], "743")
        self.assertTrue(ov["running"])

    def test_out_of_pid_t_range_is_dropped(self):
        # pid_t is signed 32-bit; same bound cloudflared_svc applies.
        ov = _overview(str(2 ** 31))
        self.assertIsNone(ov["pid"])
        self.assertFalse(ov["running"])

    def test_digit_string_pid_from_the_real_listing_is_kept(self):
        ov = _overview("743")
        _starlette(ov)
        self.assertEqual(ov["pid"], "743")
        self.assertTrue(ov["running"])


class SurvivorPinTests(unittest.TestCase):
    """Already-guarded shapes on the same payload, pinned so they stay guarded."""

    def test_surrogate_label_is_scrubbed_before_it_becomes_a_lookup_key(self):
        # Listing scrubs mapping keys on construction, so a surrogate label
        # can never alias local.system-nginx — and the whole jobs view stays
        # UTF-8 encodable.
        listing = _parse("77\t0\tlocal.system-nginx\ud800")
        self.assertIsNone(listing.pid_for("local.system-nginx"))
        self.assertIsNone(listing.pid_for("local.system-nginx\ud800"))
        _starlette(dict(listing.jobs))

    def test_over_cap_digit_string_pid_reads_as_not_running(self):
        listing = Listing({"local.system-nginx": ("9" * 5000, "0")})
        with (
            mock.patch.object(nginx_svc, "nginx_sites", return_value=[]),
            mock.patch("hub.nginx_svc.launchd_listing", return_value=listing),
        ):
            ov = nginx_svc.overview()
        _starlette(ov)
        self.assertIsNone(ov["pid"])
        self.assertFalse(ov["running"])

    def test_surrogate_nginx_t_stderr_is_scrubbed(self):
        with tempfile.NamedTemporaryFile(suffix=".conf") as conf:
            with (
                mock.patch.object(nginx_svc, "NGINX_CONF", Path(conf.name)),
                mock.patch.object(nginx_svc, "sh", return_value=(1, "", "bad \ud800 conf")),
                mock.patch.object(nginx_svc, "_nginx_present", return_value=True),
            ):
                out = nginx_svc.test_config()
        _starlette(out)
        self.assertFalse(out["ok"])
        self.assertNotIn("\ud800", out["message"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
