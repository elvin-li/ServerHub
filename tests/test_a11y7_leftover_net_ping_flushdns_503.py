"""Seventh a11y leftover sweep: vanished-CLI lies on the Tools net helpers.

a11y4–a11y6 taught the Network tab's networksetup/ifconfig/route/ping/
dscacheutil/dig seams the house vanished-CLI rule — a fresh disk probe on
the spawn-sentinel failure path only, a coded 503 for a confirmed-absent
binary, honest answers kept everywhere else — but the Tools tab's own net
helpers still lied through ``sh``'s ``(-1, "", "not found")`` sentinel:

* POST /api/tools/net/ping spawns ``/sbin/ping`` directly.  A vanished
  ping answered 200 ``{"ok": false, "output": "not found"}`` — which reads
  like the *target host* does not respond, the exact NXDOMAIN-style lie
  a11y6 fixed on GET /api/system/network/dns-lookup;
* POST /api/tools/net/flush-dns runs ``dscacheutil -flushcache`` then
  ``killall -HUP mDNSResponder``.  With both vanished it answered 200
  "partially failed (may need administrator privileges)" — blaming sudo
  rights for missing host tools — and still spawned the sudo fallback
  over the confirmed-gone killall.

Reproduced live over ``create_app()`` + ``TestClient`` before fixing
(Linux CI verbatim: neither macOS tool is on disk, so both routes answered
the 200 lies word for word).  The fix follows the a11y4–a11y6 rule exactly:
module-level path constants (the network_svc ROUTE/PING convention) so the
disk probe re-checks the exact path the spawn used, the probe runs only
when the spawn answered the sentinel, a present-but-failing tool keeps its
existing honest answer, and the flush-dns raise fires *before* the sudo
fallback so nothing re-spawns over a confirmed-gone binary.
"""
from __future__ import annotations

import sys
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from hub import tools_svc
from hub.auth import require_auth

_APP = None

#: A path that exists on every host, standing in for a binary still on disk.
_ON_DISK = sys.executable
_GONE = "/nonexistent/a11y7/tool"

#: Exactly what ``hub.util.sh`` answers for a FileNotFoundError spawn.
_SENTINEL = (-1, "", "not found")


def _client() -> TestClient:
    global _APP
    if _APP is None:
        from hub.app_factory import create_app

        _APP = create_app()
        _APP.dependency_overrides[require_auth] = lambda: True
    return TestClient(_APP, raise_server_exceptions=False)


def _strict(resp) -> str:
    """The body must already be valid UTF-8 — decode strictly on purpose."""
    return resp.content.decode("utf-8")


class VanishedPingToolsNetPingTests(unittest.TestCase):
    """POST /api/tools/net/ping: the host-not-found lie becomes the coded 503."""

    def _ping(self, *, ping_path, ping_result=_SENTINEL, calls=None):
        def fake(argv, timeout=10, **kwargs):
            if calls is not None:
                calls.append(list(argv))
            if argv[0] == tools_svc.PING:
                return ping_result
            return 1, "", "not run"

        with (
            mock.patch.object(tools_svc, "sh", side_effect=fake),
            mock.patch.object(tools_svc, "PING", ping_path),
        ):
            return _client().post(
                "/api/tools/net/ping", json={"host": "example.com", "count": 1}
            )

    def test_confirmed_absent_ping_is_the_coded_503(self):
        # Fails on the pre-fix tree: 200 {"ok": false, "output": "not found"}
        # — reads like example.com does not respond.
        resp = self._ping(ping_path=_GONE)
        self.assertEqual(resp.status_code, 503, _strict(resp)[:300])
        self.assertEqual(resp.json()["detail"]["code"], "tools.ping_missing")

    def test_sentinel_with_the_binary_on_disk_keeps_the_honest_answer(self):
        # Present-but-failing must not upgrade to 503 (the a11y4 rule): a
        # genuine ping whose output merely reads "not found" stays honest.
        resp = self._ping(ping_path=_ON_DISK)
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        payload = resp.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["output"], "not found")

    def test_ping_present_but_unreachable_keeps_the_honest_answer(self):
        # An unreachable host is exactly what the tool reports honestly.
        resp = self._ping(
            ping_path=_ON_DISK,
            ping_result=(1, "", "Request timeout for icmp_seq 0"),
        )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        payload = resp.json()
        self.assertFalse(payload["ok"])
        self.assertIn("Request timeout", payload["output"])

    def test_working_ping_keeps_the_honest_success(self):
        resp = self._ping(
            ping_path=_ON_DISK,
            ping_result=(0, "1 packets transmitted, 1 received", ""),
        )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertTrue(resp.json()["ok"])

    def test_bad_host_refusal_still_precedes_the_spawn(self):
        # The coded soft-fail fires before any spawn, so the tool's absence
        # never turns a caller mistake into the 503.
        calls: list = []

        def fake(argv, timeout=10, **kwargs):
            calls.append(list(argv))
            return _SENTINEL

        with (
            mock.patch.object(tools_svc, "sh", side_effect=fake),
            mock.patch.object(tools_svc, "PING", _GONE),
        ):
            resp = _client().post("/api/tools/net/ping", json={"host": "-f"})
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        payload = resp.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["code"], "tools.bad_host")
        self.assertEqual(calls, [])


class VanishedFlushToolsFlushDnsTests(unittest.TestCase):
    """POST /api/tools/net/flush-dns: the sudo-rights lie becomes the coded
    503, and nothing re-spawns over the confirmed-gone killall."""

    def _flush(self, *, dsc_path, kill_path, dsc_result=_SENTINEL,
               kill_result=_SENTINEL, sudo_result=(1, "", "sudo: a password is required"),
               calls=None):
        def fake(argv, timeout=10, **kwargs):
            if calls is not None:
                calls.append(list(argv))
            if argv[0] == "/usr/bin/sudo":
                return sudo_result
            if argv[0] == tools_svc.DSCACHEUTIL:
                return dsc_result
            if argv[0] == tools_svc.KILLALL:
                return kill_result
            return 1, "", "not run"

        with (
            mock.patch.object(tools_svc, "sh", side_effect=fake),
            mock.patch.object(tools_svc, "DSCACHEUTIL", dsc_path),
            mock.patch.object(tools_svc, "KILLALL", kill_path),
        ):
            return _client().post("/api/tools/net/flush-dns")

    def test_both_tools_confirmed_absent_is_the_coded_503_without_sudo_churn(self):
        # Fails on the pre-fix tree: 200 "partially failed (may need
        # administrator privileges)" plus a sudo spawn over the gone tool.
        calls: list = []
        resp = self._flush(dsc_path=_GONE, kill_path=_GONE, calls=calls)
        self.assertEqual(resp.status_code, 503, _strict(resp)[:300])
        self.assertEqual(
            resp.json()["detail"]["code"], "tools.dns_flush_tools_missing"
        )
        sudo_calls = [c for c in calls if c[0] == "/usr/bin/sudo"]
        self.assertEqual(sudo_calls, [], "the raise must precede the sudo fallback")

    def test_sentinel_with_the_binaries_on_disk_keeps_the_honest_escalation(self):
        # Present-but-failing must not upgrade to 503: the honest sudo
        # fallback still runs and the 200 keeps its privilege hint.
        calls: list = []
        resp = self._flush(dsc_path=_ON_DISK, kill_path=_ON_DISK, calls=calls)
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        payload = resp.json()
        self.assertFalse(payload["ok"])
        self.assertIn("administrator privileges", payload["message"])
        sudo_calls = [c for c in calls if c[0] == "/usr/bin/sudo"]
        self.assertEqual(len(sudo_calls), 1)

    def test_killall_still_on_disk_keeps_the_honest_escalation(self):
        # dscacheutil genuinely gone but killall present-but-failing: either
        # tool still on disk keeps the honest answer (the a11y6 dns rule).
        resp = self._flush(
            dsc_path=_GONE,
            kill_path=_ON_DISK,
            kill_result=(1, "", "No matching processes"),
        )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertFalse(resp.json()["ok"])

    def test_sudo_fallback_success_keeps_the_honest_flush(self):
        resp = self._flush(
            dsc_path=_ON_DISK,
            kill_path=_ON_DISK,
            kill_result=(1, "", "Operation not permitted"),
            sudo_result=(0, "", ""),
        )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        payload = resp.json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["message"], "DNS cache flushed")

    def test_direct_killall_success_never_pays_the_disk_probe_or_sudo(self):
        calls: list = []
        resp = self._flush(
            dsc_path=_GONE,
            kill_path=_ON_DISK,
            kill_result=(0, "", ""),
            calls=calls,
        )
        self.assertEqual(resp.status_code, 200, _strict(resp)[:300])
        self.assertTrue(resp.json()["ok"])
        sudo_calls = [c for c in calls if c[0] == "/usr/bin/sudo"]
        self.assertEqual(sudo_calls, [])


if __name__ == "__main__":
    unittest.main()
