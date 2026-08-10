"""Live state that cannot be read is not the same as a stopped tunnel.

`status()` reports `running: False` for two very different situations, and the page
rendered both identically:

  * the tunnel really is down, and
  * live state could not be read at all -- which needs root (`wg show <utun> dump`),
    so a pinned `wg` that is not installed, a browser tab with no cached admin
    password, or an interface the backend cannot disambiguate all land here.  The
    second case sets `state_error`.

Treating the second as "stopped" is what produced the report that the page could
neither start nor stop the tunnel: the Stop button was rendered only in the `v-else`
of `data.running`, so it disappeared, while `interface_action("up")` short-circuits
on wg-quick's own *filesystem* view of liveness and answered `already_running: True`
with a success toast — the page kept saying stopped and offered no way out.

The diagnostic explaining it was already being computed and then discarded: its only
consumer was a readiness row that the view filters out of both the blocking and the
warning lists.

These tests pin the backend contract (`state_error` is populated and distinct from a
clean stop) and the template's three-state handling.
"""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

VIEW = (BASE / "web" / "src" / "views" / "WireGuard.vue").read_text(encoding="utf-8")
STYLES = (BASE / "web" / "src" / "styles.css").read_text(encoding="utf-8")


class StatusContractTests(unittest.TestCase):
    """The backend has to distinguish the two cases for the view to render them."""

    def test_status_reports_a_state_error_field(self):
        from hub import wireguard_svc

        source = (BASE / "hub" / "wireguard_svc.py").read_text(encoding="utf-8")
        self.assertIn('"state_error": error', source)
        self.assertTrue(hasattr(wireguard_svc, "live_interface"))

    def test_live_interface_returns_a_reason_when_it_cannot_read(self):
        from unittest.mock import patch

        from hub import wireguard_svc

        # sudo declining is the common case: no pinned binary, or no password.
        with patch.object(
            wireguard_svc,
            "sudo_capture",
            return_value=(1, "", "sudo: a password is required"),
        ):
            device, _, error = wireguard_svc.live_interface("wg0")
        self.assertFalse(device)
        self.assertTrue(
            error,
            "live_interface reported no device and no reason, so the page cannot "
            "tell a stopped tunnel from an unreadable one",
        )


class ThreeStateViewTests(unittest.TestCase):
    def test_the_view_computes_a_three_way_state(self):
        self.assertIn("const liveState = computed(", VIEW)
        for state in ("'running'", "'unknown'", "'stopped'"):
            with self.subTest(state=state):
                self.assertIn(state, VIEW)

    def test_unknown_is_driven_by_state_error(self):
        self.assertRegex(
            VIEW,
            r"state_error\s*\?\s*'unknown'\s*:\s*'stopped'",
            "the unknown state is not derived from state_error",
        )

    def test_stop_is_not_hidden_behind_running(self):
        # The regression shape: `v-if="!data?.running"` on Start with `v-else` on
        # Stop, which makes an unreadable state indistinguishable from stopped and
        # removes the only control that could fix it.
        self.assertNotRegex(
            VIEW,
            r'class="danger wg-stop"[^>]*\n?\s*v-else',
            "Stop is still rendered as the v-else of running",
        )
        self.assertIn("v-if=\"liveState !== 'stopped'\"", VIEW)
        self.assertIn("v-if=\"liveState !== 'running'\"", VIEW)

    def test_both_buttons_are_available_when_state_is_unknown(self):
        # Derived from the two conditions above rather than restated: with
        # liveState === 'unknown', `!== 'stopped'` and `!== 'running'` are both true.
        start = "liveState !== 'running'"
        stop = "liveState !== 'stopped'"
        self.assertIn(start, VIEW)
        self.assertIn(stop, VIEW)
        for condition in (start, stop):
            with self.subTest(condition=condition):
                self.assertNotIn("unknown", condition)

    def test_the_reason_is_rendered(self):
        self.assertIn("data.state_error", VIEW)

    def test_the_unknown_state_has_its_own_label(self):
        self.assertIn("wg.tunnel_unknown", VIEW)

    def test_every_locale_translates_the_new_label(self):
        for locale in ("zh-CN", "en", "ja"):
            source = (BASE / "web" / "src" / "i18n" / f"{locale}.js").read_text(
                encoding="utf-8"
            )
            with self.subTest(locale=locale):
                self.assertRegex(source, r"\btunnel_unknown\s*:")

    def test_unknown_is_not_painted_as_down(self):
        # The red "stopped" styling applied to :not(.running), which included the
        # unknown case and said "the tunnel is off" when the truth was "this page
        # could not find out".
        self.assertIn(".wg-status-bar:not(.running):not(.unknown)", VIEW)
        self.assertIn(".wg-status-bar.unknown", VIEW)

    def test_sync_and_ping_are_not_disabled_merely_because_state_is_unknown(self):
        self.assertNotIn('busy || !data?.running', VIEW)
        self.assertIn("busy || liveState === 'stopped'", VIEW)


class QrIsNotClippedTests(unittest.TestCase):
    """The modal was a max-height flex column with `overflow: hidden`.

    Nothing inside it scrolled except the config `<pre>`, so on a short viewport the
    QR (and sometimes the Copy/Download row) was cut off with no scrollbar to
    reveal it — the "displayed QR is incomplete" report.  An earlier fix gave the
    scalable SVG an explicitly sized box, which addressed intrinsic sizing but not
    the clipping.
    """

    def test_the_modal_scrolls_vertically(self):
        # styles.css declares `.modal` more than once (a mobile media query
        # overrides width and radius), so pick the rule that actually establishes
        # the flex column rather than the first match.
        bodies = [
            match.group(1)
            for match in re.finditer(r"\.modal\s*\{(.*?)\}", STYLES, re.S)
            if "flex-direction: column" in match.group(1)
        ]
        self.assertEqual(
            len(bodies), 1, "expected exactly one .modal rule to define the column"
        )
        body = bodies[0]
        self.assertNotRegex(
            body,
            r"overflow:\s*hidden\s*;",
            "`overflow: hidden` on a max-height flex column silently clips "
            "whatever does not fit, with no scrollbar to reveal it",
        )
        self.assertRegex(body, r"overflow:\s*hidden\s+auto")

    def test_the_qr_box_refuses_to_shrink(self):
        qr = re.search(r"\.wg-qr\s*\{(.*?)\}", VIEW, re.S)
        self.assertIsNotNone(qr, ".wg-qr rule not found")
        self.assertRegex(
            qr.group(1),
            r"flex-shrink:\s*0",
            "a flex child with default shrink is the item that gets squeezed, "
            "so the QR shrank instead of the dialog scrolling",
        )


class BatchDoesNotShipKeysTests(unittest.TestCase):
    """A batch of 50 returned 50 client private keys the caller never reads."""

    def test_retained_peers_come_back_without_key_material(self):
        from hub import wireguard_svc

        created = [
            {"pub": "A" * 43 + "=", "name": "peer-1", "reissuable": True,
             "client_conf": "PrivateKey = secret", "psk": "P" * 43 + "="},
        ]
        payload = wireguard_svc._batch_payload(created)
        self.assertNotIn("client_conf", payload[0])
        self.assertNotIn("psk", payload[0])
        self.assertEqual(payload[0]["name"], "peer-1")

    def test_a_non_retained_peer_keeps_its_config(self):
        # keep_key=False means the key is handed over exactly once and stored
        # nowhere; withholding it here would destroy it rather than protect it.
        from hub import wireguard_svc

        created = [
            {"pub": "B" * 43 + "=", "name": "throwaway", "reissuable": False,
             "client_conf": "PrivateKey = only-copy", "psk": ""},
        ]
        payload = wireguard_svc._batch_payload(created)
        self.assertEqual(payload[0]["client_conf"], "PrivateKey = only-copy")

    def test_the_batch_caller_only_needs_the_count(self):
        # Justifies the strip: if the view started reading peer configs from the
        # batch response this test should fail and make that visible.
        self.assertNotRegex(
            VIEW,
            r"result\.peers",
            "createBatch now reads the per-peer payload; revisit whether the "
            "private keys need to be sent",
        )


if __name__ == "__main__":
    unittest.main()
