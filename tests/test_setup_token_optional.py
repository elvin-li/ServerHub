"""The first-run token is required where it protects something, and not elsewhere.

Claiming a fresh panel used to demand a 64-character token even when the browser
was running on the machine itself. That is pure friction: ``/api/auth/setup-token``
hands the token to any loopback client that asks, so a browser on this Mac can
always obtain it. Requiring it there excludes no attacker -- it just makes the
operator copy a secret from one box into another, or go and read a file.

Off the machine it is doing real work. It is the only thing between an unclaimed
panel and whoever reaches it first, and this host publishes the panel over a
Cloudflare tunnel and a VPN, so "first" is not necessarily someone in the house.

So the default is: exempt on loopback, required from anywhere else. ``always`` and
``never`` remain available for operators who want to override that. These tests pin
the boundary, because getting it wrong in the lenient direction hands the panel to
a stranger.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hub import auth  # noqa: E402


class _Req:
    def __init__(self, host: str = "127.0.0.1", headers: dict | None = None):
        self.client = type("C", (), {"host": host})() if host is not None else None
        self.headers = headers or {}
        self.url = type("U", (), {"path": "/api/auth/setup"})()
        self.state = type("S", (), {})()
        self.cookies = {}


def with_mode(mode: str):
    return patch.object(auth, "_auth_cfg", return_value={"setup_token_mode": mode})


class RequirementBoundaryTests(unittest.TestCase):
    def test_default_mode_is_auto(self):
        with patch.object(auth, "_auth_cfg", return_value={}):
            self.assertEqual(auth.setup_token_mode(), "auto")

    def test_an_unknown_mode_falls_back_to_auto(self):
        """A typo in the config must not silently disable the protection."""
        for value in ("", "off", "no", "TRUE", "disabled", None):
            with self.subTest(value=value):
                with patch.object(auth, "_auth_cfg", return_value={"setup_token_mode": value}):
                    self.assertEqual(auth.setup_token_mode(), "auto")

    def test_loopback_does_not_need_a_token(self):
        with with_mode("auto"):
            for host in ("127.0.0.1", "::1"):
                with self.subTest(host=host):
                    self.assertFalse(auth.setup_token_required(_Req(host)))

    def test_a_proxied_loopback_claim_needs_a_token(self):
        """Tunnel/nginx hops are TCP-loopback but are not 'on this Mac'.

        cloudflared and typical reverse proxies connect to 127.0.0.1:8086, so
        ``request.client.host`` is loopback for every remote visitor. The Host
        header and forwarded-client headers are what distinguish that from a
        browser opened on the machine itself. Getting this wrong in the lenient
        direction lets the first stranger through a published tunnel claim the
        panel with no setup token.
        """
        with with_mode("auto"):
            cases = [
                _Req("127.0.0.1", headers={"host": "panel.example.com"}),
                _Req("127.0.0.1", headers={"host": "localhost:8086", "x-forwarded-for": "203.0.113.9"}),
                _Req("127.0.0.1", headers={"cf-connecting-ip": "203.0.113.9"}),
                _Req("::1", headers={"x-forwarded-proto": "https"}),
                _Req("127.0.0.1", headers={"forwarded": "for=203.0.113.9;proto=https"}),
            ]
            for req in cases:
                with self.subTest(headers=dict(req.headers)):
                    self.assertTrue(auth.setup_token_required(req))

    def test_a_direct_localhost_host_header_is_still_local(self):
        with with_mode("auto"):
            for host_header in ("localhost", "localhost:8086", "127.0.0.1:8086", "[::1]:8086"):
                with self.subTest(host=host_header):
                    req = _Req("127.0.0.1", headers={"host": host_header})
                    self.assertFalse(auth.setup_token_required(req))

    def test_a_lan_client_needs_a_token(self):
        with with_mode("auto"):
            for host in ("192.168.1.50", "10.10.0.2", "203.0.113.9"):
                with self.subTest(host=host):
                    self.assertTrue(auth.setup_token_required(_Req(host)))

    def test_an_unknown_source_fails_closed(self):
        """No client information must never be read as "probably local"."""
        with with_mode("auto"):
            self.assertTrue(auth.setup_token_required(_Req("")))
            self.assertTrue(auth.setup_token_required(_Req(None)))
            self.assertTrue(auth.setup_token_required(None))

    def test_a_hostname_that_merely_looks_local_is_not_loopback(self):
        with with_mode("auto"):
            for host in ("127.0.0.1.evil.com", "localhost", "0.0.0.0", "::2"):
                with self.subTest(host=host):
                    self.assertTrue(auth.setup_token_required(_Req(host)))

    def test_always_mode_requires_it_even_on_loopback(self):
        with with_mode("always"):
            self.assertTrue(auth.setup_token_required(_Req("127.0.0.1")))

    def test_never_mode_requires_it_nowhere(self):
        with with_mode("never"):
            self.assertFalse(auth.setup_token_required(_Req("192.168.1.50")))


class CompleteSetupTests(unittest.TestCase):
    """The claim itself, with the token demanded or not."""

    def setUp(self):
        self.set_password = patch.object(auth, "set_password").start()
        patch.object(auth, "setup_required", return_value=True).start()
        patch.object(auth, "consume_setup_token").start()
        patch.object(auth, "setup_token", return_value="T" * 43).start()
        self.addCleanup(patch.stopall)

    def test_a_claim_without_a_token_succeeds_when_not_required(self):
        self.assertTrue(
            auth.complete_setup("", "a-long-password", "admin", require_token=False)
        )
        self.set_password.assert_called_once()

    def test_a_claim_without_a_token_fails_when_required(self):
        self.assertFalse(
            auth.complete_setup("", "a-long-password", "admin", require_token=True)
        )
        self.set_password.assert_not_called()

    def test_a_wrong_token_fails_even_when_not_required(self):
        """A supplied-but-wrong token is a mistake worth surfacing, not ignoring.

        Silently accepting it would mean a stale or mistyped value appeared to
        work, which is exactly the confusion this feature already caused once.
        """
        self.assertFalse(
            auth.complete_setup("wrong-token", "a-long-password", "admin", require_token=False)
        )
        self.set_password.assert_not_called()

    def test_the_correct_token_still_works(self):
        self.assertTrue(
            auth.complete_setup("T" * 43, "a-long-password", "admin", require_token=True)
        )

    def test_requiring_a_token_is_the_default(self):
        """A caller that forgets the keyword must get the strict behaviour."""
        self.assertFalse(auth.complete_setup("", "a-long-password", "admin"))

    def test_an_already_claimed_panel_cannot_be_reclaimed(self):
        with patch.object(auth, "setup_required", return_value=False):
            self.assertFalse(
                auth.complete_setup("", "a-long-password", "admin", require_token=False)
            )


class StatusPayloadTests(unittest.TestCase):
    def test_status_tells_the_form_whether_to_ask(self):
        source = (BASE / "hub" / "routers" / "auth_api.py").read_text()
        self.assertIn('"setup_token_required": auth.setup_token_required(request)', source)
        self.assertIn('"setup_token_mode": auth.setup_token_mode()', source)

    def test_the_setup_route_passes_the_request_through(self):
        source = (BASE / "hub" / "routers" / "auth_api.py").read_text()
        self.assertIn("require_token=auth.setup_token_required(request)", source)

    def test_the_form_defaults_to_asking(self):
        """A failed status call must not make the form look easier than it is."""
        view = (BASE / "web" / "src" / "views" / "Login.vue").read_text()
        self.assertIn("const tokenNeeded = ref(true)", view)
        self.assertIn("state.setup_token_required !== false", view)


class SetupUsernameTests(unittest.TestCase):
    def test_a_colon_username_cannot_claim_the_panel(self):
        with self.assertRaises(ValueError) as ctx:
            auth.set_password("a-long-enough-password", "admin:evil")
        self.assertEqual(str(ctx.exception), "bad_username")


if __name__ == "__main__":
    unittest.main()
