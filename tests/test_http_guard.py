"""Local-origin and no-redirect guards used by Ollama, Immich, PhotosHub, notify."""
from __future__ import annotations

import unittest

from hub.http_guard import (
    NoRedirect,
    RedirectRefused,
    is_allowed_webhook_url,
    is_local_http_origin,
    local_http_origin,
    local_connect_peer,
    notify_connect_peer,
    pinned_no_redirect_opener,
)


class LocalOriginTests(unittest.TestCase):
    def test_loopback_and_lan_are_allowed(self):
        for url in (
            "http://127.0.0.1:11434",
            "http://[::1]:11434",
            "http://[0:0:0:0:0:0:0:1]:2283",
            "http://192.168.1.206:2283",
            "http://10.0.0.2:11434",
            "http://immich:2283",
            "http://nas.local:2283",
        ):
            with self.subTest(url=url):
                self.assertEqual(local_http_origin(url), url)

    def test_public_and_metadata_are_rejected(self):
        for url in (
            "https://ollama.example.com",
            "http://8.8.8.8:11434",
            "http://[2001:4860:4860::8888]:11434",
            "http://169.254.169.254/latest/meta-data",
            "http://[fd00:ec2::254]/",
            "http://metadata/",
            "file:///etc/passwd",
            "javascript:alert(1)",
            # Decimal / hex IPv4 used to pass as single-label hostnames.
            "http://2852039166/",          # 169.254.169.254
            "http://134744072/",           # 8.8.8.8
            "http://0x08080808/",          # 8.8.8.8
            "http://[::ffff:169.254.169.254]/",
            "http://[::ffff:8.8.8.8]/",
        ):
            with self.subTest(url=url):
                self.assertFalse(is_local_http_origin(url))

    def test_encoded_loopback_and_lan_ips_are_still_local(self):
        for url in (
            "http://2130706433:11434",           # 127.0.0.1
            "http://0x7f000001:11434",           # 127.0.0.1
            "http://[::ffff:127.0.0.1]:11434",
            "http://[::ffff:192.168.1.1]:11434",
        ):
            with self.subTest(url=url):
                self.assertEqual(local_http_origin(url), url)

    def test_trailing_slash_is_stripped(self):
        self.assertEqual(
            local_http_origin("http://127.0.0.1:11434/"),
            "http://127.0.0.1:11434",
        )


class LocalConnectPeerTests(unittest.TestCase):
    def test_loopback_and_lan_ips_are_returned(self):
        self.assertEqual(local_connect_peer("127.0.0.1"), "127.0.0.1")
        self.assertEqual(local_connect_peer("192.168.1.10"), "192.168.1.10")

    def test_public_and_metadata_ips_are_refused(self):
        self.assertIsNone(local_connect_peer("8.8.8.8"))
        self.assertIsNone(local_connect_peer("169.254.169.254"))

    def test_a_lan_name_that_resolves_public_is_refused(self):
        import socket
        from unittest.mock import patch

        def fake_addrinfo(host, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 0))]

        with patch("hub.http_guard.socket.getaddrinfo", side_effect=fake_addrinfo):
            self.assertIsNone(local_connect_peer("immich.lan"))

    def test_unresolved_lan_name_fail_opens(self):
        import socket
        from unittest.mock import patch

        with patch("hub.http_guard.socket.getaddrinfo", side_effect=socket.gaierror("boom")):
            self.assertEqual(local_connect_peer("immich.lan"), "immich.lan")
            self.assertEqual(local_connect_peer("immich"), "immich")
            self.assertIsNone(local_connect_peer("example.com"))


class WebhookUrlTests(unittest.TestCase):
    """Notify webhooks may be public; metadata and link-local must not."""

    def test_public_and_lan_webhooks_are_allowed(self):
        for url in (
            "https://hooks.slack.com/services/x",
            "https://discord.com/api/webhooks/1/x",
            "https://ntfy.sh/topic",
            "http://ha.lan:8123/api/webhook/x",
            "http://192.168.1.2:8123/api/webhook/x",
            "http://127.0.0.1:8123/api/webhook/x",
        ):
            with self.subTest(url=url):
                self.assertTrue(is_allowed_webhook_url(url))

    def test_metadata_and_link_local_are_blocked(self):
        for url in (
            "http://169.254.169.254/latest/meta-data",
            "http://[fd00:ec2::254]/",
            "http://metadata/",
            "http://metadata.google.internal/",
            "http://169.254.1.1/",
            "http://[fe80::1]/",
            "http://100.100.100.200/",
            "http://192.0.0.192/",
            "http://168.63.129.16/",
            "http://2852039166/",          # 169.254.169.254
            "http://0xa9fea9fe/",          # 169.254.169.254
            "http://[::ffff:169.254.169.254]/",
            "file:///etc/passwd",
            "gopher://x",
        ):
            with self.subTest(url=url):
                self.assertFalse(is_allowed_webhook_url(url))

    def test_torn_ipv6_urls_are_rejected_not_raised(self):
        """``urlsplit('http://[::1')`` raises; notify save used to 500."""
        for url in ("http://[::1", "http://[", "http://[]", "http://[:::1]/"):
            with self.subTest(url=url):
                self.assertFalse(is_allowed_webhook_url(url))
                self.assertFalse(is_local_http_origin(url))

    def test_nul_and_surrogate_hosts_are_rejected_not_raised(self):
        """inet_aton / IDNA leftover used to 500 POST /api/alerts/channels."""
        for url in ("http://\x00", "http://127.0.0.1\x00", "http://" + "\udcff"):
            with self.subTest(url=url):
                self.assertFalse(is_allowed_webhook_url(url))
                self.assertFalse(is_local_http_origin(url))
        self.assertIsNone(local_connect_peer("\udcff"))
        self.assertIsNone(notify_connect_peer("\x00"))

    def test_surrogate_path_and_lan_name_are_rejected_not_500(self):
        """Leftover ``\\ud800`` in the path or a ``.lan`` name used to leak."""
        self.assertIsNone(local_http_origin("http://127.0.0.1/\ud800"))
        self.assertFalse(is_allowed_webhook_url("http://example.com/\ud800", resolve=False))
        self.assertIsNone(local_connect_peer("ha\ud800.lan"))
        self.assertIsNone(notify_connect_peer("immich\ud800"))
        self.assertFalse(is_local_http_origin("http://ha.lan/\ud800"))

    def test_unicode_digit_host_does_not_500(self):
        """``'١٢٣'.isdigit()`` is True; leftover ``int()`` made 0.0.0.123 local."""
        url = "http://\u0661\u0662\u0663/"
        self.assertFalse(is_local_http_origin(url))
        is_allowed_webhook_url(url)  # public-name path; must not raise
        self.assertIsNone(local_connect_peer("\u0661\u0662\u0663"))

    def test_short_and_octal_ips_are_parsed(self):
        from hub.http_guard import is_local_http_origin
        self.assertTrue(is_local_http_origin("http://127.1:11434"))
        self.assertTrue(is_allowed_webhook_url("http://127.1:8123/hook"))
        self.assertTrue(is_allowed_webhook_url("http://0177.0.0.1:8123/hook"))

    def test_send_path_fails_closed_when_dns_fails(self):
        import socket
        from unittest.mock import patch
        from hub.http_guard import is_allowed_notify_host

        with patch("hub.http_guard.socket.getaddrinfo", side_effect=socket.gaierror("boom")):
            self.assertTrue(is_allowed_notify_host("ntfy.sh", resolve_required=False))
            self.assertFalse(is_allowed_notify_host("ntfy.sh", resolve_required=True))

    def test_a_hostname_that_resolves_to_metadata_is_blocked(self):
        import socket
        from unittest.mock import patch

        def fake_addrinfo(host, *args, **kwargs):
            self.assertEqual(host, "169.254.169.254.nip.io")
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("169.254.169.254", 0))]

        with patch("hub.http_guard.socket.getaddrinfo", side_effect=fake_addrinfo):
            self.assertFalse(
                is_allowed_webhook_url("http://169.254.169.254.nip.io/latest/meta-data")
            )

    def test_notify_connect_peer_returns_the_resolved_ip(self):
        import socket
        from unittest.mock import patch

        def fake_addrinfo(host, *args, **kwargs):
            self.assertEqual(host, "hooks.example.com")
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("203.0.113.10", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("203.0.113.11", 0)),
            ]

        with patch("hub.http_guard.socket.getaddrinfo", side_effect=fake_addrinfo):
            self.assertEqual(notify_connect_peer("hooks.example.com"), "203.0.113.10")

    def test_notify_connect_peer_refuses_any_metadata_record(self):
        import socket
        from unittest.mock import patch

        def fake_addrinfo(host, *args, **kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("203.0.113.10", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("169.254.169.254", 0)),
            ]

        with patch("hub.http_guard.socket.getaddrinfo", side_effect=fake_addrinfo):
            self.assertIsNone(notify_connect_peer("evil.example"))

    def test_notify_connect_peer_keeps_unresolved_lan_names(self):
        import socket
        from unittest.mock import patch

        with patch("hub.http_guard.socket.getaddrinfo", side_effect=socket.gaierror("boom")):
            self.assertEqual(notify_connect_peer("ha.lan"), "ha.lan")
            self.assertIsNone(notify_connect_peer("ntfy.sh"))

    def test_pinned_opener_dials_the_given_ip(self):
        opener = pinned_no_redirect_opener("203.0.113.10")
        https = next(
            h for h in opener.handlers
            if type(h).__name__ == "PinnedHTTPSHandler"
        )
        self.assertEqual(https._dest_ip, "203.0.113.10")


class NoRedirectTests(unittest.TestCase):
    def test_any_redirect_is_refused(self):
        handler = NoRedirect()
        with self.assertRaises(RedirectRefused):
            handler.redirect_request(
                None, None, 302, "Found", {}, "http://169.254.169.254/",
            )


if __name__ == "__main__":
    unittest.main()
